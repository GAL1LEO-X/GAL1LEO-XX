"""SQLite contention must not stall unrelated work on the request event loop."""
import asyncio
from dataclasses import replace
import sqlite3
import threading
import time
from types import SimpleNamespace

import pytest
from mcp import types
from starlette.requests import Request

from test_mcp_resource_reads import mcp_app
from sally_whatsapp.server import Unsubscribe
from sally_whatsapp.linking import LinkPortal, COOKIE, digest


def request(name):
    if name == 'prepare_file':
        return {'file': {'file_id': 'synthetic-upload', 'download_url': 'https://files.example/file',
                         'file_name': 'synthetic.txt'}}
    return {'idempotency_key': 'synthetic-history-request-0001', 'chat_ids': ['synthetic@g.us']}


async def completed(task):
    async with asyncio.timeout(4):
        while not task.done():
            await asyncio.sleep(.005)
    return task.result()


@pytest.mark.parametrize('name', ['prepare_file', 'start_history_sync', 'control_history_sync',
                                 'events/unsubscribe', 'portal/logout'])
def test_contended_sqlite_tool_yields_to_other_request(mcp_app, environment, name):
    service = mcp_app['service']
    arguments = request(name)
    if name == 'control_history_sync':
        job = service.history.start('test-owner', arguments['idempotency_key'], arguments['chat_ids'])
        arguments = {'job_id': job['id'], 'action': 'pause'}
    if name == 'portal/logout':
        portal = LinkPortal(SimpleNamespace(settings=replace(service.settings, link_client_id='test-client'),
            store=service.store, gateway=service.gateway, diagnostics=service.diagnostics, run_sync=service.run_sync),
            oauth_client=SimpleNamespace(close=lambda: None))
        with service.store.db() as db:
            db.execute('INSERT INTO link_sessions VALUES(?,?,?,?,?)',
                       (digest('a'*43), 'test-owner', portal.cipher.encrypt(environment[3](scope='whatsapp:link').encode()),
                        'synthetic-csrf', time.time()+600))
        logout = Request({'type':'http','method':'POST','path':'/connect/api/logout', 'headers':[
            (b'cookie',(COOKIE+'='+'a'*43).encode()), (b'origin',service.settings.public_url.encode()),
            (b'x-csrf-token',b'synthetic-csrf')]})
    async def invoke():
        if name == 'events/unsubscribe':
            handler = mcp_app['sdk'].get_request_handler(name).handler
            return await handler(None, Unsubscribe(name='message.received', arguments={'all_chats':True},
                delivery={'mode':'webhook','url':'https://receiver.example/events'}))
        if name == 'portal/logout':
            return await portal.logout(logout)
        return await mcp_app['on_call_tool'](None, types.CallToolRequestParams(name=name, arguments=arguments))
    lock = sqlite3.connect(service.settings.database, check_same_thread=False)
    lock.execute('BEGIN IMMEDIATE')
    released = threading.Event()
    def release():
        lock.rollback()
        released.set()
    timer = threading.Timer(.3, release)
    async def exercise():
        timer.start()
        task = asyncio.create_task(invoke())
        # With the former synchronous callback, this coroutine only resumes
        # after the SQLite writer releases. With the fix it progresses during
        # contention, while the real work remains tracked by RuntimeReadiness.
        await asyncio.sleep(.03)
        assert not released.is_set() and not task.done()
        # Logout first completes its read-only session verification, then
        # submits the contended delete as a separate owned synchronous unit.
        for _ in range(10):
            if service.readiness._futures:
                break
            await asyncio.sleep(.005)
        assert service.readiness._futures
        value = await completed(task)
        if name == 'portal/logout':
            assert value.status_code == 200 and b'"signed_out":true' in value.body
        elif name == 'events/unsubscribe':
            assert value == {'resultType':'complete'}
        else:
            assert not value.is_error
        return value
    try:
        asyncio.run(exercise())
    finally:
        timer.join()
        lock.close()
    assert service.gateway.sent == []
    if name == 'portal/logout':
        with service.store.db() as db:
            assert db.execute('SELECT count(*) FROM link_sessions').fetchone()[0] == 0


def test_cancelled_request_keeps_database_work_owned_until_drained(mcp_app):
    service = mcp_app['service']
    lock = sqlite3.connect(service.settings.database, check_same_thread=False)
    lock.execute('BEGIN IMMEDIATE')
    started = threading.Event()
    enqueue = service.media.enqueue
    def observed(*args, **kwargs):
        started.set()
        return enqueue(*args, **kwargs)
    service.media.enqueue = observed
    async def exercise():
        task = asyncio.create_task(mcp_app['on_call_tool'](None, types.CallToolRequestParams(
            name='prepare_file', arguments=request('prepare_file'))))
        async with asyncio.timeout(3):
            while not started.is_set():
                await asyncio.sleep(.005)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert service.readiness._futures
        closed = []
        service.readiness.close_when_drained(lambda: closed.append(True))
        assert not closed
        with pytest.raises(RuntimeError, match='stopping'):
            await service.run_sync(lambda: pytest.fail('No new work after shutdown'))
        lock.rollback()
        async with asyncio.timeout(3):
            while not closed:
                await asyncio.sleep(.005)
        assert closed == [True]
    try:
        asyncio.run(exercise())
    finally:
        lock.rollback()
        lock.close()
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM media_jobs').fetchone()[0] == 1
    assert service.gateway.sent == []


def test_history_idempotency_survives_thread_dispatch(mcp_app):
    async def exercise():
        params = types.CallToolRequestParams(name='start_history_sync', arguments=request('start_history_sync'))
        calls = [asyncio.create_task(mcp_app['on_call_tool'](None, params)) for _ in range(2)]
        values = [await completed(task) for task in calls]
        assert all(not value.is_error for value in values)
        assert values[0].structured_content['id'] == values[1].structured_content['id']
    asyncio.run(exercise())
    with mcp_app['service'].store.db() as db:
        assert db.execute('SELECT count(*) FROM history_jobs').fetchone()[0] == 1
