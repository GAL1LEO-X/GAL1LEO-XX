"""Release activation repairs legacy derivatives before any background worker."""
import asyncio
from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import threading
import time

import httpx
import pytest

from sally_whatsapp.server import create_app
from sally_whatsapp.store import Store, REVOCATION_REPAIR_KEY, canonical


PLUGIN = Path(__file__).resolve().parents[1]
ORIGINAL = 'synthetic-activation-original'
REACTION = 'synthetic-activation-reaction'
EVENT = 'change_' + 'a' * 64
MEDIA = 'media_' + 'b' * 32
WORKERS = ('worker', 'transfer_worker', 'history_worker', 'action_worker')


def seed_archive(path, version=7):
    if version == 7:
        Store(path, migrate_schema=False)
    with closing(sqlite3.connect(path)) as db:
        if version == 6:
            db.executescript((Path(__file__).parent / 'fixtures/schema6.sql').read_text())
        db.execute("INSERT INTO messages(id,chat_id,timestamp,from_me,body,deleted,source,observed_at) VALUES(?,?,?,0,'',1,'webhook',?)",
                   (ORIGINAL, '12345@c.us', int(time.time()), time.time()))
        db.execute("INSERT INTO message_mutations VALUES(?,'revoked',NULL,?)", (ORIGINAL, time.time()))
        payload = {'id': REACTION, 'reaction': {'messageId': ORIGINAL, 'text': 'synthetic reaction'}}
        db.execute('INSERT INTO account_events(id,event_type,chat_id,timestamp,data) VALUES(?,?,?,?,?)',
                   (EVENT, 'message.reaction', '12345@c.us', time.time(), canonical(payload)))
        db.execute("""INSERT INTO media_jobs(id,owner,identity,state,source,filename,mimetype,size,sha256,created,expires,error)
                      VALUES(?,?,?,'ready',X'','synthetic-private.pdf','application/pdf',31,?,?,?,NULL)""",
                   (MEDIA, 'test-owner', 'synthetic-activation-media', 'synthetic-digest', time.time(), time.time()+3600))
        if version == 7:
            db.execute('UPDATE account_events SET source_message_id=? WHERE id=?', (REACTION, EVENT))
            db.execute('UPDATE media_jobs SET source_message_id=? WHERE id=?', (ORIGINAL, MEDIA))
        db.commit()


def snapshot(path):
    with closing(sqlite3.connect(path)) as db:
        return tuple(db.iterdump())


def assert_repaired(path):
    with closing(sqlite3.connect(path)) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
        assert json.loads(db.execute('SELECT value FROM state WHERE key=?', (REVOCATION_REPAIR_KEY,)).fetchone()[0]) is True
        source, data = db.execute('SELECT source_message_id,data FROM account_events WHERE id=?', (EVENT,)).fetchone()
        assert source == ORIGINAL
        assert json.loads(data) == {'message_id': ORIGINAL, 'revoked': True}
        assert db.execute('SELECT state,source,filename,mimetype,size,sha256 FROM media_jobs WHERE id=?', (MEDIA,)).fetchone() == (
            'cancelled', b'', '', '', None, None)


def app_with_portal(environment, gate, *, start_worker=True):
    settings, receiver, gateway, _ = environment
    settings = replace(settings, live_account_enabled=True, link_enabled=True,
                       link_client_id='synthetic-link-client', link_authorize_url='https://issuer.example/authorize',
                       link_token_url='https://issuer.example/token')
    oauth = httpx.Client(transport=httpx.MockTransport(lambda request: pytest.fail('No network request expected')))
    return create_app(settings, gateway=gateway, event_transport=receiver, start_worker=start_worker,
                      recover_inflight=False, activation_event=gate, link_oauth_client=oauth)


def replace_workers(app, monkeypatch, seen, started=None):
    for obj, name in [(app.state.service, name) for name in WORKERS] + [(app.state.link_portal, 'maintenance')]:
        async def worker(name=name):
            assert_repaired(app.state.service.settings.database)
            seen.append(name)
            if started is not None and len(seen) == 5:
                started.set()
            await asyncio.Event().wait()
        monkeypatch.setattr(obj, name, worker)


@pytest.mark.parametrize('version', [7, 6], ids=['legacy-schema7', 'declared-schema6-upgrade'])
def test_activation_repairs_once_before_all_workers_and_portal(environment, monkeypatch, version):
    path = environment[0].database
    seed_archive(path, version)
    if version == 6:
        monkeypatch.syspath_prepend(str(PLUGIN / 'scripts'))
        from release_database import migrate
        assert migrate(path, PLUGIN)['toSchema'] == 8
    before = snapshot(path)

    async def exercise():
        baseline = asyncio.all_tasks()
        gate, started = asyncio.Event(), asyncio.Event()
        app = app_with_portal(environment, gate)
        seen, calls = [], []
        replace_workers(app, monkeypatch, seen, started)
        original = app.state.service.store._repair_revocation_derivatives
        main_thread = threading.get_ident()
        def repair():
            calls.append(threading.get_ident())
            original()
        monkeypatch.setattr(app.state.service.store, '_repair_revocation_derivatives', repair)
        async with app.router.lifespan_context(app):
            await asyncio.sleep(0)
            assert calls == [] and seen == []
            assert snapshot(path) == before
            gate.set()
            await asyncio.wait_for(started.wait(), 3)
            assert len(calls) == 1 and calls[0] != main_thread
            assert set(seen) == {*WORKERS, 'maintenance'}
            assert_repaired(path)
        await asyncio.sleep(0)
        assert asyncio.all_tasks() <= baseline
    asyncio.run(exercise())


def test_repair_failure_blocks_every_worker_and_logs_no_exception_details(environment, monkeypatch, caplog):
    path = environment[0].database
    seed_archive(path)
    before = snapshot(path)

    async def exercise():
        from sally_whatsapp.server import log
        baseline = asyncio.all_tasks()
        gate, failed = asyncio.Event(), asyncio.Event()
        app = app_with_portal(environment, gate)
        seen, calls = [], []
        replace_workers(app, monkeypatch, seen)
        def repair():
            calls.append(True)
            raise RuntimeError('synthetic private exception detail')
        monkeypatch.setattr(app.state.service.store, '_repair_revocation_derivatives', repair)
        original = log.error
        def error(message):
            original(message)
            failed.set()
        monkeypatch.setattr(log, 'error', error)
        async with app.router.lifespan_context(app):
            gate.set()
            await asyncio.wait_for(failed.wait(), 3)
            await asyncio.sleep(0)
            assert calls == [True] and seen == []
            assert snapshot(path) == before
        await asyncio.sleep(0)
        assert asyncio.all_tasks() <= baseline
    asyncio.run(exercise())
    assert caplog.text.count('Revocation repair failed; background workers remain stopped') == 1
    assert 'synthetic private exception detail' not in caplog.text


@pytest.mark.parametrize(('start_worker', 'gate_open'), [(True, False), (False, False), (False, True)],
                         ids=['shutdown-with-gate-closed', 'check-gate-closed', 'check-gate-open'])
def test_closed_gate_and_checks_never_start_repair(environment, monkeypatch, start_worker, gate_open):
    path = environment[0].database
    seed_archive(path)
    before = snapshot(path)

    async def exercise():
        baseline = asyncio.all_tasks()
        gate = asyncio.Event()
        if gate_open:
            gate.set()
        app = app_with_portal(environment, gate, start_worker=start_worker)
        seen, calls = [], []
        replace_workers(app, monkeypatch, seen)
        monkeypatch.setattr(app.state.service.store, '_repair_revocation_derivatives', lambda: calls.append(True))
        async with app.router.lifespan_context(app):
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            assert calls == [] and seen == []
            assert snapshot(path) == before
        await asyncio.sleep(0)
        assert calls == [] and seen == []
        assert snapshot(path) == before
        assert asyncio.all_tasks() <= baseline
    asyncio.run(exercise())


def test_shutdown_waits_for_running_repair_and_does_not_start_workers(environment, monkeypatch):
    path = environment[0].database
    seed_archive(path)

    async def exercise():
        baseline = asyncio.all_tasks()
        gate, entered, shutdown = asyncio.Event(), asyncio.Event(), asyncio.Event()
        release = threading.Event()
        loop = asyncio.get_running_loop()
        app = app_with_portal(environment, gate)
        seen, finished = [], []
        replace_workers(app, monkeypatch, seen)
        original = app.state.service.store._repair_revocation_derivatives
        def repair():
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(3), 'Test must release synthetic repair'
            original()
            finished.append(True)
        monkeypatch.setattr(app.state.service.store, '_repair_revocation_derivatives', repair)
        async def serve():
            async with app.router.lifespan_context(app):
                gate.set()
                await shutdown.wait()
        task = asyncio.create_task(serve())
        try:
            await asyncio.wait_for(entered.wait(), 3)
            shutdown.set()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            assert not task.done() and finished == [] and seen == []
            assert app.state.readiness.snapshot()['state'] == 'stopping'
            assert not app.state.readiness.snapshot()['ready']
        finally:
            release.set()
            await asyncio.wait_for(task, 3)
        assert finished == [True] and seen == []
        assert_repaired(path)
        assert asyncio.all_tasks() <= baseline
    asyncio.run(exercise())
