"""Thread ownership during shutdown, using only synthetic Event barriers."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import threading

import pytest

from sally_whatsapp import readiness as readiness_module
from sally_whatsapp.server import SendText, create_app
from sally_whatsapp.store import Store
from test_revocation_activation import app_with_portal


TARGETS = ('actions', 'transfers', 'history', 'events', 'poll', 'portal')


def block_worker(app, monkeypatch, target, blocked):
    service = app.state.service
    obj, method = {
        'actions': (service, 'process_action'),
        'transfers': (service.media, 'process_one'),
        'history': (service.history, 'process_one'),
        'events': (service.events, 'dispatch_one'),
        'poll': (service, 'poll_connection'),
        'portal': (app.state.link_portal, 'cleanup'),
    }[target]
    monkeypatch.setattr(obj, method, blocked)


@pytest.mark.parametrize('target', TARGETS)
def test_shutdown_drains_each_worker_before_closing_resources(environment, monkeypatch, target):
    # All worker families use the same lifecycle; run them independently so a
    # blocked callback/poll cannot accidentally conceal a missing action drain.
    async def exercise():
        Store(environment[0].database, migrate_schema=False)  # Explicit synthetic installation.
        app = app_with_portal(environment, None)
        loop = asyncio.get_running_loop()
        entered, shutdown = asyncio.Event(), asyncio.Event()
        release = threading.Event()
        finished, closed, calls = [], [], []
        def blocked():
            calls.append(target)
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(3)
            assert not closed
            finished.append(target)
            return False
        block_worker(app, monkeypatch, target, blocked)
        monkeypatch.setattr(app.state.service.gateway, 'close', lambda: closed.append('gateway'))
        monkeypatch.setattr(app.state.link_portal, 'close', lambda: closed.append('portal'))
        monkeypatch.setattr(app.state.service.diagnostics, 'close', lambda: closed.append('diagnostics'))
        async def serve():
            async with app.router.lifespan_context(app):
                await shutdown.wait()
        task = asyncio.create_task(serve())
        try:
            await asyncio.wait_for(entered.wait(), 3)
            shutdown.set()
            # Yield enough for cancellation and a broken unshielded stop
            # to finish. The thread barrier remains closed throughout.
            for _ in range(20):
                await asyncio.sleep(0)
            assert not task.done(), target
            assert not finished and not closed, target
        finally:
            release.set()
            await asyncio.wait_for(task, 3)
        assert finished == [target] and closed == ['gateway', 'portal', 'diagnostics']
        assert calls == [target]  # Cancellation cannot claim a second job.
    asyncio.run(exercise())


@pytest.mark.parametrize('queued', [False, True], ids=['direct-send', 'queued-action'])
def test_shutdown_timeout_retains_resources_after_loop_exit_and_never_retries(environment, monkeypatch, queued):
    settings, receiver, gateway, _ = environment
    settings = replace(settings, live_account_enabled=True, send_enabled=True,
                       send_chat_ids=['synthetic@c.us'])
    monkeypatch.setattr(readiness_module, 'SHUTDOWN_GRACE_SECONDS', .02)
    app = create_app(settings, gateway=gateway, event_transport=receiver)
    service = app.state.service
    key = 'synthetic_shutdown_key'
    args = SendText(chat_id='synthetic@c.us', text='Synthetic shutdown message', idempotency_key=key)
    action_arguments = {'path': {}, 'query': {}, 'body': {'chatId': args.chat_id, 'text': args.text}}
    if queued:
        service.store.queue_action(key, settings.owner_subject, 'messages_send_text', action_arguments)
    release, closed = threading.Event(), threading.Event()
    sent, finished = [], []
    def send(chat_id, text):
        sent.append((chat_id, text))
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(3)
        assert not closed.is_set()
        finished.append(True)
        return {'id': 'synthetic-shutdown-provider-id'}
    monkeypatch.setattr(gateway, 'send', send)
    monkeypatch.setattr(gateway, 'request', lambda *a, **kw: send(args.chat_id, args.text), raising=False)
    monkeypatch.setattr(gateway, 'close', closed.set)
    async def exercise():
        nonlocal loop, entered
        loop = asyncio.get_running_loop()
        entered = asyncio.Event()
        async with app.router.lifespan_context(app):
            request = None
            if not queued:
                request = asyncio.create_task(service.run_sync(service.send, args, settings.owner_subject))
            await asyncio.wait_for(entered.wait(), 3)
            if request is not None:
                request.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await request
        assert not finished and not closed.is_set()
        assert service.store.send_status(key)['state'] == 'sending'
        with pytest.raises(RuntimeError, match='stopping'):
            await service.run_sync(lambda: pytest.fail('No new claims after shutdown'))
    loop, entered = None, None
    try:
        # Completing lifespan and closing its event loop must be bounded while
        # the real send remains blocked. Cleanup cannot depend on that loop.
        asyncio.run(asyncio.wait_for(exercise(), 1))
        assert not closed.is_set()
    finally:
        release.set()
        assert closed.wait(3)
    assert finished == [True]
    status = service.store.send_status(key)
    assert status['state'] == 'uncertain'
    assert status['provider_id'] == 'synthetic-shutdown-provider-id'
    if queued:
        assert service.store.queue_action(key, settings.owner_subject, 'messages_send_text', action_arguments)['state'] == 'uncertain'
        assert service.process_action() is False
    else:
        assert service.send(args, settings.owner_subject)['state'] == 'uncertain'
    assert sent == [(args.chat_id, args.text)]


def test_failed_worker_keeps_cancelled_sibling_thread_owned(environment, monkeypatch):
    async def exercise():
        settings, receiver, gateway, _ = environment
        app = create_app(settings, gateway=gateway, event_transport=receiver)
        service, runtime = app.state.service, app.state.readiness
        loop = asyncio.get_running_loop()
        entered, fail = asyncio.Event(), asyncio.Event()
        release = threading.Event()
        finished, closed = [], []
        def blocked():
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(3)
            assert not closed
            finished.append(True)
        monkeypatch.setattr(service, 'process_action', blocked)
        monkeypatch.setattr(gateway, 'close', lambda: closed.append(True))
        async def broken():
            await fail.wait()
            raise RuntimeError('Synthetic worker failure')
        monkeypatch.setattr(service, 'transfer_worker', broken)
        async def serve():
            async with app.router.lifespan_context(app):
                await entered.wait()
                fail.set()
                for _ in range(20):
                    await asyncio.sleep(0)
                assert runtime.state == 'failed'
                with pytest.raises(RuntimeError, match='stopping'):
                    await service.run_sync(lambda: pytest.fail('No claims after failure'))
        task = asyncio.create_task(serve())
        try:
            await asyncio.wait_for(entered.wait(), 3)
            for _ in range(30):
                await asyncio.sleep(0)
            assert not task.done() and not closed
        finally:
            release.set()
            await asyncio.wait_for(task, 3)
        assert finished == [True] and closed == [True]
    asyncio.run(exercise())


def test_executor_queued_units_cannot_claim_after_stop(monkeypatch):
    async def exercise():
        runtime = readiness_module.RuntimeReadiness(enabled=False, worker_names=[])
        runtime._executor = ThreadPoolExecutor(max_workers=1)
        loop = asyncio.get_running_loop()
        entered, released = asyncio.Event(), threading.Event()
        claims, closed = [], []
        def first():
            loop.call_soon_threadsafe(entered.set)
            assert released.wait(3)
        running = asyncio.create_task(runtime.run_sync(first))
        await asyncio.wait_for(entered.wait(), 3)
        queued = asyncio.create_task(runtime.run_sync(lambda: claims.append(True)))
        await asyncio.sleep(0)  # The second unit is now queued in the executor.
        stopping = asyncio.create_task(runtime.stop())
        await asyncio.sleep(0)
        try:
            assert runtime._stopping
            with pytest.raises(RuntimeError, match='replaced'):
                runtime.enabled = True
                runtime.start(lambda: None, {})
        finally:
            released.set()
            await asyncio.wait_for(running, 3)
            assert await asyncio.wait_for(stopping, 3)
            runtime.close_when_drained(lambda: closed.append(True))
        with pytest.raises(RuntimeError, match='stopping'):
            await queued
        assert not claims and closed == [True]
    asyncio.run(exercise())


def test_completed_worker_does_not_wait_for_its_bookkeeping_callback(monkeypatch):
    """Future completion precedes callbacks, which may be descheduled."""
    async def exercise():
        runtime = readiness_module.RuntimeReadiness(enabled=False, worker_names=[])
        loop = asyncio.get_running_loop()
        entered, callback_entered = asyncio.Event(), asyncio.Event()
        release_work, release_callback = threading.Event(), threading.Event()
        closed = []
        original = runtime._thread_finished

        def delayed_callback(future):
            loop.call_soon_threadsafe(callback_entered.set)
            assert release_callback.wait(3)
            original(future)

        def work():
            loop.call_soon_threadsafe(entered.set)
            assert release_work.wait(3)

        monkeypatch.setattr(runtime, '_thread_finished', delayed_callback)
        task = asyncio.create_task(runtime.run_sync(work))
        try:
            await asyncio.wait_for(entered.wait(), 3)
            release_work.set()
            await asyncio.wait_for(callback_entered.wait(), 3)
            # The original awaiter is behind the blocked callback. stop wraps
            # the already completed concurrent Future independently.
            assert not task.done()
            assert await asyncio.wait_for(runtime.stop(), 1)
            assert not runtime.shutdown_timed_out.is_set()
            runtime.close_when_drained(lambda: closed.append(True))
            assert closed == [True]
        finally:
            release_work.set()
            release_callback.set()
            await asyncio.wait_for(task, 3)
        assert closed == [True]

    asyncio.run(exercise())
