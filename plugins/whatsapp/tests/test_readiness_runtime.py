"""Runtime readiness and request admission with synthetic SQLite and ASGI."""
import asyncio
from contextlib import closing, contextmanager
import hmac
import json
from pathlib import Path
import sqlite3
import sys
import threading
import time

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from conftest import call, message
from sally_whatsapp import readiness as readiness_module
from sally_whatsapp.server import create_app
from sally_whatsapp.store import Store
from test_revocation_activation import app_with_portal, assert_repaired, seed_archive, snapshot

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from release_runtime import Maintenance


WORKERS = {'events': 'worker', 'transfers': 'transfer_worker', 'history': 'history_worker',
           'actions': 'action_worker', 'portal': 'maintenance'}


def install_workers(app, monkeypatch, *, target=None, outcome=None, signal=None):
    entered, stopped = [], []
    for name, method in WORKERS.items():
        obj = app.state.link_portal if name == 'portal' else app.state.service
        if obj is None:
            continue
        async def worker(name=name):
            assert_repaired(app.state.service.settings.database)
            entered.append(name)
            try:
                if name == target:
                    await signal.wait()
                    if outcome == 'error':
                        raise RuntimeError('synthetic private worker diagnostic')
                    if outcome == 'cancel':
                        asyncio.current_task().cancel()
                        await asyncio.sleep(0)
                    return
                await asyncio.Event().wait()
            finally:
                stopped.append(name)
        monkeypatch.setattr(obj, method, worker)
    return entered, stopped


def wait_state(client, expected):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        response = client.get('/healthz')
        assert response.status_code == 200
        value = response.json()['readiness']
        if value['state'] == expected:
            return value
        time.sleep(0.01)
    pytest.fail('Readiness did not reach ' + expected)


def signed_webhook(client, service, identifier):
    envelope = message(identifier)
    raw = json.dumps(envelope).encode()
    return client.post('/webhooks/waha', content=raw,
                       headers={'x-webhook-hmac-algorithm': 'sha512',
                                'x-webhook-hmac': hmac.digest(service.webhook_key, raw, 'sha512').hex()})


def assert_admission_closed(client, service, identifier):
    for path in ('/mcp', '/files/synthetic-grant', '/connect/api/status', '/connect/static/style.css'):
        response = client.get(path)
        assert response.status_code == 503 and response.json() == {'error': 'service_not_ready'}
        assert response.headers['retry-after'] == '1'
    assert client.post('/healthz').status_code == 503
    assert signed_webhook(client, service, identifier).status_code == 503
    assert service.store.message(identifier) is None
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect('/mcp'):
            pytest.fail('A non-ready runtime must not admit WebSockets')
    assert error.value.code == 1013
    for path in ('/healthz', '/.well-known/oauth-protected-resource'):
        assert client.get(path).status_code == 200
        assert client.head(path).status_code == 200


@pytest.mark.parametrize('portal', [False, True])
def test_gate_and_slow_repair_admit_requests_only_after_every_worker_enters(environment, monkeypatch, portal):
    settings, receiver, gateway, token = environment
    seed_archive(settings.database)
    gate_path = settings.database.parent / 'synthetic-gate'
    gate_path.touch()
    activation = asyncio.Event()
    app = (app_with_portal(environment, activation) if portal else
           create_app(settings, gateway=gateway, event_transport=receiver, recover_inflight=False,
                      activation_event=activation))
    service = app.state.service
    entered, stopped = install_workers(app, monkeypatch)
    repair_entered, release = threading.Event(), threading.Event()
    original = service.store._repair_revocation_derivatives
    calls = []
    def delayed_repair():
        calls.append(True)
        repair_entered.set()
        assert release.wait(3)
        original()
    monkeypatch.setattr(service.store, '_repair_revocation_derivatives', delayed_repair)
    before = snapshot(settings.database)
    try:
        with TestClient(Maintenance(app, activation, gate_path)) as client:
            waiting = wait_state(client, 'waiting')
            assert waiting['ready'] is False and not any(waiting['workers'].values())
            assert client.post('/mcp').status_code == 503  # Outer maintenance gate.
            assert not calls and not entered and snapshot(settings.database) == before
            gate_path.unlink()
            assert repair_entered.wait(3)
            preparing = wait_state(client, 'preparing')
            assert not preparing['ready'] and not any(preparing['workers'].values())
            assert_admission_closed(client, service, 'synthetic-before-ready')
            assert snapshot(settings.database) == before
            release.set()
            ready = wait_state(client, 'ready')
            expected = set(WORKERS) if portal else set(WORKERS) - {'portal'}
            assert ready == {'state': 'ready', 'ready': True, 'workers': dict.fromkeys(expected, True)}
            assert set(entered) == expected and calls == [True]
            assert client.get('/mcp').status_code == 401  # Normal auth is preserved.
            client.headers.update({'Authorization': 'Bearer ' + token(), 'Accept': 'application/json, text/event-stream',
                                   'MCP-Protocol-Version': '2026-07-28'})
            assert call(client, 'connection_status')['result']['structuredContent']['readiness'] == ready
            assert signed_webhook(client, service, 'synthetic-after-ready').status_code == 200
            assert service.store.message('synthetic-after-ready') is not None
            gate_path.touch()
            assert client.post('/mcp').status_code == 503  # Gate still overrides readiness.
    finally:
        release.set()
    assert set(stopped) == expected
    assert app.state.readiness.snapshot()['state'] == 'stopping'
    assert app.state.readiness.snapshot()['ready'] is False


def test_permanent_repair_failure_stays_closed_until_a_fresh_lifespan(environment, monkeypatch, caplog):
    settings = environment[0]
    seed_archive(settings.database)
    activation = asyncio.Event()
    app = app_with_portal(environment, activation)
    entered, _ = install_workers(app, monkeypatch)
    calls = []
    def broken():
        calls.append(True)
        raise RuntimeError('synthetic private repair diagnostic')
    monkeypatch.setattr(app.state.service.store, '_repair_revocation_derivatives', broken)
    before = snapshot(settings.database)
    with TestClient(app) as client:
        client.portal.call(activation.set)
        failed = wait_state(client, 'failed')
        assert failed == {'state': 'failed', 'ready': False, 'workers': dict.fromkeys(WORKERS, False),
                          'error_code': 'REVOCATION_REPAIR_FAILED'}
        assert_admission_closed(client, app.state.service, 'synthetic-failed-admission')
        client.portal.call(activation.clear)
        client.portal.call(activation.set)
        time.sleep(0.05)
        assert calls == [True] and not entered and snapshot(settings.database) == before
    assert 'synthetic private repair diagnostic' not in caplog.text
    assert caplog.text.count('Revocation repair failed; background workers remain stopped') == 1
    # A restart is explicit and gets a new preparation budget, after the cause
    # has been removed. It never reuses a failed worker task or old permit.
    restarted = app_with_portal(environment, None)
    seen, _ = install_workers(restarted, monkeypatch)
    with TestClient(restarted) as client:
        assert wait_state(client, 'ready')['ready']
        assert set(seen) == set(WORKERS)


@pytest.mark.parametrize('release_after_first_failure', [True, False], ids=['busy-then-ready', 'busy-budget-exhausted'])
def test_real_sqlite_busy_with_existing_marker_is_bounded(environment, monkeypatch, release_after_first_failure):
    settings = environment[0]
    seed_archive(settings.database)
    Store(settings.database)  # A previous application startup already repaired this DB.
    assert_repaired(settings.database)
    activation = asyncio.Event()
    app = app_with_portal(environment, activation)
    entered, _ = install_workers(app, monkeypatch)
    store = app.state.service.store
    original_db = store.db
    # Preserve the actual Store transaction/SQL and SQLite error code, while
    # shortening only its busy wait for a fast deterministic regression.
    @contextmanager
    def short_busy_wait():
        with original_db() as db:
            db.execute('PRAGMA busy_timeout=30')
            yield db
    monkeypatch.setattr(store, 'db', short_busy_wait)
    original = store._repair_revocation_derivatives
    calls, codes = [], []
    with closing(sqlite3.connect(settings.database, check_same_thread=False)) as locked:
        locked.execute('BEGIN IMMEDIATE')
        def repairing():
            calls.append(True)
            try:
                original()
            except sqlite3.OperationalError as error:
                codes.append(error.sqlite_errorcode)
                if release_after_first_failure:
                    locked.rollback()  # Simulated competing writer releases.
                raise
        monkeypatch.setattr(store, '_repair_revocation_derivatives', repairing)
        with TestClient(app) as client:
            client.portal.call(activation.set)
            result = wait_state(client, 'ready' if release_after_first_failure else 'failed')
            assert all(code & 0xff == sqlite3.SQLITE_BUSY for code in codes)
            if release_after_first_failure:
                assert len(calls) == 2 and len(codes) == 1
                assert result['ready'] and set(entered) == set(WORKERS)
            else:
                assert len(calls) == 3 and len(codes) == 3 and not entered
                assert result['error_code'] == 'REVOCATION_REPAIR_FAILED'
                locked.rollback()
                client.portal.call(activation.clear)
                client.portal.call(activation.set)
                assert_admission_closed(client, app.state.service, 'synthetic-after-budget')
                time.sleep(0.05)
                assert len(calls) == 3


@pytest.mark.parametrize('target', list(WORKERS))
@pytest.mark.parametrize('outcome', ['error', 'return', 'cancel'])
def test_loss_of_any_worker_closes_admission_and_stops_siblings(environment, monkeypatch, caplog, target, outcome):
    seed_archive(environment[0].database)
    app = app_with_portal(environment, None)
    signal = asyncio.Event()
    entered, stopped = install_workers(app, monkeypatch, target=target, outcome=outcome, signal=signal)
    with TestClient(app) as client:
        assert wait_state(client, 'ready')['ready'] and set(entered) == set(WORKERS)
        client.portal.call(signal.set)
        failed = wait_state(client, 'failed')
        assert not failed['ready'] and failed['error_code'] == 'BACKGROUND_WORKER_STOPPED'
        assert_admission_closed(client, app.state.service, 'synthetic-worker-failure')
        assert set(stopped) == set(WORKERS)
        assert not any(client.get('/healthz').json()['readiness']['workers'].values())
    assert 'synthetic private worker diagnostic' not in caplog.text
    assert caplog.text.count('Background worker stopped; service is not ready') == 1


def test_shutdown_during_retry_backoff_has_no_late_repair_or_workers(environment, monkeypatch):
    seed_archive(environment[0].database)
    monkeypatch.setattr(readiness_module, 'PREPARATION_BACKOFF', (10, 10))
    async def exercise():
        baseline = asyncio.all_tasks()
        app = app_with_portal(environment, None)
        entered, _ = install_workers(app, monkeypatch)
        attempted = asyncio.Event()
        loop = asyncio.get_running_loop()
        calls = []
        def blocked():
            calls.append(True)
            error = sqlite3.OperationalError('synthetic busy')
            error.sqlite_errorcode = sqlite3.SQLITE_BUSY
            loop.call_soon_threadsafe(attempted.set)
            raise error
        monkeypatch.setattr(app.state.service.store, '_repair_revocation_derivatives', blocked)
        async def serve():
            async with app.router.lifespan_context(app):
                await attempted.wait()
                await asyncio.sleep(0)
        await asyncio.wait_for(serve(), 3)
        assert calls == [True] and not entered
        assert app.state.readiness.snapshot()['state'] == 'stopping'
        assert asyncio.all_tasks() <= baseline
    asyncio.run(exercise())


def test_disabled_workers_keep_fixture_routes_and_do_not_prepare(environment, monkeypatch):
    seed_archive(environment[0].database)
    before = snapshot(environment[0].database)
    app = app_with_portal(environment, None, start_worker=False)
    monkeypatch.setattr(app.state.service.store, '_repair_revocation_derivatives', lambda: pytest.fail('No fixture repair'))
    with TestClient(app) as client:
        value = client.get('/healthz').json()['readiness']
        assert value == {'state': 'disabled', 'ready': False, 'workers': dict.fromkeys(WORKERS, False)}
        assert client.get('/mcp').status_code == 401
        assert client.get('/.well-known/oauth-protected-resource').status_code == 200
    assert snapshot(environment[0].database) == before


def test_repeated_shutdown_cancellation_joins_repair_before_propagating(environment, monkeypatch):
    seed_archive(environment[0].database)
    async def exercise():
        baseline = asyncio.all_tasks()
        app = app_with_portal(environment, None)
        service = app.state.service
        entered, _ = install_workers(app, monkeypatch)
        loop = asyncio.get_running_loop()
        repairing, shutdown = asyncio.Event(), asyncio.Event()
        release = threading.Event()
        finished, closed = [], []
        original = service.store._repair_revocation_derivatives
        def repair():
            loop.call_soon_threadsafe(repairing.set)
            assert release.wait(3)
            original()
            finished.append(True)
        monkeypatch.setattr(service.store, '_repair_revocation_derivatives', repair)
        monkeypatch.setattr(service.gateway, 'close', lambda: closed.append(True))
        async def serve():
            async with app.router.lifespan_context(app):
                await shutdown.wait()
        task = asyncio.create_task(serve())
        try:
            await asyncio.wait_for(repairing.wait(), 3)
            shutdown.set()
            await asyncio.sleep(0)
            assert app.state.readiness.snapshot()['state'] == 'stopping'
            for _ in range(3):
                task.cancel()
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                assert not task.done() and not finished and not closed
                assert app.state.readiness._repair_thread is not None
        finally:
            release.set()
            await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 3)
        assert task.cancelled() and finished == [True] and closed == [True]
        assert not entered and not app.state.readiness.snapshot()['ready']
        assert_repaired(environment[0].database)
        assert asyncio.all_tasks() <= baseline
    asyncio.run(exercise())
