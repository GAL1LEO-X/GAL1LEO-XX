"""Synthetic release startup must prepare legacy ClearChat state before admission."""
import asyncio
from contextlib import closing
import hmac
import importlib.util
import json
from pathlib import Path
import sqlite3
import threading
import time

import pytest
from starlette.testclient import TestClient

from conftest import message
from sally_whatsapp import visibility
from sally_whatsapp.store import Store, REVOCATION_REPAIR_KEY, OPERATION_RESULT_REPAIR_KEY, canonical
from test_revocation_activation import app_with_portal


PLUGIN = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('synthetic_clear_release_runtime', PLUGIN / 'scripts/release_runtime.py')
release_runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_runtime)
Maintenance = release_runtime.Maintenance
CHAT = '15550001111@c.us'
IDENTIFIER = 'false_' + CHAT + '_SYNTHETIC'
WORKERS = {'events': 'worker', 'transfers': 'transfer_worker', 'history': 'history_worker',
           'actions': 'action_worker', 'portal': 'maintenance'}


def seed_legacy(path):
    store = Store(path, migrate_schema=False)
    now = int(time.time())
    with store.db() as db:
        for key in (REVOCATION_REPAIR_KEY, OPERATION_RESULT_REPAIR_KEY):
            store._state(db, key, True)
        db.execute('DELETE FROM state WHERE key=?', (visibility.CLEAR_REPAIR,))
        db.execute("INSERT INTO messages(id,chat_id,timestamp,from_me,body,deleted,source,observed_at) VALUES(?,?,?,0,?,0,'webhook',?)",
                   (IDENTIFIER, CHAT, now - 20, 'synthetic legacy retained content', now))
        db.execute('INSERT INTO message_search(id,body) VALUES(?,?)', (IDENTIFIER, 'synthetic legacy retained content'))
        # Historical 0.4.7 payload: its lost range and absent anchors cannot be
        # reconstructed. Serving needs a boundary_unknown warning on this row.
        data = {'chatId': CHAT, 'reason': 'chat_cleared', 'eventAt': now - 10,
                'coverage': 'unresolved', 'excludedReferences': 0, 'fromFullSync': False}
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,?)',
                   ('synthetic-legacy-clear', 'chat.cleared', CHAT, now - 10, canonical(data), ''))


def snapshot(path):
    with closing(sqlite3.connect(path)) as db:
        return tuple(db.iterdump())


def prepared(store):
    with store.db() as db:
        row = db.execute('SELECT value FROM state WHERE key=?', (visibility.CLEAR_REPAIR,)).fetchone()
        assert row and json.loads(row[0]) is True
    result = store.search(chat_id=CHAT)
    assert result['clear_chat_coverage']['boundary_unknown'] is True
    assert len(result['messages']) == 1
    assert result['messages'][0]['id'] == IDENTIFIER
    assert result['messages'][0]['current_state'] == visibility.CLEAR_UNCERTAIN
    assert result['messages'][0]['clear_chat_coverage']['boundary_unknown'] is True


def install_workers(app, monkeypatch):
    entered = []
    for name, method in WORKERS.items():
        obj = app.state.link_portal if name == 'portal' else app.state.service
        async def worker(name=name):
            prepared(app.state.service.store)
            entered.append(name)
            await asyncio.Event().wait()
        monkeypatch.setattr(obj, method, worker)
    return entered


def actual_clear_repair(store):
    # The fallback lets baseline tests bind the future callback without
    # altering old production code: old readiness never calls it and fails.
    if hasattr(store, '_repair_clear_coverage'):
        return store._repair_clear_coverage
    def repair():
        with store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            visibility.repair_clear_coverage(db, store._canonical_chat)
    return repair


def wait_state(client, state):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        response = client.get('/healthz')
        assert response.status_code == 200
        value = response.json()['readiness']
        if value['state'] == state:
            return value
        threading.Event().wait(.005)
    pytest.fail('Readiness did not reach ' + state)


def closed(client, service):
    for path in ('/mcp', '/files/synthetic-grant', '/connect/api/status'):
        response = client.get(path)
        assert response.status_code == 503
    envelope = message('synthetic-not-admitted', CHAT)
    raw = json.dumps(envelope).encode()
    response = client.post('/webhooks/waha', content=raw,
        headers={'x-webhook-hmac-algorithm': 'sha512',
                 'x-webhook-hmac': hmac.digest(service.webhook_key, raw, 'sha512').hex()})
    assert response.status_code == 503
    assert service.store.message('synthetic-not-admitted') is None


@pytest.mark.parametrize('start_workers', [False, True])
def test_maintenance_gate_never_repairs_or_mutates_before_activation(environment, monkeypatch, start_workers):
    path = environment[0].database
    seed_legacy(path)
    before = snapshot(path)
    activation = asyncio.Event()
    gate = path.parent / 'synthetic-maintenance-gate'
    gate.touch()
    app = app_with_portal(environment, activation, start_worker=start_workers)
    entered = install_workers(app, monkeypatch)
    calls = []
    monkeypatch.setattr(app.state.service.store, '_repair_clear_coverage', lambda: calls.append(True), raising=False)
    with TestClient(Maintenance(app, activation, gate)) as client:
        assert not client.get('/healthz').json()['readiness']['ready']
        closed(client, app.state.service)
        assert calls == [] and entered == []
        assert snapshot(path) == before
    assert snapshot(path) == before


def test_delayed_clear_preparation_blocks_all_admission_and_precedes_every_worker(environment, monkeypatch):
    path = environment[0].database
    seed_legacy(path)
    before = snapshot(path)
    activation = asyncio.Event()
    gate = path.parent / 'synthetic-maintenance-gate'
    gate.touch()
    app = app_with_portal(environment, activation)
    service = app.state.service
    entered = install_workers(app, monkeypatch)
    repair_entered, release = threading.Event(), threading.Event()
    original = actual_clear_repair(service.store)
    calls = []
    def delayed():
        calls.append(threading.get_ident())
        repair_entered.set()
        assert release.wait(3), 'Synthetic preparation must be released'
        original()
    monkeypatch.setattr(service.store, '_repair_clear_coverage', delayed, raising=False)
    try:
        with TestClient(Maintenance(app, activation, gate)) as client:
            wait_state(client, 'waiting')
            assert snapshot(path) == before and not calls and not entered
            gate.unlink()
            assert repair_entered.wait(3), 'ClearChat preparation callback was not called'
            assert wait_state(client, 'preparing')['workers'] == dict.fromkeys(WORKERS, False)
            closed(client, service)
            assert snapshot(path) == before and not entered
            release.set()
            ready = wait_state(client, 'ready')
            assert ready['workers'] == dict.fromkeys(WORKERS, True)
            assert set(entered) == set(WORKERS) and len(calls) == 1
            prepared(service.store)
            assert client.get('/mcp').status_code == 401
    finally:
        release.set()


def test_clear_preparation_failure_rolls_back_and_requires_clean_restart(environment, monkeypatch, caplog):
    path = environment[0].database
    seed_legacy(path)
    before = snapshot(path)
    activation = asyncio.Event()
    app = app_with_portal(environment, activation)
    entered = install_workers(app, monkeypatch)
    apply = visibility.apply
    calls = []
    def broken(*args, **kwargs):
        calls.append(True)
        apply(*args, **kwargs)
        raise RuntimeError('synthetic private clear preparation diagnostic')
    with monkeypatch.context() as patch:
        patch.setattr(visibility, 'apply', broken)
        with TestClient(app) as client:
            client.portal.call(activation.set)
            failed = wait_state(client, 'failed')
            assert failed['ready'] is False and failed['workers'] == dict.fromkeys(WORKERS, False)
            assert failed['error_code'] == 'REVOCATION_REPAIR_FAILED'
            closed(client, app.state.service)
            assert calls == [True] and entered == [] and snapshot(path) == before
            client.portal.call(activation.clear)
            client.portal.call(activation.set)
            closed(client, app.state.service)
            assert calls == [True] and snapshot(path) == before
    assert 'synthetic private clear preparation diagnostic' not in caplog.text
    restarted = app_with_portal(environment, None)
    seen = install_workers(restarted, monkeypatch)
    with TestClient(restarted) as client:
        assert wait_state(client, 'ready')['ready']
        assert set(seen) == set(WORKERS)
        prepared(restarted.state.service.store)
    successful = snapshot(path)
    # A later process rechecks the marker transactionally but creates no new
    # observations or warning records and never rebuilds a missing range.
    again = app_with_portal(environment, None)
    seen_again = install_workers(again, monkeypatch)
    with TestClient(again) as client:
        assert wait_state(client, 'ready')['ready']
        assert set(seen_again) == set(WORKERS)
        prepared(again.state.service.store)
        assert snapshot(path) == successful


def test_transient_clear_preparation_retries_one_rolled_back_transaction(environment, monkeypatch):
    path = environment[0].database
    seed_legacy(path)
    app = app_with_portal(environment, None)
    entered = install_workers(app, monkeypatch)
    apply = visibility.apply
    calls = []
    def busy_once(*args, **kwargs):
        calls.append(True)
        apply(*args, **kwargs)
        if len(calls) == 1:
            error = sqlite3.OperationalError('synthetic competing writer')
            error.sqlite_errorcode = sqlite3.SQLITE_BUSY
            raise error
    monkeypatch.setattr(visibility, 'apply', busy_once)
    with TestClient(app) as client:
        assert wait_state(client, 'ready')['ready']
        assert calls == [True, True] and set(entered) == set(WORKERS)
        prepared(app.state.service.store)
        with app.state.service.store.db() as db:
            assert len(visibility.records(db)) == 1
