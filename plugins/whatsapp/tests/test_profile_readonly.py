"""Profile preparation versus read-only MCP, using synthetic SQLite and ASGI."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from dataclasses import replace
import hashlib
import json
import os
import socket
import sqlite3
import threading

import pytest
from starlette.testclient import TestClient

from conftest import FakeGateway, Receiver, call
from sally_whatsapp.server import Service, create_app
from sally_whatsapp.state_continuity import StateContinuityError
from sally_whatsapp.store import SCHEMA_7, Store


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Profile tests must not contact a real service')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)


def profile_key(owner):
    return 'profile_id:' + hashlib.sha256(owner.encode()).hexdigest()


def stored_identity(store, owner):
    with store.db() as db:
        row = db.execute('SELECT value FROM state WHERE key=?', (profile_key(owner),)).fetchone()
        return None if row is None else row[0]


def state_rows(store):
    with store.db() as db:
        return list(db.execute('SELECT key,value FROM state ORDER BY key'))


def readonly_connections(store, monkeypatch):
    """Keep real SQLite; query_only rejects writes even if output looks right."""
    original = store.db
    statements = []

    @contextmanager
    def readonly():
        with original() as db:
            db.execute('PRAGMA query_only=ON')
            before = db.total_changes
            db.set_trace_callback(statements.append)
            try:
                yield db
            finally:
                db.set_trace_callback(None)
                assert db.total_changes == before
    monkeypatch.setattr(store, 'db', readonly)
    return statements


def test_first_mcp_profile_reads_prepared_identity_without_sql_writes(environment, app_client, monkeypatch):
    app, client = app_client
    store, owner = app.state.service.store, environment[0].owner_subject
    prepared = stored_identity(store, owner)
    assert isinstance(json.loads(prepared), str) and json.loads(prepared).strip()
    before = state_rows(store)
    statements = readonly_connections(store, monkeypatch)
    client.headers['Authorization'] = 'Bearer ' + environment[3](scope='whatsapp:read')
    first = call(client, 'get_profile')['result']
    assert not first.get('isError', False)
    assert first['structuredContent']['id'] == json.loads(prepared)
    assert call(client, 'get_profile')['result']['structuredContent'] == first['structuredContent']
    assert statements and all(sql.lstrip().upper().startswith('SELECT ') for sql in statements)
    assert state_rows(store) == before
    assert environment[1].requests == [] and environment[2].sent == []


INVALID_IDENTITIES = ['not-json', 'null', 'false', '123', '{}', '[]', '""', '"   "']


@pytest.mark.parametrize('raw', [None, *INVALID_IDENTITIES],
                         ids=['missing', 'malformed-json', 'null', 'bool', 'number', 'object', 'array', 'empty', 'whitespace'])
def test_profile_missing_or_invalid_is_controlled_error_without_regeneration(environment, app_client, monkeypatch, raw):
    app, client = app_client
    store, owner = app.state.service.store, environment[0].owner_subject
    with store.db() as db:
        if raw is None:
            db.execute('DELETE FROM state WHERE key=?', (profile_key(owner),))
        else:
            db.execute('UPDATE state SET value=? WHERE key=?', (raw, profile_key(owner)))
    before = state_rows(store)
    statements = readonly_connections(store, monkeypatch)
    for _ in range(2):
        result = call(client, 'get_profile')['result']
        assert result['isError'] is True
        expected = 'Connection profile is not initialized' if raw is None else 'Connection profile identity is invalid'
        assert result['content'] == [{'type': 'text', 'text': expected}]
        assert result.get('structuredContent') is None
    assert statements and all(sql.lstrip().upper().startswith('SELECT ') for sql in statements)
    assert state_rows(store) == before
    assert stored_identity(store, owner) == raw


@pytest.mark.parametrize('raw', INVALID_IDENTITIES)
def test_preparation_never_replaces_invalid_existing_identity(tmp_path, raw):
    store, owner = Store(tmp_path / 'invalid.sqlite'), 'synthetic-owner'
    with store.db() as db:
        db.execute('INSERT INTO state(key,value) VALUES(?,?)', (profile_key(owner), raw))
    with pytest.raises(ValueError, match='identity is invalid'):
        store.prepare_profile(owner)
    assert stored_identity(store, owner) == raw


def test_schema7_upgrade_and_restart_preserve_existing_profile_bytes(environment):
    settings, receiver, gateway, _ = environment
    legacy = 'legacy-opaque-profile-id'
    raw = '  ' + json.dumps(legacy) + '  '
    with closing(sqlite3.connect(settings.database)) as db:
        db.executescript(SCHEMA_7)
        db.execute('INSERT INTO state(key,value) VALUES(?,?)', (profile_key(settings.owner_subject), raw))
        db.commit()
    for _ in range(2):
        app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
        with TestClient(app):
            store = app.state.service.store
            assert stored_identity(store, settings.owner_subject) == raw
            assert store.profile(settings.owner_subject)['id'] == legacy
            with store.db() as db:
                assert db.execute('PRAGMA user_version').fetchone()[0] == 8
    assert receiver.requests == [] and gateway.sent == []


def test_concurrent_preparation_for_same_owner_converges_without_overwrite(tmp_path):
    store, owner = Store(tmp_path / 'concurrent.sqlite'), 'synthetic-owner'
    barrier = threading.Barrier(8)

    def prepare(_):
        barrier.wait(timeout=5)
        store.prepare_profile(owner)
        return store.profile(owner)['id']

    with ThreadPoolExecutor(max_workers=8) as executor:
        values = list(executor.map(prepare, range(8)))
    assert len(set(values)) == 1
    assert json.loads(stored_identity(store, owner)) == values[0]
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM state WHERE key LIKE 'profile_id:%'").fetchone()[0] == 1


def test_separate_tenants_prepare_distinct_ids_and_reads_do_not_create_other_owner(environment, tmp_path):
    settings = environment[0]
    ids = []
    for owner in ('synthetic-personal', 'synthetic-work'):
        tenant = replace(settings, owner_subject=owner, database=tmp_path / owner / 'state.sqlite')
        app = create_app(tenant, gateway=FakeGateway(), event_transport=Receiver(), start_worker=False)
        with TestClient(app):
            store = app.state.service.store
            ids.append(store.profile(owner)['id'])
            with pytest.raises(ValueError, match='not initialized'):
                store.profile('unprepared-owner')
            assert stored_identity(store, 'unprepared-owner') is None
    assert ids[0] != ids[1]


def test_check_construction_does_not_prepare_profile_or_enroll_identity(environment):
    settings, receiver, gateway, _ = environment
    existing = Store(settings.database)
    before = state_rows(existing)
    app = create_app(settings, gateway=gateway, event_transport=receiver,
                     start_worker=False, recover_inflight=False)
    with TestClient(app):
        assert stored_identity(app.state.service.store, settings.owner_subject) is None
        assert state_rows(existing) == before
        assert not app.state.service.continuity.marker.exists()
    assert receiver.requests == [] and gateway.sent == []


def test_activation_prepares_profile_after_gate_and_before_workers(environment, monkeypatch):
    settings, receiver, gateway, _ = environment
    existing = Store(settings.database)
    before = state_rows(existing)

    async def exercise():
        baseline = asyncio.all_tasks()
        gate, started = asyncio.Event(), asyncio.Event()
        app = create_app(settings, gateway=gateway, event_transport=receiver,
                         recover_inflight=False, activation_event=gate)
        service = app.state.service
        seen = []
        methods = ('worker', 'transfer_worker', 'history_worker', 'action_worker')
        for name in methods:
            async def worker(name=name):
                # Observe the real preparation before each synthetic worker enters.
                seen.append((name, service.store.profile(settings.owner_subject)['id']))
                if len(seen) == len(methods):
                    started.set()
                await asyncio.Event().wait()
            monkeypatch.setattr(service, name, worker)
        async with app.router.lifespan_context(app):
            await asyncio.sleep(0)
            assert app.state.readiness.state == 'waiting' and seen == []
            assert state_rows(existing) == before
            assert stored_identity(service.store, settings.owner_subject) is None
            assert not service.continuity.marker.exists()
            gate.set()
            await asyncio.wait_for(started.wait(), timeout=3)
            assert app.state.readiness.ready
            assert {name for name, _ in seen} == set(methods)
            assert {identifier for _, identifier in seen} == {service.store.profile(settings.owner_subject)['id']}
            assert service.continuity.marker.exists()
        await asyncio.sleep(0)
        assert asyncio.all_tasks() <= baseline

    asyncio.run(exercise())
    assert receiver.requests == [] and gateway.sent == []


@pytest.mark.parametrize('damage', ['missing', 'replacement'])
def test_state_loss_blocks_profile_read_and_preparation_without_new_identity(environment, tmp_path, damage):
    settings, receiver, gateway, _ = environment
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app):
        service = app.state.service
        original_marker = service.continuity.marker.read_bytes()
        if damage == 'missing':
            settings.database.unlink()
        else:
            replacement = Store(tmp_path / 'replacement.sqlite')
            os.replace(replacement.path, settings.database)
        with pytest.raises(StateContinuityError):
            service.store.profile(settings.owner_subject)
        with pytest.raises(StateContinuityError):
            service._prepare_serving()
        with pytest.raises(StateContinuityError):
            Service(settings, gateway=gateway, event_transport=receiver)
        assert service.continuity.marker.read_bytes() == original_marker
        if damage == 'missing':
            assert not settings.database.exists()
        else:
            with closing(sqlite3.connect(settings.database)) as db:
                assert db.execute('SELECT value FROM state WHERE key=?', (profile_key(settings.owner_subject),)).fetchone() is None
    assert receiver.requests == [] and gateway.sent == []
