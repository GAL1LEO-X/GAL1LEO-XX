"""Poll durability and serialization with real SQLite, synthetic gateways only."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import os
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import threading

import pytest

from sally_whatsapp.server import Service
from sally_whatsapp.store import CHAT_ARCHIVE_GAP_KEY, Store, utc
from sally_whatsapp.connection_observations import KEY as CONNECTION_OBSERVATION_KEY


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Poll tests must not contact real services')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)


def poll(store, status='FAILED', epoch=2000):
    return store.record_connection_poll(status, checked_epoch=epoch, checked_at=utc(epoch))


def rows(store):
    with store.db() as db:
        return [tuple(row) for row in db.execute('SELECT key,value FROM state ORDER BY key')]


def seeded(path):
    store = Store(path)
    poll(store, 'WORKING', 1000)
    store.require_recovery('chat_alias_unresolved')
    store.prepare_profile('synthetic-owner')
    return store


POLL_KEYS = ('connection', 'connection_checked_epoch', 'last_connection_check_at',
             'recovery_reasons', 'recovery_required', CONNECTION_OBSERVATION_KEY)


@pytest.mark.parametrize('failed_key', POLL_KEYS)
def test_sqlite_write_error_rolls_back_entire_poll(tmp_path, monkeypatch, failed_key):
    store = seeded(tmp_path / 'state.sqlite')
    before = rows(store)
    original = store._state

    def fail_after_write(db, key, value):
        original(db, key, value)
        if key == failed_key:
            raise sqlite3.OperationalError('Synthetic write failure')

    monkeypatch.setattr(store, '_state', fail_after_write)
    with pytest.raises(sqlite3.OperationalError, match='Synthetic write failure'):
        poll(store)
    reopened = Store(store.path, migrate_schema=False)
    assert rows(reopened) == before
    assert poll(reopened, 'WORKING', 3000) == 'WORKING'
    assert set(reopened.state()['recovery_reasons']) == {'chat_alias_unresolved'}


# Exit without Python cleanup at exact boundaries. SQLite itself rolls back or
# retains the WAL transaction; commit is never replaced with a fake result.
CRASH_CHILD = r'''
from contextlib import contextmanager
import os
from pathlib import Path
import sys
from sally_whatsapp.store import Store, utc

store = Store(Path(sys.argv[1]), migrate_schema=False)
# Freeze only the child poll's observation clock for an exact gap epoch oracle.
import sally_whatsapp.store as store_module
store_module.time.time = lambda: 2000
checkpoint = sys.argv[2]
original_state = store._state
original_db = store.db

def write(db, key, value):
    original_state(db, key, value)
    if checkpoint == 'after-first-write' and key == 'connection':
        os._exit(77)
    if checkpoint == 'after-reason-write' and key == 'recovery_required':
        os._exit(77)

@contextmanager
def boundary():
    with original_db() as db:
        yield db
        if checkpoint == 'before-commit':
            os._exit(77)
    if checkpoint == 'after-commit':
        os._exit(77)

store._state = write
store.db = boundary
store.record_connection_poll('FAILED', checked_epoch=2000, checked_at=utc(2000))
raise AssertionError('Crash checkpoint was not reached')
'''


@pytest.mark.parametrize('checkpoint', [
    'after-first-write', 'after-reason-write', 'before-commit', 'after-commit'])
@pytest.mark.parametrize('prior_gap', [None, {
    'invalidated_at': 1500, 'reason': 'event_stream_restart'}], ids=['no-prior-gap','prior-gap'])
def test_process_exit_preserves_whole_old_or_committed_poll(tmp_path, checkpoint, prior_gap):
    store = seeded(tmp_path / 'state.sqlite')
    if prior_gap is not None:
        store.set_state(CHAT_ARCHIVE_GAP_KEY, prior_gap)
    before = rows(store)
    if prior_gap is None:
        assert CHAT_ARCHIVE_GAP_KEY not in dict(before)
    else:
        assert json.loads(dict(before)[CHAT_ARCHIVE_GAP_KEY]) == prior_gap
    unrelated = store.state()['recovery_reasons']['chat_alias_unresolved']
    env = {'PYTHONPATH': str(Path(__file__).resolve().parents[1]),
           'PYTHONDONTWRITEBYTECODE': '1'}
    if os.name == 'nt' and 'SystemRoot' in os.environ:
        env['SystemRoot'] = os.environ['SystemRoot']
    child = subprocess.run([sys.executable, '-B', '-c', CRASH_CHILD, str(store.path), checkpoint],
                           env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    assert child.returncode == 77, (child.returncode, child.stdout, child.stderr)
    reopened = Store(store.path, migrate_schema=False)
    with reopened.db() as db:
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
    if checkpoint != 'after-commit':
        assert rows(reopened) == before
        if prior_gap is None:
            assert CHAT_ARCHIVE_GAP_KEY not in dict(rows(reopened))
        else:
            assert json.loads(dict(rows(reopened))[CHAT_ARCHIVE_GAP_KEY]) == prior_gap
        assert poll(reopened, 'WORKING', 3000) == 'WORKING'
        assert set(reopened.state()['recovery_reasons']) == {'chat_alias_unresolved'}
    else:
        state = reopened.state()
        assert state['connection'] == 'FAILED'
        assert state['connection_checked_epoch'] == 2000
        assert state['last_connection_check_at'] == utc(2000)
        issue = state['recovery_reasons']['connection_interrupted']
        assert issue['status'] == 'open' and state['recovery_required'] is True
        assert state['recovery_reasons']['chat_alias_unresolved'] == unrelated
        committed = dict(rows(reopened))
        gap = json.loads(committed[CHAT_ARCHIVE_GAP_KEY])
        assert gap == {'invalidated_at': 2000, 'reason': 'event_stream_gap'}
        # Only this exact additional state key belongs to the atomic poll.
        # Every unrelated row, including other private metadata, stays equal.
        expected_keys = set(dict(before)) | {CHAT_ARCHIVE_GAP_KEY}
        assert set(committed) == expected_keys
        assert json.loads(committed[CONNECTION_OBSERVATION_KEY]) == {
            'generation': 2, 'source': 'poll', 'observed_at': 2000, 'discarded_polls': 0}
        assert {key: value for key, value in committed.items()
                if key not in (*POLL_KEYS, CHAT_ARCHIVE_GAP_KEY)} == {
            key: value for key, value in before if key not in (*POLL_KEYS, CHAT_ARCHIVE_GAP_KEY)}
        assert poll(reopened, 'WORKING', 3000) == 'FAILED'
        assert reopened.state()['recovery_reasons']['connection_interrupted'] == issue
        assert json.loads(dict(rows(reopened))[CHAT_ARCHIVE_GAP_KEY]) == gap


def hold_write(monkeypatch, store, key):
    entered, release = threading.Event(), threading.Event()
    original = store._state

    def write(db, name, value):
        original(db, name, value)
        if name == key:
            entered.set()
            assert release.wait(5), 'Test did not release the SQLite writer'

    monkeypatch.setattr(store, '_state', write)
    return entered, release


def trace_begin(monkeypatch, store):
    attempted = threading.Event()
    original = store.db

    @contextmanager
    def traced():
        with original() as db:
            db.set_trace_callback(lambda sql: attempted.set() if sql == 'BEGIN IMMEDIATE' else None)
            yield db

    monkeypatch.setattr(store, 'db', traced)
    return attempted


def test_reader_snapshot_cannot_mix_poll_and_recovery_across_commit(tmp_path, monkeypatch):
    writer = seeded(tmp_path / 'state.sqlite')
    reader = Store(writer.path, migrate_schema=False)
    before = reader.state()
    entered, release = hold_write(monkeypatch, writer, 'connection')
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(poll, writer)
        try:
            assert entered.wait(5)
            # The writer has already changed connection in its transaction.
            assert reader.state() == before
            original = reader._recovery_reasons

            def reasons_across_commit(db):
                # state() has read the state rows, and retains its WAL snapshot
                # while the writer commits before the subsequent reasons query.
                release.set()
                assert future.result(timeout=5) == 'WORKING'
                return original(db)

            with monkeypatch.context() as patch:
                patch.setattr(reader, '_recovery_reasons', reasons_across_commit)
                assert reader.state() == before
        finally:
            release.set()
        future.result(timeout=5)
    after = reader.state()
    assert after['connection'] == 'FAILED'
    assert after['connection_checked_epoch'] == 2000 and after['last_connection_check_at'] == utc(2000)
    assert after['recovery_reasons']['connection_interrupted']['status'] == 'open'


def test_not_linked_reads_previous_after_concurrent_webhook_commits(tmp_path, monkeypatch):
    webhook = Store(tmp_path / 'state.sqlite')
    polling = Store(webhook.path, migrate_schema=False)
    entered, release = hold_write(monkeypatch, webhook, 'connection')
    attempted = trace_begin(monkeypatch, polling)
    event = {'id': 'synthetic-working', 'event': 'session.status', 'session': 'default',
             'payload': {'status': 'WORKING'}}
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(webhook.ingest, event)
        try:
            assert entered.wait(5)
            second = pool.submit(poll, polling, 'NOT_LINKED')
            assert attempted.wait(5)
        finally:
            release.set()
        assert first.result(timeout=5) == {'status': 'WORKING'}
        assert second.result(timeout=5) == 'WORKING'
    state = polling.state()
    assert state['connection'] == 'NOT_LINKED'
    assert state['recovery_reasons']['connection_interrupted']['status'] == 'open'


@pytest.mark.parametrize('first_action', ['poll', 'reconcile'])
def test_reconciliation_serializes_with_failure_in_both_orders(tmp_path, monkeypatch, first_action):
    polling = seeded(tmp_path / 'state.sqlite')
    poll(polling)
    admin = Store(polling.path, migrate_schema=False)
    before = admin.state()['recovery_reasons']
    token = before['connection_interrupted']['last_seen']
    # Even a repeated clock must produce a newer compare-and-set token.
    monkeypatch.setattr('sally_whatsapp.store.utc', lambda: token)
    actions = {
        'poll': lambda: poll(polling, 'FAILED', 3000),
        'reconcile': lambda: admin.reconcile_recovery('connection_interrupted', token),
    }
    first_store, second_store = (polling, admin) if first_action == 'poll' else (admin, polling)
    entered, release = hold_write(monkeypatch, first_store,
                                  'connection' if first_action == 'poll' else 'recovery_required')
    attempted = trace_begin(monkeypatch, second_store)
    second_action = 'reconcile' if first_action == 'poll' else 'poll'
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(actions[first_action])
        try:
            assert entered.wait(5)
            second = pool.submit(actions[second_action])
            assert attempted.wait(5)
        finally:
            release.set()
        first.result(timeout=5)
        if first_action == 'poll':
            with pytest.raises(ValueError, match='Recovery reason changed'):
                second.result(timeout=5)
        else:
            second.result(timeout=5)
    after = Store(polling.path, migrate_schema=False).state()
    issue = after['recovery_reasons']['connection_interrupted']
    assert issue['status'] == 'open' and issue['last_seen'] > token
    assert issue['first_seen'] == before['connection_interrupted']['first_seen']
    assert after['recovery_reasons']['chat_alias_unresolved'] == before['chat_alias_unresolved']
    assert after['recovery_required'] is True


def test_gateway_runs_outside_transaction_and_diagnostic_sees_committed_poll(environment, monkeypatch):
    settings, receiver, gateway, _ = environment
    service = Service(settings, gateway=gateway, event_transport=receiver)
    emitted = []

    def status():
        # A separate writer can obtain the lock during the gateway operation.
        with sqlite3.connect(settings.database, timeout=0) as db:
            db.execute('BEGIN IMMEDIATE')
            db.rollback()
        return 'FAILED'

    def emit(*args, **kwargs):
        state = Store(settings.database, migrate_schema=False).state()
        assert state['connection'] == 'FAILED'
        assert state['last_connection_check_at'] == utc(state['connection_checked_epoch'])
        assert state['recovery_reasons']['connection_interrupted']['status'] == 'open'
        emitted.append((args, kwargs))

    monkeypatch.setattr(gateway, 'status', status)
    monkeypatch.setattr(service.diagnostics, 'emit', emit)
    service.poll_connection()
    assert emitted == [(('connection.changed', 'warning'), {
        'state': 'FAILED', 'previous_state': 'UNKNOWN', 'observation_source': 'poll'})]


def test_failed_poll_does_not_emit_change_or_persist_partial_state(environment, monkeypatch):
    settings, receiver, gateway, _ = environment
    service = Service(settings, gateway=gateway, event_transport=receiver)
    before = rows(service.store)
    original = service.store.require_recovery
    emitted = []

    def fail(reason, *, db=None):
        original(reason, db=db)
        raise sqlite3.OperationalError('Synthetic incident write failure')

    gateway.state = 'FAILED'
    monkeypatch.setattr(service.store, 'require_recovery', fail)
    monkeypatch.setattr(service.diagnostics, 'emit', lambda *a, **kw: emitted.append((a, kw)))
    with pytest.raises(sqlite3.OperationalError, match='Synthetic incident write failure'):
        service.poll_connection()
    assert emitted == [] and rows(service.store) == before


@pytest.mark.parametrize('previous', ['missing', None, 'UNKNOWN', 'NOT_LINKED'])
def test_initial_not_linked_does_not_invent_an_interruption(tmp_path, previous):
    store = Store(tmp_path / 'state.sqlite')
    if previous != 'missing':
        store.set_state('connection', previous)
    assert poll(store, 'NOT_LINKED') == ('UNKNOWN' if previous == 'missing' else previous)
    assert store.state()['recovery_reasons'] == {}
    assert store.state()['recovery_required'] is False


def test_historical_partial_status_is_not_silently_backfilled(environment):
    settings, receiver, gateway, _ = environment
    service = Service(settings, gateway=gateway, event_transport=receiver)
    # Deliberately reproduce an already-existing legacy partial observation.
    service.store.set_state('connection', 'FAILED')
    gateway.state = 'WORKING'
    service.poll_connection()
    state = service.store.state()
    assert state['connection'] == 'WORKING'
    assert state['recovery_reasons'] == {} and state['recovery_required'] is False
