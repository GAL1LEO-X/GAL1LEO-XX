"""Provider dispatch, durable completion and status reads are separate phases."""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import sqlite3
from threading import Event
from types import SimpleNamespace

import pytest

from sally_whatsapp import job_metadata, store as store_module
from sally_whatsapp.server import OperationAction, SendText, Service
from sally_whatsapp.store import Store


KEY = 'synthetic_completion_boundary'
CHAT = '15555550177@c.us'
PROVIDER = 'true_' + CHAT + '_COMPLETION'


@pytest.fixture
def completion(environment):
    settings, receiver, gateway, _ = environment
    settings = replace(settings, live_account_enabled=True, send_enabled=True,
                       allow_all_destinations=True)
    calls = []
    def acknowledge(*args, **kwargs):
        calls.append((args, kwargs))
        return {'id': PROVIDER, 'success': True}
    gateway.send = gateway.request = acknowledge
    service = Service(settings, gateway=gateway, event_transport=receiver)
    try:
        yield service, calls
    finally:
        service.diagnostics.close()


def request(service, queued):
    if queued:
        return service.operation(OperationAction(operation='messages_send_text',
            arguments={'body': {'chatId': CHAT, 'text': 'Synthetic completion'}},
            idempotency_key=KEY), service.settings.owner_subject)
    return service.send(SendText(chat_id=CHAT, text='Synthetic completion', idempotency_key=KEY),
                        service.settings.owner_subject)


def attempt(service, queued):
    if queued:
        return service.process_action()
    return request(service, False)


def ledger(store):
    with store.db() as db:
        return {table: [tuple(row) for row in db.execute('SELECT * FROM ' + table + ' WHERE key=?', (KEY,))]
                for table in ('sends', 'operation_results', 'action_jobs',
                              'action_job_metadata', 'action_job_sources')}


def assert_durable_ack(service, calls, queued, state='submitted'):
    status = service.store.send_status(KEY)
    assert status['state'] == state and status['provider_id'] == PROVIDER
    before = ledger(service.store)
    assert request(service, queued)['state'] == state
    assert not service.process_action() and len(calls) == 1
    assert ledger(service.store) == before
    restarted = Store(service.store.path, recover_inflight=True)
    assert restarted.send_status(KEY) == status and ledger(restarted) == before
    service.store.ingest({'id': 'synthetic_completion_receipt', 'event': 'message.ack',
        'payload': {'id': PROVIDER, 'fromMe': True, 'from': CHAT, 'to': None,
                    'ack': 3, 'ackName': 'READ'}})
    current = service.store.send_status(KEY)
    assert current['state'] == state and set(current['delivery']['evidence']) == {'read'}


@pytest.mark.parametrize('queued', [False, True], ids=['direct', 'queued'])
def test_projection_failure_cannot_reclassify_committed_ack(completion, monkeypatch, queued):
    service, calls = completion
    if queued:
        assert request(service, queued)['state'] == 'queued'
    original = store_module.delivery_status
    failures = []
    def fail_once(db, send, job, **kwargs):
        if send['state'] == 'submitted' and not failures:
            with service.store.db() as check:
                failures.append(tuple(check.execute(
                    'SELECT state,provider_id FROM sends WHERE key=?', (KEY,)).fetchone()))
            raise sqlite3.OperationalError('synthetic projection failure after commit')
        return original(db, send, job, **kwargs)
    monkeypatch.setattr(store_module, 'delivery_status', fail_once)
    if queued:
        assert attempt(service, queued)
        assert failures == []  # A worker completion does not need a public status projection.
        with pytest.raises(sqlite3.OperationalError):
            service.store.send_status(KEY)
    else:
        with pytest.raises(sqlite3.OperationalError):
            attempt(service, queued)
    assert failures == [('submitted', PROVIDER)]
    assert_durable_ack(service, calls, queued)


@pytest.mark.parametrize('queued', [False, True], ids=['direct', 'queued'])
def test_failure_after_commit_keeps_whole_ack_ledger(completion, monkeypatch, queued):
    service, calls = completion
    if queued:
        request(service, queued)
    original = service.store.db
    committed = []
    @contextmanager
    def fail_after_commit():
        with original() as db:
            yield db
            row = db.execute('SELECT state FROM sends WHERE key=?', (KEY,)).fetchone()
            fail = bool(db.in_transaction and row and row['state'] == 'submitted' and not committed)
        if fail:
            committed.append(ledger(service.store))
            raise sqlite3.OperationalError('synthetic error after completion commit')
    monkeypatch.setattr(service.store, 'db', fail_after_commit)
    with pytest.raises(sqlite3.OperationalError):
        attempt(service, queued)
    assert len(committed) == 1 and ledger(service.store) == committed[0]
    assert_durable_ack(service, calls, queued)


@pytest.mark.parametrize('queued', [False, True], ids=['direct', 'queued'])
def test_completion_rollback_remains_consumed_and_recovers_uncertain(completion, monkeypatch, queued):
    service, calls = completion
    if queued:
        request(service, queued)
    original = job_metadata.reconcile
    failures = []
    def fail_before_commit(db, key, **kwargs):
        row = db.execute('SELECT state FROM sends WHERE key=?', (key,)).fetchone()
        if row and row['state'] == 'submitted' and not failures:
            failures.append(True)
            raise sqlite3.OperationalError('synthetic completion rollback')
        return original(db, key, **kwargs)
    monkeypatch.setattr(job_metadata, 'reconcile', fail_before_commit)
    with pytest.raises(sqlite3.OperationalError):
        attempt(service, queued)
    status = service.store.send_status(KEY)
    assert status['state'] == 'sending' and status['provider_id'] is None
    assert request(service, queued)['state'] == 'sending'
    assert len(calls) == 1 and not service.process_action()
    restarted = Store(service.store.path, recover_inflight=True)
    status = restarted.send_status(KEY)
    assert status['state'] == 'uncertain' and status['provider_id'] is None
    assert request(service, queued)['state'] == 'uncertain'
    assert len(calls) == 1 and not service.process_action()


@pytest.mark.parametrize('queued', [False, True], ids=['direct', 'queued'])
def test_completion_commits_before_fallible_diagnostics(completion, monkeypatch, queued):
    service, calls = completion
    if queued:
        request(service, queued)
    original = service.diagnostics.emit
    observed = []
    def fail_finished(event, *args, **kwargs):
        if event == 'action.finished' and not observed:
            with service.store.db() as db:
                observed.append(tuple(db.execute(
                    'SELECT state,provider_id FROM sends WHERE key=?', (KEY,)).fetchone()))
            raise RuntimeError('synthetic diagnostics failure')
        return original(event, *args, **kwargs)
    monkeypatch.setattr(service.diagnostics, 'emit', fail_finished)
    with pytest.raises(RuntimeError, match='synthetic diagnostics failure'):
        attempt(service, queued)
    assert observed == [('submitted', PROVIDER)]
    assert_durable_ack(service, calls, queued)


@pytest.mark.parametrize('queued', [False, True], ids=['direct', 'queued'])
def test_concurrent_replay_cannot_dispatch_again_after_local_completion_error(completion, monkeypatch, queued):
    service, calls = completion
    if queued:
        request(service, queued)
    entered, release = Event(), Event()
    original = service.gateway.send
    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(2), 'Synthetic provider was not released'
        return original(*args, **kwargs)
    monkeypatch.setattr(service.gateway, 'send', blocked)
    monkeypatch.setattr(service.gateway, 'request', blocked)
    original_emit = service.diagnostics.emit
    failures = []
    def fail_finished(event, *args, **kwargs):
        if event == 'action.finished' and not failures:
            failures.append(True)
            raise RuntimeError('synthetic post-commit diagnostic failure')
        return original_emit(event, *args, **kwargs)
    monkeypatch.setattr(service.diagnostics, 'emit', fail_finished)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(attempt, service, queued)
        try:
            assert entered.wait(2)
            assert request(service, queued)['state'] == 'sending'
            assert not service.process_action()
        finally:
            release.set()
        with pytest.raises(RuntimeError, match='synthetic post-commit diagnostic failure'):
            first.result(timeout=2)
    assert_durable_ack(service, calls, queued)


@pytest.mark.parametrize('queued', [False, True], ids=['direct', 'queued'])
def test_shutdown_uncertainty_keeps_late_ack_and_never_retries(completion, queued):
    service, calls = completion
    if queued:
        request(service, queued)
    timed_out = Event()
    timed_out.set()
    service.readiness = SimpleNamespace(shutdown_timed_out=timed_out)
    attempt(service, queued)
    assert_durable_ack(service, calls, queued, state='uncertain')
