"""Reconcile real SQLite transactions/ASGI requests without real services."""
import hashlib
import hmac
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import message, subscribe
from sally_whatsapp import ingestion_metrics
from sally_whatsapp.store import Store


def counts(store):
    return store.state()['ingestion_diagnostics']['counts']


def test_live_history_duplicates_and_epoch_are_distinct(tmp_path):
    one, two = Store(tmp_path/'one.db'), Store(tmp_path/'two.db')
    event = message('synthetic-same')
    one.ingest(event, historical=True)
    one.ingest(event)
    one.ingest(event)
    two.ingest(event)
    c = counts(one)
    assert c['history.calls'] == c['history.messages_inserted'] == 1
    assert c['live.calls'] == c['live.duplicate'] == 2
    assert 'live.messages_inserted' not in c
    assert c['live.first_live_messages'] == 1
    assert counts(two)['live.messages_inserted'] == 1
    a, b = one.state()['ingestion_diagnostics'], two.state()['ingestion_diagnostics']
    assert a['epoch'] != b['epoch'] and a['coverage_since'] > 0
    assert Store(one.path, migrate_schema=False).state()['ingestion_diagnostics'] == a
    assert not a['http_acceptance_counted'] and not a['absence_proves_no_message_loss']


def test_concurrent_duplicate_has_one_receipt_and_message(tmp_path):
    store = Store(tmp_path/'one.db'); event = message('synthetic-duplicate')
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _:store.ingest(event), range(12)))
    assert sum(not r['duplicate'] for r in results) == 1
    c = counts(store)
    assert c['live.calls'] == 12 and c['live.duplicate'] == 11
    assert c['live.messages_inserted'] == c['live.receipts_inserted'] == 1


def test_concurrent_ignored_events_do_not_lose_counter_updates(tmp_path, monkeypatch):
    store = Store(tmp_path/'ignored.db')
    original = ingestion_metrics._read

    def delayed_counter_read(db):
        value = original(db)
        # Inject scheduling delay between the real read and write. Ignored
        # events do not otherwise open an ingestion write transaction.
        time.sleep(.02)
        return value

    monkeypatch.setattr(ingestion_metrics, '_read', delayed_counter_read)
    event = {'event':'engine.event', 'engine':'GOWS', 'payload':{'event':'events.Unknown'}}
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _:store.ingest(event), range(8)))
    assert all(row == {'ignored':True, 'reason':'unsupported_engine_event'} for row in results)
    c = counts(store)
    assert c == {'live.calls':8, 'live.ignored':8}
    assert store.state()['archive_messages'] == 0


def test_ingestion_counts_rollback_with_supplied_transaction(tmp_path):
    store = Store(tmp_path/'one.db')
    with pytest.raises(RuntimeError):
        with store.db() as db:
            store.ingest(message('synthetic-rollback'), db=db)
            raise RuntimeError('rollback before history checkpoint')
    assert store.state()['archive_messages'] == 0
    assert store.state()['ingestion_diagnostics']['availability'] == 'not_observed'


def post(client, service, event):
    body = json.dumps(event).encode()
    return client.post('/webhooks/waha', content=body, headers={
        'x-webhook-hmac-algorithm':'sha512',
        'x-webhook-hmac':hmac.digest(service.webhook_key, body, 'sha512').hex()})


def test_http_ingestion_queue_and_callback_correlation(app_client, environment):
    app, client = app_client; service = app.state.service
    subscribe(client)
    response = post(client, service, message('synthetic-trace'))
    assert response.status_code == 200
    assert counts(service.store)['live.callbacks_queued'] == 1
    service.events.dispatch_one()
    logs = [json.loads(s) for s in (service.diagnostics.directory/'events.jsonl').read_text().splitlines()]
    acquired = next(r for r in logs if r['event'] == 'ingestion.committed')
    callback = next(r for r in logs if r['event'] == 'callback.started')
    assert acquired['ingestion_ref'] == callback['ingestion_ref']
    assert acquired['request_id'] == response.headers['x-request-id']
    assert acquired['callbacks_queued'] == acquired['receipts_inserted'] == acquired['messages_inserted'] == 1
    assert 'synthetic-trace' not in json.dumps(logs)
    before = counts(service.store)
    assert client.post('/webhooks/waha', json=message('untrusted')).status_code == 401
    assert counts(service.store) == before
    assert post(client, service, {'event':'unknown', 'session':'default', 'payload':{}}).status_code == 400
    assert counts(service.store) == before


def test_logger_failure_does_not_undo_committed_message(app_client, monkeypatch):
    app, client = app_client; service = app.state.service
    def unavailable(*_):
        raise OSError('private filesystem error')
    monkeypatch.setattr(service.diagnostics.handler, 'handle', unavailable)
    assert post(client, service, message('synthetic-log-failure')).status_code == 200
    assert counts(service.store)['live.messages_inserted'] == 1


def test_corrupt_counter_metadata_does_not_replace_history_or_leak_keys(tmp_path):
    store = Store(tmp_path/'one.db')
    store.set_state(ingestion_metrics.KEY, {'version':1, 'epoch':'a'*24, 'coverage_since':1,
                                          'counts':{'private-untrusted':9}})
    store.ingest(message('synthetic-metrics-invalid'))
    assert store.state()['archive_messages'] == 1
    state = store.state()['ingestion_diagnostics']
    assert state['availability'] == 'metadata_invalid'
    assert 'private-untrusted' not in json.dumps(state)
