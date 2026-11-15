"""Local ordering of observations, independent of why WhatsApp disconnected."""
import time
import json
from dataclasses import replace

import httpx
import pytest
from sally_whatsapp.store import Store, utc
from sally_whatsapp.connection_observations import SUPERSEDED

from sally_whatsapp.server import Service
from sally_whatsapp.gateway import Waha


def test_poll_started_before_new_webhook_cannot_overwrite_it(environment, monkeypatch):
    settings, receiver, gateway, _ = environment
    service = Service(settings, gateway=gateway, event_transport=receiver)
    clock = [time.time()]
    monkeypatch.setattr(time, 'time', lambda: clock[0])

    def slow_old_status():
        clock[0] += 1
        service.ingest({'event': 'session.status', 'id': 'synthetic-new-working',
                        'payload': {'status': 'WORKING'}, 'timestamp': clock[0] * 1000})
        clock[0] += 1
        return 'STARTING'

    gateway.status = slow_old_status
    service.poll_connection()
    assert service.store.state()['connection'] == 'WORKING'
    assert service.store.state()['connection_observation']['discarded_polls'] == 1
    assert not receiver.requests


def test_two_instances_and_overlapping_poll_generations(tmp_path):
    one, two = Store(tmp_path/'one.db'), Store(tmp_path/'two.db')
    first, second = one.connection_generation(), two.connection_generation()
    assert one.record_connection_poll('WORKING',checked_epoch=2,checked_at=utc(2),expected_generation=first) == 'UNKNOWN'
    assert one.record_connection_poll('FAILED',checked_epoch=3,checked_at=utc(3),expected_generation=first) is SUPERSEDED
    assert two.record_connection_poll('STARTING',checked_epoch=3,checked_at=utc(3),expected_generation=second) == 'UNKNOWN'
    assert one.state()['connection'] == 'WORKING' and two.state()['connection'] == 'STARTING'
    assert one.state()['recovery_reasons'] == {}
    # Superseded polling did not extend the freshness of the accepted sample.
    assert one.state()['connection_checked_epoch'] == 2


def test_clock_skew_and_duplicate_status_do_not_invent_remote_cause(tmp_path):
    store = Store(tmp_path/'connection.db')
    event = {'event':'session.status','id':'synthetic-working','timestamp':1,
             'payload':{'status':'WORKING'}}
    store.ingest(event)
    generation = store.connection_generation()
    assert store.ingest(event)['duplicate']
    assert store.connection_generation() == generation
    state = store.state()['connection_observation']
    assert state['ordering'] == 'local_committed_observations'
    assert state['observed_at'] > event['timestamp']
    assert not state['event_interval_is_total_downtime']
    assert state['remote_cause'] == 'not_determined_by_status'


@pytest.mark.parametrize('failure', ['rest_eof', 'rest_503', 'rest_read_timeout'])
def test_transport_failure_and_recovery_do_not_resolve_history_or_retry_actions(environment, failure):
    # These are REST failures, not a simulation/proof of a WhatsApp WebSocket
    # close. The diagnostic must keep those distinct even when both say EOF/503.
    settings, receiver, _, _ = environment
    settings = replace(settings, live_account_enabled=True)
    gateway = Waha(settings)
    gateway.client.close()
    requests = []

    def handle(request):
        requests.append((request.method, request.url.path))
        if len(requests) > 1:
            return httpx.Response(200, json={'status':'WORKING'})
        if failure == 'rest_503':
            return httpx.Response(503, json={'message':'synthetic-private-response'})
        error = httpx.ReadError if failure == 'rest_eof' else httpx.ReadTimeout
        raise error('EOF synthetic-private-response', request=request)

    gateway.client = httpx.Client(base_url=settings.waha_url, transport=httpx.MockTransport(handle))
    service = Service(settings, gateway=gateway, event_transport=receiver)
    service.store.queue_action('synthetic-old-uncertain', settings.owner_subject,
                               'messages_send_list', {'body':{}})
    service.store.finish_send('synthetic-old-uncertain', 'uncertain')
    with service.store.db() as db:
        before = [tuple(r) for r in db.execute('SELECT * FROM sends')]
    try:
        service.poll_connection()
        assert service.store.state()['connection'] == 'UNREACHABLE'
        service.poll_connection()
        state = service.store.state()
        assert state['connection'] == 'WORKING'
        assert state['connection_observation']['remote_cause'] == 'not_determined_by_status'
        assert state['recovery_reasons']['connection_interrupted']['status'] == 'open'
        with service.store.db() as db:
            assert [tuple(r) for r in db.execute('SELECT * FROM sends')] == before
        assert len(requests) == 2 and all(method == 'GET' for method, _ in requests)
        assert not receiver.requests
        records = [json.loads(line) for line in (service.diagnostics.directory/'events.jsonl').read_text().splitlines()]
        failure_record = next(row for row in records if row['event'] == 'gateway.failed')
        assert failure_record['provider_error_kind'] == ('provider_failure' if failure == 'rest_503' else 'transport_failure')
        assert 'synthetic-private-response' not in json.dumps(records)
    finally:
        gateway.client.close()
        service.diagnostics.close()
