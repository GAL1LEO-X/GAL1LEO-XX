"""Synthetic callback races, fair scheduling and observable delivery boundaries."""
import base64
import json
import time

import pytest

from conftest import message, subscribe
from sally_whatsapp.events import signed_headers

NEW_SECRET = 'whsec_' + base64.b64encode(b'y' * 32).decode()
FILTERS = {'chat_ids': ['group-1@g.us']}
URL = 'https://receiver.example/callback'


def test_rotating_secret_after_claim_signs_with_current_key(app_client, environment, monkeypatch):
    app, client = app_client
    service = app.state.service
    subscribe(client)
    service.store.ingest(message('rotation-during-claim'))
    original = service.events.cipher.decrypt
    armed = [True]

    def rotate_once(*args, **kwargs):
        result = original(*args, **kwargs)
        if armed[0]:
            armed[0] = False
            service.events.subscribe(service.settings.owner_subject, 'message.received', FILTERS,
                                     {'url': URL, 'secret': NEW_SECRET})
        return result

    monkeypatch.setattr(service.events.cipher, 'decrypt', rotate_once)
    service.events.dispatch_one()
    _, body, headers = environment[1].requests[-1]
    current_signature = signed_headers(NEW_SECRET, json.loads(body)['eventId'],
                                      headers['X-MCP-Subscription-Id'], body,
                                      int(headers['webhook-timestamp']))['webhook-signature']
    assert current_signature in headers['webhook-signature'].split()


def test_missing_account_event_cannot_send_unreadable_reference(app_client, environment):
    app, client = app_client
    service = app.state.service
    subscribe(client, name='whatsapp.event', arguments={'all_chats': True, 'event_types': ['session.status']})
    service.store.ingest({'event': 'session.status', 'id': 'connection-1', 'session': 'default',
                          'timestamp': int(time.time()*1000), 'payload': {'status': 'WORKING'}})
    with service.store.db() as db:
        source = db.execute('SELECT id FROM account_events').fetchone()[0]
        db.execute('DELETE FROM account_events WHERE id=?', (source,))
    assert service.store.account_event(source) is None
    service.events.dispatch_one()
    assert len(environment[1].requests) == 1
    assert service.store.state()['deliveries'] == {'cancelled': 1}


def test_callbacks_may_overtake_retry_but_keep_identity(app_client, environment):
    app, client = app_client
    service = app.state.service
    subscribe(client)
    service.store.ingest(message('order-first'))
    service.store.ingest(message('order-second'))
    now = time.time()
    environment[1].responses.append((503, b''))
    assert service.events.dispatch_one(now=now)
    assert service.events.dispatch_one(now=now)
    assert service.events.dispatch_one(now=now+120)
    callbacks = [json.loads(body) for _, body, _ in environment[1].requests[1:]]
    assert [x['data']['message_id'] for x in callbacks] == ['order-first', 'order-second', 'order-first']
    assert callbacks[0]['eventId'] == callbacks[2]['eventId']


def change(kind, identifier, payload):
    return {'event': kind, 'id': identifier, 'session': 'default',
            'timestamp': int(time.time()*1000), 'payload': payload}


def diagnostics(service):
    path = service.diagnostics.directory / 'events.jsonl'
    return [json.loads(line) for line in path.read_text().splitlines()]


def callback_requests(receiver):
    return [(body, headers) for _, body, headers in receiver.requests
            if json.loads(body).get('type') != 'verification']


def test_expired_rotation_overlap_not_extended_by_old_claim_time(app_client, environment, monkeypatch):
    app, client = app_client
    service = app.state.service
    clock = [int(time.time())]
    monkeypatch.setattr(time, 'time', lambda: clock[0])
    subscribe(client)
    service.events.subscribe(service.settings.owner_subject, 'message.received', FILTERS,
                             {'url': URL, 'secret': NEW_SECRET})
    service.store.ingest(message('past-key-overlap'))
    original = service.events.cipher.decrypt
    armed = [True]

    def cross_overlap(*args, **kwargs):
        result = original(*args, **kwargs)
        if armed[0]:
            armed[0] = False
            clock[0] += 61
        return result

    monkeypatch.setattr(service.events.cipher, 'decrypt', cross_overlap)
    service.events.dispatch_one()
    _, headers = callback_requests(environment[1])[-1]
    assert len(headers['webhook-signature'].split()) == 1


@pytest.mark.parametrize('reactivate', [False, True])
def test_old_410_does_not_deactivate_subscription_renewed_inflight(app_client, environment, reactivate):
    app, client = app_client
    service = app.state.service
    subscribe(client)
    service.store.ingest(message('old-generation'))
    receiver = environment[1]
    post = receiver.post
    armed = [True]

    def post_with_renewal(url, body, headers):
        if json.loads(body).get('name') == 'message.received' and armed[0]:
            armed[0] = False
            if reactivate:
                service.events.unsubscribe(service.settings.owner_subject, 'message.received', FILTERS, URL)
            service.events.subscribe(service.settings.owner_subject, 'message.received', FILTERS,
                                     {'url': URL, 'secret': NEW_SECRET})
            return 410, b''
        return post(url, body, headers)

    receiver.post = post_with_renewal
    service.events.dispatch_one()
    assert service.store.state()['active_subscriptions'] == 1
    service.store.ingest(message('renewed-generation'))
    service.events.dispatch_one()
    assert json.loads(callback_requests(receiver)[-1][0])['data']['message_id'] == 'renewed-generation'


def test_revocation_notification_keeps_usable_pointer_without_original_content(app_client, environment):
    app, client = app_client
    service = app.state.service
    target = 'false_12025550100@c.us_TARGET'
    service.store.ingest(message(target, chat='12025550100@c.us', text='private original'))
    subscribe(client, name='whatsapp.event', arguments={'all_chats': True, 'event_types': ['message.revoked']})
    service.store.ingest(change('message.revoked', 'revoke-target',
        {'revokedMessageId': target, 'from': '12025550100@c.us', 'before': {'id': target, 'body': 'private original'}}))
    # The callback can carry its target even though that target is revoked.
    with service.store.db() as db:
        row = db.execute('SELECT id,body FROM deliveries').fetchone()
        body = json.loads(row['body'])
        body['data']['message_id'] = target
        db.execute('UPDATE deliveries SET body=? WHERE id=?', (json.dumps(body), row['id']))
    service.events.dispatch_one()
    callback = json.loads(callback_requests(environment[1])[-1][0])
    detail = service.store.account_event(callback['data']['event_id'])
    assert detail['event_type'] == 'message.revoked'
    assert 'private original' not in json.dumps(detail)
    assert service.store.state()['deliveries'] == {'accepted': 1}


def test_account_reference_removed_after_claim_is_cancelled(app_client, environment, monkeypatch):
    app, client = app_client
    service = app.state.service
    subscribe(client, name='whatsapp.event', arguments={'all_chats': True, 'event_types': ['session.status']})
    service.store.ingest(change('session.status', 'connection-after-claim', {'status': 'WORKING'}))
    decrypt = service.events.cipher.decrypt

    def delete_after_claim(*args, **kwargs):
        result = decrypt(*args, **kwargs)
        with service.store.db() as db:
            db.execute('DELETE FROM account_events')
        return result

    monkeypatch.setattr(service.events.cipher, 'decrypt', delete_after_claim)
    service.events.dispatch_one()
    assert not callback_requests(environment[1])
    assert service.store.state()['deliveries'] == {'cancelled': 1}


def test_scheduling_fairness_survives_restart_and_account_backlog(app_client, environment):
    from sally_whatsapp.server import Service
    app, client = app_client
    service = app.state.service
    subscribe(client, name='whatsapp.event', arguments={'all_chats': True, 'event_types': ['message.ack']})
    for i in range(120):
        service.store.ingest(change('message.ack', 'ack-'+str(i),
            {'id': 'true_12025550100@c.us_ACK'+str(i), 'from': '12025550100@c.us', 'fromMe': True, 'ack': 3}))
    assert service.events.dispatch_one()
    subscribe(client)
    service.store.ingest(message('fresh-behind-ack-backlog'))
    restarted = Service(environment[0], gateway=environment[2], event_transport=environment[1])
    try:
        for _ in range(3):
            restarted.events.dispatch_one()
        callbacks = [json.loads(body) for body, _ in callback_requests(environment[1])]
        fresh = [i for i, event in enumerate(callbacks) if event['name'] == 'message.received']
        assert fresh and fresh[0] <= 3
        assert sum(event['name'] == 'whatsapp.event' for event in callbacks) >= 2
        assert restarted.store.state()['deliveries']['pending'] >= 115
    finally:
        restarted.diagnostics.close()


def test_due_retry_not_starved_by_new_same_class_events(app_client, environment, monkeypatch):
    app, client = app_client
    service = app.state.service
    clock = [int(time.time())]
    monkeypatch.setattr(time, 'time', lambda: clock[0])
    subscribe(client)
    service.store.ingest(message('retry-old'))
    environment[1].responses.append((503, b''))
    service.events.dispatch_one()
    first = callback_requests(environment[1])[0][0]
    clock[0] += 30
    for i in range(10):
        service.store.ingest(message('fresh-'+str(i)))
    service.events.dispatch_one()
    assert callback_requests(environment[1])[1][0] == first


def test_disconnect_reconnect_keeps_authorized_queue_without_history_replay(app_client, environment):
    app, client = app_client
    service = app.state.service
    subscribe(client)
    subscribe(client, name='whatsapp.event', arguments={'all_chats': True, 'event_types': ['session.status']})
    service.store.ingest(message('before-disconnect'))
    service.store.ingest(change('session.status', 'session-failed', {'status': 'FAILED', 'qr': 'never-log-qr'}))
    service.store.ingest(message('imported-after-disconnect'), historical=True)
    service.store.ingest(change('session.status', 'session-working', {'status': 'WORKING'}))
    while service.events.dispatch_one():
        pass
    callbacks = [json.loads(body) for body, _ in callback_requests(environment[1])]
    assert [v['data']['message_id'] for v in callbacks if v['name'] == 'message.received'] == ['before-disconnect']
    assert len([v for v in callbacks if v['name'] == 'whatsapp.event']) == 2
    assert service.store.state()['active_subscriptions'] == 2
    assert 'connection_interrupted' in service.store.state()['recovery_reasons']
    assert 'never-log-qr' not in json.dumps(diagnostics(service))


@pytest.mark.parametrize('timeout', [False, True])
def test_latency_is_transport_acceptance_not_platform_start(app_client, environment, monkeypatch, timeout):
    from sally_whatsapp.events import CallbackError
    app, client = app_client
    service = app.state.service
    clock = [int(time.time())]
    monkeypatch.setattr(time, 'time', lambda: clock[0])
    subscribe(client)
    service.store.ingest(message('latency-reference', timestamp=clock[0]-2, text='never-log-content'))
    clock[0] += 5
    monotonic = iter([100.0, 100.25])
    monkeypatch.setattr(time, 'monotonic', lambda: next(monotonic))
    original_post = environment[1].post

    def observed_post(*args):
        assert diagnostics(service)[-1]['event'] == 'callback.started'
        if timeout:
            raise CallbackError('timeout')
        return original_post(*args)

    environment[1].post = observed_post
    service.events.dispatch_one()
    records = [row for row in diagnostics(service) if row['event'].startswith('callback.')]
    start, finish = records[-2:]
    assert start['attempt_at'] == clock[0]
    assert start['provider_at'] == clock[0]-7
    assert start['ingested_at'] == start['queued_at'] == clock[0]-5
    assert start['event_age_ms'] == 7000 and start['queue_delay_ms'] == 5000
    assert finish['duration_ms'] == 250
    assert start['event_ref'] == finish['event_ref'] and start['job_ref'] == finish['job_ref']
    assert finish['state'] == ('pending' if timeout else 'accepted')
    assert ('accepted_at' in finish) is (not timeout)
    assert not any('platform' in key for record in records for key in record)
    assert 'never-log-content' not in json.dumps(records) and 'latency-reference' not in json.dumps(records)


def test_recovery_optional_pointer_is_bound_and_legacy_body_stays_eligible(app_client):
    from sally_whatsapp.event_recovery import EventRecovery
    app, client = app_client
    service = app.state.service
    identifier = 'true_12025550100@c.us_SENT'
    subscription = subscribe(client, name='whatsapp.event', arguments={
        'all_chats': True, 'event_types': ['message.sent']})['result']['id']
    service.store.ingest(message(identifier, chat='12025550100@c.us', from_me=True))
    with service.store.db() as db:
        row = db.execute('SELECT id,body FROM deliveries').fetchone()
        db.execute("UPDATE deliveries SET state='failed',attempts=?,last_status=503 WHERE id=?",
                   (service.settings.max_callback_attempts, row['id']))
    recovery = EventRecovery(service.store, service.settings)
    assert recovery.preview(subscription, [row['id']])['eligible']
    body = json.loads(row['body'])
    body['data']['message_id'] = 'false_12025550100@c.us_WRONG'
    with service.store.db() as db:
        db.execute('UPDATE deliveries SET body=? WHERE id=?', (json.dumps(body), row['id']))
    assert recovery.preview(subscription, [row['id']])['deliveries'][0]['reason'] == 'source_changed'
    body['data'].pop('message_id')
    with service.store.db() as db:
        db.execute('UPDATE deliveries SET body=? WHERE id=?', (json.dumps(body), row['id']))
    assert recovery.preview(subscription, [row['id']])['eligible']


def test_round_robin_three_classes_persists_position_after_restart(app_client, environment, monkeypatch):
    from sally_whatsapp.server import Service
    app, client = app_client
    service = app.state.service
    clock = [int(time.time()//60)*60+1]
    monkeypatch.setattr(time, 'time', lambda: clock[0])
    subscribe(client)
    subscribe(client, name='message.digest', arguments={**FILTERS, 'digest_window_seconds': 60})
    subscribe(client, name='whatsapp.event', arguments={'all_chats': True, 'event_types': ['message.ack']})
    for i in range(6):
        service.store.ingest(message('round-robin-'+str(i)))
        service.store.ingest(change('message.ack', 'round-robin-ack-'+str(i),
            {'id': 'true_12025550100@c.us_ROUND'+str(i), 'from': '12025550100@c.us', 'fromMe': True, 'ack': 2}))
    clock[0] += 60
    service.events.dispatch_one()
    restarted = Service(environment[0], gateway=environment[2], event_transport=environment[1])
    try:
        for _ in range(6):
            restarted.events.dispatch_one()
        names = [json.loads(body)['name'] for body, _ in callback_requests(environment[1])]
        assert names == ['message.received', 'message.digest', 'whatsapp.event',
                         'message.received', 'whatsapp.event', 'message.received', 'whatsapp.event']
        assert not any(key.startswith('private:') for key in restarted.store.state())
    finally:
        restarted.diagnostics.close()


def test_legacy_delivery_does_not_invent_acquisition_or_queue_time(app_client, environment):
    app, client = app_client
    service = app.state.service
    subscribe(client)
    service.store.ingest(message('legacy-timing-unknown'))
    with service.store.db() as db:
        db.execute("DELETE FROM state WHERE key LIKE 'private:event_timing:%'")
    service.events.dispatch_one()
    start = [row for row in diagnostics(service) if row['event'] == 'callback.started'][-1]
    assert 'attempt_at' in start
    for key in ('provider_at', 'ingested_at', 'queued_at', 'event_age_ms', 'queue_delay_ms'):
        assert key not in start
    assert service.store.state()['deliveries'] == {'accepted': 1}
