"""Callback claims consume a durable budget, including abandoned leases."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Event, Lock
import time

import pytest

from conftest import message, subscribe
from sally_whatsapp.event_recovery import EventRecovery


def queued(app_client, *, state='pending', attempts=0):
    app, client = app_client
    service = app.state.service
    subscription = subscribe(client)['result']['id']
    now = time.time()
    service.store.ingest(message('budget-message', timestamp=int(now) - 1))
    with service.store.db() as db:
        db.execute("UPDATE deliveries SET state=?,attempts=?,lease_until=?,next_attempt=0,last_status=503",
                   (state, attempts, now - 1))
        identifier = db.execute('SELECT id FROM deliveries').fetchone()[0]
    service.events.transport.requests.clear()
    return service, subscription, identifier, now


def delivery(service):
    with service.store.db() as db:
        return dict(db.execute('SELECT * FROM deliveries').fetchone())


@pytest.mark.parametrize('state', ['pending', 'sending'])
@pytest.mark.parametrize('extra_attempts', [0, 2])
def test_exhausted_callback_never_posts_after_requeue(app_client, state, extra_attempts):
    maximum = app_client[0].state.service.settings.max_callback_attempts
    service, _, _, now = queued(app_client, state=state, attempts=maximum + extra_attempts)
    before = delivery(service)

    assert service.events.dispatch_one(now=now)

    after = delivery(service)
    assert service.events.transport.requests == []
    assert after['state'] == 'failed'
    assert after['attempts'] == before['attempts']
    assert after['lease_until'] == 0 and after['last_status'] == 0
    assert (after['id'], after['event_id'], after['body']) == (before['id'], before['event_id'], before['body'])
    assert not service.events.dispatch_one(now=now + 1)


@pytest.mark.parametrize('state', ['pending', 'sending'])
@pytest.mark.parametrize('remaining', [0, 1])
def test_concurrent_callback_claimers_share_remaining_budget(app_client, state, remaining):
    maximum = app_client[0].state.service.settings.max_callback_attempts
    service, _, _, now = queued(app_client, state=state, attempts=maximum - remaining)
    start = Barrier(2)

    def dispatch():
        start.wait(timeout=5)
        return service.events.dispatch_one(now=now)

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: dispatch(), range(2)))

    assert sorted(results) == [False, True]
    assert len(service.events.transport.requests) == remaining
    row = delivery(service)
    assert row['attempts'] == maximum
    assert row['state'] == ('accepted' if remaining else 'failed')


@pytest.mark.parametrize('administrative', [False, True])
def test_final_callback_lease_cannot_be_reclaimed_or_overwritten(app_client, administrative):
    maximum = app_client[0].state.service.settings.max_callback_attempts
    service, subscription, identifier, now = queued(
        app_client, state='failed' if administrative else 'pending',
        attempts=maximum if administrative else maximum - 1)
    if administrative:
        recovery = EventRecovery(service.store, service.settings)
        preview = recovery.preview(subscription, [identifier])
        recovery.execute(subscription, [identifier], fingerprint=preview['fingerprint'],
                         request_id='callback-budget-permit')
        now = time.time()
    entered, release = Event(), Event()
    calls, guard = [], Lock()

    class BlockedReceiver:
        def post(self, *args):
            with guard:
                calls.append(args)
                first = len(calls) == 1
            if first:
                entered.set()
                assert release.wait(timeout=5), 'test did not release synthetic callback'
            return 204, b''

    service.events.transport = BlockedReceiver()
    with ThreadPoolExecutor(max_workers=1) as workers:
        first = workers.submit(service.events.dispatch_one, now)
        try:
            assert entered.wait(timeout=5)
            assert service.events.dispatch_one(now=now + 121)
            exhausted = delivery(service)
            assert len(calls) == 1
            assert exhausted['state'] == 'failed' and exhausted['last_status'] == 0
            assert exhausted['attempts'] == maximum + int(administrative)
        finally:
            release.set()
        assert first.result(timeout=5)
    assert delivery(service) == exhausted


def test_administrative_callback_permit_survives_lower_general_budget(app_client):
    maximum = app_client[0].state.service.settings.max_callback_attempts
    service, subscription, identifier, now = queued(app_client, state='failed', attempts=maximum)
    recovery = EventRecovery(service.store, service.settings)
    preview = recovery.preview(subscription, [identifier])
    recovery.execute(subscription, [identifier], fingerprint=preview['fingerprint'],
                     request_id='callback-lower-budget')
    now = time.time()
    service.events.settings = replace(service.settings, max_callback_attempts=1)

    assert service.events.dispatch_one(now=now)

    assert len(service.events.transport.requests) == 1
    assert delivery(service)['attempts'] == maximum + 1
    assert delivery(service)['state'] == 'accepted'
    assert not service.events.dispatch_one(now=now + 121)
