"""Late responses cannot complete or revoke a newer delivery claim."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock

import pytest

from test_callback_budget import delivery, queued


@pytest.mark.parametrize('late_status', [204, 410, 503])
def test_stale_callback_result_is_fenced_by_persisted_attempt(app_client, late_status):
    service, subscription, _, now = queued(app_client)
    entered = [Event(), Event()]
    release = [Event(), Event()]
    calls, lock = [], Lock()

    class Receiver:
        def post(self, url, body, headers):
            with lock:
                index = len(calls)
                calls.append((body, headers))
            entered[index].set()
            assert release[index].wait(timeout=5), 'synthetic receiver was not released'
            return (late_status if index == 0 else 204), b''

    service.events.transport = Receiver()
    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(service.events.dispatch_one, now)
        try:
            assert entered[0].wait(timeout=5)
            second = workers.submit(service.events.dispatch_one, now + 121)
            assert entered[1].wait(timeout=5)
            newer = delivery(service)
            assert newer['state'] == 'sending' and newer['attempts'] == 2
            release[0].set()
            assert first.result(timeout=5)
            assert delivery(service) == newer
            with service.store.db() as db:
                assert db.execute('SELECT active FROM subscriptions WHERE id=?', (subscription,)).fetchone()[0] == 1
        finally:
            for signal in release:
                signal.set()
        assert second.result(timeout=5)

    final = delivery(service)
    assert final['state'] == 'accepted' and final['attempts'] == 2
    assert final['last_status'] == 204
    # Ambiguous callback transport remains at-least-once: consumers deduplicate
    # this stable event ID, even when a previous sender resumes after its lease.
    assert calls[0][0] == calls[1][0]
    assert calls[0][1]['webhook-id'] == calls[1][1]['webhook-id']
