"""Requested subscription lifetimes bound actual synthetic callback delivery."""
from dataclasses import replace
from datetime import datetime
import time

import pytest

from conftest import message, subscribe
from sally_whatsapp.server import Service


def deadline(value):
    return datetime.fromisoformat(value["refreshBefore"].replace("Z", "+00:00")).timestamp()


@pytest.mark.parametrize("ttl_ms", [1000, 59000, 60000, 120000])
def test_requested_ttl_bounds_delivery_without_a_minimum_minute(
    environment, app_client, monkeypatch, ttl_ms,
):
    app, client = app_client
    service, receiver = app.state.service, environment[1]
    now = int(time.time())
    monkeypatch.setattr(time, "time", lambda: now)

    subscription = subscribe(client, ttlMs=ttl_ms)["result"]
    expires = now + ttl_ms / 1000
    assert deadline(subscription) == expires
    service.store.ingest(message("within-requested-ttl", timestamp=now))
    assert service.events.dispatch_one(now=expires - 0.01)
    assert len(receiver.requests) == 2  # Verification plus one event.

    service.store.ingest(message("after-requested-ttl", timestamp=now))
    assert not service.events.dispatch_one(now=expires)
    assert len(receiver.requests) == 2
    assert service.store.state()["deliveries"] == {"accepted": 1, "cancelled": 1}


@pytest.mark.parametrize(
    "ttl_ms,configured_ttl,token_ttl,expected_ttl",
    [(120000, 60, 300, 60), (120000, 86400, 30, 30),
     (1000, 60, 30, 1), (None, 60, 30, 30)],
)
def test_ttl_keeps_configured_and_oauth_expiration_ceilings(
    environment, app_client, monkeypatch, ttl_ms, configured_ttl, token_ttl, expected_ttl,
):
    app, client = app_client
    service = app.state.service
    now = int(time.time())
    monkeypatch.setattr(time, "time", lambda: now)
    service.events.settings = replace(service.settings, subscription_ttl=configured_ttl)
    client.headers["Authorization"] = "Bearer " + environment[3](exp=now + token_ttl)

    subscription = subscribe(client, ttlMs=ttl_ms)["result"]
    assert deadline(subscription) == now + expected_ttl
    service.store.ingest(message("ttl-ceiling", timestamp=now))
    assert not service.events.dispatch_one(now=now + expected_ttl)
    assert len(environment[1].requests) == 1  # Callback verification only.
    assert service.store.state()["deliveries"] == {"cancelled": 1}


def test_shorter_refresh_preserves_identity_and_expires_pending_delivery_after_restart(
    environment, app_client, monkeypatch,
):
    app, client = app_client
    service = app.state.service
    now = int(time.time())
    clock = [now]
    monkeypatch.setattr(time, "time", lambda: clock[0])

    original = subscribe(client, ttlMs=120000)["result"]
    service.store.ingest(message("pending-before-refresh", timestamp=now))
    clock[0] += 0.5
    refreshed = subscribe(client, ttlMs=1000)["result"]
    assert refreshed["id"] == original["id"]
    assert deadline(refreshed) == now + 1.5
    assert len(environment[1].requests) == 1  # Verification cache remains valid.
    assert service.store.state()["deliveries"] == {"pending": 1}

    restarted = Service(environment[0], gateway=environment[2], event_transport=environment[1])
    try:
        assert not restarted.events.dispatch_one(now=deadline(refreshed))
        assert restarted.store.state()["deliveries"] == {"cancelled": 1}
        assert len(environment[1].requests) == 1
    finally:
        restarted.diagnostics.close()


def test_expiration_between_dispatch_claim_and_callback_prevents_delivery(
    environment, app_client, monkeypatch,
):
    app, client = app_client
    service = app.state.service
    clock = [int(time.time())]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    subscribe(client, ttlMs=1000)
    service.store.ingest(message("expires-after-claim", timestamp=clock[0]))
    decrypt = service.events.cipher.decrypt

    def decrypt_after_expiry(*args, **kwargs):
        value = decrypt(*args, **kwargs)
        clock[0] += 2
        return value

    monkeypatch.setattr(service.events.cipher, "decrypt", decrypt_after_expiry)
    assert service.events.dispatch_one()
    assert service.store.state()["deliveries"] == {"cancelled": 1}
    assert len(environment[1].requests) == 1
