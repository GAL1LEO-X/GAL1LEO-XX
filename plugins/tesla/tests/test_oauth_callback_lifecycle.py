"""OAuth callbacks may not commit across a newer owner consent decision."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import socket
import threading
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from tesla_plugin.config import TESLA_SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.oauth import TeslaOAuth
from tesla_plugin.store import Store, digest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("OAuth lifecycle tests must use the synthetic transport")
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)


def tokens(label):
    return {"access_token": "synthetic-" + label,
            "refresh_token": "synthetic-refresh-" + label,
            "expires_in": 3600, "scope": " ".join(TESLA_SCOPES)}


def begin(oauth):
    return parse_qs(urlsplit(oauth.begin("synthetic-owner-session")).query)["state"][0]


def connection(store):
    with store.db() as db:
        row = db.execute("SELECT * FROM connection WHERE id=1").fetchone()
        return dict(row) if row else None


@pytest.mark.parametrize("initially_connected", [False, True])
@pytest.mark.parametrize("change", ["disconnect", "new_consent", "disconnect_then_reconsent"])
def test_late_callback_preserves_new_owner_decision(store, clock, initially_connected, change):
    store.settings = replace(store.settings, live_enabled=True)
    if not initially_connected:
        store.disconnect()
    other = Store(store.settings, clock=clock)
    entered, release = threading.Event(), threading.Event()
    requests = []

    def exchange(request):
        requests.append(request)
        entered.set()
        assert release.wait(5)
        return httpx.Response(200, json=tokens("obsolete-callback"))

    with httpx.Client(transport=httpx.MockTransport(exchange)) as client:
        oauth = TeslaOAuth(store, client)
        state = begin(oauth)
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(oauth.complete, state, "synthetic-code", "synthetic-owner-session")
            try:
                assert entered.wait(3)
                if change in ("disconnect", "disconnect_then_reconsent"):
                    other.disconnect()
                if change in ("new_consent", "disconnect_then_reconsent"):
                    other.set_tokens(tokens("new-consent"), TESLA_SCOPES, "eu")
                expected = connection(other)
                release.set()
                with pytest.raises(TeslaError) as caught:
                    result.result(timeout=3)
                assert caught.value.code == "AUTHORIZATION_CHANGED"
                assert connection(Store(store.settings, clock=clock)) == expected
                assert len(requests) == 1
            finally:
                release.set()


@pytest.mark.parametrize("change", ["disconnect", "new_consent"])
def test_changed_owner_decision_before_callback_does_not_exchange(store, clock, change):
    store.settings = replace(store.settings, live_enabled=True)
    calls = []
    with httpx.Client(transport=httpx.MockTransport(
            lambda request: calls.append(request) or httpx.Response(200, json=tokens("late")))) as client:
        state = begin(TeslaOAuth(store, client))
        other = Store(store.settings, clock=clock)
        if change == "disconnect":
            other.disconnect()
        else:
            other.set_tokens(tokens("new-consent"), TESLA_SCOPES, "eu")
        expected = connection(other)
        with pytest.raises(TeslaError):
            TeslaOAuth(other, client).complete(state, "synthetic-code", "synthetic-owner-session")
        assert calls == []
        assert connection(other) == expected


def test_newer_completed_callback_fences_older_exchange_across_instances(store, clock):
    store.settings = replace(store.settings, live_enabled=True)
    other = Store(store.settings, clock=clock)
    entered, release = threading.Event(), threading.Event()
    calls = []

    def exchange(request):
        code = parse_qs(request.content.decode())["code"][0]
        calls.append(code)
        if code == "old-code":
            entered.set()
            assert release.wait(5)
        return httpx.Response(200, json=tokens(code))

    with httpx.Client(transport=httpx.MockTransport(exchange)) as client:
        old_oauth, new_oauth = TeslaOAuth(store, client), TeslaOAuth(other, client)
        old_state, new_state = begin(old_oauth), begin(new_oauth)
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(old_oauth.complete, old_state, "old-code", "synthetic-owner-session")
            try:
                assert entered.wait(3)
                assert new_oauth.complete(new_state, "new-code", "synthetic-owner-session")["status"] == "connected"
                expected = connection(other)
                release.set()
                with pytest.raises(TeslaError) as caught:
                    result.result(timeout=3)
                assert caught.value.code == "AUTHORIZATION_CHANGED"
                assert connection(other) == expected
                assert store.unseal(expected["tokens"])["access_token"] == "synthetic-new-code"
                assert calls == ["old-code", "new-code"]
            finally:
                release.set()


def test_callback_state_is_single_use_while_exchange_is_in_flight(store, clock):
    store.settings = replace(store.settings, live_enabled=True)
    entered, release = threading.Event(), threading.Event()
    calls = []

    def exchange(request):
        calls.append(request)
        entered.set()
        assert release.wait(5)
        return httpx.Response(200, json=tokens("single-use"))

    with httpx.Client(transport=httpx.MockTransport(exchange)) as client:
        oauth = TeslaOAuth(store, client)
        state = begin(oauth)
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(oauth.complete, state, "synthetic-code", "synthetic-owner-session")
            try:
                assert entered.wait(3)
                with pytest.raises(TeslaError) as caught:
                    TeslaOAuth(Store(store.settings, clock=clock), client).complete(
                        state, "synthetic-code", "synthetic-owner-session")
                assert caught.value.code == "AUTH_STATE_INVALID"
                release.set()
                assert result.result(timeout=3)["status"] == "connected"
                assert len(calls) == 1
            finally:
                release.set()


def test_same_consent_token_rotation_does_not_invalidate_pending_callback(store, clock):
    store.settings = replace(store.settings, live_enabled=True)
    other = Store(store.settings, clock=clock)
    generation = store.connection()["generation"]
    calls = []

    def exchange(request):
        calls.append(request)
        other.set_tokens(tokens("rotation"), TESLA_SCOPES, "eu", generation=generation)
        return httpx.Response(200, json=tokens("new-consent"))

    with httpx.Client(transport=httpx.MockTransport(exchange)) as client:
        oauth = TeslaOAuth(store, client)
        state = begin(oauth)
        assert TeslaOAuth(other, client).complete(state, "synthetic-code", "synthetic-owner-session")["status"] == "connected"
        assert store.connection()["generation"] == generation + 1
        assert store.unseal(store.connection()["tokens"])["access_token"] == "synthetic-new-consent"
        assert len(calls) == 1


def test_unbound_pending_state_requires_new_connect_without_exchange(store, clock):
    store.settings = replace(store.settings, live_enabled=True)
    with store.db() as db:
        db.execute("INSERT INTO oauth_states VALUES(?,?,?,?)", (
            digest("synthetic-legacy-state"), "synthetic-owner-session", clock()+300,
            store.seal("synthetic-legacy-verifier")))
    expected = connection(store)
    calls = []
    with httpx.Client(transport=httpx.MockTransport(
            lambda request: calls.append(request) or httpx.Response(200, json=tokens("legacy")))) as client:
        with pytest.raises(TeslaError) as caught:
            TeslaOAuth(store, client).complete("synthetic-legacy-state", "synthetic-code", "synthetic-owner-session")
        assert caught.value.code == "AUTH_STATE_INVALID"
        assert calls == []
        assert connection(store) == expected


def test_callback_expiry_during_exchange_does_not_commit(store, clock):
    store.settings = replace(store.settings, live_enabled=True)
    expected = connection(store)

    def exchange(_):
        clock.advance(301)
        return httpx.Response(200, json=tokens("expired"))

    with httpx.Client(transport=httpx.MockTransport(exchange)) as client:
        oauth = TeslaOAuth(store, client)
        with pytest.raises(TeslaError) as caught:
            oauth.complete(begin(oauth), "synthetic-code", "synthetic-owner-session")
        assert caught.value.code == "AUTH_STATE_INVALID"
        assert connection(store) == expected
