"""Queued-event access checks with a real Fleet client and synthetic transports."""
import base64
from dataclasses import replace
import json

import httpx
import pytest
from starlette.testclient import TestClient

from tesla_plugin.catalogue import operation
from tesla_plugin.config import SCOPES, TESLA_SCOPES
from tesla_plugin.delivery_access import DeliveryAccess, STATE_KEY
from tesla_plugin.events import Events
from tesla_plugin.fleet import Fleet
from tesla_plugin.server import create_app
from tesla_plugin.service import Service
from tesla_plugin.store import canonical
from tesla_plugin.triggers import Triggers
from conftest import VIN
from test_mcp_portal import login, rpc
from test_telemetry_events import Delivery, subscription


@pytest.fixture
def rig(store, clock, vehicle_ref):
    store.settings = replace(store.settings, live_enabled=True)
    requests = []
    data = store.vehicle(vehicle_ref)["data"] | {"state": "offline"}
    def response(request):
        assert request.method == "GET" and request.url.path == "/api/1/vehicles"
        requests.append(request)
        return httpx.Response(200, json={"response": [data]})
    holder = {"response": response, "requests": requests, "data": data}
    fleet = Fleet(store, transport=httpx.MockTransport(lambda r: holder["response"](r)))
    service = Service(store.settings, store=store, fleet=fleet)
    transport = Delivery()
    events = Events(store, transport=transport, access_check=DeliveryAccess(service))
    result, filters, secret = subscription(events, vehicle_ref, clock)
    holder.update(store=store, fleet=fleet, service=service, transport=transport, events=events,
                  ref=vehicle_ref, subscription=result, filters=filters, secret=secret)
    yield holder
    fleet.close()


def enable(rig, value=True):
    manager = Triggers(rig["store"])
    view = manager.view(rig["ref"], SCOPES)
    return manager.update(rig["ref"], [], SCOPES, expected_revision=view["revision"], automatic_access_checks=value)


def emit(rig, *, occurred=None, kind="battery_low", value=19):
    now = rig["store"].clock()
    with rig["store"].db() as db:
        return Events.emit(db, rig["ref"], kind, now if occurred is None else occurred, {"synthetic": True, "value": value}, now)


def callbacks(rig):
    return [json.loads(b) for _, b, _ in rig["transport"].calls if json.loads(b).get("type") != "verification"]


def test_manual_default_and_enabling_do_not_make_network_calls(rig, clock):
    clock.advance(301)
    emit(rig)
    assert not rig["events"].dispatch_one()
    assert not Triggers(rig["store"]).view(rig["ref"], SCOPES)["delivery_access"]["automatic"]
    enable(rig)
    assert rig["requests"] == [] and callbacks(rig) == []


def test_stale_access_is_checked_once_for_queued_events_without_waking_offline_car(rig, clock):
    enable(rig)
    before = Triggers(rig["store"]).view(rig["ref"], SCOPES)
    # Fresh membership needs no REST request, even with the option enabled.
    emit(rig)
    assert rig["events"].dispatch_one() and rig["requests"] == []
    clock.advance(301)
    first = emit(rig)
    assert rig["events"].dispatch_one()
    clock.advance(1)
    second = emit(rig)
    assert rig["events"].dispatch_one()
    assert len(rig["requests"]) == 1 and rig["requests"][0].url.params["page"] == "1"
    assert rig["requests"][0].url.params["per_page"] == "100"
    assert [c["eventId"] for c in callbacks(rig)][-2:] == [first, second]
    assert rig["store"].vehicle(rig["ref"])["data"]["state"] == "offline"
    after = Triggers(rig["store"]).view(rig["ref"], SCOPES)
    assert after["revision"] == before["revision"] and after["batch_seconds"] == before["batch_seconds"]
    assert [(i["id"], i["enabled"]) for i in after["items"]] == [(i["id"], i["enabled"]) for i in before["items"]]
    assert after["delivery_access"]["last_result"] == "verified" and after["membership_fresh"]
    with rig["store"].db() as db:
        assert db.execute("SELECT COUNT(*) FROM intents").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM requests WHERE category='free'").fetchone()[0] == 1
    clock.advance(301)
    assert not rig["events"].dispatch_one() and len(rig["requests"]) == 1  # empty queue, no polling


@pytest.mark.parametrize("case", ["empty", "disabled", "expired_event", "future_event", "expired_subscription", "no_live", "scope", "tariff"])
def test_ineligible_events_or_access_never_start_provider_checks(rig, clock, monkeypatch, case):
    enable(rig)
    clock.advance(301)
    if case == "disabled":
        manager = Triggers(rig["store"])
        manager.apply_preset(rig["ref"], "none", SCOPES, expected_revision=1)
    if case == "no_live":
        rig["store"].settings = replace(rig["store"].settings, live_enabled=False)
    if case == "scope":
        with rig["store"].db() as db:
            db.execute("UPDATE connection SET scopes=?", (canonical([s for s in TESLA_SCOPES if s != "vehicle_device_data"]),))
    if case == "tariff":
        monkeypatch.setattr("tesla_plugin.delivery_access.operation", lambda _: operation("vehicle_list") | {"pricing_category": "data"})
    if case != "empty":
        emit(rig, occurred=clock()-901 if case == "expired_event" else clock()+1 if case == "future_event" else None)
    if case == "expired_subscription":
        clock.advance(3601)
    rig["events"].dispatch_one()
    assert rig["requests"] == [] and callbacks(rig) == []


def test_failed_checks_back_off_and_rate_limit_survives_restart_and_new_events(rig, clock):
    enable(rig)
    clock.advance(301)
    calls = []
    def unavailable(request):
        calls.append(request)
        raise httpx.ConnectError("synthetic network interruption")
    rig["response"] = unavailable
    event = emit(rig)
    assert not rig["events"].dispatch_one() and len(calls) == 1
    for _ in range(3):
        clock.advance(10)
        emit(rig)
        assert not rig["events"].dispatch_one()
    assert len(calls) == 1
    clock.advance(30)
    rig["events"] = Events(rig["store"], transport=rig["transport"], access_check=DeliveryAccess(rig["service"]))
    assert not rig["events"].dispatch_one() and len(calls) == 2
    clock.advance(120)
    assert not rig["events"].dispatch_one() and len(calls) == 3
    for _ in range(10):
        clock.advance(30)
        emit(rig)
        rig["events"].dispatch_one()
    assert len(calls) == 3 and callbacks(rig) == []
    with rig["store"].db() as db:
        assert db.execute("SELECT attempts FROM deliveries WHERE event=?", (event,)).fetchone()[0] == 0
        state = json.loads(db.execute("SELECT value FROM meta WHERE key=?", (STATE_KEY,)).fetchone()[0])
        assert state["failures"] == 3 and state["error"] == "PROVIDER_UNAVAILABLE"
    # A fresh event can recover after the bounded failure window. Old events
    # expire; no wake or command is replayed to compensate for the outage.
    clock.advance(421)
    rig["response"] = lambda request: httpx.Response(200, json={"response": [rig["data"]]})
    current = emit(rig)
    for _ in range(30):
        rig["events"].dispatch_one()
    assert current in [c["eventId"] for c in callbacks(rig)]
    assert event not in [c["eventId"] for c in callbacks(rig)]


@pytest.mark.parametrize("change", ["selector", "subscription", "revoked", "new_consent", "event_expired"])
def test_delivery_revalidates_after_network_gap_and_does_not_restore_old_consent(rig, clock, change):
    enable(rig)
    clock.advance(301)
    emit(rig)
    def mutate(request):
        if change == "selector":
            Triggers(rig["store"]).apply_preset(rig["ref"], "none", SCOPES, expected_revision=1)
        if change == "subscription":
            rig["events"].unsubscribe("tesla.vehicle_event", rig["filters"], "https://receiver.example/callback", SCOPES)
        if change == "new_consent":
            rig["store"].set_tokens({"access_token": "synthetic-new", "refresh_token": "synthetic-renew", "expires_in": 3600}, TESLA_SCOPES, "eu")
        if change == "event_expired":
            clock.advance(901)
        return httpx.Response(200, json={"response": [] if change == "revoked" else [rig["data"]]})
    rig["response"] = mutate
    rig["events"].dispatch_one()
    assert callbacks(rig) == []
    with rig["store"].db() as db:
        assert db.execute("SELECT COUNT(*) FROM deliveries WHERE state='accepted'").fetchone()[0] == 0
        if change == "new_consent":
            assert db.execute("SELECT active FROM vehicles").fetchone()[0] == 0


def test_account_lease_prevents_concurrent_provider_check(rig, clock):
    enable(rig)
    clock.advance(301)
    emit(rig)
    second = DeliveryAccess(rig["service"])
    def concurrent(request):
        assert second.check(rig["ref"]) > clock()
        return httpx.Response(200, json={"response": [rig["data"]]})
    rig["response"] = concurrent
    assert rig["events"].dispatch_one()
    with rig["store"].db() as db:
        state = json.loads(db.execute("SELECT value FROM meta WHERE key=?", (STATE_KEY,)).fetchone()[0])
        assert len(state["attempts"]) == 1


def test_paginated_checks_are_bounded_and_partial_inventory_never_replaces_membership(rig, clock):
    enable(rig)
    clock.advance(301)
    old = rig["store"].vehicle(rig["ref"])["checked"]
    emit(rig)
    pages = []
    def full_page(request):
        pages.append(int(request.url.params["page"]))
        return httpx.Response(200, json={"response": [rig["data"]]*100})
    rig["response"] = full_page
    assert not rig["events"].dispatch_one()
    assert pages == [1, 2, 3] and rig["store"].vehicle(rig["ref"])["checked"] == old
    assert callbacks(rig) == []


def test_pagination_stops_before_using_a_new_account_consent(rig, clock):
    enable(rig)
    clock.advance(301)
    emit(rig)
    pages = []
    def new_consent(request):
        pages.append(int(request.url.params["page"]))
        rig["store"].set_tokens({"access_token": "synthetic-new", "refresh_token": "synthetic-renew", "expires_in": 3600}, TESLA_SCOPES, "eu")
        return httpx.Response(200, json={"response": [rig["data"]]*100})
    rig["response"] = new_consent
    assert not rig["events"].dispatch_one()
    assert pages == [1] and callbacks(rig) == []


def test_presets_preserve_explicit_access_choice_and_new_consent_does_not_inherit_it(rig):
    from tesla_plugin.store import Store
    enable(rig)
    restarted = Store(rig["store"].settings, clock=rig["store"].clock)
    manager = Triggers(restarted)
    result = manager.apply_preset(rig["ref"], "none", SCOPES, expected_revision=1)
    assert result["delivery_access"]["automatic"]
    manager.apply_preset(rig["ref"], "recommended", SCOPES, expected_revision=2)
    assert manager.view(rig["ref"], SCOPES)["delivery_access"]["automatic"]
    rig["store"].set_tokens({"access_token": "synthetic-new", "refresh_token": "synthetic-renew", "expires_in": 3600}, TESLA_SCOPES, "eu")
    rig["store"].save_vehicles([rig["data"]])
    assert not manager.view(rig["ref"], SCOPES)["delivery_access"]["automatic"]


def test_missing_device_scope_blocks_even_a_fresh_cached_delivery(rig):
    emit(rig)
    with rig["store"].db() as db:
        db.execute("UPDATE connection SET scopes=?", (canonical([s for s in TESLA_SCOPES if s != "vehicle_device_data"]),))
    assert not rig["events"].dispatch_one()
    assert rig["requests"] == [] and callbacks(rig) == []


def test_panel_and_chat_share_opt_in_revision_and_preserve_selection(rig, headers):
    manager = Triggers(rig["store"])
    before = manager.view(rig["ref"], SCOPES)
    with TestClient(create_app(rig["store"].settings, service=rig["service"], start_worker=False), base_url="https://bridge.example") as client:
        csrf = login(client)
        path = "/tesla/owner/triggers/"+rig["ref"]
        args = {"vehicle_ref": rig["ref"], "expected_revision": 0, "automatic_access_checks": True}
        denied = rpc(client, headers(scopes=["tesla:read"]), "tools/call", {"name": "tesla_update_triggers", "arguments": args}).json()["result"]
        assert denied["isError"]
        changed = rpc(client, headers(), "tools/call", {"name": "tesla_update_triggers", "arguments": args}).json()["result"]
        assert not changed.get("isError")
        assert changed["structuredContent"]["delivery_access"]["automatic"]
        html = client.get(path).text
        assert 'name="automatic_access_checks" value="true" checked' in html
        form = {"csrf": csrf, "revision": "0", "category": "delivery_access"}
        assert client.post(path, data=form, headers={"origin": "https://bridge.example"}).status_code == 409
        form["revision"] = "1"
        assert client.post(path, data=form, headers={"origin": "https://attacker.invalid"}).status_code == 400
        assert client.post(path, data=form, headers={"origin": "https://bridge.example"}).status_code == 200
        after = manager.view(rig["ref"], SCOPES)
        assert after["revision"] == 2 and not after["delivery_access"]["automatic"]
        assert after["batch_seconds"] == before["batch_seconds"]
        assert [(i["id"], i["enabled"]) for i in after["items"]] == [(i["id"], i["enabled"]) for i in before["items"]]
    assert rig["requests"] == [] and callbacks(rig) == []


def test_renewal_and_retry_keep_one_subscription_and_one_event_identity(rig, clock):
    emit(rig)
    rig["transport"].status = 503
    assert rig["events"].dispatch_one()
    clock.advance(3)
    secret = "whsec_"+base64.b64encode(b"synthetic-second-signing-key-0000").decode()
    renewed = rig["events"].subscribe("tesla.vehicle_event", rig["filters"],
        {"url": "https://receiver.example/callback", "secret": secret}, SCOPES, expires_at=clock()+3600)
    assert renewed["id"] == rig["subscription"]["id"]
    rig["transport"].status = 200
    assert rig["events"].dispatch_one() and not rig["events"].dispatch_one()
    bodies = callbacks(rig)
    assert len(bodies) == 2 and bodies[0] == bodies[1]  # at-least-once, same deduplication key
    with rig["store"].db() as db:
        assert db.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM deliveries WHERE state='accepted'").fetchone()[0] == 1
    assert rig["requests"] == []
