import base64
import json
from types import SimpleNamespace
import pytest
from starlette.testclient import TestClient

from tesla_plugin.config import SCOPES, TESLA_SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.events import Events
from tesla_plugin.cli import process_batch
from tesla_plugin.server import create_app
from tesla_plugin.store import Store, canonical
from tesla_plugin.telemetry import Telemetry
from tesla_plugin.trigger_catalog import BASE_RULES
from tesla_plugin.triggers import Triggers, preset_id
from test_mcp_portal import rpc, login
from test_telemetry_events import Delivery, payload, subscription
from conftest import VIN


def test_one_delivery_connection_follows_panel_and_chat_choices_without_resubscribing(store, clock, vehicle_ref):
    manager = Triggers(store)
    manager.apply_preset(vehicle_ref, "none", SCOPES, expected_revision=0)
    before = manager.view(vehicle_ref, SCOPES)
    plan = before["delivery_connection"]["subscription_plan"]
    assert plan["available"] and before["delivery_connection"]["state"] == "not_connected"
    delivery = Delivery()
    events = Events(store, transport=delivery)
    result = events.subscribe(plan["name"], plan["arguments"], {
        "url": "https://receiver.example/callback",
        "secret": "whsec_"+base64.b64encode(b"synthetic-signing-key-for-tests!!").decode()
    }, SCOPES, expires_at=clock()+3600)
    after = manager.view(vehicle_ref, SCOPES)
    assert after["revision"] == before["revision"]
    assert [i["enabled"] for i in after["items"]] == [i["enabled"] for i in before["items"]]
    assert after["delivery_connection"]["state"] == "shared"

    def emit(kind):
        clock.advance(1)
        with store.db() as db:
            return Events.emit(db, vehicle_ref, kind, clock(), {}, clock())

    emit("battery_low")
    assert not events.dispatch_one()  # A broad connection never enables events.
    manager.update(vehicle_ref, [{"trigger_id": "event:battery_low", "enabled": True}], SCOPES,
                   expected_revision=after["revision"], source="owner_panel")
    first = emit("battery_low")
    assert events.dispatch_one()
    update(store, vehicle_ref, {"event:battery_low": False, "event:charge_completed": True})
    emit("battery_low")
    second = emit("charge_completed")
    assert events.dispatch_one()
    assert not events.dispatch_one()
    callbacks = [json.loads(body) for _, body, _ in delivery.calls if json.loads(body).get("type") != "verification"]
    assert [c["eventId"] for c in callbacks] == [first, second]
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM subscriptions").fetchone()[0] == 1
        assert db.execute("SELECT id FROM subscriptions").fetchone()[0] == result["id"]
        assert db.execute("SELECT count(*) FROM intents").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM snapshots").fetchone()[0] == 0
    assert manager.view(vehicle_ref, SCOPES)["delivery_connection"]["future_selection_covered"]
    clock.advance(3600)
    assert manager.view(vehicle_ref, SCOPES)["delivery_connection"]["state"] == "not_connected"


def test_connection_plan_respects_permissions_and_reports_existing_narrow_filters(store, clock, vehicle_ref):
    from tesla_plugin.trigger_catalog import LOCATION_EVENTS
    manager = Triggers(store)
    scopes = tuple(s for s in SCOPES if s != "tesla:location")
    events = Events(store, transport=Delivery())
    plan = manager.view(vehicle_ref, scopes)["delivery_connection"]["subscription_plan"]
    assert not set(plan["arguments"]["kinds"]) & LOCATION_EVENTS
    assert events.filters(plan["arguments"], scopes) == plan["arguments"]
    assert not manager.view(vehicle_ref, ("tesla:read",))["delivery_connection"]["subscription_plan"]["available"]
    subscription(events, vehicle_ref, clock)
    assert manager.view(vehicle_ref, scopes)["delivery_connection"]["state"] == "partial"
    manager.apply_preset(vehicle_ref, "none", SCOPES, expected_revision=0)
    update(store, vehicle_ref, {"event:battery_low": True})
    connection = manager.view(vehicle_ref, scopes)["delivery_connection"]
    assert connection["state"] == "selected_only" and connection["selected_kinds_covered"]
    assert not connection["future_selection_covered"]


def update(store, ref, changes, *, scopes=SCOPES, batch_seconds=None):
    manager = Triggers(store)
    return manager.update(ref, [{"trigger_id": key, "enabled": enabled} for key, enabled in changes.items()], scopes,
                          expected_revision=manager.view(ref, scopes)["revision"], batch_seconds=batch_seconds)


def event_data(store, kind="telemetry_changed"):
    with store.db() as db:
        return [json.loads(row[0]) for row in db.execute("SELECT data FROM events WHERE name=? ORDER BY occurred", (kind,))]


def test_base_presets_and_full_documented_catalogue_are_durable(store, settings, vehicle_ref):
    view = Triggers(store).view(vehicle_ref, SCOPES)
    fields = [i for i in view["items"] if i["id"].startswith("field:")]
    assert len(fields) == 239 and not any(i["enabled"] for i in fields)
    assert {i["label"] for i in view["items"] if i.get("preset")} == set(BASE_RULES)
    assert all(i["enabled"] for i in view["items"] if i.get("preset"))
    assert not view["subscription_active"] and not view["chatgpt_processing_verified"]
    update(store, vehicle_ref, {"field:InsideTemp": True, "event:battery_low": False})
    restarted = Store(settings, clock=store.clock)
    assert Triggers(restarted).view(vehicle_ref, SCOPES) == Triggers(store).view(vehicle_ref, SCOPES)
    store.save_vehicles([{"vin": VIN, "display_name": "the vehicle"}])
    assert not next(i for i in Triggers(store).view(vehicle_ref, SCOPES)["items"] if i["id"] == "event:battery_low")["enabled"]


def test_default_battery_rule_emits_without_manual_rule_configuration(store, clock, vehicle_ref):
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 25}))
    clock.advance(10)
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 19}))
    assert len(event_data(store, "battery_low")) == 1


def test_selected_changes_batch_transients_and_persist_across_restart(store, clock, vehicle_ref, settings):
    update(store, vehicle_ref, {"field:InsideTemp": True}, batch_seconds=30)
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"InsideTemp": 20, "OutsideTemp": 10}))
    for value in [21, 20, 20]:
        clock.advance(5)
        telemetry.ingest("V", payload(clock, {"InsideTemp": value, "OutsideTemp": 11}))
    telemetry.ingest("V", payload(clock, {"InsideTemp": 9}, when=clock()-10))  # old replay
    assert event_data(store) == []
    clock.advance(15)
    Telemetry(Store(settings, clock=clock)).tick()
    [event] = event_data(store)
    [field] = event["changes"]
    assert field == "InsideTemp"
    assert event["changes"][field]["before"] is None  # initial observation, not an invented change
    assert event["changes"][field]["after"]["value"] == 20
    assert event["changes"][field]["count"] == 3  # duplicate values are not changes
    assert event["physical_continuity_guaranteed"] is False
    assert event["intermediate_samples_in_history"] is True
    telemetry.tick()
    assert len(event_data(store)) == 1


def test_quality_conflicts_and_restoration_are_events_without_fabricated_values(store, clock, vehicle_ref):
    update(store, vehicle_ref, {"field:InsideTemp": True}, batch_seconds=10)
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"InsideTemp": 20}))
    telemetry.ingest("V", payload(clock, {"InsideTemp": 30}))
    clock.advance(10)
    telemetry.tick()
    assert event_data(store)[0]["changes"]["InsideTemp"]["after"]["quality"] == "time_conflict"
    telemetry.ingest("V", payload(clock, {"InsideTemp": None}))
    clock.advance(10)
    telemetry.tick()
    assert event_data(store)[1]["changes"]["InsideTemp"]["after"]["value"] is None
    telemetry.ingest("V", payload(clock, {"InsideTemp": 22}))
    clock.advance(10)
    telemetry.tick()
    assert event_data(store)[2]["changes"]["InsideTemp"]["after"]["quality"] == "valid"


def test_disabled_trigger_cancels_queue_and_does_not_replay_when_reenabled(store, clock, vehicle_ref):
    delivery = Delivery()
    events = Events(store, transport=delivery)
    subscription(events, vehicle_ref, clock)
    with store.db() as db:
        Events.emit(db, vehicle_ref, "battery_low", clock(), {}, clock())
    update(store, vehicle_ref, {"event:battery_low": False})
    assert not events.dispatch_one()
    update(store, vehicle_ref, {"event:battery_low": True})
    assert not events.dispatch_one()
    assert len(delivery.calls) == 1
    with store.db() as db:
        assert db.execute("SELECT state FROM deliveries").fetchone()[0] == "cancelled"


def test_disabled_field_removes_buffer_and_cancels_immutable_batch(store, clock, vehicle_ref):
    delivery = Delivery()
    events = Events(store, transport=delivery)
    _, _, secret = subscription(events, vehicle_ref, clock)
    events.subscribe("tesla.vehicle_event", {"vehicle_ref": vehicle_ref, "kinds": ["telemetry_changed"]},
                     {"url": "https://receiver.example/changes", "secret": secret}, SCOPES, expires_at=clock()+3600)
    update(store, vehicle_ref, {"field:InsideTemp": True}, batch_seconds=10)
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"InsideTemp": 20}))
    clock.advance(10)
    telemetry.tick()
    delivery.status = 503
    assert events.dispatch_one()  # Freeze exact bytes before a failed delivery.
    telemetry.ingest("V", payload(clock, {"InsideTemp": 25}))
    update(store, vehicle_ref, {"field:InsideTemp": False})
    clock.advance(10)
    telemetry.tick()
    assert len(event_data(store)) == 1
    assert not events.dispatch_one()
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM trigger_buffer").fetchone()[0] == 0


def test_location_is_separate_from_general_events_and_rechecked_on_delivery(store, clock, vehicle_ref):
    delivery = Delivery()
    events = Events(store, transport=delivery)
    _, _, secret = subscription(events, vehicle_ref, clock)
    events.subscribe("tesla.vehicle_event", {"vehicle_ref": vehicle_ref, "kinds": ["location_changed", "telemetry_changed"]},
                     {"url": "https://receiver.example/changes", "secret": secret}, SCOPES, expires_at=clock()+3600)
    update(store, vehicle_ref, {"field:Location": True, "field:InsideTemp": True}, batch_seconds=10)
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"Location": {"latitude": 48.2, "longitude": 16.3}, "InsideTemp": 22}))
    clock.advance(10)
    telemetry.tick()
    assert set(event_data(store)[0]["changes"]) == {"InsideTemp"}
    assert set(event_data(store, "location_changed")[0]["changes"]) == {"Location"}
    with store.db() as db:
        db.execute("UPDATE vehicles SET data=?", (canonical({"granular_access": {"hide_private": True}}),))
    while events.dispatch_one():
        pass
    posted = [json.loads(body) for _, body, _ in delivery.calls if json.loads(body).get("eventId")]
    assert [item["data"]["kind"] for item in posted] == ["telemetry_changed"]


@pytest.mark.parametrize("scopes", [["tesla:read"], ["tesla:read", "tesla:manage"]])
def test_scope_failures_are_atomic_and_disabling_location_remains_possible(store, vehicle_ref, scopes):
    before = Triggers(store).view(vehicle_ref, SCOPES)
    with pytest.raises(TeslaError):
        update(store, vehicle_ref, {"field:InsideTemp": True, "field:Location": True}, scopes=scopes)
    assert Triggers(store).view(vehicle_ref, SCOPES) == before
    if "tesla:manage" in scopes:
        update(store, vehicle_ref, {"field:Location": True})
        update(store, vehicle_ref, {"field:Location": False}, scopes=scopes)


def test_rule_pause_reenable_starts_fresh_and_shared_revision_changes(store, clock, vehicle_ref):
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 25}))
    rule = preset_id(vehicle_ref, "battery_low")
    update(store, vehicle_ref, {"rule:"+rule: False})
    clock.advance(10)
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 19}))
    update(store, vehicle_ref, {"rule:"+rule: True})
    clock.advance(10)
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 18}))
    assert not event_data(store, "battery_low")
    revision = Triggers(store).view(vehicle_ref, SCOPES)["revision"]
    telemetry.configure_rule(vehicle_ref, "battery_low", {"threshold": 15}, rule_id=rule)
    assert Triggers(store).view(vehicle_ref, SCOPES)["revision"] == revision+1


def test_new_tables_removed_on_revocation_disconnect_and_new_grant_pauses_them(store, vehicle_ref):
    update(store, vehicle_ref, {"field:InsideTemp": True})
    store.set_tokens({"access_token": "synthetic-new", "refresh_token": "synthetic-refresh", "expires_in": 3600}, TESLA_SCOPES, "eu")
    store.save_vehicles([{"vin": VIN, "display_name": "the vehicle"}])
    assert not any(i["enabled"] for i in Triggers(store).view(vehicle_ref, SCOPES)["items"])
    store.save_vehicles([])
    for table in ("trigger_settings", "trigger_preferences", "trigger_buffer", "trigger_audit"):
        with store.db() as db:
            assert db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
    store.disconnect()


def test_without_subscription_events_stay_local_and_reconnect_does_not_replay_them(store, clock, vehicle_ref):
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 25}))
    clock.advance(5)
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 19}))
    assert len(event_data(store, "battery_low")) == 1
    delivery = Delivery()
    events = Events(store, transport=delivery)
    subscription(events, vehicle_ref, clock)
    assert not events.dispatch_one()
    assert len(delivery.calls) == 1  # No replay masquerading as a fresh event.


def test_old_changes_are_history_and_not_fresh_batches_after_downtime(store, clock, vehicle_ref):
    update(store, vehicle_ref, {"field:InsideTemp": True}, batch_seconds=10)
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"InsideTemp": 20}, when=clock()-400))
    clock.advance(10)
    telemetry.tick()
    assert event_data(store) == []
    telemetry.ingest("V", payload(clock, {"InsideTemp": 25}))
    clock.advance(301)  # Receiver/worker down long enough to lose freshness.
    telemetry.tick()
    assert event_data(store) == []
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM samples").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM trigger_buffer").fetchone()[0] == 0


def test_maximum_batch_interval_tolerates_worker_scheduling_delay(store, clock, vehicle_ref):
    update(store, vehicle_ref, {"field:InsideTemp": True}, batch_seconds=300)
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"InsideTemp": 20}))
    clock.advance(302)
    telemetry.tick()
    assert len(event_data(store)) == 1


def test_missing_membership_pauses_delivery_then_expires_old_queue(store, clock, vehicle_ref):
    events = Events(store, transport=Delivery())
    subscription(events, vehicle_ref, clock)
    with store.db() as db:
        Events.emit(db, vehicle_ref, "battery_low", clock(), {}, clock())
    clock.advance(301)
    assert not events.dispatch_one()
    assert not Triggers(store).view(vehicle_ref, SCOPES)["membership_fresh"]
    clock.advance(600)
    with store.db() as db:
        db.execute("UPDATE vehicles SET checked=?", (clock(),))
    assert events.dispatch_one()
    with store.db() as db:
        assert db.execute("SELECT state FROM deliveries").fetchone()[0] == "expired"
    assert len(events.transport.calls) == 1


def test_missing_tesla_connection_does_not_deliver_or_flush(store, clock, vehicle_ref):
    events = Events(store, transport=Delivery())
    subscription(events, vehicle_ref, clock)
    update(store, vehicle_ref, {"field:InsideTemp": True}, batch_seconds=10)
    Telemetry(store).ingest("V", payload(clock, {"InsideTemp": 20}))
    with store.db() as db:
        Events.emit(db, vehicle_ref, "battery_low", clock(), {}, clock())
        db.execute("UPDATE connection SET status='disconnected'")
    clock.advance(10)
    Telemetry(store).tick()
    assert not events.dispatch_one() and event_data(store) == []
    view = Triggers(store).view(vehicle_ref, SCOPES)
    assert not view["tesla_connected"]
    update(store, vehicle_ref, {"field:InsideTemp": False})
    with pytest.raises(TeslaError, match="Reconnect"):
        update(store, vehicle_ref, {"field:InsideTemp": True})
    class Consumer:
        def commit(self, offsets):
            pytest.fail("A missing connection must not acknowledge the source record")
    record = SimpleNamespace(value=canonical(payload(clock, {"InsideTemp": 25})).encode(), key=VIN.encode(),
                             headers=[("vin", VIN.encode()), ("txtype", b"V")], topic="tesla_V", partition=0, offset=1)
    with pytest.raises(TeslaError, match="Connect"):
        process_batch(Consumer(), Telemetry(store), [record])


def test_location_permission_revoked_before_batch_flush_is_not_disclosed(store, clock, vehicle_ref):
    update(store, vehicle_ref, {"field:Location": True}, batch_seconds=10)
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"Location": {"latitude": 48.2, "longitude": 16.3}}))
    with store.db() as db:
        db.execute("UPDATE connection SET scopes=?", (canonical([s for s in TESLA_SCOPES if s != "vehicle_location"]),))
    clock.advance(10)
    telemetry.tick()
    assert event_data(store, "location_changed") == []
    assert not next(i for i in Triggers(store).view(vehicle_ref, SCOPES)["items"] if i["id"] == "field:Location")["available"]


def test_duplicate_frames_and_restarts_do_not_multiply_batches(store, clock, vehicle_ref):
    update(store, vehicle_ref, {"field:InsideTemp": True}, batch_seconds=10)
    telemetry = Telemetry(store)
    frame = payload(clock, {"InsideTemp": 20})
    telemetry.ingest("V", frame)
    telemetry.ingest("V", frame | {"isResend": True})
    Telemetry(store).ingest("V", frame)
    clock.advance(10)
    Telemetry(store).tick()
    Telemetry(store).tick()
    assert len(event_data(store)) == 1
    assert event_data(store)[0]["changes"]["InsideTemp"]["count"] == 1


def test_batch_retry_preserves_exact_identity_and_never_claims_display(store, clock, vehicle_ref):
    delivery = Delivery()
    events = Events(store, transport=delivery)
    _, _, secret = subscription(events, vehicle_ref, clock)
    events.subscribe("tesla.vehicle_event", {"vehicle_ref": vehicle_ref, "kinds": ["telemetry_changed"]},
                     {"url": "https://receiver.example/changes", "secret": secret}, SCOPES, expires_at=clock()+3600)
    update(store, vehicle_ref, {"field:InsideTemp": True}, batch_seconds=10)
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"InsideTemp": 20}))
    clock.advance(10)
    telemetry.tick()
    delivery.status = 503
    assert events.dispatch_one()
    body = delivery.calls[-1][1]
    clock.advance(3)
    delivery.status = 200
    assert Events(store, transport=delivery).dispatch_one()
    assert body == delivery.calls[-1][1]
    status = Triggers(store).view(vehicle_ref, SCOPES)
    assert status["deliveries_last_24h"]["accepted"] == 1
    assert not status["chatgpt_processing_verified"]


def test_schema_one_upgrade_preserves_user_rule_and_other_settings(store, settings, vehicle_ref):
    telemetry = Telemetry(store)
    rule = preset_id(vehicle_ref, "battery_low")
    telemetry.configure_rule(vehicle_ref, "battery_low", {"threshold": 17}, rule_id=rule)
    with store.db() as db:
        for table in ("trigger_settings", "trigger_preferences", "trigger_buffer", "trigger_audit"):
            db.execute(f"DROP TABLE {table}")
        db.execute("UPDATE meta SET value='1' WHERE key='schema'")
    migrated = Store(settings, clock=store.clock)
    with migrated.db() as db:
        assert db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()[0] == "3"
        configs = [json.loads(r[0]) for r in db.execute("SELECT config FROM rules WHERE kind='battery_low'")]
        assert len(configs) == 1 and configs[0]["threshold"] == 17


@pytest.mark.integration
def test_mcp_and_panel_share_selection_and_reject_stale_form_without_tesla_calls(settings, service, fleet, store, headers, vehicle_ref):
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        csrf = login(client)
        path = "/tesla/owner/triggers/"+vehicle_ref
        assert client.get(path).status_code == 200
        def tool(name, arguments, scopes=SCOPES):
            return rpc(client, headers(scopes=scopes), "tools/call", {"name": name, "arguments": arguments}).json()["result"]
        arguments = {"vehicle_ref": vehicle_ref, "category": "Climate"}
        listed = tool("tesla_list_triggers", arguments)["structuredContent"]
        revision = listed["revision"]
        change = {"vehicle_ref": vehicle_ref, "expected_revision": revision,
                  "changes": [{"trigger_id": "field:InsideTemp", "enabled": True}]}
        denied = tool("tesla_update_triggers", change, scopes=["tesla:read"])
        assert denied["isError"] and "tesla:manage" in str(denied["_meta"])
        changed = tool("tesla_update_triggers", change)["structuredContent"]
        assert changed["changed"] == {"field:InsideTemp": True}
        page = client.get(path)
        assert 'value="field:InsideTemp" checked' in page.text
        stale = client.post(path, data={"csrf": csrf, "revision": str(revision), "category": "Climate", "selection": "none"},
                            headers={"origin": "https://bridge.example"})
        assert stale.status_code == 409
        assert client.post(path, data={"csrf": "fake", "revision": changed["revision"], "category": "Climate", "selection": "none"},
                           headers={"origin": "https://bridge.example"}).status_code == 400
        saved = client.post(path, data={"csrf": csrf, "revision": changed["revision"], "category": "Climate", "selection": "none"},
                            headers={"origin": "https://bridge.example"})
        assert saved.status_code == 200 and "Selection saved" in saved.text
        items = tool("tesla_list_triggers", arguments)["structuredContent"]["items"]
        assert not next(i for i in items if i["id"] == "field:InsideTemp")["enabled"]
        assert not fleet.calls
        with store.db() as db:
            assert [r[0] for r in db.execute("SELECT source FROM trigger_audit ORDER BY revision")] == ["chatgpt", "owner_panel"]


@pytest.mark.integration
def test_generic_event_access_does_not_expose_location_or_require_location_scope(settings, service, store, clock, headers, vehicle_ref):
    update(store, vehicle_ref, {"field:InsideTemp": True, "field:Location": True}, batch_seconds=10)
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"InsideTemp": 20, "Location": {"latitude": 48.2, "longitude": 16.3}}))
    clock.advance(10)
    telemetry.tick()
    with store.db() as db:
        ids = {r["name"]: r["id"] for r in db.execute("SELECT id,name FROM events")}
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        for kind in ("telemetry_changed", "location_changed"):
            result = rpc(client, headers(scopes=["tesla:read"]), "tools/call", {"name": "tesla_get_event", "arguments": {"event_id": ids[kind]}}).json()["result"]
            assert bool(result.get("isError")) == (kind == "location_changed")


@pytest.mark.integration
def test_event_evidence_is_paginated_and_large_values_need_explicit_history_read(settings, service, store, clock, headers, vehicle_ref):
    fields = ("InsideTemp", "OutsideTemp", "Version")
    update(store, vehicle_ref, {"field:"+field: True for field in fields}, batch_seconds=10)
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"InsideTemp": 20, "OutsideTemp": 10, "Version": "x"*3000}))
    clock.advance(10)
    telemetry.tick()
    with store.db() as db:
        event_id = db.execute("SELECT id FROM events WHERE name='telemetry_changed'").fetchone()[0]
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        def page(offset):
            return rpc(client, headers(), "tools/call", {"name": "tesla_get_event", "arguments": {
                "event_id": event_id, "offset": offset, "limit": 2}}).json()["result"]["structuredContent"]["data"]
        first = page(0)
        assert set(first["changes"]) == {"InsideTemp", "OutsideTemp"}
        assert first["changes_total"] == 3 and first["next_offset"] == 2
        last = page(2)
        observation = last["changes"]["Version"]["after"]
        assert last["next_offset"] is None and observation["value_omitted"]
        assert "value" not in observation and observation["retrieve_with"] == "tesla_get_history"
        assert event_data(store)[0]["changes"]["Version"]["after"]["value"] == "x"*3000
