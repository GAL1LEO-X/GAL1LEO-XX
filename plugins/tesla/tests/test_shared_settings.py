"""Web/MCP parity, explicit collection review and economical event selection."""
import json
from dataclasses import replace

import pytest
from starlette.testclient import TestClient

from tesla_plugin.collection import Collection, CREATE, DELETE
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.server import create_app
from tesla_plugin.telemetry import Telemetry
from tesla_plugin.triggers import Triggers, RECOMMENDED_EVENTS, preset_id
from test_collection import prepared_service
from test_mcp_portal import login, rpc


def call(client, headers, name, **arguments):
    result = rpc(client, headers, "tools/call", {"name": name, "arguments": arguments}).json()["result"]
    assert not result.get("isError"), result
    return result["structuredContent"]


def test_cost_preview_is_local_and_all_modes_are_available(prepared_service, fleet, vehicle_ref, headers):
    with TestClient(create_app(prepared_service.settings, service=prepared_service, start_worker=False), base_url="https://bridge.example") as client:
        state = call(client, headers(), "tesla_get_collection", vehicle_ref=vehicle_ref)
        assert state["last_request"] is None
        assert set(state["presets"]) == {
            "normal", "travel", "charging", "diagnostic", "on_demand",
            "recommended", "essential", "notifications", "journeys", "comfort",
            "drive_diagnostics", "full", "custom",
        }
        for mode, count in (("recommended", 7), ("on_demand", 0), ("full", 234)):
            scenario = call(client, headers(), "tesla_estimate_collection", vehicle_ref=vehicle_ref, preset=mode)
            assert len(scenario["fields"]) == count
            assert scenario["estimate"]["billing_cap"] is False
            assert scenario["customer_alerts"] == (mode == "recommended")
            assert scenario["estimate"]["estimated_gross_usd"] >= 0
        assert fleet.calls == []
        with prepared_service.store.db() as db:
            assert db.execute("SELECT COUNT(*) FROM intents").fetchone()[0] == 0


def test_chat_catalogue_and_custom_timings_match_the_editor(prepared_service, fleet, vehicle_ref, headers):
    from tesla_plugin.collection_catalog import field_info
    from tesla_plugin.telemetry import FIELD_MAP
    with TestClient(create_app(prepared_service.settings, service=prepared_service, start_worker=False), base_url="https://bridge.example") as client:
        items, offset = [], 0
        while offset is not None:
            result = call(client, headers(), "tesla_get_collection", vehicle_ref=vehicle_ref,
                          include_catalog=True, catalog_offset=offset, catalog_limit=100)
            items.extend(result["catalog"]["items"])
            offset = result["catalog"]["next_offset"]
        assert len(items) == len({item["field"] for item in items}) == 259
        unavailable = next(item for item in items if item['field'] == 'RouteLastUpdated')
        assert unavailable['known_unavailable'] and unavailable['default_options'] is None
        battery = next(item for item in items if item["field"] == "BatteryLevel")
        assert battery["description"] == field_info(FIELD_MAP["BatteryLevel"])["description"]
        assert battery["delta_unit"] == 'percentage points'
        assert not battery["vehicle_availability_verified"]
        technical = call(client, headers(), "tesla_telemetry_catalogue", category="Charging", limit=100)
        technical_battery = next(item for item in technical["items"] if item["field"] == "BatteryLevel")
        assert technical_battery["collection_guidance"]["description"] == battery["description"]
        assert next(item for item in items if item["field"] == "SelfDrivingMilesSinceReset")["delta_minimum"] == 1
        search = call(client, headers(), "tesla_get_collection", vehicle_ref=vehicle_ref,
                      include_catalog=True, catalog_search="BatteryLevel")
        assert [item["field"] for item in search["catalog"]["items"]] == ["BatteryLevel"]
        fields = {"BatteryLevel": {"interval_seconds": 120, "resend_interval_seconds": 1800, "minimum_delta": 1}}
        quote = call(client, headers(), "tesla_estimate_collection", vehicle_ref=vehicle_ref,
                     preset="custom", custom_fields=fields, active_hours_per_day=4)
        assert quote["fields"] == fields
        assert quote["field_estimates"]["BatteryLevel"]["planned_signals_30_days"] == quote["estimate"]["planned_signals_30_days"]
        csrf = login(client)
        page = client.post("/tesla/owner/collection/"+vehicle_ref,
                           data={"csrf": csrf, "collection_action": "estimate", "field": "BatteryLevel",
                                 "revision": Collection(prepared_service).view(vehicle_ref)["revision"],
                                 "interval_BatteryLevel": "120", "resend_BatteryLevel": "1800", "delta_BatteryLevel": "1", "hours": "4"},
                           headers={"origin": "https://bridge.example"})
        assert page.status_code == 200
        assert 'id="signal-count">'+str(quote["estimate"]["planned_signals_30_days"])+"</output>" in page.text
        assert 'every 2 minutes' in page.text and 'Requested resend: 30 minutes' in page.text
        assert fleet.calls == []


def test_chat_review_confirm_web_pause_and_chat_resume_share_state(prepared_service, fleet, vehicle_ref, headers, clock):
    service, manager = prepared_service, Collection(prepared_service)
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        before = Triggers(service.store).view(vehicle_ref, SCOPES)
        review = call(client, headers(), "tesla_prepare_collection", vehicle_ref=vehicle_ref,
                      action="configure", preset="recommended", active_hours_per_day=6,
                      expected_revision=manager.view(vehicle_ref)["revision"], client_request_id="shared-configure-request")
        assert len(review["fields"]) == 7 and review["customer_alerts"] is True
        assert review["estimate"]["active_hours_per_day"] == 6
        assert "BEGIN CERTIFICATE" not in json.dumps(review)
        assert not any(name == CREATE for name, *_ in fleet.calls)
        csrf = login(client)
        page = client.get("/tesla/owner/intents/"+review["intent_id"])
        assert '6 hours/day' in page.text
        bad = rpc(client, headers(), "tools/call", {"name": "tesla_confirm_collection", "arguments": {
            "vehicle_ref": vehicle_ref, "intent_id": review["intent_id"], "review_digest": "0"*64, "decision": "confirm"}}).json()["result"]
        assert bad["isError"]
        result = call(client, headers(), "tesla_confirm_collection", vehicle_ref=vehicle_ref,
                      intent_id=review["intent_id"], review_digest=review["review_digest"], decision="confirm")
        assert result["status"] == "acknowledged"
        assert result["result"]["confirmation_source"] == "explicit_chat_request"
        call(client, headers(), "tesla_confirm_collection", vehicle_ref=vehicle_ref,
             intent_id=review["intent_id"], review_digest=review["review_digest"], decision="confirm")
        assert sum(name == CREATE for name, *_ in fleet.calls) == 1
        assert manager.view(vehicle_ref)["state"] == "starting"  # not yet vehicle-verified
        clock.advance(1)
        page = client.post("/tesla/owner/collection/"+vehicle_ref, data={"csrf": csrf, "collection_action": "pause",
                           "revision": manager.view(vehicle_ref)["revision"], "request_id": "shared-web-pause-request"},
                           headers={"origin": "https://bridge.example"})
        assert 'Confirm pause' in page.text
        pending = call(client, headers(), "tesla_get_collection", vehicle_ref=vehicle_ref)["last_request"]
        call(client, headers(), "tesla_confirm_collection", vehicle_ref=vehicle_ref,
             intent_id=pending["intent_id"], review_digest=pending["review_digest"], decision="confirm")
        assert sum(name == DELETE for name, *_ in fleet.calls) == 1
        clock.advance(1)
        resumed = call(client, headers(), "tesla_prepare_collection", vehicle_ref=vehicle_ref, action="resume",
                       expected_revision=manager.view(vehicle_ref)["revision"], client_request_id="shared-resume-request")
        assert resumed["fields"] == review["fields"] and resumed["customer_alerts"]
        assert resumed["estimate"]["active_hours_per_day"] == 6
        # The same pending request can be cancelled in either surface.
        call(client, headers(), "tesla_confirm_collection", vehicle_ref=vehicle_ref,
             intent_id=resumed["intent_id"], review_digest=resumed["review_digest"], decision="cancel")
        assert manager.view(vehicle_ref)["last"]["status"] == "cancelled"
        after = Triggers(service.store).view(vehicle_ref, SCOPES)
        assert after["revision"] == before["revision"] and after["batch_seconds"] == before["batch_seconds"]
        assert {i["id"]: i["enabled"] for i in after["items"]} == {i["id"]: i["enabled"] for i in before["items"]}
        assert after["collection"]["state"] == "pausing"
        assert not any(name == "vehicle_wake_up" for name, *_ in fleet.calls)


def test_collection_confirmation_never_opens_physical_command_path(prepared_service, vehicle_ref, fleet):
    service, manager = prepared_service, Collection(prepared_service)
    physical = service.prepare("set_charge_limit", {"percent": 80}, vehicle_ref, "physical-still-owner-only", SCOPES)
    with pytest.raises(TeslaError, match="only"):
        manager.resolve(vehicle_ref, physical["id"], "0"*64, "confirm", SCOPES)
    with pytest.raises(TeslaError, match="Physical commands"):
        service.execute_collection_from_chat(physical["id"], SCOPES)
    assert not any(name == "set_charge_limit" for name, *_ in fleet.calls)


def test_confirmation_rechecks_permission_expiry_and_never_retries_unknown(prepared_service, vehicle_ref, fleet, clock, monkeypatch):
    manager = Collection(prepared_service)
    item = manager.prepare_change(vehicle_ref, "pause", manager.view(vehicle_ref)["revision"], "shared-pause-recheck", SCOPES,
                                  access_expires=clock()+10)
    review = manager.review(vehicle_ref, item["id"])
    with pytest.raises(TeslaError, match="permissions"):
        manager.resolve(vehicle_ref, item["id"], review["review_digest"], "confirm", ["tesla:read", "tesla:manage"])
    clock.advance(11)
    with pytest.raises(TeslaError, match="expired"):
        manager.resolve(vehicle_ref, item["id"], review["review_digest"], "confirm", SCOPES)
    new = manager.prepare_change(vehicle_ref, "pause", manager.view(vehicle_ref)["revision"], "shared-pause-unknown", SCOPES)
    review = manager.review(vehicle_ref, new["id"])
    fleet.error = TeslaError("TIMEOUT", "Unknown outcome", uncertain=True)
    assert manager.resolve(vehicle_ref, new["id"], review["review_digest"], "confirm", SCOPES)["status"] == "unknown"
    assert manager.resolve(vehicle_ref, new["id"], review["review_digest"], "confirm", SCOPES)["status"] == "unknown"
    assert sum(name == DELETE for name, *_ in fleet.calls) == 1
    with pytest.raises(TeslaError, match="pending"):
        manager.prepare_change(vehicle_ref, "pause", manager.view(vehicle_ref)["revision"], "another-pause-request", SCOPES)


def test_prepare_rechecks_revision_after_provider_qualification(prepared_service, vehicle_ref, monkeypatch):
    manager = Collection(prepared_service)
    original = prepared_service.fleet.call
    def concurrent(name, *args, **kwargs):
        if name == "vehicle_fleet_status":
            prepared_service.store.snapshot(vehicle_ref, "telemetry_remote", {"synced": True, "config": None}, "test", prepared_service.store.clock())
        return original(name, *args, **kwargs)
    monkeypatch.setattr(prepared_service.fleet, "call", concurrent)
    with pytest.raises(TeslaError, match="changed"):
        manager.prepare_change(vehicle_ref, "configure", manager.view(vehicle_ref)["revision"], "stale-during-qualification", SCOPES,
                               preset="recommended")
    with prepared_service.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM intents").fetchone()[0] == 0


def test_trigger_presets_web_mcp_parity_and_no_acquisition(service, vehicle_ref, headers, fleet):
    triggers = Triggers(service.store)
    rule_id = preset_id(vehicle_ref, "battery_low")
    Telemetry(service.store).configure_rule(vehicle_ref, "battery_low", {"threshold": 25}, rule_id=rule_id)
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        csrf = login(client)
        path = "/tesla/owner/triggers/"+vehicle_ref
        revision = triggers.view(vehicle_ref, SCOPES)["revision"]
        response = client.post(path, data={"csrf": csrf, "category": "preset", "preset": "recommended", "revision": revision},
                               headers={"origin": "https://bridge.example"})
        assert response.status_code == 200
        view = call(client, headers(), "tesla_list_triggers", vehicle_ref=vehicle_ref)
        assert view["selection_preset"] == "recommended" and view["revision"] == revision+1
        assert {i["id"][6:] for i in view["items"] if i["id"].startswith("event:") and i["enabled"]} == RECOMMENDED_EVENTS
        with service.store.db() as db:
            assert json.loads(db.execute("SELECT config FROM rules WHERE id=?", (rule_id,)).fetchone()[0])["threshold"] == 25
            assert db.execute("SELECT COUNT(*) FROM intents").fetchone()[0] == 0
        assert not any(i["enabled"] for i in triggers.view(vehicle_ref, SCOPES)["items"] if i["id"].startswith("field:"))
        call(client, headers(), "tesla_update_triggers", vehicle_ref=vehicle_ref, preset="none", expected_revision=view["revision"])
        assert '<strong>None</strong>' in client.get(path).text
        assert not any(i["enabled"] for i in triggers.view(vehicle_ref, SCOPES)["items"])
        stale = client.post(path, data={"csrf": csrf, "category": "preset", "preset": "all", "revision": revision},
                            headers={"origin": "https://bridge.example"})
        assert stale.status_code == 409
    assert fleet.calls == []


def test_all_preset_respects_location_and_custom_changes_change_label(service, vehicle_ref):
    triggers = Triggers(service.store)
    scopes = [s for s in SCOPES if s != "tesla:location"]
    triggers.apply_preset(vehicle_ref, "all", scopes, expected_revision=0)
    view = triggers.view(vehicle_ref, scopes)
    assert view["selection_preset"] == "all"
    assert all(not i["enabled"] for i in view["items"] if i["requires_location"])
    triggers.update(vehicle_ref, [{"trigger_id": "field:BatteryLevel", "enabled": False}], scopes, expected_revision=1)
    assert triggers.view(vehicle_ref, scopes)["selection_preset"] == "custom"


def test_rule_editing_preserves_disabled_state_and_uses_shared_revision(service, vehicle_ref, headers):
    triggers = Triggers(service.store)
    rule_id = preset_id(vehicle_ref, "battery_low")
    triggers.apply_preset(vehicle_ref, "none", SCOPES, expected_revision=0)
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        csrf = login(client)
        path = "/tesla/owner/triggers/"+vehicle_ref
        form = {"csrf": csrf, "category": "rule", "rule_id": rule_id, "revision": 1,
                "max_age_seconds": 120, "max_gap_seconds": 600, "dwell_seconds": 120, "hysteresis": 3, "threshold": 30}
        assert client.post(path, data=form, headers={"origin": "https://bridge.example"}).status_code == 200
        rules = call(client, headers(), "tesla_list_rules", vehicle_ref=vehicle_ref)["rules"]
        edited = next(r for r in rules if r["id"] == rule_id)
        assert edited["config"]["threshold"] == 30 and edited["enabled"] == 0
        assert client.post(path, data=form, headers={"origin": "https://bridge.example"}).status_code == 409
        result = call(client, headers(), "tesla_configure_rule", vehicle_ref=vehicle_ref, rule_id=rule_id,
                      kind="battery_low", config={"threshold": 18}, expected_revision=2)
        assert result["revision"] == 3
        assert 'name="threshold" type="number" step="any" value="18"' in client.get(path).text
