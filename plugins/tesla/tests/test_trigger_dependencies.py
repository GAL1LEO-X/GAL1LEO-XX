"""Cross-layer contract: selected events, observed acquisition and shared drafts."""
from copy import deepcopy
from unittest.mock import Mock

import pytest
from starlette.testclient import TestClient

from tesla_plugin.collection import Collection, CREATE
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.profiles import estimate
from tesla_plugin.server import create_app
from tesla_plugin.telemetry import Telemetry
from tesla_plugin.triggers import Triggers, preset_id
from test_collection import prepared_service
from test_mcp_portal import login
from test_shared_settings import call
from test_telemetry_events import payload


def observed(store, ref, fields=None, *, alerts=False, synced=True):
    config = {"fields": deepcopy(fields)} if fields is not None else None
    if config is not None and alerts:
        config["alert_types"] = ["customer"]
    store.snapshot(ref, "telemetry_remote", {"config": config, "synced": synced}, "tesla_api", store.clock())
    return config


def item(store, ref, key="event:battery_low", scopes=SCOPES):
    return next(i for i in Triggers(store).view(ref, scopes)["items"] if i["id"] == key)


def toggle(store, ref, key, enabled):
    manager = Triggers(store)
    return manager.update(ref, [{"trigger_id": key, "enabled": enabled}], SCOPES,
                          expected_revision=manager.view(ref, SCOPES)["revision"])


def test_saved_requested_and_observed_are_distinct(store, vehicle_ref, clock):
    fields = {"BatteryLevel": {"interval_seconds": 30, "resend_interval_seconds": 60}}
    Telemetry(store).ingest("V", payload(clock, {"BatteryLevel": 55}))
    store.snapshot(vehicle_ref, "telemetry_saved", {"fields": fields}, "local", clock())
    store.snapshot(vehicle_ref, "telemetry_target", {"fields": fields}, "local", clock())
    assert item(store, vehicle_ref)["readiness"]["status"] == "collection_unverified"
    observed(store, vehicle_ref, {"InsideTemp": {"interval_seconds": 30}}, synced=False)
    assert item(store, vehicle_ref)["readiness"]["status"] == "collection_unverified"
    observed(store, vehicle_ref, {"InsideTemp": {"interval_seconds": 30}})
    assert item(store, vehicle_ref)["readiness"]["missing_fields"] == ["BatteryLevel"]
    observed(store, vehicle_ref, fields)
    assert item(store, vehicle_ref)["readiness"]["status"] == "inputs_available"
    clock.advance(1)
    store.snapshot(vehicle_ref, "telemetry_target", None, "local", clock())
    assert item(store, vehicle_ref)["readiness"]["status"] == "collection_unverified"
    clock.advance(1)
    observed(store, vehicle_ref)
    assert item(store, vehicle_ref)["readiness"]["status"] == "collection_paused"
    assert item(store, vehicle_ref)["enabled"] is True


@pytest.mark.parametrize("observation,expected", [("none", "data_missing"), ("old", "data_stale"),
                                                    ("bad", "data_invalid"), ("fresh", "inputs_available")])
def test_collection_coverage_does_not_certify_samples(store, vehicle_ref, clock, observation, expected):
    observed(store, vehicle_ref, {"BatteryLevel": {"interval_seconds": 30, "resend_interval_seconds": 60}})
    if observation != "none":
        Telemetry(store).ingest("V", payload(clock, {"BatteryLevel": 55}, when=clock()-180 if observation == "old" else clock()))
        if observation == "bad":
            with store.db() as db:
                db.execute("UPDATE latest SET quality='time_conflict'")
    result = item(store, vehicle_ref)
    assert result["enabled"] and result["readiness"]["status"] == expected


def test_multifield_rule_requires_all_fields_and_aligned_samples(store, vehicle_ref, clock):
    fields = {name: {"interval_seconds": 10, "resend_interval_seconds": 10}
              for name in ("Locked", "Gear", "DriverSeatOccupied")}
    observed(store, vehicle_ref, {k: v for k, v in fields.items() if k != "DriverSeatOccupied"})
    assert item(store, vehicle_ref, "event:unlocked_parked")["readiness"]["missing_fields"] == ["DriverSeatOccupied"]
    observed(store, vehicle_ref, fields)
    Telemetry(store).ingest("V", payload(clock, {"Locked": False, "Gear": "ShiftStateP"}, when=clock()-40))
    Telemetry(store).ingest("V", payload(clock, {"DriverSeatOccupied": False}))
    assert item(store, vehicle_ref, "event:unlocked_parked")["readiness"]["status"] == "data_incoherent"


def test_timing_and_stale_rules_have_different_requirements(store, vehicle_ref, clock):
    observed(store, vehicle_ref, {"BatteryLevel": {"interval_seconds": 1200, "resend_interval_seconds": 3600}})
    Telemetry(store).ingest("V", payload(clock, {"BatteryLevel": 55}))
    assert item(store, vehicle_ref)["readiness"]["status"] == "timing_warning"
    clock.advance(901)
    readiness = item(store, vehicle_ref, "event:data_stale")["readiness"]
    assert readiness["paths"][0]["observation_status"] == "available"
    assert readiness["status"] != "data_stale"
    Telemetry(store).tick()
    with store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM events WHERE name='data_stale'").fetchone()[0] == 1


def test_alerts_need_alert_stream_and_connectivity_is_not_a_battery_field(store, vehicle_ref):
    fields = {"BatteryLevel": {"interval_seconds": 60}}
    observed(store, vehicle_ref, fields)
    alert = item(store, vehicle_ref, "event:alert_started")["readiness"]
    assert alert["customer_alerts_missing"] and alert["missing_fields"] == []
    assert item(store, vehicle_ref, "event:connectivity_changed")["readiness"]["status"] == "inputs_available"
    observed(store, vehicle_ref, fields, alerts=True)
    assert item(store, vehicle_ref, "event:alert_started")["readiness"]["status"] == "inputs_available"


def test_alternative_rules_do_not_require_union_of_their_fields(store, vehicle_ref):
    telemetry = Telemetry(store)
    first = telemetry.configure_rule(vehicle_ref, "threshold", {"field": "InsideTemp", "direction": "above", "threshold": 30})
    telemetry.configure_rule(vehicle_ref, "threshold", {"field": "OutsideTemp", "direction": "above", "threshold": 30})
    observed(store, vehicle_ref, {"InsideTemp": {"interval_seconds": 30, "resend_interval_seconds": 60}})
    ready = item(store, vehicle_ref, "event:threshold_crossed")["readiness"]
    assert len(ready["paths"]) == 2 and ready["paths"][0]["fields"] == ["InsideTemp"]
    assert ready["missing_fields"] == [] and ready["status"] == "data_missing"
    toggle(store, vehicle_ref, "rule:"+first["id"], False)
    assert item(store, vehicle_ref, "event:threshold_crossed")["readiness"]["missing_fields"] == ["OutsideTemp"]


def test_draft_preserves_unrelated_data_and_never_changes_selection(service, fleet, vehicle_ref):
    baseline = {"InsideTemp": {"interval_seconds": 1200, "resend_interval_seconds": 3600, "minimum_delta": 2},
                "BatteryLevel": {"interval_seconds": 600, "minimum_delta": 1}}
    observed(service.store, vehicle_ref, baseline)
    toggle(service.store, vehicle_ref, "event:battery_low", False)
    before = Triggers(service.store).view(vehicle_ref, SCOPES)
    proposal = Collection(service).trigger_proposal(vehicle_ref, ["event:battery_low", "event:charge_completed"], SCOPES)
    assert proposal["available"]
    assert proposal["fields"]["InsideTemp"] == baseline["InsideTemp"]
    assert proposal["fields"]["BatteryLevel"] == {"interval_seconds": 60, "resend_interval_seconds": 60, "minimum_delta": 1}
    assert set(proposal["changed_fields"]) == {"BatteryLevel", "DetailedChargeState"}
    assert proposal["previous_estimate"] == estimate(baseline, 8)
    assert proposal["estimated_delta_usd"] > 0 and fleet.calls == []
    assert Triggers(service.store).view(vehicle_ref, SCOPES)["revision"] == before["revision"]
    assert not item(service.store, vehicle_ref)["enabled"]
    with service.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM intents").fetchone()[0] == 0


def test_unknown_collection_and_unavailable_rule_cannot_be_silently_repaired(service, vehicle_ref):
    manager = Collection(service)
    assert not manager.trigger_proposal(vehicle_ref, ["event:battery_low"], SCOPES)["available"]
    observed(service.store, vehicle_ref)
    toggle(service.store, vehicle_ref, "rule:"+preset_id(vehicle_ref, "battery_low"), False)
    assert item(service.store, vehicle_ref)["readiness"]["status"] == "rule_required"
    draft = manager.trigger_proposal(vehicle_ref, ["event:battery_low"], SCOPES)
    assert not draft["available"] and draft["unresolved"][0]["reason"] == "rule_required"
    # A missing rule does not remove the event from a requested subscription.
    assert "battery_low" in Triggers(service.store).view(vehicle_ref, SCOPES)["required_event_kinds"]


def test_location_permissions_apply_to_readiness_and_draft(service, vehicle_ref):
    observed(service.store, vehicle_ref)
    scopes = set(SCOPES)-{"tesla:location"}
    ready = item(service.store, vehicle_ref, "field:Location", scopes)["readiness"]
    assert ready["status"] == "permission_required" and ready["paths"] == []
    draft = Collection(service).trigger_proposal(vehicle_ref, ["field:Location"], scopes)
    assert not draft["available"]


def test_web_and_mcp_show_the_same_missing_data_and_costed_draft(service, fleet, vehicle_ref, headers):
    observed(service.store, vehicle_ref, {"InsideTemp": {"interval_seconds": 600, "resend_interval_seconds": 1200}})
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        login(client)
        result = call(client, headers(), "tesla_list_triggers", vehicle_ref=vehicle_ref, category='Primary')
        battery = next(i for i in result["items"] if i["id"] == "event:battery_low")
        assert battery["readiness"]["missing_fields"] == ["BatteryLevel"]
        panel = client.get("/tesla/owner/triggers/"+vehicle_ref)
        assert 'Missing fields: Battery level' in panel.text
        assert 'Connect ChatGPT event delivery' in panel.text
        native = call(client, headers(), "tesla_get_collection", vehicle_ref=vehicle_ref,
                      for_triggers=["event:battery_low"])["trigger_proposal"]
        editor = client.get("/tesla/owner/collection/"+vehicle_ref+"?for_trigger=event%3Abattery_low")
        assert editor.status_code == 200 and 'id="trigger-proposal"' in editor.text
        assert f'name="interval_BatteryLevel" type="number" min="1" max="86400" step="1" value="{native["fields"]["BatteryLevel"]["interval_seconds"]}"' in editor.text
        assert f'name="trigger_revision" value="{native["expected_trigger_revision"]}"' in editor.text
        assert "Previous estimate:" in editor.text
        assert client.get("/tesla/owner/collection/"+vehicle_ref+"?for_trigger=not-a-trigger").status_code == 400
    assert fleet.calls == []


def test_trigger_changes_invalidate_prepared_collection_before_dispatch(prepared_service, fleet, vehicle_ref):
    service, manager = prepared_service, Collection(prepared_service)
    observed(service.store, vehicle_ref)
    draft = manager.trigger_proposal(vehicle_ref, ["event:battery_low"], SCOPES)
    intent = manager.prepare_change(vehicle_ref, "configure", draft["expected_revision"], "trigger-repair-synthetic-01", SCOPES,
                                    preset="custom", custom_fields=draft["fields"],
                                    expected_trigger_revision=draft["expected_trigger_revision"])
    toggle(service.store, vehicle_ref, "event:battery_low", False)
    calls = list(fleet.calls)
    review = manager.review(vehicle_ref, intent["id"])
    with pytest.raises(TeslaError, match="Events or rules"):
        manager.resolve(vehicle_ref, intent["id"], review["review_digest"], "confirm", SCOPES)
    with pytest.raises(TeslaError, match="Events or rules"):
        service.execute_from_owner(intent["id"])
    assert fleet.calls == calls and not any(name == CREATE for name, *_ in fleet.calls)
    assert service.store.intent(intent["id"])["status"] == "prepared"


def test_stale_repair_form_rejected_before_provider_reads(prepared_service, fleet, vehicle_ref):
    manager = Collection(prepared_service)
    observed(prepared_service.store, vehicle_ref)
    draft = manager.trigger_proposal(vehicle_ref, ["event:battery_low"], SCOPES)
    toggle(prepared_service.store, vehicle_ref, "event:battery_low", False)
    with pytest.raises(TeslaError, match="Events or rules"):
        manager.prepare_change(vehicle_ref, "configure", draft["expected_revision"], "trigger-repair-synthetic-02", SCOPES,
                               preset="custom", custom_fields=draft["fields"],
                               expected_trigger_revision=draft["expected_trigger_revision"])
    assert fleet.calls == []


def test_pause_preserves_event_revision_until_confirmation(prepared_service, fleet, vehicle_ref):
    manager = Collection(prepared_service)
    observed(prepared_service.store, vehicle_ref)
    revision = Triggers(prepared_service.store).view(vehicle_ref, SCOPES)["revision"]
    intent = manager.prepare_change(vehicle_ref, "pause", manager.view(vehicle_ref)["revision"],
                                    "pause-revision-synthetic-01", SCOPES, expected_trigger_revision=revision)
    toggle(prepared_service.store, vehicle_ref, "event:battery_low", False)
    calls = list(fleet.calls)
    review = manager.review(vehicle_ref, intent["id"])
    with pytest.raises(TeslaError, match="Events or rules"):
        manager.resolve(vehicle_ref, intent["id"], review["review_digest"], "confirm", SCOPES)
    assert fleet.calls == calls
    assert prepared_service.store.intent(intent["id"])["status"] == "prepared"


def test_recommended_profile_covers_initial_recommended_events_without_timing_gaps(service, fleet, vehicle_ref):
    from tesla_plugin.profiles import profile_fields
    manager = Triggers(service.store)
    view = manager.view(vehicle_ref, SCOPES)
    manager.apply_preset(vehicle_ref, "recommended", SCOPES, expected_revision=view["revision"])
    impact = Collection(service).impact(vehicle_ref, profile_fields("recommended"), True, SCOPES)
    assert impact["selected_count"] == 7 and impact["issues"] == []
    assert fleet.calls == []


def test_rule_edits_are_local_even_with_old_membership(service, fleet, vehicle_ref, headers, clock):
    clock.advance(301)
    fleet.discover = Mock(side_effect=AssertionError("An event setting must not poll Tesla"))
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        result = call(client, headers(), "tesla_configure_rule", vehicle_ref=vehicle_ref,
                      kind="battery_low", config={"threshold": 25}, rule_id=preset_id(vehicle_ref, "battery_low"))
        assert result["id"]
        call(client, headers(), "tesla_remove_rule", vehicle_ref=vehicle_ref, rule_id=result["id"])
    fleet.discover.assert_not_called()
    assert fleet.calls == []


def test_proposed_removal_slowdown_and_pause_explain_impact_without_changing_selection(service, fleet, vehicle_ref, headers):
    manager = Collection(service)
    observed(service.store, vehicle_ref, {"BatteryLevel": {"interval_seconds": 30, "resend_interval_seconds": 60}})
    initial = Triggers(service.store).view(vehicle_ref, SCOPES)
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        scenarios = [("custom", {"InsideTemp": {"interval_seconds": 30}}, "collection_missing"),
                     ("custom", {"BatteryLevel": {"interval_seconds": 600}}, "timing_warning"),
                     ("on_demand", None, "collection_paused")]
        for preset, fields, reason in scenarios:
            args = {"vehicle_ref": vehicle_ref, "preset": preset}
            if fields is not None:
                args["custom_fields"] = fields
            estimate_result = call(client, headers(), "tesla_estimate_collection", **args)
            impact = estimate_result["trigger_impact"]
            issue = next(i for i in impact["issues"] if i["trigger_id"] == "event:battery_low")
            assert issue["reason"] == reason
            assert impact["future_delivery_guaranteed"] is False
    assert Triggers(service.store).view(vehicle_ref, SCOPES) == initial
    assert manager.view(vehicle_ref)["last"] is None
    assert fleet.calls == []
