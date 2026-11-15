"""Synthetic reproductions of the owner's checkpoint; no real car or callbacks."""
import base64
import json
from dataclasses import replace

import pytest
from starlette.testclient import TestClient

from tesla_plugin.collection import Collection
from tesla_plugin.config import SCOPES
from tesla_plugin.diagnostics import consumer_heartbeat, consumer_status, operation_evidence
from tesla_plugin.errors import TeslaError
from tesla_plugin.server import create_app
from tesla_plugin.telemetry import Telemetry
from tesla_plugin.triggers import Triggers
from test_mcp_portal import rpc
from test_shared_settings import call
from test_telemetry_events import payload, Delivery, subscription
from test_trigger_dependencies import observed


def test_position_uses_telemetry_own_timestamp_and_never_polls(service, fleet, vehicle_ref, clock):
    point = {"latitude": 12.5, "longitude": 21.0}
    Telemetry(service.store).ingest("V", payload(clock, {"Location": point}, when=clock()-600))
    service.store.snapshot(vehicle_ref, "drive_state", {"shift_state": None}, "tesla_live", clock())
    result = service.state(vehicle_ref, ["location_data", "drive_state"], "cached_only", SCOPES)
    location = result["data"]["location_data"]
    assert location["data"] == point and location["quality"] == "stale" and location["age_seconds"] == pytest.approx(600)
    assert location["source"] == "fleet_telemetry" and location["time_basis"] == "payload_created_at"
    assert location["accuracy_meters"] is None and location["instantaneous_position"] is False
    assert "latitude" not in result["data"]["drive_state"]["data"] and fleet.calls == []
    with pytest.raises(TeslaError):
        service.state(vehicle_ref, ["location_data"], "cached_only", set(SCOPES)-{"tesla:location"})
    clock.advance(1)
    Telemetry(service.store).ingest("V", payload(clock, {"Location": None}))
    invalid = service.state(vehicle_ref, ["location_data"], "cached_only", SCOPES)["data"]["location_data"]
    assert invalid["data"] is None and invalid["quality"] == "invalid"


def test_newer_rest_location_wins_over_older_telemetry(service, vehicle_ref, clock):
    Telemetry(service.store).ingest("V", payload(clock, {"Location": {"latitude": 12., "longitude": 21.}}, when=clock()-10))
    service.store.snapshot(vehicle_ref, "location_data", {"latitude": 13., "longitude": 22.}, "tesla_live", clock())
    result = service.state(vehicle_ref, ["location_data"], "cached_only", SCOPES)["data"]["location_data"]
    assert result["source"] == "tesla_live" and result["data"]["latitude"] == 13


def test_matching_config_samples_and_consumer_do_not_replace_provider_sync(service, vehicle_ref, clock, fleet):
    config = observed(service.store, vehicle_ref, {"BatteryLevel": {"interval_seconds": 60, "resend_interval_seconds": 60}})
    service.store.snapshot(vehicle_ref, "telemetry_target", config, "owner_request", clock())
    service.store.snapshot(vehicle_ref, "telemetry_remote", {"config": config, "synced": False}, "tesla_api", clock())
    consumer_heartbeat(service.store, "running")
    clock.advance(1)
    Telemetry(service.store).ingest("V", payload(clock, {"BatteryLevel": 45}))
    result = Collection(service).public_view(vehicle_ref, SCOPES)
    assert result["state"] == "syncing" and result["synced"] is False
    evidence = result["evidence"]
    assert evidence["configuration_matches_target"] is True and evidence["reason"] == "provider_sync_pending"
    assert evidence["consumer"]["active"] and evidence["samples_since_request"]["valid_field_count"] == 1
    battery = next(i for i in Triggers(service.store).view(vehicle_ref, SCOPES)["items"] if i["id"] == "event:battery_low")
    assert battery["readiness"]["collection_reason"] == "provider_sync_pending"
    assert battery["readiness"]["paths"][0]["observation_status"] == "fresh"
    assert battery["readiness"]["status"] == "collection_unverified" and fleet.calls == []


def test_runtime_heartbeat_does_not_change_owner_revision(service, vehicle_ref, clock):
    manager = Collection(service)
    before = manager.view(vehicle_ref)["revision"]
    consumer_heartbeat(service.store, "running")
    assert consumer_status(service.store)["active"]
    clock.advance(61)
    assert consumer_status(service.store)["state"] == "unknown"
    consumer_heartbeat(service.store, "paused")
    assert consumer_status(service.store)["state"] == "paused" and not consumer_status(service.store)["active"]
    assert manager.view(vehicle_ref)["revision"] == before


def test_accepted_wake_offline_can_be_checked_once_without_new_wake(service, fleet, vehicle_ref, clock):
    service.settings = replace(service.settings, live_enabled=True)
    fleet.result = {"state": "offline"}
    result = service.wake_from_chat(vehicle_ref, "checkpoint-wake-synthetic", SCOPES)
    assert "online not yet observed" in result["note"] and not result["vehicle_online_observed"]
    before = list(fleet.calls)
    assert not service.intent_view(result["intent_id"])["verification"]["effect_observed"]
    assert fleet.calls == before
    clock.advance(2)
    follow = result["follow_up"]["arguments"]
    service.read(follow["operation"], follow["arguments"], follow["vehicle_ref"], SCOPES)
    check = service.intent_view(result["intent_id"])
    assert check["verification"]["effect_observed"] and not check["verification"]["causality_proven"]
    assert check["result"]["physical_effect_verified"] is False
    assert [c[0] for c in fleet.calls] == ["vehicle_wake_up", "vehicle_vehicle"]


def test_capability_evidence_is_per_operation_and_needs_later_fresh_match(service, fleet, vehicle_ref, clock):
    intent = service.prepare("set_temps", {"driver_temp": 21, "passenger_temp": 22}, vehicle_ref, "checkpoint-climate-test", SCOPES)
    service.execute_from_owner(intent["id"])
    clock.advance(2)
    service.store.snapshot(vehicle_ref, "climate_state", {"driver_temp_setting": 21, "passenger_temp_setting": 22}, "tesla_live", clock())
    capabilities = {i["operation"]: i for i in service.capabilities(vehicle_ref)["operations"]}
    assert capabilities["set_temps"]["qualification"]["status"] == "effect_observed"
    assert capabilities["set_temps"]["vehicle_qualified"]
    assert capabilities["auto_conditioning_start"]["qualification"]["status"] == "not_tested"
    assert capabilities["navigation_sc_request"]["availability"] == "supported_transport"
    assert capabilities["navigation_sc_request"]["qualification"]["status"] == "not_tested"
    assert not capabilities["navigation_sc_request"]["vehicle_qualified"]
    clock.advance(121)
    evidence = service.intent_view(intent["id"])["verification"]
    assert evidence["command_accepted"] and not evidence["effect_observed"]


def test_old_intent_creation_time_is_not_dispatch_proof(service, vehicle_ref, clock):
    intent = service.prepare("set_temps", {"driver_temp": 21, "passenger_temp": 22}, vehicle_ref, "checkpoint-legacy-test", SCOPES)
    with service.store.db() as db:
        db.execute("UPDATE intents SET status='acknowledged',result=? WHERE id=?", ('{"accepted":true}', intent["id"]))
    clock.advance(2)
    service.store.snapshot(vehicle_ref, "climate_state", {"driver_temp_setting": 21, "passenger_temp_setting": 22}, "tesla_live", clock())
    evidence = service.intent_view(intent["id"])["verification"]
    assert evidence["reason"] == "dispatch_time_not_recorded" and not evidence["effect_observed"]


def test_other_functions_do_not_suggest_unrelated_climate_verification(service, vehicle_ref, clock, fleet):
    evidence = operation_evidence(service.store, {
        "status": "acknowledged", "operation": "navigation_request", "vehicle": vehicle_ref,
        "generation": service.store.connection()["generation"], "result": {"completed_at": clock()},
    })
    assert evidence["command_accepted"] and not evidence["effect_observed"]
    assert evidence["reason"] == "effect_check_not_implemented" and "observation" not in evidence
    assert fleet.calls == []


def test_observed_command_remains_historical_evidence_when_state_changes(service, vehicle_ref, clock, fleet):
    intent = service.prepare("set_temps", {"driver_temp": 21, "passenger_temp": 22}, vehicle_ref, "checkpoint-recorded-effect", SCOPES)
    service.execute_from_owner(intent["id"])
    clock.advance(2)
    service._cache(vehicle_ref, {"climate_state": {"driver_temp_setting": 21, "passenger_temp_setting": 22, "timestamp": clock()*1000}}, "tesla_live", authorization=fleet.authorization())
    clock.advance(121)
    service._cache(vehicle_ref, {"climate_state": {"driver_temp_setting": 19, "passenger_temp_setting": 19, "timestamp": clock()*1000}}, "tesla_live", authorization=fleet.authorization())
    before = list(fleet.calls)
    evidence = service.intent_view(intent["id"])["verification"]
    assert evidence["effect_observed"] and evidence["verification_basis"] == "recorded_later_observation"
    assert not evidence["proves_current_state"] and not evidence["observation"]["fresh"] and not evidence["causality_proven"]
    capabilities = {i["operation"]: i for i in service.capabilities(vehicle_ref)["operations"]}
    assert capabilities["set_temps"]["vehicle_qualified"]
    assert fleet.calls == before
    with service.store.db() as db:
        db.execute("UPDATE connection SET generation=generation+1")
    assert service.intent_view(intent["id"])["verification"]["reason"] == "connection_changed"
    assert not service.intent_view(intent["id"])["verification"]["effect_observed"]


def test_malformed_wake_is_uncertain_and_not_retried(service, vehicle_ref, fleet):
    service.settings = replace(service.settings, live_enabled=True)
    fleet.result = {"unexpected": "response"}
    first = service.wake_from_chat(vehicle_ref, "checkpoint-malformed-wake", SCOPES)
    assert first["status"] == "unknown" and not first["vehicle_online_observed"]
    second = service.wake_from_chat(vehicle_ref, "checkpoint-malformed-wake", SCOPES)
    assert second["intent_id"] == first["intent_id"] and second["status"] == "unknown"
    assert [c[0] for c in fleet.calls] == ["vehicle_wake_up"]


def test_checkpoint_cost_comparison_preserves_profile_and_warns_about_slow_park(service, vehicle_ref):
    fields = {
        "BatteryLevel": {"interval_seconds": 60, "resend_interval_seconds": 60, "minimum_delta": 1},
        "DetailedChargeState": {"interval_seconds": 15, "resend_interval_seconds": 60},
        **{name: {"interval_seconds": 15, "resend_interval_seconds": 15} for name in ("DriverSeatOccupied", "Gear", "Locked")},
        "Location": {"interval_seconds": 1800, "resend_interval_seconds": 1800, "minimum_delta": 25},
        **{name: {"interval_seconds": 300, "resend_interval_seconds": 1800} for name in ("DestinationName", "DestinationLocation", "ExpectedEnergyPercentAtTripArrival", "RouteTrafficMinutesDelay")},
    }
    config = observed(service.store, vehicle_ref, fields)
    service.store.snapshot(vehicle_ref, "telemetry_saved", config, "owner_request", service.store.clock())
    manager = Collection(service)
    before = manager.view(vehicle_ref)
    current = manager.scenario("custom", fields, 8, True)
    proposal = fields | {name: {"interval_seconds": 60, "resend_interval_seconds": 60} for name in ("Gear", "Locked", "DriverSeatOccupied")}
    proposal["TimeToFullCharge"] = {"interval_seconds": 300, "resend_interval_seconds": 1800}
    quote = manager.scenario("custom", proposal, 8, True)
    comparison = manager.cost_comparison(vehicle_ref, quote)
    assert current["estimate"]["estimated_gross_usd"] == 3.074
    assert comparison["proposed_streaming_usd"] == 1.3686 and comparison["delta_streaming_usd"] == -1.7054
    assert next(i for i in manager.impact(vehicle_ref, proposal, True, SCOPES)["issues"] if i["trigger_id"] == "event:unlocked_parked")["reason"] == "timing_warning"
    assert manager.view(vehicle_ref)["revision"] == before["revision"]
    assert manager.view(vehicle_ref)["saved"] == before["saved"]


def test_null_gear_cannot_trigger_park_and_slow_profile_reports_coherence_risk(service, vehicle_ref, clock):
    manager = Collection(service)
    fields = {k: {"interval_seconds": 60, "resend_interval_seconds": 60} for k in ("Gear", "Locked", "DriverSeatOccupied")}
    observed(service.store, vehicle_ref, fields)
    telemetry = Telemetry(service.store, monotonic=clock)
    for _ in range(5):
        telemetry.ingest("V", payload(clock, {"Gear": None, "Locked": False, "DriverSeatOccupied": False}))
        clock.advance(60)
    with service.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM events WHERE name='unlocked_parked'").fetchone()[0] == 0
    impact = manager.impact(vehicle_ref, fields, True, SCOPES)
    assert next(i for i in impact["issues"] if i["trigger_id"] == "event:unlocked_parked")["reason"] == "timing_warning"


def test_reports_are_bounded_and_cost_delta_uses_same_hours(service, vehicle_ref, headers, fleet):
    config = observed(service.store, vehicle_ref, {"BatteryLevel": {"interval_seconds": 60, "resend_interval_seconds": 60}})
    service.store.snapshot(vehicle_ref, "telemetry_saved", config, "owner_request", service.store.clock())
    Triggers(service.store).apply_preset(vehicle_ref, "all", SCOPES, expected_revision=0)
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        quote = call(client, headers(), "tesla_estimate_collection", vehicle_ref=vehicle_ref, preset="on_demand", active_hours_per_day=8)
        assert quote["cost_comparison"]["proposed_streaming_usd"] == 0
        assert quote["cost_comparison"]["delta_streaming_usd"] == -quote["cost_comparison"]["previous_streaming_usd"]
        impact = quote["trigger_impact"]
        assert len(impact["issues"]) <= 20 and all(i["trigger_id"].startswith("event:") for i in impact["issues"])
        assert impact["total_issues"] > 200 and impact["filtered_total"] <= 17
        fields = call(client, headers(), "tesla_estimate_collection", vehicle_ref=vehicle_ref, preset="on_demand", impact_scope="fields", impact_limit=10)
        assert fields["trigger_impact"]["next_offset"] == 10 and len(fields["trigger_impact"]["issues"]) == 10
        results = call(client, headers(), "tesla_list_triggers", vehicle_ref=vehicle_ref, search="BatteryLevel", selected=True, needs_attention=True)
        assert results["total"] == 1 and results["items"][0]["id"] == "field:BatteryLevel"
    assert fleet.calls == []


def test_parameters_rejected_arguments_validated_before_any_intent(service, headers, vehicle_ref, fleet):
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        request = {"operation": "set_temps", "vehicle_ref": vehicle_ref, "client_request_id": "checkpoint-schema-test"}
        for wrong in ({"parameters": {"driver_temp": 21}}, {"arguments": {"driver_temp": 70, "passenger_temp": 21}}):
            result = rpc(client, headers(), "tools/call", {"name": "tesla_prepare_action", "arguments": request | wrong}).json()["result"]
            assert result["isError"]
        assert fleet.calls == []
        result = call(client, headers(), "tesla_prepare_action", **request, arguments={"driver_temp": 21, "passenger_temp": 22})
        assert result["arguments"] == {"driver_temp": 21, "passenger_temp": 22}
        assert result["status"] == "prepared" and fleet.calls == []


def test_native_event_protocol_renewal_dedup_evidence_and_delivery_boundaries(service, headers, vehicle_ref, clock, fleet):
    delivery = Delivery()
    secret = "whsec_"+base64.b64encode(b"synthetic-key-for-protocol-test!!").decode()
    with TestClient(create_app(service.settings, service=service, start_worker=False, event_transport=delivery), base_url="https://bridge.example") as client:
        listed = rpc(client, headers(), "events/list").json()["result"]
        assert listed["events"][0]["name"] == "tesla.vehicle_event"
        plan = call(client, headers(), "tesla_list_triggers", vehicle_ref=vehicle_ref, limit=1)["delivery_connection"]["subscription_plan"]
        params = {"name": plan["name"], "arguments": plan["arguments"], "delivery": {"mode": "webhook", "url": "https://receiver.example/checkpoint", "secret": secret}, "ttlMs": 120000}
        first = rpc(client, headers(), "events/subscribe", params).json()["result"]
        clock.advance(1)
        renewed = rpc(client, headers(), "events/subscribe", params).json()["result"]
        assert first["id"] == renewed["id"] and first["refreshBefore"] != renewed["refreshBefore"]
        telemetry = Telemetry(service.store)
        telemetry.ingest("V", payload(clock, {"BatteryLevel": 25}))
        clock.advance(1)
        crossing = payload(clock, {"BatteryLevel": 19})
        telemetry.ingest("V", crossing)
        telemetry.ingest("V", crossing)
        from tesla_plugin.events import Events
        sender = Events(service.store, transport=delivery)
        assert sender.dispatch_one()
        assert not sender.dispatch_one()
        with service.store.db() as db:
            assert db.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0] == 1
            event_id = db.execute("SELECT id FROM events WHERE name='battery_low'").fetchone()[0]
            assert db.execute("SELECT COUNT(*) FROM deliveries WHERE state='accepted'").fetchone()[0] == 1
        evidence = call(client, headers(), "tesla_get_event", event_id=event_id)
        assert evidence["data"]["observed"]["BatteryLevel"] == 19
        state = call(client, headers(), "tesla_list_triggers", vehicle_ref=vehicle_ref, limit=1)
        assert state["delivery_pipeline"]["webhook_accepted"] == 1
        assert not state["delivery_pipeline"]["chatgpt_activation_verified"] and not state["delivery_pipeline"]["user_notification_verified"]
        clock.advance(121)
        assert not call(client, headers(), "tesla_list_triggers", vehicle_ref=vehicle_ref, limit=1)["subscription_active"]
    assert fleet.calls == []


@pytest.mark.parametrize("additional_delay,expected", [(60, "accepted"), (901, "expired")])
def test_stale_membership_blocks_without_polling_and_old_events_expire(service, vehicle_ref, clock, fleet, additional_delay, expected):
    from tesla_plugin.events import Events
    delivery = Delivery()
    sender = Events(service.store, transport=delivery)
    subscription(sender, vehicle_ref, clock)
    with service.store.db() as db:
        event = Events.emit(db, vehicle_ref, "battery_low", clock(), {"synthetic": True}, clock())
    clock.advance(301)
    assert not sender.dispatch_one() and len(delivery.calls) == 1
    diagnostics = Triggers(service.store).view(vehicle_ref, SCOPES)["delivery_pipeline"]
    assert "membership_check_stale" in diagnostics["blocking_reasons"]
    clock.advance(additional_delay)
    with service.store.db() as db:
        # A synthetic externally refreshed grant, never a hidden Tesla request.
        db.execute("UPDATE vehicles SET checked=? WHERE ref=?", (clock(), vehicle_ref))
    assert sender.dispatch_one()
    with service.store.db() as db:
        assert db.execute("SELECT state FROM deliveries WHERE event=?", (event,)).fetchone()[0] == expected
    assert len(delivery.calls) == (2 if expected == "accepted" else 1)
    assert fleet.calls == []
