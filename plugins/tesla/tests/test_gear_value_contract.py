"""Synthetic wire-to-guard regressions; no Tesla requests or physical effects."""
import json
from dataclasses import replace

import httpx
import pytest

from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.gear_evidence import view as gear_view
from tesla_plugin.preconditions import drive_precondition
from tesla_plugin.telemetry import Telemetry, typed_value
from test_telemetry_events import payload


@pytest.fixture(autouse=True)
def no_external_http(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected external HTTP request")
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)


def gear_payload(clock, envelope, **fields):
    message = payload(clock, {"Gear": None, "BatteryLevel": 45, **fields})
    message["data"][0]["value"] = envelope
    return message


@pytest.mark.parametrize("branch", ["stringValue", "string_value", "shiftStateValue", "shift_state_value"])
@pytest.mark.parametrize("value,state", [("ShiftStateP", "verified"), ("ShiftStateD", "not_park"),
                                        ("ShiftStateR", "not_park"), ("ShiftStateN", "not_park")])
def test_documented_gear_wire_branches_reach_evidence(store, vehicle_ref, clock, branch, value, state):
    Telemetry(store).ingest("V", gear_payload(clock, {branch: value}))
    evidence = gear_view(store, vehicle_ref)
    assert evidence["status"] == state
    assert evidence["current_telemetry"]["input_evidence"]["normalization_reason"] == "recognized_gear_value"


@pytest.mark.parametrize("branch", ["stringValue", "string_value"])
@pytest.mark.parametrize("value,state", [("P", "verified"), ("D", "not_park"), ("R", "not_park"), ("N", "not_park")])
def test_documented_legacy_short_gear_replaces_previous_park(store, vehicle_ref, clock, branch, value, state):
    telemetry = Telemetry(store)
    telemetry.ingest("V", gear_payload(clock, {"shiftStateValue": "ShiftStateP"}))
    clock.advance(1)
    telemetry.ingest("V", gear_payload(clock, {branch: value}))
    evidence = gear_view(store, vehicle_ref)
    assert evidence["status"] == state
    assert evidence["current_telemetry"]["value"] == value
    assert evidence["current_telemetry"]["quality"] == "valid"
    assert evidence["current_telemetry"]["input_evidence"]["branch"] == branch
    with store.db() as db:
        row = db.execute("SELECT * FROM latest WHERE field='Gear'").fetchone()
        assert json.loads(row["value"]) == "ShiftState"+value
        for operation in ("window_control", "remote_start_drive"):
            assert drive_precondition(operation, {}, row, clock())["allows_dispatch"] is (value == "P")


@pytest.mark.parametrize("envelope", [
    {"doorValue": "ShiftStateP"}, {"bogusValue": "ShiftStateP"}, {"intValue": "ShiftStateP"},
    {"long_value": "ShiftStateP"}, {"booleanValue": "ShiftStateP"}, {"locationValue": "ShiftStateP"},
    {"charging_value": "ShiftStateP"}, {"private-unknown-keyValue": "ShiftStateP"},
    {"invalid": True}, {"invalid": False}, {}, None, [],
    {"shiftStateValue": "ShiftStateP", "invalid": True},
    {"stringValue": "ShiftStateP", "shift_state_value": "ShiftStateD"},
])
@pytest.mark.parametrize("entry", ["chat", "panel"])
def test_malformed_or_invalid_gear_cannot_authorize_or_emit_park_event(service, fleet, vehicle_ref, clock, envelope, entry):
    service.settings = replace(service.settings, live_enabled=True)
    fleet.park = None
    telemetry = Telemetry(service.store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, "unlocked_parked", {"dwell_seconds": 1})
    # An earlier real P must not be carried forward through the new invalid record.
    telemetry.ingest("V", payload(clock, {"Gear": "ShiftStateP", "Locked": False, "DriverSeatOccupied": False}))
    clock.advance(1)
    telemetry.ingest("V", gear_payload(clock, envelope, Locked=False, DriverSeatOccupied=False))
    evidence = service.state(vehicle_ref, ["drive_state"], "cached_only", SCOPES)["park_evidence"]
    current = evidence["current_telemetry"]
    assert evidence["status"] == "unknown" and current["value"] is None
    assert current["quality"] == "invalid"
    assert current["input_evidence"]["normalization_reason"] != "recognized_gear_value"
    assert "private-unknown-key" not in json.dumps(evidence)
    assert evidence["last_valid_observation"]["age_seconds"] == pytest.approx(1, abs=1e-6)
    assert evidence["historical_observation_used_for_admission"] is False
    assert fleet.calls == []
    with service.store.db() as db:
        assert json.loads(db.execute("SELECT value FROM latest WHERE field='BatteryLevel'").fetchone()[0]) == 45
        assert not db.execute("SELECT 1 FROM events WHERE name='unlocked_parked'").fetchone()
    intent = service.prepare("window_control", {"command": "vent"}, vehicle_ref, "malformed-gear-guard", SCOPES)
    with pytest.raises(TeslaError) as error:
        if entry == "chat":
            service.execute_action_from_chat(intent["id"], intent["action_digest"], "execute", SCOPES)
        else:
            service.execute_from_owner(intent["id"])
    assert error.value.code == "PRECONDITION_FAILED"
    assert error.value.details["command_sent"] is False
    assert not any(name == "window_control" for name, *_ in fleet.calls)


@pytest.mark.parametrize("branch,value,expected_events", [
    ("stringValue", "ShiftStateP", 1), ("string_value", "ShiftStateP", 1),
    ("shiftStateValue", "ShiftStateP", 1), ("shift_state_value", "ShiftStateP", 1),
    ("stringValue", "P", 1), ("string_value", "P", 1),
    ("doorValue", "ShiftStateP", 0), ("bogusValue", "ShiftStateP", 0),
    ("intValue", "ShiftStateP", 0), ("long_value", "ShiftStateP", 0),
    ("booleanValue", "ShiftStateP", 0), ("locationValue", "ShiftStateP", 0),
    ("charging_value", "ShiftStateP", 0),
])
def test_unlocked_event_depends_on_gear_contract_with_other_requirements_met(store, vehicle_ref, clock, branch, value, expected_events):
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, "unlocked_parked", {"dwell_seconds": 1})
    telemetry.ingest("V", gear_payload(clock, {"shiftStateValue": "ShiftStateP"},
                                      Locked=False, DriverSeatOccupied=False))
    with store.db() as db:
        assert not db.execute("SELECT 1 FROM events WHERE name='unlocked_parked'").fetchone()
    clock.advance(1)
    # Every required field has two coherent, fresh observations and dwell elapsed.
    # The only difference from the positive controls is the Gear wire branch.
    telemetry.ingest("V", gear_payload(clock, {branch: value},
                                      Locked=False, DriverSeatOccupied=False))
    with store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM events WHERE name='unlocked_parked'").fetchone()[0] == expected_events


@pytest.mark.parametrize("value", [2, True, None, "P", "ShiftStateUnknown", "ShiftStateInvalid", "ShiftStateSNA"])
def test_unrecognized_or_unavailable_gear_value_is_not_park(value):
    assert typed_value("Gear", {"shiftStateValue": value})[1] != "valid"


@pytest.mark.parametrize("branch", ["stringValue", "string_value", "shiftStateValue", "shift_state_value"])
@pytest.mark.parametrize("value", ["p", "ShiftStatep", " P"])
def test_gear_normalization_does_not_guess_casing_or_whitespace(branch, value):
    assert typed_value("Gear", {branch: value})[1] != "valid"


@pytest.mark.parametrize("branch", ["stringValue", "string_value"])
def test_legacy_drive_conflicts_with_park_at_same_timestamp(store, vehicle_ref, clock, branch):
    telemetry = Telemetry(store)
    telemetry.ingest("V", gear_payload(clock, {"shiftStateValue": "ShiftStateP"}))
    telemetry.ingest("V", gear_payload(clock, {branch: "D"}))
    evidence = gear_view(store, vehicle_ref)
    assert evidence["current_telemetry"]["quality"] == "time_conflict"
    assert evidence["current_telemetry"]["value"] is None
    assert evidence["status"] != "verified"
    assert evidence["last_valid_observation"] is None


def test_absent_gear_staleness_and_explicit_invalid_have_distinct_effects(store, vehicle_ref, clock):
    telemetry = Telemetry(store)
    telemetry.ingest("V", gear_payload(clock, {"shiftStateValue": "ShiftStateP"}))
    first = gear_view(store, vehicle_ref)["current_telemetry"]
    clock.advance(5)
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 44}))
    still_current = gear_view(store, vehicle_ref)
    assert still_current["status"] == "verified"
    for key in ("quality", "source_timestamp", "received_at", "input_evidence"):
        assert still_current["current_telemetry"][key] == first[key]
    clock.advance(11)
    stale = gear_view(store, vehicle_ref)
    assert stale["status"] == "stale" and stale["current_telemetry"]["quality"] == "valid"
    telemetry.ingest("V", gear_payload(clock, {"invalid": True}))
    unavailable = gear_view(store, vehicle_ref)
    assert unavailable["status"] == "unknown"
    assert unavailable["current_telemetry"]["quality"] == "invalid"
    assert unavailable["current_telemetry"]["input_evidence"]["normalization_reason"] == "invalid_branch_received"
    assert unavailable["last_valid_observation"]["source_timestamp"] == first["source_timestamp"]
