"""V1 boundaries exercised across ingestion, persistence and public operations.

Synthetic values and fake Fleet only. Reopening the same database also runs the
schema admission path: historical evidence must not become new authorization.
"""
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from conftest import VIN
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.service import Service
from tesla_plugin.store import Store, canonical, utc
from tesla_plugin.telemetry import Telemetry
from tesla_plugin.temporary_collection import CHECK_SECONDS, TemporaryCollection
from test_temporary_collection import temporary_setup, start as start_window


def frame(clock, field, envelope, *, when=None):
    return {"vin": VIN, "createdAt": utc(clock() if when is None else when),
            "data": [{"key": field, "value": envelope}]}


def reopen(service, clock):
    store = Store(service.settings, clock=clock)
    service.fleet.store = store
    return Service(service.settings, store=store, fleet=service.fleet)


@pytest.mark.parametrize("case,expected", [
    ("D", "not_park"), ("R", "not_park"), ("N", "not_park"),
    ("invalid", "unknown"), ("timestamp_conflict", "conflicting"),
    ("source_conflict", "conflicting"),
])
def test_ingested_nonpark_or_unknown_cannot_recover_old_park_after_reopen(
        service, vehicle_ref, fleet, clock, case, expected):
    telemetry = Telemetry(service.store)
    telemetry.ingest("V", frame(clock, "Gear", {"shiftStateValue": "ShiftStateP"}))
    clock.advance(1)
    if case == "timestamp_conflict":
        telemetry.ingest("V", frame(clock, "Gear", {"shiftStateValue": "ShiftStateP"}))
    envelope = ({"invalid": True} if case == "invalid" else
                {"shiftStateValue": "ShiftState"+(case if case in ("D", "R", "N") else "D")})
    telemetry.ingest("V", frame(clock, "Gear", envelope))
    fleet.park = "P" if case == "source_conflict" else None
    restarted = reopen(service, clock)
    item = restarted.prepare("actuate_trunk", {"which_trunk": "front"}, vehicle_ref,
                             "v1-park-restart-"+case, SCOPES)
    with pytest.raises(TeslaError) as error:
        restarted.execute_from_owner(item["id"])
    assert error.value.code == "PRECONDITION_FAILED"
    assert error.value.details["precondition"]["status"] == expected
    if case == "timestamp_conflict":
        observation = next(row for row in error.value.details["precondition"]["observations"]
                           if row["source"] == "fleet_telemetry")
        assert observation["quality"] == "time_conflict"
        assert observation["fresh"] and not observation["usable"]
    assert error.value.details["command_sent"] is False
    assert restarted.intent_view(item["id"])["status"] == "prepared"
    assert not any(name in ("actuate_trunk", "vehicle_wake_up") for name, *_ in fleet.calls)


@pytest.mark.parametrize("field", ["Location", "RemoteStartActive"])
@pytest.mark.parametrize("revoked", ["plugin_scope", "tesla_scope", "hide_private"])
def test_history_continuation_rechecks_location_grant_after_reopen(
        service, vehicle_ref, clock, fleet, field, revoked):
    start = clock()
    telemetry = Telemetry(service.store)
    for latitude in (10.125, 10.375):
        telemetry.ingest("V", frame(clock, field, {
            "locationValue": {"latitude": latitude, "longitude": 20.875}}))
        clock.advance(1)
    first = service.history(vehicle_ref, [field], start-1, clock()+1, SCOPES, limit=1)
    assert first["next_cursor"] and first["samples"][0]["value"]["latitude"] == 10.125
    scopes = SCOPES
    with service.store.db() as db:
        if revoked == "plugin_scope":
            scopes = [scope for scope in SCOPES if scope != "tesla:location"]
        elif revoked == "tesla_scope":
            grant = json.loads(db.execute("SELECT scopes FROM connection WHERE id=1").fetchone()[0])
            db.execute("UPDATE connection SET scopes=? WHERE id=1",
                       (canonical([scope for scope in grant if scope != "vehicle_location"]),))
        else:
            data = json.loads(db.execute("SELECT data FROM vehicles WHERE ref=?", (vehicle_ref,)).fetchone()[0])
            data["granular_access"]["hide_private"] = True
            db.execute("UPDATE vehicles SET data=? WHERE ref=?", (canonical(data), vehicle_ref))
    restarted = reopen(service, clock)
    with pytest.raises(TeslaError) as error:
        restarted.history(vehicle_ref, [field], start-1, clock()+1, scopes,
                          limit=1, cursor=first["next_cursor"])
    assert error.value.code == ("SCOPE_REQUIRED" if revoked == "plugin_scope" else "LOCATION_WITHHELD")
    assert "10.375" not in canonical(error.value.public())
    assert "20.875" not in canonical(error.value.public())
    assert fleet.calls == []


def test_history_cursor_survives_restart_and_excludes_late_and_new_arrivals(
        service, vehicle_ref, clock, fleet):
    start = clock()
    telemetry = Telemetry(service.store)
    originals = []
    for value in range(4):
        originals.append(frame(clock, "BatteryLevel", {"doubleValue": value}))
        telemetry.ingest("V", originals[-1])
        clock.advance(1)
    first = service.history(vehicle_ref, ["BatteryLevel"], start-1, start+20, SCOPES, limit=2)
    assert [row["value"] for row in first["samples"]] == [0, 1]
    restarted = reopen(service, clock)
    telemetry = Telemetry(restarted.store)
    assert telemetry.ingest("V", originals[-1] | {"isResend": True})["status"] == "duplicate"
    telemetry.ingest("V", frame(clock, "BatteryLevel", {"doubleValue": 50}, when=start+2.5))
    telemetry.ingest("V", frame(clock, "BatteryLevel", {"doubleValue": 70}, when=start+3))
    telemetry.ingest("V", frame(clock, "BatteryLevel", {"doubleValue": 60}))
    second = restarted.history(vehicle_ref, ["BatteryLevel"], start-1, start+20,
                               SCOPES, limit=2, cursor=first["next_cursor"])
    assert [row["value"] for row in second["samples"]] == [2, 3]
    assert second["next_cursor"] is None and not second["truncated"]
    assert second["snapshot_at"] == first["snapshot_at"]
    assert all(row["timestamp_conflict"] is False for row in second["samples"])
    fresh = restarted.history(vehicle_ref, ["BatteryLevel"], start-1, start+20, SCOPES)
    assert [row["value"] for row in fresh["samples"][:4]] == [0, 1, 2, 50]
    assert {row["value"] for row in fresh["samples"][4:6]} == {3, 70}
    assert all(row["timestamp_conflict"] is True for row in fresh["samples"][4:6])
    assert fresh["samples"][-1]["value"] == 60
    assert fresh["complete_history"] is False
    with restarted.store.db() as db:
        latest = db.execute("SELECT value FROM latest WHERE vehicle=? AND field='BatteryLevel'",
                            (vehicle_ref,)).fetchone()[0]
    assert json.loads(latest) == 60
    assert fleet.calls == []


@pytest.mark.parametrize("outcome", ["acknowledged", "rejected", "unknown"])
def test_final_command_outcome_survives_reopen_without_replay_or_effect_claim(
        service, vehicle_ref, clock, fleet, outcome):
    if outcome == "rejected":
        fleet.result = {"result": False}
    elif outcome == "unknown":
        fleet.error = TeslaError("OUTCOME_UNKNOWN", "Synthetic interrupted response", uncertain=True)
    item = service.prepare("set_charge_limit", {"percent": 80}, vehicle_ref,
                           "v1-durable-action-"+outcome, SCOPES)
    first = service.execute_from_owner(item["id"])
    assert first["status"] == outcome
    calls = list(fleet.calls)
    restarted = reopen(service, clock)
    restarted.store.recover_inflight()
    replay = restarted.execute_from_owner(item["id"])
    assert replay["status"] == outcome
    assert replay["result"].get("physical_effect_verified") is not True
    assert replay["verification"]["effect_observed"] is False
    assert fleet.calls == calls
    assert sum(name == "set_charge_limit" for name, *_ in calls) == 1


def test_late_restore_read_failure_cannot_reactivate_superseded_window(
        temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, manager, _, provider = temporary_setup
    item = start_window(temporary_setup, vehicle_ref)
    clock.advance(60)
    entered, release = Event(), Event()

    def delayed_read(name, arguments=None, **kwargs):
        if name == "vehicle_fleet_telemetry_config_get":
            entered.set()
            assert release.wait(5)
            raise TeslaError("PROVIDER_UNAVAILABLE", "Synthetic delayed read failure")
        return provider(name, arguments, **kwargs)

    monkeypatch.setattr(fleet, "call", delayed_read)
    with ThreadPoolExecutor(1) as pool:
        worker = pool.submit(TemporaryCollection(service).tick)
        assert entered.wait(5)
        try:
            later = manager.prepare_change(vehicle_ref, "pause", manager.view(vehicle_ref)["revision"],
                                           "v1-owner-supersedes-during-read", SCOPES)
            service.execute_from_owner(later["id"])
        finally:
            release.set()
        assert worker.result()["status"] == "superseded"
    with service.store.db() as db:
        row = db.execute("SELECT status,lease_owner FROM temporary_collections WHERE intent_id=?",
                         (item["id"],)).fetchone()
    assert tuple(row) == ("superseded", None)
    calls = list(fleet.calls)
    clock.advance(CHECK_SECONDS)
    assert TemporaryCollection(service).tick() is None
    assert fleet.calls == calls


def test_vehicle_revocation_and_reappearance_do_not_reauthorize_old_restore(
        temporary_setup, vehicle_ref, clock, fleet):
    service = temporary_setup[0]
    item = start_window(temporary_setup, vehicle_ref)
    generation = service.store.connection()["generation"]
    service.store.save_vehicles([])
    service.store.save_vehicles([{
        "vin": VIN, "display_name": "Synthetic reauthorized vehicle", "state": "online",
        "access_type": "OWNER", "granular_access": {"hide_private": False},
    }])
    assert service.store.vehicle(vehicle_ref)["active"]
    assert service.store.connection()["generation"] == generation
    restarted = reopen(service, clock)
    calls = list(fleet.calls)
    clock.advance(61)
    TemporaryCollection(restarted).tick()
    with restarted.store.db() as db:
        row = db.execute("SELECT status,error FROM temporary_collections WHERE intent_id=?",
                         (item["id"],)).fetchone()
    assert tuple(row) == ("blocked", "VEHICLE_ACCESS_REVOKED")
    assert fleet.calls == calls


def test_baseline_readback_does_not_claim_unknown_temporary_start_was_accepted(
        temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, _, _, provider = temporary_setup

    def uncertain_without_apply(name, arguments=None, **kwargs):
        if name == "vehicle_fleet_telemetry_config_create":
            fleet.calls.append((name, arguments, None))
            raise TeslaError("OUTCOME_UNKNOWN", "Synthetic request outcome unavailable", uncertain=True)
        return provider(name, arguments, **kwargs)

    monkeypatch.setattr(fleet, "call", uncertain_without_apply)
    item = start_window(temporary_setup, vehicle_ref)
    assert service.intent_view(item["id"])["status"] == "unknown"
    monkeypatch.setattr(fleet, "call", provider)
    clock.advance(60)
    assert TemporaryCollection(service).tick()["restore_verified"]
    original = service.intent_view(item["id"])
    assert original["status"] != "acknowledged"
    assert original["verification"]["command_accepted"] is False
    assert original["verification"]["effect_observed"] is False
    assert original["result"].get("configuration_verified") is not True
    assert original["result"]["start_effect_unknown"] is True
    assert sum(name == "vehicle_fleet_telemetry_config_create" for name, *_ in fleet.calls) == 1


def test_baseline_readback_does_not_claim_unknown_restore_command_was_accepted(
        temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, _, _, provider = temporary_setup
    start_window(temporary_setup, vehicle_ref)

    def lost_restore_response(name, arguments=None, **kwargs):
        response = provider(name, arguments, **kwargs)
        if name == "vehicle_fleet_telemetry_config_create":
            raise TeslaError("OUTCOME_UNKNOWN", "Synthetic restore response lost", uncertain=True)
        return response

    monkeypatch.setattr(fleet, "call", lost_restore_response)
    clock.advance(60)
    pending = TemporaryCollection(service).tick()
    assert pending["status"] == "restore_unknown"
    restore_id = pending["restore_intent_id"]
    assert service.intent_view(restore_id)["status"] == "unknown"
    clock.advance(CHECK_SECONDS)
    assert TemporaryCollection(service).tick()["restore_verified"]
    restore = service.intent_view(restore_id)
    assert restore["status"] != "acknowledged"
    assert restore["verification"]["command_accepted"] is False
    assert restore["verification"]["effect_observed"] is False
    assert sum(name == "vehicle_fleet_telemetry_config_create" for name, *_ in fleet.calls) == 2
