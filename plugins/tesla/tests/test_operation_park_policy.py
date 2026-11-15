"""Per-operation admission; synthetic transport only, no vehicle calls."""
from dataclasses import replace

import pytest
from starlette.testclient import TestClient

from tesla_plugin.catalogue import describe
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.server import create_app
from test_operation_diagnostics import set_gear


@pytest.mark.parametrize("entry", ["chat", "panel"])
@pytest.mark.parametrize("gear", [None, "D", "P"])
def test_unlock_has_no_drive_query_and_preserves_once_only_dispatch(service, fleet, vehicle_ref, entry, gear):
    service.settings = replace(service.settings, live_enabled=True)
    fleet.park = gear
    set_gear(service.store, vehicle_ref, "ShiftStateD")
    item = service.prepare("door_unlock", {}, vehicle_ref, "unlock-policy-request", SCOPES)
    assert not any(r["id"] == "explicit_park" for r in item["requirements"])
    execute = (lambda: service.execute_action_from_chat(item["id"], item["action_digest"], "execute", SCOPES)) if entry == "chat" else lambda: service.execute_from_owner(item["id"])
    result = execute()
    assert result["status"] == "acknowledged"
    assert result["result"]["physical_effect_verified"] is False
    assert [name for name, *_ in fleet.calls] == ["vehicle_fleet_status", "door_unlock"]
    before = list(fleet.calls)
    execute()
    assert fleet.calls == before


@pytest.mark.parametrize("entry", ["chat", "panel"])
@pytest.mark.parametrize("rest,rest_age,gear,gear_age,quality,allowed,park_verified", [
    (None, 0, None, 0, "invalid", True, False),
    (None, 0, "ShiftStateP", 16, "valid", True, False),
    ("P", 0, None, 0, "invalid", True, True),
    ("D", 0, None, 0, "invalid", False, False),
    ("R", 0, None, 0, "invalid", False, False),
    ("N", 0, None, 0, "invalid", False, False),
    (None, 0, "ShiftStateD", 1, "valid", False, False),
    ("P", 20, "ShiftStateD", 1, "valid", False, False),
    ("P", 20, "ShiftStateD", 16, "valid", False, False),
    ("D", 1, "ShiftStateP", 0, "valid", False, False),
])
def test_keyless_drive_keeps_evidence_unknown_and_blocks_driving_or_conflict(
        service, fleet, vehicle_ref, clock, entry, rest, rest_age, gear, gear_age, quality, allowed, park_verified):
    service.settings = replace(service.settings, live_enabled=True)
    set_gear(service.store, vehicle_ref, gear, age=gear_age, quality=quality)
    original = fleet.call
    def response(name, *args, **kwargs):
        result = original(name, *args, **kwargs)
        if name == "vehicle_vehicle_data":
            result["drive_state"] = {"shift_state": rest, "timestamp": (clock()-rest_age)*1000}
        return result
    fleet.call = response
    item = service.prepare("remote_start_drive", {}, vehicle_ref, "keyless-policy-request", SCOPES)
    execute = (lambda: service.execute_action_from_chat(item["id"], item["action_digest"], "execute", SCOPES)) if entry == "chat" else lambda: service.execute_from_owner(item["id"])
    if allowed:
        result = execute()
        assert result["status"] == "acknowledged"
        admission = result["result"]["admission"]
        assert admission["allows_dispatch"] and admission["park_verified"] is park_verified
        assert (admission["status"] == "verified") is park_verified
        assert result["result"]["physical_effect_verified"] is False
        before = list(fleet.calls)
        execute()
        assert fleet.calls == before
    else:
        with pytest.raises(TeslaError) as exc:
            execute()
        assert exc.value.code == "PRECONDITION_FAILED"
        assert exc.value.details["command_sent"] is False
        assert exc.value.details["precondition"]["id"] == "no_recent_driving_gear"
    assert sum(name == "remote_start_drive" for name, *_ in fleet.calls) == int(allowed)
    assert not any(name == "vehicle_wake_up" for name, *_ in fleet.calls)


def test_keyless_requirements_and_panel_do_not_claim_park_for_missing_gear(service, fleet, vehicle_ref):
    requirements = describe("remote_start_drive")["requirements"]
    policy = next(r for r in requirements if r["id"] == "no_recent_driving_gear")
    assert not policy["unknown_blocks"] and policy["conflict_blocks"]
    assert any(r["id"] == "keyless_driving_enabled" for r in requirements)
    fleet.park = None
    item = service.prepare("remote_start_drive", {}, vehicle_ref, "keyless-unknown-panel", SCOPES)
    service.execute_from_owner(item["id"])
    from test_mcp_portal import login
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        login(client)
        before = list(fleet.calls)
        page = client.get("/tesla/owner/intents/"+item["id"])
        assert page.status_code == 200 and "Park not established" in page.text
        assert fleet.calls == before


@pytest.mark.parametrize("operation", ["door_unlock", "remote_start_drive"])
def test_new_policy_retains_digest_scope_and_uncertain_result_protections(service, fleet, vehicle_ref, operation):
    service.settings = replace(service.settings, live_enabled=True)
    fleet.park = None
    item = service.prepare(operation, {}, vehicle_ref, "policy-auth-protections", SCOPES)
    with pytest.raises(TeslaError):
        service.execute_action_from_chat(item["id"], "0"*64, "execute", SCOPES)
    with pytest.raises(TeslaError):
        service.execute_action_from_chat(item["id"], item["action_digest"], "execute", ["tesla:read"])
    assert fleet.calls == []
    fleet.error = TeslaError("OUTCOME_UNKNOWN", "synthetic timeout", uncertain=True)
    assert service.execute_action_from_chat(item["id"], item["action_digest"], "execute", SCOPES)["status"] == "unknown"
    before = list(fleet.calls)
    assert service.execute_action_from_chat(item["id"], item["action_digest"], "execute", SCOPES)["status"] == "unknown"
    assert fleet.calls == before
