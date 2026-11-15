"""Explicit text/voice commands share the owner execution checks and audit."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor

import pytest
from starlette.testclient import TestClient

from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.server import create_app
from test_shared_settings import call
from test_mcp_portal import rpc


@pytest.fixture
def live_service(service):
    service.settings = replace(service.settings, live_enabled=True)
    return service


def test_explicit_wake_uses_one_fleet_call_and_replay_does_not_wake_again(live_service, fleet, vehicle_ref, headers):
    service = live_service
    fleet.result = {"state": "online", "vin": "DO-NOT-EXPOSE", "display_name": "Demo vehicle"}
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        args = {"vehicle_ref": vehicle_ref, "client_request_id": "explicit-wake-request-01"}
        result = call(client, headers(), "tesla_wake_up", **args)
        assert result["status"] == "acknowledged" and result["vehicle_online_observed"] is True
        assert "DO-NOT-EXPOSE" not in str(result)
        assert call(client, headers(), "tesla_wake_up", **args)["intent_id"] == result["intent_id"]
        intent = call(client, headers(), "tesla_get_operation", intent_id=result["intent_id"])
        assert intent["result"]["confirmation_source"] == "explicit_chat_request"
    assert [name for name, *_ in fleet.calls] == ["vehicle_wake_up"]


def test_uncertain_wake_cannot_be_automatically_repeated(live_service, fleet, vehicle_ref):
    fleet.error = TeslaError("OUTCOME_UNKNOWN", "synthetic timeout", uncertain=True)
    first = live_service.wake_from_chat(vehicle_ref, "explicit-wake-timeout-01", SCOPES)
    assert first["status"] == "unknown" and not first["vehicle_online_observed"]
    assert live_service.wake_from_chat(vehicle_ref, "explicit-wake-timeout-01", SCOPES)["status"] == "unknown"
    with pytest.raises(TeslaError, match='already in progress'):
        live_service.wake_from_chat(vehicle_ref, "different-wake-request-02", SCOPES)
    assert len(fleet.calls) == 1


def test_wake_requires_command_scope_and_live_mode(service, fleet, vehicle_ref, headers):
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        args = {"vehicle_ref": vehicle_ref, "client_request_id": "explicit-wake-disabled-01"}
        denied = rpc(client, headers(scopes=["tesla:read"]), "tools/call", {"name": "tesla_wake_up", "arguments": args}).json()["result"]
        assert denied["isError"] and "tesla:commands" in str(denied)
        disabled = rpc(client, headers(), "tools/call", {"name": "tesla_wake_up", "arguments": args}).json()["result"]
        assert disabled["isError"] and "LIVE_DISABLED" in str(disabled)
    assert fleet.calls == []


def test_chat_action_digest_cancel_and_concurrent_execution(live_service, fleet, vehicle_ref):
    service = live_service
    intent = service.prepare("set_charge_limit", {"percent": 80}, vehicle_ref, "chat-command-synthetic-01", SCOPES)
    with pytest.raises(TeslaError, match="review"):
        service.execute_action_from_chat(intent["id"], "0"*64, "execute", SCOPES)
    assert fleet.calls == []
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: service.execute_action_from_chat(intent["id"], intent["action_digest"], "execute", SCOPES), range(2)))
    assert sum(name == "set_charge_limit" for name, *_ in fleet.calls) == 1
    assert service.intent_view(intent["id"])["result"]["confirmation_source"] == "explicit_chat_request"
    cancel = service.prepare("set_charge_limit", {"percent": 85}, vehicle_ref, "chat-command-synthetic-02", SCOPES)
    assert service.execute_action_from_chat(cancel["id"], cancel["action_digest"], "cancel", SCOPES)["status"] == "cancelled"


def test_chat_actions_preserve_park_and_secret_field_requirements(live_service, fleet, vehicle_ref):
    service = live_service
    fleet.park = "D"
    trunk = service.prepare("actuate_trunk", {"which_trunk": "front"}, vehicle_ref, "chat-command-synthetic-03", SCOPES)
    with pytest.raises(TeslaError, match="Park"):
        service.execute_action_from_chat(trunk["id"], trunk["action_digest"], "execute", SCOPES)
    pin = service.prepare("parental_controls_activate", {}, vehicle_ref, "chat-command-synthetic-04", SCOPES)
    with pytest.raises(TeslaError, match="secret fields"):
        service.execute_action_from_chat(pin["id"], pin["action_digest"], "execute", SCOPES)
    assert not any(name in ("actuate_trunk", "parental_controls_activate") for name, *_ in fleet.calls)


def test_reading_or_changing_triggers_never_wakes(live_service, fleet, vehicle_ref, headers):
    with TestClient(create_app(live_service.settings, service=live_service, start_worker=False), base_url="https://bridge.example") as client:
        for name, args in (("tesla_connection_status", {}), ("tesla_get_state", {"vehicle_ref": vehicle_ref, "freshness": "cached_only"}),
                           ("tesla_get_collection", {"vehicle_ref": vehicle_ref}),
                           ("tesla_update_triggers", {"vehicle_ref": vehicle_ref, "expected_revision": 0, "preset": "recommended"})):
            call(client, headers(), name, **args)
    assert fleet.calls == []


def test_new_tools_discovery_separates_effects(live_service, headers):
    with TestClient(create_app(live_service.settings, service=live_service, start_worker=False), base_url="https://bridge.example") as client:
        tools = {t["name"]: t for t in rpc(client, headers(), "tools/list").json()["result"]["tools"]}
        assert len(tools) == 24
        assert tools["tesla_execute_action"]["annotations"]["destructiveHint"] is True
        assert tools["tesla_wake_up"]["annotations"]["readOnlyHint"] is False
        assert "tesla:commands" in tools["tesla_wake_up"]["securitySchemes"][0]["scopes"]
        assert "for_triggers" in tools["tesla_get_collection"]["inputSchema"]["properties"]


def test_cancelling_an_intent_after_location_scope_removal_does_not_return_coordinates(live_service, fleet, vehicle_ref, headers):
    service = live_service
    intent = service.prepare("trigger_homelink", {"lat": 12.34, "lon": 56.78}, vehicle_ref,
                             "chat-cancel-location-01", SCOPES)
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        result = call(client, headers(scopes=["tesla:read", "tesla:commands"]), "tesla_execute_action",
                      intent_id=intent["id"], action_digest=intent["action_digest"], decision="cancel")
        assert result["status"] == "cancelled"
        assert "lat" not in result["arguments"] and "lon" not in result["arguments"]
    assert fleet.calls == []
