"""Cached MCP reads must not refresh vehicle membership through Tesla."""
from dataclasses import replace

import httpx
import pytest
from starlette.testclient import TestClient

from tesla_plugin.config import SCOPES
from tesla_plugin.events import Events
from tesla_plugin.fleet import Fleet
from tesla_plugin.server import create_app
from tesla_plugin.service import Service
from tesla_plugin.store import utc
from tesla_plugin.telemetry import Telemetry
from test_mcp_portal import rpc
from test_telemetry_events import payload

pytestmark = pytest.mark.integration
LOCAL_TOOLS = ("tesla_get_state", "tesla_get_capabilities", "tesla_get_history",
               "tesla_list_rules", "tesla_get_event")


@pytest.fixture
def cached_case(store, clock, vehicle_ref):
    observed = clock()
    store.snapshot(vehicle_ref, "charge_state", {"battery_level": 80}, "synthetic_rest_fixture", observed)
    Telemetry(store).ingest("V", payload(clock, {"BatteryLevel": 80}))
    with store.db() as db:
        event = Events.emit(db, vehicle_ref, "battery_low", observed,
                            {"observed": {"BatteryLevel": 80}}, observed)
    clock.advance(15 * 3600)
    return {
        "tesla_get_state": {"vehicle_ref": vehicle_ref, "freshness": "cached_only"},
        "tesla_get_capabilities": {"vehicle_ref": vehicle_ref, "refresh": False},
        "tesla_get_history": {"vehicle_ref": vehicle_ref, "fields": ["BatteryLevel"],
                              "after": observed - 1, "before": clock()},
        "tesla_list_rules": {"vehicle_ref": vehicle_ref},
        "tesla_get_event": {"event_id": event},
    }


def no_network(request):
    pytest.fail("A local read attempted an outbound HTTP request")


@pytest.mark.parametrize("name", LOCAL_TOOLS)
@pytest.mark.parametrize("live", [False, True])
def test_local_reads_keep_old_membership_without_network(settings, store, headers, vehicle_ref, cached_case, name, live):
    settings = replace(settings, live_enabled=live)
    store.settings = settings
    service = Service(settings, store=store, fleet=Fleet(store, transport=httpx.MockTransport(no_network)))
    checked = store.vehicle(vehicle_ref)["checked"]
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        result = rpc(client, headers(), "tools/call", {"name": name, "arguments": cached_case[name]}).json()["result"]
    assert result.get("isError", False) is False, result
    data = result["structuredContent"]
    assert data["membership_fresh"] is False
    assert data["authorization_checked_at"] == utc(checked)
    assert store.vehicle(vehicle_ref)["checked"] == checked
    if name == "tesla_get_state":
        assert data["data"]["charge_state"]["data"]["battery_level"] == 80
        assert data["data"]["charge_state"]["quality"] == "stale"
        assert data["data"]["charge_state"]["source"] == "synthetic_rest_fixture"
        assert data["data"]["climate_state"] == {"quality": "missing", "data": None}
        assert data["wake_sent"] is False
    elif name == "tesla_get_capabilities":
        assert data["fleet_status"] == {"state": "unknown"}
    elif name == "tesla_get_history":
        assert len(data["samples"]) == 1
        assert data["samples"][0]["value"] == 80
    elif name == "tesla_list_rules":
        assert len(data["rules"]) == 6
    else:
        assert data["data"]["observed"]["BatteryLevel"] == 80
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM requests").fetchone()[0] == 0


@pytest.mark.parametrize("name", LOCAL_TOOLS[:-1])
@pytest.mark.parametrize("revocation,code", [("removed", "VEHICLE_ACCESS_REQUIRED"),
                                            ("reauth_required", "AUTH_REQUIRED"), ("disconnect", "AUTH_REQUIRED")])
def test_local_reads_still_reject_revoked_access(settings, store, headers, cached_case, name, revocation, code):
    if revocation == "removed":
        store.save_vehicles([])
    elif revocation == "disconnect":
        store.disconnect()
    else:
        with store.db() as db:
            db.execute("UPDATE connection SET status='reauth_required'")
    service = Service(settings, store=store, fleet=Fleet(store, transport=httpx.MockTransport(no_network)))
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        result = rpc(client, headers(), "tools/call", {"name": name, "arguments": cached_case[name]}).json()["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["code"] == code
    assert "battery_level" not in str(result)


@pytest.mark.parametrize("restriction,code", [("plugin_scope", "SCOPE_REQUIRED"),
                                             ("tesla_scope", "LOCATION_WITHHELD"), ("hide_private", "LOCATION_WITHHELD")])
def test_cached_location_still_requires_both_permissions(settings, store, headers, vehicle_ref, cached_case, restriction, code):
    Telemetry(store).configure_rule(vehicle_ref, "geofence", {"latitude": 48.2, "longitude": 16.3, "radius_m": 100})
    scopes = SCOPES
    with store.db() as db:
        if restriction == "plugin_scope":
            scopes = [s for s in SCOPES if s != "tesla:location"]
        elif restriction == "tesla_scope":
            db.execute("UPDATE connection SET scopes='[\"vehicle_device_data\"]'")
        else:
            db.execute("UPDATE vehicles SET data=json_set(data, '$.granular_access.hide_private', json('true'))")
    service = Service(settings, store=store, fleet=Fleet(store, transport=httpx.MockTransport(no_network)))
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        result = rpc(client, headers(scopes=scopes), "tools/call", {"name": "tesla_get_state", "arguments": {
            "vehicle_ref": vehicle_ref, "sections": ["drive_state"], "freshness": "cached_only"}}).json()["result"]
        rules = rpc(client, headers(scopes=scopes), "tools/call", {"name": "tesla_list_rules", "arguments": {
            "vehicle_ref": vehicle_ref}}).json()["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["code"] == code
    assert rules.get("isError", False) is False
    assert [r["config"] for r in rules["structuredContent"]["rules"] if r["kind"] == "geofence"] == [None]


@pytest.mark.parametrize("name", ["tesla_get_state", "tesla_get_capabilities", "tesla_prepare_action"])
def test_explicit_live_paths_remain_closed(settings, store, headers, vehicle_ref, cached_case, name):
    arguments = {"vehicle_ref": vehicle_ref}
    if name == "tesla_get_state":
        arguments["freshness"] = "live_if_online"
    elif name == "tesla_get_capabilities":
        arguments["refresh"] = True
    else:
        arguments.update(operation="set_charge_limit", arguments={"percent": 80}, client_request_id="closed-pilot-request-01")
    service = Service(settings, store=store, fleet=Fleet(store, transport=httpx.MockTransport(no_network)))
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        result = rpc(client, headers(), "tools/call", {"name": name, "arguments": arguments}).json()["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["code"] == "LIVE_DISABLED"
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM intents").fetchone()[0] == 0
