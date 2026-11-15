"""Public FAQ reason and synthetic transport only; no vehicle or raw private logs."""
from dataclasses import replace
import json

import httpx
import pytest
from starlette.testclient import TestClient

from tesla_plugin.config import SCOPES
from tesla_plugin.fleet import Fleet
from tesla_plugin.provider_diagnostics import rejection_reason
from tesla_plugin.server import create_app
from test_mcp_portal import login, rpc


PUBLIC_REASON = "cabin comfort remote settings not enabled"
SDK_PREFIX = "car could not execute command: "
REASON_CODE = "CABIN_COMFORT_REMOTE_SETTINGS_DISABLED"


@pytest.fixture(autouse=True)
def no_external_http(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected external HTTP request")
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)


@pytest.mark.parametrize("reason", [PUBLIC_REASON, SDK_PREFIX+PUBLIC_REASON])
def test_official_comfort_reason_is_distinct_from_observed_hvac_state(reason):
    result = rejection_reason(reason)
    assert result["reason_code"] == REASON_CODE
    assert result["provider_reason_present"] is True
    assert not result.get("reason_withheld")
    assert "preconditioning" in result["reason"] and "climate keeper" in result["reason"]
    assert "non è attiva" not in result["reason"]
    assert result.get("reason_format") == ("sdk_nominal_error" if reason.startswith(SDK_PREFIX) else None)
    assert rejection_reason("is_climate_on is false")["reason_code"] == "CLIMATE_NOT_ACTIVE"


@pytest.mark.parametrize("reason", [
    PUBLIC_REASON+" private-marker",
    SDK_PREFIX+PUBLIC_REASON+" private-marker",
    "private-marker "+PUBLIC_REASON,
    SDK_PREFIX+SDK_PREFIX+PUBLIC_REASON,
    SDK_PREFIX+PUBLIC_REASON+"\nprivate-marker",
    PUBLIC_REASON+"x"*4096,
    "cabin comfort remote settings",
])
def test_near_matches_remain_withheld(reason):
    result = rejection_reason(reason)
    assert result["reason_code"] == "PROVIDER_REASON_UNCLASSIFIED"
    assert result["reason_withheld"] is True
    assert "private-marker" not in json.dumps(result)
    assert "preconditioning" not in result["reason"]


@pytest.mark.parametrize("entry", ["chat", "panel"])
@pytest.mark.parametrize("http_status,status,code", [
    (200, "rejected", "COMMAND_REJECTED"),
    (400, "rejected", "PROVIDER_ERROR"),
    (408, "unknown", "OUTCOME_UNKNOWN"),
    (500, "unknown", "OUTCOME_UNKNOWN"),
])
def test_comfort_diagnostic_preserves_command_outcome_and_never_retries(
        service, store, vehicle_ref, headers, entry, http_status, status, code):
    service.settings = replace(service.settings, live_enabled=True)
    store.settings = service.settings
    old = service.prepare("remote_seat_heater_request", {"seat_position": 0, "level": 1},
                          vehicle_ref, "comfort-historical-rejection", SCOPES)
    historical = json.dumps({"accepted": False, "physical_effect_verified": False,
        "reason_code": "PROVIDER_REASON_UNCLASSIFIED", "reason_withheld": True})
    with store.db() as db:
        db.execute("UPDATE intents SET status='rejected',result=? WHERE id=?", (historical, old["id"]))

    item = service.prepare("remote_seat_heater_request", {"seat_position": 1, "level": 1},
                           vehicle_ref, "comfort-diagnostic-only", SCOPES)
    requests = []
    def response(request):
        requests.append(request)
        assert request.method == "POST"
        if request.url.path.endswith("/fleet_status"):
            vin = json.loads(request.content)["vins"][0]
            return httpx.Response(200, json={"response": {"key_paired_vins": [vin],
                "vehicle_info": {vin: {"vehicle_command_protocol_required": True}}}})
        assert request.url.host == "proxy.example"
        assert request.url.path.endswith("/command/remote_seat_heater_request")
        assert json.loads(request.content) == {"seat_position": 1, "level": 1}
        return httpx.Response(http_status, json={"response": {"result": False,
            "reason": SDK_PREFIX+PUBLIC_REASON}, "private-field": "private-marker"})

    service.fleet = Fleet(store, transport=httpx.MockTransport(response))
    try:
        with TestClient(create_app(service.settings, service=service, start_worker=False),
                        base_url="https://bridge.example") as client:
            csrf = login(client)
            arguments = {"intent_id": item["id"], "action_digest": item["action_digest"], "decision": "execute"}
            if entry == "chat":
                executed = rpc(client, headers(), "tools/call", {
                    "name": "tesla_execute_action", "arguments": arguments}).json()["result"]
                assert executed["isError"] is True
                assert executed["structuredContent"]["status"] == status
            else:
                executed = client.post("/tesla/owner/intents/"+item["id"],
                    data={"csrf": csrf, "decision": "execute"}, headers={"origin": "https://bridge.example"})
                assert executed.status_code == 200

            read = rpc(client, headers(), "tools/call", {"name": "tesla_get_operation",
                "arguments": {"intent_id": item["id"]}}).json()["result"]
            assert not read.get("isError")
            view = read["structuredContent"]
            assert view["status"] == status
            outcome = view["result"]
            assert outcome["code"] == code
            assert view["verification"]["effect_observed"] is False
            diagnostic = outcome["diagnostic"]
            assert diagnostic["reason_code"] == REASON_CODE
            assert diagnostic["automatic_retry"] is False
            assert diagnostic["provider_http_status"] == http_status
            assert diagnostic["transport"] == "signed_proxy"
            if http_status == 200:
                assert outcome["accepted"] is False
                assert outcome["reason_code"] == REASON_CODE
            if status == "unknown":
                assert outcome["outcome"] == "unknown"
            page = client.get("/tesla/owner/intents/"+item["id"])
            if status == "rejected":
                assert "preconditioning" in page.text
                assert "climate keeper" in page.text
            assert "private-marker" not in json.dumps(read)+page.text

            # Local reads and an explicit repeat of the same intent must not
            # send a second command, wake the car or start climate implicitly.
            rpc(client, headers(), "tools/call", {"name": "tesla_execute_action", "arguments": arguments})
            old_read = rpc(client, headers(), "tools/call", {"name": "tesla_get_operation",
                "arguments": {"intent_id": old["id"]}}).json()["result"]["structuredContent"]
            assert old_read["status"] == "rejected"
            assert old_read["result"]["reason_code"] == "PROVIDER_REASON_UNCLASSIFIED"
            assert len(requests) == 2  # Existing pairing check + one heater command.
            with store.db() as db:
                assert db.execute("SELECT result FROM intents WHERE id=?", (old["id"],)).fetchone()[0] == historical
                saved = [row[0] for row in db.execute("SELECT value FROM meta WHERE key GLOB 'request_diagnostic:*'")]
            assert "private-marker" not in json.dumps(saved)
    finally:
        service.fleet.close()
