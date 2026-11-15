"""HTTP error diagnostics from synthetic provider bodies; never contact Tesla."""
from dataclasses import replace
import json

import httpx
import pytest
from starlette.testclient import TestClient

from tesla_plugin.errors import TeslaError
from tesla_plugin.fleet import Fleet
from tesla_plugin.provider_diagnostics import http_rejection_reason
from tesla_plugin.server import create_app
from test_mcp_portal import rpc


PRIVATE = "synthetic-private-provider-text"


@pytest.fixture(autouse=True)
def no_external_http(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Only synthetic HTTP is allowed")
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)


@pytest.mark.parametrize("body,code,source", [
    ({"code": 400, "message": "invalid value"}, "PROVIDER_VALUE_REJECTED", "message"),
    ({"message": "car could not execute command: cabin comfort remote settings not enabled"},
     "CABIN_COMFORT_REMOTE_SETTINGS_DISABLED", "message"),
    ({"message": PRIVATE}, "PROVIDER_REASON_UNCLASSIFIED", "message"),
    ({"message": "invalid value " + PRIVATE}, "PROVIDER_REASON_UNCLASSIFIED", "message"),
    ({"message": PRIVATE * 300}, "PROVIDER_REASON_UNCLASSIFIED", "message"),
    ({"response": {"reason": "not_in_park"}, "error": "unsupported", "message": "invalid value"},
     "NOT_IN_PARK", "response.reason"),
    ({"response": {"reason": PRIVATE}, "message": "invalid value"},
     "PROVIDER_REASON_UNCLASSIFIED", "response.reason"),
    ({"error": "unsupported", "message": "invalid value"}, "COMMAND_NOT_SUPPORTED", "error"),
    ({"error": PRIVATE, "message": "invalid value"}, "PROVIDER_REASON_UNCLASSIFIED", "error"),
    ({"response": {"reason": " "}, "error": "unsupported", "message": "invalid value"},
     "COMMAND_NOT_SUPPORTED", "error"),
    ({"response": {}, "error": "unsupported"}, "COMMAND_NOT_SUPPORTED", "error"),
    ({"response": [], "error": "unsupported"}, "COMMAND_NOT_SUPPORTED", "error"),
    ({"response": {"reason": False}, "error": None, "message": "invalid value"},
     "PROVIDER_VALUE_REJECTED", "message"),
    ({"error": {"message": PRIVATE}, "message": "invalid value"}, "PROVIDER_VALUE_REJECTED", "message"),
    ({"error": "\t", "message": "invalid value"}, "PROVIDER_VALUE_REJECTED", "message"),
])
def test_bounded_reason_selection_preserves_precedence_and_withholds_unknown_text(body, code, source):
    before = json.dumps(body, sort_keys=True)
    result = http_rejection_reason(body)
    assert result["reason_code"] == code
    assert result["reason_source"] == source
    assert result["provider_reason_present"] is True
    assert result.get("reason_withheld", False) is (code == "PROVIDER_REASON_UNCLASSIFIED")
    assert PRIVATE not in json.dumps(result)
    assert json.dumps(body, sort_keys=True) == before
    assert len(json.dumps(result)) < 600


@pytest.mark.parametrize("body", [
    None, [], True, 400, "invalid value", {},
    {"message": None}, {"message": False}, {"message": 400}, {"message": " \n"},
    {"message": {"error": "invalid value", "secret": PRIVATE}},
    {"message": ["invalid value", PRIVATE]},
    {"nested": {"message": "invalid value"}},
])
def test_non_string_or_absent_message_is_not_coerced_or_searched_recursively(body):
    result = http_rejection_reason(body)
    assert result["reason_code"] == "PROVIDER_REASON_MISSING"
    assert "reason_source" not in result and "provider_reason_present" not in result
    assert PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("message,code", [
    ("invalid value", "PROVIDER_VALUE_REJECTED"),
    (PRIVATE, "PROVIDER_REASON_UNCLASSIFIED"),
])
def test_history_http400_message_reaches_mcp_and_persistence_without_raw_text(
        service, store, vehicle_ref, headers, message, code):
    service.settings = replace(service.settings, live_enabled=True)
    store.settings = service.settings
    requests = []
    def response(request):
        requests.append(request)
        assert request.method == "GET"
        assert request.url.path == "/api/1/dx/charging/history"
        assert request.url.params["pageNo"] == "1"
        assert request.url.params["pageSize"] == "100"
        return httpx.Response(400, json={"code": 400, "message": message, PRIVATE: PRIVATE})
    service.fleet = Fleet(store, transport=httpx.MockTransport(response))
    try:
        with TestClient(create_app(service.settings, service=service, start_worker=False),
                        base_url="https://bridge.example") as client:
            result = rpc(client, headers(), "tools/call", {"name": "tesla_read", "arguments": {
                "vehicle_ref": vehicle_ref, "operation": "charging_history",
                "arguments": {"pageNo": 1, "pageSize": 100}}}).json()["result"]
        assert result["isError"] is True
        view = result["structuredContent"]
        assert view["code"] == "PROVIDER_ERROR" and view["provider_http_status"] == 400
        diagnostic = view["diagnostic"]
        assert diagnostic["reason_code"] == code and diagnostic["reason_source"] == "message"
        assert diagnostic["provider_reason_present"] is True
        assert diagnostic.get("reason_withheld", False) is (code == "PROVIDER_REASON_UNCLASSIFIED")
        assert diagnostic["response_shape"]["fields"]["message"] == {"kind": "string"}
        assert diagnostic["response_shape"]["other_field_count"] == 1
        assert diagnostic["automatic_retry"] is False
        assert diagnostic["request_options"] == {"pageNo": 1, "pageSize": 100}
        with store.db() as db:
            stored = json.loads(db.execute("SELECT value FROM meta WHERE key=?",
                ("request_diagnostic:" + diagnostic["request_id"],)).fetchone()[0])
        assert stored == diagnostic
        assert PRIVATE not in json.dumps(result) and PRIVATE not in json.dumps(stored)
        assert len(requests) == 1  # no fallback with a smaller page or retry
    finally:
        service.fleet.close()


@pytest.mark.parametrize("status,read_error,command_error,uncertain", [
    (400, "PROVIDER_ERROR", "PROVIDER_ERROR", False),
    (403, "PERMISSION_DENIED", "PERMISSION_DENIED", False),
    (408, "ASLEEP_OR_OFFLINE", "OUTCOME_UNKNOWN", True),
    (429, "RATE_LIMITED", "RATE_LIMITED", False),
    (500, "PROVIDER_ERROR", "OUTCOME_UNKNOWN", True),
    (503, "PROVIDER_ERROR", "OUTCOME_UNKNOWN", True),
])
@pytest.mark.parametrize("readonly", [False, True])
def test_message_diagnostics_do_not_change_http_failure_or_uncertain_outcome(
        store, vehicle_ref, status, read_error, command_error, uncertain, readonly):
    store.settings = replace(store.settings, live_enabled=True)
    requests = []
    def response(request):
        requests.append(request)
        return httpx.Response(status, json={"message": "not in park"})
    fleet = Fleet(store, transport=httpx.MockTransport(response))
    try:
        operation = "charging_history" if readonly else "remote_seat_heater_request"
        arguments = {"pageSize": 20} if readonly else {"seat_position": 0, "level": 1}
        with pytest.raises(TeslaError) as error:
            fleet.call(operation, arguments, vehicle=store.vehicle(vehicle_ref))
        assert error.value.code == (read_error if readonly else command_error)
        assert error.value.http_status == status
        assert error.value.uncertain is (uncertain and not readonly)
        diagnostic = error.value.diagnostic
        assert diagnostic["reason_code"] == "NOT_IN_PARK"
        assert diagnostic["reason_source"] == "message"
        assert diagnostic["automatic_retry"] is False
        assert len(requests) == 1
    finally:
        fleet.close()


def test_successful_command_does_not_use_an_http_error_message(store, vehicle_ref):
    store.settings = replace(store.settings, live_enabled=True)
    requests = []
    def response(request):
        requests.append(request)
        return httpx.Response(200, json={"response": {"result": True}, "message": PRIVATE})
    fleet = Fleet(store, transport=httpx.MockTransport(response))
    try:
        result = fleet.call("remote_seat_heater_request", {"seat_position": 0, "level": 1},
                            vehicle=store.vehicle(vehicle_ref))
        assert result == {"result": True}
        assert "reason_code" not in result.diagnostic
        assert "reason_source" not in result.diagnostic
        assert PRIVATE not in json.dumps(result.diagnostic)
        assert len(requests) == 1
    finally:
        fleet.close()
