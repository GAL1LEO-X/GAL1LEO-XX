"""Narrow compatibility for the observed history envelope; synthetic pages only."""
from dataclasses import replace
import json

import httpx
import pytest

from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.fleet import Fleet
from test_operation_diagnostics import query_read


@pytest.fixture(autouse=True)
def no_external_http(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected external HTTP request")
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)


@pytest.mark.parametrize("count,total", [(0, 0), (0, 100), (2, 20), (20, 73)])
@pytest.mark.parametrize("wrapped", [False, True])
def test_flat_page_and_existing_wrapped_page_preserve_data_and_limits(
        service, store, vehicle_ref, headers, count, total, wrapped):
    rows = [{"sessionId": 100-index, "fees": [{"totalDue": 1.25, "currencyCode": "EUR"}]}
            for index in range(count)]
    page = {"data": rows, "totalResults": total}
    result, request = query_read(service, store, vehicle_ref, headers, "charging_history",
        {"pageNo": 1, "pageSize": 20}, {"response": page} if wrapped else page)
    assert not result.get("isError"), result
    view = result["structuredContent"]
    assert view["data"] == page
    assert view["read_evidence"]["sessions_returned"] == count
    assert view["read_evidence"]["empty"] is (count == 0)
    assert view["read_evidence"]["complete_history"] is False
    assert view["read_evidence"]["ordering"]["latest_sessions_verified"] is False
    assert view["read_evidence"]["ordering"]["default_documented"] is False
    assert request.method == "GET" and request.url.path == "/api/1/dx/charging/history"
    assert request.url.params["pageNo"] == "1" and request.url.params["pageSize"] == "20"
    diagnostic = view["diagnostic"]
    assert diagnostic["transport"] == "fleet_api" and diagnostic["automatic_retry"] is False
    assert diagnostic["provider_http_status"] == 200
    if not wrapped:
        assert diagnostic["response_envelope"] == "charging_history_flat"
        shape = diagnostic["response_shape"]["fields"]
        assert "response" not in shape and shape["data"]["count"] == count


@pytest.mark.parametrize("page,issue", [
    ({"data": None, "totalResults": 0}, "charging_history_sessions_missing"),
    ({"data": {}, "totalResults": 0}, "charging_history_sessions_missing"),
    ({"data": [{}], "totalResults": 1}, "charging_history_session_invalid"),
    ({"data": [None], "totalResults": 1}, "charging_history_session_invalid"),
    ({"data": [{"sessionId": True}], "totalResults": 1}, "charging_history_session_invalid"),
    ({"data": [{"sessionId": -1}], "totalResults": 1}, "charging_history_session_invalid"),
    ({"data": [{"sessionId": " "}], "totalResults": 1}, "charging_history_session_invalid"),
    ({"data": [{"sessionId": "x"*257}], "totalResults": 1}, "charging_history_session_invalid"),
    ({"data": [], "totalResults": None}, "charging_history_total_invalid"),
    ({"data": [], "totalResults": True}, "charging_history_total_invalid"),
    ({"data": [], "totalResults": -1}, "charging_history_total_invalid"),
    ({"data": [], "totalResults": "1"}, "charging_history_total_invalid"),
    ({"data": [], "totalResults": 1.5}, "charging_history_total_invalid"),
    ({"data": [{"sessionId": 1}], "totalResults": 0}, "charging_history_total_invalid"),
])
@pytest.mark.parametrize("wrapped", [False, True])
def test_both_history_shapes_require_valid_rows_and_reported_total(
        service, store, vehicle_ref, headers, page, issue, wrapped):
    result, _ = query_read(service, store, vehicle_ref, headers, "charging_history", {},
                           {"response": page} if wrapped else page)
    assert result["isError"] is True
    view = result["structuredContent"]
    assert view["code"] == "PROVIDER_RESPONSE_INVALID" and view["response_issue"] == issue
    assert "read_evidence" not in view
    assert view["diagnostic"]["provider_http_status"] == 200


@pytest.mark.parametrize("body,issue", [
    ({"data": []}, "response_envelope_missing"),
    ({"totalResults": 0}, "response_envelope_missing"),
    ([], "response_envelope_missing"),
    ({"data": [], "totalResults": 0, "error": "private-marker"}, "response_envelope_missing"),
    ({"data": [], "totalResults": 0, "private-marker": 1}, "response_envelope_missing"),
    ({"response": None, "data": [], "totalResults": 0}, "charging_history_sessions_missing"),
    ({"response": {"data": [{}]}, "data": [], "totalResults": 0}, "charging_history_session_invalid"),
])
def test_no_generic_or_error_body_fallback(service, store, vehicle_ref, headers, body, issue):
    result, _ = query_read(service, store, vehicle_ref, headers, "charging_history", {}, body)
    assert result["isError"] is True
    view = result["structuredContent"]
    assert view["response_issue"] == issue and "private-marker" not in json.dumps(view)


@pytest.mark.parametrize("http_status,content_type", [(202, "application/json"), (200, "text/html"),
    (200, "text/plain"), (400, "application/json"), (500, "application/json")])
def test_flat_compatibility_requires_successful_json_response(
        service, store, vehicle_ref, http_status, content_type):
    service.settings = replace(service.settings, live_enabled=True)
    store.settings = service.settings
    requests = []
    def response(request):
        requests.append(request)
        return httpx.Response(http_status, content=b'{"data":[],"totalResults":0}',
                              headers={"content-type": content_type})
    service.fleet = Fleet(store, transport=httpx.MockTransport(response))
    try:
        with pytest.raises(TeslaError) as err:
            service.read("charging_history", {}, vehicle_ref, SCOPES)
        assert err.value.code == ("PROVIDER_ERROR" if http_status >= 400 else "PROVIDER_RESPONSE_INVALID")
        assert err.value.diagnostic["automatic_retry"] is False
        assert len(requests) == 1
    finally:
        service.fleet.close()


@pytest.mark.parametrize("operation,arguments", [
    ("vehicle_nearby_charging_sites", {"detail": True}),
    ("vehicle_fleet_status", {}),
    ("vehicle_fleet_telemetry_config_get", {}),
])
def test_history_compatibility_does_not_change_other_endpoint_envelopes(
        service, store, vehicle_ref, headers, operation, arguments):
    result, _ = query_read(service, store, vehicle_ref, headers, operation, arguments,
                           {"data": [], "totalResults": 0})
    assert result["isError"] is True
    assert result["structuredContent"]["response_issue"] == "response_envelope_missing"


def test_flat_history_preserves_redaction_and_invoice_binding(service, store, vehicle_ref, headers):
    page = {"data": [{"sessionId": "synthetic-session", "vin": "synthetic-private-vin",
        "invoices": [{"contentId": "synthetic-private-content-id", "fileName": "synthetic.pdf"}],
        "fees": [{"totalDue": 2.5, "currencyCode": "EUR"}]}], "totalResults": 1}
    result, _ = query_read(service, store, vehicle_ref, headers, "charging_history", {"pageSize": 20}, page)
    assert not result.get("isError"), result
    view = result["structuredContent"]
    row = view["data"]["data"][0]
    assert row["fees"] == page["data"][0]["fees"]
    document_ref = row["invoices"][0]["document_ref"]
    assert document_ref.startswith("doc_")
    assert "synthetic-private" not in json.dumps(view)
    with store.db() as db:
        invoice = db.execute("SELECT * FROM documents WHERE ref=?", (document_ref,)).fetchone()
        diagnostic = json.loads(db.execute("SELECT value FROM meta WHERE key=?",
            ("request_diagnostic:"+view["diagnostic"]["request_id"],)).fetchone()[0])
    assert invoice["vehicle"] == vehicle_ref and invoice["provider_id"] == "synthetic-private-content-id"
    assert "synthetic-session" not in json.dumps(diagnostic)
