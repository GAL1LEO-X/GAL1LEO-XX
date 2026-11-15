"""Regressions from owner diagnostics. All data and transports are synthetic."""
from copy import deepcopy
from dataclasses import replace
import json

import httpx
import pytest
from starlette.testclient import TestClient

from tesla_plugin.catalogue import describe, validate
from tesla_plugin.config import SCOPES, TESLA_SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.fleet import Fleet
from tesla_plugin.preconditions import CLIMATE_ACTIONS, PARK_ACTIONS, park_evidence
from tesla_plugin.provider_diagnostics import new_diagnostic, record
from tesla_plugin.server import create_app
from test_mcp_portal import login, rpc


@pytest.fixture(autouse=True)
def no_external_http(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected external HTTP request")
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)


def gear_row(value, now, age=1, quality="valid"):
    return {"value": json.dumps(value), "quality": quality, "source_at": now-age}


def set_gear(store, ref, value, *, age=1, quality="valid"):
    with store.db() as db:
        db.execute("INSERT OR REPLACE INTO latest VALUES(?,?,?,?,?,?,?)",
            (ref, "Gear", json.dumps(value), store.clock()-age, store.clock(), quality, "payload_created_at"))


@pytest.mark.parametrize("rest,rest_age,telemetry,gear_age,quality,expected", [
    ("P", 20, "ShiftStateD", 1, "valid", "conflicting"),
    ("P", 20, "ShiftStateD", 16, "valid", "conflicting"),
    ("P", 1, "ShiftStateD", 1, "valid", "conflicting"),
    ("D", 1, "ShiftStateP", 2, "valid", "conflicting"),
    ("P", 1, "ShiftStateD", 16, "valid", "verified"),
    (None, 0, "ShiftStateP", 1, "valid", "verified"),
    (None, 0, "ShiftStateP", 16, "valid", "stale"),
    (None, 0, "ShiftStateP", 1, "invalid", "unknown"),
    (None, 0, None, 1, "invalid", "unknown"),
    ("P", 31, None, 1, "invalid", "stale"),
    ("P", -5, None, 1, "invalid", "unknown"),
    (None, 0, "ShiftStateP", -5, "valid", "unknown"),
    ("N", 1, None, 1, "invalid", "not_park"),
    ("R", 1, "ShiftStateD", 1, "valid", "not_park"),
])
def test_park_sources_freshness_and_conflicts(rest, rest_age, telemetry, gear_age, quality, expected):
    now = 1800000000.0
    result = park_evidence({"shift_state": rest, "timestamp": (now-rest_age)*1000},
                          gear_row(telemetry, now, gear_age, quality), now)
    assert result["status"] == expected
    assert len(result["observations"]) == 2
    assert result["automatic_retry"] is False


@pytest.mark.parametrize("timestamp", [None, True, float("nan"), float("inf"), 0])
def test_park_without_valid_timestamp_is_unknown(timestamp):
    result = park_evidence({"shift_state": "P", "timestamp": timestamp}, None, 1800000000)
    assert result["status"] == "unknown"


@pytest.mark.parametrize("operation,arguments", [
    ("remote_boombox", {"sound": 0}), ("window_control", {"command": "vent"}), ("actuate_trunk", {"which_trunk": "front"})])
@pytest.mark.parametrize("entry", ["chat", "panel"])
def test_blocked_operations_persist_evidence_without_dispatch(service, fleet, vehicle_ref, operation, arguments, entry):
    service.settings = replace(service.settings, live_enabled=True)
    fleet.park = None
    set_gear(service.store, vehicle_ref, None, quality="invalid")
    item = service.prepare(operation, arguments, vehicle_ref, "park-"+operation, SCOPES)
    with pytest.raises(TeslaError) as error:
        if entry == "chat":
            service.execute_action_from_chat(item["id"], item["action_digest"], "execute", SCOPES)
        else:
            service.execute_from_owner(item["id"])
    assert error.value.code == "PRECONDITION_FAILED"
    assert error.value.public()["command_sent"] is False
    assert error.value.public()["precondition"]["status"] == "unknown"
    assert [name for name, *_ in fleet.calls] == ["vehicle_fleet_status", "vehicle_vehicle_data"]
    view = service.intent_view(item["id"])
    assert view["status"] == "prepared"
    assert view["verification"]["status"] == "blocked_before_dispatch"
    assert view["preflight"]["precondition"]["reason"] == "PARK_EVIDENCE_UNAVAILABLE"
    assert view["action_digest"] == item["action_digest"]


def test_previously_blocked_intent_can_be_explicitly_executed_once_after_new_evidence(service, fleet, vehicle_ref):
    fleet.park = None
    item = service.prepare("window_control", {"command": "vent"}, vehicle_ref, "park-later-evidence", SCOPES)
    with pytest.raises(TeslaError):
        service.execute_from_owner(item["id"])
    set_gear(service.store, vehicle_ref, "ShiftStateP")
    result = service.execute_from_owner(item["id"])
    assert result["status"] == "acknowledged" and "preflight" not in result
    assert "stage" not in result["result"]
    calls = list(fleet.calls)
    service.execute_from_owner(item["id"])
    assert fleet.calls == calls
    assert sum(name == "window_control" for name, *_ in calls) == 1


def test_conflicting_park_blocks_actual_service_dispatch(service, fleet, vehicle_ref, clock):
    set_gear(service.store, vehicle_ref, "ShiftStateD")
    original = fleet.call
    def response(name, *args, **kwargs):
        result = original(name, *args, **kwargs)
        if name == "vehicle_vehicle_data":
            result["drive_state"] = {"shift_state": "P", "timestamp": (clock()-20)*1000}
        return result
    fleet.call = response
    item = service.prepare("window_control", {"command": "vent"}, vehicle_ref, "park-newer-drive", SCOPES)
    with pytest.raises(TeslaError) as error:
        service.execute_from_owner(item["id"])
    assert error.value.details["precondition"]["status"] == "conflicting"
    assert not any(name == "window_control" for name, *_ in fleet.calls)


@pytest.mark.parametrize("successor", ["cancelled", "sending", "acknowledged"])
def test_late_preflight_cannot_overwrite_an_intent_owned_by_another_attempt(service, fleet, vehicle_ref, successor):
    fleet.park = None
    item = service.prepare("window_control", {"command": "vent"}, vehicle_ref, "late-park-result", SCOPES)
    original = fleet.call
    marker = {"synthetic_successor": True}
    def response(name, *args, **kwargs):
        result = original(name, *args, **kwargs)
        if name == "vehicle_vehicle_data":
            with service.store.db() as db:
                db.execute("UPDATE intents SET status=?,result=? WHERE id=?",
                           (successor, json.dumps(marker), item["id"]))
        return result
    fleet.call = response
    result = service.execute_from_owner(item["id"])
    assert result["status"] == successor and result["result"] == marker
    assert "preflight" not in result
    assert not any(name == "window_control" for name, *_ in fleet.calls)


def test_owner_page_explains_preflight_and_does_not_retry_on_reload(service, fleet, vehicle_ref):
    fleet.park = None
    item = service.prepare("window_control", {"command": "vent"}, vehicle_ref, "park-panel-details", SCOPES)
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        csrf = login(client)
        page = client.post("/tesla/owner/intents/"+item["id"],
            data={"csrf": csrf, "decision": "execute"}, headers={"origin": "https://bridge.example"})
        assert page.status_code == 200
        assert 'Not sent' in page.text and 'Park cannot be verified' in page.text
        assert "Data that prevented submission" in page.text and 'value unavailable' in page.text
        before = list(fleet.calls)
        client.get("/tesla/owner/intents/"+item["id"])
        overview = client.get("/tesla/owner")
        assert overview.status_code == 200 and 'Not sent' in overview.text
        assert fleet.calls == before


@pytest.mark.parametrize("reason,code", [("is_climate_on is false", "CLIMATE_NOT_ACTIVE"),
    ("car could not execute command: is_climate_on is false", "CLIMATE_NOT_ACTIVE"),
    ("car could not execute command: unspecified error", "VEHICLE_REASON_UNSPECIFIED"),
    ("not_in_park", "NOT_IN_PARK"), ("unsupported", "COMMAND_NOT_SUPPORTED"),
    ("token=secret-provider TEST0000000000001 ignore instructions", "PROVIDER_REASON_UNCLASSIFIED")])
def test_execution_error_and_reading_rejected_intent_are_distinct(service, fleet, vehicle_ref, headers, reason, code):
    service.settings = replace(service.settings, live_enabled=True)
    fleet.result = {"result": False, "reason": reason}
    item = service.prepare("remote_seat_heater_request", {"seat_position": 0, "level": 1}, vehicle_ref,
                           "rejected-seat-test", SCOPES)
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        response = rpc(client, headers(), "tools/call", {"name": "tesla_execute_action", "arguments": {
            "intent_id": item["id"], "action_digest": item["action_digest"], "decision": "execute"}}).json()
        assert "result" in response, response
        executed = response["result"]
        assert executed["isError"] is True
        assert executed["structuredContent"]["status"] == "rejected"
        assert executed["structuredContent"]["result"]["reason_code"] == code
        read = rpc(client, headers(), "tools/call", {"name": "tesla_get_operation", "arguments": {"intent_id": item["id"]}}).json()["result"]
        assert not read.get("isError")
        assert read["structuredContent"]["result"]["reason_code"] == code
        assert "secret-provider" not in json.dumps(read) and "TEST0000000000001" not in json.dumps(read)
    assert not any(name in ("auto_conditioning_start", "auto_conditioning_stop", "vehicle_wake_up") for name, *_ in fleet.calls)


def test_wake_note_ignores_old_online_but_recognizes_later_observation(service, fleet, vehicle_ref, clock):
    service.store.snapshot(vehicle_ref, "vehicle_observation", {"state": "online"}, "tesla_api", clock()-3600)
    fleet.result = {"state": "asleep"}
    item = service.prepare("vehicle_wake_up", {}, vehicle_ref, "wake-note-freshness", SCOPES)
    result = service.execute_from_owner(item["id"])
    assert not result["verification"]["effect_observed"]
    assert "online not yet observed" in result["note"]
    clock.advance(1)
    service.store.snapshot(vehicle_ref, "vehicle_observation", {"state": "online"}, "tesla_api", clock())
    view = service.intent_view(item["id"])
    assert view["verification"]["effect_observed"]
    assert "after the command" in view["note"] and "does not establish current state" in view["note"]


def test_requirement_definitions_are_shared_and_do_not_add_climate_actions(service, fleet, vehicle_ref):
    for name in PARK_ACTIONS:
        requirement = next(r for r in describe(name)["requirements"] if r["id"] == "explicit_park")
        assert requirement["origin"] == "plugin_policy" and requirement["unknown_blocks"]
    for name in CLIMATE_ACTIONS:
        assert next(r for r in describe(name)["requirements"] if r["id"] == "climate_active")["automatic_climate_start"] is False
    item = service.prepare("remote_seat_heater_request", {"seat_position": 0, "level": 1}, vehicle_ref, "seat-requirement", SCOPES)
    assert item["requirements"] == describe(item["operation"])["requirements"]
    assert item["limitations"] == describe(item["operation"])["limitations"]
    assert fleet.calls == []


def test_capabilities_expose_the_same_requirements_as_schema_and_preparation(service, fleet, vehicle_ref):
    capabilities = {row["operation"]: row for row in service.capabilities(vehicle_ref)["operations"]}
    for name in (*PARK_ACTIONS, *CLIMATE_ACTIONS, "remote_start_drive"):
        contract = describe(name)
        assert capabilities[name]["requirements"] == contract["requirements"]
        assert capabilities[name]["limitations"] == contract["limitations"]
    cooler = describe("remote_seat_cooler_request")
    assert cooler["requirements"][0]["id"] == "climate_active"
    assert cooler["requirements"][0]["enforcement"] == "provider"
    assert cooler["requirements"][0]["automatic_climate_start"] is False
    assert fleet.calls == []


def query_read(service, store, vehicle_ref, headers, operation, arguments, body, *, html=False):
    service.settings = replace(service.settings, live_enabled=True)
    store.settings = service.settings
    requests = []
    def response(request):
        requests.append(request)
        return httpx.Response(200, content=body if html else json.dumps(body).encode(),
                              headers={"content-type": "text/html" if html else "application/json"})
    service.fleet = Fleet(store, transport=httpx.MockTransport(response))
    try:
        with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
            result = rpc(client, headers(), "tools/call", {"name": "tesla_read", "arguments": {
                "operation": operation, "arguments": arguments, "vehicle_ref": vehicle_ref}}).json()["result"]
        assert len(requests) == 1
        return result, requests[0]
    finally:
        service.fleet.close()


@pytest.mark.parametrize("body,html,issue", [
    (b"<html>secret-provider-body</html>", True, "invalid_json"),
    ({"data": []}, False, "response_envelope_missing"),
    ({"response": None}, False, "charging_history_sessions_missing"),
    ({"response": {"unexpected": "secret-provider-body"}}, False, "charging_history_sessions_missing"),
    ({"response": {"data": [{}]}}, False, "charging_history_session_invalid"),
])
def test_charging_failures_are_distinct_and_correlated(service, store, vehicle_ref, headers, body, html, issue):
    result, _ = query_read(service, store, vehicle_ref, headers, "charging_history", {"pageNo": 1, "pageSize": 5}, body, html=html)
    assert result["isError"] is True
    data = result["structuredContent"]
    assert data["code"] == "PROVIDER_RESPONSE_INVALID" and data["response_issue"] == issue
    diagnostic = data["diagnostic"]
    assert diagnostic["request_id"].startswith("req_") and diagnostic["provider_http_status"] == 200
    assert diagnostic["operation"] == "charging_history"
    with store.db() as db:
        saved = db.execute("SELECT value FROM meta WHERE key=?", ("request_diagnostic:"+diagnostic["request_id"],)).fetchone()[0]
    assert json.loads(saved) == diagnostic
    assert "secret-provider-body" not in saved and "TEST0000000000001" not in saved


@pytest.mark.parametrize("rows", [[], [{"sessionId": 123, "fees": []}]])
def test_charging_valid_pages_preserve_order_and_do_not_claim_latest(service, store, vehicle_ref, headers, rows):
    result, request = query_read(service, store, vehicle_ref, headers, "charging_history", {"pageNo": 1, "pageSize": 5}, {"response": {"data": rows}})
    assert not result.get("isError")
    assert result["structuredContent"]["data"]["data"] == rows
    assert result["structuredContent"]["read_evidence"]["empty"] == (not rows)
    assert result["structuredContent"]["read_evidence"]["ordering"]["latest_sessions_verified"] is False
    assert request.url.params["pageSize"] == "5"


@pytest.mark.parametrize("arguments", [
    {"startTime": "2026-10-27"}, {"startTime": "2026-10-27T10:00:00"},
    {"endTime": "2026-02-30T10:00:00Z"}, {"sortOrder": "newest"},
    {"startTime": "2026-10-28T10:00:00Z", "endTime": "2026-10-27T10:00:00Z"},
])
def test_undocumented_or_ambiguous_history_inputs_rejected_locally(arguments):
    with pytest.raises(TeslaError):
        validate("charging_history", arguments)


def test_valid_history_timezone_and_sort_schema():
    args = {"startTime": "2026-10-27T00:00:00+01:00", "endTime": "2026-10-27T23:00:00Z", "sortOrder": "DESC"}
    assert validate("charging_history", args) == args
    assert "enum" not in describe("charging_history")["input_schema"]["properties"]["sortBy"]
    assert "miles" in describe("vehicle_nearby_charging_sites")["input_schema"]["properties"]["radius"]["description"]


@pytest.mark.parametrize("rich", [False, True])
def test_nearby_query_fields_and_timestamp_evidence(service, store, vehicle_ref, headers, rich):
    site = {"name": "Synthetic station", "id": 1, "billing_info": "", "site_closed": False}
    if rich:
        site.update(available_stalls=3, total_stalls=8, max_power_kw=250, price_per_kwh=0.3, billing_info="Synthetic tariff")
    payload = {"timestamp": 1700000000000, "congestion_sync_time_utc_secs": 1699997710,
               "superchargers": [deepcopy(site) for _ in range(5)], "destination_charging": [deepcopy(site) for _ in range(5)]}
    result, request = query_read(service, store, vehicle_ref, headers, "vehicle_nearby_charging_sites",
                                {"count": 5, "detail": True}, {"response": payload})
    assert not result.get("isError")
    data = result["structuredContent"]
    assert dict(request.url.params) == {"count": "5", "detail": "true"}
    assert data["data"] == payload
    evidence = data["read_evidence"]
    assert evidence["superchargers_with_available_stalls"] == (5 if rich else 0)
    assert evidence["availability_freshness_verified"] is False
    assert evidence["congestion_timestamp_gap_seconds"] == 2290
    assert data["diagnostic"]["response_summary"]["superchargers_with_available_stalls"] == (5 if rich else 0)


def test_diagnostic_retention_is_bounded_without_touching_user_settings(store, clock):
    before = store.connection()
    for index in range(105):
        record(store, new_diagnostic("charging_history", clock()))
        clock.advance(0.01)
    with store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM meta WHERE key LIKE 'request_diagnostic:%'").fetchone()[0] == 100
        assert db.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0
    clock.advance(8*86400)
    store.prune()
    with store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM meta WHERE key LIKE 'request_diagnostic:%'").fetchone()[0] == 0
    record(store, new_diagnostic("charging_history", clock()))
    with store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM meta WHERE key LIKE 'request_diagnostic:%'").fetchone()[0] == 1
    assert store.connection()["generation"] == before["generation"]


@pytest.mark.parametrize("accepted", [True, False])
def test_unavailable_diagnostic_storage_does_not_erase_provider_outcome(store, vehicle_ref, accepted):
    store.settings = replace(store.settings, live_enabled=True)
    with store.db() as db:
        db.execute("CREATE TRIGGER unavailable_diagnostics BEFORE INSERT ON meta "
                   "WHEN NEW.key LIKE 'request_diagnostic:%' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
    calls = []
    def response(request):
        calls.append(request)
        return httpx.Response(200, json={"response": {"result": accepted, "reason": "is_climate_on is false"}})
    fleet = Fleet(store, transport=httpx.MockTransport(response))
    try:
        result = fleet.call("remote_seat_heater_request", {"seat_position": 0, "level": 1}, vehicle=store.vehicle(vehicle_ref))
        assert result["result"] is accepted
        assert result.diagnostic["persisted"] is False
        assert result.diagnostic["provider_http_status"] == 200
        if not accepted:
            assert result.diagnostic["reason_code"] == "CLIMATE_NOT_ACTIVE"
        assert len(calls) == 1
    finally:
        fleet.close()


@pytest.mark.parametrize("status", [200, 400, 500])
def test_actual_transport_retains_safe_rejection_evidence_without_replay(store, vehicle_ref, status):
    store.settings = replace(store.settings, live_enabled=True)
    calls = []
    def response(request):
        calls.append(request)
        return httpx.Response(status, json={"response": {"result": False, "reason": "is_climate_on is false"},
                                           "access_token": "synthetic-private-provider"})
    fleet = Fleet(store, transport=httpx.MockTransport(response))
    try:
        if status == 200:
            result = fleet.call("remote_seat_heater_request", {"seat_position": 0, "level": 1}, vehicle=store.vehicle(vehicle_ref))
            diagnostic = result.diagnostic
            assert result["result"] is False
        else:
            with pytest.raises(TeslaError) as error:
                fleet.call("remote_seat_heater_request", {"seat_position": 0, "level": 1}, vehicle=store.vehicle(vehicle_ref))
            diagnostic = error.value.diagnostic
            assert error.value.uncertain is (status == 500)
        assert diagnostic["reason_code"] == "CLIMATE_NOT_ACTIVE"
        assert diagnostic["provider_http_status"] == status and diagnostic["persisted"] is True
        assert "synthetic-private-provider" not in json.dumps(diagnostic)
        assert len(calls) == 1
    finally:
        fleet.close()


def test_disconnect_erases_request_diagnostics_but_not_unrelated_metadata(store):
    record(store, new_diagnostic("charging_history", store.clock()))
    with store.db() as db:
        db.execute("INSERT INTO meta VALUES('request-diagnostic:unrelated', 'keep')")
    store.disconnect()
    with store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM meta WHERE key GLOB 'request_diagnostic:*'").fetchone()[0] == 0
        assert db.execute("SELECT value FROM meta WHERE key='request-diagnostic:unrelated'").fetchone()[0] == "keep"


@pytest.mark.parametrize("reconnect", [False, True])
def test_late_response_cannot_recreate_diagnostics_after_disconnect_or_reauthorization(store, vehicle_ref, reconnect):
    store.settings = replace(store.settings, live_enabled=True)
    old = store.connection()["generation"]
    vehicle = store.vehicle(vehicle_ref)
    def response(request):
        store.disconnect()
        if reconnect:
            store.set_tokens({"access_token": "synthetic-new-access", "refresh_token": "synthetic-new-refresh", "expires_in": 3600}, TESLA_SCOPES, "eu")
        return httpx.Response(200, json={"response": {"state": "online"}})
    fleet = Fleet(store, transport=httpx.MockTransport(response))
    try:
        with pytest.raises(TeslaError) as error:
            fleet.call("vehicle_vehicle", vehicle=vehicle)
        assert error.value.diagnostic["authorization_generation"] == old
        assert error.value.diagnostic["persisted"] is False
        assert error.value.diagnostic["persistence_reason"] == "authorization_changed"
        with store.db() as db:
            assert db.execute("SELECT COUNT(*) FROM meta WHERE key GLOB 'request_diagnostic:*'").fetchone()[0] == 0
        if reconnect:
            assert store.connection()["generation"] != old
    finally:
        fleet.close()
