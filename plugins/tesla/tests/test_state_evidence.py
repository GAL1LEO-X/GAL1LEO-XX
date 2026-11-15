"""Synthetic regressions for the 28 October report. Never access Tesla."""
from dataclasses import replace
import json

import httpx
import pytest
from starlette.testclient import TestClient

from tesla_plugin.config import SCOPES
from tesla_plugin.dashboard import park_panel
from tesla_plugin.errors import TeslaError
from tesla_plugin.fleet import Fleet
from tesla_plugin.gear_evidence import view as gear_view
from tesla_plugin.provider_diagnostics import rejection_reason, response_shape
from tesla_plugin.server import create_app
from tesla_plugin.service import redact, timestamp
from tesla_plugin.state_evidence import timestamp_evidence
from tesla_plugin.telemetry import Telemetry
from test_mcp_portal import rpc
from test_operation_diagnostics import query_read
from test_telemetry_events import payload


@pytest.fixture(autouse=True)
def no_external_http(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected external HTTP request")
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)


@pytest.mark.parametrize("raw,expected,encoding", [
    (1800000000, 1800000000, "unix_seconds"),
    (1800000000751, 1800000000.751, "unix_milliseconds"),
    ({"seconds": 1800000000, "nanos": 751000000}, 1800000000.751, "protobuf_seconds_nanos"),
    ({"seconds": "1800000000", "nanos": 123456789}, 1800000000.123456789, "protobuf_seconds_nanos"),
    ({"seconds": 1800000000}, 1800000000, "protobuf_seconds_nanos"),
])
def test_typed_times_keep_provenance_and_components(raw, expected, encoding):
    evidence = timestamp_evidence(raw)
    assert timestamp(raw) == pytest.approx(expected, abs=1e-7, rel=0)
    assert evidence["status"] == "parsed" and evidence["encoding"] == encoding
    if isinstance(raw, dict):
        assert evidence["components"] == {"seconds": int(raw["seconds"]), "nanos": raw.get("nanos", 0)}


@pytest.mark.parametrize("raw", [None, True, False, 0, -1, float("nan"), float("inf"), -float("inf"),
    10**400, "1800000000", [], {}, {"seconds": True}, {"seconds": -1}, {"seconds": 1800000000.5},
    {"seconds": "not-a-time"}, {"seconds": "1"*400}, {"seconds": 1800000000, "nanos": True},
    {"seconds": 1800000000, "nanos": -1}, {"seconds": 1800000000, "nanos": 1000000000},
    {"seconds": 1800000000, "nanos": "10"}, {"seconds": 1800000000, "unexpected": "private"},
    {"seconds": 253402300800}, {"nanos": 10}])
def test_malformed_times_never_become_receipt_time(raw):
    evidence = timestamp_evidence(raw)
    assert evidence["source_timestamp"] is None
    assert evidence["status"] == ("missing" if raw is None else "invalid")
    assert "private" not in json.dumps(evidence)


@pytest.mark.parametrize("cached_before_upgrade", [False, True])
@pytest.mark.parametrize("offset,quality", [(0, "fresh_observed"), (-600, "stale"), (60, "future")])
def test_schedule_block_time_is_normalized_without_receipt_fallback(service, vehicle_ref, clock, headers, cached_before_upgrade, offset, quality):
    clock.value = 1800000000.751
    raw = {"seconds": 1800000000+offset, "nanos": 751000000}
    data = {name: {"timestamp": raw, "schedules": []} for name in ("charge_schedule_data", "preconditioning_schedule_data")}
    if cached_before_upgrade:
        for name, block in data.items():
            # A historical row predates Store.snapshot's source-time ordering
            # and normalization; insert the old representation, not today's writer.
            with service.store.db() as db:
                db.execute('INSERT INTO snapshots VALUES(?,?,?,?,?,?)',
                           (vehicle_ref, name, json.dumps(block), 'tesla_live', None, clock()))
    else:
        service._cache(vehicle_ref, data, "tesla_live", authorization=service.fleet.authorization())
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        response = rpc(client, headers(), "tools/call", {"name": "tesla_get_state", "arguments": {
            "vehicle_ref": vehicle_ref, "freshness": "cached_only", "sections": list(data)}}).json()["result"]
    assert not response.get("isError")
    for block in response["structuredContent"]["data"].values():
        assert block["quality"] == quality and block["source_timestamp"] == clock()+offset
        assert block["age_seconds"] == -offset
        assert block["timestamp_evidence"]["components"] == raw
        assert block["timestamp_scope"] == "block_not_individual_fields"
    assert service.fleet.calls == []
    if cached_before_upgrade:
        with service.store.db() as db:
            assert all(r[0] is None for r in db.execute("SELECT source_at FROM snapshots"))


def test_gear_sequence_retains_history_but_invalid_does_not_authorize(service, vehicle_ref, clock):
    telemetry = Telemetry(service.store)
    for value, state in [("ShiftStateD", "not_park"), ("ShiftStateR", "not_park"), ("ShiftStateP", "verified"), (None, "unknown")]:
        clock.advance(16)
        telemetry.ingest("V", payload(clock, {"Gear": value}))
        observed = service.state(vehicle_ref, ["drive_state"], "cached_only", SCOPES)["park_evidence"]
        assert observed["status"] == state
    assert observed["last_valid_observation"]["value"] == "P"
    assert observed["last_valid_observation"]["age_seconds"] == pytest.approx(16, abs=1e-6)
    assert observed["current_telemetry"]["quality"] == "invalid"
    assert observed["current_telemetry"]["input_evidence"]["normalization_reason"] == "invalid_branch_received"
    assert observed["historical_observation_used_for_admission"] is False
    page = park_panel(service.store, vehicle_ref, "Europe/Amsterdam")
    assert 'Park cannot be verified' in page and "This is historical data" in page
    assert 'invalid-value marker' in page
    assert service.fleet.calls == []
    service.fleet.park = None
    intent = service.prepare("window_control", {"command": "vent"}, vehicle_ref, "historical-park-not-authorizing", SCOPES)
    with pytest.raises(TeslaError) as err:
        service.execute_from_owner(intent["id"])
    assert err.value.details["command_sent"] is False
    assert not any(name == "window_control" for name, *_ in service.fleet.calls)


def test_old_and_absent_gear_do_not_replace_current_trace_and_conflict_is_not_last_valid(service, vehicle_ref, clock):
    telemetry = Telemetry(service.store)
    telemetry.ingest("V", payload(clock, {"Gear": "ShiftStateR"}))
    clock.advance(5)
    telemetry.ingest("V", payload(clock, {"Gear": "ShiftStateP"}))
    before = gear_view(service.store, vehicle_ref)
    telemetry.ingest("V", payload(clock, {"Gear": None}, when=clock()-1))
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 40}))
    assert gear_view(service.store, vehicle_ref) == before
    telemetry.ingest("V", payload(clock, {"Gear": "ShiftStateD"}))
    view = gear_view(service.store, vehicle_ref)
    assert view["current_telemetry"]["quality"] == "time_conflict"
    assert view["last_valid_observation"]["value"] == "R"
    assert view["current_telemetry"]["input_evidence"]["timestamp_conflict"]


def test_unknown_gear_trace_does_not_retain_untrusted_text_and_is_erased_on_disconnect(service, vehicle_ref, clock):
    Telemetry(service.store).ingest("V", payload(clock, {"Gear": "private-unknown-enum"}))
    view = gear_view(service.store, vehicle_ref)
    assert view["current_telemetry"]["input_evidence"]["normalization_reason"] == "unrecognized_gear_value"
    assert "private-unknown-enum" not in json.dumps(view)
    assert view["last_valid_observation"] is None
    service.store.disconnect()
    with service.store.db() as db:
        assert db.execute("SELECT count(*) FROM snapshots WHERE section='gear_ingestion'").fetchone()[0] == 0


def test_gear_history_is_not_disclosed_without_history_scope(service, vehicle_ref, clock):
    telemetry = Telemetry(service.store)
    telemetry.ingest("V", payload(clock, {"Gear": "ShiftStateP"}))
    clock.advance(20)
    telemetry.ingest("V", payload(clock, {"Gear": None}))
    result = service.state(vehicle_ref, ["drive_state"], "cached_only", set(SCOPES)-{"tesla:history"})
    evidence = result["park_evidence"]
    assert evidence["status"] == "unknown" and evidence["last_valid_observation"] is None
    assert evidence["history_access"] == "scope_required" and service.fleet.calls == []


def test_parent_navigation_and_media_are_partial_and_use_parent_time(service, vehicle_ref, clock):
    service._cache(vehicle_ref, {
        "drive_state": {"timestamp": (clock()-600)*1000, "active_route_destination": "Synthetic destination",
                        "active_route_miles_to_arrival": 12, "speed": 60},
        "vehicle_state": {"timestamp": clock()*1000, "locked": True,
                          "media_info": {"now_playing_title": "Synthetic title"}},
    }, "tesla_live", authorization=service.fleet.authorization())
    result = service.state(vehicle_ref, ["navigation_data", "media_state"], "cached_only", SCOPES)["data"]
    nav, media = result["navigation_data"], result["media_state"]
    assert nav["quality"] == "stale" and nav["age_seconds"] == pytest.approx(600)
    assert nav["derived_from"] == "drive_state.active_route_*" and nav["coverage"] == "partial"
    assert nav["data"] == {"active_route_destination": "Synthetic destination", "active_route_miles_to_arrival": 12}
    assert nav["complete_itinerary"] is False
    assert media["data"] == {"now_playing_title": "Synthetic title"}
    assert media["derived_from"] == "vehicle_state.media_info" and media["quality"] == "fresh_observed"
    assert media["time_basis"] == "parent_rest_block_timestamp" and service.fleet.calls == []


@pytest.mark.parametrize("age,expected", [(0, "direct"), (20, "parent")])
def test_projections_prefer_newest_source_without_merging_times(service, vehicle_ref, clock, age, expected):
    service._cache(vehicle_ref, {"media_state": {"timestamp": (clock()-age)*1000, "origin": "direct"},
        "vehicle_state": {"timestamp": (clock()-10)*1000, "media_info": {"origin": "parent"}}},
        "tesla_live", authorization=service.fleet.authorization())
    result = service.state(vehicle_ref, ["media_state"], "cached_only", SCOPES)["data"]["media_state"]
    assert result["data"]["origin"] == expected


def test_live_projection_adds_parent_to_same_read_without_wake_or_extra_call(service, vehicle_ref, clock):
    before = service.fleet.call
    def call(name, *args, **kw):
        data = before(name, *args, **kw)
        if name == "vehicle_vehicle_data":
            data["vehicle_state"] = {"timestamp": clock()*1000, "media_info": {"now_playing_title": "Synthetic title"}}
        return data
    service.fleet.call = call
    data = service.state(vehicle_ref, ["media_state"], "live_if_online", SCOPES)["data"]["media_state"]
    assert data["derived_from"] == "vehicle_state.media_info"
    assert [name for name, *_ in service.fleet.calls] == ["vehicle_vehicle", "vehicle_vehicle_data"]
    assert service.fleet.calls[-1][1] == {"endpoints": "media_state;vehicle_state"}


@pytest.mark.parametrize("restriction", ["plugin_scope", "tesla_scope", "hide_private"])
def test_projection_location_permission_is_not_bypassed(service, vehicle_ref, clock, restriction):
    scopes = SCOPES
    service._cache(vehicle_ref, {"drive_state": {"timestamp": clock()*1000,
                   "active_route_destination": "private-route"}}, "tesla_live", authorization=service.fleet.authorization())
    with service.store.db() as db:
        if restriction == "plugin_scope":
            scopes = [s for s in SCOPES if s != "tesla:location"]
        elif restriction == "tesla_scope":
            db.execute("UPDATE connection SET scopes='[\"vehicle_device_data\"]'")
        else:
            db.execute("UPDATE vehicles SET data=json_set(data, '$.granular_access.hide_private', json('true'))")
    with pytest.raises(TeslaError):
        service.state(vehicle_ref, ["navigation_data"], "cached_only", scopes)
    assert service.fleet.calls == []


def test_redaction_covers_nested_route_fields_and_longitude_alias():
    private = {"wrapper": {"active_route_destination": "private-destination", "active_route_latitude": 12,
        "active_route_longitude": 21, "long": 22, "siteLocationName": "private-site", "battery_level": 40}}
    assert redact(private, location=False) == {"wrapper": {"battery_level": 40}}
    assert redact(private, location=True) == private


def test_rest_drive_position_is_not_hidden_by_older_telemetry(service, vehicle_ref, clock):
    Telemetry(service.store).ingest("V", payload(clock, {"Location": {"latitude": 12., "longitude": 21.}}, when=clock()-600))
    service._cache(vehicle_ref, {"drive_state": {"timestamp": clock()*1000, "latitude": 13., "longitude": 22.}},
                   "tesla_live", authorization=service.fleet.authorization())
    result = service.state(vehicle_ref, ["location_data"], "cached_only", SCOPES)["data"]["location_data"]
    assert result["source"] == "tesla_live" and result["data"]["latitude"] == 13.
    assert result["derived_from"] == "drive_state.latitude/longitude" and result["age_seconds"] < .001


@pytest.mark.parametrize("status", [200, 400, 500])
def test_actual_sdk_prefixed_reason_survives_transport_without_exposing_payload(store, vehicle_ref, status):
    store.settings = replace(store.settings, live_enabled=True)
    calls = []
    def response(request):
        calls.append(request)
        return httpx.Response(status, json={"response": {"result": False,
            "reason": "car could not execute command: is_climate_on is false"}, "private-field": "private-token"})
    fleet = Fleet(store, transport=httpx.MockTransport(response))
    try:
        if status == 200:
            result = fleet.call("remote_seat_heater_request", {"seat_position": 0, "level": 1}, vehicle=store.vehicle(vehicle_ref))
            diagnostic = result.diagnostic
        else:
            with pytest.raises(TeslaError) as err:
                fleet.call("remote_seat_heater_request", {"seat_position": 0, "level": 1}, vehicle=store.vehicle(vehicle_ref))
            diagnostic = err.value.diagnostic
            assert err.value.uncertain is (status == 500)
        assert diagnostic["reason_code"] == "CLIMATE_NOT_ACTIVE"
        assert diagnostic["reason_format"] == "sdk_nominal_error"
        assert len(calls) == 1 and "private-" not in json.dumps(diagnostic)
    finally:
        fleet.close()


@pytest.mark.parametrize("reason", ["car could not execute command: is_climate_on is false private-token",
    "car could not execute command: car could not execute command: is_climate_on is false",
    "untrusted prefix: not_in_park", "x"*5000])
def test_reason_classifier_is_exact_and_bounded(reason):
    assert rejection_reason(reason)["reason_code"] == "PROVIDER_REASON_UNCLASSIFIED"
    assert "private-token" not in json.dumps(rejection_reason(reason))


def test_shape_diagnostics_never_store_values_or_unknown_keys():
    shape = response_shape({"data": [{"sessionId": "private-session"}], "error": {"code": "private-code", "private-key": 1},
                            "secret-as-key": "private-token"})
    assert shape["fields"]["data"]["count"] == 1
    assert shape["fields"]["error"]["fields"]["code"]["kind"] == "string"
    assert shape["other_field_count"] == 1
    assert "private" not in json.dumps(shape) and "secret-as-key" not in json.dumps(shape)


def test_charging_unwrapped_payload_remains_error_but_has_bounded_shape(service, store, vehicle_ref, headers):
    result, request = query_read(service, store, vehicle_ref, headers, "charging_history", {"pageNo": 1, "pageSize": 5},
                                 {"data": [{"sessionId": "private-session"}], "private-key": "private-token"})
    assert result["isError"] is True
    data = result["structuredContent"]
    assert data["code"] == "PROVIDER_RESPONSE_INVALID" and "error_code" not in data
    shape = data["diagnostic"]["response_shape"]
    assert shape["fields"]["data"]["kind"] == "array" and shape["fields"]["data"]["count"] == 1
    assert "response" not in shape["fields"] and shape["other_field_count"] == 1
    assert not any(secret in json.dumps(data) for secret in ("private-session", "private-key", "private-token"))
    assert request.url.params["pageSize"] == "5"


@pytest.mark.parametrize("body", [b'{"response":{"timestamp":NaN}}',
    b'{"response":{"result":false,"result":true}}', b'{"response":{"timestamp":Infinity}}',
    b'{"response":{"timestamp":1e1000}}', b'{"response":'+b'['*100+b'0'+b']'*100+b'}'],
    ids=["nan", "duplicate_result", "infinity", "float_overflow", "excessive_nesting"])
@pytest.mark.parametrize("command", [False, True])
def test_non_finite_or_ambiguous_json_is_not_a_success(store, vehicle_ref, body, command):
    store.settings = replace(store.settings, live_enabled=True)
    requests = []
    def reply(request):
        requests.append(request)
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})
    fleet = Fleet(store, transport=httpx.MockTransport(reply))
    try:
        with pytest.raises(TeslaError) as err:
            fleet.call("door_lock" if command else "vehicle_vehicle", vehicle=store.vehicle(vehicle_ref))
        assert err.value.code == "PROVIDER_RESPONSE_INVALID"
        assert err.value.details["response_issue"] == "invalid_json"
        assert err.value.uncertain is command
        assert len(requests) == 1
    finally:
        fleet.close()
