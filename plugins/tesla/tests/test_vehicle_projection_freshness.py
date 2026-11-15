"""Synthetic K4 regressions: cache provenance and projections, without live I/O."""
import json

import httpx
import pytest

from tesla_plugin.config import SCOPES
from tesla_plugin.state_evidence import block_view, snapshot_row
from tesla_plugin.telemetry import Telemetry
from test_telemetry_events import payload


SECTIONS = ("navigation_data", "media_state", "location_data")


@pytest.fixture(autouse=True)
def offline_fixed_clock(monkeypatch, clock):
    clock.value = 1800000000
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected external HTTP request")
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)


def values(section, variant=0):
    return {"navigation_data": {"active_route_destination": "Synthetic stop "+str(variant)},
            "media_state": {"now_playing_title": "Synthetic track "+str(variant)},
            "location_data": {"latitude": 12.+variant, "longitude": 21.+variant}}[section]


def parent_block(section, data, at):
    name = "vehicle_state" if section == "media_state" else "drive_state"
    return name, {"timestamp": at, **({"media_info": data} if section == "media_state" else data)}


def save(service, ref, section, data, at):
    service.store.snapshot(ref, section, {"timestamp": at, **data}, "tesla_cached", at)


def conflict(service, ref, section, at, empty_first):
    blocks = [{}, values(section)]
    for data in blocks if empty_first else reversed(blocks):
        save(service, ref, section, data, at)


def fake_read(service, response):
    original = service.fleet.call
    def call(name, *args, **kwargs):
        result = original(name, *args, **kwargs)
        return response if name in ("vehicle_vehicle_data_cached", "vehicle_vehicle_data") else result
    service.fleet.call = call


@pytest.mark.parametrize("section", SECTIONS)
@pytest.mark.parametrize("empty_first", [False, True])
@pytest.mark.parametrize("mode", ["cached_only", "cache_preferred", "live_if_online"])
def test_dedicated_conflict_cannot_revive_older_parent(service, vehicle_ref, clock, section, empty_first, mode):
    name, parent = parent_block(section, values(section, 1), clock()-10)
    save(service, vehicle_ref, name, parent, parent["timestamp"])
    conflict(service, vehicle_ref, section, clock(), empty_first)
    fake_read(service, {name: parent, section: {"timestamp": clock(), **values(section)}})
    result = service.state(vehicle_ref, [section], mode, SCOPES)["data"][section]
    assert result["quality"] == "time_conflict" and result["data"] is None
    assert result["source_timestamp"] == clock() and result["source"] == "rest_time_conflict"
    assert result["timestamp_evidence"]["proves_current_state"] is False
    assert result["selection_evidence"]["selected_section"] == section
    assert [call[0] for call in service.fleet.calls] == {
        "cached_only": [], "cache_preferred": ["vehicle_vehicle_data_cached"],
        "live_if_online": ["vehicle_vehicle", "vehicle_vehicle_data"]}[mode]


@pytest.mark.parametrize("section", SECTIONS)
@pytest.mark.parametrize("empty_first", [False, True])
def test_parent_conflict_is_not_hidden_by_retained_payload_shape(service, vehicle_ref, clock, section, empty_first):
    save(service, vehicle_ref, section, values(section), clock()-10)
    blocks = [{}, values(section, 1)]
    for data in blocks if empty_first else reversed(blocks):
        name, parent = parent_block(section, data, clock())
        save(service, vehicle_ref, name, parent, clock())
    result = service.state(vehicle_ref, [section], "cached_only", SCOPES)["data"][section]
    assert result["quality"] == "time_conflict" and result["data"] is None
    assert result["source_timestamp"] == clock() and result["coverage"] == "partial"


@pytest.mark.parametrize("section", SECTIONS)
@pytest.mark.parametrize("offset", [30, 30.001, 86400])
@pytest.mark.parametrize("parent_age", [0, 120, 120.001])
def test_future_dedicated_uses_plausible_parent_with_its_own_age(service, vehicle_ref, clock, section, offset, parent_age):
    save(service, vehicle_ref, section, values(section), clock()+offset)
    name, parent = parent_block(section, values(section, 1), clock()-parent_age)
    save(service, vehicle_ref, name, parent, parent["timestamp"])
    result = service.state(vehicle_ref, [section], "cached_only", SCOPES)["data"][section]
    if offset == 30:
        assert result["data"] == {"timestamp": clock()+offset, **values(section)}
        assert result["age_seconds"] == -30 and result["quality"] == "fresh_observed"
    else:
        assert result["data"] == values(section, 1)
        assert result["source_timestamp"] == clock()-parent_age
        assert result["age_seconds"] == pytest.approx(parent_age)
        assert result["quality"] == ("fresh_observed" if parent_age <= 120 else "stale")
        assert result["time_basis"] == "parent_rest_block_timestamp"
        alternative = result["selection_evidence"]["alternative"]
        assert alternative["source_timestamp"] == clock()+offset and alternative["quality"] == "future"
        assert alternative["future_clock"] is True


@pytest.mark.parametrize("section", SECTIONS)
def test_future_parent_does_not_displace_plausible_dedicated(service, vehicle_ref, clock, section):
    save(service, vehicle_ref, section, values(section), clock()-121)
    name, parent = parent_block(section, values(section, 1), clock()+31)
    save(service, vehicle_ref, name, parent, parent["timestamp"])
    result = service.state(vehicle_ref, [section], "cached_only", SCOPES)["data"][section]
    assert result["quality"] == "stale" and result["age_seconds"] == 121
    assert result["selection_evidence"]["alternative"]["quality"] == "future"


@pytest.mark.parametrize("section", SECTIONS)
@pytest.mark.parametrize("parent_offset", [0, 1, 31])
def test_only_newer_plausible_parent_supersedes_dedicated_conflict(service, vehicle_ref, clock, section, parent_offset):
    conflict(service, vehicle_ref, section, clock(), True)
    name, parent = parent_block(section, values(section, 1), clock()+parent_offset)
    save(service, vehicle_ref, name, parent, parent["timestamp"])
    result = service.state(vehicle_ref, [section], "cached_only", SCOPES)["data"][section]
    if parent_offset == 1:
        assert result["quality"] == "fresh_observed" and result["data"] == values(section, 1)
        assert result["selection_evidence"]["alternative"]["quality"] == "time_conflict"
    else:
        assert result["quality"] == "time_conflict" and result["data"] is None


@pytest.mark.parametrize("section", SECTIONS)
def test_future_conflict_fallback_still_exposes_invalidation(service, vehicle_ref, clock, section):
    conflict(service, vehicle_ref, section, clock()+86400, True)
    name, parent = parent_block(section, values(section, 1), clock()-121)
    save(service, vehicle_ref, name, parent, parent["timestamp"])
    result = service.state(vehicle_ref, [section], "cached_only", SCOPES)["data"][section]
    assert result["quality"] == "stale" and result["age_seconds"] == 121
    alternative = result["selection_evidence"]["alternative"]
    assert alternative["quality"] == "time_conflict" and alternative["future_clock"] is True
    assert alternative["timestamp_evidence"]["proves_current_state"] is False


@pytest.mark.parametrize("raw,quality", [(None, "unknown_time"), ("bad", "unknown_time"),
    (1800000030, "fresh_observed"), (1800000030.001, "future"),
    (1799999880, "fresh_observed"), (1799999879.999, "stale")])
def test_block_freshness_boundaries_do_not_use_receipt_time(clock, raw, quality):
    row = snapshot_row({"data": json.dumps({"timestamp": raw, "value": 1}),
                        "source_at": None, "source": "tesla_cached", "received": clock()})
    result = block_view(row, "media_state", clock())
    assert result["quality"] == quality
    if quality == "unknown_time":
        assert result["source_timestamp"] is None and result["age_seconds"] is None


def test_cached_wrapper_preserves_raw_data_and_matches_normalized_state(service, vehicle_ref, clock):
    response = {"drive_state": {"timestamp": (clock()-121)*1000, "speed": 1,
                               "active_route_destination": "Synthetic stop", "latitude": 12., "longitude": 21.},
                "vehicle_state": {"timestamp": {"seconds": int(clock()), "nanos": 0}, "tpms_pressure_fl": 2.6,
                                  "media_info": {"now_playing_title": "Synthetic track"}},
                "charge_state": {"battery_level": 50, "timestamp": "bad"}}
    fake_read(service, response)
    result = service.read("vehicle_vehicle_data_cached", {}, vehicle_ref, SCOPES)
    assert result["source"] == "tesla_cached" and result["data"] == response
    evidence = result["read_evidence"]
    assert evidence["data_semantics"] == "raw_provider_cached_response"
    sections = [*response, *SECTIONS]
    state = service.state(vehicle_ref, sections, "cached_only", SCOPES)["data"]
    assert evidence["cache_state"] == state
    for section in response:
        assert evidence["response_sections"][section] == {key: value for key, value in state[section].items() if key != "data"}
    assert state["vehicle_state"]["units"]["tpms_pressure_fl"] == "bar"
    assert "TPMS" in state["vehicle_state"]["limitations"][0]
    assert state["drive_state"]["units"]["speed"] == "mph"
    assert state["drive_state"]["quality"] == "stale"
    assert state["charge_state"]["quality"] == "unknown_time"
    assert [call[0] for call in service.fleet.calls] == ["vehicle_vehicle_data_cached"]


@pytest.mark.parametrize("incoming_age,quality", [(10, "fresh_observed"), (0, "time_conflict")])
def test_cached_wrapper_distinguishes_response_from_retained_or_conflicted_state(service, vehicle_ref, clock, incoming_age, quality):
    save(service, vehicle_ref, "charge_state", {"battery_level": 80}, clock())
    response = {"charge_state": {"timestamp": clock()-incoming_age, "battery_level": 55}}
    fake_read(service, response)
    result = service.read("vehicle_vehicle_data_cached", {}, vehicle_ref, SCOPES)
    assert result["data"] == response
    assert result["read_evidence"]["response_sections"]["charge_state"]["quality"] == "fresh_observed"
    current = result["read_evidence"]["cache_state"]["charge_state"]
    assert current["quality"] == quality
    assert current["data"] is None if quality == "time_conflict" else current["data"]["battery_level"] == 80
    assert current == service.state(vehicle_ref, ["charge_state"], "cached_only", SCOPES)["data"]["charge_state"]


def test_cached_wrapper_evidence_respects_location_redaction(service, vehicle_ref, clock):
    response = {"drive_state": {"timestamp": clock(), "latitude": 12., "longitude": 21.,
                               "active_route_destination": "private-synthetic-destination"},
                "vehicle_state": {"timestamp": clock(), "locked": True}}
    fake_read(service, response)
    result = service.read("vehicle_vehicle_data_cached", {}, vehicle_ref, set(SCOPES)-{"tesla:location"})
    assert "private-synthetic" not in json.dumps(result)
    for data in [result["data"], result["read_evidence"]["response_sections"], result["read_evidence"]["cache_state"]]:
        assert not {"drive_state", "navigation_data", "location_data"} & data.keys()


@pytest.mark.parametrize("offset", [-1, 0, 1, 31])
def test_location_telemetry_cannot_hide_rest_conflict_unless_newer_and_plausible(service, vehicle_ref, clock, offset):
    conflict(service, vehicle_ref, "location_data", clock(), True)
    at = clock()
    # Model a cached observation becoming future after a local clock correction;
    # ingestion correctly rejects timestamps already >30 seconds in the future.
    if offset > 30:
        clock.advance(offset)
    Telemetry(service.store).ingest("V", payload(clock, {"Location": values("location_data", 1)}, when=at+offset))
    clock.value = at
    result = service.state(vehicle_ref, ["location_data"], "cached_only", SCOPES)["data"]["location_data"]
    if offset == 1:
        assert result["source"] == "fleet_telemetry" and result["quality"] == "fresh_observed"
        assert result["selection_evidence"]["alternative"]["quality"] == "time_conflict"
    else:
        assert result["quality"] == "time_conflict" and result["data"] is None
