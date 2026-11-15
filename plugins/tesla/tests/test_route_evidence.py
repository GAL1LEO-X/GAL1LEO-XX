import base64
import json

import pytest

from tesla_plugin.route_evidence import view


def route_value():
    # Two synthetic nearby points (0,0) and (0.000001,0.000001).
    line = b"??AA"
    return base64.b64encode(b"\x0a" + bytes([len(line)]) + line).decode()


def latest(store, vehicle_ref, clock, *, quality="valid", age=0, value=None):
    with store.db() as db:
        db.execute("INSERT OR REPLACE INTO latest VALUES(?,?,?,?,?,?,?)",
                   (vehicle_ref, "RouteLine", json.dumps(route_value() if value is None else value),
                    clock()-age, clock(), quality, "synthetic"))


def test_route_permission_is_checked_before_any_database_read(store, vehicle_ref, monkeypatch):
    def forbidden():
        raise AssertionError("unauthorized route read")
    monkeypatch.setattr(store, "db", forbidden)
    result = view(store, vehicle_ref, location_allowed=False)
    assert result["reason"] == "LOCATION_PERMISSION_REQUIRED"
    assert result["geometry"] is None and "observation" not in result


def test_current_route_preserves_observation_and_partial_semantics(store, vehicle_ref, clock):
    latest(store, vehicle_ref, clock)
    result = view(store, vehicle_ref, location_allowed=True)
    assert result["status"] == "available"
    assert result["geometry"]["point_count"] == 2
    assert result["observation"]["source_timestamp"] == clock()
    assert "value" not in result["observation"]
    assert not result["complete_itinerary_verified"]
    assert not result["destination_final_verified"]
    assert not result["stop_list_available"]
    assert not result["current_vehicle_position"]


@pytest.mark.parametrize("quality,age", [("invalid", 0), ("unqualified", 0),
                                          ("time_conflict", 0), ("valid", 121), ("valid", -1)])
def test_invalid_or_expired_route_never_promoted_to_current_geometry(store, vehicle_ref, clock, quality, age):
    latest(store, vehicle_ref, clock, quality=quality, age=age)
    result = view(store, vehicle_ref, location_allowed=True)
    assert result["status"] == "unavailable" and result["geometry"] is None
    assert result["reason"] == "ROUTE_NOT_CURRENT_VALID"
    assert result["observation"]["quality"] == quality


def test_malformed_current_route_does_not_expose_original_payload(store, vehicle_ref, clock):
    original = "private-invalid-route-content"
    latest(store, vehicle_ref, clock, value=original)
    result = view(store, vehicle_ref, location_allowed=True)
    assert result["status"] == "unavailable" and result["geometry"] is None
    assert original not in json.dumps(result)
