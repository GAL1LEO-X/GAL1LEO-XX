"""Synthetic RouteLine projections; never persist a real route or location."""
import base64
import json

import pytest

from tesla_plugin import route_geometry
from tesla_plugin.route_geometry import (MAX_ROUTE_BASE64_CHARS, MAX_ROUTE_DECODED_BYTES,
                                         MAX_ROUTE_FIELDS, MAX_ROUTE_POINTS, parse_route_line)
from tesla_plugin.telemetry_privacy import contains_location


def varint(value):
    data = bytearray()
    while value >= 128:
        data.append((value & 127) | 128)
        value >>= 7
    data.append(value)
    return bytes(data)


def field(number, value):
    return varint(number << 3 | 2) + varint(len(value)) + value


def payload(data):
    return base64.b64encode(data).decode("ascii")


def route(polyline=b"??AC", extra=b""):
    return payload(field(1, polyline) + extra)


def encoded_points(points):
    """Encode only synthetic integer microdegrees for boundary fixtures."""
    previous = (0, 0)
    out = []
    for point in points:
        for coordinate, before in zip(point, previous):
            delta = coordinate - before
            value = (delta << 1) if delta >= 0 else ~(delta << 1)
            while value >= 32:
                out.append(chr(63 + ((value & 31) | 32)))
                value >>= 5
            out.append(chr(63 + value))
        previous = point
    return "".join(out).encode("ascii")


def unavailable(value, reason):
    result = parse_route_line(value)
    assert result == {"status": "unavailable", "reason": reason,
                      "coverage": "partial_route_geometry",
                      "complete_itinerary_verified": False,
                      "stop_list_available": False,
                      "destination_final_verified": False}
    assert not contains_location(result)
    return result


def test_observed_envelope_projects_only_field_one_at_precision_six():
    raw = route(extra=field(2, b"\xff\x00\x80xx") + field(2, b"unknown"))
    result = parse_route_line(raw)
    assert result == {"status": "available", "encoding": "base64_protobuf_field1_polyline6",
                      "precision": 6, "point_count": 2,
                      "points": [{"latitude": 0.0, "longitude": 0.0},
                                 {"latitude": 0.000001, "longitude": 0.000002}],
                      "opaque_field_count": 2, "coverage": "partial_route_geometry",
                      "complete_itinerary_verified": False,
                      "stop_list_available": False,
                      "destination_final_verified": False}
    assert contains_location(result)
    assert raw not in json.dumps(result)
    assert "unknown" not in json.dumps(result)
    assert "source_at" not in result and "received_at" not in result and "quality" not in result


def test_opaque_fields_can_precede_geometry_and_use_all_supported_wire_types():
    opaque = (varint(2 << 3) + varint((1 << 64) - 1) +
              varint(3 << 3 | 1) + b"\x00" * 8 +
              field(4, b"") + varint(5 << 3 | 5) + b"\x00" * 4)
    result = parse_route_line(payload(opaque + field(1, b"??AC")))
    assert result["status"] == "available"
    assert result["point_count"] == 2 and result["opaque_field_count"] == 4


@pytest.mark.parametrize("value", [None, ""])
def test_missing_geometry(value):
    unavailable(value, "missing")


@pytest.mark.parametrize("value", [False, True, 12, [], {}, b"CgQ/P0FD"])
def test_non_string_input_is_not_coerced(value):
    unavailable(value, "invalid_type")


@pytest.mark.parametrize("value", [" ", "\n", "?", "-w==", "_w==", "é", "CgQ/P0FD\n",
                                    "CgQ/P0FD=", "CgQ/P0FD====", "AB==", "AAB=", "A"])
def test_base64_is_strict_and_canonical(value):
    unavailable(value, "invalid_base64")


@pytest.mark.parametrize("wire", [0, 1, 5])
def test_field_one_must_be_length_delimited(wire):
    unavailable(payload(varint(8 | wire) + b"\x00" * 8), "polyline_wire_type")


@pytest.mark.parametrize("number", [0, 1 << 29])
def test_invalid_protobuf_field_number(number):
    unavailable(payload(varint(number << 3 | 2) + b"\x00"), "invalid_field_number")


@pytest.mark.parametrize("wire", [3, 4, 6, 7])
def test_groups_and_unknown_wire_types_are_rejected(wire):
    unavailable(route(extra=varint(2 << 3 | wire)), "unsupported_wire_type")


@pytest.mark.parametrize("bad", [b"\x80\x00", b"\x80" * 10, b"\xff" * 9 + b"\x02"])
@pytest.mark.parametrize("position", ["tag", "length", "opaque_value"])
def test_malformed_or_overlong_varints(bad, position):
    data = bad if position == "tag" else b"\x0a" + bad if position == "length" else b"\x10" + bad
    unavailable(payload(data), "invalid_varint")


@pytest.mark.parametrize("data", [b"\x80", b"\x0a\x80", b"\x10\x80"])
def test_truncated_varints(data):
    unavailable(payload(data), "truncated_varint")


@pytest.mark.parametrize("data", [b"\x0a\x05??AC", b"\x0a" + varint((1 << 64) - 1),
                                   b"\x11" + b"\x00" * 7, b"\x15" + b"\x00" * 3])
def test_truncated_and_oversized_declared_fields(data):
    unavailable(payload(data), "truncated_field")


def test_duplicate_missing_and_empty_polyline_are_unavailable():
    unavailable(route(extra=field(1, b"??AC")), "duplicate_polyline")
    unavailable(payload(field(2, b"??AC")), "missing_polyline")
    unavailable(route(polyline=b""), "empty_polyline")
    unavailable(route(polyline=b"", extra=field(1, b"??AC")), "duplicate_polyline")


@pytest.mark.parametrize("suffix,reason", [(b"\x80", "truncated_varint"),
                                          (b"\x12\x05abc", "truncated_field"),
                                          (b"\x00", "invalid_field_number")])
def test_valid_prefix_never_hides_bad_wrapper_suffix(suffix, reason):
    unavailable(route(extra=suffix), reason)


@pytest.mark.parametrize("value,reason", [(b"\xff", "invalid_utf8"), (b"\xc0\xaf", "invalid_utf8"),
                                         ("é".encode(), "invalid_polyline_alphabet"),
                                         (b"??AC\x00", "invalid_polyline_alphabet"),
                                         (b"??AC ", "invalid_polyline_alphabet"),
                                         (b"??AC\x7f", "invalid_polyline_alphabet")])
def test_polyline_text_is_strict(value, reason):
    unavailable(route(value), reason)


@pytest.mark.parametrize("value", [b"?", b"_", b"??AC?", b"??AC_"])
def test_incomplete_coordinate_pairs_reject_entire_geometry(value):
    unavailable(route(value), "truncated_polyline")


@pytest.mark.parametrize("value", [b"_??", b"______C?", b"_______?", b"~~~~~~~?"])
def test_polyline_integer_overflow_and_overlong_encodings(value):
    unavailable(route(value), "invalid_polyline_varint")


def test_one_point_does_not_claim_a_route_line():
    unavailable(route(b"??"), "insufficient_points")


@pytest.mark.parametrize("point", [(90_000_001, 0), (-90_000_001, 0),
                                   (0, 180_000_001), (0, -180_000_001)])
def test_geographic_bounds_apply_to_accumulated_coordinates(point):
    unavailable(route(encoded_points([(0, 0), point])), "coordinate_out_of_range")


def test_geographic_boundaries_and_negative_deltas_are_supported():
    result = parse_route_line(route(encoded_points([(90_000_000, 180_000_000),
                                                   (-90_000_000, -180_000_000)])))
    assert result["points"] == [{"latitude": 90.0, "longitude": 180.0},
                                {"latitude": -90.0, "longitude": -180.0}]
    # A successful result is JSON-safe with no NaN/Infinity extension required.
    json.dumps(result, allow_nan=False)


def test_maximum_point_count_is_supported_without_silent_truncation():
    result = parse_route_line(route(b"??" * MAX_ROUTE_POINTS))
    assert result["status"] == "available" and result["point_count"] == MAX_ROUTE_POINTS
    unavailable(route(b"??" * (MAX_ROUTE_POINTS + 1)), "point_limit_exceeded")


def test_wrapper_field_count_is_bounded():
    result = parse_route_line(route(extra=field(2, b"") * (MAX_ROUTE_FIELDS - 1)))
    assert result["status"] == "available" and result["opaque_field_count"] == MAX_ROUTE_FIELDS - 1
    unavailable(route(extra=field(2, b"") * MAX_ROUTE_FIELDS), "field_limit_exceeded")


def test_encoded_and_decoded_byte_limits_are_exact_and_bounded(monkeypatch):
    # Fill a bounded opaque field; payload contents have no inferred semantics.
    opaque = b"x" * (MAX_ROUTE_DECODED_BYTES - len(field(1, b"??AC")) - 4)
    raw = route(extra=field(2, opaque))
    assert len(raw) == MAX_ROUTE_BASE64_CHARS
    assert len(base64.b64decode(raw)) == MAX_ROUTE_DECODED_BYTES
    assert parse_route_line(raw)["status"] == "available"
    unavailable(raw + "A", "encoded_byte_limit_exceeded")
    monkeypatch.setattr(route_geometry, "MAX_ROUTE_DECODED_BYTES", MAX_ROUTE_DECODED_BYTES - 1)
    unavailable(raw, "decoded_byte_limit_exceeded")


def test_unwrapped_polyline_is_not_heuristically_accepted():
    unavailable(payload(b"??AC"), "unsupported_wire_type")


def test_projection_is_pure_and_failure_does_not_reclassify_sample():
    sample = {"value": "historical opaque RouteLine", "quality": "valid",
              "source_at": 1, "received_at": 2}
    before = json.dumps(sample)
    unavailable(sample["value"], "invalid_base64")
    assert json.dumps(sample) == before
