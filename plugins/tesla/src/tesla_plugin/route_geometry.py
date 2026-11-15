"""Bounded, optional geometry projection of an observed RouteLine encoding.

Tesla documents Base64/polyline6; the protobuf envelope (one field 1 string)
is supported by archived observations and community implementations, not an
official envelope schema. Other fields are opaque: they are never stops.

This pure helper grants no access. Callers must check location permissions
before passing a stored value or returning this projection, and retain the
sample's quality and timestamps separately. Parsing never changes that sample.
"""
import base64
import binascii
import math


MAX_ROUTE_BASE64_CHARS = 65_536
MAX_ROUTE_DECODED_BYTES = 49_152
MAX_ROUTE_POINTS = 10_000
MAX_ROUTE_FIELDS = 1_024
ENCODING = "base64_protobuf_field1_polyline6"


class _RouteLineError(ValueError):
    """A finite reason code, never the input or a coordinate."""


def _varint(data, offset):
    """Read a canonical protobuf uint64, including the tenth-byte bound."""
    value = 0
    for group in range(10):
        if offset == len(data):
            raise _RouteLineError("truncated_varint")
        byte = data[offset]
        offset += 1
        if group == 9 and byte > 1:
            raise _RouteLineError("invalid_varint")
        value |= (byte & 0x7f) << (7 * group)
        if not byte & 0x80:
            if group and byte == 0:
                raise _RouteLineError("invalid_varint")
            return value, offset
    raise _RouteLineError("invalid_varint")


def _polyline_field(data):
    offset, fields, opaque = 0, 0, 0
    polyline = None
    while offset < len(data):
        fields += 1
        if fields > MAX_ROUTE_FIELDS:
            raise _RouteLineError("field_limit_exceeded")
        tag, offset = _varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if not 1 <= number <= (1 << 29) - 1:
            raise _RouteLineError("invalid_field_number")
        if wire not in (0, 1, 2, 5):
            # Deprecated groups are intentionally unsupported, including nesting.
            raise _RouteLineError("unsupported_wire_type")
        if number == 1:
            if wire != 2:
                raise _RouteLineError("polyline_wire_type")
            if polyline is not None:
                raise _RouteLineError("duplicate_polyline")
        else:
            opaque += 1
        if wire == 0:
            _, offset = _varint(data, offset)
            continue
        if wire == 2:
            size, offset = _varint(data, offset)
        else:
            size = 8 if wire == 1 else 4
        if size > len(data) - offset:
            raise _RouteLineError("truncated_field")
        if number == 1:
            polyline = data[offset:offset + size]
        offset += size
    if polyline is None:
        raise _RouteLineError("missing_polyline")
    if not polyline:
        raise _RouteLineError("empty_polyline")
    try:
        return polyline.decode("utf-8", errors="strict"), opaque
    except UnicodeDecodeError:
        raise _RouteLineError("invalid_utf8") from None


def _component(polyline, offset):
    value = 0
    for group in range(7):
        if offset == len(polyline):
            raise _RouteLineError("truncated_polyline")
        byte = ord(polyline[offset]) - 63
        offset += 1
        # Polyline uses unsigned chunks from the 32-bit zigzag representation.
        if group == 6 and byte > 3:
            raise _RouteLineError("invalid_polyline_varint")
        value |= (byte & 0x1f) << (5 * group)
        if not byte & 0x20:
            if group and byte == 0:
                raise _RouteLineError("invalid_polyline_varint")
            return (~(value >> 1) if value & 1 else value >> 1), offset
    raise _RouteLineError("invalid_polyline_varint")


def _points(polyline):
    if any(not 63 <= ord(char) <= 126 for char in polyline):
        raise _RouteLineError("invalid_polyline_alphabet")
    offset, latitude, longitude = 0, 0, 0
    points = []
    while offset < len(polyline):
        if len(points) >= MAX_ROUTE_POINTS:
            raise _RouteLineError("point_limit_exceeded")
        delta, offset = _component(polyline, offset)
        latitude += delta
        delta, offset = _component(polyline, offset)
        longitude += delta
        if not (-90_000_000 <= latitude <= 90_000_000 and
                -180_000_000 <= longitude <= 180_000_000):
            raise _RouteLineError("coordinate_out_of_range")
        lat, lon = latitude / 1_000_000, longitude / 1_000_000
        if not math.isfinite(lat) or not math.isfinite(lon):
            raise _RouteLineError("coordinate_out_of_range")
        # Named spatial keys preserve the existing generic privacy detector.
        points.append({"latitude": lat, "longitude": lon})
    if len(points) < 2:
        raise _RouteLineError("insufficient_points")
    return points


def parse_route_line(value):
    """Return complete bounded geometry or an unavailable, coordinate-free result.

    A successful projection is only the geometry present in one received
    sample. It does not prove an active route, current position, remaining
    distance, complete itinerary, stop list, or final destination. Unsupported
    encodings are not heuristically stripped or retried with another precision.
    """
    coverage = {"coverage": "partial_route_geometry",
                "complete_itinerary_verified": False,
                "stop_list_available": False,
                "destination_final_verified": False}
    try:
        if value is None or value == "":
            raise _RouteLineError("missing")
        if not isinstance(value, str):
            raise _RouteLineError("invalid_type")
        if len(value) > MAX_ROUTE_BASE64_CHARS:
            raise _RouteLineError("encoded_byte_limit_exceeded")
        try:
            encoded = value.encode("ascii", errors="strict")
            decoded = base64.b64decode(encoded, validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError):
            raise _RouteLineError("invalid_base64") from None
        if len(decoded) > MAX_ROUTE_DECODED_BYTES:
            raise _RouteLineError("decoded_byte_limit_exceeded")
        # Reject redundant padding and nonzero pad bits as well as whitespace.
        if base64.b64encode(decoded) != encoded:
            raise _RouteLineError("invalid_base64")
        polyline, opaque = _polyline_field(decoded)
        points = _points(polyline)
        return {"status": "available", "encoding": ENCODING, "precision": 6,
                "points": points, "point_count": len(points),
                "opaque_field_count": opaque, **coverage}
    except _RouteLineError as exc:
        return {"status": "unavailable", "reason": str(exc), **coverage}
