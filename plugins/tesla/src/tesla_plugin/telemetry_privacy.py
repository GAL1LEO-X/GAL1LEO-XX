"""Recognize structured spatial content independently of a telemetry key.

Proto-only fields have no per-key value contract. Their unqualified status is
not a privacy permission. Recheck stored structures as well as incoming values;
this also protects rows created before the ingestion check was introduced.
This is not a detector for addresses or coordinates embedded in free text.
"""

SPATIAL_KEYS = frozenset({
    'latitude', 'longitude', 'lat', 'lon', 'long',
    'native_latitude', 'native_longitude', 'location_value', 'locationValue',
})


def contains_location(value):
    if isinstance(value, dict):
        return bool(SPATIAL_KEYS.intersection(value)) or any(
            contains_location(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_location(item) for item in value)
    return False
