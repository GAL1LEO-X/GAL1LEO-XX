"""Equality of decoded observations, independent of JSON/wire spelling.

Stored samples and their provenance are never rewritten by these comparisons.
Only aliases accepted by the pinned field contract are normalized. Equality is
exact: it does not round measurements, merge booleans with numbers, or turn a
missing member into a default value.
"""
import json
import math

from .telemetry_values import TIRE_KEYS
from .trigger_catalog import FIELD_MAP


def _key(value):
    if value is None:
        return ('null',)
    if type(value) is bool:
        return ('boolean', value)
    if type(value) in (int, float):
        if not math.isfinite(value):
            raise ValueError('Non-finite observation')
        # Python compares int/float numerically without rounding the integer to
        # float first. This also equates -0.0/0, but not adjacent large integers.
        return ('number', value)
    if isinstance(value, str):
        return ('string', value)
    if isinstance(value, list):
        return ('array', tuple(_key(item) for item in value))
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return ('object', tuple(sorted((key, _key(item)) for key, item in value.items())))
    raise ValueError('Not a JSON observation')


def _field_key(field, value):
    if FIELD_MAP.get(field, {}).get('protobuf_value_type') == 'TireLocation' and isinstance(value, dict):
        keys = [TIRE_KEYS.get(key) for key in value]
        if keys and None not in keys and len(set(keys)) == len(value) and all(type(item) is bool for item in value.values()):
            value = {TIRE_KEYS[key]: item for key, item in value.items()}
    return _key(value)


def equal(field, left, right):
    """Compare values, preserving strict type and missing-member distinctions."""
    try:
        return _field_key(field, left) == _field_key(field, right)
    except (ValueError, TypeError, OverflowError, RecursionError):
        return False


def json_equal(field, left, right):
    """SQLite/Python adapter; corrupt serialized values cannot prove equality."""
    try:
        return equal(field, json.loads(left) if left is not None else None,
                     json.loads(right) if right is not None else None)
    except (ValueError, TypeError, RecursionError):
        return False
