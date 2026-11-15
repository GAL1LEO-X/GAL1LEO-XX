"""Discoverable notification rule options without a root tool-schema union."""
from .trigger_catalog import RULE_DEFAULTS


CONFIG_BY_KIND = {
    'battery_low': {'required': [], 'defaults': {'field': 'BatteryLevel', 'direction': 'below', 'threshold': 20}},
    'charging': {'required': [], 'fields': ['DetailedChargeState']},
    'unlocked_parked': {'required': [], 'fields': ['Locked', 'Gear', 'DriverSeatOccupied']},
    'geofence': {'required': ['latitude', 'longitude', 'radius_m'], 'fields': ['Location', 'GpsState']},
    'threshold': {'required': ['field', 'threshold', 'direction'], 'field_constraint': 'numeric documented telemetry field'},
    'field_changed': {'required': ['field'], 'field_constraint': 'documented telemetry field'},
    'trip': {'required': [], 'fields': ['Gear']},
    'software': {'required': [], 'fields': ['Version']},
    'stale': {'required': ['field'], 'field_constraint': 'documented telemetry field except Version'},
}

RULE_CONFIG_SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'description': 'Options depend on kind; see x-config-by-kind. Threshold needs field, threshold and direction; '
                   'field_changed/stale need field; geofence needs latitude, longitude and radius_m. '
                   'Other kinds have defaults. These rules only notify and never send vehicle commands.',
    'properties': {
        **{key: {'type': 'number', 'minimum': 1, 'maximum': 86400, 'default': RULE_DEFAULTS[key],
                 'description': 'Seconds; omitted values use this default.'}
           for key in ('max_age_seconds', 'max_gap_seconds', 'dwell_seconds')},
        'hysteresis': {'type': 'number', 'minimum': 0, 'default': RULE_DEFAULTS['hysteresis'],
                       'description': 'Threshold rearm margin; distance in metres for geofence.'},
        'field': {'type': 'string', 'description': 'Exact documented telemetry identifier from tesla_telemetry_catalogue. '
                  'Required for threshold, field_changed and stale; threshold requires a numeric field; stale excludes Version.'},
        'threshold': {'type': 'number', 'description': 'Required for threshold; battery_low defaults to 20 percent.'},
        'direction': {'type': 'string', 'enum': ['above', 'below'], 'description': 'Required for threshold; battery_low uses below.'},
        'latitude': {'type': 'number', 'minimum': -90, 'maximum': 90, 'description': 'Required for geofence; location authorization required.'},
        'longitude': {'type': 'number', 'minimum': -180, 'maximum': 180, 'description': 'Required for geofence.'},
        'radius_m': {'type': 'number', 'minimum': 50, 'maximum': 100000, 'description': 'Required for geofence, in metres.'},
    },
    'x-config-by-kind': CONFIG_BY_KIND,
}
