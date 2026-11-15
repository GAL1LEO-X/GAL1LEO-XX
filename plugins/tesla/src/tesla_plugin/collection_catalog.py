"""Shared collection vocabulary for the owner editor and ChatGPT."""
import re

from .profiles import full_profile
from .telemetry import FIELD_MAP, LOCATION_FIELDS
from .field_capabilities import qualification, selectable

CATEGORIES = {"Charging": 'Battery and charging', "Climate": 'Climate', "Driving": 'Driving',
              "Location": 'Location', "Media": "Media", "Powertrain": 'Motors and drivetrain',
              "Safety": 'Safety', "Service": 'Diagnostics', "User Preference": 'Preferences',
              "Vehicle Configuration": 'Vehicle configuration', "Vehicle State": 'Vehicle state'}
LABELS = {"BatteryLevel": 'Battery level', "Location": 'Location', "Locked": 'Door locking',
          "VehicleSpeed": 'Speed', "Odometer": 'Odometer', "Version": 'Software version',
          "InsideTemp": 'Cabin temperature', "OutsideTemp": 'Outside temperature',
          "DetailedChargeState": 'Charging state', "SelfDrivingMilesSinceReset": 'Assisted-driving distance',
          "SentryMode": 'Sentry Mode', "ChargeLimitSoc": 'Charge limit',
          "Gear": 'Selected gear', "DriverSeatOccupied": 'Driver occupancy', "GpsState": 'GPS status'}
DESCRIPTIONS = {
    "BatteryLevel": 'Battery state of charge percentage.',
    "DetailedChargeState": 'Indicates whether charging is active, completed or interrupted, or the cable is disconnected.',
    "Locked": 'Indicates whether the vehicle is locked. It does not describe the physical opening of each door.',
    "Version": 'Software version installed on the vehicle.',
    "Gear": 'Observed gear. It may be unavailable with inactive drive systems even while connected. Only valid, recent P establishes Park.',
    "DriverSeatOccupied": "Indicates whether the driver seat is occupied.",
    "ChargeLimitSoc": 'Battery percentage configured as the charging limit.',
    "VehicleSpeed": 'Vehicle speed.', "Odometer": 'Total vehicle distance travelled.',
    "Location": 'Vehicle latitude and longitude. The change threshold is measured in metres.',
    "GpsState": "Indicates GPS signal validity, used to assess location events.",
    "InsideTemp": "Observed cabin temperature.", "OutsideTemp": 'Observed outside temperature.',
    "SentryMode": 'Sentry Mode status.',
    "SelfDrivingMilesSinceReset": 'Assisted-driving distance since the last reset, in miles.',
}
PRESETS = {"saved": 'Last saved or recommended profile', "recommended": 'Recommended · essential automatic collection',
           "essential": 'Minimal · four fields', "notifications": 'Primary events · frequent',
           "journeys": 'Trips', "charging": 'Charging · energy and timing', "comfort": 'Comfort · climate and seats',
           "drive_diagnostics": 'Driving diagnostics · short observation', "full": 'Maximum coverage · compatibility requires verification'}
def duration(seconds):
    parts = []
    for unit, singular, plural in ((3600, 'hour', 'hours'), (60, 'minute', 'minutes'), (1, 'second', 'seconds')):
        value, seconds = divmod(seconds, unit)
        if value:
            parts.append(f'{value} {singular if value == 1 else plural}')
    return " and ".join(parts)


def timing_text(options, unit='field unit'):
    text = 'On change: at most one submission every '+duration(options["interval_seconds"])+"."
    resend = options.get("resend_interval_seconds")
    text += ' Requested resend: '+duration(resend)+'; reception at exact intervals is not guaranteed.' if resend else " Resend unchanged: Tesla default."
    if "minimum_delta" in options:
        text += ' Change threshold: '+str(options["minimum_delta"])+" "+unit+"."
    return text


def field_info(spec, vehicle_context=None):
    name = spec["field"]
    label = LABELS.get(name, re.sub(r"(?<=[a-z])(?=[A-Z])", " ", name))
    kind = spec["documented_type"]
    kind = {"boolean": "yes / no", "real": 'number', "integer": 'integer', "string": 'text'}.get(kind, kind)
    unit = 'metres' if name == "Location" else spec["unit_explicit_in_description"]
    unit = {"percent": 'percentage points'}.get(unit, unit)
    category = CATEGORIES.get(spec['category'], 'Diagnostics')
    description = DESCRIPTIONS.get(name, 'Data for '+category.lower()+". Format: "+(kind or 'defined by the protobuf message')+("; unit: "+unit if unit else "")+".")
    notes = [spec['notes']] if spec.get('notes') else []
    if name.startswith('TpmsLastSeenPressureTime'):
        description += ' Tesla reports a timezone defect: this value does not establish when pressure was measured.'
    if name == 'PassengerSeatBelt':
        description = 'Second-row centre seat belt: Tesla states that this field does not describe the front passenger.'
    if name in ('DestinationName', 'DestinationLocation', 'ExpectedEnergyPercentAtTripArrival'):
        description += ' This may refer to the next stop. It does not reconstruct the complete route or guarantee the final destination.'
    delta = spec["documented_type"].lower() in ("real", "integer") or name == "Location"
    return {"field": name, "label": label, "description": description, "category": category,
            'catalog_status': spec['catalog_status'], 'configurable': selectable(spec),
            'acquisition': {'channel': 'fleet_telemetry', 'mode': 'configured_push',
                            'rest_equivalent': spec.get('vehicle_data_equivalent') or None,
                            'history_tool': 'tesla_get_history', 'sampling_guaranteed': False},
            'requirements': {'firmware': spec['minimum_firmware_field'], 'client': spec['minimum_client_field'],
                             'tesla_scope': spec['base_scope'], 'extra_scope': spec['extra_scope']},
            'qualification': qualification(spec, vehicle_context), 'notes': notes, 'limitations': notes,
            'sources': [v for v in (spec.get('source_docs'), spec.get('source_proto')) if v],
            "documented_type": spec["documented_type"], "delta_supported": delta, "delta_unit": unit or 'field unit',
            "delta_minimum": 1 if name == "SelfDrivingMilesSinceReset" else 0,
            "location_required": name in LOCATION_FIELDS, "vehicle_availability_verified": False,
            "hardware_requirement": spec["hardware_notes"], "known_unavailable": name == "RouteLastUpdated"}


CONTROLS = {
    "interval_seconds": 'Minimum interval between changed values, 1 to 86400 seconds. This is not periodic polling.',
    "resend_interval_seconds": 'Resend even when unchanged, at least the minimum interval and at most 86400 seconds. Omission uses the Tesla default.',
    "minimum_delta": 'Thresholds may be decimal for numeric fields and Location; consult delta_supported, delta_unit and delta_minimum in the catalogue.',
    "include_fields": 'Fields included with the primary signal, even when unchanged; they increase cost. They do not change their independent intervals and inclusions are not recursive. Requires firmware 2026.26.6 and telemetry client 1.3.0.',
    "delivery": 'Delivery requires an awake, connected vehicle and an available value. Longer intervals can delay events and exceed rule freshness requirements.',
    "active_hours_per_day": 'Calculation assumption, not a collection schedule.',
    "customer_alerts": 'Alerts are sent when an event occurs, without a periodic interval; cost excluded from the estimate.',
    "changes": 'Proposals and estimates are local. Changing collection requires preparation, review and explicit confirmation; then verify application with Tesla.',
}


def catalogue_page(search, offset, limit, *, location_authorized, evidence=None, vehicle_context=None):
    defaults = full_profile()
    entries = []
    for name in sorted(name for name, spec in FIELD_MAP.items() if spec['catalog_status'] in ('DOCUMENTED', 'PROTO_ONLY_UNDOCUMENTED')):
        info = field_info(FIELD_MAP[name], vehicle_context)
        if search and search.casefold() not in (name+" "+info["label"]+" "+info["description"]+" "+info["category"]).casefold():
            continue
        entries.append({**info, "default_options": defaults.get(name),
                        **({"evidence": evidence[name]} if evidence and name in evidence else {}),
                        "location_permission_satisfied": location_authorized or name not in LOCATION_FIELDS})
    return {"items": entries[offset:offset+limit], "total": len(entries),
            "next_offset": offset+limit if offset+limit < len(entries) else None}


