"""Shared event vocabulary and selectable, documented telemetry signals."""
from .catalogue import FIELDS

FIELD_MAP = {row["field"]: row for row in FIELDS}
LOCATION_FIELDS = {row["field"] for row in FIELDS if row["category"] == "Location"} | {
    "Location", "OriginLocation", "DestinationLocation", "DestinationName", "RouteLine", "GpsState", "GpsHeading", "LocatedAtHome", "LocatedAtWork"}

EVENT_LABELS = {
    "battery_low": 'Battery below threshold', "charge_started": 'Charging started',
    "charge_resumed": 'Charging resumed', "charge_stopped": 'Charging interrupted', "charge_completed": 'Charging completed',
    "unlocked_parked": 'Vehicle parked and open', "alert_started": 'Vehicle alert',
    "alert_ended": "Alert cleared", "data_stale": 'Stale data', "geofence_enter": "Area entry",
    "geofence_exit": "Area exit", "field_changed": "Change from a custom rule",
    "threshold_crossed": 'Custom threshold raggiunta', "trip_started": 'D or R selected · movement unverified',
    "trip_ended": 'Returned to P · end of movement unverified', "software_changed": 'Software version cambiata',
    "connectivity_changed": 'Connection aggiornata', "telemetry_changed": 'Changes to selected fields',
    "location_changed": 'Changes to selected location fields',
}
EVENT_KINDS = tuple(EVENT_LABELS)
RULE_EVENTS = {
    "battery_low": ("battery_low",), "charging": ("charge_started", "charge_resumed", "charge_stopped", "charge_completed"),
    "unlocked_parked": ("unlocked_parked",), "geofence": ("geofence_enter", "geofence_exit"),
    "threshold": ("threshold_crossed",), "field_changed": ("field_changed",), "trip": ("trip_started", "trip_ended"),
    "software": ("software_changed",), "stale": ("data_stale",),
}
BASE_RULES = {
    "battery_low": {"field": "BatteryLevel", "direction": "below", "threshold": 20},
    "charging": {}, "unlocked_parked": {}, "trip": {}, "software": {},
    "stale": {"field": "BatteryLevel", "max_age_seconds": 900},
}
RULE_DEFAULTS = {"max_age_seconds": 120, "max_gap_seconds": 600, "dwell_seconds": 120, "hysteresis": 2}
RULE_FIELDS = {"charging": ["DetailedChargeState"], "unlocked_parked": ["Locked", "Gear", "DriverSeatOccupied"],
               "geofence": ["Location", "GpsState"], "trip": ["Gear"], "software": ["Version"]}
LOCATION_EVENTS = {"geofence_enter", "geofence_exit", "trip_started", "trip_ended", "field_changed", "threshold_crossed", "location_changed"}


def event_selected(db, ref, kind):
    row = db.execute("SELECT enabled FROM trigger_preferences WHERE vehicle=? AND id=?", (ref, "event:"+kind)).fetchone()
    return row is None or bool(row[0])


def location_allowed(connection, vehicle, scopes):
    import json
    return (bool(connection) and "tesla:location" in scopes and "vehicle_location" in json.loads(connection["scopes"])
            and not vehicle["data"].get("granular_access", {}).get("hide_private"))
