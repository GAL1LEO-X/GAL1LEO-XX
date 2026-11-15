"""Validated telemetry selection, independent of receiver/operator configuration."""
from copy import deepcopy
import math
import re
from cryptography import x509

from .catalogue import FIELDS
from .errors import TeslaError
from .trigger_catalog import FIELD_MAP, LOCATION_FIELDS
from .field_capabilities import selectable, select_maximum, context, qualification, version, meets_version


def included_sources(fields):
    """One-level includes are emitted with their parent, not recursively."""
    sources = {}
    for parent, options in fields.items():
        for child in options.get("include_fields", []):
            sources.setdefault(child, []).append(parent)
    return sources


def effective_fields(fields):
    return set(fields) | set(included_sources(fields))

ESSENTIAL = {"BatteryLevel": (60, 900, 1), "DetailedChargeState": (60, 300, None),
             "Locked": (60, 300, None), "ChargeLimitSoc": (300, 1800, 1)}
NOTIFICATIONS = {"BatteryLevel": (30, 300, 1), "DetailedChargeState": (5, 120, None), "ChargeLimitSoc": (60, 900, 1),
                 "Locked": (5, 15, None), "Gear": (5, 15, None), "DriverSeatOccupied": (5, 15, None),
                 "Version": (60, 60, None)}
JOURNEYS = {**NOTIFICATIONS, "VehicleSpeed": (5, 60, 1), "Odometer": (30, 300, None), "Location": (10, 60, 25), "GpsState": (10, 60, None)}
# Keep the suggested profile compatible with the initial rules: 120s freshness,
# 30s multi-field coherence, with margin for delivery. This changes proposals,
# never a saved/applied profile. Custom rules still require an impact review.
RECOMMENDED = {"BatteryLevel": (60, 60, 1), "DetailedChargeState": (15, 60, None),
               "Locked": (15, 15, None), "Gear": (15, 15, None),
               "DriverSeatOccupied": (15, 15, None), "ChargeLimitSoc": (300, 1800, 1),
               "Version": (60, 60, None)}
CHARGING = {"BatteryLevel": (60, 300, 1), "DetailedChargeState": (15, 60, None),
            "ChargeLimitSoc": (300, 1800, 1), "ChargeAmps": (60, 300, 1), "ChargerVoltage": (60, 300, 1),
            "ACChargingPower": (60, 300, None), "DCChargingPower": (60, 300, None),
            "DCChargingEnergyIn": (300, 1800, None), "EstimatedHoursToChargeTermination": (300, 1800, None)}
COMFORT = {"InsideTemp": (60, 300, 0.5), "OutsideTemp": (300, 1800, 1), "HvacPower": (15, 60, None),
           "HvacAutoMode": (60, 300, None), "SeatHeaterLeft": (15, 60, None), "SeatHeaterRight": (15, 60, None),
           "HvacSteeringWheelHeatLevel": (15, 60, None), "HvacSteeringWheelHeatAuto": (60, 300, None)}
DRIVE_DIAGNOSTICS = {"Gear": (5, 5, None), "DriveRail": (5, 5, None), "BrakePedal": (5, 5, None),
                     "CenterDisplay": (5, 5, None), "DriverSeatOccupied": (5, 5, None), "Locked": (5, 5, None),
                     "DetailedChargeState": (15, 60, None)}


def full_profile():
    fields = {name: {"interval_seconds": 300 if row["category"] in ("Vehicle Configuration", "User Preference") else 60,
                     "resend_interval_seconds": 3600}
              for name, row in FIELD_MAP.items() if selectable(row)}
    fields.update(profile_fields("journeys"))
    fields["SelfDrivingMilesSinceReset"]["minimum_delta"] = 1
    return fields


def profile_fields(preset, custom=None, *, vehicle_context=None):
    presets = {"normal": RECOMMENDED, "travel": JOURNEYS, "diagnostic": DRIVE_DIAGNOSTICS,
               "recommended": RECOMMENDED, "essential": ESSENTIAL, "notifications": NOTIFICATIONS, "journeys": JOURNEYS,
               "charging": CHARGING, "comfort": COMFORT, "drive_diagnostics": DRIVE_DIAGNOSTICS}
    if preset == "full" and custom is None:
        fields = select_maximum(full_profile(), vehicle_context)[0]
    elif preset == "custom":
        if not isinstance(custom, dict) or not custom:
            raise TeslaError("INVALID_ARGUMENT", "Custom profile requires fields")
        fields = deepcopy(custom)
    elif preset in presets and custom is None:
        fields = {k: {"interval_seconds": i, "resend_interval_seconds": r, **({"minimum_delta": d} if d is not None else {})}
                  for k, (i, r, d) in presets[preset].items()}
    else:
        raise TeslaError("INVALID_ARGUMENT", "Choose a profile or explicit custom fields")
    for name, value in fields.items():
        field = FIELD_MAP.get(name)
        if not field or not selectable(field) or not isinstance(value, dict):
            raise TeslaError("UNSUPPORTED_FIELD", "Field is not documented for ordinary telemetry use")
        if set(value)-{"interval_seconds", "resend_interval_seconds", "minimum_delta", "include_fields"}:
            raise TeslaError("INVALID_ARGUMENT", "Unsupported field configuration")
        interval = value.get("interval_seconds")
        if type(interval) is not int or not 1 <= interval <= 86400:
            raise TeslaError("INVALID_ARGUMENT", "Invalid telemetry interval")
        resend = value.get("resend_interval_seconds")
        if "resend_interval_seconds" in value and (type(resend) is not int or not interval <= resend <= 86400):
            raise TeslaError("INVALID_ARGUMENT", "Resend interval must be at least the publication interval")
        if "minimum_delta" in value:
            if (type(value["minimum_delta"]) not in (int, float) or not math.isfinite(value["minimum_delta"]) or not 0 <= value["minimum_delta"] <= 1000000
                    or (field["documented_type"].lower() not in ("real", "integer") and name != "Location")):
                raise TeslaError("INVALID_ARGUMENT", "Delta is supported only for numeric fields or Location metres")
        if name == "SelfDrivingMilesSinceReset" and value.get("minimum_delta", 0) < 1:
            raise TeslaError("INVALID_ARGUMENT", "SelfDrivingMilesSinceReset requires an explicit minimum_delta of at least 1 mile")
        included = value.get("include_fields", [])
        if (not isinstance(included, list) or len(included) > len(FIELD_MAP)
                or any(not isinstance(f, str) or f == name or f not in FIELD_MAP
                       or not selectable(FIELD_MAP[f]) for f in included)
                or len(set(included)) != len(included)):
            raise TeslaError("INVALID_ARGUMENT", "Included fields must be unique documented fields other than the parent")
        paired = {"MilesSinceReset", "SelfDrivingMilesSinceReset"}
        if (name in paired and set(included)-paired) or (name not in paired and set(included) & paired):
            raise TeslaError("INVALID_ARGUMENT", "Driving counters may only include each other")
    return fields


def estimate(fields, active_hours_per_day=8):
    if type(active_hours_per_day) not in (int, float) or not math.isfinite(active_hours_per_day) or not 0 < active_hours_per_day <= 24:
        raise TeslaError("INVALID_ARGUMENT", "Active hours must be above zero and at most 24")
    seconds = active_hours_per_day*3600
    signals = 30*sum((1+len(v.get("include_fields", [])))*(1+math.ceil(seconds/v["interval_seconds"])+(math.ceil(seconds/v["resend_interval_seconds"]) if "resend_interval_seconds" in v else 0)) for v in fields.values())
    return {"planned_signals_30_days": signals, "estimated_gross_usd": round(signals/150000, 4),
            "active_hours_per_day": active_hours_per_day, "billing_cap": False,
            "assumptions": "30 sessions; includes each attached signal per parent emission, without cross-parent deduplication; excludes retries, extra events, REST, hosting, taxes and account discount"}


def build(service, ref, preset, custom, scopes, active_hours_per_day, customer_alerts=None):
    vehicle_context = context(service.store, ref)
    fields = profile_fields(preset, custom, vehicle_context=vehicle_context)
    for name in effective_fields(fields):
        blockers = [r for r in qualification(FIELD_MAP[name], vehicle_context)['blockers']
                    if r in ('different_model', 'model_unknown', 'field_not_configurable', 'receiver_upgrade_required')]
        if blockers:
            raise TeslaError('UNSUPPORTED_FIELD', name+': '+', '.join(blockers))
    cost = estimate(fields, active_hours_per_day)
    customer_alerts = preset in ("normal", "recommended") if customer_alerts is None else customer_alerts
    if type(customer_alerts) is not bool:
        raise TeslaError("INVALID_ARGUMENT", "Invalid customer alerts option")
    vehicle = service.vehicle(ref)
    if effective_fields(fields) & LOCATION_FIELDS:
        service.location_allowed(vehicle, scopes)
    settings = service.settings
    if not settings.telemetry_host or not settings.telemetry_ca_file or not re.fullmatch(r"[a-z0-9.-]+", settings.telemetry_host):
        raise TeslaError("SETUP_REQUIRED", "Configure the qualified telemetry receiver and public CA first")
    ca = settings.telemetry_ca_file.read_text()
    try:
        if len(ca)>65536 or not x509.load_pem_x509_certificates(ca.encode()):
            raise ValueError()
    except ValueError:
        raise TeslaError("SETUP_REQUIRED", "Invalid public telemetry CA")
    info = service._fleet_info(vehicle, service.fleet.call("vehicle_fleet_status", vehicle=vehicle))
    firmware = version(info.get('firmware_version')) or (0, 0, 0, 0)
    client = version(info.get('fleet_telemetry_version')) or (0, 0, 0, 0)
    if not info.get("key_paired") or firmware < (2025, 2, 6) or client < (1, 1, 0):
        raise TeslaError("UNSUPPORTED_FIRMWARE", "This telemetry profile requires a paired key, firmware 2025.2.6+ and telemetry client 1.1.0+")
    # Field-specific gates remain visible; newer explicitly gated fields are
    # admitted only when their reported firmware/client satisfies that gate.
    if included_sources(fields) and (firmware < (2026, 26, 6) or client < (1, 3, 0)):
        raise TeslaError("UNSUPPORTED_FIRMWARE", "include_fields requires firmware 2026.26.6+ and telemetry client 1.3.0+")
    for field in effective_fields(fields):
        spec = FIELD_MAP[field]
        capability = qualification(spec, {**vehicle_context, **info})
        if capability['blockers']:
            raise TeslaError('UNSUPPORTED_FIELD', field+': '+', '.join(capability['blockers']))
        if field == "RouteLastUpdated":
            raise TeslaError("UNSUPPORTED_FIELD", "Tesla documents RouteLastUpdated as broken; no data is available")
        for label, actual in (("minimum_firmware_field", info.get("firmware_version")), ("minimum_client_field", info.get("fleet_telemetry_version"))):
            if meets_version(actual, spec[label]) is not True:
                raise TeslaError("UNSUPPORTED_FIRMWARE", "A selected telemetry field requires newer vehicle software")
    return {"config": {"hostname": settings.telemetry_host, "port": settings.telemetry_port, "ca": ca,
                       "fields": fields, "delivery_policy": "latest", **({"alert_types": ["customer"]} if customer_alerts else {})}}, cost
