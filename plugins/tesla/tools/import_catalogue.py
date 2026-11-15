"""Import the reviewed, public 2026-10-25 handoff; never read account configuration.

Usage: python tools/import_catalogue.py /path/to/tesla-design-report
The emitted catalogue is reviewed source, not a runtime schema download.
"""
import csv
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def closed(raw):
    out = {k: v for k, v in raw.items() if k in ("type", "properties", "items", "enum", "minimum", "maximum", "pattern")}
    if out.get("type") == "json":
        # Source shorthand on the excluded Energy tariff endpoint is not JSON
        # Schema. Keep it closed and unqualified rather than accepting raw JSON.
        out["type"] = "object"
    if out.get("type") == "object":
        props = raw.get("properties", {})
        out.update(properties={k: closed(v) for k, v in props.items()}, additionalProperties=False,
                   required=[k for k, v in props.items() if v.get("required") is True])
        if isinstance(raw.get("required"), list):
            out["required"] = raw["required"]
    if out.get("type") == "array":
        out["items"] = closed(raw.get("items", {"type": "string"}))
        out["maxItems"] = 100
    if out.get("type") == "string":
        out.update(minLength=1, maxLength=512)
    if out.get("type") == "integer":
        out.setdefault("minimum", 0)
        out.setdefault("maximum", 2147483647)
    return out


def main(folder):
    folder = Path(folder)
    registry = json.loads((folder / "endpoint-registry.json").read_text())
    commands = {r["endpoint"]: r for r in csv.DictReader((folder / "commands.csv").open(encoding="utf-8-sig"))}
    params = list(csv.DictReader((folder / "request-parameters.csv").open()))
    fields = list(csv.DictReader((folder / "telemetry-fields.csv").open()))
    rows = []
    prefixes = {"vehicle-endpoints": "vehicle", "partner-endpoints": "partner", "user-endpoints": "account",
                "vehicle-management": "product", "energy": "energy"}
    gaps = {"navigation_gps_request", "navigation_sc_request", "navigation_waypoints_request",
            "remote_auto_steering_wheel_heat_climate_request", "remote_steering_wheel_heat_level_request",
            "upcoming_calendar_entries", "remote_boombox"}
    for r in registry:
        command = r["category"] == "vehicle-commands"
        name = r["path"].rsplit("/", 1)[-1] if command else re.sub(r"[^a-z0-9]+", "_", r["name"].lower()).strip("_")
        if not command and r["category"] in prefixes:
            name = prefixes[r["category"]] + "_" + name
        body = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
        locations = {}
        for p in params:
            if (p["method"], p["path"]) != (r["method"], r["path"]):
                continue
            v = json.loads(p["technical_schema"])
            if p["name"] in ("vin", "vins", "vehicle_id", "energy_site_id"):
                continue
            if p["in"] == "body":
                b = closed(v.get("schema", {}))
                body["properties"].update(b.get("properties", {}))
                body["required"].extend(b.get("required", []))
                locations.update({k: "body" for k in b.get("properties", {})})
            else:
                body["properties"][p["name"]] = closed(v.get("schema", v))
                locations[p["name"]] = p["in"]
                if v.get("required"):
                    body["required"].append(p["name"])
        for key in ("vin", "vins", "vehicle_id"):
            body["properties"].pop(key, None)
            body["required"] = [k for k in body["required"] if k != key]
            locations.pop(key, None)
        props = body["properties"]
        for k, limits in {"lat": (-90, 90), "lon": (-180, 180), "latitude": (-90, 90), "longitude": (-180, 180)}.items():
            if k in props:
                props[k].update(minimum=limits[0], maximum=limits[1])
        for k in ("pageSize", "per_page", "limit"):
            if k in props:
                props[k].update(minimum=1, maximum=100)
        for k in ("page", "pageNo"):
            if k in props:
                props[k].update(minimum=1, maximum=1000)
        for k in ("start_time", "end_time", "precondition_time", "departure_time", "end_off_peak_time", "time"):
            if k in props:
                props[k].update(minimum=0, maximum=1439)
        if "days_of_week" in props:
            props["days_of_week"]["pattern"] = r"^(All|Weekdays|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)(,(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday))*$"
        overrides = {
            "actuate_trunk": {"which_trunk": {"enum": ["front", "rear"]}},
            "set_temps": {k: {"type": "number", "minimum": 15, "maximum": 28} for k in ("driver_temp", "passenger_temp")},
            "set_charge_limit": {"percent": {"minimum": 50, "maximum": 100}},
            "set_charging_amps": {"charging_amps": {"minimum": 1, "maximum": 48}},
            "adjust_volume": {"volume": {"minimum": 0, "maximum": 10}},
            "remote_seat_heater_request": {"seat_position": {"enum": [0, 1, 2, 4, 5]}, "level": {"minimum": 0, "maximum": 3}},
            "remote_auto_seat_climate_request": {"auto_seat_position": {"enum": [1, 2]}},
            "remote_seat_cooler_request": {"seat_position": {"enum": [1, 2]}, "seat_cooler_level": {"minimum": 0, "maximum": 3}},
            "set_climate_keeper_mode": {"climate_keeper_mode": {"enum": [0, 1, 2, 3]}},
            "set_cop_temp": {"cop_temp": {"enum": [0, 1, 2]}},
            "remote_steering_wheel_heat_level_request": {"level": {"enum": [0, 1, 3]}},
            "speed_limit_set_limit": {"limit_mph": {"minimum": 50, "maximum": 120}},
            "parental_controls_set_speed_limit": {"limit_mph": {"minimum": 50, "maximum": 120}},
            "parental_controls_enable_setting": {"setting": {"enum": ["SpeedLimit", "Acceleration", "SafetyFeatures", "Curfew", "BrowserBlocked", "TheaterBlocked", "ArcadeBlocked"]}},
            "window_control": {"command": {"enum": ["vent", "close"]}},
            "sun_roof_control": {"state": {"enum": ["vent", "close", "stop"]}},
            "remote_boombox": {"sound": {"enum": [0, 2000]}},
            "schedule_software_update": {"offset_sec": {"minimum": 0, "maximum": 604800}},
            "navigation_request": {
                "type": {"const": "share_ext_content_raw"},
                "value": {"type": "object", "properties": {"android.intent.extra.TEXT": {"type": "string", "minLength": 1, "maxLength": 2048}},
                          "required": ["android.intent.extra.TEXT"], "additionalProperties": False},
                "locale": {"pattern": "^[a-z]{2}[-_][A-Z]{2}$"}, "timestamp_ms": {"pattern": "^[0-9]{13}$"}},
        }
        for k, value in overrides.get(name, {}).items():
            props.setdefault(k, {}).update(value)
        if name == "trigger_homelink":
            # The pinned official signed proxy consumes only latitude/longitude.
            # Do not ask the user for the REST-only token ignored by that transport.
            props.pop("token", None)
            body["required"] = [k for k in body["required"] if k != "token"]
            locations.pop("token", None)
        if name == "vehicle_fleet_telemetry_config_create":
            field_schema = {"type": "object", "properties": {
                "interval_seconds": {"type": "integer", "minimum": 1, "maximum": 86400},
                "minimum_delta": {"type": "integer", "minimum": 0, "maximum": 1000000},
                "resend_interval_seconds": {"type": "integer", "minimum": 1, "maximum": 86400}},
                "required": ["interval_seconds"], "additionalProperties": False}
            config = props["config"]
            config["properties"]["ca"]["maxLength"] = 65536
            config["properties"]["fields"] = {"type": "object", "minProperties": 1,
                "properties": {f["field"]: deepcopy(field_schema) for f in fields if f["catalog_status"] == "DOCUMENTED"}, "additionalProperties": False}
            driving = config["properties"]["fields"]["properties"]["SelfDrivingMilesSinceReset"]
            driving["required"].append("minimum_delta")
            driving["properties"]["minimum_delta"]["minimum"] = 1
            config["properties"]["alert_types"] = {"type": "array", "items": {"enum": ["customer"]}, "maxItems": 1}
            config["required"].append("fields")
        sensitive = [k for k in props if k in ("pin", "password", "token")]
        if name == "vehicle_share_invites_redeem":
            sensitive.append("code")
        if name == "vehicle_drivers_remove":
            body["required"] = ["share_user_id"]
        for k in sensitive:
            if k in ("pin", "password"):
                props[k] = {"type": "string", "pattern": "^[0-9]{4}$"}
        availability, reason = "supported_transport", "Vehicle qualification pending"
        if name in gaps:
            availability, reason = "sdk_gap", "Public signed transport or payload contract is incomplete"
        if name in ("sun_roof_control", "remote_seat_cooler_request"):
            availability, reason = "not_applicable", "Hardware not present on the target Model Y Legacy"
        if r["category"] == "energy" or "enterprise" in name or "only_for_business" in name:
            availability, reason = "not_applicable", "Outside the personal vehicle scope"
        if r["category"] == "partner-endpoints" or name in ("vehicle_signed_command", "vehicle_fleet_telemetry_config_jws", "product_pricing", "product_specs"):
            availability, reason = "operator_only", "Technical API; not exposed as an arbitrary MCP operation"
        if name == "vehicle_fleet_telemetry_config_create":
            availability, reason = "profile_only", "Use a validated telemetry profile"
        readonly = r["method"] == "GET" or name in ("vehicle_fleet_status", "product_pricing")
        security = json.loads(r["security_raw"])
        scopes = sorted({s for item in security for s in item.get("scopes", [])})
        if name == "account_region":
            scopes = ["user_data"]
        if name == "vehicle_vehicle_data":
            scopes = ["vehicle_device_data"]  # Location is checked separately for requested sections.
        rows.append(dict(id=name, method=r["method"], path=r["path"], category=r["category"],
                         description=commands[name]["effect"] if command else r["name"], readonly=readonly,
                         vehicle_bound=name in ("vehicle_fleet_status", "vehicle_fleet_telemetry_config_create") or "{vin}" in r["path"] or any(p["path"] == r["path"] and p["name"] in ("vin", "vins") for p in params),
                         scopes=scopes, schema=body, parameter_locations=locations, sensitive_fields=sensitive,
                         pricing_category=r["pricing_category"],
                         transport="proxy" if command and name != "navigation_request" else "fleet",
                         availability=availability, reason=reason,
                         source="https://developer.tesla.com/docs/fleet-api/endpoints/"+r["category"]))
    if len(rows) != 125 or len({r["id"] for r in rows}) != 125:
        raise ValueError("Unexpected catalogue cardinality or duplicate IDs")
    out = ROOT / "src/tesla_plugin/data"
    out.mkdir(parents=True, exist_ok=True)
    provenance = {f: hashlib.sha256((folder/f).read_bytes()).hexdigest() for f in
                  ("endpoint-registry.json", "commands.csv", "request-parameters.csv", "telemetry-fields.csv")}
    (out / "operations.json").write_text(json.dumps({"snapshot": "2026-10-25", "sources_sha256": provenance,
        "vehicle_command_commit": "fc5a1910ad45c42921d541089e3e366d0b897f52", "operations": rows}, ensure_ascii=False, indent=2)+"\n")
    (out / "telemetry.json").write_text(json.dumps(fields, ensure_ascii=False, indent=2)+"\n")
    from extend_catalogue import main as extend_reviewed
    extend_reviewed()
    print(f"Imported {len(rows)} operations and {len(fields)} telemetry identifiers")


if __name__ == "__main__":
    main(sys.argv[1])
