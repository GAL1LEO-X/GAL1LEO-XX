"""Read-specific validation and completeness. Missing never becomes zero."""
import json

from .errors import TeslaError
from .preconditions import seconds
from .provider_diagnostics import value_kind
from .state_evidence import REST_STATE_SECTIONS, block_view, snapshot_row


def validate_response(name, data):
    if name == "charging_history":
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            raise TeslaError("PROVIDER_RESPONSE_INVALID", 'Charging history does not contain a valid session list.',
                             details={"response_issue": "charging_history_sessions_missing", "response_kind": value_kind(data)})
        if any(not isinstance(row, dict) or not row or not
               (type(row.get("sessionId")) is int and row["sessionId"] >= 0 or
                isinstance(row.get("sessionId"), str) and 0 < len(row["sessionId"].strip()) <= 256)
               for row in data["data"]):
            raise TeslaError("PROVIDER_RESPONSE_INVALID", 'Charging history contains incomplete or invalid sessions.',
                             details={"response_issue": "charging_history_session_invalid"})
        if "totalResults" in data and (type(data["totalResults"]) is not int or data["totalResults"] < len(data["data"])):
            raise TeslaError("PROVIDER_RESPONSE_INVALID", 'Charging history contains an invalid total count.',
                             details={"response_issue": "charging_history_total_invalid"})
    if name == "vehicle_nearby_charging_sites":
        if not isinstance(data, dict) or any(key in data and
                (not isinstance(data[key], list) or any(not isinstance(row, dict) for row in data[key]))
                for key in ("superchargers", "destination_charging")):
            raise TeslaError("PROVIDER_RESPONSE_INVALID", 'The charging-station response has an unexpected format.',
                             details={"response_issue": "nearby_sites_invalid", "response_kind": value_kind(data)})


def read_evidence(name, data, arguments, now):
    validate_response(name, data)
    if name == "vehicle_vehicle_data_cached" and isinstance(data, dict):
        sections = {}
        for section, value in data.items():
            if section not in REST_STATE_SECTIONS or not isinstance(value, dict):
                continue
            row = snapshot_row({"data": json.dumps(value), "source": "tesla_cached",
                                "source_at": None, "received": now})
            sections[section] = {key: item for key, item in block_view(row, section, now).items() if key != "data"}
        return {"data_semantics": "raw_provider_cached_response", "timestamp_scope": "per_block_not_response_receipt",
                "max_age_seconds": 120, "response_sections": sections,
                "limitations": ['Receiving a response does not update section or individual sensor timestamps.']}
    if name == "charging_history":
        return {"sessions_returned": len(data["data"]), "empty": not data["data"],
                "ordering": {"requested_field": arguments.get("sortBy"), "requested_direction": arguments.get("sortOrder"),
                             "default_documented": False, "latest_sessions_verified": False},
                "complete_history": False,
                "limitations": ['One page does not establish complete or most-recent session coverage.',
                                'Tesla history does not guarantee coverage of home charging or other networks.']}
    if name != "vehicle_nearby_charging_sites":
        return None
    def count_valid(rows, key):
        return sum(type(row.get(key)) is int and row[key] >= 0 for row in rows)
    sites = data.get("superchargers", [])
    at = seconds(data.get("timestamp"))
    sync = seconds(data.get("congestion_sync_time_utc_secs"))
    return {"radius_unit": "mile", "detail_requested": arguments.get("detail"),
            "superchargers_returned": len(sites) if "superchargers" in data else None,
            "destination_charging_returned": len(data["destination_charging"]) if "destination_charging" in data else None,
            "superchargers_with_available_stalls": count_valid(sites, "available_stalls"),
            "superchargers_with_total_stalls": count_valid(sites, "total_stalls"),
            "superchargers_with_billing_text": sum(isinstance(row.get("billing_info"), str) and bool(row["billing_info"].strip()) for row in sites),
            "source_timestamp": at, "congestion_sync_timestamp": sync,
            "congestion_timestamp_gap_seconds": at-sync if at is not None and sync is not None else None,
            "availability_freshness_verified": False,
            "limitations": ['Missing details do not mean zero stalls or free charging.',
                            'site_closed=false does not prove free stalls.',
                            'The congestion timestamp does not establish freshness for every station.',
                            'Numeric power and pricing values are not guaranteed by the documented contract.']}
