"""Shared, explicit command requirements. Unknown is never evidence of Park."""
import json

PARK_ACTIONS = frozenset({"remote_boombox", "close_trunk", "actuate_trunk",
    "window_control", "trigger_homelink", "erase_user_data",
    "set_valet_mode", "reset_valet_pin", "schedule_software_update"})
DRIVE_GUARDED_ACTIONS = PARK_ACTIONS | {"remote_start_drive"}
CLIMATE_ACTIONS = frozenset({"remote_seat_heater_request", "set_seat_heaters",
    "remote_seat_cooler_request", "remote_auto_seat_climate_request", "remote_steering_wheel_heater_request",
    "remote_auto_steering_wheel_heat_climate_request", "remote_steering_wheel_heat_level_request"})
COMMAND_SOURCE = "https://developer.tesla.com/docs/fleet-api/endpoints/vehicle-commands"


def requirements(name):
    result = []
    if name in PARK_ACTIONS:
        result.append({"id": "explicit_park", "origin": "plugin_policy", "enforcement": "before_dispatch",
            "rest_max_age_seconds": 30, "telemetry_max_age_seconds": 15,
            "unknown_blocks": True, "conflict_blocks": True,
            "label": 'Recent, explicit Park evidence is required. Null or invalid values are insufficient.',
            "scope": "Local precaution for this operation; not a claim of a uniform Tesla API requirement."})
    if name in CLIMATE_ACTIONS:
        result.append({"id": "climate_active", "origin": "tesla_api_documentation",
            "enforcement": "provider", "automatic_climate_start": False, "source": COMMAND_SOURCE,
            "label": 'This API path requires active preconditioning or climate keeper. Climate is not started automatically.',
            "scope": "API requirement; does not describe every capability of the official Tesla app."})
    if name == "remote_start_drive":
        result.append({"id": "no_recent_driving_gear", "origin": "plugin_policy", "enforcement": "before_dispatch",
            "rest_max_age_seconds": 30, "telemetry_max_age_seconds": 15,
            "unknown_blocks": False, "conflict_blocks": True,
            "label": 'Keyless driving is blocked when sources indicate a recently selected drive gear or conflict. Missing data does not establish Park and does not alone block this authorization.',
            "scope": "Authorizes keyless driving, not vehicle movement. No automatic retry or wake."})
        result.append({"id": "keyless_driving_enabled", "origin": "tesla_api_documentation",
            "enforcement": "provider", "source": COMMAND_SOURCE,
            "label": 'Keyless driving must be enabled on the vehicle.'})
    return result


def seconds(value):
    from .state_evidence import timestamp_evidence
    # Admission must interpret the same clock formats as stored REST evidence.
    # Freshness and the policy for unavailable observations stay with the guard.
    return timestamp_evidence(value)["source_timestamp"]


def _observation(source, value, source_at, quality, now, maximum):
    at = seconds(source_at)
    age = now-at if at is not None else None
    if age is not None and -0.001 <= age < 0:
        age = 0.0
    gear = value if isinstance(value, str) and value in ("P", "D", "R", "N") else None
    valid = quality == "valid" and gear is not None
    fresh = age is not None and 0 <= age <= maximum
    # A same-time contradiction must reach the conflict guard, including when
    # another source reports P or keyless driving permits missing gear.
    observed_quality = "valid" if valid else quality if quality in ("missing", "time_conflict") else "invalid"
    return {"source": source, "value": gear, "source_timestamp": at,
        "age_seconds": age, "quality": observed_quality,
        "fresh": fresh, "usable": valid and fresh, "max_age_seconds": maximum}


def park_evidence(drive, gear, now, *, rest_source="tesla_live", stored_rest=None):
    from .state_evidence import REST_TIME_CONFLICT
    drive = drive if isinstance(drive, dict) else {}
    rest = _observation(rest_source, drive.get("shift_state"), drive.get("timestamp"),
                        "valid" if "shift_state" in drive else "missing", now, 30)
    if rest_source == REST_TIME_CONFLICT:
        rest.update(value=None, quality='time_conflict', usable=False)
    value = None
    if gear:
        try:
            decoded = json.loads(gear["value"])
            value = {"ShiftStateP": "P", "ShiftStateD": "D", "ShiftStateR": "R", "ShiftStateN": "N"}.get(decoded) if isinstance(decoded, str) else None
        except (TypeError, ValueError):
            pass
    telemetry = _observation("fleet_telemetry", value, gear["source_at"] if gear else None,
                             gear["quality"] if gear else "missing", now, 15)
    evidence = [rest, telemetry]
    if stored_rest is not None:
        stored_data = json.loads(stored_rest['data'])
        cached = _observation(stored_rest['source'], stored_data.get('shift_state'), stored_data.get('timestamp'),
                              'valid' if 'shift_state' in stored_data else 'missing', now, 30)
        if stored_rest['source'] == REST_TIME_CONFLICT:
            cached.update(value=None, quality='time_conflict', usable=False)
        # A delayed REST response cannot hide a newer negative observation or a
        # known same-time contradiction. Cached P, however, never substitutes
        # for null/missing/raw preflight evidence or grants dispatch.
        cached['admission_role'] = 'stored_negative_evidence_only'
        cached['usable'] = cached['usable'] and cached['value'] != 'P'
        evidence.append(cached)
    usable = [row for row in evidence if row["usable"]]
    positive = [row for row in usable if row["value"] == "P"]
    negative = [row for row in usable if row["value"] != "P"]
    if positive:
        oldest_positive = min(row["source_timestamp"] for row in positive)
        negative = [row for row in evidence if row["quality"] == "valid" and row["value"] != "P"
                    and row["age_seconds"] is not None and row["age_seconds"] >= 0
                    and (row["usable"] or row["source_timestamp"] >= oldest_positive)]
    # Both still-fresh contradictory observations block, including at equal
    # timestamps. Never let the first source short-circuit the other source.
    if any(row['quality'] == 'time_conflict' and row['fresh'] for row in evidence):
        state, reason = "conflicting", "PARK_EVIDENCE_CONFLICT"
    elif positive and negative:
        state, reason = "conflicting", "PARK_EVIDENCE_CONFLICT"
    elif negative:
        state, reason = "not_park", "NOT_IN_PARK"
    elif positive:
        state, reason = "verified", "PARK_VERIFIED"
    elif any(row["quality"] == "valid" and row["age_seconds"] is not None
             and row["age_seconds"] > row["max_age_seconds"] for row in evidence):
        state, reason = "stale", "PARK_EVIDENCE_STALE"
    else:
        state, reason = "unknown", "PARK_EVIDENCE_UNAVAILABLE"
    messages = {
        "verified": 'Park verified in the available observations.',
        "conflicting": 'Recent sources disagree about Park. Command not sent.',
        "not_park": 'A recent observation indicates a gear other than Park. Command not sent.',
        "stale": 'Explicit Park evidence is not recent enough. Command not sent.',
        "unknown": 'Park cannot be verified: available sources contain no explicit valid value. Command not sent.',
    }
    return {"id": "explicit_park", "status": state, "reason": reason,
            "checked_at": now, "observations": evidence, "message": messages[state],
            "automatic_retry": False,
            "next_step": 'Resolve the stated prerequisite before another explicit attempt; a fresh read with a null value does not prove Park.' if state != "verified" else None}


def drive_precondition(name, drive, gear, now, *, stored_rest=None):
    """Evaluate the operation's policy without turning missing gear into Park."""
    evidence = park_evidence(drive, gear, now, stored_rest=stored_rest)
    evidence["allows_dispatch"] = evidence["status"] == "verified"
    if name == "remote_start_drive":
        evidence["id"] = "no_recent_driving_gear"
        evidence["allows_dispatch"] = evidence["status"] not in ("not_park", "conflicting")
        evidence["park_verified"] = evidence["status"] == "verified"
        if evidence["allows_dispatch"]:
            evidence["reason"] = "NO_RECENT_DRIVING_GEAR"
            evidence["next_step"] = None
            evidence["message"] = ('No recent drive gear detected: keyless driving authorization may be sent. '
                                   + ('Park observed in the available sources.' if evidence["park_verified"] else 'Park not established.'))
    return evidence
