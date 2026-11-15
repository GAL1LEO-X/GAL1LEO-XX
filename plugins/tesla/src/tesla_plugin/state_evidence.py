"""Local state normalization and provenance. No requests or admission decisions."""
import json
import math
import re

from .value_semantics import equal

MAX_SECONDS = 253402300799  # End of year 9999, the protobuf Timestamp range.
REST_STATE_SECTIONS = frozenset({'charge_state', 'climate_state', 'vehicle_state', 'vehicle_config',
    'gui_settings', 'drive_state', 'location_data', 'navigation_data', 'media_state',
    'charge_schedule_data', 'preconditioning_schedule_data'})
REST_TIME_CONFLICT = 'rest_time_conflict'
PARENTS = {"navigation_data": "drive_state", "media_state": "vehicle_state",
           "location_data": "drive_state"}
ROUTE_FIELDS = frozenset({"active_route_destination", "active_route_energy_at_arrival",
    "active_route_latitude", "active_route_longitude", "active_route_miles_to_arrival",
    "active_route_minutes_to_arrival", "active_route_traffic_minutes_delay"})


def timestamp_evidence(value):
    """Accept finite epoch seconds/ms or a typed seconds/nanos object.

    Keep exact protobuf components: the normalized float is not nanosecond
    precision. Missing/invalid times never fall back to the receipt time.
    """
    result = {"status": "missing" if value is None else "invalid", "encoding": None,
              "source_timestamp": None}
    if type(value) in (int, float):
        # Bound integers before float conversion (including hostile huge ints).
        if not 0 < value < (MAX_SECONDS+1)*1000 or not math.isfinite(value):
            return result
        milliseconds = value > 100_000_000_000
        seconds = value / 1000 if milliseconds else value
        result["encoding"] = "unix_milliseconds" if milliseconds else "unix_seconds"
        if seconds >= MAX_SECONDS+1:
            return result
    elif isinstance(value, dict):
        result["encoding"] = "protobuf_seconds_nanos"
        if not value or set(value)-{"seconds", "nanos"}:
            return result
        whole, nanos = value.get("seconds"), value.get("nanos", 0)
        if isinstance(whole, str) and re.fullmatch(r"-?(?:0|[1-9][0-9]{0,11})", whole):
            whole = int(whole)
        if type(whole) is not int or not 0 <= whole <= MAX_SECONDS or type(nanos) is not int or not 0 <= nanos < 1_000_000_000:
            return result
        seconds = whole + nanos/1_000_000_000
        if not 0 < seconds < MAX_SECONDS+1:
            return result
        result["components"] = {"seconds": whole, "nanos": nanos}
    else:
        return result
    return result | {"status": "parsed", "source_timestamp": seconds}


def snapshot_row(row):
    """Also interpret old cached protobuf times, without rewriting the cache."""
    row = dict(row)
    data = json.loads(row["data"])
    evidence = timestamp_evidence(data.get("timestamp") if "timestamp" in data else row["source_at"])
    conflict = row['source'] == REST_TIME_CONFLICT
    if conflict:
        evidence = evidence | {'status': 'same_source_time_conflict',
                               'proves_current_state': False}
    return row | {"source_at": evidence["source_timestamp"], "timestamp_evidence": evidence,
                  **({'snapshot_quality': 'time_conflict'} if conflict else {})}


def snapshot_transition(previous, data, source_at, *, now):
    """Order REST blocks by source time, never by a later cache receipt.

    Equal-time contradictions remain conflicted until a strictly newer timed
    observation arrives. Untimed blocks may replace other untimed blocks, but
    never a timed observation and never gain freshness from their receipt.
    """
    incoming = timestamp_evidence(data.get('timestamp') if 'timestamp' in data else source_at)['source_timestamp']
    if previous is None:
        return 'replace', incoming
    previous = snapshot_row(previous)
    old_time = previous['source_at']
    # A bad future vehicle clock is not a watermark for years of later valid
    # observations. Keep it labelled future until a plausible timed block arrives.
    if old_time is not None and old_time > now+30 and incoming is not None and incoming <= now+30:
        return 'replace', incoming
    if old_time is not None and (incoming is None or incoming < old_time):
        return 'keep', incoming
    if old_time == incoming:
        if previous['source'] == REST_TIME_CONFLICT:
            return 'keep', incoming
        old_data = json.loads(previous['data'])
        old_value = {key: value for key, value in old_data.items() if key != 'timestamp'}
        new_value = {key: value for key, value in data.items() if key != 'timestamp'}
        if equal(None, old_value, new_value):
            return 'keep', incoming
        if incoming is not None:
            return 'conflict', incoming
    return 'replace', incoming


def request_sections(sections):
    """Request parent blocks in the same authorized read, never another call."""
    return list(dict.fromkeys([*sections, *(PARENTS[s] for s in sections if s in PARENTS)]))


def row_quality(row, now, max_age=120):
    if row is None:
        return "missing"
    age = now-row["source_at"] if row["source_at"] is not None else None
    return row.get("snapshot_quality") or ("unknown_time" if age is None else "future" if age < -30
                                           else "fresh_observed" if age <= max_age else "stale")


def block_view(row, section, now, max_age=120):
    """One REST presentation contract for state reads and cached API evidence."""
    quality = row_quality(row, now, max_age)
    if row is None:
        return {"quality": quality, "data": None}
    return {"data": None if quality == "time_conflict" else json.loads(row["data"]),
            "source": row["source"], "source_timestamp": row["source_at"], "received_at": row["received"],
            "time_basis": row.get("time_basis", "rest_block_timestamp"), "quality": quality,
            "age_seconds": now-row["source_at"] if row["source_at"] is not None else None,
            "timestamp_evidence": row["timestamp_evidence"], **field_notes(section),
            **({"derived_from": row["derived_from"], "coverage": "partial"} if "derived_from" in row else {}),
            **({"selection_evidence": row["selection_evidence"]} if "selection_evidence" in row else {})}


def projected_row(rows, section, *, now, max_age=120):
    """Select whole observations without borrowing their clocks or hiding conflicts.

    A conflicted dedicated block is evidence even if its retained payload is
    empty. A plausible parent must be strictly newer to supersede it, except
    when the dedicated clock is itself future. Future clocks cannot outrank
    plausible observations; their rejection stays visible.
    """
    direct, parent = rows.get(section), rows.get(PARENTS.get(section))
    if not parent:
        return direct
    data = json.loads(parent["data"])
    if section == "navigation_data":
        selected = {key: value for key, value in data.items() if key in ROUTE_FIELDS}
        path = "drive_state.active_route_*"
    elif section == "media_state":
        selected = data.get("media_info")
        path = "vehicle_state.media_info"
    else:
        selected = {key: data[key] for key in ("latitude", "longitude") if key in data}
        path = "drive_state.latitude/longitude"
        if not coordinates_valid(selected) and parent.get("snapshot_quality") != "time_conflict":
            return direct
    if parent.get("snapshot_quality") == "time_conflict":
        selected = {}  # Retained values depend on arrival order and are unusable.
    elif not isinstance(selected, dict) or not selected:
        return direct
    parent = parent | {"data": json.dumps(selected), "derived_from": path, "coverage": "partial",
                       "time_basis": "parent_rest_block_timestamp"}
    if not direct:
        return parent
    direct_time, parent_time = direct["source_at"], parent["source_at"]
    direct_future = direct_time is not None and direct_time > now+30
    parent_future = parent_time is not None and parent_time > now+30
    if direct.get("snapshot_quality") == "time_conflict" and (parent_future or parent_time is None):
        chosen, discarded, reason = direct, parent, "dedicated_conflict_not_resolved"
    elif direct_future and parent_time is not None and not parent_future:
        chosen, discarded, reason = parent, direct, "plausible_parent_over_future_dedicated"
    elif parent_future and direct_time is not None and not direct_future:
        chosen, discarded, reason = direct, parent, "plausible_dedicated_over_future_parent"
    elif (direct.get("snapshot_quality") != "time_conflict"
          and not any(key != "timestamp" for key in json.loads(direct["data"]))):
        chosen, discarded, reason = parent, direct, "parent_fields_available"
    elif parent_time is not None and (direct_time is None or parent_time > direct_time):
        chosen, discarded, reason = parent, direct, "newer_parent_source_time"
    else:
        chosen, discarded, reason = direct, parent, "dedicated_source_time_not_older"
    return chosen | {"selection_evidence": {
        "reason": reason, "selected_section": PARENTS[section] if chosen is parent else section,
        "alternative": {"section": section if discarded is direct else PARENTS[section],
                        "source": discarded["source"], "source_timestamp": discarded["source_at"],
                        "quality": row_quality(discarded, now, max_age),
                        "future_clock": discarded["source_at"] is not None and discarded["source_at"] > now+30,
                        "timestamp_evidence": discarded["timestamp_evidence"]}}}


def coordinates_valid(data):
    return all(type(data.get(key)) in (int, float) and -bound <= data[key] <= bound
               for key, bound in (("latitude", 90), ("longitude", 180)))


def field_notes(section):
    """Document the scope of a block clock and known units, not field freshness."""
    notes = {"timestamp_scope": "block_not_individual_fields"}
    if section == "drive_state":
        notes["units"] = {"speed": "mph", "power": "kW", "active_route_miles_to_arrival": "mile"}
    elif section == "navigation_data":
        notes["units"] = {"active_route_miles_to_arrival": "mile", "active_route_minutes_to_arrival": "minute",
                          "active_route_traffic_minutes_delay": "minute"}
        notes["complete_itinerary"] = False
    if section in ('drive_state', 'navigation_data'):
        notes['complete_itinerary'] = False
        notes['route_target_semantics'] = 'Reported active target may be the next stop, not the final destination. No complete itinerary guarantee.'
        notes['route_residuals'] = 'A block timestamp does not establish independent freshness of residual destination coordinates or arrival estimates.'
    elif section == "vehicle_state":
        notes["units"] = {"tpms_pressure_"+corner: "bar" for corner in ("fl", "fr", "rl", "rr")}
        notes["limitations"] = ['The section timestamp does not establish TPMS pressure freshness; inspect individual sensor timestamps.']
    elif section == "charge_state":
        notes["limitations"] = ['Requested currents and AC fields do not measure DC current during fast charging.']
    return notes
