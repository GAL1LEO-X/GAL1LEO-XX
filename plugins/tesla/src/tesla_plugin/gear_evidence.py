"""Read-only Gear evidence; historical observations never enter the guard."""
import json

from .preconditions import park_evidence
from .provider_diagnostics import value_kind

GEARS = {"ShiftStateP": "P", "ShiftStateD": "D", "ShiftStateR": "R", "ShiftStateN": "N"}
BRANCHES = frozenset({"invalid", "stringValue", "string_value", "shiftStateValue", "shift_state_value",
                     "intValue", "int_value", "longValue", "long_value"})


def input_evidence(envelope, quality):
    """Retain branch/type, never an unknown raw value or arbitrary field name."""
    branch = next(iter(envelope)) if isinstance(envelope, dict) and len(envelope) == 1 else None
    if branch == "invalid":
        reason = "invalid_branch_received"
    elif quality == "enum_unknown":
        reason = "unrecognized_gear_value"
    elif quality == "valid":
        reason = "recognized_gear_value"
    else:
        reason = "invalid_value_envelope"
    return {"branch": branch if branch in BRANCHES else "other" if branch is not None else None,
            "value_kind": value_kind(envelope[branch]) if branch is not None else "unknown",
            "normalization_reason": reason, "sample_quality": quality,
            "raw_value_retained": False}


def view(store, ref, rest=None, *, include_history=True):
    now = store.clock()
    with store.db() as db:
        db.execute("BEGIN")
        gear = db.execute("SELECT * FROM latest WHERE vehicle=? AND field='Gear'", (ref,)).fetchone()
        trace = db.execute("SELECT * FROM snapshots WHERE vehicle=? AND section='gear_ingestion'", (ref,)).fetchone()
        # A contradictory sample at the same source time is not a last valid
        # observation, even if the individual historical row says 'valid'.
        previous = db.execute("SELECT s.* FROM samples s WHERE s.vehicle=? AND s.field='Gear' "
            "AND s.quality='valid' AND s.source_at<=? AND s.value IN (?,?,?,?) "
            "AND NOT EXISTS (SELECT 1 FROM samples c WHERE c.vehicle=s.vehicle AND c.field=s.field "
            "AND c.source_at=s.source_at AND (c.quality!='valid' OR NOT telemetry_value_equal(s.field,c.value,s.value))) "
            "ORDER BY s.source_at DESC,s.id DESC LIMIT 1", (ref, now, *(json.dumps(k) for k in GEARS))).fetchone() if include_history else None
        if rest is None:
            rest = db.execute("SELECT * FROM snapshots WHERE vehicle=? AND section='drive_state'", (ref,)).fetchone()
    decision = park_evidence(json.loads(rest["data"]) if rest else {}, gear, now,
                             rest_source=rest["source"] if rest else "tesla_live")

    def sample(row):
        if not row:
            return None
        value = json.loads(row["value"])
        return {"value": GEARS.get(value) if row["quality"] == "valid" and isinstance(value, str) else None,
                "quality": row["quality"], "source": "fleet_telemetry",
                "source_timestamp": row["source_at"], "received_at": row["received"],
                "age_seconds": now-row["source_at"], "time_basis": row["time_basis"]}

    current = sample(gear)
    if current and trace and trace["source_at"] == gear["source_at"] and trace["received"] == gear["received"]:
        current["input_evidence"] = json.loads(trace["data"])
    return {"status": decision["status"], "reason": decision["reason"], "checked_at": now,
            "observations": decision["observations"], "current_telemetry": current,
            "last_valid_observation": sample(previous), "historical_observation_used_for_admission": False,
            "history_access": "allowed" if include_history else "scope_required",
            "scope": "Local evidence for explicit Park; command requirements remain operation-specific.",
            "limitations": ['The last valid value is historical: it does not replace a later invalid sample.',
                            'The normalization reason describes the received record, not the cause on the vehicle.']}
