"""Bounded provider metadata; raw bodies, request values and free text stay private."""
import json
import secrets
import sqlite3


class ProviderObject(dict):
    """Response payload with out-of-band transport evidence, never a JSON key."""
    def __init__(self, value, diagnostic):
        super().__init__(value)
        self.diagnostic = diagnostic


def value_kind(value):
    if value is None:
        return "null"
    return {dict: "object", list: "array", str: "string", bool: "boolean", int: "number", float: "number"}.get(type(value), "unknown")


def new_diagnostic(operation, now):
    return {"request_id": "req_"+secrets.token_hex(16), "operation": operation,
            "started_at": now, "origin": "provider", "automatic_retry": False}


def media_type(value):
    value = value.split(";", 1)[0].lower().strip()
    return value if value in ("application/json", "text/html", "text/plain", "application/pdf") else "other"


def rejection_reason(value):
    """Recognize known reasons; never echo an untrusted provider sentence.

    Unknown reasons remain explicitly unclassified, linked to a request ID.
    This is intentionally not a generic regex redactor for arbitrary secrets.
    """
    if not isinstance(value, str) or not value.strip():
        return {"reason_code": "PROVIDER_REASON_MISSING", "reason": 'The provider did not supply a usable reason.'}
    # vehicle-command/pkg/vehicle/infotainment.go wraps plain text in this
    # exact prefix. Strip it once; classify only a complete known reason.
    # Never match substrings or expose arbitrary suffixes/credential values.
    normalized = value.strip().lower() if len(value) <= 4096 else ""
    prefix = "car could not execute command: "
    wrapped = normalized.startswith(prefix)
    if wrapped:
        normalized = normalized[len(prefix):].strip()
    normalized = normalized.replace("_", " ")
    known = {
        "not in park": ("NOT_IN_PARK", 'The vehicle reports that it is not in Park.'),
        "vehicle not in park": ("NOT_IN_PARK", 'The vehicle reports that it is not in Park.'),
        "car not in park": ("NOT_IN_PARK", 'The vehicle reports that it is not in Park.'),
        "is climate on is false": ("CLIMATE_NOT_ACTIVE", 'The vehicle reports that climate is inactive.'),
        "is climate on=false": ("CLIMATE_NOT_ACTIVE", 'The vehicle reports that climate is inactive.'),
        "climate is off": ("CLIMATE_NOT_ACTIVE", 'The vehicle reports that climate is inactive.'),
        "climate not active": ("CLIMATE_NOT_ACTIVE", 'The vehicle reports that climate is inactive.'),
        # Tesla's public FAQ names this prerequisite separately from HVAC state:
        # https://developer.tesla.com/docs/fleet-api/support/faq
        "cabin comfort remote settings not enabled": (
            "CABIN_COMFORT_REMOTE_SETTINGS_DISABLED",
            'The vehicle reports that remote comfort commands are unavailable in the current condition. Tesla requires active preconditioning or climate keeper for this reason.'),
        "vehicle unavailable": ("VEHICLE_UNAVAILABLE", 'The vehicle is unavailable for this command.'),
        "vehicle is offline": ("VEHICLE_UNAVAILABLE", 'The vehicle is unavailable for this command.'),
        "could not wake buses": ("VEHICLE_UNAVAILABLE", 'The provider reports that vehicle systems are not ready.'),
        "not supported": ("COMMAND_NOT_SUPPORTED", 'The command is not supported in the current condition.'),
        "unsupported": ("COMMAND_NOT_SUPPORTED", 'The command is not supported in the current condition.'),
        "invalid value": ("PROVIDER_VALUE_REJECTED", 'The provider rejected the requested value.'),
        "unspecified error": ("VEHICLE_REASON_UNSPECIFIED", 'The vehicle rejected the command without a specific reason.'),
    }
    if normalized in known:
        code, message = known[normalized]
        return {"reason_code": code, "reason": message, "provider_reason_present": True,
                **({"reason_format": "sdk_nominal_error"} if wrapped else {})}
    return {"reason_code": "PROVIDER_REASON_UNCLASSIFIED", "provider_reason_present": True,
            "reason_withheld": True, "reason": 'The provider supplied an unclassified reason; raw text is withheld.'}


def http_rejection_reason(body):
    """Classify the first usable HTTP-error reason without retaining its text.

    Preserve precedence of response.reason and error over the flat message
    used by charging history. An unknown primary reason remains withheld;
    a familiar secondary message must not replace it. Empty/non-string
    candidates are unusable, and arbitrary nested objects are never searched.
    """
    if isinstance(body, dict):
        response = body.get("response")
        candidates = (
            ("response.reason", response.get("reason") if isinstance(response, dict) else None),
            ("error", body.get("error")),
            ("message", body.get("message")),
        )
        for source, value in candidates:
            if isinstance(value, str) and value.strip():
                return {**rejection_reason(value), "reason_source": source}
    return rejection_reason(None)


def response_shape(value):
    """Bounded diagnostic shape of public contract keys, with no leaf values.

    Unknown key names can themselves be secrets; count them, never log them.
    Inspect one level of response/error/data to distinguish an API error,
    an unexpected envelope and missing sessions without retaining the body.
    """
    allowed = frozenset({"response", "data", "error", "errors", "error_description", "message", "code",
        "error_code", "result", "reason", "sessionId", "total", "totalCount", "totalRecords", "totalResults", "pageNo", "pageSize",
        "superchargers", "destination_charging", "timestamp", "congestion_sync_time_utc_secs"})

    def shape(item, depth):
        result = {"kind": value_kind(item)}
        if isinstance(item, dict):
            result["fields"] = {key: shape(item[key], depth-1) if depth else {"kind": value_kind(item[key])}
                                for key in sorted(allowed & item.keys())}
            result["other_field_count"] = len(item.keys()-allowed)
        elif isinstance(item, list):
            result["count"] = len(item)
            result["item_kinds"] = sorted({value_kind(element) for element in item[:5]})
            result["sampled_items"] = min(len(item), 5)
        return result
    return shape(value, 1)


def record(store, diagnostic):
    """Keep a bounded local trail using the existing metadata table (no migration)."""
    diagnostic["persisted"] = True
    try:
        with store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if "authorization_generation" in diagnostic:
                active = db.execute("SELECT generation FROM connection WHERE id=1").fetchone()
                if not active or active[0] != diagnostic["authorization_generation"]:
                    diagnostic.update(persisted=False, persistence_reason="authorization_changed")
                    return
            db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)",
                       ("request_diagnostic:"+diagnostic["request_id"], json.dumps(diagnostic, sort_keys=True)))
            prune(db, store.clock())
    except (sqlite3.Error, OSError):
        # Losing this optional trail must not erase a provider acknowledgement
        # or rejection. The result still carries the bounded diagnostic.
        diagnostic.update(persisted=False, persistence_reason="storage_unavailable")


def prune(db, now):
    rows = db.execute("SELECT key,value FROM meta WHERE key GLOB 'request_diagnostic:*'").fetchall()
    entries = []
    for key, value in rows:
        try:
            at = json.loads(value).get("started_at", 0)
            if type(at) not in (int, float) or not 0 < at <= now:
                at = 0
        except (ValueError, AttributeError):
            at = 0
        entries.append((key, at))
    ordered = sorted(entries, key=lambda row: row[1], reverse=True)
    db.executemany("DELETE FROM meta WHERE key=?", [(key,) for i, (key, at) in enumerate(ordered)
                   if i >= 100 or at < now-7*86400])
