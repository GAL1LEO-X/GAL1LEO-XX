"""Local collection evidence shared by acquisition and trigger diagnostics."""
import json
import math
from dataclasses import dataclass

from .store import canonical, digest
from .errors import TeslaError
from .diagnostics import consumer_status
from .state_sequences import advance, counter, membership_key

CREATE = "vehicle_fleet_telemetry_config_create"
DELETE = "vehicle_fleet_telemetry_config_delete"


@dataclass(frozen=True)
class ReadbackAttempt:
    vehicle_ref: str
    sequence: int
    revision: str
    membership_epoch: int


def _readback_key(ref, *, applied=False):
    return ("collection_readback_applied:" if applied else "collection_readback_sequence:") + ref


def _readback_revision(db, ref):
    """Fence dispatched changes, including uncertain writes without a target.

    Prepared and definitively rejected intents do not change provider state.
    Include the target's identity and times so returning to an older profile
    cannot make a read spanning that change eligible again.
    """
    target = db.execute("SELECT * FROM snapshots WHERE vehicle=? AND section='telemetry_target'", (ref,)).fetchone()
    intent = db.execute("SELECT id,status FROM intents WHERE vehicle=? AND operation IN (?,?) "
                        "AND status IN ('sending','unknown','acknowledged','reconciled') "
                        "ORDER BY created DESC,rowid DESC LIMIT 1", (ref, CREATE, DELETE)).fetchone()
    return digest(canonical([dict(target) if target else None, dict(intent) if intent else None]))


def begin_readback(store, ref, authorization):
    """Reserve a persistent order before the provider request, without network I/O."""
    with store.db() as db:
        db.execute('BEGIN IMMEDIATE')
        store.assert_authorization(db, authorization)
        member = db.execute('SELECT active FROM vehicles WHERE ref=?', (ref,)).fetchone()
        if not member or not member['active']:
            raise TeslaError('AUTHORIZATION_CHANGED', 'Vehicle access changed before the configuration read')
        return ReadbackAttempt(ref, advance(db, _readback_key(ref)), _readback_revision(db, ref),
                               counter(db, membership_key(ref)))


def valid_observed_options(options):
    if not isinstance(options, dict) or type(options.get('interval_seconds')) is not int or options['interval_seconds'] < 1:
        return False
    resend = options.get('resend_interval_seconds')
    if 'resend_interval_seconds' in options and (type(resend) is not int or resend < 1):
        return False
    delta = options.get('minimum_delta')
    if 'minimum_delta' in options and (type(delta) not in (int, float) or delta < 0 or (type(delta) is float and not math.isfinite(delta))):
        return False
    included = options.get('include_fields', [])
    return isinstance(included, list) and all(isinstance(name, str) and name for name in included) and len(set(included)) == len(included)


def record_readback(store, ref, data, authorization, *, attempt):
    """Observe provider state without replacing a deliberately saved profile.

    Only bootstrap a missing profile from an adopted configuration. A mismatch,
    partial or pending readback must not silently alter a later resume request.
    """
    if not isinstance(data, dict) or type(data.get('synced')) is not bool or 'config' not in data:
        raise TeslaError('PROVIDER_RESPONSE_INVALID', 'Invalid telemetry configuration status')
    config = data['config']
    if config is not None and (not isinstance(config, dict) or not isinstance(config.get('fields'), dict)
            or any(not isinstance(name, str) or not name or not valid_observed_options(opts) for name, opts in config['fields'].items())):
        raise TeslaError('PROVIDER_RESPONSE_INVALID', 'Invalid telemetry configuration fields')
    now = store.clock()
    with store.db() as db:
        db.execute('BEGIN IMMEDIATE')
        store.assert_authorization(db, authorization)
        member = db.execute('SELECT active FROM vehicles WHERE ref=?', (ref,)).fetchone()
        if (not member or not member['active']
                or counter(db, membership_key(ref)) != attempt.membership_epoch):
            raise TeslaError('AUTHORIZATION_CHANGED', 'Vehicle access changed during the configuration read; the obsolete result was not stored')
        if (attempt.vehicle_ref != ref
                or attempt.sequence <= counter(db, _readback_key(ref, applied=True))
                or attempt.sequence > counter(db, _readback_key(ref))
                or attempt.revision != _readback_revision(db, ref)):
            raise TeslaError('COLLECTION_READBACK_SUPERSEDED',
                             'The configuration read overlapped a change or a newer applied read; the obsolete result was not stored')
        db.execute('INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?)',
                   (ref, 'telemetry_remote', canonical(data), 'tesla_api', now, now))
        existing = db.execute("SELECT 1 FROM snapshots WHERE vehicle=? AND section IN ('telemetry_saved','telemetry_target')", (ref,)).fetchone()
        pending = db.execute("SELECT 1 FROM intents WHERE vehicle=? AND operation IN (?,?) AND (status IN ('sending','unknown') OR (status='prepared' AND expires>?))",
                             (ref, CREATE, DELETE, now)).fetchone()
        if not existing and not pending and data['synced'] and config and config['fields']:
            db.execute('INSERT INTO snapshots VALUES(?,?,?,?,?,?)',
                       (ref, 'telemetry_saved', canonical(config), 'tesla_api', now, now))
        db.execute('INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                   (_readback_key(ref, applied=True), str(attempt.sequence)))


def check_trigger_revision(db, ref, expected):
    if expected is None:
        return
    row = db.execute("SELECT revision FROM trigger_settings WHERE vehicle=?", (ref,)).fetchone()
    if type(expected) is not int or not row or row[0] != expected:
        raise TeslaError("REVISION_CONFLICT", 'Events or rules changed: recalculate the proposal before confirmation.')


def config_without_signing_metadata(config):
    """Project settings without the top-level claims rewritten by Tesla's proxy.

    aud/iss describe the signed envelope, not collection options. Keep the raw
    request/readback intact and retain every other key, including unknown ones.
    """
    if not isinstance(config, dict):
        return config
    return {key: value for key, value in config.items() if key not in ("aud", "iss")}


def normalized_config(config):
    """Exclude signing claims; preserve options and normalize unordered lists."""
    if not isinstance(config, dict) or not isinstance(config.get("fields"), dict):
        return None
    fields = {}
    for name, options in config["fields"].items():
        if not isinstance(name, str) or not valid_observed_options(options):
            return None
        fields[name] = {**options, "include_fields": sorted(options.get("include_fields", []))}
    alerts = config.get("alert_types", [])
    if (not isinstance(alerts, list) or any(not isinstance(a, str) for a in alerts)
            or len(set(alerts)) != len(alerts)):
        return None
    return {**config_without_signing_metadata(config), "fields": fields, "alert_types": sorted(alerts)}


def matches_config(expected, observed):
    if expected is None or observed is None:
        return expected is observed
    left, right = normalized_config(expected), normalized_config(observed)
    return left is not None and right is not None and left == right


def review_state(db, intent):
    """A missing user create preview never supplies implicit consent defaults."""
    row = db.execute("SELECT data FROM snapshots WHERE vehicle=? AND section=?",
                     (intent["vehicle"], "telemetry_preview_"+intent["id"])).fetchone()
    try:
        preview = json.loads(row[0]) if row else {}
    except (ValueError, TypeError):
        preview = {}
    if not isinstance(preview, dict):
        preview = {}
    if intent["operation"] not in (CREATE, DELETE):
        return preview, True
    if db.execute("SELECT 1 FROM temporary_collections WHERE restore_intent=?", (intent["id"],)).fetchone():
        # The worker restores the immutable baseline approved with the window;
        # before_dispatch additionally requires its current lease and readback.
        return preview, True
    if preview.get("intent_id") != intent["id"] or type(preview.get("trigger_revision")) is not int:
        return preview, False
    if intent["operation"] == DELETE:
        return preview, True
    from .profiles import estimate
    try:
        args = json.loads(intent["arguments"]) if isinstance(intent["arguments"], str) else intent["arguments"]
        complete = (preview.get("intent_id") == intent["id"]
                    and "hours" in preview and "estimate" in preview
                    and preview["estimate"] == estimate(args["config"]["fields"], preview["hours"]))
    except (KeyError, TypeError, ValueError, TeslaError):
        complete = False
    return preview, complete


def require_complete_review(db, intent):
    preview, complete = review_state(db, intent)
    if not complete:
        raise TeslaError("COLLECTION_REVIEW_INCOMPLETE", 'The collection review is incomplete. Cancel this request and prepare it again.')
    return preview


def read_collection(store, ref):
    vehicle = store.vehicle(ref)
    with store.db() as db:
        rows = {r["section"]: {"data": json.loads(r["data"]), "at": r["received"]}
                for r in db.execute("SELECT section,data,received FROM snapshots WHERE vehicle=? AND section IN "
                                    "('telemetry_target','telemetry_saved','telemetry_remote','telemetry_preview')", (ref,))}
        last = db.execute("SELECT id,status,operation,created,expires,result FROM intents WHERE vehicle=? "
                          "AND operation IN (?,?) ORDER BY created DESC,rowid DESC LIMIT 1", (ref, CREATE, DELETE)).fetchone()
        sample = db.execute("SELECT MAX(received) FROM samples WHERE vehicle=?", (ref,)).fetchone()[0]
    last = dict(last) if last else None
    if last and last["status"] == "prepared" and last["expires"] <= store.clock():
        last["status"] = "expired"
    remote = rows.get("telemetry_remote", {})
    target = rows.get("telemetry_target", {})
    saved = rows.get("telemetry_saved", {}).get("data") or target.get("data")
    data = remote.get("data", {})
    state = "unverified"
    if remote and remote["at"] >= target.get("at", 0):
        state = ("active" if data.get("config") else "paused") if data.get("synced") is True else "syncing"
        if state == "active" and target and not matches_config(target["data"], data.get("config")):
            state = "mismatch"
    elif target:
        state = "starting" if target.get("data") else "pausing"
    blocked = bool(last and last["status"] in ("prepared", "sending", "unknown"))
    if blocked:
        state = {"prepared": "review", "sending": "sending", "unknown": "unknown"}[last["status"]]
    preview = rows.get("telemetry_preview", {}).get("data", {})
    recent_readback = bool(remote and remote["at"] >= target.get("at", 0))
    matching = matches_config(target.get("data"), data.get("config")) if remote and target else None
    reason = ("operation_pending" if blocked else "no_readback" if not remote
              else "readback_predates_request" if not recent_readback
              else "provider_sync_pending" if data.get("synced") is not True
              else "configuration_mismatch" if matching is False else "synchronized_readback")
    with store.db() as db:
        first = db.execute("SELECT received FROM samples INDEXED BY sample_retention WHERE vehicle=? AND quality='valid' AND source_at>=? AND received>=? ORDER BY received LIMIT 1",
                           (ref, target.get("at", 0), target.get("at", 0))).fetchone()
        valid = db.execute("SELECT MAX(received),COUNT(*) FROM latest WHERE vehicle=? AND quality='valid' AND source_at>=? AND received>=?",
                           (ref, target.get("at", 0), target.get("at", 0))).fetchone()
    evidence = {"reason": reason, "configuration_matches_target": matching,
                "provider_synced": data.get("synced"), "readback_after_request": recent_readback,
                "consumer": consumer_status(store),
                "samples_since_request": {"first_valid_at": first[0] if first else None, "last_valid_at": valid[0], "valid_field_count": valid[1],
                                          "proves_complete_configuration": False}}
    return {"vehicle_ref": ref, "name": vehicle["name"], "state": state, "blocked": blocked,
            "last": last, "saved": saved, "remote": remote, "target": target, "last_sample": sample,
            "evidence": evidence, "hours": preview.get("hours", 8), "revision": digest(canonical([rows, last]))}
