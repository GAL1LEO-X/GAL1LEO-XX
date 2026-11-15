"""Typed telemetry, ordered observations and notification-only rules.

The Kafka adapter consumes the official receiver's decoded records. Offset commits
follow SQLite commits; a replay is deduplicated by observation, not by a promise of
globally unique Tesla transaction IDs. Payload time is not sensor measurement time.
"""
from datetime import datetime
import json
import math
import re
import secrets
import time

from .catalogue import finite
from .errors import TeslaError
from .gear_evidence import input_evidence
from .events import Events
from .store import canonical, digest
from .trigger_catalog import FIELD_MAP, LOCATION_FIELDS, RULE_DEFAULTS, RULE_FIELDS
from .field_capabilities import selectable
from .telemetry_privacy import contains_location
from .triggers import bump, cancel_rule_deliveries, record_change, flush_changes
from .sample_evidence import record_sample, record_latest
from .telemetry_values import decode_evidence, rule_eligibility
from .value_semantics import equal, json_equal
from . import event_support

RULE_KINDS = ("battery_low", "charging", "unlocked_parked", "geofence", "threshold", "field_changed", "trip", "software", "stale")
# vehicle_data.proto at the pinned receiver commit defines ShiftState in this
# oneof; older firmware also sends the enum name in string_value. The value
# spelling alone must never turn another protobuf branch into Park evidence.
GEAR_VALUE_BRANCHES = frozenset({"stringValue", "string_value", "shiftStateValue", "shift_state_value"})


def source_time(value):
    try:
        if not isinstance(value, str):
            raise ValueError()
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError()
        return dt.timestamp()
    except (ValueError, TypeError, OverflowError):
        raise TeslaError("INVALID_TELEMETRY", "Missing or invalid source timestamp") from None


def typed_value(field, envelope):
    from .telemetry_values import decode
    return decode(FIELD_MAP[field], envelope)


def distance_m(a, b):
    lat1, lat2 = math.radians(a["latitude"]), math.radians(b["latitude"])
    dl = lat2-lat1
    dn = math.radians(b["longitude"]-a["longitude"])
    h = math.sin(dl/2)**2+math.cos(lat1)*math.cos(lat2)*math.sin(dn/2)**2
    return 6371000*2*math.asin(min(1, math.sqrt(h)))


class Telemetry:
    def __init__(self, store, *, monotonic=time.monotonic):
        self.store = store
        self.monotonic = monotonic
        self.epoch = secrets.token_hex(16)

    def configure_rule(self, ref, kind, config, *, rule_id=None, expected_revision=None, source="rule_tool"):
        self.store.vehicle(ref)
        if kind not in RULE_KINDS or not isinstance(config, dict):
            raise TeslaError("INVALID_ARGUMENT", "Unknown notification rule")
        allowed = {"max_age_seconds", "max_gap_seconds", "dwell_seconds", "threshold", "hysteresis", "direction", "field", "latitude", "longitude", "radius_m"}
        if set(config)-allowed:
            raise TeslaError("INVALID_ARGUMENT", "Unknown rule option")
        finite(config)
        options = {**RULE_DEFAULTS, **config}
        for key in ("max_age_seconds", "max_gap_seconds", "dwell_seconds"):
            if type(options[key]) not in (int, float) or not 1 <= options[key] <= 86400:
                raise TeslaError("INVALID_ARGUMENT", "Rule time windows must be 1–86400 seconds")
        if type(options["hysteresis"]) not in (int, float) or options["hysteresis"] < 0:
            raise TeslaError("INVALID_ARGUMENT", "Invalid hysteresis")
        if kind == "battery_low":
            options.update(field="BatteryLevel", direction="below")
            options.setdefault("threshold", 20)
        if kind in ("threshold", "battery_low"):
            if type(options.get("threshold")) not in (int, float) or options.get("direction") not in ("above", "below"):
                raise TeslaError("INVALID_ARGUMENT", "Threshold and direction are required")
            field = FIELD_MAP.get(options.get("field"), {})
            if field.get("documented_type", "").lower() not in ("real", "integer"):
                raise TeslaError("INVALID_ARGUMENT", "Threshold rules require a numeric documented field")
        if kind in ("field_changed", "stale") and FIELD_MAP.get(options.get("field"), {}).get("catalog_status") != "DOCUMENTED":
            raise TeslaError("INVALID_ARGUMENT", "Choose a telemetry field")
        if kind == "stale" and options["field"] == "Version":
            raise TeslaError("INVALID_ARGUMENT", "Software version is not a heartbeat")
        if kind == "geofence":
            for key, low, high in (("latitude", -90, 90), ("longitude", -180, 180), ("radius_m", 50, 100000)):
                if type(options.get(key)) not in (int, float) or not low <= options[key] <= high:
                    raise TeslaError("INVALID_ARGUMENT", "Invalid geofence")
        if rule_id is not None:
            with self.store.db() as db:
                old = db.execute("SELECT vehicle FROM rules WHERE id=?", (rule_id,)).fetchone()
            if not old or old[0] != ref:
                raise TeslaError("NOT_FOUND", "Rule not found for this vehicle")
        identifier = rule_id or "rule_"+secrets.token_hex(12)
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if expected_revision is not None:
                revision = db.execute("SELECT revision FROM trigger_settings WHERE vehicle=?", (ref,)).fetchone()
                if type(expected_revision) is not int or not revision or revision[0] != expected_revision:
                    raise TeslaError("REVISION_CONFLICT", "Rule settings changed; read them again before saving")
            if not db.execute("SELECT 1 FROM vehicles WHERE ref=? AND active=1", (ref,)).fetchone():
                raise TeslaError("VEHICLE_ACCESS_REQUIRED", "Vehicle authorization changed")
            old = db.execute("SELECT enabled FROM rules WHERE id=? AND vehicle=?", (identifier, ref)).fetchone()
            if rule_id and not old:
                raise TeslaError("NOT_FOUND", "Rule no longer exists")
            db.execute("INSERT OR REPLACE INTO rules VALUES(?,?,?,?,?,?)", (identifier, ref, kind, canonical(options), "{}", old[0] if old else 1))
            cancel_rule_deliveries(db, ref, identifier)
            revision = bump(db, ref, source, {"configured_rule": identifier}, self.store.clock())
        return {"id": identifier, "kind": kind, "config": options, "revision": revision, "vehicle_actuations": 0}

    def ingest(self, record_type, payload, *, source_id=None, source_transport='decoded_receiver'):
        if record_type not in ("V", "alerts", "connectivity") or not isinstance(payload, dict):
            raise TeslaError("INVALID_TELEMETRY", "Unsupported telemetry envelope")
        if len(canonical(payload)) > 1_000_000:
            raise TeslaError("INVALID_TELEMETRY", "Telemetry payload is too large")
        connection = self.store.connection()
        now = self.store.clock()
        created = source_time(payload.get("createdAt", payload.get("created_at")))
        if created > now+30:
            raise TeslaError("INVALID_TELEMETRY", "Telemetry timestamp is in the future")
        ignored, unknown, ingested = [], 0, 0
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT generation,status FROM connection WHERE id=1").fetchone()
            if not current or current["status"] != "active" or current["generation"] != connection["generation"]:
                raise TeslaError("AUTH_REQUIRED", "Connection changed during ingestion")
            vehicle = db.execute("SELECT * FROM vehicles WHERE vin=? AND active=1", (payload.get("vin"),)).fetchone()
            if not vehicle:
                raise TeslaError("VEHICLE_ACCESS_REQUIRED", "Telemetry vehicle is not authorized")
            ref = vehicle["ref"]
            # isResend does not establish uniqueness or invalidate a fresh sample.
            identity = digest(canonical([record_type, {k: v for k, v in payload.items() if k not in ("isResend", "is_resend")}]))
            if db.execute("SELECT 1 FROM ingest WHERE id=?", (identity,)).fetchone():
                return {"status": "duplicate", "vehicle_actuations": 0}
            if record_type == "V":
                items = payload.get("data")
                if not isinstance(items, list) or len(items)>len(FIELD_MAP):
                    raise TeslaError("INVALID_TELEMETRY", "Invalid telemetry field list")
                seen, changed = set(), set()
                for item in items:
                    if (not isinstance(item, dict) or set(item) != {"key", "value"}
                            or not isinstance(item['key'], str) or item["key"] in seen):
                        raise TeslaError("INVALID_TELEMETRY", "Invalid or repeated telemetry field")
                    field = item["key"]
                    seen.add(field)
                    if field not in FIELD_MAP:
                        unknown += 1
                        continue
                    if not selectable(FIELD_MAP[field]):
                        ignored.append(field)
                        continue
                    if field in LOCATION_FIELDS and ("vehicle_location" not in json.loads(connection["scopes"]) or json.loads(vehicle["data"]).get("granular_access", {}).get("hide_private")):
                        continue
                    value, quality, evidence = decode_evidence(FIELD_MAP[field], item["value"], source_transport=source_transport)
                    # A known field's malformed spatial envelope must still
                    # invalidate its preceding observation (not leave old P).
                    # Check privacy after validation strips invalid content.
                    if contains_location(value) and ("vehicle_location" not in json.loads(connection["scopes"]) or json.loads(vehicle["data"]).get("granular_access", {}).get("hide_private")):
                        continue
                    ingested += 1
                    sample_id = digest(canonical([ref, field, created, value, quality]))
                    inserted = db.execute("INSERT OR IGNORE INTO samples VALUES(?,?,?,?,?,?,?,?)", (sample_id, ref, field, canonical(value), created, now, quality, "payload_created_at"))
                    if inserted.rowcount:
                        record_sample(db, sample_id, evidence)
                        # A late contradiction can invalidate an earlier event
                        # or rule baseline even when latest has moved on.
                        if db.execute("SELECT 1 FROM samples WHERE vehicle=? AND field=? AND source_at=? "
                                      "AND (quality!=? OR NOT telemetry_value_equal(field,value,?)) LIMIT 1",
                                      (ref, field, created, quality, canonical(value))).fetchone():
                            event_support.invalidate(db, ref, field, created)
                    old = db.execute("SELECT * FROM latest WHERE vehicle=? AND field=?", (ref, field)).fetchone()
                    if old and created < old["source_at"]:
                        continue
                    if old and created == old["source_at"]:
                        if not json_equal(field, old["value"], canonical(value)) or old["quality"] != quality:
                            db.execute("UPDATE latest SET quality='time_conflict',received=? WHERE vehicle=? AND field=?", (now, ref, field))
                            record_latest(db, ref, field, dict(old) | {"quality": "time_conflict", "received": now},
                                          None, evidence, conflict=True)
                            changed.add(field)
                            record_change(db, ref, field, old, dict(old) | {"quality": "time_conflict", "received": now}, now)
                            if field == "Gear":
                                self._gear_trace(db, ref, item["value"], quality, created, now, conflict=True)
                        continue
                    db.execute("INSERT OR REPLACE INTO latest VALUES(?,?,?,?,?,?,?)", (ref, field, canonical(value), created, now, quality, "payload_created_at"))
                    record_latest(db, ref, field, {"value": canonical(value), "source_at": created, "received": now, "quality": quality},
                                  sample_id, evidence)
                    if field == "Gear":
                        self._gear_trace(db, ref, item["value"], quality, created, now)
                    changed.add(field)
                    record_change(db, ref, field, old, {"value": canonical(value), "quality": quality, "source_at": created, "received": now}, now)
                self._evaluate(db, ref, changed, now)
            elif record_type == "alerts":
                for alert in payload.get("alerts", []):
                    if not isinstance(alert, dict) or not isinstance(alert.get("name"), str) or "Customer" not in alert.get("audiences", []):
                        continue
                    started = source_time(alert.get("startedAt", alert.get("started_at")))
                    raw_end = alert.get("endedAt", alert.get("ended_at"))
                    ended = source_time(raw_end) if raw_end else None
                    if started > created+30 or (ended is not None and not started <= ended <= created+30):
                        continue
                    name = alert["name"][:256]
                    old = db.execute("SELECT ended FROM alert_states WHERE vehicle=? AND name=? AND started=?", (ref, name, started)).fetchone()
                    if old and old[0] is not None:
                        continue
                    db.execute("INSERT INTO alert_states VALUES(?,?,?,?) ON CONFLICT(vehicle,name,started) DO UPDATE SET ended=coalesce(excluded.ended,alert_states.ended)", (ref, name, started, ended))
                    when = ended if ended is not None else started
                    # A newly discovered old alert is history, not a new alert.
                    if -0.001 <= now-when <= 300 and (ended is not None or old is None):
                        Events.emit(db, ref, "alert_ended" if ended is not None else "alert_started", when,
                                    {"name": name, "started_at": started, "ended_at": ended, "time_basis": "alert_timestamp"}, now)
            else:
                status, cid = payload.get("status"), payload.get("connectionId", payload.get("connection_id"))
                if status in ("CONNECTED", "DISCONNECTED") and isinstance(cid, str) and 1 <= len(cid) <= 256:
                    old = db.execute("SELECT * FROM connectivity WHERE vehicle=? AND connection_id=?", (ref, cid)).fetchone()
                    if not old or created > old["source_at"]:
                        db.execute("INSERT OR REPLACE INTO connectivity VALUES(?,?,?,?)", (ref, cid, status, created))
                        if -0.001 <= now-created <= 300 and (not old or old["status"] != status):
                            Events.emit(db, ref, "connectivity_changed", created,
                                        {"status": status, "time_basis": "payload_created_at", "vehicle_offline_proven": False}, now)
            db.execute("INSERT INTO ingest VALUES(?,?)", (identity, now))
        return {"status": "accepted", "vehicle_actuations": 0,
                **({'ingested_field_count': ingested, 'ignored_catalogue_fields': ignored,
                    'unrecognized_field_count': unknown} if record_type == 'V' else {})}

    @staticmethod
    def _gear_trace(db, ref, envelope, quality, created, now, *, conflict=False):
        detail = input_evidence(envelope, quality) | {"timestamp_conflict": conflict}
        db.execute("INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?)",
                   (ref, "gear_ingestion", canonical(detail), "fleet_telemetry", created, now))

    def _evaluate(self, db, ref, changed, now):
        latest = {r["field"]: dict(r) for r in db.execute("SELECT * FROM latest WHERE vehicle=?", (ref,))}
        for rule in db.execute("SELECT * FROM rules WHERE vehicle=? AND enabled=1", (ref,)).fetchall():
            config, state, kind = json.loads(rule["config"]), json.loads(rule["state"]), rule["kind"]
            if kind in ("unlocked_parked", "geofence") and state.get("epoch") != self.epoch:
                state = {}
            fields = RULE_FIELDS.get(kind, [config.get("field")])
            if kind == "stale" or not set(fields) & changed:
                continue
            records = [latest.get(f) for f in fields]
            valid = all(r and r["quality"] == "valid" and -0.001 <= now-r["source_at"] <= config["max_age_seconds"] for r in records)
            if valid and kind in ('battery_low', 'threshold'):
                # A narrow local plausibility policy is separate from the wire
                # contract; neither stored values nor their quality is changed.
                valid = all(rule_eligibility(r['field'], json.loads(r['value']), r['quality'])['eligible']
                            for r in records)
            current_support = event_support.points(records) if valid else None
            if valid:
                valid = not event_support.conflicted(db, ref, current_support)
            # Old persisted rule states did not record per-field times. They
            # cannot supply a qualified baseline after an upgrade.
            if state and (not event_support.known(state.get(event_support.KEY))
                          or (kind not in ('unlocked_parked', 'geofence')
                              and event_support.conflicted(db, ref, state[event_support.KEY]))):
                state = {}
            if valid and kind in ("unlocked_parked", "geofence"):
                valid = max(r["source_at"] for r in records)-min(r["source_at"] for r in records) <= 30
            if not valid:
                state = {}
            else:
                values = {f: json.loads(latest[f]["value"]) for f in fields}
                when = max(r["source_at"] for r in records)
                if state and (when-state.get("source_at", when) > config["max_gap_seconds"] or now-state.get("received", now) > config["max_gap_seconds"]):
                    state = {}
                events = []
                baseline = "value" not in state
                support = event_support.combine(state.get(event_support.KEY), current_support)
                next_support = current_support
                if kind in ("battery_low", "threshold"):
                    value = values[config["field"]]
                    threshold = config["threshold"]
                    active = value <= threshold if config["direction"] == "below" else value >= threshold
                    rearmed = value > threshold+config["hysteresis"] if config["direction"] == "below" else value < threshold-config["hysteresis"]
                    if not baseline and active and not state.get("latched", False):
                        events.append("battery_low" if kind == "battery_low" else "threshold_crossed")
                    if baseline or active:
                        state["latched"] = active
                    elif rearmed:
                        state["latched"] = False
                    else:
                        # Hysteresis preserves the earlier rearm/latched fact;
                        # an intervening neutral value must not replace its source.
                        next_support = state.get(event_support.KEY, current_support)
                elif kind == "charging" and not baseline:
                    value, old = values["DetailedChargeState"], state["value"]["DetailedChargeState"]
                    if value != old:
                        if value == "DetailedChargeStateCharging":
                            events.append("charge_resumed" if old == "DetailedChargeStateStopped" else "charge_started")
                        elif old == "DetailedChargeStateCharging" and value == "DetailedChargeStateComplete":
                            events.append("charge_completed")
                        elif old == "DetailedChargeStateCharging" and value in ("DetailedChargeStateStopped", "DetailedChargeStateNoPower", "DetailedChargeStateDisconnected"):
                            events.append("charge_stopped")
                elif kind == "unlocked_parked":
                    active = values["Locked"] is False and values["Gear"] == "ShiftStateP" and values["DriverSeatOccupied"] is False
                    if active:
                        support = event_support.combine(state.get(event_support.KEY) if 'since' in state else None,
                                                        current_support, span=True)
                        next_support = support
                        state.setdefault("since", self.monotonic())
                        counts = state.setdefault("observations", {})
                        for field in set(fields) & changed:
                            counts[field] = counts.get(field, 0)+1
                        if not state.get("latched") and self.monotonic()-state["since"] >= config["dwell_seconds"] and all(counts.get(f, 0) >= 2 for f in fields):
                            events.append("unlocked_parked")
                            state["latched"] = True
                    else:
                        state = {}
                elif kind == "geofence":
                    if values["GpsState"] is not True:
                        db.execute("UPDATE rules SET state='{}' WHERE id=?", (rule["id"],))
                        continue
                    else:
                        support = event_support.combine(state.get(event_support.KEY), current_support, span=True)
                        dist = distance_m(values["Location"], config)
                        inside = dist <= config["radius_m"]
                        if not baseline and inside != state.get("inside"):
                            boundary = config["radius_m"]+config["hysteresis"]
                            if inside or dist > boundary:
                                desired = "geofence_enter" if inside else "geofence_exit"
                                if state.get("pending") != desired:
                                    state.update(pending=desired, since=self.monotonic())
                                elif self.monotonic()-state["since"] >= config["dwell_seconds"]:
                                    events.append(desired)
                                    state.update(inside=inside, pending=None)
                        else:
                            state.update(inside=inside, pending=None)
                        # Keep the baseline and all dwell inputs until the
                        # boundary is committed (or the pending dwell is reset).
                        if state.get("pending"):
                            next_support = support
                elif kind == "trip" and not baseline:
                    current, old = values["Gear"], state["value"]["Gear"]
                    if old == "ShiftStateP" and current in ("ShiftStateD", "ShiftStateR"):
                        events.append("trip_started")
                    elif current == "ShiftStateP" and old in ("ShiftStateD", "ShiftStateR"):
                        events.append("trip_ended")
                elif kind in ("field_changed", "software") and not baseline and any(
                        not equal(field, values[field], state["value"].get(field)) for field in fields):
                    events.append("software_changed" if kind == "software" else "field_changed")
                state.update(value=values, source_at=when, received=now, epoch=self.epoch,
                             **{event_support.KEY: next_support})
                # Ingestion atomically resets a dwell state on every new
                # contradiction. Do not rescan its growing history on every
                # ordinary frame; check the complete support when it would
                # actually produce an event (also covering other DB writers).
                if events and kind in ('unlocked_parked', 'geofence') and event_support.conflicted(db, ref, support):
                    state, events = {}, []
                for event in events:
                    Events.emit(db, ref, event, when, {"rule_id": rule["id"], "observed": values,
                                                      "time_basis": "payload_created_at", "physical_continuity_guaranteed": False,
                                                      **({'basis': 'gear_transition', 'physical_motion_verified': False}
                                                         if event in ('trip_started', 'trip_ended') else {})}, now, support=support)
            db.execute("UPDATE rules SET state=? WHERE id=?", (canonical(state), rule["id"]))

    def tick(self):
        now = self.store.clock()
        try:
            self.store.connection()
        except TeslaError:
            return
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            flush_changes(db, now)
            for rule in db.execute("SELECT * FROM rules WHERE kind='stale' AND enabled=1").fetchall():
                c, state = json.loads(rule["config"]), json.loads(rule["state"])
                row = db.execute("SELECT * FROM latest WHERE vehicle=? AND field=?", (rule["vehicle"], c["field"])).fetchone()
                if not row:
                    continue  # Never-observed data does not prove a transition.
                stale = now-row["source_at"] > c["max_age_seconds"]
                if stale and not state.get("latched", False):
                    Events.emit(db, rule["vehicle"], "data_stale", now,
                                {"rule_id": rule["id"], "field": c["field"], "last_observed_at": row["source_at"], "vehicle_offline_proven": False}, now)
                db.execute("UPDATE rules SET state=? WHERE id=?", (canonical({"latched": stale}), rule["id"]))


def consume_record(telemetry, record):
    """Return only after commit. Caller commits this Kafka offset afterward."""
    if not isinstance(record.value, bytes) or len(record.value)>1_000_000:
        raise TeslaError("INVALID_TELEMETRY", "Invalid Kafka record")
    try:
        headers = {k: v.decode("utf-8") for k, v in record.headers if k in ("vin", "txtype") and isinstance(v, bytes)}
        payload = json.loads(record.value)
        key = record.key.decode("utf-8") if isinstance(record.key, bytes) else None
    except (ValueError, TypeError):
        raise TeslaError("INVALID_TELEMETRY", "Invalid receiver encoding") from None
    if not isinstance(payload, dict) or payload.get("vin") != headers.get("vin") or key != payload.get("vin"):
        raise TeslaError("INVALID_TELEMETRY", "Receiver and payload vehicle identities differ")
    return telemetry.ingest(headers.get("txtype"), payload,
                            source_id=f"{record.topic}:{record.partition}:{record.offset}", source_transport='kafka')
