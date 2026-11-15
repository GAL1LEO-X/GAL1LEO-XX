"""Explicitly approved, durable collection windows; never replay an uncertain write.

The lease coordinates readback workers. The durable restore intent is the write
fence: once sending, even a dead lease can only be reconciled by a provider read.
Nothing creates a session from an installed/saved profile during startup.
"""
from copy import deepcopy
import json
import math
import secrets

from .collection_state import CREATE, DELETE, config_without_signing_metadata
from .errors import TeslaError
from .profiles import effective_fields
from .store import canonical, digest
from .trigger_catalog import FIELD_MAP

TERMINAL = ("restored_verified", "superseded", "cancelled", "start_rejected")
LEASE_SECONDS = 120
CHECK_SECONDS = 60
MAX_CHECKS = 10
BASELINE_MAX_AGE = 300
SUSPENDED = ("VEHICLE_ACCESS_REVOKED", "AUTHORIZATION_REMOVED")


def validate_duration(value):
    if value is not None and (type(value) is not int or not 60 <= value <= 86400):
        raise TeslaError("INVALID_ARGUMENT", 'Temporary duration must be an integer between 60 and 86400 seconds.')
    return value


def window_cost(fields, seconds):
    signals = sum((1+len(opts.get("include_fields", [])))*
                  (1+math.ceil(seconds/opts["interval_seconds"])+
                   (math.ceil(seconds/opts["resend_interval_seconds"]) if opts.get("resend_interval_seconds") else 0))
                  for opts in fields.values())
    return {"planned_signals": signals, "estimated_gross_usd": round(signals/150000, 4),
            "duration_seconds": seconds, "continuous_activity_assumed": True, "billing_cap": False,
            "other_costs_included": False}


def same_config(left, right):
    """Compare every option, allowing only a documented threshold's JSON roundtrip.

    The pinned signer decodes JSON numbers and serializes integral floats as
    integers. Only minimum_delta has a number (rather than integer) contract;
    unknown options, lists and transport settings retain canonical comparison.
    Never normalize stored requests, readbacks or their approved digests.
    """
    def projection(config):
        value = deepcopy(config_without_signing_metadata(config))
        if isinstance(value, dict) and isinstance(value.get("fields"), dict):
            for name, options in value["fields"].items():
                field = FIELD_MAP.get(name)
                if (not field or not isinstance(options, dict)
                        or (field["documented_type"].lower() not in ("real", "integer") and name != "Location")):
                    continue
                delta = options.get("minimum_delta")
                if type(delta) is float and math.isfinite(delta) and delta.is_integer():
                    options["minimum_delta"] = int(delta)
        return value
    try:
        return canonical(projection(left)) == canonical(projection(right))
    except (TypeError, ValueError):
        # Non-JSON/non-finite input cannot attest an equivalent configuration.
        return False


def plan_for(service, ref, view, duration, fields, scopes):
    validate_duration(duration)
    with service.store.db() as db:
        assert_no_active_window(db, ref)
    data = view["remote"].get("data", {})
    baseline = data.get("config")
    if (view["state"] not in ("active", "paused") or data.get("synced") is not True
            or not 0 <= service.store.clock()-view["remote"].get("at", 0) <= BASELINE_MAX_AGE
            or (view["target"] and not same_config(view["target"]["data"], baseline))):
        raise TeslaError("BASELINE_UNVERIFIED", 'Explicitly verify Tesla collection before preparing a temporary duration.')
    from .trigger_catalog import LOCATION_FIELDS
    if effective_fields((baseline or {}).get("fields", {})) & LOCATION_FIELDS:
        service.location_allowed(service.vehicle(ref, refresh_membership=False), scopes)
    cost = window_cost(fields, duration)
    previous = window_cost((baseline or {}).get("fields", {}), duration)
    with service.store.db() as db:
        trigger = db.execute("SELECT revision FROM trigger_settings WHERE vehicle=?", (ref,)).fetchone()
    return {"duration_seconds": duration, "baseline_config": deepcopy(baseline),
            "baseline_target": deepcopy(view["target"].get("data")), "baseline_target_present": bool(view["target"]),
            "baseline_saved": deepcopy(view["saved"]), "baseline_hours": view["hours"],
            "baseline_observed_at": view["remote"].get("at"), "scopes": sorted(scopes),
            "baseline_max_age_seconds": BASELINE_MAX_AGE,
            "tesla_scopes": sorted(json.loads(service.store.connection()["scopes"])),
            "trigger_revision": trigger[0] if trigger else None,
            "cost": cost, "baseline_cost": previous,
            "estimated_delta_usd": round(cost["estimated_gross_usd"]-previous["estimated_gross_usd"], 4),
            "restore_policy": "restore_only_if_temporary_configuration_still_matches",
            "automatic_readback": True, "max_verification_reads": MAX_CHECKS, "expires_from": "dispatch"}


def public_plan(plan, row=None):
    baseline = plan["baseline_config"]
    row = row or {}
    return {"duration_seconds": plan["duration_seconds"],
            "baseline": None if baseline is None else {"fields": baseline.get("fields", {}),
                       "customer_alerts": "customer" in baseline.get("alert_types", [])},
            "baseline_observed_at": plan["baseline_observed_at"],
            "baseline_max_age_seconds": plan["baseline_max_age_seconds"],
            "restore_action": "configure" if baseline else "pause", "expires_from": "dispatch",
            "estimated_gross_usd": plan["cost"]["estimated_gross_usd"],
            "baseline_estimated_gross_usd": plan["baseline_cost"]["estimated_gross_usd"],
            "estimated_delta_usd": plan["estimated_delta_usd"], "cost": plan["cost"],
            "restore_policy": plan["restore_policy"], "automatic_readback": True,
            "verification_interval_seconds": CHECK_SECONDS,
            "max_verification_reads": plan["max_verification_reads"], "verification_reads": row.get("check_count", 0),
            "status": row.get("status", "prepared"), "started_at": row.get("started"),
            "expires_at": row.get("expires"), "restore_intent_id": row.get("restore_intent"),
            "last_error": row.get("error"), "restore_verified": row.get("status") == "restored_verified"}


def latest(store, ref):
    now = store.clock()
    with store.db() as db:
        row = db.execute("SELECT * FROM temporary_collections WHERE vehicle=? ORDER BY updated DESC,rowid DESC LIMIT 1", (ref,)).fetchone()
        if not row:
            return None
        row = dict(row)
        intent = db.execute("SELECT status,expires,arguments FROM intents WHERE id=?", (row["intent_id"],)).fetchone()
    if row["status"] == "prepared" and row["started"] is None:
        if not intent or intent["status"] in ("cancelled", "expired") or (intent["status"] == "prepared" and intent["expires"] <= now):
            row["status"] = "cancelled"
    plan = json.loads(row["plan"])
    result = public_plan(plan, row)
    fields = json.loads(intent["arguments"]).get("config", {}).get("fields", {}) if intent else {}
    result["timing"] = timing_evidence(plan, row, now, fields)
    return result


def timing_evidence(plan, row, now, fields):
    """Project the local deadline; do not infer vehicle state or alter the plan."""
    started, expires = row.get("started"), row.get("expires")
    backwards = started is not None and now < started
    due = started is not None and expires is not None and now >= expires and not backwards
    overdue = due and row["status"] not in TERMINAL
    seconds = now-expires if overdue else None
    cost = None
    if overdue and fields:
        # Difference of the same approved scenario cancels its initial sample.
        # This is conditional streaming only, not observed usage or a spending cap.
        duration = plan["duration_seconds"]
        additional = (window_cost(fields, duration+seconds)["planned_signals"]
                      - window_cost(fields, duration)["planned_signals"])
        cost = {"condition": "temporary_configuration_continues_with_continuous_activity",
                "additional_duration_seconds": seconds, "additional_planned_signals": additional,
                "estimated_gross_usd": round(additional/150000, 4), "currency": "USD",
                "observed_charge": False, "billing_cap": False, "other_costs_included": False}
    return {"evaluated_at": now, "scope": "local_deadline_and_restore_obligation",
            "elapsed_seconds": now-started if started is not None and not backwards else None,
            "clock_before_start": backwards, "deadline_elapsed": due,
            "restore_overdue": overdue, "overdue_seconds": seconds,
            "streaming_duration_verified": False, "conditional_additional_streaming_cost": cost}


def expire_unstarted(db, now):
    """Retire abandoned consent, never an obligation whose dispatch started."""
    db.execute("UPDATE temporary_collections SET status='cancelled',error='CONFIRMATION_EXPIRED_OR_CANCELLED',updated=?,"
               "lease_owner=NULL,lease_until=0 WHERE status='prepared' AND started IS NULL AND ("
               "NOT EXISTS (SELECT 1 FROM intents i WHERE i.id=temporary_collections.intent_id) OR "
               "intent_id IN (SELECT id FROM intents WHERE status IN ('cancelled','expired') "
               "OR (status='prepared' AND expires<=?)))", (now, now))


def assert_no_active_window(db, ref):
    # Restoring another temporary profile would extend that profile beyond its
    # original deadline. Finish or explicitly replace its obligation first.
    row = db.execute("SELECT 1 FROM temporary_collections WHERE vehicle=? AND started IS NOT NULL "
                     "AND status NOT IN ('restored_verified','superseded','cancelled','start_rejected')", (ref,)).fetchone()
    if row:
        raise TeslaError("TEMPORARY_COLLECTION_PENDING", 'Finish restoring the current temporary collection before preparing another; you may select an ordinary configuration or pause collection.')


def register(db, store, intent, plan):
    """Persist immutable consent beside its intent, in the same transaction."""
    assert_no_active_window(db, intent["vehicle"])
    db.execute("INSERT INTO temporary_collections(intent_id,vehicle,plan,generation,status,updated) VALUES(?,?,?,?,?,?)",
               (intent["id"], intent["vehicle"], canonical(plan), intent["generation"], "prepared", store.clock()))


def cancel_unsent_restore(db, row, reason):
    if row["restore_intent"]:
        db.execute("UPDATE intents SET status='cancelled',result=? WHERE id=? AND status='prepared'",
                   (canonical({"code": reason, "dispatch_attempted": False, "accepted": False}), row["restore_intent"]))


def supersede(db, row, now, reason):
    cancel_unsent_restore(db, row, reason)
    db.execute("UPDATE temporary_collections SET status='superseded',error=?,updated=?,lease_owner=NULL,lease_until=0 WHERE intent_id=?",
               (reason, now, row["intent_id"]))


def supersede_after_owner_change(db, intent, now):
    """A definitive later owner change replaces the old restore obligation."""
    if db.execute("SELECT 1 FROM temporary_collections WHERE restore_intent=?", (intent["id"],)).fetchone():
        return
    rows = db.execute("SELECT * FROM temporary_collections WHERE vehicle=? AND intent_id<>? "
                      "AND status NOT IN ('restored_verified','superseded','cancelled','start_rejected')",
                      (intent["vehicle"], intent["id"])).fetchall()
    for row in rows:
        supersede(db, row, now, "later_owner_collection_change")


def assert_restore_baseline(db, row):
    """Legacy nested windows cannot extend a predecessor's temporary profile.

    A later ordinary selection is affirmative authorization for that profile;
    its saved baseline must not be mistaken for an unresolved nested window.
    """
    if row["error"] == "TEMPORARY_BASELINE_REVIEW_REQUIRED":
        # A positive lineage finding survives retention pruning of its source
        # intent. Only a subsequent explicit owner choice supersedes the window.
        raise TeslaError("TEMPORARY_BASELINE_REVIEW_REQUIRED", 'Confirm an ordinary profile to resolve the paused temporary restoration.')
    plan = json.loads(row["plan"])
    baseline = plan["baseline_config"]
    if baseline is None or same_config(baseline, plan["baseline_saved"]):
        return
    predecessor = db.execute(
        "SELECT i.arguments,t.started,t.status FROM intents i "
        "LEFT JOIN temporary_collections t ON t.intent_id=i.id "
        "WHERE i.vehicle=? AND i.rowid<(SELECT rowid FROM intents WHERE id=?) "
        "AND i.operation IN (?,?) AND i.status IN ('acknowledged','reconciled','unknown','sending') "
        "AND i.created<=? ORDER BY i.created DESC,i.rowid DESC LIMIT 1",
        (row["vehicle"], row["intent_id"], CREATE, DELETE, plan["baseline_observed_at"])).fetchone()
    if (predecessor and predecessor["started"] is not None
            and predecessor["status"] not in ("restored_verified", "cancelled", "start_rejected")
            and same_config(json.loads(predecessor["arguments"]).get("config"), baseline)):
        raise TeslaError("TEMPORARY_BASELINE_REVIEW_REQUIRED",
                         'The proposed restoration matches an earlier temporary collection that was not restored. Choose and confirm an ordinary profile before continuing.')


def preserve_restore_lineage(db, now):
    """Persist proven legacy blockers before retention removes their evidence."""
    rows = db.execute("SELECT * FROM temporary_collections WHERE started IS NOT NULL "
                      "AND status NOT IN ('restored_verified','superseded','cancelled','start_rejected')").fetchall()
    for row in rows:
        # Revocation is already a durable non-resumable fence; never replace it
        # with a different error or enable the worker when history is removed.
        if row["error"] in SUSPENDED:
            continue
        try:
            assert_restore_baseline(db, row)
        except TeslaError as exc:
            if exc.code != "TEMPORARY_BASELINE_REVIEW_REQUIRED":
                raise
            db.execute("UPDATE temporary_collections SET status='blocked',error=?,updated=? WHERE intent_id=?",
                       (exc.code, now, row["intent_id"]))


def before_dispatch(service, db, intent, *, lease_owner=None):
    """Called inside the transaction that marks a collection intent sending."""
    store, now = service.store, service.store.clock()
    restoring = db.execute("SELECT * FROM temporary_collections WHERE restore_intent=?", (intent["id"],)).fetchone()
    if restoring:
        restoring = dict(restoring)
        if (not lease_owner or restoring["lease_owner"] != lease_owner or restoring["lease_until"] <= now
                or restoring["status"] != "restore_pending"):
            raise TeslaError("RESTORE_LEASE_LOST", 'Restoration requires the authorized worker and its current lease.')
        assert_permissions(service, dict(restoring))
        assert_local_revision(db, dict(restoring), intent["id"], now=now)
        assert_restore_baseline(db, restoring)
        # A preflight provider read may have allowed a concurrent explicit
        # configuration read. Recheck the latest committed evidence at the
        # write fence, not merely the read that reserved this restore intent.
        remote = db.execute("SELECT data,received FROM snapshots WHERE vehicle=? AND section='telemetry_remote'", (intent["vehicle"],)).fetchone()
        observed = json.loads(remote["data"]) if remote else {}
        if (not remote or observed.get("synced") is not True
                or not 0 <= now-remote["received"] <= CHECK_SECONDS):
            db.execute("UPDATE temporary_collections SET status='blocked',error='RESTORE_READBACK_REQUIRED',updated=?,next_check=?,lease_owner=NULL,lease_until=0 WHERE intent_id=?",
                       (now, now+CHECK_SECONDS, restoring["intent_id"]))
            return False
        plan = json.loads(restoring["plan"])
        start = db.execute("SELECT arguments,status FROM intents WHERE id=?", (restoring["intent_id"],)).fetchone()
        temporary = json.loads(start["arguments"])["config"] if start else None
        target = db.execute("SELECT data FROM snapshots WHERE vehicle=? AND section='telemetry_target'", (intent["vehicle"],)).fetchone()
        target_config = json.loads(target["data"]) if target else None
        target_unchanged = bool(start) and ((target is not None and same_config(target_config, temporary)) or
            (start["status"] in ("unknown", "sending", "reconciled")
             and bool(target) == plan["baseline_target_present"] and same_config(target_config, plan["baseline_target"])))
        if not target_unchanged:
            supersede(db, restoring, now, "local_collection_target_changed")
            return False
        if same_config(observed.get("config"), plan["baseline_config"]):
            TemporaryCollection(service)._verified(db, restoring, plan)
            return False
        if not start or not same_config(observed.get("config"), temporary):
            supersede(db, restoring, now, "observed_configuration_changed")
            return False
        return True
    row = db.execute("SELECT * FROM temporary_collections WHERE intent_id=?", (intent["id"],)).fetchone()
    if row:
        plan = json.loads(row["plan"])
        remote = db.execute("SELECT data,received FROM snapshots WHERE vehicle=? AND section='telemetry_remote'", (intent["vehicle"],)).fetchone()
        target = db.execute("SELECT data FROM snapshots WHERE vehicle=? AND section='telemetry_target'", (intent["vehicle"],)).fetchone()
        observed = json.loads(remote[0]) if remote else {}
        if (observed.get("synced") is not True or not same_config(observed.get("config"), plan["baseline_config"])
                or not remote or not 0 <= now-remote["received"] <= plan["baseline_max_age_seconds"]
                or bool(target) != plan["baseline_target_present"]
                or (target and not same_config(json.loads(target[0]), plan["baseline_target"]))):
            raise TeslaError("REVISION_CONFLICT", 'The initial configuration changed: prepare a new temporary collection.')
        assert_permissions(service, dict(row))
        from .collection_state import check_trigger_revision
        check_trigger_revision(db, intent["vehicle"], plan["trigger_revision"])
        db.execute("UPDATE temporary_collections SET status='active',started=?,expires=?,next_check=?,updated=? WHERE intent_id=? AND status='prepared'",
                   (now, now+plan["duration_seconds"], now+plan["duration_seconds"], now, intent["id"]))
    # Prepared/sending/unknown later actions suspend restore through its intent
    # revision fence. Only a definitive accepted change retires the obligation.
    return True


def finish_dispatch(service, db, intent, state, outcome):
    if state == "acknowledged" and outcome.get("configuration_state_recorded") is not False:
        supersede_after_owner_change(db, intent, service.store.clock())
    row = db.execute("SELECT * FROM temporary_collections WHERE intent_id=? OR restore_intent=?", (intent["id"], intent["id"])).fetchone()
    if not row or row["status"] in TERMINAL or row["error"] in (*SUSPENDED, "TEMPORARY_BASELINE_REVIEW_REQUIRED"):
        return
    restore = row["restore_intent"] == intent["id"]
    status = ({"acknowledged": "restore_accepted", "unknown": "restore_unknown", "rejected": "restore_rejected"} if restore else
              {"acknowledged": "active", "unknown": "start_unknown", "rejected": "start_rejected"})[state]
    error = outcome.get("code") if state in ("rejected", "unknown") else None
    db.execute("UPDATE temporary_collections SET status=?,updated=?,next_check=?,error=? WHERE intent_id=?",
               (status, service.store.clock(), service.store.clock()+CHECK_SECONDS if restore else row["expires"], error, row["intent_id"]))


def assert_permissions(service, row):
    from .service import require
    plan = json.loads(row["plan"])
    connection = service.store.connection()
    if row["generation"] != connection["generation"]:
        raise TeslaError("AUTHORIZATION_CHANGED", 'The connection changed; automatic restoration remains paused.')
    scopes = set(plan["scopes"]) & set(service.settings.allowed_scopes)
    require(scopes, "tesla:read", "tesla:manage", "tesla:commands")
    require(scopes, *plan["scopes"])
    if not set(plan["tesla_scopes"]) <= set(json.loads(connection["scopes"])):
        raise TeslaError("SCOPE_REQUIRED", 'Tesla permissions changed; restoration paused.')
    vehicle = service.vehicle(row["vehicle"], refresh_membership=False)
    from .trigger_catalog import LOCATION_FIELDS
    if effective_fields((plan["baseline_config"] or {}).get("fields", {})) & LOCATION_FIELDS:
        service.location_allowed(vehicle, scopes)
    return scopes


def assert_local_revision(db, row, restoring=None, *, now):
    plan = json.loads(row["plan"])
    last = db.execute("SELECT id FROM intents WHERE vehicle=? AND operation IN (?,?) "
                      "AND status NOT IN ('cancelled','rejected','expired') AND (status<>'prepared' OR expires>?) "
                      "ORDER BY created DESC,rowid DESC LIMIT 1", (row["vehicle"], CREATE, DELETE, now)).fetchone()
    if last and last[0] not in (row["intent_id"], restoring):
        raise TeslaError("REVISION_CONFLICT", 'A subsequent collection request requires review.')
    trigger = db.execute("SELECT revision FROM trigger_settings WHERE vehicle=?", (row["vehicle"],)).fetchone()
    if plan["trigger_revision"] is not None and (not trigger or trigger[0] != plan["trigger_revision"]):
        raise TeslaError("REVISION_CONFLICT", 'Events changed; review collection restoration.')


class TemporaryCollection:
    def __init__(self, service):
        self.service, self.store = service, service.store

    def _update(self, row, owner, status, error=None, *, delay=CHECK_SECONDS):
        with self.store.db() as db:
            db.execute("UPDATE temporary_collections SET status=?,error=CASE WHEN error='TEMPORARY_BASELINE_REVIEW_REQUIRED' THEN error ELSE ? END,updated=?,next_check=?,lease_owner=NULL,lease_until=0 "
                       "WHERE intent_id=? AND lease_owner=? AND lease_until>? AND status NOT IN ('restored_verified','superseded','cancelled','start_rejected')",
                       (status, error, self.store.clock(), self.store.clock()+delay, row["intent_id"], owner, self.store.clock()))

    def observe(self, ref, authorization):
        """An explicit read can finish verification after the automatic budget ends.

        This only records an observed baseline. It never dispatches or renews a
        restore authorization, including one suspended by revoked membership.
        """
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            self.store.assert_authorization(db, authorization)
            row = db.execute("SELECT * FROM temporary_collections WHERE vehicle=? AND started IS NOT NULL AND expires<=? "
                             "AND status NOT IN ('restored_verified','superseded','cancelled','start_rejected') ORDER BY updated DESC LIMIT 1",
                             (ref, self.store.clock())).fetchone()
            remote = db.execute("SELECT data FROM snapshots WHERE vehicle=? AND section='telemetry_remote'", (ref,)).fetchone()
            if not row or not remote:
                return
            row, data = dict(row), json.loads(remote[0])
            if row["error"] in SUSPENDED:
                return
            try:
                assert_permissions(self.service, row)
                assert_local_revision(db, row, row["restore_intent"], now=self.store.clock())
                assert_restore_baseline(db, row)
            except TeslaError:
                return
            plan = json.loads(row["plan"])
            if data.get("synced") is True and same_config(data.get("config"), plan["baseline_config"]):
                self._verified(db, row, plan)

    def tick(self):
        """One leased, bounded readback/restore. Idle upgrades issue no requests."""
        with self.store.db() as db:
            expire_unstarted(db, self.store.clock())
        if not self.service.settings.live_enabled:
            return None
        owner, now = secrets.token_hex(16), self.store.clock()
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            # Prepared/cancelled/expired approvals never authorize a worker.
            row = db.execute("SELECT * FROM temporary_collections WHERE started IS NOT NULL AND expires<=? AND next_check<=? "
                             "AND lease_until<=? AND status NOT IN ('restored_verified','superseded','cancelled','start_rejected') "
                             "ORDER BY next_check,intent_id LIMIT 1", (now, now, now)).fetchone()
            if not row:
                return None
            row = dict(row)
            db.execute("UPDATE temporary_collections SET lease_owner=?,lease_until=? WHERE intent_id=?", (owner, now+LEASE_SECONDS, row["intent_id"]))
        try:
            self._reconcile(row, owner)
        except TeslaError as exc:
            self._update(row, owner, "blocked", exc.code)
        except Exception:
            self._update(row, owner, "blocked", "RESTORE_CHECK_FAILED")
        return latest(self.store, row["vehicle"])

    def _reconcile(self, row, owner):
        service, store = self.service, self.store
        plan = json.loads(row["plan"])
        scopes = assert_permissions(service, row)
        with store.db() as db:
            assert_local_revision(db, row, row["restore_intent"], now=store.clock())
            assert_restore_baseline(db, row)
        with store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT check_count FROM temporary_collections WHERE intent_id=? AND lease_owner=? AND lease_until>?",
                                 (row["intent_id"], owner, store.clock())).fetchone()
            if not current:
                return
            if current[0] >= plan["max_verification_reads"]:
                db.execute("UPDATE temporary_collections SET status='blocked',error='RESTORE_VERIFICATION_LIMIT_REACHED',next_check=?,lease_owner=NULL,lease_until=0 WHERE intent_id=?",
                           (1e30, row["intent_id"]))
                return
            db.execute("UPDATE temporary_collections SET check_count=check_count+1 WHERE intent_id=?", (row["intent_id"],))
        # GET is always first, including after a worker/host restart or unknown.
        result = service.read("vehicle_fleet_telemetry_config_get", {}, row["vehicle"], scopes)
        observed = result["data"]
        with store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT * FROM temporary_collections WHERE intent_id=? AND lease_owner=? AND lease_until>?",
                                 (row["intent_id"], owner, store.clock())).fetchone()
            if not current or current["status"] in TERMINAL:
                return
            row = dict(current)
            assert_permissions(service, row)
            assert_local_revision(db, row, row["restore_intent"], now=store.clock())
            assert_restore_baseline(db, row)
            remote = db.execute("SELECT data FROM snapshots WHERE vehicle=? AND section='telemetry_remote'", (row["vehicle"],)).fetchone()
            if not remote or json.loads(remote[0]) != observed or observed.get("synced") is not True:
                db.execute("UPDATE temporary_collections SET error='PROVIDER_SYNC_PENDING',next_check=?,lease_owner=NULL,lease_until=0 WHERE intent_id=?",
                           (store.clock()+CHECK_SECONDS, row["intent_id"]))
                return
            start = store.intent(row["intent_id"])
            if same_config(observed["config"], plan["baseline_config"]):
                self._verified(db, row, plan)
                return
            if not same_config(observed["config"], start["arguments"]["config"]):
                supersede(db, row, store.clock(), "observed_configuration_changed")
                return
            if row["restore_intent"]:
                # Sending may mean a dead worker. Never redispatch: only reads.
                restore = db.execute("SELECT status FROM intents WHERE id=?", (row["restore_intent"],)).fetchone()
                state = restore[0] if restore else "unknown"
                if state == "sending":
                    db.execute("UPDATE intents SET status='unknown',result=? WHERE id=? AND status='sending'",
                               (canonical({"code": "OUTCOME_UNKNOWN", "message": "Interrupted restore; no automatic retry"}), row["restore_intent"]))
                if state != "prepared":
                    status = {"acknowledged": "restore_accepted", "rejected": "restore_rejected"}.get(state, "restore_unknown")
                    db.execute("UPDATE temporary_collections SET status=?,next_check=?,lease_owner=NULL,lease_until=0 WHERE intent_id=?",
                               (status, store.clock()+CHECK_SECONDS, row["intent_id"]))
                    return
                identifier = row["restore_intent"]
                # A never-dispatched prepared restore can be taken over safely.
                db.execute("UPDATE intents SET expires=? WHERE id=? AND status='prepared'", (store.clock()+service.settings.intent_ttl_seconds, identifier))
            else:
                identifier = "intent_"+secrets.token_hex(16)
                # Preserve the reviewed raw baseline; the proxy signs these
                # settings again and owns the top-level aud/iss claims.
                baseline = config_without_signing_metadata(plan["baseline_config"])
                name, arguments = (CREATE, {"config": baseline}) if baseline else (DELETE, {})
                db.execute("INSERT INTO intents VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                           (identifier, "temporary_restore_"+row["intent_id"], digest(canonical([row["intent_id"], plan])),
                            row["vehicle"], name, canonical(arguments), canonical(plan["scopes"]), row["generation"],
                            store.clock(), store.clock()+service.settings.intent_ttl_seconds, "prepared"))
                db.execute("UPDATE temporary_collections SET restore_intent=? WHERE intent_id=?", (identifier, row["intent_id"]))
                # Resolve only this start from readback; an unknown start is not retried.
                db.execute("UPDATE intents SET status='reconciled',result=? WHERE id=? AND status IN ('sending','unknown')",
                           (canonical({"configuration_verified": True, "acceptance_unknown": True, "source": "temporary_readback"}), row["intent_id"]))
            db.execute("UPDATE temporary_collections SET status='restore_pending',updated=? WHERE intent_id=?", (store.clock(), row["intent_id"]))
        service.execute_from_owner(identifier, confirmation_source="approved_temporary_restore", _restore_lease=owner)
        with store.db() as db:
            db.execute("UPDATE temporary_collections SET lease_owner=NULL,lease_until=0 WHERE intent_id=? AND lease_owner=?", (row["intent_id"], owner))

    def _verified(self, db, row, plan):
        now = self.store.clock()
        cancel_unsent_restore(db, row, "BASELINE_ALREADY_VERIFIED")
        observed = db.execute("SELECT received FROM snapshots WHERE vehicle=? AND section='telemetry_remote'", (row["vehicle"],)).fetchone()
        at = observed[0] if observed else now
        db.execute("UPDATE temporary_collections SET status='restored_verified',error=NULL,updated=?,lease_owner=NULL,lease_until=0 WHERE intent_id=?", (now, row["intent_id"]))
        db.execute("INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?)", (row["vehicle"], "telemetry_target", canonical(plan["baseline_config"]), "tesla_api", at, at))
        if plan["baseline_saved"] is not None:
            db.execute("INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?)", (row["vehicle"], "telemetry_saved", canonical(plan["baseline_saved"]), "owner_request", now, now))
        db.execute("INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?)",
                   (row["vehicle"], "telemetry_preview", canonical({"hours": plan["baseline_hours"], "restored_from": row["intent_id"]}), "owner_request", now, now))
        for identifier in (row["intent_id"], row["restore_intent"]):
            if identifier:
                evidence = ({"configuration_verified": True, "acceptance_unknown": True, "source": "temporary_restore_readback"} if identifier == row["restore_intent"] else
                            {"baseline_restored_verified": True, "start_effect_unknown": True, "source": "temporary_restore_readback"})
                # Baseline observation resolves the obligation but cannot prove
                # that an uncertain initial temporary write was ever accepted.
                db.execute("UPDATE intents SET status='reconciled',result=? WHERE id=? AND status IN ('sending','unknown')",
                           (canonical(evidence), identifier))
