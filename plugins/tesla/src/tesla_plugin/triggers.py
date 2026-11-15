"""One durable trigger selection shared by owner forms, MCP and the worker."""
import json

from .errors import TeslaError
from .store import canonical, digest, utc
from .value_semantics import json_equal
from .trigger_dependencies import annotate
from .trigger_status import operational_status, operational_summary
from .delivery_access import POLICY, diagnostics as access_diagnostics
from .telemetry_privacy import contains_location
from .trigger_catalog import (BASE_RULES, EVENT_KINDS, EVENT_LABELS, FIELD_MAP, LOCATION_EVENTS,
                              LOCATION_FIELDS, RULE_DEFAULTS, RULE_EVENTS, RULE_FIELDS, location_allowed)

RECOMMENDED_EVENTS = frozenset({"battery_low", "charge_stopped", "charge_completed", "unlocked_parked",
                                "alert_started", "alert_ended", "software_changed"})
RECOMMENDED_RULES = frozenset({"battery_low", "charging", "unlocked_parked", "software"})


def preset_selection(items, preset):
    if preset not in ("recommended", "all", "none"):
        raise TeslaError("INVALID_ARGUMENT", "Unknown trigger preset")
    rules = {}
    for item in sorted(items, key=lambda i: (not i.get("preset", False), i["id"])):
        if item["id"].startswith("rule:") and item["available"]:
            rules.setdefault(item["label"], item["id"])
    recommended = {"event:"+kind for kind in RECOMMENDED_EVENTS} | {v for k, v in rules.items() if k in RECOMMENDED_RULES}
    return {item["id"]: item["available"] and (preset == "all" or (preset == "recommended" and item["id"] in recommended))
            for item in items}


def preset_id(ref, kind):
    return "rule_"+digest(ref+":"+kind)[:24]


def initialize(db, ref):
    if db.execute("SELECT 1 FROM trigger_settings WHERE vehicle=?", (ref,)).fetchone():
        return
    db.execute("INSERT INTO trigger_settings VALUES(?,0,60)", (ref,))
    db.executemany("INSERT INTO trigger_preferences VALUES(?,?,1)",
                   [(ref, "event:"+kind) for kind in EVENT_KINDS if kind not in ("telemetry_changed", "location_changed")])
    # Respect previously configured rules when adopting a schema-1 database.
    for kind, config in BASE_RULES.items():
        if not db.execute("SELECT 1 FROM rules WHERE vehicle=? AND kind=?", (ref, kind)).fetchone():
            db.execute("INSERT INTO rules VALUES(?,?,?,?,?,1)",
                       (preset_id(ref, kind), ref, kind, canonical(RULE_DEFAULTS | config), "{}"))


def bump(db, ref, source, changes, now):
    db.execute("UPDATE trigger_settings SET revision=revision+1 WHERE vehicle=?", (ref,))
    revision = db.execute("SELECT revision FROM trigger_settings WHERE vehicle=?", (ref,)).fetchone()[0]
    db.execute("INSERT INTO trigger_audit VALUES(?,?,?,?,?)", (ref, revision, source, canonical(changes), now))
    return revision


def cancel_rule_deliveries(db, ref, rule_id):
    db.execute("UPDATE deliveries SET state='cancelled' WHERE state IN ('pending','sending') AND event IN "
               "(SELECT id FROM events WHERE vehicle=? AND json_extract(data,'$.rule_id')=?)", (ref, rule_id))


class Triggers:
    def __init__(self, store):
        self.store = store

    def view(self, ref, scopes):
        try:
            connection = self.store.connection()
        except TeslaError:
            connection = None
        vehicle = self.store.vehicle(ref)
        allowed_location = location_allowed(connection, vehicle, scopes)
        with self.store.db() as db:
            settings = dict(db.execute("SELECT * FROM trigger_settings WHERE vehicle=?", (ref,)).fetchone())
            preferences = {r["id"]: bool(r["enabled"]) for r in db.execute("SELECT * FROM trigger_preferences WHERE vehicle=?", (ref,))}
            rules = [dict(r) for r in db.execute("SELECT * FROM rules WHERE vehicle=? ORDER BY id", (ref,))]
            latest = {r["field"]: dict(r) for r in db.execute("SELECT field,source_at,quality FROM latest WHERE vehicle=?", (ref,))}
            subscription_rows = [dict(r) for r in db.execute("SELECT id,filters,expires FROM subscriptions WHERE active=1 AND expires>?", (self.store.clock(),))]
            subscriptions = [json.loads(r["filters"]) for r in subscription_rows]
            delivery_counts = {r[0]: r[1] for r in db.execute("SELECT d.state,count(*) FROM deliveries d JOIN events e ON e.id=d.event WHERE e.vehicle=? GROUP BY d.state", (ref,))}
            recent_deliveries = {r[0]: r[1] for r in db.execute("SELECT d.state,count(*) FROM deliveries d JOIN events e ON e.id=d.event WHERE e.vehicle=? AND e.occurred>=? GROUP BY d.state", (ref, self.store.clock()-86400))}
            observed_count = db.execute("SELECT count(*) FROM events WHERE vehicle=?", (ref,)).fetchone()[0]
        subscribed = set().union(*(set(s["kinds"]) for s in subscriptions if s["vehicle_ref"] == ref))
        by_event = {}
        for rule in rules:
            rule["config"] = json.loads(rule["config"])
            for event in RULE_EVENTS[rule["kind"]]:
                by_event.setdefault(event, []).append(rule)
        items = []
        for kind, label in EVENT_LABELS.items():
            # These are transport envelopes; individual field switches govern them.
            if kind in ("telemetry_changed", "location_changed"):
                continue
            sources = by_event.get(kind, [])
            fields = sorted({f for r in sources for f in RULE_FIELDS.get(r["kind"], [r["config"].get("field")]) if f})
            ready = kind in ("alert_started", "alert_ended", "connectivity_changed") or any(r["enabled"] for r in sources)
            items.append({"id": "event:"+kind, "label": label, "category": 'Primary', "enabled": preferences.get("event:"+kind, True),
                          "requires_location": kind in LOCATION_EVENTS, "available": kind not in LOCATION_EVENTS or allowed_location,
                          "source_fields": fields, "source_ready": ready, "subscribed": kind in subscribed})
        for field, spec in FIELD_MAP.items():
            if spec["catalog_status"] != "DOCUMENTED":
                continue
            is_location = field in LOCATION_FIELDS
            record = latest.get(field) if not is_location or allowed_location else None
            items.append({"id": "field:"+field, "label": field, "category": spec["category"],
                          "enabled": preferences.get("field:"+field, False), "requires_location": is_location,
                          "available": not is_location or allowed_location, "source_fields": [field],
                          "source_ready": record is not None, "last_observed_at": record["source_at"] if record else None,
                          "observed_age_seconds": max(0, self.store.clock()-record["source_at"]) if record else None,
                          "quality": record["quality"] if record else None,
                          "subscribed": ("location_changed" if is_location else "telemetry_changed") in subscribed})
        for rule in rules:
            is_location = rule["kind"] == "geofence" or rule["config"].get("field") in LOCATION_FIELDS
            items.append({"id": "rule:"+rule["id"], "label": rule["kind"], "category": 'Rules',
                          "enabled": bool(rule["enabled"]), "requires_location": is_location, "available": not is_location or allowed_location,
                          "config": rule["config"] if not is_location or allowed_location else None,
                          "source_fields": RULE_FIELDS.get(rule["kind"], [rule["config"].get("field")]),
                          "source_ready": True, "preset": rule["id"] == preset_id(ref, rule["kind"]),
                          "event_kinds": list(RULE_EVENTS[rule["kind"]])})
        collection = annotate(self.store, ref, items, rules, latest)
        # Subscriptions may be created before data arrives. Missing acquisition
        # must be reported, not remove a selected event from the requested stream.
        required = {i["id"][6:] for i in items if i["id"].startswith("event:") and i["enabled"] and i["available"]}
        for item in items:
            if item["id"].startswith("field:") and item["enabled"] and item["available"]:
                required.add("location_changed" if item["requires_location"] else "telemetry_changed")
        streams = len({"location" if i["requires_location"] else "general" for i in items if i["id"].startswith("field:") and i["enabled"] and i["available"]})
        selection = {item["id"]: item["enabled"] for item in items}
        active_preset = next((p for p in ("none", "recommended", "all") if preset_selection(items, p) == selection), "custom")
        # The host subscribes once to all authorized kinds. The shared selector
        # remains the delivery gate (emit AND dispatch), including future edits.
        # A transport subscription never enables a selector or changes collection.
        authorized = set(EVENT_KINDS) - (set() if allowed_location else LOCATION_EVENTS)
        delivery_state = ("not_connected" if not subscribed else "partial" if required-subscribed
                          else "selected_only" if authorized-subscribed else "shared")
        delivery_connection = {"state": delivery_state, "selection_shared": True,
            "selected_kinds_covered": bool(subscribed) and not bool(required-subscribed),
            "future_selection_covered": bool(subscribed) and not bool(authorized-subscribed),
            "setup_required": delivery_state != "shared", "host_renewal_required": True,
            "subscription_plan": {"available": bool(connection) and "tesla:events" in scopes,
                "name": "tesla.vehicle_event", "arguments": {"vehicle_ref": ref, "kinds": sorted(authorized)},
                "selection_changed": False, "acquisition_changed": False},
            "note": "One shared selection for panel and chat. Subscribe to all authorized kinds once and renew through the host; the server forwards only selected events. Delivery does not prove ChatGPT processing."}
        membership_fresh = bool(connection) and 0 <= self.store.clock()-vehicle["checked"] <= 300
        access = access_diagnostics(self.store, ref, connection)
        selected_events = {i["id"][6:] for i in items if i["id"].startswith("event:") and i["enabled"]}
        for item in items:
            item["operational"] = operational_status(item, connected=bool(connection), membership_fresh=membership_fresh,
                                                     access=access, subscribed=subscribed, selected_events=selected_events)
        delivery_connection["subscriptions"] = [{"id": row["id"], "refreshBefore": utc(row["expires"])}
                                                  for row in subscription_rows if json.loads(row["filters"])["vehicle_ref"] == ref]
        delivery_pipeline = {"blocking_reasons": (["native_subscription_missing"] if not subscribed else [])+
                             (["membership_check_stale"] if not membership_fresh else []),
                             "webhook_accepted": delivery_counts.get("accepted", 0),
                             "chatgpt_activation_verified": False, "user_notification_verified": False,
                             "stages": {
                                 "observed": {"state": "recorded_locally", "count": observed_count},
                                 "forwarded": {"state": "accepted_by_host", "count": delivery_counts.get("accepted", 0)},
                                 "processed": {"state": "not_observable_by_plugin", "evidence_required": "host_execution"},
                                 "notified": {"state": "not_observable_by_plugin", "evidence_required": "host_message_or_user_confirmation"}},
                             "legacy_verification_flags": "False means not attested by this plugin, not a failed or absent host notification.",
                             "delivery_semantics": "at_least_once_deduplicate_event_id",
                             "automatic_provider_polling_added": False}
        return {"vehicle_ref": ref, "revision": settings["revision"], "batch_seconds": settings["batch_seconds"],
                "selection_preset": active_preset, "recommended_event_kinds": sorted(RECOMMENDED_EVENTS),
                "items": items, "total": len(items), "subscription_active": bool(subscribed),
                "delivery_connection": delivery_connection,
                "delivery_pipeline": delivery_pipeline,
                "operational_summary": operational_summary(items),
                "operational_summary_scope": "all_selectors",
                "delivery_access": access,
                "required_event_kinds": sorted(required), "unsubscribed_event_kinds": sorted(required-subscribed),
                "tesla_connected": bool(connection), "membership_fresh": membership_fresh,
                "delivery_counts": delivery_counts, "deliveries_last_24h": recent_deliveries,
                "additional_batch_envelopes_per_hour_max": streams*3600/settings["batch_seconds"],
                "collection": collection, "chatgpt_processing_verified": False, "vehicle_actuations": 0}

    def apply_preset(self, ref, preset, scopes, *, expected_revision, batch_seconds=None, automatic_access_checks=None, source="chatgpt"):
        view = self.view(ref, scopes)
        selected = preset_selection(view["items"], preset)
        changes = [{"trigger_id": item["id"], "enabled": selected[item["id"]]}
                   for item in view["items"] if selected[item["id"]] != item["enabled"]]
        result = self.update(ref, changes, scopes, expected_revision=expected_revision,
                             batch_seconds=view["batch_seconds"] if batch_seconds is None else batch_seconds,
                             automatic_access_checks=automatic_access_checks, source=source)
        return {**result, "selection_preset": preset,
                "unavailable_ids": [i["id"] for i in view["items"] if not i["available"]],
                "acquisition_changed": False, "rule_conditions_changed": False}

    def update(self, ref, changes, scopes, *, expected_revision, batch_seconds=None, automatic_access_checks=None, source="chatgpt"):
        if "tesla:manage" not in scopes:
            raise TeslaError("SCOPE_REQUIRED", "Trigger management requires tesla:manage")
        if (type(expected_revision) is not int or expected_revision < 0 or not isinstance(changes, list) or len(changes) > 512
                or (not changes and batch_seconds is None and automatic_access_checks is None) or source not in ("chatgpt", "owner_panel")
                or (automatic_access_checks is not None and type(automatic_access_checks) is not bool)
                or (batch_seconds is not None and (type(batch_seconds) is not int or not 10 <= batch_seconds <= 300))):
            raise TeslaError("INVALID_ARGUMENT", "Choose triggers and a valid revision or batching interval (10–300 seconds)")
        current = self.view(ref, scopes)
        catalogue = {r["id"]: r for r in current["items"]}
        normalized = {}
        for change in changes:
            if (not isinstance(change, dict) or set(change) != {"trigger_id", "enabled"} or type(change["enabled"]) is not bool
                    or not isinstance(change["trigger_id"], str) or change["trigger_id"] not in catalogue or change["trigger_id"] in normalized):
                raise TeslaError("INVALID_ARGUMENT", "Unknown, duplicate or invalid trigger")
            item = catalogue[change["trigger_id"]]
            if change["enabled"] and not item["available"]:
                raise TeslaError("LOCATION_WITHHELD", "This trigger requires location authorization")
            normalized[item["id"]] = change["enabled"]
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT revision FROM trigger_settings WHERE vehicle=?", (ref,)).fetchone()
            if not row or row[0] != expected_revision:
                raise TeslaError("REVISION_CONFLICT", "Trigger selection changed. Read it again before saving.")
            connection = db.execute("SELECT * FROM connection WHERE id=1 AND status='active'").fetchone()
            vehicle = db.execute("SELECT data FROM vehicles WHERE ref=? AND active=1", (ref,)).fetchone()
            if not vehicle:
                raise TeslaError("AUTH_REQUIRED", "Vehicle authorization changed")
            if not connection and (any(enabled for enabled in normalized.values()) or automatic_access_checks is True):
                raise TeslaError("AUTH_REQUIRED", "Reconnect Tesla before enabling triggers; disabling remains available")
            for key, enabled in normalized.items():
                if enabled and catalogue[key]["requires_location"] and not location_allowed(connection, {"data": json.loads(vehicle[0])}, scopes):
                    raise TeslaError("LOCATION_WITHHELD", "Location authorization changed")
                if key.startswith("rule:"):
                    if bool(catalogue[key]["enabled"]) != enabled:
                        db.execute("UPDATE rules SET enabled=?,state='{}' WHERE vehicle=? AND id=?", (int(enabled), ref, key[5:]))
                        cancel_rule_deliveries(db, ref, key[5:])
                else:
                    db.execute("INSERT INTO trigger_preferences VALUES(?,?,?) ON CONFLICT(vehicle,id) DO UPDATE SET enabled=excluded.enabled",
                               (ref, key, int(enabled)))
                if not enabled and key.startswith("event:"):
                    kind = key[6:]
                    db.execute("UPDATE deliveries SET state='cancelled' WHERE state IN ('pending','sending') AND event IN "
                               "(SELECT id FROM events WHERE vehicle=? AND name=?)", (ref, kind))
                if not enabled and key.startswith("field:"):
                    db.execute("DELETE FROM trigger_buffer WHERE vehicle=? AND field=?", (ref, key[6:]))
                    # A frozen batch must never be rewritten after signing/retrying.
                    # Cancel batches containing a disabled field, retaining history.
                    db.execute("UPDATE deliveries SET state='cancelled' WHERE state IN ('pending','sending') AND event IN "
                               "(SELECT e.id FROM events e,json_each(e.data,'$.changes') f WHERE e.vehicle=? "
                               "AND e.name IN ('telemetry_changed','location_changed') AND f.key=?)", (ref, key[6:]))
            if batch_seconds is not None:
                db.execute("UPDATE trigger_settings SET batch_seconds=? WHERE vehicle=?", (batch_seconds, ref))
            audit = {"triggers": normalized, "batch_seconds": batch_seconds}
            if automatic_access_checks is not None:
                policy = {"automatic": automatic_access_checks, "generation": connection["generation"] if connection else None}
                db.execute("INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?)",
                           (ref, POLICY, canonical(policy), source, self.store.clock(), self.store.clock()))
                audit["automatic_access_checks"] = automatic_access_checks
            revision = bump(db, ref, source, audit, self.store.clock())
        after = self.view(ref, scopes)
        return {"vehicle_ref": ref, "revision": revision, "changed": normalized, "batch_seconds": batch_seconds or current["batch_seconds"],
                "readiness": {i["id"]: i["readiness"] for i in after["items"] if i["id"] in normalized},
                "delivery_access": after["delivery_access"],
                "acquisition_changed": False,
                "vehicle_actuations": 0, "in_flight_callback_may_complete": True}


def record_change(db, ref, field, old, current, now):
    selected = db.execute("SELECT enabled FROM trigger_preferences WHERE vehicle=? AND id=?", (ref, "field:"+field)).fetchone()
    if not selected or not selected[0] or now-current["source_at"] > 300:
        return
    if old and old["quality"] == current["quality"] and json_equal(field, old["value"], current["value"]):
        return
    def observation(row):
        return {"value": json.loads(row["value"]), "quality": row["quality"], "source_at": row["source_at"], "received_at": row["received"]} if row else None
    pending = db.execute("SELECT data FROM trigger_buffer WHERE vehicle=? AND field=?", (ref, field)).fetchone()
    item = json.loads(pending[0]) if pending else {"before": observation(old), "first_observed_at": current["source_at"], "count": 0,
                                                 "includes_initial_observation": old is None}
    item.update(after=observation(current), count=item["count"]+1)
    db.execute("INSERT INTO trigger_buffer VALUES(?,?,?,?) ON CONFLICT(vehicle,field) DO UPDATE SET data=excluded.data",
               (ref, field, now, canonical(item)))


def flush_changes(db, now):
    from .events import Events
    vehicles = db.execute("SELECT b.vehicle,s.batch_seconds FROM trigger_buffer b JOIN trigger_settings s ON s.vehicle=b.vehicle "
                          "GROUP BY b.vehicle HAVING min(b.started)+s.batch_seconds<=?", (now,)).fetchall()
    for ref, interval in vehicles:
        vehicle = db.execute("SELECT data FROM vehicles WHERE ref=? AND active=1", (ref,)).fetchone()
        connection = db.execute("SELECT * FROM connection WHERE id=1 AND status='active'").fetchone()
        can_locate = bool(vehicle and connection and location_allowed(connection, {"data": json.loads(vehicle[0])}, ("tesla:location",)))
        groups = {"telemetry_changed": {}, "location_changed": {}}
        if vehicle and connection:
            for row in db.execute("SELECT * FROM trigger_buffer WHERE vehicle=?", (ref,)):
                data = json.loads(row["data"])
                # A configured five-minute batch needs scheduling tolerance;
                # do not classify its first observation as stale at flush time.
                private = row["field"] in LOCATION_FIELDS or contains_location(data)
                if now-data["after"]["source_at"] > max(300, interval+30) or (private and not can_locate):
                    continue
                groups["location_changed" if private else "telemetry_changed"][row["field"]] = data
            for kind, changes in groups.items():
                if changes:
                    # Timestamp describes batch creation. Each observation keeps its
                    # own source time; first observation is explicitly a snapshot.
                    Events.emit(db, ref, kind, now, {"changes": changes, "time_basis": "batch_created_at",
                        "first_observed_at": min(v["first_observed_at"] for v in changes.values()),
                        "intermediate_samples_in_history": True, "physical_continuity_guaranteed": False}, now)
        db.execute("DELETE FROM trigger_buffer WHERE vehicle=?", (ref,))
