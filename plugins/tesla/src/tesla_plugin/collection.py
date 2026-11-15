"""Owner-controlled acquisition; trigger selection is deliberately independent."""
import json
from copy import deepcopy

from .errors import TeslaError
from .profiles import profile_fields, estimate, full_profile, effective_fields
from .store import canonical, digest
from .telemetry import FIELD_MAP
from .collection_catalog import CONTROLS, catalogue_page
from .collection_state import CREATE, DELETE, matches_config, read_collection, check_trigger_revision
from .diagnostics import impact_page
from .field_capabilities import context, selectable, select_maximum


def collection_enabled(store):
    """Only accepted acquisition requests enable the consumer's provider reads."""
    with store.db() as db:
        rows = db.execute("SELECT s.data,s.received,r.data AS remote,r.received AS checked FROM snapshots s JOIN vehicles v ON v.ref=s.vehicle "
                          "JOIN connection c ON c.id=1 LEFT JOIN snapshots r ON r.vehicle=s.vehicle AND r.section='telemetry_remote' "
                          "WHERE s.section='telemetry_target' AND v.active=1 AND c.status='active'").fetchall()
    for row in rows:
        value = json.loads(row["data"])
        if row["remote"] and row["checked"] >= row["received"]:
            remote = json.loads(row["remote"])
            if remote.get("synced") is True and remote.get("config") is None:
                continue
        if isinstance(value, dict) and value.get("fields"):
            return True
    return False


class Collection:
    def __init__(self, service):
        self.service, self.store = service, service.store

    def view(self, ref, *, include_fields=False, scopes=None):
        self.service.vehicle(ref, refresh_membership=False)
        view = read_collection(self.store, ref)
        from .temporary_collection import latest
        view['temporary_collection'] = latest(self.store, ref)
        view['vehicle_context'] = context(self.store, ref)
        if include_fields:
            from .collection_evidence import field_evidence
            from .trigger_catalog import location_allowed
            allowed = location_allowed(self.store.connection(), self.store.vehicle(ref),
                                       self.service.settings.allowed_scopes if scopes is None else scopes)
            view["field_evidence"] = field_evidence(self.store, ref, view, location_authorized=allowed)
        return view

    def check_revision(self, ref, revision):
        view = self.view(ref)
        if revision != view["revision"]:
            raise TeslaError("REVISION_CONFLICT", 'Collection changed. Reload the panel before preparing a change.')
        if view["blocked"]:
            raise TeslaError("OPERATION_PENDING", 'Review the pending request before preparing another. An uncertain outcome must not be repeated.')
        return view

    def refresh(self, ref, scopes):
        # Explicit owner read: never wake and never run a recurring API poll.
        before = self.view(ref)["last"]
        authorization = self.service.fleet.authorization()
        result = self.service.read("vehicle_fleet_telemetry_config_get", {}, ref, scopes, _authorization=authorization)
        if before and before["status"] == "unknown" and result["data"]["synced"]:
            item = self.store.intent(before["id"])
            expected = item["arguments"].get("config") if item["operation"] == CREATE else None
            if matches_config(expected, result["data"]["config"]):
                with self.store.db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    self.store.assert_authorization(db, authorization)
                    remote = db.execute("SELECT data,received FROM snapshots WHERE vehicle=? AND section='telemetry_remote'", (ref,)).fetchone()
                    latest = json.loads(remote['data']) if remote else {}
                    if latest.get('synced') is not True or not matches_config(expected, latest.get('config')):
                        return result  # A concurrent read superseded this evidence.
                    status = "reconciled"
                    evidence = {"configuration_verified": True, "source": "explicit_readback", "acceptance_unknown": True}
                    changed = db.execute("UPDATE intents SET status=?,result=? WHERE id=? AND status='unknown'",
                                         (status, canonical(evidence), before["id"])).rowcount
                    if changed:
                        from .temporary_collection import supersede_after_owner_change
                        supersede_after_owner_change(db, item, remote['received'])
                        # The readback resolves this exact intent. Keep its observation
                        # time and save the approved profile atomically; a later target
                        # timestamp would incorrectly make this readback look outdated.
                        at = remote['received']
                        temporary = db.execute("SELECT 1 FROM temporary_collections WHERE intent_id=?", (before["id"],)).fetchone()
                        for section in ("telemetry_target", "telemetry_saved") if expected and not temporary else ("telemetry_target",):
                            db.execute("INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?)",
                                       (ref, section, canonical(expected), "tesla_api", at, at))
        from .temporary_collection import TemporaryCollection
        TemporaryCollection(self.service).observe(ref, authorization)
        return result

    @staticmethod
    def form_profile(form):
        selected = form.getlist("field")
        if not selected or len(selected) != len(set(selected)):
            raise TeslaError("INVALID_ARGUMENT", 'Choose at least one field. Use Pause collection to stop collection.')
        fields = {}
        try:
            for name in selected:
                if name not in FIELD_MAP or not selectable(FIELD_MAP[name]):
                    raise ValueError()
                options = {"interval_seconds": int(form.get("interval_"+name, ""))}
                for prefix, parameter in (("resend_", "resend_interval_seconds"), ("delta_", "minimum_delta")):
                    raw = form.get(prefix+name, "")
                    if raw:
                        options[parameter] = float(raw) if parameter == "minimum_delta" else int(raw)
                included = form.get("include_"+name, "").strip()
                if included:
                    options["include_fields"] = [f.strip() for f in included.split(",")]
                fields[name] = options
            hours = float(form.get("hours", "8"))
        except (ValueError, TypeError):
            raise TeslaError("INVALID_ARGUMENT", 'Check selected fields and numeric interval values.') from None
        profile_fields("custom", fields)
        estimate(fields, hours)
        return fields, form.get("customer_alerts") == "on", hours

    def prepare(self, ref, form, scopes):
        action = form.get("collection_action")
        options = {}
        if action == "configure":
            fields, alerts, hours = self.form_profile(form)
            options = dict(preset="custom", custom_fields=fields, customer_alerts=alerts, active_hours_per_day=hours)
            raw_duration = form.get("duration_seconds", "")
            if raw_duration:
                try:
                    options["duration_seconds"] = int(raw_duration)
                except (ValueError, TypeError):
                    raise TeslaError("INVALID_ARGUMENT", 'Invalid temporary duration.') from None
            if form.get("trigger_revision") is not None:
                try:
                    options["expected_trigger_revision"] = int(form["trigger_revision"])
                except ValueError:
                    raise TeslaError("INVALID_ARGUMENT", 'Invalid event revision.') from None
        return self.prepare_change(ref, action, form.get("revision"), form.get("request_id", ""), scopes, **options)

    @staticmethod
    def scenario(preset, custom_fields=None, active_hours_per_day=8, customer_alerts=None, *, vehicle_context=None):
        if preset == "on_demand":
            if custom_fields is not None or customer_alerts:
                raise TeslaError("INVALID_ARGUMENT", 'On-demand mode does not provide streaming or automatic alerts.')
            fields, alerts = {}, False
        else:
            fields = profile_fields(preset, custom_fields, vehicle_context=vehicle_context)
            alerts = preset in ("normal", "recommended") if customer_alerts is None else customer_alerts
        if type(alerts) is not bool:
            raise TeslaError("INVALID_ARGUMENT", "Invalid customer alerts option")
        selection = select_maximum(full_profile(), vehicle_context)[1] if preset == 'full' else None
        return {"preset": preset, "fields": fields, "customer_alerts": alerts, 'selection_review': selection,
                "estimate": estimate(fields, active_hours_per_day), "continuous_estimate": estimate(fields, 24),
                "field_estimates": {name: {key: value for key, value in estimate({name: options}, active_hours_per_day).items()
                                           if key in ("planned_signals_30_days", "estimated_gross_usd")}
                                    for name, options in fields.items()},
                "controls": CONTROLS,
                "tesla_requests": 0, "vehicle_actuations": 0,
                "note": 'Streaming-only estimate. On-demand reads, alerts, retransmissions, taxes and the Tesla discount are excluded.'}

    def _prepared_request(self, key, fingerprint):
        """Recover the immutable request before stale-form/pending checks."""
        from .collection_state import review_state
        with self.store.db() as db:
            db.execute("BEGIN")
            item = db.execute("SELECT * FROM intents WHERE client_key=?", (key,)).fetchone()
            if item is None:
                return None
            preview, complete = review_state(db, item)
        if preview.get("request_fingerprint") != fingerprint:
            raise TeslaError("IDEMPOTENCY_CONFLICT", "Request ID already identifies a different collection request")
        if not complete:
            raise TeslaError("COLLECTION_REVIEW_INCOMPLETE", 'The collection review is incomplete. Cancel this request and prepare it again.')
        return {**self.service.intent_view(item["id"]), "estimate": preview.get("estimate"),
                "selection_review": preview.get("selection_review"), "retention_days": self.service.settings.history_days}

    def prepare_change(self, ref, action, revision, key, scopes, *, preset=None, custom_fields=None,
                       active_hours_per_day=None, customer_alerts=None, access_expires=None, expected_trigger_revision=None,
                       duration_seconds=None):
        from .service import require
        require(scopes, "tesla:manage", "tesla:commands")
        from .temporary_collection import validate_duration, plan_for
        validate_duration(duration_seconds)
        if duration_seconds is not None and (action != "configure" or preset == "on_demand"):
            raise TeslaError("INVALID_ARGUMENT", 'A temporary duration requires configuring a streaming profile.')
        self.service.vehicle(ref, refresh_membership=False)
        request_hours = 8 if active_hours_per_day is None else active_hours_per_day
        if type(request_hours) in (int, float):
            request_hours = float(request_hours)
        request_alerts = (preset in ("normal", "recommended") if customer_alerts is None else customer_alerts) if action == "configure" else customer_alerts
        request_fingerprint = digest(canonical([ref, action, preset, custom_fields,
            request_hours, request_alerts,
            expected_trigger_revision, duration_seconds, sorted(scopes), self.store.connection()["generation"]]))
        existing = self._prepared_request(key, request_fingerprint)
        if existing is not None:
            return existing
        try:
            view = self.check_revision(ref, revision)
        except TeslaError:
            # An identical concurrent preparation may have committed since the
            # first lookup; recover it rather than reject its now-stale form.
            existing = self._prepared_request(key, request_fingerprint)
            if existing is not None:
                return existing
            raise
        with self.store.db() as db:
            check_trigger_revision(db, ref, expected_trigger_revision)
        if action in ("pause", "resume") and any(x is not None for x in (preset, custom_fields, customer_alerts, active_hours_per_day)):
            raise TeslaError("INVALID_ARGUMENT", 'Pause and resume use the saved profile without new parameters.')
        active_hours_per_day = 8 if active_hours_per_day is None else active_hours_per_day
        selection_review = None
        if action == "pause" or (action == "configure" and preset == "on_demand"):
            if action == "configure":
                self.scenario(preset, custom_fields, active_hours_per_day, customer_alerts)
            preview = {"request_fingerprint": request_fingerprint}
            if expected_trigger_revision is not None:
                preview["trigger_revision"] = expected_trigger_revision
            return self.service.prepare(DELETE, {}, ref, key, scopes, access_expires=access_expires,
                                        collection_revision=revision, trigger_revision=expected_trigger_revision,
                                        collection_preview=preview)
        if action == "resume":
            saved = view["saved"]
            if not saved or not saved.get("fields"):
                raise TeslaError("INVALID_ARGUMENT", 'There is no saved profile to resume yet.')
            fields, alerts, hours = deepcopy(saved["fields"]), "customer" in saved.get("alert_types", []), view["hours"]
        elif action == "configure":
            scenario = self.scenario(preset, custom_fields, active_hours_per_day, customer_alerts, vehicle_context=view['vehicle_context'])
            fields, alerts, hours = scenario["fields"], scenario["customer_alerts"], active_hours_per_day
            selection_review = scenario['selection_review']
        else:
            raise TeslaError("INVALID_ARGUMENT", 'Invalid collection action.')
        # Validate before any provider request; the service repeats validation.
        profile_fields("custom", fields)
        estimate(fields, hours)
        temporary_plan = None
        if duration_seconds is not None:
            require(scopes, "tesla:read")
            temporary_plan = plan_for(self.service, ref, view, duration_seconds, fields, scopes)
        return self.service.prepare_profile(ref, "custom", fields, key, scopes,
                                            active_hours_per_day=hours, customer_alerts=alerts, access_expires=access_expires,
                                            collection_revision=revision, trigger_revision=expected_trigger_revision,
                                            selection_review=selection_review, temporary_plan=temporary_plan,
                                            request_fingerprint=request_fingerprint)

    def review(self, ref, identifier, *, impact_scope="events", impact_offset=0, impact_limit=20):
        item = self.store.intent(identifier)
        if item["vehicle"] != ref or item["operation"] not in (CREATE, DELETE):
            raise TeslaError("INVALID_ARGUMENT", 'Chat confirmation applies only to collection for this vehicle.')
        from .collection_state import review_state
        with self.store.db() as db:
            preview, complete = review_state(db, item)
            temporary = db.execute("SELECT * FROM temporary_collections WHERE intent_id=?", (identifier,)).fetchone()
        config = item["arguments"].get("config", {})
        result = {"intent_id": identifier, "vehicle_ref": ref, "status": item["status"], "expires": item["expires"],
                  "action": "configure" if item["operation"] == CREATE else "pause", "fields": config.get("fields", {}),
                  "customer_alerts": "customer" in config.get("alert_types", []),
                  "review_complete": complete,
                  "estimate": (preview.get("estimate") if item["operation"] == CREATE else estimate({}, 8)) if complete else None,
                  "selection_review": preview.get("selection_review") if complete else None,
                  "retention_days": self.service.settings.history_days, "result": item["result"],
                  "confirmation_url": self.service.intent_view(identifier)["confirmation_url"]}
        if result["status"] == "prepared" and item["expires"] <= self.store.clock():
            result["status"] = "expired"
        plan = json.loads(temporary["plan"]) if temporary else None
        if plan is not None:
            from .temporary_collection import public_plan
            result["temporary_collection"] = public_plan(plan, dict(temporary))
            if result["status"] in ("expired", "cancelled") and temporary["status"] == "prepared":
                result["temporary_collection"]["status"] = result["status"]
        # Immutable request + its own cost assumptions, never the latest form's.
        result["review_digest"] = digest(canonical([item["id"], item["vehicle"], item["operation"], item["arguments"],
                                                   item["generation"], item["expires"], preview, plan]))
        result["trigger_impact"] = impact_page(self.impact(ref, config.get("fields", {}), result["customer_alerts"], self.service.settings.allowed_scopes),
                                              scope=impact_scope, offset=impact_offset, limit=impact_limit)
        return result

    def cost_comparison(self, ref, scenario):
        view = self.view(ref)
        baseline = view["saved"]
        hours = scenario["estimate"]["active_hours_per_day"]
        previous = estimate(baseline.get("fields", {}), hours)["estimated_gross_usd"] if baseline is not None else None
        total = scenario["estimate"]["estimated_gross_usd"]
        return {"baseline_source": "saved_profile" if baseline is not None else "unavailable",
                "baseline_applied_verified": view["state"] == "active" and matches_config(baseline, view["remote"].get("data", {}).get("config")),
                "active_hours_per_day": hours, "days": 30, "currency": "USD",
                "previous_streaming_usd": previous, "proposed_streaming_usd": total,
                "delta_streaming_usd": round(total-previous, 4) if previous is not None else None,
                "billing_cap": False, "other_costs_included": False}

    def impact(self, ref, fields, alerts, scopes):
        from .triggers import Triggers
        from .trigger_dependencies import collection_impact
        view = Triggers(self.store).view(ref, scopes)
        return {**collection_impact(view["items"], fields, alerts), "trigger_revision": view["revision"]}

    def trigger_proposal(self, ref, trigger_ids, scopes):
        """A local, costed draft. Never switch a trigger, collect or poll implicitly."""
        from .triggers import Triggers
        from .trigger_catalog import LOCATION_FIELDS
        view = self.view(ref)
        triggers = Triggers(self.store).view(ref, scopes)
        items = {item["id"]: item for item in triggers["items"]}
        if trigger_ids == ["selected"]:
            trigger_ids = [key for key, item in items.items() if item["enabled"] and not key.startswith("rule:")]
        if (not trigger_ids or len(trigger_ids) > 512 or len(set(trigger_ids)) != len(trigger_ids)
                or any(key not in items for key in trigger_ids)):
            raise TeslaError("INVALID_ARGUMENT", 'Choose trigger IDs or selected for the current selection.')
        result = {"trigger_ids": trigger_ids, "expected_revision": view["revision"],
                  "expected_trigger_revision": triggers["revision"], "available": False,
                  "tesla_requests": 0, "vehicle_actuations": 0, "acquisition_changed": False}
        if view["blocked"] or not triggers["collection"]["verified"]:
            return {**result, "reason": 'Review the pending request or verify Tesla state before proposing a change to existing collection.'}
        baseline = view["remote"].get("data", {}).get("config") or {}
        fields = deepcopy(baseline.get("fields", {}))
        baseline_alerts = "customer" in baseline.get("alert_types", [])
        alerts, defaults, unresolved = baseline_alerts, full_profile(), []
        can_locate = self.public_view(ref, scopes)["location_authorized"]
        if effective_fields(fields) & LOCATION_FIELDS and not can_locate:
            return {**result, "reason": 'The existing profile includes location: the corresponding permission is required to prepare a change that preserves it.'}
        for key in trigger_ids:
            item = items[key]
            paths = item["readiness"]["paths"]
            if not item["available"] or not paths:
                unresolved.append({"trigger_id": key, "reason": item["readiness"]["status"]})
                continue
            path = paths[0]
            if set(path["fields"]) & LOCATION_FIELDS and not can_locate:
                unresolved.append({"trigger_id": key, "reason": "permission_required"})
                continue
            alerts = alerts or path["customer_alerts"]
            for name in path["fields"]:
                if name not in defaults:
                    unresolved.append({"trigger_id": key, "field": name, "reason": "field_not_usable"})
                    continue
                opts = fields.setdefault(name, deepcopy(defaults[name]))
                limit = path["suggested_max_interval_seconds"]
                opts["interval_seconds"] = min(opts["interval_seconds"], limit)
                opts["resend_interval_seconds"] = min(opts.get("resend_interval_seconds", limit), limit)
        if not fields:
            return {**result, "unresolved": unresolved, "reason": 'Choose at least one field to collect first; this event alone does not define a collection profile.'}
        scenario = self.scenario("custom", fields, view["hours"], alerts)
        before = estimate(baseline.get("fields", {}), view["hours"])
        changed = {name: {"before": baseline.get("fields", {}).get(name), "after": opts}
                   for name, opts in fields.items() if baseline.get("fields", {}).get(name) != opts}
        return {**result, **scenario, "available": True, "unresolved": unresolved, "changed_fields": changed,
                "customer_alerts_changed": alerts != baseline_alerts, "previous_estimate": before,
                "estimated_delta_usd": round(scenario["estimate"]["estimated_gross_usd"]-before["estimated_gross_usd"], 4),
                "note": 'Proposal requiring confirmation: preserves other fields and thresholds, adds required fields and adjusts timing. Does not enable events, rules or subscriptions. An awake vehicle and available data are still required; Tesla alerts are excluded from the estimate.'}

    def public_view(self, ref, scopes, *, include_catalog=False, catalog_search=None, catalog_offset=0, catalog_limit=50, for_triggers=None,
                    impact_scope="events", impact_offset=0, impact_limit=20, for_context=None):
        from .trigger_catalog import location_allowed
        view = self.view(ref, include_fields=True, scopes=scopes)
        can_locate = location_allowed(self.store.connection(), self.store.vehicle(ref), scopes)
        from .data_access import CHANNELS, CONTEXTS
        def profile(value):
            return None if value is None else {"fields": value.get("fields", {}), "customer_alerts": "customer" in value.get("alert_types", [])}
        remote = view["remote"].get("data", {})
        result = {"vehicle_ref": ref, "state": view["state"], "revision": view["revision"], "blocked": view["blocked"],
                "evidence": view["evidence"],
                "field_summary": view["field_evidence"]["summary"],
                "saved_profile": profile(view["saved"]), "observed_profile": profile(remote.get("config")),
                "observed_at": view["remote"].get("at"), "synced": remote.get("synced"), "last_sample_at": view["last_sample"],
                "active_hours_per_day": view["hours"], "location_authorized": can_locate,
                "temporary_collection": view["temporary_collection"],
                "last_request": self.review(ref, view["last"]["id"], impact_scope=impact_scope, impact_offset=impact_offset, impact_limit=impact_limit) if view["last"] else None,
                "retention_days": self.service.settings.history_days, "vehicle_actuations": 0,
                "presets": ["normal", "travel", "charging", "diagnostic", "on_demand", "recommended", "essential", "notifications", "journeys", "comfort", "drive_diagnostics", "full", "custom"],
                "vehicle_context": view['vehicle_context'],
                "controls": CONTROLS, 'data_channels': CHANNELS, 'available_contexts': list(CONTEXTS)}
        if for_context is not None:
            if for_context not in CONTEXTS:
                raise TeslaError('INVALID_ARGUMENT', 'Choose a documented data context')
            use = CONTEXTS[for_context]
            proposal = self.scenario(use['preset'], active_hours_per_day=view['hours'], vehicle_context=view['vehicle_context'])
            result['context_proposal'] = {**use, **proposal, 'cost_comparison': self.cost_comparison(ref, proposal),
                                           'proposal_only': True, 'applied': False}
        if include_catalog:
            result["catalog"] = catalogue_page(catalog_search, catalog_offset, catalog_limit, location_authorized=can_locate,
                                                evidence=view["field_evidence"]["fields"], vehicle_context=view['vehicle_context'])
        if for_triggers:
            result["trigger_proposal"] = self.trigger_proposal(ref, for_triggers, scopes)
        return result

    def resolve(self, ref, identifier, review_digest, decision, scopes):
        from .service import require
        require(scopes, "tesla:manage", "tesla:commands")
        self.service.vehicle(ref, refresh_membership=False)
        review = self.review(ref, identifier)
        if review_digest != review["review_digest"]:
            raise TeslaError("REVISION_CONFLICT", 'The review does not match the request: read it again before confirmation.')
        if decision == "confirm":
            self.service.execute_collection_from_chat(identifier, scopes)
        elif decision == "cancel":
            with self.store.db() as db:
                db.execute("UPDATE intents SET status='cancelled' WHERE id=? AND vehicle=? AND status='prepared'", (identifier, ref))
                db.execute("UPDATE temporary_collections SET status='cancelled',updated=? WHERE intent_id=? AND status='prepared'", (self.store.clock(), identifier))
        else:
            raise TeslaError("INVALID_ARGUMENT", "Choose confirm or cancel")
        return self.review(ref, identifier)
