"""Explain trigger prerequisites without changing acquisition or polling Tesla.

Collection coverage describes the last synchronized readback, not a guarantee
of current vehicle connectivity. Several rules for one event are alternatives;
the fields within a rule are all required. Diagnostics never suppress a real
event (in particular an intentional data-stale event).
"""
from .collection_state import read_collection
from .profiles import effective_fields, included_sources
from .trigger_catalog import RULE_EVENTS, RULE_FIELDS


def collection_evidence(view, now):
    remote, target = view["remote"], view["target"]
    last = view["last"] or {}
    verified = bool(remote and remote["at"] >= target.get("at", 0)
                    and remote.get("data", {}).get("synced") is True
                    and last.get("status") not in ("sending", "unknown"))
    return {"state": view["state"], "verified": verified,
            "reason": view["evidence"]["reason"], "configuration_matches_target": view["evidence"]["configuration_matches_target"],
            "provider_synced": view["evidence"]["provider_synced"],
            "basis": "last_synchronized_readback", "checked_at": remote.get("at"),
            "age_seconds": max(0, now-remote["at"]) if remote else None,
            "pending_change": view["blocked"],
            "note": 'Latest cached check: not a live read. A saved or requested profile does not prove application.'}


def rule_requirement(rule):
    config, kind = rule["config"], rule["kind"]
    fields = RULE_FIELDS.get(kind, [config.get("field")])
    age = config["max_age_seconds"]
    # Multi-field rules also require observations no more than 30 seconds apart.
    coherence = 30 if kind in ("unlocked_parked", "geofence") else None
    horizon = min(age, config["max_gap_seconds"], coherence or age)
    return {"rule_id": rule["id"], "kind": kind, "fields": [f for f in fields if f],
            "max_age_seconds": age, "coherence_seconds": coherence,
            "suggested_max_interval_seconds": max(1, int(horizon/2)),
            "max_gap_seconds": config["max_gap_seconds"], "customer_alerts": False}


def requirements(item, rules):
    key = item["id"]
    if key.startswith("field:"):
        return [{"rule_id": None, "kind": "field", "fields": [key[6:]], "max_age_seconds": 300,
                 "coherence_seconds": None, "suggested_max_interval_seconds": 150,
                 "max_gap_seconds": None, "customer_alerts": False}]
    selected = [r for r in rules if (key == "rule:"+r["id"] if key.startswith("rule:")
                else key[6:] in RULE_EVENTS[r["kind"]]) and r["enabled"]]
    if selected:
        return [rule_requirement(r) for r in selected]
    if key in ("event:alert_started", "event:alert_ended", "event:connectivity_changed"):
        return [{"rule_id": None, "kind": "stream", "fields": [], "max_age_seconds": None,
                 "coherence_seconds": None, "suggested_max_interval_seconds": None,
                 "max_gap_seconds": None, "customer_alerts": key != "event:connectivity_changed"}]
    return []


def assess_path(requirement, evidence, config, latest, now):
    fields = config.get("fields", {}) if config else {}
    missing = [f for f in requirement["fields"] if f not in effective_fields(fields)] if evidence["verified"] else []
    alerts_missing = evidence["verified"] and requirement["customer_alerts"] and "customer" not in (config or {}).get("alert_types", [])
    observations = []
    warnings = []
    for name in requirement["fields"]:
        record = latest.get(name)
        age = now-record["source_at"] if record else None
        state = "missing" if not record else "invalid" if record["quality"] != "valid" or age < -0.001 else "fresh"
        if state == "fresh" and age > requirement["max_age_seconds"]:
            state = "stale"
        observations.append({"field": name, "status": state, "age_seconds": age,
                             "sample_quality": record["quality"] if record else None,
                             "reason": "explicit_park_not_observed" if name == "Gear" and state == "invalid" else None})
        opts = fields.get(name)
        if not opts:
            if name in included_sources(fields):
                warnings.append({"field": name, "reason": "included_only_no_independent_interval", "parents": included_sources(fields)[name]})
            continue
        limit = requirement["suggested_max_interval_seconds"]
        interval, resend = opts.get("interval_seconds"), opts.get("resend_interval_seconds")
        # These are risks, not a claim that telemetry sends periodically.
        if not isinstance(interval, (int, float)) or interval > limit or resend is None or resend > limit:
            warnings.append({"field": name, "reason": "timing_may_leave_gaps",
                             "suggested_max_interval_seconds": limit,
                             "interval_seconds": interval, "resend_interval_seconds": resend})
    if not evidence["verified"]:
        coverage = "unverified"
    elif not config:
        coverage = "paused"
    elif missing or alerts_missing:
        coverage = "missing"
    else:
        coverage = "covered"
    if not observations:
        observation = "event_driven"
    elif requirement["kind"] == "stale":
        # Old observations are precisely the input to a stale-data rule.
        observation = "available" if all(o["status"] != "missing" for o in observations) else "missing"
    else:
        observation = next((s for s in ("missing", "invalid", "stale") if any(o["status"] == s for o in observations)), "fresh")
        if observation == "fresh" and requirement["coherence_seconds"] is not None:
            ages = [o["age_seconds"] for o in observations]
            if max(ages)-min(ages) > requirement["coherence_seconds"]:
                observation = "incoherent"
    return {**requirement, "coverage": coverage, "missing_fields": missing,
            "customer_alerts_missing": bool(alerts_missing), "observations": observations,
            "observation_status": observation, "timing_warnings": warnings}


def annotate(store, ref, items, rules, latest):
    now = store.clock()
    view = read_collection(store, ref)
    evidence = collection_evidence(view, now)
    config = view["remote"].get("data", {}).get("config")
    for item in items:
        paths = requirements(item, rules) if item["available"] else []
        paths = [assess_path(r, evidence, config, latest, now) for r in paths]
        # Prefer a covered/observed alternative; do not require every rule to run.
        paths.sort(key=lambda p: (p["coverage"] != "covered", len(p["missing_fields"])+p["customer_alerts_missing"],
                                 p["observation_status"] not in ("fresh", "available", "event_driven"),
                                 len(p["timing_warnings"]), p["rule_id"] or ""))
        best = paths[0] if paths else None
        status = ("permission_required" if not item["available"] else "rule_required" if not best
                  else "collection_"+best["coverage"] if best["coverage"] != "covered"
                  else "data_"+best["observation_status"] if best["observation_status"] not in ("fresh", "available", "event_driven")
                  else "timing_warning" if best["timing_warnings"] else "inputs_available")
        item["readiness"] = {"status": status, "paths": paths,
                             "collection_reason": evidence["reason"],
                             "missing_fields": best["missing_fields"] if best else [],
                             "customer_alerts_missing": best["customer_alerts_missing"] if best else False,
                             "can_propose_collection": bool(best and evidence["verified"] and not view["blocked"]),
                             "selection_is_not_readiness": True}
        item["source_ready"] = status == "inputs_available"
    return evidence


def collection_impact(items, fields, customer_alerts):
    """Predict acquisition coverage only; never predict future observations."""
    config = {"fields": fields, "alert_types": ["customer"] if customer_alerts else []} if fields else None
    issues, selected = [], 0
    for item in items:
        if not item["enabled"] or item["id"].startswith("rule:"):
            continue
        selected += 1
        paths = [assess_path(p, {"verified": True}, config, {}, 0) for p in item["readiness"]["paths"]]
        paths.sort(key=lambda p: (p["coverage"] != "covered", len(p["missing_fields"])+p["customer_alerts_missing"], len(p["timing_warnings"])))
        best = paths[0] if paths else None
        if not best or best["coverage"] != "covered" or best["timing_warnings"]:
            issues.append({"trigger_id": item["id"], "label": item["label"],
                           "reason": "permission_required" if not item["available"] else "rule_required" if not best
                           else "collection_"+best["coverage"] if best["coverage"] != "covered" else "timing_warning",
                           "missing_fields": best["missing_fields"] if best else [],
                           "customer_alerts_missing": best["customer_alerts_missing"] if best else False})
    return {"selected_count": selected, "issues": issues, "future_delivery_guaranteed": False,
            "note": 'Proposal compatibility with selected events; does not change events, rules or subscriptions. Valid, fresh data will be required.'}
