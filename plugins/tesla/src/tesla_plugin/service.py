"""User-facing operations, immutable intents and capability checks."""
import base64
from copy import deepcopy
import json
import math
import re
import secrets
from cryptography.fernet import InvalidToken

from .catalogue import OPERATIONS, FIELDS, operation, validate, describe
from .config import REGIONS
from .errors import TeslaError
from .fleet import Fleet
from .profiles import effective_fields
from .store import Store, canonical, digest, utc
from .diagnostics import operation_evidence, record_operation_observations
from .preconditions import DRIVE_GUARDED_ACTIONS, drive_precondition
from .provider_diagnostics import rejection_reason
from .read_contracts import read_evidence
from .gear_evidence import view as gear_evidence
from .telemetry_privacy import contains_location
from .state_evidence import (PARENTS, block_view, coordinates_valid, projected_row, request_sections,
                             row_quality, snapshot_row, timestamp_evidence)

STATE_SECTIONS = ("charge_state", "climate_state", "vehicle_state", "vehicle_config", "gui_settings",
                  "drive_state", "location_data", "navigation_data", "media_state", "charge_schedule_data", "preconditioning_schedule_data")
LOCATION_SECTIONS = {"drive_state", "location_data", "navigation_data"}
OWNER_ACTIONS = {"remote_start_drive", "erase_user_data", "clear_pin_to_drive_admin", "reset_pin_to_drive_pin",
                 "reset_valet_pin", "parental_controls_clear_pin_admin", "speed_limit_clear_pin_admin",
                 "vehicle_drivers_remove", "vehicle_share_invites_create", "vehicle_share_invites_revoke"}
SECRET_KEYS = {"vin", "tokens", "token", "access_token", "refresh_token", "id_token", "password", "pin", "backseat_token", "backseat_token_updated_at"}
LOCATION_KEYS = {"lat", "lon", "latitude", "longitude", "native_latitude", "native_longitude", "heading", "location", "route_line",
                 "long", "destination_location", "destination_name", "sitelocationname", "drive_state", "location_data", "navigation_data"}


def redact(value, *, location=True):
    if isinstance(value, dict):
        return {k: redact(v, location=location) for k, v in value.items()
                if k.lower() not in SECRET_KEYS and (location or k.lower() not in LOCATION_KEYS and not k.lower().startswith("active_route_"))}
    if isinstance(value, list):
        return [redact(v, location=location) for v in value]
    return value


def timestamp(value):
    return timestamp_evidence(value)["source_timestamp"]


def require(scopes, *needed):
    if not set(needed) <= set(scopes):
        error = TeslaError("SCOPE_REQUIRED", "Required plugin permissions: "+", ".join(needed))
        error.required_scopes = list(needed)
        raise error


class Service:
    def __init__(self, settings, *, store=None, fleet=None):
        self.settings = settings
        self.store = store or Store(settings)
        self.fleet = fleet or Fleet(self.store)

    def connection_status(self):
        try:
            row = self.store.connection()
            status = {"connected": True, "region": row["region"], "tesla_scopes": json.loads(row["scopes"])}
        except TeslaError:
            status = {"connected": False, "setup_required": "owner_console"}
        return {**status, "live_enabled": self.settings.live_enabled, "timezone": self.settings.timezone,
                "owner_console": self.settings.public_url.rsplit("/mcp", 1)[0]+"/owner",
                "vehicle_qualified": False, "qualification_scope": "per_operation",
                "qualification_note": "No blanket qualification. Use get_capabilities for acceptance and observed effects per operation.",
                "request_budget_usd": self.settings.monthly_limit_usd}

    def _request(self, name, arguments=None, *, vehicle=None, binary=False, authorization=None, generation=None):
        authorization = authorization or self.fleet.authorization()
        if generation is not None and authorization.generation != generation:
            raise TeslaError("AUTHORIZATION_CHANGED", "Authorization changed before dispatch; no command was sent")
        data = self.fleet.call(name, arguments, vehicle=vehicle, binary=binary, authorization=authorization)
        try:
            self.store.require_authorization(authorization)
        except TeslaError:
            if not operation(name)["readonly"]:
                raise TeslaError("OUTCOME_UNKNOWN", "Authorization changed after dispatch; no command was replayed", uncertain=True) from None
            raise
        return data, authorization

    def list_vehicles(self, *, refresh=True):
        if refresh:
            self.fleet.discover()
        with self.store.db() as db:
            return [{"vehicle_ref": r["ref"], "name": r["name"], "authorization_checked_at": utc(r["checked"]),
                     "state": json.loads(r["data"]).get("state", "unknown")}
                    for r in db.execute("SELECT * FROM vehicles WHERE active=1 ORDER BY ref")]

    def vehicle(self, ref, *, refresh_membership=True):
        """Local reads retain the last known grant; live operations recheck it."""
        self.store.connection()
        vehicle = self.store.vehicle(ref)
        if refresh_membership and self.store.clock()-vehicle["checked"] > 300:
            self.fleet.discover()
            vehicle = self.store.vehicle(ref)
        return vehicle

    def membership_status(self, vehicle):
        return {"authorization_checked_at": utc(vehicle["checked"]),
                "membership_fresh": 0 <= self.store.clock()-vehicle["checked"] <= 300}

    def location_allowed(self, vehicle, scopes):
        require(scopes, "tesla:location")
        state = self.store.connection()
        if "vehicle_location" not in json.loads(state["scopes"]) or vehicle["data"].get("granular_access", {}).get("hide_private") is True:
            raise TeslaError("LOCATION_WITHHELD", "Location is not authorized for this connection")

    def capabilities(self, ref, *, refresh=False):
        vehicle = self.vehicle(ref, refresh_membership=refresh)
        info = None
        if refresh:
            result, authorization = self._request("vehicle_fleet_status", vehicle=vehicle)
            info = self._fleet_info(vehicle, result)
            self.store.snapshot(ref, "capabilities", info, "fleet_status", self.store.clock(), authorization=authorization)
        else:
            with self.store.db() as db:
                row = db.execute("SELECT data FROM snapshots WHERE vehicle=? AND section='capabilities'", (ref,)).fetchone()
            info = json.loads(row[0]) if row else {"state": "unknown"}
        with self.store.db() as db:
            rows = db.execute("SELECT id,operation FROM intents WHERE vehicle=? AND generation=? ORDER BY created DESC,rowid DESC",
                              (ref, self.store.connection()["generation"])).fetchall()
        latest = {}
        for row in rows:
            latest.setdefault(row["operation"], row["id"])
        operations = []
        for name, op in OPERATIONS.items():
            contract = describe(name)
            evidence = operation_evidence(self.store, self.store.intent(latest[name])) if name in latest else {"status": "not_tested", "effect_observed": False}
            operations.append({"operation": name, "availability": op["availability"],
                               "transport_requirement": op.get("proxy_extension"),
                               "reason": evidence.get("reason") or evidence["status"],
                               "catalogue_limitation": None if op["reason"] == "Vehicle qualification pending" else op["reason"],
                               "limitations": contract["limitations"],
                               "requirements": contract["requirements"],
                               "implementation_status": op.get("implementation_status", "transport_implemented" if op["availability"] == "supported_transport" else "catalogue_only"),
                               "vehicle_qualified": evidence["effect_observed"], "qualification": evidence})
        return {"vehicle_ref": ref, **self.membership_status(vehicle), "fleet_status": info,
                "qualification_scope": "per_operation_observations_not_blanket_vehicle_support",
                "operations": operations,
                "telemetry_fields": len(FIELDS)}

    @staticmethod
    def _fleet_info(vehicle, result):
        if not isinstance(result, dict):
            raise TeslaError("PROVIDER_RESPONSE_INVALID", "Invalid fleet status")
        info = result.get("vehicle_info", {}).get(vehicle["vin"], {})
        return {**info, "key_paired": vehicle["vin"] in result.get("key_paired_vins", [])}

    def read(self, name, arguments, ref, scopes, *, _authorization=None):
        require(scopes, "tesla:read")
        op = operation(name)
        args = validate(name, arguments)
        if not op["readonly"] or op["availability"] != "supported_transport":
            raise TeslaError("UNSUPPORTED_OPERATION", op["reason"])
        if name == "vehicle_list":
            return self.list_vehicles()
        vehicle = self.vehicle(ref) if op["vehicle_bound"] else None
        if name == "vehicle_vehicle_data":
            sections = args.get("endpoints", "charge_state;climate_state;vehicle_state;vehicle_config;gui_settings").split(";")
            return self.state(ref, sections, "live_if_online", scopes)
        if name == "vehicle_nearby_charging_sites":
            self.location_allowed(vehicle, scopes)
        if name in ("charging_history", "charging_invoice"):
            require(scopes, "tesla:history")
        if name == "charging_invoice":
            if ref is None:
                raise TeslaError("INVALID_ARGUMENT", "vehicle_ref is required for charging_invoice")
            with self.store.db() as db:
                doc = db.execute("SELECT * FROM documents WHERE ref=? AND expires>?", (args["id"], self.store.clock())).fetchone()
            if not doc or ref != doc["vehicle"]:
                raise TeslaError("NOT_FOUND", "Choose an invoice returned by your charging history")
            vehicle = self.vehicle(ref)
            content, authorization = self._request(name, {"id": doc["provider_id"]}, vehicle=vehicle, binary=True, authorization=_authorization)
            # HTTP console returns PDF bytes; MCP exposes a protected console link.
            return {"document_ref": doc["ref"], "mime_type": "application/pdf", "content": content}
        if name == "vehicle_fleet_telemetry_config_get":
            from .collection_state import begin_readback
            _authorization = _authorization or self.fleet.authorization()
            readback_attempt = begin_readback(self.store, ref, _authorization)
        data, authorization = self._request(name, args, vehicle=vehicle, authorization=_authorization)
        diagnostic = getattr(data, "diagnostic", None)
        evidence = read_evidence(name, data, args, self.store.clock())
        if name == "vehicle_vehicle" and isinstance(data, dict):
            self.store.snapshot(ref, "vehicle_observation", {"state": data.get("state")}, "tesla_api", self.store.clock(), authorization=authorization)
            record_operation_observations(self.store, ref, "vehicle_observation", authorization=authorization)
        if name == "account_region":
            if not isinstance(data, dict) or data.get("region") not in REGIONS or data.get("fleet_api_base_url") != REGIONS[data["region"]]:
                raise TeslaError("REGION_MISMATCH", "Unexpected Tesla region; configuration needs review")
            with self.store.db() as db:
                db.execute("BEGIN IMMEDIATE")
                self.store.assert_authorization(db, authorization)
                db.execute("UPDATE connection SET region=? WHERE id=1", (data["region"],))
        if name == "vehicle_vehicle_data_cached" and isinstance(data, dict):
            self._cache(ref, data, "tesla_cached", authorization=authorization)
        if name == "vehicle_fleet_status":
            data = self._fleet_info(vehicle, data)
            self.store.snapshot(ref, "capabilities", data, "fleet_status", self.store.clock(), authorization=authorization)
        if name == "vehicle_fleet_telemetry_config_get":
            from .collection_state import record_readback
            record_readback(self.store, ref, data, authorization, attempt=readback_attempt)
        if name == "charging_history":
            data = deepcopy(data)
            self._documents(data, ref, authorization=authorization)
        can_locate = ("tesla:location" in scopes and "vehicle_location" in json.loads(self.store.connection()["scopes"])
                      and vehicle and not vehicle["data"].get("granular_access", {}).get("hide_private", False))
        if name == "vehicle_vehicle_data_cached" and evidence is not None:
            sections = list(evidence["response_sections"])
            sections.extend(section for section, parent in PARENTS.items() if parent in sections and section not in sections)
            evidence["cache_state"] = self._state_data(ref, self._state_rows(ref), sections, can_locate=bool(can_locate))
            evidence["cache_state_semantics"] = "Latest local state after source-time merge; may differ from raw response data."
        return {"source": "tesla_cached" if name == "vehicle_vehicle_data_cached" else "tesla_api", "received_at": utc(self.store.clock()),
                "data": redact(data, location=bool(can_locate)), "vehicle_ref": ref,
                "limitations": ["API response; not an independent observation of a physical effect"],
                **({"diagnostic": diagnostic} if diagnostic else {}),
                **({"read_evidence": redact(evidence, location=bool(can_locate))} if evidence else {})}

    def _documents(self, value, ref, *, authorization):
        if isinstance(value, dict):
            if isinstance(value.get("contentId"), str):
                identifier = value.pop("contentId")
                document_ref = "doc_"+digest(ref+":"+identifier)[:32]
                with self.store.db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    self.store.assert_authorization(db, authorization)
                    db.execute("INSERT OR REPLACE INTO documents VALUES(?,?,?,?)", (document_ref, ref, identifier, self.store.clock()+86400))
                value["document_ref"] = document_ref
            for child in value.values():
                self._documents(child, ref, authorization=authorization)
        elif isinstance(value, list):
            for child in value:
                self._documents(child, ref, authorization=authorization)

    def _cache(self, ref, result, source, *, authorization):
        for name, section in result.items():
            if name in STATE_SECTIONS and isinstance(section, dict):
                self.store.snapshot(ref, name, redact(section), source, timestamp(section.get("timestamp")), authorization=authorization)
                record_operation_observations(self.store, ref, name, authorization=authorization)

    def _state_rows(self, ref):
        with self.store.db() as db:
            return {r["section"]: snapshot_row(r) for r in db.execute(
                "SELECT * FROM snapshots WHERE vehicle=? AND section IN ("+",".join("?" for _ in STATE_SECTIONS)+")",
                (ref, *STATE_SECTIONS))}

    def _state_data(self, ref, rows, sections, *, can_locate, max_age=120):
        now, data = self.store.clock(), {}
        for section in sections:
            row = projected_row(rows, section, now=now, max_age=max_age)
            position = self._position(ref, row, max_age) if section == "location_data" else None
            data[section] = redact(position if position is not None else block_view(row, section, now, max_age),
                                   location=can_locate)
        return data

    def state(self, ref, sections, freshness, scopes, *, max_age=120,
              include_route_geometry=False, telemetry_fields=None):
        require(scopes, "tesla:read")
        if type(include_route_geometry) is not bool:
            raise TeslaError("INVALID_ARGUMENT", "Route geometry selection must be boolean")
        if telemetry_fields is not None:
            known = {field['field'] for field in FIELDS}
            if (not isinstance(telemetry_fields, list) or not telemetry_fields
                    or any(not isinstance(field, str) for field in telemetry_fields)
                    or len(telemetry_fields) > len(known)
                    or len(telemetry_fields) != len(set(telemetry_fields))
                    or not set(telemetry_fields) <= known):
                raise TeslaError("INVALID_ARGUMENT", "Choose known, distinct telemetry fields")
        if not sections or not set(sections) <= set(STATE_SECTIONS) or len(sections) != len(set(sections)):
            raise TeslaError("INVALID_ARGUMENT", "Choose known, distinct state sections")
        if freshness not in ("cached_only", "cache_preferred", "live_if_online"):
            raise TeslaError("INVALID_ARGUMENT", "Unknown freshness policy")
        vehicle = self.vehicle(ref, refresh_membership=freshness != "cached_only")
        if set(sections) & LOCATION_SECTIONS:
            self.location_allowed(vehicle, scopes)
        from .telemetry import LOCATION_FIELDS
        if include_route_geometry or set(telemetry_fields or []) & LOCATION_FIELDS:
            self.location_allowed(vehicle, scopes)
        if freshness == "live_if_online":
            current, authorization = self._request("vehicle_vehicle", vehicle=vehicle)
            if isinstance(current, dict):
                self.store.snapshot(ref, "vehicle_observation", {"state": current.get("state")}, "tesla_api", self.store.clock(), authorization=authorization)
                record_operation_observations(self.store, ref, "vehicle_observation", authorization=authorization)
            if not isinstance(current, dict) or current.get("state") != "online":
                raise TeslaError("ASLEEP_OR_OFFLINE", "Vehicle is not online; no wake request was sent")
            result, authorization = self._request("vehicle_vehicle_data", {"endpoints": ";".join(request_sections(sections))}, vehicle=vehicle)
            if not isinstance(result, dict):
                raise TeslaError("PROVIDER_RESPONSE_INVALID", "Invalid vehicle state")
            self._cache(ref, result, "tesla_live", authorization=authorization)
        elif freshness == "cache_preferred":
            rows, now = self._state_rows(ref), self.store.clock()
            candidates = [projected_row(rows, s, now=now, max_age=max_age) for s in sections]
            if any(row_quality(r, now, max_age) != "fresh_observed" for r in candidates):
                try:
                    result, authorization = self._request("vehicle_vehicle_data_cached", vehicle=vehicle)
                    if isinstance(result, dict):
                        self._cache(ref, result, "tesla_cached", authorization=authorization)
                except TeslaError as exc:
                    if exc.code not in ("NOT_FOUND", "PRECONDITION_FAILED", "ASLEEP_OR_OFFLINE"):
                        raise
        rows = self._state_rows(ref)
        can_locate = ("tesla:location" in scopes and "vehicle_location" in json.loads(self.store.connection()["scopes"])
                      and not vehicle["data"].get("granular_access", {}).get("hide_private", False))
        data = self._state_data(ref, rows, sections, can_locate=can_locate, max_age=max_age)
        extra = {}
        if 'drive_state' in sections:
            from .operating_context import explain
            park = gear_evidence(self.store, ref, rows.get('drive_state'), include_history='tesla:history' in scopes)
            extra = {'park_evidence': park, 'operating_context': explain(self.store, ref, park)}
        if telemetry_fields is not None:
            from .sample_evidence import view as sample_view
            observations = {}
            for field in telemetry_fields:
                evidence = sample_view(self.store, ref, field,
                                       include_history='tesla:history' in scopes,
                                       max_age_seconds=max_age)
                if contains_location(evidence):
                    self.location_allowed(vehicle, scopes)
                observations[field] = evidence
            extra['telemetry'] = observations
        if include_route_geometry:
            from .route_evidence import view as route_view
            extra['route_geometry'] = route_view(self.store, ref, location_allowed=can_locate,
                                                 max_age_seconds=max_age)
        return {"vehicle_ref": ref, **self.membership_status(vehicle), "data": data, "wake_sent": False, **extra}

    def _position(self, ref, rest, max_age):
        """Use the newest location observation with its own clock, never a REST clock."""
        with self.store.db() as db:
            row = db.execute("SELECT * FROM latest WHERE vehicle=? AND field='Location'", (ref,)).fetchone()
        if not row:
            return None
        previous = json.loads(rest["data"]) if rest else {}
        now = self.store.clock()
        rest_future = rest is not None and rest["source_at"] is not None and rest["source_at"] > now+30
        future = row["source_at"] > now+30
        if rest and rest.get("snapshot_quality") == "time_conflict":
            if (row["quality"] != "valid" or future or rest["source_at"] is None
                    or not rest_future and rest["source_at"] >= row["source_at"]):
                return None
        if (rest and coordinates_valid(previous)
                and rest["source_at"] is not None
                and (future and not rest_future or rest["source_at"] >= row["source_at"] and not (rest_future and not future))):
            return None
        age = now-row["source_at"]
        quality = (row["quality"] if row["quality"] != "valid" else "future" if age < -30
                   else "fresh_observed" if age <= max_age else "stale")
        return {"data": json.loads(row["value"]) if row["quality"] == "valid" else None,
                "source": "fleet_telemetry", "field": "Location", "source_timestamp": row["source_at"],
                "received_at": row["received"], "time_basis": row["time_basis"], "quality": quality,
                "sample_quality": row["quality"], "age_seconds": age, "accuracy_meters": None,
                "instantaneous_position": False,
                **({"selection_evidence": {"reason": "newer_or_plausible_telemetry_location",
                    "alternative": {"source": rest["source"], "source_timestamp": rest["source_at"],
                                    "quality": row_quality(rest, now, max_age), "future_clock": rest_future},
                    **({"rest_selection": rest["selection_evidence"]} if "selection_evidence" in rest else {})}} if rest else {}),
                "note": 'Last observed position; accuracy not supplied. minimum_delta is a transmission threshold, not GPS accuracy.'}

    def prepare(self, name, arguments, ref, client_key, scopes, *, access_expires=None, _profile=False, collection_revision=None, trigger_revision=None, temporary_plan=None, collection_preview=None):
        require(scopes, "tesla:commands")
        op, args = operation(name), validate(name, arguments)
        require(scopes, *op.get("input_permissions", []))
        if op["readonly"] or (op["availability"] != "supported_transport" and not (_profile and name == "vehicle_fleet_telemetry_config_create")):
            raise TeslaError("UNSUPPORTED_OPERATION", op["reason"])
        if name == "vehicle_fleet_telemetry_config_create" and collection_preview is None:
            raise TeslaError("COLLECTION_REVIEW_INCOMPLETE", "Prepare this configuration through its collection review")
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", client_key):
            raise TeslaError("INVALID_ARGUMENT", "Use a stable client request ID of 16–128 characters")
        if op.get("proxy_extension"):
            self.fleet.require_extension(op)
        vehicle = self.vehicle(ref) if op["vehicle_bound"] else None
        if name in OWNER_ACTIONS and (not vehicle or vehicle["data"].get("access_type") != "OWNER"):
            raise TeslaError("OWNER_REQUIRED", "This operation requires verified owner access")
        if "lat" in args or "lon" in args:
            require(scopes, "tesla:location")
        connection = self.store.connection()
        now = self.store.clock()
        expires = min(now+self.settings.intent_ttl_seconds, access_expires or now+self.settings.intent_ttl_seconds)
        if expires <= now:
            raise TeslaError("AUTH_REQUIRED", "Authorization has expired")
        fingerprint = digest(canonical([name, ref, args, connection["generation"], sorted(scopes)]))
        if trigger_revision is not None:
            fingerprint = digest(canonical([fingerprint, trigger_revision]))
        if temporary_plan is not None:
            fingerprint = digest(canonical([fingerprint, temporary_plan]))
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            active = db.execute("SELECT generation FROM connection WHERE id=1 AND status='active'").fetchone()
            if not active or active[0] != connection["generation"]:
                raise TeslaError("AUTHORIZATION_CHANGED", "Authorization changed while preparing the action")
            from .collection_state import check_trigger_revision
            existing = db.execute("SELECT * FROM intents WHERE client_key=?", (client_key,)).fetchone()
            if existing:
                if existing["fingerprint"] != fingerprint:
                    raise TeslaError("IDEMPOTENCY_CONFLICT", "Request ID already identifies a different action")
                identifier = existing["id"]
                if collection_preview is not None and existing["status"] == "prepared":
                    from .collection_state import require_complete_review
                    previous = require_complete_review(db, existing)
                    expected = {"intent_id": identifier, **collection_preview}
                    ignored = {"selection_review"}
                    if trigger_revision is None:
                        ignored.add("trigger_revision")
                    if "request_fingerprint" not in expected:
                        ignored.add("request_fingerprint")
                    if ({k: v for k, v in previous.items() if k not in ignored}
                            != {k: v for k, v in expected.items() if k not in ignored}):
                        raise TeslaError("IDEMPOTENCY_CONFLICT", "Request ID already identifies another cost scenario")
            else:
                bound_trigger_revision = trigger_revision
                if name in ("vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete") and bound_trigger_revision is None:
                    trigger = db.execute("SELECT revision FROM trigger_settings WHERE vehicle=?", (ref,)).fetchone()
                    if not trigger:
                        raise TeslaError("REVISION_CONFLICT", 'Read events again before preparing collection.')
                    bound_trigger_revision = trigger[0]
                check_trigger_revision(db, ref, bound_trigger_revision)
                if collection_revision is not None:
                    from .collection_state import read_collection
                    view = read_collection(self.store, ref)
                    if collection_revision != view["revision"]:
                        raise TeslaError("REVISION_CONFLICT", 'Collection changed. Reload the panel before preparing a change.')
                    if view["blocked"]:
                        raise TeslaError("OPERATION_PENDING", 'Review the pending request before preparing another.')
                if name in ("vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete"):
                    pending = db.execute("SELECT id FROM intents WHERE vehicle=? AND operation IN (?,?) "
                                         "AND (status IN ('sending','unknown') OR (status='prepared' AND expires>?))",
                                         (ref, "vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete", now)).fetchone()
                    if pending:
                        raise TeslaError("OPERATION_PENDING", "Review the pending telemetry request before preparing another")
                identifier = "intent_"+secrets.token_hex(16)
                db.execute("INSERT INTO intents VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                           (identifier, client_key, fingerprint, ref, name, canonical(args), canonical(sorted(scopes)),
                            connection["generation"], now, expires, "prepared"))
                if temporary_plan is not None:
                    from .temporary_collection import register
                    register(db, self.store, {"id": identifier, "vehicle": ref, "generation": connection["generation"]}, temporary_plan)
                if collection_preview is not None:
                    preview = {"intent_id": identifier, **deepcopy(collection_preview)}
                    if name in ("vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete"):
                        preview["trigger_revision"] = bound_trigger_revision
                    db.execute("INSERT INTO snapshots VALUES(?,?,?,?,?,?)",
                               (ref, "telemetry_preview_"+identifier, canonical(preview), "owner_request", now, now))
                    if name == "vehicle_fleet_telemetry_config_create":
                        from .collection_state import require_complete_review
                        require_complete_review(db, {"id": identifier, "vehicle": ref, "operation": name, "arguments": args})
                        db.execute("INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?)",
                                   (ref, "telemetry_preview", canonical(preview), "owner_request", now, now))
                elif name == "vehicle_fleet_telemetry_config_delete":
                    db.execute("INSERT INTO snapshots VALUES(?,?,?,?,?,?)",
                               (ref, "telemetry_preview_"+identifier,
                                canonical({"intent_id": identifier, "trigger_revision": bound_trigger_revision}),
                                "owner_request", now, now))
        return self.intent_view(identifier)

    def prepare_profile(self, ref, preset, custom, client_key, scopes, *, active_hours_per_day=8, access_expires=None, customer_alerts=None, collection_revision=None, trigger_revision=None, selection_review=None, temporary_plan=None, request_fingerprint=None):
        from .profiles import build
        require(scopes, "tesla:manage", "tesla:commands")
        if preset == 'full' and selection_review is None:
            from .field_capabilities import context, select_maximum
            from .profiles import full_profile
            selection_review = select_maximum(full_profile(), context(self.store, ref))[1]
        arguments, estimate = build(self, ref, preset, custom, scopes, active_hours_per_day, customer_alerts)
        preview = {"hours": active_hours_per_day, "estimate": estimate}
        if trigger_revision is not None:
            preview["trigger_revision"] = trigger_revision
        if selection_review is not None:
            preview["selection_review"] = deepcopy(selection_review)
        if request_fingerprint is not None:
            preview["request_fingerprint"] = request_fingerprint
        result = self.prepare("vehicle_fleet_telemetry_config_create", arguments, ref, client_key, scopes,
                              access_expires=access_expires, _profile=True, collection_revision=collection_revision,
                              trigger_revision=trigger_revision, temporary_plan=temporary_plan, collection_preview=preview)
        # All review data was committed with the intent. Replays only read the
        # original bundle, including qualifications observed at preparation.
        from .collection_state import review_state
        with self.store.db() as db:
            previous, complete = review_state(db, self.store.intent(result["id"]))
        return {**self.intent_view(result["id"]), "estimate": previous.get("estimate") if complete else None,
                "selection_review": previous.get("selection_review"), "retention_days": self.settings.history_days}

    def intent_view(self, identifier):
        intent = self.store.intent(identifier)
        contract = describe(intent["operation"])
        view = {k: intent[k] for k in ("id", "vehicle", "operation", "arguments", "expires", "status", "result")} | {
            "action_digest": digest(canonical([intent["id"], intent["vehicle"], intent["operation"], intent["arguments"],
                                               intent["generation"], intent["expires"], intent["scopes"]])),
            "confirmation_url": self.settings.public_url.rsplit("/mcp", 1)[0]+"/owner/intents/"+identifier,
            "secure_owner_fields": operation(intent["operation"])["sensitive_fields"]}
        if intent["operation"] in ("vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete"):
            from .collection_state import review_state
            with self.store.db() as db:
                _, view["review_complete"] = review_state(db, intent)
            view["next_step"] = {"tool": "tesla_get_collection", "arguments": {"vehicle_ref": intent["vehicle"]},
                                 "confirmation_tool": "tesla_confirm_collection", "review_required": True}
        view["verification"] = operation_evidence(self.store, intent)
        view["requirements"] = contract["requirements"]
        if intent["status"] == "prepared" and (intent["result"] or {}).get("stage") == "preflight":
            view["preflight"] = intent["result"]
        if contract["limitations"]:
            view["limitations"] = contract["limitations"]
            view["notice"] = operation(intent["operation"]).get("owner_note")
        if intent["operation"] == "vehicle_wake_up":
            view["follow_up"] = {"tool": "tesla_read", "arguments": {"operation": "vehicle_vehicle", "arguments": {}, "vehicle_ref": intent["vehicle"]},
                                 "explicit_request_required": True, "may_cost_api_read": True, "wake_sent": False}
            observed_online = view["verification"].get("effect_observed") is True
            view["note"] = ('An online observation was recorded after the command: inspect source, timestamp and age. It does not establish current state or causality.' if observed_online
                            else 'Wake accepted, online not yet observed after the command.' if intent["status"] == "acknowledged"
                            else 'Wake outcome unconfirmed; no second automatic command.')
        return view

    def execute_action_from_chat(self, identifier, action_digest, decision, scopes):
        """Explicitly requested command, with exactly the owner-panel checks."""
        require(set(scopes) & set(self.settings.allowed_scopes), "tesla:commands")
        item = self.intent_view(identifier)
        if item["action_digest"] != action_digest:
            raise TeslaError("REVISION_CONFLICT", 'The command does not match the review: read it again before execution.')
        if decision == "cancel":
            with self.store.db() as db:
                db.execute("UPDATE intents SET status='cancelled' WHERE id=? AND status='prepared'", (identifier,))
            return self.intent_view(identifier)
        if decision != "execute":
            raise TeslaError("INVALID_ARGUMENT", "Choose execute or cancel")
        if item["operation"] in ("vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete"):
            raise TeslaError("INVALID_ARGUMENT", 'Use the data-collection review and confirmation for this operation.')
        if item["secure_owner_fields"]:
            raise TeslaError("OWNER_REQUIRED", 'This command requires secret fields in the protected form; do not enter them in chat.')
        if not self.settings.live_enabled:
            raise TeslaError("LIVE_DISABLED", "Live Tesla requests are disabled")
        original = self.store.intent(identifier)
        require(set(scopes), *set(original["scopes"]))
        return self.execute_from_owner(identifier, confirmation_source="explicit_chat_request")

    def wake_from_chat(self, ref, client_key, scopes, *, access_expires=None):
        require(set(scopes) & set(self.settings.allowed_scopes), "tesla:commands")
        if not self.settings.live_enabled:
            raise TeslaError("LIVE_DISABLED", "Live Tesla requests are disabled")
        with self.store.db() as db:
            pending = db.execute("SELECT client_key FROM intents WHERE vehicle=? AND operation='vehicle_wake_up' "
                                 "AND status IN ('prepared','sending','unknown') AND expires>?",
                                 (ref, self.store.clock())).fetchall()
        if any(row[0] != client_key for row in pending):
            raise TeslaError("OPERATION_PENDING", 'A wake request is already in progress or uncertain. Read the operation again; do not send another automatic attempt.')
        item = self.prepare("vehicle_wake_up", {}, ref, client_key, scopes, access_expires=access_expires)
        result = self.execute_action_from_chat(item["id"], item["action_digest"], "execute", scopes)
        outcome = result["result"] or {}
        state = outcome.get("data", {}).get("state") if isinstance(outcome.get("data"), dict) else None
        return {"vehicle_ref": ref, "intent_id": item["id"], "status": result["status"],
                "reported_state": state if state in ("online", "offline", "asleep") else None,
                "vehicle_online_observed": state == "online", "result": {k: v for k, v in outcome.items() if k != "data"},
                "verification": result["verification"], "follow_up": result["follow_up"],
                "note": ('Wake accepted, online not yet observed.' if result["status"] == "acknowledged" and state != "online"
                         else 'Online state reported in the wake response.' if state == "online" else 'Wake outcome unconfirmed.')+
                        ' No periodic checks or second automatic wake command.'}

    def execute_collection_from_chat(self, identifier, scopes):
        """Narrow confirmation path: never dispatch physical vehicle commands."""
        require(set(scopes) & set(self.settings.allowed_scopes), "tesla:manage", "tesla:commands")
        item = self.store.intent(identifier)
        if item["operation"] not in ("vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete"):
            raise TeslaError("OWNER_REQUIRED", "Physical commands use their separate explicit action review")
        with self.store.db() as db:
            temporary = db.execute("SELECT plan FROM temporary_collections WHERE intent_id=?", (identifier,)).fetchone()
        if temporary:
            require(set(scopes), *json.loads(temporary["plan"])["scopes"])
        from .telemetry import LOCATION_FIELDS
        if effective_fields(item["arguments"].get("config", {}).get("fields", {})) & LOCATION_FIELDS:
            self.location_allowed(self.vehicle(item["vehicle"], refresh_membership=False), scopes)
        return self.execute_from_owner(identifier, confirmation_source="explicit_chat_request")

    def execute_from_owner(self, identifier, sensitive=None, *, confirmation_source="owner_panel", _restore_lease=None):
        intent = self.store.intent(identifier)
        if intent["status"] != "prepared":
            return self.intent_view(identifier)
        if intent["expires"] <= self.store.clock():
            raise TeslaError("INTENT_EXPIRED", "Prepare a new action; this request has expired")
        connection = self.store.connection()
        if intent["generation"] != connection["generation"]:
            raise TeslaError("AUTH_REQUIRED", "Authorization changed; prepare a new action")
        require(set(intent["scopes"]) & set(self.settings.allowed_scopes), "tesla:commands")
        name, op = intent["operation"], operation(intent["operation"])
        needed = set(op.get("input_permissions", []))
        if "lat" in intent["arguments"] or "lon" in intent["arguments"]:
            needed.add("tesla:location")
        require(set(intent["scopes"]) & set(self.settings.allowed_scopes), *needed)
        if op.get("proxy_extension"):
            self.fleet.require_extension(op)
        from .collection_state import check_trigger_revision
        with self.store.db() as db:
            from .collection_state import require_complete_review
            preview = require_complete_review(db, intent)
            trigger_revision = preview.get("trigger_revision")
            check_trigger_revision(db, intent["vehicle"], trigger_revision)
        secure = sensitive or {}
        if set(secure) != set(op["sensitive_fields"]):
            raise TeslaError("INVALID_ARGUMENT", "Complete the secure owner fields")
        arguments = validate(name, {**intent["arguments"], **secure}, sensitive=True)
        vehicle = self.vehicle(intent["vehicle"]) if op["vehicle_bound"] else None
        if name == "vehicle_fleet_telemetry_config_create":
            from .trigger_catalog import LOCATION_FIELDS
            if effective_fields(arguments["config"]["fields"]) & LOCATION_FIELDS:
                self.location_allowed(vehicle, set(intent["scopes"]) & set(self.settings.allowed_scopes))
        if name in OWNER_ACTIONS and (not vehicle or vehicle["data"].get("access_type") != "OWNER"):
            raise TeslaError("OWNER_REQUIRED", "Verified owner access is required")
        if op["transport"] == "proxy" or name == "vehicle_fleet_telemetry_config_create":
            result, _ = self._request("vehicle_fleet_status", vehicle=vehicle, generation=intent["generation"])
            info = self._fleet_info(vehicle, result)
            if info.get("vehicle_command_protocol_required") is not True or not info["key_paired"]:
                raise TeslaError("KEY_REQUIRED", "A paired signing key and verified command protocol are required")
        blocked = None
        admission = None
        if name in DRIVE_GUARDED_ACTIONS:
            result, authorization = self._request("vehicle_vehicle_data", {"endpoints": "drive_state"}, vehicle=vehicle, generation=intent["generation"])
            drive = result.get("drive_state", {}) if isinstance(result, dict) else {}
            if isinstance(drive, dict):
                self.store.snapshot(vehicle["ref"], "drive_state", redact(drive), "tesla_live",
                                    timestamp(drive.get("timestamp")), authorization=authorization)
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            active = db.execute("SELECT generation FROM connection WHERE id=1 AND status='active'").fetchone()
            current_preview = require_complete_review(db, intent)
            if current_preview != preview:
                raise TeslaError("REVISION_CONFLICT", 'The review changed before submission. Read it again before confirmation.')
            check_trigger_revision(db, intent["vehicle"], trigger_revision)
            member = db.execute("SELECT active FROM vehicles WHERE ref=?", (intent["vehicle"],)).fetchone() if vehicle else None
            if not active or active[0] != intent["generation"] or (vehicle and (not member or not member[0])):
                raise TeslaError("AUTH_REQUIRED", "Authorization changed before dispatch; prepare a new action")
            if name in DRIVE_GUARDED_ACTIONS:
                self.store.assert_authorization(db, authorization)
                gear = db.execute("SELECT * FROM latest WHERE vehicle=? AND field='Gear'", (vehicle["ref"],)).fetchone()
                stored_drive = db.execute("SELECT * FROM snapshots WHERE vehicle=? AND section='drive_state'", (vehicle["ref"],)).fetchone()
                admission = drive_precondition(name, drive, gear, self.store.clock(), stored_rest=stored_drive)
                if not admission["allows_dispatch"]:
                    blocked = {"stage": "preflight", "command_sent": False, "dispatch_attempted": False,
                               "accepted": False, "physical_effect_verified": False, "attempted_at": self.store.clock(),
                               "precondition": admission, "confirmation_source": confirmation_source}
            if blocked:
                changed = db.execute("UPDATE intents SET result=? WHERE id=? AND status='prepared' AND expires>?",
                                     (canonical(blocked), identifier, self.store.clock())).rowcount
            else:
                dispatch_allowed = True
                if name in ("vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete"):
                    # The deadline and one-write restore fence commit with sending.
                    from .temporary_collection import before_dispatch
                    current = db.execute("SELECT status,expires FROM intents WHERE id=?", (identifier,)).fetchone()
                    if current and current["status"] == "prepared" and current["expires"] > self.store.clock():
                        dispatch_allowed = before_dispatch(self, db, intent, lease_owner=_restore_lease)
                changed = db.execute("UPDATE intents SET status='sending',result=NULL WHERE id=? AND status='prepared' AND expires>?",
                                     (identifier, self.store.clock())).rowcount if dispatch_allowed else 0
        if not changed:
            return self.intent_view(identifier)
        if blocked:
            raise TeslaError("PRECONDITION_FAILED", admission["message"], details={"intent_id": identifier, **blocked})
        try:
            result, authorization = self._request(name, arguments, vehicle=vehicle, generation=intent["generation"])
            if name == "vehicle_fleet_telemetry_config_create":
                from .collection_diagnostics import configuration_outcome
                state, outcome = configuration_outcome(result, vehicle['vin'])
            elif name == "vehicle_fleet_telemetry_config_delete":
                from .collection_diagnostics import deletion_outcome
                state, outcome = deletion_outcome(result)
            elif isinstance(result, dict) and type(result.get("result")) is bool:
                state = "acknowledged" if result["result"] else "rejected"
                outcome = {"accepted": result["result"], "physical_effect_verified": False, "dispatch_attempted": True}
                if not result["result"]:
                    outcome.update(code="COMMAND_REJECTED", origin="provider", **rejection_reason(result.get("reason")))
                if type(result.get("queued")) is bool:
                    outcome["queued"] = result["queued"]
            elif name == "vehicle_wake_up" and isinstance(result, dict) and result.get("state") in ("online", "offline", "asleep"):
                state, outcome = "acknowledged", {"data": redact(result), "physical_effect_verified": False}
            elif name.startswith("vehicle_share_invites") or name == "vehicle_drivers_remove":
                state, outcome = "acknowledged", {"data": redact(result), "physical_effect_verified": False}
            else:
                state, outcome = "unknown", {"code": "OUTCOME_UNKNOWN", "physical_effect_verified": False}
            if getattr(result, "diagnostic", None):
                outcome["diagnostic"] = result.diagnostic
            if state == "acknowledged" and name in ("vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete"):
                config = arguments["config"] if name == "vehicle_fleet_telemetry_config_create" else None
                with self.store.db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    self.store.assert_authorization(db, authorization)
                    member = db.execute("SELECT active FROM vehicles WHERE ref=?", (vehicle["ref"],)).fetchone()
                    temporary = db.execute("SELECT intent_id,status,error FROM temporary_collections WHERE intent_id=? OR restore_intent=?", (identifier, identifier)).fetchone()
                    current = db.execute("SELECT status FROM intents WHERE id=?", (identifier,)).fetchone()
                    latest = db.execute("SELECT id FROM intents WHERE vehicle=? AND operation IN (?,?) ORDER BY created DESC,rowid DESC LIMIT 1",
                                        (vehicle["ref"], "vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete")).fetchone()
                    from .temporary_collection import SUSPENDED, TERMINAL
                    revoked = not member or not member["active"] or (temporary and temporary["error"] in SUSPENDED)
                    current_dispatch = (current and current["status"] == "sending" and latest and latest["id"] == identifier
                                        and not (temporary and temporary["status"] in TERMINAL))
                    if not revoked and current_dispatch:
                        at = self.store.clock()
                        sections = ("telemetry_target", "telemetry_saved") if config and not (temporary and temporary["intent_id"] == identifier) else ("telemetry_target",)
                        for section in sections:
                            db.execute("INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?)",
                                       (vehicle["ref"], section, canonical(config), "local_configuration", at, at))
                    else:
                        outcome["configuration_state_recorded"] = False
                        outcome["state_recording_reason"] = "vehicle_access_revoked" if revoked else "collection_operation_superseded"
        except TeslaError as exc:
            state, outcome = ("unknown" if exc.uncertain or exc.code == "AUTHORIZATION_CHANGED" else "rejected"), exc.public()
        except Exception:
            state, outcome = "unknown", {"code": "OUTCOME_UNKNOWN", "message": "Interrupted dispatch; no automatic retry"}
        if admission is not None:
            outcome["admission"] = admission
        outcome["confirmation_source"] = confirmation_source
        if name not in ("vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete"):
            outcome["completed_at"] = self.store.clock()
        with self.store.db() as db:
            changed = db.execute("UPDATE intents SET status=?, result=? WHERE id=? AND status='sending'", (state, canonical(outcome), identifier)).rowcount
            if changed and name in ("vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete"):
                from .temporary_collection import finish_dispatch
                finish_dispatch(self, db, intent, state, outcome)
        return self.intent_view(identifier)

    def history(self, ref, fields, after, before, scopes, *, limit=500, cursor=None):
        require(scopes, "tesla:read", "tesla:history")
        vehicle = self.vehicle(ref, refresh_membership=False)
        known = {f["field"] for f in FIELDS}
        if (not isinstance(fields, list) or not fields or any(not isinstance(f, str) for f in fields)
                or not set(fields) <= known or len(fields) != len(set(fields)) or len(fields) > len(known)
                or type(limit) is not int or not 1 <= limit <= 1000
                or any(type(t) not in (int, float) or not math.isfinite(t) for t in (after, before)) or after >= before):
            raise TeslaError("INVALID_ARGUMENT", "Invalid history selection")
        from .telemetry import LOCATION_FIELDS
        location_fields = LOCATION_FIELDS
        if set(fields) & location_fields:
            self.location_allowed(vehicle, scopes)
        marks = ",".join("?" for _ in fields)
        generation = self.store.connection()["generation"]
        query = digest(canonical([generation, ref, sorted(set(fields)), float(after), float(before)]))
        page = None
        if cursor is not None:
            try:
                page = self.store.unseal(cursor.encode())
                if page["query"] != query or not 0 <= self.store.clock()-page["at"] <= 600 or page["version"] != 1:
                    raise ValueError()
            except (InvalidToken, ValueError, KeyError, TypeError, AttributeError):
                raise TeslaError("INVALID_CURSOR", "History cursor expired or belongs to another query; start a new history read") from None
        with self.store.db() as db:
            db.execute("BEGIN")
            if page is None:
                page = {"version": 1, "query": query, "at": self.store.clock(),
                        "watermark": db.execute("SELECT coalesce(max(rowid),0) FROM samples").fetchone()[0], "last": None}
            continuation = " AND (source_at,field,id)>(?,?,?)" if page["last"] else ""
            parameters = (ref, *fields, after, before, page["watermark"], page["at"], *(page["last"] or []), limit+1)
            rows = db.execute(f"SELECT id,field,value,source_at,received,quality,time_basis FROM samples "
                              f"WHERE vehicle=? AND field IN ({marks}) AND source_at>=? AND source_at<? "
                              f"AND rowid<=? AND received<=?{continuation} ORDER BY source_at,field,id LIMIT ?", parameters).fetchall()
            from .sample_evidence import history_provenance
            provenance = history_provenance(db, [row['id'] for row in rows[:limit]],
                                           watermark=page['watermark'], as_of=page['at'])
        next_cursor = None
        if len(rows) > limit:
            last = rows[limit-1]
            next_cursor = self.store.seal(page | {"last": [last["source_at"], last["field"], last["id"]]}).decode()
        from .telemetry_values import semantics
        from .sample_evidence import enrich_history
        samples = []
        for r in rows[:limit]:
            value = json.loads(r['value']) if r['value'] else None
            if contains_location(value):
                self.location_allowed(vehicle, scopes)
            sample = enrich_history(r, self.store.clock(), provenance.get(r['id']))
            notes = semantics(r['field'], value, r['source_at'], r['quality'])
            samples.append(sample | ({'semantics': notes} if notes else {}))
        return {"vehicle_ref": ref, **self.membership_status(vehicle),
                "samples": samples, "requested_fields": fields, "effective_fields": fields,
                "fields_without_samples_on_page": sorted(set(fields)-{r['field'] for r in rows[:limit]}),
                "selection_note": "All requested fields are queried. Missing on this page does not establish unsupported hardware or empty history.",
                "truncated": len(rows)>limit, "next_cursor": next_cursor, "snapshot_at": page["at"],
                "pagination_note": "Use next_cursor with the same query within 10 minutes. New arrivals are excluded; retention can remove old samples.",
                "complete_history": False, "retention_days": self.settings.history_days}
