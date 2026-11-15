"""Bounded, region-aware Fleet API and official command-proxy transport."""
import json
import math
import re
import ssl
from urllib.parse import quote

import httpx
from .catalogue import operation
from .config import REGIONS
from .errors import TeslaError
from .oauth import TeslaOAuth
from .provider_diagnostics import ProviderObject, new_diagnostic, media_type, record, rejection_reason, http_rejection_reason, response_shape, value_kind
from .read_contracts import read_evidence, validate_response
from .collection_diagnostics import rejection as collection_rejection, rejection_diagnostic, request_summary


def provider_json(data):
    def invalid_constant(_):
        raise ValueError("Non-finite JSON number")
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    parsed = json.loads(data, parse_constant=invalid_constant, object_pairs_hook=unique_object)
    # Bound nesting independently of the interpreter's recursion limit. Keep
    # traversal memory proportional to depth, not the number of array elements.
    end = object()
    stack = [iter((parsed,))]
    while stack:
        value = next(stack[-1], end)
        if value is end:
            stack.pop()
        elif isinstance(value, (dict, list)):
            if len(stack) > 64:
                raise ValueError("Excessive JSON nesting")
            stack.append(iter(value.values() if isinstance(value, dict) else value))
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Non-finite JSON number")
    return parsed


def telemetry_rejection(data, selected_fields):
    """Classify provider errors without exposing their free text or identifiers."""
    try:
        body = json.loads(data)
    except (ValueError, UnicodeError):
        return None
    if not isinstance(body, dict):
        return None
    detail = collection_rejection(body, selected_fields)
    return detail['message'] if detail else None


class Fleet:
    def __init__(self, store, *, transport=None):
        self.store, self.settings = store, store.settings
        self.client = httpx.Client(timeout=8, follow_redirects=False, transport=transport,
                                   verify=ssl.create_default_context())
        self.proxy = httpx.Client(timeout=8, follow_redirects=False, transport=transport,
                                  verify=ssl.create_default_context(cafile=str(self.settings.command_proxy_ca))
                                  if self.settings.command_proxy_ca else ssl.create_default_context())
        self.oauth = TeslaOAuth(store, self.client)

    def close(self):
        self.client.close()
        self.proxy.close()

    def authorization(self):
        return self.oauth.authorization()

    def require_extension(self, op):
        """Local TLS proxy capability check, without a token or Tesla request.

        No caching: rollback to an older proxy must immediately close this gate.
        The proxy probe route must never forward to Tesla.
        """
        if not op.get("proxy_extension"):
            return
        if not self.settings.command_proxy_url:
            raise TeslaError("SETUP_REQUIRED", "Configure the versioned command proxy adapter")
        try:
            with self.proxy.stream("GET", self.settings.command_proxy_url+"/gal1leo/capabilities") as response:
                data = bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data) > 8192:
                        raise ValueError()
                info = json.loads(data)
                valid = (response.status_code == 200 and isinstance(info, dict)
                         and info.get("protocol") == op["proxy_extension"]
                         and isinstance(info.get("operations"), list)
                         and all(isinstance(name, str) for name in info["operations"])
                         and op["id"] in info.get("operations", []))
        except (httpx.HTTPError, ValueError, TypeError):
            valid = False
        if not valid:
            raise TeslaError("TRANSPORT_UNAVAILABLE", "The installed proxy does not attest this SDK extension; no Tesla command was sent")

    def call(self, name, arguments=None, *, vehicle=None, binary=False, authorization=None):
        diagnostic = new_diagnostic(name, self.store.clock())
        try:
            result = self._call(name, arguments, vehicle=vehicle, binary=binary,
                                authorization=authorization, diagnostic=diagnostic)
            if not binary:
                diagnostic["response_kind"] = value_kind(result)
                evidence = read_evidence(name, result, arguments or {}, self.store.clock())
                if evidence:
                    diagnostic["response_summary"] = {key: value for key, value in evidence.items()
                        if key not in ("ordering", "limitations")}
                if isinstance(result, dict) and result.get("result") is False:
                    diagnostic.update(rejection_reason(result.get("reason")))
            diagnostic["completed_at"] = self.store.clock()
            record(self.store, diagnostic)
            return ProviderObject(result, diagnostic) if isinstance(result, dict) else result
        except TeslaError as exc:
            if diagnostic.get("request_attempted"):
                if exc.http_status is None:
                    exc.http_status = diagnostic.get("provider_http_status")
                diagnostic.update(completed_at=self.store.clock(), error_code=exc.code)
                diagnostic.update(exc.details)
                exc.diagnostic = diagnostic
                record(self.store, diagnostic)
            raise

    def _call(self, name, arguments=None, *, vehicle=None, binary=False, authorization=None, diagnostic):
        if not self.settings.live_enabled:
            raise TeslaError("LIVE_DISABLED", "Live Tesla requests are disabled")
        op, arguments = operation(name), dict(arguments or {})
        self.require_extension(op)
        authorization = authorization or self.authorization()
        self.store.require_authorization(authorization)
        diagnostic["authorization_generation"] = authorization.generation
        granted = authorization.grants
        # The published arrays do not clearly distinguish all/any; conservative
        # checks retain all declared grants until qualified with a narrower token.
        if not set(op["scopes"]) <= granted:
            raise TeslaError("TESLA_SCOPE_REQUIRED", "Reconnect Tesla with the permissions required by this operation")
        path = op["path"]
        query, body = {}, {}
        if "{vin}" in path:
            if not vehicle:
                raise TeslaError("VEHICLE_ACCESS_REQUIRED", "Select an authorized vehicle")
            path = path.replace("{vin}", quote(vehicle["vin"], safe=""))
        for key, value in arguments.items():
            location = op["parameter_locations"].get(key, "body")
            if location == "path":
                path = path.replace("{"+key+"}", quote(str(value), safe=""))
            elif location == "query":
                query[key] = value
            else:
                body[key] = value
        if op["vehicle_bound"] and "{vin}" not in op["path"]:
            if not vehicle:
                raise TeslaError("VEHICLE_ACCESS_REQUIRED", "Select an authorized vehicle")
            if name == "vehicle_fleet_status":
                body["vins"] = [vehicle["vin"]]
            elif name == "vehicle_fleet_telemetry_config_create":
                body["vins"] = [vehicle["vin"]]
            else:
                query["vin"] = vehicle["vin"]
        if "{" in path or not path.startswith("/api/1/") or "?" in path:
            raise TeslaError("UNSUPPORTED_OPERATION", "Operation has no qualified request route")
        signed = op["transport"] == "proxy" or name == "vehicle_fleet_telemetry_config_create"
        if signed and not self.settings.command_proxy_url:
            raise TeslaError("KEY_REQUIRED", "Configure the official command proxy and pair the virtual key")
        origin = self.settings.command_proxy_url if signed else REGIONS[authorization.region]
        declared = op["pricing_category"]
        category = "free" if declared == "explicit_null_no_charge" else "wake" if name == "vehicle_wake_up" else "data" if op["readonly"] else "commands"
        self.store.reserve_request(category)
        client = self.proxy if signed else self.client
        diagnostic.update(request_attempted=True, transport="signed_proxy" if signed else "fleet_api",
                          parameter_names=sorted(key for key in arguments if key in op["schema"]["properties"]),
                          private_parameter_values_logged=False)
        if name == "vehicle_fleet_telemetry_config_create":
            diagnostic['collection_request'] = request_summary(arguments.get('config', {}))
        if name in ("vehicle_nearby_charging_sites", "charging_history"):
            diagnostic["request_options"] = {key: value for key, value in arguments.items()
                if (key in ("count", "radius", "pageNo", "pageSize") and type(value) is int and 0 <= value <= 2147483647)
                or (key == "detail" and type(value) is bool) or (key == "sortOrder" and value in ("ASC", "DESC"))}
        try:
            with client.stream(op["method"], origin+path, params=query,
                               json=body if op["method"] != "GET" else None,
                               headers={"Authorization": "Bearer "+authorization.access_token, "Accept": "application/pdf" if binary else "application/json"}) as response:
                data = bytearray()
                maximum = 10*1024*1024 if binary else 2*1024*1024
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data) > maximum:
                        raise TeslaError("PROVIDER_RESPONSE_INVALID", "Response exceeds the size limit", uncertain=not op["readonly"])
                status = response.status_code
                media = response.headers.get("content-type", "").split(";", 1)[0].lower()
                diagnostic.update(provider_http_status=status, content_type=media_type(media))
        except httpx.HTTPError:
            raise TeslaError("OUTCOME_UNKNOWN" if not op["readonly"] else "PROVIDER_UNAVAILABLE",
                             "Tesla request interrupted; no automatic retry was made", uncertain=not op["readonly"]) from None
        if not 200 <= status < 300:
            if status == 401:
                if not self.store.invalidate_authorization(authorization):
                    raise TeslaError("AUTHORIZATION_CHANGED", "A previous authorization was rejected; the current connection was preserved", http_status=401)
            codes = {401: "AUTH_REQUIRED", 403: "PERMISSION_DENIED", 404: "NOT_FOUND", 408: "ASLEEP_OR_OFFLINE",
                     412: "PRECONDITION_FAILED", 421: "REGION_MISMATCH", 429: "RATE_LIMITED"}
            uncertain = not op["readonly"] and (status >= 500 or status == 408)
            detail = None
            collection_failure = name == "vehicle_fleet_telemetry_config_create" and status in (400, 413, 422)
            try:
                parsed = provider_json(data)
                diagnostic["response_shape"] = response_shape(parsed)
                diagnostic.update(http_rejection_reason(parsed))
                if collection_failure:
                    issue = rejection_diagnostic(parsed, arguments.get('config', {}).get('fields', {}))
                    diagnostic['collection_rejection'] = issue
                    if issue['classification'] == 'recognized':
                        detail = issue['message']
            except (ValueError, UnicodeError, RecursionError):
                if collection_failure:
                    diagnostic['collection_rejection'] = {
                        'classification': 'unavailable', 'response_issue': 'invalid_json',
                        'issues': [], 'source': 'provider_response', 'automatic_field_removal': False,
                        'evidence': {'sources': [], 'mentions_are_not_rejection_findings': True,
                                     'raw_text_stored': False}}
            raise TeslaError("OUTCOME_UNKNOWN" if uncertain else codes.get(status, "PROVIDER_ERROR"),
                             detail or (diagnostic["reason"] if diagnostic.get("reason_code") not in
                                (None, "PROVIDER_REASON_MISSING", "PROVIDER_REASON_UNCLASSIFIED") else
                                "Tesla rejected or could not complete the request"), http_status=status, uncertain=uncertain)
        try:
            self.store.require_authorization(authorization)
        except TeslaError:
            if not op["readonly"]:
                raise TeslaError("OUTCOME_UNKNOWN", "Authorization changed during dispatch; no command was replayed", uncertain=True) from None
            raise
        if binary:
            if media != "application/pdf" or not data.startswith(b"%PDF-"):
                raise TeslaError("PROVIDER_RESPONSE_INVALID", "Expected a PDF invoice")
            return bytes(data)
        try:
            decoded = provider_json(data)
        except (ValueError, UnicodeError, RecursionError):
            raise TeslaError("PROVIDER_RESPONSE_INVALID", "Tesla returned a response that is not valid JSON",
                http_status=status, uncertain=not op["readonly"], details={"response_issue": "invalid_json"}) from None
        diagnostic["response_shape"] = response_shape(decoded)
        # charging_history also returns a flat data/totalResults page. Accept
        # only this endpoint's observed envelope and validate every session;
        # never turn arbitrary JSON or an error body into a successful read.
        if (name == "charging_history" and status == 200 and media == "application/json"
                and isinstance(decoded, dict) and set(decoded) == {"data", "totalResults"}):
            validate_response(name, decoded)
            diagnostic["response_envelope"] = "charging_history_flat"
            return decoded
        if not isinstance(decoded, dict) or "response" not in decoded:
            raise TeslaError("PROVIDER_RESPONSE_INVALID", "Tesla response has no valid response envelope",
                http_status=status, uncertain=not op["readonly"],
                details={"response_issue": "response_envelope_missing", "envelope_kind": value_kind(decoded)})
        if any(decoded.get(key) for key in ("error", "errors", "error_description")):
            # A 2xx transport status does not turn an error/contradictory outer
            # envelope into command acceptance. Never copy provider free text.
            raise TeslaError("PROVIDER_RESPONSE_INVALID" if op["readonly"] else "OUTCOME_UNKNOWN",
                "Tesla returned an error in a successful response envelope; acceptance is not confirmed",
                http_status=status, uncertain=not op["readonly"],
                details={"response_issue": "error_envelope"})
        return decoded["response"]

    def discover(self, *, max_pages=100, expected_generation=None):
        if type(max_pages) is not int or not 1 <= max_pages <= 100:
            raise TeslaError("INVALID_ARGUMENT", "Invalid vehicle discovery page limit")
        vehicles = []
        authorization = self.authorization()
        if expected_generation is not None and authorization.generation != expected_generation:
            raise TeslaError("AUTH_REQUIRED", "Account authorization changed before vehicle discovery")
        sequence = self.store.begin_discovery(authorization)
        for page in range(1, max_pages+1):
            if expected_generation is not None and self.store.connection()["generation"] != expected_generation:
                raise TeslaError("AUTH_REQUIRED", "Account authorization changed during vehicle discovery")
            result = self.call("vehicle_list", {"page": page, "per_page": 100}, authorization=authorization)
            if not isinstance(result, list):
                raise TeslaError("PROVIDER_RESPONSE_INVALID", "Expected a paginated vehicle list")
            vehicles.extend(result)
            if len(result) < 100:
                self.store.save_vehicles(vehicles, expected_generation=expected_generation, authorization=authorization,
                                         discovery_sequence=sequence)
                return
        raise TeslaError("PROVIDER_RESPONSE_INVALID", "Vehicle discovery exceeded the page limit")
