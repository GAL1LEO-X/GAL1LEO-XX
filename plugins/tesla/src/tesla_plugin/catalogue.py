"""Closed endpoint catalogue. Callers cannot choose hosts, VINs or HTTP paths."""
from copy import deepcopy
from datetime import datetime
from importlib.resources import files
import json
import math
import re
from jsonschema import Draft202012Validator

from .errors import TeslaError
from .preconditions import requirements

CATALOGUE = json.loads(files(__package__).joinpath("data/operations.json").read_text())
OPERATIONS = {row["id"]: row for row in CATALOGUE["operations"]}
FIELDS = json.loads(files(__package__).joinpath("data/telemetry.json").read_text())
# Wide telemetry profiles plus include_fields are larger than ordinary command
# arguments. Remain below the MCP envelope (256 KiB) and signed proxy (1 MiB).
COLLECTION_ARGUMENT_BYTES = 192 * 1024


def operation(name):
    if not isinstance(name, str) or name not in OPERATIONS:
        raise TeslaError("INVALID_OPERATION", "Unknown Tesla operation")
    return OPERATIONS[name]


def finite(value):
    if isinstance(value, float) and not math.isfinite(value):
        raise TeslaError("INVALID_ARGUMENT", "Non-finite numbers are not accepted")
    if isinstance(value, dict):
        for v in value.values():
            finite(v)
    elif isinstance(value, list):
        for v in value:
            finite(v)


def validate(name, arguments, *, sensitive=False):
    op = operation(name)
    finite(arguments)
    if not isinstance(arguments, dict):
        raise TeslaError("INVALID_ARGUMENT", "Arguments must be an object")
    size = len(json.dumps(arguments, allow_nan=False).encode('utf-8'))
    maximum = COLLECTION_ARGUMENT_BYTES if name == 'vehicle_fleet_telemetry_config_create' else 32768
    if size > maximum:
        raise TeslaError("INVALID_ARGUMENT", "Telemetry configuration exceeds the local size limit; no fields were removed"
                         if name == 'vehicle_fleet_telemetry_config_create' else "Arguments are too large",
                         details={'argument_bytes': size, 'maximum_argument_bytes': maximum})
    schema = op["schema"] if sensitive else public_schema(op)
    errors = sorted(Draft202012Validator(schema).iter_errors(arguments), key=lambda e: str(e.path))
    if errors:
        # jsonschema's default error message can contain the supplied PIN/body.
        raise TeslaError("INVALID_ARGUMENT", "Arguments do not match the operation schema")
    if name == "charging_history":
        dates = {}
        for key in ("startTime", "endTime"):
            if key in arguments:
                value = arguments[key]
                try:
                    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})", value):
                        raise ValueError()
                    dates[key] = datetime.fromisoformat(value.replace("z", "+00:00").replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    raise TeslaError("INVALID_ARGUMENT", "Use ISO 8601 dates with a timezone, for example 2026-10-27T00:00:00+01:00") from None
        if len(dates) == 2 and dates["startTime"] > dates["endTime"]:
            raise TeslaError("INVALID_ARGUMENT", "startTime must not be after endTime")
    if name == "add_charge_schedule":
        for flag, key in (("start_enabled", "start_time"), ("end_enabled", "end_time")):
            if arguments.get(flag) and key not in arguments:
                raise TeslaError("INVALID_ARGUMENT", "Enabled schedule boundaries need a local time")
    for key in ("waypoints", "calendar_data"):
        if key in arguments:
            value = arguments[key]
            try:
                valid = bool(value.strip()) and "\x00" not in value and len(value.encode("utf-8")) <= 16384
            except (UnicodeError, AttributeError):
                valid = False
            if not valid:
                raise TeslaError("INVALID_ARGUMENT", "Navigation/calendar text must be nonempty UTF-8, without NUL, at most 16384 bytes")
    return deepcopy(arguments)


def public_schema(op):
    schema = deepcopy(op["schema"])
    for key in op.get("sensitive_fields", []):
        schema["properties"].pop(key, None)
        schema["required"] = [r for r in schema.get("required", []) if r != key]
    return schema


def invocation(name):
    """One public routing policy, distinct from the provider endpoint shape."""
    op = operation(name)
    if name in ('vehicle_fleet_telemetry_config_create', 'vehicle_fleet_telemetry_config_delete'):
        return {'mode': 'collection', 'callable': True, 'tool': 'tesla_prepare_collection',
                'fixed_arguments': {'action': 'configure' if name.endswith('_create') else 'pause'},
                'vehicle_ref_required': True, 'client_request_id_required': True,
                'expected_revision_required': True,
                'workflow': ['tesla_get_collection', 'tesla_prepare_collection', 'tesla_confirm_collection'],
                'confirmation_requires': ['intent_id', 'review_digest', 'decision'],
                'note': 'Use the collection tool schema and reviewed fields; raw provider config is not a tool argument.'}
    if op['availability'] != 'supported_transport':
        return {'mode': 'operator_only' if op['availability'] == 'operator_only' else 'unavailable',
                'callable': False, 'reason': op['reason']}
    return {'mode': 'read' if op['readonly'] else 'command', 'callable': True,
            'tool': 'tesla_read' if op['readonly'] else 'tesla_prepare_action',
            'operation': name, 'parameters_key': 'arguments',
            'vehicle_ref_required': op['vehicle_bound'] or name == 'charging_invoice',
            'client_request_id_required': not op['readonly']}


def describe(name):
    op = operation(name)
    conditions = requirements(name)
    return {**{k: op[k] for k in ("id", "description", "category", "availability", "reason", "readonly", "scopes", "source")},
            "input_schema": public_schema(op), "secure_owner_fields": op.get("sensitive_fields", []),
            "vehicle_qualified": False, "qualification_scope": "catalogue_only",
            "transport_requirement": op.get("proxy_extension"),
            "implementation_status": op.get("implementation_status", "transport_implemented" if op["availability"] == "supported_transport" else "catalogue_only"),
            "contract_source": op.get("contract_source", op["source"]),
            "limitations": list(dict.fromkeys(op.get("limitations", [])+[row["label"] for row in conditions])),
            "requirements": conditions, "input_permissions": op.get("input_permissions", []),
            "call_contract": invocation(name)}
