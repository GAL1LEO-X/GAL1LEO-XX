"""Generate bounded, deterministic contract cases from the published schemas.

The schema is the oracle, not the implementation under test. Semantic rules
outside JSON Schema are listed explicitly; they are not inferred from failures.
All generated identities and content are synthetic. Nothing here uses a gateway.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import itertools
import json
import math
import re
from typing import Any, Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from jsonschema import Draft202012Validator, ValidationError as SchemaError, validators


MISSING = object()
MAX_BOUNDARY_ITEMS = 5001
MAX_BOUNDARY_TEXT = 65536
STRICT_TYPES = Draft202012Validator.TYPE_CHECKER.redefine(
    'integer', lambda checker, value: type(value) is int
)
StrictValidator = validators.extend(Draft202012Validator, type_checker=STRICT_TYPES)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def pointer(path):
    return '/' + '/'.join(str(part).replace('~', '~0').replace('/', '~1') for part in path) if path else ''


def resolve(schema, root):
    schema = copy.deepcopy(schema)
    ref = schema.pop('$ref', None)
    if ref:
        if not ref.startswith('#/'):
            raise ValueError('Only local schema references are supported')
        target = root
        for part in ref[2:].split('/'):
            target = target[part.replace('~1', '/').replace('~0', '~')]
        schema = merge(resolve(target, root), schema)
    return schema


def merge(left, right):
    result = copy.deepcopy(left)
    for key, value in right.items():
        if key == 'required':
            result[key] = sorted(set(result.get(key, ())) | set(value))
        elif key == 'properties':
            result[key] = {**result.get(key, {}), **copy.deepcopy(value)}
        else:
            result[key] = copy.deepcopy(value)
    return result


def branches(schema, root):
    schema = resolve(schema, root)
    for part in schema.pop('allOf', []):
        schema = merge(schema, resolve(part, root))
    for keyword in ('oneOf', 'anyOf'):
        if keyword in schema:
            choices = schema.pop(keyword)
            required = set(schema.get('required', ()))
            all_required = set().union(*(set(c.get('required', ())) for c in choices))
            result = []
            for choice in choices:
                selected = merge(schema, resolve(choice, root))
                # Required-only oneOf branches (label color/colorHex) must not
                # acquire the opposing selector via the optional-field seed.
                selected['_qa_exclude'] = sorted(all_required - set(selected.get('required', ())) - required)
                result.extend(branches(selected, root))
            return result
    if isinstance(schema.get('type'), list):
        return [{**schema, 'type': kind} for kind in schema['type']]
    return [schema]


def string_seed(schema, name):
    pattern = schema.get('pattern', '')
    if pattern.startswith('^media_'):
        value = 'media_' + 'a' * 32
    elif pattern.startswith('^history_'):
        value = 'history_' + 'a' * 32
    elif pattern.startswith('^change_'):
        value = 'change_' + 'a' * 64
    elif '@' in pattern or name in ('chatId', 'chat_id', 'contactId', 'participant', 'sender_ids', 'mention_ids'):
        value = '199999998@c.us'
    elif 'HH' in pattern or '[0-5][0-9]' in pattern:
        value = '22:00' if name == 'start' else '07:00'
    elif name == 'timezone':
        value = 'Europe/Berlin'
    elif name in ('url', 'download_url'):
        value = 'https://example.org/qa'
    elif name == 'idempotency_key':
        value = 'synthetic-qa-key-0001'
    elif name in ('phone', 'phoneNumber', 'whatsappId'):
        value = '199999998'
    elif name == 'vcard':
        value = 'BEGIN:VCARD\nVERSION:3.0\nFN:Synthetic QA\nEND:VCARD'
    else:
        value = 'synthetic-qa'
    length = schema.get('minLength', 0)
    value += 'a' * max(0, length - len(value))
    return value[:schema.get('maxLength', max(len(value), 1))]


def sample(schema, root, *, optional=True, name=''):
    schema = branches(schema, root)[0]
    if 'const' in schema:
        return copy.deepcopy(schema['const'])
    if 'enum' in schema:
        return copy.deepcopy(schema['enum'][0])
    kind = schema.get('type')
    if kind == 'null':
        return None
    if kind == 'object' or 'properties' in schema:
        keys = set(schema.get('required', ()))
        if optional:
            keys.update(schema.get('properties', {}))
        keys.difference_update(schema.get('_qa_exclude', ()))
        return {key: sample(schema.get('properties', {}).get(key, {}), root,
                            optional=optional, name=key) for key in sorted(keys)}
    if kind == 'array':
        size = max(schema.get('minItems', 0), 1 if optional else 0)
        return [sample(schema.get('items', {}), root, optional=optional, name=name) for _ in range(size)]
    if kind == 'boolean':
        return schema.get('default', False)
    if kind in ('integer', 'number'):
        number = schema.get('minimum', 0)
        if 'exclusiveMinimum' in schema:
            number = schema['exclusiveMinimum'] + (1 if kind == 'integer' else 0.5)
        return number
    if kind == 'string':
        return string_seed(schema, name)
    return 'synthetic-qa'


def replace_at(value, path, replacement):
    result = copy.deepcopy(value)
    if not path:
        return copy.deepcopy(replacement)
    target = result
    for part in path[:-1]:
        target = target[part]
    if replacement is MISSING:
        del target[path[-1]]
    else:
        target[path[-1]] = copy.deepcopy(replacement)
    return result


def contexts(schema, root, value, path=(), name=''):
    """Every branch and property gets a context, including optional parents."""
    for branch_index, branch in enumerate(branches(schema, root)):
        seeded = sample(branch, root, name=name)
        context = replace_at(value, path, seeded)
        yield branch, path, branch_index, context
        if branch.get('type') == 'object' or 'properties' in branch:
            for key, child in branch.get('properties', {}).items():
                if key in branch.get('_qa_exclude', ()):
                    continue
                yield from contexts(child, root, context, path + (key,), key)
        elif branch.get('type') == 'array':
            if not seeded:
                context = replace_at(value, path, [sample(branch.get('items', {}), root, name=name)])
            yield from contexts(branch.get('items', {}), root, context, path + (0,), name)


def mutations(schema, root, name):
    for label, value in [('null', None), ('boolean', True), ('false', False),
                         ('integer-zero', 0), ('fraction', 0.5), ('integer-float', 1.0),
                         ('empty-text', ''), ('text', 'synthetic-qa'),
                         ('unicode', 'QA à 😀\nseconda riga'), ('array-empty', []), ('object-empty', {})]:
        yield label, value
    if 'enum' in schema:
        for index, value in enumerate(schema['enum']):
            yield f'enum-{index}', value
        yield 'enum-outside', '__outside_enum__'
    if 'const' in schema:
        yield 'const-exact', schema['const']
        yield 'const-outside', '__outside_const__'
    if schema.get('type') == 'string':
        for bound in ('minLength', 'maxLength'):
            if bound in schema:
                for delta in (-1, 0, 1):
                    size = schema[bound] + delta
                    if 0 <= size <= MAX_BOUNDARY_TEXT:
                        yield f'{bound}-{delta:+d}', 'a' * size
        if 'pattern' in schema:
            yield 'pattern-valid', string_seed(schema, name)
            yield 'pattern-invalid', '!'
    if schema.get('type') in ('number', 'integer'):
        for bound in ('minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum'):
            if bound in schema:
                for delta in (-1, 0, 1):
                    yield f'{bound}-{delta:+d}', schema[bound] + delta
    if schema.get('type') == 'array':
        item = sample(schema.get('items', {}), root, name=name)
        yield 'array-one', [item]
        yield 'array-duplicates', [item, item]
        for bound in ('minItems', 'maxItems'):
            if bound in schema:
                for delta in (-1, 0, 1):
                    size = schema[bound] + delta
                    if 0 <= size <= MAX_BOUNDARY_ITEMS:
                        yield f'{bound}-{delta:+d}', [item] * size
    if schema.get('type') == 'object' or 'properties' in schema:
        yield 'unknown-property', {**sample(schema, root), '__unknown__': True}


def operation_semantics(name, value):
    args = {'path': {}, 'query': {}, 'body': {}, **value}
    if len(canonical(args)) > 200000:
        return False
    for item in args['path'].values():
        if not isinstance(item, str) or not item or len(item) > 512 or any(c in item for c in ('/', '\\', '..', '%')):
            return False
    body = args['body']
    if name == 'presence_set_presence':
        return (body['presence'] in ('typing', 'recording', 'paused')) == bool(body.get('chatId'))
    if name == 'calendar_send_event':
        return body['event'].get('endTime', body['event']['startTime']) >= body['event']['startTime']
    if name == 'messages_send_list':
        return bool(re.fullmatch(r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)', body['chatId']))
    if name == 'messages_send_link_custom_preview':
        from urllib.parse import urlsplit
        url = urlsplit(body['preview']['url'])
        return url.scheme in ('http', 'https') and bool(url.hostname) and not url.username and not url.password
    return True


def model_semantics(value):
    def check(part):
        if isinstance(part, dict):
            if {'timezone', 'start', 'end'} <= set(part):
                if part['start'] == part['end']:
                    return False
                try:
                    ZoneInfo(part['timezone'])
                except (ZoneInfoNotFoundError, ValueError):
                    return False
            return all(check(v) for v in part.values())
        return all(check(v) for v in part) if isinstance(part, list) else True
    return check(value)


@dataclass
class Surface:
    name: str
    schema: dict
    kind: str
    validate: Callable[[Any], Any]
    unsupported: bool = False
    strict: bool = False


def surfaces():
    # Imports define models/functions only; no app, database or session starts.
    from sally_whatsapp import server
    from sally_whatsapp.operations import OPERATIONS, validate_operation
    from sally_whatsapp.event_policies import Filters, QuietHours
    def validate_call(name, operation, value):
        wrapped = server.OperationArguments.model_validate({'operation': name, 'arguments': value})
        return validate_operation(name, wrapped.arguments, readonly=operation['readonly'],
                                  transfer={'id': 'synthetic'} if operation['media_required'] else None,
                                  provider_operations=tuple(OPERATIONS))
    for name, op in OPERATIONS.items():
        yield Surface(name, op['schema'], 'operation',
                      lambda value, n=name, o=op: validate_call(n, o, value),
                      unsupported=op['capability'] == 'unsupported_gows')
    for name, (model, *_) in server.TOOLS.items():
        yield Surface(name, model.model_json_schema(), 'tool', model.model_validate, strict=True)
    for model in (server.Subscribe, server.Unsubscribe, Filters, QuietHours, server.Profile):
        yield Surface(model.__name__, model.model_json_schema(), 'model', model.model_validate, strict=True)
    for definition in (server.EVENT_DEFINITION, server.DIGEST_EVENT_DEFINITION, server.ACCOUNT_EVENT_DEFINITION):
        schema = definition['payloadSchema']
        yield Surface(definition['name'], schema, 'event_payload', Draft202012Validator(schema).validate)


def generate(surface):
    root = surface.schema
    Draft202012Validator.check_schema(root)
    oracle = (StrictValidator if surface.strict else Draft202012Validator)(root)
    seen = set()
    baseline = sample(root, root)
    for schema, path, branch, context in contexts(root, root, baseline):
        candidates = [('present', sample(schema, root, name=str(path[-1]) if path else ''))]
        candidates.extend(mutations(schema, root, str(path[-1]) if path else ''))
        if path and not isinstance(path[-1], int):
            candidates.append(('omitted', MISSING))
        for variant, replacement in candidates:
            payload = replace_at(context, path, replacement)
            if surface.kind == 'operation' and isinstance(payload, dict):
                # This is the documented defaulting at the operation boundary.
                checked = {'path': {}, 'query': {}, 'body': {}, **payload}
            else:
                checked = payload
            # SDK-owned request metadata is not a strict application model.
            # JSON Schema permits 1.0 for an integer, but never true/false.
            metadata = surface.kind == 'model' and surface.name in {'Subscribe', 'Unsubscribe'} and path[:1] == ('_meta',)
            valid = (Draft202012Validator(root) if metadata else oracle).is_valid(checked)
            if valid and surface.kind == 'operation':
                valid = operation_semantics(surface.name, checked)
            elif valid and surface.strict:
                valid = model_semantics(checked)
            key = (pointer(path), variant, canonical(payload))
            if key in seen:
                continue
            seen.add(key)
            identifier = hashlib.sha256(canonical([surface.kind, surface.name, *key]).encode()).hexdigest()[:16]
            yield {'case_id': f'{surface.kind}-{surface.name}-{identifier}', 'surface': surface.name,
                   'kind': surface.kind, 'field': pointer(path), 'branch': branch, 'variant': variant,
                   'expected': 'unsupported' if surface.unsupported and isinstance(payload, dict) else 'accept' if valid else 'reject',
                   'payload': payload, 'evidence_level': 'synthetic_contract'}


def run_contracts(output, *, selected=None):
    """Validate generated inputs without constructing a service or HTTP client."""
    from collections import Counter
    from pathlib import Path
    from unittest.mock import patch
    from sally_whatsapp.operations import OperationUnavailable
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True)
    counts, fields, failures = Counter(), {}, []
    # The only validator that resolves DNS gets a controlled public address.
    with patch('sally_whatsapp.events.public_addresses', return_value=['93.184.216.34']), \
         (directory / 'contract-results.jsonl').open('w', encoding='utf-8') as results:
        for surface in surfaces():
            if selected and surface.name not in selected:
                continue
            for case in generate(surface):
                try:
                    surface.validate(case['payload'])
                    actual = 'accept'
                except OperationUnavailable as error:
                    actual = 'unsupported' if error.detail()['error_code'] == 'OPERATION_UNSUPPORTED' else 'exception'
                except (ValueError, SchemaError, TypeError, KeyError, AttributeError) as error:
                    actual = 'reject' if isinstance(error, (ValueError, SchemaError)) else 'exception:' + type(error).__name__
                passed = actual == case['expected']
                entry = {k: v for k, v in case.items() if k != 'payload'}
                entry.update(actual=actual, status='PASS' if passed else 'FAIL')
                # Unsupported validation is recorded separately from a positive
                # functional success. Schema rejection never proves delivery.
                counts[entry['status']] += 1
                counts['expected_' + case['expected']] += 1
                key = surface.kind + ':' + surface.name + ':' + case['field']
                fields.setdefault(key, set()).add(case['variant'])
                if not passed:
                    failures.append({**entry, 'synthetic_input': case['payload']})
                results.write(canonical(entry) + '\n')
    summary = {'evidence_level': 'synthetic_contract', 'counts': dict(counts), 'field_paths': len(fields),
               'fields': {k: sorted(v) for k, v in sorted(fields.items())},
               'failures': failures, 'live_calls': 0,
               'limit': 'Input contracts only; provider effects, outputs and phone rendering require their own evidence.'}
    (directory / 'contract-summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return summary
