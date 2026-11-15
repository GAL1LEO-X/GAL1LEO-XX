"""Finite collection diagnostics. Provider text never becomes stored instructions."""
import json
import math
import re


PARAMETERS = frozenset({'interval_seconds', 'resend_interval_seconds', 'minimum_delta',
                        'include_fields', 'alert_types', 'delivery_policy', 'hostname', 'port', 'ca', 'exp'})
SKIP_REASONS = frozenset({'missing_key', 'unsupported_hardware', 'unsupported_firmware', 'max_configs'})
CONSTRAINT_TERMS = frozenset({'unknown', 'invalid', 'unsupported', 'missing', 'required', 'minimum', 'maximum',
                             'limit', 'size', 'bytes', 'length', 'rate', 'interval', 'integer', 'number',
                             'string', 'array', 'object', 'schema', 'signature', 'certificate', 'hostname',
                             'expired', 'scope', 'permission', 'firmware', 'hardware'})


def reason_sources(body):
    if not isinstance(body, dict):
        return []
    sources = [(key, body[key]) for key in ('error', 'error_description', 'message') if key in body]
    response = body.get('response')
    if isinstance(response, dict) and 'reason' in response:
        sources.append(('response.reason', response['reason']))
    return sources


def rejection_diagnostic(body, selected_fields):
    """Keep bounded public-token hints when an exact error template is unknown.

    Mentions are not findings: the provider may quote a request or unrelated text.
    No raw text, arbitrary identifiers, values, numbers or executable advice is kept.
    """
    from .telemetry import FIELD_MAP
    selected = set(selected_fields) & set(FIELD_MAP)
    recognized = rejection(body, selected)
    sources = []
    for source, value in reason_sources(body):
        state = ('non_text' if not isinstance(value, str) else 'too_long' if len(value) > 4096
                 else 'empty' if not value.strip() else 'present')
        observation = {'source': source, 'text_state': state}
        if state == 'present':
            words = set(re.findall(r'[A-Za-z][A-Za-z0-9_]*', value))
            fields = sorted(words & selected)
            observation.update(field_mentions=fields, field_mentions_truncated=False, field_mention_count=len(fields),
                               parameter_mentions=sorted(words & PARAMETERS),
                               constraint_terms=sorted({word.lower() for word in words} & CONSTRAINT_TERMS))
        sources.append(observation)
    return {**(recognized or {'issues': [], 'source': 'provider_response', 'automatic_field_removal': False,
                             'message': 'Tesla rejected the telemetry configuration; the reason remains unclassified.'}),
            'classification': 'recognized' if recognized else 'unclassified',
            'evidence': {'sources': sources, 'mentions_are_not_rejection_findings': True,
                         'raw_text_stored': False}}


def structured_issue(value, selected):
    if not isinstance(value, dict):
        return None
    field, parameter, code = value.get('field'), value.get('parameter'), value.get('code')
    if not isinstance(field, str) or field not in selected or not isinstance(code, str):
        return None
    if code in ('unknown_field', 'unsupported_field', 'invalid_field'):
        return {'code': 'FIELD_REJECTED', 'field': field}
    if not isinstance(parameter, str) or parameter not in PARAMETERS:
        return None
    if code in ('minimum', 'maximum'):
        bound = value.get(code)
        if type(bound) in (int, float) and 0 <= bound <= 1_000_000_000 and math.isfinite(bound):
            return {'code': 'PARAMETER_'+code.upper(), 'field': field, 'parameter': parameter, code: bound}
    if code == 'invalid_parameter':
        return {'code': 'PARAMETER_REJECTED', 'field': field, 'parameter': parameter}
    return None


def request_summary(config):
    fields = config.get('fields', {})
    intervals = [v.get('interval_seconds') for v in fields.values() if isinstance(v, dict)]
    return {'selected_field_count': len(fields),
            'config_bytes': len(json.dumps(config, separators=(',', ':'), ensure_ascii=False).encode()),
            'minimum_interval_seconds': min(intervals) if intervals and all(type(v) is int for v in intervals) else None,
            'field_values_logged': False, 'automatic_field_removal': False}


def rejection(body, selected_fields):
    """Recognize public tokens and bounded limits, never keep arbitrary sentences.

    Exact templates are deliberately conservative. An unrecognized response
    remains unclassified; these issues never authorize retries or field removal.
    The historical 238-field response is unavailable and is not reconstructed.
    """
    from .telemetry import FIELD_MAP
    selected = set(selected_fields) & set(FIELD_MAP)
    if not isinstance(body, dict):
        return None
    candidates = reason_sources(body)
    issues = []
    for source, text in candidates:
        if not isinstance(text, str) or not 0 < len(text) <= 4096:
            continue
        text = text.strip()
        for prefix in ('Invalid configuration: ', 'Invalid config: '):
            if text.startswith(prefix):
                text = text[len(prefix):]
                break
        issue = None
        plural = re.fullmatch(r'(?:Unknown|Unrecognized|Unsupported|Invalid) fields:\s*(\[?)([A-Za-z0-9_,\s\'\"]+)(\]?)[.!]?', text, re.I)
        if plural and bool(plural[1]) == bool(plural[3]):
            tokens = [p.strip().strip('\'\"') for p in plural[2].split(',')]
            if tokens and all(re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', p) and p in selected for p in tokens):
                issues.extend({'code': 'FIELD_REJECTED', 'field': p, 'source': source} for p in sorted(set(tokens)))
                continue
        match = re.fullmatch(r'(?:Unknown|Unrecognized|Unsupported|Invalid) field [\'\"]?([A-Za-z][A-Za-z0-9_]*)[\'\"]?[.!]?', text, re.I)
        if match and match[1] in selected:
            issue = {'code': 'FIELD_REJECTED', 'field': match[1]}
        # Existing public prerequisite, with no echo of optional private context.
        elif 'SelfDrivingMilesSinceReset' in selected and re.match(
                r'^SelfDrivingMilesSinceReset requires minimum_delta (?:>=|of at least) 1(?: mile)?(?:[.;](?!\d)|$)', text):
            issue = {'code': 'PARAMETER_MINIMUM', 'field': 'SelfDrivingMilesSinceReset',
                     'parameter': 'minimum_delta', 'minimum': 1}
        elif text == ('Total data transfer rate is too high. Please reduce field count or '
                      'increase interval_seconds for some fields.'):
            # Public historical Tesla wording, not evidence of a current limit:
            # fleet-telemetry issue 118, comment 2109641663; limits later removed.
            issue = {'code': 'TRANSFER_RATE_REJECTED'}
        else:
            match = re.fullmatch(r'(?:fields\.)?([A-Za-z][A-Za-z0-9_]*)\.([a-z_]+) must be (at least|at most|>=|<=) ([0-9]{1,9}(?:\.[0-9]{1,6})?)(?: seconds)?[.!]?', text)
            if match and match[1] in selected and match[2] in PARAMETERS:
                bound = 'minimum' if match[3] in ('at least', '>=') else 'maximum'
                issue = {'code': 'PARAMETER_'+bound.upper(), 'field': match[1], 'parameter': match[2], bound: float(match[4])}
            match = re.fullmatch(r'(?:Too many fields: maximum|Maximum number of fields is) ([0-9]{1,6})[.!]?', text, re.I)
            if match:
                issue = {'code': 'FIELD_COUNT_LIMIT', 'maximum_fields': int(match[1])}
            match = re.fullmatch(r'(?:Configuration|Request)(?: size)? exceeds (?:maximum )?([0-9]{1,9}) bytes[.!]?', text, re.I)
            if match:
                issue = {'code': 'CONFIGURATION_SIZE_LIMIT', 'maximum_bytes': int(match[1])}
            if issue is None:
                for parameter in sorted(PARAMETERS):
                    if re.match(r'^'+parameter+r'(?: must be positive| is invalid| is not supported)(?:[.;]|$)', text):
                        issue = {'code': 'PARAMETER_REJECTED', 'parameter': parameter}
                        break
        if issue:
            issues.append({**issue, 'source': source})
    # Optional structured errors are evidence only, not an assumed Tesla schema.
    # Keep solely selected public field names, finite codes/parameters and limits.
    errors = body.get('errors')
    if isinstance(errors, list):
        for value in errors[:len(FIELD_MAP)]:
            issue = structured_issue(value, selected)
            if issue:
                issues.append({**issue, 'source': 'errors'})
    if not issues:
        return None
    # Bounded by catalogue size/source count; only public tokens, never raw text.
    unique = list({json.dumps(issue, sort_keys=True): issue for issue in issues}.values())
    return {'issues': unique, 'source': 'provider_response', 'automatic_field_removal': False,
            'message': message(issues[0])}


def message(issue):
    code = issue['code']
    if code == 'FIELD_REJECTED':
        return 'Tesla did not recognize or accept the selected telemetry field: '+issue['field']
    if code == 'PARAMETER_MINIMUM' and issue.get('field') == 'SelfDrivingMilesSinceReset' and issue.get('minimum') == 1:
        return 'Tesla requires minimum_delta of at least 1 mile for SelfDrivingMilesSinceReset'
    if code in ('PARAMETER_MINIMUM', 'PARAMETER_MAXIMUM'):
        bound = 'minimum' if code == 'PARAMETER_MINIMUM' else 'maximum'
        return f"Tesla rejected {issue['field']}.{issue['parameter']}: {bound} {issue[bound]:g}"
    if code == 'FIELD_COUNT_LIMIT':
        return f"Tesla reports a maximum of {issue['maximum_fields']} telemetry fields"
    if code == 'CONFIGURATION_SIZE_LIMIT':
        return f"Tesla reports a maximum configuration size of {issue['maximum_bytes']} bytes"
    if code == 'TRANSFER_RATE_REJECTED':
        return 'Tesla rejected the configured aggregate data transfer rate; no numeric limit was provided'
    return 'Tesla rejected the telemetry parameter: '+issue['parameter']


def configuration_outcome(result, vin):
    """A single-vehicle result must be consistent before replacing its profile."""
    unknown = ('unknown', {'accepted': None, 'synced': False, 'code': 'OUTCOME_UNKNOWN',
                          'reason_code': 'CONFIGURATION_RESPONSE_INVALID', 'dispatch_attempted': True,
                          'message': 'Configuration response is incomplete or contradictory; check the readback before any new request.'})
    if not isinstance(result, dict) or type(result.get('updated_vehicles')) is not int or result['updated_vehicles'] not in (0, 1):
        return unknown
    # The endpoint documents this member for skipped VINs, not as mandatory
    # on every success. Absence is allowed; an explicit null/malformed member
    # or contradictory contents must still produce an uncertain outcome.
    skipped = result.get('skipped_vehicles', {})
    if not isinstance(skipped, dict) or any(not isinstance(v, list) or any(not isinstance(x, str) for x in v) for v in skipped.values()):
        return unknown
    reasons = [reason for reason, vins in skipped.items() if vin in vins]
    if result['updated_vehicles'] == 1:
        if any(skipped.values()):
            return unknown
        return 'acknowledged', {'accepted': True, 'synced': False, 'dispatch_attempted': True}
    return 'rejected', {'accepted': False, 'synced': False, 'dispatch_attempted': True,
                        'reason_code': 'CONFIGURATION_NOT_ACCEPTED',
                        'skipped_reasons': sorted(set(reasons) & SKIP_REASONS),
                        'unclassified_skip_reason': bool(set(reasons)-SKIP_REASONS)}


def deletion_outcome(result):
    """Classify pause replies without persisting provider text or guessing effects.

    Retain the existing null/true success representations; the public DELETE
    description does not establish a stricter envelope. Explicit errors cannot
    become success, and unrecognized structures require readback, never retry.
    """
    from .provider_diagnostics import rejection_reason
    base = {'physical_effect_verified': False, 'dispatch_attempted': True, 'synced': False}
    unknown = ('unknown', {**base, 'accepted': None, 'code': 'OUTCOME_UNKNOWN',
                          'reason_code': 'CONFIGURATION_DELETE_RESPONSE_UNQUALIFIED'})
    if result is False:
        return 'rejected', {**base, 'accepted': False, 'code': 'COMMAND_REJECTED',
                            **rejection_reason(None)}
    if result is None or result is True:
        return 'acknowledged', {**base, 'accepted': True, 'acceptance_basis': 'legacy_delete_response'}
    if not isinstance(result, dict):
        return unknown
    indicators = [result.get(key) for key in ('error', 'errors', 'error_description')]
    indicators = [value for value in indicators if value is not None and value is not False
                  and value != '' and value != [] and value != {}]
    error = indicators[0] if indicators else None
    has_error = bool(indicators)
    accepted = result.get('result')
    if has_error and accepted is True:
        return unknown
    if has_error or accepted is False:
        return 'rejected', {**base, 'accepted': False, 'code': 'COMMAND_REJECTED',
                            **rejection_reason(error if has_error else result.get('reason'))}
    if accepted is True:
        return 'acknowledged', {**base, 'accepted': True}
    return unknown
