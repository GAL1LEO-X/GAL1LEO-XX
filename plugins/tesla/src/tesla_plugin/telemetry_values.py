"""Validate a decoded protobuf oneof before using it as an observation.

The receiver emits unpopulated message members. Missing fields are never filled
here: an incomplete location or door message must not invent a physical state.
"""
import json
import hashlib
import math
from pathlib import Path
import re

from .catalogue import FIELDS

CONTRACT = json.loads((Path(__file__).parent/'data/telemetry-wire.json').read_text())
WIRE = CONTRACT['branches']
SCALARS = {'string_value', 'int_value', 'long_value', 'float_value', 'double_value'}
NUMERIC = SCALARS-{'string_value'}
DOORS = {'DriverFront', 'DriverRear', 'PassengerFront', 'PassengerRear', 'TrunkFront', 'TrunkRear'}
TIRES = {'front_left', 'front_right', 'rear_left', 'rear_right', 'semi_middle_axle_left_2',
         'semi_middle_axle_right_2', 'semi_rear_axle_left', 'semi_rear_axle_right',
         'semi_rear_axle_left_2', 'semi_rear_axle_right_2'}
TIRE_KEYS = {alias: key for key in TIRES for alias in
             (key, ''.join(p.title() if i else p for i, p in enumerate(key.split('_'))))}
DECODER_VERSION = '1.0.0'
# Fingerprint both the wire branches and field qualification/type/unit contracts.
# Receipt time and arbitrary receiver metadata do not identify either contract.
CONTRACT_VERSION = 'sha256:'+hashlib.sha256(json.dumps(
    {'wire': CONTRACT, 'fields': FIELDS}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
KNOWN_BRANCHES = frozenset(WIRE.values()) | SCALARS | {'boolean_value', 'invalid'}


def safe_branch(envelope):
    """Return only a known normalized branch name, never an input property."""
    if not isinstance(envelope, dict) or len(envelope) != 1:
        return None
    branch = next(iter(envelope))
    if not isinstance(branch, str):
        return None
    normalized = snake(branch)
    camel = ''.join(p.title() if i else p for i, p in enumerate(normalized.split('_')))
    return normalized if normalized in KNOWN_BRANCHES and branch in (normalized, camel) else None


def decode_evidence(spec, envelope, *, source_transport='decoded_receiver'):
    """Decode unchanged values and retain a bounded explanation of that decode.

    No arbitrary transport identifiers, property names, enum values, receiver
    metadata or payload fragments are copied into provenance.
    """
    value, quality = decode(spec, envelope)
    branch = safe_branch(envelope)
    if quality == 'valid':
        reason = 'recognized_value'
    elif quality == 'unqualified':
        reason = 'field_value_contract_unavailable'
    elif quality == 'enum_unknown':
        reason = 'enum_value_unknown_or_unavailable'
    elif branch == 'invalid':
        reason = 'invalid_branch_received'
    elif not isinstance(envelope, dict) or len(envelope) != 1:
        reason = 'invalid_value_envelope'
    elif branch is None:
        reason = 'unrecognized_oneof_branch'
    else:
        reason = 'invalid_value_for_contract'
    return value, quality, {
        'source_transport': source_transport if source_transport in ('decoded_receiver', 'kafka') else 'unknown',
        'quality_reason': reason, 'decoder_version': DECODER_VERSION,
        'contract_version': CONTRACT_VERSION, 'oneof_branch': branch,
    }


def snake(value):
    return re.sub(r'(?<!^)(?=[A-Z])', '_', value).lower()


def decode(spec, envelope):
    if not isinstance(envelope, dict) or len(envelope) != 1:
        return None, 'invalid'
    branch, value = next(iter(envelope.items()))
    if not isinstance(branch, str):
        return None, 'invalid'
    normalized = snake(branch)
    # Accept only the exact proto spelling and its canonical JSON alias.
    camel = ''.join(p.title() if i else p for i, p in enumerate(normalized.split('_')))
    if branch not in (normalized, camel) or normalized == 'invalid':
        return None, 'invalid'
    kind = spec['documented_type'].lower()
    proto = spec['protobuf_value_type']
    enum = spec['enum_values']
    if spec.get('value_contract') == 'protobuf_oneof_only':
        # Public Key without a public per-field value contract. Preserve its
        # typed observation, but never promote it to rule/safety evidence.
        inferred_proto = next((k for k, v in WIRE.items() if v == normalized), '')
        inferred_kind = ('real' if normalized in SCALARS-{'string_value'} else 'string' if normalized == 'string_value'
                         else 'boolean' if normalized == 'boolean_value' else '')
        if not inferred_proto and not inferred_kind:
            return None, 'invalid'
        shadow = {**spec, 'value_contract': None, 'documented_type': inferred_kind,
                  'protobuf_value_type': inferred_proto, 'enum_values': CONTRACT['enums'].get(inferred_proto, '')}
        decoded, quality = decode(shadow, envelope)
        return decoded, 'unqualified' if quality == 'valid' else quality
    if enum:
        if normalized not in {'string_value', WIRE.get(proto)}:
            return None, 'invalid'
        if spec['field'] == 'Gear' and normalized == 'string_value' and isinstance(value, str):
            value = {'P': 'ShiftStateP', 'D': 'ShiftStateD', 'R': 'ShiftStateR', 'N': 'ShiftStateN'}.get(value, value)
        names = {p.split('=')[0] for p in enum.split('|')}
        if not isinstance(value, str) or value not in names:
            return None, 'enum_unknown'
        return value, 'enum_unknown' if value.endswith(('Unknown', 'Invalid', 'SNA')) else 'valid'
    if kind in ('real', 'integer', 'timestamp'):
        if normalized not in SCALARS or type(value) is bool:
            return None, 'invalid'
        if normalized == 'string_value' or (normalized == 'long_value' and isinstance(value, str)):
            if not isinstance(value, str) or len(value) > 64 or not re.fullmatch(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?', value):
                return None, 'invalid'
            value = float(value) if any(x in value for x in '.eE') else int(value)
        if type(value) not in (int, float) or not -1e308 <= value <= 1e308 or not math.isfinite(value):
            return None, 'invalid'
        if normalized in ('int_value', 'long_value'):
            bits = 32 if normalized == 'int_value' else 64
            if int(value) != value or not -(2**(bits-1)) <= value < 2**(bits-1):
                return None, 'invalid'
        if normalized == 'float_value' and abs(value) > 3.4028234663852886e38:
            return None, 'invalid'
        if kind in ('integer', 'timestamp'):
            if int(value) != value or (kind == 'timestamp' and not 0 <= value <= 253402300799):
                return None, 'invalid'
            value = int(value)
        return value, 'valid'
    if kind in ('boolean', 'bool'):
        if normalized == 'string_value' and type(value) is str and value in ('true', 'false'):
            return value == 'true', 'valid'
        return (value, 'valid') if normalized == 'boolean_value' and type(value) is bool else (None, 'invalid')
    if kind == 'string':
        limit = 65536 if spec['field'] == 'RouteLine' else 4096
        return (value, 'valid') if normalized == 'string_value' and isinstance(value, str) and len(value) <= limit else (None, 'invalid')
    if normalized != WIRE.get(proto) or not isinstance(value, dict):
        return None, 'invalid'
    if proto == 'LocationValue':
        if set(value) != {'latitude', 'longitude'}:
            return None, 'invalid'
        if all(type(value[k]) in (int, float) and -bound <= value[k] <= bound and math.isfinite(value[k])
               for k, bound in (('latitude', 90), ('longitude', 180))):
            return value, 'valid'
    elif proto == 'Doors':
        if set(value) == DOORS and all(type(v) is bool for v in value.values()):
            return value, 'valid'
    elif proto == 'TireLocation':
        keys = [TIRE_KEYS.get(k) for k in value if isinstance(k, str)]
        if keys and len(set(keys)) == len(value) and set(keys) <= TIRES and all(type(v) is bool for v in value.values()):
            return value, 'valid'
    elif proto == 'Time':
        if set(value) == {'hour', 'minute', 'second'} and all(type(value[k]) is int and 0 <= value[k] < limit
                 for k, limit in (('hour', 24), ('minute', 60), ('second', 60))):
            return value, 'valid'
    return None, 'invalid'


def plausibility(field, value, quality):
    """Interpretation warnings do not reclassify a well-formed wire value.

    These exact decimal/binary32 representations are a diagnostic pattern,
    not a certified Tesla sentinel or a physical range/zero threshold. Tesla
    does not document a unit or a valid physical range for DiAxleSpeedR.
    """
    if (field == 'DiAxleSpeedR' and quality == 'valid' and type(value) in (int, float)
            and value in (-3276.8, -3276.800048828125)):
        return {'status': 'review_required', 'reason': 'axle_speed_numeric_pattern_semantics_unverified',
                'policy': 'exact_decimal_or_binary32_pattern', 'unit': None,
                'wire_quality_changed': False, 'value_changed': False,
                'certified_sentinel': False}
    return None


def rule_eligibility(field, value, quality):
    """Local decision policy; neither a Tesla invalid flag nor a data rewrite."""
    if quality != 'valid':
        return {'eligible': False, 'reason': 'wire_quality_not_valid', 'policy': 'wire_contract',
                'scope': 'numeric_threshold'}
    if plausibility(field, value, quality):
        return {'eligible': False, 'reason': 'local_plausibility_review_required',
                'policy': 'local_exact_axle_pattern_v1', 'scope': 'numeric_threshold'}
    return {'eligible': True, 'reason': 'no_local_rule_exclusion', 'policy': 'local_exact_axle_pattern_v1',
            'scope': 'numeric_threshold'}


def semantics(field, value, source_at, quality):
    """Additional meaning/measurement warnings, without rewriting stored values."""
    notes = []
    if field.startswith('TpmsLastSeenPressureTime'):
        notes.append('tesla_documents_tpms_timezone_issue')
        if quality == 'valid' and type(value) in (int, float) and source_at is not None and value > source_at + 30:
            notes.append('measurement_timestamp_after_payload_timestamp')
    if field == 'ChargeRateMilePerHour' and quality == 'valid' and type(value) in (int, float) and value < 0:
        notes.append('negative_rate_semantics_unverified_do_not_treat_as_physical_rate')
    if field in ('DestinationName', 'DestinationLocation', 'ExpectedEnergyPercentAtTripArrival'):
        notes.append('reported_route_target_may_be_next_stop_not_final_destination')
    assessment = plausibility(field, value, quality)
    if assessment:
        notes.append(assessment['reason'])
    motion = None
    if field == 'VehicleSpeed':
        notes.append('reported_speed_alone_does_not_establish_current_motion')
        motion = {'status': 'not_assessed', 'unit': 'mph',
                  'requires': ['field_specific_freshness', 'temporally_coherent_cross_field_evidence'],
                  'zero_or_low_speed_is_not_park_evidence': True,
                  'residual_speed_is_not_automatically_zeroed': True}
    if not notes:
        return None
    return {'warnings': notes, 'payload_quality_is_not_measurement_freshness': True,
            **({'plausibility': assessment, 'rule_eligibility': rule_eligibility(field, value, quality)} if assessment else {}),
            **({'motion_interpretation': motion} if motion else {})}
