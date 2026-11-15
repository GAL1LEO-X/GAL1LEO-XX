"""Local capability evidence and explicit preset exclusions; no provider calls."""
import json
import math
import re

from .catalogue import FIELDS

BY_NAME = {f['field']: f for f in FIELDS}
REASONS = {
    'receiver_upgrade_required': 'update the receiver before configuring this field',
    'field_not_configurable': 'field not configurable under the current contract',
    'model_unknown': 'the model needs verification for a field limited to other platforms',
    'different_model': 'field limited to another Tesla model',
    'requires_HW4': 'requires HW4 hardware, not yet verified in local data',
    'firmware_version_too_old': 'firmware is older than the required version',
    'fleet_telemetry_version_too_old': 'telemetry client is older than the required version',
    'firmware_version_unknown': 'firmware version unavailable in local data',
    'fleet_telemetry_version_unknown': 'telemetry client version unavailable in local data',
    'field_semantics_not_documented': 'field present in the protocol; its specific type and meaning require qualification',
}


def selectable(spec):
    return spec.get('configurable', spec['catalog_status'] == 'DOCUMENTED')


def version(text):
    if not isinstance(text, str):
        return None
    match = re.fullmatch(r'(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\s+.*)?', text)
    return tuple(int(x or 0) for x in match.groups()) if match else None


def meets_version(actual, required):
    thresholds = [version(s) for s in required.split(' / ')]
    thresholds = [v for v in thresholds if v is not None]
    if not thresholds:
        return True
    found = version(actual)
    if found is None:
        return None
    # Alternative firmware branches are not a single minimum. For example,
    # 2026.38.3 must not qualify through 2026.32.300.
    same = [v for v in thresholds if v[:2] == found[:2]]
    return found >= min(same) if same else found >= max(thresholds)


def context(store, ref):
    with store.db() as db:
        rows = {r['section']: dict(r) for r in db.execute(
            "SELECT * FROM snapshots WHERE vehicle=? AND section IN ('capabilities','vehicle_config')", (ref,))}
        latest = {r['field']: dict(r) for r in db.execute(
            "SELECT * FROM latest WHERE vehicle=? AND field IN ('CarType','Version') AND quality='valid'", (ref,))}
    capabilities = json.loads(rows['capabilities']['data']) if 'capabilities' in rows else {}
    config = json.loads(rows['vehicle_config']['data']) if 'vehicle_config' in rows else {}
    def most_recent(candidates):
        # A retained telemetry value is not necessarily newer than a REST
        # capability observation. Static metadata need not be 15s fresh, but a
        # future/invalid timestamp must not win source selection.
        eligible = [(value, at, source) for value, at, source in candidates if value is not None
                    and (at is None or type(at) in (int, float) and -1e308 <= at <= store.clock()+30 and math.isfinite(at))]
        return max(eligible, key=lambda item: item[1] if item[1] is not None else -math.inf, default=(None, None, None))
    models = {'modely': 'ModelY', 'model3': 'Model3', 'models': 'ModelS', 'modelx': 'ModelX',
              'cybertruck': 'Cybertruck', 'semitruck': 'SemiTruck'}
    def model_name(value):
        return models.get(str(value).removeprefix('CarType').lower())
    model, model_at, model_source = most_recent([
        (model_name(json.loads(latest['CarType']['value'])), latest['CarType']['source_at'], 'CarType') if 'CarType' in latest else (None, None, None),
        (model_name(config.get('car_type')), rows.get('vehicle_config', {}).get('source_at'), 'vehicle_config')])
    def firmware(value):
        return value if version(value) is not None else None
    firmware_value, firmware_at, firmware_source = most_recent([
        (firmware(json.loads(latest['Version']['value'])), latest['Version']['source_at'], 'Version') if 'Version' in latest else (None, None, None),
        (firmware(capabilities.get('firmware_version')), rows.get('capabilities', {}).get('source_at'), 'capabilities')])
    return {'model': model, 'firmware_version': firmware_value,
            'fleet_telemetry_version': capabilities.get('fleet_telemetry_version'),
            'hardware': None, 'hardware_note': 'Do not infer HW3/HW4 from model, trim or marketing name.',
            'source': 'stored_vehicle_evidence', 'capabilities_observed_at': rows.get('capabilities', {}).get('source_at'),
            'model_evidence': {'source': model_source, 'source_at': model_at},
            'firmware_evidence': {'source': firmware_source, 'source_at': firmware_at},
            'tesla_requests': 0}


def qualification(spec, vehicle=None):
    vehicle = vehicle or {}
    blocks, warnings = [], []
    if not selectable(spec):
        blocks.append('receiver_upgrade_required' if spec.get('receiver_supported') is False else 'field_not_configurable')
    requirement = spec['hardware_notes']
    required_model = 'SemiTruck' if requirement == 'Semi only' else 'Cybertruck' if 'Cybertruck' in requirement else None
    if required_model and vehicle.get('model') != required_model:
        blocks.append('model_unknown' if not vehicle.get('model') else 'different_model')
    if requirement == 'HW4 only' and vehicle.get('hardware') != 'HW4':
        (blocks if vehicle.get('hardware') is not None else warnings).append('requires_HW4')
    for actual, required in (('firmware_version', 'minimum_firmware_field'), ('fleet_telemetry_version', 'minimum_client_field')):
        meets = meets_version(vehicle.get(actual), spec[required])
        if meets is False:
            blocks.append(actual+'_too_old')
        elif meets is None:
            warnings.append(actual+'_unknown')
    if spec.get('value_contract') == 'protobuf_oneof_only':
        warnings.append('field_semantics_not_documented')
    return {'configurable_in_plugin': selectable(spec), 'blockers': blocks, 'warnings': warnings,
            'eligible_for_proposal': not blocks, 'vehicle_support_verified': False,
            'note': 'Eligibility is not Tesla acceptance, receipt, valid data or hardware qualification.'}


def select_maximum(fields, vehicle):
    kept, excluded, warnings = {}, [], []
    for name, options in fields.items():
        info = qualification(BY_NAME[name], vehicle)
        if info['blockers']:
            excluded.append({'field': name, 'reasons': info['blockers']})
        else:
            kept[name] = options
            if info['warnings']:
                warnings.append({'field': name, 'reasons': info['warnings']})
    return kept, {'context': vehicle or {}, 'excluded': excluded, 'warnings': warnings,
                  'automatic_application': False, 'selection_is_proposal': True}
