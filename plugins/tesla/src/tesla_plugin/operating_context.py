"""Explain unavailable gear using independent, timed observations.

This module does not admit commands, infer Park or extend any safety freshness
window. Its 30-second diagnostic window is not a replacement for the Park guard.
"""
import json

from .trigger_catalog import FIELD_MAP

SIGNALS = ('Gear', 'DriveRail', 'BrakePedal', 'DriverSeatOccupied', 'CenterDisplay',
           'DetailedChargeState', 'ChargingCableType', 'Locked')
CONNECTED_CABLES = {'CableTypeIEC', 'CableTypeSAE', 'CableTypeGB_AC', 'CableTypeGB_DC'}
SOURCES = [
    'https://developer.tesla.com/docs/fleet-api/fleet-telemetry/available-data',
    'https://www.tesla.com/ownersmanual/2020_2024_modely/en_us/GUID-41E02406-1983-4511-BBB4-158DD94796C6.html',
    'https://www.tesla.com/ownersmanual/2020_2024_modely/en_us/GUID-E75DB1EC-A705-4784-9983-DE677D1BF7C1.html',
]


def _stored_value(field, row):
    """Old rows are not proof that a fixed signal still has its expected type.

    Only documented booleans and enum names may leave this diagnostic view.
    Incompatible legacy structures can contain location or arbitrary content;
    keep their quality and times, but do not expose or diagnose from that value.
    """
    if row is None:
        return None, None
    try:
        value = json.loads(row['value']) if row['value'] is not None else None
    except (ValueError, TypeError):
        return None, 'invalid_stored_json'
    if value is None and row['quality'] != 'valid':
        return None, None
    spec = FIELD_MAP[field]
    enum = spec.get('enum_values')
    if enum:
        compatible = type(value) is str and value in {part.split('=')[0] for part in enum.split('|')}
    else:
        compatible = spec.get('documented_type', '').lower() in ('boolean', 'bool') and type(value) is bool
    return (value, None) if compatible else (None, 'incompatible_stored_value')


def explain(store, ref, park):
    now = store.clock()
    with store.db() as db:
        rows = {r['field']: dict(r) for r in db.execute(
            'SELECT * FROM latest WHERE vehicle=? AND field IN ('+','.join('?' for _ in SIGNALS)+')', (ref, *SIGNALS))}
    observations = {}
    for field in SIGNALS:
        row = rows.get(field)
        age = now-row['source_at'] if row else None
        observed, withheld = _stored_value(field, row)
        observations[field] = {'value': observed, 'value_withheld': withheld is not None,
                               'value_withheld_reason': withheld,
                               'quality': row['quality'] if row else 'missing',
                               'source_at': row['source_at'] if row else None, 'received_at': row['received'] if row else None,
                               'age_seconds': age, 'recent_for_diagnosis': age is not None and -0.001 <= age <= 30}
    def value(name):
        item = observations[name]
        return item['value'] if item['quality'] == 'valid' and item['recent_for_diagnosis'] else None
    charge, cable, rail = value('DetailedChargeState'), value('ChargingCableType'), value('DriveRail')
    # A charge outcome such as Complete/Stopped/NoPower is not itself a current
    # cable observation. Prefer an explicit charging/cable signal and compare
    # it with Disconnected, including cross-field timestamp conflicts.
    connection_evidence = []
    if charge in ('DetailedChargeStateCharging', 'DetailedChargeStateDisconnected'):
        connection_evidence.append({'field': 'DetailedChargeState',
            'state': 'connected' if charge == 'DetailedChargeStateCharging' else 'disconnected',
            'source_at': observations['DetailedChargeState']['source_at']})
    if cable in CONNECTED_CABLES:
        connection_evidence.append({'field': 'ChargingCableType', 'state': 'connected',
                                   'source_at': observations['ChargingCableType']['source_at']})
    if connection_evidence:
        newest = max(item['source_at'] for item in connection_evidence)
        states = {item['state'] for item in connection_evidence if item['source_at'] == newest}
        connection_state = next(iter(states)) if len(states) == 1 else 'conflicting'
    else:
        connection_state = 'unknown'
    connected = connection_state == 'connected'
    accessory = value('CenterDisplay') == 'DisplayStateAccessory'
    # A contradictory current gear is never replaced by a cable or display hint.
    state = park['status']
    if state in ('conflicting', 'time_conflict'):
        diagnosis, message = 'conflicting_evidence', 'Gear sources conflict.'
    elif state == 'verified':
        diagnosis, message = 'park_observed', 'P observed recently enough for the Park check.'
    elif state == 'not_park':
        diagnosis, message = 'driving_gear_observed', 'A gear other than P was observed; this alone does not prove movement.'
    elif state == 'stale':
        diagnosis, message = 'gear_stale', 'The observed valid gear is too old for the Park check.'
    elif connection_state == 'conflicting':
        diagnosis, message = 'charging_connection_conflicting', 'Charging data conflicts about cable connection. Gear remains unavailable.'
    elif connected:
        diagnosis, message = 'charging_connection_observed', 'A charging connection was observed: the manual specifies drive inhibition. Gear remains unavailable.'
    elif rail is False:
        diagnosis, message = 'drive_power_inactive_observed', 'DriveRail indicates inactive drive power. This does not necessarily mean the vehicle is asleep.'
    elif accessory:
        diagnosis, message = 'accessory_display_observed', 'Display in Accessory mode. This alone does not establish drive system or gear state.'
    else:
        diagnosis, message = 'gear_unavailable', 'Gear unavailable: available data does not identify the cause.'
    return {'state': diagnosis, 'message': message, 'observations': observations,
            'charging_connection_observed': connected, 'park_inferred': False,
            'charging_connection': {'status': connection_state, 'evidence': connection_evidence,
                                    'basis': 'newest_recent_explicit_signal_not_charge_outcome'},
            'drive_power': 'active_observed' if rail is True else 'inactive_observed' if rail is False else 'unknown',
            'accessory_display_observed': accessory,
            'vehicle_sleep_inferred': False, 'physical_motion_verified': False,
            'command_admission_changed': False, 'diagnostic_window_seconds': 30,
            'causality_proven': False, 'confidence_scope': 'observed_signals_not_cause_of_unavailable_gear',
            'next_step': 'Features requiring Park remain subject to their own P evidence checks. No automatic wake commands or periodic checks.',
            'sources': SOURCES}
