"""Local, value-free evidence: selection, provider adoption and reception differ."""
from collections import Counter
import json
from statistics import median

from .trigger_catalog import FIELD_MAP, LOCATION_FIELDS
from .field_capabilities import selectable
from .sample_evidence import DEFAULT_MAX_AGE_SECONDS, _freshness


def routes(config):
    """Include attached fields without pretending they have their own cadence."""
    result = {}
    for parent, options in (config or {}).get('fields', {}).items():
        normalized = {**options, 'include_fields': sorted(options.get('include_fields', []))}
        for name in {parent, *options.get('include_fields', [])}:
            result.setdefault(name, {})[parent] = normalized
    return result


def field_evidence(store, ref, view, *, location_authorized, max_age_seconds=DEFAULT_MAX_AGE_SECONDS):
    """Separate wire quality from the shared retained-payload display policy.

    This policy describes payload age only. It does not override individual
    rule/command freshness or claim that the physical measurement is fresh.
    """
    remote = view['remote']
    observed = routes(remote.get('data', {}).get('config'))
    desired = routes(view['target'].get('data'))
    saved = routes(view['saved'])
    requested = {}
    now = store.clock()
    with store.db() as db:
        latest = {r['field']: dict(r) for r in db.execute(
            'SELECT field,source_at,received,quality,time_basis FROM latest WHERE vehicle=?', (ref,))}
        cadence_rows = list(db.execute('SELECT field,source_at FROM samples WHERE vehicle=? AND source_at>=? AND source_at<=? '
                                      'ORDER BY source_at DESC LIMIT 4096', (ref, now-86400, now)))
        if view['last']:
            row = db.execute('SELECT arguments FROM intents WHERE id=?', (view['last']['id'],)).fetchone()
            if row:
                requested = routes(json.loads(row[0]).get('config'))
    readback_current = bool(remote and remote['at'] >= view['target'].get('at', 0))
    synced = remote.get('data', {}).get('synced') is True
    fields = {}
    cadence = {}
    for row in cadence_rows:
        cadence.setdefault(row['field'], set()).add(row['source_at'])
    for name, spec in FIELD_MAP.items():
        if not selectable(spec):
            continue
        status = ('not_verified' if not remote else 'readback_outdated' if not readback_current
                  else 'sync_pending' if not synced
                  else 'confirmed' if name in observed
                  else 'missing_from_readback' if name in desired else 'not_configured')
        restricted = name in LOCATION_FIELDS and not location_authorized
        row = None if restricted else latest.get(name)
        received = ({'status': row['quality'], 'quality': row['quality'],
                     'source_at': row['source_at'], 'received_at': row['received'],
                     'age_seconds': round(now-row['source_at'], 3), 'time_basis': row['time_basis'],
                     'since_requested_configuration': bool(view['target'] and row['source_at'] >= view['target']['at']
                                                           and row['received'] >= view['target']['at'])}
                    if row else {'status': 'permission_required' if restricted else 'not_observed', 'quality': None,
                                 'source_at': None, 'received_at': None,
                                 'age_seconds': None, 'since_requested_configuration': False})
        freshness = _freshness(row['source_at'], now, max_age_seconds)[0] if row else received['status']
        received['freshness'] = {'status': freshness, 'max_age_seconds': max_age_seconds,
                                 'basis': 'retained_payload_timestamp', 'policy': 'sample_evidence_display',
                                 'future_tolerance_seconds': 0.001,
                                 'physical_measurement_freshness_verified': False}
        times = sorted(cadence.get(name, ())) if not restricted else []
        intervals = [b-a for a, b in zip(times, times[1:])]
        received['observed_cadence'] = {'sample_count': len(times),
            'median_interval_seconds': round(median(intervals), 3) if intervals else None,
            'maximum_gap_seconds': round(max(intervals), 3) if intervals else None,
            'window_start': times[0] if times else None, 'window_end': times[-1] if times else None,
            'basis': 'unique_payload_timestamps_all_qualities_last_4096_samples_within_24h',
            'periodic_delivery_guaranteed': False}
        fields[name] = {'saved': name in saved, 'requested': name in desired,
                        'last_request_included': name in requested,
                        'configuration': {'status': status, 'observed_at': remote.get('at'),
                                          'observed': name in observed,
                                          'matches_requested_options': observed.get(name) == desired.get(name) if view['target'] else None,
                                          'included_by': sorted(p for p in observed.get(name, {}) if p != name)},
                        'reception': received,
                        'vehicle_reception_verified': bool(row and row['quality'] == 'valid'),
                        'fresh_valid_payload_received': bool(row and row['quality'] == 'valid' and freshness == 'fresh')}
    selected = set(saved) | set(desired) | set(observed) | set(requested)
    selected_items = [value for name, value in fields.items() if name in selected]
    uncatalogued = len(selected-set(fields))
    configuration = dict(Counter(v['configuration']['status'] for v in selected_items))
    reception = dict(Counter(v['reception']['status'] for v in selected_items))
    freshness = dict(Counter(v['reception']['freshness']['status'] for v in selected_items))
    if uncatalogued:
        configuration['not_catalogued'] = reception['not_catalogued'] = freshness['not_catalogued'] = uncatalogued
    return {'fields': fields, 'summary': {
        'scope': 'union_of_saved_requested_observed_and_last_request_fields',
        'field_count': len(selected), 'uncatalogued_field_count': uncatalogued, 'saved_count': len(saved), 'requested_count': len(desired),
        'observed_count': len(observed), 'last_request_count': len(requested),
        'configuration': configuration, 'reception': reception, 'quality': dict(reception),
        'freshness': freshness,
        'freshness_policy': {'name': 'sample_evidence_display', 'max_age_seconds': max_age_seconds,
                             'future_tolerance_seconds': 0.001, 'basis': 'retained_payload_timestamp',
                             'physical_measurement_freshness_verified': False},
        'last_request_status': view['last']['status'] if view['last'] else None,
        'snapshot_at': now, 'values_included': False,
        'note': 'Local evidence only. Confirmed means present in the last synchronized readback, not continuously available. '
                'Reception and quality describe the latest retained sample. Freshness uses the stated payload-age display policy, '
                'not a universal physical measurement, rule or command threshold. Vehicle reception verified does not mean current state verified. '
                'Not observed does not prove unsupported hardware. A rejected request does not identify every field as rejected.'}}
