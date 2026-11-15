"""Local sample evidence, without promoting historical values to current state.

Callers must enforce their normal read/history/location permissions before
exposing results. Provenance is recorded only at ingestion; a missing row is
unknown provenance, including for samples created before schema 3.
"""
import hashlib
import json

from .telemetry_values import semantics
from .trigger_catalog import FIELD_MAP

PROVENANCE_FIELDS = ('source_transport', 'quality_reason', 'decoder_version', 'contract_version', 'oneof_branch')
DEFAULT_MAX_AGE_SECONDS = 120


def _fingerprint(value):
    return hashlib.sha256((value if value is not None else 'null').encode()).hexdigest()


def record_sample(db, sample_id, evidence):
    """Called only when the sample INSERT succeeded; never backfill old rows."""
    db.execute('INSERT INTO sample_provenance VALUES(?,?,?,?,?,?)',
               (sample_id, *(evidence[key] for key in PROVENANCE_FIELDS)))


def record_latest(db, ref, field, row, sample_id, evidence, *, conflict=False):
    if conflict:
        # The retained latest value and the contradictory incoming value are
        # different observations: neither branch explains this composite state.
        sample_id = None
        evidence = evidence | {'quality_reason': 'same_source_time_conflict', 'oneof_branch': None}
    db.execute('INSERT OR REPLACE INTO latest_provenance VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
               (ref, field, sample_id, row['source_at'], row['received'], row['quality'],
                _fingerprint(row['value']), *(evidence[key] for key in PROVENANCE_FIELDS)))


def provenance(evidence=None):
    return {'status': 'recorded' if evidence is not None else 'unavailable',
            'source': 'fleet_telemetry' if evidence is not None else None,
            **{key: evidence[key] if evidence is not None else None for key in PROVENANCE_FIELDS},
            'raw_payload_retained': False}


def _freshness(source_at, now, max_age_seconds):
    age = now-source_at
    return ('future' if age < -0.001 else 'stale' if age > max_age_seconds else 'fresh'), age


def observation(row, now, evidence=None, *, max_age_seconds=DEFAULT_MAX_AGE_SECONDS):
    if row is None:
        return None
    quality = row['quality']
    freshness, age = _freshness(row['source_at'], now, max_age_seconds)
    value = json.loads(row['value']) if row['value'] is not None and quality in ('valid', 'unqualified') else None
    notes = semantics(row['field'], value, row['source_at'], quality) if 'field' in row.keys() else None
    return {'value': value,
            'quality': quality, 'status': quality if quality != 'valid' or freshness == 'fresh' else freshness,
            'freshness': freshness, 'source_timestamp': row['source_at'], 'received_at': row['received'],
            'age_seconds': age, 'time_basis': row['time_basis'], 'provenance': provenance(evidence),
            'payload_quality_is_not_measurement_freshness': True,
            **({'semantics': notes} if notes else {})}


def _current_provenance(db, ref, field, current):
    if current is None:
        return None
    row = db.execute('SELECT * FROM latest_provenance WHERE vehicle=? AND field=?', (ref, field)).fetchone()
    if row is not None and all(row[key] == current[key] for key in ('source_at', 'received', 'quality')) and row['value_digest'] == _fingerprint(current['value']):
        return row
    return None


def view(store, ref, field, *, include_history=True, max_age_seconds=DEFAULT_MAX_AGE_SECONDS):
    """Separate the latest received state from a prior unambiguous valid value."""
    store.vehicle(ref)
    now = store.clock()
    with store.db() as db:
        db.execute('BEGIN')
        current = db.execute('SELECT * FROM latest WHERE vehicle=? AND field=?', (ref, field)).fetchone()
        current_evidence = _current_provenance(db, ref, field, current)
        previous = db.execute(
            "SELECT s.* FROM samples s WHERE s.vehicle=? AND s.field=? AND s.quality='valid' AND s.source_at<=? "
            'AND NOT EXISTS (SELECT 1 FROM samples c WHERE c.vehicle=s.vehicle AND c.field=s.field '
            "AND c.source_at=s.source_at AND (c.quality!='valid' OR NOT telemetry_value_equal(s.field,c.value,s.value))) "
            'ORDER BY s.source_at DESC,s.id DESC LIMIT 1', (ref, field, now+0.001)).fetchone() if include_history else None
        previous_evidence = db.execute('SELECT * FROM sample_provenance WHERE sample_id=?',
                                       (previous['id'],)).fetchone() if previous is not None else None
    spec = FIELD_MAP.get(field, {})
    return {'field': field, 'documented_type': spec.get('documented_type') or None,
            'unit': spec.get('unit_explicit_in_description') or None,
            'current_observation': observation(current, now, current_evidence, max_age_seconds=max_age_seconds),
            'last_valid_observation': observation(previous, now, previous_evidence, max_age_seconds=max_age_seconds),
            'history_access': 'allowed' if include_history else 'scope_required',
            'historical_observation_used_as_current': False}


def history_provenance(db, sample_ids, *, watermark=None, as_of=None):
    """Read provenance and equal-time contradictions within the page snapshot."""
    if not sample_ids:
        return {}
    marks = ','.join('?' for _ in sample_ids)
    bounds, parameters = '', []
    if watermark is not None:
        bounds += ' AND c.rowid<=?'
        parameters.append(watermark)
    if as_of is not None:
        bounds += ' AND c.received<=?'
        parameters.append(as_of)
    rows = db.execute(
        'SELECT s.id,p.*,EXISTS(SELECT 1 FROM samples c WHERE c.vehicle=s.vehicle AND c.field=s.field '
        'AND c.source_at=s.source_at AND (c.quality!=s.quality OR NOT telemetry_value_equal(s.field,c.value,s.value))'+bounds+') AS timestamp_conflict '
        f'FROM samples s LEFT JOIN sample_provenance p ON p.sample_id=s.id WHERE s.id IN ({marks})', (*parameters, *sample_ids))
    return {row['id']: dict(row) for row in rows}


def enrich_history(row, now, evidence=None, *, max_age_seconds=DEFAULT_MAX_AGE_SECONDS):
    """Add evidence without changing stored value, quality or original times."""
    sample = {key: row[key] for key in row.keys() if key != 'id'}
    sample['value'] = json.loads(row['value']) if row['value'] is not None else None
    freshness, age = _freshness(row['source_at'], now, max_age_seconds)
    conflict = bool(evidence and evidence.get('timestamp_conflict'))
    recorded = evidence if evidence is not None and evidence.get('sample_id') is not None else None
    return sample | {'provenance': provenance(recorded), 'freshness': freshness, 'age_seconds': age,
                     'timestamp_conflict': conflict,
                     'status': 'time_conflict' if conflict else row['quality'] if row['quality'] != 'valid' or freshness == 'fresh' else freshness}
