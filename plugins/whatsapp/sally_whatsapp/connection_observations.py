"""Fence overlapping local observations, without guessing remote chronology."""
import json

KEY = 'private:connection_observation:v1'
SUPERSEDED = object()


def read(db):
    row = db.execute('SELECT value FROM state WHERE key=?', (KEY,)).fetchone()
    if not row:
        return {'generation': 0, 'source': 'legacy_unknown', 'observed_at': None,
                'discarded_polls': 0}
    return json.loads(row[0])


def generation(db):
    return read(db)['generation']


def record(db, *, source, observed_at, expected_generation=None, write=None):
    """Caller owns the same write transaction as the connection status update."""
    value = read(db)
    applied = expected_generation is None or value['generation'] == expected_generation
    if applied:
        value.update(generation=value['generation'] + 1, source=source, observed_at=observed_at)
    else:
        value['discarded_polls'] += 1
    if write is not None:
        write(db, KEY, value)
    else:
        db.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                   (KEY, json.dumps(value, separators=(',', ':'))))
    return applied


def summary(db):
    return {**read(db), 'ordering': 'local_committed_observations',
            'remote_cause': 'not_determined_by_status',
            'event_interval_is_total_downtime': False,
            'historical_gaps_resolved': False}
