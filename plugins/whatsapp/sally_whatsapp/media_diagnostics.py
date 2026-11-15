"""Content-free media quota observations; private state uses the existing schema."""
import json
import math
import time


PREFIX = 'private:media_limit:v1:'
FILE_LIMIT = 'MEDIA_FILE_LIMIT_EXCEEDED'
CACHE_LIMIT = 'MEDIA_CACHE_CAPACITY_EXCEEDED'
MESSAGES = {
    FILE_LIMIT: 'File or encoded transfer exceeds the configured per-file limit',
    CACHE_LIMIT: 'Media cache quota is insufficient for this transfer; wait for expired transfers to clear',
}
RECOVERY = {
    FILE_LIMIT: 'Request a smaller file or ask the administrator to review the per-file limit. Retrying the same file unchanged will not help.',
    CACHE_LIMIT: 'Wait for cached transfers to expire, then request a new transfer. An administrator can review cache capacity. Existing valid files are preserved.',
}


class TransferLimitExceeded(ValueError):
    def __init__(self, observed_bytes, *, basis='file'):
        super().__init__('File exceeds the configured transfer limit')
        self.observed_bytes = observed_bytes
        self.basis = basis


class CacheCapacityExceeded(ValueError):
    def __init__(self):
        super().__init__(MESSAGES[CACHE_LIMIT])


def quota_snapshot(db, settings, *, now=None):
    """Logical quota, not filesystem free bytes or a reservation for future work."""
    now = time.time() if now is None else now
    used = db.execute("SELECT coalesce(sum(size),0) FROM media_jobs WHERE state='ready' AND expires>?", (now,)).fetchone()[0]
    remaining = max(0, settings.media_cache_bytes - used)
    return {'capacity_bytes': settings.media_cache_bytes, 'used_bytes': used,
            'remaining_bytes': remaining, 'file_limit_bytes': settings.max_attachment_bytes,
            'effective_limit_bytes': min(settings.max_attachment_bytes, remaining),
            'observed_at': now, 'accounting': 'ready_unexpired'}


def limit_failure(exc, snapshot):
    if isinstance(exc, CacheCapacityExceeded):
        return {'reason': CACHE_LIMIT, 'cache_at_attempt': snapshot}
    if not isinstance(exc, TransferLimitExceeded):
        return None
    # A declared size may already prove the individual limit is exceeded.
    # Streaming may prove only that the smaller residual quota was crossed.
    reason = (FILE_LIMIT if exc.observed_bytes > snapshot['file_limit_bytes']
              or snapshot['effective_limit_bytes'] == snapshot['file_limit_bytes'] else CACHE_LIMIT)
    return {'reason': reason, 'cache_at_attempt': snapshot,
            'observed_bytes': exc.observed_bytes, 'limit_basis': exc.basis}


def save_failure(db, identifier, failure):
    db.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
               (PREFIX + identifier, json.dumps(failure, separators=(',', ':'), allow_nan=False)))


def forget_failure(db, identifier):
    db.execute('DELETE FROM state WHERE key=?', (PREFIX + identifier,))


def forget_source_failures(db, message_id):
    db.execute('DELETE FROM state WHERE key IN (SELECT ? || id FROM media_jobs WHERE source_message_id=?)',
               (PREFIX, message_id))


def clean_failures(db, now):
    db.execute("""DELETE FROM state WHERE key GLOB ? AND NOT EXISTS
        (SELECT 1 FROM media_jobs WHERE state.key=? || media_jobs.id
         AND media_jobs.state='failed' AND media_jobs.expires>?)""", (PREFIX + '*', PREFIX, now))


def read_failure(db, identifier):
    """Never project arbitrary state data or infer a legacy cause from prose."""
    row = db.execute("""SELECT s.value FROM state s JOIN media_jobs m ON s.key=? || m.id
        WHERE m.id=? AND m.state='failed' AND m.expires>?""", (PREFIX, identifier, time.time())).fetchone()
    if row is None:
        return None
    try:
        value = json.loads(row[0])
        if not isinstance(value, dict) or value.get('reason') not in MESSAGES:
            return None
        snapshot = value['cache_at_attempt']
        numbers = ('capacity_bytes', 'used_bytes', 'remaining_bytes', 'file_limit_bytes', 'effective_limit_bytes')
        if (not isinstance(snapshot, dict) or snapshot.get('accounting') != 'ready_unexpired'
                or any(type(snapshot.get(key)) is not int or snapshot[key] < 0 for key in numbers)
                or type(snapshot.get('observed_at')) not in (int, float)
                or not math.isfinite(snapshot['observed_at']) or snapshot['observed_at'] < 0
                or snapshot['remaining_bytes'] != max(0, snapshot['capacity_bytes'] - snapshot['used_bytes'])
                or snapshot['effective_limit_bytes'] != min(snapshot['file_limit_bytes'], snapshot['remaining_bytes'])):
            return None
        result = {'reason': value['reason'], 'cache_at_attempt': {
            key: snapshot[key] for key in (*numbers, 'observed_at', 'accounting')}}
        if 'observed_bytes' in value or 'limit_basis' in value:
            if type(value.get('observed_bytes')) is not int or value['observed_bytes'] < 0 or value.get('limit_basis') not in ('file', 'wire', 'decoded'):
                return None
            result.update(observed_bytes=value['observed_bytes'], limit_basis=value['limit_basis'])
        return result
    except (ValueError, TypeError, KeyError):
        return None


def log_fields(failure):
    snapshot = failure['cache_at_attempt']
    return {'failure_reason': failure['reason'], 'quota_observed_at': snapshot['observed_at'],
            'cache_capacity_bytes': snapshot['capacity_bytes'], 'cache_used_bytes': snapshot['used_bytes'],
            'cache_remaining_bytes': snapshot['remaining_bytes'],
            'file_limit_bytes': snapshot['file_limit_bytes'], 'effective_limit_bytes': snapshot['effective_limit_bytes'],
            **({key: failure[key] for key in ('observed_bytes', 'limit_basis')} if 'observed_bytes' in failure else {})}
