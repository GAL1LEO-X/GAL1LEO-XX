"""Bounded transactional counters and per-ingestion opaque correlations.

These count Store calls/stages, not HTTP deliveries or WhatsApp delivery/read.
The epoch begins at first instrumented ingestion; no historical backfill.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import json
import re
import secrets
import time

KEY = 'private:ingestion_metrics:v1'
STAGES = frozenset({'receipts_inserted', 'messages_inserted', 'first_live_messages', 'account_events_inserted',
                    'callbacks_queued', 'digest_members_added', 'callbacks_cancelled'})
DISPOSITIONS = frozenset({'acquired', 'duplicate', 'ignored'})
MAX_COUNT = 2**53 - 1
current = ContextVar('whatsapp_ingestion_observation', default=None)


@dataclass
class Observation:
    origin: str
    ingestion_ref: str = field(default_factory=lambda: secrets.token_hex(12))
    counts: dict = field(default_factory=dict)


@contextmanager
def observing(historical):
    value = Observation('history' if historical else 'live')
    token = current.set(value)
    try:
        yield value
    finally:
        current.reset(token)


def stage(name, count=1):
    value = current.get()
    if value is not None and name in STAGES and type(count) is int and count > 0:
        value.counts[name] = min(MAX_COUNT, value.counts.get(name, 0) + count)


def disposition(result):
    if result.get('ignored') or result.get('recorded') is False:
        return 'ignored'
    return 'duplicate' if result.get('duplicate') is True else 'acquired'


def _read(db):
    row = db.execute('SELECT value FROM state WHERE key=?', (KEY,)).fetchone()
    if row is None:
        return None
    try:
        value = json.loads(row[0])
        allowed = {origin+'.'+key for origin in ('live', 'history')
                   for key in ('calls', *DISPOSITIONS, *STAGES)}
        if (value.get('version') == 1 and isinstance(value.get('epoch'), str)
                and re.fullmatch(r'[0-9a-f]{24}', value['epoch'])
                and isinstance(value.get('counts'), dict)
                and not set(value['counts']) - allowed
                and type(value.get('coverage_since')) in (int, float)
                and all(type(v) is int and 0 <= v <= MAX_COUNT for v in value['counts'].values())):
            return {k:value[k] for k in ('version','epoch','coverage_since','counts','last_committed_at') if k in value}
    except (ValueError, TypeError, AttributeError):
        pass
    return False  # Preserve invalid metadata; never silently replace its history.


def record(db, observation, result):
    # Ignored engine events return before the archive's write transaction.
    # Serialize the counter read too, otherwise parallel ignores lose updates.
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    value = _read(db)
    if value is False:
        return
    now = time.time()
    if value is None:
        value = {'version': 1, 'epoch': secrets.token_hex(12), 'coverage_since': now, 'counts': {}}
    counts = {'calls': 1, disposition(result): 1, **observation.counts}
    for key, delta in counts.items():
        name = observation.origin + '.' + key
        value['counts'][name] = min(MAX_COUNT, value['counts'].get(name, 0) + delta)
    value['last_committed_at'] = now
    db.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
               (KEY, json.dumps(value, separators=(',', ':'))))


def summary(db):
    value = _read(db)
    return {'availability': 'available' if value else 'metadata_invalid' if value is False else 'not_observed',
            **(value or {}), 'coverage': 'instrumented_store_transactions_only',
            'http_acceptance_counted': False, 'historical_backfill': False,
            'one_ingestion_may_create_multiple_events_or_callbacks': True,
            'duplicate_result_may_queue_first_live_callback': True,
            'count_limit': MAX_COUNT, 'absence_proves_no_message_loss': False}
