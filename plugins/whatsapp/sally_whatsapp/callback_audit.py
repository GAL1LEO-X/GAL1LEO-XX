"""Transactional cancellation evidence, separate from signed callback payloads.

Schema-8 private metadata is ignored by older backends. No reason is backfilled
from current source state, and observing a cancellation never reopens a delivery.
"""
import hashlib
import json
import time

PREFIX = 'private:callback_cancellation:v1:'
REASONS = frozenset({
    'subscription_reactivated', 'subscription_unsubscribed', 'authorization_unavailable',
    'event_expired', 'source_unavailable', 'source_revoked', 'source_lifetime_unavailable',
    'source_edited', 'alias_duplicate', 'recovery_source_changed', 'digest_source_revoked',
    'source_identity_repaired',
})
ACTIVE = ('collecting', 'pending', 'sending')


def _binding(row):
    value = json.dumps([row['subscription'], row['event_id']], separators=(',', ':'))
    return hashlib.sha256(value.encode()).hexdigest()


def cancel(db, predicate, params, reason, *, reset_lease=False, now=None):
    """Use only internal SQL predicates; retain caller fencing and transaction.

    RETURNING ties evidence to rows actually transitioned, including zero-row
    stale attempts. No audit can be committed without the cancellation itself.
    """
    if reason not in REASONS:
        raise ValueError('Unknown callback cancellation reason')
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    rows = db.execute("UPDATE deliveries SET state='cancelled'" +
                      (',lease_until=0' if reset_lease else '') +
                      " WHERE (" + predicate + ") AND state IN ('collecting','pending','sending')"
                      " RETURNING id,subscription,event_id,attempts", params).fetchall()
    from .ingestion_metrics import stage
    stage('callbacks_cancelled', len(rows))
    observed = time.time() if now is None else now
    for row in rows:
        value = dict(version=1, binding=_binding(row), reason=reason,
                     observed_at=observed, attempt=row['attempts'],
                     http_attempt_started='not_inferred_from_claim_count')
        db.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                   (PREFIX + str(row['id']), json.dumps(value, separators=(',', ':'))))
    return len(rows)


def evidence(db, row):
    stored = db.execute('SELECT value FROM state WHERE key=?', (PREFIX + str(row['id']),)).fetchone()
    return _decode(row, stored[0] if stored else None)


def _decode(row, stored):
    if stored:
        try:
            value = json.loads(stored)
            if (value.get('version') == 1 and value.get('binding') == _binding(row)
                    and value.get('reason') in REASONS and type(value.get('attempt')) is int
                    and value['attempt'] == row['attempts']
                    and type(value.get('observed_at')) in (int, float)):
                return {k: value[k] for k in ('reason', 'observed_at', 'attempt')}
        except (ValueError, TypeError, AttributeError):
            pass
    return {'reason': 'historical_or_unattributed', 'observed_at': None, 'attempt': None}


def summary(db):
    counts = {}
    # Stream metadata only; neither callbacks nor source contents are decoded.
    for row in db.execute("""SELECT d.id,d.subscription,d.event_id,d.attempts,s.value
            FROM deliveries d LEFT JOIN state s ON s.key=? || d.id WHERE d.state='cancelled'""", (PREFIX,)):
        reason = _decode(row, row['value'])['reason']
        counts[reason] = counts.get(reason, 0) + 1
    return {'cancelled_by_reason': counts, 'historical_reasons_inferred': False,
            'attempt_count_is_claim_count': True, 'cancellations_are_retries': False}
