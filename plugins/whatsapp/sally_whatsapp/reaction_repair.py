"""Explicit offline repair of sender-relative private reaction references.

No startup hook, provider calls, re-ingestion or notification replay. The
operator must establish the historical GOWS contract and account identity,
quiesce workers, back up the archive and approve the exact private plan digest.
Plans contain private identifiers and must stay with the tenant on the server.
"""
import hashlib
import json

from . import lifetime, visibility
from .reaction_identity import private_address, private_reaction_target
from .store import canonical
from .callback_audit import cancel as cancel_delivery

CONTRACT = 'gows-sender-private-v1'
FORMAT = 'whatsapp-private-reaction-repair-v1'
MARKER = 'private:reaction_identity_repair:v1:'


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _context(db, me, contract):
    if contract != CONTRACT or not isinstance(me, dict):
        raise ValueError('Verified historical provider contract and account identity required')
    own = sorted({v for k in ('id', 'lid') if (v := private_address(me.get(k)))})
    profiles = [tuple(r) for r in db.execute("SELECT key,value FROM state WHERE key GLOB 'profile_id:*' ORDER BY key")]
    if not own or not profiles:
        raise ValueError('Account and archive profile identity required')
    return {'account_sha256': digest(own), 'profiles_sha256': digest(profiles)}


def _correction(store, db, row, me):
    data = store._event_data(row)
    target = private_reaction_target(data, me)
    if target is None or row['event_type'] != 'message.reaction':
        return None
    source = data['reaction']['messageId']
    if row['source_message_id'] != source:
        return None
    if store._canonical_chat(db, row['chat_id']) != store._canonical_chat(db, data['from']):
        return None
    if not store._identity_context_matches(db, target, row['chat_id']):
        return None
    variants = visibility.identifier_variants(db, target, store._canonical_chat)
    rows = db.execute('SELECT id,chat_id,sender,from_me FROM messages WHERE id IN '
                      '(SELECT value FROM json_each(?)) ORDER BY rowid', (canonical(variants),)).fetchall()
    if not rows or any(not store._identity_context_matches(db, r['id'], r['chat_id'], bool(r['from_me']))
                       or store._canonical_chat(db, r['chat_id']) != store._canonical_chat(db, row['chat_id'])
                       for r in rows):
        return None
    identities = {visibility.canonical_identifier(db, r['id'], store._canonical_chat) for r in rows}
    if len(identities) != 1:
        return None
    return {'event_id': row['id'], 'event_sha256': digest(dict(row)),
            'target': rows[0]['id'], 'target_identity_sha256': digest([dict(r) for r in rows])}


def plan(store, me, *, contract):
    with store.db() as db, visibility.read_snapshot(db):
        context = _context(db, me, contract)
        rows = db.execute("SELECT * FROM account_events WHERE event_type='message.reaction' ORDER BY id LIMIT 10001").fetchall()
        if len(rows) > 10000:
            raise ValueError('Archive exceeds the reviewed repair batch limit')
        changes = [change for row in rows if (change := _correction(store, db, row, me))]
    return {'format': FORMAT, 'contract': contract, **context, 'changes': changes}


def apply(store, me, proposal, *, expected_sha256):
    if not isinstance(proposal, dict) or digest(proposal) != expected_sha256 or proposal.get('format') != FORMAT:
        raise ValueError('Exact reviewed repair plan digest required')
    changes = proposal.get('changes')
    if (not isinstance(changes, list) or len(changes) > 10000
            or any(not isinstance(c, dict) or not isinstance(c.get('event_id'), str) for c in changes)
            or len({c['event_id'] for c in changes}) != len(changes)):
        raise ValueError('Invalid repair plan')
    with store.db() as db:
        db.execute('BEGIN IMMEDIATE')
        context = _context(db, me, proposal.get('contract'))
        if any(proposal.get(k) != v for k, v in context.items()):
            raise ValueError('Repair account or archive identity changed')
        marker = MARKER + expected_sha256
        previous = db.execute('SELECT value FROM state WHERE key=?', (marker,)).fetchone()
        if previous:
            return {**json.loads(previous[0]), 'already_applied': True}
        prepared = []
        # Check every input before changing anything. Late revocations/deletions
        # remain authoritative and are evaluated again during projection.
        for change in changes:
            row = db.execute('SELECT * FROM account_events WHERE id=?', (change['event_id'],)).fetchone()
            if row is None or _correction(store, db, row, me) != change:
                raise ValueError('Repair evidence changed; prepare a new plan')
            prepared.append((row, change))
        redacted = cancelled = 0
        for row, change in prepared:
            data = store._event_data(row)
            data = {**data, 'reaction': {**data['reaction'], 'messageId': change['target']}}
            updated = {**dict(row), 'source_message_id': change['target'], 'data': canonical(data)}
            store._save_event_references(db, updated, data)
            projected = store._event_projection(db, updated, data)
            _, state = store._event_availability(db, updated, data)
            retained = projected if state in ('revoked', *lifetime.BLOCKED) else data
            redacted += retained != data
            db.execute('UPDATE account_events SET source_message_id=?,data=? WHERE id=?',
                       (change['target'], canonical(retained), row['id']))
            # Old callback bytes may already have been attempted. Do not rewrite,
            # enqueue or replay them as a consequence of repairing a reference.
            cancelled += cancel_delivery(db, 'event_id=?', (row['id'],),
                                         'source_identity_repaired', reset_lease=True)
        result = {'repaired': len(prepared), 'redacted': redacted, 'callbacks_cancelled': cancelled,
                  'notifications_created': 0, 'whatsapp_actions': 0}
        store._state(db, marker, result)
        return {**result, 'already_applied': False}
