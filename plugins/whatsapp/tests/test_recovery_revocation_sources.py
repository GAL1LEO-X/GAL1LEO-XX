"""Recovery must resolve legacy reaction targets without repairing the archive.

All databases, webhook payloads, identities and callbacks here are synthetic.
The stale source column models schema7 before the PR25 semantic repair.
"""
import base64
from contextlib import closing
from dataclasses import replace
import json
import sqlite3
import time
from types import SimpleNamespace

import pytest

from conftest import message
from sally_whatsapp.event_recovery import EventRecovery, attempt_limit
from sally_whatsapp.server import Service
from sally_whatsapp.store import REVOCATION_REPAIR_KEY, Store, canonical


ORIGINAL = 'synthetic-recovery-original'
REACTION = 'synthetic-recovery-reaction'
OTHER_ORIGINAL = 'synthetic-recovery-other-original'
REDACTED = {'message_id': ORIGINAL, 'revoked': True}


def snapshot(store):
    with store.db() as db:
        return tuple(db.iterdump())


def assert_no_administrative_writes(case):
    with case.service.store.db() as db:
        assert attempt_limit(db, case.delivery['id']) is None
        assert db.execute('SELECT 1 FROM state WHERE key=?', (REVOCATION_REPAIR_KEY,)).fetchone() is None
        assert db.execute("SELECT count(*) FROM state WHERE key GLOB 'private:event_recovery:*'").fetchone()[0] == 0
        current = dict(db.execute('SELECT * FROM deliveries WHERE id=?', (case.delivery['id'],)).fetchone())
        assert current == case.delivery


def mark_revoked(store, identifier=ORIGINAL, *, representation='mutation'):
    # A legacy tombstone predates repair and must not accidentally invoke the
    # newer ingest redaction path while constructing the old archive.
    with store.db() as db:
        if representation == 'mutation':
            db.execute("INSERT INTO message_mutations VALUES(?,'revoked',NULL,?)", (identifier, time.time()))
        else:
            db.execute("UPDATE messages SET deleted=1,body='' WHERE id=?", (identifier,))


@pytest.fixture
def legacy_reaction(environment):
    settings, receiver, gateway, _ = environment
    # Maintenance opens an existing technical database; it never bootstraps one.
    from sally_whatsapp.store import Store
    Store(settings.database, migrate_schema=False)
    service = Service(settings, gateway=gateway, event_transport=receiver, recover_inflight=False)
    filters = {'all_chats': True, 'chat_ids': [], 'contains': '', 'event_types': ['message.reaction']}
    sub = service.events.subscribe(settings.owner_subject, 'whatsapp.event', filters,
        {'url': 'https://receiver.example/callback',
         'secret': 'whsec_' + base64.b64encode(b'x' * 32).decode()})['id']
    service.store.ingest(message(ORIGINAL))
    payload = {'id': REACTION, 'from': 'group-1@g.us', 'fromMe': False,
               'reaction': {'messageId': ORIGINAL, 'text': 'synthetic reaction'}}
    service.store.ingest({'id': 'synthetic-recovery-envelope', 'event': 'message.reaction',
                          'timestamp': int(time.time() * 1000), 'payload': payload})
    with service.store.db() as db:
        db.execute("UPDATE account_events SET source_message_id=? WHERE event_type='message.reaction'", (REACTION,))
        db.execute("UPDATE deliveries SET state='failed',attempts=?,last_status=503", (settings.max_callback_attempts,))
        delivery = dict(db.execute('SELECT * FROM deliveries WHERE subscription=?', (sub,)).fetchone())
    # Match the administrative CLI: opening a schema7 database is nonmutating.
    recovery = EventRecovery(Store(settings.database, migrate_schema=False), settings)
    case = SimpleNamespace(service=service, recovery=recovery, receiver=receiver,
                           subscription=sub, delivery=delivery, payload=payload)
    assert_no_administrative_writes(case)
    try:
        yield case
    finally:
        service.gateway.close()
        service.diagnostics.close()


def preview(case):
    return case.recovery.preview(case.subscription, [case.delivery['id']])


def execute(case, fingerprint, request_id='synthetic-reaction-recovery'):
    return case.recovery.execute(case.subscription, [case.delivery['id']],
                                 fingerprint=fingerprint, request_id=request_id)


@pytest.mark.parametrize('representation', ['mutation', 'deleted'])
def test_revoked_canonical_target_rejects_preview_without_repair(legacy_reaction, representation):
    case = legacy_reaction
    mark_revoked(case.service.store, representation=representation)
    before = snapshot(case.service.store)
    calls = len(case.receiver.requests)
    assert case.service.store.account_event(case.delivery['event_id'])['data'] == REDACTED
    result = preview(case)
    assert not result['eligible'] and result['fingerprint'] is None
    assert result['deliveries'][0]['reason'] == 'source_revoked'
    assert snapshot(case.service.store) == before
    assert_no_administrative_writes(case)
    assert len(case.receiver.requests) == calls


@pytest.mark.parametrize('representation', ['mutation', 'deleted'])
def test_revoke_after_valid_preview_rejects_execute_without_permit_audit_or_requeue(legacy_reaction, representation):
    case = legacy_reaction
    initial = preview(case)
    assert initial['eligible'] and initial['fingerprint']
    mark_revoked(case.service.store, representation=representation)
    before = snapshot(case.service.store)
    calls = len(case.receiver.requests)
    with pytest.raises(ValueError):
        execute(case, initial['fingerprint'])
    assert snapshot(case.service.store) == before
    assert_no_administrative_writes(case)
    with pytest.raises(ValueError, match='Unknown recovery request'):
        case.recovery.audit('synthetic-reaction-recovery')
    assert len(case.receiver.requests) == calls


def test_revoked_reaction_id_does_not_revoke_a_distinct_live_target(legacy_reaction):
    case = legacy_reaction
    mark_revoked(case.service.store, REACTION)
    before = snapshot(case.service.store)
    assert case.service.store.account_event(case.delivery['event_id'])['data'] == case.payload
    result = preview(case)
    assert result['eligible'] and result['fingerprint']
    assert snapshot(case.service.store) == before
    execute(case, result['fingerprint'])
    calls = len(case.receiver.requests)
    assert case.service.events.dispatch_one()
    assert len(case.receiver.requests) == calls + 1
    with case.service.store.db() as db:
        row = db.execute('SELECT state,attempts FROM deliveries WHERE id=?', (case.delivery['id'],)).fetchone()
        assert tuple(row) == ('accepted', case.delivery['attempts'] + 1)


def test_already_redacted_tombstone_uses_its_original_even_with_stale_source_column(legacy_reaction):
    case = legacy_reaction
    mark_revoked(case.service.store)
    with case.service.store.db() as db:
        db.execute('UPDATE account_events SET data=? WHERE id=?', (canonical(REDACTED), case.delivery['event_id']))
    before = snapshot(case.service.store)
    assert case.service.store.account_event(case.delivery['event_id'])['data'] == REDACTED
    result = preview(case)
    assert not result['eligible'] and result['deliveries'][0]['reason'] == 'source_revoked'
    assert snapshot(case.service.store) == before
    assert_no_administrative_writes(case)


@pytest.mark.parametrize('raw', [
    '{invalid json', 'null', '[]', '"untrusted text"',
    canonical({'id': ORIGINAL}),
    canonical({'id': ORIGINAL, 'reaction': ORIGINAL}),
    canonical({'id': ORIGINAL, 'reaction': {'messageId': ''}}),
    canonical({'id': ORIGINAL, 'reaction': {'messageId': False}}),
    canonical({'id': ORIGINAL, 'reaction': {'messageId': 42}}),
    canonical({'id': ORIGINAL, 'reaction': {'messageId': [ORIGINAL]}}),
    canonical({'id': ORIGINAL, 'reaction': {'text': ORIGINAL}}),
])
def test_malformed_reaction_fails_closed_without_guessing_target_or_writing(legacy_reaction, raw):
    case = legacy_reaction
    initial = preview(case)
    assert initial['eligible']
    with case.service.store.db() as db:
        db.execute('UPDATE account_events SET data=? WHERE id=?', (raw, case.delivery['event_id']))
    before = snapshot(case.service.store)
    result = preview(case)
    assert not result['eligible'] and result['deliveries'][0]['reason'] == 'invalid_event'
    with pytest.raises(ValueError):
        execute(case, initial['fingerprint'])
    detail = case.service.store.account_event(case.delivery['event_id'])
    try:
        expected = json.loads(raw)
    except ValueError:
        expected = None
    # The getter does not invent a target from text/top-level IDs either;
    # recovery is conservatively refused because provenance is unavailable.
    assert detail['data'] == ({} if expected is None else expected)
    assert snapshot(case.service.store) == before
    assert_no_administrative_writes(case)


def test_reaction_recovery_still_requires_subscription_owner(legacy_reaction):
    case = legacy_reaction
    valid = preview(case)
    other = EventRecovery(case.service.store, replace(case.service.settings, owner_subject='synthetic-other-owner'))
    before = snapshot(case.service.store)
    result = other.preview(case.subscription, [case.delivery['id']])
    assert not result['eligible'] and result['deliveries'][0]['reason'] == 'subscription_unavailable'
    with pytest.raises(ValueError):
        other.execute(case.subscription, [case.delivery['id']], fingerprint=valid['fingerprint'], request_id='synthetic-other-recovery')
    assert snapshot(case.service.store) == before
    assert_no_administrative_writes(case)


def test_one_newly_revoked_reaction_rejects_entire_recovery_selection(legacy_reaction):
    case = legacy_reaction
    case.service.store.ingest(message(OTHER_ORIGINAL))
    case.service.store.ingest({'id': 'synthetic-second-recovery-envelope', 'event': 'message.reaction',
        'timestamp': int(time.time() * 1000), 'payload': {
            **case.payload, 'id': 'synthetic-second-reaction',
            'reaction': {'messageId': OTHER_ORIGINAL, 'text': 'synthetic second reaction'}}})
    with case.service.store.db() as db:
        db.execute("UPDATE account_events SET source_message_id='synthetic-second-reaction' WHERE source_message_id=?", (OTHER_ORIGINAL,))
        db.execute("UPDATE deliveries SET state='failed',attempts=?,last_status=503", (case.delivery['attempts'],))
        ids = [row[0] for row in db.execute('SELECT id FROM deliveries WHERE subscription=? ORDER BY id', (case.subscription,))]
    assert len(ids) == 2
    initial = case.recovery.preview(case.subscription, ids)
    assert initial['eligible']
    mark_revoked(case.service.store, OTHER_ORIGINAL)
    before = snapshot(case.service.store)
    with pytest.raises(ValueError):
        case.recovery.execute(case.subscription, ids, fingerprint=initial['fingerprint'], request_id='synthetic-atomic-selection')
    assert snapshot(case.service.store) == before
    assert_no_administrative_writes(case)
    with case.service.store.db() as db:
        assert all(attempt_limit(db, identifier) is None for identifier in ids)


def test_identical_ids_in_independent_database_do_not_share_revocation_or_fingerprint(legacy_reaction, tmp_path):
    case = legacy_reaction
    valid = preview(case)
    other_path = tmp_path / 'other-owner.sqlite'
    with case.service.store.db() as source, closing(sqlite3.connect(other_path)) as destination:
        source.backup(destination)
    settings = replace(case.service.settings, database=other_path)
    other = EventRecovery(Store(other_path, migrate_schema=False), settings)
    mark_revoked(case.service.store)
    first_before, other_before = snapshot(case.service.store), snapshot(other.store)
    assert not preview(case)['eligible']
    eligible = other.preview(case.subscription, [case.delivery['id']])
    assert eligible['eligible'] and eligible['fingerprint'] != valid['fingerprint']
    with pytest.raises(ValueError, match='Preview changed'):
        other.execute(case.subscription, [case.delivery['id']], fingerprint=valid['fingerprint'], request_id='synthetic-cross-database')
    assert snapshot(other.store) == other_before
    other.execute(case.subscription, [case.delivery['id']], fingerprint=eligible['fingerprint'], request_id='synthetic-local-database')
    assert snapshot(case.service.store) == first_before
    assert_no_administrative_writes(case)


@pytest.mark.parametrize('stage', ['before-claim', 'before-post'])
@pytest.mark.parametrize('change', ['target-revoked', 'different-revoked-target'])
def test_recovery_worker_rechecks_canonical_reaction_source_without_callback(legacy_reaction, monkeypatch, stage, change):
    case = legacy_reaction
    valid = preview(case)
    execute(case, valid['fingerprint'])
    calls = len(case.receiver.requests)
    changed = []
    def invalidate():
        if changed:
            return
        changed.append(True)
        identifier = ORIGINAL if change == 'target-revoked' else OTHER_ORIGINAL
        mark_revoked(case.service.store, identifier)
        if change == 'different-revoked-target':
            value = {**case.payload, 'reaction': {'messageId': identifier, 'text': 'synthetic changed target'}}
            with case.service.store.db() as db:
                db.execute('UPDATE account_events SET data=? WHERE id=?', (canonical(value), case.delivery['event_id']))
    if stage == 'before-claim':
        invalidate()
    else:
        decrypt = case.service.events.cipher.decrypt
        def decrypt_after_change(value):
            invalidate()
            return decrypt(value)
        monkeypatch.setattr(case.service.events.cipher, 'decrypt', decrypt_after_change)
    assert case.service.events.dispatch_one()
    assert changed == [True] and len(case.receiver.requests) == calls
    with case.service.store.db() as db:
        row = db.execute('SELECT state,attempts FROM deliveries WHERE id=?', (case.delivery['id'],)).fetchone()
        assert tuple(row) == ('cancelled', case.delivery['attempts'] + int(stage == 'before-post'))
        assert attempt_limit(db, case.delivery['id']) == case.delivery['attempts'] + 1
        assert db.execute('SELECT 1 FROM state WHERE key=?', (REVOCATION_REPAIR_KEY,)).fetchone() is None
    assert not case.service.events.dispatch_one()
