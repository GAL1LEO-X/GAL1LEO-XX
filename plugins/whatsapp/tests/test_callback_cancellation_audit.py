"""Cancellation decisions are atomic, fenced and content-free; synthetic DBs."""
import json

import pytest

from conftest import message, subscribe
from sally_whatsapp.callback_audit import PREFIX, cancel, evidence, summary
from sally_whatsapp.store import Store


def seed(store, *, attempts=0, state='pending'):
    with store.db() as db:
        db.execute('INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,1)',
                   ('synthetic-sub', 'owner', 'message.received', '{}', 'https://receiver.example/', b'', 9e12))
        db.execute('INSERT INTO deliveries(subscription,event_id,body,state,attempts) VALUES(?,?,?,?,?)',
                   ('synthetic-sub', 'synthetic-event', '{"private":"content"}', state, attempts))


def retained(store):
    with store.db() as db:
        row = db.execute('SELECT * FROM deliveries').fetchone()
        return dict(row), evidence(db, row)


def test_cancellation_and_evidence_share_commit_and_rollback(tmp_path):
    store = Store(tmp_path/'one.db'); seed(store)
    before = retained(store)
    with pytest.raises(RuntimeError):
        with store.db() as db:
            assert cancel(db, 'id=?', (1,), 'source_revoked', now=123) == 1
            raise RuntimeError('synthetic rollback')
    assert retained(store) == before
    with store.db() as db:
        assert cancel(db, 'id=?', (1,), 'source_revoked', now=123) == 1
    row, audit = retained(Store(store.path, migrate_schema=False))
    assert row['state'] == 'cancelled' and row['attempts'] == 0
    assert audit == {'reason':'source_revoked', 'observed_at':123, 'attempt':0}
    with store.db() as db:
        assert cancel(db, 'id=?', (1,), 'event_expired', now=456) == 0
        raw = db.execute('SELECT value FROM state WHERE key=?', (PREFIX+'1',)).fetchone()[0]
        assert 'private' not in raw and 'content' not in raw and 'synthetic-' not in raw
    assert retained(store)[1] == audit


def test_superseded_attempt_cannot_claim_cause_and_tenants_are_separate(tmp_path):
    one, two = Store(tmp_path/'one.db'), Store(tmp_path/'two.db')
    seed(one, attempts=2, state='sending'); seed(two, attempts=2, state='sending')
    with one.db() as db:
        assert cancel(db, "id=? AND state='sending' AND attempts=?", (1,1), 'source_unavailable') == 0
        assert cancel(db, "id=? AND state='sending' AND attempts=?", (1,2), 'source_unavailable') == 1
    assert retained(one)[1]['attempt'] == 2
    assert retained(two)[0]['state'] == 'sending'
    assert retained(two)[1]['reason'] == 'historical_or_unattributed'


def test_old_cancelled_row_is_not_reclassified_from_current_source(tmp_path):
    store = Store(tmp_path/'legacy.db'); seed(store, state='cancelled')
    with store.db() as db:
        assert cancel(db, 'id=?', (1,), 'source_unavailable') == 0
        assert summary(db)['cancelled_by_reason'] == {'historical_or_unattributed':1}
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
        assert not db.execute('SELECT 1 FROM state WHERE key GLOB ?', (PREFIX+'*',)).fetchone()


def test_revocation_and_unsubscribe_keep_actual_cause_without_callback(app_client, environment):
    app, client = app_client; service = app.state.service
    subscribe(client)
    service.store.ingest(message('synthetic-cancel'))
    service.store.ingest({'event':'message.revoked', 'id':'synthetic-revoke',
                         'payload':{'revokedMessageId':'synthetic-cancel'}})
    with service.store.db() as db:
        row = db.execute('SELECT * FROM deliveries').fetchone()
        assert row['state'] == 'cancelled'
        assert evidence(db, row)['reason'] == 'source_revoked'
    assert not service.events.dispatch_one()
    assert len(environment[1].requests) == 1  # Only the synthetic subscription verification.
