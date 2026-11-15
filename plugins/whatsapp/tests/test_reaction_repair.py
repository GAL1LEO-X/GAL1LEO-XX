"""Offline historical repair: exact evidence, privacy, atomicity, no replay."""
import copy

import pytest

from conftest import message
from sally_whatsapp import reaction_repair as repair
from sally_whatsapp.store import Store, canonical
from test_reaction_perspective import incoming, SELF, PEER


@pytest.fixture
def archive(tmp_path):
    store = Store(tmp_path / 'synthetic.sqlite')
    store.prepare_profile('synthetic-owner')
    target = 'true_' + PEER + '_SOURCE'
    store.ingest(message(target, chat=PEER, from_me=True))
    event = incoming()
    # A legacy envelope omitted engine/me. The old source remains unnormalized.
    me = event.pop('me')
    event.pop('engine')
    store.ingest(event)
    assert 'reaction_events' not in store.message(target)
    return store, me, target


def proposal(store, me):
    return repair.plan(store, me, contract=repair.CONTRACT)


def test_repair_recovers_existing_event_without_receipt_or_callback_replay(archive):
    store, me, target = archive
    with store.db() as db:
        before = {table: db.execute('SELECT count(*) FROM ' + table).fetchone()[0]
                  for table in ('receipts', 'account_events', 'sends', 'deliveries')}
    plan = proposal(store, me)
    assert len(plan['changes']) == 1
    assert 'reaction_events' not in store.message(target)  # Planning only reads.
    result = repair.apply(store, me, plan, expected_sha256=repair.digest(plan))
    assert result['repaired'] == 1 and result['notifications_created'] == result['whatsapp_actions'] == 0
    events = store.message(target)['reaction_events']
    assert len(events) == 1 and events[0]['text'] == '❤️' and events[0]['from_me'] is False
    assert store.account_event(events[0]['event_id'])['message_id'] == target
    assert store.search(chat_id=PEER)['messages'][0]['reaction_events'] == events
    with store.db() as db:
        assert before == {table: db.execute('SELECT count(*) FROM ' + table).fetchone()[0] for table in before}
    assert repair.apply(store, me, plan, expected_sha256=repair.digest(plan))['already_applied']
    assert proposal(store, me)['changes'] == []


@pytest.mark.parametrize('when', ['before_plan', 'after_plan', 'after_apply'])
def test_revocation_always_wins_over_repair(archive, when):
    store, me, target = archive
    def revoke():
        store.ingest({'id': 'synthetic-repair-revoke', 'event': 'message.revoked',
                      'payload': {'revokedMessageId': target}})
    if when == 'before_plan': revoke()
    plan = proposal(store, me)
    assert len(plan['changes']) == 1
    if when == 'after_plan': revoke()
    result = repair.apply(store, me, plan, expected_sha256=repair.digest(plan))
    if when == 'after_apply': revoke()
    else: assert result['redacted'] == 1
    assert store.message(target) is None
    assert 'reaction' not in store.account_event(plan['changes'][0]['event_id'])['data']
    with store.db() as db:
        assert '❤️' not in db.execute('SELECT data FROM account_events WHERE id=?',
                                       (plan['changes'][0]['event_id'],)).fetchone()[0]


@pytest.mark.parametrize('mutation', ['plan_digest', 'account', 'profile', 'event', 'target', 'duplicate'])
def test_repair_refuses_changed_or_ambiguous_evidence(archive, mutation):
    store, me, target = archive
    plan = proposal(store, me)
    expected = repair.digest(plan)
    if mutation == 'plan_digest': plan['changes'][0]['target'] = 'true_77777@c.us_SOURCE'
    if mutation == 'account': me = {'id': '77777@c.us'}
    if mutation == 'profile': store.prepare_profile('different-owner')
    if mutation == 'event':
        with store.db() as db: db.execute('UPDATE account_events SET timestamp=timestamp+1')
    if mutation == 'target':
        with store.db() as db: db.execute('UPDATE messages SET from_me=0 WHERE id=?', (target,))
    if mutation == 'duplicate':
        plan['changes'] *= 2
        expected = repair.digest(plan)
    with store.db() as db:
        before = [tuple(r) for r in db.execute('SELECT * FROM account_events')]
    with pytest.raises(ValueError): repair.apply(store, me, plan, expected_sha256=expected)
    with store.db() as db:
        assert [tuple(r) for r in db.execute('SELECT * FROM account_events')] == before
        assert not db.execute('SELECT 1 FROM state WHERE key GLOB ?', (repair.MARKER + '*',)).fetchone()


def test_unacquired_source_is_not_recovered_by_short_id(archive):
    store, me, target = archive
    with store.db() as db: db.execute('UPDATE messages SET id=?', ('true_77777@c.us_SOURCE',))
    assert proposal(store, me)['changes'] == []


def test_no_implicit_provider_or_archive_identity(archive):
    store, me, _ = archive
    with pytest.raises(ValueError): repair.plan(store, me, contract='NOWEB')
    with pytest.raises(ValueError): proposal(store, {})


def test_historical_callback_bytes_are_not_replayed_or_rewritten(archive):
    store, me, _ = archive
    plan = proposal(store, me)
    event_id = plan['changes'][0]['event_id']
    with store.db() as db:
        for index, state in enumerate(('pending', 'sending', 'accepted', 'failed')):
            subscription = 'synthetic-sub-' + str(index)
            db.execute('INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?)',
                (subscription, 'synthetic-owner', 'whatsapp.event', '{}', 'https://callback.example.invalid/', b'synthetic', 0, 0))
            db.execute('INSERT INTO deliveries(subscription,event_id,body,state,attempts) VALUES(?,?,?,?,?)',
                (subscription, event_id, '{"synthetic":"original signed bytes"}', state, 1))
    result = repair.apply(store, me, plan, expected_sha256=repair.digest(plan))
    assert result['callbacks_cancelled'] == 2 and result['notifications_created'] == 0
    with store.db() as db:
        rows = db.execute('SELECT * FROM deliveries ORDER BY id').fetchall()
        assert [row['state'] for row in rows] == ['cancelled', 'cancelled', 'accepted', 'failed']
        from sally_whatsapp.callback_audit import evidence
        assert [evidence(db,row)['reason'] for row in rows[:2]] == ['source_identity_repaired'] * 2
        assert all(row['body'] == '{"synthetic":"original signed bytes"}' and row['attempts'] == 1 for row in rows)
