"""Reopening needs attributable evidence, never global raw-ID correlation."""
import json
import time
from types import SimpleNamespace

import pytest

from sally_whatsapp import uncertain_review as review, visibility
from sally_whatsapp.ab_sources import verify_target
from sally_whatsapp.store import Store

OWNER = 'synthetic-review-owner'
CHAT = '15550001111@c.us'
OTHER = '15550002222@c.us'
LID = '99999000001@lid'
TARGET = 'false_' + CHAT + '_TARGET'
KEY = 'synthetic-review-request'


def seeded(tmp_path, *, target=TARGET, chat=CHAT, owner=OWNER, acknowledge=True):
    store = Store(tmp_path / 'synthetic.sqlite')
    arguments = {'body': {'chatId': chat, 'messageId': target, 'star': True}}
    observed = {'id': target, 'from': chat, 'fromMe': False,
                'timestamp': int(time.time()) - 120, 'body': 'synthetic private text',
                '_data': {'IsViewOnce': False, 'IsViewOnceV2': False,
                          'IsViewOnceV2Extension': False, 'IsEphemeral': False,
                          'Message': {'conversation': 'synthetic private text'}}}
    if visibility.message_identity(target) is not None:
        verify_target(store, SimpleNamespace(request=lambda *a, **k: observed),
                      SimpleNamespace(session='default'), 'messages_set_star', arguments)
    # Opaque historical references can predate the complete-key preflight.
    assert store.message(target) is None
    store.queue_action(KEY, owner, 'messages_set_star', arguments)
    store.finish_send(KEY, 'uncertain')
    if acknowledge:
        apply(store, plan(store, owner))
    return store


def plan(store, owner=OWNER):
    with store.db() as db:
        return review.prepare(db, owner, [KEY])


def apply(store, value):
    with store.db() as db:
        return review.apply(db, value, review.digest(value))


def status(store, owner=OWNER):
    with store.db() as db:
        return review.status(db, owner, KEY)


def ledger(store):
    with store.db() as db:
        return {name: [tuple(r) for r in db.execute('SELECT * FROM ' + name + ' ORDER BY rowid')]
                for name in ('sends', 'action_jobs', 'operation_results',
                             'action_job_sources', 'action_job_metadata')}


def revoke(store, *, chat=CHAT, target='TARGET', event='synthetic-revocation'):
    return store.ingest({'id': event, 'event': 'message.revoked',
                         'timestamp': int(time.time() * 1000),
                         'payload': {'id': 'false_' + chat + '_NOTICE', 'fromMe': False,
                                     'from': chat, 'revokedMessageId': target}})


def historical(store, *, chat=CHAT, from_me=False, target=None):
    target = target or str(from_me).lower() + '_' + chat + '_TARGET'
    return store.ingest({'id': 'synthetic-history', 'event': 'message.any',
                         'payload': {'id': target, 'fromMe': from_me,
                                     'from': chat, 'timestamp': int(time.time()) - 60,
                                     'body': 'synthetic private acquired text'}}, historical=True)


@pytest.mark.parametrize('evidence', ['raw_revocation', 'full_revocation', 'history'])
def test_new_source_evidence_reopens_without_changing_uncertain_action(tmp_path, evidence):
    store = seeded(tmp_path)
    original = ledger(store)
    before = status(store)
    if evidence == 'history':
        historical(store)
    else:
        revoke(store, target=TARGET if evidence == 'full_revocation' else 'TARGET')
    after = status(store)
    assert before['classification'] == 'known_historical_unverifiable'
    assert after['classification'] == 'reopened_evidence_changed'
    assert after['requires_attention'] and after['repeat_alert_eligible']
    assert after['outcome'] == 'uncertain' and not after['outcome_verified']
    assert ledger(store) == original
    if evidence != 'history':
        assert not store.action_ready(KEY)
    assert 'synthetic private' not in json.dumps(after)


@pytest.mark.parametrize('evidence', ['raw_revocation', 'full_revocation', 'history'])
def test_same_short_id_in_other_chat_does_not_reopen(tmp_path, evidence):
    store = seeded(tmp_path)
    if evidence == 'history':
        historical(store, chat=OTHER)
    else:
        revoke(store, chat=OTHER,
               target='false_' + OTHER + '_TARGET' if evidence == 'full_revocation' else 'TARGET')
    assert status(store)['classification'] == 'known_historical_unverifiable'


@pytest.mark.parametrize('evidence', ['history', 'full_revocation'])
def test_same_chat_and_short_id_opposite_direction_does_not_reopen(tmp_path, evidence):
    store = seeded(tmp_path)
    if evidence == 'history':
        historical(store, from_me=True)
    else:
        revoke(store, target='true_' + CHAT + '_TARGET')
    assert status(store)['classification'] == 'known_historical_unverifiable'


@pytest.mark.parametrize('mapped', [False, True])
@pytest.mark.parametrize('evidence', ['history', 'raw_revocation'])
def test_lid_evidence_uses_only_persisted_verified_alias(tmp_path, mapped, evidence):
    store = seeded(tmp_path, acknowledge=False)
    if mapped:
        with store.db() as db:
            db.execute('INSERT INTO chat_aliases VALUES(?,?)', (LID, CHAT))
    apply(store, plan(store))
    if evidence == 'history':
        historical(store, chat=LID)
    else:
        revoke(store, chat=LID)
    assert status(store)['requires_attention'] is mapped


def test_scoped_raw_target_does_not_collect_other_chat_exact_raw_events(tmp_path):
    store = seeded(tmp_path, target='TARGET')
    revoke(store, chat=OTHER)
    assert status(store)['classification'] == 'known_historical_unverifiable'
    revoke(store, event='synthetic-same-chat-revocation')
    assert status(store)['classification'] == 'reopened_evidence_changed'


def test_new_acquired_evidence_invalidates_prepared_plan_before_any_marker(tmp_path):
    store = seeded(tmp_path, acknowledge=False)
    stale = plan(store)
    historical(store)
    with pytest.raises(ValueError, match='evidence or prior review changed'):
        apply(store, stale)
    assert status(store)['classification'] == 'unreviewed'
    with store.db() as db:
        assert not db.execute('SELECT 1 FROM state WHERE key GLOB ?', (review.PREFIX + '*',)).fetchone()


def test_other_owner_and_database_do_not_share_review_or_evidence(tmp_path):
    one = tmp_path / 'one'; one.mkdir()
    two = tmp_path / 'two'; two.mkdir()
    first, second = seeded(one), seeded(two, owner='second-owner')
    revoke(first)
    assert status(first)['requires_attention']
    assert status(second, 'second-owner')['classification'] == 'known_historical_unverifiable'
    assert status(first, 'second-owner')['classification'] == 'unreviewed'
    assert status(second)['classification'] == 'unreviewed'


def test_legacy_marker_without_context_evidence_version_fails_open(tmp_path):
    store = seeded(tmp_path)
    with store.db() as db:
        for prefix in (review.PREFIX, review.AUDIT):
            for row in db.execute('SELECT key,value FROM state WHERE key GLOB ?', (prefix + '*',)).fetchall():
                value = json.loads(row['value'])
                value.pop('fingerprint_version', None)
                db.execute('UPDATE state SET value=? WHERE key=?', (review.encoded(value), row['key']))
    result = status(store)
    assert result['classification'] == 'review_unverifiable'
    assert result['requires_attention'] and result['repeat_alert_eligible']


def test_related_evidence_bound_fails_open_without_unbounded_result(tmp_path, monkeypatch):
    store = seeded(tmp_path)
    monkeypatch.setattr(review, 'MAX_EVIDENCE', 1)
    revoke(store)
    result = status(store)
    assert result['requires_attention']


def test_repeated_reads_and_unrelated_metadata_preserve_acknowledgment(tmp_path):
    store = seeded(tmp_path)
    before = status(store)
    store.set_state('unrelated', {'message': 'synthetic private unrelated text'})
    assert status(store) == before == status(store)
    with store.db() as db:
        payload = '\n'.join(r[0] for r in db.execute(
            'SELECT value FROM state WHERE key GLOB ?', ('private:uncertain_review*',)))
    assert 'synthetic private' not in payload


@pytest.mark.parametrize('evidence', ['history', 'full_revocation'])
def test_group_participant_is_part_of_complete_source_identity(tmp_path, evidence):
    group = '123456789-12345@g.us'
    target = 'false_' + group + '_TARGET_15550003333@c.us'
    other = 'false_' + group + '_TARGET_15550004444@c.us'
    store = seeded(tmp_path, target=target, chat=group)
    if evidence == 'history':
        historical(store, chat=group, target=other)
    else:
        revoke(store, chat=group, target=other)
    assert status(store)['classification'] == 'known_historical_unverifiable'
    revoke(store, chat=group, target=target, event='synthetic-matching-revocation')
    assert status(store)['requires_attention']


@pytest.mark.parametrize('same_chat', [False, True])
def test_opaque_acquired_source_respects_recorded_chat(tmp_path, same_chat):
    store = seeded(tmp_path, target='TARGET')
    historical(store, chat=CHAT if same_chat else OTHER, target='TARGET')
    assert status(store)['requires_attention'] is same_chat


@pytest.mark.parametrize('matches', [False, True])
def test_clear_with_known_boundary_only_reopens_affected_source(tmp_path, matches):
    store = seeded(tmp_path, acknowledge=False)
    historical(store)
    apply(store, plan(store))
    with store.db() as db:
        at = db.execute('SELECT timestamp FROM messages WHERE id=?', (TARGET,)).fetchone()[0]
        visibility.apply(db, [{'kind': 'clear', 'chat_id': CHAT,
                              'reason': visibility.CLEAR_UNCERTAIN, 'event_at': at + 20,
                              'through': at + 1 if matches else at - 1,
                              'anchors': [], 'range': {}, 'before': 0}], Store._canonical_chat)
    assert status(store)['requires_attention'] is matches


def test_evidence_row_limit_keeps_attention_and_rejects_acknowledgment(tmp_path, monkeypatch):
    store = seeded(tmp_path)
    monkeypatch.setattr(review, 'MAX_EVIDENCE', 3)
    with store.db() as db:
        for number in range(4):
            visibility.apply(db, [{'kind': 'clear', 'chat_id': CHAT,
                                  'reason': visibility.CLEAR_UNCERTAIN, 'event_at': number,
                                  'through': None, 'anchors': [], 'range': {}, 'before': 0}],
                             Store._canonical_chat)
    result = status(store)
    assert result['classification'] == 'review_unverifiable'
    assert result['requires_attention'] and result['repeat_alert_eligible']
    with pytest.raises(ValueError, match='evidence exceeds review bound'):
        plan(store)


def test_unrelated_visibility_records_do_not_consume_related_evidence_bound(tmp_path, monkeypatch):
    store = seeded(tmp_path)
    monkeypatch.setattr(review, 'MAX_EVIDENCE', 3)
    with store.db() as db:
        visibility.apply(db, [{'kind': 'message', 'chat_id': CHAT, 'raw_id': 'UNRELATED-' + str(number),
                              'from_me': False, 'reason': 'revoked', 'event_at': 1000 + number}
                             for number in range(10)], Store._canonical_chat)
    assert status(store)['classification'] == 'known_historical_unverifiable'


def test_invalid_evidence_does_not_silence_or_expose_raw_failure(tmp_path):
    store = seeded(tmp_path)
    with store.db() as db:
        db.execute('INSERT INTO state VALUES(?,?)', (visibility.PREFIX + 'invalid', 'synthetic-private-invalid-json'))
    result = status(store)
    assert result['classification'] == 'review_unverifiable'
    assert result['requires_attention'] and 'synthetic-private' not in json.dumps(result)


def test_contradictory_persisted_alias_does_not_create_false_equivalence(tmp_path):
    store = seeded(tmp_path, target='false_' + LID + '_TARGET', chat=LID, acknowledge=False)
    with store.db() as db:
        db.execute('INSERT INTO chat_aliases VALUES(?,?)', (LID, CHAT))
    apply(store, plan(store))
    with store.db() as db:
        db.execute('UPDATE chat_aliases SET chat_id=? WHERE alias=?', (OTHER, LID))
    assert status(store)['requires_attention']
    assert store.send_status(KEY, owner=OWNER)['state'] == 'uncertain'
