"""Reaction target provenance and revocation, with synthetic gateway payloads.

WAHA GOWS 2026.9.2 has separate IDs for the reaction and its target:
https://github.com/devlikeapro/waha/blob/90ba445a0e765701c8910f0fac08176250c3e0fd/src/core/engines/gows/session.gows.core.ts#L3301
"""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time

import pytest

from conftest import call, message
from sally_whatsapp.account_events import source_message
from sally_whatsapp.store import Store, canonical

ORIGINAL = 'false_12345@c.us_SYNTHETIC_ORIGINAL'
REACTION = 'false_12345@c.us_SYNTHETIC_REACTION'
CHAT = '12345@c.us'
REDACTED = {'message_id': ORIGINAL, 'revoked': True}
PLUGIN = Path(__file__).resolve().parents[1]


def reaction(*, receipt='reaction-envelope', text='👍'):
    now = int(time.time())
    return {'id': receipt, 'event': 'message.reaction', 'timestamp': now * 1000,
            'payload': {'id': REACTION, 'from': CHAT, 'to': '67890@c.us',
                        'fromMe': False, 'timestamp': now,
                        'reaction': {'text': text, 'messageId': ORIGINAL}}}


def revoke():
    return {'id': 'revoke-envelope', 'event': 'message.revoked',
            'timestamp': int(time.time() * 1000), 'payload': {'revokedMessageId': ORIGINAL}}


def event_id(receipt='reaction-envelope'):
    return 'change_' + hashlib.sha256(receipt.encode()).hexdigest()


def original():
    return message(ORIGINAL, CHAT, text='synthetic original text')


def persisted(store, identifier=None):
    with store.db() as db:
        row = db.execute('SELECT source_message_id,data FROM account_events WHERE id=?',
                         (identifier or event_id(),)).fetchone()
    return row['source_message_id'], json.loads(row['data'])


@pytest.mark.parametrize('top_level', [REACTION, ORIGINAL, None, 17])
def test_reaction_source_is_typed_nested_target(top_level):
    payload = reaction()['payload']
    payload['id'] = top_level
    assert source_message('message.reaction', payload) == ORIGINAL


@pytest.mark.parametrize('payload', [
    None, [], 'untrusted', {}, {'id': ORIGINAL},
    {'id': ORIGINAL, 'reaction': None}, {'id': ORIGINAL, 'reaction': 'untrusted'},
    {'id': ORIGINAL, 'reaction': []}, {'id': ORIGINAL, 'reaction': {}},
    {'id': ORIGINAL, 'reaction': {'messageId': None}},
    {'id': ORIGINAL, 'reaction': {'messageId': ''}},
    {'id': ORIGINAL, 'reaction': {'messageId': False}},
    {'id': ORIGINAL, 'reaction': {'messageId': 42}},
    {'id': ORIGINAL, 'reaction': {'messageId': [ORIGINAL]}},
    {'id': ORIGINAL, 'reaction': {'messageId': {'id': ORIGINAL}}},
    {'id': ORIGINAL, 'reaction': {'text': ORIGINAL}},
    {'id': ORIGINAL, 'reaction.messageId': ORIGINAL},
])
def test_malformed_reaction_never_falls_back_to_top_level_id_or_text(payload):
    assert source_message('message.reaction', payload) is None


def test_ack_source_contract_is_unchanged():
    payload = reaction()['payload']
    assert source_message('message.ack', payload) == REACTION
    assert source_message('message.ack.group', payload) == REACTION


@pytest.mark.parametrize('late', [False, True], ids=['reaction-before-revoke', 'reaction-after-revoke'])
def test_reaction_revocation_redacts_mcp_detail_and_persisted_payload(app_client, late):
    app, client = app_client
    store = app.state.service.store
    store.ingest(original())
    for item in ([revoke(), reaction()] if late else [reaction(), revoke()]):
        store.ingest(item)
    detail = call(client, 'get_account_event', {'event_id': event_id()})['result']['structuredContent']['event']
    assert detail['data'] == REDACTED
    assert 'source_message_id' not in detail
    assert persisted(store) == (ORIGINAL, REDACTED)
    assert call(client, 'get_message', {'message_id': ORIGINAL})['result']['structuredContent']['message'] is None


def test_restart_and_replays_keep_reaction_tombstone(tmp_path):
    path = tmp_path / 'archive.sqlite'
    store = Store(path)
    store.ingest(revoke())
    store.ingest(reaction())
    restarted = Store(path, recover_inflight=False)
    restarted.ingest(original())
    assert restarted.ingest(reaction())['duplicate']
    # A fresh envelope ID can represent a repeated provider observation. It must
    # remain redacted as well, without resurrecting the original message.
    restarted.ingest(reaction(receipt='reaction-replayed-envelope'))
    assert restarted.message(ORIGINAL) is None
    for identifier in (event_id(), event_id('reaction-replayed-envelope')):
        assert restarted.account_event(identifier)['data'] == REDACTED
        assert persisted(restarted, identifier) == (ORIGINAL, REDACTED)
    with restarted.db() as db:
        assert db.execute('SELECT kind FROM message_mutations WHERE message_id=?', (ORIGINAL,)).fetchone()[0] == 'revoked'
        assert db.execute("SELECT count(*) FROM account_events WHERE event_type='message.reaction'").fetchone()[0] == 2


def test_same_message_and_reaction_ids_remain_independent_between_databases(tmp_path):
    first = Store(tmp_path / 'first' / 'archive.sqlite')
    second = Store(tmp_path / 'second' / 'archive.sqlite')
    for store, text in ((first, '👍'), (second, '🎉')):
        store.ingest(original())
        store.ingest(reaction(text=text))
    first.ingest(revoke())
    assert first.account_event(event_id())['data'] == REDACTED
    assert first.message(ORIGINAL) is None
    assert second.account_event(event_id())['data']['reaction']['text'] == '🎉'
    assert second.message(ORIGINAL)['body'] == 'synthetic original text'
    assert persisted(second)[0] == ORIGINAL


def seed_legacy(path):
    """Use the frozen full schema6 shipped in tests, not a reduced SQL model."""
    with closing(sqlite3.connect(path)) as db:
        db.executescript((Path(__file__).parent / 'fixtures/schema6.sql').read_text())
        db.execute('INSERT INTO messages(id,chat_id,timestamp,from_me,body,deleted,source,observed_at) VALUES(?,?,?,0,?,1,?,?)',
                   (ORIGINAL, CHAT, int(time.time()), 'legacy revoked body', 'webhook', time.time()))
        db.execute("INSERT INTO message_mutations VALUES(?,'revoked',NULL,?)", (ORIGINAL, time.time()))
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?)',
                   (event_id(), 'message.reaction', CHAT, time.time(), canonical(reaction()['payload'])))
        # A previously redacted payload is already a tombstone, not a gateway
        # reaction with a missing nested field. The migration must preserve it.
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?)',
                   (event_id('already-redacted'), 'message.reaction', CHAT, time.time(), canonical(REDACTED)))
        db.commit()


@pytest.mark.parametrize('mode', ['declared', 'runtime'])
def test_real_schema6_migration_redacts_reaction_and_preserves_redacted_record(tmp_path, mode):
    source = tmp_path / 'source.sqlite'
    target = tmp_path / 'copy.sqlite'
    seed_legacy(source)
    before = source.read_bytes()
    sys.path.insert(0, str(PLUGIN / 'scripts'))
    from release_database import migrate, snapshot
    snapshot(source, target)
    assert (PLUGIN / 'deploy/6-7.sql').read_bytes() == (PLUGIN / 'sally_whatsapp/migrations/6-7.sql').read_bytes()
    if mode == 'declared':
        evidence = migrate(target, PLUGIN)
        assert evidence == {'fromSchema': 6, 'toSchema': 8, 'integrity': 'ok', 'recordIdentitiesPreserved': True}
        store = Store(target, recover_inflight=False, migrate_schema=False)
    else:
        store = Store(target, recover_inflight=False)
    assert source.read_bytes() == before
    assert store.message(ORIGINAL) is None
    for identifier in (event_id(), event_id('already-redacted')):
        assert store.account_event(identifier)['data'] == REDACTED
        assert persisted(store, identifier) == (ORIGINAL, REDACTED)
    with store.db() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert not db.execute('PRAGMA foreign_key_check').fetchall()


def inject_mislinked_schema7(store, *, revoked):
    store.ingest(original())
    if revoked:
        store.ingest(revoke())
    with store.db() as db:
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,?)',
                   (event_id(), 'message.reaction', CHAT, time.time(), canonical(reaction()['payload']), REACTION))


def test_mislinked_schema7_getter_is_defensive_without_mutating_in_check_mode(tmp_path):
    path = tmp_path / 'old-schema7.sqlite'
    store = Store(path, migrate_schema=False)
    inject_mislinked_schema7(store, revoked=True)
    before = persisted(store)
    checked = Store(path, recover_inflight=False, migrate_schema=False)
    assert checked.account_event(event_id())['data'] == REDACTED
    assert persisted(checked) == before  # Pure defensive read; check is nonmutating.


def test_mislinked_schema7_is_repaired_at_startup_and_never_unredacted(tmp_path):
    path = tmp_path / 'old-schema7.sqlite'
    # A pre-fix schema7 archive has not run the versioned startup repair. Create
    # its full schema without running that repair before injecting legacy rows.
    store = Store(path, migrate_schema=False)
    inject_mislinked_schema7(store, revoked=True)
    with store.db() as db:
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,?)',
                   (event_id('already-redacted'), 'message.reaction', CHAT, time.time(), canonical(REDACTED), ORIGINAL))
    for _ in range(2):
        repaired = Store(path, recover_inflight=False, migrate_schema=True)
        for identifier in (event_id(), event_id('already-redacted')):
            assert repaired.account_event(identifier)['data'] == REDACTED
            assert persisted(repaired, identifier) == (ORIGINAL, REDACTED)
    assert repaired.message(ORIGINAL) is None


def test_original_revocation_finds_mislinked_reaction_before_startup_repair(tmp_path):
    store = Store(tmp_path / 'old-schema7.sqlite', migrate_schema=False)
    inject_mislinked_schema7(store, revoked=False)
    store.ingest(revoke())
    assert persisted(store) == (ORIGINAL, REDACTED)
    assert store.account_event(event_id())['data'] == REDACTED
