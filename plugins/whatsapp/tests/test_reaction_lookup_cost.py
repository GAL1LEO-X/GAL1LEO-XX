"""Bound work by returned full identities, with equivalent revocation rules."""
import json
import sqlite3
import time

import pytest

from conftest import message
from sally_whatsapp import visibility
from sally_whatsapp.store import Store, canonical


def test_complete_key_read_does_not_scan_unrelated_conversation_messages(tmp_path):
    store = Store(tmp_path / 'synthetic.sqlite')
    chat = '12345@c.us'
    now = int(time.time())
    target = 'true_' + chat + '_SOURCE'
    store.ingest(message(target, chat=chat, from_me=True))
    store.ingest({'id': 'synthetic-cost-reaction', 'event': 'message.reaction',
        'payload': {'id': 'false_' + chat + '_REACTION', 'from': chat, 'fromMe': False,
                    'reaction': {'messageId': target, 'text': '👍'}}})
    with store.db() as db:
        db.executemany('INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?,?)',
            ((f'true_{chat}_UNRELATED{i}', chat, None, now, 1, '', None, 0, 'fixture', now)
             for i in range(10000)))
        # An instruction budget is deterministic across machine speeds. The
        # former per-reaction conversation scan exceeds it on this fixture.
        steps = 0
        def progress():
            nonlocal steps
            steps += 1000
            return steps > 100000
        db.set_progress_handler(progress, 1000)
        with visibility.read_snapshot(db):
            result = store._message_reactions(db, target, chat)
        assert result['reaction_events'][0]['text'] == '👍'


@pytest.mark.parametrize('revoked', [False, True])
def test_indexed_reference_preserves_verified_alias_and_direction_boundaries(tmp_path, revoked):
    store = Store(tmp_path / 'synthetic.sqlite')
    pn, lid, other = '12345@c.us', '77777@lid', '54321@c.us'
    target = 'true_' + pn + '_SOURCE'
    equivalent = 'true_' + lid + '_SOURCE'
    opposite = 'false_' + pn + '_SOURCE'
    unrelated = 'true_' + other + '_SOURCE'
    for identifier, chat in [(target,pn),(equivalent,lid),(opposite,pn),(unrelated,other)]:
        store.ingest(message(identifier, chat=chat, from_me=identifier.startswith('true_')))
    for identifier in [opposite, unrelated, *([equivalent] if revoked else [])]:
        store.ingest({'id': 'revoke-' + identifier, 'event': 'message.revoked',
                      'payload': {'revokedMessageId': identifier}})
    with store.db() as db:
        assert visibility.reference_ids(db, target, pn, store._canonical_chat) == []
    store.bind_chat_alias(lid, pn)
    assert (store.message(target) is None) is revoked
