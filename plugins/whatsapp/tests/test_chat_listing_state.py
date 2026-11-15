"""Chat metadata follows visible acquired activity, never directory presence."""
import json

import pytest

from conftest import call
from test_linked_device_visibility import CHAT, LID, acquired, event
from sally_whatsapp import visibility
from sally_whatsapp.store import Store


def listed(store, **kwargs):
    return {row['id']: row for row in store.chats(**kwargs)['chats']}


def test_deleted_chat_hidden_but_explicit_metadata_and_private_rows_preserved(tmp_path):
    store = Store(tmp_path/'archive.sqlite')
    old = acquired(store)
    store.cache_chat_names([{'id': CHAT, 'name': 'Synthetic name'}], 'live_directory')
    store.ingest(event())
    assert store.chats()['chats'] == []
    row = listed(store, include_deleted=True)[CHAT]
    assert row['chat_state'] == 'deleted' and row['current_state'] == 'chat_deleted'
    assert row['deletion_evidence_at'] == 1500
    assert row['name'] == 'Synthetic name' and row['name_source'] == 'live_directory'
    assert row['archived_messages'] == 0
    assert row['first_message_at'] is row['last_message_at'] is None
    assert 'Synthetic retained content' not in json.dumps(row)
    assert store.message(old) is None and store.search()['messages'] == []
    with store.db() as db:
        assert db.execute('SELECT body FROM messages WHERE id=?', (old,)).fetchone()[0]
        assert db.execute('SELECT count(*) FROM message_search WHERE id=?', (old,)).fetchone()[0] == 1


def test_directory_metadata_without_messages_is_not_phone_empty_evidence(tmp_path):
    store = Store(tmp_path/'archive.sqlite')
    store.cache_chat_names([{'id': CHAT, 'name': 'First'}], 'live_directory', observed_at=10)
    row = listed(store)[CHAT]
    assert row['chat_state'] == 'no_acquired_messages'
    assert row['current_state'] == 'unknown' and row['deletion_evidence_at'] is None
    store.cache_chat_names([{'id': CHAT, 'name': 'Renamed'}], 'group_event', observed_at=20)
    row = listed(store)[CHAT]
    assert row['name'] == 'Renamed' and row['name_source'] == 'group_event'
    assert row['name_updated_at'] == '1970-01-01T00:00:20Z'
    assert row['chat_state'] == 'no_acquired_messages'


def test_directory_update_never_reopens_deleted_chat(tmp_path):
    store = Store(tmp_path/'archive.sqlite')
    acquired(store)
    store.ingest(event())
    store.cache_chat_names([{'id': CHAT, 'name': 'New directory name'}], 'live_directory')
    assert store.chats()['chats'] == []
    assert listed(store, include_deleted=True)[CHAT]['name'] == 'New directory name'


@pytest.mark.parametrize('historical', [False, True])
def test_only_strictly_newer_visible_activity_reopens_without_old_content(tmp_path, historical):
    store = Store(tmp_path/'archive.sqlite')
    old = acquired(store)
    store.ingest(event())
    equal = acquired(store, 'EQUAL', when=1500, historical=historical)
    # Keep the existing strict message exclusion; equality cannot reopen a chat.
    assert store.message(equal) is not None
    assert store.chats()['chats'] == []
    new = acquired(store, 'NEW', when=1501, historical=historical)
    row = listed(store)[CHAT]
    assert row['chat_state'] == 'has_acquired_messages'
    assert row['current_state'] == 'unknown' and row['deletion_evidence_at'] == 1500
    assert row['first_message_at'] == 1500 and row['last_message_at'] == 1501
    assert row['archived_messages'] == 2
    assert store.message(old) is None
    assert {m['id'] for m in store.search()['messages']} == {equal, new}
    acquired(store, 'LATE-OLD', historical=True)
    assert listed(store)[CHAT]['archived_messages'] == 2


@pytest.mark.parametrize('removal', ['revoked', 'DeleteForMe', 'ClearChatAnchor', 'ClearChatRange', 'DeleteChat'])
def test_removing_last_visible_activity_recomputes_deleted_state(tmp_path, removal):
    store = Store(tmp_path/'archive.sqlite')
    acquired(store)
    store.ingest(event())
    new = acquired(store, 'NEW', when=1600)
    assert listed(store)[CHAT]['last_message_at'] == 1600
    if removal == 'revoked':
        store.ingest({'event': 'message.revoked', 'id': 'synthetic-revoke',
                      'payload': {'revokedMessageId': new}})
    elif removal == 'ClearChatRange':
        change = event('ClearChat', when=1700)
        change['payload']['data']['Action'] = {'messageRange': {'lastMessageTimestamp': 1600}}
        store.ingest(change)
    elif removal == 'ClearChatAnchor':
        store.ingest(event('ClearChat', when=1700, refs=[('NEW', False)]))
    elif removal == 'DeleteChat':
        store.ingest(event(when=1700))
    else:
        store.ingest(event(removal, when=1700, raw='NEW'))
    assert store.chats()['chats'] == []
    row = listed(store, include_deleted=True)[CHAT]
    assert row['chat_state'] == 'deleted' and row['archived_messages'] == 0
    assert row['last_message_at'] is None
    assert store.message(new) is None


@pytest.mark.parametrize('removal', ['revoked', 'DeleteForMe', 'ClearChat'])
def test_zero_visible_messages_without_delete_chat_does_not_claim_deletion(tmp_path, removal):
    store = Store(tmp_path/'archive.sqlite')
    target = acquired(store)
    if removal == 'revoked':
        store.ingest({'event': 'message.revoked', 'id': 'synthetic-revoke',
                      'payload': {'revokedMessageId': target}})
    else:
        store.ingest(event(removal, refs=[('OLD', False)]))
    row = listed(store)[CHAT]
    assert row['chat_state'] == 'no_acquired_messages'
    assert row['archived_messages'] == 0
    assert row['deletion_evidence_at'] is None
    if removal == 'ClearChat':
        assert row['clear_chat_coverage']['certainty'] == 'uncertain'
        assert row['current_state'] == visibility.CLEAR_UNCERTAIN


@pytest.mark.parametrize('bind_before', [False, True])
def test_aliases_share_latest_boundary_and_visibility(tmp_path, bind_before):
    store = Store(tmp_path/'archive.sqlite')
    acquired(store, chat=LID)
    acquired(store, 'NEW', when=1700)
    if bind_before:
        store.bind_chat_alias(LID, CHAT)
    store.ingest(event(chat=LID, when=1800))
    store.ingest(event(chat=CHAT, when=1500))
    if not bind_before:
        store.bind_chat_alias(LID, CHAT)
    assert store.chats()['chats'] == []
    rows = listed(store, include_deleted=True)
    assert list(rows) == [CHAT]
    assert rows[CHAT]['deletion_evidence_at'] == 1800
    acquired(store, 'AFTER', chat=LID, when=1801)
    assert listed(store)[CHAT]['last_message_at'] == 1801


def test_out_of_order_and_duplicate_deletion_never_reduce_boundary(tmp_path):
    path = tmp_path/'archive.sqlite'
    store = Store(path)
    acquired(store, when=1600)
    newer = event(when=1700)
    store.ingest(newer)
    store.ingest(event(when=1500))
    assert store.ingest(newer)['duplicate']
    reopened = Store(path)
    assert reopened.chats()['chats'] == []
    assert listed(reopened, include_deleted=True)[CHAT]['deletion_evidence_at'] == 1700


@pytest.mark.parametrize('legacy_anchor', [False, True])
def test_deletion_metadata_exists_without_any_acquired_message(tmp_path, legacy_anchor):
    store = Store(tmp_path/'archive.sqlite')
    if legacy_anchor:
        with store.db() as db:
            visibility.apply(db, [{'kind': 'message', 'chat_id': CHAT, 'raw_id': 'LEGACY',
                                  'from_me': False, 'reason': 'chat_deleted', 'event_at': 1500}],
                             store._canonical_chat)
    else:
        store.ingest(event())
    assert store.chats()['chats'] == []
    row = listed(store, include_deleted=True)[CHAT]
    assert row['chat_state'] == 'deleted' and row['archived_messages'] == 0
    assert row['name'] is None and row['deletion_evidence_at'] == 1500


def test_deleted_filter_precedes_offset_and_next_page_calculation(tmp_path):
    store = Store(tmp_path/'archive.sqlite')
    for i in range(3):
        chat = f'1555000111{i}@c.us'
        acquired(store, chat=chat, when=1000-i)
        store.ingest(event(chat=chat))
        # These remain message-visible under the preexisting strict boundary.
        acquired(store, 'EQUAL', chat=chat, when=1500)
    visible = ['15550002221@c.us', '15550002222@c.us']
    for i, chat in enumerate(visible):
        acquired(store, chat=chat, when=1200-i)
    first = store.chats(limit=1)
    assert [r['id'] for r in first['chats']] == visible[:1]
    assert first['next_offset'] == 1
    second = store.chats(limit=1, offset=first['next_offset'])
    assert [r['id'] for r in second['chats']] == visible[1:]
    assert second['next_offset'] is None
    assert len(store.chats(include_deleted=True)['chats']) == 5


def test_other_chats_and_stores_keep_their_own_metadata(tmp_path):
    one, two = Store(tmp_path/'one.sqlite'), Store(tmp_path/'two.sqlite')
    acquired(one)
    acquired(two)
    other = '15550009999@c.us'
    acquired(one, chat=other)
    one.ingest(event())
    assert list(listed(one)) == [other]
    assert list(listed(two)) == [CHAT]


def test_mcp_schema_and_explicit_deleted_metadata(app_client):
    app, client = app_client
    store = app.state.service.store
    acquired(store)
    store.ingest(event())
    assert call(client, 'list_chats')['result']['structuredContent']['chats'] == []
    row = call(client, 'list_chats', {'include_deleted': True})['result']['structuredContent']['chats'][0]
    assert row['chat_state'] == 'deleted'
    assert call(client, 'list_chats', {'include_deleted': 'true'})['result']['isError']
    # list_live_chats keeps its separate paging-only contract.
    assert call(client, 'list_live_chats', {'include_deleted': True})['result']['isError']
