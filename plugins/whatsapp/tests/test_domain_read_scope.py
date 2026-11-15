"""Synthetic request scopes, typed archive pages and legacy PN namespaces."""
import copy
from types import SimpleNamespace

import pytest

from sally_whatsapp.gateway import GatewayUnavailable
from sally_whatsapp.server import ChatList, Conversation, OperationArguments, Search, Service
from sally_whatsapp.store import Store


PN = '15550001000@c.us'
LEGACY = '15550001000@s.whatsapp.net'
OTHER = '15550002000@c.us'
LID = '15550009999@lid'
SELF = '15550000000@c.us'
GROUP = '15550003000-123@g.us'
CHANNEL = '15550004000@newsletter'


def row(chat=PN, raw='SYNTHETIC', timestamp=1500, **extra):
    return {'id': f'false_{chat}_{raw}', 'from': chat, 'to': SELF,
            'fromMe': False, 'timestamp': timestamp, 'body': 'Synthetic content', **extra}


@pytest.fixture
def service(tmp_path):
    value = Service.__new__(Service)
    value.store = Store(tmp_path / 'archive.sqlite')
    value.settings = SimpleNamespace(session='synthetic', owner_subject='synthetic-owner')
    value.requests = []
    value.rows = []
    def request(method, path, **kwargs):
        value.requests.append((method, path, kwargs))
        assert method == 'GET'
        return copy.deepcopy(value.rows)
    value.gateway = SimpleNamespace(request=request)
    return value


def read(service, *, generic=False, **kwargs):
    if generic:
        return service.operation(OperationArguments(operation='chats_get_chat_messages', arguments={
            'path': {'chatId': PN}, 'query': {'limit': 10,
                'filter.timestamp.gte': 1000, 'filter.timestamp.lte': 2000}}),
            'synthetic-owner', readonly=True)
    return service.read_conversation(Conversation(chat_id=PN, source='live', after=1000, before=2000, **kwargs))


@pytest.mark.parametrize('generic', [False, True])
@pytest.mark.parametrize('payload', [row(OTHER), row('status@broadcast'), row(timestamp=999),
    row(timestamp=2001), row(id=f'false_{OTHER}_SYNTHETIC'), row(fromMe=True),
    {key: value for key, value in row().items() if key != 'timestamp'},
    row(timestamp=True), row(timestamp=10**1000), row(fromMe='false')])
def test_live_rejects_entire_inconsistent_page(service, payload, generic):
    service.rows = [row(raw='VALID'), payload]
    with pytest.raises(GatewayUnavailable, match='scope'):
        read(service, generic=generic)
    assert service.store.search()['messages'] == []


@pytest.mark.parametrize('chat', [PN, LEGACY, LID])
def test_live_accepts_boundaries_namespace_and_only_verified_alias(service, chat):
    if chat == LID:
        service.rows = [row(chat)]
        with pytest.raises(GatewayUnavailable, match='scope'):
            read(service)
        service.store.bind_chat_alias(LID, PN)
    service.rows = [row(chat, raw='FIRST', timestamp=1000), row(chat, raw='LAST', timestamp=2000)]
    result = read(service)
    assert len(result['messages']) == 2
    assert result['chat_type'] == 'private'


def test_single_read_rejects_wrong_key_but_accepts_verified_alias(service):
    requested = f'false_{PN}_TARGET'
    args = OperationArguments(operation='chats_get_chat_message', arguments={
        'path': {'chatId': PN, 'messageId': requested}})
    service.rows = row(PN, raw='OTHER')
    with pytest.raises(GatewayUnavailable, match='scope'):
        service.operation(args, 'synthetic-owner', readonly=True)
    service.store.bind_chat_alias(LID, PN)
    service.rows = row(LID, raw='TARGET')
    assert service.operation(args, 'synthetic-owner', readonly=True)['result']['id'] == service.rows['id']


def test_scope_checks_precede_lifetime_redaction_and_do_not_apply_to_quotes(service):
    service.rows = [row(OTHER, _data={'Message': {'viewOnceMessage': {'message': {'imageMessage': {}}}}})]
    with pytest.raises(GatewayUnavailable, match='scope'):
        read(service)
    service.rows = [row(replyTo=row(OTHER, timestamp=1))]
    assert read(service)['messages'][0]['replyTo']['from'] == OTHER


def ingest(store, payload):
    store.ingest({'id': 'event-' + payload['id'], 'event': 'message', 'payload': payload}, historical=True)


def test_chat_type_filter_runs_before_limits_and_cursor_binds_filter(service):
    store = service.store
    chats = [(PN, 'private'), (LID, 'private'), (GROUP, 'group'), ('status@broadcast', 'status'),
             (CHANNEL, 'channel'), ('15550005000@broadcast', 'broadcast'), ('opaque', 'unknown')]
    for index, (chat, _) in enumerate(chats):
        ingest(store, row(chat, timestamp=1000 + index))
    assert len(store.search()['messages']) == len(chats)
    assert len(store.chats()['chats']) == len(chats)
    for chat, kind in chats:
        assert store.message(f'false_{chat}_SYNTHETIC')['chat_type'] == kind
    first = store.search(chat_type='private', limit=1)
    assert first['messages'][0]['chat_id'] == LID
    assert first['messages'][0]['chat_type'] == 'private'
    assert first['next_cursor']
    second = store.search(chat_type='private', limit=1, cursor=first['next_cursor'])
    assert [value['chat_id'] for value in second['messages']] == [PN]
    assert second['next_cursor'] is None
    with pytest.raises(ValueError, match='cursor'):
        store.search(chat_type='all', cursor=first['next_cursor'])
    assert store.chats(chat_type='private', limit=1)['chats'][0]['id'] == LID
    assert store.chats(chat_type='private', limit=1, offset=1)['chats'][0]['id'] == PN
    for _, kind in chats[2:]:
        assert {value['chat_type'] for value in store.search(chat_type=kind)['messages']} == {kind}
        assert {value['chat_type'] for value in store.chats(chat_type=kind)['chats']} == {kind}
    assert Search(chat_type='private').chat_type == ChatList(chat_type='private').chat_type == 'private'


def test_live_type_filter_is_a_scope_assertion_before_provider_request(service):
    with pytest.raises(ValueError, match='Requested chat type'):
        service.read_conversation(Conversation(chat_id='status@broadcast', source='live', chat_type='private'))
    assert service.requests == []


def delete(chat, raw='SYNTHETIC'):
    return {'id': 'synthetic-delete-' + chat, 'event': 'engine.event', 'engine': 'GOWS',
        'payload': {'event': 'events.DeleteForMe', 'data': {'ChatJID': chat,
            'Timestamp': '1970-01-01T00:30:00Z', 'FromFullSync': False,
            'IsFromMe': False, 'MessageID': raw, 'Action': {'messageTimestamp': 1500}}}}


@pytest.mark.parametrize('legacy_stored', [False, True])
def test_phone_namespace_ingress_and_legacy_reads_share_tombstones(service, legacy_stored):
    store = service.store
    payload = row(LEGACY)
    ingest(store, payload)
    if legacy_stored:
        # Reconstruct an accepted pre-fix row in this disposable DB only.
        with store.db() as db:
            db.execute('UPDATE messages SET chat_id=?', (LEGACY,))
            db.execute('DELETE FROM chats')
            db.execute('INSERT INTO chats(id,name) VALUES(?,?)', (LEGACY, 'Synthetic legacy'))
    else:
        with store.db() as db:
            assert db.execute('SELECT chat_id FROM messages').fetchone()[0] == PN
    assert store.canonical_chat(LEGACY) == PN
    assert store.message(payload['id'])['chat_id'] == PN
    assert store.search(chat_id=PN)['messages'][0]['chat_id'] == PN
    assert store.chats()['chats'][0]['id'] == PN
    store.ingest(delete(LEGACY))
    for chat in (PN, LEGACY):
        identifier = payload['id'].replace(LEGACY, chat)
        assert store.message_state(identifier)['state'] == 'deleted_for_me'
        assert store.message(identifier) is None
        assert store.search(chat_id=chat)['messages'] == []
    assert store.chats()['chats'][0]['archived_messages'] == 0
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM chat_aliases').fetchone()[0] == 0
        if legacy_stored:
            assert db.execute('SELECT chat_id FROM messages').fetchone()[0] == LEGACY


def test_unverified_lid_is_not_hidden_by_phone_tombstone(service):
    ingest(service.store, row(LID))
    service.store.ingest(delete(PN))
    assert service.store.search(chat_id=LID)['messages'][0]['body'] == 'Synthetic content'
    service.store.bind_chat_alias(LID, PN)
    assert service.store.search(chat_id=PN)['messages'] == []


@pytest.mark.parametrize('chat,kind', [(LEGACY, 'private'), (LID, 'private'), (GROUP, 'group'),
    ('status@broadcast', 'status'), (CHANNEL, 'channel'), ('15550005000@broadcast', 'broadcast'),
    ('Status', 'unknown'), ('person@c.us', 'unknown'), ('name@g.us', 'unknown'),
    ('status@broadcast.invalid', 'unknown'), ('15550001000@c.us\n', 'unknown')])
def test_type_uses_identifier_namespace_only(chat, kind):
    from sally_whatsapp.chat_identity import chat_type
    assert chat_type(chat) == kind


@pytest.mark.parametrize('namespace', [LEGACY, LID])
def test_live_outgoing_key_and_fields_can_use_verified_namespaces(service, namespace):
    if namespace == LID:
        service.store.bind_chat_alias(LID, PN)
    service.rows = [row(PN, id=f'true_{namespace}_SYNTHETIC', fromMe=True, to=None)]
    assert read(service)['messages'][0]['body'] == 'Synthetic content'


def test_opaque_key_cannot_reattribute_an_acquired_other_chat(service):
    ingest(service.store, row(OTHER, id='opaque'))
    service.rows = [row(PN, id='opaque')]
    with pytest.raises(GatewayUnavailable, match='scope'):
        read(service)


def test_legacy_edit_and_raw_revocation_keep_original_id_and_redact_retained_content(service):
    store = service.store
    payload = row(LEGACY)
    ingest(store, payload)
    with store.db() as db:
        db.execute('UPDATE messages SET chat_id=?', (LEGACY,))
    store.ingest({'id': 'edit', 'event': 'message.edited', 'timestamp': 1800000,
        'payload': row(PN, raw='NOTICE', editedMessageId='SYNTHETIC', body='Synthetic edit')})
    current = store.message(payload['id'])
    assert current['id'] == payload['id'] and current['body'] == 'Synthetic edit'
    store.ingest({'id': 'revoke', 'event': 'message.revoked', 'timestamp': 2000000,
        'payload': {'from': PN, 'revokedMessageId': 'SYNTHETIC'}})
    assert store.message(payload['id']) is None
    with store.db() as db:
        assert db.execute('SELECT body,media FROM messages').fetchone()[:] == ('', None)
    ingest(store, payload)
    assert store.search()['messages'] == []


@pytest.mark.parametrize('event', ['events.ClearChat', 'events.DeleteChat'])
def test_legacy_chat_boundaries_withhold_old_rows_and_preserve_new_activity(service, event):
    store = service.store
    payload = row(LEGACY, timestamp=1000)
    ingest(store, payload)
    with store.db() as db:
        db.execute('UPDATE messages SET chat_id=?', (LEGACY,))
    store.ingest({'id': 'boundary', 'event': 'engine.event', 'engine': 'GOWS',
        'payload': {'event': event, 'data': {'JID': LEGACY,
            'Timestamp': '1970-01-01T00:33:20Z', 'FromFullSync': False,
            'Action': {'messageRange': {'lastMessageTimestamp': 1500}}}}})
    assert store.message(payload['id']) is None
    assert store.search()['messages'] == []
    assert not store.chats()['chats'] or store.chats()['chats'][0]['archived_messages'] == 0
    ingest(store, row(PN, raw='NEW', timestamp=3000))
    assert [item['timestamp'] for item in store.search(chat_id=LEGACY)['messages']] == [3000]
    assert store.chats()['chats'][0]['archived_messages'] == 1
    assert store.chats()['chats'][0]['id'] == PN


def test_legacy_tombstone_namespace_is_projected_without_rewriting(service):
    store = service.store
    payload = row(PN)
    ingest(store, payload)
    store.ingest(delete(PN))
    with store.db() as db:
        db.execute("UPDATE state SET value=json_set(value,'$.chat_id',?) WHERE json_extract(value,'$.kind')='message'", (LEGACY,))
    assert store.message_state(payload['id'])['state'] == 'deleted_for_me'
    assert store.message(payload['id']) is None
    assert store.search()['messages'] == []
    assert store.chats()['chats'][0]['archived_messages'] == 0
