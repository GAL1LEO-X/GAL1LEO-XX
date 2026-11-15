"""Synthetic read projections: provider observations do not prove a phone mirror."""
import copy
from types import SimpleNamespace

import pytest

from conftest import call, message
from sally_whatsapp.gateway import GatewayUnavailable


CHAT = '123456789@c.us'
IDENTIFIER = 'false_123456789@c.us_SYNTHETIC'


def read(service, operation='chats_get_chat_message', arguments=None):
    arguments = arguments or {'path': {'chatId': CHAT, 'messageId': IDENTIFIER}}
    return service.operation(SimpleNamespace(operation=operation, arguments=arguments),
                             'test-owner', readonly=True)


def test_revoked_message_cannot_return_from_live_read(app_client):
    app, _ = app_client
    service = app.state.service
    service.store.ingest({'id': 'synthetic-revoke', 'event': 'message.revoked',
                          'payload': {'revokedMessageId': IDENTIFIER}})
    service.gateway.request = lambda *a, **k: {
        'id': IDENTIFIER, 'body': 'synthetic revoked body',
        'media': {'filename': 'synthetic revoked attachment'}}
    result = read(service)
    assert result['result'] == {'id': IDENTIFIER, 'content_state': 'revoked'}
    assert result['source'] == 'live_gateway'
    assert result['current_state'] == 'provider_observation'
    assert result['mirror_complete'] is False


@pytest.mark.parametrize('revoked_alias',[True,False])
@pytest.mark.parametrize('returned_alias',[True,False])
def test_group_revocation_before_acquisition_redacts_live_participant_alias(app_client,revoked_alias,returned_alias):
    app,_=app_client
    service=app.state.service
    alias='123456780@lid'
    group='123456781@g.us'
    service.store.bind_chat_alias(alias,CHAT)
    reference=alias if revoked_alias else CHAT
    author=alias if returned_alias else CHAT
    identifier=f'false_{group}_RAW_{author}'
    service.store.ingest({'id':'group-revoke-without-acquisition','event':'message.revoked',
                          'payload':{'revokedMessageId':f'false_{group}_RAW_{reference}'}})
    payload={'id':identifier,'body':'Synthetic revoked live body','participant':author}
    service.gateway.request=lambda *a,**k:copy.deepcopy(payload)
    arguments={'path':{'chatId':group,'messageId':identifier}}
    assert read(service,arguments=arguments)['result']=={'id':identifier,'content_state':'revoked'}
    # Equal stanza IDs from another group participant are independent.
    other=f'false_{group}_RAW_123456782@c.us'
    payload={'id':other,'body':'Synthetic visible live body','participant':'123456782@c.us'}
    assert read(service,arguments={'path':{'chatId':group,'messageId':other}})['result']=={**payload,'chat_type':'group'}


@pytest.mark.parametrize('operation,arguments,payload', [
    ('chats_get_chat_messages', {'path': {'chatId': CHAT}, 'query': {'limit': 2}},
     [{'id': IDENTIFIER, 'body': 'hidden'}, {'id': f'false_{CHAT}_OTHER', 'body': 'visible'}]),
    ('chats_get_chats_overview', {},
     [{'id': CHAT, 'lastMessage': {'id': IDENTIFIER, 'body': 'hidden'}}]),
    ('chats_post_chats_overview', {'body': {'pagination': {}}},
     [{'id': CHAT, 'lastMessage': {'id': IDENTIFIER, 'body': 'hidden'}}]),
    ('chats_get_chats', {},
     [{'id': CHAT, 'lastMessage': {'id': IDENTIFIER, 'body': 'hidden'}}]),
    ('channels_preview_channel_messages', {'path': {'id': 'synthetic@newsletter'},
                                         'query': {'limit': 2, 'downloadMedia': False}},
     [{'message': {'id': IDENTIFIER, 'body': 'hidden'}, 'reactions': {'synthetic': 2}, 'viewCount': 3}]),
])
def test_live_collections_do_not_resurrect_content(app_client, operation, arguments, payload):
    app, _ = app_client
    service = app.state.service
    service.store.ingest({'id': 'synthetic-revoke', 'event': 'message.revoked',
                          'payload': {'revokedMessageId': IDENTIFIER}})
    service.gateway.request = lambda *a, **k: copy.deepcopy(payload)
    result = read(service, operation, arguments or {'query': {}})
    assert 'hidden' not in str(result)
    assert 'revoked' in str(result)
    assert len(result['result']) == len(payload)  # Preserve provider offsets.


def test_empty_live_source_does_not_hide_acquired_archive(app_client):
    app, _ = app_client
    service = app.state.service
    service.store.ingest(message(IDENTIFIER, chat=CHAT, text='synthetic acquired body'))
    service.gateway.request = lambda *a, **k: []
    result = read(service, 'chats_get_chat_messages',
                  {'path': {'chatId': CHAT}, 'query': {'limit': 2}})
    assert result['result'] == []
    assert result['current_state'] == 'provider_observation'
    assert service.store.message(IDENTIFIER)['body'] == 'synthetic acquired body'


def test_documented_reply_target_is_redacted_without_hiding_new_reply(app_client):
    app, _ = app_client
    service = app.state.service
    service.store.ingest({'id': 'synthetic-revoke', 'event': 'message.revoked',
                          'payload': {'revokedMessageId': IDENTIFIER}})
    service.gateway.request = lambda *a, **k: {
        'id': 'new-reply', 'from': CHAT, 'body': 'visible reply',
        'replyTo': {'id': IDENTIFIER, 'body': 'hidden quote', 'media': {'filename': 'hidden'}}}
    result = read(service, arguments={'path': {'chatId': CHAT, 'messageId': 'new-reply'}})['result']
    assert result['body'] == 'visible reply'
    assert result['replyTo'] == {'id': IDENTIFIER, 'content_state': 'revoked'}


def test_unidentified_quote_does_not_guess_target_from_text_or_participant(app_client):
    app, _ = app_client
    service = app.state.service
    service.store.ingest({'id': 'synthetic-revoke', 'event': 'message.revoked',
                          'payload': {'revokedMessageId': IDENTIFIER}})
    payload = {'id': 'new-reply', 'from': CHAT, 'body': 'visible reply',
               'replyTo': {'participant': CHAT, 'body': IDENTIFIER}}
    service.gateway.request = lambda *a, **k: copy.deepcopy(payload)
    assert read(service, arguments={'path': {'chatId': CHAT, 'messageId': 'new-reply'}})['result'] == {**payload,'chat_type':'private'}


def test_unavailable_live_source_does_not_return_archive_fallback(app_client):
    app, _ = app_client
    service = app.state.service
    service.store.ingest(message(IDENTIFIER, chat=CHAT, text='synthetic acquired body'))
    def unavailable(*args, **kwargs):
        raise GatewayUnavailable('Synthetic unavailable source')
    service.gateway.request = unavailable
    with pytest.raises(GatewayUnavailable):
        read(service)
    assert service.store.message(IDENTIFIER)['body'] == 'synthetic acquired body'


def test_acquired_message_and_missing_message_have_explicit_provenance(app_client):
    app, client = app_client
    app.state.service.store.ingest(message(IDENTIFIER, chat=CHAT))
    result = call(client, 'get_message', {'message_id': IDENTIFIER})['result']['structuredContent']
    assert result['source'] == 'acquired_archive'
    assert result['current_state'] == 'unknown'
    assert result['mirror_complete'] is False
    missing = call(client, 'get_message', {'message_id': 'missing'})['result']['structuredContent']
    assert missing['message'] is None
    assert missing['current_state'] == 'unknown'


def test_missing_revoked_message_explains_state_without_content(app_client):
    app, client = app_client
    app.state.service.store.ingest({'id': 'synthetic-revoke', 'event': 'message.revoked',
                                   'payload': {'revokedMessageId': IDENTIFIER}})
    result = call(client, 'get_message', {'message_id': IDENTIFIER})['result']['structuredContent']
    assert result['message'] is None
    assert result['current_state'] == 'revoked'


def test_model_limits_do_not_claim_provider_subscription_or_mirror(app_client):
    _, client = app_client
    for name in ('connection_status', 'get_capabilities'):
        result = call(client, name)['result']['structuredContent']
        model = result['message_state_model']
        assert model['mirror_complete'] is False
        assert model['absence_implies_deletion'] is False
        assert model['provider_event_configuration_verified'] is False


def test_unrelated_live_read_shape_is_unchanged(app_client):
    app, _ = app_client
    service = app.state.service
    payload = [{'requesterId': 'synthetic@lid', 'requestMethod': 'invite_link'}]
    service.gateway.request = lambda *a, **k: payload
    assert read(service, 'groups_get_group_join_requests',
                {'path': {'id': 'synthetic@g.us'}}) == {'result': payload}


@pytest.mark.parametrize('state', ['revoked', 'deleted_for_me', 'chat_deleted', 'chat_cleared'])
def test_known_unavailable_states_allow_only_identifier_and_state(state):
    from sally_whatsapp.linked_state_reads import project_live_read
    store = SimpleNamespace(message_state=lambda *a, **k: {'state': state, 'source': 'synthetic'})
    result = project_live_read(store, 'chats_get_chat_message', {'path': {'chatId': CHAT}}, {
        'id': IDENTIFIER, 'body': 'hidden', 'futureContentField': 'hidden',
        'media': {'url': 'https://synthetic.example/hidden'}, 'replyTo': {'body': 'hidden'}})
    assert result['result'] == {'id': IDENTIFIER, 'content_state': state}


def test_revocation_during_gateway_read_wins_before_response(app_client):
    app, _ = app_client
    service = app.state.service
    def provider(*args, **kwargs):
        service.store.ingest({'id': 'synthetic-race', 'event': 'message.revoked',
                              'payload': {'revokedMessageId': IDENTIFIER}})
        return {'id': IDENTIFIER, 'body': 'hidden'}
    service.gateway.request = provider
    assert read(service)['result'] == {'id': IDENTIFIER, 'content_state': 'revoked'}


def test_wrong_provider_identifier_is_rejected_even_for_requested_tombstone(app_client):
    app, _ = app_client
    service = app.state.service
    service.store.ingest({'id': 'synthetic-revoke', 'event': 'message.revoked',
                          'payload': {'revokedMessageId': IDENTIFIER}})
    service.gateway.request = lambda *a, **k: {'id': 'different-provider-id', 'body': 'hidden'}
    with pytest.raises(GatewayUnavailable, match='scope'):
        read(service)


@pytest.mark.parametrize('event,reason,fields', [
    ('events.DeleteForMe', 'deleted_for_me', {'ChatJID': CHAT, 'MessageID': 'SYNTHETIC', 'IsFromMe': False}),
    ('events.DeleteChat', 'chat_deleted', {'JID': CHAT}),
    ('events.ClearChat', 'clear_chat_coverage_uncertain', {'JID': CHAT, 'Action': {'messageRange': {'messages': [
        {'key': {'remoteJID': CHAT, 'ID': 'SYNTHETIC', 'fromMe': False}}]}}}),
])
def test_supported_provider_deletions_apply_to_live_results(app_client, event, reason, fields):
    app, _ = app_client
    service = app.state.service
    service.store.ingest({'id': 'synthetic-app-state', 'event': 'engine.event', 'engine': 'GOWS',
                          'payload': {'event': event, 'data': {
                              **fields, 'Timestamp': '2020-01-01T00:00:00Z', 'FromFullSync': False}}})
    service.gateway.request = lambda *a, **k: {'id': IDENTIFIER, 'timestamp': 1, 'body': 'hidden'}
    assert read(service)['result'] == {'id': IDENTIFIER, 'content_state': reason}


def test_new_live_message_after_chat_deletion_is_visible(app_client):
    app, _ = app_client
    service = app.state.service
    service.store.ingest({'id': 'synthetic-app-state', 'event': 'engine.event', 'engine': 'GOWS',
                          'payload': {'event': 'events.DeleteChat', 'data': {
                              'JID': CHAT, 'Timestamp': '2020-01-01T00:00:00Z', 'FromFullSync': False}}})
    payload = {'id': 'false_123456789@c.us_NEW', 'timestamp': 1577836801, 'body': 'visible new message'}
    service.gateway.request = lambda *a, **k: copy.deepcopy(payload)
    result = read(service, arguments={'path': {'chatId': CHAT, 'messageId': payload['id']}})
    assert result['result'] == {**payload,'chat_type':'private'}


@pytest.mark.parametrize('bind_alias', [True, False])
def test_live_projection_uses_only_verified_pn_lid_alias(app_client, bind_alias):
    app, _ = app_client
    service = app.state.service
    lid = '987654321@lid'
    if bind_alias:
        service.store.bind_chat_alias(lid, CHAT)
    service.store.ingest({'id': 'synthetic-app-state', 'event': 'engine.event', 'engine': 'GOWS',
                          'payload': {'event': 'events.DeleteForMe', 'data': {
                              'ChatJID': lid, 'MessageID': 'SYNTHETIC', 'IsFromMe': False,
                              'Timestamp': '2020-01-01T00:00:00Z', 'FromFullSync': False}}})
    payload = {'id': IDENTIFIER, 'timestamp': 1, 'body': 'synthetic original'}
    service.gateway.request = lambda *a, **k: copy.deepcopy(payload)
    result = read(service)['result']
    if bind_alias:
        assert result == {'id': IDENTIFIER, 'content_state': 'deleted_for_me'}
    else:
        assert result == {**payload,'chat_type':'private'}


@pytest.mark.parametrize('timestamp', ['1', True, -1, float('nan'), float('inf'), 10**1000])
def test_invalid_provider_timestamp_cannot_infer_chat_deletion(timestamp):
    from sally_whatsapp.linked_state_reads import project_live_read
    observed = []
    def state(*args, **kwargs):
        observed.append(kwargs['timestamp'])
        return {'state': 'unknown'}
    project_live_read(SimpleNamespace(message_state=state), 'chats_get_chat_message',
                      {'path': {'chatId': CHAT}}, {'id': IDENTIFIER, 'timestamp': timestamp})
    assert observed == [None]
