"""Pinned Go event JSON fixtures: no accounts, network, credentials or receipts."""
import copy
from datetime import datetime
import json
import time

import pytest

from sally_whatsapp.linked_state import decode_engine_event
from sally_whatsapp.provider_events import NORMALIZED_EVENT_TYPES, decode_provider_event


STAMP = '2026-10-20T08:00:00Z'
EPOCH = datetime.fromisoformat(STAMP).timestamp()
PN = '15550001111@s.whatsapp.net'
CHAT = '15550001111@c.us'
GROUP = '120363000000000@g.us'
CHANNEL = '120363000000000@newsletter'


def appstate(action, **extra):
    return {'JID': PN, 'Timestamp': STAMP, 'FromFullSync': False, 'Action': action, **extra}


FIXTURES = [
    ('events.Star', 'message.starred', appstate({'starred': True}, ChatJID=PN, SenderJID='', IsFromMe=False, MessageID='ABC')),
    ('events.Pin', 'chat.pinned', appstate({'pinned': True})),
    ('events.Mute', 'chat.muted', appstate({'muted': True, 'muteEndTimestamp': -1, 'autoMuted': False})),
    ('events.MarkChatAsRead', 'chat.read', appstate({'read': False, 'messageRange': {'private': 'omit'}})),
    ('events.LabelAssociationMessage', 'label.message.added', appstate({'labeled': True}, LabelID='12', MessageID='ABC')),
    ('events.LabelAssociationMessage', 'label.message.deleted', appstate({'labeled': False}, LabelID='12', MessageID='ABC')),
    ('events.PushNameSetting', 'profile.name.changed', appstate({'name': 'Synthetic own name'})),
    ('events.UnarchiveChatsSetting', 'chat.archive_setting', appstate({'unarchiveChats': False})),
    ('events.UserStatusMute', 'status.muted', appstate({'muted': False})),
    ('events.PushName', 'contact.push_name', {'JID': PN, 'OldPushName': 'Before', 'NewPushName': 'After', 'Message': {'body': 'omit'}}),
    ('events.BusinessName', 'contact.business_name', {'JID': PN, 'OldBusinessName': '', 'NewBusinessName': 'Synthetic Business'}),
    ('events.Picture', 'contact.picture', {'JID': GROUP, 'Author': PN, 'Timestamp': STAMP, 'Remove': False, 'PictureID': '123'}),
    ('events.UserAbout', 'contact.about', {'JID': PN, 'Timestamp': STAMP, 'Status': 'Synthetic about'}),
    ('events.IdentityChange', 'contact.identity', {'JID': PN, 'Timestamp': STAMP, 'Implicit': True}),
    ('events.PrivacySettings', 'account.privacy', {'NewSettings': {'ReadReceipts': 'none', 'Online': 'match_last_seen'}, 'ReadReceiptsChanged': True}),
    ('events.Blocklist', 'account.blocklist', {'Action': '', 'DHash': 'omit', 'Changes': [{'JID': PN, 'Action': 'block'}]}),
    ('events.NewsletterJoin', 'channel.joined', {'id': CHANNEL, 'state': {'type': 'active'}, 'thread_metadata': {'name': {'text': 'Synthetic Channel'}, 'description': {'text': 'Description'}, 'invite': 'omit'}}),
    ('events.NewsletterLeave', 'channel.left', {'id': CHANNEL, 'role': 'subscriber'}),
    ('events.NewsletterMuteChange', 'channel.muted', {'id': CHANNEL, 'mute': 'on'}),
    ('events.NewsletterLiveUpdate', 'channel.updated', {'JID': CHANNEL, 'Time': STAMP, 'Messages': [{'MessageServerID': 42, 'MessageID': 'ABC', 'Type': 'message', 'Timestamp': STAMP, 'ViewsCount': 12, 'ReactionCounts': {'👍': 2}, 'Message': {'body': 'omit'}}]}),
    ('events.UndecryptableMessage', 'message.unavailable', {'Info': {'Chat': PN, 'Sender': PN, 'ID': 'ABC', 'IsFromMe': False, 'IsGroup': False, 'Timestamp': STAMP}, 'IsUnavailable': True, 'UnavailableType': 'view_once', 'DecryptFailMode': 'hide'}),
    ('events.NotifyAccountReachoutTimelock', 'account.reachout_timelock', {'is_active': True, 'enforcement_type': 'LIMITED', 'time_enforcement_ends': str(int(EPOCH)+3600)}),
    ('gows.MessageCapping', 'account.message_capping', {'capping_status': 'CAPPED', 'total_quota': 10, 'used_quota': 10, 'cycle_start_timestamp': str(int(EPOCH)), 'cycle_end_timestamp': int(EPOCH)+3600}),
    ('events.CallTerminate', 'call.terminated', {'CallID': 'SYNTHETIC-CALL', 'From': PN, 'GroupJID': GROUP, 'Timestamp': STAMP, 'Reason': 'accepted_elsewhere', 'Data': {'Content': 'omit'}}),
    ('events.Receipt', 'message.receipt.self', {'Chat': PN, 'Sender': PN, 'IsFromMe': True, 'IsGroup': False, 'MessageSender': '', 'MessageIDs': ['ABC', 'DEF'], 'Timestamp': STAMP, 'Type': 'read-self'}),
    ('events.GroupInfo', 'group.v2.metadata', {'JID': GROUP, 'Timestamp': STAMP, 'Locked': {'IsLocked': True}, 'Ephemeral': {'IsEphemeral': True, 'DisappearingTimer': 86400}, 'Delete': {'Deleted': False, 'DeleteReason': ''}, 'Link': {'Type': 'parent_group', 'UnlinkReason': '', 'Group': {'JID': '120363000000001@g.us', 'Name': 'omit'}}, 'NewInviteLink': 'omit', 'UnknownChanges': [{'Data': 'omit'}]}),
]


def envelope(raw, data):
    return {'event': 'engine.event', 'engine': 'GOWS', 'session': 'synthetic',
            'payload': {'event': raw, 'session': 'synthetic', 'data': copy.deepcopy(data)}}


@pytest.mark.parametrize('raw,event,data', FIXTURES, ids=[row[1] for row in FIXTURES])
def test_every_declared_kind_has_typed_projection_and_linked_dispatch(raw, event, data):
    source = envelope(raw, data)
    original = copy.deepcopy(source)
    result = decode_provider_event(source)
    assert result['event'] == event
    assert result['exclusions'] == []
    assert result['payload']['providerEvent'] == raw
    assert result['payload']['source'] == 'gows_provider_event'
    assert result['payload']['fromFullSync'] is False
    assert 'chatId' in result['payload']
    assert 'omit' not in json.dumps(result)
    assert source == original
    assert decode_engine_event(source) == result


def test_declared_catalog_matches_all_exercised_output_names():
    assert set(NORMALIZED_EVENT_TYPES) == {row[1] for row in FIXTURES}
    assert len(NORMALIZED_EVENT_TYPES) == len(set(NORMALIZED_EVENT_TYPES))


@pytest.mark.parametrize('raw,event,data', FIXTURES, ids=[row[1] for row in FIXTURES])
def test_unknown_fields_and_nested_auth_material_never_survive(raw, event, data):
    source = envelope(raw, data)
    source['payload']['data'].update(secret='AUTH-MATERIAL', QR='AUTH-MATERIAL',
        PasskeyRequest={'PublicKey': 'AUTH-MATERIAL'}, MediaKey='AUTH-MATERIAL',
        _data={'Message': 'AUTH-MATERIAL'}, Raw={'Attrs': {'token': 'AUTH-MATERIAL'}})
    result = decode_provider_event(source)
    assert 'AUTH-MATERIAL' not in json.dumps(result)


@pytest.mark.parametrize('raw', [
    'whatsmeow.QRChannelItem', 'events.QR', 'events.RotateADVSecret',
    'events.PairSuccess', 'events.PairError', 'events.PairPasskeyRequest',
    'events.PairPasskeyConfirmation', 'events.PairPasskeyError',
    'events.AppState', 'events.AppStateSyncComplete', 'events.AppStateSyncError',
    'events.HistorySync', 'events.Contact', 'events.OfflineSyncPreview',
    'events.OfflineSyncCompleted', 'events.MediaRetry', 'events.UnknownCallEvent',
    'events.CallTransport', 'events.CallRelayLatency', 'events.CallPreAccept',
    'events.UnknownFutureEvent',
])
def test_raw_auth_history_protocol_and_internal_events_remain_ignored(raw):
    assert decode_engine_event(envelope(raw, {'Code': 'AUTH-MATERIAL'})) is None


@pytest.mark.parametrize('raw,event,data', FIXTURES, ids=[row[1] for row in FIXTURES])
def test_fullsync_flag_is_preserved_for_delivery_suppression(raw, event, data):
    source = envelope(raw, data)
    source['payload']['data']['FromFullSync'] = True
    assert decode_provider_event(source)['payload']['fromFullSync'] is True
    source['payload']['data']['FromFullSync'] = 1
    with pytest.raises(ValueError, match='^Invalid GOWS provider event$'):
        decode_provider_event(source)


@pytest.mark.parametrize('raw,event,data', FIXTURES, ids=[row[1] for row in FIXTURES])
def test_known_kind_requires_object_and_matching_session(raw, event, data):
    source = envelope(raw, data)
    source['payload']['session'] = 'another-owner'
    with pytest.raises(ValueError, match='^Invalid GOWS provider event$'):
        decode_provider_event(source)
    source['payload']['session'] = 'synthetic'
    source['payload']['data'] = ['private synthetic data']
    with pytest.raises(ValueError, match='^Invalid GOWS provider event$'):
        decode_provider_event(source)


@pytest.mark.parametrize('field,value', [
    ('JID', 'display-name'), ('JID', '1@evil.example'), ('JID', '15550001111:99999@lid'),
    ('Timestamp', '2026-10-20'), ('Timestamp', '0001-01-01T00:00:00Z'),
    ('Timestamp', '2026-02-31T00:00:00Z'), ('Timestamp', True),
    ('Action', {}), ('Action', {'pinned': 1}), ('Action', {'pinned': 'false'}),
    ('Action', None), ('Action', []),
])
def test_missing_and_malformed_boolean_is_unknown_not_false(field, value):
    source = envelope('events.Pin', appstate({'pinned': True}))
    source['payload']['data'][field] = value
    with pytest.raises(ValueError, match='^Invalid GOWS provider event$'):
        decode_provider_event(source)


@pytest.mark.parametrize('direction,participant,expected', [
    (False, PN, 'false_'+GROUP+'_ABC_'+CHAT),
    (True, PN, 'true_'+GROUP+'_ABC_'+CHAT),
    (True, '', None), (False, None, None),
    (False, '15550001111:4@lid', 'false_'+GROUP+'_ABC_15550001111@lid'),
])
def test_group_star_requires_actual_participant_for_complete_key(direction, participant, expected):
    source = envelope('events.Star', appstate({'starred': False}, ChatJID=GROUP,
        IsFromMe=direction, SenderJID=participant, MessageID='ABC'))
    result = decode_provider_event(source)['payload']
    assert result.get('id') == expected
    assert result['rawMessageId'] == 'ABC'
    assert result['messageIdentity'] == ('complete' if expected else 'partial')


def test_label_message_never_guesses_direction_even_if_unknown_fields_offer_it():
    source = envelope('events.LabelAssociationMessage', appstate({'labeled': False},
        LabelID='12', MessageID='ABC', IsFromMe=False, SenderJID=PN))
    result = decode_provider_event(source)
    assert result['event'] == 'label.message.deleted'
    assert result['payload']['messageIdentity'] == 'partial'
    assert 'id' not in result['payload']
    assert 'fromMe' not in result['payload']


def test_undecryptable_has_observed_key_but_never_claims_readable_content():
    raw, _, data = next(row for row in FIXTURES if row[0] == 'events.UndecryptableMessage')
    result = decode_provider_event(envelope(raw, data))['payload']
    assert result['id'] == 'false_'+CHAT+'_ABC'
    assert result['contentAvailable'] is False
    data = copy.deepcopy(data)
    data['Info'].update(Chat=GROUP, IsGroup=False)
    with pytest.raises(ValueError):
        decode_provider_event(envelope(raw, data))


def test_bounded_channel_and_blocklist_lists_report_truncation_without_content():
    raw, _, data = next(row for row in FIXTURES if row[0] == 'events.NewsletterLiveUpdate')
    data = copy.deepcopy(data)
    data['Messages'] *= 101
    result = decode_provider_event(envelope(raw, data))['payload']
    assert result['messageCount'] == 101 and result['truncated']
    assert len(result['messages']) == 100
    assert 'body' not in json.dumps(result)
    result = decode_provider_event(envelope('events.Blocklist', {'Action': 'modify',
        'Changes': [{'JID': PN, 'Action': 'unblock'}]*101}))['payload']
    assert result['changeCount'] == 101 and result['truncated'] and result['requiresRefresh']


@pytest.mark.parametrize('raw,data', [
    ('events.Blocklist', {'Action': '', 'Changes': False}),
    ('events.PrivacySettings', {'NewSettings': {'ReadReceipts': 'AUTH-MATERIAL'}}),
    ('events.NewsletterMuteChange', {'id': PN, 'mute': 'on'}),
    ('events.NewsletterLiveUpdate', {'JID': CHANNEL, 'Time': STAMP, 'Messages': [{'MessageServerID': True}]}),
    ('events.NewsletterLiveUpdate', {'JID': CHANNEL, 'Time': STAMP, 'Messages': [{'MessageServerID': 1, 'Timestamp': True}]}),
    ('events.NotifyAccountReachoutTimelock', {'is_active': 'false'}),
    ('events.NotifyAccountReachoutTimelock', {'time_enforcement_ends': 'NaN'}),
    ('gows.MessageCapping', {'total_quota': -2, 'used_quota': 0}),
    ('gows.MessageCapping', {'total_quota': 2, 'used_quota': -1}),
    ('events.UserAbout', {'JID': PN, 'Timestamp': STAMP, 'Status': 'x'*4001}),
])
def test_type_and_size_limits_never_echo_rejected_data(raw, data):
    with pytest.raises(ValueError, match='^Invalid GOWS provider event$'):
        decode_provider_event(envelope(raw, data))


def test_go_omitted_false_is_supported_only_where_contract_explicitly_uses_omitempty():
    result = decode_provider_event(envelope('events.NotifyAccountReachoutTimelock', {}))
    assert result['payload']['active'] is False
    with pytest.raises(ValueError):
        decode_provider_event(envelope('events.Pin', appstate({})))


def test_read_marker_is_metadata_only_and_does_not_publish_message_range():
    result = decode_provider_event(envelope('events.MarkChatAsRead', appstate({
        'read': True, 'messageRange': {'messages': [{'key': {'ID': 'PRIVATE'}}]}})))
    assert result['payload']['read'] is True
    assert 'PRIVATE' not in json.dumps(result)
    assert result['exclusions'] == []


@pytest.mark.parametrize('kind', ['read-self', 'played-self'])
def test_self_receipt_batch_has_no_singular_ack_and_group_author_is_required(kind):
    data = {'Chat': GROUP, 'Sender': '15550009999:4@lid', 'IsFromMe': True,
            'MessageSender': PN, 'MessageIDs': ['ABC', 'DEF'], 'Timestamp': STAMP, 'Type': kind}
    result = decode_provider_event(envelope('events.Receipt', data))['payload']
    assert result['receiptType'] == kind and result['messageCount'] == 2
    assert 'id' not in result and 'ack' not in result
    assert [item['id'] for item in result['messages']] == [
        'false_'+GROUP+'_'+raw+'_'+CHAT for raw in ('ABC', 'DEF')]
    data['MessageSender'] = ''
    result = decode_provider_event(envelope('events.Receipt', data))['payload']
    assert all(item['messageIdentity'] == 'partial' and 'id' not in item for item in result['messages'])


@pytest.mark.parametrize('kind', ['', 'read', 'played', 'inactive', 'active', 'server-error', 'sender', 'retry', 'hist_sync', 'peer_msg'])
def test_public_or_internal_receipts_are_not_duplicated_as_self_receipts(kind):
    assert decode_provider_event(envelope('events.Receipt', {'Type': kind})) is None


@pytest.mark.parametrize('data', [
    {'JID': GROUP, 'Name': {'Name': 'already public'}},
    {'JID': GROUP, 'NewInviteLink': 'PRIVATE-INVITE'},
    {'JID': GROUP, 'Join': [PN]},
    {'JID': GROUP, 'MembershipApprovalMode': {'IsJoinApprovalRequired': True}},
    {'JID': GROUP, 'Announce': {'IsAnnounce': False}, 'Suspended': False, 'Unsuspended': False},
])
def test_public_group_updates_are_not_duplicated_in_metadata(data):
    assert decode_provider_event(envelope('events.GroupInfo', data)) is None


def test_group_metadata_never_exposes_invitation_and_keeps_delete_unlink_suspension():
    data = {'JID': GROUP, 'Timestamp': STAMP, 'Delete': {'Deleted': True, 'DeleteReason': 'deleted'},
            'Unlink': {'Type': 'sub_group', 'UnlinkReason': 'delete_parent', 'Group': {'JID': '120363000000001@g.us'}},
            'Unsuspended': True, 'NewInviteLink': 'PRIVATE-INVITE'}
    result = decode_provider_event(envelope('events.GroupInfo', data))['payload']
    assert result['changes']['suspended'] is False
    assert result['changes']['delete']['deleted'] is True
    assert result['changes']['unlink']['groupId'] == '120363000000001@g.us'
    assert 'PRIVATE-INVITE' not in json.dumps(result)
    data['Suspended'] = True
    with pytest.raises(ValueError):
        decode_provider_event(envelope('events.GroupInfo', data))


@pytest.mark.parametrize('extra,chat,group', [
    ({}, CHAT, False),
    ({'GroupJID': GROUP}, GROUP, True),
    ({'Data': {'Attrs': {'group-jid': GROUP}}}, GROUP, True),
    ({'GroupJID': GROUP, 'Data': {'Attrs': {'group-jid': GROUP}}}, GROUP, True),
    ({'GroupJID': GROUP, 'Data': {'Attrs': {'group-jid': '120363000000001@g.us'}}}, None, True),
    ({'Data': {'Attrs': {'type': 'group'}}}, None, True),
    ({'GroupJID': 'invalid'}, None, True),
    ({'Data': {'Attrs': {'group-jid': PN}}}, None, True),
])
def test_terminated_group_call_never_uses_caller_dm_as_group_scope(extra, chat, group):
    data = {'CallID': 'SYNTHETIC-CALL', 'From': PN, 'Timestamp': STAMP,
            'Reason': 'accepted_elsewhere', **extra}
    result = decode_provider_event(envelope('events.CallTerminate', data))['payload']
    assert result['chatId'] == chat and result['isGroup'] is group
    assert result['from'] == CHAT and result['callId'] == 'SYNTHETIC-CALL'
    if group:
        assert result['groupIdentity'] == ('complete' if chat else 'unknown')


@pytest.mark.parametrize('raw,event,data', FIXTURES, ids=[row[1] for row in FIXTURES])
def test_raw_event_reaches_authenticated_ingest_callback_schema_and_context(
    app_client, environment, monkeypatch, raw, event, data,
):
    import jsonschema
    from conftest import call, message, rpc, subscribe
    from test_event_catalog_pipeline import webhook

    app, client = app_client
    service = app.state.service
    def forbidden(*args, **kwargs):
        raise AssertionError('context retrieval must not call provider or send receipts')
    for method in ('request', 'send', 'messages', 'message', 'mark_seen', 'status'):
        monkeypatch.setattr(service.gateway, method, forbidden, raising=False)
    # One known source permits the star callback to hand off a readable message.
    # The undecryptable fixture intentionally has no readable archived source.
    if event == 'message.starred':
        service.store.ingest(message('false_'+CHAT+'_ABC', CHAT, text='Synthetic context'), historical=True)
    assert 'result' in subscribe(client, name='whatsapp.event',
        arguments={'all_chats': True, 'event_types': [event]})
    source = envelope(raw, data)
    source.update(id='raw-catalog-'+event, session='default', timestamp=int(time.time()*1000))
    source['payload']['session'] = 'default'
    source['payload']['data']['QR'] = 'AUTH-MATERIAL'
    first = webhook(client, environment[0], source)
    assert first.get('recorded') is True
    assert webhook(client, environment[0], source)['duplicate'] is True
    assert service.events.dispatch_one()
    callbacks = [json.loads(request[1]) for request in environment[1].requests
                 if json.loads(request[1]).get('type') != 'verification']
    assert len(callbacks) == 1
    callback = callbacks[0]
    assert callback['data']['event_type'] == event
    schema = next(item for item in rpc(client, 'events/list')['result']['events']
                  if item['name'] == 'whatsapp.event')['payloadSchema']
    jsonschema.validate(callback['data'], schema)
    detail = call(client, 'get_account_event', {'event_id': callback['data']['event_id']})['result']['structuredContent']['event']
    assert detail['id'] == callback['eventId'] and detail['event_type'] == event
    assert 'AUTH-MATERIAL' not in json.dumps(detail)
    if event == 'message.starred':
        source_read = call(client, 'get_message', {'message_id': callback['data']['message_id']})
        assert source_read['result']['structuredContent']['message']['body'] == 'Synthetic context'
    if callback['data']['chat_id']:
        context = call(client, 'read_conversation', {'chat_id': callback['data']['chat_id']})
        assert not context['result'].get('isError')
    assert service.store.state()['deliveries'] == {'accepted': 1}


@pytest.mark.parametrize('raw,event,data', FIXTURES, ids=[row[1] for row in FIXTURES])
def test_fullsync_raw_event_is_readable_but_never_delivered(app_client, raw, event, data):
    from conftest import subscribe
    app, client = app_client
    service = app.state.service
    assert 'result' in subscribe(client, name='whatsapp.event',
        arguments={'all_chats': True, 'event_types': [event]})
    source = envelope(raw, data)
    source.update(id='raw-fullsync-'+event, session='default', timestamp=int(time.time()*1000))
    source['payload']['session'] = 'default'
    source['payload']['data']['FromFullSync'] = True
    assert service.ingest(source)['recorded'] is True
    assert service.store.list_account_events()['events'][0]['event_type'] == event
    assert service.store.state()['deliveries'] == {}
    assert not service.events.dispatch_one()
    assert service.ingest(source)['duplicate'] is True
