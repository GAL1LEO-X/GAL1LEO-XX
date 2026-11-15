"""Synthetic fixtures from the pinned Go JSON types, without provider access."""
import copy
from datetime import datetime
import json

import pytest

from sally_whatsapp.linked_state import decode_engine_event


STAMP = '2026-10-16T08:00:00Z'
EPOCH = datetime.fromisoformat(STAMP).timestamp()
CHAT = '15550001111@s.whatsapp.net'


def envelope(kind='DeleteChat', *, chat=CHAT):
    data = {'JID': chat, 'Timestamp': STAMP, 'FromFullSync': False, 'DeleteMedia': False,
            'Action': {'messageRange': {'lastMessageTimestamp': int(EPOCH)-1, 'messages': [
                {'key': {'remoteJID': chat, 'fromMe': False, 'ID': 'ABC'},
                 'timestamp': int(EPOCH)-1}]}}}
    if kind == 'DeleteForMe':
        data = {'ChatJID': chat, 'SenderJID': '', 'IsFromMe': False, 'MessageID': 'ABC',
                'Timestamp': STAMP, 'Action': {'deleteMedia': False, 'messageTimestamp': int(EPOCH)-1},
                'FromFullSync': False}
    return {'event': 'engine.event', 'engine': 'GOWS', 'session': 'synthetic',
            'payload': {'session': 'synthetic', 'event': 'events.'+kind, 'data': data}}


def test_delete_chat_matches_provider_strict_cutoff_and_explicit_reference():
    result = decode_engine_event(envelope())
    assert result == {'event': 'chat.deleted', 'payload': {
        'chatId': '15550001111@c.us', 'reason': 'chat_deleted', 'eventAt': EPOCH,
        'fromFullSync': False, 'coverage': 'provider_chat_before', 'before': EPOCH,
        'excludedReferences': 1}, 'exclusions': [
            {'kind': 'chat', 'chat_id': '15550001111@c.us', 'before': EPOCH,
             'reason': 'chat_deleted', 'event_at': EPOCH},
            {'kind': 'message', 'chat_id': '15550001111@c.us', 'raw_id': 'ABC',
             'from_me': False, 'reason': 'chat_deleted', 'event_at': EPOCH}]}


def test_clear_chat_preserves_anchor_and_conflicting_range_as_uncertainty():
    source = envelope('ClearChat')
    source['payload']['data']['Action']['messageRange']['lastMessageTimestamp'] = int(EPOCH)+300
    result = decode_engine_event(source)
    assert result['event'] == 'chat.cleared'
    assert result['payload']['coverage'] == 'uncertain'
    assert result['payload']['clearCoverage']['boundaryUnknown'] is True
    assert len(result['exclusions']) == 1
    assert result['exclusions'][0]['reason'] == 'clear_chat_coverage_uncertain'
    assert result['exclusions'][0]['kind'] == 'clear'
    assert 'before' not in result['payload']


@pytest.mark.parametrize('action', [None, {}, {'messageRange': {}},
    {'messageRange': {'lastMessageTimestamp': int(EPOCH)}}])
def test_clear_chat_without_references_persists_uncertainty(action):
    source = envelope('ClearChat')
    source['payload']['data']['Action'] = action
    result = decode_engine_event(source)
    assert len(result['exclusions']) == 1
    assert result['exclusions'][0]['kind'] == 'clear'
    assert result['payload']['coverage'] == 'uncertain'


@pytest.mark.parametrize('kind', ['DeleteChat', 'ClearChat', 'DeleteForMe'])
def test_full_sync_replay_preserves_exclusions_and_source_is_not_mutated(kind):
    source = envelope(kind)
    source['payload']['data']['FromFullSync'] = True
    before = copy.deepcopy(source)
    result = decode_engine_event(source)
    assert result['payload']['fromFullSync'] is True
    assert result['exclusions']
    assert source == before
    assert decode_engine_event(source) == result


@pytest.mark.parametrize('chat', ['15550001111@lid', '120363000000000@g.us', '12345-67890@g.us'])
def test_delete_for_me_is_scoped_to_chat_raw_id_direction_without_inventing_sender(chat):
    source = envelope('DeleteForMe', chat=chat)
    source['payload']['data']['IsFromMe'] = True
    result = decode_engine_event(source)
    assert result['exclusions'] == [{'kind': 'message', 'chat_id': chat, 'raw_id': 'ABC',
        'from_me': True, 'reason': 'deleted_for_me', 'event_at': EPOCH}]
    assert result['payload']['fromMe'] is True


def test_range_deduplicates_tuple_and_normalizes_pn_without_guessing_aliases():
    source = envelope()
    refs = source['payload']['data']['Action']['messageRange']['messages']
    refs.append(copy.deepcopy(refs[0]))
    refs.append(copy.deepcopy(refs[0]))
    refs[-1]['key']['fromMe'] = True
    result = decode_engine_event(source)
    assert len(result['exclusions']) == 3
    assert result['payload']['excludedReferences'] == 2


def test_safe_projection_drops_source_body_unknown_fields_and_actions():
    source = envelope('DeleteForMe')
    source['payload']['data']['body'] = 'private synthetic body'
    source['payload']['data']['Action']['quotedMessage'] = {'body': 'private synthetic body'}
    result = decode_engine_event(source)
    encoded = json.dumps(result)
    assert 'private synthetic body' not in encoded
    assert 'Action' not in encoded
    assert '_data' not in encoded


@pytest.mark.parametrize('change', [
    {'engine': 'NOWEB'}, {'engine': None}, {'event': 'message'},
    {'payload': {'event': 'events.UnknownAppState', 'data': {'unexpected': True}}},
    {'payload': {'event': ['events.DeleteChat']}}, {'payload': None},
])
def test_unknown_engine_or_event_is_ignored(change):
    assert decode_engine_event({**envelope(), **change}) is None


@pytest.mark.parametrize('field,value', [
    ('JID', 'display-name'), ('JID', '1555@evil.example'), ('JID', '../@c.us'),
    ('JID', '1'*201+'@lid'), ('Timestamp', '2026-10-16'),
    ('Timestamp', '2026-10-16T08:00:00'), ('Timestamp', 'invalid'),
    ('Timestamp', '2026-02-31T08:00:00Z'), ('Timestamp', True),
    ('FromFullSync', 1), ('DeleteMedia', 'false'), ('Action', []),
])
def test_malformed_known_event_is_rejected_without_reflecting_source(field, value):
    source = envelope()
    source['payload']['data'][field] = value
    with pytest.raises(ValueError, match='^Invalid GOWS linked-state event$'):
        decode_engine_event(source)


@pytest.mark.parametrize('value', [None, [], {'messages': 'bad'}, {'messages': [{}]},
    {'messages': [{'key': {'ID': 'ABC', 'fromMe': 'false'}}]},
    {'messages': [{'key': {'ID': 'ABC'}}]},
    {'messages': [{'key': {'ID': 'ABC', 'fromMe': False, 'remoteJID': '15550002222@c.us'}}]},
    {'lastMessageTimestamp': True}, {'lastMessageTimestamp': float('inf')},
    {'messages': [{}]*1001},
])
def test_bad_ranges_are_rejected(value):
    # Null range is allowed by protobuf; distinguish it from malformed values.
    source = envelope('ClearChat')
    if value is None:
        source['payload']['data'] = None
    else:
        source['payload']['data']['Action']['messageRange'] = value
    with pytest.raises(ValueError):
        decode_engine_event(source)


@pytest.mark.parametrize('field,value', [
    ('IsFromMe', None), ('IsFromMe', 0), ('MessageID', 'A'*201), ('MessageID', ''),
    ('MessageID', 'private body\n'), ('SenderJID', 'invalid'),
    ('SenderJID', []), ('SenderJID', None),
    ('Action', {'messageTimestamp': True}), ('Action', {'deleteMedia': 0}),
])
def test_bad_delete_for_me_rejected(field, value):
    source = envelope('DeleteForMe')
    source['payload']['data'][field] = value
    with pytest.raises(ValueError):
        decode_engine_event(source)


def test_cross_session_envelope_rejected_and_missing_optional_inner_session_allowed():
    source = envelope()
    source['payload']['session'] = 'other-user'
    with pytest.raises(ValueError):
        decode_engine_event(source)
    del source['payload']['session']
    assert decode_engine_event(source)['event'] == 'chat.deleted'


def test_offset_timestamp_and_nanosecond_precision_are_valid():
    source = envelope()
    source['payload']['data']['Timestamp'] = '2026-10-16T10:00:00.123456789+02:00'
    assert decode_engine_event(source)['payload']['eventAt'] == pytest.approx(EPOCH+0.123456)
