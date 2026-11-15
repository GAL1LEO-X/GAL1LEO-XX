"""Incoming GOWS private reactions carry the sender's target key perspective."""
import copy
import hashlib
import time

import pytest

from conftest import call, message

SELF = '99999@c.us'
PEER = '12345@c.us'


def incoming(*, original_outgoing=True, self_id=SELF, chat=PEER):
    return {'id': 'synthetic-perspective-reaction', 'event': 'message.reaction',
            'engine': 'GOWS', 'me': {'id': SELF, 'lid': '88888@lid'},
            'timestamp': int(time.time() * 1000),
            'payload': {'id': 'false_' + chat + '_REACTION', 'from': chat, 'to': None,
                        'fromMe': False, 'participant': None,
                        'reaction': {'messageId': str(not original_outgoing).lower() + '_' + self_id + '_SOURCE',
                                     'text': '❤️'}}}


@pytest.mark.parametrize('outgoing', [True, False])
@pytest.mark.parametrize('self_id', [SELF, '99999@s.whatsapp.net', '88888@lid'])
def test_incoming_private_reaction_normalizes_only_authenticated_self(app_client, outgoing, self_id):
    service, client = app_client[0].state.service, app_client[1]
    target = str(outgoing).lower() + '_' + PEER + '_SOURCE'
    decoys = [str(not outgoing).lower() + '_' + PEER + '_SOURCE',
              str(outgoing).lower() + '_54321@c.us_SOURCE']
    for identifier in [target, *decoys]:
        service.ingest(message(identifier, chat=identifier.split('_')[1],
                               from_me=identifier.startswith('true_'), text='Synthetic source'))
    envelope = incoming(original_outgoing=outgoing, self_id=self_id)
    original = copy.deepcopy(envelope)
    service.ingest(envelope)
    assert envelope == original
    event_id = 'change_' + hashlib.sha256(envelope['id'].encode()).hexdigest()
    event = service.store.account_event(event_id)
    assert event['message_id'] == target
    assert event['data']['reaction']['messageId'] == target
    assert service.ingest(envelope)['duplicate']
    for name, args, key in [('get_message', {'message_id': target}, 'message'),
                            ('read_conversation', {'chat_id': PEER}, 'messages'),
                            ('search_messages', {'query': 'Synthetic source'}, 'messages')]:
        result = call(client, name, args)['result']['structuredContent'][key]
        value = next(v for v in result if v['id'] == target) if isinstance(result, list) else result
        assert value['reaction_events'][0]['text'] == '❤️'
        assert value['reaction_events'][0]['from_me'] is False
    for identifier in decoys:
        assert 'reaction_events' not in service.store.message(identifier)
    service.ingest({'id': 'synthetic-revoke-perspective', 'event': 'message.revoked',
                    'payload': {'revokedMessageId': target}})
    assert service.store.message(target) is None
    assert 'reaction' not in service.store.account_event(event_id)['data']


@pytest.mark.parametrize('mutation', ['no_me', 'wrong_me', 'other_engine', 'no_engine',
    'outgoing_reaction', 'wrong_event_chat', 'group', 'self_chat', 'unknown_direction', 'participant'])
def test_unproved_context_never_rewrites_reaction_target(app_client, mutation):
    service = app_client[0].state.service
    target = 'true_' + PEER + '_SOURCE'
    service.ingest(message(target, chat=PEER, from_me=True))
    event = incoming()
    if mutation == 'no_me': event.pop('me')
    if mutation == 'wrong_me': event['me'] = {'id': '77777@c.us'}
    if mutation == 'other_engine': event['engine'] = 'NOWEB'
    if mutation == 'no_engine': event.pop('engine')
    if mutation == 'outgoing_reaction': event['payload']['fromMe'] = True
    if mutation == 'unknown_direction': event['payload']['fromMe'] = 0
    if mutation == 'wrong_event_chat': event['payload']['id'] = 'false_77777@c.us_REACTION'
    if mutation == 'group': event['payload']['from'] = '12345@g.us'
    if mutation == 'self_chat': event['payload']['from'] = SELF
    if mutation == 'participant': event['payload']['participant'] = '54321@c.us'
    service.ingest(event)
    assert 'reaction_events' not in service.store.message(target)


def test_corrected_provider_key_is_not_normalized_twice(app_client):
    service = app_client[0].state.service
    target = 'true_' + PEER + '_SOURCE'
    service.ingest(message(target, chat=PEER, from_me=True))
    event = incoming()
    event['payload']['reaction']['messageId'] = target
    service.ingest(event)
    assert service.store.message(target)['reaction_events'][0]['text'] == '❤️'
