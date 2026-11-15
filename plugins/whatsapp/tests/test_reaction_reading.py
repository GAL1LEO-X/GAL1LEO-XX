"""User-reported missing 👍/❤️: acquired event versus ordinary message reads."""
import hashlib
import time

import pytest

from conftest import call, message


@pytest.mark.parametrize('outgoing', [False, True])
@pytest.mark.parametrize('chat', ['12345@c.us', '12345@g.us'])
@pytest.mark.parametrize('emoji', ['👍', '❤️'])
def test_reactions_are_read_with_incoming_and_outgoing_messages(app_client, outgoing, chat, emoji):
    app, client = app_client
    service = app.state.service
    identifier = str(outgoing).lower() + '_' + chat + '_ORIGINAL'
    if chat.endswith('@g.us'):
        identifier += '_67890@c.us'
    service.ingest(message(identifier, chat=chat, from_me=outgoing, text='Synthetic source'))
    now = int(time.time())
    envelope = {'id': 'synthetic-reaction-event', 'event': 'message.reaction', 'timestamp': now * 1000,
                'payload': {'id': 'false_' + chat + '_REACTION', 'from': chat,
                            'to': '99999@c.us', 'fromMe': False, 'timestamp': now,
                            'participant': '54321@lid' if chat.endswith('@g.us') else None,
                            'reaction': {'messageId': identifier, 'text': emoji}}}
    service.ingest(envelope)
    event_id = 'change_' + hashlib.sha256(envelope['id'].encode()).hexdigest()
    detail = call(client, 'get_account_event', {'event_id': event_id})['result']['structuredContent']['event']
    assert detail['data']['reaction']['text'] == emoji
    reads = [call(client, 'get_message', {'message_id': identifier})['result']['structuredContent']['message'],
             call(client, 'read_conversation', {'chat_id': chat})['result']['structuredContent']['messages'][0],
             call(client, 'search_messages', {'query': 'Synthetic source'})['result']['structuredContent']['messages'][0]]
    for value in reads:
        assert value['reaction_events'][0]['text'] == emoji
        assert value['reaction_events'][0]['event_id'] == event_id
        assert value['reaction_coverage']['complete'] is False
        assert value['reaction_coverage']['current_state'] == 'unknown'
    assert service.ingest(envelope)['duplicate']
    assert len(service.store.search()['messages'][0]['reaction_events']) == 1
    # Replacement and withdrawal remain dated observations, never two likes.
    for index, text in enumerate(['❤️', '']):
        service.ingest({**envelope, 'id': 'synthetic-reaction-next-' + str(index),
                        'timestamp': (now + index + 1) * 1000,
                        'payload': {**envelope['payload'], 'reaction': {'messageId': identifier, 'text': text}}})
    history = service.store.search()['messages'][0]['reaction_events']
    assert [row['text'] for row in history] == ['', '❤️', emoji]
    assert history[0]['removed'] is True
    # Revocation removes both the original and the visible derived content.
    service.ingest({'id': 'synthetic-revoke', 'event': 'message.revoked',
                    'payload': {'revokedMessageId': identifier}, 'timestamp': now * 1000})
    assert service.store.message(identifier) is None
    assert service.store.search()['messages'] == []
    assert 'reaction' not in service.store.account_event(event_id)['data']


def test_reaction_identity_never_crosses_chat_or_direction(app_client):
    service = app_client[0].state.service
    ids = ['true_12345@c.us_SAME', 'false_12345@c.us_SAME', 'true_54321@c.us_SAME']
    for identifier in ids:
        _, chat, _ = identifier.split('_')
        service.ingest(message(identifier, chat=chat, from_me=identifier.startswith('true_')))
    service.ingest({'id': 'synthetic-distinct-reaction', 'event': 'message.reaction',
                    'timestamp': int(time.time() * 1000),
                    'payload': {'id': 'false_12345@c.us_REACTION', 'from': '12345@c.us', 'fromMe': False,
                                'reaction': {'messageId': ids[0], 'text': '👍'}}})
    assert service.store.message(ids[0])['reaction_events'][0]['text'] == '👍'
    assert 'reaction_events' not in service.store.message(ids[1])
    assert 'reaction_events' not in service.store.message(ids[2])
