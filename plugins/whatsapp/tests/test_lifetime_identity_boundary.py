"""ST-01: contradictory observations cannot persist restrictions on another key."""
import hashlib
import json
import time
from types import SimpleNamespace

import pytest

from sally_whatsapp import forwarding, lifetime
from sally_whatsapp.linked_state_reads import project_live_read
from sally_whatsapp.live_attachments import read_source
from sally_whatsapp.store import Store
from test_verified_message_identity import subscribe


GROUP = '15550001111-111@g.us'
OTHER_GROUP = '15550009999-999@g.us'
AUTHOR = '15550002222@c.us'
OTHER = '15550003333@c.us'
ALIAS = '15550004444@lid'
SOURCE = f'false_{GROUP}_SYNTHETIC_{AUTHOR}'
BODY = 'Synthetic retained content'


@pytest.fixture
def acquired(tmp_path):
    store = Store(tmp_path / 'synthetic.sqlite')
    subscribe(store)
    original = {'id': SOURCE, 'from': GROUP, 'to': '15550005555@c.us', 'fromMe': False,
                'participant': AUTHOR, 'timestamp': int(time.time()), 'body': BODY,
                'media': {'filename': 'retained.txt', 'mimetype': 'text/plain'},
                'vCards': ['BEGIN:VCARD\nFN:Synthetic\nEND:VCARD']}
    store.ingest({'event': 'message.any', 'id': 'original', 'payload': original})
    with store.db() as db:
        db.execute("INSERT INTO message_mutations VALUES(?,'edited',?,?)", (SOURCE, BODY, time.time()))
        db.execute('INSERT INTO media_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)', (
            'synthetic-job', 'owner', 'synthetic-identity', 'ready', b'synthetic-encrypted-source',
            'retained.txt', 'text/plain', 5, '0' * 64, time.time(), time.time() + 3600, None, SOURCE))
    return store, original


def snapshot(store):
    with store.db() as db:
        return [
            [tuple(row) for row in db.execute('SELECT * FROM messages WHERE id=?', (SOURCE,))],
            [tuple(row) for row in db.execute('SELECT * FROM message_content WHERE message_id=?', (SOURCE,))],
            [tuple(row) for row in db.execute('SELECT * FROM message_search WHERE id=?', (SOURCE,))],
            [tuple(row) for row in db.execute('SELECT * FROM message_mutations WHERE message_id=?', (SOURCE,))],
            [tuple(row) for row in db.execute('SELECT * FROM media_jobs WHERE source_message_id=?', (SOURCE,))],
            [tuple(row) for row in db.execute('SELECT * FROM deliveries WHERE event_id=?',
                ('evt_' + hashlib.sha256(SOURCE.encode()).hexdigest(),))],
            [tuple(row) for row in db.execute("SELECT key,value FROM state WHERE json_extract(value,'$.kind')='lifetime'")],
        ]


def restriction(kind):
    if kind == 'view_once':
        return {'_data': {'IsViewOnce': True}}
    if kind == 'future':
        return {'content_expires_at': int(time.time()) + 3600}
    return {'content_state': 'lifetime_unknown'}


def contradict(original, field):
    value = {**original}
    if field == 'chat':
        value['from'] = OTHER_GROUP
    elif field == 'direction':
        value['fromMe'] = True
        value['to'] = GROUP
    else:
        value['participant'] = OTHER
    return value


@pytest.mark.parametrize('surface', ['observer', 'message', 'edit', 'live'])
@pytest.mark.parametrize('field', ['chat', 'direction', 'participant'])
@pytest.mark.parametrize('kind', ['view_once', 'future', 'unknown'])
def test_contradictory_lifetime_preserves_source_and_all_derivatives(acquired, surface, field, kind):
    store, original = acquired
    before = snapshot(store)
    value = {**contradict(original, field), **restriction(kind)}
    if surface == 'observer':
        assert store.observe_message_lifetime(SOURCE, value['from'], lifetime.metadata(value),
            from_me=value['fromMe'], participant=value['participant']) is False
    elif surface in ('message', 'edit'):
        event = 'message.edited' if surface == 'edit' else 'message.any'
        value = {**value, **({'editedMessageId': SOURCE} if surface == 'edit' else {})}
        result = store.ingest({'event': event, 'id': 'contradictory', 'payload': value})
        assert result['recorded'] is False
        assert result['reason'] == ('ambiguous_edit_identity' if surface == 'edit' else 'ambiguous_message_identity')
    else:
        result = project_live_read(store, 'chats_get_chat_message',
            {'path': {'chatId': GROUP, 'messageId': SOURCE}}, value)
        assert result['result'] == {'id': SOURCE, 'content_state': 'unverified_reference'}
    assert snapshot(store) == before
    assert store.message_state(SOURCE)['state'] == 'unknown'
    assert store.message(SOURCE)['body'] == BODY
    assert Store(store.path).message(SOURCE)['body'] == BODY


@pytest.mark.parametrize('live', [False, True])
@pytest.mark.parametrize('invalid_parent', [False, True])
def test_invalid_quote_subtree_cannot_restrict_valid_descendant(acquired, live, invalid_parent):
    store, original = acquired
    before = snapshot(store)
    quote = {**original, **restriction('view_once')}
    invalid = {**contradict(original, 'participant'), 'replyTo': quote}
    parent = invalid if invalid_parent else {
        'id': f'false_{GROUP}_PARENT_{AUTHOR}', 'from': GROUP, 'fromMe': False,
        'participant': AUTHOR, 'timestamp': int(time.time()), 'body': 'Ordinary parent', 'replyTo': invalid}
    if live:
        result = project_live_read(store, 'chats_get_chat_messages', {'path': {'chatId': GROUP}}, [parent])
        projected = result['result'][0] if invalid_parent else result['result'][0]['replyTo']
        assert projected == {'id': SOURCE, 'content_state': 'unverified_reference'}
    else:
        store.ingest({'event': 'message.any', 'id': 'parent-observation', 'payload': parent})
    assert snapshot(store) == before


@pytest.mark.parametrize('surface', ['observer', 'edit', 'live', 'quote'])
@pytest.mark.parametrize('participant', [AUTHOR, ALIAS])
def test_attributable_lifetime_still_redacts_source_and_derivatives(acquired, surface, participant):
    store, original = acquired
    store.bind_chat_alias(ALIAS, AUTHOR)
    value = {**original, 'participant': participant, **restriction('view_once')}
    if surface == 'observer':
        store.observe_message_lifetime(SOURCE, GROUP, lifetime.metadata(value),
            from_me=False, participant=participant)
    elif surface == 'edit':
        store.ingest({'event': 'message.edited', 'id': 'valid-edit',
            'payload': {**value, 'editedMessageId': SOURCE}})
    else:
        supplied = value if surface == 'live' else {
            'id': f'false_{GROUP}_PARENT_{AUTHOR}', 'from': GROUP, 'fromMe': False,
            'participant': AUTHOR, 'timestamp': int(time.time()), 'body': 'Ordinary parent', 'replyTo': value}
        project_live_read(store, 'chats_get_chat_message', {'path': {'chatId': GROUP}}, supplied)
    assert store.message_state(SOURCE)['state'] == 'view_once'
    assert Store(store.path).message(SOURCE) is None
    with store.db() as db:
        assert db.execute('SELECT body,media FROM messages WHERE id=?', (SOURCE,)).fetchone()[:] == ('', None)
        assert not db.execute('SELECT 1 FROM message_content WHERE message_id=?', (SOURCE,)).fetchone()
        assert not db.execute('SELECT 1 FROM message_search WHERE id=?', (SOURCE,)).fetchone()
        assert db.execute('SELECT body FROM message_mutations WHERE message_id=?', (SOURCE,)).fetchone()[0] is None
        assert db.execute('SELECT state,source FROM media_jobs').fetchone()[:] == ('cancelled', b'')
        delivery = db.execute('SELECT state,body FROM deliveries').fetchone()
        assert delivery['state'] == 'cancelled'
        assert json.loads(delivery['body'])['data']['preview'] == ''


@pytest.mark.parametrize('consumer', ['forward', 'attachment'])
@pytest.mark.parametrize('participant', [OTHER, AUTHOR, ALIAS])
def test_source_preflight_validates_participant_before_retaining_lifetime(acquired, consumer, participant):
    store, original = acquired
    store.bind_chat_alias(ALIAS, AUTHOR)
    before = snapshot(store)
    observation = {**original, 'participant': participant, '_data': {
        'IsViewOnce': True, 'IsViewOnceV2': False, 'IsViewOnceV2Extension': False,
        'IsEphemeral': False, 'Message': {'conversation': BODY}}}
    expected = 'identity' if participant == OTHER else 'temporary|view-once'
    with pytest.raises(ValueError, match=expected):
        if consumer == 'forward':
            forwarding.require_source(store, SOURCE, observation)
        else:
            gateway = SimpleNamespace(request=lambda *args, **kwargs: observation)
            read_source(store, SimpleNamespace(session='default'), gateway, SOURCE)
    if participant == OTHER:
        assert snapshot(store) == before
        assert store.message(SOURCE)['body'] == BODY
    else:
        assert store.message_state(SOURCE)['state'] == 'view_once'
        assert store.message(SOURCE) is None
