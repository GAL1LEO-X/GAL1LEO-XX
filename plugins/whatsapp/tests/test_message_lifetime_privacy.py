"""Temporary-message privacy at archive, live-read and file boundaries.

All payloads, bytes, clocks and event receivers are synthetic. No provider is
connected and no removed content is fetched to perform these regressions.
"""
import base64
import copy
from dataclasses import replace
import hashlib
import json
from urllib.parse import quote

import pytest

from conftest import message
from sally_whatsapp import lifetime
from sally_whatsapp.linked_state_reads import project_live_read
from sally_whatsapp.operations import public_result
from sally_whatsapp.server import Service
from sally_whatsapp.store import Store


NOW = 1_802_880_000
CHAT = '15550001111@c.us'
LID = '15550002222@lid'
MID = f'false_{CHAT}_TEMPORARY'
PRIVATE = 'SYNTHETIC TEMPORARY CONTENT NEVER REAPPEAR'
FLAGS = {'IsViewOnce': False, 'IsViewOnceV2': False,
         'IsViewOnceV2Extension': False, 'IsEphemeral': False}


@pytest.fixture
def clock(monkeypatch):
    value = [NOW]
    monkeypatch.setattr(lifetime.time, 'time', lambda: value[0])
    return value


def temporary(*, identifier=MID, chat=CHAT, flag=None, expiration=None, raw_flags=True, media=False):
    envelope = message(identifier, chat, timestamp=NOW, text=PRIVATE)
    content = {'extendedTextMessage': {'text': PRIVATE}}
    if expiration is not None:
        content['extendedTextMessage']['contextInfo'] = {'expiration': expiration}
    raw = {**FLAGS, 'Message': content} if raw_flags else {'Message': content}
    if flag:
        raw[flag] = True
    envelope['payload']['_data'] = raw
    if media:
        envelope['payload'].update(hasMedia=True, media={
            'url': 'http://127.0.0.1:8821/api/files/synthetic-private',
            'filename': 'synthetic-temporary.jpg', 'mimetype': 'image/jpeg'})
    return envelope


def service_for(environment):
    settings, receiver, gateway, _ = environment
    return Service(replace(settings, live_account_enabled=True), gateway=gateway, event_transport=receiver)


def subscribe(service):
    service.events.subscribe('test-owner', 'message.received', {'chat_ids': [CHAT]}, {
        'mode': 'webhook', 'url': 'https://receiver.example/callback',
        'secret': 'whsec_' + base64.b64encode(b'x' * 32).decode()})


@pytest.mark.parametrize('flag', ['IsViewOnce', 'IsViewOnceV2', 'IsViewOnceV2Extension'])
def test_view_once_content_is_not_retained_or_notified(environment, clock, flag):
    service = service_for(environment)
    subscribe(service)
    service.store.ingest(temporary(flag=flag, media=True))
    assert service.store.message(MID) is None
    assert service.store.search(query='TEMPORARY')['messages'] == []
    with service.store.db() as db:
        stored = '\n'.join(db.iterdump())
        assert PRIVATE not in stored
        assert 'synthetic-temporary.jpg' not in stored
        assert '/api/files/synthetic-private' not in stored
        assert db.execute("SELECT count(*) FROM deliveries WHERE state IN ('collecting','pending','sending')").fetchone()[0] == 0
    # A later history payload that lost internal metadata cannot resurrect it.
    replay = temporary(media=True)
    replay['id'] = 'synthetic-late-view-once-replay'
    replay['payload'].pop('_data')
    service.store.ingest(replay, historical=True)
    restarted = Store(service.settings.database)
    assert restarted.message(MID) is None
    assert restarted.search()['messages'] == []


@pytest.mark.parametrize('flag', [None, 'IsEphemeral'])
def test_ephemeral_remains_readable_until_expiry_then_stays_hidden_after_restart_replay(environment, clock, flag):
    service = service_for(environment)
    original = temporary(expiration=60, flag=flag, media=True)
    service.store.ingest(original)
    assert service.store.message(MID)['body'] == PRIVATE
    clock[0] = NOW + 59
    assert service.store.search()['messages'][0]['body'] == PRIVATE
    clock[0] = NOW + 60
    assert service.store.message(MID) is None
    assert service.store.search()['messages'] == []
    assert service.store.message_state(MID)['state'] != 'unknown'
    restarted = Store(service.settings.database)
    assert restarted.message(MID) is None
    replay = copy.deepcopy(original)
    replay['id'] = 'synthetic-expired-replay'
    replay['payload'].pop('_data')
    restarted.ingest(replay, historical=True)
    assert restarted.message(MID) is None
    assert restarted.search(query='TEMPORARY')['messages'] == []


def test_positive_ephemeral_without_verifiable_expiry_is_not_assumed_current(environment, clock):
    service = service_for(environment)
    service.store.ingest(temporary(flag='IsEphemeral'))
    assert service.store.message(MID) is None
    assert service.store.search()['messages'] == []


def test_normalized_future_expiry_cannot_override_new_view_once_evidence(environment, clock):
    service = service_for(environment)
    envelope = temporary(flag='IsViewOnce', media=True)
    envelope['payload']['content_expires_at'] = NOW + 86400
    assert lifetime.metadata(envelope['payload']) == {'kind': 'view_once'}
    service.store.ingest(envelope)
    assert service.store.message(MID) is None
    assert PRIVATE not in json.dumps(public_result(envelope['payload']))


def test_absent_lifetime_metadata_preserves_ordinary_legacy_messages(environment, clock):
    service = service_for(environment)
    ordinary = message(MID, CHAT, timestamp=NOW, text='Synthetic ordinary legacy message')
    service.store.ingest(ordinary)
    clock[0] += 365 * 86400
    assert service.store.message(MID)['body'] == ordinary['payload']['body']


@pytest.mark.parametrize('flag,expiration,advance', [
    ('IsViewOnce', None, 0), (None, 60, 60), ('IsEphemeral', None, 0),
])
def test_live_result_filters_lifetime_before_dropping_engine_data(environment, clock, flag, expiration, advance):
    service = service_for(environment)
    payload = temporary(flag=flag, expiration=expiration, media=True)['payload']
    clock[0] += advance
    public = public_result(payload)
    projected = project_live_read(service.store, 'chats_get_chat_message',
        {'path': {'chatId': CHAT, 'messageId': MID}}, public)
    encoded = json.dumps(projected)
    assert PRIVATE not in encoded and 'synthetic-temporary.jpg' not in encoded
    assert '_data' not in encoded and '/api/files/synthetic-private' not in encoded
    assert service.store.search()['messages'] == []  # Reading never imports history.


def test_temporary_quote_is_withheld_without_hiding_the_ordinary_parent(environment, clock):
    service = service_for(environment)
    parent = message(f'false_{CHAT}_PARENT', CHAT, timestamp=NOW,
                     text='Synthetic normal reply')['payload']
    parent['replyTo'] = temporary(flag='IsViewOnce', media=True)['payload']
    projected = project_live_read(service.store, 'chats_get_chat_messages',
        {'path': {'chatId': CHAT}}, [public_result(parent)])['result'][0]
    assert projected['body'] == 'Synthetic normal reply'
    assert PRIVATE not in json.dumps(projected)
    assert 'synthetic-temporary.jpg' not in json.dumps(projected)


@pytest.mark.parametrize('field,content', [
    ('Message', {'viewOnceMessage': {'message': {'imageMessage': {'caption': PRIVATE}}}}),
    ('Message', {'imageMessage': {'viewOnce': True, 'caption': PRIVATE}}),
    ('RawMessage', {'viewOnceMessageV2': {'message': {'imageMessage': {'caption': PRIVATE}}}}),
])
def test_view_once_wrappers_and_media_flags_survive_false_outer_flags(environment, clock, field, content):
    service = service_for(environment)
    envelope = temporary(media=True)
    envelope['payload']['_data'][field] = content
    service.store.ingest(envelope)
    assert service.store.message(MID) is None
    assert service.store.search()['messages'] == []
    assert PRIVATE not in json.dumps(public_result(envelope['payload']))


def test_normalized_quote_timer_expires_without_hiding_ordinary_parent(environment, clock):
    service = service_for(environment)
    parent = message(f'false_{CHAT}_PARENT', CHAT, timestamp=NOW, text='Synthetic normal reply')['payload']
    parent['replyTo'] = temporary(expiration=60)['payload']
    observed = public_result(parent)
    assert observed['replyTo']['body'] == PRIVATE
    assert observed['replyTo']['content_expires_at'] == NOW + 60
    clock[0] += 60
    projected = project_live_read(service.store, 'chats_get_chat_messages',
        {'path': {'chatId': CHAT}}, [observed])['result'][0]
    assert projected['body'] == 'Synthetic normal reply'
    assert PRIVATE not in json.dumps(projected)


@pytest.mark.parametrize('proto,state', [
    ({'imageMessage': {'viewOnce': True, 'caption': PRIVATE}}, 'view_once'),
    ({'extendedTextMessage': {'text': PRIVATE, 'contextInfo': {'expiration': 60}}}, 'lifetime_unknown'),
])
def test_gows_quote_raw_proto_without_original_time_never_uses_parent_time(environment, clock, proto, state):
    service = service_for(environment)
    parent = message(f'false_{CHAT}_PARENT', CHAT, timestamp=NOW, text='Synthetic normal reply')['payload']
    # extractReplyTo in the pinned adapter has a raw stanza ID, no timestamp,
    # and puts the quoted protobuf directly in _data (no Message wrapper).
    parent['replyTo'] = {'id': 'TEMPORARY', 'participant': CHAT, 'body': PRIVATE,
                         'hasMedia': True, 'media': None, '_data': proto}
    projected = project_live_read(service.store, 'chats_get_chat_messages',
        {'path': {'chatId': CHAT}}, [public_result(parent)])['result'][0]
    assert projected['body'] == 'Synthetic normal reply'
    assert projected['replyTo']['content_state'] == state
    assert PRIVATE not in json.dumps(projected)


def test_verified_alias_does_not_discard_expiry_evidence(environment, clock):
    service = service_for(environment)
    alias_mid = f'false_{LID}_TEMPORARY'
    service.store.ingest(temporary(identifier=alias_mid, chat=LID, expiration=60))
    service.store.bind_chat_alias(LID, CHAT)
    clock[0] += 61
    assert service.store.message(alias_mid) is None
    assert service.store.message_state(MID, chat_id=CHAT, timestamp=NOW)['state'] != 'unknown'
    assert service.store.search(chat_id=LID)['messages'] == []
    assert service.store.search(chat_id=CHAT)['messages'] == []


def test_cached_attachment_grant_stops_at_source_expiry(environment, clock):
    service = service_for(environment)
    gateway = environment[2]
    original = temporary(expiration=60, media=True)
    original['payload']['_data']['Message'] = {'imageMessage': {
        'caption': PRIVATE, 'contextInfo': {'expiration': 60},
        'mimetype': 'image/jpeg', 'fileName': 'synthetic-temporary.jpg',
        'fileLength': len(gateway.media_bytes),
        'fileSHA256': base64.b64encode(hashlib.sha256(gateway.media_bytes).digest()).decode(),
    }}
    requests = []
    path = f'/api/{service.settings.session}/chats/{quote(CHAT, safe="")}/messages/{quote(MID, safe="")}'
    def read_source(method, actual_path, **kwargs):
        assert method == 'GET' and actual_path == path
        requests.append(kwargs)
        return copy.deepcopy(original['payload'])
    gateway.request = read_source
    service.store.ingest(original)
    transfer = service.media.enqueue('test-owner', {
        'kind': 'gateway', 'message_id': MID, 'chat_id': CHAT, 'timestamp': NOW,
        'media': original['payload']['media']}, 'synthetic-temporary.jpg', 'image/jpeg')
    assert service.media.process_one()
    ready = service.media.status(transfer['id'], 'test-owner')
    assert ready['state'] == 'ready'
    grant = ready['download_url'].rsplit('/', 1)[-1]
    service.media.resolve(grant)
    clock[0] += 61
    assert service.store.message_state(MID)['state'] != 'unknown'
    before_expired_read = len(requests)
    with pytest.raises(ValueError):
        service.media.resolve(grant)
    with pytest.raises(ValueError, match='Transfer expired'):
        service.media.status(transfer['id'], 'test-owner')
    with service.store.db() as db:
        expired = db.execute('SELECT state,source,filename,sha256 FROM media_jobs WHERE id=?',
                             (transfer['id'],)).fetchone()
    assert tuple(expired) == ('cancelled', b'', '', None)
    assert len(requests) == before_expired_read


@pytest.mark.parametrize('already_attempted', [False, True])
def test_ephemeral_notification_is_not_dispatched_or_retried_after_expiry(environment, clock, already_attempted):
    service = service_for(environment)
    receiver = environment[1]
    subscribe(service)
    service.store.ingest(temporary(expiration=60))
    if already_attempted:
        receiver.responses = [(500, b'')]
        assert service.events.dispatch_one()
    requests_before_expiry = len(receiver.requests)
    clock[0] += 61
    service.events.dispatch_one()
    assert len(receiver.requests) == requests_before_expiry
    with service.store.db() as db:
        assert db.execute("SELECT count(*) FROM deliveries WHERE state IN ('pending','sending','collecting')").fetchone()[0] == 0


@pytest.mark.parametrize('flag,expiration', [('IsViewOnce', None), (None, 60)])
def test_existing_event_lifetime_evidence_repairs_retained_content_at_startup(environment, clock, flag, expiration):
    settings = environment[0]
    legacy = Store(settings.database, migrate_schema=False)
    source = temporary(flag=flag, expiration=expiration, media=True)
    ordinary_source = copy.deepcopy(source)
    ordinary_source['payload'].pop('_data')
    legacy.ingest(ordinary_source)
    parent_id = f'false_{CHAT}_PARENT'
    parent = message(parent_id, CHAT, timestamp=NOW, text='Synthetic ordinary parent')
    legacy.ingest(parent)
    quote_event = {**parent['payload'], 'replyTo': copy.deepcopy(source['payload'])}
    with legacy.db() as db:
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,?)', (
            'synthetic-legacy-source-event', 'message.edited', CHAT, NOW,
            json.dumps(source['payload']), MID))
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,?)', (
            'synthetic-legacy-quote-event', 'message.edited', CHAT, NOW,
            json.dumps(quote_event), parent_id))
    assert legacy.message(MID)['body'] == PRIVATE
    clock[0] += 61
    repaired = Store(settings.database)
    assert repaired.message(MID) is None
    assert repaired.message(parent_id)['body'] == 'Synthetic ordinary parent'
    assert repaired.search(query='TEMPORARY')['messages'] == []
    with repaired.db() as db:
        retained = '\n'.join(db.iterdump())
        assert PRIVATE not in retained
        assert 'synthetic-temporary.jpg' not in retained
        assert '/api/files/synthetic-private' not in retained


def test_binding_alias_purges_previous_view_once_content_without_cross_chat_or_direction_leak(environment, clock):
    service = service_for(environment)
    alias_id = f'false_{LID}_TEMPORARY'
    ordinary = temporary(identifier=alias_id, chat=LID, media=True)
    ordinary['payload'].pop('_data')
    service.store.ingest(ordinary)
    other_id = 'false_15550009999@c.us_TEMPORARY'
    own_id = f'true_{LID}_TEMPORARY'
    service.store.ingest(message(other_id, '15550009999@c.us', timestamp=NOW, text='Synthetic other chat'))
    service.store.ingest(message(own_id, LID, timestamp=NOW, text='Synthetic other direction', from_me=True))
    service.store.observe_message_lifetime(MID, CHAT, {'kind': 'view_once'})
    assert service.store.message(alias_id) is not None  # No guessed alias.
    service.store.bind_chat_alias(LID, CHAT)
    assert service.store.message(alias_id) is None
    assert service.store.message(other_id)['body'] == 'Synthetic other chat'
    assert service.store.message(own_id)['body'] == 'Synthetic other direction'
    with service.store.db() as db:
        retained = '\n'.join(db.iterdump())
        assert PRIVATE not in retained and 'synthetic-temporary.jpg' not in retained


def test_lifetime_startup_repair_resumes_after_interrupted_batch(environment, clock, monkeypatch):
    legacy = Store(environment[0].database, migrate_schema=False)
    with legacy.db() as db:
        for index in range(205):
            identifier = f'false_{CHAT}_TEMPORARY{index:03d}'
            payload = temporary(identifier=identifier, flag='IsViewOnce')['payload']
            db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,?)', (
                f'synthetic-legacy-{index:03d}', 'message.edited', CHAT, NOW,
                json.dumps(payload), identifier))
    original = Store._observe_payload_lifetimes
    observed = []

    def interrupt_second_batch(self, db, payload, identifier, chat_id, **kwargs):
        observed.append(identifier)
        if len(observed) == 101:
            raise RuntimeError('Synthetic startup interruption')
        return original(self, db, payload, identifier, chat_id, **kwargs)

    monkeypatch.setattr(Store, '_observe_payload_lifetimes', interrupt_second_batch)
    with pytest.raises(RuntimeError, match='Synthetic startup interruption'):
        Store(legacy.path)
    with legacy.db() as db:
        progress = json.loads(db.execute('SELECT value FROM state WHERE key=?',
            ('private:message_lifetime_repair:v1',)).fetchone()[0])
        assert progress == {'phase': 'events', 'after': 100}
        assert db.execute('SELECT count(*) FROM account_events WHERE data LIKE ?', ('%' + PRIVATE + '%',)).fetchone()[0] == 105
    monkeypatch.setattr(Store, '_observe_payload_lifetimes', original)
    restarted = Store(legacy.path)
    with restarted.db() as db:
        progress = json.loads(db.execute('SELECT value FROM state WHERE key=?',
            ('private:message_lifetime_repair:v1',)).fetchone()[0])
        assert progress['complete'] is True
        assert db.execute('SELECT count(*) FROM account_events').fetchone()[0] == 205
        assert PRIVATE not in '\n'.join(db.iterdump())
