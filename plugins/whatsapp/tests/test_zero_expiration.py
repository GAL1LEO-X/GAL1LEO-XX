"""Explicit zero message timers; synthetic group payloads and gateway only."""
import copy

import pytest

from sally_whatsapp import lifetime
from sally_whatsapp.linked_state_reads import project_live_read
from sally_whatsapp.operations import public_result
from sally_whatsapp.store import Store
from test_forwarding import action, alter_source, enabled, observed, posts


NOW = 1_802_880_000
GROUP = '15550003333@g.us'
SOURCE = f'true_{GROUP}_ZEROTIMER'
BODY = 'Synthetic ordinary group message with an explicit zero timer'
SETTINGS = {
    'ephemeralSettingTimestamp': 1_802_879_000,
    'ephemeralSharedSecret': 'synthetic-setting',
    'disappearingMode': {'initiator': 0},
}


def zero_message(context=None, *, field='Message'):
    payload = observed(SOURCE, GROUP, from_me=True, timestamp=NOW, text=BODY)
    payload['_data'][field] = {'extendedTextMessage': {
        'text': BODY, 'contextInfo': {'expiration': 0, **SETTINGS} if context is None else context}}
    return payload


def envelope(payload, suffix='initial'):
    return {'id': 'synthetic-zero-' + suffix, 'event': 'message.any', 'payload': payload}


@pytest.mark.parametrize('field', ['Message', 'RawMessage'])
@pytest.mark.parametrize('context', [
    {'expiration': 0},
    {'expiration': '0'},
    {'expiration': 0.0},
    {'expiration': 0, **SETTINGS},
    {'expiration': '0', **SETTINGS},
    {'expiration': 0, 'disappearingMode': {}},
    {'expiration': '0', 'ephemeral_setting_timestamp': '0'},
])
def test_group_zero_timer_survives_live_read_archive_restart_and_forward(environment, monkeypatch, field, context):
    monkeypatch.setattr(lifetime.time, 'time', lambda: NOW)
    service, gateway = enabled(environment)
    payload = zero_message(context, field=field)
    assert lifetime.metadata(payload) is None
    projected = project_live_read(service.store, 'chats_get_chat_message',
        {'path': {'chatId': GROUP, 'messageId': SOURCE}}, public_result(payload))
    assert projected['result']['body'] == BODY
    assert service.store.search()['messages'] == []  # A live read is not an archive import.
    service.store.ingest(envelope(payload))
    assert service.store.message(SOURCE)['body'] == BODY
    assert Store(service.settings.database).message(SOURCE)['body'] == BODY
    gateway.observation = copy.deepcopy(payload)
    assert service.operation(action(SOURCE), 'test-owner')['state'] == 'queued'
    assert service.process_action()
    assert service.store.send_status(action(SOURCE).idempotency_key)['state'] == 'submitted'
    assert len(posts(gateway)) == 1


@pytest.mark.parametrize('duration', [
    pytest.param(True, id='boolean-true'),
    pytest.param(False, id='boolean-false'),
    pytest.param(-1, id='negative'),
    pytest.param('invalid', id='invalid-string'),
    pytest.param('0.0', id='decimal-string'),
    pytest.param(0.5, id='fraction'),
    pytest.param(4294967296, id='uint32-overflow'),
    pytest.param(10**1000, id='huge-integer'),
    pytest.param(float('inf'), id='infinity'),
    pytest.param(float('nan'), id='not-a-number'),
])
def test_malformed_duration_cannot_claim_zero_or_forward(environment, monkeypatch, duration):
    monkeypatch.setattr(lifetime.time, 'time', lambda: NOW)
    service, gateway = enabled(environment)
    gateway.observation = zero_message({'expiration': duration, **SETTINGS})
    assert lifetime.metadata(gateway.observation) == {'kind': 'unknown'}
    assert 'body' not in public_result(gateway.observation)
    assert service.store.ingest(envelope(gateway.observation))['reason'] == 'message_lifetime_unavailable'
    assert service.store.message(SOURCE) is None
    with pytest.raises(ValueError):
        service.operation(action(SOURCE), 'test-owner')
    assert not posts(gateway)


@pytest.mark.parametrize('case,expected', [
    ('view-once-flag', {'kind': 'view_once'}),
    ('view-once-wrapper', {'kind': 'view_once'}),
    ('media-view-once', {'kind': 'view_once'}),
    ('ephemeral-flag', {'kind': 'unknown'}),
    ('ephemeral-wrapper', {'kind': 'unknown'}),
    ('invalid-flag', {'kind': 'unknown'}),
    ('other-context-hint', {'kind': 'unknown'}),
    ('other-context-positive', {'kind': 'ephemeral', 'expires_at': NOW + 60}),
    ('same-context-positive', {'kind': 'ephemeral', 'expires_at': NOW + 60}),
    ('same-context-invalid', {'kind': 'unknown'}),
    ('projected-positive', {'kind': 'ephemeral', 'expires_at': NOW + 60}),
])
def test_zero_never_clears_conflicting_lifetime_evidence(environment, monkeypatch, case, expected):
    monkeypatch.setattr(lifetime.time, 'time', lambda: NOW)
    service, gateway = enabled(environment)
    payload = zero_message()
    raw = payload['_data']
    if case == 'view-once-flag':
        raw['IsViewOnceV2'] = True
    elif case == 'view-once-wrapper':
        raw['RawMessage'] = {'viewOnceMessageV2': {'message': copy.deepcopy(raw['Message'])}}
    elif case == 'media-view-once':
        raw['RawMessage'] = {'imageMessage': {'viewOnce': True, 'contextInfo': {'expiration': 0}}}
    elif case == 'ephemeral-flag':
        raw['IsEphemeral'] = True
    elif case == 'ephemeral-wrapper':
        raw['RawMessage'] = {'ephemeralMessage': {'message': copy.deepcopy(raw['Message'])}}
    elif case == 'invalid-flag':
        raw['IsEphemeral'] = 'false'
    elif case == 'other-context-hint':
        raw['RawMessage'] = {'imageMessage': {'contextInfo': {'disappearingMode': {}}}}
    elif case == 'other-context-positive':
        raw['RawMessage'] = {'imageMessage': {'contextInfo': {'expiration': 60}}}
    elif case == 'same-context-positive':
        raw['Message']['extendedTextMessage']['contextInfo']['Expiration'] = 60
    elif case == 'same-context-invalid':
        raw['Message']['extendedTextMessage']['contextInfo']['Expiration'] = 'invalid'
    else:
        payload['content_expires_at'] = NOW + 60
    assert lifetime.metadata(payload) == expected
    gateway.observation = payload
    with pytest.raises(ValueError, match='lifetime|temporary'):
        service.operation(action(SOURCE), 'test-owner')
    assert not posts(gateway)
    service.store.ingest(envelope(payload))
    if expected['kind'] == 'ephemeral':
        assert service.store.message(SOURCE)['body'] == BODY
        monkeypatch.setattr(lifetime.time, 'time', lambda: NOW + 61)
    assert service.store.message(SOURCE) is None


@pytest.mark.parametrize('restriction', [
    {'kind': 'unknown'},
    {'kind': 'view_once'},
    {'kind': 'ephemeral', 'expires_at': NOW - 1},
])
def test_fixed_zero_parser_does_not_remove_previous_restrictions(environment, monkeypatch, restriction):
    monkeypatch.setattr(lifetime.time, 'time', lambda: NOW)
    service, gateway = enabled(environment)
    service.store.ingest(envelope(zero_message()))
    service.store.observe_message_lifetime(SOURCE, GROUP, restriction)
    assert service.store.message(SOURCE) is None
    store = Store(service.settings.database)
    assert store.ingest(envelope(zero_message(), 'replay'), historical=True)['reason'] == 'message_lifetime_unavailable'
    assert store.message(SOURCE) is None
    gateway.observation = zero_message()
    with pytest.raises(ValueError, match='removed|visibility'):
        service.operation(action(SOURCE), 'test-owner')
    assert not posts(gateway)


def test_zero_replay_does_not_remove_a_previously_observed_active_timer(environment, monkeypatch):
    monkeypatch.setattr(lifetime.time, 'time', lambda: NOW)
    service, _ = enabled(environment)
    service.store.ingest(envelope(zero_message({'expiration': 60})))
    assert service.store.message(SOURCE)['body'] == BODY
    service.store.ingest(envelope(zero_message(), 'zero-replay'), historical=True)
    store = Store(service.settings.database)
    assert store.message(SOURCE)['body'] == BODY
    monkeypatch.setattr(lifetime.time, 'time', lambda: NOW + 60)
    assert store.message(SOURCE) is None
    assert store.message_state(SOURCE)['state'] == 'expired'


def test_zero_timer_does_not_change_an_independent_quote_lifetime():
    payload = zero_message()
    payload['replyTo'] = {
        'id': 'SYNTHETIC_QUOTE',
        'body': 'Synthetic unavailable quoted message',
        '_data': {'extendedTextMessage': {
            'text': 'Synthetic unavailable quoted message',
            'contextInfo': {'expiration': 60}}},
    }
    projected = public_result(payload)
    assert projected['body'] == BODY
    assert projected['replyTo']['content_state'] == 'lifetime_unknown'
    assert 'body' not in projected['replyTo']


def test_zero_timer_does_not_bypass_observed_edit_guard(environment, monkeypatch):
    monkeypatch.setattr(lifetime.time, 'time', lambda: NOW)
    service, gateway = enabled(environment)
    gateway.observation = zero_message()
    alter_source(service, 'edit', source=SOURCE, chat=GROUP)
    with pytest.raises(ValueError, match='latest observed edit'):
        service.operation(action(SOURCE), 'test-owner')
    assert not posts(gateway)
