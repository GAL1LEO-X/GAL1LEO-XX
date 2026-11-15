"""Synthetic metadata-target validation: no WhatsApp calls or archive imports."""
import copy
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from conftest import message
from test_linked_device_visibility import event
from sally_whatsapp import ab_sources, lifetime
from sally_whatsapp.store import Store

CHAT = '15550001111@c.us'
OTHER = '15550009999@c.us'
LID = '15550002222@lid'
GROUP = '15550003333@g.us'
PARTICIPANT = '15550004444@c.us'
PARTICIPANT_LID = '15550005555@lid'
SOURCE = f'false_{CHAT}_SOURCE'
NOW = 1800000000
PRIVATE = 'synthetic private content must stay transient'
FLAGS = {'IsViewOnce': False, 'IsViewOnceV2': False, 'IsViewOnceV2Extension': False, 'IsEphemeral': False}


def observed(identifier=SOURCE, chat=CHAT, *, from_me=False, participant=None):
    value = message(identifier, chat, from_me=from_me, timestamp=NOW-60, text=PRIVATE)['payload']
    if participant is not None:
        value['participant'] = participant
    return {**value, '_data': {**FLAGS, 'Message': {'conversation': PRIVATE}}}


def arguments(name='chats_pin_message', identifier=SOURCE, chat=CHAT, *, star=True):
    if name == 'messages_set_star':
        return {'body': {'chatId': chat, 'messageId': identifier, 'star': star}}
    return {'path': {'chatId': chat, 'messageId': identifier},
            'body': {'duration': 86400} if name == 'chats_pin_message' else {}}


class Gateway:
    def __init__(self):
        self.observation = observed()
        self.calls = []
        self.before = None

    def request(self, method, path, **kwargs):
        assert method == 'GET'
        self.calls.append((method, path, kwargs))
        if self.before:
            self.before()
        return copy.deepcopy(self.observation)


@pytest.fixture
def target_env(tmp_path, monkeypatch):
    monkeypatch.setattr(lifetime.time, 'time', lambda: NOW)
    return Store(tmp_path/'synthetic.sqlite'), Gateway(), SimpleNamespace(session='synthetic-session')


def verify(env, name='chats_pin_message', args=None):
    return ab_sources.verify_target(*env, name, args or arguments(name))


def revoke(store, identifier=SOURCE):
    store.ingest({'event': 'message.revoked', 'payload': {'revokedMessageId': identifier}})


def test_metadata_only_uses_exact_false():
    assert ab_sources.metadata_only('chats_unpin_message', {})
    assert ab_sources.metadata_only('messages_set_star', {'body': {'star': False}})
    for value in (None, 0, '', 'false', True):
        assert not ab_sources.metadata_only('messages_set_star', {'body': {'star': value}})
    assert not ab_sources.metadata_only('chats_pin_message', {})


@pytest.mark.parametrize('name', ['chats_pin_message', 'messages_set_star'])
def test_positive_one_live_read_empty_archive_no_private_content(target_env, name):
    store, gateway, settings = target_env
    result = verify(target_env, name)
    assert result == {'id': SOURCE, 'chat_id': CHAT, 'timestamp': NOW-60, 'from_me': False,
                      'participant': None, 'lifetime': None, 'metadata_only': False}
    assert gateway.calls == [('GET', '/api/synthetic-session/chats/'+quote(CHAT, safe='')+
        '/messages/'+quote(SOURCE, safe=''), {'params': {'downloadMedia': 'false'}, 'timeout': 15})]
    with store.db() as db:
        assert db.execute('SELECT COUNT(*) FROM messages').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM message_content').fetchone()[0] == 0
        assert PRIVATE not in '\n'.join(db.iterdump())


@pytest.mark.parametrize('from_me', [False, True])
@pytest.mark.parametrize('chat', [CHAT, LID, GROUP])
def test_full_identity_directions_namespaces_and_group_participant(target_env, from_me, chat):
    store, gateway, _ = target_env
    participant = PARTICIPANT_LID if chat == GROUP else None
    identifier = f'{str(from_me).lower()}_{chat}_SOURCE'+('_'+participant if participant else '')
    gateway.observation = observed(identifier, chat, from_me=from_me, participant=participant)
    result = verify(target_env, args=arguments(identifier=identifier, chat=chat))
    assert result['id'] == identifier and result['from_me'] is from_me
    assert result['participant'] == participant and len(gateway.calls) == 1


@pytest.mark.parametrize('identifier,chat', [
    ('SOURCE', CHAT), (f'false_{CHAT}_', CHAT), (f'false_{OTHER}_SOURCE', CHAT),
    (f'false_{GROUP}_SOURCE', GROUP), (f'true_{GROUP}_SOURCE', GROUP),
    (f'false_{GROUP}_SOURCE_{OTHER}_EXTRA', GROUP),
    (f'false_{CHAT}_SOURCE_{PARTICIPANT}', CHAT),
    (f'false_{CHAT}_SOURCE\n', CHAT), ('false_bad@invalid_SOURCE', CHAT),
])
def test_partial_or_wrong_chat_keys_never_read(target_env, identifier, chat):
    with pytest.raises(ValueError):
        verify(target_env, args=arguments(identifier=identifier, chat=chat))
    assert not target_env[1].calls


def test_only_verified_aliases_match(target_env):
    store, gateway, _ = target_env
    identifier = f'false_{LID}_SOURCE'
    with pytest.raises(ValueError, match='chat'):
        verify(target_env, args=arguments(identifier=identifier, chat=CHAT))
    assert not gateway.calls
    store.bind_chat_alias(LID, CHAT)
    result = verify(target_env, args=arguments(identifier=identifier, chat=CHAT))
    assert result['id'] == identifier and len(gateway.calls) == 1


def test_group_participant_alias_is_verified_without_rewriting_key(target_env):
    store, gateway, _ = target_env
    store.bind_chat_alias(PARTICIPANT_LID, PARTICIPANT)
    identifier = f'false_{GROUP}_SOURCE_{PARTICIPANT_LID}'
    gateway.observation = observed(f'false_{GROUP}_SOURCE_{PARTICIPANT}', GROUP, participant=PARTICIPANT)
    result = verify(target_env, args=arguments(identifier=identifier, chat=GROUP))
    assert result['participant'] == PARTICIPANT_LID


@pytest.mark.parametrize('change', [
    lambda value: value.update(id=f'false_{OTHER}_SOURCE', **{'from': OTHER}),
    lambda value: value.update(fromMe=True),
    lambda value: value.update(id=f'false_{CHAT}_OTHER'),
    lambda value: value.update(**{'from': OTHER}),
])
def test_wrong_provider_identity_cannot_attach_lifetime_evidence(target_env, change):
    store, gateway, _ = target_env
    change(gateway.observation)
    gateway.observation['_data']['IsViewOnce'] = True
    with pytest.raises(ValueError, match='identity'):
        verify(target_env)
    assert store.message_state(SOURCE)['state'] == 'unknown'
    assert len(gateway.calls) == 1


def test_wrong_group_sender_is_rejected(target_env):
    store, gateway, _ = target_env
    identifier = f'false_{GROUP}_SOURCE_{PARTICIPANT}'
    gateway.observation = observed(identifier, GROUP, participant=OTHER)
    # The shared full-identity guard now rejects this before lifetime evidence
    # or the operation-specific participant validation can run.
    with pytest.raises(ValueError, match='identity'):
        verify(target_env, args=arguments(identifier=identifier, chat=GROUP))


@pytest.mark.parametrize('kind', ['revoke', 'DeleteForMe', 'ClearChat', 'expired', 'view_once'])
def test_known_removal_precedes_live_read(target_env, kind):
    store, gateway, _ = target_env
    if kind == 'revoke':
        revoke(store)
    elif kind in ('expired', 'view_once'):
        evidence = {'kind': 'view_once'} if kind == 'view_once' else {'kind': 'ephemeral', 'expires_at': NOW-1}
        store.observe_message_lifetime(SOURCE, CHAT, evidence)
    else:
        store.ingest(event(kind, chat=CHAT, raw='SOURCE', refs=[('SOURCE', False)] if kind == 'ClearChat' else None))
    with pytest.raises(ValueError, match='removed|visibility'):
        verify(target_env)
    assert not gateway.calls


def test_removal_during_live_read_wins(target_env):
    store, gateway, _ = target_env
    gateway.before = lambda: revoke(store)
    with pytest.raises(ValueError, match='removed|visibility'):
        verify(target_env)
    assert len(gateway.calls) == 1


def test_alias_binding_during_read_exposes_existing_removal(target_env):
    store, gateway, _ = target_env
    revoke(store)
    identifier = f'false_{LID}_SOURCE'
    gateway.observation = observed(identifier, LID)
    gateway.before = lambda: store.bind_chat_alias(LID, CHAT)
    with pytest.raises(ValueError, match='removed|visibility'):
        verify(target_env, args=arguments(identifier=identifier, chat=LID))
    assert len(gateway.calls) == 1


@pytest.mark.parametrize('kind', ['once', 'unknown_ephemeral', 'expired', 'missing_raw', 'revoked_protocol'])
def test_unavailable_live_source_is_rejected_without_body_retention(target_env, kind):
    store, gateway, _ = target_env
    if kind == 'once':
        gateway.observation['_data']['IsViewOnce'] = True
    elif kind == 'unknown_ephemeral':
        gateway.observation['_data']['IsEphemeral'] = True
    elif kind == 'expired':
        gateway.observation['_data']['Message'] = {'extendedTextMessage': {
            'text': PRIVATE, 'contextInfo': {'expiration': 1}}}
    elif kind == 'missing_raw':
        gateway.observation.pop('_data')
    else:
        gateway.observation['_data']['Message'] = {'protocolMessage': {'type': 0}}
    with pytest.raises(ValueError, match='removed|temporary|lifetime') as error:
        verify(target_env)
    assert PRIVATE not in str(error.value)
    with store.db() as db:
        assert PRIVATE not in '\n'.join(db.iterdump())


def test_ephemeral_future_timer_is_allowed_and_still_checks_expiry_later(target_env):
    store, gateway, _ = target_env
    gateway.observation['_data']['IsEphemeral'] = True
    gateway.observation['_data']['Message'] = {'extendedTextMessage': {
        'text': PRIVATE, 'contextInfo': {'expiration': 3600}}}
    result = verify(target_env)
    assert result['lifetime'] == {'kind': 'ephemeral', 'expires_at': NOW-60+3600}
    assert len(gateway.calls) == 1
    store.observe_message_lifetime(SOURCE, CHAT, {'kind': 'ephemeral', 'expires_at': NOW-1})
    with pytest.raises(ValueError, match='removed|visibility'):
        verify(target_env)
    assert len(gateway.calls) == 1


def test_known_restriction_survives_later_metadata_missing(target_env):
    store, gateway, _ = target_env
    gateway.observation['_data']['IsViewOnce'] = True
    with pytest.raises(ValueError):
        verify(target_env)
    gateway.observation = observed()
    with pytest.raises(ValueError, match='removed|visibility'):
        verify(target_env)
    assert store.message_state(SOURCE)['state'] == 'view_once' and len(gateway.calls) == 1


@pytest.mark.parametrize('name', ['chats_unpin_message', 'messages_set_star'])
def test_metadata_removal_never_reads_body_or_blocks_on_tombstone(target_env, name, monkeypatch):
    store, gateway, _ = target_env
    revoke(store)
    store.observe_message_lifetime(SOURCE, CHAT, {'kind': 'view_once'})
    def no_body(*args, **kwargs):
        pytest.fail('Metadata removal attempted a source-content or lifetime read')
    monkeypatch.setattr(store, 'message', no_body)
    monkeypatch.setattr(store, '_message_state', no_body)
    result = verify(target_env, name, arguments(name, star=False))
    assert result['metadata_only'] is True and result['timestamp'] is None
    assert ab_sources.recheck_target(store, name, arguments(name, star=False), result) == result
    assert not gateway.calls


def test_live_failure_does_not_leak_private_provider_exception(target_env):
    def failure():
        raise TimeoutError(PRIVATE)
    target_env[1].before = failure
    with pytest.raises(ValueError, match='provider') as error:
        verify(target_env)
    assert PRIVATE not in str(error.value) and len(target_env[1].calls) == 1


@pytest.mark.parametrize('when,allowed', [(NOW-120, True), (NOW-30, False)])
def test_live_epoch_resolves_known_delete_boundary_without_import(target_env, when, allowed):
    store, gateway, _ = target_env
    store.ingest(event('DeleteChat', chat=CHAT, when=when))
    if allowed:
        metadata = verify(target_env)
        assert ab_sources.recheck_target(store, 'chats_pin_message', arguments(), metadata) == metadata
    else:
        with pytest.raises(ValueError, match='removed|visibility'):
            verify(target_env)
    assert len(gateway.calls) == 1


def test_recheck_removal_after_verification_uses_no_second_read(target_env):
    store, gateway, _ = target_env
    metadata = verify(target_env)
    revoke(store)
    with pytest.raises(ValueError, match='removed|visibility'):
        ab_sources.recheck_target(store, 'chats_pin_message', arguments(), metadata)
    assert len(gateway.calls) == 1


def test_recheck_alias_binding_exposes_existing_tombstone(target_env):
    store, gateway, _ = target_env
    identifier = f'false_{LID}_SOURCE'
    args = arguments(identifier=identifier, chat=LID)
    gateway.observation = observed(identifier, LID)
    metadata = verify(target_env, args=args)
    revoke(store)
    store.bind_chat_alias(LID, CHAT)
    with pytest.raises(ValueError, match='removed|visibility'):
        ab_sources.recheck_target(store, 'chats_pin_message', args, metadata)
    assert len(gateway.calls) == 1


def test_recheck_ephemeral_expiry_between_validation_and_dispatch(target_env, monkeypatch):
    store, gateway, _ = target_env
    gateway.observation['_data']['IsEphemeral'] = True
    gateway.observation['_data']['Message'] = {'extendedTextMessage': {
        'text': PRIVATE, 'contextInfo': {'expiration': 3600}}}
    metadata = verify(target_env)
    monkeypatch.setattr(lifetime.time, 'time', lambda: NOW+3600)
    with pytest.raises(ValueError, match='lifetime'):
        ab_sources.recheck_target(store, 'chats_pin_message', arguments(), metadata)
    assert len(gateway.calls) == 1


@pytest.mark.parametrize('change', [
    {'id': f'false_{OTHER}_SOURCE'}, {'chat_id': OTHER}, {'from_me': True},
    {'participant': PARTICIPANT}, {'metadata_only': True}, {'timestamp': None}, {'lifetime': PRIVATE},
])
def test_recheck_cannot_use_metadata_for_another_target(target_env, change):
    metadata = verify(target_env)
    with pytest.raises(ValueError):
        ab_sources.recheck_target(target_env[0], 'chats_pin_message', arguments(), {**metadata, **change})
    assert len(target_env[1].calls) == 1


@pytest.mark.parametrize('timestamp', [0, '0'])
def test_zero_web_revoke_timestamp_is_not_a_removal(target_env, timestamp):
    target_env[1].observation['_data']['SourceWebMsg'] = {'revokeMessageTimestamp': timestamp}
    assert verify(target_env)['id'] == SOURCE
