"""Synthetic action payload lifecycle, metadata compatibility and no resend."""
from dataclasses import replace
import hashlib
import json
import sqlite3
import time

import pytest

from conftest import attachment_payload, install_attachment_readback, message
from sally_whatsapp import job_metadata
from sally_whatsapp.operations import validate_operation
from sally_whatsapp.server import OperationAction, Service
from sally_whatsapp.store import JOB_METADATA_REPAIR_KEY, SCHEMA_7, Store, canonical


CHAT = '393331112222@c.us'
OTHER = '393339999999@c.us'
LID = '555001@lid'
SOURCE = f'false_{CHAT}_SOURCE'
PROVIDER = f'true_{CHAT}_PRODUCED'
TEXT = 'Synthetic private action text'
KEY = 'synthetic-metadata-action'


def arguments(**body):
    return validate_operation('messages_send_text', {'body': {'chatId': CHAT, 'text': TEXT, **body}}, readonly=False)[1]


def revoke(store, identifier=PROVIDER, *, chat=None):
    payload = {'revokedMessageId': identifier}
    if chat:
        payload.update({'from': chat, 'fromMe': False})
    envelope = {'id': 'revoke-' + identifier, 'event': 'message.revoked', 'payload': payload}
    store.ingest(envelope)
    return envelope


def receipt(store, provider, chat, *, group=False, from_me=True):
    store.ingest({'id': 'receipt-' + provider, 'event': 'message.ack.group' if group else 'message.ack',
                  'payload': {'id': provider, 'from': 'self@c.us' if from_me else chat,
                              'to': chat, 'fromMe': from_me, 'ack': 2, 'ackName': 'DEVICE'}})


def persisted(store, key=KEY):
    with store.db() as db:
        return dict(db.execute('SELECT s.*,j.arguments FROM sends s JOIN action_jobs j USING(key) WHERE key=?', (key,)).fetchone())


def enabled(environment):
    settings, receiver, gateway, _ = environment
    settings = replace(settings, live_account_enabled=True, send_enabled=True, send_chat_ids=[CHAT, OTHER])
    service = Service(settings, gateway=gateway, event_transport=receiver)
    gateway.requests = []
    def request(*args, **kwargs):
        gateway.requests.append((args, kwargs))
        return {'id': PROVIDER}
    gateway.request = request
    return service, gateway


@pytest.mark.parametrize(('args', 'chat', 'group', 'from_me', 'expected'), [
    (arguments(id='caller-id'), CHAT, False, True, 'caller_supplied_message_id'),
    (arguments(), OTHER, False, True, 'receipt_destination_conflict'),
    (arguments(chatId='393330000000@g.us'), '393330000000@g.us', True, False, 'observed'),
    ({'body': {}, 'path': {'chatId': CHAT}}, OTHER, False, True, 'receipt_destination_conflict'),
    ({'body': {'chatId': CHAT}, 'path': {'chatId': OTHER}}, CHAT, False, True, 'observed'),
])
def test_delivery_metadata_survives_disposal_of_execution_payload(tmp_path, args, chat, group, from_me, expected):
    store = Store(tmp_path/'archive.sqlite')
    provider = 'opaque-provider-id'
    store.queue_action(KEY, 'owner', 'messages_send_text', args)
    store.finish_send(KEY, 'submitted', provider)
    receipt(store, provider, chat, group=group, from_me=from_me)
    before = store.send_status(KEY)['delivery']
    assert before.get('reason', before['status']) == expected
    with store.db() as db:
        db.execute("UPDATE action_jobs SET arguments='{}' WHERE key=?", (KEY,))
        db.execute("UPDATE action_job_metadata SET payload_state='redacted' WHERE key=?", (KEY,))
    assert store.send_status(KEY)['delivery'] == before


@pytest.mark.parametrize('state', ['submitted', 'uncertain'])
def test_revoke_redacts_payload_without_erasing_hash_state_or_caller_metadata(tmp_path, state):
    store = Store(tmp_path/'archive.sqlite')
    args = arguments(id='caller-id')
    store.queue_action(KEY, 'owner', 'messages_send_text', args)
    store.finish_send(KEY, state, PROVIDER, result={'id': PROVIDER, 'body': TEXT})
    before = persisted(store)
    envelope = revoke(store)
    assert store.ingest(envelope) == {'duplicate': True}
    reopened = Store(store.path, recover_inflight=True)
    after = persisted(reopened)
    assert after['arguments'] == '{}'
    assert after['state'] == state and after['payload_hash'] == before['payload_hash']
    assert reopened.queue_action(KEY, 'owner', 'messages_send_text', args)['state'] == state
    assert reopened.send_status(KEY)['delivery']['reason'] == 'message_revoked'
    assert TEXT not in canonical(reopened.send_status(KEY))
    with reopened.db() as db:
        metadata = job_metadata.delivery_metadata(db, KEY)
        assert metadata['caller_id_state'] == 'present' and metadata['caller_message_id'] == 'caller-id'
        assert metadata['destination_chat_id'] == CHAT and metadata['payload_state'] == 'redacted'
    with pytest.raises(ValueError, match='another payload'):
        reopened.queue_action(KEY, 'owner', 'messages_send_text', arguments(text='Different'))
    with pytest.raises(ValueError, match='another payload'):
        reopened.queue_action(KEY, 'different-owner', 'messages_send_text', args)


def test_revoke_while_mock_gateway_request_is_in_flight_wins_after_finish(environment):
    service, gateway = enabled(environment)
    args = OperationAction(operation='messages_send_text', arguments=arguments(), idempotency_key=KEY)
    service.operation(args, 'test-owner')
    before = persisted(service.store)
    def request(*a, **kw):
        gateway.requests.append((a, kw))
        assert persisted(service.store)['state'] == 'sending'
        revoke(service.store)
        return {'id': PROVIDER, 'body': TEXT}
    gateway.request = request
    assert service.process_action()
    after = persisted(service.store)
    assert after['state'] == 'submitted' and after['arguments'] == '{}'
    assert after['payload_hash'] == before['payload_hash']
    restored = Service(service.settings, gateway=gateway, event_transport=environment[1])
    assert restored.operation(args, 'test-owner')['state'] == 'submitted'
    assert not restored.process_action() and len(gateway.requests) == 1


@pytest.mark.parametrize(('operation', 'body', 'redacted'), [
    ('messages_forward_message', {'chatId': OTHER, 'messageId': SOURCE}, True),
    ('messages_send_text', {'chatId': CHAT, 'text': TEXT, 'reply_to': SOURCE}, False),
])
def test_queued_revoked_dependency_never_reaches_gateway(environment, operation, body, redacted):
    service, gateway = enabled(environment)
    service.store.ingest(message(SOURCE, CHAT))
    args = OperationAction(operation=operation, arguments={'body': body}, idempotency_key=KEY)
    if operation == 'messages_forward_message':
        # Retained historical rows also require source redaction independently
        # of the live identity preflight performed for newly queued forwards.
        service.store.queue_action(KEY, 'test-owner', operation, {'body': body})
    else:
        service.operation(args, 'test-owner')
    before = persisted(service.store)
    revoke(service.store, SOURCE)
    assert (persisted(service.store)['arguments'] == '{}') is redacted
    if not redacted:
        assert TEXT in persisted(service.store)['arguments']  # Independently authored reply text.
    assert service.process_action()
    assert service.store.send_status(KEY)['state'] == 'failed_before_send'
    assert persisted(service.store)['payload_hash'] == before['payload_hash']
    assert not gateway.requests
    if operation == 'messages_forward_message':
        assert service.store.queue_action(KEY, 'test-owner', operation, {'body': body})['state'] == 'failed_before_send'
    else:
        assert service.operation(args, 'test-owner')['state'] == 'failed_before_send'
    assert not service.process_action()


def test_dependency_revoked_during_preparation_is_checked_before_http(environment, monkeypatch):
    from sally_whatsapp import server
    service, gateway = enabled(environment)
    service.store.ingest(message(SOURCE, CHAT))
    args = OperationAction(operation='messages_send_text', arguments=arguments(reply_to=SOURCE), idempotency_key=KEY)
    service.operation(args, 'test-owner')
    require = server.require_action
    def during_preparation(*a, **kw):
        require(*a, **kw)
        revoke(service.store, SOURCE)
    monkeypatch.setattr(server, 'require_action', during_preparation)
    assert service.process_action()
    assert service.store.send_status(KEY)['state'] == 'failed_before_send'
    assert not gateway.requests


def test_local_deletion_withholds_queued_source_without_destroying_payload(environment):
    from test_linked_device_visibility import event
    service, gateway = enabled(environment)
    service.store.ingest(message(SOURCE, CHAT))
    args = OperationAction(operation='messages_send_text',
                           arguments=arguments(reply_to=SOURCE), idempotency_key=KEY)
    service.operation(args, 'test-owner')
    service.store.ingest(event('DeleteForMe', chat=CHAT, raw='SOURCE'))
    assert service.process_action()
    assert service.store.send_status(KEY)['state'] == 'failed_before_send'
    assert persisted(service.store)['arguments'] != '{}'
    assert not gateway.requests


def test_revoked_media_source_redacts_queued_payload_and_preserves_transfer_identity(environment):
    service, gateway = enabled(environment)
    source = message(SOURCE, CHAT)
    source['payload']=attachment_payload(SOURCE,CHAT,gateway.media_bytes,
        name='synthetic.pdf',mimetype='application/pdf')
    install_attachment_readback(gateway,source['payload'])
    service.store.ingest(source)
    transfer = service.media.enqueue('test-owner', {'kind': 'gateway', 'message_id': SOURCE,
                                     'chat_id': CHAT, 'media': source['payload']['media']},
                                     'synthetic.pdf', 'application/pdf')['id']
    assert service.media.process_one()
    args = OperationAction(operation='messages_send_file',
                           arguments={'body': {'chatId': OTHER, 'caption': TEXT}}, idempotency_key=KEY)
    assert service.operation(args, 'test-owner', transfer_id=transfer)['state'] == 'queued'
    before = persisted(service.store)
    revoke(service.store, SOURCE)
    assert persisted(service.store)['arguments'] == '{}'
    with service.store.db() as db:
        assert db.execute('SELECT transfer_id FROM action_jobs WHERE key=?', (KEY,)).fetchone()[0] == transfer
        assert db.execute("SELECT message_id FROM action_job_sources WHERE key=? AND role='media'", (KEY,)).fetchone()[0] == SOURCE
    assert service.process_action()
    assert service.store.send_status(KEY)['state'] == 'failed_before_send'
    assert persisted(service.store)['payload_hash'] == before['payload_hash']
    assert not gateway.requests


@pytest.mark.parametrize('bind_before_revoke', [False, True])
def test_late_verified_alias_redacts_produced_payload(tmp_path, bind_before_revoke):
    store = Store(tmp_path/'archive.sqlite')
    alias_provider = f'true_{LID}_PRODUCED'
    store.queue_action(KEY, 'owner', 'messages_send_text', arguments(chatId=LID))
    store.finish_send(KEY, 'submitted', alias_provider)
    if bind_before_revoke:
        store.bind_chat_alias(LID, CHAT)
    revoke(store)
    if not bind_before_revoke:
        assert persisted(store)['arguments'] != '{}'
        store.bind_chat_alias(LID, CHAT)
    assert persisted(store)['arguments'] == '{}'
    assert store.send_status(KEY)['provider_id'] == alias_provider
    assert store.send_status(KEY)['delivery']['reason'] == 'message_revoked'


def test_scoped_raw_revoke_without_acquisition_does_not_touch_other_chat_or_tenant(tmp_path):
    first, other_tenant = Store(tmp_path/'first.sqlite'), Store(tmp_path/'other.sqlite')
    for store in (first, other_tenant):
        for key, chat in ((KEY, CHAT), ('other-chat', OTHER)):
            store.queue_action(key, 'owner', 'messages_send_text', arguments(chatId=chat))
            store.finish_send(key, 'submitted', f'true_{chat}_RAW')
    revoke(first, 'RAW', chat=CHAT)
    assert persisted(first)['arguments'] == '{}'
    assert persisted(first, 'other-chat')['arguments'] != '{}'
    assert persisted(other_tenant)['arguments'] != '{}'
    assert first.send_status(KEY)['state'] == 'submitted'


def test_sending_crash_remains_uncertain_even_after_redaction(environment):
    service, gateway = enabled(environment)
    service.store.queue_action(KEY, 'test-owner', 'messages_send_text', arguments())
    service.store.finish_send(KEY, 'sending', PROVIDER)
    before = persisted(service.store)
    revoke(service.store)
    assert persisted(service.store)['state'] == 'sending'
    restored = Service(service.settings, gateway=gateway, event_transport=environment[1])
    assert persisted(restored.store)['state'] == 'uncertain'
    assert persisted(restored.store)['payload_hash'] == before['payload_hash']
    assert persisted(restored.store)['arguments'] == '{}'
    assert not restored.process_action() and not gateway.requests


def test_exact_opaque_provider_id_revocation_without_acquired_message_redacts_payload(tmp_path):
    store = Store(tmp_path/'archive.sqlite')
    store.queue_action(KEY, 'owner', 'messages_send_text', arguments())
    store.finish_send(KEY, 'submitted', 'opaque-provider-id')
    original = persisted(store)
    revoke(store, 'opaque-provider-id')
    assert persisted(store)['arguments'] == '{}'
    assert persisted(store)['payload_hash'] == original['payload_hash']
    assert store.send_status(KEY)['delivery']['reason'] == 'message_revoked'


def legacy_database(path, payloads):
    with sqlite3.connect(path) as db:
        db.executescript(SCHEMA_7)
        for i, payload in enumerate(payloads):
            key = KEY + str(i)
            provider = PROVIDER + str(i)
            # Deliberately preserve an opaque historical digest without deriving
            # a replacement from either the original or redacted arguments.
            digest = hashlib.sha256(('historical-digest-' + str(i)).encode()).hexdigest()
            db.execute('INSERT INTO sends VALUES(?,?,?,?,?,?,?)',
                       (key, 'owner', digest, 'submitted', provider, 1, 2))
            db.execute('INSERT INTO action_jobs VALUES(?,?,?,NULL)', (key, 'messages_send_text', payload))
        return [r[0] for r in db.execute('SELECT payload_hash FROM sends ORDER BY key')]


@pytest.mark.parametrize(('payload', 'state'), [
    ('{}', 'unknown'), ('bad json', 'malformed'), ('[]', 'malformed'),
    ('{"body":[]}', 'malformed'), ('{"body":{"chatId":[]}}', 'known'),
])
def test_legacy_missing_or_malformed_metadata_never_asserts_receipt_evidence(tmp_path, payload, state):
    path = tmp_path/'legacy.sqlite'
    before = legacy_database(path, [payload])
    store = Store(path)
    key, provider = KEY+'0', PROVIDER+'0'
    receipt(store, provider, CHAT)
    assert store.send_status(key)['delivery']['reason'] == 'action_metadata_unavailable'
    with store.db() as db:
        metadata = job_metadata.delivery_metadata(db, key)
        assert metadata['metadata_state'] == state
        assert [r[0] for r in db.execute('SELECT payload_hash FROM sends ORDER BY key')] == before
    assert persisted(store, key)['arguments'] == payload


def test_fresh_and_schema7_upgrade_share_metadata_and_revocation_semantics(tmp_path):
    args = arguments(id='caller-selected-id')
    legacy_path = tmp_path/'legacy.sqlite'
    legacy_database(legacy_path, [canonical(args)])
    upgraded = Store(legacy_path)
    fresh = Store(tmp_path/'fresh.sqlite')
    fresh.queue_action(KEY+'0', 'owner', 'messages_send_text', args)
    fresh.finish_send(KEY+'0', 'submitted', PROVIDER+'0')
    for table in ('action_job_metadata', 'action_job_sources'):
        with fresh.db() as first, upgraded.db() as second:
            assert [tuple(r) for r in first.execute('SELECT * FROM '+table)] == [tuple(r) for r in second.execute('SELECT * FROM '+table)]
    hashes = [persisted(store, KEY+'0')['payload_hash'] for store in (fresh, upgraded)]
    for index, store in enumerate((fresh, upgraded)):
        revoke(store, PROVIDER+'0')
        assert persisted(store, KEY+'0')['arguments'] == '{}'
        assert persisted(store, KEY+'0')['payload_hash'] == hashes[index]
        assert store.send_status(KEY+'0')['delivery']['reason'] == 'message_revoked'


def test_legacy_backfill_resumes_committed_batches_without_changing_hash_or_requeue(tmp_path, monkeypatch):
    path = tmp_path/'legacy.sqlite'
    before = legacy_database(path, [canonical(arguments()) for _ in range(105)])
    with sqlite3.connect(path) as db:
        db.executemany("INSERT INTO message_mutations VALUES(?,'revoked',NULL,100)",
                       [(PROVIDER+str(i),) for i in range(105)])
    original = job_metadata.backfill_batch
    calls = []
    def interrupted(*a, **kw):
        calls.append(True)
        if len(calls) == 2:
            raise RuntimeError('synthetic interruption')
        return original(*a, **kw)
    monkeypatch.setattr(job_metadata, 'backfill_batch', interrupted)
    with pytest.raises(RuntimeError, match='synthetic interruption'):
        Store(path)
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT count(*) FROM action_job_metadata').fetchone()[0] == 100
        assert db.execute("SELECT count(*) FROM action_jobs WHERE arguments='{}'").fetchone()[0] == 100
        assert json.loads(db.execute('SELECT value FROM state WHERE key=?', (JOB_METADATA_REPAIR_KEY,)).fetchone()[0])['complete'] is False
    monkeypatch.setattr(job_metadata, 'backfill_batch', original)
    restored = Store(path, recover_inflight=True)
    with restored.db() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
        assert db.execute('SELECT count(*) FROM action_job_metadata').fetchone()[0] == 105
        assert db.execute("SELECT count(*) FROM action_jobs WHERE arguments='{}'").fetchone()[0] == 105
        assert {r[0] for r in db.execute('SELECT state FROM sends')} == {'submitted'}
        assert [r[0] for r in db.execute('SELECT payload_hash FROM sends ORDER BY key')] == before
