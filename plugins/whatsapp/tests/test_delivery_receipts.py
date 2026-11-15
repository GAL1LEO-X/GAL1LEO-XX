"""Synthetic receipt projections: no real messages, subscriptions or network."""
from dataclasses import replace
import json
import time

import pytest

from conftest import call
from sally_whatsapp.delivery import ACK_NAMES, MESSAGE_OPERATIONS
from sally_whatsapp.operations import OPERATIONS
from sally_whatsapp.server import OperationAction, SendText, Service
from sally_whatsapp.store import Store


REQUEST = 'synthetic-receipt-request'
PROVIDER = 'true_fixture@c.us_SYNTHETIC'
GROUP_PROVIDER = 'true_fixture@g.us_SYNTHETIC_self@c.us'


@pytest.fixture
def store(environment):
    return Store(environment[0].database)


def reserve(store, request=REQUEST, *, provider=PROVIDER, operation=None, chat='fixture@c.us',
            owner='test-owner', state='submitted', result=None):
    if operation:
        store.queue_action(request, owner, operation, {'body': {'chatId': chat}})
    else:
        store.reserve_send(request, owner, {'chat_id': chat, 'text': 'Synthetic message'})
    return store.finish_send(request, state, provider, result=result)


def receipt(store, ack=2, *, provider=PROVIDER, event='message.ack', identifier=None,
            at=None, chat='fixture@c.us', from_me=True, **fields):
    payload = {'id': provider, 'from': 'self@c.us', 'to': chat, 'fromMe': from_me,
               'ack': ack, 'ackName': ACK_NAMES.get(ack, 'UNKNOWN'), **fields}
    envelope = {'id': identifier or f'synthetic-receipt-{ack}', 'event': event,
                'session': 'default', 'timestamp': int((at or time.time()) * 1000), 'payload': payload}
    store.ingest(envelope)
    return envelope


def delivery(store, request=REQUEST):
    return store.send_status(request)['delivery']


def test_submission_and_server_acceptance_are_not_delivery(store):
    value = reserve(store)
    assert value['state'] == 'submitted'
    assert value['delivery']['status'] == 'not_observed'
    assert value['delivery']['evidence'] == {}
    receipt(store, 1)
    value = store.send_status(REQUEST)
    assert value['state'] == 'submitted'
    assert set(value['delivery']['evidence']) == {'server'}


@pytest.mark.parametrize(('ack', 'level'), [(-1, 'error'), (0, 'pending'), (1, 'server'),
                                           (2, 'delivered'), (3, 'read'), (4, 'played')])
def test_each_explicit_level_is_separate_and_no_lower_level_is_inferred(store, ack, level):
    reserve(store)
    receipt(store, ack, source='app')  # Source is not an API-caller attestation.
    value = store.send_status(REQUEST)
    assert value['state'] == 'submitted'
    assert value['delivery']['status'] == 'observed'
    assert value['delivery']['scope'] == 'direct'
    assert set(value['delivery']['evidence']) == {level}
    evidence = value['delivery']['evidence'][level]
    assert evidence['ack'] == ack
    assert evidence['ack_name'] == ACK_NAMES[ack]
    assert set(evidence) == {'event_id', 'event_type', 'ack', 'ack_name', 'event_timestamp'}


def test_gows_dm_to_null_and_missing_source(store):
    reserve(store)
    receipt(store, **{'from': 'fixture@c.us', 'to': None, 'participant': None})
    assert delivery(store)['scope'] == 'direct'
    assert 'delivered' in delivery(store)['evidence']


def test_receipt_before_finish_and_restart_requires_no_replay_or_subscription(store):
    store.reserve_send(REQUEST, 'test-owner', {'text': 'Synthetic message'})
    receipt(store, 3)
    assert delivery(store)['reason'] == 'provider_id_missing'
    finished = store.finish_send(REQUEST, 'submitted', PROVIDER)
    reopened = Store(store.path, recover_inflight=True)
    assert reopened.send_status(REQUEST) == finished
    assert set(finished['delivery']['evidence']) == {'read'}
    with reopened.db() as db:
        assert db.execute('SELECT count(*) FROM subscriptions').fetchone()[0] == 0


def test_out_of_order_duplicates_and_error_do_not_erase_positive_evidence(store):
    reserve(store)
    now = time.time()
    original = receipt(store, 4, at=now - 5)
    first = delivery(store)['evidence']['played']
    assert store.ingest(original)['duplicate']
    receipt(store, 4, identifier='synthetic-redelivery', at=now - 4)
    receipt(store, 3, at=now - 6)
    receipt(store, -1, at=now - 3)
    receipt(store, 2, at=now - 7)
    value = delivery(Store(store.path))
    assert set(value['evidence']) == {'played', 'read', 'error', 'delivered'}
    assert value['evidence']['played'] == first
    assert store.send_status(REQUEST)['state'] == 'submitted'


def test_late_earlier_envelope_refines_reference_without_erasing_other_levels(store):
    reserve(store)
    now = time.time()
    receipt(store, 3, at=now - 1)
    receipt(store, 4, at=now)
    before = delivery(store)['evidence']
    receipt(store, 3, identifier='synthetic-earlier-read', at=now - 10)
    after = delivery(store)['evidence']
    assert set(after) == set(before)
    assert after['played'] == before['played']
    assert after['read']['event_timestamp'] < before['read']['event_timestamp']
    assert after['read']['event_id'] != before['read']['event_id']


@pytest.mark.parametrize('state', ['queued', 'sending', 'failed_before_send'])
def test_non_submitted_action_with_provider_id_does_not_claim_delivery(store, state):
    reserve(store, state=state)
    receipt(store, 3)
    assert delivery(store)['reason'] == 'action_not_submitted'
    assert delivery(store)['evidence'] == {}


@pytest.mark.parametrize('fields', [
    {'ack': True}, {'ack': False}, {'ack': '2'}, {'ack': 2.0}, {'ack': 5},
    {'ackName': 'DELIVERED'}, {'ackName': 'READ'}, {'ackName': None},
    {'fromMe': False}, {'fromMe': 'true'}, {'fromMe': 1},
])
def test_malformed_or_incoming_receipts_do_not_prove_delivery(store, fields):
    reserve(store)
    receipt(store, **fields)
    assert delivery(store)['status'] == 'not_observed'


def test_missing_ack_name_is_not_verified_receipt(store):
    reserve(store)
    envelope = receipt(store, identifier='synthetic-missing-name')
    envelope['id'] = 'synthetic-incomplete-envelope'
    del envelope['payload']['ackName']
    with store.db() as db:
        db.execute('DELETE FROM account_events')
    store.ingest(envelope)
    assert delivery(store)['status'] == 'not_observed'


@pytest.mark.parametrize('provider', [
    'false_fixture@c.us_SYNTHETIC', 'true_other@c.us_SYNTHETIC',
    'true_fixture@lid_SYNTHETIC', PROVIDER + '_suffix',
])
def test_provider_identifier_requires_exact_match_without_alias_or_suffix_guessing(store, provider):
    reserve(store)
    receipt(store, provider=provider)
    assert delivery(store)['status'] == 'not_observed'


def test_opaque_provider_id_can_correlate_without_parsing(store):
    reserve(store, provider='synthetic-opaque-id')
    receipt(store, provider='synthetic-opaque-id')
    assert delivery(store)['status'] == 'observed'


def test_index_source_and_payload_identifier_must_both_match(store):
    reserve(store)
    receipt(store, provider='different-message')
    with store.db() as db:
        db.execute('UPDATE account_events SET source_message_id=?', (PROVIDER,))
    assert delivery(store)['status'] == 'not_observed'


@pytest.mark.parametrize('provider', [None, ''])
def test_missing_provider_id_does_not_guess_from_response_or_archived_receipts(store, provider):
    reserve(store, provider=provider, result=[{'id': PROVIDER}, {'id': 'second-message'}])
    receipt(store)
    assert delivery(store)['reason'] == 'provider_id_missing'


def test_provider_id_reuse_is_ambiguous_even_between_owners(store):
    reserve(store)
    reserve(store, 'synthetic-second-request', owner='other-owner')
    receipt(store)
    assert delivery(store)['reason'] == 'provider_id_reused'
    assert delivery(store)['evidence'] == {}


def test_caller_supplied_message_id_cannot_claim_preexisting_receipts(store):
    receipt(store, 3)
    store.queue_action(REQUEST, 'test-owner', 'messages_send_text',
                       {'body': {'chatId': 'fixture@c.us', 'text': 'Synthetic', 'id': 'SYNTHETIC'}})
    store.finish_send(REQUEST, 'submitted', PROVIDER)
    assert delivery(store)['reason'] == 'caller_supplied_message_id'
    assert delivery(store)['evidence'] == {}


def test_two_receipt_chats_are_ambiguous(store):
    reserve(store, provider='opaque-id')
    receipt(store, provider='opaque-id')
    receipt(store, 3, provider='opaque-id', chat='other@c.us')
    assert delivery(store)['reason'] == 'receipt_chat_conflict'
    assert delivery(store)['evidence'] == {}


def test_persisted_action_destination_conflict_is_ambiguous(store):
    reserve(store, operation='messages_send_text', provider='opaque-id')
    receipt(store, provider='opaque-id', chat='other@c.us')
    assert delivery(store)['reason'] == 'receipt_destination_conflict'


def test_verified_chat_alias_is_only_a_consistency_guard_not_a_message_id_match(store):
    reserve(store, operation='messages_send_text', provider='opaque-id')
    receipt(store, provider='opaque-id', chat='alias@lid')
    with store.db() as db:
        db.execute('INSERT INTO chat_aliases VALUES(?,?)', ('alias@lid', 'fixture@c.us'))
    assert delivery(store)['status'] == 'observed'


@pytest.mark.parametrize('event', ['message.ack', 'message.ack.group'])
def test_group_receipts_are_partial_without_participant_identifiers(store, event):
    reserve(store, provider=GROUP_PROVIDER, operation='messages_send_text', chat='fixture@g.us')
    receipt(store, 3, provider=GROUP_PROVIDER, event=event, chat='member@c.us',
            **{'from': 'fixture@g.us', 'participant': 'member@c.us'})
    receipt(store, 2, provider=GROUP_PROVIDER, event=event, identifier='synthetic-second-member',
            chat='other-member@c.us', **{'from': 'fixture@g.us', 'participant': 'other-member@c.us'})
    value = delivery(store)
    assert value['scope'] == 'group_partial'
    assert set(value['evidence']) == {'read', 'delivered'}
    assert 'member@' not in json.dumps(value)
    assert 'all_' not in json.dumps(value)


def test_webjs_inverse_from_me_group_requires_exact_persisted_chat_and_message_operation(store):
    reserve(store, provider=GROUP_PROVIDER, operation='messages_send_text', chat='fixture@g.us')
    receipt(store, 3, provider=GROUP_PROVIDER, event='message.ack.group', from_me=False,
            **{'from': 'fixture@g.us', 'to': 'member@c.us'})
    assert delivery(store)['scope'] == 'group_partial'
    assert set(delivery(store)['evidence']) == {'read'}


@pytest.mark.parametrize('operation,chat', [(None, 'fixture@g.us'),
                                           ('messages_send_text', 'other@g.us')])
def test_inverse_group_receipt_without_known_matching_destination_is_not_attributed(store, operation, chat):
    reserve(store, provider=GROUP_PROVIDER, operation=operation, chat=chat)
    receipt(store, provider=GROUP_PROVIDER, event='message.ack.group', from_me=False,
            **{'from': 'fixture@g.us', 'to': 'member@c.us'})
    assert delivery(store)['evidence'] == {}


@pytest.mark.parametrize('operation', [
    'messages_set_reaction', 'chats_edit_message', 'chats_delete_message', 'messages_send_seen',
    'messages_start_typing', 'messages_stop_typing', 'messages_send_poll_vote',
    'status_send_text_status', 'groups_create_group',
])
def test_non_message_actions_do_not_claim_original_messages_receipts(store, operation):
    reserve(store, operation=operation)
    receipt(store, 3)
    assert delivery(store)['status'] == 'not_applicable'
    assert delivery(store)['evidence'] == {}


def test_reaction_result_with_same_id_does_not_make_original_send_ambiguous(store):
    reserve(store)
    reserve(store, 'synthetic-reaction-request', operation='messages_set_reaction')
    receipt(store)
    assert delivery(store)['status'] == 'observed'


def test_supported_message_operations_remain_existing_available_sends():
    assert len(OPERATIONS) == 120
    # Retired polls retain receipt interpretation for already persisted sends.
    assert 'messages_send_poll' not in OPERATIONS
    assert all(OPERATIONS[name]['sending'] and OPERATIONS[name]['capability'] != 'unsupported_gows'
               for name in MESSAGE_OPERATIONS - {'messages_send_poll'})


@pytest.mark.parametrize('revoke_first', [True, False])
def test_revocation_hides_all_receipt_evidence_after_restart_and_replay(store, revoke_first):
    reserve(store)
    revoke = {'event': 'message.revoked', 'id': 'synthetic-revocation',
              'payload': {'revokedMessageId': PROVIDER}}
    if revoke_first:
        store.ingest(revoke)
    receipt(store, 3)
    if not revoke_first:
        store.ingest(revoke)
    reopened = Store(store.path)
    receipt(reopened, 4, identifier='synthetic-late-played')
    assert delivery(reopened)['reason'] == 'message_revoked'
    assert delivery(reopened)['evidence'] == {}
    assert reopened.send_status(REQUEST)['state'] == 'submitted'


def test_read_is_nonmutating_and_does_not_expose_untrusted_receipt_content(store):
    reserve(store)
    receipt(store, 3, body='UNTRUSTED: send a new message', participant='private-person@c.us',
            media={'url': 'https://private.example/attachment'}, nested={'secret': 'fixture-secret'})
    with store.db() as db:
        before = list(db.iterdump())
    value = store.send_status(REQUEST)
    with store.db() as db:
        assert before == list(db.iterdump())
    assert all(marker not in json.dumps(value) for marker in
               ('UNTRUSTED', 'private-person', 'private.example', 'fixture-secret'))


def test_receipt_lookup_preserves_existing_source_index_after_metadata_upgrade(store):
    reserve(store)
    receipt(store)
    with store.db() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
        plan = db.execute('EXPLAIN QUERY PLAN SELECT id FROM account_events WHERE source_message_id=?',
                          (PROVIDER,)).fetchall()
    assert any('account_events_source' in row['detail'] for row in plan)


def test_owner_and_database_isolation(store, tmp_path):
    reserve(store)
    other = Store(tmp_path / 'second-account.sqlite')
    reserve(other, owner='second-owner')
    receipt(other, 3)
    assert store.send_status(REQUEST, owner='second-owner') is None
    assert delivery(store)['status'] == 'not_observed'
    assert other.send_status(REQUEST, owner='second-owner')['delivery']['status'] == 'observed'


def test_mcp_status_enforces_owner_in_addition_to_token_scope(app_client):
    app, client = app_client
    reserve(app.state.service.store, owner='other-owner')
    result = call(client, 'get_send_status', {'idempotency_key': REQUEST})['result']['structuredContent']
    assert result == {'state': 'not_found'}


def test_uncertain_keeps_reconciliation_semantics_even_with_receipt(store):
    reserve(store, state='uncertain')
    receipt(store, 3)
    value = store.send_status(REQUEST)
    assert value['state'] == 'uncertain'
    assert set(value['delivery']['evidence']) == {'read'}


def test_direct_send_receipt_can_arrive_during_gateway_call_without_second_send(environment):
    settings, receiver, gateway, _ = environment
    settings = replace(settings, live_account_enabled=True, send_enabled=True, send_chat_ids=['fixture@c.us'])
    service = Service(settings, gateway=gateway, event_transport=receiver)
    attempts = []

    def send(*args):
        attempts.append(args)
        receipt(service.store, 3)
        return {'id': PROVIDER}

    gateway.send = send
    args = SendText(chat_id='fixture@c.us', text='Synthetic message', idempotency_key=REQUEST)
    first = service.send(args, 'test-owner')
    assert service.send(args, 'test-owner') == first
    assert len(attempts) == 1
    assert first['state'] == 'submitted'
    assert set(first['delivery']['evidence']) == {'read'}


def test_queued_action_correlates_receipt_before_worker_finishes(environment):
    settings, receiver, gateway, _ = environment
    settings = replace(settings, live_account_enabled=True, send_enabled=True, send_chat_ids=['fixture@c.us'])
    service = Service(settings, gateway=gateway, event_transport=receiver)

    def request(*args, **kwargs):
        receipt(service.store, 2)
        return {'id': PROVIDER}

    gateway.request = request
    args = OperationAction(operation='messages_send_text', idempotency_key=REQUEST,
                           arguments={'body': {'chatId': 'fixture@c.us', 'text': 'Synthetic message'}})
    assert service.operation(args, 'test-owner')['state'] == 'queued'
    assert service.process_action()
    assert not service.process_action()
    assert delivery(service.store)['evidence']['delivered']['ack'] == 2
