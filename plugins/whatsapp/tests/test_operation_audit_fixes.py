"""Regression cases for audit F04/F05/F06/F13; all gateways and data are synthetic."""
from dataclasses import replace
import json
from pathlib import Path
import socket
import subprocess
import sys

from jsonschema import Draft202012Validator
import pytest

from conftest import message
from sally_whatsapp.events import CallbackError
from sally_whatsapp.operations import OPERATIONS, validate_operation
from sally_whatsapp.server import OperationAction, Service
from sally_whatsapp.store import Store


def enabled_service(environment, **overrides):
    settings, receiver, gateway, _ = environment
    settings = replace(settings, live_account_enabled=True, send_enabled=True,
                       send_chat_ids=['fixture@g.us'], **overrides)
    gateway.requests = []

    def request(*args, **kwargs):
        gateway.requests.append((args, kwargs))
        return {'id': 'synthetic-provider-id'}

    gateway.request = request
    return Service(settings, gateway=gateway, event_transport=receiver), gateway


def action(operation, body, key='synthetic-operation-0001'):  # gitleaks:allow -- synthetic idempotency key, not a credential
    return OperationAction(operation=operation, arguments={'body': body}, idempotency_key=key)


def test_vcard_content_is_not_a_destination(environment):
    service, gateway = enabled_service(environment)
    body = {'chatId': 'fixture@g.us', 'contacts': [{'vcard': 'BEGIN:VCARD\nFN:Synthetic\nEND:VCARD'}]}
    args = action('messages_send_contact_vcard', body)
    assert service.operation(args, 'test-owner')['state'] == 'queued'
    assert service.process_action()
    assert service.store.send_status(args.idempotency_key)['state'] == 'submitted'
    assert gateway.requests[0][1]['json']['contacts'] == body['contacts']
    assert service.operation(args, 'test-owner')['state'] == 'submitted'
    assert not service.process_action()
    assert len(gateway.requests) == 1
    body['chatId'] = 'forbidden@g.us'
    with pytest.raises(ValueError, match='not allowed'):
        service.operation(action('messages_send_contact_vcard', body, 'synthetic-denied-0001'), 'test-owner')


@pytest.mark.parametrize('contacts', [[], ['forbidden@c.us'], ['fixture@g.us', 'forbidden@c.us']])
def test_status_contacts_remain_destinations(environment, contacts):
    service, gateway = enabled_service(environment)
    with pytest.raises(ValueError, match='not allowed'):
        service.operation(action('status_send_text_status', {
            'text': 'synthetic', 'backgroundColor': '#FFFFFF', 'font': 1, 'contacts': contacts}), 'test-owner')
    assert not gateway.requests


def test_status_with_only_allowed_contacts_can_be_queued(environment):
    service, _ = enabled_service(environment)
    assert service.operation(action('status_send_text_status', {
        'text': 'synthetic', 'backgroundColor': '#FFFFFF', 'font': 1,
        'contacts': ['fixture@g.us']}), 'test-owner')['state'] == 'queued'


def test_reaction_uses_acquired_message_and_rechecks_before_send(environment):
    service, gateway = enabled_service(environment)
    service.store.ingest(message('synthetic-reaction', chat='fixture@g.us'))
    args = action('messages_set_reaction', {'messageId': 'synthetic-reaction', 'reaction': '👍'})
    assert service.operation(args, 'test-owner')['state'] == 'queued'
    assert service.process_action()
    assert gateway.requests[0][1]['json']['messageId'] == 'synthetic-reaction'
    second = args.model_copy(update={'idempotency_key': 'synthetic-reaction-0002'})
    assert service.operation(second, 'test-owner')['state'] == 'queued'
    service.store.ingest({'id': 'synthetic-revoke', 'event': 'message.revoked',
                          'payload': {'revokedMessageId': 'synthetic-reaction'}})
    assert service.process_action()
    assert service.store.send_status(second.idempotency_key)['state'] == 'failed_before_send'
    assert len(gateway.requests) == 1


@pytest.mark.parametrize('kind', ['unknown', 'forbidden', 'revoked'])
def test_reaction_cannot_trust_an_id_or_bypass_allowlist(environment, kind):
    service, gateway = enabled_service(environment)
    identifier = 'false_fixture@g.us_SYNTHETIC'
    if kind != 'unknown':
        service.store.ingest(message(identifier, chat='forbidden@g.us' if kind == 'forbidden' else 'fixture@g.us'))
    if kind == 'revoked':
        service.store.ingest({'id': 'synthetic-revoke', 'event': 'message.revoked',
                              'payload': {'revokedMessageId': identifier}})
    with pytest.raises(ValueError, match='not allowed'):
        service.operation(action('messages_set_reaction', {'messageId': identifier, 'reaction': '👍'}), 'test-owner')
    assert not gateway.requests


def test_all_destinations_still_allows_unarchived_reaction(environment):
    service, _ = enabled_service(environment, allow_all_destinations=True)
    assert service.operation(action('messages_set_reaction', {
        'messageId': 'synthetic-unarchived', 'reaction': ''}), 'test-owner')['state'] == 'queued'


def test_all_catalog_schemas_are_valid():
    assert len(OPERATIONS) == 120
    for operation in OPERATIONS.values():
        Draft202012Validator.check_schema(operation['schema'])


@pytest.mark.parametrize('operation', ['messages_send_poll','messages_send_poll_vote'])
def test_removed_poll_writes_have_no_runtime_schema(operation):
    assert operation not in OPERATIONS
    with pytest.raises(ValueError, match='Unknown operation'):
        validate_operation(operation, {'body': {}}, readonly=False)


def generator_source():
    # Minimal reproduction of the two known Swagger mistakes in pinned WAHA 2026.9.2.
    return {
        'components': {'schemas': {
            'MessagePoll': {'type': 'object', 'properties': {'multipleAnswers': {'type': 'object'}}},
            'MessagePollVoteRequest': {'type': 'object', 'properties': {
                'votes': {'type': 'array', 'items': {'required': True, 'type': 'array', 'items': {'type': 'string'}}}}},
        }},
        'paths': {
            '/api/sendPollVote': {'post': {'operationId': 'ChattingController_sendPollVote', 'requestBody': {
                'content': {'application/json': {'schema': {'$ref': '#/components/schemas/MessagePollVoteRequest'}}}}}},
            '/api/sendPoll': {'post': {'operationId': 'ChattingController_sendPoll', 'requestBody': {
                'content': {'application/json': {'schema': {'$ref': '#/components/schemas/MessagePoll'}}}}}},
        },
    }


@pytest.mark.parametrize('invalid', [False, True])
def test_generator_omits_poll_routes_and_rejects_unrelated_invalid_schema(tmp_path, invalid):
    source = generator_source()
    if invalid:
        source['paths']['/api/{session}/profile/name'] = {'put': {
            'operationId':'ProfileController_setProfileName','requestBody':{'content':{
                'application/json':{'schema':{'type':'object','properties':{
                    'unrelated':{'type':'object','required':True}}}}}}}}
    input_file, output_file = tmp_path/'openapi.json', tmp_path/'operations.json'
    input_file.write_text(json.dumps(source))
    output_file.write_text('original catalog')
    script = Path(__file__).parents[1]/'scripts/build_operations.py'
    result = subprocess.run([sys.executable, str(script), str(input_file), '--output', str(output_file)],
                            capture_output=True, text=True)
    if invalid:
        assert result.returncode != 0 and 'SchemaError' in result.stderr
        assert output_file.read_text() == 'original catalog'
    else:
        assert result.returncode == 0, result.stderr
        catalog = json.loads(output_file.read_text())
        assert catalog == {}


@pytest.mark.parametrize('failure', [CallbackError('non_public_address'), socket.gaierror('synthetic DNS failure'),
                                    TimeoutError('synthetic timeout')])
def test_preview_preparation_failure_is_terminal_before_send(environment, monkeypatch, failure):
    import sally_whatsapp.events as events
    service, gateway = enabled_service(environment)
    monkeypatch.setattr(events, 'public_addresses', lambda host: [])
    from conftest import ready_external_media
    transfer=ready_external_media(service,name='synthetic.png',mimetype='image/png')['id']
    args = action('messages_send_link_custom_preview', {
        'chatId': 'fixture@g.us', 'text': 'https://public.example/a',
        'preview': {'url': 'https://public.example/a', 'title': 'synthetic', 'description': 'synthetic'}})
    assert service.operation(args, 'test-owner', transfer_id=transfer)['state'] == 'queued'

    def fail(host):
        raise failure

    monkeypatch.setattr(events, 'public_addresses', fail)
    assert service.process_action()
    assert not gateway.requests
    status = service.store.send_status(args.idempotency_key)
    assert status['state'] == 'failed_before_send'
    assert 'no provider request made' in status['result']['error']
    restored = Store(service.settings.database, recover_inflight=True)
    assert restored.send_status(args.idempotency_key)['state'] == 'failed_before_send'
    monkeypatch.setattr(events, 'public_addresses', lambda host: [])
    assert service.operation(args, 'test-owner', transfer_id=transfer)['state'] == 'failed_before_send'
    assert not service.process_action()
    next_args = action('messages_send_text', {'chatId': 'fixture@g.us', 'text': 'synthetic'}, 'synthetic-next-0001')
    assert service.operation(next_args, 'test-owner')['state'] == 'queued'
    assert service.process_action()
    assert len(gateway.requests) == 1


def test_failure_after_provider_call_remains_uncertain(environment):
    service, gateway = enabled_service(environment)

    def sent_then_timeout(*args, **kwargs):
        gateway.requests.append((args, kwargs))
        raise TimeoutError('synthetic response lost')

    gateway.request = sent_then_timeout
    args = action('messages_send_text', {'chatId': 'fixture@g.us', 'text': 'synthetic'})
    service.operation(args, 'test-owner')
    assert service.process_action()
    assert service.store.send_status(args.idempotency_key)['state'] == 'uncertain'
    assert service.operation(args, 'test-owner')['state'] == 'uncertain'
    assert not service.process_action()
    assert len(gateway.requests) == 1


def test_failed_transfer_offers_recovery_without_polling(environment,monkeypatch):
    service, gateway = enabled_service(environment)

    def fail(*args):
        raise ValueError('Synthetic transfer failure')

    monkeypatch.setattr('sally_whatsapp.media.download_public',fail)
    job = service.media.enqueue('test-owner', {'kind':'external','file_id':'file-synthetic',
        'download_url':'https://files.example/synthetic'}, 'synthetic.txt')
    assert job['next_tool'] == 'get_transfer_status'
    assert service.media.process_one()
    failed = service.media.status(job['id'], 'test-owner')
    assert failed['state'] == 'failed' and 'next_tool' not in failed
    assert 'get_attachment' in failed['recovery'] and 'prepare_file' in failed['recovery']
    assert not service.media.process_one()


@pytest.mark.parametrize('state', ['queued', 'downloading', 'cancelled'])
def test_transfer_polling_only_for_active_jobs(environment, state):
    service, _ = enabled_service(environment)
    job = service.media.enqueue('test-owner', {'kind': 'gateway', 'media': {'url': 'synthetic'}}, 'synthetic.txt')
    with service.store.db() as db:
        db.execute('UPDATE media_jobs SET state=? WHERE id=?', (state, job['id']))
    status = service.media.status(job['id'], 'test-owner')
    assert ('next_tool' in status) == (state in ('queued', 'downloading'))
