"""Synthetic regressions linked to the 23 October handoff, without live actions."""
from dataclasses import replace
import json

import httpx
import pytest
from pydantic import ValidationError

from conftest import call
from test_family_capabilities import full_family_client, GROUP
from test_ab_operations import ab_env
from sally_whatsapp.server import Subscribe, Unsubscribe


@pytest.mark.parametrize('model', [Subscribe, Unsubscribe])
@pytest.mark.parametrize('token', [True, False, 0, 1, -1, '', 'opaque'])
def test_s01_progress_token_preserves_json_type(model, token):
    value = {'name': 'message.received', 'arguments': {'chat_ids': [GROUP]},
             'delivery': {'mode': 'webhook', 'url': 'https://receiver.example/events'},
             '_meta': {'progressToken': token, 'custom': {'kept': True}}}
    if model is Subscribe:
        value['delivery']['secret'] = 'synthetic-secret-0000000000000000'
    if type(token) is bool:
        with pytest.raises(ValidationError, match='progressToken'):
            model.model_validate(value)
    else:
        actual = model.model_validate(value).model_dump(by_alias=True)['_meta']
        assert actual['progressToken'] == token
        assert type(actual['progressToken']) is type(token)
        assert actual['custom'] == {'kept': True}


@pytest.mark.parametrize('operation', ['groups_get_invite_code', 'groups_revoke_invite_code'])
@pytest.mark.parametrize('wire_format', ['text', 'html', 'json'])
def test_f05_invite_code_wire_formats_survive_queue_without_repeat(full_family_client, operation, wire_format):
    service, client, requests, _, _ = full_family_client
    code = 'SYNTHETIC-INVITE-CODE'
    def handle(request):
        requests.append(request)
        return (httpx.Response(200, text=code, headers={'content-type': 'text/html' if wire_format == 'html' else 'text/plain'}) if wire_format != 'json'
                else httpx.Response(200, json=code))
    service.gateway.client.close()
    service.gateway.client = httpx.Client(base_url=service.settings.waha_url,
                                         transport=httpx.MockTransport(handle))
    payload = {'operation': operation, 'arguments': {'path': {'id': GROUP}},
               'idempotency_key': 'qa120-invite-code-0001'}
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'queued'
    assert service.process_action()
    status = call(client, 'get_send_status', {'idempotency_key': payload['idempotency_key']})['result']['structuredContent']
    assert status['state'] == 'submitted'
    assert status['result'] == code
    assert status['provider_outcome'] == 'unverified'
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['result'] == code
    assert not service.process_action() and len(requests) == 1


@pytest.mark.parametrize('body', ['<html>private upstream error</html>', 'bad code', 'X' * 4097])
def test_f05_malformed_text_keeps_revocation_uncertain_and_private(full_family_client, body):
    service, client, requests, _, _ = full_family_client
    def handle(request):
        requests.append(request)
        return httpx.Response(200, text=body)
    service.gateway.client.close()
    service.gateway.client = httpx.Client(base_url=service.settings.waha_url,
                                         transport=httpx.MockTransport(handle))
    payload = {'operation': 'groups_revoke_invite_code', 'arguments': {'path': {'id': GROUP}},
               'idempotency_key': 'qa120-invite-invalid-0001'}
    call(client, 'write_whatsapp', payload)
    assert service.process_action()
    status = service.store.send_status(payload['idempotency_key'])
    assert status['state'] == 'uncertain'
    assert body not in json.dumps(status)
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'uncertain'
    assert not service.process_action() and len(requests) == 1


@pytest.mark.parametrize('observations', [
    [{'participant': '199999998@c.us', 'lastKnownPresence': 'online', 'lastSeen': 1792769200, 'private': 'discard'}],
    [], None,
    [{'participant': '0', 'lastKnownPresence': 'online'}],
])
def test_f10_presence_survives_persistence_restart_and_idempotency(full_family_client, observations):
    from sally_whatsapp.store import Store
    service, client, requests, response, _ = full_family_client
    response['value'] = {'id': '199999998@c.us', 'private': 'discard'}
    if observations is not None:
        response['value']['presences'] = observations
    payload = {'operation': 'presence_get_presence',
               'arguments': {'path': {'chatId': '199999998@c.us'}},
               'idempotency_key': 'qa120-presence-cache-0001'}
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'queued'
    assert service.process_action()
    status = call(client, 'get_send_status', {'idempotency_key': payload['idempotency_key']})['result']['structuredContent']
    result = status['result']
    assert result['source'] == 'provider_cache' and result['current_state'] == 'unknown'
    assert 'discard' not in json.dumps(status)
    if observations and observations[0]['participant'] != '0':
        assert result['availability'] == 'observed'
        assert result['presences'] == [{'participant': '199999998@c.us', 'lastKnownPresence': 'online', 'lastSeen': 1792769200}]
    else:
        assert result['availability'] == 'unavailable'
        assert result['reason'] in ('invalid_presence_response', 'no_cached_observation')
    assert Store(service.settings.database, recover_inflight=True).send_status(payload['idempotency_key']) == status
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent'] == status
    assert not service.process_action() and len(requests) == 1


@pytest.mark.parametrize('reported,listed', [(2, 3), (0, 1), (0, 2), (2, 2)])
def test_f02_f09_group_cache_exposes_freshness_and_disagreement(full_family_client, reported, listed):
    service, client, requests, response, _ = full_family_client
    response['value'] = {'ParticipantCount': reported, 'Participants': [{}] * listed,
                         'MemberAddMode': 'all_member_add'}
    value = call(client, 'read_whatsapp', {'operation': 'groups_get_group',
                 'arguments': {'path': {'id': GROUP}}})['result']['structuredContent']
    assert value['result'] == response['value']
    assert value['freshness']['may_be_stale_after_mutation'] is True
    assert value['participant_count_evidence'] == {
        'reported': reported, 'listed': listed,
        'agreement': 'consistent' if reported == listed else 'mismatch',
        'list_completeness': 'unverified', 'current_count': 'unknown'}
    assert len(requests) == 1 and requests[0].method == 'GET'
    assert not service.process_action()


@pytest.mark.parametrize('star', [True, False])
@pytest.mark.parametrize('ack', [False, True])
def test_f03_actual_star_controller_body_drives_persistent_state(ab_env, star, ack):
    from test_ab_operations import action
    from sally_whatsapp.gateway import Waha
    from sally_whatsapp.store import Store
    service = ab_env.service
    wire = Waha(ab_env.settings)
    wire.client.close()
    mutations = []
    def handle(request):
        if request.method == 'GET':
            return httpx.Response(200, json=ab_env.control.source)
        mutations.append(request)
        return httpx.Response(200, json={'success': True}) if ack else httpx.Response(200, content=b'')
    wire.client = httpx.Client(base_url=ab_env.settings.waha_url, transport=httpx.MockTransport(handle))
    ab_env.gateway.request = wire.request
    args = action('messages_set_star', star=star)
    try:
        assert service.operation(args, 'test-owner')['state'] == 'queued'
        assert service.process_action()
        status = service.store.send_status(args.idempotency_key)
        assert status['state'] == ('submitted' if ack else 'uncertain')
        assert status['provider_outcome'] == ('accepted' if ack else 'unverified')
        assert Store(service.settings.database, recover_inflight=True).send_status(args.idempotency_key) == status
        assert service.operation(args, 'test-owner') == status
        assert not service.process_action() and len(mutations) == 1
    finally:
        wire.close()


@pytest.mark.parametrize('value', ['', {}, None, {'code': 'SYNTHETIC'}])
def test_f05_missing_invite_code_is_uncertain_without_revoke_retry(full_family_client, value):
    service, client, requests, response, _ = full_family_client
    response['value'] = value
    payload = {'operation': 'groups_revoke_invite_code', 'arguments': {'path': {'id': GROUP}},
               'idempotency_key': 'qa120-invite-missing-0001'}  # gitleaks:allow -- synthetic idempotency identifier, not a credential
    call(client, 'write_whatsapp', payload)
    assert service.process_action()
    assert service.store.send_status(payload['idempotency_key'])['state'] == 'uncertain'
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'uncertain'
    assert not service.process_action() and len(requests) == 1


@pytest.mark.parametrize('sender', ['199999998@c.us', '199999998@lid'])
def test_f01_empty_reject_response_only_proves_submission(full_family_client, sender):
    service, client, requests, response, _ = full_family_client
    response['value'] = {}
    payload = {'operation': 'calls_reject_call',
               'arguments': {'body': {'from': sender, 'id': 'SYNTHETIC-CALL'}},
               'idempotency_key': 'qa120-call-reject-0001'}
    call(client, 'write_whatsapp', payload)
    assert service.process_action()
    status = service.store.send_status(payload['idempotency_key'])
    assert status['state'] == 'submitted' and status['provider_outcome'] == 'unverified'
    assert status['result'] == {}
    assert status['delivery']['status'] == 'not_applicable'
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent'] == status
    assert not service.process_action() and len(requests) == 1


@pytest.mark.parametrize('operation', ['channels_get', 'channels_preview_channel_messages'])
def test_f08_provider_failure_is_not_invalid_argument_or_hidden_follow(full_family_client, operation):
    service, client, requests, response, _ = full_family_client
    response.update(status=500, value={'error': 'private upstream details'})
    arguments = {'path': {'id': '15550007777@newsletter'}}
    if operation == 'channels_preview_channel_messages':
        arguments['query'] = {'downloadMedia': False, 'limit': 3}
    value = call(client, 'read_whatsapp', {'operation': operation, 'arguments': arguments})['result']
    assert value['isError']
    assert value['structuredContent']['error_code'] == 'PROVIDER_UNAVAILABLE'
    assert value['structuredContent']['gateway_status'] == 500
    assert value['structuredContent']['operation'] == operation
    assert 'private upstream details' not in json.dumps(value)
    assert len(requests) == 1 and requests[0].method == 'GET'
    assert not service.process_action()


@pytest.mark.parametrize('operation,arguments', [
    ('messages_send_buttons_reply', {'body': {'chatId': '199999998@c.us', 'selectedDisplayText': 'QA', 'selectedButtonID': 'qa'}}),
    ('chats_delete_chat', {'path': {'chatId': GROUP}}),
    ('chats_clear_messages', {'path': {'chatId': GROUP}}),
    ('groups_delete_group', {'path': {'id': GROUP}}),
    ('channels_delete', {'path': {'id': '15550007777@newsletter'}}),
])
def test_f07_valid_unsupported_requests_keep_capability_error(full_family_client, operation, arguments):
    service, client, requests, _, _ = full_family_client
    result = call(client, 'write_whatsapp', {'operation': operation, 'arguments': arguments,
                  'idempotency_key': 'qa120-unsupported-0001'})['result']
    assert result['isError']
    assert result['structuredContent']['error_code'] == 'OPERATION_UNSUPPORTED'
    assert result['structuredContent']['retryable'] is False
    assert service.store.send_status('qa120-unsupported-0001') is None
    assert not service.process_action() and not requests
