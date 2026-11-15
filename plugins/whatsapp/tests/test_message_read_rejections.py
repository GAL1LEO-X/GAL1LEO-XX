"""Synthetic identity refusals through provider, MCP and privacy boundaries."""
from dataclasses import replace
import json

import httpx
import pytest

from conftest import call
from sally_whatsapp.gateway import Waha, GatewayUnavailable, GatewayNotSent, GatewayReadRejected


PATH = '/api/default/chats/12345%40c.us/messages/false_12345%40c.us_SYNTHETIC'
INVALID = 'Invalid serialized message identity'
MISMATCH = 'Stored message does not match the requested message identity'


def rejection(message=INVALID):
    return {'statusCode': 422, 'error': 'Unprocessable Entity', 'message': message}


def install(app, status, payload):
    gateway = Waha(replace(app.state.service.settings, live_account_enabled=True))
    gateway.client.close()
    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(status, json=payload)
    gateway.client = httpx.Client(base_url=gateway.settings.waha_url, transport=httpx.MockTransport(respond))
    gateway.diagnostics = app.state.service.diagnostics
    app.state.service.gateway = gateway
    return gateway, requests


@pytest.mark.parametrize('message,code,kind', [
    ('Invalid message identity', 'INVALID_ARGUMENT', 'invalid_message_identity'),
    (INVALID, 'INVALID_ARGUMENT', 'invalid_message_identity'),
    ('Message identity does not match the requested chat', 'INVALID_ARGUMENT', 'invalid_message_identity'),
    ('Invalid message participant', 'INVALID_ARGUMENT', 'invalid_message_identity'),
    ('Invalid WhatsApp identifier', 'INVALID_ARGUMENT', 'invalid_message_identity'),
    (MISMATCH, 'MESSAGE_IDENTITY_MISMATCH', 'message_identity_mismatch'),
])
def test_known_identity_refusal_is_consistent_from_gateway_to_mcp(app_client, message, code, kind):
    app, client = app_client
    gateway, requests = install(app, 422, {**rejection(message), 'request': 'private-upstream-detail'})
    try:
        result = call(client, 'read_whatsapp', {'operation': 'chats_get_chat_message',
            'arguments': {'path': {'chatId': '12345@c.us', 'messageId': 'false_12345@c.us_SYNTHETIC'}}})['result']
        value = result['structuredContent']
        assert result['isError'] is True
        assert value['error_code'] == value['whatsapp_error_code'] == code
        assert value['gateway_status'] == 422 and value['provider_error_kind'] == kind
        assert value['operation'] == 'chats_get_chat_message'
        assert value['message'] == result['content'][0]['text']
        assert value['request_id'] == result['_meta']['whatsapp/request_id']
        assert 'mcp/www_authenticate' not in result['_meta']
        assert [r.method for r in requests] == ['GET']
        logs = (app.state.service.settings.database.parent/'diagnostics/events.jsonl').read_text()
        rows = [json.loads(line) for line in logs.splitlines()]
        failure = next(row for row in rows if row['event'] == 'gateway.failed')
        assert failure['error_code'] == code and failure['provider_error_kind'] == kind
        assert failure['request_id'] == value['request_id']
        for private in ('private-upstream-detail', '12345@c.us', 'SYNTHETIC', message):
            assert private not in json.dumps(result) + logs
        with app.state.service.store.db() as db:
            assert db.execute('SELECT count(*) FROM sends').fetchone()[0] == 0
            assert db.execute('SELECT count(*) FROM action_jobs').fetchone()[0] == 0
    finally:
        gateway.close()


@pytest.mark.parametrize('status,payload', [
    (500, rejection()), (403, rejection()),
    (422, {'statusCode': '422', 'message': INVALID, 'error': 'Unprocessable Entity'}),
    (422, {'statusCode': 422, 'message': INVALID}),
    (422, {'statusCode': 422, 'message': [INVALID], 'error': 'Unprocessable Entity'}),
    (422, rejection(INVALID + ' private suffix')),
    (422, rejection('Session not ready')),
    (422, rejection('Feature available only in Plus')),
    (422, rejection('Profile not found')),
    (422, rejection('Invalid LID')),
    (422, {**rejection(), 'padding': 'x' * 65536}),
    (422, []),
])
def test_other_422_and_malformed_signatures_do_not_blame_the_arguments(app_client, status, payload):
    app, client = app_client
    gateway, _ = install(app, status, payload)
    try:
        value = call(client, 'read_whatsapp', {'operation': 'chats_get_chat_message',
            'arguments': {'path': {'chatId': '12345@c.us', 'messageId': 'SYNTHETIC'}}})['result']['structuredContent']
        assert value['error_code'] == value['whatsapp_error_code'] == 'PROVIDER_UNAVAILABLE'
        assert value['provider_error_kind'] == 'provider_failure'
        assert value['gateway_status'] == status
        assert 'private suffix' not in json.dumps(value)
    finally:
        gateway.close()


@pytest.mark.parametrize('method,path', [
    ('POST', PATH), ('PUT', PATH), ('DELETE', PATH),
    ('GET', '/api/default/profile'), ('GET', '/api/default/chats/12345%40c.us/messages'),
])
def test_only_single_message_get_is_specialized(app_client, method, path):
    gateway, _ = install(app_client[0], 422, rejection(MISMATCH))
    try:
        with pytest.raises(GatewayUnavailable) as caught:
            gateway.request(method, path)
        assert type(caught.value) is GatewayUnavailable
        assert not isinstance(caught.value, (GatewayReadRejected, GatewayNotSent))
        assert caught.value.provider_error_kind == 'message_identity_mismatch'
        if method != 'GET':
            assert 'outcome may be uncertain' in str(caught.value)
    finally:
        gateway.close()


def test_identity_422_does_not_turn_queued_write_into_safe_retry(environment):
    from sally_whatsapp.server import Service
    settings, receiver, _, _ = environment
    settings = replace(settings, live_account_enabled=True, account_actions_enabled=True)
    gateway = Waha(settings)
    gateway.client.close()
    gateway.client = httpx.Client(base_url=settings.waha_url,
        transport=httpx.MockTransport(lambda r: httpx.Response(422, json=rejection(MISMATCH))))
    service = Service(settings, gateway=gateway, event_transport=receiver)
    try:
        key = 'synthetic-uncertain-identity-422'
        service.store.queue_action(key, 'test-owner', 'profile_set_profile_status',
            {'path': {}, 'query': {}, 'body': {'status': 'private-text'}})
        assert service.process_action()
        assert service.store.send_status(key)['state'] == 'uncertain'
        assert not service.process_action()
    finally:
        gateway.close()
        service.diagnostics.close()


@pytest.mark.parametrize('payload,expected', [
    ({'exception': {'code': 3, 'details': 'private-validation-detail'}}, 'INVALID_ARGUMENT'),
    ({'exception': {'code': 7, 'details': 'private-permission-detail'}}, 'PROVIDER_PERMISSION_DENIED'),
    ({'exception': {'code': 2, 'details': 'info query returned status 403: forbidden'}}, 'PROVIDER_PERMISSION_DENIED'),
    ({'exception': {'code': 2, 'details': 'info query returned status 404: item-not-found'}}, 'PROVIDER_RESOURCE_NOT_FOUND'),
    ({'exception': {'code': 14, 'details': 'private-temporary-failure'}}, 'PROVIDER_UNAVAILABLE'),
    ({'exception': {'code': 2.0, 'details': 'info query returned status 404: item-not-found'}}, 'PROVIDER_UNAVAILABLE'),
])
def test_known_grpc_read_refusals_are_not_an_outage_or_oauth_challenge(app_client, payload, expected):
    app, client = app_client
    gateway, requests = install(app, 500, payload)
    try:
        result = call(client, 'read_whatsapp', {'operation': 'chats_get_chat_message',
            'arguments': {'path': {'chatId': '12345@c.us', 'messageId': 'SYNTHETIC'}}})['result']
        value = result['structuredContent']
        assert result['isError'] is True
        assert value['error_code'] == value['whatsapp_error_code'] == expected
        assert value['gateway_status'] == 500 and len(requests) == 1
        assert value['message'] == result['content'][0]['text']
        assert 'mcp/www_authenticate' not in result['_meta']
        assert 'private-' not in json.dumps(result)
    finally:
        gateway.close()


@pytest.mark.parametrize('status', [401, 403, 429, 503])
def test_gateway_http_refusals_are_not_inferred_from_grpc_text(app_client, status):
    app, client = app_client
    gateway, _ = install(app, status, {'exception': {'code': 7, 'details': 'private-gateway-error'}})
    try:
        result = call(client, 'read_whatsapp', {'operation': 'chats_get_chat_message',
            'arguments': {'path': {'chatId': '12345@c.us', 'messageId': 'SYNTHETIC'}}})['result']
        assert result['structuredContent']['error_code'] == 'PROVIDER_UNAVAILABLE'
        assert result['structuredContent']['gateway_status'] == status
        assert 'mcp/www_authenticate' not in result['_meta']
        assert 'private-' not in json.dumps(result)
    finally:
        gateway.close()


@pytest.mark.parametrize('method,path,specialized', [
    ('POST', '/api/default/chats/overview', True),
    ('POST', '/api/default/channels/search/by-view', True),
    ('POST', '/api/default/channels/search/by-text', True),
    ('POST', '/api/sendText', False),
    ('PUT', PATH, False), ('DELETE', PATH, False),
])
def test_grpc_refusal_uses_the_existing_read_allowlist(app_client, method, path, specialized):
    gateway, requests = install(app_client[0], 500, {'exception': {'code': 3, 'details': 'private'}})
    try:
        with pytest.raises(GatewayUnavailable) as caught:
            gateway.request(method, path)
        assert type(caught.value) is (GatewayReadRejected if specialized else GatewayUnavailable)
        assert len(requests) == 1
        if not specialized:
            assert 'outcome may be uncertain' in str(caught.value)
    finally:
        gateway.close()
