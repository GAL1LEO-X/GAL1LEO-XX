"""Synthetic gateway/MCP regressions: no real WhatsApp connection or actions."""
from dataclasses import replace
import asyncio
import json

import httpx
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from conftest import call
from sally_whatsapp.gateway import Waha, GatewayUnavailable, GroupPermissionDenied, GatewayReadRejected
from sally_whatsapp.server import create_app


PATH = '/api/default/groups/123456789%40g.us/participants/join-requests'
REASON = 'info query returned status 403: forbidden'


def refusal():
    return {'exception': {'code': 2, 'details': REASON, 'message': '2 UNKNOWN: ' + REASON,
                          'stack': 'private-upstream-stack'},
            'request': {'body': 'private-upstream-body'}}


def mocked_gateway(settings, handler):
    gateway = Waha(replace(settings, live_account_enabled=True))
    gateway.client.close()
    gateway.client = httpx.Client(base_url=settings.waha_url, transport=httpx.MockTransport(handler))
    return gateway


def install(app, handler):
    gateway = mocked_gateway(app.state.service.settings, handler)
    gateway.diagnostics = app.state.service.diagnostics
    app.state.service.gateway = gateway
    return gateway


def query(client):
    return call(client, 'read_whatsapp', {'operation': 'groups_get_group_join_requests',
        'arguments': {'path': {'id': '123456789@g.us'}}})['result']


@pytest.mark.parametrize('field', ['details', 'message'])
def test_iq_refusal_has_safe_group_error(environment, field):
    payload = refusal()
    del payload['exception']['message' if field == 'details' else 'details']
    gateway = mocked_gateway(environment[0], lambda request: httpx.Response(500, json=payload))
    try:
        with pytest.raises(GroupPermissionDenied) as caught:
            gateway.request('GET', PATH)
        assert caught.value.status_code == 500
        assert 'group administrator' in str(caught.value)
        assert 'uncertain' not in str(caught.value)
        assert 'private-upstream' not in str(caught.value)
    finally:
        gateway.close()


def test_non_admin_mcp_error_is_not_an_oauth_challenge_or_action(app_client):
    app, client = app_client
    observed = []
    def handler(request):
        observed.append(request.method)
        return httpx.Response(500, json=refusal())
    install(app, handler)
    value = query(client)
    assert value['isError'] is True
    assert value['structuredContent'] == {
        'error_code': 'WHATSAPP_GROUP_PERMISSION_DENIED',
        'whatsapp_error_code': 'WHATSAPP_GROUP_PERMISSION_DENIED',
        'message': value['content'][0]['text'],
        'operation': 'groups_get_group_join_requests', 'required_role': 'admin',
        'gateway_status': 500, 'whatsapp_status': 403,
    }
    assert 'mcp/www_authenticate' not in value.get('_meta', {})
    assert observed == ['GET']
    assert 'private-upstream' not in json.dumps(value)
    assert 'uncertain' not in json.dumps(value)
    with app.state.service.store.db() as db:
        assert db.execute('SELECT count(*) FROM sends').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM action_jobs').fetchone()[0] == 0
    logs = (app.state.service.settings.database.parent/'diagnostics/events.jsonl').read_text()
    assert 'GROUP_PERMISSION_DENIED' in logs
    assert 'private-upstream' not in logs


@pytest.mark.parametrize('requests', [[], [{'requesterId': '12345@lid', 'requestMethod': 'invite_link', 'timestamp': 10}]])
def test_admin_response_remains_successful(app_client, requests):
    app, client = app_client
    install(app, lambda request: httpx.Response(200, json=requests))
    value = query(client)
    assert value.get('isError') is not True
    assert value['structuredContent'] == {'result': requests}


@pytest.mark.parametrize('mode', ['auto', 'legacy'])
@pytest.mark.parametrize('status,payload,expected', [
    (500, refusal(), 'denied'),
    (200, [], 'success'),
    (200, [{'requesterId': '12345@lid', 'requestMethod': 'invite_link', 'timestamp': 10}], 'success'),
    (500, {'exception': {'code': 2, 'details': 'info query returned status 500: internal-server-error'}}, 'other'),
])
def test_group_error_contract_through_official_mcp_client(environment, mode, status, payload, expected):
    """Isolated HTTP/MCP round trip, not an OpenAI host/normalization simulation."""
    settings, receiver, gateway, token = environment
    app = create_app(replace(settings, allowed_hosts=['bridge.example']), gateway=gateway,
                     event_transport=receiver, start_worker=False)
    observed = []
    async def exercise():
        async with app.router.lifespan_context(app):
            def handler(request):
                observed.append(request.method)
                assert request.url.path == '/api/default/groups/123456789@g.us/participants/join-requests'
                return httpx.Response(status, json=payload)
            install(app, handler)
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),
                                         headers={'Authorization': 'Bearer ' + token()}) as http:
                async with Client(streamable_http_client('https://bridge.example/mcp', http_client=http),
                                  mode=mode) as client:
                    result = await client.call_tool('read_whatsapp', {
                        'operation': 'groups_get_group_join_requests',
                        'arguments': {'path': {'id': '123456789@g.us'}}})
                    value = result.structured_content or {}
                    if expected == 'denied':
                        assert result.is_error is True
                        assert value['error_code'] == value['whatsapp_error_code'] == 'WHATSAPP_GROUP_PERMISSION_DENIED'
                        assert value['required_role'] == 'admin'
                        assert value['gateway_status'] == 500 and value['whatsapp_status'] == 403
                        assert result.content[0].text == value['message']
                        assert 'mcp/www_authenticate' not in (result.meta or {})
                    elif expected == 'success':
                        assert result.is_error is not True
                        assert value == {'result': payload}
                    else:
                        assert result.is_error is True
                        assert value['error_code'] == value['whatsapp_error_code'] == 'PROVIDER_UNAVAILABLE'
                        assert value['gateway_status'] == 500
                        assert value['operation'] == 'groups_get_group_join_requests'
                        assert 'required_role' not in value and 'whatsapp_status' not in value
                        assert result.content[0].text == 'WAHA read request failed'
                    serialized = result.model_dump_json(by_alias=True)
                    assert 'private-upstream' not in serialized and 'uncertain' not in serialized
    asyncio.run(exercise())
    assert observed == ['GET']
    with app.state.service.store.db() as db:
        assert db.execute('SELECT count(*) FROM sends').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM action_jobs').fetchone()[0] == 0


def test_missing_oauth_read_scope_still_requests_consent(app_client, environment):
    app, client = app_client
    def no_gateway_request(request):
        pytest.fail('Missing OAuth scope must be checked before any gateway query')
    install(app, no_gateway_request)
    client.headers['Authorization'] = 'Bearer ' + environment[3](scope='whatsapp:events')
    response = client.post('/mcp', headers={'mcp-method': 'tools/call', 'mcp-name': 'read_whatsapp'},
        json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
            'name': 'read_whatsapp', 'arguments': {'operation': 'groups_get_group_join_requests',
                'arguments': {'path': {'id': '123456789@g.us'}}}}})
    assert response.status_code == 403
    assert response.json()['error'] == 'insufficient_scope'
    assert 'whatsapp:read' in response.json()['error_description']


@pytest.mark.parametrize('status,payload', [
    (403, refusal()),  # A gateway HTTP 403 is not the observed GOWS wrapper.
    (500, {'exception': {'code': 2, 'details': 'info query returned status 500: internal-server-error'}}),
    (500, {'exception': {'code': 7, 'details': REASON}}),
    (500, {'exception': {'code': 2, 'details': REASON + ' private-suffix'}}),
    (500, {'exception': {'code': 2, 'details': 'info query returned status 404: item-not-found'}}),
    (500, []),
    (500, {'exception': []}),
    (500, {'exception': {'code': 2, 'details': REASON}, 'padding': 'x'*65536}),
])
def test_other_failures_are_not_misclassified(environment, status, payload):
    gateway = mocked_gateway(environment[0], lambda request: httpx.Response(status, json=payload))
    try:
        with pytest.raises(GatewayUnavailable) as caught:
            gateway.request('GET', PATH)
        # Recognized provider read refusals have their own public code; they
        # still must not be turned into this route's group-admin diagnosis.
        expected = GatewayReadRejected if payload in (
            {'exception': {'code': 7, 'details': REASON}},
            {'exception': {'code': 2, 'details': 'info query returned status 404: item-not-found'}},
        ) else GatewayUnavailable
        assert type(caught.value) is expected
        assert caught.value.status_code == status
        assert 'uncertain' not in str(caught.value)
        assert 'private-suffix' not in str(caught.value)
    finally:
        gateway.close()


@pytest.mark.parametrize('response', [
    lambda request: httpx.Response(500, text='private-not-json'),
    lambda request: httpx.Response(200, text='private-not-json'),
    lambda request: (_ for _ in ()).throw(httpx.ReadTimeout('private-timeout')),
])
def test_malformed_or_timeout_read_errors_are_safe(environment, response):
    gateway = mocked_gateway(environment[0], response)
    try:
        with pytest.raises(GatewayUnavailable) as caught:
            gateway.request('GET', PATH)
        assert type(caught.value) is GatewayUnavailable
        assert str(caught.value) == 'WAHA read request failed'
    finally:
        gateway.close()


def test_other_read_route_does_not_claim_admin_is_required(environment):
    gateway = mocked_gateway(environment[0], lambda request: httpx.Response(500, json=refusal()))
    try:
        with pytest.raises(GatewayUnavailable) as caught:
            gateway.request('GET', '/api/default/groups/123456789%40g.us')
        assert type(caught.value) is GatewayReadRejected
        assert caught.value.error_code == 'PROVIDER_PERMISSION_DENIED'
        assert 'administrator' not in str(caught.value)
    finally:
        gateway.close()


def test_write_failure_preserves_uncertain_outcome(environment):
    gateway = mocked_gateway(environment[0], lambda request: httpx.Response(500, json=refusal()))
    try:
        with pytest.raises(GatewayUnavailable) as caught:
            gateway.request('POST', PATH + '/approve', json={'participants': []})
        assert type(caught.value) is GatewayUnavailable
        assert caught.value.status_code == 500
        assert 'outbound outcome may be uncertain' in str(caught.value)
    finally:
        gateway.close()


def test_invalid_arguments_still_fail_before_gateway(app_client):
    app, client = app_client
    install(app, lambda request: pytest.fail('Invalid arguments must not reach the gateway'))
    value = call(client, 'read_whatsapp', {'operation': 'groups_get_group_join_requests',
        'arguments': {'path': {'id': '../invalid'}}})['result']
    assert value['isError'] is True
    assert value.get('structuredContent', {}).get('error_code') != 'WHATSAPP_GROUP_PERMISSION_DENIED'
    assert 'whatsapp_error_code' not in value.get('structuredContent', {})
