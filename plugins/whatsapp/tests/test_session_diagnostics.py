"""Owner-bound account diagnostics through MCP; all HTTP responses are synthetic."""
from dataclasses import replace

import httpx
import pytest
from starlette.testclient import TestClient

from conftest import call
from test_oauth_contract import headers, grant
from sally_whatsapp.gateway import Waha
from sally_whatsapp.server import create_app


# Pinned WAHA 90ba445: sessions.controller.ts:104-135 and
# sessions.dto.ts:381-460. Literal routes and nullable fields are independent
# of the generated operation catalog. Provider enum values remain open.
CASES = [
    ('sessions_fetch_message_capping', 'capping', {
        'cappingStatus': 'UNCAPPED', 'totalQuota': -1, 'usedQuota': 0,
        'cycleStart': None, 'cycleEnd': None, 'mvStatus': None}),
    ('sessions_fetch_reachout_timelock', 'timelock', {
        'enforcementType': 'NONE', 'isActive': False, 'timeEnforcementEnds': None}),
]


@pytest.fixture
def diagnostics_client(environment):
    settings, receiver, _, token = environment
    settings = replace(settings, live_account_enabled=True, session='synthetic-owner-session')
    gateway = Waha(settings)
    gateway.client.close()
    requests, response = [], {}
    def handle(request):
        requests.append(request)
        return httpx.Response(200, json=response)
    gateway.client = httpx.Client(base_url=settings.waha_url, transport=httpx.MockTransport(handle))
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app) as client:
        client.headers.update(headers(grant(token, ['whatsapp:read'])))
        yield app.state.service, client, requests, response, token
    assert not receiver.requests


@pytest.mark.parametrize('operation,suffix,value', CASES)
def test_account_limits_are_readable_without_send_permission(diagnostics_client, operation, suffix, value):
    service, client, requests, response, _ = diagnostics_client
    assert not service.settings.send_enabled and not service.settings.account_actions_enabled
    response.update(value)
    result = call(client, 'read_whatsapp', {'operation': operation})['result']
    assert result['structuredContent'] == {'result': value}
    assert len(requests) == 1
    assert requests[0].method == 'GET'
    assert requests[0].url.path == '/api/sessions/synthetic-owner-session/' + suffix
    assert requests[0].url.query == b'' and requests[0].content == b''
    assert not service.process_action()
    with service.store.db() as db:
        for table in ('action_jobs', 'sends', 'history_jobs'):
            assert db.execute('SELECT count(*) FROM ' + table).fetchone()[0] == 0


@pytest.mark.parametrize('operation,_,__', CASES)
@pytest.mark.parametrize('arguments', [
    {'path': {'session': 'other-owner'}}, {'query': {'session': 'other-owner'}},
    {'body': {'session': 'other-owner'}}, {'method': 'DELETE'},
    {'url': 'https://untrusted.invalid/api/sessions'},
])
def test_diagnostics_never_accept_caller_selected_session_or_route(diagnostics_client, operation, _, __, arguments):
    service, client, requests, _, _ = diagnostics_client
    result = call(client, 'read_whatsapp', {'operation': operation, 'arguments': arguments})['result']
    assert result['isError'] and requests == []
    assert not service.process_action()


@pytest.mark.parametrize('operation,_,__', CASES)
def test_diagnostics_require_owner_and_read_scope(diagnostics_client, operation, _, __):
    service, client, requests, _, token = diagnostics_client
    arguments = {'operation': operation}
    client.headers.update(headers(grant(token, ['whatsapp:read'], sub='another-owner')))
    response = client.post('/mcp', headers={'mcp-method': 'tools/call', 'mcp-name': 'read_whatsapp'},
                           json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                 'params': {'name': 'read_whatsapp', 'arguments': arguments}})
    assert response.status_code == 401 and requests == []
    client.headers.update(headers(grant(token, ['whatsapp:events'])))
    response = client.post('/mcp', headers={'mcp-method': 'tools/call', 'mcp-name': 'read_whatsapp'},
                           json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                 'params': {'name': 'read_whatsapp', 'arguments': arguments}})
    assert response.status_code == 403 and requests == []
    client.headers.update(headers(grant(token, ['whatsapp:read', 'whatsapp:send'])))
    result = call(client, 'write_whatsapp', {**arguments, 'idempotency_key': 'diagnostics-no-action-001'})['result']
    assert result['isError'] and requests == [] and not service.process_action()


@pytest.mark.parametrize('operation', ['sessions_start', 'sessions_logout', 'sessions_list', 'sessions_get'])
def test_read_diagnostics_do_not_expose_session_administration(diagnostics_client, operation):
    _, client, requests, _, _ = diagnostics_client
    assert call(client, 'read_whatsapp', {'operation': operation})['result']['isError']
    assert requests == []
