"""Pinned label color rules reject invalid jobs before any provider request."""
from dataclasses import replace
import json

import httpx
import pytest
from starlette.testclient import TestClient

from conftest import call
from test_oauth_contract import headers, grant, challenged
from sally_whatsapp.gateway import Waha
from sally_whatsapp.server import create_app


@pytest.fixture
def label_client(environment):
    settings, receiver, _, token = environment
    settings = replace(settings, live_account_enabled=True, account_actions_enabled=True)
    gateway = Waha(settings)
    gateway.client.close()
    requests = []
    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={'id': 'synthetic-label'})
    gateway.client = httpx.Client(base_url=settings.waha_url, transport=httpx.MockTransport(handle))
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app) as client:
        client.headers.update(headers(grant(token, ['whatsapp:read', 'whatsapp:send'])))
        yield app.state.service, client, requests, token
    assert not receiver.requests


def action(operation, body):
    return {'operation': operation, 'arguments': {
        'path': {'labelId': 'synthetic-label'} if operation == 'labels_update' else {}, 'body': body},
        'idempotency_key': 'synthetic-label-operation-001'}  # gitleaks:allow -- synthetic idempotency identifier, not a credential


# WAHA 90ba445 src/structures/labels.dto.ts:53-78 requires exactly one color
# and resolves colorHex against its literal, case-sensitive 20-color palette.
@pytest.mark.parametrize('operation', ['labels_create', 'labels_update'])
@pytest.mark.parametrize('body', [
    {'name': 'Synthetic'},
    {'name': 'Synthetic', 'color': 0, 'colorHex': '#ff9485'},
    {'name': 'Synthetic', 'colorHex': '#123456'},
    {'name': 'Synthetic', 'colorHex': '#FF9485'},
    {'name': 'Synthetic', 'color': None},
    {'name': 'Synthetic', 'colorHex': None},
    {'color': 0},
])
def test_invalid_label_color_cannot_enter_action_queue(label_client, operation, body):
    service, client, requests, _ = label_client
    result = call(client, 'write_whatsapp', action(operation, body))['result']
    assert result['isError']
    assert requests == [] and not service.process_action()
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM action_jobs').fetchone()[0] == 0


@pytest.mark.parametrize('operation,method,suffix', [
    ('labels_create', 'POST', ''), ('labels_update', 'PUT', '/synthetic-label')])
@pytest.mark.parametrize('color', [{'color': 0}, {'colorHex': '#ff9485'}])
def test_valid_label_color_preserves_value_at_provider_boundary(label_client, operation, method, suffix, color):
    service, client, requests, token = label_client
    body = {'name': 'Synthetic', **color}
    payload = action(operation, body)
    client.headers.update(headers(grant(token, ['whatsapp:read'])))
    assert 'whatsapp:send' in challenged(call(client, 'write_whatsapp', payload)['result'])
    assert requests == [] and not service.process_action()
    client.headers.update(headers(grant(token, ['whatsapp:read', 'whatsapp:send'])))
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'queued'
    assert requests == [] and service.process_action()
    assert len(requests) == 1
    assert requests[0].method == method and requests[0].url.path == '/api/default/labels' + suffix
    assert json.loads(requests[0].content) == body
    assert call(client, 'get_send_status', {'idempotency_key': payload['idempotency_key']})['result']['structuredContent']['state'] == 'submitted'
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'submitted'
    assert not service.process_action() and len(requests) == 1
