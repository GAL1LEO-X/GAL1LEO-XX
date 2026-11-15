"""HTTP completion does not make malformed or unparseable JSON a valid result."""
from dataclasses import replace
import json
import sys

import httpx
import pytest

from conftest import call
from sally_whatsapp.diagnostics import Diagnostics
from sally_whatsapp.gateway import Waha, GatewayUnavailable, GatewayNotSent


DEEP_JSON = b'[' * 10000 + b'0' + b']' * 10000


def gateway_with_response(settings, status, body, *, parser_limit=False):
    gateway = Waha(replace(settings, live_account_enabled=True))
    gateway.client.close()
    requests = []
    def respond(request):
        requests.append(request)
        response = httpx.Response(status, content=body, headers={'content-type': 'application/json'})
        if parser_limit:
            # CPython 3.14 accepts this depth, while 3.13 raises. Model the
            # parser's failure explicitly so both runtimes exercise the same
            # error/uncertainty contract; the real 3.13 payload is tested below.
            def cannot_decode():
                raise RecursionError('private-parser-detail')
            response.json = cannot_decode
        return response
    gateway.client = httpx.Client(base_url=settings.waha_url, transport=httpx.MockTransport(respond))
    return gateway, requests


@pytest.mark.parametrize('status', [200, 500])
@pytest.mark.parametrize('method', ['GET', 'POST'])
@pytest.mark.parametrize('body', [DEEP_JSON, b'{"private-provider-detail":"unfinished', b'<html>private-provider-detail</html>'],
                         ids=['deep-json', 'invalid-json', 'html'])
def test_unparseable_provider_reply_keeps_safe_diagnostics_and_write_uncertainty(environment, status, method, body):
    settings, *_ = environment
    gateway, requests = gateway_with_response(settings, status, body, parser_limit=body == DEEP_JSON)
    gateway.diagnostics = Diagnostics(settings)
    try:
        with pytest.raises(GatewayUnavailable) as caught:
            gateway.request(method, '/api/default/groups/12345%40g.us/participants/join-requests')
        assert type(caught.value) is GatewayUnavailable
        assert not isinstance(caught.value, GatewayNotSent)
        assert caught.value.status_code == status
        assert caught.value.provider_error_kind == 'invalid_provider_response'
        assert ('outcome may be uncertain' in str(caught.value)) == (method == 'POST')
        assert len(requests) == 1
        rows = [json.loads(line) for line in (settings.database.parent/'diagnostics/events.jsonl').read_text().splitlines()]
        failure = rows[-1]
        assert failure['event'] == 'gateway.failed' and failure['status'] == status
        assert failure['provider_error_kind'] == 'invalid_provider_response'
        assert 'private-' not in str(caught.value) + json.dumps(rows)
    finally:
        gateway.close()
        gateway.diagnostics.close()


def test_http_200_deep_json_returns_provider_error_through_mcp(app_client):
    app, client = app_client
    gateway, requests = gateway_with_response(app.state.service.settings, 200, DEEP_JSON, parser_limit=True)
    app.state.service.gateway = gateway
    gateway.diagnostics = app.state.service.diagnostics
    try:
        result = call(client, 'read_whatsapp', {'operation': 'chats_get_chat_message',
            'arguments': {'path': {'chatId': '12345@c.us', 'messageId': 'SYNTHETIC'}}})['result']
        assert result['isError'] is True
        value = result['structuredContent']
        assert value['error_code'] == value['whatsapp_error_code'] == 'PROVIDER_UNAVAILABLE'
        assert value['provider_error_kind'] == 'invalid_provider_response'
        assert value['gateway_status'] == 200 and len(requests) == 1
        assert value['request_id'] == result['_meta']['whatsapp/request_id']
    finally:
        gateway.close()


def test_success_http_with_deep_json_never_makes_a_write_retryable(environment):
    from sally_whatsapp.server import Service
    settings, receiver, _, _ = environment
    settings = replace(settings, live_account_enabled=True, account_actions_enabled=True)
    gateway, requests = gateway_with_response(settings, 200, DEEP_JSON, parser_limit=True)
    service = Service(settings, gateway=gateway, event_transport=receiver)
    try:
        key = 'synthetic-uncertain-deep-json'
        service.store.queue_action(key, 'test-owner', 'profile_set_profile_status',
            {'path': {}, 'query': {}, 'body': {'status': 'private-text'}})
        assert service.process_action()
        assert service.store.send_status(key)['state'] == 'uncertain'
        assert not service.process_action() and len(requests) == 1
    finally:
        gateway.close()
        service.diagnostics.close()


def test_real_deep_json_obeys_the_runtime_parser_without_forcing_a_failure(environment):
    settings, *_ = environment
    gateway, requests = gateway_with_response(settings, 200, DEEP_JSON)
    try:
        if sys.version_info[:2] == (3, 13):
            # Reproduced with the deployment runtime, without a parser stub.
            with pytest.raises(GatewayUnavailable) as caught:
                gateway.request('GET', '/api/default/profile')
            assert caught.value.provider_error_kind == 'invalid_provider_response'
            assert caught.value.status_code == 200
        else:
            # 3.14's parser accepts this fixture; do not invent a provider
            # failure or introduce a new arbitrary depth limit for valid JSON.
            value = gateway.request('GET', '/api/default/profile')
            for _ in range(10000):
                assert isinstance(value, list) and len(value) == 1
                value = value[0]
            assert value == 0
        assert len(requests) == 1
    finally:
        gateway.close()
