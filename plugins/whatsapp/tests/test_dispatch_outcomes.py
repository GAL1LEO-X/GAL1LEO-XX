"""Dispatch certainty across the real queue with controlled HTTP transport.

No WhatsApp account or remote provider is contacted. Transport exceptions model
the documented HTTPX boundary, not evidence about a production send.
"""
from dataclasses import replace
import json

import httpx
import pytest

from conftest import call
from test_family_capabilities import full_family_client
from sally_whatsapp import ab_operations
from sally_whatsapp.gateway import DisconnectedGateway, Waha
from sally_whatsapp.operations import OPERATIONS, execute
from sally_whatsapp.server import OperationAction, SendText, Service
from sally_whatsapp.store import Store


KEY = 'synthetic-dispatch-boundary-0001'
CHAT = '199999998@c.us'


def action():
    return OperationAction(operation='messages_send_text',
        arguments={'body': {'chatId': CHAT, 'text': 'Synthetic message'}},
        idempotency_key=KEY)


@pytest.mark.parametrize('acknowledgement', [
    {}, None, False, {'success': True}, {'accepted': True}, {'id': ''},
    {'id': '   '}, {'id': 7}, {'id': {'_serialized': 'synthetic'}},
    {'id': 'synthetic\n'}, {'id': 'x' * 513},
    {'id': 'synthetic', 'success': False},
    {'id': 'synthetic', 'accepted': False},
    {'id': 'synthetic', 'result': False},
    {'id': 'synthetic', 'status': 403},
    {'id': 'synthetic', 'error': 500},
    {'id': 'synthetic', 'outcome': 'uncertain'},
])
@pytest.mark.parametrize('operation', ['messages_send_text', 'status_send_text_status'])
def test_incomplete_message_acknowledgement_stays_uncertain_after_restart(
        full_family_client, acknowledgement, operation):
    service, client, requests, response, _ = full_family_client
    response['value'] = acknowledgement
    payload = action().model_dump()
    if operation == 'status_send_text_status':
        payload.update(operation=operation, arguments={'body': {
            'text': 'Synthetic status', 'backgroundColor': '#FFFFFF', 'font': 1,
            'contacts': [CHAT]}})
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'queued'
    assert service.process_action()
    status = service.store.send_status(KEY)
    assert status['state'] == 'uncertain'
    assert status['provider_id'] is None
    if operation == 'status_send_text_status':
        assert status['delivery']['status'] == 'not_applicable'
        assert status['delivery']['reason'] == 'operation_not_tracked'
    else:
        assert status['delivery']['status'] == 'unavailable'
    assert Store(service.settings.database, recover_inflight=True).send_status(KEY) == status
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'uncertain'
    assert not service.process_action() and len(requests) == 1


@pytest.mark.parametrize('error_type,expected', [
    (httpx.PoolTimeout, 'failed_before_send'),
    (httpx.ConnectTimeout, 'failed_before_send'),
    (httpx.ConnectError, 'failed_before_send'),
    (httpx.WriteTimeout, 'uncertain'),
    (httpx.WriteError, 'uncertain'),
    (httpx.ReadTimeout, 'uncertain'),
    (httpx.ReadError, 'uncertain'),
    (httpx.RemoteProtocolError, 'uncertain'),
])
@pytest.mark.parametrize('queued', [True, False], ids=['queued-operation', 'direct-send'])
def test_transport_certainty_is_persisted_without_automatic_retry(
        environment, error_type, expected, queued):
    settings, receiver, _, _ = environment
    settings = replace(settings, live_account_enabled=True, send_enabled=True,
                       allow_all_destinations=True)
    gateway = Waha(settings)
    gateway.client.close()
    requests = []
    def fail(request):
        requests.append(request)
        raise error_type('private upstream message', request=request)
    gateway.client = httpx.Client(base_url=settings.waha_url,
                                 transport=httpx.MockTransport(fail))
    service = Service(settings, gateway=gateway, event_transport=receiver)
    def invoke():
        return (service.operation(action(), 'test-owner') if queued else
                service.send(SendText(chat_id=CHAT, text='Synthetic message',
                                      idempotency_key=KEY), 'test-owner'))
    try:
        invoke()
        if queued:
            assert service.process_action()
        status = service.store.send_status(KEY)
        assert status['state'] == expected
        assert Store(settings.database, recover_inflight=True).send_status(KEY) == status
        assert invoke()['state'] == expected
        assert not service.process_action() and len(requests) == 1
        assert 'private upstream message' not in json.dumps(status)
    finally:
        gateway.close()


@pytest.mark.parametrize('gateway_kind', ['disabled-waha', 'disconnected'])
def test_locally_disabled_gateway_is_proven_not_sent(environment, gateway_kind):
    settings = environment[0]
    gateway = Waha(settings) if gateway_kind == 'disabled-waha' else DisconnectedGateway()
    try:
        from sally_whatsapp.gateway import GatewayUnavailable
        with pytest.raises(GatewayUnavailable) as caught:
            gateway.request('POST', '/api/sendText', json={'chatId': CHAT, 'text': 'Synthetic'})
        assert type(caught.value).__name__ == 'GatewayNotSent'
        assert 'no provider request made' in str(caught.value)
    finally:
        gateway.close()


def test_gateway_destination_preflight_is_proven_not_sent(environment):
    gateway = Waha(replace(environment[0], live_account_enabled=True))
    gateway.request = lambda *args, **kwargs: pytest.fail('Denied destination must not reach dispatch')
    try:
        from sally_whatsapp.gateway import GatewayUnavailable
        with pytest.raises(GatewayUnavailable) as caught:
            gateway.send(CHAT, 'Synthetic message')
        assert type(caught.value).__name__ == 'GatewayNotSent'
    finally:
        gateway.close()


@pytest.mark.parametrize('value', [
    {'outcome': 'accepted', 'success': False},
    {'success': True, 'accepted': False},
    {'outcome': 'rejected', 'success': True},
    {'outcome': 'accepted', 'result': False},
    {'outcome': 'accepted', 'status': 403},
    {'outcome': 'accepted', 'error': 500},
])
def test_contradictory_ab_acknowledgements_are_uncertain(environment, value):
    settings, _, gateway, _ = environment
    gateway.request = lambda *args, **kwargs: value
    from sally_whatsapp.gateway import GatewayUnavailable
    with pytest.raises(GatewayUnavailable, match='uncertain'):
        execute(gateway, settings, OPERATIONS['contacts_block'],
                {'body': {'contactId': CHAT}, 'path': {}, 'query': {}},
                intent=ab_operations.durable_intent('test-owner', KEY, 1792600000))


@pytest.mark.parametrize('operation', [
    'messages_send_buttons_reply', 'chats_delete_chat', 'chats_clear_messages',
    'groups_delete_group', 'channels_delete',
])
def test_unsupported_operation_has_structured_limitation_without_dispatch(
        full_family_client, operation):
    service, client, requests, _, _ = full_family_client
    value = call(client, 'write_whatsapp', {'operation': operation,
        'arguments': {}, 'idempotency_key': KEY})['result']
    assert value['isError']
    detail = value['structuredContent']
    assert detail['error_code'] == 'OPERATION_UNSUPPORTED'
    assert detail['operation'] == operation
    assert detail['capability'] == 'unsupported_gows'
    assert detail['retryable'] is False
    assert service.store.send_status(KEY) is None
    assert not requests and not service.process_action()


@pytest.mark.parametrize('payload', [None, [], {}, {'status': None}, {'status': False},
                                      {'status': {'private': 'upstream'}}])
def test_partial_status_response_replaces_stale_connected_observation(environment, payload):
    settings, receiver, _, _ = environment
    settings = replace(settings, live_account_enabled=True)
    gateway = Waha(settings)
    gateway.client.close()
    response = {'value': {'status': 'WORKING'}}
    gateway.client = httpx.Client(base_url=settings.waha_url,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=response['value'])))
    service = Service(settings, gateway=gateway, event_transport=receiver)
    try:
        service.poll_connection()
        assert service.connection_status()['connection'] == 'WORKING'
        response['value'] = payload
        service.poll_connection()
        current = service.connection_status()
        assert current['connection'] == 'UNREACHABLE'
        assert current['connection_fresh']
        response['value'] = {'status': 'WORKING'}
        service.poll_connection()
        recovered = service.connection_status()
        assert recovered['connection'] == 'WORKING'
        assert recovered['recovery_diagnostics']['warning_kind'] != 'connection_review_required'
    finally:
        gateway.close()


def test_unknown_provider_status_is_safe_unknown_without_logging_payload(environment):
    settings = replace(environment[0], live_account_enabled=True)
    gateway = Waha(settings)
    gateway.client.close()
    gateway.client = httpx.Client(base_url=settings.waha_url,
        transport=httpx.MockTransport(lambda request: httpx.Response(200,
            json={'status': 'new provider status with private data'})))
    try:
        assert gateway.status() == 'UNKNOWN'
    finally:
        gateway.close()


@pytest.mark.parametrize('acknowledgement', [
    {'id': 'synthetic', 'success': False}, {'id': 'synthetic', 'accepted': False},
    {'id': 'synthetic', 'outcome': 'uncertain'}, {'id': '  '}, {'id': 'synthetic\n'},
    {'id': 'synthetic', 'result': False}, {'id': 'synthetic', 'status': 403},
    {'id': 'synthetic', 'error': 500},
])
def test_direct_send_uses_same_acknowledgement_rules(environment, acknowledgement):
    settings, receiver, gateway, _ = environment
    settings = replace(settings, live_account_enabled=True, send_enabled=True,
                       allow_all_destinations=True)
    calls = []
    def send(*args):
        calls.append(args)
        return acknowledgement
    gateway.send = send
    service = Service(settings, gateway=gateway, event_transport=receiver)
    args = SendText(chat_id=CHAT, text='Synthetic message', idempotency_key=KEY)
    assert service.send(args, 'test-owner')['state'] == 'uncertain'
    assert service.send(args, 'test-owner')['state'] == 'uncertain'
    assert len(calls) == 1


@pytest.mark.parametrize('operation,arguments,response_value,outcome', [
    ('groups_set_subject', {'path': {'id': '199999999@g.us'}, 'body': {'subject': 'Synthetic'}},
     False, 'rejected'),
    ('groups_set_description', {'path': {'id': '199999999@g.us'}, 'body': {'description': 'Synthetic'}},
     {'success': False, 'body': 'private echo'}, 'rejected'),
    ('groups_add_participants', {'path': {'id': '199999999@g.us'},
        'body': {'participants': [{'id': CHAT}, {'id': '199999997@c.us'}]}},
     [{'id': CHAT, 'status': 200}, {'id': '199999997@c.us', 'status': 403}], 'partial'),
    ('labels_delete', {'path': {'labelId': '7'}}, {'result': False}, 'rejected'),
])
def test_negative_or_partial_administrative_results_are_explicit_and_never_retried(
        full_family_client, operation, arguments, response_value, outcome):
    service, client, requests, response, _ = full_family_client
    response['value'] = response_value
    payload = {'operation': operation, 'arguments': arguments, 'idempotency_key': KEY}
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'queued'
    assert service.process_action()
    status = service.store.send_status(KEY)
    assert status['state'] == 'uncertain'
    assert status['provider_outcome'] == outcome
    assert 'private echo' not in json.dumps(status)
    assert Store(service.settings.database, recover_inflight=True).send_status(KEY) == status
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'uncertain'
    assert not service.process_action() and len(requests) == 1


@pytest.mark.parametrize('value,expected', [
    (None, 'unverified'), ({}, 'unverified'), ([], 'unverified'),
    ({'id': 'synthetic'}, 'unverified'), ({'success': True}, 'accepted'),
    ({'success': False}, 'rejected'), ({'status': 403}, 'rejected'),
    ({'success': True, 'status': 403}, 'uncertain'),
    ([{'success': True}, {'success': False}], 'partial'),
    ([{'success': False}, {}], 'uncertain'),
])
def test_provider_outcome_never_infers_missing_evidence(value, expected):
    from sally_whatsapp.operation_outcomes import provider_outcome
    assert provider_outcome(value) == expected


def test_empty_successful_http_body_does_not_fabricate_provider_acceptance(full_family_client):
    service, client, requests, response, _ = full_family_client
    response.update(status=204, value=None)
    payload = {'operation': 'labels_delete', 'arguments': {'path': {'labelId': '7'}},
               'idempotency_key': KEY}
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'queued'
    assert service.process_action()
    status = service.store.send_status(KEY)
    assert status['state'] == 'submitted'
    assert status['provider_outcome'] == 'unverified'
    assert status['result'] == {}
    assert not service.process_action() and len(requests) == 1
