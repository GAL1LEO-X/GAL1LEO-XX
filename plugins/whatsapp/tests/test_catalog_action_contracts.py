"""Pinned group responses, list preflight, event units and removed poll writes.

All HTTP exchanges are MockTransport calls; no WhatsApp session is contacted.
"""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from conftest import call, rpc
from test_family_capabilities import full_family_client
from test_operation_audit_fixes import generator_source
from sally_whatsapp.operations import OPERATIONS
from sally_whatsapp.store import Store


GROUP = '199999999@g.us'
CONTACT = '199999998@c.us'
GROUP_BODIES = {
    'groups_create_group': {'name': 'Synthetic group', 'participants': [{'id': CONTACT}]},
    'groups_join_group': {'code': 'SYNTHETIC-INVITE'},
}


def list_arguments(chat=CONTACT):
    return {'body': {'chatId': chat, 'message': {
        'title': 'Synthetic list', 'button': 'Select',
        'sections': [{'title': 'Section', 'rows': [{'title': 'A', 'rowId': 'a'}]}]}}}


def calendar_arguments(start=1792609200, end=1792611000):
    event = {'name': 'Synthetic event', 'startTime': start}
    if end is not None:
        event['endTime'] = end
    return {'body': {'chatId': GROUP, 'event': event}}


@pytest.mark.parametrize('operation,provider_value', [
    ('groups_create_group', {'JID': GROUP, 'Name': 'Private name', 'OwnerJID': CONTACT}),
    ('groups_create_group', {'JID': '123456-789012@g.us', 'Name': 'Legacy group'}),
    ('groups_join_group', GROUP),
    ('groups_create_group', {'id': GROUP, 'JID': GROUP, 'body': 'Private echo'}),
    ('groups_join_group', {'id': GROUP, 'success': True, 'body': 'Private echo'}),
])
def test_group_result_id_survives_queue_projection_restart_and_retry(
        full_family_client, operation, provider_value):
    service, client, requests, response, _ = full_family_client
    response['value'] = provider_value
    payload = {'operation': operation, 'arguments': {'body': GROUP_BODIES[operation]},
               'idempotency_key': 'synthetic-group-result-0001'}
    queued = call(client, 'write_whatsapp', payload)['result']
    assert queued['structuredContent']['state'] == 'queued'
    assert service.process_action()
    expected = provider_value if isinstance(provider_value, str) else provider_value.get('JID', provider_value.get('id'))
    status = call(client, 'get_send_status', {'idempotency_key': payload['idempotency_key']})['result']['structuredContent']
    assert status['state'] == 'submitted'
    assert status['provider_id'] == expected
    assert status['result'] == {'id': expected, **({'success': True} if isinstance(provider_value, dict) and provider_value.get('success') else {})}
    assert 'Private' not in json.dumps(status)
    reopened = Store(service.store.path)
    assert reopened.send_status(payload['idempotency_key']) == status
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'submitted'
    assert not service.process_action() and len(requests) == 1


@pytest.mark.parametrize('provider_value', [
    {'JID': CONTACT, 'Name': 'Private echo'},
    {'OwnerJID': GROUP, 'Name': 'Private echo'},
    {'JID': GROUP, 'id': '188888888@g.us'},
    {'JID': None, 'id': GROUP},
    {'id': {'_serialized': GROUP}},
    {'JID': GROUP + '\n'},
    {'JID': '9' * 80 + '@g.us'},
    'not-a-group',
    None,
])
def test_group_acceptance_without_proven_id_is_uncertain_and_never_retried(
        full_family_client, provider_value):
    service, client, requests, response, _ = full_family_client
    response['value'] = provider_value
    payload = {'operation': 'groups_create_group',
               'arguments': {'body': GROUP_BODIES['groups_create_group']},
               'idempotency_key': 'synthetic-group-no-id-0001'}
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'queued'
    assert service.process_action()
    status = service.store.send_status(payload['idempotency_key'])
    assert status['state'] == 'uncertain'
    assert status['provider_id'] is None and status['result'] == {}
    assert status['group_identity']['state'] == 'unknown'
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'uncertain'
    assert not service.process_action() and len(requests) == 1


def test_group_read_response_stays_independent_of_action_projection(full_family_client):
    _, client, _, response, _ = full_family_client
    response['value'] = {'JID': GROUP, 'Name': 'Synthetic group', 'Participants': [{'JID': CONTACT}]}
    result = call(client, 'read_whatsapp', {'operation': 'groups_get_group',
                  'arguments': {'path': {'id': GROUP}}})['result']['structuredContent']
    assert result['result'] == response['value']
    assert result['source'] == 'provider_group_cache'
    assert isinstance(result['retrieved_at'], float)
    assert result['freshness'] == {'state': 'unverified', 'may_be_stale_after_mutation': True,
                                   'refresh_operation': 'groups_refresh_groups'}


@pytest.mark.parametrize('chat', [GROUP, 'status@broadcast', '199999999@newsletter',
                                CONTACT + '\n', 'not-a-chat', '', '123@c.us'])
def test_list_invalid_destination_is_rejected_before_queue(full_family_client, chat):
    service, client, requests, _, _ = full_family_client
    result = call(client, 'write_whatsapp', {'operation': 'messages_send_list',
                  'arguments': list_arguments(chat), 'idempotency_key': 'synthetic-list-denied-0001'})['result']
    assert result['isError'] and requests == []
    assert service.store.send_status('synthetic-list-denied-0001') is None
    assert not service.process_action()


def test_legacy_queued_group_list_is_stopped_by_worker_preflight(full_family_client):
    service, _, requests, _, _ = full_family_client
    values = {'path': {}, 'query': {}, **list_arguments(GROUP)}
    service.store.queue_action('synthetic-legacy-list-0001', service.settings.owner_subject,
                               'messages_send_list', values)
    assert service.process_action()
    assert service.store.send_status('synthetic-legacy-list-0001')['state'] == 'failed_before_send'
    assert requests == [] and not service.process_action()


@pytest.mark.parametrize('chat', [CONTACT, '199999998@lid', '199999998@s.whatsapp.net'])
def test_list_direct_destination_and_fields_reach_provider_once(full_family_client, chat):
    service, client, requests, response, _ = full_family_client
    response['value'] = {'id': 'true_' + chat + '_SYNTHETIC'}
    payload = {'operation': 'messages_send_list', 'arguments': list_arguments(chat),
               'idempotency_key': 'synthetic-list-direct-0001'}
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'queued'
    assert service.process_action()
    assert requests[0].url.path == '/api/sendList'
    assert json.loads(requests[0].content) == {**payload['arguments']['body'], 'session': 'default'}
    assert service.store.send_status(payload['idempotency_key'])['state'] == 'submitted'
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'submitted'
    assert not service.process_action() and len(requests) == 1


@pytest.mark.parametrize('start,end', [
    (1792609200000, 1792611000000), (1792609200.5, 1792611000),
    (1792609200, 1792611000.5), (-1, 0), (1792609200, -1),
    (1792609200, 1792609199), (True, 1792611000), (1792609200, True),
    (253402300800, None), (1792609200, 253402300800),
])
def test_event_invalid_units_range_or_order_fail_before_queue(full_family_client, start, end):
    service, client, requests, _, _ = full_family_client
    result = call(client, 'write_whatsapp', {'operation': 'calendar_send_event',
                  'arguments': calendar_arguments(start, end),
                  'idempotency_key': 'synthetic-event-invalid-0001'})['result']
    assert result['isError'] and requests == []
    assert service.store.send_status('synthetic-event-invalid-0001') is None


@pytest.mark.parametrize('start,end', [(1792609200, 1792611000), (1792609200, None),
                                     (0, 0), (253402300799, None)])
def test_event_unix_seconds_are_preserved_without_timezone_conversion(
        full_family_client, start, end):
    service, client, requests, response, _ = full_family_client
    response['value'] = {'id': 'true_' + GROUP + '_SYNTHETIC'}
    values = calendar_arguments(start, end)
    payload = {'operation': 'calendar_send_event', 'arguments': values,
               'idempotency_key': 'synthetic-event-valid-0001'}
    assert call(client, 'write_whatsapp', payload)['result']['structuredContent']['state'] == 'queued'
    assert service.process_action()
    assert json.loads(requests[0].content) == values['body']
    assert requests[0].url.path == '/api/default/events'


def test_legacy_event_rechecks_order_before_dispatch(full_family_client):
    service, _, requests, _, _ = full_family_client
    values = {'path': {}, 'query': {}, **calendar_arguments(1792609200, 1792609199)}
    service.store.queue_action('synthetic-legacy-event-0001', service.settings.owner_subject,
                               'calendar_send_event', values)
    assert service.process_action()
    assert service.store.send_status('synthetic-legacy-event-0001')['state'] == 'failed_before_send'
    assert requests == []


@pytest.mark.parametrize('operation', ['messages_send_poll', 'messages_send_poll_vote'])
def test_poll_writes_absent_from_discovery_and_rejected_by_both_wrappers(full_family_client, operation):
    service, client, requests, _, _ = full_family_client
    tools = rpc(client, 'tools/list')['result']['tools']
    assert len(tools) == 27
    for name in ('get_operation_schema', 'read_whatsapp', 'write_whatsapp', 'send_media'):
        tool = next(item for item in tools if item['name'] == name)
        assert operation not in json.dumps(tool['inputSchema'])
    capabilities = call(client, 'get_capabilities', {})['result']['structuredContent']['operations']
    assert len(capabilities) == 120
    assert operation not in {item['operation'] for item in capabilities}
    probe_count = len(requests)
    for tool, values in [
        ('get_operation_schema', {'operation': operation}),
        ('read_whatsapp', {'operation': operation, 'arguments': {}}),
        ('write_whatsapp', {'operation': operation, 'arguments': {}, 'idempotency_key': 'removed-poll-action-0001'}),
    ]:
        assert call(client, tool, values)['result']['isError']
    assert len(requests) == probe_count and not service.process_action()


def test_generator_preserves_list_and_event_preflight_contracts(tmp_path):
    source = generator_source()
    source['paths'].update({
        '/api/sendList': {'post': {'operationId': 'ChattingController_sendList',
            'requestBody': {'content': {'application/json': {'schema': {
                'type': 'object', 'properties': {'chatId': {'type': 'string'}}}}}}}},
        '/api/{session}/events': {'post': {'operationId': 'EventsController_sendEvent',
            'requestBody': {'content': {'application/json': {'schema': {
                'type': 'object', 'properties': {'event': {'type': 'object', 'properties': {
                    'startTime': {'type': 'number'}, 'endTime': {'type': 'number'}}}}}}}}}},
    })
    input_path, output_path = tmp_path/'openapi.json', tmp_path/'operations.json'
    input_path.write_text(json.dumps(source))
    proc = subprocess.run([sys.executable, str(Path(__file__).parents[1]/'scripts/build_operations.py'),
                           str(input_path), '--output', str(output_path)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    actual = json.loads(output_path.read_text())
    assert set(actual) == {'messages_send_list', 'calendar_send_event'}
    chat = actual['messages_send_list']['schema']['properties']['body']['properties']['chatId']
    assert chat == OPERATIONS['messages_send_list']['schema']['properties']['body']['properties']['chatId']
    event = actual['calendar_send_event']['schema']['properties']['body']['properties']['event']['properties']
    assert event == {key: OPERATIONS['calendar_send_event']['schema']['properties']['body']['properties']['event']['properties'][key]
                     for key in ('startTime', 'endTime')}
