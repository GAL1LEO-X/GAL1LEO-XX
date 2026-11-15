"""QA174 contract boundaries, using synthetic state and no live provider.

The source fixture below transcribes the six relevant WAHA 2026.9.2 OpenAPI
routes/DTOs. It deliberately includes Swagger's required Contact.vcard and
ChannelSearch.startCursor mistakes; expected behavior is tested independently
through validation, dispatch and queue admission.
"""
import asyncio
import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from sally_whatsapp import ab_operations
from sally_whatsapp.operations import OPERATIONS, OperationArgumentError, validate_operation
from sally_whatsapp.server import OperationAction, OperationArguments
from test_mcp_resource_reads import dispatch, mcp_app
from test_operation_audit_fixes import enabled_service


CHAT = 'fixture@g.us'
VCARD = 'BEGIN:VCARD\nVERSION:3.0\nFN:Synthetic\nEND:VCARD'


def pinned_contract_source():
    schemas = {
        'VCardContact': {'type': 'object', 'properties': {
            'vcard': {'type': 'string', 'description': 'The vcard string'}}, 'required': ['vcard']},
        'Contact': {'type': 'object', 'properties': {
            'fullName': {'type': 'string', 'description': 'The full name of the contact'},
            'organization': {'type': 'string', 'description': 'The organization of the contact'},
            'phoneNumber': {'type': 'string', 'description': 'The phone number of the contact'},
            'whatsappId': {'type': 'string', 'description': 'The whatsapp id of the contact. DO NOT add + or @c.us'},
            'vcard': {'type': 'string', 'default': None}},
            'required': ['fullName', 'phoneNumber', 'vcard']},
        'MessageContactVcardRequest': {'type': 'object', 'properties': {
            'session': {'type': 'string'}, 'chatId': {'type': 'string'},
            'id': {'type': 'string', 'description': 'Pre-generated message id'},
            'contacts': {'type': 'array', 'items': {'oneOf': [
                {'$ref': '#/components/schemas/VCardContact'}, {'$ref': '#/components/schemas/Contact'}]}},
            'reply_to': {'type': 'string', 'description': 'The ID of the message to reply to - false_11111111111@c.us_AAAAAAAAAAAAAAAAAAAA'}},
            'required': ['session', 'chatId', 'contacts']},
        'ChannelSearchByView': {'type': 'object', 'properties': {
            'view': {'type': 'string'}, 'countries': {'type': 'array', 'items': {'type': 'string'}},
            'categories': {'type': 'array', 'items': {'type': 'string'}},
            'limit': {'type': 'number', 'default': 50}, 'startCursor': {'type': 'string', 'default': ''}},
            'required': ['view', 'countries', 'categories', 'limit', 'startCursor']},
        'ChannelSearchByText': {'type': 'object', 'properties': {
            'text': {'type': 'string'}, 'categories': {'type': 'array', 'items': {'type': 'string'}},
            'limit': {'type': 'number', 'default': 50}, 'startCursor': {'type': 'string', 'default': ''}},
            'required': ['text', 'categories', 'limit', 'startCursor']},
        'LabelBody': {'type': 'object', 'properties': {
            'name': {'type': 'string', 'description': 'Label name'},
            'colorHex': {'type': 'string', 'description': 'Color in hex'},
            'color': {'type': 'number', 'description': 'Color number, not hex'}}, 'required': ['name']},
    }
    session = {'name': 'session', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}
    def route(operation, summary, parameters, body=None):
        return {'operationId': operation, 'summary': summary, 'parameters': parameters,
                **({'requestBody': {'content': {'application/json': {
                    'schema': {'$ref': '#/components/schemas/' + body}}}}} if body else {})}
    return {'components': {'schemas': schemas}, 'paths': {
        '/api/sendContactVcard': {'post': route('ChattingController_sendContactVcard',
            'sendContactVcard', [], 'MessageContactVcardRequest')},
        '/api/{session}/chats/{chatId}/messages/read': {'post': route('ChatsController_readChatMessages',
            'Read unread messages in the chat', [session,
                {'name': 'chatId', 'in': 'path', 'required': True, 'schema': {'type': 'string'}},
                {'name': 'messages', 'in': 'query', 'schema': {'type': 'number'}},
                {'name': 'days', 'in': 'query', 'schema': {'type': 'number', 'default': 7}}])},
        '/api/{session}/channels/search/by-view': {'post': route('ChannelsController_searchByView',
            'Search for channels (by view)', [session], 'ChannelSearchByView')},
        '/api/{session}/channels/search/by-text': {'post': route('ChannelsController_searchByText',
            'Search for channels (by text)', [session], 'ChannelSearchByText')},
        '/api/{session}/labels': {'post': route('LabelsController_create',
            'Create a new label', [session], 'LabelBody')},
        '/api/{session}/labels/{labelId}': {'put': route('LabelsController_update',
            'Update a label', [session,
                {'name': 'labelId', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}], 'LabelBody')},
    }}


@pytest.mark.parametrize('updated_provider', [False, True])
def test_generator_reproduces_repaired_catalog_from_both_provider_declarations(tmp_path, updated_provider):
    source = pinned_contract_source()
    if updated_provider:
        source['components']['schemas']['Contact']['required'].remove('vcard')
        source['components']['schemas']['Contact']['properties']['vcard']['description'] = (
            'Optional raw vCard override; generated from the structured contact when omitted.')
        for name in ('ChannelSearchByView', 'ChannelSearchByText'):
            source['components']['schemas'][name]['required'].remove('startCursor')
            source['components']['schemas'][name]['required'].remove('limit')
    input_file, output_file = tmp_path / 'source.json', tmp_path / 'catalog.json'
    input_file.write_text(json.dumps(source))
    script = Path(__file__).parents[1] / 'scripts/build_operations.py'
    subprocess.run([sys.executable, str(script), str(input_file), '--output', str(output_file)],
                   check=True, capture_output=True, text=True, timeout=20)
    generated = json.loads(output_file.read_text())
    assert len(generated) == 6
    for name, operation in generated.items():
        assert operation == OPERATIONS[name], name
    assert 'vcard' not in generated['messages_send_contact_vcard']['schema']['properties']['body'][
        'properties']['contacts']['items']['oneOf'][1]['required']
    cursor = generated['channels_search_by_text']['schema']['properties']['body']
    assert 'startCursor' not in cursor['required']
    assert 'first page' in cursor['properties']['startCursor']['description']


@pytest.mark.parametrize('contact', [
    {'fullName': 'Synthetic', 'phoneNumber': '+15550001234'},
    {'fullName': 'Synthetic', 'phoneNumber': '+15550001234', 'organization': 'Example'},
    {'fullName': 'Synthetic', 'phoneNumber': '+15550001234', 'vcard': ''},
    {'fullName': 'Synthetic', 'phoneNumber': '+15550001234', 'vcard': VCARD},
    {'vcard': VCARD},
])
def test_contact_alternatives_reach_provider_without_fabricating_fields(environment, contact):
    service, gateway = enabled_service(environment)
    action = OperationAction(operation='messages_send_contact_vcard', arguments={
        'body': {'chatId': CHAT, 'contacts': [contact]}}, idempotency_key='qa174-contact-00000001')
    assert service.operation(action, 'test-owner')['state'] == 'queued'
    assert service.process_action()
    assert gateway.requests[0][1]['json']['contacts'] == [contact]
    assert service.store.send_status(action.idempotency_key)['state'] == 'submitted'
    assert service.operation(action, 'test-owner')['state'] == 'submitted'
    assert len(gateway.requests) == 1 and not service.process_action()


@pytest.mark.parametrize('contact', [{}, {'fullName': 'Synthetic'}, {'phoneNumber': '+15550001234'},
    {'fullName': 1, 'phoneNumber': '+15550001234'}, {'vcard': None}, {'vcard': VCARD, 'unknown': True}])
def test_invalid_contacts_fail_before_queue(environment, contact):
    service, gateway = enabled_service(environment)
    action = OperationAction(operation='messages_send_contact_vcard', arguments={
        'body': {'chatId': CHAT, 'contacts': [contact]}}, idempotency_key='qa174-invalid-contact-0001')
    with pytest.raises(OperationArgumentError):
        service.operation(action, 'test-owner')
    assert not gateway.requests and not service.process_action()


@pytest.mark.parametrize('name,body', [
    ('channels_search_by_text', {'text': 'Synthetic', 'categories': [], 'limit': 2}),
    ('channels_search_by_view', {'view': 'RECOMMENDED', 'countries': ['IT'], 'categories': [], 'limit': 2}),
])
@pytest.mark.parametrize('cursor', [None, '', 'synthetic-next-cursor'])
def test_channel_initial_and_continuation_pages_have_exact_cursor(environment, name, body, cursor):
    service, gateway = enabled_service(environment)
    supplied = copy.deepcopy(body)
    if cursor is not None:
        supplied['startCursor'] = cursor
    before = copy.deepcopy(supplied)
    service.operation(OperationArguments(operation=name, arguments={'body': supplied}), 'test-owner', readonly=True)
    assert gateway.requests[0][1]['json']['startCursor'] == (cursor or '')
    assert supplied == before


INVALID_NUMBERS = [
    *[('channels_search_by_text', {'body': {'text': 'Synthetic', 'categories': [],
        'limit': value, 'startCursor': ''}}, True) for value in (-1, 0, 1.5, True, '1', 101)],
    *[('channels_search_by_view', {'body': {'view': 'RECOMMENDED', 'countries': ['IT'],
        'categories': [], 'limit': value, 'startCursor': ''}}, True) for value in (-1, 0, 101)],
    *[('chats_read_chat_messages', {'path': {'chatId': CHAT}, 'query': {'messages': value}}, False)
      for value in (-1, 0, -0.5, 1.5, True, '1', 101)],
    *[('chats_read_chat_messages', {'path': {'chatId': CHAT}, 'query': {'days': value}}, False)
      for value in (-1, -0.5)],
    *[(name, {'path': {'labelId': '1'} if name == 'labels_update' else {},
        'body': {'name': 'Synthetic', 'color': value}}, False)
      for name in ('labels_create', 'labels_update')
      for value in (-0.5, 1.5, -(2**31)-1, 2**31)],
]


@pytest.mark.parametrize('name,arguments,readonly', INVALID_NUMBERS)
def test_invalid_numbers_fail_before_provider_and_persistent_job(environment, name, arguments, readonly):
    service, gateway = enabled_service(environment, account_actions_enabled=True)
    params = {'operation': name, 'arguments': arguments}
    args = OperationArguments(**params) if readonly else OperationAction(**params,
        idempotency_key='qa174-invalid-number-0001')
    with pytest.raises(OperationArgumentError):
        service.operation(args, 'test-owner', readonly=readonly)
    assert not gateway.requests and not service.process_action()
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM sends').fetchone()[0] == 0


@pytest.mark.parametrize('name,arguments', [
    ('chats_read_chat_messages', {'path': {'chatId': CHAT}, 'query': {'messages': 1.5}}),
    ('labels_create', {'body': {'name': 'Synthetic', 'color': 1.5}}),
])
def test_preexisting_invalid_jobs_are_stopped_again_before_dispatch(environment, name, arguments):
    service, gateway = enabled_service(environment, account_actions_enabled=True)
    key = 'qa174-preexisting-00000001'
    service.store.queue_action(key, 'test-owner', name, {'path': {}, 'query': {}, 'body': {}, **arguments})
    assert service.process_action()
    assert service.store.send_status(key)['state'] == 'failed_before_send'
    assert not gateway.requests


@pytest.mark.parametrize('count,days', [(1, 0), (1.0, .5), (100, 7)])
def test_valid_receipt_count_has_integer_wire_value_and_fractional_days_remain_supported(environment, count, days):
    service, gateway = enabled_service(environment)
    args = OperationAction(operation='chats_read_chat_messages', arguments={
        'path': {'chatId': CHAT}, 'query': {'messages': count, 'days': days}},
        idempotency_key='qa174-receipt-000000001')
    assert service.operation(args, 'test-owner')['state'] == 'queued'
    assert service.process_action()
    query = gateway.requests[0][1]['params']
    assert type(query['messages']) is int and query == {'messages': count, 'days': days}


@pytest.mark.parametrize('color', [-(2**31), -1, 0, 19, 2**31-1])
def test_integer_label_domain_is_preserved_without_claiming_remote_palette_limits(color):
    _, args = validate_operation('labels_create', {'body': {'name': 'Synthetic', 'color': color}}, readonly=False)
    assert args['body']['color'] == color


@pytest.mark.parametrize('scopes', [['whatsapp:read'], ['whatsapp:read', 'whatsapp:send']])
def test_operation_schema_shares_current_authorization_and_engine_evidence(mcp_app, scopes):
    mcp_app['token'].scopes = scopes
    mcp_app['service'].ab_provider_operations = lambda: ab_operations.OPERATIONS
    async def check():
        capabilities = (await dispatch(mcp_app, 'tools/call', name='get_capabilities', arguments={})).structured_content
        for row in capabilities['operations']:
            actual = (await dispatch(mcp_app, 'tools/call', name='get_operation_schema',
                arguments={'operation': row['operation']})).structured_content
            for field in ('required_scope', 'scope_granted', 'configuration_enabled', 'permission_enabled',
                          'authorization_rules', 'destination_policy', 'destination_checked',
                          'engine_available', 'limitation'):
                assert actual[field] == row[field], (row['operation'], field)
        assert not mcp_app['service'].gateway.sent
    asyncio.run(check())
