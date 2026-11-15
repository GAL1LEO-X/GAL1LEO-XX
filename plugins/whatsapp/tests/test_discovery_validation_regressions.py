"""Native diagnostic reproduced against synthetic gateways, with zero writes."""
import copy
import json

import pytest
from jsonschema import Draft202012Validator

from conftest import call, rpc
from sally_whatsapp.operations import OPERATIONS, validate_operation
from test_family_capabilities import full_family_client


@pytest.mark.parametrize('field,value', [('limit', 1.5), ('offset', 0.5), ('limit', True), ('offset', '1')])
def test_invalid_contact_paging_stops_before_gateway(full_family_client, field, value):
    service, client, requests, _, _ = full_family_client
    result = call(client, 'read_whatsapp', {'operation': 'contacts_get_all',
        'arguments': {'query': {field: value}}})['result']
    assert result['isError']
    assert result['structuredContent']['error_code'] == 'INVALID_ARGUMENT'
    assert 'PROVIDER_UNAVAILABLE' not in json.dumps(result)
    assert requests == []
    assert not service.process_action()


def test_integral_json_number_has_integer_wire_representation(full_family_client):
    _, client, requests, _, _ = full_family_client
    result = call(client, 'read_whatsapp', {'operation': 'contacts_get_all',
        'arguments': {'query': {'limit': 1.0, 'offset': 0.0}}})['result']
    assert not result.get('isError')
    assert requests[-1].url.params['limit'] == '1'
    assert requests[-1].url.params['offset'] == '0'


def test_advertised_operations_match_the_tool_and_engine(app_client):
    _, client = app_client
    tools = {t['name']: t for t in rpc(client, 'tools/list')['result']['tools']}
    assert len(tools) == 27
    expected = {
        'get_operation_schema': set(OPERATIONS),
        'read_whatsapp': {n for n, o in OPERATIONS.items() if o['readonly']},
        'write_whatsapp': {n for n, o in OPERATIONS.items() if not o['readonly']
                          and not o['media_required'] and o['capability'] != 'unsupported_gows'},
        'send_media': {n for n, o in OPERATIONS.items() if o['media'] and not o['readonly']
                       and o['capability'] != 'unsupported_gows'},
    }
    assert [len(expected[n]) for n in expected] == [120, 44, 60, 12]
    for name, operations in expected.items():
        assert set(tools[name]['inputSchema']['properties']['operation']['enum']) == operations


def test_required_containers_and_channel_ids_match_validation():
    for name, op in OPERATIONS.items():
        schema = op['schema']
        for location, child in schema['properties'].items():
            if not Draft202012Validator(child).is_valid({}):
                assert location in schema.get('required', []), (name, location)
        for child in schema['properties']['path']['properties'].values():
            assert child['type'] == 'string', name


def test_missing_container_is_rejected_by_published_schema():
    schema = OPERATIONS['messages_send_text']['schema']
    assert not Draft202012Validator(schema).is_valid({})
    assert Draft202012Validator(schema).is_valid({'body': {'chatId': '12345@c.us', 'text': 'synthetic'}})


@pytest.mark.parametrize('name', ['channels_get', 'channels_delete'])
def test_channel_identifier_type_is_visible_in_schema(name):
    schema = OPERATIONS[name]['schema']
    assert not Draft202012Validator(schema).is_valid({'path': {'id': 12345}})
    assert Draft202012Validator(schema).is_valid({'path': {'id': '12345@newsletter'}})


@pytest.mark.parametrize('name', ['contacts_get_all', 'chats_get_chats', 'groups_get_groups',
                                'channels_preview_channel_messages', 'identifiers_get_all'])
def test_catalog_paging_rejects_fractional_values(name):
    op = OPERATIONS[name]
    query = op['schema']['properties']['query']
    for field in ('limit', 'offset'):
        if field in query['properties']:
            assert not Draft202012Validator(query['properties'][field]).is_valid(1.5)


def test_nested_paging_is_integer_and_does_not_mutate_input():
    args = {'body': {'pagination': {'limit': 1.0, 'offset': 0.0}}}
    before = copy.deepcopy(args)
    _, normalized = validate_operation('chats_post_chats_overview', args, readonly=True)
    assert type(normalized['body']['pagination']['limit']) is int
    assert args == before and type(args['body']['pagination']['limit']) is float
    args['body']['pagination']['limit'] = 1.5
    with pytest.raises(ValueError):
        validate_operation('chats_post_chats_overview', args, readonly=True)
