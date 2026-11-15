"""Remaining application routes, using only synthetic HTTP and temporary state.

Literal expectations were transcribed from WAHA 90ba445 controllers/DTOs and
GOWS 5f093fe server handlers, not generated from the catalog under test.
These checks cover the bridge contract; they do not certify account capability
or a change visible on a phone.
"""
from copy import deepcopy
from dataclasses import dataclass, replace
import json
from pathlib import Path
import subprocess
import sys

import httpx
from jsonschema import Draft202012Validator
import pytest
from starlette.testclient import TestClient

from conftest import call
from test_oauth_contract import challenged, grant, headers
from sally_whatsapp.gateway import Waha
from sally_whatsapp.operations import validate_operation
from sally_whatsapp.server import create_app
from sally_whatsapp.store import Store


SESSION = 'synthetic-secondary'
BASE = '/api/' + SESSION
CONTACT = '15550001234@c.us'
LID = '15550009999@lid'
GROUP = '15550000000-123@g.us'
CHANNEL = '15550007777@newsletter'
LABEL = {'id': '7', 'name': 'Synthetic label', 'color': 0, 'colorHex': '#ff9485'}
CHANNEL_INFO = {'id': CHANNEL, 'name': 'Synthetic channel', 'role': 'SUBSCRIBER',
                'verified': False, 'subscribersCount': 2}
PAGE = {'page': {'startCursor': None, 'endCursor': 'synthetic-next',
                 'hasNextPage': True, 'hasPreviousPage': False},
        'channels': [CHANNEL_INFO]}


@dataclass
class Route:
    operation: str
    arguments: dict
    method: str
    path: str
    query: dict
    response: object


# channels.controller.ts:59–246, contacts.controller.ts:52–108,
# labels.controller.ts:43–160, lids.controller.ts:40–110,
# groups.controller.ts:73–125/176–189/498–508.
READS = [
    Route('profile_get_my_profile', {}, 'GET', BASE + '/profile', {},
          {'id': CONTACT, 'name': 'Synthetic profile'}),
    Route('chats_get_chat_picture', {'path': {'chatId': CONTACT}, 'query': {'refresh': False}},
          'GET', BASE + '/chats/' + CONTACT + '/picture', {'refresh': 'false'}, {'url': None}),
    Route('channels_list', {'query': {'role': 'SUBSCRIBER'}}, 'GET', BASE + '/channels',
          {'role': 'SUBSCRIBER'}, [CHANNEL_INFO]),
    Route('channels_get', {'path': {'id': CHANNEL}}, 'GET', BASE + '/channels/' + CHANNEL,
          {}, CHANNEL_INFO),
    Route('channels_search_by_view', {'body': {'view': 'RECOMMENDED', 'countries': ['IT'],
          'categories': [], 'limit': 2, 'startCursor': ''}}, 'POST',
          BASE + '/channels/search/by-view', {}, PAGE),
    Route('channels_search_by_text', {'body': {'text': 'Synthetic science',
          'categories': [], 'limit': 2, 'startCursor': 'synthetic-cursor'}}, 'POST',
          BASE + '/channels/search/by-text', {}, PAGE),
    Route('channels_get_search_views', {}, 'GET', BASE + '/channels/search/views', {},
          [{'value': 'RECOMMENDED', 'name': 'Recommended'}]),
    Route('channels_get_search_countries', {}, 'GET', BASE + '/channels/search/countries', {},
          [{'code': 'IT', 'name': 'Italy'}]),
    Route('channels_get_search_categories', {}, 'GET', BASE + '/channels/search/categories', {},
          [{'value': 'SCIENCE', 'name': 'Science'}]),
    Route('labels_get_all', {}, 'GET', BASE + '/labels', {}, [LABEL]),
    Route('labels_get_chat_labels', {'path': {'chatId': CONTACT}}, 'GET',
          BASE + '/labels/chats/' + CONTACT, {}, [LABEL]),
    Route('labels_get_chats_by_label', {'path': {'labelId': '7'}}, 'GET',
          BASE + '/labels/7/chats', {}, [{'id': CONTACT}]),
    Route('contacts_get', {'query': {'contactId': CONTACT}}, 'GET', '/api/contacts',
          {'contactId': CONTACT, 'session': SESSION}, {'id': CONTACT, 'name': 'Synthetic contact'}),
    Route('contacts_check_exists', {'query': {'phone': '15550001234'}}, 'GET',
          '/api/contacts/check-exists', {'phone': '15550001234', 'session': SESSION},
          {'numberExists': False, 'chatId': None}),
    Route('contacts_get_profile_picture', {'query': {'contactId': CONTACT, 'refresh': True}},
          'GET', '/api/contacts/profile-picture',
          {'contactId': CONTACT, 'refresh': 'true', 'session': SESSION}, {'profilePictureURL': None}),
    Route('contacts_get_session', {'path': {'id': CONTACT}}, 'GET',
          BASE + '/contacts/' + CONTACT, {}, {'id': CONTACT, 'firstName': 'Synthetic'}),
    Route('identifiers_get_all', {'query': {'limit': 2, 'offset': 3}}, 'GET',
          BASE + '/lids', {'limit': '2', 'offset': '3'}, [{'lid': LID, 'pn': CONTACT}]),
    Route('identifiers_get_lids_count', {}, 'GET', BASE + '/lids/count', {}, {'count': 2}),
    Route('identifiers_find_p_n_by_lid', {'path': {'lid': LID}}, 'GET',
          BASE + '/lids/' + LID, {}, {'lid': LID, 'pn': None}),
    Route('identifiers_find_l_i_d_by_phone_number', {'path': {'phoneNumber': CONTACT}}, 'GET',
          BASE + '/lids/pn/' + CONTACT, {}, {'lid': None, 'pn': CONTACT}),
    Route('groups_get_groups', {'query': {'sortBy': 'subject', 'sortOrder': 'asc',
          'limit': 2, 'offset': 1, 'exclude': ['participants']}}, 'GET', BASE + '/groups',
          {'sortBy': 'subject', 'sortOrder': 'asc', 'limit': '2', 'offset': '1',
           'exclude': 'participants'}, {GROUP: {'JID': GROUP, 'Name': 'Synthetic group'}}),
    Route('groups_join_info_group', {'query': {'code': 'SYNTHETIC-INVITE'}}, 'GET',
          BASE + '/groups/join-info', {'code': 'SYNTHETIC-INVITE'},
          {'JID': GROUP, 'Name': 'Synthetic group', 'ParticipantCount': 2}),
    Route('groups_get_groups_count', {}, 'GET', BASE + '/groups/count', {}, {'count': 1}),
    Route('groups_get_chat_picture', {'path': {'id': GROUP}, 'query': {'refresh': False}},
          'GET', BASE + '/groups/' + GROUP + '/picture', {'refresh': 'false'}, {'url': None}),
    Route('groups_get_participants', {'path': {'id': GROUP}}, 'GET',
          BASE + '/groups/' + GROUP + '/participants', {},
          [{'id': CONTACT, 'isAdmin': True, 'isSuperAdmin': False}]),
]

# labels.go:57–133, actions.go:76–115, calls.go:11–28,
# newsletter.go:82–141 and their WAHA controller routes.
WRITES = [
    Route('chats_unread_chat', {'path': {'chatId': CONTACT}}, 'POST',
          BASE + '/chats/' + CONTACT + '/unread', {}, {'success': True}),
    Route('calls_reject_call', {'body': {'from': CONTACT, 'id': 'SYNTHETIC-CALL'}},
          'POST', BASE + '/calls/reject', {}, {}),
    Route('channels_create', {'body': {'name': 'Synthetic channel', 'description': 'Synthetic'}},
          'POST', BASE + '/channels', {}, CHANNEL_INFO),
    Route('channels_follow', {'path': {'id': CHANNEL}}, 'POST',
          BASE + '/channels/' + CHANNEL + '/follow', {}, {}),
    Route('channels_unfollow', {'path': {'id': CHANNEL}}, 'POST',
          BASE + '/channels/' + CHANNEL + '/unfollow', {}, {}),
    Route('channels_mute', {'path': {'id': CHANNEL}}, 'POST',
          BASE + '/channels/' + CHANNEL + '/mute', {}, {}),
    Route('channels_unmute', {'path': {'id': CHANNEL}}, 'POST',
          BASE + '/channels/' + CHANNEL + '/unmute', {}, {}),
    Route('status_delete_status', {'body': {'id': 'SYNTHETIC-STATUS', 'contacts': [CONTACT]}},
          'POST', BASE + '/status/delete', {}, {}),
    Route('labels_delete', {'path': {'labelId': '7'}}, 'DELETE', BASE + '/labels/7',
          {}, {'result': True}),
    Route('labels_put_chat_labels', {'path': {'chatId': CONTACT},
          'body': {'labels': [{'id': '7'}, {'id': '8'}]}}, 'PUT',
          BASE + '/labels/chats/' + CONTACT, {}, {}),
]


@pytest.fixture
def catalog_client(environment):
    settings, receiver, _, token = environment
    # These writes organize the account; no outbound message grant is enabled.
    settings = replace(settings, session=SESSION, live_account_enabled=True,
                       account_actions_enabled=True, send_enabled=False)
    gateway = Waha(settings)
    gateway.client.close()
    requests, reply = [], {'value': {}}
    def handle(request):
        requests.append(request)
        if reply.get('timeout'):
            raise httpx.ReadTimeout('synthetic response lost', request=request)
        if reply.get('empty'):
            return httpx.Response(204)
        return httpx.Response(reply.get('status', 200), json=reply['value'])
    gateway.client = httpx.Client(base_url=settings.waha_url, transport=httpx.MockTransport(handle))
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app) as client:
        client.headers.update(headers(grant(token, ['whatsapp:read', 'whatsapp:send'])))
        yield app.state.service, client, requests, reply, token
    assert receiver.requests == []


def invoke(client, route, *, readonly, key='synthetic-remaining-action-0001'):
    arguments = {'operation': route.operation, 'arguments': deepcopy(route.arguments)}
    if not readonly:
        arguments['idempotency_key'] = key
    return call(client, 'read_whatsapp' if readonly else 'write_whatsapp', arguments)['result']


def assert_request(request, route):
    assert request.method == route.method
    assert request.url.path == route.path
    assert dict(request.url.params) == route.query
    assert (json.loads(request.content) if request.content else {}) == route.arguments.get('body', {})


@pytest.mark.parametrize('route', READS, ids=lambda case: case.operation)
def test_read_routes_preserve_typed_results_without_import_or_send(catalog_client, route):
    service, client, requests, reply, token = catalog_client
    client.headers.update(headers(grant(token, ['whatsapp:read'])))
    reply['value'] = route.response
    projected = invoke(client, route, readonly=True)['structuredContent']
    assert projected['result'] == route.response
    if route.operation == 'groups_get_group':
        assert projected['source'] == 'provider_group_cache'
        assert projected['freshness']['state'] == 'unverified'
        assert projected['participant_count_evidence']['list_completeness'] == 'unverified'
    else:
        assert projected == {'result': route.response}
    assert len(requests) == 1
    assert_request(requests[0], route)
    assert not service.process_action()
    with service.store.db() as db:
        for table in ('messages', 'action_jobs', 'history_jobs', 'chat_aliases'):
            assert db.execute('SELECT count(*) FROM ' + table).fetchone()[0] == 0


@pytest.mark.parametrize('route', WRITES, ids=lambda case: case.operation)
def test_account_write_requires_scope_then_submits_once_and_persists(catalog_client, route):
    service, client, requests, reply, token = catalog_client
    key = 'synthetic-remaining-action-0001'
    client.headers.update(headers(grant(token, ['whatsapp:read'])))
    assert challenged(invoke(client, route, readonly=False)) == ['whatsapp:read', 'whatsapp:send']
    assert service.store.send_status(key) is None and requests == []
    client.headers.update(headers(grant(token, ['whatsapp:read', 'whatsapp:send'])))
    reply['value'] = {**route.response, 'body': 'PRIVATE-ECHO', '_data': {'token': 'PRIVATE-ECHO'}}
    assert invoke(client, route, readonly=False)['structuredContent']['state'] == 'queued'
    assert requests == [] and service.process_action()
    assert len(requests) == 1
    assert_request(requests[0], route)
    status = call(client, 'get_send_status', {'idempotency_key': key})['result']['structuredContent']
    assert status['state'] == 'submitted'
    assert status['delivery']['reason'] == 'operation_not_tracked'
    assert 'PRIVATE-ECHO' not in json.dumps(status)
    assert Store(service.settings.database).send_status(key, owner='test-owner') == status
    assert invoke(client, route, readonly=False)['structuredContent']['state'] == 'submitted'
    assert not service.process_action() and len(requests) == 1
    with service.store.db() as db:
        saved = db.execute('SELECT result FROM operation_results WHERE key=?', (key,)).fetchone()[0]
        assert 'PRIVATE-ECHO' not in saved


@pytest.mark.parametrize('route', WRITES, ids=lambda case: case.operation)
def test_account_policy_is_rechecked_after_queue_without_network(catalog_client, route):
    service, client, requests, _, _ = catalog_client
    service.settings = replace(service.settings, account_actions_enabled=False)
    assert invoke(client, route, readonly=False)['isError']
    assert not service.process_action() and requests == []
    service.settings = replace(service.settings, account_actions_enabled=True)
    assert invoke(client, route, readonly=False)['structuredContent']['state'] == 'queued'
    service.settings = replace(service.settings, account_actions_enabled=False)
    assert service.process_action()
    assert requests == []
    status = service.store.send_status('synthetic-remaining-action-0001')
    assert status['state'] == 'failed_before_send'
    service.settings = replace(service.settings, account_actions_enabled=True)
    assert invoke(client, route, readonly=False)['structuredContent']['state'] == 'failed_before_send'
    assert not service.process_action()


@pytest.mark.parametrize('failure', ['provider_refusal', 'timeout'])
@pytest.mark.parametrize('route', WRITES, ids=lambda case: case.operation)
def test_uncertain_actions_never_retry_after_response_loss_or_provider_refusal(catalog_client, route, failure):
    service, client, requests, reply, _ = catalog_client
    reply.update(status=403, value={'message': 'PRIVATE-UPSTREAM-DETAIL'})
    if failure == 'timeout':
        reply['timeout'] = True
    assert invoke(client, route, readonly=False)['structuredContent']['state'] == 'queued'
    assert service.process_action() and len(requests) == 1
    status = service.store.send_status('synthetic-remaining-action-0001')
    assert status['state'] == 'uncertain'
    assert status['provider_id'] is None
    assert 'PRIVATE-UPSTREAM-DETAIL' not in json.dumps(status)
    assert Store(service.settings.database).send_status(status['key']) == status
    assert invoke(client, route, readonly=False)['structuredContent']['state'] == 'uncertain'
    assert not service.process_action() and len(requests) == 1
    collision = WRITES[1] if route is WRITES[0] else WRITES[0]
    assert invoke(client, collision, readonly=False)['isError']
    assert not service.process_action() and len(requests) == 1


@pytest.mark.parametrize('route', [READS[i] for i in (0, 1, 5, 9, 12, 16, 20)],
                         ids=lambda case: case.operation)
@pytest.mark.parametrize('failure', ['provider_refusal', 'timeout'])
def test_read_failure_has_no_persistent_action_and_hides_upstream_details(catalog_client, route, failure):
    service, client, requests, reply, token = catalog_client
    client.headers.update(headers(grant(token, ['whatsapp:read'])))
    reply.update(status=500, value={'message': 'PRIVATE-UPSTREAM-DETAIL'})
    reply['timeout'] = failure == 'timeout'
    result = invoke(client, route, readonly=True)
    assert result['isError'] and 'PRIVATE-UPSTREAM-DETAIL' not in json.dumps(result)
    assert 'mcp/www_authenticate' not in result.get('_meta', {})
    assert len(requests) == 1 and not service.process_action()
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM sends').fetchone()[0] == 0


@pytest.mark.parametrize('route', READS + WRITES, ids=lambda case: case.operation)
@pytest.mark.parametrize('section', ['path', 'query', 'body'])
def test_catalog_callers_cannot_select_another_session(route, section):
    arguments = deepcopy(route.arguments)
    arguments.setdefault(section, {})['session'] = 'another-owner-session'
    with pytest.raises(ValueError, match='Invalid operation arguments'):
        validate_operation(route.operation, arguments, readonly=route in READS)


@pytest.mark.parametrize('route', READS + WRITES, ids=lambda case: case.operation)
def test_read_and_action_wrappers_are_not_interchangeable(route):
    with pytest.raises(ValueError, match='incorrect read/action tool'):
        validate_operation(route.operation, route.arguments, readonly=route not in READS)


@pytest.mark.parametrize('bad', ['../other', '7%2fother', '7/other', '', None, 7, {'id': '7'}])
@pytest.mark.parametrize('operation,field', [
    ('labels_delete', 'labelId'), ('labels_put_chat_labels', 'chatId'),
    ('channels_follow', 'id'), ('contacts_get_session', 'id'),
    ('identifiers_find_p_n_by_lid', 'lid'),
])
def test_path_identifiers_cannot_escape_fixed_routes(operation, field, bad):
    arguments = {'path': {field: bad}}
    if operation == 'labels_put_chat_labels':
        arguments['body'] = {'labels': []}
    with pytest.raises(ValueError):
        validate_operation(operation, arguments, readonly=operation in
                           ('contacts_get_session', 'identifiers_find_p_n_by_lid'))


@pytest.mark.parametrize('labels', [[], [{'id': '7'}]])
def test_label_assignment_supports_explicit_removal_and_identifier_objects(catalog_client, labels):
    service, client, requests, reply, _ = catalog_client
    route = replace(WRITES[-1], arguments={'path': {'chatId': CONTACT}, 'body': {'labels': labels}})
    reply['empty'] = True
    assert invoke(client, route, readonly=False)['structuredContent']['state'] == 'queued'
    assert service.process_action()
    assert_request(requests[0], route)
    assert service.store.send_status('synthetic-remaining-action-0001')['state'] == 'submitted'


@pytest.mark.parametrize('labels', [['7'], [{}], [{'id': 7}], [{'id': '7', 'name': 'unused'}], None])
def test_label_assignment_does_not_accept_names_or_untyped_ids(catalog_client, labels):
    service, client, requests, _, _ = catalog_client
    route = replace(WRITES[-1], arguments={'path': {'chatId': CONTACT}, 'body': {'labels': labels}})
    assert invoke(client, route, readonly=False)['isError']
    assert not service.process_action() and requests == []


def test_live_contact_read_strips_internal_fields_without_discarding_visible_profile(catalog_client):
    service, client, requests, reply, _ = catalog_client
    route = next(route for route in READS if route.operation == 'contacts_get')
    reply['value'] = {'id': CONTACT, 'name': 'Synthetic visible name',
        '_data': {'anything': 'PRIVATE-INTERNAL'}, 'token': 'PRIVATE-INTERNAL',
        'nested': {'about': 'Synthetic visible about', 'mediaKey': 'PRIVATE-INTERNAL',
                   'entries': [{'description': 'Synthetic visible entry', 'credentials': 'PRIVATE-INTERNAL'}]}}
    result = invoke(client, route, readonly=True)['structuredContent']['result']
    assert result == {'id': CONTACT, 'name': 'Synthetic visible name',
        'nested': {'about': 'Synthetic visible about', 'entries': [{'description': 'Synthetic visible entry'}]}}
    assert len(requests) == 1
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM messages').fetchone()[0] == 0


@pytest.mark.parametrize('operation,arguments', [
    ('groups_get_groups', {'query': {'limit': 101}}),
    ('groups_get_groups', {'query': {'offset': -1}}),
    ('identifiers_get_all', {'query': {'limit': 0}}),
    ('identifiers_get_all', {'query': {'offset': -1}}),
    ('channels_list', {'query': {'role': 'GUEST'}}),
    ('chats_get_chat_picture', {'path': {'chatId': CONTACT}, 'query': {'refresh': 'true'}}),
    ('contacts_get_profile_picture', {'query': {'contactId': CONTACT, 'refresh': 1}}),
])
def test_read_query_boundaries_fail_without_provider_requests(catalog_client, operation, arguments):
    service, client, requests, _, _ = catalog_client
    assert invoke(client, Route(operation, arguments, '', '', {}, {}), readonly=True)['isError']
    assert not service.process_action() and requests == []


def test_channel_invite_code_is_an_identifier_not_a_caller_url(catalog_client):
    _, client, requests, reply, _ = catalog_client
    route = replace(next(route for route in READS if route.operation == 'channels_get'),
                    arguments={'path': {'id': 'SYNTHETIC-INVITE-CODE'}},
                    path=BASE + '/channels/SYNTHETIC-INVITE-CODE')
    reply['value'] = CHANNEL_INFO
    assert invoke(client, route, readonly=True)['structuredContent'] == {'result': CHANNEL_INFO}
    assert_request(requests[0], route)


@pytest.mark.parametrize('operation,arguments,readonly', [
    ('status_delete_status', {'body': {}}, False),
    ('calls_reject_call', {'body': {'from': '', 'id': 'SYNTHETIC-CALL'}}, False),
    ('calls_reject_call', {'body': {'from': CONTACT, 'id': ''}}, False),
    ('channels_search_by_view', {'body': {'view': 'RECOMMENDED', 'countries': [],
       'categories': [], 'limit': 2, 'startCursor': ''}}, True),
    ('channels_search_by_text', {'body': {'text': '', 'categories': [],
       'limit': 2, 'startCursor': ''}}, True),
])
def test_required_provider_fields_fail_before_network_or_queue(catalog_client, operation, arguments, readonly):
    service, client, requests, _, _ = catalog_client
    route = Route(operation, arguments, '', '', {}, {})
    assert invoke(client, route, readonly=readonly)['isError']
    assert not service.process_action() and requests == []
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM sends').fetchone()[0] == 0


def test_generator_preserves_pinned_required_status_call_and_search_constraints(tmp_path):
    bodies = {
        'StatusController_deleteStatus': {'id': {'type': 'string'}, 'contacts': {'type': 'array', 'items': {'type': 'string'}}},
        'CallsController_rejectCall': {'from': {'type': 'string'}, 'id': {'type': 'string'}},
        'ChannelsController_searchByView': {'view': {'type': 'string'},
            'countries': {'type': 'array', 'items': {'type': 'string'}},
            'categories': {'type': 'array', 'items': {'type': 'string'}},
            'limit': {'type': 'number'}, 'startCursor': {'type': 'string'}},
        'ChannelsController_searchByText': {'text': {'type': 'string'},
            'categories': {'type': 'array', 'items': {'type': 'string'}},
            'limit': {'type': 'number'}, 'startCursor': {'type': 'string'}},
    }
    paths = {}
    for operation, suffix in [('StatusController_deleteStatus', 'status/delete'),
            ('CallsController_rejectCall', 'calls/reject'),
            ('ChannelsController_searchByView', 'channels/search/by-view'),
            ('ChannelsController_searchByText', 'channels/search/by-text')]:
        properties = bodies[operation]
        body = {'type': 'object', 'properties': properties,
                'required': [] if operation.startswith('Status') else list(properties)}
        paths['/api/{session}/' + suffix] = {'post': {'operationId': operation,
            'parameters': [{'name': 'session', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}],
            'requestBody': {'content': {'application/json': {'schema': body}}}}}
    source, output = tmp_path / 'pinned.json', tmp_path / 'catalog.json'
    source.write_text(json.dumps({'components': {'schemas': {}}, 'paths': paths}))
    subprocess.run([sys.executable, str(Path(__file__).parents[1] / 'scripts/build_operations.py'),
                    str(source), '--output', str(output)], check=True, capture_output=True, text=True)
    generated = json.loads(output.read_text())
    bad = [('status_delete_status', {}), ('calls_reject_call', {'from': CONTACT, 'id': ''}),
           ('channels_search_by_view', {'view': 'RECOMMENDED', 'countries': [],
            'categories': [], 'limit': 2, 'startCursor': ''}),
           ('channels_search_by_text', {'text': '', 'categories': [], 'limit': 2, 'startCursor': ''})]
    for operation, body in bad:
        schema = generated[operation]['schema']
        assert not Draft202012Validator(schema).is_valid({'body': body})
        good = next(route.arguments for route in READS + WRITES if route.operation == operation)
        Draft202012Validator(schema).validate(good)
