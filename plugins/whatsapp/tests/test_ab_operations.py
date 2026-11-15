"""A/B provider admission, authorization and durable actions with synthetic data."""
import copy
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace
from urllib.parse import quote

import httpx
import pytest
from starlette.testclient import TestClient

from conftest import call
from test_ab_sources import CHAT, LID, SOURCE, PRIVATE, observed
from test_oauth_contract import challenged, grant, headers
from test_standalone_setup import load_script
from sally_whatsapp import ab_operations
from sally_whatsapp.capabilities import capabilities
from sally_whatsapp.config import MCP_SCOPES
from sally_whatsapp.gateway import GatewayUnavailable, Waha
from sally_whatsapp.operations import OPERATIONS, validate_operation
from sally_whatsapp.server import OperationAction, OperationArguments, Service, create_app


AB = frozenset({
    'contacts_get_about', 'contacts_block', 'contacts_unblock',
    'chats_archive_chat', 'chats_unarchive_chat', 'messages_set_star',
    'chats_pin_message', 'chats_unpin_message',
})
WRITES = sorted(AB - {'contacts_get_about'})


def arguments(name, *, identifier=SOURCE, chat=CHAT, star=True):
    if name == 'contacts_get_about':
        return {'query': {'contactId': chat}}
    if name in ('contacts_block', 'contacts_unblock'):
        return {'body': {'contactId': chat}}
    if name == 'messages_set_star':
        return {'body': {'chatId': chat, 'messageId': identifier, 'star': star}}
    result = {'path': {'chatId': chat}}
    if name in ('chats_pin_message', 'chats_unpin_message'):
        result['path']['messageId'] = identifier
    if name == 'chats_pin_message':
        result['body'] = {'duration': 86400}
    return result


def action(name='contacts_block', *, key='fixture_ab_00000001', **changes):
    return OperationAction(operation=name, arguments=arguments(name, **changes), idempotency_key=key)


def persisted(service, key):
    with service.store.db() as db:
        return dict(db.execute('SELECT s.*,j.arguments FROM sends s JOIN action_jobs j USING(key) WHERE key=?', (key,)).fetchone())


@pytest.fixture
def ab_env(environment, monkeypatch):
    settings, receiver, gateway, token = environment
    updates, summary = load_script('tenant_admin', monkeypatch).capability_selection(settings)
    assert summary['profile'] == 'full' and set(summary['required_mcp_scopes']) == set(MCP_SCOPES)
    settings = replace(settings, live_account_enabled=True, **updates)
    requests = []
    control = SimpleNamespace(value={'accepted': True}, failure=None, before_read=None,
                              source=observed())
    gateway.ab_operations = lambda: AB

    def request(method, path, **kwargs):
        requests.append((method, path, copy.deepcopy(kwargs)))
        if method == 'GET' and '/messages/' in path:
            if control.before_read:
                control.before_read()
            return copy.deepcopy(control.source)
        if method == 'GET':
            return {'about': ''}
        if control.failure:
            raise control.failure
        return copy.deepcopy(control.value)

    gateway.request = request
    service = Service(settings, gateway=gateway, event_transport=receiver)
    return SimpleNamespace(service=service, settings=settings, gateway=gateway, receiver=receiver,
                           token=token, requests=requests, control=control)


@pytest.fixture
def ab_client(ab_env):
    app = create_app(ab_env.settings, gateway=ab_env.gateway, event_transport=ab_env.receiver, start_worker=False)
    ab_env.service = app.state.service
    with TestClient(app) as client:
        client.headers.update(headers(grant(ab_env.token, list(MCP_SCOPES))))
        yield ab_env, client
    assert not ab_env.receiver.requests


@pytest.mark.parametrize('payload', [
    None, [], {}, {'version': 'old', 'operations': sorted(AB)},
    {'version': 'gows-ab-v1', 'operations': 'contacts_get_about'},
    {'version': 'gows-ab-v1', 'operations': [None]},
    {'version': 'gows-ab-v1', 'operations': ['contacts_block', 'contacts_block']},
    {'version': 'gows-ab-v1', 'operations': ['x' * 129]},
    {'version': 'gows-ab-v1', 'operations': [str(i) for i in range(65)]},
])
def test_provider_probe_rejects_old_or_malformed_contract(environment, payload):
    settings = replace(environment[0], live_account_enabled=True)
    gateway = Waha(settings)
    gateway.client.close()
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(200, json=payload)

    gateway.client = httpx.Client(base_url=settings.waha_url, transport=httpx.MockTransport(handle))
    try:
        with pytest.raises(GatewayUnavailable):
            gateway.ab_operations()
        assert len(calls) == 1
        assert calls[0].method == 'GET' and calls[0].url.path == '/api/contacts/ab-capabilities'
        assert dict(calls[0].url.params) == {'session': settings.session}
    finally:
        gateway.close()


def test_partial_contract_cannot_enable_absent_or_unrelated_operations(ab_env):
    value = ab_operations.contract_operations({'version': 'gows-ab-v1', 'operations': ['contacts_get_about', 'chats_delete_chat']})
    assert value == {'contacts_get_about'}
    ab_env.gateway.ab_operations = lambda: value
    assert ab_env.service.operation(OperationArguments(operation='contacts_get_about', arguments=arguments('contacts_get_about')), 'test-owner', readonly=True) == {'result': {'about': ''}}
    for name in WRITES:
        with pytest.raises(ValueError, match='provider'):
            ab_env.service.operation(action(name), 'test-owner')
    assert [request[0] for request in ab_env.requests] == ['GET']
    assert not ab_env.service.process_action()


@pytest.mark.parametrize('mode', ['absent', 'timeout', 'unavailable', 'malformed'])
def test_service_provider_admission_fails_before_action_dispatch(ab_env, mode):
    if mode == 'absent':
        del ab_env.gateway.ab_operations
    elif mode == 'malformed':
        ab_env.gateway.ab_operations = lambda: {'operations': sorted(AB)}
    else:
        def failure():
            raise TimeoutError('synthetic') if mode == 'timeout' else GatewayUnavailable('synthetic')
        ab_env.gateway.ab_operations = failure
    with pytest.raises(ValueError, match='provider'):
        ab_env.service.operation(action(), 'test-owner')
    assert ab_env.requests == [] and not ab_env.service.process_action()


@pytest.mark.parametrize('mode', ['missing_rpc', 'server_error', 'invalid_json', 'timeout'])
def test_failed_http_compatibility_probe_cannot_issue_mutation(ab_env, mode):
    gateway = Waha(ab_env.settings)
    gateway.client.close()
    calls = []

    def handle(request):
        calls.append(request)
        if mode == 'timeout':
            raise httpx.ReadTimeout('synthetic probe timeout', request=request)
        if mode == 'invalid_json':
            return httpx.Response(200, content=b'not json')
        return httpx.Response(404 if mode == 'missing_rpc' else 503, json={'error': PRIVATE})

    gateway.client = httpx.Client(base_url=ab_env.settings.waha_url, transport=httpx.MockTransport(handle))
    service = Service(ab_env.settings, gateway=gateway, event_transport=ab_env.receiver)
    try:
        with pytest.raises(ValueError, match='provider'):
            service.operation(action(), 'test-owner')
        assert not service.process_action()
        assert len(calls) == 1 and calls[0].method == 'GET'
    finally:
        gateway.close()


def test_only_eight_catalog_operations_gain_ab_capability(ab_env):
    assert ab_operations.OPERATIONS == AB
    assert {name for name, op in OPERATIONS.items() if op['capability'] == 'gows_ab_v1'} == AB
    available = {value['operation']: value for value in capabilities(ab_env.settings, set(MCP_SCOPES), provider_operations=AB)}
    for name in AB:
        assert available[name]['engine_available'] and available[name]['permission_enabled']
    for name in ('messages_send_buttons_reply', 'chats_delete_chat', 'chats_clear_messages', 'channels_delete', 'groups_delete_group'):
        assert available[name]['engine_available'] is False
    for name in AB:
        with pytest.raises(ValueError, match='read/action'):
            validate_operation(name, arguments(name), readonly=name != 'contacts_get_about', provider_operations=AB)


@pytest.mark.parametrize('name', sorted(AB))
def test_full_grant_reaches_all_eight_fixed_routes(ab_client, name):
    env, client = ab_client
    body = {'operation': name, 'arguments': arguments(name)}
    if name != 'contacts_get_about':
        body['idempotency_key'] = 'synthetic-ab-route-0001'
    response = call(client, 'read_whatsapp' if name == 'contacts_get_about' else 'write_whatsapp', body)['result']
    assert not response.get('isError'), response
    if name == 'contacts_get_about':
        assert response['structuredContent'] == {'result': {'about': ''}}
        assert env.requests == [('GET', '/api/contacts/about', {'params': {'contactId': CHAT, 'session': 'default'}})]
        assert not env.service.process_action()
        return
    assert response['structuredContent']['state'] == 'queued'
    assert all(method == 'GET' for method, _, _ in env.requests)
    assert env.service.process_action() and not env.service.process_action()
    writes = [request for request in env.requests if request[0] != 'GET']
    route = {
        'contacts_block': ('POST', '/api/contacts/block'),
        'contacts_unblock': ('POST', '/api/contacts/unblock'),
        'messages_set_star': ('PUT', '/api/star'),
        'chats_archive_chat': ('POST', '/api/default/chats/' + quote(CHAT, safe='') + '/archive'),
        'chats_unarchive_chat': ('POST', '/api/default/chats/' + quote(CHAT, safe='') + '/unarchive'),
        'chats_pin_message': ('POST', '/api/default/chats/' + quote(CHAT, safe='') + '/messages/' + quote(SOURCE, safe='') + '/pin'),
        'chats_unpin_message': ('POST', '/api/default/chats/' + quote(CHAT, safe='') + '/messages/' + quote(SOURCE, safe='') + '/unpin'),
    }
    assert len(writes) == 1 and writes[0][:2] == route[name]
    expected_body = ({'contactId': CHAT, 'session': 'default'} if name.startswith('contacts_') else
                     {'chatId': CHAT, 'messageId': SOURCE, 'star': True, 'session': 'default'} if name == 'messages_set_star' else
                     {'duration': 86400} if name == 'chats_pin_message' else {})
    assert writes[0][2].get('json', {}) == expected_body
    assert set(writes[0][2]['headers']) == {'X-WhatsApp-Intent-Id', 'X-WhatsApp-Intent-Timestamp-Ms'}
    assert env.service.store.send_status(body['idempotency_key'], owner='test-owner')['state'] == 'submitted'
    with env.service.store.db() as db:
        assert PRIVATE not in '\n'.join(db.iterdump())


@pytest.mark.parametrize('name', WRITES)
def test_read_scope_cannot_authorize_any_ab_mutation(ab_client, name):
    env, client = ab_client
    client.headers.update(headers(grant(env.token, ['whatsapp:read'])))
    response = call(client, 'write_whatsapp', {'operation': name, 'arguments': arguments(name), 'idempotency_key': 'fixture_ab_00000002'})['result']
    assert set(challenged(response)) == set(MCP_SCOPES)
    assert env.requests == [] and not env.service.process_action()


def test_read_scope_still_reads_about_without_granting_mutation_permission(ab_client):
    env, client = ab_client
    client.headers.update(headers(grant(env.token, ['whatsapp:read'])))
    response = call(client, 'read_whatsapp', {'operation': 'contacts_get_about', 'arguments': arguments('contacts_get_about')})['result']
    assert not response.get('isError') and response['structuredContent'] == {'result': {'about': ''}}
    visible = {item['operation']: item for item in capabilities(env.settings, {'whatsapp:read'}, provider_operations=AB)}
    assert visible['contacts_get_about']['permission_enabled']
    assert all(visible[name]['engine_available'] and not visible[name]['permission_enabled'] for name in WRITES)


@pytest.mark.parametrize('name', sorted(AB))
def test_caller_cannot_override_server_owned_session(ab_env, name):
    values = arguments(name)
    location = 'query' if name == 'contacts_get_about' else 'body' if name.startswith('contacts_') or name == 'messages_set_star' else 'path'
    values.setdefault(location, {})['session'] = 'another-owner-session'
    args = OperationArguments(operation=name, arguments=values) if name == 'contacts_get_about' else OperationAction(operation=name, arguments=values, idempotency_key='synthetic-ab-session-0001')
    with pytest.raises(ValueError, match='Invalid operation arguments'):
        ab_env.service.operation(args, 'test-owner', readonly=name == 'contacts_get_about')
    assert ab_env.requests == [] and not ab_env.service.process_action()


@pytest.mark.parametrize('claim', [
    {'sub': 'other-owner'}, {'aud': 'https://other.example'},
    {'iss': 'https://other-issuer.example'}, {'azp': 'other-client'},
])
def test_wrong_oauth_identity_never_reaches_ab_provider(ab_client, claim):
    env, client = ab_client
    client.headers.update(headers(grant(env.token, list(MCP_SCOPES), **claim)))
    response = client.post('/mcp', json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
        'name': 'write_whatsapp', 'arguments': {'operation': 'contacts_block', 'arguments': arguments('contacts_block'), 'idempotency_key': 'fixture_ab_00000003'}}})
    assert response.status_code == 401 and env.requests == []
    assert not env.service.process_action()


def test_durable_intent_survives_restart_and_duplicate_never_resends(ab_env):
    env = ab_env
    args = action()
    assert env.service.operation(args, 'test-owner')['state'] == 'queued'
    before = persisted(env.service, args.idempotency_key)
    assert env.service.operation(args, 'test-owner')['state'] == 'queued' and env.requests == []
    reopened = Service(env.settings, gateway=env.gateway, event_transport=env.receiver)
    assert reopened.process_action() and not reopened.process_action()
    method, _, options = env.requests[0]
    expected = 'AB' + hashlib.sha256(('gows-ab-v1\0test-owner\0' + args.idempotency_key).encode()).hexdigest()[:38].upper()
    assert method == 'POST' and options['headers'] == {
        'X-WhatsApp-Intent-Id': expected,
        'X-WhatsApp-Intent-Timestamp-Ms': str(int(before['created'] * 1000)),
    }
    after = persisted(reopened, args.idempotency_key)
    assert after['arguments'] == before['arguments'] and after['payload_hash'] == before['payload_hash']
    assert json.loads(after['arguments'])['body'] == {'contactId': CHAT}
    again = Service(env.settings, gateway=env.gateway, event_transport=env.receiver)
    assert again.operation(args, 'test-owner')['state'] == 'submitted'
    assert not again.process_action() and len(env.requests) == 1
    assert again.store.send_status(args.idempotency_key, owner='other-owner') is None
    with pytest.raises(ValueError, match='another payload'):
        again.operation(args, 'other-owner')
    assert ab_operations.durable_intent('other-owner', args.idempotency_key, before['created'])['id'] != expected


def test_restart_after_uncertain_dispatch_boundary_never_resumes_sending(ab_env):
    args = action()
    ab_env.service.operation(args, 'test-owner')
    before = persisted(ab_env.service, args.idempotency_key)
    # Model a process interruption after the durable sending marker. Whether
    # an external request happened is unknowable; recovery must not dispatch.
    with ab_env.service.store.db() as db:
        db.execute("UPDATE sends SET state='sending' WHERE key=?", (args.idempotency_key,))
    reopened = Service(ab_env.settings, gateway=ab_env.gateway, event_transport=ab_env.receiver)
    assert reopened.store.send_status(args.idempotency_key)['state'] == 'uncertain'
    assert reopened.operation(args, 'test-owner')['state'] == 'uncertain'
    assert not reopened.process_action() and ab_env.requests == []
    after = persisted(reopened, args.idempotency_key)
    assert after['payload_hash'] == before['payload_hash'] and after['arguments'] == before['arguments']


@pytest.mark.parametrize('name', WRITES)
def test_provider_downgrade_between_queue_and_worker_fails_before_send(ab_env, name):
    assert ab_env.service.operation(action(name), 'test-owner')['state'] == 'queued'
    before = len(ab_env.requests)
    ab_env.gateway.ab_operations = lambda: AB - {name}
    assert ab_env.service.process_action()
    assert ab_env.service.store.send_status('fixture_ab_00000001')['state'] == 'failed_before_send'
    assert len(ab_env.requests) == before and not ab_env.service.process_action()


@pytest.mark.parametrize('failure', ['timeout', 'uncertain', 'unexpected'])
def test_post_request_uncertainty_is_durable_and_never_automatically_retried(ab_env, failure):
    args = action()
    ab_env.service.operation(args, 'test-owner')
    if failure == 'timeout':
        ab_env.control.failure = TimeoutError(PRIVATE)
    else:
        ab_env.control.value = {'outcome': 'uncertain'} if failure == 'uncertain' else {'unexpected': True}
    assert ab_env.service.process_action()
    assert ab_env.service.store.send_status(args.idempotency_key)['state'] == 'uncertain'
    assert len(ab_env.requests) == 1 and not ab_env.service.process_action()
    reopened = Service(ab_env.settings, gateway=ab_env.gateway, event_transport=ab_env.receiver)
    assert reopened.operation(args, 'test-owner')['state'] == 'uncertain'
    assert not reopened.process_action() and len(ab_env.requests) == 1
    assert PRIVATE not in json.dumps(reopened.store.send_status(args.idempotency_key))


@pytest.mark.parametrize('duration', [None, True, 0, -1, 86401, 2**40, '86400', float('nan'), float('inf')])
def test_invalid_pin_duration_cannot_read_source_or_queue(ab_env, duration):
    args = action('chats_pin_message')
    args.arguments['body']['duration'] = duration
    with pytest.raises(ValueError):
        ab_env.service.operation(args, 'test-owner')
    assert ab_env.requests == [] and not ab_env.service.process_action()


@pytest.mark.parametrize('duration', [86400, 604800, 2592000])
def test_allowed_pin_durations_reach_wire_without_narrowing(ab_env, duration):
    args = action('chats_pin_message')
    args.arguments['body']['duration'] = duration
    ab_env.service.operation(args, 'test-owner')
    assert ab_env.service.process_action()
    assert [options['json']['duration'] for method, _, options in ab_env.requests if method == 'POST'] == [duration]


def test_unpin_rejects_duration_instead_of_ignoring_it(ab_env):
    args = action('chats_unpin_message')
    args.arguments['body'] = {'duration': 86400}
    with pytest.raises(ValueError):
        ab_env.service.operation(args, 'test-owner')
    assert ab_env.requests == []


@pytest.mark.parametrize('name', ['chats_pin_message', 'chats_unpin_message'])
def test_chat_visible_pin_actions_require_send_and_destination_permission(ab_env, name):
    settings = replace(ab_env.settings, allow_all_destinations=False, send_chat_ids=['15550009999@c.us'], account_actions_enabled=True)
    service = Service(settings, gateway=ab_env.gateway, event_transport=ab_env.receiver)
    with pytest.raises(ValueError, match='destination'):
        service.operation(action(name), 'test-owner')
    assert ab_env.requests == []
    disabled = Service(replace(settings, send_enabled=False, send_chat_ids=[CHAT]), gateway=ab_env.gateway, event_transport=ab_env.receiver)
    with pytest.raises(ValueError, match='disabled'):
        disabled.operation(action(name), 'test-owner')
    assert ab_env.requests == []
    settings = replace(settings, send_chat_ids=[CHAT], account_actions_enabled=False)
    service = Service(settings, gateway=ab_env.gateway, event_transport=ab_env.receiver)
    assert service.operation(action(name), 'test-owner')['state'] == 'queued'
    assert service.process_action()
    assert service.store.send_status('fixture_ab_00000001')['state'] == 'submitted'


def test_personal_star_requires_account_permission_and_not_send_permission(ab_env):
    settings = replace(ab_env.settings, send_enabled=False, allow_all_destinations=False, send_chat_ids=[])
    service = Service(settings, gateway=ab_env.gateway, event_transport=ab_env.receiver)
    assert service.operation(action('messages_set_star'), 'test-owner')['state'] == 'queued'
    assert service.process_action()
    denied = Service(replace(settings, account_actions_enabled=False), gateway=ab_env.gateway, event_transport=ab_env.receiver)
    count = len(ab_env.requests)
    with pytest.raises(ValueError, match='authorization'):
        denied.operation(action('messages_set_star', key='fixture_ab_00000004'), 'test-owner')
    assert len(ab_env.requests) == count


@pytest.mark.parametrize('name', ['messages_set_star', 'chats_unpin_message'])
def test_revoked_target_allows_only_metadata_removal_with_no_body_get(ab_env, name, monkeypatch):
    ab_env.service.store.ingest({'event': 'message.revoked', 'payload': {'revokedMessageId': SOURCE}})
    monkeypatch.setattr(ab_env.service.store, 'message', lambda *a, **kw: pytest.fail('Metadata removal read acquired body'))
    args = action(name, star=False)
    assert ab_env.service.operation(args, 'test-owner')['state'] == 'queued'
    assert ab_env.service.process_action()
    assert ab_env.service.store.send_status(args.idempotency_key)['state'] == 'submitted'
    assert len(ab_env.requests) == 1 and ab_env.requests[0][0] != 'GET'


@pytest.mark.parametrize('name', ['messages_set_star', 'chats_pin_message'])
@pytest.mark.parametrize('kind', ['revoke', 'expiry'])
def test_positive_action_rechecks_revocation_and_expiry_between_queue_and_worker(ab_env, name, kind):
    args = action(name)
    assert ab_env.service.operation(args, 'test-owner')['state'] == 'queued'
    if kind == 'revoke':
        ab_env.service.store.ingest({'event': 'message.revoked', 'payload': {'revokedMessageId': SOURCE}})
    else:
        ab_env.service.store.observe_message_lifetime(SOURCE, CHAT, {'kind': 'ephemeral', 'expires_at': 1})
    assert ab_env.service.process_action()
    assert ab_env.service.store.send_status(args.idempotency_key)['state'] == 'failed_before_send'
    assert len(ab_env.requests) == 1 and ab_env.requests[0][0] == 'GET'


def test_final_source_recheck_blocks_revocation_after_worker_live_read(ab_env, monkeypatch):
    args = action('chats_pin_message')
    ab_env.service.operation(args, 'test-owner')
    ready = ab_env.service.store.action_ready

    def raced(key):
        allowed = ready(key)
        ab_env.service.store.ingest({'event': 'message.revoked', 'payload': {'revokedMessageId': SOURCE}})
        return allowed

    monkeypatch.setattr(ab_env.service.store, 'action_ready', raced)
    assert ab_env.service.process_action()
    assert ab_env.service.store.send_status(args.idempotency_key)['state'] == 'failed_before_send'
    assert len(ab_env.requests) == 2 and all(method == 'GET' for method, _, _ in ab_env.requests)


@pytest.mark.parametrize('name', ['messages_set_star', 'chats_pin_message'])
def test_verified_alias_preserves_full_wire_namespace_without_mutating_job(ab_env, name):
    identifier = f'false_{LID}_SOURCE'
    ab_env.service.store.bind_chat_alias(LID, CHAT)
    ab_env.control.source = observed(identifier, LID)
    args = action(name, identifier=identifier)
    ab_env.service.operation(args, 'test-owner')
    before = persisted(ab_env.service, args.idempotency_key)
    assert ab_env.service.process_action()
    after = persisted(ab_env.service, args.idempotency_key)
    assert after['arguments'] == before['arguments'] and after['payload_hash'] == before['payload_hash']
    method, path, options = [value for value in ab_env.requests if value[0] != 'GET'][0]
    if name == 'messages_set_star':
        assert method == 'PUT' and options['json']['chatId'] == LID and options['json']['messageId'] == identifier
    else:
        assert '/chats/' + quote(LID, safe='') + '/messages/' + quote(identifier, safe='') + '/pin' in path
    assert ab_env.service.store.send_status(args.idempotency_key)['state'] == 'submitted'


@pytest.mark.parametrize('name', ['chats_archive_chat', 'chats_unarchive_chat'])
def test_archive_cache_read_failure_cannot_change_accepted_action_to_uncertain(ab_env, name):
    def failed_cache(chat):
        raise GatewayUnavailable(PRIVATE)
    ab_env.gateway.chat_archive_state = failed_cache
    args = action(name)
    ab_env.service.operation(args, 'test-owner')
    assert ab_env.service.process_action()
    assert ab_env.service.store.send_status(args.idempotency_key)['state'] == 'submitted'
    assert len(ab_env.requests) == 1 and not ab_env.service.process_action()
