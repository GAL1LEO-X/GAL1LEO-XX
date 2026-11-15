"""QA129: authenticated synthetic events and ASGI requests; no live accounts."""
import asyncio
import hmac
import json
from pathlib import Path
import re
import time

import httpx
import pytest
from jsonschema import Draft202012Validator

from conftest import call, rpc
from sally_whatsapp.diagnostics import reference
from sally_whatsapp.event_validation import EventValidationError, REJECTION_CONTRACT
from sally_whatsapp.server import SendKey
from test_diagnostics import records


def engine_event(subtype='events.Pin', data=None):
    return {'id': 'synthetic-private-event-id', 'event': 'engine.event', 'engine': 'GOWS',
            'session': 'default', 'payload': {'event': subtype, 'session': 'default', 'data': data or {
                'JID': '1234567@c.us', 'Timestamp': '2026-10-24T07:15:30Z',
                'Action': {'pinned': True}, 'private': 'never-log-private-event-content'}}}


def signed_post(client, settings, value):
    body = value if isinstance(value, bytes) else json.dumps(value).encode()
    return client.post('/webhooks/waha', content=body, headers={
        'x-webhook-hmac-algorithm': 'sha512',
        'x-webhook-hmac': hmac.digest(settings.webhook_secret_file.read_bytes(), body, 'sha512').hex(),
        'x-webhook-request-id': 'synthetic-private-delivery-id',
    })


@pytest.mark.parametrize('field,bad,expected,reason', [
    ('JID', None, 'JID', 'invalid_type'),
    ('Timestamp', 123, 'Timestamp', 'invalid_type'),
    ('Timestamp', 'not-a-date-private', 'Timestamp', 'invalid_value'),
    ('Action', {'pinned': 'private-yes'}, 'Action.pinned', 'invalid_type'),
    ('Action', [], 'Action', 'invalid_type'),
    ('FromFullSync', 'private-no', 'FromFullSync', 'invalid_type'),
])
def test_engine_rejection_is_classified_correlated_and_does_not_acquire(app_client, environment, field, bad, expected, reason):
    app, client = app_client
    settings, *_ = environment
    event = engine_event()
    event['payload']['data'][field] = bad
    before = app.state.service.store.path.read_bytes()
    response = signed_post(client, settings, event)
    repeated = signed_post(client, settings, event)
    assert response.status_code == repeated.status_code == 400
    assert response.json() == {'error': 'invalid_event', 'contract': REJECTION_CONTRACT,
                               'error_code': 'EVENT_ENGINE_VALIDATION', 'retryable': False}
    rows = [r for r in records(settings) if r['event'] == 'webhook.rejected']
    assert len(rows) == 2
    for row, result in zip(rows, (response, repeated)):
        assert row['source_event'] == 'engine.event' and row['source_subtype'] == 'events.Pin'
        assert (row['validation_field'], row['validation_reason']) == (expected, reason)
        assert row['event_ref'] == reference(event['id'])
        assert row['delivery_ref'] == reference('synthetic-private-delivery-id')
        assert row['request_id'] == result.headers['x-request-id']
    assert rows[0]['request_id'] != rows[1]['request_id']
    assert before == app.state.service.store.path.read_bytes()
    assert not any(secret in json.dumps(rows) for secret in (
        '1234567', event['id'], 'synthetic-private-delivery-id', 'private-event-content', 'private-yes', 'private-no', 'not-a-date-private'))


@pytest.mark.parametrize('subtype,data,expected', [
    ('events.Archive', {'JID': '1234567@c.us', 'Timestamp': '2026-10-24T07:15:30Z', 'Action': {}}, 'archived'),
    ('events.ClearChat', {'JID': '1234567@c.us', 'Timestamp': '2026-10-24T07:15:30Z', 'Action': {'messageRange': []}}, 'Action.messageRange'),
])
def test_linked_state_rejections_share_the_bounded_contract(app_client, environment, subtype, data, expected):
    _, client = app_client
    settings, *_ = environment
    assert signed_post(client, settings, engine_event(subtype, data)).status_code == 400
    row = [r for r in records(settings) if r['event'] == 'webhook.rejected'][-1]
    assert row['source_subtype'] == subtype and row['validation_field'] == expected


def test_unknown_engine_subtypes_remain_ignored_and_valid_events_are_deduplicated(app_client, environment):
    _, client = app_client
    settings, *_ = environment
    unknown = engine_event('private-unlisted-subtype')
    response = signed_post(client, settings, unknown)
    assert response.status_code == 200 and response.json()['ignored'] is True
    event = engine_event()
    assert signed_post(client, settings, event).status_code == 200
    repeated = signed_post(client, settings, event)
    assert repeated.status_code == 200 and repeated.json()['duplicate'] is True
    assert 'private-unlisted-subtype' not in json.dumps(records(settings))


@pytest.mark.parametrize('error', [ValueError('unclassified-private-failure'), TypeError('Message chat/timestamp required'), KeyError('private-key')])
def test_unclassified_ingestion_failures_do_not_disable_provider_retries(app_client, environment, monkeypatch, error):
    app, client = app_client
    settings, *_ = environment
    def failed(_): raise error
    monkeypatch.setattr(app.state.service, 'ingest', failed)
    result = signed_post(client, settings, engine_event())
    assert result.status_code == 400 and result.json() == {'error': 'invalid_event'}
    assert 'unclassified-private-failure' not in json.dumps(records(settings))


def test_json_is_terminal_but_credentials_and_outer_session_are_not(app_client, environment):
    _, client = app_client
    settings, *_ = environment
    bad_json = signed_post(client, settings, b'{"private-body":')
    assert bad_json.json()['error_code'] == 'EVENT_JSON' and bad_json.json()['retryable'] is False
    wrong_session = engine_event(); wrong_session['session'] = 'wrong-private-session'
    assert signed_post(client, settings, wrong_session).json() == {'error': 'invalid_event'}
    unsigned = client.post('/webhooks/waha', json=engine_event())
    assert unsigned.status_code == 401 and 'retryable' not in unsigned.json()


def test_error_field_labels_cannot_echo_arbitrary_keys():
    from sally_whatsapp.provider_events import _bool
    with pytest.raises(EventValidationError) as error:
        _bool('private-value', field='private-field-name')
    assert error.value.field == 'data' and 'private' not in str(error.value)


@pytest.mark.parametrize('args,valid', [
    ({'idempotency_key': 'synthetic-known-key'}, True),
    ({'mode': 'uncertain'}, True),
    ({'mode': 'uncertain', 'limit': 1, 'offset': 1}, True),
    ({'mode': 'uncertain', 'limit': 100, 'offset': 1000000}, True),
    ({}, False), ({'mode': 'single'}, False),
    ({'mode': 'uncertain', 'idempotency_key': None}, False),
    ({'idempotency_key': 'synthetic-known-key', 'limit': 1}, False),
    ({'mode': 'uncertain', 'limit': 1.5}, False),
    ({'mode': 'uncertain', 'limit': True}, False),
    ({'mode': 'uncertain', 'limit': 0}, False),
    ({'mode': 'uncertain', 'offset': -1}, False),
    ({'mode': 'uncertain', 'offset': 1000001}, False),
    ({'idempotency_key': 'short'}, False),
    ({'idempotency_key': 'x'*129}, False),
    ({'mode': 'uncertain', 'extra': 'forbidden'}, False),
])
def test_send_status_union_is_self_contained_for_branch_projection(args, valid):
    schema = SendKey.model_json_schema()
    Draft202012Validator.check_schema(schema)
    assert Draft202012Validator(schema).is_valid(args) is valid
    assert sum(Draft202012Validator(branch).is_valid(args) for branch in schema['oneOf']) == int(valid)
    if valid: SendKey.model_validate(args)
    else:
        with pytest.raises(ValueError): SendKey.model_validate(args)


def test_mcp_discovery_exposes_pagination_and_calls_continue_without_writes(app_client):
    app, client = app_client
    tool = next(t for t in rpc(client, 'tools/list')['result']['tools'] if t['name'] == 'get_send_status')
    branch = next(b for b in tool['inputSchema']['oneOf'] if b['properties']['mode']['const'] == 'uncertain')
    assert set(branch['properties']) == {'mode', 'limit', 'offset'}
    assert all(branch['properties'][n]['type'] == 'integer' for n in ('limit', 'offset'))
    store = app.state.service.store
    for number in range(3):
        key = f'synthetic-own-action-{number}'
        store.queue_action(key, 'test-owner', 'messages_set_star', {})
        store.finish_send(key, 'uncertain')
    store.queue_action('synthetic-other-action', 'other-owner', 'messages_set_star', {})
    store.finish_send('synthetic-other-action', 'uncertain')
    before = store.path.read_bytes()
    offset, keys = 0, []
    while offset is not None:
        args = {'mode': 'uncertain', 'limit': 1, 'offset': offset}
        Draft202012Validator(branch).validate(args)
        page = call(client, 'get_send_status', args)['result']['structuredContent']
        assert page['total'] == 3
        keys.extend(item['key'] for item in page['actions']); offset = page['next_offset']
    assert len(set(keys)) == 3 and 'synthetic-other-action' not in keys
    assert before == store.path.read_bytes()


@pytest.mark.parametrize('case,status,code,stage', [
    ('missing', 401, 'AUTH_MISSING', 'admission'),
    ('scheme', 401, 'AUTH_SCHEME', 'admission'),
    ('empty', 401, 'AUTH_EMPTY', 'admission'),
    ('malformed', 401, 'AUTH_TOKEN', 'verification'),
    ('expired', 401, 'AUTH_TOKEN', 'verification'),
    ('owner', 401, 'AUTH_OWNER', 'verification'),
    ('client', 401, 'AUTH_CLIENT', 'verification'),
    ('audience', 401, 'AUTH_TOKEN', 'verification'),
    ('issuer', 401, 'AUTH_TOKEN', 'verification'),
    ('scope', 403, 'AUTH_SCOPE', 'authorization'),
])
def test_auth_admission_is_classified_once_and_correlated(app_client, environment, case, status, code, stage):
    _, client = app_client
    settings, _, _, token = environment
    headers = {'missing': None, 'scheme': 'Basic private-credential', 'empty': 'Bearer ',
               'malformed': 'Bearer private-not-a-token',
               'expired': 'Bearer '+token(exp=int(time.time())-60),
               'owner': 'Bearer '+token(sub='private-other-owner'),
               'client': 'Bearer '+token(azp='private-other-client'),
               'audience': 'Bearer '+token(aud='https://private.example'),
               'issuer': 'Bearer '+token(iss='https://private.example'),
               'scope': 'Bearer '+token(scope='whatsapp:send')}
    if headers[case] is None: del client.headers['Authorization']
    else: client.headers['Authorization'] = headers[case]
    response = client.post('/mcp')
    assert response.status_code == status
    rows = [r for r in records(settings) if r['event'] == 'auth.rejected']
    assert len(rows) == 1
    assert (rows[0]['error_code'], rows[0]['auth_stage']) == (code, stage)
    assert rows[0]['request_id'] == response.headers['x-request-id']
    assert 'private' not in json.dumps(rows)
    assert not headers[case] or headers[case] not in json.dumps(rows)


def test_auth_context_is_isolated_across_concurrent_requests_and_cleared(app_client, environment):
    app, _ = app_client
    settings, _, _, token = environment
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
            return await asyncio.gather(*[client.post('/mcp', headers=header) for header in (
                {}, {'Authorization': 'Basic private'}, {'Authorization': 'Bearer '+token(sub='other-owner')},
                {'Authorization': 'Bearer '+token(scope='whatsapp:send')},
                {'Authorization': 'Bearer '+token()},
            )])
    responses = asyncio.run(run())
    rows = {r['request_id']: r for r in records(settings) if r['event'] == 'auth.rejected'}
    assert len(rows) == 4
    for result, code in zip(responses, ('AUTH_MISSING', 'AUTH_SCHEME', 'AUTH_OWNER', 'AUTH_SCOPE')):
        assert rows[result.headers['x-request-id']]['error_code'] == code
    assert responses[-1].headers['x-request-id'] not in rows
    from sally_whatsapp.diagnostics import auth_admission
    assert auth_admission.get() is None


def test_auth_admission_does_not_blame_permissions_for_unrelated_http_forbidden():
    from sally_whatsapp.diagnostics import AuthAdmission
    observation = AuthAdmission({'headers': [(b'authorization', b'Bearer private-token')]})
    observation.verified = True
    assert observation.rejected_fields(403) is None
    assert observation.rejected_fields(503) is None
    observation.challenge = 'invalid_token'
    assert observation.rejected_fields(401)['auth_reason'] == 'post_verification_rejected'


def test_duplicate_credentials_are_described_without_guessing_the_rejected_cause():
    from sally_whatsapp.diagnostics import AuthAdmission
    observation = AuthAdmission({'headers': [(b'authorization', b''), (b'Authorization', b'Bearer private-token')]})
    observation.challenge = 'invalid_token'
    assert observation.credential_state == 'multiple'
    assert observation.rejected_fields(401)['error_code'] == 'AUTH_ADMISSION'


def test_versioned_webhook_handshake_matches_the_corresponding_provider_patch():
    import hashlib
    from sally_whatsapp.event_validation import PERMANENT_EVENT_CODES
    folder = Path(__file__).parents[1] / 'provider-checkpoint/qa129'
    patch = (folder / 'waha.patch').read_bytes()
    manifest = json.loads((folder / 'manifest.json').read_text())
    assert hashlib.sha256(patch).hexdigest() == manifest['sources']['waha']['patch_sha256']
    assert len(patch) == manifest['sources']['waha']['patch_bytes']
    added_source = '\n'.join(line[1:] for line in patch.decode().splitlines() if line.startswith('+') and not line.startswith('+++'))
    literal = re.search(r'const PERMANENT_EVENT_CODES = new Set\(\[(.*?)\]\);', added_source, re.S)
    assert literal is not None
    assert set(re.findall(r"'([A-Z_]+)'", literal[1])) == PERMANENT_EVENT_CODES
    assert REJECTION_CONTRACT in added_source and manifest['contract']['receiver'] == REJECTION_CONTRACT
