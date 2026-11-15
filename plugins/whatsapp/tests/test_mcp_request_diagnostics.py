"""ASGI-only protocol probes: no sockets, credentials outside fixtures, or chat actions."""
import asyncio
import json

import pytest

from conftest import rpc
from sally_whatsapp.diagnostics import Diagnostics, RequestDiagnostics, request_id
from sally_whatsapp.mcp_diagnostics import ERROR_BODY_LIMIT


def records(settings):
    return [json.loads(line) for line in (settings.database.parent/'diagnostics/events.jsonl').read_text().splitlines()]


@pytest.mark.parametrize('method,status,code', [
    ('initialize', 404, -32601), ('ping', 404, -32601), ('tools/list', 200, None),
])
def test_modern_unsupported_handshake_is_diagnosable_without_changing_routing(app_client, environment, method, status, code):
    _, client = app_client
    value = rpc(client, method, expected_status=status)
    rows = records(environment[0])
    row = next(r for r in reversed(rows) if r['event'] == 'request.completed')
    assert row['status'] == status
    assert row['mcp_protocol_header'] == '2026-07-28'
    assert row['mcp_method_header'] == method
    if code:
        assert row['http_failure_layer'] == 'mcp_protocol'
        assert row['rpc_error_code'] == value['error']['code'] == code
        assert row['mcp_error_observation'] == 'jsonrpc'
    else:
        assert 'rpc_error_code' not in row and 'mcp_error_observation' not in row
    assert not any(r['event'] == 'tool.completed' for r in rows)


@pytest.mark.parametrize('version_header', [True, False])
def test_legacy_initialize_still_succeeds_and_missing_method_header_is_not_invented(app_client, environment, version_header):
    _, client = app_client
    del client.headers['mcp-protocol-version']
    response = client.post('/mcp', headers={'mcp-protocol-version': '2025-03-26'} if version_header else {}, json={
        'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': '2025-03-26', 'capabilities': {},
            'clientInfo': {'name': 'private-client', 'version': '0.0.1'}}})
    assert response.status_code == 200 and response.json()['result']['protocolVersion'] == '2025-03-26'
    row = next(r for r in reversed(records(environment[0])) if r['event'] == 'request.completed')
    assert row['mcp_protocol_header'] == ('2025-03-26' if version_header else 'missing')
    assert row['mcp_method_header'] == 'missing'
    assert 'rpc_error_code' not in row
    assert 'private-client' not in json.dumps(records(environment[0]))


@pytest.mark.parametrize('version,method,status,code', [
    ('2026-07-28', 'private-method', 404, -32601),
    ('2099-01-01', 'tools/list', 400, -32022),
])
def test_unknown_method_and_protocol_have_distinct_codes(app_client, environment, version, method, status, code):
    _, client = app_client
    response = client.post('/mcp', headers={'mcp-protocol-version': version, 'mcp-method': method}, json={
        'jsonrpc': '2.0', 'id': 1, 'method': method,
        'params': {'_meta': {'io.modelcontextprotocol/protocolVersion': version,
                            'io.modelcontextprotocol/clientCapabilities': {}}}})
    assert response.status_code == status and response.json()['error']['code'] == code
    row = next(r for r in reversed(records(environment[0])) if r['event'] == 'request.completed')
    assert row['rpc_error_code'] == code
    assert row['mcp_protocol_header'] == (version if version == '2026-07-28' else 'other')
    assert row['mcp_method_header'] == (method if method == 'tools/list' else 'other')
    assert 'private-method' not in json.dumps(records(environment[0]))


@pytest.mark.parametrize('version,method,status', [
    ('2026-07-28', 'GET', 405), ('2026-07-28', 'DELETE', 405),
    ('2025-03-26', 'GET', 406), ('2025-03-26', 'DELETE', 405),
])
def test_http_method_refusals_preserve_legacy_and_modern_semantics(app_client, environment, version, method, status):
    _, client = app_client
    # No SSE accept: the legacy GET ends with 406 rather than opening a stream.
    response = client.request(method, '/mcp', headers={'mcp-protocol-version': version, 'accept': 'application/json'})
    assert response.status_code == status
    row = next(r for r in reversed(records(environment[0])) if r['event'] == 'request.completed')
    assert row['method'] == method and row['status'] == status
    assert row['mcp_protocol_header'] == version and row['mcp_method_header'] == 'missing'
    assert row.get('rpc_error_code') == (None if version == '2026-07-28' else -32600)


def test_unrelated_router_404_is_not_a_protocol_error(app_client, environment):
    _, client = app_client
    response = client.post('/private-missing-route', headers={'mcp-method': 'ping'})
    assert response.status_code == 404
    row = next(r for r in reversed(records(environment[0])) if r['event'] == 'request.completed')
    assert row['route'] == 'other' and row['status'] == 404
    assert row['http_failure_layer'] == 'http_routing'
    assert not any(k.startswith(('mcp_', 'rpc_')) for k in row)
    assert 'private-' not in json.dumps(row)


def test_header_body_disagreement_is_not_mislabeled_method_not_found(app_client, environment):
    _, client = app_client
    response = client.post('/mcp', headers={'mcp-method': 'ping'}, json={
        'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list',
        'params': {'_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                            'io.modelcontextprotocol/clientCapabilities': {}}}})
    assert response.status_code == 400
    row = next(r for r in reversed(records(environment[0])) if r['event'] == 'request.completed')
    assert row['rpc_error_code'] == response.json()['error']['code'] == -32020
    # This is the observed header, not a claim that a ping was validated/dispatched.
    assert row['mcp_method_header'] == 'ping'


def test_auth_rejection_keeps_its_own_evidence(app_client, environment):
    _, client = app_client
    del client.headers['authorization']
    response = client.post('/mcp', headers={'mcp-method': 'tools/call'}, content=b'private-unparsed-body')
    assert response.status_code == 401
    rows = records(environment[0])
    admission = next(r for r in rows if r['event'] == 'auth.rejected')
    completed = next(r for r in rows if r['event'] == 'request.completed')
    assert admission['error_code'] == 'AUTH_MISSING'
    assert admission['request_id'] == completed['request_id'] == response.headers['x-request-id']
    assert completed['mcp_error_observation'] == 'not_jsonrpc'
    assert completed['http_failure_layer'] == 'authentication'
    assert 'rpc_error_code' not in completed and 'private-unparsed-body' not in json.dumps(rows)


def observe(settings, messages, *, headers=(), path='/mcp'):
    """Pass-through check: every chunk stays intact, and receive is never touched."""
    output = []
    async def receive():
        pytest.fail('Diagnostics must not read the request body')
    async def send(message):
        output.append(message)
    async def app(scope, incoming, outgoing):
        assert incoming is receive
        for message in messages:
            await outgoing(message)
    diagnostics = Diagnostics(settings)
    try:
        asyncio.run(RequestDiagnostics(app, diagnostics)(
            {'type': 'http', 'path': path, 'method': 'POST', 'headers': headers}, receive, send))
    finally:
        diagnostics.close()
    assert len(output) == len(messages)
    assert output[0]['status'] == messages[0]['status']
    assert output[0]['headers'][:-1] == messages[0]['headers']
    assert output[1:] == messages[1:]
    assert request_id.get() == ''
    return records(settings)[-1]


def response_messages(body, *, status=404, content_type=b'application/json', split=None):
    start = {'type': 'http.response.start', 'status': status, 'headers': [(b'content-type', content_type)]}
    chunks = [body] if split is None else [body[:split], body[split:]]
    return [start, *({'type': 'http.response.body', 'body': chunk, 'more_body': i < len(chunks)-1}
                    for i, chunk in enumerate(chunks))]


def test_only_finite_metadata_survives_chunked_error_and_duplicate_headers(environment):
    body = json.dumps({'jsonrpc': '2.0', 'id': 'private-rpc-id', 'error': {
        'code': -32601, 'message': 'private-message', 'data': {'token': 'private-token'}}}).encode()
    row = observe(environment[0], response_messages(body, split=35), headers=[
        (b'Mcp-Method', b'private-method'), (b'mcp-method', b'tools/list'),
        (b'mcp-protocol-version', b'private-version'), (b'authorization', b'Bearer private-credential'),
        (b'mcp-session-id', b'private-session')])
    assert row['mcp_method_header'] == 'multiple' and row['mcp_protocol_header'] == 'other'
    assert row['rpc_error_code'] == -32601 and row['mcp_error_observation'] == 'jsonrpc'
    assert 'private-' not in json.dumps(records(environment[0]))


@pytest.mark.parametrize('body,expected', [
    (b'not json private', 'invalid_json'),
    (b'['*2000 + b'!', 'invalid_json'),
    (b'{"error":{"code":-32601}}', 'not_jsonrpc'),
    (b'{"jsonrpc":"2.0","error":{"code":true}}', 'not_jsonrpc'),
    (b'{"jsonrpc":"2.0","error":{"code":123456789}}', 'other_code'),
    (b'{"jsonrpc":"2.0","error":{"code":-32601}}' + b' ' * ERROR_BODY_LIMIT, 'too_large'),
], ids=['not-json', 'deep-invalid', 'not-jsonrpc', 'bool-code', 'unknown-code', 'too-large'])
def test_malformed_large_or_nonstandard_responses_are_bounded(environment, body, expected):
    row = observe(environment[0], response_messages(body, split=20))
    assert row['mcp_error_observation'] == expected and 'rpc_error_code' not in row
    assert 'private' not in json.dumps(row)


@pytest.mark.parametrize('status,content_type', [(200, b'application/json'), (404, b'text/event-stream')])
def test_success_and_sse_bodies_are_not_inspected(environment, status, content_type):
    body = b'{"jsonrpc":"2.0","error":{"code":-32601},"secret":"private"}'
    row = observe(environment[0], response_messages(body, status=status, content_type=content_type))
    assert 'rpc_error_code' not in row
    assert row.get('mcp_error_observation') == ('not_json' if status == 404 else None)


def test_non_mcp_route_does_not_collect_protocol_fields(environment):
    row = observe(environment[0], response_messages(b'{"jsonrpc":"2.0","error":{"code":-32601}}'),
                  headers=[(b'mcp-method', b'ping')], path='/files/private-grant')
    assert row['route'] == 'files'
    assert not any(k.startswith(('mcp_', 'rpc_')) for k in row)


def test_logger_allowlist_does_not_accept_arbitrary_method_versions_or_signed_numbers(environment):
    diagnostics = Diagnostics(environment[0])
    diagnostics.emit('test.invalid', mcp_method_header='private-method', mcp_protocol_header='private-version',
                     mcp_error_observation='private', rpc_error_code=-123456, count=-1)
    diagnostics.emit('test.valid', mcp_method_header='tools/list', mcp_protocol_header='2026-07-28',
                     rpc_error_code=-32601, count=1)
    diagnostics.close()
    first, second = records(environment[0])
    assert not any(k.startswith(('mcp_', 'rpc_')) for k in first) and 'count' not in first
    assert second['mcp_method_header'] == 'tools/list' and second['rpc_error_code'] == -32601
    assert second['count'] == 1 and 'private' not in json.dumps([first, second])


@pytest.mark.parametrize('cancelled', [False, True])
def test_interrupted_response_is_not_a_complete_error_and_context_is_reset(environment, cancelled):
    output = []
    async def receive():
        pytest.fail('Diagnostics must not consume the request')
    async def send(message):
        output.append(message)
    async def app(scope, incoming, outgoing):
        await outgoing({'type': 'http.response.start', 'status': 404,
                        'headers': [(b'content-type', b'application/json')]})
        await outgoing({'type': 'http.response.body', 'body': b'{"private":', 'more_body': True})
        if cancelled:
            raise asyncio.CancelledError()
        raise RuntimeError('private-exception')
    diagnostics = Diagnostics(environment[0])
    async def exercise():
        wrapped = RequestDiagnostics(app, diagnostics)
        if cancelled:
            with pytest.raises(asyncio.CancelledError):
                await wrapped({'type': 'http', 'path': '/mcp', 'method': 'POST'}, receive, send)
        else:
            await wrapped({'type': 'http', 'path': '/mcp', 'method': 'POST'}, receive, send)
        assert request_id.get() == ''
    try:
        asyncio.run(exercise())
    finally:
        diagnostics.close()
    rows = records(environment[0])
    assert rows[-1]['mcp_error_observation'] == 'incomplete' and 'rpc_error_code' not in rows[-1]
    assert output[1]['body'] == b'{"private":'
    assert len(output) == (2 if cancelled else 3)
    if not cancelled:
        assert output[-1] == {'type': 'http.response.body', 'body': b'', 'more_body': False}
        assert rows[0]['event'] == 'request.failed' and rows[0]['exception'] == 'RuntimeError'
    assert 'private' not in json.dumps(rows)
