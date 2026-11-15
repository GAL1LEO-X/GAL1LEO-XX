"""Real SDK dispatch and synthetic attachments, without sockets or HTTP clients."""
import asyncio
import base64
from dataclasses import replace
import hashlib
import time
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from mcp import types
from mcp.server.connection import Connection
from mcp.server.runner import ServerRunner
from mcp.shared.exceptions import MCPError

from sally_whatsapp import server
from sally_whatsapp.auth import JWTVerifier
from sally_whatsapp.mcp_resources import MAX_RESOURCE_BYTES, read_attachment
from test_revoked_media_metadata import CONTENT, attachment, revoke


@pytest.fixture
def mcp_app(environment, monkeypatch):
    settings, receiver, gateway, token = environment
    captured = {}
    constructor = server.Server
    def capture(*args, **kwargs):
        captured.update(kwargs)
        captured['sdk'] = constructor(*args, **kwargs)
        return captured['sdk']
    monkeypatch.setattr(server, 'Server', capture)
    app = server.create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    service = app.state.service
    verified = JWTVerifier(settings)._verify(token())
    monkeypatch.setattr(server, 'get_access_token', lambda: verified)
    captured.update(service=service, token=verified, app=app)
    yield captured
    service.readiness.close_when_drained(service.diagnostics.close)
    service.transcriptions.close()
    gateway.close()


def external_file(service, content=b'synthetic bytes', owner=None):
    owner = owner or service.settings.owner_subject
    job = service.media.enqueue(owner, {'kind': 'external', 'file_id': 'synthetic',
        'download_url': 'https://files.example/synthetic'}, 'synthetic.bin', 'application/octet-stream')
    service.media.path(job['id']).write_bytes(content)
    with service.store.db() as db:
        db.execute("UPDATE media_jobs SET state='ready', size=?, sha256=?, source=X'' WHERE id=?",
            (len(content), hashlib.sha256(content).hexdigest(), job['id']))
    return job['id'], service.media.url(job['id'], owner)


async def dispatch(captured, method, **params):
    connection = Connection.from_envelope('2026-07-28', None, {})
    runner = ServerRunner(captured['sdk'], connection, None)
    context = SimpleNamespace(message_metadata=None, request_id=1)
    task = asyncio.create_task(runner.on_request(context, method, {**params, '_meta': {
        'io.modelcontextprotocol/protocolVersion': '2026-07-28',
        'io.modelcontextprotocol/clientCapabilities': {}}}))
    # A finite timer also makes this no-socket harness usable in sandboxes
    # whose event-loop self-pipe cannot wake on worker-thread completion.
    async with asyncio.timeout(5):
        while not task.done():
            await asyncio.sleep(.005)
    value = task.result()
    model = {'tools/list': types.ListToolsResult, 'tools/call': types.CallToolResult,
             'resources/read': types.ReadResourceResult, 'resources/list': types.ListResourcesResult,
             'resources/templates/list': types.ListResourceTemplatesResult}[method]
    return model.model_validate(value)


def test_emitted_link_is_readable_through_real_sdk_and_not_enumerated(mcp_app):
    captured = mcp_app
    identifier, _ = external_file(captured['service'])
    async def exercise():
        tools = await dispatch(captured, 'tools/list')
        assert len(tools.tools) == 27
        status = await dispatch(captured, 'tools/call', name='get_transfer_status',
                                arguments={'transfer_id': identifier})
        link = next(block for block in status.content if block.type == 'resource_link')
        assert status.structured_content['resource_read']['available'] is True
        value = await dispatch(captured, 'resources/read', uri=str(link.uri))
        assert base64.b64decode(value.contents[0].blob) == b'synthetic bytes'
        assert str(value.contents[0].uri) == str(link.uri)
        assert (await dispatch(captured, 'resources/list')).resources == []
        assert (await dispatch(captured, 'resources/templates/list')).resource_templates == []
    asyncio.run(exercise())
    assert captured['sdk'].get_capabilities(protocol_version='2026-07-28').resources is not None
    from sally_whatsapp.discovery_contract import expected_contract
    expected = expected_contract()['capabilities']
    expected.pop('events')  # Advertised by the plugin metadata middleware.
    assert captured['sdk'].get_capabilities(protocol_version='2026-07-28').model_dump(
        by_alias=True, exclude_none=True) == expected
    assert captured['service'].gateway.sent == []


@pytest.mark.parametrize('size', [MAX_RESOURCE_BYTES, MAX_RESOURCE_BYTES + 1])
def test_bounded_resource_contract_preserves_large_https_downloads(mcp_app, size):
    service = mcp_app['service']
    identifier, uri = external_file(service, b'x' * size)
    async def exercise():
        status = await dispatch(mcp_app, 'tools/call', name='get_transfer_status', arguments={'transfer_id': identifier})
        available = size <= MAX_RESOURCE_BYTES
        assert status.structured_content['resource_read']['available'] is available
        assert any(item.type == 'resource_link' for item in status.content) is available
        assert status.structured_content['download_url'].startswith(service.settings.public_url + '/files/')
        if available:
            assert len(base64.b64decode((await dispatch(mcp_app, 'resources/read', uri=uri)).contents[0].blob)) == size
        else:
            with pytest.raises(MCPError):
                await dispatch(mcp_app, 'resources/read', uri=uri)
            # The existing streamed HTTPS resolution is not subject to the MCP cap.
            assert service.media.resolve(uri.rsplit('/', 1)[1])[1]['size'] == size
    asyncio.run(exercise())


@pytest.mark.parametrize('kind', ['anonymous', 'wrong_scope', 'wrong_owner'])
def test_resource_methods_require_owner_and_read_scope(mcp_app, monkeypatch, kind):
    _, uri = external_file(mcp_app['service'])
    token = mcp_app['token'].model_copy(deep=True)
    if kind == 'wrong_scope': token.scopes = ['whatsapp:send']
    if kind == 'wrong_owner': token.subject = 'other-owner'
    monkeypatch.setattr(server, 'get_access_token', lambda: None if kind == 'anonymous' else token)
    async def exercise():
        for method in ('resources/list', 'resources/templates/list', 'resources/read'):
            with pytest.raises(MCPError):
                await dispatch(mcp_app, method, **({'uri': uri} if method.endswith('/read') else {}))
    asyncio.run(exercise())


@pytest.mark.parametrize('uri', ['https://other.example/files/a', 'file:///etc/passwd',
    'https://bridge.example/files/../private', 'https://bridge.example/files/a?token=x',
    'https://bridge.example/files/a#fragment', 'https://bridge.example/files/a%2Fb',
    'https://bridge.example/files/' + 'a' * 4097])
def test_foreign_or_malformed_uri_is_rejected_before_media_resolution(mcp_app, monkeypatch, uri):
    monkeypatch.setattr(mcp_app['service'].media, 'resolve', lambda *a, **kw: pytest.fail('No URI fetch/resolution allowed'))
    with pytest.raises(ValueError):
        read_attachment(mcp_app['service'].media, uri, 'test-owner')


def test_foreign_transfer_owner_and_foreign_instance_grant_rejected(mcp_app, environment, tmp_path):
    service = mcp_app['service']
    _, uri = external_file(service, owner='other-owner')
    with pytest.raises(ValueError):
        read_attachment(service.media, uri, 'test-owner')
    _, uri = external_file(service)
    key = tmp_path / 'other-instance.key'
    key.write_bytes(Fernet.generate_key())
    other = server.Service(replace(environment[0], database=tmp_path/'other.sqlite', encryption_key_file=key),
                           gateway=environment[2], event_transport=environment[1])
    try:
        with pytest.raises(ValueError):
            read_attachment(other.media, uri, 'test-owner')
    finally:
        other.diagnostics.close()
        other.transcriptions.close()


@pytest.mark.parametrize('change', ['expired', 'grant_expired', 'tampered', 'revoked', 'changed_after_read', 'mime_changed_after_read'])
def test_resource_read_rechecks_lifetime_integrity_and_revocation(mcp_app, monkeypatch, change):
    service = mcp_app['service']
    if change == 'revoked':
        service.gateway.media_bytes = CONTENT
        identifier = attachment(service)
        assert service.media.process_one()
        uri = service.media.url(identifier, 'test-owner')
        revoke(service)
    else:
        identifier, uri = external_file(service)
        if change == 'expired':
            with service.store.db() as db:
                db.execute('UPDATE media_jobs SET expires=0 WHERE id=?', (identifier,))
        elif change == 'grant_expired':
            original = service.media.cipher.decrypt(uri.rsplit('/', 1)[1].encode())
            uri = service.settings.public_url + '/files/' + service.media.cipher.encrypt_at_time(
                original, int(time.time()) - service.settings.media_ttl_seconds - 1).decode()
        elif change == 'tampered':
            service.media.path(identifier).write_bytes(b'modified bytes')
        elif change in {'changed_after_read', 'mime_changed_after_read'}:
            resolve = service.media.resolve
            calls = []
            def invalidate(*args, **kwargs):
                calls.append(True)
                if len(calls) == 2:
                    with service.store.db() as db:
                        if change == 'changed_after_read':
                            db.execute('UPDATE media_jobs SET expires=0 WHERE id=?', (identifier,))
                        else:
                            db.execute("UPDATE media_jobs SET mimetype='text/plain' WHERE id=?", (identifier,))
                return resolve(*args, **kwargs)
            monkeypatch.setattr(service.media, 'resolve', invalidate)
    async def exercise():
        with pytest.raises(MCPError):
            await dispatch(mcp_app, 'resources/read', uri=uri)
    asyncio.run(exercise())
