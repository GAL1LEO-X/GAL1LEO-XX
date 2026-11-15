"""Real SDK tool responses with synthetic image bytes; no resource RPC or server."""
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import zlib

import pytest

from conftest import attachment_payload, install_attachment_readback
from sally_whatsapp import server
from sally_whatsapp.inline_images import attachment_image, image_dimensions
from sally_whatsapp.mcp_resources import MAX_RESOURCE_BYTES, read_attachment
from test_mcp_resource_reads import dispatch, external_file, mcp_app


FIXTURES = Path(__file__).parent / 'fixtures/media-integrity'


def image_file(service, name='sample.png', *, content=None, mimetype=None, owner=None):
    data = (FIXTURES / name).read_bytes() if content is None else content
    kind = mimetype or {'sample.png': 'image/png', 'sample.jpg': 'image/jpeg',
                        'sample.webp': 'image/webp'}[name]
    identifier, uri = external_file(service, data, owner=owner)
    with service.store.db() as db:
        db.execute('UPDATE media_jobs SET filename=?,mimetype=? WHERE id=?', (name, kind, identifier))
    return identifier, uri, data


def call_status(app, identifier):
    return asyncio.run(dispatch(app, 'tools/call', name='get_transfer_status',
                                arguments={'transfer_id': identifier}))


def png_chunk(kind, payload):
    return (len(payload).to_bytes(4, 'big') + kind + payload
            + (zlib.crc32(kind + payload) & 0xffffffff).to_bytes(4, 'big'))


@pytest.mark.parametrize('name', ['sample.jpg', 'sample.png', 'sample.webp'])
def test_ready_image_delivers_original_pixels_in_the_tool_result(mcp_app, name):
    service = mcp_app['service']
    identifier, _, data = image_file(service, name)
    value = call_status(mcp_app, identifier)
    assert not value.is_error
    assert [item.type for item in value.content] == ['text', 'image', 'resource_link']
    block = value.content[1]
    assert base64.b64decode(block.data, validate=True) == data
    assert block.mime_type == value.structured_content['mimetype']
    # Check wire spelling and actual payload, not merely a ready/available flag.
    raw = block.model_dump(by_alias=True, exclude_none=True)
    assert raw == {'type': 'image', 'data': base64.b64encode(data).decode(), 'mimeType': block.mime_type}
    assert value.structured_content['sha256'] == hashlib.sha256(data).hexdigest()
    info = value.structured_content['image_content']
    assert info == {'included': True, 'max_bytes': MAX_RESOURCE_BYTES, 'client_rendering_verified': False,
                    'transport': 'mcp_image_content', 'width': 16, 'height': 16}
    assert block.data not in value.content[0].text
    assert block.data not in json.dumps(value.structured_content)
    assert value.structured_content['resource_read']['availability_scope'] == 'server_only'
    assert value.structured_content['resource_read']['client_support_verified'] is False
    assert value.content[2].uri == value.structured_content['download_url']
    # This test invokes only tools/call. It cannot prove a hosted adapter renders it.
    assert service.gateway.sent == []


@pytest.mark.parametrize('size', [MAX_RESOURCE_BYTES, MAX_RESOURCE_BYTES + 1])
def test_inline_size_boundary_preserves_original_download(mcp_app, size):
    png = (FIXTURES / 'sample.png').read_bytes()
    png = png[:-12] + png_chunk(b'tEXt', b'x' * (size - len(png) - 12)) + png[-12:]
    assert len(png) == size
    identifier, _, _ = image_file(mcp_app['service'], content=png)
    value = call_status(mcp_app, identifier)
    assert not value.is_error and value.structured_content['state'] == 'ready'
    included = size <= MAX_RESOURCE_BYTES
    assert value.structured_content['image_content']['included'] is included
    assert any(item.type == 'image' for item in value.content) is included
    assert value.structured_content['download_url'].startswith('https://bridge.example/files/')
    if included:
        block = next(item for item in value.content if item.type == 'image')
        assert base64.b64decode(block.data) == png
    else:
        assert value.structured_content['image_content']['reason'] == 'size_limit'
    assert mcp_app['service'].media.path(identifier).read_bytes() == png


@pytest.mark.parametrize('mimetype,data', [
    ('application/pdf', b'%PDF-1.7 synthetic'), ('text/plain', b'synthetic text'),
    ('image/svg+xml', b'<svg><script>not executable</script></svg>'),
    ('image/gif', b'GIF89a'), ('image/jpeg', b'not an image'),
    ('image/jpeg', (FIXTURES / 'sample.png').read_bytes()),
    ('image/png', (FIXTURES / 'sample.png').read_bytes()[:-1]),
    ('image/webp', b'RIFF\x04\x00\x00\x00WEBP'),
])
def test_unsupported_invalid_or_mislabeled_bytes_do_not_become_image_content(mcp_app, mimetype, data):
    service = mcp_app['service']
    identifier, uri, _ = image_file(service, content=data, mimetype=mimetype)
    value = call_status(mcp_app, identifier)
    assert not value.is_error and value.structured_content['state'] == 'ready'
    assert not value.structured_content['image_content']['included']
    assert not any(item.type == 'image' for item in value.content)
    assert value.structured_content['download_url']
    # Rejecting visual admission does not delete, re-encode or invalidate a file.
    assert service.media.path(identifier).read_bytes() == data
    assert base64.b64decode(read_attachment(service.media, uri, 'test-owner').contents[0].blob) == data


@pytest.mark.parametrize('width,height', [(0, 16), (8193, 16), (4001, 4000), (2**32-1, 2**32-1)])
def test_image_dimensions_are_bounded_without_decompression(mcp_app, width, height):
    data = (FIXTURES / 'sample.png').read_bytes()
    header = width.to_bytes(4, 'big') + height.to_bytes(4, 'big') + data[24:29]
    data = data[:8] + png_chunk(b'IHDR', header) + data[33:]
    identifier, _, _ = image_file(mcp_app['service'], content=data)
    value = call_status(mcp_app, identifier)
    assert value.structured_content['image_content']['reason'] == 'unsupported_or_invalid_image'
    assert not any(item.type == 'image' for item in value.content)


def test_animated_png_is_not_silently_presented_as_a_static_image(mcp_app):
    data = (FIXTURES / 'sample.png').read_bytes()
    data = data[:33] + png_chunk(b'acTL', (2).to_bytes(4, 'big') + b'\0'*4) + data[33:]
    identifier, _, _ = image_file(mcp_app['service'], content=data)
    value = call_status(mcp_app, identifier)
    assert not value.structured_content['image_content']['included']
    assert not any(item.type == 'image' for item in value.content)


def webp_chunk(kind, payload):
    return kind + len(payload).to_bytes(4, 'little') + payload + b'\0' * (len(payload) % 2)


@pytest.mark.parametrize('flags,extra,accepted', [
    (0, b'', True), (2, b'', False), (0, webp_chunk(b'ANIM', b'\0' * 6), False),
    (0, webp_chunk(b'ANMF', b'\0' * 16), False), (0x80, b'', False),
])
def test_extended_webp_admits_static_frames_and_rejects_animation(flags, extra, accepted):
    simple = (FIXTURES / 'sample.webp').read_bytes()
    header = bytes([flags]) + b'\0' * 3 + (15).to_bytes(3, 'little') * 2
    chunks = webp_chunk(b'VP8X', header) + extra + simple[12:]
    data = b'RIFF' + (4 + len(chunks)).to_bytes(4, 'little') + b'WEBP' + chunks
    assert image_dimensions(data, 'image/webp') == ((16, 16) if accepted else None)


@pytest.mark.parametrize('mutation', ['crc', 'invalid_depth', 'missing_data'])
def test_png_container_rejects_corruption_and_invalid_header(mutation):
    data = (FIXTURES / 'sample.png').read_bytes()
    if mutation == 'crc':
        data = data[:29] + bytes([data[29] ^ 1]) + data[30:]
    elif mutation == 'invalid_depth':
        # RGB does not permit a 1-bit sample depth, even with a matching CRC.
        data = data[:8] + png_chunk(b'IHDR', data[16:24] + b'\x01\x02' + data[26:29]) + data[33:]
    else:
        data = data[:33] + data[-12:]
    assert image_dimensions(data, 'image/png') is None


@pytest.mark.parametrize('mutation', ['expired_after_read', 'metadata_changed_after_read'])
def test_source_change_before_return_emits_no_image_or_stale_link(mcp_app, monkeypatch, mutation):
    media = mcp_app['service'].media
    identifier, _, _ = image_file(mcp_app['service'])
    original, calls = media.resolve, []
    def race(*args, **kwargs):
        calls.append(True)
        if len(calls) == 2:
            with media.store.db() as db:
                if mutation == 'expired_after_read':
                    db.execute('UPDATE media_jobs SET expires=0 WHERE id=?', (identifier,))
                else:
                    db.execute("UPDATE media_jobs SET mimetype='image/jpeg' WHERE id=?", (identifier,))
        return original(*args, **kwargs)
    monkeypatch.setattr(media, 'resolve', race)
    value = call_status(mcp_app, identifier)
    assert value.is_error and all(item.type == 'text' for item in value.content)
    assert '/files/' not in value.content[0].text


@pytest.mark.parametrize('source', ['archive', 'live'])
@pytest.mark.parametrize('stage', ['before_status', 'after_image_read'])
def test_gateway_image_source_is_verified_and_revocation_prevents_delivery(mcp_app, monkeypatch, source, stage):
    service = mcp_app['service']
    data = (FIXTURES / 'sample.png').read_bytes()
    identifier = 'false_15550001111@c.us_SYNTHETICIMAGE'
    payload = attachment_payload(identifier, '15550001111@c.us', data,
                                 name='sample.png', mimetype='image/png', kind='imageMessage')
    install_attachment_readback(service.gateway, payload)
    original_read, reads = service.gateway.request, []
    def read(method, path, **kwargs):
        reads.append(method)
        return original_read(method, path, **kwargs)
    monkeypatch.setattr(service.gateway, 'request', read)
    service.gateway.media_bytes = data
    if source == 'archive':
        service.store.ingest({'id': 'synthetic-image-event', 'event': 'message.any', 'payload': payload})
    queued = asyncio.run(dispatch(mcp_app, 'tools/call', name='get_attachment',
        arguments={'message_id': identifier, 'source': source}))
    assert not queued.is_error
    transfer = queued.structured_content['id']
    assert service.media.process_one()
    first = call_status(mcp_app, transfer)
    assert not first.is_error
    assert base64.b64decode(next(block.data for block in first.content if block.type == 'image')) == data
    assert reads == ['GET'] * (2 if source == 'archive' else 6)
    def revoke():
        service.store.ingest({'event': 'message.revoked', 'id': 'synthetic-revocation',
                             'payload': {'revokedMessageId': identifier}})
    if stage == 'before_status':
        revoke()
    else:
        original_resolve, resolutions = service.media.resolve, []
        def raced(*args, **kwargs):
            resolutions.append(True)
            if len(resolutions) == 2:
                revoke()
            return original_resolve(*args, **kwargs)
        monkeypatch.setattr(service.media, 'resolve', raced)
    final = call_status(mcp_app, transfer)
    assert all(block.type == 'text' for block in final.content)
    assert '/files/' not in final.content[0].text
    if stage == 'before_status':
        assert final.structured_content['state'] == 'cancelled'
        assert final.structured_content['sha256'] is None
    else:
        assert final.is_error
    assert service.gateway.sent == []


@pytest.mark.parametrize('kind', ['anonymous', 'wrong_scope', 'wrong_owner', 'foreign_transfer'])
def test_inline_image_preserves_authentication_scope_and_tenant_isolation(mcp_app, monkeypatch, kind):
    identifier, _, _ = image_file(mcp_app['service'], owner='other-owner' if kind == 'foreign_transfer' else None)
    token = mcp_app['token'].model_copy(deep=True)
    if kind == 'wrong_scope': token.scopes = ['whatsapp:send']
    if kind == 'wrong_owner': token.subject = 'other-owner'
    monkeypatch.setattr(server, 'get_access_token', lambda: None if kind == 'anonymous' else token)
    value = call_status(mcp_app, identifier)
    assert value.is_error and all(item.type == 'text' for item in value.content)
    assert '/files/' not in value.content[0].text
    assert mcp_app['service'].gateway.sent == []


@pytest.mark.parametrize('status', [
    {'state': 'queued'}, {'state': 'downloading'}, {'state': 'failed'},
    {'state': 'ready', 'mimetype': 'image/svg+xml', 'size': 12},
    {'state': 'ready', 'mimetype': 'image/png', 'size': MAX_RESOURCE_BYTES + 1},
])
def test_no_content_read_for_ineligible_status(status):
    class Unused:
        def __getattribute__(self, name):
            pytest.fail('No access to media before eligibility is established')
    info, block = attachment_image(Unused(), status, 'test-owner')
    assert not info['included'] and block is None


@pytest.mark.parametrize('name,mimetype', [('sample.jpg','image/jpeg'), ('sample.png','image/png'), ('sample.webp','image/webp')])
def test_truncated_format_headers_are_finite_and_not_accepted(name, mimetype):
    data = (FIXTURES / name).read_bytes()
    assert image_dimensions(data, mimetype) == (16, 16)
    for length in range(len(data)):
        assert image_dimensions(data[:length], mimetype) is None


def test_catalog_digest_and_comparison_include_the_tool_description(monkeypatch):
    from datetime import datetime, timezone
    from mcp_types import SERVER_INFO_META_KEY
    from sally_whatsapp.discovery_contract import compare_snapshot, contract_summary, expected_contract
    expected = expected_contract()
    digest = contract_summary()['contract_sha256']
    snapshot = {'format': 'whatsapp-discovery-v1', 'observed_at': datetime.now(timezone.utc).isoformat(),
        'responses': {
            'server/discover': {'resultType': 'complete', 'supportedVersions': expected['supportedVersions'],
                'capabilities': expected['capabilities'],
                '_meta': {SERVER_INFO_META_KEY: {'version': expected['backend_version']}}},
            'tools/list': {'resultType': 'complete', 'tools': [
                {'name': name, **value} for name, value in expected['tools'].items()]},
            'events/list': {'resultType': 'complete', 'events': [
                {'name': name, **value} for name, value in expected['events'].items()]},
        }}
    assert compare_snapshot(snapshot)['status'] == 'aligned'
    model, description, scope, readonly = server.TOOLS['get_transfer_status']
    monkeypatch.setitem(server.TOOLS, 'get_transfer_status', (model, description + ' Updated.', scope, readonly))
    assert contract_summary()['contract_sha256'] != digest
    assert compare_snapshot(snapshot)['differences'] == [{
        'location': 'tools.get_transfer_status.description', 'reason': 'contract_mismatch'}]
