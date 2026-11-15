"""Synthetic MCP-to-worker contracts for the pinned GOWS media families.

The fake provider checks the requests, not real WhatsApp delivery or transcoding.
Native-file retrieval is replaced at the network boundary with fixture bytes.
"""
from dataclasses import replace
import hashlib
import json
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from starlette.testclient import TestClient

from conftest import call
from sally_whatsapp.media import copy_bounded
from sally_whatsapp.operations import validate_operation
from sally_whatsapp.server import create_app


CHAT = 'fixture-media@c.us'
FILE_BYTES = b'SYNTHETIC MEDIA FIXTURE: no WhatsApp connection'
MEDIA_CASES = [
    ('messages_send_image', '/api/sendImage', {'chatId': CHAT, 'caption': 'Synthetic image'}, 'image/jpeg', 'fixture.jpg'),
    ('messages_send_file', '/api/sendFile', {'chatId': CHAT, 'caption': 'Synthetic document'}, 'application/pdf', 'fixture.pdf'),
    ('messages_send_voice', '/api/sendVoice', {'chatId': CHAT, 'convert': True}, 'audio/ogg', 'fixture.ogg'),
    ('messages_send_video', '/api/sendVideo', {'chatId': CHAT, 'convert': True, 'asNote': False, 'caption': 'Synthetic video'}, 'video/mp4', 'fixture.mp4'),
    ('messages_send_video', '/api/sendVideo', {'chatId': CHAT, 'convert': False, 'asNote': True}, 'video/mp4', 'note.mp4'),
    ('messages_send_sticker', '/api/sendSticker', {'chatId': CHAT}, 'image/webp', 'fixture.webp'),
    ('status_send_image_status', '/api/default/status/image', {'contacts': [CHAT], 'caption': 'Synthetic status'}, 'image/jpeg', 'status.jpg'),
    ('status_send_voice_status', '/api/default/status/voice', {'contacts': [CHAT], 'convert': True, 'backgroundColor': '#123456'}, 'audio/ogg', 'status.ogg'),
    ('status_send_video_status', '/api/default/status/video', {'contacts': [CHAT], 'convert': False, 'caption': 'Synthetic status'}, 'video/mp4', 'status.mp4'),
]


def result(client, name, arguments):
    response = call(client, name, arguments)['result']
    assert not response.get('isError'), response
    return response['structuredContent']


@pytest.mark.parametrize('operation,path,body,mimetype,filename', MEDIA_CASES)
def test_native_file_to_media_family_uses_owned_transfer_and_one_provider_submission(
        environment, monkeypatch, operation, path, body, mimetype, filename):
    settings, receiver, gateway, token = environment
    settings = replace(settings, live_account_enabled=True, send_enabled=True,
                       allow_all_destinations=True, account_actions_enabled=True)
    source_url = 'https://files.example/fixture?signature=synthetic-private-source'
    downloads, requests = [], []

    def download(url, target, maximum):
        downloads.append(url)
        return copy_bounded(iter([FILE_BYTES]), target, maximum, len(FILE_BYTES))

    def request(method, actual_path, **kwargs):
        requests.append((method, actual_path, kwargs))
        assert method == 'POST' and actual_path == path
        wire = kwargs['json']
        assert {key: wire[key] for key in body} == body
        assert wire.get('session', settings.session) == settings.session
        file = wire['file']
        assert file['filename'] == filename and file['mimetype'] == mimetype
        assert urlsplit(file['url']).netloc == urlsplit(settings.media_gateway_origin).netloc
        assert urlsplit(file['url']).path.startswith('/files/')
        assert 'signature=' not in json.dumps(wire)
        assert set(file) == {'url', 'filename', 'mimetype'}
        assert kwargs['timeout'] == 600
        return {'id': 'true_' + CHAT + '_SYNTHETICMEDIA', '_data': {'secret': 'synthetic-provider-private'}}

    monkeypatch.setattr('sally_whatsapp.media.download_public', download)
    gateway.request = request
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app) as client:
        client.headers.update({'Authorization': 'Bearer ' + token(),
                               'Accept': 'application/json, text/event-stream',
                               'MCP-Protocol-Version': '2026-07-28'})
        prepared = result(client, 'prepare_file', {'file': {
            'file_id': 'file-synthetic-native', 'download_url': source_url,
            'file_name': filename, 'mime_type': mimetype}})
        assert prepared['state'] == 'queued' and not requests
        assert app.state.service.media.process_one()
        ready = result(client, 'get_transfer_status', {'transfer_id': prepared['id']})
        assert ready['state'] == 'ready'
        assert ready['sha256'] == hashlib.sha256(FILE_BYTES).hexdigest()
        assert downloads == [source_url]
        assert source_url not in json.dumps(ready)
        assert client.get(ready['download_url']).content == FILE_BYTES
        action = {'operation': operation, 'arguments': {'body': body},
                  'transfer_id': prepared['id'], 'idempotency_key': 'media-family-synthetic-001'}
        assert result(client, 'send_media', action)['state'] == 'queued'
        assert not requests
        assert app.state.service.process_action()
        status = result(client, 'get_send_status', {'idempotency_key': action['idempotency_key']})
        assert status['state'] == 'submitted'
        expected_delivery = 'not_applicable' if operation.startswith('status_') else 'not_observed'
        assert status['delivery']['status'] == expected_delivery
        assert 'synthetic-provider-private' not in json.dumps(status)
        app.state.service.store.ingest({'id': 'synthetic-read-receipt', 'event': 'message.ack',
            'session': settings.session, 'timestamp': int(time.time() * 1000), 'payload': {
                'id': 'true_' + CHAT + '_SYNTHETICMEDIA', 'fromMe': True,
                'from': 'self@c.us', 'to': CHAT, 'ack': 3, 'ackName': 'READ'}})
        acknowledged = result(client, 'get_send_status', {'idempotency_key': action['idempotency_key']})
        assert acknowledged['state'] == 'submitted'
        if operation.startswith('status_'):
            assert acknowledged['delivery']['status'] == 'not_applicable'
        else:
            assert acknowledged['delivery']['status'] == 'observed'
            assert set(acknowledged['delivery']['evidence']) == {'read'}
        assert result(client, 'send_media', action)['state'] == 'submitted'
        assert not app.state.service.process_action()
        assert len(requests) == 1 and receiver.requests == []


@pytest.mark.parametrize('field,value', [
    ('latitude', 90.0001), ('latitude', -90.0001),
    ('longitude', 180.0001), ('longitude', -180.0001),
])
def test_outside_earth_coordinates_are_rejected_before_queueing(environment, field, value):
    settings, receiver, gateway, token = environment
    settings = replace(settings, live_account_enabled=True, send_enabled=True, allow_all_destinations=True)
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app) as client:
        client.headers.update({'Authorization': 'Bearer ' + token(),
                               'Accept': 'application/json, text/event-stream',
                               'MCP-Protocol-Version': '2026-07-28'})
        body = {'chatId': CHAT, 'latitude': 45.46, 'longitude': 9.19, 'title': 'Synthetic point', field: value}
        action = {'operation': 'messages_send_location', 'arguments': {'body': body},
                  'idempotency_key': 'synthetic-invalid-coordinate-001'}  # gitleaks:allow -- synthetic idempotency identifier, not a credential
        assert call(client, 'write_whatsapp', action)['result']['isError']
        assert not app.state.service.process_action()
        assert result(client, 'get_send_status', {'idempotency_key': action['idempotency_key']}) == {'state': 'not_found'}


@pytest.mark.parametrize('value', [float('nan'), float('inf'), float('-inf')])
@pytest.mark.parametrize('operation,body,field', [
    ('messages_send_location', {'chatId': CHAT, 'latitude': 45.46, 'longitude': 9.19, 'title': 'Fixture'}, 'latitude'),
    ('status_send_text_status', {'text': 'Fixture', 'backgroundColor': '#000000', 'font': 1}, 'font'),
])
def test_non_finite_numbers_are_rejected_at_operation_boundary(operation, body, field, value):
    with pytest.raises(ValueError):
        validate_operation(operation, {'body': {**body, field: value}}, readonly=False)


@pytest.mark.parametrize('latitude,longitude', [(90, 180), (-90, -180)])
def test_coordinate_boundaries_remain_valid(latitude, longitude):
    _, values = validate_operation('messages_send_location', {'body': {
        'chatId': CHAT, 'latitude': latitude, 'longitude': longitude, 'title': 'Synthetic boundary'}}, readonly=False)
    assert values['body']['latitude'] == latitude and values['body']['longitude'] == longitude


@pytest.mark.parametrize('response', [
    [{'id': '0'}], [{'id': '0', 'presences': []}], [{'id': 0, 'presences': []}],
    [{'id': 0.0, 'presences': []}], {'0': {'id': CHAT, 'presences': []}},
    [{'id': CHAT, 'presences': []}, {'id': '1', 'presences': []}],
    [{'id': 'private-provider-payload', 'presences': []}],
    [{'id': CHAT, 'presences': [{'participant': '0', 'lastKnownPresence': 'online'}]}],
])
def test_presence_cache_indices_are_reported_as_provider_failure(environment, response):
    settings, receiver, gateway, token = environment
    settings = replace(settings, live_account_enabled=True)
    requests, diagnostics = [], []

    def request(method, path, **kwargs):
        requests.append((method, path))
        return response

    gateway.request = request
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    gateway.diagnostics = SimpleNamespace(emit=lambda *args, **kwargs: diagnostics.append((args, kwargs)))
    with TestClient(app) as client:
        client.headers.update({'Authorization': 'Bearer ' + token(),
                               'Accept': 'application/json, text/event-stream',
                               'MCP-Protocol-Version': '2026-07-28'})
        rejected = call(client, 'read_whatsapp', {'operation': 'presence_get_presence_all'})['result']
        assert rejected['isError']
        assert 'invalid presence list' in json.dumps(rejected)
        assert 'private-provider-payload' not in json.dumps(rejected)
        assert rejected['structuredContent']['error_code'] == 'PROVIDER_UNAVAILABLE'
        assert rejected['structuredContent']['operation'] == 'presence_get_presence_all'
        assert requests == [('GET', '/api/default/presence')]
        assert not app.state.service.process_action()
        assert diagnostics == [(('gateway.failed', 'warning'), {
            'operation': 'presence_get_presence_all', 'error_code': 'WAHA_PRESENCE_SCHEMA'})]


@pytest.mark.parametrize('response', [
    [], [{'id': CHAT, 'presences': []}],
    [{'id': CHAT, 'presences': [{'participant': CHAT, 'lastKnownPresence': 'offline', 'lastSeen': 1802880000}]}],
    [{'id': '15550001111@g.us', 'presences': [{'participant': '15550002222@lid', 'lastKnownPresence': 'typing', 'lastSeen': None}]}],
])
def test_valid_cached_presence_observations_are_preserved(environment, response):
    settings, receiver, gateway, token = environment
    settings = replace(settings, live_account_enabled=True)
    gateway.request = lambda *args, **kwargs: response
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app) as client:
        client.headers.update({'Authorization': 'Bearer ' + token(),
                               'Accept': 'application/json, text/event-stream',
                               'MCP-Protocol-Version': '2026-07-28'})
        assert result(client, 'read_whatsapp', {'operation': 'presence_get_presence_all'}) == {'result': response}
        assert not app.state.service.process_action()


@pytest.mark.parametrize('operation,arguments', [
    ('messages_send_location', {'body': {'chatId': CHAT, 'latitude': 45.46, 'longitude': 9.19, 'title': 'Synthetic point'}}),
    ('messages_send_seen', {'body': {'chatId': CHAT, 'messageIds': ['false_' + CHAT + '_SYNTHETIC']}}),
    ('messages_send_seen', {'body': {'chatId': CHAT}}),
    ('chats_read_chat_messages', {'path': {'chatId': CHAT}, 'query': {'days': 1, 'messages': 5}}),
    ('presence_get_presence', {'path': {'chatId': CHAT}}),
    ('presence_subscribe', {'path': {'chatId': CHAT}}),
    ('presence_set_presence', {'body': {'chatId': CHAT, 'presence': 'recording'}}),
])
def test_read_receipts_location_and_presence_require_mutation_path(environment, operation, arguments):
    settings, receiver, gateway, token = environment
    settings = replace(settings, live_account_enabled=True, send_enabled=True,
                       allow_all_destinations=True, account_actions_enabled=True)
    requests = []

    def request(method, path, **kwargs):
        requests.append((method, path, kwargs))
        return {'id': 'true_' + CHAT + '_SYNTHETICEFFECT'}

    gateway.request = request
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app) as client:
        client.headers.update({'Authorization': 'Bearer ' + token(),
                               'Accept': 'application/json, text/event-stream',
                               'MCP-Protocol-Version': '2026-07-28'})
        read = call(client, 'read_whatsapp', {'operation': operation, 'arguments': arguments})['result']
        assert read['isError'] and not requests
        action = {'operation': operation, 'arguments': arguments,
                  'idempotency_key': 'synthetic-controlled-effect-001'}
        assert result(client, 'write_whatsapp', action)['state'] == 'queued'
        assert app.state.service.process_action()
        status = result(client, 'get_send_status', {'idempotency_key': action['idempotency_key']})
        assert status['state'] == 'submitted'
        assert status['delivery']['status'] == ('not_observed' if operation == 'messages_send_location' else 'not_applicable')
        assert result(client, 'write_whatsapp', action)['state'] == 'submitted'
        assert not app.state.service.process_action()
        assert len(requests) == 1 and receiver.requests == []
