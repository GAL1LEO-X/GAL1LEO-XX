"""Synthetic auth, source-lifetime and local worker boundaries; no real chats."""
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import threading
import time

import pytest
from starlette.testclient import TestClient

from conftest import call, rpc, ready_external_media
from test_media_integrity_formats import FILES, acquire, setup, headers, result
from sally_whatsapp.transcription_protocol import (TranscriptionError, request, send_json,
                                                  receive_json, receive_exact)
from sally_whatsapp.transcriber import serve, handle


@pytest.fixture
def audio_client(environment):
    settings, *rest = environment
    settings = replace(settings, transcription_socket=Path('/tmp/synthetic-transcriber.sock'),
                       transcription_server_uid=os.getuid())
    item = next(item for item in FILES if item['name'] == 'sample.ogg')
    app, gateway, token = setup((settings, *rest), item)
    service = app.state.service
    acquire(service, gateway)
    with TestClient(app) as client:
        headers(client, token)
        client.headers['Authorization'] = 'Bearer ' + token(scope='whatsapp:read')
        transfer = result(client, 'get_attachment', {'message_id': gateway.observation['id']})
        assert service.media.process_one()
        yield service, client, transfer['id'], gateway
    assert not gateway.sent


def transcript(*_):
    return {'model': 'large-v3', 'language': 'it', 'text': 'Testo sintetico, non inviare nulla.',
            'segments': [{'start': 0, 'end': 1, 'text': 'Testo sintetico, non inviare nulla.'}]}


def finished(service, job):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        value = service.transcriptions.status(job['id'], service.settings.owner_subject)
        if value['state'] not in ('queued', 'processing'):
            return value
        time.sleep(0.01)
    raise AssertionError('Synthetic transcription did not finish')


def test_mcp_returns_text_without_audio_support_or_chat_mutations(audio_client):
    service, client, transfer, gateway = audio_client
    observed = []
    def transcribe(path, uid, audio, language):
        observed.append((audio, language))
        return transcript()
    service.transcriptions.transport = transcribe
    job = result(client, 'transcribe_audio', {'transfer_id': transfer})
    value = finished(service, job)
    response = result(client, 'get_transcription', {'job_id': job['id']})
    assert response == value and response['text'] == transcript()['text']
    assert response['source_message_id'] == gateway.observation['id']
    assert response['content_is_untrusted'] and not response['read_receipts_sent']
    assert observed == [(gateway.media_bytes, None)]
    assert result(client, 'transcribe_audio', {'transfer_id': transfer})['id'] == job['id']
    assert len(observed) == 1
    logs = (service.settings.database.parent / 'diagnostics/events.jsonl').read_text()
    assert response['text'] not in logs and gateway.observation['id'] not in logs
    assert 'transcription.completed' in logs


@pytest.mark.parametrize('change', ['revoke', 'expire', 'tamper'])
def test_source_change_hides_completed_text(audio_client, change):
    service, client, transfer, gateway = audio_client
    service.transcriptions.transport = transcript
    job = result(client, 'transcribe_audio', {'transfer_id': transfer})
    assert finished(service, job)['state'] == 'ready'
    if change == 'revoke':
        service.store.ingest({'event': 'message.revoked',
                             'payload': {'revokedMessageId': gateway.observation['id']}})
    elif change == 'expire':
        with service.store.db() as db:
            db.execute('UPDATE media_jobs SET expires=? WHERE id=?', (time.time()-1, transfer))
    else:
        service.media.path(transfer).write_bytes(b'x' * len(gateway.media_bytes))
    value = result(client, 'get_transcription', {'job_id': job['id']})
    assert value['state'] == 'unavailable' and 'text' not in value
    assert 'result' not in service.transcriptions.jobs[job['id']]


def test_revocation_during_inference_discards_result(audio_client):
    service, client, transfer, gateway = audio_client
    def revoke(*_):
        service.store.ingest({'event': 'message.revoked',
                             'payload': {'revokedMessageId': gateway.observation['id']}})
        return transcript()
    service.transcriptions.transport = revoke
    job = result(client, 'transcribe_audio', {'transfer_id': transfer})
    value = finished(service, job)
    assert value['state'] == 'unavailable' and 'text' not in value


def test_other_tenant_cannot_read_or_start_job(audio_client):
    service, client, transfer, _ = audio_client
    service.transcriptions.transport = transcript
    job = result(client, 'transcribe_audio', {'transfer_id': transfer})
    assert finished(service, job)['state'] == 'ready'
    with pytest.raises(TranscriptionError, match='NOT_FOUND'):
        service.transcriptions.status(job['id'], 'other-owner')
    with pytest.raises(ValueError, match='not found'):
        service.transcriptions.start(transfer, 'other-owner')
    # A second instance has an independent store/job namespace even when UID
    # or model service is shared. A copied opaque ID does not provide access.
    from sally_whatsapp.transcription import Transcriptions
    second = Transcriptions(service.media, service.settings, service.diagnostics)
    with pytest.raises(TranscriptionError, match='NOT_FOUND'):
        second.status(job['id'], service.settings.owner_subject)


def test_restart_does_not_repeat_transcription(audio_client):
    service, client, transfer, _ = audio_client
    service.transcriptions.transport = transcript
    job = result(client, 'transcribe_audio', {'transfer_id': transfer})
    assert finished(service, job)['state'] == 'ready'
    service.transcriptions.close()
    assert not service.transcriptions.jobs and not service.transcriptions.queue
    value = call(client, 'get_transcription', {'job_id': job['id']})['result']
    assert value['isError'] and value['structuredContent']['error_code'] == 'TRANSCRIPTION_NOT_FOUND_OR_EXPIRED'


def test_transcription_is_optional_and_discovered_with_read_scope(app_client, environment):
    app, client = app_client
    tools = {item['name']: item for item in rpc(client, 'tools/list')['result']['tools']}
    for name in ('transcribe_audio', 'get_transcription'):
        assert tools[name]['securitySchemes'] == [{'type': 'oauth2', 'scopes': ['whatsapp:read']}]
        assert not tools[name]['annotations']['readOnlyHint']
        assert tools[name]['annotations']['destructiveHint']
    value = call(client, 'transcribe_audio', {'transfer_id': 'media_' + 'a'*32})['result']
    assert value['isError'] and value['structuredContent']['error_code'] == 'TRANSCRIPTION_NOT_CONFIGURED'
    client.headers['Authorization'] = 'Bearer ' + environment[3](sub='other-owner')
    response = client.get('/mcp')
    assert response.status_code in (401, 403)


def test_external_file_is_not_whatsapp_transcription_source(audio_client):
    service, _, _, _ = audio_client
    external = ready_external_media(service, mimetype='audio/ogg', data=b'synthetic')
    with pytest.raises(TranscriptionError, match='SOURCE_UNAVAILABLE'):
        service.transcriptions.start(external['id'], service.settings.owner_subject)


def test_failure_is_explicit_and_repeated_request_does_not_retry(audio_client):
    service, client, transfer, _ = audio_client
    attempts = []
    def fail(*_):
        attempts.append(1)
        raise TranscriptionError('INVALID_AUDIO')
    service.transcriptions.transport = fail
    job = result(client, 'transcribe_audio', {'transfer_id': transfer})
    value = finished(service, job)
    assert value['state'] == 'failed' and value['error_code'] == 'INVALID_AUDIO'
    assert 'text' not in value
    assert result(client, 'transcribe_audio', {'transfer_id': transfer})['id'] == job['id']
    assert attempts == [1]
    retry = result(client, 'transcribe_audio', {'transfer_id': transfer, 'retry': True})
    assert retry['id'] != job['id']
    assert finished(service, retry)['state'] == 'failed'
    assert attempts == [1, 1]


def test_unix_worker_serializes_two_callers_and_checks_identity(short_socket_tmp_path):
    root = short_socket_tmp_path
    path = root / 'worker.sock'
    ready, stop = threading.Event(), threading.Event()
    active, maximum, calls = 0, 0, []
    def infer(audio, language):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        calls.append(audio)
        time.sleep(0.03)
        active -= 1
        return transcript()
    worker = threading.Thread(target=serve, args=(path, {os.getuid()}, infer, ready, stop))
    worker.start()
    assert ready.wait(2)
    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(request, path, os.getuid(), audio, None) for audio in (b'a', b'b')]
            assert all(item.result()['text'] == transcript()['text'] for item in futures)
        assert maximum == 1 and sorted(calls) == [b'a', b'b']
        with pytest.raises(TranscriptionError, match='IDENTITY_MISMATCH'):
            request(path, os.getuid()+1, b'no', None)
        assert len(calls) == 2
    finally:
        stop.set()
        worker.join(2)
    assert not path.exists()


def test_worker_refuses_unadmitted_peer_and_oversized_request():
    for uids, header in [({os.getuid()+1}, None),
                         ({os.getuid()}, {'version': 1, 'bytes': 2**40, 'language': None})]:
        client, server = socket.socketpair()
        calls = []
        thread = threading.Thread(target=handle, args=(server, uids, lambda *_: calls.append(1)))
        thread.start()
        try:
            if header is not None:
                send_json(client, header, 4096)
                assert receive_json(client, 4096)['error_code'] == 'TRANSCRIBER_PROTOCOL_ERROR'
            thread.join(1)
            assert not thread.is_alive() and not calls
        finally:
            client.close()
            server.close()


def test_warm_worker_reuses_model_and_exits_on_shutdown_sentinel(monkeypatch):
    import logging
    import multiprocessing
    from sally_whatsapp import transcriber
    # This fixture runs the child loop in a thread: preserve the test process's
    # logging/environment, which would be private in the actual spawned worker.
    monkeypatch.setattr(logging, 'disable', lambda *_: None)
    for key in ('HF_HUB_OFFLINE', 'HF_HUB_DISABLE_TELEMETRY', 'DO_NOT_TRACK'):
        monkeypatch.setenv(key, os.environ.get(key, ''))
    loaded = []
    class Engine:
        def __init__(self, **_):
            loaded.append(1)
        def transcribe_decoded(self, audio, language):
            assert audio == b'synthetic'
            return transcript()
    monkeypatch.setattr(transcriber, 'Engine', Engine)
    monkeypatch.setattr(transcriber, 'decode_audio', lambda audio: audio)
    parent, child = multiprocessing.Pipe()
    worker = threading.Thread(target=transcriber.child_loop, args=(child, {}))
    worker.start()
    try:
        for _ in range(2):
            parent.send((b'synthetic', None))
            assert parent.poll(2) and parent.recv()['text'] == transcript()['text']
        assert loaded == [1]
        parent.send(None)
        worker.join(2)
        assert not worker.is_alive()
    finally:
        parent.close()
        child.close()
