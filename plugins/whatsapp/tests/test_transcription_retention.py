"""Release reachable request/result objects while keeping idle workers warm."""
import gc
import hashlib
import os
import threading
import time
from types import SimpleNamespace
import weakref

import pytest

from sally_whatsapp import transcriber, transcription


class Result(dict):
    pass


def test_expiry_releases_last_result_without_stopping_worker(tmp_path, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(transcription.time, 'time', lambda: now[0])
    path = tmp_path / 'synthetic.ogg'
    content = b'synthetic audio, no decoder or model'
    path.write_bytes(content)
    row = {'id': 'media_' + 'a' * 32, 'state': 'ready', 'source_message_id': 'synthetic',
           'mimetype': 'audio/ogg', 'size': len(content), 'sha256': hashlib.sha256(content).hexdigest(),
           'expires': 1100}
    media = SimpleNamespace(ready=lambda *_: dict(row), row=lambda *_: dict(row),
                            _verify_cache=lambda *_, **__: os.open(path, os.O_RDONLY))
    completed, references = threading.Event(), []
    def transport(*_):
        value = Result(text='Synthetic result', language='it', segments=[])
        references.append(weakref.ref(value))
        return value
    def emit(event, *_, **__):
        if event == 'transcription.completed':
            completed.set()
    worker = transcription.Transcriptions(media,
        SimpleNamespace(transcription_socket='/synthetic', transcription_server_uid=42),
        SimpleNamespace(emit=emit), transport)
    try:
        job = worker.start(row['id'], 'synthetic-owner')
        assert completed.wait(2)
        with worker.condition:
            now[0] = 1200
            worker.condition.notify_all()
        end = time.monotonic() + 2
        while time.monotonic() < end:
            with worker.condition:
                if not worker.jobs:
                    break
            time.sleep(.005)
        assert not worker.jobs and worker.thread.is_alive()
        gc.collect()
        assert references[0]() is None
        with pytest.raises(transcription.TranscriptionError, match='NOT_FOUND_OR_EXPIRED'):
            worker.status(job['id'], 'synthetic-owner')
    finally:
        worker.close()
        worker.thread.join(2)
    assert not worker.thread.is_alive()


@pytest.mark.parametrize('failed', [False, True])
def test_warm_child_releases_raw_request_before_waiting_again(monkeypatch, failed):
    class Audio(bytearray):
        pass
    references, loaded, responses = [], [], []
    class Channel:
        count = 0
        def recv(self):
            gc.collect()
            assert all(reference() is None for reference in references)
            self.count += 1
            if self.count == 3:
                return None
            audio = Audio(b'synthetic audio')
            references.append(weakref.ref(audio))
            return audio, None
        def send(self, result):
            responses.append(result)
    class Engine:
        def __init__(self, **_):
            loaded.append(1)
        def transcribe_decoded(self, *_):
            return {'text': 'Synthetic result'}
    def decode(_):
        if failed:
            raise transcription.TranscriptionError('INVALID_AUDIO')
        return b'decoded synthetic'
    monkeypatch.setattr(transcriber, 'decode_audio', decode)
    monkeypatch.setattr(transcriber, 'Engine', Engine)
    monkeypatch.setattr('logging.disable', lambda *_: None)
    for key in ('HF_HUB_OFFLINE', 'HF_HUB_DISABLE_TELEMETRY', 'DO_NOT_TRACK'):
        monkeypatch.setenv(key, os.environ.get(key, ''))
    transcriber.child_loop(Channel(), {})
    assert len(responses) == 2 and loaded == ([] if failed else [1])
