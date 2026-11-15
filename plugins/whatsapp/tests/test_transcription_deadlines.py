"""One elapsed IPC budget, using real framing and deterministic socket boundaries."""
import json
import struct
import threading
import time

import pytest

from sally_whatsapp import transcription_protocol as protocol
from sally_whatsapp.transcriber import handle


RESULT = {'model': 'large-v3', 'language': 'it', 'text': 'Synthetic', 'segments': []}


class Clock:
    now = 0.0

    def wait(self, delay, timeout):
        if delay >= timeout:
            self.now += timeout
            raise TimeoutError('synthetic socket timeout')
        self.now += delay


class Connection:
    def __init__(self, clock, *, connect=0, writes=(0, 0), reads=None):
        self.clock, self.connect_delay = clock, connect
        self.writes = list(writes)
        encoded = json.dumps(RESULT).encode()
        self.reads = list(reads if reads is not None else [
            (0, struct.pack('!I', len(encoded))), (0, encoded)])
        self.timeout, self.closed = None, False
        self.sent, self.timeouts = [], []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def settimeout(self, value):
        assert value > 0
        self.timeout = value
        self.timeouts.append(value)

    def connect(self, _):
        self.clock.wait(self.connect_delay, self.timeout)

    def sendall(self, data):
        self.clock.wait(self.writes.pop(0) if self.writes else 0, self.timeout)
        self.sent.append(data)

    def recv(self, size):
        if not self.reads:
            return b''
        delay, data = self.reads.pop(0)
        self.clock.wait(delay, self.timeout)
        if len(data) > size:
            self.reads.insert(0, (0, data[size:]))
        return data[:size]


@pytest.fixture
def clock(monkeypatch):
    value = Clock()
    monkeypatch.setattr(time, 'monotonic', lambda: value.now)
    return value


def request(monkeypatch, connection, *, uid=42):
    monkeypatch.setattr(protocol.socket, 'socket', lambda *_: connection)
    monkeypatch.setattr(protocol, 'peer_uid', lambda *_: uid)
    return protocol.request('/synthetic/no-socket', 42, b'x' * (512 * 1024), None)


def test_queue_wait_and_inference_share_one_request_budget(monkeypatch, clock):
    encoded = json.dumps(RESULT).encode()
    connection = Connection(clock, writes=(0, 590), reads=[
        (590, struct.pack('!I', len(encoded))), (0, encoded)])
    threads = {thread.ident for thread in threading.enumerate()}
    with pytest.raises(protocol.TranscriptionError, match='^TRANSCRIPTION_TIMEOUT$'):
        request(monkeypatch, connection)
    assert clock.now == pytest.approx(900)
    assert connection.closed
    assert {thread.ident for thread in threading.enumerate()} == threads


@pytest.mark.parametrize('phase', ['connect', 'header_write', 'audio_write', 'prefix', 'body'])
def test_each_blocking_phase_uses_the_remaining_budget(monkeypatch, clock, phase):
    encoded = json.dumps(RESULT).encode()
    options = {
        'connect': dict(connect=901),
        'header_write': dict(connect=400, writes=(501, 0)),
        'audio_write': dict(connect=400, writes=(200, 301)),
        'prefix': dict(connect=400, writes=(200, 200),
                       reads=[(101, struct.pack('!I', len(encoded))), (0, encoded)]),
        'body': dict(connect=400, writes=(200, 200),
                     reads=[(50, struct.pack('!I', len(encoded))), (51, encoded)]),
    }
    connection = Connection(clock, **options[phase])
    with pytest.raises(protocol.TranscriptionError, match='^TRANSCRIPTION_TIMEOUT$'):
        request(monkeypatch, connection)
    assert clock.now == pytest.approx(900)
    assert connection.closed


@pytest.mark.parametrize('part', ['prefix', 'body'])
def test_fragmented_frames_do_not_restart_the_budget(monkeypatch, clock, part):
    encoded = json.dumps(RESULT).encode()
    prefix = struct.pack('!I', len(encoded))
    reads = ([(250, bytes([byte])) for byte in prefix] + [(0, encoded)] if part == 'prefix'
             else [(0, prefix)] + [(20, bytes([byte])) for byte in encoded])
    connection = Connection(clock, reads=reads)
    with pytest.raises(protocol.TranscriptionError, match='^TRANSCRIPTION_TIMEOUT$'):
        request(monkeypatch, connection)
    assert clock.now == pytest.approx(900)
    assert connection.closed


def test_fast_response_preserves_framing_and_identity_check(monkeypatch, clock):
    connection = Connection(clock, connect=200, writes=(200, 200))
    assert request(monkeypatch, connection) == RESULT
    assert clock.now == 600
    assert json.loads(connection.sent[0][4:]) == {
        'version': 1, 'bytes': 512 * 1024, 'language': None}
    assert connection.sent[1] == b'x' * (512 * 1024)
    assert connection.closed
    wrong = Connection(clock)
    with pytest.raises(protocol.TranscriptionError, match='IDENTITY_MISMATCH'):
        request(monkeypatch, wrong, uid=43)
    assert wrong.closed and not wrong.sent


def test_worker_request_header_and_audio_share_input_budget(monkeypatch, clock):
    header = json.dumps({'version': 1, 'bytes': 1, 'language': None}).encode()
    connection = Connection(clock, reads=[(5, struct.pack('!I', len(header))),
                                          (5, header), (6, b'a')])
    monkeypatch.setattr('sally_whatsapp.transcriber.peer_uid', lambda *_: 42)
    inferred = []
    handle(connection, {42}, lambda *_: inferred.append(1))
    assert clock.now == pytest.approx(15)
    assert not inferred
    assert json.loads(connection.sent[0][4:])['error_code'] == 'TRANSCRIPTION_TIMEOUT'
