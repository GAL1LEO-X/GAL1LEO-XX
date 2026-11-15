"""Bounded, local-only speech protocol. No URLs, paths or message identifiers."""
import json
import socket
import struct
import time

MAX_AUDIO_BYTES = 32 * 1024 * 1024
MAX_AUDIO_SECONDS = 900
MAX_RESULT_BYTES = 1024 * 1024
MODEL = 'large-v3'
REQUEST_TIMEOUT_SECONDS = 900


class TranscriptionError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class Deadline:
    """One elapsed budget across connect, all writes, and fragmented reads."""
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    def remaining(self):
        value = self.end - time.monotonic()
        if value <= 0:
            raise TranscriptionError('TRANSCRIPTION_TIMEOUT')
        return value

    def arm(self, connection):
        connection.settimeout(self.remaining())


def send_bytes(connection, content, *, deadline=None):
    if deadline is not None:
        deadline.arm(connection)
    try:
        connection.sendall(content)
    except TimeoutError:
        if deadline is not None:
            deadline.remaining()
        raise
    if deadline is not None:
        deadline.remaining()


def peer_uid(connection):
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def receive_exact(connection, length, *, deadline=None):
    chunks = bytearray()
    while len(chunks) < length:
        if deadline is not None:
            deadline.arm(connection)
        try:
            chunk = connection.recv(min(65536, length - len(chunks)))
        except TimeoutError:
            if deadline is not None:
                deadline.remaining()
            raise
        if deadline is not None:
            deadline.remaining()
        if not chunk:
            raise TranscriptionError('TRANSCRIBER_PROTOCOL_ERROR')
        chunks.extend(chunk)
    return bytes(chunks)


def receive_json(connection, maximum, *, deadline=None):
    length = struct.unpack('!I', receive_exact(connection, 4, deadline=deadline))[0]
    if not 1 <= length <= maximum:
        raise TranscriptionError('TRANSCRIBER_PROTOCOL_ERROR')
    try:
        content = receive_exact(connection, length, deadline=deadline)
        value = json.loads(content)
    except TranscriptionError:
        raise
    except (UnicodeError, ValueError):
        raise TranscriptionError('TRANSCRIBER_PROTOCOL_ERROR') from None
    if deadline is not None:
        deadline.remaining()
    if not isinstance(value, dict):
        raise TranscriptionError('TRANSCRIBER_PROTOCOL_ERROR')
    return value


def send_json(connection, value, maximum, *, deadline=None):
    content = json.dumps(value, ensure_ascii=False, allow_nan=False).encode()
    if len(content) > maximum:
        raise TranscriptionError('TRANSCRIPTION_RESULT_TOO_LARGE')
    send_bytes(connection, struct.pack('!I', len(content)) + content, deadline=deadline)


def request(socket_path, expected_uid, audio, language):
    if not 0 < len(audio) <= MAX_AUDIO_BYTES:
        raise TranscriptionError('AUDIO_SIZE_LIMIT')
    deadline = Deadline(REQUEST_TIMEOUT_SECONDS)
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            deadline.arm(connection)
            try:
                connection.connect(str(socket_path))
            except TimeoutError:
                deadline.remaining()
                raise
            deadline.remaining()
            if peer_uid(connection) != expected_uid:
                raise TranscriptionError('TRANSCRIBER_IDENTITY_MISMATCH')
            send_json(connection, {'version': 1, 'bytes': len(audio), 'language': language}, 4096,
                      deadline=deadline)
            send_bytes(connection, audio, deadline=deadline)
            result = receive_json(connection, MAX_RESULT_BYTES, deadline=deadline)
    except (OSError, TimeoutError):
        raise TranscriptionError('TRANSCRIBER_UNAVAILABLE') from None
    if result.get('error_code'):
        known = {'INVALID_AUDIO', 'AUDIO_DURATION_LIMIT', 'LANGUAGE_UNSUPPORTED',
                 'TRANSCRIPTION_TIMEOUT', 'TRANSCRIPTION_FAILED', 'TRANSCRIPTION_RESULT_TOO_LARGE',
                 'TRANSCRIBER_PROTOCOL_ERROR', 'TRANSCRIBER_MODEL_UNAVAILABLE', 'TRANSCRIBER_PROCESS_EXITED'}
        raise TranscriptionError(result['error_code'] if result['error_code'] in known else 'TRANSCRIPTION_FAILED')
    if (result.get('model') != MODEL or not isinstance(result.get('text'), str)
            or not isinstance(result.get('segments'), list)
            or not isinstance(result.get('language'), str)):
        raise TranscriptionError('TRANSCRIBER_PROTOCOL_ERROR')
    return result
