"""Optional shared faster-whisper worker; run separately from tenant backends."""
import argparse
import io
import json
import multiprocessing
import os
from pathlib import Path
import re
import signal
import socket
import stat
import time

from .transcription_protocol import (MODEL, MAX_AUDIO_BYTES, MAX_AUDIO_SECONDS, MAX_RESULT_BYTES,
    Deadline, TranscriptionError, peer_uid, receive_exact, receive_json, send_json)


def decode_audio(content):
    """Decode local bytes only, bounding decoded duration before model inference."""
    import av
    import numpy as np
    chunks, samples = [], 0
    try:
        with av.open(io.BytesIO(content), options={
                'format_whitelist': 'ogg,wav,mp3,mov,matroska,webm,flac,aac',
                'protocol_whitelist': 'pipe'}) as container:
            if len(container.streams.audio) != 1:
                raise TranscriptionError('INVALID_AUDIO')
            resampler = av.AudioResampler(format='s16', layout='mono', rate=16000)
            for frame in container.decode(audio=0):
                for output in resampler.resample(frame):
                    samples += output.samples
                    if samples > MAX_AUDIO_SECONDS * 16000:
                        raise TranscriptionError('AUDIO_DURATION_LIMIT')
                    chunks.append(output.to_ndarray().flatten())
            for output in resampler.resample(None):
                samples += output.samples
                if samples > MAX_AUDIO_SECONDS * 16000:
                    raise TranscriptionError('AUDIO_DURATION_LIMIT')
                chunks.append(output.to_ndarray().flatten())
    except TranscriptionError:
        raise
    except Exception:
        raise TranscriptionError('INVALID_AUDIO') from None
    if not samples:
        raise TranscriptionError('INVALID_AUDIO')
    return np.concatenate(chunks).astype(np.float32) / 32768.0


class Engine:
    def __init__(self, model_directory, device='cpu', compute_type='float32', threads=4):
        import onnxruntime
        onnxruntime.disable_telemetry_events()
        from faster_whisper import WhisperModel
        self.model = WhisperModel(str(model_directory), device=device, compute_type=compute_type,
                                  cpu_threads=threads, num_workers=1, local_files_only=True)
        if not self.model.model.is_multilingual or self.model.model.n_mels != 128:
            raise ValueError('Expected multilingual large-v3')

    def transcribe(self, content, language):
        return self.transcribe_decoded(decode_audio(content), language)

    def transcribe_decoded(self, audio, language):
        from faster_whisper.tokenizer import _LANGUAGE_CODES
        if language is not None and language not in _LANGUAGE_CODES:
            raise TranscriptionError('LANGUAGE_UNSUPPORTED')
        started = time.monotonic()
        segments, info = self.model.transcribe(audio, language=language, task='transcribe',
                                               beam_size=5, vad_filter=True)
        values = []
        characters = 0
        for segment in segments:
            characters += len(segment.text)
            if characters > 100000 or len(values) >= 3000:
                raise TranscriptionError('TRANSCRIPTION_RESULT_TOO_LARGE')
            values.append({'start': round(segment.start, 3), 'end': round(segment.end, 3),
                           'text': segment.text.strip()})
        return {'model': MODEL, 'engine': 'faster-whisper', 'task': 'transcribe',
                'text': ' '.join(value['text'] for value in values).strip(), 'segments': values,
                'language': info.language, 'language_probability': info.language_probability,
                'duration_seconds': len(audio) / 16000,
                'inference_seconds': round(time.monotonic() - started, 3),
                'quality_notice': 'Automatic transcription may contain errors; not verified against the speaker.'}


def child_loop(channel, options):
    # Dependency logs and exceptions must never disclose audio or transcription.
    import logging
    logging.disable(logging.CRITICAL)
    os.environ.update(HF_HUB_OFFLINE='1', HF_HUB_DISABLE_TELEMETRY='1', DO_NOT_TRACK='1')
    engine = None
    while True:
        try:
            incoming = channel.recv()
        except EOFError:
            return
        if incoming is None:
            return
        audio, language = incoming
        del incoming  # The idle receive must not retain the preceding raw audio.
        try:
            decoded = decode_audio(audio)
            if engine is None:
                engine = Engine(**options)
            result = engine.transcribe_decoded(decoded, language)
        except TranscriptionError as exc:
            result = {'error_code': exc.code}
        except Exception as exc:
            result = {'error_code': 'TRANSCRIPTION_FAILED' if engine is not None else 'TRANSCRIBER_MODEL_UNAVAILABLE'}
            print(json.dumps({'event': 'transcriber.failed', 'error_code': result['error_code'],
                              'exception': type(exc).__name__}), flush=True)
        try:
            channel.send(result)
        finally:
            decoded = None
            del audio, result


class InferenceProcess:
    """One warm process, killed on deadline; a timed-out job is never retried."""
    def __init__(self, options, timeout=600):
        self.options, self.timeout = options, timeout
        self.process = self.channel = None

    def __call__(self, audio, language):
        if self.process is None or not self.process.is_alive():
            self.close()
            context = multiprocessing.get_context('spawn')
            self.channel, child = context.Pipe()
            self.process = context.Process(target=child_loop, args=(child, self.options), daemon=True)
            self.process.start()
            child.close()
        try:
            self.channel.send((audio, language))
            if not self.channel.poll(self.timeout):
                self.close()
                raise TranscriptionError('TRANSCRIPTION_TIMEOUT')
            return self.channel.recv()
        except (EOFError, BrokenPipeError, OSError):
            self.process.join(0.2)
            print(json.dumps({'event': 'transcriber.process_exited', 'exit_code': self.process.exitcode}), flush=True)
            self.close()
            raise TranscriptionError('TRANSCRIBER_PROCESS_EXITED') from None

    def close(self):
        if self.process is not None:
            if self.process.is_alive() and self.channel is not None:
                try:
                    self.channel.send(None)
                except (BrokenPipeError, EOFError, OSError):
                    pass
                self.process.join(2)
            if self.process.is_alive():
                self.process.terminate()
                self.process.join(5)
                if self.process.is_alive():
                    self.process.kill()
            self.process.join()
        if self.channel is not None:
            self.channel.close()
        self.process = self.channel = None


def handle(connection, allowed_uids, infer):
    connection.settimeout(15)
    if peer_uid(connection) not in allowed_uids:
        return
    try:
        # This input budget is distinct from inference and the caller's full
        # queue/connect/write/result budget. A trickling peer cannot monopolize
        # the shared worker by restarting a timeout for every frame byte.
        deadline = Deadline(15)
        header = receive_json(connection, 4096, deadline=deadline)
        length, language = header.get('bytes'), header.get('language')
        if (set(header) != {'version', 'bytes', 'language'} or type(header['version']) is not int
                or header['version'] != 1 or type(length) is not int or not 0 < length <= MAX_AUDIO_BYTES
                or language is not None and (not isinstance(language, str) or not re.fullmatch('[a-z]{2,3}', language))):
            raise TranscriptionError('TRANSCRIBER_PROTOCOL_ERROR')
        audio = receive_exact(connection, length, deadline=deadline)
        result = infer(audio, language)
        del audio
        send_json(connection, result, MAX_RESULT_BYTES, deadline=Deadline(15))
    except TranscriptionError as exc:
        send_json(connection, {'error_code': exc.code}, 4096, deadline=Deadline(15))


def serve(socket_path, allowed_uids, infer, ready=None, stop=None):
    path = Path(socket_path)
    parent = path.parent.stat()
    if path.parent.resolve() != path.parent or parent.st_mode & 0o022:
        raise ValueError('Socket requires a physical directory without group/public write access')
    # Never remove an existing socket: it could belong to another active worker.
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        os.chmod(path, 0o660)
        identity = path.stat()
        listener.listen(8)
        listener.settimeout(0.5)
        if ready:
            ready.set()
        try:
            while stop is None or not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    try:
                        handle(connection, allowed_uids, infer)
                    except (OSError, ValueError):
                        pass  # Fixed protocol failures; no payload/exception logging.
        finally:
            current = path.lstat()
            if stat.S_ISSOCK(current.st_mode) and current.st_ino == identity.st_ino:
                path.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--model-directory', required=True, type=Path)
    parser.add_argument('--allow-uid', required=True, action='append', type=int)
    parser.add_argument('--device', choices=('cpu', 'cuda'), default='cpu')
    parser.add_argument('--compute-type', choices=('float32', 'float16'), default='float32')
    parser.add_argument('--threads', type=int, default=4)
    args = parser.parse_args(argv)
    if not 1 <= args.threads <= 16 or any(uid < 0 for uid in args.allow_uid):
        parser.error('Invalid worker limits')
    if not args.model_directory.is_dir():
        parser.error('A preinstalled, verified large-v3 model is required')
    infer = InferenceProcess(dict(model_directory=args.model_directory, device=args.device,
                                  compute_type=args.compute_type, threads=args.threads))
    def terminate(*_):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, terminate)
    try:
        serve(args.socket, set(args.allow_uid), infer)
    finally:
        infer.close()


if __name__ == '__main__':
    main()
