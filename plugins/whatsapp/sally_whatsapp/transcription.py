"""Per-tenant, bounded, ephemeral transcription jobs over verified media."""
from collections import deque
import hashlib
import os
import threading
import time
import uuid

from .diagnostics import reference
from .transcription_protocol import (MODEL, MAX_AUDIO_BYTES, MAX_AUDIO_SECONDS,
                                     TranscriptionError, request)


class Transcriptions:
    def __init__(self, media, settings, diagnostics, transport=request):
        self.media, self.settings, self.diagnostics = media, settings, diagnostics
        self.transport = transport
        self.jobs, self.queue = {}, deque()
        self.condition = threading.Condition()
        self.thread = None
        self.closed = False

    def capabilities(self):
        return {'configured': self.settings.transcription_socket is not None,
                'availability': 'checked_on_request', 'model': MODEL, 'engine': 'faster-whisper',
                'execution': 'local', 'automatic_processing': False,
                'max_audio_bytes': MAX_AUDIO_BYTES, 'max_duration_seconds': MAX_AUDIO_SECONDS,
                'max_pending_jobs_per_instance': 4, 'max_retained_results_per_instance': 64,
                'result_persistence': 'memory_until_source_expiry_or_restart',
                'translation': 'consumer_translates_returned_text', 'read_receipts_sent': False}

    def _enabled(self):
        if self.settings.transcription_socket is None:
            raise TranscriptionError('TRANSCRIPTION_NOT_CONFIGURED')

    def _source(self, transfer_id, owner, *, verify=True):
        row = self.media.ready(transfer_id, owner) if verify else self.media.row(transfer_id, owner)
        if row['state'] != 'ready' or not row['source_message_id']:
            raise TranscriptionError('TRANSCRIPTION_SOURCE_UNAVAILABLE')
        if not (row['mimetype'].startswith('audio/') or row['mimetype'] == 'application/ogg'):
            raise TranscriptionError('TRANSCRIPTION_REQUIRES_AUDIO')
        if not 0 < row['size'] <= MAX_AUDIO_BYTES:
            raise TranscriptionError('AUDIO_SIZE_LIMIT')
        return row

    def _valid(self, job, *, verify=False):
        try:
            row = self._source(job['transfer_id'], job['owner'], verify=verify)
            if row['sha256'] != job['sha256'] or row['expires'] <= time.time():
                raise ValueError('Unavailable')
            job['expires'] = min(job['expires'], row['expires'])
            return row
        except Exception:
            job.pop('result', None)
            job['state'], job['error_code'] = 'unavailable', 'TRANSCRIPTION_SOURCE_UNAVAILABLE'
            return None

    def _purge(self):
        now = time.time()
        for identifier, job in list(self.jobs.items()):
            if job['expires'] <= now:
                job.pop('result', None)
                del self.jobs[identifier]
            else:
                self._valid(job)
        self.queue = deque(identifier for identifier in self.queue if identifier in self.jobs)

    def start(self, transfer_id, owner, language=None, retry=False):
        self._enabled()
        row = self._source(transfer_id, owner)
        with self.condition:
            if self.closed:
                raise TranscriptionError('TRANSCRIBER_UNAVAILABLE')
            self._purge()
            for job in list(self.jobs.values()):
                if (job['owner'], job['transfer_id'], job['language']) == (owner, transfer_id, language):
                    if retry and job['state'] in ('failed', 'unavailable'):
                        del self.jobs[job['id']]
                        continue
                    return self._public(job)
            if len(self.jobs) >= 64 or sum(job['state'] in ('queued', 'processing')
                                         for job in self.jobs.values()) >= 4:
                raise TranscriptionError('TRANSCRIPTION_QUEUE_FULL')
            identifier = 'transcript_' + uuid.uuid4().hex
            job = {'id': identifier, 'owner': owner, 'transfer_id': transfer_id, 'language': language,
                   'message_id': row['source_message_id'], 'sha256': row['sha256'],
                   'expires': row['expires'], 'created': time.time(), 'state': 'queued'}
            self.jobs[identifier] = job
            self.queue.append(identifier)
            if self.thread is None:
                self.thread = threading.Thread(target=self._run, name='whatsapp-transcription', daemon=True)
                self.thread.start()
            self.condition.notify()
            return self._public(job)

    def status(self, identifier, owner):
        self._enabled()
        with self.condition:
            job = self.jobs.get(identifier)
            if job is None or job['owner'] != owner or job['expires'] <= time.time():
                raise TranscriptionError('TRANSCRIPTION_NOT_FOUND_OR_EXPIRED')
            # Recheck current source and bytes before returning any transcript.
            self._valid(job, verify=True)
            return self._public(job)

    def _public(self, job):
        result = {key: job[key] for key in ('id', 'transfer_id', 'state', 'created', 'expires')}
        result.update(model=MODEL, read_receipts_sent=False)
        if job['state'] == 'ready':
            result.update(job['result'], source_message_id=job['message_id'],
                          source_sha256=job['sha256'], content_is_untrusted=True)
        elif job['state'] in ('queued', 'processing'):
            result.update(next_tool='get_transcription', poll_after_seconds=5)
        if job.get('error_code'):
            result['error_code'] = job['error_code']
            result['recovery'] = 'After resolving the cause, retry=true starts a fresh job only if the user explicitly requests a retry. Source access must still be valid.'
        return result

    def _process(self, job):
        row = self._source(job['transfer_id'], job['owner'])
        descriptor = self.media._verify_cache(row, keep_open=True)
        with os.fdopen(descriptor, 'rb') as source:
            audio = source.read(MAX_AUDIO_BYTES + 1)
        if len(audio) != row['size'] or hashlib.sha256(audio).hexdigest() != job['sha256']:
            raise TranscriptionError('TRANSCRIPTION_SOURCE_UNAVAILABLE')
        # Revocation/expiry can overlap the byte read; check again before IPC.
        with self.condition:
            if self.closed or not self._valid(job):
                return
        started = time.monotonic()
        result = self.transport(self.settings.transcription_socket, self.settings.transcription_server_uid,
                                audio, job['language'])
        del audio
        with self.condition:
            if self.closed or self.jobs.get(job['id']) is not job:
                return
            if self._valid(job, verify=True):
                job['result'], job['state'] = result, 'ready'
                self.diagnostics.emit('transcription.completed', job_ref=reference(job['id']),
                                      duration_ms=(time.monotonic() - started) * 1000, state='ready')

    def _run(self):
        while True:
            with self.condition:
                if self.closed:
                    return
                self._purge()
                if not self.queue:
                    self.condition.wait(5)
                    continue
                job = self.jobs.get(self.queue.popleft())
                if job is None or job['state'] != 'queued':
                    continue
                job['state'] = 'processing'
            try:
                self._process(job)
            except Exception as exc:
                code = exc.code if isinstance(exc, TranscriptionError) else 'TRANSCRIPTION_FAILED'
                with self.condition:
                    if not self.closed and self.jobs.get(job['id']) is job:
                        job.pop('result', None)
                        if job['state'] != 'unavailable':
                            job['state'], job['error_code'] = 'failed', code
                        self.diagnostics.emit('transcription.failed', 'warning',
                                              job_ref=reference(job['id']), error_code=code)
            finally:
                # Keeping the worker warm must not keep its last completed job
                # alive after expiry removes that job from the public mapping.
                job = None

    def close(self):
        with self.condition:
            self.closed = True
            self.jobs.clear()
            self.queue.clear()
            self.condition.notify_all()
