"""Synthetic ClearChat coverage at media/callback boundaries, with real Store state.

The provider's range references are anchors, never an exhaustive deletion list.
No production identities, sessions, files or network callbacks are used here.
"""
import base64
from datetime import datetime, timezone
import hashlib
import json
import time

import pytest

from conftest import attachment_payload, install_attachment_readback, message
from sally_whatsapp.event_recovery import EventRecovery
from sally_whatsapp.server import Service


CHAT = '15550001111@c.us'
UNCERTAIN = 'clear_chat_coverage_uncertain'
CONTENT = b'synthetic ClearChat attachment bytes'
FILENAME = 'synthetic-clearchat-private.pdf'


def identifier(raw):
    return 'false_' + CHAT + '_' + raw


@pytest.fixture
def coverage(environment, monkeypatch):
    settings, receiver, gateway, _ = environment
    now = int(time.time())
    # Keep one fresh clock instant throughout each case, including digest
    # bucket selection. A real minute boundary must not split this fixture.
    monkeypatch.setattr(time, 'time', lambda: now)
    service = Service(settings, gateway=gateway, event_transport=receiver)
    bound = now - 20
    dates = {'B': bound - 10, 'C': bound, 'F': bound + 10}
    gateway.media_bytes = CONTENT
    return service, receiver, now, bound, dates


def acquire(fixture, *raw_ids):
    service, _, _, _, dates = fixture
    for raw in raw_ids:
        envelope=message(identifier(raw), CHAT, timestamp=dates[raw],text='synthetic retained ' + raw)
        envelope['payload'].update(attachment_payload(identifier(raw),CHAT,CONTENT,
            name=FILENAME,mimetype='application/pdf',timestamp=dates[raw]))
        envelope['payload']['body']='synthetic retained ' + raw
        service.store.ingest(envelope)


def clear(fixture, *, boundary=True, system_boundary=None):
    service, _, now, bound, _ = fixture
    span = {'messages': [{'key': {'ID': 'C', 'fromMe': False, 'remoteJID': CHAT},
                          'timestamp': bound}]}
    if boundary:
        span['lastMessageTimestamp'] = bound
    if system_boundary is not None:
        span['lastSystemMessageTimestamp'] = system_boundary
    return service.store.ingest({'id': 'synthetic-clear-range', 'event': 'engine.event',
        'engine': 'GOWS', 'session': 'default', 'payload': {'session': 'default',
        'event': 'events.ClearChat', 'data': {'JID': CHAT,
            'Timestamp': datetime.fromtimestamp(now, timezone.utc).isoformat(),
            'FromFullSync': False, 'DeleteMedia': False, 'Action': {'messageRange': span}}}})


def subscribe(fixture, name='message.received'):
    service = fixture[0]
    filters = {'chat_ids': [CHAT]}
    if name == 'message.digest':
        filters['digest_window_seconds'] = 60
    elif name == 'whatsapp.event':
        filters['event_types'] = ['message.reaction']
    return service.events.subscribe('test-owner', name, filters,
        {'url': 'https://receiver.example/callback',
         'secret': 'whsec_' + base64.b64encode(b'x' * 32).decode()})['id']


def transfer(fixture, raw='B'):
    service, _, _, _, dates = fixture
    install_attachment_readback(service.gateway,attachment_payload(identifier(raw),CHAT,CONTENT,
        name=FILENAME,mimetype='application/pdf',timestamp=dates[raw]))
    return service.media.enqueue('test-owner', {'kind': 'gateway',
        'message_id': identifier(raw), 'chat_id': CHAT, 'timestamp': dates[raw],
        'media': {'url': 'http://synthetic.invalid/file', 'filename': FILENAME,
                  'mimetype': 'application/pdf'}}, FILENAME, 'application/pdf')['id']


def media_row(service, transfer_id):
    with service.store.db() as db:
        return dict(db.execute('SELECT * FROM media_jobs WHERE id=?', (transfer_id,)).fetchone())


def delivery_rows(service):
    with service.store.db() as db:
        return [dict(row) for row in db.execute('SELECT * FROM deliveries ORDER BY id')]


def assert_withheld(service, raw):
    assert service.store.message_state(identifier(raw))['state'] == UNCERTAIN
    with service.store.db() as db:
        assert service.store.is_unavailable(db, identifier(raw))
        assert not service.store.is_revoked(db, identifier(raw))


@pytest.mark.parametrize('raw', ['B', 'C'])
def test_clear_range_withholds_queued_media_anchor_and_unlisted_preceding_message(coverage, raw):
    service = coverage[0]
    acquire(coverage, 'B', 'C', 'F')
    job = transfer(coverage, raw)
    before = media_row(service, job)
    clear(coverage)
    assert_withheld(service, raw)
    status = service.media.status(job, 'test-owner')
    assert status['state'] == 'unavailable'
    assert status['filename'] == status['mimetype'] == ''
    assert status['size'] is None and status['sha256'] is None
    assert 'download_url' not in status and 'next_tool' not in status
    assert not service.media.process_one()
    assert media_row(service, job) == before


def test_clear_range_hides_ready_metadata_and_existing_grants_without_erasing_bytes(coverage):
    service = coverage[0]
    acquire(coverage, 'B', 'C', 'F')
    job = transfer(coverage)
    assert service.media.process_one()
    grant = service.media.status(job, 'test-owner')['download_url'].rsplit('/', 1)[-1]
    before = media_row(service, job)
    clear(coverage)
    status = service.media.status(job, 'test-owner')
    assert status['state'] == 'unavailable'
    assert status['filename'] == status['mimetype'] == ''
    assert status['size'] is None and status['sha256'] is None
    assert 'download_url' not in status
    with pytest.raises(ValueError, match='not ready'):
        service.media.resolve(grant)
    with pytest.raises(ValueError, match='not ready'):
        service.media.url(job, 'test-owner')
    assert media_row(service, job) == before
    assert service.media.path(job).read_bytes() == CONTENT


@pytest.mark.parametrize('failed', [False, True])
def test_clear_range_during_download_wins_completion_and_preserves_retry_source(coverage, failed):
    service = coverage[0]
    acquire(coverage, 'B', 'C', 'F')
    job = transfer(coverage)
    before = media_row(service, job)
    download = service.gateway.attachment_to_file
    def raced(media, target, maximum):
        result = download(media, target, maximum)
        clear(coverage)
        if failed:
            raise ValueError('Synthetic attachment failure')
        return result
    service.gateway.attachment_to_file = raced
    assert service.media.process_one()
    assert_withheld(service, 'B')
    after = media_row(service, job)
    assert after['state'] == 'queued' and after['source'] == before['source']
    assert after['filename'] == FILENAME
    assert not service.media.path(job).exists()
    assert not service.media.process_one()
    assert service.media.status(job, 'test-owner')['state'] == 'unavailable'


def test_system_boundary_does_not_hide_post_message_boundary_attachment(coverage):
    service, _, now, _, _ = coverage
    acquire(coverage, 'B', 'C', 'F')
    job = transfer(coverage, 'F')
    clear(coverage, system_boundary=now - 1)
    assert service.store.message_state(identifier('F'))['state'] == 'unknown'
    assert service.media.process_one()
    assert service.media.status(job, 'test-owner')['state'] == 'ready'


def test_unknown_range_boundary_does_not_hide_other_acquired_media(coverage):
    service = coverage[0]
    acquire(coverage, 'B', 'C', 'F')
    job = transfer(coverage, 'B')
    clear(coverage, boundary=False)
    assert_withheld(service, 'C')
    assert service.store.message_state(identifier('B'))['state'] == 'unknown'
    assert service.media.process_one()
    assert service.media.status(job, 'test-owner')['state'] == 'ready'


@pytest.mark.parametrize('attempts', [0, 1])
def test_mixed_digest_trims_only_before_attempt_and_preserves_attempted_payload(coverage, attempts):
    service, receiver, *_ = coverage
    subscribe(coverage, 'message.digest')
    acquire(coverage, 'B', 'C', 'F')
    receiver.requests.clear()
    with service.store.db() as db:
        db.execute('UPDATE deliveries SET next_attempt=0,attempts=?', (attempts,))
    before = delivery_rows(service)[0]
    assert json.loads(before['body'])['data']['message_ids'] == [identifier(raw) for raw in ('B', 'C', 'F')]
    clear(coverage)
    for _ in range(5):
        if not service.events.dispatch_one():
            break
    after = delivery_rows(service)[0]
    assert after['event_id'] == before['event_id']
    if attempts == 0:
        assert after['state'] == 'accepted' and after['attempts'] == 1
        assert len(receiver.requests) == 1
        assert json.loads(receiver.requests[0][1])['data']['message_ids'] == [identifier('F')]
    else:
        assert receiver.requests == []
        assert after['body'] == before['body']
        assert after['state'] == 'cancelled' and after['attempts'] == attempts
        assert service.store.state()['recovery_reasons']['digest_cancelled_after_attempt']['status'] == 'open'


def test_mixed_digest_clear_after_claim_keeps_payload_and_reports_recovery(coverage, monkeypatch):
    service, receiver, *_ = coverage
    subscribe(coverage, 'message.digest')
    acquire(coverage, 'B', 'C', 'F')
    receiver.requests.clear()
    with service.store.db() as db:
        db.execute('UPDATE deliveries SET next_attempt=0')
    before = delivery_rows(service)[0]
    decrypt = service.events.cipher.decrypt
    def claimed(*args, **kwargs):
        clear(coverage)
        return decrypt(*args, **kwargs)
    monkeypatch.setattr(service.events.cipher, 'decrypt', claimed)
    assert service.events.dispatch_one()
    after = delivery_rows(service)[0]
    assert receiver.requests == []
    assert after['body'] == before['body'] and after['event_id'] == before['event_id']
    assert after['state'] == 'cancelled' and after['attempts'] == 1
    assert service.store.state()['recovery_reasons']['digest_cancelled_after_attempt']['status'] == 'open'


def reaction(fixture, raw='B'):
    service, _, now, *_ = fixture
    receipt = 'synthetic-range-reaction-' + raw
    service.store.ingest({'id': receipt, 'event': 'message.reaction', 'timestamp': now * 1000,
        'payload': {'id': identifier('REACTION'), 'from': CHAT, 'to': '15550009999@c.us',
            'fromMe': False, 'timestamp': now,
            'reaction': {'text': 'synthetic private reaction', 'messageId': identifier(raw)}}})
    return 'change_' + hashlib.sha256(receipt.encode()).hexdigest()


def test_account_event_preview_withholds_range_source_without_rewriting_history(coverage):
    service = coverage[0]
    acquire(coverage, 'B', 'C', 'F')
    event_id = reaction(coverage)
    with service.store.db() as db:
        before = db.execute('SELECT data FROM account_events WHERE id=?', (event_id,)).fetchone()[0]
    clear(coverage)
    preview = service.store.account_event(event_id)
    assert preview['data'] == {'message_id': identifier('B'), 'unavailable': True}
    assert 'synthetic private reaction' not in json.dumps(preview)
    with service.store.db() as db:
        assert db.execute('SELECT data FROM account_events WHERE id=?', (event_id,)).fetchone()[0] == before


@pytest.mark.parametrize('name', ['message.received', 'whatsapp.event'])
def test_callback_recovery_rejects_uncertain_range_source_and_retains_audit(coverage, name):
    service, receiver, *_ = coverage
    subscription = subscribe(coverage, name)
    acquire(coverage, 'B')
    if name == 'whatsapp.event':
        reaction(coverage)
    with service.store.db() as db:
        db.execute("UPDATE deliveries SET state='failed',last_status=503,attempts=?",
                   (service.settings.max_callback_attempts,))
    before = delivery_rows(service)[0]
    recovery = EventRecovery(service.store, service.settings)
    assert recovery.preview(subscription, [before['id']])['eligible']
    receiver.requests.clear()
    clear(coverage)
    blocked = recovery.preview(subscription, [before['id']])
    assert not blocked['eligible']
    assert blocked['deliveries'][0]['reason'] == 'source_unavailable'
    assert delivery_rows(service)[0] == before
    assert receiver.requests == []


def test_single_message_callback_never_posts_preboundary_preview(coverage):
    service, receiver, *_ = coverage
    subscribe(coverage)
    acquire(coverage, 'B', 'C', 'F')
    receiver.requests.clear()
    clear(coverage)
    for _ in range(5):
        if not service.events.dispatch_one():
            break
    assert len(receiver.requests) == 1
    posted = json.loads(receiver.requests[0][1])
    assert posted['data']['message_id'] == identifier('F')
    assert posted['data']['preview'] == 'synthetic retained F'


@pytest.mark.parametrize('definite', ['revoked', 'deleted_for_me', 'chat_deleted'])
def test_definite_state_precedes_clearchat_uncertainty_for_consumers(coverage, definite):
    service, _, now, *_ = coverage
    acquire(coverage, 'B', 'C', 'F')
    clear(coverage)
    if definite == 'revoked':
        service.store.ingest({'id': 'synthetic-definite-revoke', 'event': 'message.revoked',
                             'payload': {'revokedMessageId': identifier('B')}})
    else:
        kind = 'DeleteForMe' if definite == 'deleted_for_me' else 'DeleteChat'
        data = {'Timestamp': datetime.fromtimestamp(now, timezone.utc).isoformat()}
        if kind == 'DeleteForMe':
            data.update(ChatJID=CHAT, MessageID='B', IsFromMe=False)
        else:
            data['JID'] = CHAT
        service.store.ingest({'id': 'synthetic-definite-' + kind, 'event': 'engine.event',
            'engine': 'GOWS', 'session': 'default', 'payload': {'session': 'default',
                'event': 'events.' + kind, 'data': data}})
    assert service.store.message_state(identifier('B'))['state'] == definite
    with service.store.db() as db:
        assert service.store.is_unavailable(db, identifier('B'))
