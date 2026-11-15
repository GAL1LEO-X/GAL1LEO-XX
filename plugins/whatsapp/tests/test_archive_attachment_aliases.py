"""M-01: verified complete aliases keep acquired attachments and existing jobs."""
import copy
import json
import time

import pytest
from starlette.testclient import TestClient

from sally_whatsapp.live_attachments import acquired_source_visible
from sally_whatsapp.server import AttachmentId
from test_clearchat_coverage import clear
from test_media_integrity_formats import FILES, CHAT, acquire, headers, result, setup


ALIAS = '18880001111@lid'
GROUP = '15550002222-222@g.us'
OTHER = '15550003333@c.us'


def prepare(environment, stored_alias=False, group=False):
    item = next(value for value in FILES if value['name'] == 'sample.pdf')
    app, gateway, token = setup(environment, item)
    source_chat = ALIAS if stored_alias else CHAT
    if group:
        original = f'false_{GROUP}_MEDIAFORMAT_{source_chat}'
        other = f'false_{GROUP}_MEDIAFORMAT_{CHAT if stored_alias else ALIAS}'
        gateway.observation.update(id=original, **{'from': GROUP}, participant=source_chat)
    else:
        original = f'false_{source_chat}_MEDIAFORMAT'
        other = f'false_{CHAT if stored_alias else ALIAS}_MEDIAFORMAT'
        gateway.observation.update(id=original, **{'from': source_chat})
    service = app.state.service
    acquire(service, gateway)
    service.store.bind_chat_alias(ALIAS, CHAT)
    return app, gateway, token, original, other, GROUP if group else CHAT


def archived_source(service, requested):
    row = service.store.message(requested)
    media = json.loads(row['media'])
    return {'kind': 'gateway', 'message_id': requested, 'chat_id': row['chat_id'],
            'timestamp': row['timestamp'], 'media': media, 'media_identity': media['identity']}


@pytest.mark.parametrize('stored_alias', [False, True], ids=['acquired-pn', 'acquired-lid'])
@pytest.mark.parametrize('group', [False, True], ids=['direct', 'group-participant'])
def test_new_alias_requests_share_one_verified_download_after_unknown_clear(environment, stored_alias, group):
    app, gateway, token, original, other, chat = prepare(environment, stored_alias, group)
    service = app.state.service
    service.store.ingest(clear(chat=chat, through=None))
    with TestClient(app) as client:
        headers(client, token)
        first = result(client, 'get_attachment', {'message_id': other, 'source': 'archive'})
        with service.store.db() as db:
            row = db.execute('SELECT source,source_message_id FROM media_jobs WHERE id=?', (first['id'],)).fetchone()
            assert row['source_message_id'] == original
            assert json.loads(service.media.cipher.decrypt(row['source']))['message_id'] == original
        assert service.media.process_one()
        ready = result(client, 'get_transfer_status', {'transfer_id': first['id']})
        assert ready['state'] == 'ready'
        second = result(client, 'get_attachment', {'message_id': original, 'source': 'archive'})
        assert second['id'] == first['id'] and second['state'] == 'ready'
        assert len(gateway.downloads) == 1
        assert client.get(ready['download_url']).content == gateway.media_bytes
        with service.store.db() as db:
            assert db.execute('SELECT count(*) FROM media_jobs').fetchone()[0] == 1


@pytest.mark.parametrize('stored_alias', [False, True])
@pytest.mark.parametrize('stage', ['queued', 'ready', 'legacy-queued', 'legacy-ready'])
def test_existing_alias_job_is_verified_and_reused_without_duplicate_download(environment, stored_alias, stage):
    app, gateway, _, original, other, chat = prepare(environment, stored_alias)
    service = app.state.service
    source = archived_source(service, other)
    if stage == 'legacy-queued':
        source.pop('media_identity')
        source['media'].pop('identity')
    queued = service.media.enqueue(service.settings.owner_subject, source,
        source['media']['filename'], source['media']['mimetype'])
    if stage in ('ready', 'legacy-ready'):
        assert service.media.process_one()
        assert service.media.status(queued['id'], service.settings.owner_subject)['state'] == 'ready'
    if stage == 'legacy-ready':
        with service.store.db() as db:
            db.execute("UPDATE media_jobs SET source=X'' WHERE id=?", (queued['id'],))
    service.store.ingest(clear(chat=chat, through=None))
    reused = service.attachment(AttachmentId(message_id=original), service.settings.owner_subject)
    assert reused['id'] == queued['id']
    if reused['state'] == 'queued':
        assert service.media.process_one()
    ready = service.media.status(queued['id'], service.settings.owner_subject)
    assert ready['state'] == 'ready'
    assert len(gateway.downloads) == 1
    assert service.media.resolve(ready['download_url'].rsplit('/', 1)[1])[0].read_bytes() == gateway.media_bytes
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM media_jobs').fetchone()[0] == 1


@pytest.mark.parametrize('difference', ['timestamp', 'digest', 'participant', 'direction', 'chat', 'unverified-alias', 'raw', 'anchor', 'revoked'])
def test_acquired_proof_does_not_relax_identity_or_restrictions(environment, difference):
    app, gateway, _, original, other, chat = prepare(environment, group=True)
    service = app.state.service
    source = archived_source(service, other)
    identifier, timestamp, expected = other, source['timestamp'], source['media_identity']
    if difference == 'timestamp': timestamp += 1
    elif difference == 'digest': expected = {**expected, 'sha256': '0' * 64}
    elif difference == 'participant': identifier = other.replace(ALIAS, OTHER)
    elif difference == 'direction': identifier = other.replace('false_', 'true_', 1)
    elif difference == 'chat': identifier = other.replace(GROUP, '15550004444-444@g.us')
    elif difference == 'unverified-alias': identifier = other.replace(ALIAS, '18880002222@lid')
    elif difference == 'raw': identifier = 'MEDIAFORMAT'
    elif difference == 'revoked':
        service.store.ingest({'event': 'message.revoked', 'payload': {'revokedMessageId': other}})
    service.store.ingest(clear(chat=chat, through=None,
        anchors=('MEDIAFORMAT',) if difference == 'anchor' else ()))
    with service.store.db() as db:
        assert not acquired_source_visible(service.store, db, identifier, timestamp, expected)
    assert not gateway.downloads


@pytest.mark.parametrize('difference', ['owner', 'live', 'timestamp', 'digest', 'failed', 'cancelled', 'expired'])
def test_reuse_does_not_cross_owner_provenance_or_binding(environment, difference):
    app, gateway, _, original, other, chat = prepare(environment)
    service = app.state.service
    source = archived_source(service, other)
    owner = 'another-owner' if difference == 'owner' else service.settings.owner_subject
    if difference == 'live': source['provenance'] = 'live_gateway'
    elif difference == 'timestamp': source['timestamp'] += 1
    elif difference == 'digest': source['media_identity'] = {**source['media_identity'], 'sha256': '0' * 64}
    prior = service.media.enqueue(owner, source, source['media']['filename'], source['media']['mimetype'])
    with service.store.db() as db:
        if difference in ('failed', 'cancelled'):
            db.execute('UPDATE media_jobs SET state=? WHERE id=?', (difference, prior['id']))
        elif difference == 'expired':
            db.execute('UPDATE media_jobs SET expires=? WHERE id=?', (time.time() - 1, prior['id']))
    service.store.ingest(clear(chat=chat, through=None))
    current = service.attachment(AttachmentId(message_id=original), service.settings.owner_subject)
    assert current['id'] != prior['id']
    assert not gateway.downloads


@pytest.mark.parametrize('changed', ['timestamp', 'digest', 'revoked', 'source-timestamp', 'source-digest'])
def test_legacy_alias_job_does_not_bypass_source_change(environment, changed):
    app, gateway, _, original, other, chat = prepare(environment)
    service = app.state.service
    source = archived_source(service, other)
    prior = service.media.enqueue(service.settings.owner_subject, source,
        source['media']['filename'], source['media']['mimetype'])
    assert service.media.process_one()
    ready = service.media.status(prior['id'], service.settings.owner_subject)
    with service.store.db() as db:
        legacy = b''
        if changed.startswith('source-'):
            source = copy.deepcopy(source)
            if changed == 'source-timestamp': source['timestamp'] += 1
            else: source['media_identity'] = {**source['media_identity'], 'sha256': '0' * 64}
            legacy = service.media.cipher.encrypt(json.dumps(source).encode())
        db.execute('UPDATE media_jobs SET source=? WHERE id=?', (legacy, prior['id']))
    service.store.ingest(clear(chat=chat, through=None))
    if changed == 'timestamp': gateway.observation['timestamp'] += 1
    elif changed == 'digest':
        gateway.observation = copy.deepcopy(gateway.observation)
        gateway.observation['_data']['Message']['documentMessage']['fileSHA256'] = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    elif changed == 'revoked':
        service.store.ingest({'event': 'message.revoked', 'payload': {'revokedMessageId': original}})
    with pytest.raises(ValueError):
        service.media.resolve(ready['download_url'].rsplit('/', 1)[1])
    assert len(gateway.downloads) == 1
