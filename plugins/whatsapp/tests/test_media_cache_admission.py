"""Independent review: immutable identity is not continuing authorization."""
import os

import pytest
from starlette.testclient import TestClient

from conftest import ready_external_media
from sally_whatsapp.live_attachments import read_source
from test_media_integrity_formats import FILES, acquire, setup


@pytest.mark.parametrize('mode', [0o620, 0o602, 0o666])
def test_download_rejects_cache_writable_by_other_accounts(app_client, mode):
    app, client = app_client
    service = app.state.service
    job = ready_external_media(service, data=b'SYNTHETIC PRIVATE FILE')
    ready = service.media.status(job['id'], service.settings.owner_subject)
    service.media.path(job['id']).chmod(mode)
    response = client.get(ready['download_url'])
    assert response.status_code == 404
    assert b'SYNTHETIC PRIVATE FILE' not in response.content
    assert service.media.status(job['id'], service.settings.owner_subject)['state'] == 'failed'


@pytest.mark.parametrize('invalidation', ['revoked', 'expired'])
@pytest.mark.parametrize('method', ['GET', 'HEAD'])
def test_download_rechecks_source_before_headers(environment, monkeypatch, invalidation, method):
    item = next(value for value in FILES if value['name'] == 'sample.pdf')
    app, gateway, _ = setup(environment, item)
    service = app.state.service
    acquire(service, gateway)
    source = read_source(service.store, service.settings, gateway, gateway.observation['id'])
    metadata = source.pop('media')
    source['provenance'] = 'archive_gateway'
    queued = service.media.enqueue(service.settings.owner_subject, source, metadata['filename'], metadata['mimetype'])
    assert service.media.process_one()
    ready = service.media.status(queued['id'], service.settings.owner_subject)
    original = service.media.download_response
    descriptors = []

    def invalidate_after_verification(grant):
        response = original(grant)
        descriptors.append((response, response.descriptor))
        if invalidation == 'revoked':
            service.store.ingest({'event': 'message.revoked', 'payload': {
                'revokedMessageId': gateway.observation['id']}})
        else:
            with service.store.db() as db:
                db.execute('UPDATE media_jobs SET expires=0 WHERE id=?', (queued['id'],))
        return response

    monkeypatch.setattr(service.media, 'download_response', invalidate_after_verification)
    with TestClient(app) as client:
        response = client.request(method, ready['download_url'])
    assert response.status_code == 404
    assert gateway.media_bytes not in response.content
    assert descriptors[0][0].descriptor is None
    with pytest.raises(OSError):
        os.fstat(descriptors[0][1])
