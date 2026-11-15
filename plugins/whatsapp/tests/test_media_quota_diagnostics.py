"""Real bounded synthetic bytes, fake provider/HTTP, no account or chat actions."""
from dataclasses import replace
import gzip
import json

import pytest
from starlette.testclient import TestClient

from conftest import call, ready_external_media
from sally_whatsapp.media import Media, copy_bounded
from sally_whatsapp.media_diagnostics import CACHE_LIMIT, FILE_LIMIT, PREFIX
from sally_whatsapp.server import create_app
from sally_whatsapp.store import Store
from test_diagnostics import records
from test_media_gateway_downloads import gateway_response, no_network
from test_revocation_and_live_events import attachment, revoke


@pytest.fixture
def limited(environment):
    settings, receiver, gateway, token = environment
    settings = replace(settings, max_attachment_bytes=1024, media_cache_bytes=1536)
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app) as client:
        client.headers.update({'Authorization': 'Bearer ' + token(),
                               'Accept': 'application/json, text/event-stream',
                               'MCP-Protocol-Version': '2026-07-28'})
        yield app.state.service, client, gateway


def stage(limited, monkeypatch, gateway_response, size, *, source='external', declared=True):
    service, _, gateway = limited
    data = b'q' * size
    if source == 'external':
        job = service.media.enqueue(service.settings.owner_subject,
            {'kind': 'external', 'file_id': 'file-synthetic-review',
             'download_url': 'https://files.example/synthetic?secret=never-log'},
            'private-synthetic-name.bin', 'application/octet-stream')
        monkeypatch.setattr('sally_whatsapp.media.download_public',
            lambda url, target, maximum: copy_bounded(
                [data[index:index+128] for index in range(0, len(data), 128)], target,
                maximum, len(data) if declared else None))
    else:
        gateway.media_bytes = data
        job = attachment(service)
        wire = gzip.compress(data, mtime=0) if source == 'gzip' else data
        download, _, _ = gateway_response(wire, maximum=1024,
            encoding='gzip' if source == 'gzip' else 'identity', length='actual' if declared else None)
        gateway.attachment_to_file = download.attachment_to_file
    return job


def status(limited, job):
    _, client, _ = limited
    result = call(client, 'get_transfer_status', {'transfer_id': job['id']})['result']
    assert not result.get('isError'), result
    return result['structuredContent']


@pytest.mark.parametrize('source', ['external', 'gateway', 'gzip'])
@pytest.mark.parametrize('declared', [True, False])
@pytest.mark.parametrize('size, occupied, reason', [(768, 1024, CACHE_LIMIT), (1025, 0, FILE_LIMIT)])
def test_limit_cause_is_shared_by_status_and_log(limited, monkeypatch, gateway_response,
                                                source, declared, size, occupied, reason):
    service, _, _ = limited
    previous = ready_external_media(service, data=b'p' * occupied) if occupied else None
    job = stage(limited, monkeypatch, gateway_response, size, source=source, declared=declared)
    assert service.media.process_one()
    result = status(limited, job)
    assert result['state'] == 'failed' and result['error_code'] == 'TRANSFER_FAILED'
    assert result['limit_bytes'] == 1024
    failure = result['failure']
    assert failure['reason'] == reason
    assert failure['cache_at_attempt']['used_bytes'] == occupied
    assert failure['cache_at_attempt']['effective_limit_bytes'] == (512 if occupied else 1024)
    assert result['cache']['accounting'] == 'ready_unexpired'
    assert result['cache']['remaining_bytes'] == 1536 - occupied
    assert ('expire' if reason == CACHE_LIMIT else 'smaller file') in result['recovery']
    assert not service.media.path(job['id']).exists()
    if previous:
        assert service.media.path(previous['id']).read_bytes() == b'p' * occupied
    event = [row for row in records(service.settings) if row['event'] == 'transfer.finished'][-1]
    assert event['error_code'] == 'TRANSFER_FAILED' and event['failure_reason'] == reason
    assert event['effective_limit_bytes'] == failure['cache_at_attempt']['effective_limit_bytes']
    assert event['cache_used_bytes'] == occupied
    assert event['quota_observed_at'] == round(failure['cache_at_attempt']['observed_at'], 2)
    assert 'private-synthetic-name' not in json.dumps(event)
    assert 'never-log' not in json.dumps(event)
    assert 'private:media_limit' not in json.dumps(service.store.state())


@pytest.mark.parametrize('size, occupied', [(1024, 0), (512, 1024)])
def test_exact_limits_remain_usable(limited, monkeypatch, gateway_response, size, occupied):
    service, _, _ = limited
    if occupied:
        ready_external_media(service, data=b'p' * occupied)
    job = stage(limited, monkeypatch, gateway_response, size)
    assert service.media.process_one()
    result = status(limited, job)
    assert result['state'] == 'ready' and result['size'] == size
    assert 'failure' not in result
    assert result['cache']['used_bytes'] == occupied + size
    assert result['cache']['remaining_bytes'] == 1536 - occupied - size


def test_full_cache_fails_without_fetch_or_evicting_valid_files(limited, monkeypatch, gateway_response):
    service, _, _ = limited
    one = ready_external_media(service, data=b'p' * 1024)
    two = ready_external_media(service, data=b'r' * 512)
    job = stage(limited, monkeypatch, gateway_response, 1)
    monkeypatch.setattr('sally_whatsapp.media.download_public', lambda *args: pytest.fail('full cache must not fetch'))
    assert service.media.process_one()
    result = status(limited, job)
    assert result['failure']['reason'] == CACHE_LIMIT
    assert result['failure']['cache_at_attempt']['remaining_bytes'] == 0
    assert 'observed_bytes' not in result['failure']
    assert service.media.path(one['id']).read_bytes() == b'p' * 1024
    assert service.media.path(two['id']).read_bytes() == b'r' * 512


def test_failure_survives_restart_and_is_distinct_from_current_quota(limited, monkeypatch, gateway_response):
    service, _, gateway = limited
    previous = ready_external_media(service, data=b'p' * 1024)
    job = stage(limited, monkeypatch, gateway_response, 768)
    assert service.media.process_one()
    failed = status(limited, job)['failure']
    with service.store.db() as db:
        db.execute('UPDATE media_jobs SET expires=0 WHERE id=?', (previous['id'],))
    assert not service.media.process_one()  # Existing cleanup frees quota; no implicit retry.
    restarted = Media(Store(service.settings.database), service.settings, gateway)
    result = restarted.status(job['id'], service.settings.owner_subject)
    assert result['state'] == 'failed' and result['failure'] == failed
    assert result['cache']['used_bytes'] == 0 and result['cache']['effective_limit_bytes'] == 1024
    assert result['failure']['cache_at_attempt']['used_bytes'] == 1024
    with service.store.db() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
    with pytest.raises(ValueError, match='not found'):
        restarted.status(job['id'], 'other-owner')


@pytest.mark.parametrize('when', ['during-download', 'after-failure'])
def test_revocation_wins_and_removes_private_failure(limited, monkeypatch, gateway_response, when):
    service, _, gateway = limited
    ready_external_media(service, data=b'p' * 1024)
    job = stage(limited, monkeypatch, gateway_response, 768, source='gateway')
    source = service.media.row(job['id'])['source_message_id']
    original = gateway.attachment_to_file
    if when == 'during-download':
        def revoked_download(*args):
            service.store.ingest(revoke(source))
            return original(*args)
        gateway.attachment_to_file = revoked_download
    assert service.media.process_one()
    if when == 'after-failure':
        assert status(limited, job)['failure']['reason'] == CACHE_LIMIT
        service.store.ingest(revoke(source))
    with service.store.db() as db:
        assert db.execute('SELECT value FROM state WHERE key=?', (PREFIX + job['id'],)).fetchone() is None
    result = status(limited, job)
    assert result['state'] == 'cancelled' and result['filename'] == ''
    assert 'failure' not in result and 'error_code' not in result
    if when == 'during-download':
        event = [row for row in records(service.settings) if row['event'] == 'transfer.finished'][-1]
        assert event['state'] == 'cancelled' and 'failure_reason' not in event


def test_expiration_removes_private_failure(limited, monkeypatch, gateway_response):
    service, _, _ = limited
    job = stage(limited, monkeypatch, gateway_response, 1025)
    assert service.media.process_one()
    assert status(limited, job)['failure']['reason'] == FILE_LIMIT
    with service.store.db() as db:
        db.execute('UPDATE media_jobs SET expires=0 WHERE id=?', (job['id'],))
    service.media.clean()
    with service.store.db() as db:
        assert db.execute('SELECT value FROM state WHERE key=?', (PREFIX + job['id'],)).fetchone() is None
    with pytest.raises(ValueError, match='expired'):
        service.media.status(job['id'], service.settings.owner_subject)


def test_new_view_once_evidence_removes_private_failure(limited, monkeypatch, gateway_response):
    service, _, _ = limited
    job = stage(limited, monkeypatch, gateway_response, 1025, source='gateway')
    source = service.media.row(job['id'])['source_message_id']
    assert service.media.process_one()
    assert status(limited, job)['failure']['reason'] == FILE_LIMIT
    service.store.observe_message_lifetime(source, 'group-1@g.us', {'kind': 'view_once'}, from_me=False)
    with service.store.db() as db:
        assert db.execute('SELECT value FROM state WHERE key=?', (PREFIX + job['id'],)).fetchone() is None
    result = status(limited, job)
    assert result['state'] == 'cancelled' and 'failure' not in result


@pytest.mark.parametrize('declared, reason', [(True, FILE_LIMIT), (False, CACHE_LIMIT)])
def test_only_observed_limits_are_attributed(limited, monkeypatch, gateway_response, declared, reason):
    service, _, _ = limited
    ready_external_media(service, data=b'p' * 1024)
    job = stage(limited, monkeypatch, gateway_response, 1025, declared=declared)
    assert service.media.process_one()
    result = status(limited, job)
    assert result['failure']['reason'] == reason
    assert result['failure']['cache_at_attempt']['effective_limit_bytes'] == 512
    assert result['failure']['observed_bytes'] == (1025 if declared else 640)


def test_legacy_or_untyped_error_is_not_reclassified_from_its_text(limited, monkeypatch, gateway_response):
    service, _, _ = limited
    ready_external_media(service, data=b'p' * 1024)
    job = stage(limited, monkeypatch, gateway_response, 768)
    def old_error(*args):
        raise ValueError('File exceeds the configured transfer limit')
    monkeypatch.setattr('sally_whatsapp.media.download_public', old_error)
    assert service.media.process_one()
    result = status(limited, job)
    assert result['state'] == 'failed' and 'failure' not in result
    assert result['error'] == 'File exceeds the configured transfer limit'
    event = [row for row in records(service.settings) if row['event'] == 'transfer.finished'][-1]
    assert event['error_code'] == 'TRANSFER_FAILED' and 'failure_reason' not in event


@pytest.mark.parametrize('damage', ['invalid-json', 'invalid-reason', 'invalid-quota', 'extra-fields'])
def test_private_failure_projection_is_bounded_and_defensive(limited, monkeypatch, gateway_response, damage):
    service, _, _ = limited
    job = stage(limited, monkeypatch, gateway_response, 1025)
    assert service.media.process_one()
    value = status(limited, job)['failure']
    if damage == 'invalid-reason': value['reason'] = ['private-string']
    if damage == 'invalid-quota': value['cache_at_attempt']['remaining_bytes'] = -1
    if damage == 'extra-fields':
        value['private_url'] = 'must-not-be-exposed'
        value['cache_at_attempt']['private_url'] = 'must-not-be-exposed'
    with service.store.db() as db:
        db.execute('UPDATE state SET value=? WHERE key=?',
                   ('{' if damage == 'invalid-json' else json.dumps(value), PREFIX + job['id']))
    result = status(limited, job)
    assert result['state'] == 'failed'
    assert ('failure' in result) == (damage == 'extra-fields')
    assert 'must-not-be-exposed' not in json.dumps(result)


def test_reduced_capacity_is_clamped_without_eviction(limited, monkeypatch, gateway_response):
    service, _, _ = limited
    ready_external_media(service, data=b'p' * 1024)
    other = ready_external_media(service, data=b'r' * 512)
    service.media.settings = replace(service.settings, media_cache_bytes=1024)
    result = service.media.status(other['id'], service.settings.owner_subject)
    assert result['state'] == 'ready'
    assert result['cache']['used_bytes'] == 1536
    assert result['cache']['remaining_bytes'] == result['cache']['effective_limit_bytes'] == 0
    assert service.media.path(other['id']).read_bytes() == b'r' * 512


def test_quota_excludes_expired_files_even_before_disk_cleanup(limited):
    service, _, _ = limited
    expired = ready_external_media(service, data=b'p' * 1024)
    current = ready_external_media(service, data=b'r' * 512)
    with service.store.db() as db:
        db.execute('UPDATE media_jobs SET expires=0 WHERE id=?', (expired['id'],))
    result = status(limited, current)
    assert result['cache']['used_bytes'] == 512
    assert result['cache']['remaining_bytes'] == 1024
    assert service.media.path(expired['id']).exists()  # Logical quota is not disk use.


def test_second_instance_has_its_own_quota(limited, tmp_path):
    service, _, gateway = limited
    ready_external_media(service, data=b'p' * 1024)
    settings = replace(service.settings, database=tmp_path/'second-instance'/'state.sqlite', owner_subject='second-owner')
    other = Media(Store(settings.database), settings, gateway)
    job = other.enqueue('second-owner', {'kind': 'external', 'file_id': 'file-other-synthetic',
                                       'download_url': 'https://files.example/synthetic'})
    assert job['cache']['used_bytes'] == 0 and job['cache']['remaining_bytes'] == 1536


@pytest.mark.parametrize('declared', [True, False])
def test_encoded_wire_bound_keeps_its_own_explanation(limited, monkeypatch, gateway_response, declared):
    service, _, gateway = limited
    job = stage(limited, monkeypatch, gateway_response, 1, source='gzip')
    raw = gzip.compress(b'q', mtime=0)
    wire = raw[:3] + bytes([raw[3] | 8]) + raw[4:10] + b'n' * 1024 + b'\0' + raw[10:]
    assert gzip.decompress(wire) == b'q'
    download, _, _ = gateway_response(wire, encoding='gzip', maximum=1024, length='actual' if declared else None)
    gateway.attachment_to_file = download.attachment_to_file
    assert service.media.process_one()
    result = status(limited, job)
    assert result['failure']['reason'] == FILE_LIMIT
    assert result['failure']['limit_basis'] == 'wire'
    assert 'encoded transfer' in result['error']
