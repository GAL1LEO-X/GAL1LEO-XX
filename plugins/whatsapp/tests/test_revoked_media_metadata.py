"""Revoked media metadata and real schema upgrade, with synthetic files only."""
from dataclasses import replace
import hashlib
from pathlib import Path
import sqlite3
import time

from cryptography.fernet import Fernet
import pytest

from conftest import attachment_payload, call, message
from sally_whatsapp.media import Media, copy_bounded
from sally_whatsapp.server import Service, create_app
from sally_whatsapp.store import Store, canonical


CONTENT = b'synthetic attachment payload'
NAME = 'synthetic-private-report.pdf'
METADATA = {'filename': NAME, 'mimetype': 'application/pdf', 'size': len(CONTENT),
            'sha256': hashlib.sha256(CONTENT).hexdigest()}
REDACTED = {'filename': '', 'mimetype': '', 'size': None, 'sha256': None}


def service_for(environment, **changes):
    settings, receiver, gateway, _ = environment
    gateway.media_bytes = CONTENT
    return Service(replace(settings, **changes), gateway=gateway, event_transport=receiver)


def attachment(service, source_id='false_group-1@g.us_SYNTHETICSOURCE'):
    from urllib.parse import unquote
    envelope = message(source_id)
    envelope['payload'] = attachment_payload(source_id, 'group-1@g.us', CONTENT,
                                              name=NAME, mimetype='application/pdf')
    observations = getattr(service.gateway, 'attachment_observations', {})
    observations[source_id] = envelope['payload']
    service.gateway.attachment_observations = observations
    def read(method, path, **kwargs):
        assert method == 'GET' and '/messages/' in path
        return observations[unquote(path.rsplit('/messages/', 1)[1])]
    service.gateway.request = read
    service.store.ingest(envelope)
    return service.media.enqueue(service.settings.owner_subject, {
        'kind': 'gateway', 'message_id': source_id, 'chat_id': 'group-1@g.us',
        'media': envelope['payload']['media']}, NAME, 'application/pdf')['id']


def revoke(service, source_id='false_group-1@g.us_SYNTHETICSOURCE'):
    service.store.ingest({'event': 'message.revoked', 'id': 'revoke-' + source_id,
                          'payload': {'revokedMessageId': source_id}})


def raw(service, identifier):
    with service.store.db() as db:
        return dict(db.execute('SELECT * FROM media_jobs WHERE id=?', (identifier,)).fetchone())


def metadata(value):
    return {name: value[name] for name in REDACTED}


def assert_redacted(service, identifier):
    value = service.media.status(identifier, service.settings.owner_subject)
    assert value['id'] == identifier and value['state'] == 'cancelled'
    assert metadata(value) == REDACTED
    assert 'download_url' not in value and 'next_tool' not in value
    row = raw(service, identifier)
    assert metadata(row) == REDACTED and row['source'] == b''
    assert not service.media.path(identifier).exists()
    return value


@pytest.mark.parametrize('stage', ['queued', 'ready'])
def test_revoked_metadata_is_removed_in_database_and_status_before_expiry(environment, stage):
    service = service_for(environment)
    identifier = attachment(service)
    grant = None
    if stage == 'ready':
        assert service.media.process_one()
        before = service.media.status(identifier, 'test-owner')
        assert metadata(before) == METADATA
        grant = before['download_url'].rsplit('/', 1)[-1]
    revoke(service)
    # Persistence must be redacted by the revoke transaction, before status.
    assert metadata(raw(service, identifier)) == REDACTED
    value = assert_redacted(service, identifier)
    assert value['expires'] > time.time()
    assert raw(service, identifier)['source_message_id'] == 'false_group-1@g.us_SYNTHETICSOURCE'
    if grant:
        with pytest.raises(ValueError, match='not ready'):
            service.media.resolve(grant)
    assert not service.media.process_one()
    restarted = service_for(environment)
    assert_redacted(restarted, identifier)


@pytest.mark.parametrize('state', ['queued', 'downloading', 'ready', 'failed', 'cancelled', 'expired'])
@pytest.mark.parametrize('entrypoint', ['status', 'clean'])
def test_old_schema7_rows_with_revoked_source_are_scrubbed_in_every_state(environment, state, entrypoint):
    service = service_for(environment)
    identifier = attachment(service)
    service.media.path(identifier).write_bytes(CONTENT)
    with service.store.db() as db:
        db.execute('INSERT INTO message_mutations VALUES(?,?,NULL,?)',
                   ('false_group-1@g.us_SYNTHETICSOURCE', 'revoked', time.time()))
        db.execute('UPDATE media_jobs SET state=?,size=?,sha256=?,error=? WHERE id=?',
                   (state, len(CONTENT), METADATA['sha256'], 'synthetic old failure', identifier))
    if entrypoint == 'clean':
        service.media.clean()
        assert metadata(raw(service, identifier)) == REDACTED
    assert_redacted(service, identifier)


@pytest.mark.parametrize('outcome', ['success', 'failure', 'expired-source'])
def test_revocation_during_download_scrubs_metadata_and_wins_over_finalization(environment, outcome):
    from sally_whatsapp.gateway import GatewayUnavailable
    service = service_for(environment)
    identifier = attachment(service)
    calls = []

    def download(media, target, maximum):
        calls.append('download')
        target.write_bytes(CONTENT)
        revoke(service)
        if outcome == 'failure':
            raise ValueError('synthetic download failure')
        if outcome == 'expired-source':
            raise GatewayUnavailable('synthetic expired cache', status_code=404)
        return len(CONTENT), METADATA['sha256']

    service.gateway.attachment_to_file = download
    service.gateway.message = lambda *a, **kw: pytest.fail('Revoked source must not be refreshed')
    assert service.media.process_one()
    assert calls == ['download']
    assert metadata(raw(service, identifier)) == REDACTED
    assert_redacted(service, identifier)
    assert not service.media.process_one()


@pytest.mark.parametrize('entrypoint', ['status', 'clean'])
@pytest.mark.parametrize(('source', 'reason'), [
    (None, Media.LEGACY_INVALIDATED), ('', Media.LEGACY_UNAVAILABLE),
    ('false_group-1@g.us_SYNTHETICSOURCE', Media.REVOKED),
])
def test_old_cancelled_metadata_is_scrubbed_using_exact_provenance_marker(environment, source, reason, entrypoint):
    service = service_for(environment)
    identifier = attachment(service)
    with service.store.db() as db:
        db.execute("UPDATE media_jobs SET state='cancelled',source_message_id=?,error=?,size=?,sha256=? WHERE id=?",
                   (source, reason, len(CONTENT), METADATA['sha256'], identifier))
    service.media.path(identifier).write_bytes(CONTENT)
    if entrypoint == 'clean':
        service.media.clean()
        assert metadata(raw(service, identifier)) == REDACTED
    assert_redacted(service, identifier)


def test_invalid_legacy_encrypted_provenance_is_redacted_by_backfill(environment):
    service = service_for(environment)
    identifier = attachment(service)
    with service.store.db() as db:
        db.execute("UPDATE media_jobs SET source_message_id='',source=?,size=?,sha256=? WHERE id=?",
                   (b'not-a-valid-synthetic-envelope', len(CONTENT), METADATA['sha256'], identifier))
    service.media.path(identifier).write_bytes(CONTENT)
    service.media.backfill_sources()
    assert metadata(raw(service, identifier)) == REDACTED
    assert raw(service, identifier)['error'] == Media.LEGACY_UNAVAILABLE
    assert_redacted(service, identifier)


def test_recovered_legacy_provenance_is_checked_for_revocation_in_backfill(environment):
    service = service_for(environment)
    identifier = attachment(service)
    with service.store.db() as db:
        db.execute("UPDATE media_jobs SET source_message_id='' WHERE id=?", (identifier,))
        db.execute('INSERT INTO message_mutations VALUES(?,?,NULL,?)',
                   ('false_group-1@g.us_SYNTHETICSOURCE', 'revoked', time.time()))
    service.media.backfill_sources()
    assert metadata(raw(service, identifier)) == REDACTED
    assert raw(service, identifier)['source_message_id'] == 'false_group-1@g.us_SYNTHETICSOURCE'
    assert_redacted(service, identifier)


def test_status_projection_defensively_masks_cancelled_metadata(environment, monkeypatch):
    service = service_for(environment)
    identifier = attachment(service)
    row = {**raw(service, identifier), **METADATA, 'state': 'cancelled', 'error': Media.REVOKED}
    monkeypatch.setattr(service.media, 'row', lambda *args: row)
    assert metadata(service.media.status(identifier, 'test-owner')) == REDACTED


def test_revoked_expired_transfer_is_scrubbed_and_file_removed_before_expiry_error(environment):
    service = service_for(environment)
    identifier = attachment(service)
    assert service.media.process_one()
    with service.store.db() as db:
        db.execute('UPDATE media_jobs SET expires=? WHERE id=?', (time.time() - 1, identifier))
        db.execute('INSERT INTO message_mutations VALUES(?,?,NULL,?)',
                   ('false_group-1@g.us_SYNTHETICSOURCE', 'revoked', time.time()))
    with pytest.raises(ValueError, match='expired'):
        service.media.status(identifier, 'test-owner')
    assert metadata(raw(service, identifier)) == REDACTED
    assert not service.media.path(identifier).exists()


def test_wrong_owner_cannot_read_or_mutate_legacy_transfer(environment):
    service = service_for(environment)
    identifier = attachment(service)
    with service.store.db() as db:
        db.execute("UPDATE media_jobs SET state='cancelled',source_message_id=NULL,error=? WHERE id=?",
                   (Media.LEGACY_INVALIDATED, identifier))
    before = raw(service, identifier)
    with pytest.raises(ValueError, match='not found'):
        service.media.status(identifier, 'other-owner')
    assert raw(service, identifier) == before


def test_independent_instance_and_unrelated_external_upload_keep_metadata(environment, tmp_path, monkeypatch):
    service = service_for(environment)
    other = service_for(environment, database=tmp_path / 'other-instance' / 'archive.sqlite',
                        owner_subject='other-owner')
    first = attachment(service)
    unrelated = attachment(service, 'false_group-1@g.us_UNRELATEDSOURCE')
    second = attachment(other)
    external = service.media.enqueue('test-owner', {
        'kind': 'external', 'file_id': 'synthetic-upload',
        'download_url': 'https://synthetic.invalid/upload'}, NAME, 'application/pdf')['id']
    monkeypatch.setattr('sally_whatsapp.media.download_public',
                        lambda url, target, maximum: copy_bounded([CONTENT], target, maximum))
    while service.media.process_one():
        pass
    assert other.media.process_one()
    revoke(service)
    assert_redacted(service, first)
    for instance, identifier in ((service, unrelated), (other, second), (service, external)):
        assert metadata(instance.media.status(identifier, instance.settings.owner_subject)) == METADATA
    # Ordinary cancellation of an external upload is not a revocation marker.
    with service.store.db() as db:
        db.execute("UPDATE media_jobs SET state='cancelled',error='Cancelled by account policy' WHERE id=?", (external,))
    service.media.clean()
    assert metadata(service.media.status(external, 'test-owner')) == METADATA


def test_mcp_status_after_revocation_does_not_expose_metadata(app_client, environment):
    app, client = app_client
    service = app.state.service
    service.gateway.media_bytes = CONTENT
    identifier = attachment(service)
    assert service.media.process_one()
    revoke(service)
    value = call(client, 'get_transfer_status', {'transfer_id': identifier})['result']['structuredContent']
    assert metadata(value) == REDACTED


def test_real_schema6_fixture_ready_metadata_and_grant_are_invalidated(environment):
    settings, receiver, gateway, _ = environment
    now = time.time()
    identifier = 'media_' + '1' * 32
    with sqlite3.connect(settings.database) as db:
        db.executescript((Path(__file__).parent / 'fixtures/schema6.sql').read_text())
        db.execute('INSERT INTO media_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                   (identifier, 'test-owner', 'synthetic-legacy-identity', 'ready', b'', NAME,
                    'application/pdf', len(CONTENT), METADATA['sha256'], now, now + 3600, None))
    cache = settings.database.parent / 'media-cache'
    cache.mkdir()
    (cache / (identifier + '.bin')).write_bytes(CONTENT)
    cipher = Fernet(settings.encryption_key_file.read_bytes())
    grant = cipher.encrypt(canonical({'purpose': 'media-download', 'id': identifier, 'expires': now + 3600}).encode()).decode()
    service = Service(settings, gateway=gateway, event_transport=receiver)
    with service.store.db() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
    assert metadata(raw(service, identifier)) == REDACTED
    assert raw(service, identifier)['source_message_id'] is None
    assert_redacted(service, identifier)
    with pytest.raises(ValueError, match='not ready'):
        service.media.resolve(grant)
    revoke(service)
    assert_redacted(service, identifier)


def test_check_and_media_initialization_do_not_repair_existing_schema7_metadata(environment):
    settings, receiver, gateway, _ = environment
    # Old v7 has no completed-repair marker; do not run the new serving repair
    # before seeding the legacy metadata that this test asks it to repair.
    Store(settings.database, migrate_schema=False)
    service = Service(settings, gateway=gateway, event_transport=receiver, recover_inflight=False)
    identifier = attachment(service)
    with service.store.db() as db:
        db.execute("UPDATE media_jobs SET state='cancelled',source_message_id=NULL,error=?,size=?,sha256=? WHERE id=?",
                   (Media.LEGACY_INVALIDATED, len(CONTENT), METADATA['sha256'], identifier))
        before = list(db.iterdump())
    checked = Store(settings.database, recover_inflight=False, migrate_schema=False)
    Media(checked, settings, gateway)
    app = create_app(settings, gateway=gateway, event_transport=receiver,
                     start_worker=False, recover_inflight=False)
    with checked.db() as db:
        assert list(db.iterdump()) == before
    app.state.service.diagnostics.close()
    # Normal serving explicitly permits upgrade/repair; it fixes old v7 rows.
    restarted = service_for(environment)
    assert metadata(raw(restarted, identifier)) == REDACTED
    assert_redacted(restarted, identifier)
