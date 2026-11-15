"""Real synthetic snapshots exercise the shared release/restore validation gate."""
from contextlib import closing
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from backup_validation import FORMAT, SNAPSHOT_FILES, validate_snapshot
from github_release_common import ReleaseError
import github_release as release
from sally_whatsapp.store import SCHEMA


def archive(path, names, *, extra=None):
    with tarfile.open(path, 'w:gz') as target:
        for name in names:
            info = tarfile.TarInfo(name)
            content = b'synthetic-only'
            info.size = len(content)
            target.addfile(info, io.BytesIO(content))
        if extra is not None:
            target.addfile(extra, io.BytesIO(b'x'*extra.size))


def manifest_for(snapshot, user='fixture'):
    manifest = {'format': FORMAT, 'user': user, 'created_utc': '20261012T000000000000Z',
                'sqlite_integrity': 'ok', 'includes_credentials': True, 'files': {}}
    for name in SNAPSHOT_FILES:
        path = snapshot/name
        manifest['files'][name] = {'bytes': path.stat().st_size,
                                  'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    (snapshot/'manifest.json').write_text(json.dumps(manifest))
    return manifest


RUNTIME_FILES = ['etc/whatsapp-fixture/'+name for name in ('config.toml', 'encryption.key', 'webhook.key', 'waha.key')]
RUNTIME_FILES += ['var/lib/sally-browser/stack/config/'+name for name in ('authelia.yml', 'users.yml')]
SOURCE_FILES = ['pyproject.toml', 'requirements.lock', 'sally_whatsapp/__init__.py', 'sally_whatsapp/store.py']


@pytest.fixture
def snapshot(tmp_path):
    root = tmp_path/'snapshot'
    root.mkdir()
    for name in ('archive.sqlite', 'shared-authelia.sqlite3'):
        with closing(sqlite3.connect(root/name)) as db:
            if name == 'archive.sqlite':
                db.executescript(SCHEMA)
            else:
                db.executescript('CREATE TABLE user_opaque_identifier('
                                 'service TEXT,sector_id TEXT,username TEXT,identifier TEXT UNIQUE);')
    archive(root/'private-runtime.tar.gz', RUNTIME_FILES)
    archive(root/'source.tar.gz', SOURCE_FILES)
    manifest_for(root)
    return root


def receipt(snapshot, **values):
    return json.dumps({'user': 'fixture', 'backup': str(snapshot), 'complete': True, **values})


def test_valid_backup_passes_both_gates_without_changing_files(snapshot, monkeypatch):
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in snapshot.iterdir()}
    assert validate_snapshot(snapshot, 'fixture')['user'] == 'fixture'
    monkeypatch.setattr(release, 'BACKUPS', snapshot.parent)
    assert release.verify_backups(receipt(snapshot), ['fixture']) == [str(snapshot)]
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in snapshot.iterdir()}


@pytest.mark.parametrize('damage', ['empty_files', 'missing_entry', 'wrong_owner', 'wrong_format',
                                  'false_complete', 'invalid_timestamp', 'bool_size', 'invalid_hash'])
def test_manifest_drift_blocks_release_and_restore(snapshot, monkeypatch, damage):
    path = snapshot/'manifest.json'
    manifest = json.loads(path.read_text())
    if damage == 'empty_files': manifest['files'] = {}
    elif damage == 'missing_entry': manifest['files'].pop('source.tar.gz')
    elif damage == 'wrong_owner': manifest['user'] = 'another-owner'
    elif damage == 'wrong_format': manifest['format'] = 'unknown'
    elif damage == 'false_complete': manifest['includes_credentials'] = False
    elif damage == 'invalid_timestamp': manifest['created_utc'] = '20269999T999999999999Z'
    elif damage == 'bool_size': manifest['files']['archive.sqlite']['bytes'] = True
    else: manifest['files']['archive.sqlite']['sha256'] = '0'*64
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError): validate_snapshot(snapshot, 'fixture')
    monkeypatch.setattr(release, 'BACKUPS', snapshot.parent)
    with pytest.raises(ReleaseError, match='backup validation failed'):
        release.verify_backups(receipt(snapshot), ['fixture'])


@pytest.mark.parametrize('damage', ['missing_file', 'extra_file', 'linked_file', 'linked_manifest', 'duplicate_json'])
def test_invalid_inventory_or_duplicate_manifest_fields_rejected(snapshot, damage, tmp_path):
    if damage == 'missing_file': (snapshot/'source.tar.gz').unlink()
    elif damage == 'extra_file': (snapshot/'archive.sqlite-wal').write_bytes(b'not-standalone')
    elif damage in ('linked_file', 'linked_manifest'):
        name = 'source.tar.gz' if damage == 'linked_file' else 'manifest.json'
        saved = tmp_path/'saved'
        (snapshot/name).rename(saved)
        (snapshot/name).symlink_to(saved)
    else:
        path = snapshot/'manifest.json'
        path.write_text(path.read_text().replace('"format":', '"format":"duplicate","format":', 1))
    with pytest.raises(ValueError): validate_snapshot(snapshot, 'fixture')


@pytest.mark.parametrize('name', ['archive.sqlite', 'shared-authelia.sqlite3'])
@pytest.mark.parametrize('damage', ['foreign_key', 'corrupt', 'wal'])
def test_both_databases_are_validated_beyond_checksums(snapshot, name, damage):
    path = snapshot/name
    if damage == 'corrupt':
        path.write_bytes(b'not a database')
    else:
        with closing(sqlite3.connect(path)) as db:
            if damage == 'wal': db.execute('PRAGMA journal_mode=WAL')
            else:
                if name == 'archive.sqlite':
                    db.execute('INSERT INTO message_content(message_id,data) VALUES(?,?)', ('missing-message', '{}'))
                else:
                    db.executescript('CREATE TABLE backup_test_parent(id INTEGER PRIMARY KEY);'
                                     'CREATE TABLE backup_test_child(parent_id REFERENCES backup_test_parent(id));'
                                     'INSERT INTO backup_test_child VALUES(999);')
                db.commit()
    manifest_for(snapshot)
    with pytest.raises((ValueError, sqlite3.Error)) as error:
        validate_snapshot(snapshot, 'fixture')
    if damage == 'foreign_key':
        assert 'Backup SQLite foreign key check failed' in str(error.value)


@pytest.mark.parametrize('kind', ['traversal', 'absolute', 'symlink', 'hardlink', 'fifo', 'duplicate', 'path_conflict'])
def test_unsafe_archive_members_rejected_even_with_valid_checksum(snapshot, kind):
    member = tarfile.TarInfo('unexpected')
    if kind == 'traversal': member.name = '../escape'
    elif kind == 'absolute': member.name = '/escape'
    elif kind == 'symlink': member.type = tarfile.SYMTYPE; member.linkname = '/escape'
    elif kind == 'hardlink': member.type = tarfile.LNKTYPE; member.linkname = SOURCE_FILES[0]
    elif kind == 'fifo': member.type = tarfile.FIFOTYPE
    elif kind == 'duplicate': member.name = SOURCE_FILES[0]
    else: member.name = 'sally_whatsapp'
    archive(snapshot/'source.tar.gz', SOURCE_FILES, extra=member)
    manifest_for(snapshot)
    with pytest.raises(ValueError): validate_snapshot(snapshot, 'fixture')


@pytest.mark.parametrize(('name', 'files'), [('private-runtime.tar.gz', RUNTIME_FILES[:-1]),
                                         ('source.tar.gz', SOURCE_FILES[:-1])])
def test_incomplete_archive_rejected_even_with_valid_checksum(snapshot, name, files):
    archive(snapshot/name, files)
    manifest_for(snapshot)
    with pytest.raises(ValueError, match='missing required files'):
        validate_snapshot(snapshot, 'fixture')


@pytest.mark.parametrize('data', [b'not a tar archive', b'\x1f\x8b\x08\x00'])
def test_invalid_or_truncated_archive_is_rejected(snapshot, data):
    (snapshot/'source.tar.gz').write_bytes(data)
    manifest_for(snapshot)
    with pytest.raises(ValueError, match='Invalid or truncated backup archive'):
        validate_snapshot(snapshot, 'fixture')


@pytest.mark.parametrize('damage', ['truncated_footer', 'bad_crc', 'trailing_garbage'])
def test_gzip_is_validated_past_tar_end_even_with_recomputed_checksum(snapshot, monkeypatch, damage):
    path = snapshot/'source.tar.gz'
    data = path.read_bytes()
    if damage == 'truncated_footer': data = data[:-4]
    elif damage == 'bad_crc': data = data[:-8] + bytes([data[-8] ^ 1]) + data[-7:]
    else: data += b'private-diagnostic-detail'
    path.write_bytes(data)
    manifest_for(snapshot)
    with pytest.raises(ValueError, match='Invalid or truncated backup archive'):
        validate_snapshot(snapshot, 'fixture')
    monkeypatch.setattr(release, 'BACKUPS', snapshot.parent)
    with pytest.raises(ReleaseError, match='Runtime backup validation failed') as error:
        release.verify_backups(receipt(snapshot), ['fixture'])
    assert 'private-diagnostic-detail' not in str(error.value)


def test_duplicate_instance_receipt_cannot_count_as_complete_batch(snapshot, monkeypatch):
    monkeypatch.setattr(release, 'BACKUPS', snapshot.parent)
    with pytest.raises(ReleaseError, match='exactly one'):
        release.verify_backups(receipt(snapshot)+'\n'+receipt(snapshot), ['fixture'])


def test_batch_requires_all_expected_instances_and_unique_directories(snapshot, monkeypatch):
    monkeypatch.setattr(release, 'BACKUPS', snapshot.parent)
    with pytest.raises(ReleaseError, match='exactly one'):
        release.verify_backups(receipt(snapshot), ['fixture', 'second'])
    with pytest.raises(ReleaseError, match='reused'):
        release.verify_backups(receipt(snapshot)+'\n'+receipt(snapshot, user='second'), ['fixture', 'second'])


def test_backup_outside_root_or_symlinked_directory_is_rejected(snapshot, monkeypatch, tmp_path):
    monkeypatch.setattr(release, 'BACKUPS', tmp_path/'other')
    with pytest.raises(ReleaseError, match='Unexpected backup directory'):
        release.verify_backups(receipt(snapshot), ['fixture'])
    monkeypatch.setattr(release, 'BACKUPS', tmp_path)
    link = tmp_path/'linked'
    link.symlink_to(snapshot, target_is_directory=True)
    with pytest.raises(ReleaseError, match='Unexpected backup directory'):
        release.verify_backups(receipt(link), ['fixture'])
