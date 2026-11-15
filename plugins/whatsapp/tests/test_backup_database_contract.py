"""Role-specific database contracts; no migrations or repairs of backup inputs."""
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import sys

import pytest

PLUGIN = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN/'scripts'))

from backup_validation import validate_database, validate_snapshot
from github_release_common import ReleaseError
import github_release as release
from sally_whatsapp.store import SCHEMA
from test_backup_validation import manifest_for, receipt, snapshot

def database(path, sql):
    if path.exists(): path.unlink()
    with closing(sqlite3.connect(path)) as db:
        db.executescript(sql or 'VACUUM;')


def files(directory):
    return {path.name: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
            for path in directory.iterdir()}


def test_shipped_archive_contracts_match_versioned_sources():
    resources = PLUGIN/'scripts/backup_schemas'
    assert (resources/'6.sql').read_bytes() == (PLUGIN/'tests/fixtures/schema6.sql').read_bytes()
    assert (resources/'8.sql').read_text() == SCHEMA


@pytest.mark.parametrize('version', [6, 7, 8, '6-to-7', '7-to-8', '6-to-8'])
def test_supported_empty_archives_and_migrated_schema_are_read_only(tmp_path, version):
    path = tmp_path/'archive.sqlite'
    schema6 = (PLUGIN/'tests/fixtures/schema6.sql').read_text()
    sql = SCHEMA if version == 8 else (PLUGIN/'scripts/backup_schemas/7.sql').read_text() if version in (7,'7-to-8') else schema6
    if version in ('6-to-7','6-to-8'): sql += (PLUGIN/'deploy/6-7.sql').read_text()
    if version in ('7-to-8','6-to-8'): sql += (PLUGIN/'deploy/7-8.sql').read_text()
    database(path, sql)
    before = files(tmp_path)
    validate_database(path, 'archive')
    assert files(tmp_path) == before
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1', uri=True)) as db:
        assert db.execute('SELECT COUNT(*) FROM messages').fetchone() == (0,)


@pytest.mark.parametrize('damage', [
    'archive_empty', 'auth_empty', 'swapped', 'archive_unrelated', 'auth_unrelated',
    'future_version', 'wrong_declared_version', 'missing_messages', 'archive_columns',
    'auth_columns', 'auth_view', 'auth_virtual', 'missing_index', 'changed_constraint',
])
def test_wrong_database_roles_or_schema_block_both_gates_without_writes(snapshot, monkeypatch, damage):
    archive = snapshot/'archive.sqlite'
    auth = snapshot/'shared-authelia.sqlite3'
    if damage in ('archive_empty', 'auth_empty'):
        database(archive if damage == 'archive_empty' else auth, '')
    elif damage == 'swapped':
        first, second = archive.read_bytes(), auth.read_bytes()
        archive.write_bytes(second); auth.write_bytes(first)
    elif damage in ('archive_unrelated', 'auth_unrelated'):
        database(archive if damage == 'archive_unrelated' else auth,
                 'CREATE TABLE unrelated(value TEXT);PRAGMA user_version=7;')
    elif damage.startswith('auth_'):
        sql = {
            'auth_columns': 'CREATE TABLE user_opaque_identifier(unrelated TEXT);',
            'auth_view': "CREATE VIEW user_opaque_identifier AS SELECT 'x' AS service,'' AS sector_id,'u' AS username,'s' AS identifier;",
            'auth_virtual': 'CREATE VIRTUAL TABLE user_opaque_identifier USING fts5(service,sector_id,username,identifier);',
        }[damage]
        database(auth, sql)
    else:
        sql = {
            'future_version': 'PRAGMA user_version=999;',
            'wrong_declared_version': 'PRAGMA user_version=6;',
            'missing_messages': 'DROP TABLE messages;',
            'archive_columns': 'DROP TABLE messages;CREATE TABLE messages(id TEXT PRIMARY KEY,unrelated TEXT);',
            'missing_index': 'DROP INDEX messages_chat_time;',
            'changed_constraint': 'DROP TABLE link_rate_limit;CREATE TABLE link_rate_limit(singleton INTEGER PRIMARY KEY CHECK(singleton=2),last_request REAL NOT NULL);',
        }[damage]
        with closing(sqlite3.connect(archive)) as db: db.executescript(sql)
    manifest_for(snapshot)
    before = files(snapshot)
    with pytest.raises(ValueError): validate_snapshot(snapshot, 'fixture')
    monkeypatch.setattr(release, 'BACKUPS', snapshot.parent)
    with pytest.raises(ReleaseError, match='Runtime backup validation failed'):
        release.verify_backups(receipt(snapshot), ['fixture'])
    assert files(snapshot) == before


def test_authelia_allows_extra_schema_and_has_no_archive_version_requirement(snapshot):
    with closing(sqlite3.connect(snapshot/'shared-authelia.sqlite3')) as db:
        db.executescript('ALTER TABLE user_opaque_identifier ADD COLUMN provider_extra TEXT;'
                         'CREATE TABLE provider_extra(value TEXT);PRAGMA user_version=999;')
    manifest_for(snapshot)
    before = files(snapshot)
    validate_snapshot(snapshot, 'fixture')
    assert files(snapshot) == before


def test_identity_mapping_is_outside_the_minimum_schema_contract(snapshot):
    with closing(sqlite3.connect(snapshot/'shared-authelia.sqlite3')) as db:
        db.execute('INSERT INTO user_opaque_identifier VALUES(?,?,?,?)',
                   ('openid', '', 'unrelated-synthetic-user', 'unrelated-synthetic-subject'))
        db.commit()
    manifest_for(snapshot)
    validate_snapshot(snapshot, 'fixture')


def test_unknown_role_is_rejected_without_opening_database(tmp_path):
    missing = tmp_path/'must-not-be-created.sqlite'
    with pytest.raises(ValueError, match='Unknown backup database role'):
        validate_database(missing, 'other')
    assert not missing.exists()
