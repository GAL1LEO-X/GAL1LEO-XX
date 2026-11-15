"""Synthetic qualification of schema upgrades and explicit compatible rollback."""
from contextlib import closing
import sqlite3

import pytest

from tesla_plugin import schema_migrations as migrations


OWNER = "synthetic-owner"
BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS samples (id TEXT PRIMARY KEY, vehicle TEXT NOT NULL,
 field TEXT NOT NULL, value TEXT, source_at REAL NOT NULL, received REAL NOT NULL,
 quality TEXT NOT NULL, time_basis TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS latest (vehicle TEXT NOT NULL, field TEXT NOT NULL,
 value TEXT, source_at REAL NOT NULL, received REAL NOT NULL, quality TEXT NOT NULL,
 time_basis TEXT NOT NULL, PRIMARY KEY(vehicle,field));
"""
NEW_SCHEMA = BASE_SCHEMA + """
CREATE TABLE IF NOT EXISTS sample_provenance (sample_id TEXT PRIMARY KEY,
 reason TEXT NOT NULL, FOREIGN KEY(sample_id) REFERENCES samples(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS latest_provenance (vehicle TEXT NOT NULL, field TEXT NOT NULL,
 reason TEXT NOT NULL, PRIMARY KEY(vehicle,field),
 FOREIGN KEY(vehicle,field) REFERENCES latest(vehicle,field) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS temporary_collections (id TEXT PRIMARY KEY, status TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS temporary_collection_work ON temporary_collections(status);
"""
SAMPLE = ("sample-old", "vehicle-synthetic", "BatteryLevel", "42", 100.0, 110.0,
          "valid", "payload_created_at")


def empty_file(tmp_path):
    path = tmp_path / "state.sqlite3"
    path.touch(mode=0o600)
    return path


def legacy(tmp_path, version=2, *, owner=OWNER):
    path = empty_file(tmp_path)
    with closing(sqlite3.connect(path)) as db:
        db.executescript(BASE_SCHEMA)
        db.execute("INSERT INTO meta VALUES('schema',?)", (str(version),))
        db.execute("INSERT INTO meta VALUES('owner',?)", (owner,))
        db.execute("INSERT INTO meta VALUES('connection_generation','7')")
        db.execute("INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)", SAMPLE)
        db.execute("INSERT INTO latest VALUES(?,?,?,?,?,?,?)", SAMPLE[1:])
        db.commit()
    return path


def query(path, sql, args=()):
    with closing(sqlite3.connect(path)) as db:
        return db.execute(sql, args).fetchall()


def test_fresh_initialization_and_restart_need_no_backup(tmp_path):
    path = empty_file(tmp_path)
    assert migrations.initialize_database(path, OWNER, NEW_SCHEMA) is None
    assert migrations.validate_database(path, OWNER) == 3
    assert migrations.initialize_database(path, OWNER, NEW_SCHEMA) is None
    assert query(path, "SELECT value FROM meta WHERE key='connection_generation'") == [("0",)]
    assert list(tmp_path.glob("*.pre-*.sqlite3")) == []


@pytest.mark.parametrize("version", (1, 2))
def test_upgrade_preserves_legacy_rows_without_invented_provenance(tmp_path, version):
    path = legacy(tmp_path, version)
    backup = migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    assert backup != path and backup.is_file()
    assert backup.stat().st_mode & 0o777 == 0o600
    assert migrations.validate_database(backup, OWNER, allowed_versions=(version,)) == version
    assert query(backup, "PRAGMA integrity_check") == [("ok",)]
    assert query(backup, "SELECT * FROM samples") == [SAMPLE]
    assert query(backup, "SELECT name FROM sqlite_master WHERE name='sample_provenance'") == []
    assert query(path, "SELECT * FROM samples") == [SAMPLE]
    assert query(path, "SELECT * FROM latest") == [SAMPLE[1:]]
    assert query(path, "SELECT * FROM sample_provenance") == []
    assert query(path, "SELECT * FROM latest_provenance") == []
    assert query(path, "SELECT value FROM meta WHERE key='connection_generation'") == [("7",)]


def test_backup_includes_committed_wal_and_is_self_contained(tmp_path):
    path = legacy(tmp_path)
    with closing(sqlite3.connect(path)) as writer:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        writer.execute("PRAGMA wal_autocheckpoint=0")
        wal_sample = ("wal-only", *SAMPLE[1:])
        writer.execute("INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)", wal_sample)
        writer.commit()
        assert path.with_name(path.name + "-wal").stat().st_size > 0
        backup = migrations.initialize_database(path, OWNER, NEW_SCHEMA)
        assert query(backup, "SELECT * FROM samples WHERE id='wal-only'") == [wal_sample]
        assert query(backup, "PRAGMA journal_mode") == [("delete",)]
        assert not backup.with_name(backup.name + "-wal").exists()
        assert query(backup, "PRAGMA integrity_check") == [("ok",)]


@pytest.mark.parametrize("version", (0, 4, 99, "future", "03"))
def test_future_or_malformed_schema_rejected_before_writable_open(tmp_path, monkeypatch, version):
    path = legacy(tmp_path, version)
    before = path.read_bytes()
    opened = []
    original = migrations._connect

    def observed(path, *, readonly=False):
        opened.append(readonly)
        return original(path, readonly=readonly)

    monkeypatch.setattr(migrations, "_connect", observed)
    with pytest.raises(ValueError, match="Unsupported database schema"):
        migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    assert opened == [True]
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_owner_mismatch_rejected_without_writes_or_backup(tmp_path, monkeypatch):
    path = legacy(tmp_path)
    before = path.read_bytes()
    original = migrations._connect

    def readonly_only(path, *, readonly=False):
        assert readonly
        return original(path, readonly=readonly)

    monkeypatch.setattr(migrations, "_connect", readonly_only)
    with pytest.raises(ValueError, match="different owner"):
        migrations.initialize_database(path, "different-owner", NEW_SCHEMA)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_metadata_is_rechecked_under_writer_lock(tmp_path, monkeypatch):
    path = legacy(tmp_path)
    original = migrations._connect

    def changed_after_preflight(path, *, readonly=False):
        if not readonly:
            with closing(sqlite3.connect(path)) as competitor:
                competitor.execute("UPDATE meta SET value='4' WHERE key='schema'")
                competitor.commit()
        return original(path, readonly=readonly)

    monkeypatch.setattr(migrations, "_connect", changed_after_preflight)
    with pytest.raises(ValueError, match="Unsupported database schema"):
        migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    assert query(path, "SELECT value FROM meta WHERE key='schema'") == [("4",)]
    assert query(path, "SELECT name FROM sqlite_master WHERE name='sample_provenance'") == []
    assert list(tmp_path.glob("*.pre-schema-3.*.sqlite3")) == []


@pytest.mark.parametrize("missing_key", ("schema", "owner"))
def test_existing_metadata_must_be_complete(tmp_path, missing_key):
    path = legacy(tmp_path)
    with closing(sqlite3.connect(path)) as db:
        db.execute("DELETE FROM meta WHERE key=?", (missing_key,))
        db.commit()
    before = path.read_bytes()
    with pytest.raises(ValueError):
        migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    assert path.read_bytes() == before


def test_unversioned_nonempty_database_is_not_adopted(tmp_path):
    path = empty_file(tmp_path)
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE unrelated (id INTEGER)")
        db.commit()
    with pytest.raises(ValueError, match="Unsupported database schema"):
        migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    assert query(path, "SELECT name FROM sqlite_master WHERE type='table'") == [("unrelated",)]


def test_failed_ddl_is_atomic_and_keeps_valid_preupgrade_backup(tmp_path):
    path = legacy(tmp_path)
    with pytest.raises(sqlite3.OperationalError):
        migrations.initialize_database(path, OWNER, NEW_SCHEMA + "CREATE TABLE broken syntax;")
    assert migrations.validate_database(path, OWNER, allowed_versions=(2,)) == 2
    assert query(path, "SELECT name FROM sqlite_master WHERE name='sample_provenance'") == []
    assert query(path, "SELECT * FROM samples") == [SAMPLE]
    backups = list(tmp_path.glob("*.pre-schema-3.*.sqlite3"))
    assert len(backups) == 1
    assert query(backups[0], "PRAGMA integrity_check") == [("ok",)]
    assert query(backups[0], "SELECT * FROM samples") == [SAMPLE]


def test_failed_backup_prevents_schema_changes(tmp_path, monkeypatch):
    path = legacy(tmp_path)

    def unavailable(*args):
        raise OSError("synthetic backup failure")

    monkeypatch.setattr(migrations, "_backup", unavailable)
    with pytest.raises(OSError, match="synthetic backup failure"):
        migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    assert migrations.validate_database(path, OWNER, allowed_versions=(2,)) == 2
    assert query(path, "SELECT name FROM sqlite_master WHERE name='sample_provenance'") == []


def test_explicit_rollback_preserves_new_samples_and_backs_up_evidence(tmp_path):
    path = legacy(tmp_path)
    migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    new_sample = ("after-upgrade", "vehicle-synthetic", "BatteryLevel", "43", 120.0, 130.0,
                  "valid", "payload_created_at")
    with closing(sqlite3.connect(path)) as db:
        db.execute("INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)", new_sample)
        db.execute("INSERT INTO sample_provenance VALUES('after-upgrade','validated')")
        db.execute("INSERT INTO temporary_collections VALUES('finished','restored_verified')")
        db.commit()
    backup = migrations.rollback_schema(path, OWNER)
    assert migrations.validate_database(path, OWNER, allowed_versions=(2,)) == 2
    assert query(path, "SELECT * FROM samples ORDER BY source_at") == [SAMPLE, new_sample]
    assert query(path, "SELECT name FROM sqlite_master WHERE name IN ('sample_provenance','latest_provenance','temporary_collections','temporary_collection_work')") == []
    assert migrations.validate_database(backup, OWNER) == 3
    assert query(backup, "SELECT * FROM sample_provenance") == [("after-upgrade", "validated")]
    assert query(backup, "SELECT * FROM samples ORDER BY source_at") == [SAMPLE, new_sample]
    migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    assert query(path, "SELECT * FROM samples ORDER BY source_at") == [SAMPLE, new_sample]
    assert query(path, "SELECT * FROM sample_provenance") == []


def test_failed_rollback_restores_tables_and_version_atomically(tmp_path):
    path = legacy(tmp_path)
    migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    with closing(sqlite3.connect(path)) as db:
        db.execute("INSERT INTO sample_provenance VALUES('sample-old','synthetic-evidence')")
        db.execute("CREATE TRIGGER refuse_version_update BEFORE UPDATE ON meta "
                   "BEGIN SELECT RAISE(ABORT, 'synthetic rollback fault'); END;")
        db.commit()
    with pytest.raises(sqlite3.IntegrityError, match="synthetic rollback fault"):
        migrations.rollback_schema(path, OWNER)
    assert migrations.validate_database(path, OWNER) == 3
    assert query(path, "SELECT * FROM sample_provenance") == [("sample-old", "synthetic-evidence")]
    assert query(path, "SELECT name FROM sqlite_master WHERE name='temporary_collections'") == [("temporary_collections",)]
    assert query(path, "SELECT * FROM samples") == [SAMPLE]
    backups = list(tmp_path.glob("*.pre-rollback-2.*.sqlite3"))
    assert len(backups) == 1
    assert migrations.validate_database(backups[0], OWNER) == 3
    assert query(backups[0], "PRAGMA integrity_check") == [("ok",)]


@pytest.mark.parametrize("status", ("prepared", "active", "start_unknown", "restore_pending",
    "restore_accepted", "restore_unknown", "blocked", "restore_rejected", "unknown_future_status"))
def test_rollback_refuses_unresolved_temporary_collection_before_backup(tmp_path, status):
    path = empty_file(tmp_path)
    migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    with closing(sqlite3.connect(path)) as db:
        db.execute("INSERT INTO temporary_collections VALUES('unresolved',?)", (status,))
        db.commit()
    before = path.read_bytes()
    with pytest.raises(ValueError, match="temporary collection recovery"):
        migrations.rollback_schema(path, OWNER)
    assert path.read_bytes() == before
    assert list(tmp_path.glob("*.pre-rollback-2.*.sqlite3")) == []


@pytest.mark.parametrize("status", sorted(migrations.TEMPORARY_COLLECTION_TERMINAL))
def test_rollback_allows_terminal_temporary_collection(tmp_path, status):
    path = empty_file(tmp_path)
    migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    with closing(sqlite3.connect(path)) as db:
        db.execute("INSERT INTO temporary_collections VALUES('finished',?)", (status,))
        db.commit()
    assert migrations.rollback_schema(path, OWNER).is_file()


@pytest.mark.parametrize("target", (1, 3, 4, "2", True))
def test_rollback_rejects_unsupported_target_before_writes(tmp_path, target):
    path = empty_file(tmp_path)
    migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    before = path.read_bytes()
    with pytest.raises(ValueError, match="Only explicit"):
        migrations.rollback_schema(path, OWNER, target)
    assert path.read_bytes() == before


def test_rollback_rejects_other_owner_and_future_version(tmp_path):
    path = empty_file(tmp_path)
    migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    with pytest.raises(ValueError, match="different owner"):
        migrations.rollback_schema(path, "different-owner")
    with closing(sqlite3.connect(path)) as db:
        db.execute("UPDATE meta SET value='4' WHERE key='schema'")
        db.commit()
    before = path.read_bytes()
    with pytest.raises(ValueError, match="Unsupported database schema"):
        migrations.rollback_schema(path, OWNER)
    assert path.read_bytes() == before
    assert list(tmp_path.glob("*.pre-rollback-2.*.sqlite3")) == []


def test_validation_rejects_symlinks_and_public_files(tmp_path):
    path = empty_file(tmp_path)
    migrations.initialize_database(path, OWNER, NEW_SCHEMA)
    symlink = tmp_path / "alias.sqlite3"
    symlink.symlink_to(path)
    with pytest.raises(ValueError, match="symlinks"):
        migrations.validate_database(symlink, OWNER)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="permissions"):
        migrations.validate_database(path, OWNER)
