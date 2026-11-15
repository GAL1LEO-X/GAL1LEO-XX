"""Local, transactional schema changes with consistent private SQLite backups.

Rollback is an explicit maintenance operation with the application stopped. It
keeps the base tables, including samples received after the upgrade; it never
copies an older database over newer observations. No migration invents evidence
for samples that predate schema 3.
"""
from contextlib import closing
import os
from pathlib import Path
import secrets
import sqlite3
import stat


SCHEMA_VERSION = 3
PREVIOUS_VERSIONS = (1, 2)
TEMPORARY_COLLECTION_TERMINAL = frozenset({
    "restored_verified", "superseded", "cancelled", "start_rejected",
})


def _path(path):
    path = Path(path).absolute()
    if path.is_symlink():
        raise ValueError("Database symlinks are not allowed")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("Database permissions must be private")
    return path


def _connect(path, *, readonly=False):
    return sqlite3.connect(path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"),
                           uri=True, timeout=10, isolation_level=None)


def _validate(db, owner, allowed_versions, allow_empty):
    objects = db.execute("SELECT name FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").fetchall()
    if not objects and allow_empty:
        return None
    if not any(row[0] == "meta" for row in objects):
        raise ValueError("Unsupported database schema")
    try:
        versions = db.execute("SELECT value FROM meta WHERE key='schema'").fetchall()
        owners = db.execute("SELECT value FROM meta WHERE key='owner'").fetchall()
    except sqlite3.DatabaseError:
        raise ValueError("Invalid database metadata") from None
    if len(versions) != 1 or versions[0][0] not in tuple(str(v) for v in allowed_versions):
        raise ValueError("Unsupported database schema")
    if len(owners) != 1 or owners[0][0] != owner:
        raise ValueError("Database belongs to a different owner")
    return int(versions[0][0])


def validate_database(path, owner, *, allowed_versions=(SCHEMA_VERSION,), allow_empty=False):
    """Check metadata read-only, before a caller enables WAL or writes anything."""
    path = _path(path)
    with closing(_connect(path, readonly=True)) as db:
        return _validate(db, owner, allowed_versions, allow_empty)


def _backup(path, owner, version, purpose):
    """Caller holds BEGIN IMMEDIATE, so no writer can change the source snapshot."""
    destination = path.with_name(path.name + "." + purpose + "." + secrets.token_hex(8) + ".sqlite3")
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        # A second source connection is necessary: backup() on the connection
        # holding the write transaction waits for that same transaction forever.
        with closing(_connect(path, readonly=True)) as source, closing(_connect(destination)) as target:
            source.backup(target)
            # Make the delivered backup self-contained even when the source's
            # newest committed pages exist only in its WAL.
            target.execute("PRAGMA journal_mode=DELETE")
            if target.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise ValueError("Database backup integrity check failed")
            _validate(target, owner, (version,), False)
        with destination.open("rb") as saved:
            os.fsync(saved.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        # A partial or unvalidated backup must never look like a recovery copy.
        destination.unlink(missing_ok=True)
        raise
    return destination


def _execute_schema(db, schema_sql):
    # executescript() commits an outstanding transaction. Execute each complete
    # statement instead so DDL and the version marker roll back together.
    statement = ""
    for character in schema_sql:
        statement += character
        if character == ";" and sqlite3.complete_statement(statement):
            db.execute(statement)
            statement = ""
    if statement.strip():
        db.execute(statement)


def initialize_database(path, owner, schema_sql):
    """Initialize an empty file or migrate 1/2 to 3; return the pre-upgrade backup.

    A schema-3 restart returns None. Future or malformed schemas and a different
    owner are rejected before opening a writable connection.
    """
    path = _path(path)
    allowed = (*PREVIOUS_VERSIONS, SCHEMA_VERSION)
    validate_database(path, owner, allowed_versions=allowed, allow_empty=True)
    backup = None
    with closing(_connect(path)) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        try:
            db.execute("BEGIN IMMEDIATE")
            version = _validate(db, owner, allowed, True)
            if version in PREVIOUS_VERSIONS:
                backup = _backup(path, owner, version, "pre-schema-3")
            _execute_schema(db, schema_sql)
            db.execute("INSERT OR REPLACE INTO meta VALUES('schema',?)", (str(SCHEMA_VERSION),))
            db.execute("INSERT OR IGNORE INTO meta VALUES('owner',?)", (owner,))
            db.execute("INSERT OR IGNORE INTO meta VALUES('connection_generation','0')")
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return backup


def _rollback_allowed(db):
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='temporary_collections'").fetchone():
        statuses = db.execute("SELECT DISTINCT status FROM temporary_collections").fetchall()
        if any(row[0] not in TEMPORARY_COLLECTION_TERMINAL for row in statuses):
            raise ValueError("Resolve temporary collection recovery before schema rollback")


def rollback_schema(path, owner, target_version=2):
    """Explicitly remove schema-3 additions, after backup, retaining base rows.

    Stop all application workers first. Pending or uncertain temporary collection
    recovery prevents rollback; removing its durable state could abandon a
    provider configuration. This function does not restore a backup or contact
    the provider.
    """
    if type(target_version) is not int or target_version != 2:
        raise ValueError("Only explicit schema 3 to 2 rollback is supported")
    path = _path(path)
    validate_database(path, owner)
    with closing(_connect(path)) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        try:
            db.execute("BEGIN IMMEDIATE")
            _validate(db, owner, (SCHEMA_VERSION,), False)
            _rollback_allowed(db)
            backup = _backup(path, owner, SCHEMA_VERSION, "pre-rollback-2")
            db.execute("DROP TABLE IF EXISTS latest_provenance")
            db.execute("DROP TABLE IF EXISTS sample_provenance")
            db.execute("DROP INDEX IF EXISTS temporary_collection_work")
            db.execute("DROP TABLE IF EXISTS temporary_collections")
            db.execute("UPDATE meta SET value='2' WHERE key='schema'")
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return backup
