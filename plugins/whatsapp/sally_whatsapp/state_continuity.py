"""Detect loss/replacement of technical state without touching the WA account.

The host-owned marker for a registered tenant belongs outside its data directory.
The default sibling marker also protects standalone use against loss of the DB
file, but cannot detect simultaneous loss of its whole directory. This is an
identity check, not a backup, content hash, or proof against restoring an old DB.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import uuid


STATE_KEY = 'private:technical_state_identity:v1'


class StateContinuityError(RuntimeError):
    def __init__(self):
        super().__init__('TECHNICAL_STATE_RECOVERY_REQUIRED: preserve state and sessions; administrative recovery required')


def _identity(value):
    if (not isinstance(value, dict) or set(value) != {'protocol', 'id', 'tenant'}
            or type(value['protocol']) is not int or value['protocol'] != 1
            or not isinstance(value['id'], str) or not re.fullmatch('[0-9a-f]{32}', value['id'])
            or not isinstance(value['tenant'], str) or not re.fullmatch('[0-9a-f]{64}', value['tenant'])):
        raise StateContinuityError()
    return value


def _database_identity(db):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='state'").fetchone():
        return None
    row = db.execute('SELECT value FROM state WHERE key=?', (STATE_KEY,)).fetchone()
    return _identity(json.loads(row[0])) if row else None


def _read_marker(path):
    try:
        if path.is_symlink() or path.stat().st_size > 1024:
            raise StateContinuityError()
        return _identity(json.loads(path.read_text(encoding='utf-8')))
    except (OSError, ValueError, TypeError):
        raise StateContinuityError() from None


def _write_marker(path, value):
    # No replacement: losing a race must never replace an established identity.
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.state-identity-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if _read_marker(path) != value:
                raise StateContinuityError() from None
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


class StateContinuity:
    def __init__(self, settings, *, allow_bootstrap):
        self.path = Path(settings.database)
        self.external = settings.state_identity_file is not None
        self.marker = (Path(settings.state_identity_file) if self.external
                       else self.path.with_name(self.path.name + '.identity.json'))
        context = [settings.owner_subject, settings.public_url, settings.session]
        self.tenant = hashlib.sha256(json.dumps(context, separators=(',', ':')).encode()).hexdigest()
        self.expected = None
        self.file_identity = None
        self.allow_bootstrap = allow_bootstrap
        self._opened = False
        if self.path.is_symlink() or (self.external and self.marker.resolve().is_relative_to(self.path.parent.resolve())):
            raise StateContinuityError()
        if self.marker.exists() or self.marker.is_symlink():
            self.expected = _read_marker(self.marker)
            if self.expected['tenant'] != self.tenant:
                raise StateContinuityError()
        elif self.external:
            raise StateContinuityError()
        if self.path.exists():
            self.file_identity = self._file_identity()
            try:
                with closing(sqlite3.connect(self.path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
                    if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                        raise StateContinuityError()
                    if not allow_bootstrap and not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='state'").fetchone():
                        raise StateContinuityError()
                    identity = _database_identity(db)
                    if identity != self.expected:
                        raise StateContinuityError()
            except (sqlite3.Error, OSError, ValueError, TypeError):
                raise StateContinuityError() from None
        elif self.expected is not None or not allow_bootstrap:
            raise StateContinuityError()

    def _file_identity(self):
        if self.path.is_symlink():
            raise StateContinuityError()
        info = self.path.stat()
        return info.st_dev, info.st_ino

    def connect(self, *, timeout=10):
        """Only the first explicit bootstrap may create a file; never a retry."""
        try:
            if self.file_identity is not None and self._file_identity() != self.file_identity:
                raise StateContinuityError()
            create = not self._opened and self.file_identity is None and self.allow_bootstrap
            self._opened = True
            db = sqlite3.connect(self.path.resolve().as_uri() + ('?mode=rwc' if create else '?mode=rw'), timeout=timeout, uri=True)
            identity = self._file_identity()
            if self.file_identity is not None and identity != self.file_identity:
                db.close()
                raise StateContinuityError()
            self.file_identity = identity
            return db
        except (sqlite3.Error, OSError):
            raise StateContinuityError() from None

    def validate(self, db):
        try:
            if _database_identity(db) != self.expected:
                raise StateContinuityError()
        except sqlite3.Error as error:
            code = getattr(error, 'sqlite_errorcode', None)
            if type(code) is int and code & 0xff in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise  # Preserve the runtime's bounded retry policy for locks.
            raise StateContinuityError() from None
        except (ValueError, TypeError):
            raise StateContinuityError() from None

    def enroll(self, store):
        """Normal bootstrap only; check and maintenance never call this method."""
        if self.expected is not None:
            with store.db():
                pass
            return
        if self.external:
            raise StateContinuityError()
        value = {'protocol': 1, 'id': uuid.uuid4().hex, 'tenant': self.tenant}
        with store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT INTO state(key,value) VALUES (?,?)', (STATE_KEY, json.dumps(value, sort_keys=True)))
        # A crash between the DB commit and marker creation deliberately requires
        # an administrator; it never licenses a fresh database or a blind retry.
        _write_marker(self.marker, value)
        self.expected = value


def register_external_identity(settings):
    """Explicit offline enrollment of an existing DB; no schema/recovery changes.

    The administrator must stop writers and assess the current DB beforehand.
    Existing identity is preserved when moving from a sibling to a host marker.
    """
    if settings.state_identity_file is None:
        raise ValueError('Configure state_identity_file outside the data directory first')
    path, marker = Path(settings.database), Path(settings.state_identity_file)
    if not path.is_file() or path.is_symlink() or marker.resolve().is_relative_to(path.parent.resolve()):
        raise StateContinuityError()
    context = [settings.owner_subject, settings.public_url, settings.session]
    tenant = hashlib.sha256(json.dumps(context, separators=(',', ':')).encode()).hexdigest()
    try:
        with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=rw', uri=True)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise StateContinuityError()
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='state'").fetchone():
                raise StateContinuityError()
            value = _database_identity(db) or {'protocol': 1, 'id': uuid.uuid4().hex, 'tenant': tenant}
            if value['tenant'] != tenant:
                raise StateContinuityError()
            if marker.exists() and _read_marker(marker) != value:
                raise StateContinuityError()
            db.execute('INSERT OR IGNORE INTO state(key,value) VALUES (?,?)', (STATE_KEY, json.dumps(value, sort_keys=True)))
        _write_marker(marker, value)
    except (sqlite3.Error, OSError, ValueError, TypeError):
        raise StateContinuityError() from None
