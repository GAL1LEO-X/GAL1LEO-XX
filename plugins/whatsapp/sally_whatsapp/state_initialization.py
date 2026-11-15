"""Explicit first installation only; never repair or adopt existing state."""
from contextlib import closing
from dataclasses import replace
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile

from .state_continuity import StateContinuity, StateContinuityError, register_external_identity
from .store import Store


def _administrative_directory(path):
    info = path.stat()
    return info.st_uid == 0 and not info.st_mode & 0o022


def _new_paths(settings):
    if settings.state_identity_file is None:
        raise StateContinuityError()
    database, marker = Path(settings.database), Path(settings.state_identity_file)
    for path in (database, marker):
        # Provisioning has already prepared these directories and their owners.
        # Do not follow an alias into another tenant or create missing parents.
        if (not path.is_absolute() or not path.parent.is_dir()
                or any(parent.is_symlink() for parent in (path.parent, *path.parents))):
            raise StateContinuityError()
    if marker.resolve().is_relative_to(database.parent.resolve()):
        raise StateContinuityError()
    if not _administrative_directory(marker.parent):
        raise StateContinuityError()
    reserved = (database, marker, database.with_name(database.name + '.identity.json'),
                *(database.with_name(database.name + suffix) for suffix in ('-wal', '-shm', '-journal')))
    if any(path.exists() or path.is_symlink() for path in reserved):
        raise StateContinuityError()
    return database, marker


def initialize_new(settings, uid, gid):
    """Create schema and host identity after exclusively creating a new config.

    Existing config callers must only validate StateContinuity. A partial
    failure deliberately preserves its files and requires explicit recovery;
    retrying must never create a different identity or erase technical state.
    """
    database, marker = _new_paths(settings)
    try:
        descriptor = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise StateContinuityError() from None
    try:
        initial = os.fstat(descriptor)
        # SQLite must never write as root through the service-owned data path.
        # Build privately, then copy through the already-reserved descriptor;
        # this works when /etc and /var reside on different filesystems too.
        with tempfile.TemporaryDirectory(prefix='.initial-state-', dir=marker.parent) as staging:
            staged = Path(staging)/database.name
            Store(staged)
            if marker.exists() or marker.is_symlink():
                raise StateContinuityError()
            register_external_identity(replace(settings, database=staged))
            with closing(sqlite3.connect(staged.as_uri()+'?mode=rw', uri=True)) as db:
                if db.execute('PRAGMA journal_mode=DELETE').fetchone() != ('delete',):
                    raise StateContinuityError()
            StateContinuity(replace(settings, database=staged), allow_bootstrap=False)
            # DELETE provides one complete snapshot and prevents the final
            # artifact from carrying root-owned WAL/SHM sidecars. Validate
            # only in this protected directory: even a read-only SQLite open
            # can create sidecars after the bridge changes the journal mode.
            # The bridge's normal Store opening enables WAL under its own UID.
            with staged.open('rb') as source, os.fdopen(os.dup(descriptor), 'wb') as target:
                shutil.copyfileobj(source, target, length=64*1024)
                target.flush()
        current = database.stat(follow_symlinks=False)
        if (initial.st_dev, initial.st_ino) != (current.st_dev, current.st_ino):
            raise StateContinuityError()
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o600)
        os.chown(marker, 0, gid, follow_symlinks=False)
        os.chmod(marker, 0o640, follow_symlinks=False)
        os.fsync(descriptor)
        current = database.stat(follow_symlinks=False)
        if (initial.st_dev, initial.st_ino) != (current.st_dev, current.st_ino):
            raise StateContinuityError()
        directory = os.open(database.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(descriptor)
