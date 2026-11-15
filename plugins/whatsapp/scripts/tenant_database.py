"""Administrative SQLite work with the selected tenant's Unix privileges.

The parent reads only protected configuration/identity metadata. SQLite runs
in an isolated child with no supplementary groups. Snapshot bytes cross an
inherited write-only descriptor into an exclusively created administrative destination; the
tenant never gets access to the backup directory. No recovery or enrollment
is performed when files or identities are missing.
"""
from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from types import SimpleNamespace

KEY = 'private:technical_state_identity:v1'
# Filesystem/UID fixture seams only; never accepted from CLI or a request.
_TRUST_ROOT = Path('/')
_TRUST_UID = 0


def require(condition):
    if not condition:
        raise RuntimeError('Tenant database identity or filesystem safety check failed')


def identity(value):
    require(isinstance(value, dict) and set(value) == {'protocol', 'id', 'tenant'}
            and type(value['protocol']) is int and value['protocol'] == 1
            and isinstance(value['id'], str) and re.fullmatch('[0-9a-f]{32}', value['id'])
            and isinstance(value['tenant'], str) and re.fullmatch('[0-9a-f]{64}', value['tenant']))
    return value


@contextmanager
def physical_directory(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        yield fd
    finally:
        os.close(fd)


@contextmanager
def physical_file(path, *, writable=False, protected=False):
    """Pin every directory and reject symlinks, including replaced ancestors."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts)
    root = _TRUST_ROOT if protected else Path('/')
    relative = path.relative_to(root)
    # These descriptors anchor openat/fstat, not directory reads. Traversal
    # permission suffices; O_RDONLY would also require listing every ancestor.
    descriptor = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            if protected:
                info = os.fstat(descriptor)
                require(info.st_uid == _TRUST_UID and not info.st_mode & 0o022)
            child = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        if protected:
            info = os.fstat(descriptor)
            require(info.st_uid == _TRUST_UID and not info.st_mode & 0o022)
        fd = os.open(relative.name, (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=descriptor)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            if protected:
                require(info.st_uid == _TRUST_UID and not info.st_mode & 0o022)
            yield fd
        finally:
            os.close(fd)
    finally:
        os.close(descriptor)


def protected_bytes(path, maximum):
    with physical_file(path, protected=True) as fd:
        require(os.fstat(fd).st_size <= maximum)
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(maximum + 1)
        require(len(data) <= maximum)
        return data


def tenant_context(instance):
    configuration = Path(instance.config_dir)/'config.toml'
    config = tomllib.loads(protected_bytes(configuration, 131072).decode())['bridge']
    database = Path(instance.state_dir)/'archive.sqlite'
    require(config['database'] == str(database) and config['owner_subject'] == instance.subject
            and config['public_url'] == instance.public_url)
    marker = Path(config.get('state_identity_file', str(configuration.parent/'technical-state.json')))
    require(not marker.is_relative_to(database.parent))
    expected = identity(json.loads(protected_bytes(marker, 1024)))
    tenant = hashlib.sha256(json.dumps([instance.subject, instance.public_url, config.get('session', 'default')],
                                     separators=(',', ':')).encode()).hexdigest()
    require(expected['tenant'] == tenant)
    account = pwd.getpwnam(instance.service_user)
    require(account.pw_uid > 0 and account.pw_gid > 0)
    with physical_file(database) as fd:
        info = os.fstat(fd)
        require(info.st_uid == account.pw_uid and not info.st_mode & 0o022)
        inode = [info.st_dev, info.st_ino]
    return {'database': str(database), 'expected': expected, 'uid': account.pw_uid,
            'gid': account.pw_gid, 'inode': inode,
            'groups': [] if os.geteuid() == 0 else os.getgroups()}


def run_database(instance, action, *, target=None, lock_fd=None):
    require(action in ('verify', 'idle', 'suspend', 'snapshot'))
    context = tenant_context(instance)
    require((target is not None) == (action == 'snapshot'))
    # Popen switches credentials before exec. Isolated Python ignores ambient
    # PYTHONPATH/user packages; this worker imports only the standard library.
    options = {'cwd': '/', 'env': {}, 'input': Path(__file__).read_bytes(), 'stderr': subprocess.DEVNULL,
               'check': True, 'timeout': 120, 'close_fds': True}
    if os.geteuid() == 0:
        options.update(user=context['uid'], group=context['gid'], extra_groups=[])
    else:
        require(os.geteuid() == context['uid'] and os.getegid() == context['gid'])
        # An unprivileged caller can only operate under its existing identity;
        # this supports isolated test runners without adding Unix privileges.
        require(context['groups'] == os.getgroups())
    if lock_fd is not None:
        options['pass_fds'] = (lock_fd,)
    # Administrative generations may have root-only traversal parents. Feed
    # the already trusted worker source through stdin before dropping UID;
    # never require the tenant to import or reopen administrative code paths.
    command = [sys.executable, '-I', '-B', '-', action,
               json.dumps(context, separators=(',', ':'))]
    if target is None:
        subprocess.run(command, stdout=subprocess.DEVNULL, **options)
        return
    target = Path(target)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            subprocess.run(command, stdout=output, **options)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def verify_tenant_database(instance):
    run_database(instance, 'verify')


def suspend_tenant_database(instance):
    run_database(instance, 'suspend')


def snapshot_tenant_database(instance, target, *, lock_fd=None):
    run_database(instance, 'snapshot', target=target, lock_fd=lock_fd)


def registered_tenant(configuration, database, service_user):
    """Adapt a release row after its installation-bound DB path was checked."""
    config = tomllib.loads(protected_bytes(configuration,131072).decode())['bridge']
    return SimpleNamespace(config_dir=Path(configuration).parent,state_dir=Path(database).parent,
                           service_user=service_user,subject=config['owner_subject'],public_url=config['public_url'])


def unchanged(path, expected, uid):
    with physical_file(path) as fd:
        info = os.fstat(fd)
        require([info.st_dev, info.st_ino] == expected and info.st_uid == uid
                and not info.st_mode & 0o022)


def database_identity(db, expected):
    row = db.execute('SELECT value FROM state WHERE key=?', (KEY,)).fetchone()
    require(row is not None and identity(json.loads(row[0])) == expected)


def perform(context, action, output):
    require(os.geteuid() == context['uid'] and os.geteuid() != 0
            and os.getegid() == context['gid'] and set(os.getgroups()) == set(context['groups']))
    require(action in ('verify', 'idle', 'suspend', 'snapshot'))
    expected = identity(context['expected'])
    path = Path(context['database'])
    with physical_file(path) as pinned:
        info = os.fstat(pinned)
        require([info.st_dev, info.st_ino] == context['inode'] and info.st_uid == context['uid'])
        unchanged(path, context['inode'], context['uid'])
        mode = 'rw' if action == 'suspend' else 'ro'
        with closing(sqlite3.connect(path.as_uri()+'?mode='+mode, uri=True, timeout=10)) as db:
            db.execute('PRAGMA trusted_schema=OFF')
            deadline = time.monotonic()+90
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
            unchanged(path, context['inode'], context['uid'])
            with db:
                db.execute('BEGIN IMMEDIATE' if action == 'suspend' else 'BEGIN')
                database_identity(db, expected)
                require(db.execute('PRAGMA quick_check').fetchall() == [('ok',)])
                if action == 'idle':
                    count = db.execute("SELECT COUNT(*) FROM sends WHERE state='sending'").fetchone()[0]
                    count += db.execute("SELECT COUNT(*) FROM media_jobs WHERE state='downloading'").fetchone()[0]
                    count += db.execute("SELECT COUNT(*) FROM history_jobs WHERE state='running'").fetchone()[0]
                    count += db.execute('SELECT COUNT(*) FROM deliveries WHERE lease_until > ?', (time.time(),)).fetchone()[0]
                    require(count == 0)
                elif action == 'suspend':
                    db.execute('DELETE FROM link_sessions')
                    db.execute('DELETE FROM link_login_states')
                    db.execute('UPDATE subscriptions SET active=0')
                    db.execute("UPDATE deliveries SET state='cancelled' WHERE state IN ('collecting','pending','sending')")
                    db.execute("UPDATE sends SET state='failed_before_send' WHERE state='queued'")
                    db.execute("UPDATE history_jobs SET state='cancelled',updated=? WHERE state IN ('running','paused','failed')", (time.time(),))
                    db.execute("UPDATE media_jobs SET state='cancelled',source=X'',error='Cancelled by account suspension' WHERE state IN ('queued','downloading')")
                elif action == 'snapshot':
                    # Spool on disk under this UID, never serialize a large DB
                    # in memory or reopen the administrative output as root.
                    with tempfile.TemporaryDirectory(prefix='whatsapp-db-') as directory:
                        snapshot = Path(directory)/'archive.sqlite'
                        with closing(sqlite3.connect(snapshot)) as destination:
                            db.backup(destination)
                            require(destination.execute('PRAGMA integrity_check').fetchall() == [('ok',)])
                            database_identity(destination, expected)
                            destination.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                            require(destination.execute('PRAGMA journal_mode=DELETE').fetchone() == ('delete',))
                        unchanged(path, context['inode'], context['uid'])
                        with snapshot.open('rb') as stream:
                            shutil.copyfileobj(stream, output, length=1024*1024)
                unchanged(path, context['inode'], context['uid'])


if __name__ == '__main__':
    try:
        perform(json.loads(sys.argv[2]), sys.argv[1], sys.stdout.buffer)
    except BaseException:
        # The parent exposes only the failure stage, never SQLite or payload
        # diagnostics that could contain account data or paths from the DB.
        raise SystemExit(1) from None
