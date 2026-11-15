"""Read-only validation shared by the release gate and isolated restore rehearsal.

This checks managed v3, external-OIDC v4, identity-bound v5 and allocation-bound v6 snapshots, not
operational recoverability or authenticity against a privileged attacker.
No archive is extracted and no service is touched.
"""
from contextlib import closing
from datetime import datetime
import gzip
import hashlib
import json
import sys as _installation_sys
from pathlib import Path as _InstallationPath
import types as _installation_types
if 'installation_layout' not in _installation_sys.modules:
    _installation_source=_InstallationPath(__file__).with_name('installation_layout.py')
    _installation_module=_installation_types.ModuleType('installation_layout')
    _installation_module.__file__=str(_installation_source)
    _installation_sys.modules['installation_layout']=_installation_module
    try:
        exec(compile(_installation_source.read_bytes(),str(_installation_source),'exec'),_installation_module.__dict__)
    except BaseException:
        _installation_sys.modules.pop('installation_layout',None)
        raise
if getattr(_installation_sys.modules['installation_layout'], 'FORMAT', None) != 'whatsapp-installation-v1':
    raise ImportError('The whatsapp entry point cannot reuse another product installation layout')
from installation_layout import (active as installation_profile, identity_record, Installation, IDENTITY, PROFILE,
                                 encoded as installation_encoded, roster_pointer_record)
from pathlib import Path, PurePosixPath
import re
import sqlite3
import tarfile
import zlib

from release_database import schema as database_schema

SNAPSHOT_FILES = frozenset({'archive.sqlite', 'shared-authelia.sqlite3',
                            'private-runtime.tar.gz', 'source.tar.gz'})
FORMAT = 'whatsapp-isolated-backup-v3'
EXTERNAL_FORMAT = 'whatsapp-isolated-backup-v4'
IDENTITY_FORMAT = 'whatsapp-isolated-backup-v5'
EXTERNAL_FILES = SNAPSHOT_FILES - {'shared-authelia.sqlite3'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate backup manifest field')
        result[key] = value
    return result


def validate_archive_database(db):
    version = db.execute('PRAGMA user_version').fetchone()[0]
    require(version in (6, 7, 8), 'Backup archive schema version is unsupported')
    # These are trusted resources shipped with this validator, never SQL or
    # Python read from source.tar.gz. Compare without migrating the snapshot.
    contract = Path(__file__).with_name('backup_schemas')/(str(version)+'.sql')
    with closing(sqlite3.connect(':memory:')) as expected:
        expected.executescript(contract.read_text())
        require(expected.execute('PRAGMA user_version').fetchone()[0] == version,
                'Installed backup schema contract version differs')
        require(database_schema(db) == database_schema(expected),
                'Backup archive database schema differs from its supported version')


def validate_authelia_database(db):
    tables = [row for row in db.execute('PRAGMA table_list')
              if row[0] == 'main' and row[1] == 'user_opaque_identifier']
    require(len(tables) == 1 and tables[0][2] == 'table',
            'Backup authentication identity table is missing or unsupported')
    columns = {row[1] for row in db.execute('PRAGMA table_info(user_opaque_identifier)')}
    require({'service', 'sector_id', 'username', 'identifier'} <= columns,
            'Backup authentication identity columns are missing')


def validate_database(path, role):
    require(role in ('archive', 'authelia'), 'Unknown backup database role')
    # WAL snapshots are not standalone. Refuse them before opening SQLite so
    # validation never creates a journal or accidentally depends on sidecars.
    with path.open('rb') as stream:
        header = stream.read(20)
    require(header[:16] == b'SQLite format 3\0' and header[18:20] == b'\x01\x01',
            'Backup must be a standalone SQLite database')
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1', uri=True)) as db:
        require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)],
                'Backup SQLite integrity check failed')
        require(not db.execute('PRAGMA foreign_key_check').fetchall(),
                'Backup SQLite foreign key check failed')
        if role == 'archive':
            validate_archive_database(db)
        else:
            validate_authelia_database(db)


def _validate_archive(path, required_files, capture_files=()):
    members = {}
    captured = {}
    required = {PurePosixPath(name) for name in required_files}
    capture = {PurePosixPath(name) for name in capture_files}
    with gzip.open(path, 'rb') as compressed:
        # GzipFile is seekable: keep its logical position at the tar terminator,
        # without the r| adapter buffering uninspected trailing payload.
        with tarfile.open(fileobj=compressed, mode='r:') as archive:
            for member in archive:
                name = PurePosixPath(member.name)
                require(not name.is_absolute() and '..' not in name.parts
                        and '\\' not in member.name and name.as_posix() == member.name.rstrip('/')
                        and str(name) != '.' and (member.isfile() or member.isdir()),
                        'Unsafe backup archive member')
                require(name not in members, 'Duplicate backup archive member')
                members[name] = member.isfile()
                if member.isfile():
                    require(name not in required or member.size > 0,
                            'Required backup archive member is empty')
                    # Consume data without holding attachments in memory or
                    # extracting their paths.
                    with archive.extractfile(member) as stream:
                        if name in capture:
                            require(member.size <= 131072, 'Installation snapshot member exceeds its bound')
                            captured[str(name)] = stream.read(member.size)
                            require(len(captured[str(name)]) == member.size, 'Truncated backup archive member')
                            continue
                        remaining = member.size
                        while chunk := stream.read(1024 * 1024):
                            remaining -= len(chunk)
                        require(remaining == 0, 'Truncated backup archive member')
        # Validate every gzip CRC/trailer and allow only zero tar padding after
        # the terminator. Concatenated gzip members remain compatible only when
        # their decompressed continuation is empty or consists solely of zeros.
        while chunk := compressed.read(1024 * 1024):
            require(not any(chunk), 'Non-padding data after backup tar end')
    require(all(members.get(name) is True for name in required),
            'Backup archive is missing required files')
    require(not any(members.get(parent) for name in members for parent in name.parents),
            'Backup archive path types conflict')
    return captured


def validate_archive(path, required_files, *, capture_files=()):
    try:
        return _validate_archive(path, required_files, capture_files)
    except (tarfile.TarError, EOFError, gzip.BadGzipFile, zlib.error):
        raise ValueError('Invalid or truncated backup archive') from None


def validate_snapshot(directory, user, *, runtime_prefix=Path('/'), auth_mode='managed-authelia'):
    """Validate one immutable snapshot before release or any restore writes.

    runtime_prefix maps host paths only for an isolated restore rehearsal; the
    release gate uses the real absolute layout (the default '/'). auth_mode is
    selected by the trusted instance registry, never inferred from this archive.
    """
    directory = Path(directory)
    require(auth_mode in ('managed-authelia', 'external-oidc'), 'Invalid expected backup authentication mode')
    external = auth_mode == 'external-oidc'
    snapshot_files = EXTERNAL_FILES if external else SNAPSHOT_FILES
    require(isinstance(user, str) and re.fullmatch(r'[a-z][a-z0-9-]{1,19}', user),
            'Invalid backup owner')
    require(directory.is_dir() and not directory.is_symlink(), 'Invalid backup directory')
    directory = directory.resolve()
    require({path.name for path in directory.iterdir()} == snapshot_files | {'manifest.json'},
            'Incomplete or unexpected snapshot inventory')
    for name in snapshot_files | {'manifest.json'}:
        path = directory/name
        require(path.is_file() and not path.is_symlink(), 'Missing or linked snapshot file')
    manifest = json.loads((directory/'manifest.json').read_text(), object_pairs_hook=unique_object)
    require(isinstance(manifest, dict), 'Invalid snapshot manifest fields')
    roster_bound = manifest.get('format') == 'whatsapp-isolated-backup-v6'
    identity_bound = manifest.get('format') == IDENTITY_FORMAT or roster_bound
    manifest_fields = {'format', 'user', 'created_utc', 'sqlite_integrity', 'includes_credentials', 'files'}
    if external or identity_bound: manifest_fields.add('auth_mode')
    if identity_bound: manifest_fields.add('installation')
    require(isinstance(manifest, dict) and set(manifest) == manifest_fields,
        'Invalid snapshot manifest fields')
    require(manifest['format'] == ('whatsapp-isolated-backup-v6' if roster_bound else IDENTITY_FORMAT if identity_bound else EXTERNAL_FORMAT if external else FORMAT)
            and manifest['user'] == user
            and (not (external or identity_bound) or manifest['auth_mode'] == auth_mode),
            'Snapshot identity or format differs')
    require(manifest['sqlite_integrity'] == 'ok' and manifest['includes_credentials'] is True,
            'Snapshot completeness was not established')
    timestamp = manifest['created_utc']
    require(isinstance(timestamp, str) and re.fullmatch(r'\d{8}T\d{12}Z', timestamp),
            'Invalid snapshot creation timestamp')
    datetime.strptime(timestamp, '%Y%m%dT%H%M%S%fZ')
    entries = manifest['files']
    require(isinstance(entries, dict) and set(entries) == snapshot_files,
            'Incomplete snapshot manifest')
    for name, expected in entries.items():
        require(isinstance(expected, dict) and set(expected) == {'sha256', 'bytes'}
                and type(expected['bytes']) is int and expected['bytes'] > 0
                and isinstance(expected['sha256'], str)
                and re.fullmatch(r'[0-9a-f]{64}', expected['sha256']),
                'Invalid snapshot checksum declaration')
        path = directory/name
        require(path.stat().st_size == expected['bytes'], 'Snapshot size differs')
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        require(digest == expected['sha256'], 'Snapshot checksum differs')
    validate_database(directory/'archive.sqlite', 'archive')
    if not external: validate_database(directory/'shared-authelia.sqlite3', 'authelia')
    runtime_prefix = Path(runtime_prefix)
    require(runtime_prefix.is_absolute(), 'Runtime archive prefix must be absolute')
    profile = installation_profile()
    if not profile.compatibility and not roster_bound:
        require(user in profile.as_dict()['accounts'], 'A later instance requires an allocation-bound snapshot')
    configuration=profile.instance_paths(user)['configuration'].lstrip('/')
    required_runtime = [str(runtime_prefix/configuration/name).lstrip('/')
                        for name in ('config.toml', 'encryption.key', 'webhook.key', 'waha.key')]
    if not profile.compatibility:
        required_runtime.append(str(runtime_prefix/'etc/whatsapp-installation.json').lstrip('/'))
    if not external:
        required_runtime += [str(runtime_prefix/'var/lib/sally-browser/stack/config'/name).lstrip('/')
                             for name in ('authelia.yml', 'users.yml')]
    captures = {}
    if identity_bound:
        binding = manifest['installation']
        expected_identity = identity_record(profile)
        logical_files = {str(IDENTITY)} | ({str(PROFILE)} if not profile.compatibility else set())
        binding_fields = {'identity', 'files'} | ({'roster_sha256'} if roster_bound else set())
        require(isinstance(binding, dict) and set(binding) == binding_fields
                and (not roster_bound or not profile.compatibility and
                     isinstance(binding['roster_sha256'], str) and re.fullmatch('[a-f0-9]{64}', binding['roster_sha256'])),
                'Invalid allocation snapshot binding')
        if roster_bound:
            logical_files |= {profile.roster_pointer(), profile.roster_snapshot(binding['roster_sha256'])}
        require(binding['identity'] == expected_identity and isinstance(binding['files'], dict)
                and set(binding['files']) == logical_files, 'Snapshot installation identity differs')
        for logical, declaration in binding['files'].items():
            require(isinstance(declaration, dict) and set(declaration) == {'sha256', 'bytes'}
                    and type(declaration['bytes']) is int and 0 < declaration['bytes'] <= 131072
                    and isinstance(declaration['sha256'], str)
                    and re.fullmatch('[a-f0-9]{64}', declaration['sha256']),
                    'Invalid installation snapshot checksum declaration')
            member = str(runtime_prefix/logical.lstrip('/')).lstrip('/')
            captures[member] = (logical, declaration)
        required_runtime.extend(captures)
    captured = validate_archive(directory/'private-runtime.tar.gz', required_runtime, capture_files=captures)
    for member, (logical, declaration) in captures.items():
        raw = captured[member]
        require(len(raw) == declaration['bytes'] and hashlib.sha256(raw).hexdigest() == declaration['sha256'],
                'Installation snapshot member checksum differs')
        value = json.loads(raw, object_pairs_hook=unique_object)
        if logical in (str(IDENTITY), str(PROFILE)):
            actual = value if logical == str(IDENTITY) else identity_record(Installation.from_dict(value))
            require(actual == expected_identity, 'Archived installation marker or locator differs from its identity')
    if roster_bound:
        prefix = lambda logical: str(runtime_prefix/logical.lstrip('/')).lstrip('/')
        raw = captured[prefix(profile.roster_snapshot(binding['roster_sha256']))]
        previous = Installation.from_dict(profile.as_dict()).with_roster(json.loads(raw, object_pairs_hook=unique_object))
        pointer = captured[prefix(profile.roster_pointer())]
        require(raw == previous._roster and previous.roster_sha256 == binding['roster_sha256']
                and pointer == installation_encoded(roster_pointer_record(previous)),
                'Archived allocation pointer or snapshot differs')
        current = profile.roster
        require(current is not None and current['revision'] >= previous.roster['revision']
                and (current['revision'] != previous.roster['revision'] or profile.roster_sha256 == previous.roster_sha256)
                and all(current['instances'].get(slug) == item for slug, item in previous.roster['instances'].items())
                and previous.account(user) == profile.account(user)
                and previous.instance_ports(user) == profile.instance_ports(user),
                'Archived allocation is not compatible with the current additive roster')
    validate_archive(directory/'source.tar.gz', {
        'pyproject.toml', 'requirements.lock', 'sally_whatsapp/__init__.py', 'sally_whatsapp/store.py'})
    return manifest
