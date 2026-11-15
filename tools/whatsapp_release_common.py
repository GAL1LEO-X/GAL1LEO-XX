"""Local, bounded release-candidate contracts; no GitHub or server operations.

The qualification record binds declared evidence. Validating it does not prove
that CI ran or that a human approved a review; those are publisher-side gates.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import zipfile
import zlib


REPOSITORY = 'GAL1LEO-X/GAL1LEO-XX'
WORKFLOW_PATH = '.github/workflows/whatsapp-release.yml'
MANIFEST_NAME = 'candidate.json'
NOTES_NAME = 'RELEASE-NOTES.md'
ASSET_ROLES = ('gows_source', 'waha_source', 'toolchain_source',
    'debian_source_1', 'debian_source_2', 'debian_source_3', 'debian_source_4',
    'npm_sources', 'source_notices', 'runtime_oci', 'repository_source',
    'backend_source', 'validation')
BUILT_ROLES = frozenset(ASSET_ROLES[-3:])
REUSED_ROLES = frozenset(ASSET_ROLES[:-3])
MAX_TOTAL_BYTES = 4 * 1024 ** 3
MAX_ASSET_BYTES = 2 * 1024 ** 3
MAX_NOTES_BYTES = 1024 ** 2
MAX_MANIFEST_BYTES = 128 * 1024
CHUNK_BYTES = 1024 ** 2


class ReleaseError(ValueError):
    """Sanitized local release-contract failure."""


def _require(condition, message):
    if not condition:
        raise ReleaseError(message)


def canonical_json(value):
    """Return deterministic UTF-8 JSON bytes, including one final newline."""
    try:
        return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=True, allow_nan=False) + '\n').encode('utf-8')
    except (TypeError, ValueError, RecursionError):
        raise ReleaseError('Value cannot be represented as canonical JSON') from None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def _parse_json(raw):
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ReleaseError('Nonfinite JSON value')))
    except ReleaseError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise ReleaseError('Invalid bounded JSON object') from None
    _require(isinstance(value, dict), 'A JSON object is required')
    return value


def safe_basename(value):
    _require(isinstance(value, str) and len(value) <= 200
        and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', value) is not None
        and not value.endswith('.') and '..' not in value,
        'A literal portable asset basename is required')
    # Also reject names that become devices on a Windows artifact consumer.
    _require(value.split('.')[0].upper() not in {'CON', 'PRN', 'AUX', 'NUL',
        *('COM' + str(i) for i in range(1, 10)), *('LPT' + str(i) for i in range(1, 10))},
        'Reserved asset basename')
    return value


def validate_sha(value, length=64):
    _require(type(length) is int and length in (40, 64) and isinstance(value, str)
        and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None,
        'An exact lowercase hexadecimal digest is required')
    return value


def validate_version(value):
    _require(isinstance(value, str) and len(value) <= 64
        and re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', value) is not None,
        'An ordinary canonical X.Y.Z release version is required')
    return value


def validate_provider_tag(value):
    """Accept historical bundles and separately qualified provider releases."""
    _require(isinstance(value, str), 'Unexpected source Release tag')
    prefix = next((item for item in ('whatsapp/v', 'whatsapp-provider/v')
                   if value.startswith(item)), None)
    _require(prefix is not None, 'Unexpected source Release tag')
    validate_version(value[len(prefix):])
    return value


def _digest(value):
    _require(isinstance(value, str) and value.startswith('sha256:'), 'A sha256 image digest is required')
    validate_sha(value[7:])


def _fields(value, names):
    _require(isinstance(value, dict) and set(value) == set(names), 'Missing or unknown manifest fields')


def _integer(value, maximum=None):
    _require(type(value) is int and value > 0 and (maximum is None or value <= maximum),
             'A positive bounded integer is required')


def _file_record(value, maximum):
    safe_basename(value['name'])
    _integer(value['bytes'], maximum)
    validate_sha(value['sha256'])


def validate_manifest(value):
    """Validate the exact schema and internal bindings; return the same dict.

    A review_evidence URL is an operator's evidence reference, not an automatic
    semantic review approval. The validation asset holds the fuller receipts.
    """
    _fields(value, ('schema_version', 'repository', 'target_commit', 'target_tree',
        'workflow_commit', 'version', 'tag', 'provider_lock_sha256', 'runtime',
        'prepared_run', 'qualification', 'notes', 'assets'))
    _require(type(value['schema_version']) is int and value['schema_version'] == 1
             and value['repository'] == REPOSITORY, 'Wrong candidate schema or repository')
    for key in ('target_commit', 'target_tree', 'workflow_commit'):
        validate_sha(value[key], 40)
    validate_sha(value['provider_lock_sha256'])
    validate_version(value['version'])
    _require(value['tag'] == 'whatsapp/v' + value['version'], 'Release tag and version differ')
    runtime = value['runtime']
    _fields(runtime, ('config_digest', 'manifest_digest'))
    for digest in runtime.values():
        _digest(digest)
    run = value['prepared_run']
    _fields(run, ('id', 'attempt', 'workflow_path'))
    _integer(run['id']); _integer(run['attempt'])
    _require(run['workflow_path'] == WORKFLOW_PATH, 'Unexpected preparation workflow')
    proof = value['qualification']
    _fields(proof, ('target_commit', 'workflow_commit', 'runtime_config_digest',
        'ci_run_id', 'ci_run_attempt', 'review_evidence', 'kind'))
    _require(proof['kind'] == 'offline' and proof['target_commit'] == value['target_commit']
        and proof['workflow_commit'] == value['workflow_commit']
        and proof['runtime_config_digest'] == runtime['config_digest'],
        'Qualification does not bind this candidate')
    _integer(proof['ci_run_id']); _integer(proof['ci_run_attempt'])
    review = proof['review_evidence']
    _require(isinstance(review, str) and len(review) <= 512 and re.fullmatch(
        r'https://github\.com/GAL1LEO-X/GAL1LEO-XX/pull/[1-9][0-9]*(?:#[A-Za-z0-9_-]+)?', review) is not None,
        'Review evidence must reference a repository pull request without query or credentials')
    notes = value['notes']
    _fields(notes, ('name', 'bytes', 'sha256'))
    _file_record(notes, MAX_NOTES_BYTES)
    _require(notes['name'] == NOTES_NAME, 'Unexpected release-notes name')
    assets = value['assets']
    _require(isinstance(assets, list) and len(assets) == len(ASSET_ROLES), 'Exactly thirteen assets are required')
    names, roles, asset_ids, releases, tags = set(), set(), set(), {}, {}
    total = notes['bytes']
    for item in assets:
        _fields(item, ('name', 'bytes', 'sha256', 'role', 'origin'))
        _file_record(item, MAX_ASSET_BYTES)
        name, role = item['name'].casefold(), item['role']
        _require(name not in names and name not in {MANIFEST_NAME.casefold(), NOTES_NAME.casefold()}
            and isinstance(role, str) and role in ASSET_ROLES and role not in roles,
            'Asset names and exact roles must be unique')
        names.add(name); roles.add(role); total += item['bytes']
        origin = item['origin']
        if role in BUILT_ROLES:
            _fields(origin, ('kind', 'commit'))
            _require(origin['kind'] == 'built' and origin['commit'] == value['target_commit'],
                     'Built asset does not bind the target commit')
        else:
            _fields(origin, ('kind', 'release_id', 'asset_id', 'tag'))
            _require(origin['kind'] == 'reused', 'Reused asset provenance is required')
            _integer(origin['release_id']); _integer(origin['asset_id'])
            tag = origin['tag']
            validate_provider_tag(tag)
            _require(origin['asset_id'] not in asset_ids, 'A source asset ID cannot be reused twice')
            _require(releases.get(origin['release_id'], tag) == tag
                and tags.get(tag, origin['release_id']) == origin['release_id'],
                'Source Release ID and tag disagree')
            asset_ids.add(origin['asset_id'])
            releases[origin['release_id']] = tag; tags[tag] = origin['release_id']
    size = len(canonical_json(value))
    _require(size <= MAX_MANIFEST_BYTES and total + size <= MAX_TOTAL_BYTES,
             'Candidate exceeds its manifest or total size limit')
    return value


def _path(value):
    try:
        path = Path(value).absolute()
    except (TypeError, ValueError):
        raise ReleaseError('A physical filesystem path is required') from None
    _require('..' not in path.parts, 'Parent traversal is not accepted')
    return path


@contextmanager
def _physical_directory(path):
    """Anchor every ancestor without following links, including the root."""
    path = _path(path)
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
        actual = path.stat(follow_symlinks=False)
        opened = os.fstat(descriptor)
        _require((actual.st_dev, actual.st_ino) == (opened.st_dev, opened.st_ino), 'Directory changed during verification')
        _require(path.resolve(strict=True) == path, 'Directory ancestry changed during verification')
    finally:
        os.close(descriptor)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


@contextmanager
def _regular_file(parent, name, maximum):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and 0 <= before.st_size <= maximum, 'Expected a bounded physical file without hardlinks')
        yield stream, _identity(before)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _require(_identity(before) == _identity(os.fstat(stream.fileno())) == _identity(current),
                 'File changed during verification')


def _hash_stream(stream, maximum, output=None):
    size, digest = 0, hashlib.sha256()
    while True:
        chunk = stream.read(min(CHUNK_BYTES, maximum - size + 1))
        if not chunk:
            break
        size += len(chunk)
        _require(size <= maximum, 'Decompressed or local file exceeds its size limit')
        digest.update(chunk)
        if output is not None:
            output.write(chunk)
    return size, digest.hexdigest()


def read_json(path, max_bytes=MAX_MANIFEST_BYTES):
    path = _path(path)
    try:
        with _physical_directory(path.parent) as parent, _regular_file(parent, path.name, max_bytes) as (stream, _):
            raw = stream.read(max_bytes + 1)
            _require(len(raw) <= max_bytes, 'JSON exceeds its size limit')
            return _parse_json(raw)
    except OSError:
        raise ReleaseError('Cannot read a physical JSON file') from None


def sha256_file(path):
    path = _path(path)
    try:
        with _physical_directory(path.parent) as parent, _regular_file(parent, path.name, MAX_ASSET_BYTES) as (stream, _):
            return _hash_stream(stream, MAX_ASSET_BYTES)
    except OSError:
        raise ReleaseError('Cannot hash a physical asset file') from None


def _manifest(raw, expected):
    _require(len(raw) <= MAX_MANIFEST_BYTES, 'Manifest exceeds its size limit')
    if expected is not None:
        validate_sha(expected)
        _require(hashlib.sha256(raw).hexdigest() == expected, 'Candidate manifest digest differs')
    value = validate_manifest(_parse_json(raw))
    _require(raw == canonical_json(value), 'Candidate manifest must have canonical bytes')
    return value


def _members(manifest):
    return {NOTES_NAME: manifest['notes'],
            **{'assets/' + item['name']: item for item in manifest['assets']}}


def _match(size, digest, item):
    _require(size == item['bytes'] and digest == item['sha256'], 'Candidate file size or digest differs')


def verify_candidate(directory, expected_manifest_sha256=None):
    """Verify exact local layout, canonical manifest, byte pins and bindings."""
    try:
        with _physical_directory(directory) as root:
            _require(set(os.listdir(root)) == {MANIFEST_NAME, NOTES_NAME, 'assets'}, 'Candidate contains missing or extra entries')
            observations = {}
            with _regular_file(root, MANIFEST_NAME, MAX_MANIFEST_BYTES) as (stream, identity):
                manifest = _manifest(stream.read(MAX_MANIFEST_BYTES + 1), expected_manifest_sha256)
                observations[MANIFEST_NAME] = identity
            assets = os.open('assets', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            try:
                asset_identity = os.fstat(assets)
                expected_names = {item['name'] for item in manifest['assets']}
                _require(set(os.listdir(assets)) == expected_names, 'Assets directory contains missing or extra entries')
                for path, item in _members(manifest).items():
                    parent = assets if path.startswith('assets/') else root
                    with _regular_file(parent, item['name'], item['bytes']) as (stream, identity):
                        _match(*_hash_stream(stream, item['bytes']), item)
                        observations[path] = identity
                for path, identity in observations.items():
                    parent = assets if path.startswith('assets/') else root
                    _require(_identity(os.stat(path.rsplit('/', 1)[-1], dir_fd=parent, follow_symlinks=False)) == identity,
                             'Candidate changed during verification')
                current = os.stat('assets', dir_fd=root, follow_symlinks=False)
                _require((current.st_dev, current.st_ino) == (asset_identity.st_dev, asset_identity.st_ino)
                    and set(os.listdir(assets)) == expected_names
                    and set(os.listdir(root)) == {MANIFEST_NAME, NOTES_NAME, 'assets'},
                    'Candidate directory changed during verification')
            finally:
                os.close(assets)
            return manifest
    except OSError:
        raise ReleaseError('Cannot verify a physical candidate directory') from None


def _zip_bounds(stream, size):
    """Bound the central directory before ZipFile allocates or parses it."""
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    index = tail.rfind(b'PK\x05\x06')
    _require(index >= 0 and len(tail) - index >= 22, 'Missing ZIP end record')
    end = struct.unpack('<4s4H2LH', tail[index:index + 22])
    _require(index + 22 + end[7] == len(tail) and end[1] == end[2] == 0,
             'Multipart or trailing ZIP content is not accepted')
    count, central_size, central_offset = end[4:7]
    end_offset = size - len(tail) + index
    _require(end[3] == count, 'Multipart ZIP entry count differs')
    central_end = end_offset
    locator = None
    if end_offset >= 20:
        stream.seek(end_offset - 20)
        candidate = struct.unpack('<4sLQL', stream.read(20))
        if candidate[0] == b'PK\x06\x07':
            locator = candidate
    has_sentinel = count == 65535 or central_size == 0xffffffff or central_offset == 0xffffffff
    _require(not has_sentinel or locator is not None, 'Missing ZIP64 locator')
    # ZipFile honors an optional ZIP64 locator even without ordinary EOCD
    # sentinels. Bound the exact values it will consume before constructing it.
    if locator is not None:
        _require(locator[1] == 0 and locator[3] == 1 and locator[2] <= end_offset - 76,
                 'Invalid ZIP64 locator')
        stream.seek(locator[2])
        record = struct.unpack('<4sQ2H2L4Q', stream.read(56))
        _require(record[0] == b'PK\x06\x06' and 44 <= record[1] <= 1024
            and record[4] == record[5] == 0 and record[6] == record[7]
            and locator[2] + 12 + record[1] == end_offset - 20, 'Invalid ZIP64 end record')
        _require((count == 65535 or count == record[7])
            and (central_size == 0xffffffff or central_size == record[8])
            and (central_offset == 0xffffffff or central_offset == record[9]),
            'Ordinary and ZIP64 directory records disagree')
        count, central_size, central_offset = record[7:10]
        central_end = locator[2]
    _require(15 <= count <= 16 and 0 < central_size <= 65536
        and central_offset + central_size == central_end, 'Unexpected or oversized ZIP directory')
    stream.seek(0)


def _zip_members(archive):
    entries = archive.infolist()
    _require(15 <= len(entries) <= 16, 'Unexpected ZIP entry count')
    result, names, total = {}, set(), 0
    for info in entries:
        name = info.filename
        _require(info.orig_filename == name and name not in names, 'Duplicate or NUL-containing ZIP member')
        names.add(name)
        kind = stat.S_IFMT(info.external_attr >> 16)
        directory = name == 'assets/'
        _require(kind in ((0, stat.S_IFDIR) if directory else (0, stat.S_IFREG)), 'ZIP links or special files are forbidden')
        _require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
            and not info.flag_bits & ~0x80e, 'Encrypted or unsupported ZIP member')
        if directory:
            _require(info.file_size == 0 and info.compress_size <= 64, 'ZIP directory contains data')
            with archive.open(info) as member:
                _require(member.read(1) == b'', 'ZIP directory contains data')
            continue
        _require(not info.is_dir() and not info.external_attr & 0x10, 'Unexpected ZIP directory')
        if name in (MANIFEST_NAME, NOTES_NAME):
            maximum = MAX_MANIFEST_BYTES if name == MANIFEST_NAME else MAX_NOTES_BYTES
        else:
            _require(name.startswith('assets/') and name.count('/') == 1, 'Unexpected ZIP member path')
            safe_basename(name[7:])
            maximum = MAX_ASSET_BYTES
        _require(0 < info.file_size <= maximum and 0 <= info.compress_size <= MAX_TOTAL_BYTES,
                 'ZIP member exceeds its size limit')
        total += info.file_size
        _require(total <= MAX_TOTAL_BYTES, 'ZIP exceeds its total size limit')
        result[name] = info
    _require(MANIFEST_NAME in result and NOTES_NAME in result, 'ZIP lacks its manifest or notes')
    return result


def receive_artifact(zip_path, output, expected_manifest_sha256):
    """Validate every ZIP entry, CRC, size and hash before creating output.

    Output must be a new directory with physical ancestors. An extraction I/O
    failure can leave that new, private directory incomplete; it is never
    returned as verified and an existing destination is never overwritten.
    """
    validate_sha(expected_manifest_sha256)
    zip_path, output = _path(zip_path), _path(output)
    try:
        with _physical_directory(output.parent) as parent:
            _require(output.name not in os.listdir(parent), 'Artifact output must not exist')
            with _physical_directory(zip_path.parent) as source, _regular_file(
                    source, zip_path.name, MAX_TOTAL_BYTES + MAX_NOTES_BYTES) as (stream, identity):
                _zip_bounds(stream, identity[5])
                with zipfile.ZipFile(stream) as archive:
                    entries = _zip_members(archive)
                    with archive.open(entries[MANIFEST_NAME]) as member:
                        raw = member.read(MAX_MANIFEST_BYTES + 1)
                    manifest = _manifest(raw, expected_manifest_sha256)
                    records = {MANIFEST_NAME: {'bytes': len(raw), 'sha256': expected_manifest_sha256}, **_members(manifest)}
                    _require(set(entries) == set(records), 'ZIP members differ from the candidate manifest')
                    for name, item in records.items():
                        _require(entries[name].file_size == item['bytes'], 'ZIP size differs from the manifest')
                        with archive.open(entries[name]) as member:
                            _match(*_hash_stream(member, item['bytes']), item)
                    _require(identity == _identity(os.fstat(stream.fileno()))
                        == _identity(os.stat(zip_path.name, dir_fd=source, follow_symlinks=False)),
                        'ZIP changed during preflight verification')
                    # No directory or file is created until the entire archive
                    # has passed validation, including its last member's CRC.
                    os.mkdir(output.name, 0o700, dir_fd=parent)
                    destination = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    try:
                        os.mkdir('assets', 0o700, dir_fd=destination)
                        assets = os.open('assets', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=destination)
                        try:
                            for name, item in records.items():
                                target = assets if name.startswith('assets/') else destination
                                descriptor = os.open(name.rsplit('/', 1)[-1],
                                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target)
                                with os.fdopen(descriptor, 'wb') as saved, archive.open(entries[name]) as member:
                                    _match(*_hash_stream(member, item['bytes'], saved), item)
                                    saved.flush(); os.fsync(saved.fileno())
                            os.fsync(assets); os.fsync(destination)
                        finally:
                            os.close(assets)
                    finally:
                        os.close(destination)
                    os.fsync(parent)
        return verify_candidate(output, expected_manifest_sha256)
    except (OSError, zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError,
            struct.error, UnicodeError, zlib.error):
        raise ReleaseError('Cannot receive a valid physical candidate artifact') from None
