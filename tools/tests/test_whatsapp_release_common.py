"""Synthetic contracts and hostile inputs for local candidate handling."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import warnings
import zipfile

import pytest


SPEC = importlib.util.spec_from_file_location('release_common_under_test',
    Path(__file__).resolve().parents[1] / 'whatsapp_release_common.py')
common = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(common)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def manifest_for(files, notes):
    target, workflow = 'a' * 40, 'c' * 40
    assets = []
    for index, role in enumerate(common.ASSET_ROLES):
        name = role + '.tar.gz'
        origin = ({'kind': 'built', 'commit': target} if role in common.BUILT_ROLES else
            {'kind': 'reused', 'release_id': 101, 'asset_id': 1001 + index, 'tag': 'whatsapp/v0.7.0'})
        assets.append({'name': name, 'bytes': len(files[name]), 'sha256': digest(files[name]),
                       'role': role, 'origin': origin})
    return {'schema_version': 1, 'repository': common.REPOSITORY,
        'target_commit': target, 'target_tree': 'b' * 40, 'workflow_commit': workflow,
        'version': '0.8.0', 'tag': 'whatsapp/v0.8.0', 'provider_lock_sha256': 'd' * 64,
        'runtime': {'config_digest': 'sha256:' + 'e' * 64, 'manifest_digest': 'sha256:' + 'f' * 64},
        'prepared_run': {'id': 1122, 'attempt': 2, 'workflow_path': common.WORKFLOW_PATH},
        'qualification': {'kind': 'offline', 'target_commit': target, 'workflow_commit': workflow,
            'runtime_config_digest': 'sha256:' + 'e' * 64, 'ci_run_id': 1111, 'ci_run_attempt': 1,
            'review_evidence': 'https://github.com/GAL1LEO-X/GAL1LEO-XX/pull/123#issuecomment-456'},
        'notes': {'name': common.NOTES_NAME, 'bytes': len(notes), 'sha256': digest(notes)},
        'assets': assets}


@pytest.fixture
def candidate(tmp_path):
    root = tmp_path / 'candidate'
    (root / 'assets').mkdir(parents=True)
    files = {role + '.tar.gz': (role + '\n').encode() for role in common.ASSET_ROLES}
    notes = b'Offline qualification only. No server transfer.\n'
    for name, data in files.items():
        (root / 'assets' / name).write_bytes(data)
    (root / common.NOTES_NAME).write_bytes(notes)
    manifest = manifest_for(files, notes)
    (root / common.MANIFEST_NAME).write_bytes(common.canonical_json(manifest))
    return root, manifest


def save_manifest(root, manifest):
    raw = common.canonical_json(manifest)
    (root / common.MANIFEST_NAME).write_bytes(raw)
    return digest(raw)


@pytest.mark.parametrize('tag', ['whatsapp/v0.7.0', 'whatsapp-provider/v0.8.1'])
def test_provider_release_namespaces_preserve_candidate_validation(candidate, tag):
    root, manifest = candidate
    for asset in manifest['assets']:
        if asset['origin']['kind'] == 'reused':
            asset['origin']['tag'] = tag
    save_manifest(root, manifest)
    assert common.verify_candidate(root) == manifest


@pytest.mark.parametrize('tag', [None, 'provider/v0.8.1', 'whatsapp-provider/v01.2.3',
    'whatsapp-provider/v0.8.1-rc1', 'whatsapp-provider/v0.8.1/extra',
    'whatsapp-provider/v0.8.1\n', 'https://example.invalid/whatsapp-provider/v0.8.1'])
def test_provider_release_tag_remains_canonical(candidate, tag):
    _, manifest = candidate
    next(a for a in manifest['assets'] if a['origin']['kind'] == 'reused')['origin']['tag'] = tag
    with pytest.raises(common.ReleaseError):
        common.validate_manifest(manifest)


def zip_candidate(root, path, *, replacement=None, extra=None, compression=zipfile.ZIP_DEFLATED):
    replacement = replacement or {}
    with zipfile.ZipFile(path, 'w', compression=compression) as archive:
        for item in [root / common.MANIFEST_NAME, root / common.NOTES_NAME, *sorted((root / 'assets').iterdir())]:
            name = item.relative_to(root).as_posix()
            value = replacement.get(name, name)
            if value is not None:
                archive.writestr(value, item.read_bytes())
        for name, data in extra or []:
            archive.writestr(name, data)
    return path


def receive(root, tmp_path, **kwargs):
    archive = zip_candidate(root, tmp_path / 'candidate.zip', **kwargs)
    return common.receive_artifact(archive, tmp_path / 'received', digest((root / common.MANIFEST_NAME).read_bytes()))


def test_roundtrip_and_public_helpers(candidate, tmp_path):
    root, manifest = candidate
    raw = (root / common.MANIFEST_NAME).read_bytes()
    pin = digest(raw)
    assert issubclass(common.ReleaseError, ValueError)
    assert common.read_json(root / common.MANIFEST_NAME) == manifest
    assert common.sha256_file(root / common.NOTES_NAME) == (manifest['notes']['bytes'], manifest['notes']['sha256'])
    assert common.canonical_json({'z': 1, 'a': '\u00e8'}) == b'{"a":"\\u00e8","z":1}\n'
    assert common.verify_candidate(root, pin) == manifest
    assert receive(root, tmp_path, extra=[('assets/', b'')]) == manifest
    output = tmp_path / 'received'
    assert common.verify_candidate(output, pin) == manifest
    assert set(output.iterdir()) == {output / 'assets', output / common.NOTES_NAME, output / common.MANIFEST_NAME}
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    for item in output.rglob('*'):
        if item.is_file():
            assert stat.S_IMODE(item.stat().st_mode) == 0o600


@pytest.mark.parametrize('raw', [b'{"a":1,"a":2}', b'{"nested":{"a":1,"a":2}}',
    b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}', b'[]', b'null',
    b'{"a":"\xff"}', b'\xef\xbb\xbf{}', b'{} trailing'])
def test_json_rejects_ambiguous_or_nonobject_data(tmp_path, raw):
    path = tmp_path / 'value.json'
    path.write_bytes(raw)
    with pytest.raises(common.ReleaseError):
        common.read_json(path)


def test_json_bounds_and_nonfinite_canonicalization(tmp_path):
    path = tmp_path / 'value.json'
    path.write_bytes(b'{"a":1}')
    assert common.read_json(path, max_bytes=7) == {'a': 1}
    with pytest.raises(common.ReleaseError):
        common.read_json(path, max_bytes=6)
    with pytest.raises(common.ReleaseError):
        common.canonical_json({'a': float('nan')})


@pytest.mark.parametrize('name', ['', '.', '..', '../file', 'a/b', 'a\\b', '/absolute',
    'C:drive', '.hidden', 'ends.', 'two..dots', 'file\x00tail', 'new\nline', 'caf\u00e9',
    'NUL', 'con.txt', 'COM1.tar', 'lpt9', 'a' * 201])
def test_unsafe_basename(name):
    with pytest.raises(common.ReleaseError):
        common.safe_basename(name)


@pytest.mark.parametrize('version', ['01.2.3', '1.02.3', '1.2.03', '1.2', 'v1.2.3',
    '1.2.3-rc1', '1.2.3+build', '1.2.3\n', True, None])
def test_invalid_versions(version):
    with pytest.raises(common.ReleaseError):
        common.validate_version(version)


@pytest.mark.parametrize('value,length', [('a' * 63, 64), ('A' * 64, 64), ('a' * 64 + '\n', 64),
    ('sha256:' + 'a' * 64, 64), ('a' * 40, 64), ('a' * 64, 40), ('a' * 32, 32), (True, 64)])
def test_exact_digest_shape(value, length):
    with pytest.raises(common.ReleaseError):
        common.validate_sha(value, length)


@pytest.mark.parametrize('path,value', [
    (('schema_version',), True), (('schema_version',), 2), (('repository',), 'other/repo'),
    (('target_commit',), 'a' * 40 + '\n'), (('target_tree',), 'B' * 40),
    (('workflow_commit',), 'c' * 39), (('provider_lock_sha256',), 'd' * 63),
    (('tag',), 'whatsapp/v0.9.0'), (('version',), '0.8.0-rc1'),
    (('runtime', 'config_digest'), 'e' * 64),
    (('prepared_run', 'id'), True), (('prepared_run', 'attempt'), 0),
    (('prepared_run', 'workflow_path'), '.github/workflows/other.yml'),
    (('qualification', 'target_commit'), 'b' * 40),
    (('qualification', 'workflow_commit'), 'b' * 40),
    (('qualification', 'runtime_config_digest'), 'sha256:' + 'b' * 64),
    (('qualification', 'kind'), 'live'), (('qualification', 'ci_run_id'), False),
    (('qualification', 'ci_run_attempt'), -1),
    (('qualification', 'review_evidence'), 'https://github.com/other/repo/pull/1'),
    (('qualification', 'review_evidence'), 'https://github.com/GAL1LEO-X/GAL1LEO-XX/pull/1?token=secret'),
    (('qualification', 'review_evidence'), 'https://github.com/GAL1LEO-X/GAL1LEO-XX/pull/0'),
    (('qualification', 'review_evidence'), 'https://github.com/GAL1LEO-X/GAL1LEO-XX/pull/1\n'),
    (('notes', 'name'), 'OTHER.md'), (('notes', 'bytes'), 0),
    (('assets', 0, 'bytes'), True), (('assets', 0, 'bytes'), 2 * 1024 ** 3 + 1),
    (('assets', 0, 'origin', 'kind'), 'built'), (('assets', 0, 'origin', 'asset_id'), True),
    (('assets', 0, 'origin', 'release_id'), 0), (('assets', 0, 'origin', 'tag'), 'main'),
    (('assets', 12, 'origin', 'commit'), 'b' * 40),
    (('assets', 12, 'role'), 'unknown'), (('assets', 12, 'role'), {}),
])
def test_manifest_rejects_invalid_bindings(candidate, path, value):
    root, manifest = candidate
    item = manifest
    for key in path[:-1]:
        item = item[key]
    item[path[-1]] = value
    save_manifest(root, manifest)
    with pytest.raises(common.ReleaseError):
        common.verify_candidate(root)


@pytest.mark.parametrize('mutation', ['role', 'name', 'case', 'asset_id', 'release_tag', 'tag_release',
    'root_extra', 'proof_extra', 'origin_extra', 'missing', 'extra_asset', 'role_origin_swap'])
def test_manifest_duplicates_unknown_fields_and_origin_confusion(candidate, mutation):
    root, manifest = candidate
    first, second = manifest['assets'][:2]
    if mutation in ('role', 'name'):
        second[mutation] = first[mutation]
    elif mutation == 'case':
        second['name'] = first['name'].upper()
    elif mutation == 'asset_id':
        second['origin']['asset_id'] = first['origin']['asset_id']
    elif mutation == 'release_tag':
        second['origin']['tag'] = 'whatsapp/v0.6.0'
    elif mutation == 'tag_release':
        second['origin']['release_id'] += 1
    elif mutation == 'root_extra':
        manifest['machine_approved'] = True
    elif mutation == 'proof_extra':
        manifest['qualification']['approved'] = True
    elif mutation == 'origin_extra':
        first['origin']['commit'] = manifest['target_commit']
    elif mutation == 'missing':
        del manifest['qualification']['ci_run_attempt']
    elif mutation == 'extra_asset':
        manifest['assets'].append(copy.deepcopy(first))
    else:
        first['origin'], manifest['assets'][-1]['origin'] = manifest['assets'][-1]['origin'], first['origin']
    save_manifest(root, manifest)
    with pytest.raises(common.ReleaseError):
        common.verify_candidate(root)


def test_manifest_must_have_canonical_pinned_bytes(candidate):
    root, manifest = candidate
    original = (root / common.MANIFEST_NAME).read_bytes()
    with pytest.raises(common.ReleaseError, match='digest'):
        common.verify_candidate(root, '0' * 64)
    (root / common.MANIFEST_NAME).write_text(json.dumps(manifest, indent=2))
    with pytest.raises(common.ReleaseError, match='canonical'):
        common.verify_candidate(root)
    (root / common.MANIFEST_NAME).write_bytes(original.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'))
    with pytest.raises(common.ReleaseError, match='Duplicate'):
        common.verify_candidate(root)


@pytest.mark.parametrize('mutation', ['asset_corrupt', 'notes_corrupt', 'missing_asset', 'extra_asset',
    'extra_root', 'nested_directory', 'asset_symlink', 'notes_symlink', 'manifest_symlink',
    'assets_symlink', 'root_symlink', 'ancestor_symlink', 'hardlink', 'fifo'])
def test_local_candidate_is_exact_and_physical(candidate, tmp_path, mutation):
    root, manifest = candidate
    target = root / 'assets' / manifest['assets'][0]['name']
    if mutation == 'asset_corrupt':
        target.write_bytes(b'!' * target.stat().st_size)
    elif mutation == 'notes_corrupt':
        (root / common.NOTES_NAME).write_bytes(b'!' * manifest['notes']['bytes'])
    elif mutation == 'missing_asset':
        target.unlink()
    elif mutation == 'extra_asset':
        (root / 'assets' / 'extra').write_bytes(b'x')
    elif mutation == 'extra_root':
        (root / 'extra').write_bytes(b'x')
    elif mutation == 'nested_directory':
        target.unlink(); target.mkdir()
    elif mutation in ('asset_symlink', 'notes_symlink', 'manifest_symlink', 'hardlink'):
        if mutation == 'notes_symlink':
            target = root / common.NOTES_NAME
        elif mutation == 'manifest_symlink':
            target = root / common.MANIFEST_NAME
        outside = tmp_path / 'outside'
        target.rename(outside)
        if mutation == 'hardlink':
            os.link(outside, target)
        else:
            target.symlink_to(outside)
    elif mutation == 'assets_symlink':
        (root / 'assets').rename(tmp_path / 'outside-assets')
        (root / 'assets').symlink_to(tmp_path / 'outside-assets', target_is_directory=True)
    elif mutation == 'root_symlink':
        root.rename(tmp_path / 'outside-root')
        root.symlink_to(tmp_path / 'outside-root', target_is_directory=True)
    elif mutation == 'ancestor_symlink':
        alias = tmp_path / 'alias'
        alias.symlink_to(tmp_path, target_is_directory=True)
        root = alias / root.name
    else:
        target.unlink(); os.mkfifo(target)
    with pytest.raises(common.ReleaseError):
        common.verify_candidate(root)


def test_verification_detects_change_to_an_already_checked_file(candidate, monkeypatch):
    root, _ = candidate
    original = common._hash_stream
    calls = 0
    def change_notes(stream, maximum, output=None):
        nonlocal calls
        answer = original(stream, maximum, output)
        calls += 1
        if calls == 2:
            notes = root / common.NOTES_NAME
            notes.write_bytes(b'!' * notes.stat().st_size)
        return answer
    monkeypatch.setattr(common, '_hash_stream', change_notes)
    with pytest.raises(common.ReleaseError, match='changed'):
        common.verify_candidate(root)


def test_bounds_include_actual_bytes_and_manifest(candidate, monkeypatch):
    root, manifest = candidate
    size = sum(item['bytes'] for item in manifest['assets']) + manifest['notes']['bytes'] + (root / common.MANIFEST_NAME).stat().st_size
    monkeypatch.setattr(common, 'MAX_TOTAL_BYTES', size)
    assert common.verify_candidate(root) == manifest
    monkeypatch.setattr(common, 'MAX_TOTAL_BYTES', size - 1)
    with pytest.raises(common.ReleaseError, match='total size'):
        common.verify_candidate(root)
    with pytest.raises(common.ReleaseError, match='exceeds'):
        common._hash_stream(io.BytesIO(b'123456'), 5)
    assert common._hash_stream(io.BytesIO(b'12345'), 5) == (5, digest(b'12345'))


@pytest.mark.parametrize('limit,location', [('MAX_MANIFEST_BYTES', 'manifest'), ('MAX_NOTES_BYTES', 'notes'),
    ('MAX_ASSET_BYTES', 'asset')])
def test_individual_byte_limits(candidate, monkeypatch, limit, location):
    root, manifest = candidate
    size = {'manifest': (root / common.MANIFEST_NAME).stat().st_size,
        'notes': manifest['notes']['bytes'], 'asset': max(item['bytes'] for item in manifest['assets'])}[location]
    monkeypatch.setattr(common, limit, size)
    assert common.verify_candidate(root) == manifest
    monkeypatch.setattr(common, limit, size - 1)
    with pytest.raises(common.ReleaseError):
        common.verify_candidate(root)


@pytest.mark.parametrize('name', ['../escape', '/absolute', 'assets/../escape', 'assets/nested/file',
    'assets\\file', 'C:/drive', './candidate.json', 'ASSETS/file', 'prefix/assets/file', 'assets/.hidden'])
def test_zip_paths_are_rejected_before_output(candidate, tmp_path, name):
    root, manifest = candidate
    old = 'assets/' + manifest['assets'][0]['name']
    with pytest.raises(common.ReleaseError):
        receive(root, tmp_path, replacement={old: name})
    assert not (tmp_path / 'received').exists()


@pytest.mark.parametrize('kind', [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFDIR])
def test_zip_special_files_are_rejected_before_output(candidate, tmp_path, kind):
    root, manifest = candidate
    name = 'assets/' + manifest['assets'][0]['name']
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (kind | 0o600) << 16
    with pytest.raises(common.ReleaseError):
        receive(root, tmp_path, replacement={name: info})
    assert not (tmp_path / 'received').exists()


@pytest.mark.parametrize('mutation', ['duplicate', 'extra', 'missing', 'directory_data', 'bad_notes', 'bzip2'])
def test_hostile_zip_layout_and_payload(candidate, tmp_path, mutation):
    root, manifest = candidate
    kwargs = {}
    if mutation == 'duplicate':
        kwargs['extra'] = [(common.NOTES_NAME, (root / common.NOTES_NAME).read_bytes())]
    elif mutation == 'extra':
        kwargs['extra'] = [('extra.txt', b'not in manifest')]
    elif mutation == 'missing':
        kwargs['replacement'] = {'assets/' + manifest['assets'][0]['name']: None}
    elif mutation == 'directory_data':
        kwargs['extra'] = [('assets/', b'not a directory')]
    elif mutation == 'bad_notes':
        (root / common.NOTES_NAME).write_bytes(b'x' * manifest['notes']['bytes'])
    else:
        kwargs['compression'] = zipfile.ZIP_BZIP2
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with pytest.raises(common.ReleaseError):
            receive(root, tmp_path, **kwargs)
    assert not (tmp_path / 'received').exists()


@pytest.mark.parametrize('mutation', ['crc_last_asset', 'local_name', 'nul_name', 'encrypted', 'declared_size', 'truncated', 'central_count', 'utf8_name'])
def test_corrupt_zip_is_rejected_before_any_extraction(candidate, tmp_path, mutation):
    root, _ = candidate
    path = zip_candidate(root, tmp_path / 'candidate.zip', compression=zipfile.ZIP_STORED)
    with zipfile.ZipFile(path) as archive:
        last = archive.infolist()[-1]
    raw = bytearray(path.read_bytes())
    offset = last.header_offset
    name_length, extra_length = struct.unpack_from('<HH', raw, offset + 26)
    start = offset + 30 + name_length + extra_length
    central = raw.rfind(b'PK\x01\x02')
    if mutation == 'crc_last_asset':
        raw[start] ^= 1
    elif mutation == 'local_name':
        raw[offset + 30] = ord('X')
    elif mutation == 'nul_name':
        raw[central + 46 + name_length - 1] = 0
        raw[offset + 30 + name_length - 1] = 0
    elif mutation == 'encrypted':
        struct.pack_into('<H', raw, offset + 6, 1)
        struct.pack_into('<H', raw, central + 8, 1)
    elif mutation == 'declared_size':
        struct.pack_into('<I', raw, central + 24, common.MAX_ASSET_BYTES + 1)
    elif mutation == 'truncated':
        del raw[-1:]
    elif mutation == 'utf8_name':
        struct.pack_into('<H', raw, offset + 6, 0x800)
        struct.pack_into('<H', raw, central + 8, 0x800)
        raw[central + 46] = 0xff
        raw[offset + 30] = 0xff
    else:
        end = raw.rfind(b'PK\x05\x06')
        struct.pack_into('<HH', raw, end + 8, 60000, 60000)
    path.write_bytes(raw)
    with pytest.raises(common.ReleaseError):
        common.receive_artifact(path, tmp_path / 'received', digest((root / common.MANIFEST_NAME).read_bytes()))
    assert not (tmp_path / 'received').exists()


def test_invalid_deflate_is_a_release_error_before_extraction(candidate, tmp_path):
    root, _ = candidate
    path = zip_candidate(root, tmp_path / 'candidate.zip')
    with zipfile.ZipFile(path) as archive:
        offset = archive.infolist()[-1].header_offset
    raw = bytearray(path.read_bytes())
    name_length, extra_length = struct.unpack_from('<HH', raw, offset + 26)
    raw[offset + 30 + name_length + extra_length] |= 6  # Reserved deflate BTYPE.
    path.write_bytes(raw)
    with pytest.raises(common.ReleaseError):
        common.receive_artifact(path, tmp_path / 'received', digest((root / common.MANIFEST_NAME).read_bytes()))
    assert not (tmp_path / 'received').exists()


def insert_zip64(path, fake_ordinary=False, sentinels=False):
    raw = path.read_bytes()
    offset = raw.rfind(b'PK\x05\x06')
    end = list(struct.unpack('<4s4H2LH', raw[offset:offset + 22]))
    count, central_size, central_offset = end[4:7]
    record = struct.pack('<4sQ2H2L4Q', b'PK\x06\x06', 44, 45, 45, 0, 0,
                         count, count, central_size, central_offset)
    locator = struct.pack('<4sLQL', b'PK\x06\x07', 0, offset, 1)
    if fake_ordinary:
        end[3:7] = [15, 15, len(record + locator), offset]
    if sentinels:
        end[3:7] = [65535, 65535, 0xffffffff, 0xffffffff]
    path.write_bytes(raw[:offset] + record + locator + struct.pack('<4s4H2LH', *end))


@pytest.mark.parametrize('sentinels', [False, True])
def test_zip64_directory_uses_the_same_bounded_values_as_reader(candidate, tmp_path, sentinels):
    root, manifest = candidate
    path = zip_candidate(root, tmp_path / 'candidate.zip')
    insert_zip64(path, sentinels=sentinels)
    assert common.receive_artifact(path, tmp_path / 'received', digest((root / common.MANIFEST_NAME).read_bytes())) == manifest


def test_zip64_cannot_hide_large_directory_from_preflight(candidate, tmp_path, monkeypatch):
    root, _ = candidate
    path = zip_candidate(root, tmp_path / 'candidate.zip',
        extra=[('assets/unexpected-' + str(index) + '.tar', b'x') for index in range(1100)])
    insert_zip64(path, fake_ordinary=True)
    # ZipFile itself follows the ZIP64 locator even without EOCD sentinels.
    with zipfile.ZipFile(path) as archive:
        assert len(archive.infolist()) == 1115
    def must_not_parse(*args, **kwargs):
        pytest.fail('Unbounded central directory reached the ZIP parser')
    monkeypatch.setattr(zipfile, 'ZipFile', must_not_parse)
    with pytest.raises(common.ReleaseError):
        common.receive_artifact(path, tmp_path / 'received', digest((root / common.MANIFEST_NAME).read_bytes()))
    assert not (tmp_path / 'received').exists()


def test_zip_changed_after_preflight_does_not_create_output(candidate, tmp_path, monkeypatch):
    root, _ = candidate
    path = zip_candidate(root, tmp_path / 'candidate.zip')
    original = common._hash_stream
    calls = 0
    def alter_source(stream, maximum, output=None):
        nonlocal calls
        answer = original(stream, maximum, output)
        calls += 1
        if calls == 15:
            with path.open('ab') as changed:
                changed.write(b'changed during verification')
        return answer
    monkeypatch.setattr(common, '_hash_stream', alter_source)
    with pytest.raises(common.ReleaseError):
        common.receive_artifact(path, tmp_path / 'received', digest((root / common.MANIFEST_NAME).read_bytes()))
    assert not (tmp_path / 'received').exists()


def test_output_created_concurrently_is_preserved(candidate, tmp_path, monkeypatch):
    root, _ = candidate
    path = zip_candidate(root, tmp_path / 'candidate.zip')
    output = tmp_path / 'received'
    original = os.mkdir
    def concurrent_create(name, *args, **kwargs):
        if name == 'received':
            original(output)
            (output / 'marker').write_bytes(b'concurrent owner')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(os, 'mkdir', concurrent_create)
    with pytest.raises(common.ReleaseError):
        common.receive_artifact(path, output, digest((root / common.MANIFEST_NAME).read_bytes()))
    assert list(output.iterdir()) == [output / 'marker']
    assert (output / 'marker').read_bytes() == b'concurrent owner'


def test_io_failure_never_returns_an_incomplete_candidate(candidate, tmp_path, monkeypatch):
    root, _ = candidate
    path = zip_candidate(root, tmp_path / 'candidate.zip')
    original = common._hash_stream
    def fail_write(stream, maximum, output=None):
        if output is not None:
            raise OSError('synthetic disk exhaustion')
        return original(stream, maximum, output)
    monkeypatch.setattr(common, '_hash_stream', fail_write)
    with pytest.raises(common.ReleaseError):
        common.receive_artifact(path, tmp_path / 'received', digest((root / common.MANIFEST_NAME).read_bytes()))
    with pytest.raises(common.ReleaseError):
        common.verify_candidate(tmp_path / 'received')


@pytest.mark.parametrize('existing', ['directory', 'file', 'symlink', 'ancestor_symlink'])
def test_output_is_new_and_never_overwrites(candidate, tmp_path, existing):
    root, _ = candidate
    archive = zip_candidate(root, tmp_path / 'candidate.zip')
    output = tmp_path / 'received'
    marker = tmp_path / 'untouched'
    marker.write_bytes(b'preserve me')
    if existing == 'directory':
        output.mkdir(); (output / 'marker').write_bytes(b'preserve me')
    elif existing == 'file':
        output.write_bytes(b'preserve me')
    elif existing == 'symlink':
        output.symlink_to(marker)
    else:
        alias = tmp_path / 'alias'
        alias.symlink_to(tmp_path, target_is_directory=True)
        output = alias / 'received'
    with pytest.raises(common.ReleaseError):
        common.receive_artifact(archive, output, digest((root / common.MANIFEST_NAME).read_bytes()))
    assert marker.read_bytes() == b'preserve me'
    if existing == 'directory':
        assert (output / 'marker').read_bytes() == b'preserve me'
    elif existing == 'file':
        assert output.read_bytes() == b'preserve me'
    elif existing == 'ancestor_symlink':
        assert not (tmp_path / 'received').exists()


def test_receive_requires_correct_external_manifest_pin(candidate, tmp_path):
    root, _ = candidate
    archive = zip_candidate(root, tmp_path / 'candidate.zip')
    for pin in ('0' * 64, None, 'a' * 63):
        with pytest.raises(common.ReleaseError):
            common.receive_artifact(archive, tmp_path / 'received', pin)
        assert not (tmp_path / 'received').exists()


def test_zip_source_link_and_hardlink_rejected(candidate, tmp_path):
    root, _ = candidate
    archive = zip_candidate(root, tmp_path / 'candidate.zip')
    pin = digest((root / common.MANIFEST_NAME).read_bytes())
    alias = tmp_path / 'alias.zip'
    alias.symlink_to(archive)
    with pytest.raises(common.ReleaseError):
        common.receive_artifact(alias, tmp_path / 'received', pin)
    alias.unlink(); os.link(archive, alias)
    with pytest.raises(common.ReleaseError):
        common.receive_artifact(archive, tmp_path / 'received', pin)
    assert not (tmp_path / 'received').exists()
