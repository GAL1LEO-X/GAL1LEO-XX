"""Identity-bound snapshots, synthetic protected roots and immutable old formats."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]/'scripts'))
import installation_layout as layout
import backup_validation as validation
from test_backup_runtime import prepare_installation
from test_standalone_backup import case
from test_backup_validation import snapshot


def rehash(snapshot, manifest):
    for name, item in manifest['files'].items():
        raw = (snapshot/name).read_bytes()
        item.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    (snapshot/'manifest.json').write_text(json.dumps(manifest))


def replace_member(snapshot, name, raw):
    archive = snapshot/'private-runtime.tar.gz'
    with tarfile.open(archive, 'r:gz') as source:
        entries = [(member, source.extractfile(member).read() if member.isfile() else None)
                   for member in source]
    with tarfile.open(archive, 'w:gz') as target:
        for member, data in entries:
            if member.name == name:
                if raw is None: continue
                data = raw; member.size = len(data)
            target.addfile(member, io.BytesIO(data) if data is not None else None)


@pytest.mark.parametrize('damage', ['missing', 'invalid-json', 'wrong-pin', 'duplicate', 'symlink', 'writable'])
def test_marker_fault_precedes_backup_directory_and_every_service_call(case, damage):
    marker = case.mapped(layout.IDENTITY)
    if damage == 'missing': marker.unlink()
    elif damage == 'invalid-json': marker.write_bytes(b'{')
    elif damage == 'wrong-pin':
        value = json.loads(marker.read_bytes()); value['installation_sha256'] = '0'*64
        marker.write_text(json.dumps(value))
    elif damage == 'duplicate': marker.write_text(marker.read_text().replace('"mode":', '"mode":"legacy","mode":'))
    elif damage == 'symlink':
        other = marker.with_suffix('.saved'); marker.rename(other); marker.symlink_to(other)
    else: marker.chmod(0o666)
    with pytest.raises((ValueError, OSError)):
        case.backup.backup(case.instance)
    assert case.calls == case.snapshots == []
    assert not (case.host/'var/backups').exists()


def test_marker_bytes_are_captured_before_a_later_source_replacement(case, monkeypatch):
    marker = case.mapped(layout.IDENTITY); original = marker.read_bytes()
    capture = case.backup.installation_snapshot
    def replace_after_capture():
        result = capture()
        marker.write_bytes(b'untrusted replacement after the protected capture')
        return result
    monkeypatch.setattr(case.backup, 'installation_snapshot', replace_after_capture)
    result = case.backup.backup(case.instance)
    manifest = validation.validate_snapshot(result['backup'], 'fixture', runtime_prefix=case.host,
                                            auth_mode='external-oidc')
    binding = manifest['installation']['files'][str(layout.IDENTITY)]
    assert binding == {'bytes': len(original), 'sha256': hashlib.sha256(original).hexdigest()}
    with tarfile.open(Path(result['backup'])/'private-runtime.tar.gz') as archive:
        assert archive.extractfile(str(marker).lstrip('/')).read() == original


@pytest.mark.parametrize('damage', ['missing', 'empty', 'wrong-pin', 'duplicate', 'oversized', 'unbound-change'])
def test_v5_marker_validation_survives_rehashed_outer_archive(case, damage):
    result = case.backup.backup(case.instance); snapshot = Path(result['backup'])
    manifest = json.loads((snapshot/'manifest.json').read_text())
    marker = case.mapped(layout.IDENTITY); raw = marker.read_bytes()
    if damage == 'missing': raw = None
    elif damage == 'empty': raw = b''
    elif damage == 'wrong-pin':
        value = json.loads(raw); value['installation_sha256'] = '0'*64; raw = json.dumps(value).encode()
    elif damage == 'duplicate': raw = raw.replace(b'"mode":', b'"mode":"legacy","mode":')
    elif damage == 'oversized': raw = b' '*131073
    else: raw += b' '
    replace_member(snapshot, str(marker).lstrip('/'), raw)
    if raw is not None and damage != 'unbound-change':
        manifest['installation']['files'][str(layout.IDENTITY)] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    rehash(snapshot, manifest)
    with pytest.raises(ValueError):
        validation.validate_snapshot(snapshot, 'fixture', runtime_prefix=case.host, auth_mode='external-oidc')


def configured_profile(case):
    value = json.loads((Path(__file__).parents[1]/'deploy/installation.example.json').read_text())
    value['paths']['project'] = str(case.logical.project_root)
    value['accounts'] = {'fixture': 'messages-fixture'}
    value['ports'] = {'fixture': {'bridge': 19001, 'gateway': 19009}}
    return layout.Installation.from_dict(value)


def test_configured_capture_binds_exact_marker_and_locator(case, monkeypatch):
    profile = configured_profile(case)
    prepare_installation(case.backup, case.host, monkeypatch, profile)
    binding, captured = case.backup.installation_snapshot()
    assert binding['identity'] == layout.identity_record(profile)
    assert set(binding['files']) == {str(layout.IDENTITY), str(layout.PROFILE)}
    for logical, item in binding['files'].items():
        raw = captured[case.mapped(logical)]
        assert item == {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


@pytest.mark.parametrize('damage', ['missing-locator', 'mismatched-locator', 'legacy-conflict'])
def test_configured_or_conflicting_identity_precedes_services(case, monkeypatch, damage):
    profile = configured_profile(case)
    prepare_installation(case.backup, case.host, monkeypatch, profile)
    locator = case.mapped(layout.PROFILE)
    if damage == 'missing-locator': locator.unlink()
    elif damage == 'mismatched-locator':
        value = profile.as_dict(); value['services']['prefix'] = 'different'
        locator.write_text(json.dumps(value))
    else: case.mapped(layout.IDENTITY).write_bytes(layout.identity_bytes(layout.Installation.legacy()))
    with pytest.raises(ValueError): case.backup.backup(case.instance)
    assert case.calls == case.snapshots == []
    assert not (case.host/'var/backups').exists()


def test_configured_v5_archive_locator_cannot_disagree_with_marker(case, monkeypatch):
    # Reuse a fully valid synthetic external snapshot, then give its public
    # configuration the selected destination layout and add the matching pins.
    result = case.backup.backup(case.instance); snapshot = Path(result['backup'])
    profile = configured_profile(case)
    archive = snapshot/'private-runtime.tar.gz'
    old = str(case.instance.config_dir).lstrip('/')
    new = str(case.mapped(profile.instance_paths('fixture')['configuration'])).lstrip('/')
    with tarfile.open(archive) as source:
        entries = [(m, source.extractfile(m).read() if m.isfile() else None) for m in source]
    marker = layout.identity_bytes(profile); locator = profile._encoded
    with tarfile.open(archive, 'w:gz') as target:
        for member, data in entries:
            if member.name == str(case.mapped(layout.IDENTITY)).lstrip('/'):
                data = marker; member.size = len(data)
            if member.name == old or member.name.startswith(old+'/'):
                member.name = new + member.name[len(old):]
                member.pax_headers = {}
            target.addfile(member, io.BytesIO(data) if data is not None else None)
        info = tarfile.TarInfo(str(case.mapped(layout.PROFILE)).lstrip('/')); info.size = len(locator)
        target.addfile(info, io.BytesIO(locator))
    manifest = json.loads((snapshot/'manifest.json').read_text())
    manifest['installation'] = {'identity': layout.identity_record(profile), 'files': {
        str(path): {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        for path, raw in ((layout.IDENTITY, marker), (layout.PROFILE, locator))}}
    rehash(snapshot, manifest)
    monkeypatch.setattr(validation, 'installation_profile', lambda: profile)
    assert validation.validate_snapshot(snapshot, 'fixture', runtime_prefix=case.host, auth_mode='external-oidc') == manifest
    changed = profile.as_dict(); changed['services']['prefix'] = 'different'
    raw = json.dumps(changed).encode()
    replace_member(snapshot, str(case.mapped(layout.PROFILE)).lstrip('/'), raw)
    manifest['installation']['files'][str(layout.PROFILE)] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    rehash(snapshot, manifest)
    with pytest.raises(ValueError, match='marker or locator differs'):
        validation.validate_snapshot(snapshot, 'fixture', runtime_prefix=case.host, auth_mode='external-oidc')


def test_existing_v3_snapshot_stays_readable_without_new_identity(snapshot):
    before = {p.name: p.read_bytes() for p in snapshot.iterdir()}
    manifest = validation.validate_snapshot(snapshot, 'fixture')
    assert manifest['format'] == validation.FORMAT and 'installation' not in manifest
    assert before == {p.name: p.read_bytes() for p in snapshot.iterdir()}


def test_existing_v4_external_snapshot_stays_readable_without_new_identity(case):
    result = case.backup.backup(case.instance); snapshot = Path(result['backup'])
    manifest = json.loads((snapshot/'manifest.json').read_text())
    manifest['format'] = validation.EXTERNAL_FORMAT; del manifest['installation']
    replace_member(snapshot, str(case.mapped(layout.IDENTITY)).lstrip('/'), None)
    rehash(snapshot, manifest)
    before = {p.name: p.read_bytes() for p in snapshot.iterdir()}
    assert validation.validate_snapshot(snapshot, 'fixture', runtime_prefix=case.host, auth_mode='external-oidc') == manifest
    assert before == {p.name: p.read_bytes() for p in snapshot.iterdir()}
