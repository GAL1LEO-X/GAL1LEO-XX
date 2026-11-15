"""Allocation-bound backup capture, old-format compatibility and additive restore."""
import io
import json
from pathlib import Path
import tarfile

import pytest

from test_backup_installation_identity import rehash, replace_member, configured_profile
from test_backup_runtime import prepare_installation
from test_standalone_backup import case
from test_instance_expansion import write
import installation_layout as layout
import backup_validation as validation


def additional(profile, instances, previous=None):
    return profile.with_roster({'format': layout.ROSTER_FORMAT, 'installation_sha256': profile.sha256,
        'revision': 1 if previous is None else previous.roster['revision'] + 1,
        'previous': None if previous is None else previous.roster_sha256,
        'instances': {**({} if previous is None else previous.roster['instances']), **instances}})


def test_capture_binds_exact_allocation_revision_and_snapshot(case, monkeypatch):
    base = configured_profile(case)
    profile = additional(base, {'later': {'account': 'messages-later', 'bridge': 22001, 'gateway': 22009}})
    prepare_installation(case.backup, case.host, monkeypatch, profile)
    write(case.host, profile.roster_pointer(), layout.encoded(layout.roster_pointer_record(profile)))
    write(case.host, profile.roster_snapshot(profile.roster_sha256), profile._roster)
    binding, captured = case.backup.installation_snapshot()
    assert binding['roster_sha256'] == profile.roster_sha256
    assert set(binding['files']) == {str(layout.IDENTITY), str(layout.PROFILE),
                                   profile.roster_pointer(), profile.roster_snapshot(profile.roster_sha256)}
    assert captured[case.mapped(profile.roster_snapshot(profile.roster_sha256))] == profile._roster
    assert binding['identity']['installation_sha256'] == base.sha256


def convert(case, snapshot, profile, *, bind_roster):
    archive = snapshot / 'private-runtime.tar.gz'
    old = str(case.instance.config_dir).lstrip('/')
    new = str(case.mapped(profile.instance_paths('fixture')['configuration'])).lstrip('/')
    with tarfile.open(archive) as source:
        entries = [(m, source.extractfile(m).read() if m.isfile() else None) for m in source]
    payloads = {str(layout.IDENTITY): layout.identity_bytes(profile), str(layout.PROFILE): profile._encoded}
    if bind_roster:
        payloads.update({profile.roster_pointer(): layout.encoded(layout.roster_pointer_record(profile)),
                        profile.roster_snapshot(profile.roster_sha256): profile._roster})
    with tarfile.open(archive, 'w:gz') as target:
        for member, data in entries:
            if member.name == str(case.mapped(layout.IDENTITY)).lstrip('/'):
                continue
            if member.name == old or member.name.startswith(old + '/'):
                member.name = new + member.name[len(old):]
                member.pax_headers = {}
            target.addfile(member, io.BytesIO(data) if data is not None else None)
        for logical, raw in payloads.items():
            info = tarfile.TarInfo(str(case.mapped(logical)).lstrip('/'))
            info.size = len(raw)
            target.addfile(info, io.BytesIO(raw))
    import hashlib
    manifest = json.loads((snapshot / 'manifest.json').read_bytes())
    manifest['format'] = 'whatsapp-isolated-backup-v6' if bind_roster else 'whatsapp-isolated-backup-v5'
    manifest['installation'] = {'identity': layout.identity_record(profile), 'files': {
        logical: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} for logical, raw in payloads.items()}}
    if bind_roster:
        manifest['installation']['roster_sha256'] = profile.roster_sha256
    rehash(snapshot, manifest)
    return manifest


def test_old_initial_snapshot_survives_expansion(case, monkeypatch):
    result = case.backup.backup(case.instance)
    snapshot = Path(result['backup'])
    base = configured_profile(case)
    expected = convert(case, snapshot, base, bind_roster=False)
    expanded = additional(base, {'later': {'account': 'messages-later', 'bridge': 22001, 'gateway': 22009}})
    monkeypatch.setattr(validation, 'installation_profile', lambda: expanded)
    assert validation.validate_snapshot(snapshot, 'fixture', runtime_prefix=case.host,
        auth_mode='external-oidc') == expected


@pytest.mark.parametrize('mutation', ['none', 'second-expansion', 'reassigned-account', 'missing-roster',
                                     'snapshot-corruption', 'old-format'])
def test_new_tenant_backup_proves_compatible_allocation(case, monkeypatch, mutation):
    snapshot = Path(case.backup.backup(case.instance)['backup'])
    base_value = json.loads((Path(__file__).parents[1] / 'deploy/installation.example.json').read_bytes())
    base_value['paths']['project'] = str(case.logical.project_root)
    base = layout.Installation.from_dict(base_value)
    profile = additional(base, {'fixture': {'account': 'messages-fixture', 'bridge': 22001, 'gateway': 22009}})
    manifest = convert(case, snapshot, profile, bind_roster=mutation != 'old-format')
    current = profile
    if mutation in ('second-expansion', 'reassigned-account'):
        current = additional(base, {'later': {'account': 'messages-later', 'bridge': 23001, 'gateway': 23009}}, profile)
        if mutation == 'reassigned-account':
            changed = current.roster
            changed['instances']['fixture']['account'] = 'messages-other'
            current = base.with_roster(changed)
    elif mutation == 'missing-roster':
        current = base
    elif mutation == 'snapshot-corruption':
        logical = profile.roster_snapshot(profile.roster_sha256)
        replace_member(snapshot, str(case.mapped(logical)).lstrip('/'), profile._roster + b' ')
        rehash(snapshot, manifest)
    monkeypatch.setattr(validation, 'installation_profile', lambda: current)
    if mutation in ('none', 'second-expansion'):
        assert validation.validate_snapshot(snapshot, 'fixture', runtime_prefix=case.host,
            auth_mode='external-oidc') == manifest
    else:
        with pytest.raises(ValueError):
            validation.validate_snapshot(snapshot, 'fixture', runtime_prefix=case.host, auth_mode='external-oidc')
