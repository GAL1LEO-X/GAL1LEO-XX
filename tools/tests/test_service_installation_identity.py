"""The neutral supervisor selects only the requested product's public identity."""
import hashlib
import json
import os
from pathlib import Path

import pytest

from host.lifecycle import service_client


ROOT = Path(__file__).resolve().parents[2]


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def install_identity(root, owner, profile=None):
    directory = root / 'etc'
    directory.mkdir(exist_ok=True)
    value = profile or {'format': owner + '-installation-legacy-v1'}
    if profile is not None:
        (directory / (owner + '-installation.json')).write_bytes(encoded(value))
    marker = {'format': owner + '-installation-identity-v1',
              'mode': 'configured' if profile is not None else 'legacy',
              'installation_sha256': hashlib.sha256(encoded(value)).hexdigest()}
    target = directory / (owner + '-installation-identity.json')
    target.write_bytes(encoded(marker))
    return target


@pytest.mark.parametrize('owner', ['whatsapp', 'box'])
@pytest.mark.parametrize('configured', [False, True])
def test_only_requested_product_identity_is_required(tmp_path, monkeypatch, owner, configured):
    if owner == 'whatsapp':
        profile = json.loads((ROOT / 'plugins/whatsapp/deploy/installation.example.json').read_text())
        timer = profile['services']['recovery'] + '.timer'
    else:
        # Neutral finite BOX input; this test does not import or require BOX.
        profile = {'format': 'box-installation-v1', 'paths': {
            name: '/srv/media-' + name for name in
            ('code', 'configuration', 'state', 'logs', 'administration_code', 'administration_state', 'backup')},
            'service_prefix': 'cinema', 'accounts': {}, 'network_namespace': 'cinema-net', 'network_group': 'cinema-net'}
        timer = 'cinema-recovery.timer'
    install_identity(tmp_path, owner, profile if configured else None)
    foreign = 'box' if owner == 'whatsapp' else 'whatsapp'
    (tmp_path / 'etc' / (foreign + '-installation-identity.json')).write_text('invalid foreign JSON')
    (tmp_path / 'etc' / (foreign + '-installation.json')).symlink_to('/missing-foreign-profile')
    read = service_client._public_record
    visited = []

    def observed(path, **kwargs):
        visited.append(path.name)
        assert path.name.startswith(owner + '-')
        return read(path, **kwargs)

    monkeypatch.setattr(service_client, '_public_record', observed)
    monkeypatch.setattr(service_client, 'LEASES', dict(service_client.LEGACY_LEASES))
    monkeypatch.setattr(service_client, 'TIMERS', dict(service_client.LEGACY_TIMERS))
    operation = 'enable-' + ('wa' if owner == 'whatsapp' else 'box') + '-recovery'
    command = service_client.command(owner, operation, root=tmp_path, authority=os.getuid())
    assert command == ['/usr/bin/systemctl', 'enable', '--',
                       timer if configured else service_client.LEGACY_TIMERS[owner]]
    assert visited
    assert service_client.LEASES[foreign] == service_client.LEGACY_LEASES[foreign]


@pytest.mark.parametrize('owner', ['whatsapp', 'box'])
def test_missing_identity_never_selects_legacy(tmp_path, owner):
    with pytest.raises(FileNotFoundError):
        service_client.command(owner, 'reload-definitions', root=tmp_path, authority=os.getuid())


@pytest.mark.parametrize('owner', ['whatsapp', 'box'])
def test_legacy_identity_rejects_unexpected_locator(tmp_path, owner):
    install_identity(tmp_path, owner)
    (tmp_path / 'etc' / (owner + '-installation.json')).write_text('{}')
    with pytest.raises(RuntimeError, match='Legacy identity'):
        service_client.command(owner, 'reload-definitions', root=tmp_path, authority=os.getuid())


def test_configured_identity_rejects_loss_and_unapproved_change(tmp_path):
    profile = json.loads((ROOT / 'plugins/whatsapp/deploy/installation.example.json').read_text())
    install_identity(tmp_path, 'whatsapp', profile)
    target = tmp_path / 'etc/whatsapp-installation.json'
    profile['services']['recovery'] = 'different-recovery'
    target.write_bytes(encoded(profile))
    with pytest.raises(RuntimeError, match='independent identity'):
        service_client.command('whatsapp', 'reload-definitions', root=tmp_path, authority=os.getuid())
    target.unlink()
    with pytest.raises(FileNotFoundError):
        service_client.command('whatsapp', 'reload-definitions', root=tmp_path, authority=os.getuid())


@pytest.mark.parametrize('kind', ['symlink', 'writable', 'duplicate', 'oversized'])
def test_marker_must_be_protected_bounded_unique_json(tmp_path, kind):
    marker = install_identity(tmp_path, 'whatsapp')
    if kind == 'symlink':
        original = marker.with_suffix('.copy')
        marker.rename(original)
        marker.symlink_to(original)
    elif kind == 'writable':
        marker.chmod(0o666)
    elif kind == 'duplicate':
        marker.write_text('{"format":1,"format":2}')
    else:
        marker.write_bytes(b' ' * 131073)
    with pytest.raises(RuntimeError):
        service_client.command('whatsapp', 'reload-definitions', root=tmp_path, authority=os.getuid())
