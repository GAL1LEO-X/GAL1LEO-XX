"""Public installation identity: alternatives, isolation and rejected authority."""
import copy
import importlib.util
from pathlib import Path
import sys
import os
import json
import subprocess
from unittest.mock import patch

import pytest


SOURCE = Path(__file__).resolve().parents[2] / 'plugins/whatsapp/sally_whatsapp/installation.py'
spec = importlib.util.spec_from_file_location('whatsapp_installation_profile_test', SOURCE)
installation = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = installation
spec.loader.exec_module(installation)


def profile():
    return {'format': installation.FORMAT,
        'paths': {'project': '/srv/messages/app', 'configuration': '/etc/messages',
                  'state': '/var/lib/messages-data', 'gateway': '/var/lib/messages-gateways',
                  'backup': '/var/backups/messages',
                  'administration_code': '/usr/local/lib/messages-admin',
                  'administration_state': '/var/lib/messages-admin'},
        'services': {'prefix': 'messages', 'recovery': 'messages-recovery'},
        'accounts': {'personal': 'messages-owner', 'business': 'messages-work'},
        'ports': {'personal': {'bridge': 19001, 'gateway': 19009},
                  'business': {'bridge': 21005, 'gateway': 21013}},
        'authentication': 'external-oidc', 'frontend': 'existing'}


def test_alternative_names_roots_and_nonconsecutive_ports_are_one_identity():
    value = installation.Installation.from_dict(profile())
    assert value.service('personal') == 'messages-personal'
    assert value.account('business') == 'messages-work'
    assert value.instance_paths('business') == {
        'configuration': '/etc/messages/business', 'state': '/var/lib/messages-data/business',
        'gateway': '/var/lib/messages-gateways/business'}
    assert value.instance_ports('personal') == {'bridge': 19001, 'gateway': 19009}
    assert '/srv/openai-codex' not in value._encoded.decode()
    assert not value.compatibility


def test_identity_is_order_independent_and_cannot_be_changed_through_returned_data():
    original = profile()
    value = installation.Installation.from_dict(original)
    original['paths']['project'] = '/srv/changed'
    returned = value.as_dict()
    returned['accounts']['personal'] = 'different'
    reordered = dict(reversed(list(profile().items())))
    assert value.sha256 == installation.Installation.from_dict(reordered).sha256
    assert value.path('project') == '/srv/messages/app'
    assert value.account('personal') == 'messages-owner'


@pytest.mark.parametrize('bad', ['/etc', '/proc', '/sys', '/dev', '/srv/messages/../other', '/srv/messages/',
    '/srv//messages', '/srv/messages\nother', '/srv/messages;touch-x', 'relative/path'])
def test_roots_cannot_escape_the_selected_application_or_select_shared_system_dirs(bad):
    data = profile()
    data['paths']['project'] = bad
    with pytest.raises(ValueError):
        installation.Installation.from_dict(data)


def test_writable_data_and_administrative_or_code_roots_must_not_overlap():
    data = profile()
    data['paths']['administration_state'] = data['paths']['state'] + '/admin'
    with pytest.raises(ValueError, match='separate'):
        installation.Installation.from_dict(data)


@pytest.mark.parametrize('name', ['root', 'www-data', 'name with space', '-option', 'user;command'])
def test_account_configuration_does_not_grant_shared_or_injected_identities(name):
    data = profile()
    data['accounts']['personal'] = name
    with pytest.raises(ValueError):
        installation.Installation.from_dict(data)


def test_instances_cannot_share_users_or_ports():
    for field in ['accounts', 'ports']:
        data = profile()
        data[field]['business'] = copy.deepcopy(data[field]['personal'])
        with pytest.raises(ValueError):
            installation.Installation.from_dict(data)


@pytest.mark.parametrize('slug', ['personal', 'business'])
def test_recovery_cannot_replace_a_configured_bridge_unit(slug):
    data = profile()
    data['services']['recovery'] = data['services']['prefix'] + '-' + slug
    with pytest.raises(ValueError, match='distinct unit names'):
        installation.Installation.from_dict(data)


@pytest.mark.parametrize('port', [True, 443, 65536, '19000'])
def test_ports_remain_typed_unprivileged_network_inputs(port):
    data = profile()
    data['ports']['personal']['bridge'] = port
    with pytest.raises(ValueError):
        installation.Installation.from_dict(data)


def test_profile_contains_no_secret_or_arbitrary_command_extension():
    for field, value in [('password', 'not-a-setting'), ('command', 'arbitrary')]:
        data = profile()
        data[field] = value
        with pytest.raises(ValueError, match='fields'):
            installation.Installation.from_dict(data)


def test_legacy_layout_is_an_explicit_distinct_identity():
    old = installation.Installation.legacy()
    assert old.compatibility
    assert old.service('personal') == 'whatsapp-personal'
    assert old.account('personal') == 'whatsappbridge'
    assert old.instance_paths('personal')['gateway'] == '/var/lib/whatsapp-personal-waha'
    assert old.sha256 != installation.Installation.from_dict(profile()).sha256


def instance(data=None):
    plugin=SOURCE.parents[1]
    if str(plugin) not in sys.path:
        sys.path.insert(0,str(plugin))
    from sally_whatsapp import installation as runtime_layout
    with patch.object(runtime_layout, '_selected', runtime_layout.Installation.legacy()), \
            patch.object(runtime_layout, '_locator_state', None):
        from sally_whatsapp.tenancy import Instance
    return Instance('personal','Example Owner','idp|owner',19001,
        public_hostname='messages.example.org',issuer='https://identity.example.net/realm',
        jwks_url='https://keys.example.net/keys.json',auth_mode='external-oidc',
        oauth_client_id='registered-mcp',pairing_client_id='registered-pairing',
        installation=profile() if data is None else data)


def test_one_profile_controls_all_instance_runtime_artifacts():
    owner=instance()
    from sally_whatsapp.tenancy import deployment_artifacts
    artifacts=deployment_artifacts(owner,template_root=SOURCE.parents[1]/'deploy')
    assert 'User=messages-owner' in artifacts['bridge']
    assert 'WorkingDirectory=/srv/messages/app' in artifacts['bridge']
    assert '/etc/messages/personal/config.toml' in artifacts['bridge']
    assert 'ReadWritePaths=/var/lib/messages-data/personal' in artifacts['bridge']
    assert 'StateDirectory=' not in artifacts['bridge']
    assert '127.0.0.1:19009:3000' in artifacts['gateway']
    assert '/var/lib/messages-gateways/personal/sessions' in artifacts['gateway']
    assert 'CPUAffinity=0-3' not in artifacts['gateway']
    assert 'http://127.0.0.1:19001' in artifacts['apache']
    assert all('/srv/openai-codex' not in text for text in artifacts.values())


def test_instance_record_retains_the_configuration_for_later_management():
    owner=instance()
    from sally_whatsapp.tenancy import Instance
    reloaded=Instance(**owner.record())
    assert reloaded.service_user==owner.service_user
    assert reloaded.state_dir==owner.state_dir
    assert reloaded.gateway_port==19009
    assert reloaded.project_root.as_posix()=='/srv/messages/app'
    # Mutating the caller's dict cannot redirect a validated operation.
    owner.installation['paths']['project']='/srv/other'
    assert owner.record()['installation']['paths']['project']=='/srv/messages/app'


def test_instance_cannot_override_the_profile_port_or_enable_legacy_auth():
    from dataclasses import replace
    owner=instance()
    with pytest.raises(ValueError,match='port differs'):
        replace(owner,bridge_port=19002)
    with pytest.raises(ValueError):
        replace(owner,auth_mode='managed-authelia')


def test_backend_host_and_administrative_copies_are_byte_identical():
    root=SOURCE.parents[3]
    assert SOURCE.read_bytes()==(SOURCE.parents[1]/'scripts/installation_layout.py').read_bytes()
    assert SOURCE.read_bytes()==(root/'host/installation.py').read_bytes()


@pytest.mark.skipif(os.name!='posix',reason='Protected no-follow profile reads require POSIX')
def test_physical_protected_profile_and_digest_are_required(tmp_path):
    selected=tmp_path/'public.json';selected.write_bytes(installation.encoded(profile()));selected.chmod(0o600)
    value=installation.read_profile(selected,trusted_uid=os.getuid(),trust_root=tmp_path)
    assert value.sha256==installation.Installation.from_dict(profile()).sha256
    with pytest.raises(ValueError,match='digest'):
        installation.read_profile(selected,expected_sha256='0'*64,trusted_uid=os.getuid(),trust_root=tmp_path)
    selected.chmod(0o666)
    with pytest.raises(ValueError,match='protected'):
        installation.read_profile(selected,trusted_uid=os.getuid(),trust_root=tmp_path)
    selected.chmod(0o600);alias=tmp_path/'alias.json';alias.symlink_to(selected)
    with pytest.raises(ValueError,match='physical'):
        installation.read_profile(alias,trusted_uid=os.getuid(),trust_root=tmp_path)


def write_identity_fixture(root, selected=None):
    selected = selected or installation.Installation.from_dict(profile())
    marker = root / installation.IDENTITY.relative_to('/')
    locator = root / installation.PROFILE.relative_to('/')
    marker.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker.write_bytes(installation.identity_bytes(selected)); marker.chmod(0o600)
    if not selected.compatibility:
        locator.write_bytes(selected._encoded); locator.chmod(0o600)
    return marker, locator


def cold_start(root):
    # Re-imports from disk in a fresh interpreter with no cached selection.
    # The only redirection is an explicit filesystem fixture root in test code.
    code = """import importlib.util, os, sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('cold_installation',sys.argv[1])
layout=importlib.util.module_from_spec(spec);sys.modules[spec.name]=layout;spec.loader.exec_module(layout)
original=layout.read_installation
layout.read_installation=lambda:original(root=Path(sys.argv[2]),trusted_uid=os.getuid())
try:
    print(layout.active().sha256)
except ValueError as error:
    print(str(error),file=sys.stderr);sys.exit(23)
"""
    return subprocess.run([sys.executable, '-I', '-B', '-c', code, str(SOURCE), str(root)],
                          capture_output=True, text=True, timeout=10)


@pytest.mark.skipif(os.name!='posix',reason='Protected profile fixture requires POSIX')
def test_locator_loss_or_identity_change_does_not_fall_back_to_legacy(tmp_path, monkeypatch):
    _, locator = write_identity_fixture(tmp_path)
    original = installation.read_installation
    monkeypatch.setattr(installation, '_selected', None)
    monkeypatch.setattr(installation, '_locator_state', None)
    monkeypatch.setattr(installation, 'read_installation',
                        lambda: original(root=tmp_path, trusted_uid=os.getuid()))
    assert not installation.active().compatibility
    locator.unlink()
    with pytest.raises(ValueError, match='locator is missing'):
        installation.active()


@pytest.mark.skipif(os.name!='posix',reason='Protected cold-start fixtures require POSIX')
@pytest.mark.parametrize('change', ['none', 'locator-loss', 'marker-loss', 'both-loss',
                                    'locator-drift', 'locator-replacement', 'legacy-marker'])
def test_cold_start_requires_independent_identity_and_exact_locator(tmp_path, change):
    marker, locator = write_identity_fixture(tmp_path)
    if change in ('locator-loss', 'both-loss'):
        locator.unlink()
    if change in ('marker-loss', 'both-loss'):
        marker.unlink()
    if change in ('locator-drift', 'locator-replacement'):
        altered = profile(); altered['paths']['state'] = '/var/lib/other-messages'
        if change == 'locator-replacement':
            replacement = locator.with_suffix('.replacement')
            replacement.write_bytes(installation.encoded(altered)); replacement.chmod(0o600)
            replacement.replace(locator)
        else:
            locator.write_bytes(installation.encoded(altered))
    if change == 'legacy-marker':
        marker.write_bytes(installation.identity_bytes(installation.Installation.legacy()))
    result = cold_start(tmp_path)
    if change == 'none':
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == installation.Installation.from_dict(profile()).sha256
    else:
        assert result.returncode == 23, result.stderr
        assert not result.stdout.strip()


@pytest.mark.skipif(os.name!='posix',reason='Protected cold-start fixtures require POSIX')
def test_legacy_cold_start_requires_explicit_marker_and_cannot_ignore_a_locator(tmp_path):
    marker, locator = write_identity_fixture(tmp_path, installation.Installation.legacy())
    result = cold_start(tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == installation.Installation.legacy().sha256
    locator.write_bytes(installation.encoded(profile())); locator.chmod(0o600)
    assert cold_start(tmp_path).returncode == 23
    locator.unlink(); marker.unlink()
    assert cold_start(tmp_path).returncode == 23


@pytest.mark.skipif(os.name!='posix',reason='Protected identity fixture requires POSIX')
@pytest.mark.parametrize('change', ['writable-marker', 'writable-parent', 'symlink-marker',
                                    'symlink-locator', 'duplicate-field', 'oversized-marker',
                                    'wrong-legacy-digest'])
def test_identity_marker_is_bounded_physical_and_administratively_protected(tmp_path, change):
    marker, locator = write_identity_fixture(tmp_path)
    if change == 'writable-marker': marker.chmod(0o666)
    elif change == 'writable-parent': marker.parent.chmod(0o777)
    elif change in ('symlink-marker', 'symlink-locator'):
        selected = marker if change == 'symlink-marker' else locator
        physical = selected.with_suffix('.physical'); selected.rename(physical)
        selected.symlink_to(physical)
    elif change == 'duplicate-field':
        marker.write_text('{"format":"wrong","format":"' + installation.IDENTITY_FORMAT + '"}')
    elif change == 'oversized-marker': marker.write_bytes(b' ' * 131073)
    else:
        value = installation.identity_record(installation.Installation.legacy())
        value['installation_sha256'] = '0' * 64
        marker.write_bytes(installation.encoded(value)); locator.unlink()
    with pytest.raises(ValueError):
        installation.read_installation(root=tmp_path, trusted_uid=os.getuid())


@pytest.mark.skipif(os.name!='posix',reason='Protected identity fixture requires POSIX')
def test_marker_drift_or_replacing_both_files_cannot_rebind_a_running_operation(tmp_path, monkeypatch):
    marker, locator = write_identity_fixture(tmp_path)
    original = installation.read_installation
    monkeypatch.setattr(installation, '_selected', None)
    monkeypatch.setattr(installation, '_locator_state', None)
    monkeypatch.setattr(installation, 'read_installation',
                        lambda: original(root=tmp_path, trusted_uid=os.getuid()))
    expected = installation.active().sha256
    changed = profile(); changed['services']['prefix'] = 'other'
    changed = installation.Installation.from_dict(changed)
    marker.write_bytes(installation.identity_bytes(changed)); locator.write_bytes(changed._encoded)
    with pytest.raises(ValueError, match='changed'):
        installation.active()
    assert installation._selected.sha256 == expected


@pytest.mark.skipif(os.name!='posix',reason='Protected administration bundle requires POSIX')
def test_alternative_profile_compiles_and_independently_validates_administration(tmp_path):
    plugin=SOURCE.parents[1]
    code='''import json,sys,os
from pathlib import Path
sys.path.insert(0,sys.argv[1]+'/scripts')
import installation_layout as layout
profile=layout.select(layout.Installation.from_dict(json.loads(sys.argv[3])))
import build_admin_bundle as builder
import admin_manifest as validator
output=Path(sys.argv[2])
metadata=builder.build_bundle(Path(sys.argv[1]),output,source_sha='a'*40)
compiled=validator.load_bundle(output,'a'*40,uid=os.getuid(),gid=os.getgid(),expected_metadata_sha256=builder.digest(builder.encoded(metadata)))
assert metadata['format']=='whatsapp-admin-bundle-v2'
assert metadata['installation_sha256']==profile.sha256
assert '/etc/systemd/system/messages-recovery.service' in compiled['manifest']['files']
assert all('/srv/openai-codex' not in path for path in compiled['manifest']['files'])
assert '/usr/local/lib/messages-admin/whatsapp-bootstrap/release_entry.py' in (output/'systemd/develative-whatsapp-recovery.service').read_text()
manifest=json.loads((output/'generation/manifest.json').read_bytes())
assert manifest['installation_sha256']==profile.sha256
print('configured administration compiled and independently validated')
'''
    result=subprocess.run([sys.executable,'-I','-B','-c',code,str(plugin),str(tmp_path/'bundle'),json.dumps(profile())],
                          capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr


@pytest.mark.skipif(os.name!='posix',reason='Protected identity fixture requires POSIX')
def test_whatsapp_startup_does_not_read_or_require_box_identity(tmp_path, monkeypatch):
    write_identity_fixture(tmp_path)
    # The normal cold-start test has only WhatsApp files. An unrelated broken
    # BOX installation must also have no effect on WhatsApp admission.
    foreign_marker = tmp_path / 'etc/box-installation-identity.json'
    foreign_locator = tmp_path / 'etc/box-installation.json'
    foreign_marker.write_bytes(b'unrelated invalid BOX marker\n')
    foreign_locator.symlink_to(tmp_path / 'unavailable-box-profile')
    observed = []
    original = installation._read_protected

    def read_own(path, **kwargs):
        observed.append(Path(path).name)
        assert Path(path).name not in (foreign_marker.name, foreign_locator.name)
        return original(path, **kwargs)

    monkeypatch.setattr(installation, '_read_protected', read_own)
    assert not installation.read_installation(root=tmp_path, trusted_uid=os.getuid()).compatibility
    assert set(observed) == {installation.IDENTITY.name, installation.PROFILE.name}
    assert cold_start(tmp_path).returncode == 0
    assert foreign_marker.read_bytes() == b'unrelated invalid BOX marker\n'
    assert foreign_locator.is_symlink()


@pytest.mark.skipif(os.name!='posix',reason='Protected identity fixture requires POSIX')
def test_installed_bootstrap_preserves_continuous_identity_checks(tmp_path, monkeypatch):
    marker, locator = write_identity_fixture(tmp_path)
    monkeypatch.setattr(installation, '_selected', None)
    monkeypatch.setattr(installation, '_locator_state', None)
    monkeypatch.setattr(installation, '_installed_context', None)
    selected = installation.activate_installation(root=tmp_path, trusted_uid=os.getuid())
    assert installation.active().sha256 == selected.sha256
    # Even selecting the same trusted object must not turn off installed checks.
    installation.select(selected)
    locator.unlink()
    with pytest.raises(ValueError, match='locator is missing'):
        installation.active()
    locator.write_bytes(selected._encoded); locator.chmod(0o600)
    marker.unlink()
    with pytest.raises(ValueError, match='identity is missing'):
        installation.active()


@pytest.mark.skipif(os.name!='posix',reason='Protected identity fixture requires POSIX')
def test_installed_bootstrap_cannot_switch_to_another_fixture_root(tmp_path, monkeypatch):
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir(mode=0o700); second.mkdir(mode=0o700)
    write_identity_fixture(first); write_identity_fixture(second)
    monkeypatch.setattr(installation, '_selected', None)
    monkeypatch.setattr(installation, '_locator_state', None)
    monkeypatch.setattr(installation, '_installed_context', None)
    installation.activate_installation(root=first, trusted_uid=os.getuid())
    with pytest.raises(ValueError, match='context is already pinned'):
        installation.activate_installation(root=second, trusted_uid=os.getuid())


@pytest.fixture(params=['ordinary', 'overlapping-template-values'])
def cold_configured_artifacts(tmp_path, request):
    """Import tenancy only after activating a real protected configured fixture."""
    value = profile()
    hostname = 'messages.example.org'
    image = 'registry.example.org/gateway@sha256:' + 'a' * 64
    if request.param == 'overlapping-template-values':
        value['paths']['project'] = '/srv/messages/srv/openai-codex/projects/whatsapp-personal-8820'
        value['paths']['configuration'] = '/etc/messages-8821'
        value['paths']['state'] = '/var/lib/messages-data-8820'
        value['paths']['gateway'] = '/var/lib/messages-gateway-8820-8821'
        value['services']['prefix'] = 'messages-8820'
        value['ports']['personal'] = {'bridge': 18821, 'gateway': 18820}
        hostname = 'messages8820.example.org'
        image = 'registry8820.example.org/gateway8821@sha256:' + '8820' * 16
    identity_root = tmp_path / 'identity'
    identity_root.mkdir(mode=0o700)
    write_identity_fixture(identity_root, installation.Installation.from_dict(value))
    templates = tmp_path / 'reviewed-templates'; templates.mkdir()
    plugin = SOURCE.parents[1]
    for name in ('whatsapp-personal.service', 'whatsapp-waha.container', 'apache-whatsapp.conf.in'):
        (templates / name).write_bytes((plugin / 'deploy' / name).read_bytes())
    (templates / 'images.lock.json').write_text(json.dumps({'waha_image': image}))
    code = """import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from sally_whatsapp import installation
assert 'sally_whatsapp.tenancy' not in sys.modules
selected=installation.activate_installation(root=Path(sys.argv[2]),trusted_uid=os.getuid())
from sally_whatsapp import tenancy
assert tenancy.ROOT==Path(selected.path('project'))
owner=tenancy.Instance('personal','Example Owner','idp|owner',selected.instance_ports('personal')['bridge'],
    public_hostname=sys.argv[4],issuer='https://identity.example.net/realm',
    jwks_url='https://keys.example.net/keys.json',auth_mode='external-oidc',
    oauth_client_id='registered-mcp',pairing_client_id='registered-pairing',installation=selected.as_dict())
print(json.dumps(tenancy.deployment_artifacts(owner,template_root=Path(sys.argv[3]))))
"""
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(plugin),
                             str(identity_root), str(templates), hostname],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return value, hostname, image, json.loads(result.stdout)


def test_cold_configured_bridge_uses_the_selected_project_and_exact_paths(cold_configured_artifacts):
    profile, _, _, artifacts = cold_configured_artifacts
    paths = profile['paths']; text = artifacts['bridge']
    assert 'WorkingDirectory=' + paths['project'] + '\n' in text
    assert ('ExecStart=' + paths['project'] + '/.venv/bin/python -m sally_whatsapp.cli --config '
            + paths['configuration'] + '/personal/config.toml serve\n') in text
    assert 'ReadWritePaths=' + paths['state'] + '/personal\n' in text
    assert 'StateDirectory=' not in text


def test_cold_configured_quadlet_keeps_operator_ports_paths_and_image_verbatim(cold_configured_artifacts):
    profile, _, image, artifacts = cold_configured_artifacts
    ports = profile['ports']['personal']; text = artifacts['gateway']
    assert 'PublishPort=127.0.0.1:' + str(ports['gateway']) + ':3000\n' in text
    assert 'Environment=WAHA_BASE_URL=http://127.0.0.1:' + str(ports['gateway']) + '\n' in text
    assert 'http://10.0.2.2:' + str(ports['bridge']) + '/webhooks/waha' in text
    assert 'Volume=' + profile['paths']['gateway'] + '/personal/sessions:/app/.sessions\n' in text
    assert 'Image=' + image + '\n' in text
    assert 'CPUAffinity=' not in text


def test_cold_configured_apache_keeps_hostname_and_tls_lineage_verbatim(cold_configured_artifacts):
    profile, hostname, _, artifacts = cold_configured_artifacts
    text = artifacts['apache']
    assert 'ServerName ' + hostname + '\n' in text
    assert '/etc/letsencrypt/live/' + hostname + '/fullchain.pem\n' in text
    assert '/etc/letsencrypt/live/' + hostname + '/privkey.pem\n' in text
    assert 'http://127.0.0.1:' + str(profile['ports']['personal']['bridge']) + '/mcp\n' in text
    assert '/'+profile['services']['prefix']+'-personal-error.log\n' in text
