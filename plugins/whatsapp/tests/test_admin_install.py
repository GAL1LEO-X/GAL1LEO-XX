"""Cold CLI inspection and artifact binding; never execute a host advance."""
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from host.lifecycle import evidence, filesystem
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import admin_install
import test_admin_handoff as fixtures


def operation(tmp_path):
    root, plan, payloads, provider = fixtures.fixture(tmp_path, mode='fresh')
    from installation_layout import IDENTITY, Installation, identity_bytes
    fixtures.write(root.base, str(IDENTITY), identity_bytes(Installation.legacy()))
    attestation = '/etc/develative-deploy/inventory/initial.json'
    content = evidence.canonical({'format': 2, 'complete': True, 'invokers': [],
        'manual_policy': {'operation_id': plan['id'], 'unregistered_root_commands': 'frozen-for-operation'}})
    fixtures.write(root.base, attestation, content)
    profile = {'format': 'whatsapp-host-inventory-v1', 'attestation': {
        'path': attestation, 'sha256': hashlib.sha256(content).hexdigest()},
        'retirement_attestation': None,
        'stages': {name: {**item, 'units': {}} for name, item in provider.inventories.items()},
        'final_manifest': plan['actions']['install']['after'],
        'retained_manifest': fixtures.manifest(), 'invokers': [], 'generation_id': 'c'*64}
    plan['inventory_digest'] = evidence.digest(profile)
    data, digest = admin_install.encode_operation(plan, profile, payloads, source_revision='a'*40)
    return root, data, digest


def test_cold_cli_inspects_exact_artifact_without_host_effects(tmp_path):
    root, data, digest = operation(tmp_path)
    try:
        fixtures.write(root.base, '/operation.json', data)
        before = {str(path): path.read_bytes() for path in root.base.rglob('*') if path.is_file()}
        command = [sys.executable, '-I', '-B', str(Path(admin_install.__file__).resolve()),
                   'inspect', '--root', str(root.base), '--operation', '/operation.json', '--sha256', digest]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        receipt = json.loads(result.stdout)
        assert receipt['mutations'] is False and receipt['operation_sha256'] == digest
        assert receipt['mode'] == 'fresh'
        assert before == {str(path): path.read_bytes() for path in root.base.rglob('*') if path.is_file()}
        command[4] = 'advance'
        denied = subprocess.run(command, capture_output=True, text=True)
        assert denied.returncode == 1 and 'isolated tests' in denied.stderr
        assert before == {str(path): path.read_bytes() for path in root.base.rglob('*') if path.is_file()}
    finally:
        root.close()


def test_cold_cli_rejects_changed_source_before_importing_it(tmp_path):
    root, data, digest = operation(tmp_path)
    try:
        fixtures.write(root.base, '/operation.json', data)
        checkout = tmp_path / 'reviewed-source'
        for relative in admin_install.INSTALLER_SOURCES:
            target = checkout / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(admin_install.REPOSITORY / relative, target)
        marker = tmp_path / 'unreviewed-code-ran'
        helper = checkout / 'plugins/whatsapp/scripts/admin_handoff.py'
        helper.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
        result = subprocess.run([sys.executable, '-I', '-B',
            str(checkout / 'plugins/whatsapp/scripts/admin_install.py'), 'inspect',
            '--root', str(root.base), '--operation', '/operation.json', '--sha256', digest],
            capture_output=True, text=True)
        assert result.returncode == 1 and 'source differs' in result.stderr
        assert not marker.exists()
    finally:
        root.close()


@pytest.mark.parametrize('change', ['profile', 'source-closure', 'payload', 'digest'])
def test_changed_operation_cannot_be_advanced(tmp_path, change):
    root, data, digest = operation(tmp_path)
    try:
        value = json.loads(data)
        if change == 'profile':
            value['profile']['generation_id'] = 'd'*64
        elif change == 'source-closure':
            value['installer_sources']['/etc/passwd'] = 'a'*64
        elif change == 'payload':
            name = next(iter(value['payloads']['install']))
            value['payloads']['install'][name] = 'dGFtcGVy'
        else:
            digest = '0'*64
        changed = (json.dumps(value) + '\n').encode()
        if change != 'digest':
            digest = hashlib.sha256(changed).hexdigest()
        with pytest.raises((ValueError, filesystem.LifecycleError)):
            admin_install.decode_operation(changed, digest)
    finally:
        root.close()


def test_source_provenance_includes_the_executed_lifecycle_closure(tmp_path):
    root, data, digest = operation(tmp_path)
    try:
        value, _, _ = admin_install.decode_operation(data, digest)
        assert set(value['installer_sources']) == set(admin_install.INSTALLER_SOURCES)
        for name, expected in value['installer_sources'].items():
            assert hashlib.sha256((admin_install.REPOSITORY / name).read_bytes()).hexdigest() == expected
        assert 'admin_install.py' in ' '.join(value['installer_sources'])
        assert 'services.py' in ' '.join(value['installer_sources'])
    finally:
        root.close()
