"""Independent real-checkout bundle and cold CLI proof, with no host actions."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

from host.lifecycle import filesystem


REPOSITORY = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, REPOSITORY / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def actual_bundle(tmp_path_factory):
    temporary = tmp_path_factory.mktemp('real-host-bundle')
    builder = load('review_real_host_builder', 'host/build_bundle.py')
    installer = load('review_real_host_installer', 'host/install_bundle.py')
    assert set(builder.SOURCES) == set(installer.SOURCES)
    output = temporary / 'bundle'
    metadata = builder.build(REPOSITORY, output, source_revision='a'*40)
    digest = hashlib.sha256((output / 'bundle.json').read_bytes()).hexdigest()
    bundle = installer.load_bundle(output, digest)
    physical = temporary / 'root'; physical.mkdir(mode=0o700)
    (physical / 'usr/local/lib').mkdir(parents=True)
    (physical / 'var/lib').mkdir(parents=True)
    with filesystem.Root(physical) as root:
        receipt = installer.install(root, bundle, filesystem)
        assert receipt['filesystem']['phase'] == 'committed'
        for name, content in bundle['payloads'].items():
            assert root.read_bytes(name) == content
    return output, digest, metadata, physical


def file_bytes(root):
    return {str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob('*') if path.is_file()}


def test_real_checkout_bundle_installs_and_cold_inspects_without_source_execution(actual_bundle):
    output, digest, metadata, physical = actual_bundle
    generation = physical / metadata['destination'].lstrip('/')
    before = file_bytes(physical)
    result = subprocess.run([sys.executable, '-I', '-B', str(generation / 'host/install_bundle.py'),
        'inspect', '--bundle', str(output), '--sha256', digest],
        capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {'generation': metadata['generation'],
        'destination': metadata['destination'], 'metadata_sha256': digest, 'mutations': False}
    assert file_bytes(physical) == before
    assert not list(physical.rglob('__pycache__'))


@pytest.mark.parametrize('entry', ['frontend', 'qos', 'frontend_profile', 'certificates'])
def test_real_installed_entry_help_needs_no_operational_sibling_import(actual_bundle, tmp_path, entry):
    _, _, metadata, physical = actual_bundle
    installed = physical / metadata['entrypoints'][entry].lstrip('/')
    before = file_bytes(physical)
    cold = subprocess.run([sys.executable, '-I', '-B', str(installed), '--help'],
        capture_output=True, text=True, timeout=10)
    assert cold.returncode == 0 and 'usage:' in cold.stdout, cold.stderr
    assert file_bytes(physical) == before
    # The identical entrypoint also works alone: no provider, engine, contract,
    # application, protected-source bypass or UID substitution is supplied.
    isolated = tmp_path / installed.name
    isolated.write_bytes(installed.read_bytes())
    alone = subprocess.run([sys.executable, '-I', '-B', str(isolated), '--help'],
        capture_output=True, text=True, timeout=10)
    assert alone.returncode == 0 and 'usage:' in alone.stdout, alone.stderr
    assert not list(tmp_path.rglob('__pycache__'))


def test_real_installed_bootstrap_manifests_pin_exact_entrypoint_closures(actual_bundle):
    _, _, metadata, physical = actual_bundle
    for entry in ('frontend', 'qos', 'frontend_profile'):
        record = metadata['bootstrap'][entry]
        source = physical / record['path'].lstrip('/')
        content = source.read_bytes()
        assert hashlib.sha256(content).hexdigest() == record['sha256']
        manifest = json.loads(content)
        assert set(manifest) == {'format', 'sources'} and manifest['format'] == 1
        if entry == 'frontend_profile':
            assert source.name == 'frontend-profile-sources.json'
            expected = {'host/frontend/existing_profile.py', 'host/frontend/provider.py',
                        'host/frontend/adapter.py', 'host/lifecycle/filesystem.py'}
        else:
            expected = ({'host/frontend/adapter.py', 'host/frontend/provider.py', 'host/lifecycle/filesystem.py'}
                if entry == 'frontend' else
                {'host/installation.py', 'host/qos/applicator.py', 'host/qos/contract.py', 'host/qos/adoption.py',
                 'host/qos/processes.py', 'host/lifecycle/filesystem.py'})
        assert set(manifest['sources']) == expected
        for relative, expected in manifest['sources'].items():
            selected = physical / metadata['destination'].lstrip('/') / relative
            assert hashlib.sha256(selected.read_bytes()).hexdigest() == expected
