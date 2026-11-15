"""Actual filesystem installation with synthetic sources, never host effects."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

from host.lifecycle import filesystem

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


builder = module('host_install_test_builder', 'host/build_bundle.py')
installer = module('host_install_test_installer', 'host/install_bundle.py')


@pytest.fixture
def prepared(tmp_path):
    source = tmp_path/'source'
    assert set(builder.SOURCES) == set(installer.SOURCES)
    assert builder.BOOTSTRAP_SOURCES == installer.BOOTSTRAP_SOURCES
    for relative in builder.SOURCES:
        path = source/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('raise RuntimeError("payloads must not execute")\n')
    output = tmp_path/'bundle'
    metadata = builder.build(source, output, source_revision='a'*40)
    digest = hashlib.sha256((output/'bundle.json').read_bytes()).hexdigest()
    return output, digest, metadata


def fsroot(tmp_path):
    directory = tmp_path/'fs'; directory.mkdir(mode=0o700)
    (directory/'usr/local/lib').mkdir(parents=True)
    (directory/'var/lib').mkdir(parents=True)
    return filesystem.Root(directory)


def test_cold_cli_inspects_complete_bundle_without_loading_payload(prepared):
    output, digest, metadata = prepared
    result = subprocess.run([sys.executable, '-I', '-B', str(ROOT/'host/install_bundle.py'), 'inspect',
                             '--bundle', str(output), '--sha256', digest], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {'generation': metadata['generation'], 'destination': metadata['destination'],
                                        'metadata_sha256': digest, 'mutations': False}
    assert not list(output.rglob('__pycache__'))


def test_install_is_immutable_idempotent_and_keeps_app_and_other_generations(prepared, tmp_path):
    output, digest, metadata = prepared
    bundle = installer.load_bundle(output, digest)
    with fsroot(tmp_path) as root:
        kept = root.base/'srv/box'; kept.mkdir(parents=True)
        (kept/'current').write_bytes(b'survivor')
        first = installer.install(root, bundle, filesystem)
        second = installer.install(root, bundle, filesystem)
        assert first == second and first['filesystem']['phase'] == 'committed'
        assert not first['services_changed']
        for path, content in bundle['payloads'].items():
            assert root.read_bytes(path) == content
        assert (kept/'current').read_bytes() == b'survivor'
        target = metadata['destination']+'/host/qos/contract.py'
        actual = root.base/target.lstrip('/')
        actual.write_bytes(b'changed by administrator')
        with pytest.raises(filesystem.LifecycleError):
            installer.install(root, bundle, filesystem)
        assert actual.read_bytes() == b'changed by administrator'


@pytest.mark.parametrize('point', ['journal-staging', 'created-directory', 'replaced-file', 'journal-committed'])
def test_crash_resumes_original_intent_without_executing_sources(prepared, tmp_path, point):
    output, digest, _ = prepared
    bundle = installer.load_bundle(output, digest)
    seen = []
    class Crash(Exception): pass
    def crash(event, detail):
        if event == point and not seen:
            seen.append(event); raise Crash()
    with fsroot(tmp_path) as root:
        with pytest.raises(Crash):
            installer.install(root, bundle, filesystem, fault=crash)
    with filesystem.Root(tmp_path/'fs') as root:
        result = installer.install(root, bundle, filesystem)
        assert result['filesystem']['phase'] == 'committed'
        for path, content in bundle['payloads'].items(): assert root.read_bytes(path) == content


@pytest.mark.parametrize('fault', ['destination', 'extra-file', 'source-change', 'bootstrap', 'metadata-digest'])
def test_tampering_is_rejected_before_filesystem_work(prepared, fault):
    output, digest, metadata = prepared
    if fault == 'destination':
        metadata['filesystem_manifest']['files']['/etc/arbitrary'] = copy.deepcopy(
            next(iter(metadata['filesystem_manifest']['files'].values())))
        (output/'bundle.json').write_bytes(builder.encoded(metadata))
        digest = hashlib.sha256((output/'bundle.json').read_bytes()).hexdigest()
    elif fault == 'extra-file': (output/'extra.py').write_text('pass')
    elif fault == 'source-change': (output/builder.SOURCES[0]).write_text('changed')
    elif fault == 'bootstrap': (output/'frontend-sources.json').write_text('{}')
    else: digest = '0'*64
    with pytest.raises(ValueError): installer.load_bundle(output, digest)
