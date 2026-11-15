"""Pure preparation of an immutable host closure, independent from app paths."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('host_bundle_tests', ROOT / 'host/build_bundle.py')
bundle = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(bundle)


@pytest.fixture
def source(tmp_path):
    root = tmp_path / 'source'
    for name in bundle.SOURCES:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('# synthetic source must never execute\nraise RuntimeError("not executable")\n')
    return root


def tree(root):
    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob('*') if path.is_file()}


def test_exact_host_closure_has_no_application_owned_destinations(source, tmp_path):
    first, second = tmp_path / 'fresh', tmp_path / 'upgrade'
    metadata = bundle.build(source, first, source_revision='a'*40)
    other = bundle.build(source, second, source_revision='a'*40)
    assert metadata == other and tree(first) == tree(second)
    assert metadata['owner'] == 'host' and metadata['application_removal'] == 'retain'
    assert set(tree(first)) == set(bundle.SOURCES) | {'manifest.json', 'bundle.json'} | {
        entry.replace('_', '-') + '-sources.json' for entry in bundle.BOOTSTRAP_SOURCES}
    assert metadata['generation'] == hashlib.sha256((first / 'manifest.json').read_bytes()).hexdigest()
    for path, spec in metadata['filesystem_manifest']['files'].items():
        assert path.startswith(bundle.DESTINATION + '/' + metadata['generation'] + '/')
        assert spec['retention'] == 'retain' and spec['uid'] == spec['gid'] == 0
        relative = path.removeprefix(metadata['destination'] + '/')
        assert spec['sha256'] == hashlib.sha256((first / relative).read_bytes()).hexdigest()
    assert not any('/whatsapp/' in path or '/box/' in path for path in metadata['filesystem_manifest']['files'])
    for entry, sources in bundle.BOOTSTRAP_SOURCES.items():
        selected = first / (entry.replace('_', '-') + '-sources.json')
        bootstrap = json.loads(selected.read_bytes())
        assert bootstrap == {'format': 1, 'sources': {name: metadata['source_hashes'][name] for name in sources}}
        assert metadata['bootstrap'][entry] == {'path': metadata['destination']+'/'+selected.name,
                                               'sha256': hashlib.sha256(selected.read_bytes()).hexdigest()}
        assert selected.name in json.loads((first/'manifest.json').read_bytes())['files']


@pytest.mark.parametrize('fault', ['missing', 'symlink', 'existing-output'])
def test_invalid_source_never_overwrites_prior_output(source, tmp_path, fault):
    output = tmp_path / 'bundle'
    selected = source / bundle.SOURCES[0]
    if fault == 'missing':
        selected.unlink()
    elif fault == 'symlink':
        selected.unlink(); selected.symlink_to(source / bundle.SOURCES[1])
    else:
        output.mkdir(); (output / 'preserve').write_bytes(b'existing')
    with pytest.raises((ValueError, OSError)):
        bundle.build(source, output, source_revision='a'*40)
    if fault == 'existing-output':
        assert tree(output) == {'preserve': b'existing'}
    else:
        assert not output.exists()


def test_changed_source_changes_generation_without_claiming_git_provenance(source, tmp_path):
    before = bundle.build(source, tmp_path / 'before', source_revision='a'*40)
    (source / bundle.SOURCES[0]).write_text('# changed bytes\n')
    after = bundle.build(source, tmp_path / 'after', source_revision='a'*40)
    assert before['generation'] != after['generation']
    assert after['revision_verification'] == 'caller-asserted'
    assert after['source_revision'] == before['source_revision']
