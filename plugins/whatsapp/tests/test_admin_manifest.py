"""Pure compilation and real fixture-root publication; never install on a host."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

PLUGIN = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN / 'scripts'))
import admin_manifest as compiler
import build_admin_bundle as builder
from host.lifecycle import filesystem

REVISION = 'a' * 40


def sha(content):
    return hashlib.sha256(content).hexdigest()


def save_metadata(path, metadata):
    (path / 'bundle.json').write_bytes(builder.encoded(metadata))


@pytest.fixture
def bundle(tmp_path):
    path = tmp_path / 'bundle'
    metadata = builder.build_bundle(PLUGIN, path, source_sha=REVISION)
    return path, metadata


def load(path, **kwargs):
    return compiler.load_bundle(path, REVISION, uid=os.getuid(), gid=os.getgid(), **kwargs)


def spec(content):
    return {'sha256': sha(content), 'mode': 0o644, 'uid': os.getuid(), 'gid': os.getgid(), 'retention': 'managed'}


def host_parents(host, manifest):
    (host / 'var/lib').mkdir(parents=True)
    declared = set(manifest['directories'])
    for target in (*manifest['files'], *declared):
        for parent in reversed(Path(target).parents):
            logical = str(parent)
            if logical == '/' or logical in declared or any(str(item) in declared for item in parent.parents):
                continue
            (host / logical.lstrip('/')).mkdir(parents=True, exist_ok=True)


def prepare(compiled, previous):
    return compiler.prepare_action(compiled, previous, adopted_sha256=compiler.manifest_digest(previous))


def test_exact_independent_closure_and_read_only_loading(bundle):
    path, metadata = bundle
    before = {item.relative_to(path): item.read_bytes() for item in path.rglob('*') if item.is_file()}
    digest = sha((path / 'bundle.json').read_bytes())
    result = load(path, expected_metadata_sha256=digest)
    assert result['metadata_sha256'] == digest
    assert result['source_revision'] == REVISION
    assert len(result['manifest']['files']) == 47
    # New administrative helpers are source payloads only: policy, socket and
    # service activation are deliberately absent from this installation plan.
    for helper in ('web_admin_broker.py', 'provisioning_attempt.py', 'restore_runtime.py', 'plugin_skills.py'):
        assert result['manifest']['files'][compiler.PROJECT_SCRIPTS + '/' + helper]['sha256'] == sha(
            (PLUGIN / 'scripts' / helper).read_bytes())
    for helper in ('admin_deployment.py', 'backup_validation.py', 'release_database.py',
                   'backup_schemas/6.sql', 'backup_schemas/7.sql', 'backup_schemas/8.sql'):
        assert result['manifest']['files'][compiler.PROJECT_SCRIPTS + '/' + helper]['sha256'] == sha(
            (PLUGIN / 'scripts' / helper).read_bytes())
    assert not any('web-admin.service' in name or 'broker-policy' in name
                   or name.startswith('/run/') for name in result['manifest']['files'])
    # Both executable copies must be present in the independent exact closure.
    helper_sha = sha((PLUGIN / 'scripts/tenant_database.py').read_bytes())
    for component, destination in (
        ('generation', result['generation']['destination']),
        ('project-scripts', compiler.PROJECT_SCRIPTS),
    ):
        assert result['manifest']['files'][destination + '/tenant_database.py']['sha256'] == helper_sha
        assert metadata['artifacts'][component + '/tenant_database.py']['sha256'] == helper_sha
    assert result['manifest']['files'][compiler.RECEIVER]['sha256'] == metadata['artifacts']['receiver-entry/github_release.py']['sha256']
    assert result['generation']['destination'].endswith(result['generation']['manifest_sha256'])
    assert result['allowed_paths'] == sorted(set(result['manifest']['files']) | set(result['manifest']['directories']))
    assert not any('/recovery-owners/' in item or '/box/' in item for item in result['allowed_paths'])
    assert before == {item.relative_to(path): item.read_bytes() for item in path.rglob('*') if item.is_file()}
    assert all(value['uid'] == os.getuid() and value['gid'] == os.getgid()
               for value in result['manifest']['files'].values())
    assert load(path)['manifest'] == result['manifest']


@pytest.mark.parametrize('change', ['artifact-path', 'directory-path', 'metadata-owner', 'metadata-mode',
                                  'source-revision', 'source-hash', 'builder-hash', 'generation-hash',
                                  'generation-destination', 'generation-protocol', 'extra-artifact', 'cleanup-policy', 'extra-field'])
def test_forged_metadata_cannot_authorize_paths_or_change_the_closed_contract(bundle, change):
    path, metadata = bundle
    artifact = metadata['artifacts']['bootstrap/release_admin.py']
    if change == 'artifact-path': artifact['destination'] = '/etc/ssh/sshd_config'
    elif change == 'directory-path': metadata['directories']['bootstrap']['destination'] = '/etc/ssh'
    elif change == 'metadata-owner': artifact['owner'] = 'bridge'
    elif change == 'metadata-mode': artifact['mode'] = '0777'
    elif change == 'source-revision': metadata['source']['revision'] = 'b' * 40
    elif change == 'source-hash': metadata['source']['files']['scripts/release_admin.py'] = '0' * 64
    elif change == 'builder-hash': metadata['builder']['sha256'] = '0' * 64
    elif change == 'generation-hash': metadata['generation']['manifest_sha256'] = '0' * 64
    elif change == 'generation-destination': metadata['generation']['destination'] += '/extra'
    elif change == 'generation-protocol': metadata['generation']['protocol'] = True
    elif change == 'extra-artifact': metadata['artifacts']['bootstrap/arbitrary.py'] = dict(artifact)
    elif change == 'cleanup-policy': metadata['cleanup_policy']['recursive_directory_removal'] = True
    else: metadata['command'] = 'execute-unapproved-source'
    save_metadata(path, metadata)
    with pytest.raises(compiler.ManifestError): load(path)


@pytest.mark.parametrize('change', ['payload', 'missing', 'extra-file', 'extra-directory', 'symlink-file',
                                  'symlink-directory', 'bytecode', 'world-writable'])
def test_nonphysical_incomplete_or_unexpected_trees_are_rejected(bundle, tmp_path, change):
    path, _ = bundle
    target = path / 'bootstrap/release_admin.py'
    if change == 'payload': target.write_bytes(b'changed source')
    elif change == 'missing': target.unlink()
    elif change == 'extra-file': (path / 'unexpected').write_bytes(b'ignored?')
    elif change == 'extra-directory': (path / 'unused').mkdir()
    elif change == 'symlink-file':
        content = target.read_bytes(); target.unlink()
        outside = tmp_path / 'outside.py'; outside.write_bytes(content); target.symlink_to(outside)
    elif change == 'symlink-directory':
        (path / 'bootstrap').rename(tmp_path / 'outside'); (path / 'bootstrap').symlink_to(tmp_path / 'outside')
    elif change == 'bytecode': (path / 'bootstrap/release_admin.pyc').write_bytes(b'compiled')
    else: target.chmod(0o666)
    with pytest.raises((compiler.ManifestError, filesystem.LifecycleError, FileNotFoundError)): load(path)


def test_revision_is_an_assertion_and_reviewed_digest_pins_exact_metadata(bundle):
    path, metadata = bundle
    original = sha((path / 'bundle.json').read_bytes())
    with pytest.raises(compiler.ManifestError, match='reviewed digest'):
        load(path, expected_metadata_sha256='0' * 64)
    # The builder source is not a payload: do not claim a Git provenance check.
    metadata['source']['files'][builder.BUILDER_SOURCE] = '1' * 64
    metadata['builder']['sha256'] = '1' * 64
    save_metadata(path, metadata)
    assert load(path)['source_revision'] == REVISION
    with pytest.raises(compiler.ManifestError, match='reviewed digest'):
        load(path, expected_metadata_sha256=original)


def test_duplicate_json_and_invalid_identity_rejected(bundle):
    path, _ = bundle
    with pytest.raises(compiler.ManifestError): compiler.load_bundle(path, 'main')
    with pytest.raises(compiler.ManifestError): load(path, expected_metadata_sha256='main')
    data = (path / 'bundle.json').read_bytes()
    (path / 'bundle.json').write_bytes(data.replace(b'{', b'{"format":"duplicate",', 1))
    with pytest.raises(compiler.ManifestError): load(path)


def test_fresh_compiled_action_installs_and_same_active_upgrade_is_identical(bundle, tmp_path):
    compiled = load(bundle[0])
    prepared = prepare(compiled, compiler.empty_manifest())
    host = tmp_path / 'host'; host.mkdir()
    host_parents(host, prepared['action']['after'])
    with filesystem.Root(host) as root:
        receipt = filesystem.reconcile(root, operation_id='a' * 32, payloads=prepared['payloads'], **prepared['action'])
        assert len(receipt['changed']) == 47
        upgraded = prepare(compiled, prepared['action']['after'])
        second = filesystem.reconcile(root, operation_id='b' * 32, payloads=upgraded['payloads'], **upgraded['action'])
        assert second['changed'] == [] and second['quarantine'] == {}
    assert filesystem.equivalent_managed(prepared['active_manifest'], upgraded['active_manifest'])
    assert upgraded['retained_manifest'] == compiler.empty_manifest()


def test_upgrade_retains_old_generations_and_helpers_without_polluting_immutable_tree(bundle, tmp_path):
    compiled = load(bundle[0]); first = prepare(compiled, compiler.empty_manifest())
    host = tmp_path / 'host'; host.mkdir(); host_parents(host, first['action']['after'])
    with filesystem.Root(host) as root:
        filesystem.reconcile(root, operation_id='a' * 32, payloads=first['payloads'], **first['action'])
        previous = copy.deepcopy(first['action']['after'])
        legacy = compiler.LEGACY + '/release_probe.py'
        (host / legacy.lstrip('/')).write_bytes(b'inactive legacy helper')
        (host / legacy.lstrip('/')).chmod(0o644)
        previous['files'][legacy] = spec(b'inactive legacy helper')
        source = tmp_path / 'source'
        for relative in bundle[1]['source']['files']:
            target = source / relative; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(PLUGIN / relative, target)
        changed = source / 'scripts/release_build.py'
        changed.write_bytes(changed.read_bytes() + b'\n# next synthetic generation\n')
        output = tmp_path / 'upgrade'; builder.build_bundle(source, output, source_sha=REVISION)
        newer = load(output)
        upgrade = prepare(newer, previous)
        fresh = prepare(newer, compiler.empty_manifest())
        old_generation = compiled['generation']['destination']
        directory = host / old_generation.lstrip('/')
        old_tree = {item.relative_to(directory): (item.stat().st_ino, item.read_bytes())
                    for item in directory.rglob('*') if item.is_file()}
        legacy_inode = (host / legacy.lstrip('/')).stat().st_ino
        receipt = filesystem.reconcile(root, operation_id='b' * 32, payloads=upgrade['payloads'], **upgrade['action'])
        assert receipt['quarantine'] == {}
        assert upgrade['active_manifest'] == fresh['active_manifest']
        assert len(upgrade['retained_manifest']['files']) == 18
        assert old_generation + '/tenant_database.py' in upgrade['retained_manifest']['files']
        assert upgrade['action']['after'] != fresh['action']['after']
        assert all(value['retention'] == 'retain' for value in upgrade['retained_manifest']['files'].values())
        assert old_tree == {item.relative_to(directory): (item.stat().st_ino, item.read_bytes())
                            for item in directory.rglob('*') if item.is_file()}
        assert (host / legacy.lstrip('/')).stat().st_ino == legacy_inode


def test_configured_bundle_prepare_action_preserves_generation_identity(tmp_path):
    child = '''import json,sys
from pathlib import Path
plugin,output=map(Path,sys.argv[1:])
sys.path.insert(0,str(plugin/'scripts'));sys.path.insert(0,str(plugin.parents[1]))
import installation_layout as layout
layout.select(layout.Installation.from_dict(json.loads((plugin/'deploy/installation.example.json').read_bytes())))
import build_admin_bundle as builder,admin_manifest as compiler
metadata=builder.build_bundle(plugin,output,source_sha='a'*40)
import os
compiled=compiler.load_bundle(output,source_revision='a'*40,uid=os.getuid(),gid=os.getgid(),expected_metadata_sha256=compiler.sha((output/'bundle.json').read_bytes()))
previous=compiler.empty_manifest()
action=compiler.prepare_action(compiled,previous,adopted_sha256=compiler.manifest_digest(previous))
generation=compiled['generation']['destination']+'/manifest.json'
assert json.loads(action['payloads'][generation])['installation_sha256']==layout.active().sha256
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', child, str(PLUGIN), str(tmp_path/'configured')],
                            capture_output=True, text=True, timeout=10)
    assert (result.returncode, result.stdout, result.stderr) == (0, '', '')


@pytest.mark.parametrize('target', ['/etc/ssh/sshd_config', '/var/lib/whatsapp-personal/state.sqlite',
                                   '/usr/local/lib/develative-deploy/whatsapp/arbitrary.py',
                                   '/usr/local/lib/develative-deploy/whatsapp-generations/' + 'a' * 64 + '/arbitrary.py',
                                   '/usr/local/lib/develative-deploy/whatsapp-generations/not-a-digest/release_build.py'])
def test_explicit_adoption_never_broadens_source_destination_policy(bundle, target):
    compiled = load(bundle[0]); previous = compiler.empty_manifest()
    previous['files'][target] = spec(b'forged object')
    with pytest.raises(compiler.ManifestError, match='independent administration closure'):
        prepare(compiled, previous)


def test_adoption_requires_exact_digest_and_preserves_existing_runtime(bundle):
    compiled = load(bundle[0]); previous = compiler.empty_manifest()
    with pytest.raises(compiler.ManifestError, match='adoption digest'):
        compiler.prepare_action(compiled, previous, adopted_sha256='0' * 64)
    previous['files'][compiler.RUNTIME] = spec(b'different legacy runtime')
    with pytest.raises(compiler.ManifestError, match='separate reviewed update'):
        prepare(compiled, previous)
    previous['files'][compiler.RUNTIME] = compiled['manifest']['files'][compiler.RUNTIME]
    result = prepare(compiled, previous)
    assert result['action']['before']['files'][compiler.RUNTIME] == result['action']['after']['files'][compiler.RUNTIME]


def test_compiled_mutations_and_directory_repair_are_refused(bundle):
    compiled = load(bundle[0]); tampered = copy.deepcopy(compiled)
    target = compiler.BOOTSTRAP + '/release_admin.py'
    tampered['manifest']['files'][target]['mode'] = 0o777
    with pytest.raises(compiler.ManifestError, match='permission policy'): prepare(tampered, compiler.empty_manifest())
    tampered = copy.deepcopy(compiled); tampered['payloads'][target] = b'unapproved'
    with pytest.raises(compiler.ManifestError, match='payload differs'): prepare(tampered, compiler.empty_manifest())
    previous = compiler.empty_manifest()
    previous['directories'][compiler.BOOTSTRAP] = {**compiled['manifest']['directories'][compiler.BOOTSTRAP], 'mode': 0o700}
    with pytest.raises(compiler.ManifestError, match='not repair'): prepare(compiled, previous)
