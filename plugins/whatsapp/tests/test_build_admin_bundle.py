"""Local packaging only: synthetic source copies, no host installation or services."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

import pytest

PLUGIN = Path(__file__).resolve().parents[1]
SCRIPTS = PLUGIN / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import build_admin_bundle as builder

REVISION = 'a' * 40


@pytest.fixture
def source(tmp_path):
    root = tmp_path / 'source'
    names = {*(('scripts/' + name) for name in (*builder.BOOTSTRAP_FILES,
               *builder.GENERATION_FILES, *builder.PROJECT_FILES)),
             *(('deploy/' + name) for name in builder.UNIT_FILES), builder.BUILDER_SOURCE,
             'scripts/release_receiver_entry.py'}
    for name in names:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PLUGIN / name, target)
    return root


def tree(root):
    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob('*') if path.is_file()}


def build(source, tmp_path, name='bundle'):
    target = tmp_path / name
    metadata = builder.build_bundle(source, target, source_sha=REVISION)
    return target, metadata


def test_complete_exact_generation_and_independent_component_inventory(source, tmp_path):
    output, metadata = build(source, tmp_path)
    contents = tree(output)
    manifest_bytes = contents['generation/manifest.json']
    manifest = json.loads(manifest_bytes)
    assert set(manifest) == {'protocol', 'files'} and manifest['protocol'] == 1
    # Independent list: additions to the builder require a contract decision.
    expected = {'installation_layout.py', 'github_release.py', 'github_release_common.py', 'release_build.py',
                'release_database.py', 'release_transaction.py', 'release_backup.py',
                'release_recover.py', 'release_probe.py', 'backup_validation.py',
                'state_enrollment.py', 'release_runtime.py', 'tenant_database.py',
                'backup_schemas/6.sql', 'backup_schemas/7.sql', 'backup_schemas/8.sql'}
    assert set(manifest['files']) == expected
    assert set(tree(output / 'generation')) == expected | {'manifest.json'}
    assert 'release_admin.py' not in manifest['files']
    assert 'release_entry.py' not in manifest['files']
    assert set(contents) == set(metadata['artifacts']) | {'bundle.json'}
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    assert metadata['generation']['manifest_sha256'] == manifest_sha
    assert metadata['generation']['destination'] == builder.GENERATIONS + '/' + manifest_sha
    for name, value in metadata['artifacts'].items():
        assert value['sha256'] == hashlib.sha256(contents[name]).hexdigest()
        assert value['owner'] == value['group'] == 'root'
        assert value['mode'] == '0644'
        if value['source'] is not None:
            assert contents[name] == (source / value['source']).read_bytes()
    for name, value in manifest['files'].items():
        assert value == metadata['artifacts']['generation/' + name]['sha256']
    assert metadata['source']['revision'] == REVISION
    assert metadata['source']['revision_verification'] == 'caller-asserted'
    assert metadata['builder']['sha256'] == hashlib.sha256((source / builder.BUILDER_SOURCE).read_bytes()).hexdigest()
    assert metadata['source']['files'][builder.BUILDER_SOURCE] == metadata['builder']['sha256']
    assert metadata['builder']['included_as_artifact'] is False


def test_deterministic_bytes_across_output_paths_and_umasks(source, tmp_path):
    previous = os.umask(0o077)
    try:
        first, a = build(source, tmp_path, 'fresh')
        os.umask(0o022)
        second, b = build(source, tmp_path, 'upgrade')
    finally:
        os.umask(previous)
    assert tree(first) == tree(second) and a == b
    for output in (first, second):
        for path in (output, *output.rglob('*')):
            assert not path.is_symlink()
            assert path.stat().st_mode & 0o777 == (0o755 if path.is_dir() else 0o644)
    assert str(first) not in json.dumps(a) and str(source) not in json.dumps(a)


def test_installed_standalone_backup_import_defers_generation_dependencies(source,tmp_path):
    output,_=build(source,tmp_path)
    code='''
import sys
from pathlib import Path
repository,plugin,project_scripts=map(Path,sys.argv[1:])
sys.path.insert(0,str(repository))
from tools.testing.installation_fixture import select_legacy
select_legacy()
sys.path=[entry for entry in sys.path if entry!=str(plugin/'scripts')]
sys.path.insert(0,str(project_scripts))
sys.path.insert(0,str(plugin))
assert not {'backup_validation','tenant_database'} & sys.modules.keys()
# A project sibling is not an admitted generation. Even executable contents
# here must stay unopened until the protected owner gate selects the latter.
(project_scripts/'tenant_database.py').write_text("raise AssertionError('helper ran before owner admission')\\n")
import backup_runtime
assert not {'backup_validation','tenant_database'} & sys.modules.keys()
assert Path(backup_runtime.__file__).parent==project_scripts
print('validator-deferred-until-generation-selection')
'''
    result=subprocess.run([sys.executable,'-I','-B','-c',code,str(PLUGIN.parents[1]),str(PLUGIN),str(output/'project-scripts')],
                          capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='validator-deferred-until-generation-selection'


def test_bundled_exporter_has_its_dependency_and_supports_existing_templates(source,tmp_path):
    output,metadata=build(source,tmp_path)
    assert metadata['artifacts']['project-scripts/plugin_skills.py']['sha256']==hashlib.sha256(
        (PLUGIN/'scripts/plugin_skills.py').read_bytes()).hexdigest()
    installed=tmp_path/'installed'
    shutil.copytree(PLUGIN/'plugin',installed/'plugin')
    code='''
import sys, shutil, zipfile
from pathlib import Path
repository,plugin,project_scripts,installed=map(Path,sys.argv[1:])
sys.path.insert(0,str(repository))
from tools.testing.installation_fixture import select_legacy
select_legacy()
sys.path=[entry for entry in sys.path if entry!=str(plugin/'scripts')]
sys.path.insert(0,str(project_scripts))
sys.path.insert(0,str(plugin))
import export_plugin
from sally_whatsapp.tenancy import Instance
assert Path(export_plugin.__file__).parent==project_scripts
assert Path(export_plugin._skills.__file__).parent==project_scripts
instance=Instance('sample','Synthetic','11111111-1111-4111-8111-111111111111',8876)
export_plugin.export(instance,installed/'new.zip',installed)
with zipfile.ZipFile(installed/'new.zip') as archive:
    assert len([name for name in archive.namelist() if name.endswith('/SKILL.md')])==3
for name in ('whatsapp-use','whatsapp-transcription'):
    shutil.rmtree(installed/'plugin/skills'/name)
export_plugin.export(instance,installed/'old.zip',installed)
with zipfile.ZipFile(installed/'old.zip') as archive:
    assert [name for name in archive.namelist() if name.endswith('/SKILL.md')]==['skills/whatsapp-setup/SKILL.md']
(installed/'plugin/skills/whatsapp-use').mkdir()
try:
    export_plugin.export(instance,installed/'partial.zip',installed)
except (ValueError,FileNotFoundError):
    assert not (installed/'partial.zip').exists()
else:
    raise AssertionError('Partially installed new skills must not be omitted')
print('bundled-exporter-new-and-legacy-ok')
'''
    result=subprocess.run([sys.executable,'-I','-B','-c',code,str(PLUGIN.parents[1]),str(PLUGIN),
                           str(output/'project-scripts'),str(installed)],
                          capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='bundled-exporter-new-and-legacy-ok'


def test_changed_source_bytes_change_generation_identity(source, tmp_path):
    _, original = build(source, tmp_path, 'before')
    path = source / 'scripts/release_build.py'
    path.write_bytes(path.read_bytes() + b'\n# Different reviewed source\n')
    _, changed = build(source, tmp_path, 'after')
    assert original['generation']['destination'] != changed['generation']['destination']
    assert original['source']['revision'] == changed['source']['revision']
    assert original['source']['files']['scripts/release_build.py'] != changed['source']['files']['scripts/release_build.py']


def test_source_snapshot_helper_changes_project_hash_without_changing_receiver_generation(source, tmp_path):
    _, before = build(source, tmp_path, 'before-snapshot-helper')
    path = source / 'scripts/package_source.py'
    path.write_bytes(path.read_bytes() + b'\n# Reviewed public snapshot contract change\n')
    _, after = build(source, tmp_path, 'after-snapshot-helper')
    key = 'project-scripts/package_source.py'
    assert before['generation'] == after['generation']
    assert before['artifacts'][key]['sha256'] != after['artifacts'][key]['sha256']
    assert after['source']['files']['scripts/package_source.py'] == after['artifacts'][key]['sha256']
    assert {k: v for k, v in before['artifacts'].items() if k != key} == {
        k: v for k, v in after['artifacts'].items() if k != key}


def test_redeclared_revision_does_not_falsely_change_identical_generation(source, tmp_path):
    _, original = build(source, tmp_path, 'before')
    changed = builder.build_bundle(source, tmp_path / 'after', source_sha='b' * 40)
    assert original['generation'] == changed['generation']
    assert original['source']['revision'] != changed['source']['revision']


@pytest.mark.parametrize('revision', ['', 'main', 'a' * 39, 'a' * 41, 'A' * 40, '../' + 'a' * 37, None])
def test_invalid_revision_fails_before_any_output(source, tmp_path, revision):
    output = tmp_path / 'bundle'
    with pytest.raises(builder.BundleError, match='source-sha'):
        builder.build_bundle(source, output, source_sha=revision)
    assert not output.exists()


@pytest.mark.parametrize('kind', ['directory', 'file', 'symlink', 'dangling-symlink'])
def test_existing_output_is_never_overwritten_or_resumed(source, tmp_path, kind):
    output = tmp_path / 'bundle'
    existing = tmp_path / 'existing'; existing.mkdir()
    (existing / 'keep').write_bytes(b'unchanged')
    if kind == 'directory':
        output.mkdir(); (output / 'partial').write_bytes(b'partial remains')
    elif kind == 'file':
        output.write_bytes(b'unchanged output')
    else:
        output.symlink_to(existing if kind == 'symlink' else tmp_path / 'absent')
    with pytest.raises(builder.BundleError, match='already exist'):
        build(source, tmp_path)
    assert (existing / 'keep').read_bytes() == b'unchanged'
    if kind == 'directory':
        assert tree(output) == {'partial': b'partial remains'}
    elif kind == 'file':
        assert output.read_bytes() == b'unchanged output'
    else:
        assert output.is_symlink()


@pytest.mark.parametrize('kind', ['file', 'scripts-parent', 'source-root', 'output-parent'])
def test_symlink_inputs_and_output_parents_fail_before_creation(source, tmp_path, kind):
    output = tmp_path / 'bundle'
    if kind == 'file':
        path = source / 'scripts/release_recover.py'
        path.unlink(); path.symlink_to(SCRIPTS / path.name)
    elif kind == 'scripts-parent':
        (source / 'scripts').rename(source / 'real-scripts')
        (source / 'scripts').symlink_to(source / 'real-scripts', target_is_directory=True)
    elif kind == 'source-root':
        link = tmp_path / 'alias'; link.symlink_to(source, target_is_directory=True)
        source = link
    else:
        actual = tmp_path / 'actual'; actual.mkdir()
        alias = tmp_path / 'alias'; alias.symlink_to(actual, target_is_directory=True)
        output = alias / 'bundle'
    with pytest.raises(builder.BundleError, match='physical'):
        builder.build_bundle(source, output, source_sha=REVISION)
    assert not output.exists()


@pytest.mark.parametrize('name', ['scripts/state_enrollment.py', 'scripts/release_runtime.py',
                                'scripts/installation_layout.py',
                                'scripts/backup_schemas/8.sql',
                                'deploy/develative-whatsapp-recovery.timer'])
def test_missing_required_component_fails_before_output(source, tmp_path, name):
    (source / name).unlink()
    with pytest.raises(builder.BundleError, match='unavailable'):
        build(source, tmp_path)
    assert not (tmp_path / 'bundle').exists()


def test_future_local_import_requires_an_explicit_closure_update(source, tmp_path):
    (source / 'scripts/new_dependency.py').write_text('raise RuntimeError("must not execute")\n')
    path = source / 'scripts/release_build.py'
    path.write_bytes(path.read_bytes() + b'\nimport new_dependency\n')
    with pytest.raises(builder.BundleError, match='outside the exact bundle: new_dependency'):
        build(source, tmp_path)
    assert not (tmp_path / 'bundle').exists()


def test_different_source_builder_is_rejected_before_output(source, tmp_path):
    (source / builder.BUILDER_SOURCE).write_text('# a different packaging implementation\n')
    with pytest.raises(builder.BundleError, match='match the executing builder'):
        build(source, tmp_path)
    assert not (tmp_path / 'bundle').exists()


def test_sources_are_data_and_unlisted_caches_secrets_links_are_not_packaged(source, tmp_path, monkeypatch):
    for name in (*builder.BOOTSTRAP_FILES, *builder.PROJECT_FILES):
        path = source / 'scripts' / name
        path.write_bytes(path.read_bytes() + b'\nraise RuntimeError("source must never execute")\n')
    extra = source / 'scripts/__pycache__'; extra.mkdir()
    (extra / 'stale.pyc').write_bytes(b'stale')
    (source / 'scripts/host-secret.key').write_bytes(b'synthetic excluded')
    (source / 'scripts/unselected.py').symlink_to(tmp_path / 'missing')
    before = tree(source)
    def forbidden(*args, **kwargs):
        raise AssertionError('No operational or ownership action is allowed')
    monkeypatch.setattr(os, 'chown', forbidden)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    output, metadata = build(source, tmp_path)
    assert tree(source) == before
    assert all('__pycache__' not in name and not name.endswith(('.pyc', '.key')) for name in tree(output))
    assert not list(output.rglob('whatsapp.json'))
    assert metadata['handoff']['owner_record_created'] is False
    assert metadata['handoff']['application_tags_update_administration'] is False


def test_preserved_runtime_project_scripts_and_unit_destinations(source, tmp_path):
    output, metadata = build(source, tmp_path)
    artifacts = metadata['artifacts']
    assert (output / 'legacy-runtime/release_runtime.py').read_bytes() == (output / 'generation/release_runtime.py').read_bytes()
    assert artifacts['legacy-runtime/release_runtime.py']['destination'] == '/usr/local/lib/develative-deploy/whatsapp/release_runtime.py'
    assert artifacts['receiver-entry/github_release.py']['destination'] == '/usr/local/lib/develative-deploy/whatsapp/github_release.py'
    assert (output / 'receiver-entry/github_release.py').read_bytes() == (source / 'scripts/release_receiver_entry.py').read_bytes()
    assert artifacts['project-scripts/backup_runtime.py']['destination'] == builder.PROJECT + '/scripts/backup_runtime.py'
    assert artifacts['project-scripts/package_source.py']['destination'] == builder.PROJECT + '/scripts/package_source.py'
    assert artifacts['project-scripts/runtime_lifecycle.py']['destination'] == builder.PROJECT + '/scripts/runtime_lifecycle.py'
    service = (output / 'systemd/develative-whatsapp-recovery.service').read_text()
    assert 'ExecStart=/usr/bin/python3 -I -B ' + builder.BOOTSTRAP + '/release_entry.py recovery\n' in service
    assert 'Unit=develative-whatsapp-recovery.service\n' in (output / 'systemd/develative-whatsapp-recovery.timer').read_text()
    for name in builder.UNIT_FILES:
        assert artifacts['systemd/' + name]['destination'] == '/etc/systemd/system/' + name
    assert metadata['host_references']['build_parent']['destination'] == '/opt/develative-releases'
    assert metadata['host_references']['build_parent']['policy'] == 'preexisting-host-owned-no-create-or-repair'
    assert metadata['directories']['systemd']['lifecycle_owner'] == 'host-infrastructure'
    assert metadata['directories']['systemd']['policy'] == 'shared-directory-retain'
    assert metadata['directories']['legacy-runtime']['policy'] == 'retain-existing-directory-and-unlisted-legacy-helpers'
    assert metadata['cleanup_policy']['recursive_directory_removal'] is False
    assert metadata['cleanup_policy']['targets'] == 'declared-artifact-files-only'
    assert 'no-active-references' in metadata['cleanup_policy']['requires']
    assert metadata['cleanup_policy']['unrecognized_or_changed_objects'] == 'stop-and-retain'


@pytest.mark.parametrize('damage',[None,'tenant-helper'])
def test_real_core_accepts_exact_manifest_with_only_synthetic_host_identity(source, tmp_path, monkeypatch,damage):
    output, metadata = build(source, tmp_path)
    spec = importlib.util.spec_from_file_location('bundle_admission_test', output / 'bootstrap/release_admin.py')
    core = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, core)
    # Compile explicitly to keep the packaged bootstrap free of bytecode.
    exec(compile((output / 'bootstrap/release_admin.py').read_bytes(), str(output / 'bootstrap/release_admin.py'), 'exec'), core.__dict__)
    assert str(core.BOOTSTRAP) == builder.BOOTSTRAP and str(core.GENERATIONS) == builder.GENERATIONS
    core._TRUST_ROOT = tmp_path
    core.GENERATIONS = output
    core.OWNER = tmp_path / 'synthetic-owner.json'
    core._trusted_uid = lambda uid: uid == os.getuid()
    core.OWNER.write_bytes(builder.encoded({'protocol': 1, 'epoch': 'b' * 32, 'state': 'dedicated',
        'generation': str(output / 'generation'),
        'manifest_sha256': metadata['generation']['manifest_sha256']}))
    if damage == 'tenant-helper':
        helper=output/'generation/tenant_database.py'
        helper.write_bytes(helper.read_bytes()+b"\nraise AssertionError('unreviewed helper must never execute')\n")
        with pytest.raises(core.AdminError,match='hash differs'):
            core.load_generation()
        return
    generation = core.load_generation()
    assert set(generation.files) == set(builder.GENERATION_FILES)
    assert core.require_current(output / 'generation/state_enrollment.py') == generation
    assert not list(output.rglob('*.pyc'))


def test_real_python_imports_resolve_all_generation_siblings_including_probe_runtime(source, tmp_path):
    output, _ = build(source, tmp_path)
    from installation_layout import IDENTITY, Installation, identity_bytes
    installation_root = tmp_path / 'installed-identity'
    marker = installation_root / IDENTITY.relative_to('/')
    marker.parent.mkdir(mode=0o700, parents=True)
    marker.write_bytes(identity_bytes(Installation.legacy())); marker.chmod(0o600)
    script = '''import sys,os
from pathlib import Path
generation=Path(sys.argv[1]);app=Path(sys.argv[2])
sys.path[:0]=[str(generation),str(app)]
def audit(event,args):
 if event in ('socket.connect','subprocess.Popen','os.system','os.chown','sqlite3.connect'):
  raise AssertionError('No operational action during imports: '+event)
sys.addaudithook(audit)
import installation_layout as layout
layout.activate_installation(root=Path(sys.argv[3]),trusted_uid=os.getuid())
import github_release, release_recover, release_probe, state_enrollment, release_runtime, backup_validation
assert Path(layout.__file__).parent==generation
assert layout._locator_state==layout.active().selection
assert Path(release_probe.__file__).parent==generation
assert Path(release_runtime.__file__).parent==generation
assert release_probe.Maintenance is release_runtime.Maintenance
print('generation imports resolved without runtime fallback')
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(output / 'generation'), str(PLUGIN), str(installation_root)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'generation imports resolved without runtime fallback'
    assert not list(output.rglob('*.pyc'))


def test_cli_emits_content_digest_and_rejects_existing_output(source, tmp_path, capsys):
    output = tmp_path / 'bundle'
    args = ['--source', str(source), '--source-sha', REVISION, '--output', str(output)]
    builder.main(args)
    result = json.loads(capsys.readouterr().out)
    assert result['metadata_sha256'] == hashlib.sha256((output / 'bundle.json').read_bytes()).hexdigest()
    assert result['generation_manifest_sha256'] == hashlib.sha256((output / 'generation/manifest.json').read_bytes()).hexdigest()
    before = tree(output)
    with pytest.raises(SystemExit) as error:
        builder.main(args)
    assert error.value.code == 1 and tree(output) == before
    assert 'already exist' in capsys.readouterr().err
