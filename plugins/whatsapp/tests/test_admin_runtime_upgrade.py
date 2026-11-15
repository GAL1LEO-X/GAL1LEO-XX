"""Offline runtime-update gates; synthetic inventories are not live API evidence."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[3]
PLUGIN = ROOT / 'plugins/whatsapp'
sys.path[:0] = [str(PLUGIN / 'scripts'), str(PLUGIN / 'tests'), str(ROOT)]

import admin_handoff as handoff
import admin_host
import admin_manifest
import build_admin_bundle
from host.lifecycle import evidence, filesystem
import test_admin_handoff as lifecycle
import test_admin_host as host_tests
from test_admin_host import fixture as host_fixture
from test_release_transaction import sandbox as transaction_sandbox

REVISION = 'a' * 40
OLD_RUNTIME = b'# synthetic previous runtime; never executed\n'
NEW_RUNTIME = b'# synthetic successor runtime; never executed\n'
LAYOUT = b'# synthetic unchanged layout; never imported\n'


def sha(content):
    return hashlib.sha256(content).hexdigest()


def spec(content, *, retain=False):
    return {**lifecycle.file_spec(content, retain=retain), 'mode': 0o644}


def runtime_paths():
    return (handoff.RUNTIME, str(Path(handoff.RUNTIME).with_name('installation_layout.py')))


def backend():
    return {path: spec(('# synthetic backend ' + Path(path).name + '\n').encode(), retain=True)
            for path in handoff.RUNTIME_BACKEND}


def descriptor(before, after):
    return {'format': 'whatsapp-runtime-update-v1',
            'before': {path: copy.deepcopy(before['files'][path]) for path in runtime_paths()},
            'after': {path: copy.deepcopy(after['files'][path]) for path in runtime_paths()},
            'backend': backend()}


@pytest.fixture
def bundles(tmp_path):
    """Real bundle validation with a deliberately different external preimage."""
    previous_source = tmp_path / 'previous-source'
    previous_source.mkdir()
    for name in ('scripts', 'deploy'):
        shutil.copytree(PLUGIN / name, previous_source / name,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    with (previous_source / 'scripts/release_runtime.py').open('ab') as stream:
        stream.write(b'\n# Synthetic previous runtime for the offline gate regression.\n')
    result = []
    for name, source in (('before-bundle', previous_source), ('after-bundle', PLUGIN)):
        target = tmp_path / name
        build_admin_bundle.build_bundle(source, target, source_sha=REVISION)
        result.append(admin_manifest.load_bundle(target, REVISION, uid=os.getuid(), gid=os.getgid()))
    old, current = result
    return old, current, descriptor(old['manifest'], current['manifest'])


def prepare(old, current, update):
    return admin_manifest.prepare_action(current, old['manifest'],
        adopted_sha256=admin_manifest.manifest_digest(old['manifest']), runtime_update=update)


def test_compiler_runtime_change_requires_explicit_exact_descriptor(bundles):
    old, current, update = bundles
    with pytest.raises(admin_manifest.ManifestError, match='runtime|Runtime'):
        prepare(old, current, None)
    prepared = prepare(old, current, update)
    assert prepared['action']['before'] == old['manifest']
    assert prepared['active_manifest'] == current['manifest']
    assert prepared['payloads'][handoff.RUNTIME] == current['payloads'][handoff.RUNTIME]
    assert prepared['action']['after']['files'][runtime_paths()[1]] == update['before'][runtime_paths()[1]]
    assert all(path not in prepared['action']['allowed_paths'] for path in update['backend'])
    assert all(path in prepared['retained_manifest']['files']
               for path in old['manifest']['files'] if path.startswith(old['generation']['destination'] + '/'))


def damage_descriptor(update, change):
    runtime, layout = runtime_paths()
    if change == 'empty':
        update.clear()
    elif change == 'extra-field':
        update['approved'] = True
    elif change == 'format':
        update['format'] = 'whatsapp-runtime-update-v2'
    elif change == 'missing-before':
        update.pop('before')
    elif change == 'missing-layout':
        update['before'].pop(layout)
    elif change == 'extra-path':
        update['after'][str(Path(runtime).with_name('arbitrary.py'))] = copy.deepcopy(update['after'][runtime])
    elif change == 'before-hash':
        update['before'][runtime]['sha256'] = '0' * 64
    elif change == 'after-hash':
        update['after'][runtime]['sha256'] = '0' * 64
    elif change == 'invalid-hash':
        update['after'][runtime]['sha256'] = 'not-a-digest'
    elif change == 'missing-backend':
        update.pop('backend')
    elif change == 'incomplete-backend':
        update['backend'].pop(next(iter(update['backend'])))
    elif change == 'extra-backend':
        update['backend']['/srv/unrelated/server.py'] = spec(b'unrelated', retain=True)
    elif change == 'backend-writable':
        next(iter(update['backend'].values()))['mode'] = 0o666
    elif change == 'backend-owner':
        next(iter(update['backend'].values()))['uid'] += 1
    elif change == 'backend-group':
        next(iter(update['backend'].values()))['gid'] += 1
    elif change == 'backend-managed':
        next(iter(update['backend'].values()))['retention'] = 'managed'
    elif change == 'backend-invalid-hash':
        next(iter(update['backend'].values()))['sha256'] = 'invalid'
    else:
        raise AssertionError(change)


DESCRIPTOR_DAMAGE = ('empty', 'extra-field', 'format', 'missing-before', 'missing-layout',
    'extra-path', 'before-hash', 'after-hash', 'invalid-hash', 'missing-backend',
    'incomplete-backend', 'extra-backend', 'backend-writable', 'backend-owner',
    'backend-group', 'backend-managed', 'backend-invalid-hash')


@pytest.mark.parametrize('change', DESCRIPTOR_DAMAGE)
def test_compiler_rejects_inexact_runtime_descriptor(bundles, change):
    old, current, update = bundles
    damage_descriptor(update, change)
    with pytest.raises((admin_manifest.ManifestError, handoff.HandoffError, filesystem.LifecycleError)):
        prepare(old, current, update)


def upgrade_fixture(tmp_path):
    """The existing journal engine and process provider, with two pinned files."""
    root, plan, payloads, provider = lifecycle.fixture(tmp_path, 'upgrade')
    # The lightweight handoff fixture does not build a full generation bundle.
    # Provision its protected destination parent explicitly, as the host must.
    (provider.root / plan['owner']['generation'].lstrip('/')).mkdir(parents=True, mode=0o700, exist_ok=True)
    before = plan['actions']['install']['before']
    after = plan['actions']['install']['after']
    for path, previous, desired in ((runtime_paths()[0], OLD_RUNTIME, NEW_RUNTIME),
                                    (runtime_paths()[1], LAYOUT, LAYOUT)):
        target = lifecycle.write(provider.root, path, previous)
        target.chmod(0o644)
        before['files'][path] = spec(previous)
        after['files'][path] = spec(desired)
        payloads['install'][path] = desired
        generation_path = plan['owner']['generation'] + '/' + Path(path).name
        after['files'][generation_path] = spec(desired)
        payloads['install'][generation_path] = desired
        old_path = plan['previous_owner']['generation'] + '/' + Path(path).name
        lifecycle.write(provider.root, old_path, previous).chmod(0o644)
        before['files'][old_path] = spec(previous, retain=True)
        after['files'][old_path] = spec(previous, retain=True)
    plan['actions']['install']['allowed_paths'] = sorted(set(before['files']) | set(after['files']))
    plan['runtime_update'] = descriptor(before, after)
    for path, metadata in plan['runtime_update']['backend'].items():
        content = ('# synthetic backend ' + Path(path).name + '\n').encode()
        assert sha(content) == metadata['sha256']
        lifecycle.write(provider.root, path, content).chmod(0o644)
    for stage, item in provider.inventories.items():
        item['manifest'] = copy.deepcopy(after if stage == 'installed' else before)
        item['manifest']['files'].update(copy.deepcopy(plan['runtime_update']['backend']))
        plan['evidence_digests'][stage] = evidence.digest_inventory(item['scope'], item['manifest'], {})
    return root, plan, payloads, provider


def test_adapter_independently_rejects_runtime_change_without_descriptor(tmp_path):
    root, plan, payloads, provider = upgrade_fixture(tmp_path)
    plan.pop('runtime_update')
    with root:
        original = {str(path): path.read_bytes() for path in provider.root.rglob('*') if path.is_file()}
        with pytest.raises(handoff.HandoffError, match='runtime|Runtime'):
            handoff.handoff(root, plan, payloads, provider)
        assert {str(path): path.read_bytes() for path in provider.root.rglob('*') if path.is_file()} == original
        assert not provider.calls


@pytest.mark.parametrize('change', DESCRIPTOR_DAMAGE)
def test_adapter_rejects_forged_runtime_descriptor_before_writes(tmp_path, change):
    root, plan, payloads, provider = upgrade_fixture(tmp_path)
    damage_descriptor(plan['runtime_update'], change)
    with root, pytest.raises((handoff.HandoffError, filesystem.LifecycleError)):
        handoff.handoff(root, plan, payloads, provider)
    assert not provider.calls
    assert not (provider.root / 'var/lib/develative-host-lifecycle').exists()


@pytest.mark.parametrize('key,value', [('mode', 0o600), ('uid', os.getuid() + 1),
                                     ('gid', os.getgid() + 1), ('retention', 'retain')])
def test_adapter_refuses_metadata_changes_even_when_descriptor_matches_action(tmp_path, key, value):
    root, plan, payloads, provider = upgrade_fixture(tmp_path)
    plan['actions']['install']['after']['files'][handoff.RUNTIME][key] = value
    plan['runtime_update']['after'][handoff.RUNTIME][key] = value
    generation_path = plan['owner']['generation'] + '/release_runtime.py'
    plan['actions']['install']['after']['files'][generation_path][key] = value
    with root, pytest.raises(handoff.HandoffError):
        handoff.validate_plan(plan, payloads, filesystem)


@pytest.mark.parametrize('change', ['layout', 'unchanged-runtime', 'generation-runtime',
                                    'generation-layout', 'backend-action'])
def test_adapter_refuses_broader_or_spurious_runtime_update(tmp_path, change):
    root, plan, payloads, provider = upgrade_fixture(tmp_path)
    after = plan['actions']['install']['after']['files']
    if change == 'layout':
        path = runtime_paths()[1]
        after[path]['sha256'] = sha(b'changed layout')
        plan['runtime_update']['after'][path] = copy.deepcopy(after[path])
        after[plan['owner']['generation'] + '/installation_layout.py'] = copy.deepcopy(after[path])
        payloads['install'][path] = payloads['install'][plan['owner']['generation'] + '/installation_layout.py'] = b'changed layout'
    elif change == 'unchanged-runtime':
        after[handoff.RUNTIME] = copy.deepcopy(plan['runtime_update']['before'][handoff.RUNTIME])
        plan['runtime_update']['after'][handoff.RUNTIME] = copy.deepcopy(after[handoff.RUNTIME])
        after[plan['owner']['generation'] + '/release_runtime.py'] = copy.deepcopy(after[handoff.RUNTIME])
        payloads['install'][handoff.RUNTIME] = payloads['install'][plan['owner']['generation'] + '/release_runtime.py'] = OLD_RUNTIME
    elif change.startswith('generation-'):
        filename = 'release_runtime.py' if change == 'generation-runtime' else 'installation_layout.py'
        after.pop(plan['owner']['generation'] + '/' + filename)
        plan['actions']['install']['allowed_paths'].remove(plan['owner']['generation'] + '/' + filename)
        payloads['install'].pop(plan['owner']['generation'] + '/' + filename)
    else:
        path, metadata = next(iter(plan['runtime_update']['backend'].items()))
        after[path] = copy.deepcopy(metadata)
        plan['actions']['install']['allowed_paths'].append(path)
    with root, pytest.raises(handoff.HandoffError):
        handoff.validate_plan(plan, payloads, filesystem)


@pytest.mark.parametrize('mode', ['fresh', 'legacy', 'remove'])
def test_runtime_update_cannot_be_smuggled_into_other_modes(tmp_path, mode):
    root, plan, payloads, provider = lifecycle.fixture(tmp_path, mode)
    plan['runtime_update'] = {'format': 'whatsapp-runtime-update-v1', 'before': {}, 'after': {}, 'backend': {}}
    with root, pytest.raises(handoff.HandoffError):
        handoff.validate_plan(plan, payloads, filesystem)


def admission_fixture(fixture):
    root, profile, plan, commands = host_tests.upgrade_admission(fixture)
    before, after = (plan['actions']['install'][side] for side in ('before', 'after'))
    for path, previous, desired in ((runtime_paths()[0], OLD_RUNTIME, NEW_RUNTIME),
                                    (runtime_paths()[1], LAYOUT, LAYOUT)):
        before['files'][path], after['files'][path] = spec(previous), spec(desired)
        after['files'][plan['owner']['generation'] + '/' + Path(path).name] = spec(desired)
    plan['runtime_update'] = descriptor(before, after)
    for name, item in profile['stages'].items():
        item['manifest'] = copy.deepcopy(after if name == 'installed' else before)
        item['manifest']['files'].update(copy.deepcopy(plan['runtime_update']['backend']))
    profile['final_manifest'] = copy.deepcopy(after)
    return root, profile, plan, commands


def test_admission_requires_observed_runtime_and_backend_closure(host_fixture):
    root, profile, plan, commands = admission_fixture(host_fixture)
    admin_host.validate_upgrade_admission(profile, plan)
    # These are file observations. Active bridge processes are outside the
    # administrative process census and do not require stopping for this move.
    assert all(handoff.RUNTIME not in item['scope']['script_paths']
               for item in profile['stages'].values())
    assert not commands


@pytest.mark.parametrize('stage', ['inventory', 'previous', 'installed'])
@pytest.mark.parametrize('part', ['runtime', 'layout', 'backend'])
@pytest.mark.parametrize('change', ['missing', 'hash', 'mode', 'uid', 'retention'])
def test_runtime_admission_rejects_incomplete_or_changed_stage(host_fixture, stage, part, change):
    root, profile, plan, commands = admission_fixture(host_fixture)
    path = (handoff.RUNTIME if part == 'runtime' else runtime_paths()[1] if part == 'layout'
            else sorted(plan['runtime_update']['backend'])[0])
    files = profile['stages'][stage]['manifest']['files']
    if change == 'missing':
        files.pop(path)
    else:
        key, value = {'hash': ('sha256', '0' * 64), 'mode': ('mode', 0o666),
                      'uid': ('uid', os.getuid() + 1), 'retention': ('retention', 'retain' if part != 'backend' else 'managed')}[change]
        files[path][key] = value
    with pytest.raises(filesystem.LifecycleError):
        admin_host.validate_upgrade_admission(profile, plan)
    assert not commands


def interrupt_runtime_install(root, plan, payloads, provider, checkpoint):
    """Inject at the existing engine boundary, without a second update engine."""
    triggered = False

    def crash():
        nonlocal triggered
        triggered = True
        raise RuntimeError('synthetic runtime install interruption')

    class InterruptedFilesystem:
        def __getattr__(self, name):
            return getattr(filesystem, name)

        def reconcile(self, *args, **kwargs):
            if checkpoint == 'before-install-intent' and not triggered:
                control = kwargs.get('payloads', {}).get(plan['journal']['path'])
                if control is not None:
                    value = json.loads(control)
                    if value.get('phase') == 'transitioning' and value.get('intent') == 'installed':
                        crash()
            install = (kwargs['before']['files'].get(handoff.RUNTIME)
                       != kwargs['after']['files'].get(handoff.RUNTIME))
            current_file = None

            def fault(event, detail):
                nonlocal current_file
                current_file = detail.get('path') or detail.get('intent') or current_file
                if install and not triggered and event == checkpoint and current_file == handoff.RUNTIME:
                    crash()

            return filesystem.reconcile(*args, **kwargs, fault=fault)

    def phase_fault(event, journal):
        if not triggered and checkpoint == 'after-installed' and event == checkpoint:
            crash()

    with pytest.raises(RuntimeError, match='synthetic runtime install interruption'):
        for _ in range(25):
            handoff.handoff(root, plan, payloads, provider,
                            filesystem=InterruptedFilesystem(), fault=phase_fault)
    assert triggered and not provider.locked


@pytest.mark.parametrize('checkpoint', ['before-install-intent', 'intent-file',
                                        'replaced-file', 'completed-file', 'after-installed'])
def test_runtime_upgrade_crash_resumes_exact_original_install(tmp_path, checkpoint):
    root, plan, payloads, provider = upgrade_fixture(tmp_path)
    with root:
        interrupt_runtime_install(root, plan, payloads, provider, checkpoint)
        assert json.loads(root.read_bytes(handoff.OWNER)) == {**plan['owner'], 'state': 'transitioning'}
        assert root.read_bytes(plan['previous_owner']['generation'] + '/release_runtime.py') == OLD_RUNTIME
        assert 'arm-whatsapp' not in provider.calls
        expected = OLD_RUNTIME if checkpoint in ('before-install-intent', 'intent-file') else NEW_RUNTIME
        assert root.read_bytes(handoff.RUNTIME) == expected
        receipt = lifecycle.advance(root, plan, payloads, provider)
        assert receipt['phase'] == 'verified' and not receipt['pending']
        assert root.read_bytes(handoff.RUNTIME) == NEW_RUNTIME
        assert root.read_bytes(runtime_paths()[1]) == LAYOUT
        assert json.loads(root.read_bytes(handoff.OWNER)) == plan['owner']
        # Every successful resume performs a fresh installed-stage census.
        assert 'observe:installed' in provider.calls
        journal = filesystem.inspect_operation(root, owner='whatsapp',
            operation_id=handoff._operation(plan, 'action-install'),
            allowed_paths=plan['actions']['install']['allowed_paths'])
        assert journal['phase'] == 'committed'
        assert journal['before'] == filesystem.validate_manifest(plan['actions']['install']['before'])
        assert journal['after'] == filesystem.validate_manifest(plan['actions']['install']['after'])
        # The original is retained in the engine's quarantine after publication.
        changes = filesystem._changes(journal['before'], journal['after'])
        quarantine = filesystem._names(handoff.RUNTIME, journal['operation_id'], changes.index(handoff.RUNTIME))[1]
        assert root.read_bytes(quarantine) == OLD_RUNTIME
        assert lifecycle.advance(root, plan, payloads, provider)['phase'] == 'verified'


@pytest.mark.parametrize('change', ['plan', 'payload'])
def test_interrupted_runtime_upgrade_refuses_changed_replay(tmp_path, change):
    root, plan, payloads, provider = upgrade_fixture(tmp_path)
    with root:
        interrupt_runtime_install(root, plan, payloads, provider, 'replaced-file')
        original = {str(path): path.read_bytes() for path in provider.root.rglob('*') if path.is_file()}
        changed_plan, changed_payloads = copy.deepcopy(plan), copy.deepcopy(payloads)
        if change == 'plan':
            next(iter(changed_plan['runtime_update']['backend'].values()))['sha256'] = '0' * 64
        else:
            changed_payloads['install'][handoff.RUNTIME] = b'# unreviewed replacement\n'
        with pytest.raises(handoff.HandoffError):
            handoff.handoff(root, changed_plan, changed_payloads, provider)
        assert {str(path): path.read_bytes() for path in provider.root.rglob('*') if path.is_file()} == original
        assert lifecycle.advance(root, plan, payloads, provider)['phase'] == 'verified'


def test_cold_configured_cli_preserves_default_deny_and_binds_runtime_update():
    # Select the profile before importing any administrative module. The
    # installation singleton must not inherit pytest's default legacy layout.
    driver = r'''
import copy, hashlib, json, os, runpy, subprocess, sys
from pathlib import Path
def audit(event, args):
    if event in ('socket.connect', 'socket.bind'):
        raise AssertionError('Offline runtime compiler attempted network access')
    if event == 'open' and isinstance(args[0], str) and args[0].startswith(
            ('/etc/whatsapp-installation', '/etc/box-installation', '/srv/openai-codex', '/var/lib/sally-browser')):
        raise AssertionError('Offline runtime compiler consulted installed identity')
sys.addaudithook(audit)
root, directory = map(Path, sys.argv[1:])
suite = runpy.run_path(str(root / 'tools/tests/test_admin_compile.py'))
inputs, bundle, profile, old, current = suite['make_fixture'](directory, 'runtime-audit', 'upgrade')
import admin_compile as compiler
import admin_handoff as handoff
import admin_install
sha = lambda raw: hashlib.sha256(raw).hexdigest()
runtime = handoff.RUNTIME
layout = handoff.RUNTIME_LAYOUT
inputs['before']['files'][runtime]['sha256'] = sha(b'# synthetic prior external runtime\n')
update = {'format': 'whatsapp-runtime-update-v1',
    'before': {path: copy.deepcopy(inputs['before']['files'][path]) for path in (runtime, layout)},
    'after': {path: copy.deepcopy(current['manifest']['files'][path]) for path in (runtime, layout)},
    'backend': {path: {'sha256': sha(('# synthetic ' + Path(path).name).encode()),
        'mode': 0o644, 'uid': 0, 'gid': 0, 'retention': 'retain'} for path in handoff.RUNTIME_BACKEND}}
inputs['runtime_update'] = update
for stage, item in inputs['profile']['stages'].items():
    item['manifest']['files'].update(copy.deepcopy(update['backend']))
    item['manifest']['files'].update(copy.deepcopy(update['after' if stage == 'installed' else 'before']))
assert all('/srv/openai-codex' not in path for path in update['backend'])
cli_driver = "import runpy,sys\nsys.argv=sys.argv[1:]\nrunpy.run_path(sys.argv[0],run_name='__main__')\n"
argv = [sys.executable, '-I', '-B', '-c', cli_driver,
    str(root / 'plugins/whatsapp/scripts/installation_command.py'), '--profile', str(profile),
    '--profile-sha256', sha(profile.read_bytes()), 'compile-administration', '--', '--mode', 'upgrade',
    '--bundle', str(bundle), '--bundle-sha256', sha((bundle / 'bundle.json').read_bytes()), '--source-revision', 'a' * 40]
def invoke(value, name, digest=None, *, input_parent=directory):
    source = input_parent / (name + '.json')
    raw = compiler.common.encoded(value)
    source.write_bytes(raw); source.chmod(0o600)
    output = directory / name
    result = subprocess.run([*argv, '--inputs', str(source), '--inputs-sha256', digest or sha(raw),
        '--output', str(output)], capture_output=True, text=True, timeout=30)
    return result, output
for mutation in ('omitted', 'digest', 'incomplete-inventory', 'wrong-owner', 'missing-backend-stage'):
    value = copy.deepcopy(inputs)
    if mutation == 'omitted': value.pop('runtime_update')
    elif mutation == 'incomplete-inventory': value['attestations']['inventory']['record']['complete'] = False
    elif mutation == 'wrong-owner': value['previous_owner']['state'] = 'retiring'
    elif mutation == 'missing-backend-stage':
        value['profile']['stages']['previous']['manifest']['files'].pop(next(iter(update['backend'])))
    result, output = invoke(value, mutation, '0' * 64 if mutation == 'digest' else None)
    assert result.returncode != 0, result.stdout
    assert not output.exists()
# The private fixture location must not weaken the production ancestor gate.
unprotected = directory / 'unprotected-inputs'
unprotected.mkdir(mode=0o700)
unprotected.chmod(0o777)
try:
    result, output = invoke(inputs, 'writable-ancestor', input_parent=unprotected)
    assert result.returncode != 0, result.stdout
    assert 'Compiler input and ancestors must be administratively protected' in result.stderr
    assert not output.exists()
finally:
    unprotected.chmod(0o700)
result, output = invoke(inputs, 'approved')
assert result.returncode == 0, result.stderr
receipt = json.loads(result.stdout)
assert all(receipt[key] is False for key in ('host_observed', 'installed', 'owner_written', 'live_admission_certified'))
raw = (output / 'operation.json').read_bytes()
operation, payloads, _ = admin_install.decode_operation(raw, sha(raw))
assert operation['plan']['runtime_update'] == update
assert operation['plan']['previous_owner'] == inputs['previous_owner']
assert operation['plan']['actions']['install']['before']['files'][runtime] == update['before'][runtime]
assert operation['plan']['actions']['install']['after']['files'][runtime] == update['after'][runtime]
assert sha(payloads['install'][runtime]) == update['after'][runtime]['sha256']
assert all(path not in operation['plan']['actions']['install']['allowed_paths'] for path in update['backend'])
assert not (directory / 'etc').exists()
print(json.dumps({'negative_cli_cases': 6, 'profile': 'runtime-audit', 'installed': False}))
'''
    # The release source snapshot itself can be below world-writable /tmp.
    # Keep real compiler inputs in a private, owned scratch of the isolated
    # test venv instead, without changing any existing directory permissions.
    work = Path(sys.prefix)
    assert work != Path(sys.base_prefix) and work == work.resolve(strict=True)
    assert work.stat().st_uid == os.geteuid()
    for parent in (work, *work.parents):
        info = parent.lstat()
        assert stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022
    with tempfile.TemporaryDirectory(prefix='runtime-compiler-', dir=work) as directory:
        result = subprocess.run([sys.executable, '-I', '-B', '-c', driver, str(ROOT), directory],
                                capture_output=True, text=True, timeout=90)
    assert not Path(directory).exists()
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {'negative_cli_cases': 6, 'profile': 'runtime-audit', 'installed': False}


@pytest.mark.parametrize('had_override', [False, True])
def test_cli_before_upgrade_and_rollback_never_start_legacy_with_new_runtime(transaction_sandbox, monkeypatch, had_override):
    """Observe real transaction file ordering with synthetic systemd starts."""
    import release_transaction as transaction
    from github_release_common import ReleaseError
    root, candidate, instances, healthy, activate, commands = transaction_sandbox
    transaction.SYSTEMD.mkdir()
    prior = {}
    for instance in instances:
        cli = ('[Service]\nExecStart=' + str(root / '.venv/bin/python')
               + ' -m sally_whatsapp.cli --config ' + instance['config'] + ' serve\n')
        (transaction.SYSTEMD / instance['unit']).write_text(cli)
        override = transaction.SYSTEMD / (instance['unit'] + '.d/70-release-runtime.conf')
        prior[override] = None
        if had_override:
            override.parent.mkdir()
            prior[override] = cli.replace('[Service]\n', '[Service]\nExecStart=\n')
            override.write_text(prior[override])
    starts = []

    def run(arguments, **options):
        commands.append(arguments)
        if arguments[:2] != ['systemctl', 'start']:
            return
        marker = (root / 'sally_whatsapp/marker').read_text()
        for unit in arguments[2:]:
            override = transaction.SYSTEMD / (unit + '.d/70-release-runtime.conf')
            effective = override.read_text() if override.exists() else (transaction.SYSTEMD / unit).read_text()
            if str(transaction.RUNTIME) in effective:
                assert marker == 'new' and (root / '.venv').resolve() == candidate / '.venv'
                starts.append(('runtime', marker))
            else:
                assert '-m sally_whatsapp.cli ' in effective and marker == 'old'
                assert not (root / '.venv').is_symlink()
                starts.append(('cli', marker))

    monkeypatch.setattr(transaction, 'run', run)
    healthy.side_effect = [ReleaseError('synthetic candidate failure'), None]
    with pytest.raises(ReleaseError, match='synthetic candidate failure'):
        activate()
    assert starts == [('runtime', 'new')] * len(instances) + [('cli', 'old')] * len(instances)
    assert json.loads(transaction.JOURNAL.read_text())['phase'] == 'rolled-back'
    for override, content in prior.items():
        assert (override.read_text() if override.exists() else None) == content
