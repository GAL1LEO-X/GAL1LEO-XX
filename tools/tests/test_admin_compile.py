"""Cold offline administration compilers, with public synthetic inventories.

The real CLI, bundle loader, validators and envelope decoder run. These tests
do not observe systemd, assert host completeness or perform an operational move.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / 'plugins/whatsapp'
COMMAND = PLUGIN / 'scripts/installation_command.py'
REVISION = 'a' * 40
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Protected compiler inputs require POSIX')


def make_fixture(directory, name, mode, *, uid=0, gid=0):
    """Reusable only in a cold child; returns full public inputs and real bundle."""
    import shutil
    sys.path[:0] = [str(PLUGIN / 'scripts'), str(ROOT)]
    import installation_layout as layout
    value = json.loads((PLUGIN / 'deploy/installation.example.json').read_bytes())
    value['paths'] = {'project': '/srv/' + name + '/app', 'configuration': '/etc/' + name,
        'state': '/var/lib/' + name + '-data', 'gateway': '/var/lib/' + name + '-gateways',
        'backup': '/var/backups/' + name, 'administration_code': '/usr/local/lib/' + name + '-admin',
        'administration_state': '/var/lib/' + name + '-admin'}
    value['services'] = {'prefix': name, 'recovery': name + '-recovery'}
    value['accounts'] = {'personal': name + '-owner', 'team': name + '-other'}
    layout.select(layout.Installation.from_dict(value))
    profile_path = directory / 'profile.json'
    profile_path.write_text(json.dumps(value))
    import admin_compile as compiler
    import admin_manifest as manifest
    import build_admin_bundle as builder
    import admin_handoff as handoff
    from host.lifecycle import filesystem
    old_bundle = directory / 'before-bundle'
    builder.build_bundle(PLUGIN, old_bundle, source_sha=REVISION)
    old = manifest.load_bundle(old_bundle, REVISION, uid=uid, gid=gid)
    previous = {'protocol': 1, 'epoch': 'b' * 32, 'state': 'dedicated',
        'generation': old['generation']['destination'], 'manifest_sha256': old['generation']['manifest_sha256']}
    if mode == 'upgrade':
        source = directory / 'candidate-source'; source.mkdir()
        for child in ('scripts', 'deploy'):
            shutil.copytree(PLUGIN / child, source / child, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        with (source / 'scripts/release_recover.py').open('a') as stream:
            stream.write('\n# Synthetic successor generation for the compiler test.\n')
        bundle = directory / 'after-bundle'
        builder.build_bundle(source, bundle, source_sha=REVISION)
        current = manifest.load_bundle(bundle, REVISION, uid=uid, gid=gid)
        prepared = manifest.prepare_action(current, old['manifest'], adopted_sha256=manifest.manifest_digest(old['manifest']))
        final, retained = prepared['active_manifest'], prepared['retained_manifest']
        after = prepared['action']['after']
    else:
        bundle, current = old_bundle, old
        final = copy.deepcopy(old['manifest'])
        helper = value['paths']['project'] + '/scripts/runtime_lifecycle.py'
        preserve = {handoff.RUNTIME, str(Path(handoff.RUNTIME).with_name('installation_layout.py')),
                    helper, str(Path(helper).with_name('installation_layout.py'))}
        final['files'] = {path: spec for path, spec in final['files'].items() if path in preserve}
        retained = manifest.empty_manifest()
        after = final
    inputs = compiler.template(mode)
    inputs.update(operation_id='c' * 32, epoch='d' * 32 if mode == 'upgrade' else previous['epoch'],
                  before=old['manifest'], previous_owner=previous)
    scope = {'cgroups': ['/system.slice/' + name + '-recovery.service'],
             'script_roots': [previous['generation']], 'script_paths': [handoff.BOOTSTRAP + '/release_entry.py']}
    inputs['profile'].update(generation_id=current['generation']['manifest_sha256'], invokers=[],
                            final_manifest=final, retained_manifest=retained)
    inputs['profile']['stages'] = {stage: {'scope': copy.deepcopy(scope),
        'manifest': copy.deepcopy(after if stage == 'installed' else old['manifest']), 'units': {}}
        for stage in inputs['profile']['stages']}
    inputs['attestations']['inventory'] = {'path': value['paths']['configuration'] + '/admin-input.json',
        'record': {'format': 2, 'complete': True, 'invokers': [],
            'manual_policy': {'operation_id': inputs['operation_id'], 'unregistered_root_commands': 'frozen-for-operation'}}}
    if mode == 'remove':
        inputs['runtime_retirement'] = {'operation_id': 'e' * 32}
        inputs['attestations']['retirement'] = {'path': value['paths']['configuration'] + '/retirement-input.json',
            'record': {'format': 3, 'complete': True, 'invokers': [], 'operation_id': inputs['operation_id'],
                       'epoch': previous['epoch'], 'references': {}}}
    return inputs, bundle, profile_path, old, current


def _cold(directory, name, mode):
    directory = Path(directory)
    forbidden = ('/etc/whatsapp-installation', '/etc/box-installation', '/srv/openai-codex', '/var/lib/sally-browser')
    def audit(event, args):
        if event in ('socket.connect', 'socket.bind'):
            raise AssertionError('Compiler attempted network access')
        if event == 'open' and isinstance(args[0], str) and args[0].startswith(forbidden):
            raise AssertionError('Compiler consulted an installed or legacy identity')
    sys.addaudithook(audit)
    inputs, bundle, profile, old, current = make_fixture(directory, name, mode)
    import admin_compile as compiler
    import admin_install
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    digest = sha((bundle / 'bundle.json').read_bytes())
    driver = "import runpy,sys\n" + '''
def audit(event,args):
    if event in ('socket.connect','socket.bind') or event=='open' and isinstance(args[0],str) and args[0].startswith(('/etc/whatsapp-installation','/etc/box-installation','/srv/openai-codex','/var/lib/sally-browser')):
        raise AssertionError('Offline compiler accessed installed state or network')
sys.addaudithook(audit)
sys.argv=sys.argv[1:]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    argv = [sys.executable, '-I', '-B', '-c', driver, str(COMMAND), '--profile', str(profile),
        '--profile-sha256', sha(profile.read_bytes()), 'compile-administration', '--', '--mode', mode,
        '--bundle', str(bundle), '--bundle-sha256', digest, '--source-revision', REVISION]
    template = subprocess.run([*argv, '--input-template'], capture_output=True, text=True, timeout=30)
    assert template.returncode == 0, template.stderr
    incomplete = json.loads(template.stdout)
    assert incomplete['attestations']['inventory']['record']['complete'] is False
    assert incomplete['before']['files'] is None and incomplete['profile']['invokers'] is None
    source = directory / 'inputs.json'; source.write_bytes(compiler.common.encoded(inputs)); source.chmod(0o600)
    output = directory / 'operation'
    result = subprocess.run([*argv, '--inputs', str(source), '--inputs-sha256', sha(source.read_bytes()),
                             '--output', str(output)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert all(receipt[key] is False for key in ('host_observed', 'installed', 'owner_written', 'live_admission_certified'))
    operation_bytes = (output / 'operation.json').read_bytes()
    operation, payloads, _ = admin_install.decode_operation(operation_bytes, sha(operation_bytes))
    assert operation['plan']['mode'] == mode
    assert operation['plan']['previous_owner'] == inputs['previous_owner']
    assert all('/srv/openai-codex' not in path for action in operation['plan']['actions'].values()
               for path in action['allowed_paths'])
    for filename, destination in receipt['attestation_destinations'].items():
        assert destination.startswith('/etc/' + name + '/')
        assert sha((output / filename).read_bytes()) == operation['profile'][
            'attestation' if filename.startswith('inventory') else 'retirement_attestation']['sha256']
    assert not (directory / 'etc').exists()
    repeated = subprocess.run([*argv, '--inputs', str(source), '--inputs-sha256', sha(source.read_bytes()),
                               '--output', str(output)], capture_output=True, text=True, timeout=30)
    assert repeated.returncode != 0 and (output / 'operation.json').read_bytes() == operation_bytes
    oversized = directory / 'oversized.json'
    oversized.write_bytes(b' ' * (compiler.MAX_INPUT + 1)); oversized.chmod(0o600)
    rejected = subprocess.run([*argv, '--inputs', str(oversized), '--inputs-sha256', sha(oversized.read_bytes()),
        '--output', str(directory / 'oversized-output')], capture_output=True, text=True, timeout=30)
    assert rejected.returncode != 0 and not (directory / 'oversized-output').exists()
    mutations = []
    def damaged(change):
        value = copy.deepcopy(inputs); change(value); mutations.append(value)
    damaged(lambda v: v['attestations']['inventory']['record'].update(complete=False))
    damaged(lambda v: v['attestations']['inventory']['record']['manual_policy'].update(operation_id='f' * 32))
    damaged(lambda v: v['previous_owner'].update(state='retiring'))
    damaged(lambda v: v['profile'].update(generation_id='0' * 64))
    damaged(lambda v: v['profile']['stages'].pop('inventory'))
    damaged(lambda v: v['profile'].update(attestation={'path': '/etc/forged', 'sha256': '0' * 64}))
    damaged(lambda v: v['profile']['final_manifest']['files'].update({'/etc/unowned': next(iter(v['before']['files'].values()))}))
    if mode == 'upgrade':
        damaged(lambda v: v.update(epoch=v['previous_owner']['epoch']))
        damaged(lambda v: v['profile']['stages']['installed']['scope'].update(script_roots=[]))
    else:
        damaged(lambda v: v.update(epoch='f' * 32))
        damaged(lambda v: v['before']['files'].pop(next(iter(v['before']['files']))))
        damaged(lambda v: v['attestations']['retirement']['record'].update(complete=False))
        damaged(lambda v: v['attestations']['retirement']['record'].update(epoch='f' * 32))
        damaged(lambda v: v['runtime_retirement'].update(operation_id='invalid'))
    for value in mutations:
        raw = compiler.common.encoded(value)
        try:
            compiler.compile_operation(bundle, source_revision=REVISION, metadata_sha256=digest,
                input_bytes=raw, inputs_sha256=sha(raw), mode=mode)
        except (ValueError, RuntimeError, KeyError, TypeError):
            pass
        else:
            raise AssertionError('Damaged public input was accepted')
    phases = _exercise_handoff(directory / 'materialized', name, mode)
    print(json.dumps({'mode': mode, 'profile': name, 'negatives': len(mutations),
                      'input_bytes': source.stat().st_size, 'host_observed': False, 'phases': phases}))


def _exercise_handoff(directory, name, mode):
    """Real compiled plan and host adapter, only systemd/proc responses synthetic."""
    directory.mkdir()
    inputs, bundle, profile_path, old, _ = make_fixture(directory, name, mode, uid=os.getuid(), gid=os.getgid())
    import admin_compile as compiler
    import admin_handoff as handoff
    import admin_host
    import admin_install
    from host.lifecycle import filesystem, services
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    raw = compiler.common.encoded(inputs)
    files = compiler.compile_operation(bundle, source_revision=REVISION,
        metadata_sha256=sha((bundle / 'bundle.json').read_bytes()), input_bytes=raw,
        inputs_sha256=sha(raw), mode=mode, uid=os.getuid(), gid=os.getgid())
    operation, payloads, _ = admin_install.decode_operation(files['operation.json'], sha(files['operation.json']))
    base = directory / 'root'; base.mkdir(mode=0o700)
    def put(path, data, mode=0o600):
        target = base / path.lstrip('/'); target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data); target.chmod(mode)
    for path, spec in old['manifest']['directories'].items():
        target = base / path.lstrip('/'); target.mkdir(parents=True, exist_ok=True); target.chmod(spec['mode'])
    for path, data in old['payloads'].items():
        put(path, data, old['manifest']['files'][path]['mode'])
    for path in (compiler.common.STATE + '/handoff', compiler.common.PRIVATE):
        (base / path.lstrip('/')).mkdir(parents=True, exist_ok=True, mode=0o700)
    put(handoff.OWNER, handoff.encoded(inputs['previous_owner']))
    receipt = json.loads(files['compilation.json'])
    for filename, path in receipt['attestation_destinations'].items():
        put(path, files[filename])
    personal = compiler.common.PRIVATE + '/preserved-personal-state'
    put(personal, b'synthetic later messages, revokes, uncertain send and session\n')
    proc = directory / 'proc'; (proc / 'sys/kernel/random').mkdir(parents=True)
    (proc / 'sys/kernel/random/boot_id').write_text('11111111-2222-3333-4444-555555555555\n')
    class Systemd:
        armed = True
        def run(self, operation, **kwargs):
            assert kwargs['pass_fds']
            assert operation in ('reload-definitions', 'enable-wa-recovery', 'start-wa-recovery',
                                 'disable-wa-recovery', 'stop-wa-recovery')
            if operation == 'start-wa-recovery': self.armed = True
            if operation == 'stop-wa-recovery': self.armed = False
        def read(self, argv, **kwargs):
            unit = argv[-1]
            assert argv == services.recovery_show_argv(unit)
            values = {key: '' for key in services.RECOVERY_PROPERTIES[unit]}
            values.update(Id=unit, LoadState='loaded', NeedDaemonReload='no',
                FragmentPath='/etc/systemd/system/' + unit, Job='0', ActiveState='inactive', SubState='dead')
            if unit.endswith('.timer'):
                values.update(ActiveState='active' if self.armed else 'inactive',
                    UnitFileState='enabled' if self.armed else 'disabled', Unit=services.WA_RECOVERY[0],
                    TimersMonotonic='{ OnBootUSec=45s; next=1; } { OnUnitInactiveUSec=60s; next=2; }')
            else:
                values.update(MainPID='0', ControlPID='0', Type='oneshot', User='root',
                    KillMode='control-group', RemainAfterExit='no', Restart='no', TimeoutStartUSec='600s',
                    ExecStart='{ path=/usr/bin/python3; argv[]=/usr/bin/python3 -I -B '
                        + services.RECOVERY_ENTRYPOINT + ' recovery; }')
            return ('\n'.join(key + '=' + value for key, value in values.items()) + '\n').encode()
    service = Systemd()
    phases = []
    with filesystem.Root(base) as root:
        provider = admin_host.AdminHost(root, operation['profile'], proc_root=proc,
            readonly_runner=service.read, service_runner=service.run, clock_ns=lambda: 100)
        for _ in range(20):
            result = handoff.handoff(root, operation['plan'], payloads, provider)
            assert not result['pending'], result
            phases.append(result['phase'])
            if result['phase'] == ('verified' if mode == 'upgrade' else 'retired'):
                break
        assert phases[-1] == ('verified' if mode == 'upgrade' else 'retired'), phases
        assert root.read_bytes(personal).startswith(b'synthetic later messages')
        if mode == 'remove':
            # Never forge a runtime completion to get a fully green uninstall.
            try:
                handoff.handoff(root, operation['plan'], payloads, provider)
            except (ValueError, RuntimeError):
                pass
            else:
                raise AssertionError('Administrative payload removed without runtime retirement')
            assert root.snapshot(handoff.RECEIVER) is not None
        else:
            assert handoff.handoff(root, operation['plan'], payloads, provider)['phase'] == 'verified'
            assert root.read_bytes(handoff.OWNER) == handoff.encoded(operation['plan']['owner'])
            import admin_manifest as manifest
            import build_admin_bundle as builder
            generations = {inputs['previous_owner']['generation'], operation['plan']['owner']['generation']}
            sizes = [len(raw)]
            for number in (2, 3):
                # Real successive bundles and retained generation manifests;
                # never trim history to fit the fresh compiler's smaller bound.
                with (directory / 'candidate-source/scripts/release_recover.py').open('a') as stream:
                    stream.write('\n# Successor ' + str(number) + '.\n')
                candidate = directory / ('successor-' + str(number))
                builder.build_bundle(directory / 'candidate-source', candidate, source_sha=REVISION)
                compiled = manifest.load_bundle(candidate, REVISION, uid=os.getuid(), gid=os.getgid())
                before = operation['plan']['actions']['install']['after']
                prepared = manifest.prepare_action(compiled, before, adopted_sha256=manifest.manifest_digest(before))
                following = copy.deepcopy(inputs)
                following.update(operation_id=str(number + 4) * 32, epoch=str(number + 6) * 32,
                                 before=before, previous_owner=operation['plan']['owner'])
                scope = copy.deepcopy(following['profile']['stages']['inventory']['scope'])
                scope['script_roots'] = [following['previous_owner']['generation']]
                following['profile'].update(generation_id=compiled['generation']['manifest_sha256'],
                    final_manifest=prepared['active_manifest'], retained_manifest=prepared['retained_manifest'],
                    stages={stage: {'scope': copy.deepcopy(scope), 'manifest': copy.deepcopy(
                        prepared['action']['after'] if stage == 'installed' else before), 'units': {}}
                        for stage in ('inventory', 'previous', 'installed')})
                following['attestations']['inventory']['path'] += '-' + str(number)
                following['attestations']['inventory']['record']['manual_policy']['operation_id'] = following['operation_id']
                body = compiler.common.encoded(following); sizes.append(len(body))
                named_input = directory / ('successor-input-' + str(number) + '.json')
                named_input.write_bytes(body); named_input.chmod(0o600)
                captured = compiler.common.read_protected(named_input, max_bytes=compiler.MAX_INPUT)
                assert captured == body
                if number == 3:
                    assert len(body) > compiler.common.MAX_INPUT
                    with pytest.raises(ValueError):
                        compiler.common.read_protected(named_input)
                    # The actual CLI must use the same larger bound. Only the
                    # test ownership projection changes from this user's root
                    # fixture to the CLI's mandatory root:root output metadata.
                    def root_metadata(value):
                        if isinstance(value, dict):
                            return {key: 0 if key in ('uid', 'gid') else root_metadata(item) for key, item in value.items()}
                        if isinstance(value, list): return [root_metadata(item) for item in value]
                        return value
                    cli_input = directory / 'successor-cli.json'
                    cli_input.write_bytes(compiler.common.encoded(root_metadata(following))); cli_input.chmod(0o600)
                    driver = '''import runpy,sys
def audit(event,args):
    if event=='open' and isinstance(args[0],str) and args[0].startswith(('/etc/whatsapp-installation','/etc/box-installation','/srv/openai-codex')):
        raise AssertionError('Compiler read installed state')
sys.addaudithook(audit)
sys.argv=sys.argv[1:]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
                    result = subprocess.run([sys.executable, '-I', '-B', '-c', driver, str(COMMAND),
                        '--profile', str(profile_path), '--profile-sha256', sha(profile_path.read_bytes()),
                        'compile-administration', '--', '--mode', 'upgrade', '--bundle', str(candidate),
                        '--bundle-sha256', sha((candidate / 'bundle.json').read_bytes()), '--source-revision', REVISION,
                        '--inputs', str(cli_input), '--inputs-sha256', sha(cli_input.read_bytes()),
                        '--output', str(directory / 'successor-cli-output')], capture_output=True, text=True, timeout=30)
                    assert result.returncode == 0, result.stderr
                result_files = compiler.compile_operation(candidate, source_revision=REVISION,
                    metadata_sha256=sha((candidate / 'bundle.json').read_bytes()), input_bytes=captured,
                    inputs_sha256=sha(captured), mode='upgrade', uid=os.getuid(), gid=os.getgid())
                operation, payloads, _ = admin_install.decode_operation(result_files['operation.json'], sha(result_files['operation.json']))
                for filename, destination in json.loads(result_files['compilation.json'])['attestation_destinations'].items():
                    put(destination, result_files[filename])
                provider = admin_host.AdminHost(root, operation['profile'], proc_root=proc,
                    readonly_runner=service.read, service_runner=service.run, clock_ns=lambda: 100)
                for _ in range(12):
                    result = handoff.handoff(root, operation['plan'], payloads, provider)
                    assert not result['pending'], result
                    if result['phase'] == 'verified': break
                assert result['phase'] == 'verified'
                generations.add(operation['plan']['owner']['generation'])
                assert all(root.snapshot(generation + '/manifest.json') is not None for generation in generations)
                assert root.read_bytes(personal).startswith(b'synthetic later messages')
            assert len(generations) == 4 and sizes[-1] > 128 * 1024
    return phases


@pytest.mark.parametrize('name', ['alpha', 'bravo'])
@pytest.mark.parametrize('mode', ['upgrade', 'remove'])
def test_cold_configured_administration_cli(name, mode):
    work = ROOT / 'work'; work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='admin-compiler-', dir=work) as root:
        result = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()), root, name, mode],
                                capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads(result.stdout)['host_observed'] is False


@pytest.mark.parametrize('compatibility', [False, True])
def test_fresh_cli_binds_neutral_layout_before_encoding(compatibility):
    """The fresh template alone never imported the neutral service closure."""
    work = ROOT / 'work'; work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='fresh-compiler-', dir=work) as root:
        directory = Path(root)
        profile = PLUGIN / 'deploy/installation.example.json'
        sha = lambda raw: hashlib.sha256(raw).hexdigest()
        selection = ['--legacy'] if compatibility else ['--profile', str(profile), '--profile-sha256', sha(profile.read_bytes())]
        driver = '''import runpy,sys
def audit(event,args):
    if event=='open' and isinstance(args[0],str) and args[0].startswith(('/etc/whatsapp-installation','/etc/box-installation')):
        raise AssertionError('Compiler read an installed identity')
sys.addaudithook(audit)
sys.argv=sys.argv[1:]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
        base = [sys.executable, '-I', '-B', '-c', driver, str(COMMAND), *selection]
        bundle = directory / 'bundle'
        built = subprocess.run([*base, 'build-administration', '--source-sha', REVISION,
                                '--output', str(bundle)], capture_output=True, text=True, timeout=30)
        assert built.returncode == 0, built.stderr
        argv = [*base, 'compile-fresh-administration', '--', '--bundle', str(bundle),
                '--bundle-sha256', sha((bundle / 'bundle.json').read_bytes()), '--source-revision', REVISION]
        template = subprocess.run([*argv, '--input-template'], capture_output=True, text=True, timeout=30)
        assert template.returncode == 0, template.stderr
        inputs = json.loads(template.stdout)
        inputs.update(operation_id='b' * 32, epoch='c' * 32,
                      cgroups=['/system.slice/' + ('develative-whatsapp-recovery' if compatibility else 'messages-recovery') + '.service'])
        inputs['directory_modes'] = {path: '0755' for path in inputs['directory_modes']}
        inputs['attestation'].update(complete=True, manual_policy={
            'operation_id': inputs['operation_id'], 'unregistered_root_commands': 'frozen-for-operation'})
        source = directory / 'inputs.json'; source.write_text(json.dumps(inputs)); source.chmod(0o600)
        compiled = subprocess.run([*argv, '--inputs', str(source), '--inputs-sha256', sha(source.read_bytes()),
            '--output', str(directory / 'output')], capture_output=True, text=True, timeout=30)
        assert compiled.returncode == 0, compiled.stderr
        assert json.loads(compiled.stdout)['host_observed'] is False


if __name__ == '__main__':
    _cold(*sys.argv[1:])
