"""Fresh compiler through actual handoff/filesystem; services and /proc synthetic."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

PLUGIN = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN / 'scripts'))
import fresh_admin as fresh
import admin_handoff
import admin_host
import admin_install
import admin_manifest
import build_admin_bundle
from host.lifecycle import filesystem, services

REVISION = 'a' * 40
BOOT = '11111111-2222-3333-4444-555555555555'


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def source(tmp_path):
    bundle = tmp_path / 'bundle'
    build_admin_bundle.build_bundle(PLUGIN, bundle, source_sha=REVISION)
    metadata_sha = sha((bundle / 'bundle.json').read_bytes())
    compiled = admin_manifest.load_bundle(bundle, REVISION, uid=os.getuid(), gid=os.getgid(),
        expected_metadata_sha256=metadata_sha)
    inputs = {'format': fresh.FORMAT, 'mode': 'fresh', 'operation_id': 'b' * 32, 'epoch': 'c' * 32,
        'cgroups': [fresh.RECOVERY_CGROUP],
        'directory_modes': {path: '0755' for path in fresh.prerequisite_paths(compiled)},
        'attestation': {'format': 2, 'complete': True, 'invokers': [],
            'manual_policy': {'operation_id': 'b' * 32,
                              'unregistered_root_commands': 'frozen-for-operation'}}}
    inputs['directory_modes'][fresh.PRIVATE] = '0700'
    return bundle, metadata_sha, inputs


def compile_inputs(source, inputs=None):
    bundle, metadata_sha, original = source
    body = fresh.encoded(original if inputs is None else inputs)
    return fresh.compile_fresh(bundle, source_revision=REVISION, metadata_sha256=metadata_sha,
        input_bytes=body, inputs_sha256=sha(body), uid=os.getuid(), gid=os.getgid())


def protected_put(base, path, content, mode=0o600):
    target = base / path.lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    target.chmod(mode)
    return target


class ServiceFixture:
    """Only the two dedicated WA units are implemented; no BOX namespace."""
    def __init__(self):
        self.armed = False
        self.commands = []

    def run(self, operation, **kwargs):
        assert operation in ('reload-definitions', 'enable-wa-recovery', 'start-wa-recovery')
        assert kwargs['pass_fds']
        self.commands.append(operation)
        if operation == 'start-wa-recovery':
            self.armed = True

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


def host_fixture(tmp_path, files):
    operation, payloads, _ = admin_install.decode_operation(files['operation.json'], sha(files['operation.json']))
    base = tmp_path / 'host'; base.mkdir(mode=0o700)
    receipt = json.loads(files['compilation.json'])
    for path, metadata in receipt['required_existing_directories'].items():
        target = base / path.lstrip('/')
        target.mkdir(parents=True, exist_ok=True)
        target.chmod(metadata['mode'])
    protected_put(base, receipt['attestation']['path'], files['attestation.json'])
    proc = tmp_path / 'proc'
    protected_put(proc, '/sys/kernel/random/boot_id', (BOOT + '\n').encode())
    root = filesystem.Root(base)
    service = ServiceFixture()
    provider = admin_host.AdminHost(root, operation['profile'], proc_root=proc,
        readonly_runner=service.read, service_runner=service.run, clock_ns=lambda: 100)
    return root, operation, payloads, provider, service


def advance(root, operation, payloads, provider, **kwargs):
    return admin_handoff.handoff(root, operation['plan'], payloads, provider, **kwargs)


def test_deterministic_compilation_is_local_and_does_not_synthesize_attestation(source):
    first = compile_inputs(source)
    assert first == compile_inputs(source)
    result = json.loads(first['compilation.json'])
    assert result['host_observed'] is result['installed'] is result['owner_written'] is False
    assert len(result['required_absent_artifacts']) == 47
    assert json.loads(first['attestation.json']) == source[2]['attestation']
    operation, _, _ = admin_install.decode_operation(first['operation.json'], sha(first['operation.json']))
    assert {operation['plan']['owner']['generation'] + '/tenant_database.py',
            admin_manifest.PROJECT_SCRIPTS + '/plugin_skills.py',
            admin_manifest.PROJECT_SCRIPTS + '/tenant_database.py'} <= set(result['required_absent_artifacts'])
    assert {admin_manifest.PROJECT_SCRIPTS + '/' + name for name in (
        'admin_deployment.py', 'backup_validation.py', 'release_database.py',
        'backup_schemas/6.sql', 'backup_schemas/7.sql', 'backup_schemas/8.sql')
    } <= set(result['required_absent_artifacts'])
    assert operation['plan']['mode'] == 'fresh' and operation['plan']['previous_owner'] is None
    assert operation['plan']['actions']['install']['before']['files'] == {}
    assert set(operation['plan']['actions']) == {'install'}


def test_actual_fresh_handoff_from_empty_app_namespace_and_repeated_verification(source, tmp_path):
    root, operation, payloads, provider, service = host_fixture(tmp_path, compile_inputs(source))
    try:
        phases = []
        for _ in range(10):
            result = advance(root, operation, payloads, provider)
            phases.append(result['phase'])
            if result['phase'] == 'verified':
                break
        assert phases == ['prepared', 'transitioning', 'installed', 'recovery_armed', 'owner_dedicated', 'verified']
        assert json.loads(root.read_bytes(admin_handoff.OWNER)) == operation['plan']['owner']
        assert service.commands == ['reload-definitions', 'enable-wa-recovery', 'start-wa-recovery']
        assert advance(root, operation, payloads, provider)['phase'] == 'verified'
        assert service.commands == ['reload-definitions', 'enable-wa-recovery', 'start-wa-recovery']
        assert not (root.base / 'var/lib/box').exists()
        assert not (root.base / 'usr/local/lib/develative-deploy/release_recover.py').exists()
    finally:
        root.close()


def test_forward_resume_after_installed_payload_before_checkpoint(source, tmp_path):
    root, operation, payloads, provider, service = host_fixture(tmp_path, compile_inputs(source))
    class Crash(BaseException): pass
    def fault(event, _):
        if event == 'after-installed':
            raise Crash()
    try:
        advance(root, operation, payloads, provider)
        advance(root, operation, payloads, provider)
        with pytest.raises(Crash):
            advance(root, operation, payloads, provider, fault=fault)
        assert json.loads(root.read_bytes(admin_handoff.OWNER))['state'] == 'transitioning'
        assert service.commands == []
        # Reconstruct the provider, as in a new installer process.
        provider = admin_host.AdminHost(root, operation['profile'], proc_root=provider.proc_root,
            readonly_runner=service.read, service_runner=service.run, clock_ns=lambda: 100)
        for _ in range(8):
            result = advance(root, operation, payloads, provider)
            if result['phase'] == 'verified': break
        assert result['phase'] == 'verified'
        assert json.loads(root.read_bytes(admin_handoff.OWNER))['state'] == 'dedicated'
    finally:
        root.close()


def test_same_operation_cannot_be_rebound_to_another_epoch(source, tmp_path):
    files = compile_inputs(source)
    root, operation, payloads, provider, service = host_fixture(tmp_path, files)
    try:
        advance(root, operation, payloads, provider)
        saved = root.read_bytes(operation['plan']['journal']['path'])
        changed = copy.deepcopy(source[2]); changed['epoch'] = 'd' * 32
        replacement = compile_inputs(source, changed)
        other, other_payloads, _ = admin_install.decode_operation(replacement['operation.json'], sha(replacement['operation.json']))
        other_provider = admin_host.AdminHost(root, other['profile'], proc_root=provider.proc_root,
            readonly_runner=service.read, service_runner=service.run, clock_ns=lambda: 100)
        with pytest.raises(admin_handoff.HandoffError):
            advance(root, other, other_payloads, other_provider)
        assert root.read_bytes(operation['plan']['journal']['path']) == saved
        assert root.snapshot(admin_handoff.OWNER) is None and not service.commands
    finally:
        root.close()


@pytest.mark.parametrize('change', ['upgrade', 'remove', 'invoker', 'incomplete', 'manual', 'epoch',
                                  'foreign-cgroup', 'missing-directory', 'writable-directory', 'extra-field'])
def test_unsupported_or_unattested_inputs_fail_before_output(source, change):
    value = copy.deepcopy(source[2])
    if change in ('upgrade', 'remove'): value['mode'] = change
    elif change == 'invoker': value['attestation']['invokers'] = [{'id': 'existing'}]
    elif change == 'incomplete': value['attestation']['complete'] = False
    elif change == 'manual': value['attestation']['manual_policy']['operation_id'] = 'd' * 32
    elif change == 'epoch': value['epoch'] = value['operation_id']
    elif change == 'foreign-cgroup': value['cgroups'] = ['/system.slice/another-product.service']
    elif change == 'missing-directory': del value['directory_modes'][fresh.PRIVATE]
    elif change == 'writable-directory': value['directory_modes'][fresh.PRIVATE] = '0777'
    else: value['previous_owner'] = {}
    with pytest.raises((ValueError, RuntimeError)):
        compile_inputs(source, value)


def test_input_and_bundle_digest_drift_fail_closed(source):
    bundle, metadata_sha, value = source
    body = fresh.encoded(value)
    with pytest.raises(fresh.FreshError, match='digest'):
        fresh.compile_fresh(bundle, source_revision=REVISION, metadata_sha256=metadata_sha,
            input_bytes=body + b' ', inputs_sha256=sha(body))
    with pytest.raises(ValueError, match='digest'):
        fresh.compile_fresh(bundle, source_revision=REVISION, metadata_sha256='0' * 64,
            input_bytes=body, inputs_sha256=sha(body))
    with pytest.raises(fresh.FreshError, match='digest'):
        fresh.compile_fresh(bundle, source_revision=REVISION, metadata_sha256=None,
            input_bytes=body, inputs_sha256=sha(body))


def test_template_cannot_be_used_as_an_attestation(source, capsys):
    bundle, metadata_sha, _ = source
    assert fresh.main(['--bundle', str(bundle), '--bundle-sha256', metadata_sha,
        '--source-revision', REVISION, '--input-template']) == 0
    template = json.loads(capsys.readouterr().out)
    assert template['attestation']['complete'] is False
    assert all(value is None for value in template['directory_modes'].values())
    with pytest.raises(fresh.FreshError):
        compile_inputs(source, template)


def test_existing_scoped_process_blocks_before_owner_or_handoff_record(source, tmp_path):
    root, operation, payloads, provider, service = host_fixture(tmp_path, compile_inputs(source))
    fields = ['S', '1', '321', '321', *['0'] * 15, '789']
    protected_put(provider.proc_root, '/321/stat', ('321 (fixture) ' + ' '.join(fields) + '\n').encode())
    protected_put(provider.proc_root, '/321/cgroup', ('0::' + fresh.RECOVERY_CGROUP + '\n').encode())
    try:
        with pytest.raises(admin_handoff.HandoffError, match='existing scoped work'):
            advance(root, operation, payloads, provider)
        assert root.snapshot(admin_handoff.OWNER) is None
        assert root.snapshot(operation['plan']['journal']['path']) is None
        assert service.commands == []
    finally:
        root.close()


@pytest.mark.parametrize('collision', ['owner', 'payload', 'directory-mode', 'attestation'])
def test_actual_host_collisions_preserve_existing_objects_and_cannot_open_owner(source, tmp_path, collision):
    root, operation, payloads, provider, service = host_fixture(tmp_path, compile_inputs(source))
    try:
        if collision == 'owner':
            victim = protected_put(root.base, admin_handoff.OWNER,
                fresh.encoded({**operation['plan']['owner'], 'epoch': 'd' * 32}))
        elif collision == 'payload':
            victim = protected_put(root.base, admin_manifest.RECEIVER, b'preexisting unrelated bytes\n', 0o644)
        elif collision == 'directory-mode':
            victim = root.base / fresh.PRIVATE.lstrip('/'); victim.chmod(0o755)
        else:
            victim = protected_put(root.base, operation['profile']['attestation']['path'], b'{}\n')
        before = (victim.stat().st_ino, victim.stat().st_mode,
                  victim.read_bytes() if victim.is_file() else None)
        with pytest.raises((ValueError, RuntimeError)):
            for _ in range(4): advance(root, operation, payloads, provider)
        assert before == (victim.stat().st_ino, victim.stat().st_mode,
                          victim.read_bytes() if victim.is_file() else None)
        assert service.commands == []
        if collision == 'payload':
            assert json.loads(root.read_bytes(admin_handoff.OWNER))['state'] == 'transitioning'
            assert root.snapshot(admin_manifest.BOOTSTRAP + '/release_admin.py') is None
    finally:
        root.close()


def test_local_output_is_private_and_never_overwritten(source, tmp_path):
    files = compile_inputs(source)
    output = tmp_path / 'prepared'
    fresh.write_output(output, files)
    assert {path.name for path in output.iterdir()} == set(files)
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())
    with pytest.raises(fresh.FreshError, match='new directory'):
        fresh.write_output(output, files)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == files
