"""Local lifecycle transactions and owned processes; no host manager or network."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from host.lifecycle import evidence, filesystem
import admin_handoff as handoff
import admin_host as actual_host
import release_receiver_entry as launcher

BOOT = '11111111-1111-4111-8111-111111111111'
DISPATCHER = '/usr/local/lib/develative-deploy/release_recover.py'
GENERATION = '/usr/local/lib/develative-deploy/whatsapp-generations/' + 'c' * 64
SOURCE = b'"""Approved fixture."""\nfrom __future__ import annotations\nVALUE = 7\nif __name__ == "__main__":\n    print("old work")\n'
NEW = Path(launcher.__file__).read_bytes()
BACKUP_OLD = (Path(__file__).parent/'fixtures/backup_runtime_049.py.txt').read_bytes()
BACKUP_NEW = (Path(__file__).parents[1]/'scripts/backup_runtime.py').read_bytes()
DESTINATION_FIXTURES = {handoff.BACKUP_ENTRY: 'backup_runtime_049.py.txt',
    handoff.TENANT_ENTRY: 'tenant_admin_legacy_20261017.py.txt',
    handoff.PROVISION_ENTRY: 'provision_host_legacy_20261017.py.txt'}
LEGACY_SOURCES = {path: (Path(__file__).parent/'fixtures'/name).read_bytes()
                  for path, name in DESTINATION_FIXTURES.items()}
CANDIDATE_SOURCES = {path: (Path(__file__).parents[1]/'scripts'/Path(path).name).read_bytes()
                     for path in DESTINATION_FIXTURES}


@pytest.mark.parametrize('parent', [
    str(Path(handoff.TENANT_ENTRY).parent),
    str(Path(handoff.RECEIVER).parent),
    handoff.GENERATIONS + '/' + 'a' * 64,
])
def test_tenant_database_admission_is_exact_and_does_not_authorize_siblings(parent):
    assert handoff._administrative_path(parent + '/tenant_database.py')
    for name in ('tenant_database.pyc', 'tenant_database_extra.py',
                 'tenant_database.py/arbitrary.py', '../tenant_database.py',
                 'arbitrary/tenant_database.py'):
        assert not handoff._administrative_path(parent + '/' + name)


def file_spec(content, *, retain=False):
    return {'sha256': hashlib.sha256(content).hexdigest(), 'mode': 0o600, 'uid': os.getuid(), 'gid': os.getgid(),
            'retention': 'retain' if retain else 'managed'}


def manifest(files=None, *, owner='whatsapp'):
    return {'format': 1, 'owner': owner, 'files': files or {}, 'directories': {}}


def action(before, after):
    return {'before': before, 'after': after,
            'allowed_paths': sorted(set(before['files']) | set(after['files']))}


def write(root, path, content):
    selected = root / path.lstrip('/')
    # Private fixture parents must match the plan under both CI umask022 and
    # local umask077. Preserve every existing directory's inode and mode.
    missing = []
    parent = selected.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for parent in reversed(missing):
        parent.mkdir(mode=0o700)
        parent.chmod(0o700)
    selected.write_bytes(content)
    selected.chmod(0o600)
    return selected


def runtime_completion(root, plan):
    """Explicit completed synthetic runtime; no running workload in this fixture."""
    operation = plan['runtime_retirement']['operation_id']
    value = {'format':'whatsapp-runtime-retirement-v1','operation_id':operation,
        'admin_plan_sha256':handoff.digest(plan),'plan_sha256':'7'*64,'phase':'verified','intent':None,
        'processes':[], 'receipts':{'frontend':{'phase':'complete'},'renewals':{'status':'retired'}}}
    return write(root,actual_host.STATE+'/runtime-retirement-'+operation+'.json',handoff.encoded(value))


class Provider:
    def __init__(self, root, proc, plan, inventories):
        self.root, self.proc, self.plan, self.inventories = root, proc, plan, inventories
        self.locked = False
        self.calls = []
        self.terminals = True
        self.admitted = True
        self.expired = False
        self.ready = False

    def now_ns(self):
        return time.monotonic_ns() + (10_000_000_000 if self.expired else 0)

    def envelope(self, stage, prior):
        item = self.inventories[stage]
        context = {'format': 1, 'authority': 'root-inventory', 'plan_digest': handoff.digest(self.plan),
                   'invocation_id': 'local-test', 'generation_id': 'b' * 64,
                   'inventory_digest': evidence.digest_inventory(item['scope'], item['manifest'], {}, prior_processes=prior),
                   'boot_id': (self.proc/'sys/kernel/random/boot_id').read_text().strip()}
        receipt = evidence.observe(item['scope'], item['manifest'], context=context, units={}, fs_root=self.root,
                                   proc_root=self.proc, runner=lambda argv: pytest.fail('No manager calls'), prior_processes=prior)
        return {'receipt': receipt, 'context': context, 'now_ns': time.monotonic_ns()}

    def inventory(self, plan, plan_digest):
        assert not self.locked
        self.calls.append('inventory')
        if not self.admitted:
            raise handoff.HandoffError('External forced-command mapping was not inventoried')
        return self.envelope('inventory', [])

    def observe(self, plan, prior_processes, *, phase):
        assert not self.locked
        self.calls.append('observe:' + phase)
        return self.envelope(phase, prior_processes)

    @contextmanager
    def critical_section(self, plan):
        assert not self.locked
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    def journals_terminal(self, plan):
        self.calls.append('journals')
        if not self.terminals:
            raise handoff.Pending('An existing journal is not terminal')

    def verify_installation(self, plan):
        self.calls.append('verify')
        if plan['mode'] == 'remove':
            assert not (self.root / handoff.RECEIVER.lstrip('/')).exists()
        else:
            # Before owner publication, recovery is armed but owner is closed.
            assert (self.root / handoff.RECEIVER.lstrip('/')).read_bytes() == NEW

    def activate_recovery(self, plan):
        assert not self.locked
        self.calls.append('arm-whatsapp')
        self.ready = True

    def verify_invokers_absent(self, plan, *, after_removal=False, resuming_removal=False):
        assert not (after_removal and resuming_removal)
        if after_removal:
            assert not (self.root / handoff.RECEIVER.lstrip('/')).exists()
        self.calls.append('verify-absent-after' if after_removal else
                          'verify-absent-resuming' if resuming_removal else 'verify-absent-before')

    def verify_runtime_retirement(self, plan):
        self.calls.append('verify-runtime')
        with filesystem.Root(self.root) as root:
            return actual_host.runtime_retirement_receipt(root,plan,handoff.digest(plan))

    def close_recovery(self, plan):
        assert not self.locked
        self.calls.append('close-whatsapp')
        self.ready = False


def fixture(tmp_path, mode='legacy'):
    root = tmp_path / 'root'; root.mkdir()
    proc = tmp_path / 'proc'; proc.mkdir()
    (root/'var/lib').mkdir(parents=True)
    write(proc, '/sys/kernel/random/boot_id', (BOOT+'\n').encode())
    source = SOURCE if mode == 'legacy' else NEW + b'\n# previous synthetic generation\n' if mode == 'upgrade' else NEW
    if mode != 'fresh':
        write(root, handoff.RECEIVER, source)
    write(root, DISPATCHER, b'# BOX + WA fixture\n')
    write(root, handoff.RUNTIME, b'# preserved active runtime\n')
    guard = handoff.guarded_legacy_source(SOURCE, hashlib.sha256(SOURCE).hexdigest())
    owner = {'protocol': 1, 'epoch': 'a' * 32, 'state': 'dedicated', 'generation': GENERATION, 'manifest_sha256': 'c' * 64}
    previous_owner = ({**owner, 'epoch': 'f' * 32, 'generation': handoff.GENERATIONS + '/' + 'b' * 64,
                       'manifest_sha256': 'b' * 64} if mode == 'upgrade' else owner if mode == 'remove' else None)
    if previous_owner is not None:
        write(root, handoff.OWNER, handoff.encoded(previous_owner))
    directory = {'mode': 0o700, 'uid': os.getuid(), 'gid': os.getgid(), 'retention': 'retain'}
    control_dirs = {}
    for target in ('/etc/develative-deploy/recovery-owners', '/var/lib/develative-deploy/whatsapp/handoff'):
        for parent in reversed(Path(target).parents):
            if str(parent) != '/' and not (root / str(parent).lstrip('/')).exists():
                control_dirs[str(parent)] = directory
        control_dirs[target] = directory
    plan = {'format': handoff.FORMAT, 'id': 'd' * 32, 'mode': mode, 'inventory_digest': 'e' * 64,
            'evidence_digests': {}, 'owner': owner, 'previous_owner': previous_owner,
            'owner_metadata': {'mode': 0o600, 'uid': os.getuid(), 'gid': os.getgid()},
            'journal': {'path': '/var/lib/develative-deploy/whatsapp/handoff/' + 'd'*32 + '.json',
                        'mode': 0o600, 'uid': os.getuid(), 'gid': os.getgid()},
            'control_directories': control_dirs, 'actions': {}}
    old = manifest({handoff.RECEIVER: file_spec(SOURCE)})
    gated = manifest({handoff.RECEIVER: file_spec(guard)})
    final = manifest({handoff.RECEIVER: file_spec(NEW)})
    if mode == 'legacy':
        closed = {}
        for destination, content in LEGACY_SOURCES.items():
            write(root, destination, content)
            closed[destination] = handoff.guarded_legacy_destination(destination, content)
            old['files'][destination] = file_spec(content)
            gated['files'][destination] = file_spec(closed[destination])
            final['files'][destination] = file_spec(CANDIDATE_SOURCES[destination])
        plan['actions'] = {'guard_ingress': action(old, gated),
            'cut_dispatcher': action(manifest({DISPATCHER: file_spec(b'# BOX + WA fixture\n')}, owner='box'),
                                     manifest({DISPATCHER: file_spec(b'# BOX only fixture\n')}, owner='box')),
            'install': action(gated, final)}
        payloads = {'guard_ingress': {handoff.RECEIVER: guard, **closed}, 'cut_dispatcher': {DISPATCHER: b'# BOX only fixture\n'},
                    'install': {handoff.RECEIVER: NEW, **CANDIDATE_SOURCES}}
        stage_manifests = {'inventory': old, 'legacy_work': gated, 'legacy_all': gated, 'installed': final}
    elif mode == 'fresh':
        plan['actions'] = {'install': action(manifest(), final)}
        payloads = {'install': {handoff.RECEIVER: NEW}}
        stage_manifests = {'inventory': manifest({DISPATCHER: file_spec(b'# BOX + WA fixture\n')}), 'installed': final}
    elif mode == 'upgrade':
        previous = manifest({handoff.RECEIVER: file_spec(source)})
        plan['actions'] = {'install': action(previous, final)}
        payloads = {'install': {handoff.RECEIVER: NEW}}
        stage_manifests = {'inventory': previous, 'previous': previous, 'installed': final}
    else:
        closed = manifest({handoff.RECEIVER: file_spec(b'# closed external invocation fixture\n')})
        plan['actions'] = {'close_invokers': action(final, closed), 'remove': action(closed, manifest())}
        payloads = {'close_invokers': {handoff.RECEIVER: b'# closed external invocation fixture\n'}, 'remove': {}}
        stage_manifests = {'inventory': final, 'removal': closed}
    inventories = {}
    for stage, files in stage_manifests.items():
        scope = {'cgroups': ['/synthetic-whatsapp'], 'script_roots': [], 'script_paths': list(LEGACY_SOURCES) if mode == 'legacy' else []}
        inventories[stage] = {'scope': scope, 'manifest': files}
        plan['evidence_digests'][stage] = evidence.digest_inventory(scope, files, {})
    if mode == 'remove':
        plan['runtime_retirement'] = {'operation_id':'6'*32}
        runtime_completion(root,plan)
    provider = Provider(root, proc, plan, inventories)
    return filesystem.Root(root), plan, payloads, provider


def advance(root, plan, payloads, provider, *, until='verified', fault=None):
    for _ in range(25):
        receipt = handoff.handoff(root, plan, payloads, provider, fault=fault)
        if receipt['pending'] or receipt['phase'] == until:
            return receipt
    pytest.fail('Handoff did not converge')


def process(proc, *, pid=1234, state='S', start=17, boot=BOOT):
    path = proc / str(pid); path.mkdir(exist_ok=True)
    # Linux stat field 22 (starttime), fields after comm begin with state.
    fields = [state, '1', str(pid), str(pid), *(['0'] * 15), str(start), *(['0'] * 5)]
    (path/'stat').write_text(str(pid) + ' (synthetic) ' + ' '.join(fields))
    (path/'cgroup').write_text('0::/synthetic-whatsapp\n')
    (path/'cmdline').write_bytes(b'python\0fixture\0')
    return path


@pytest.mark.parametrize('mode', ['legacy', 'fresh', 'upgrade', 'remove'])
def test_actual_engine_forward_lifecycle_preserves_runtime_and_other_owner(tmp_path, mode):
    root, plan, payloads, provider = fixture(tmp_path, mode)
    with root:
        runtime = root.read_bytes(handoff.RUNTIME)
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'
        if mode == 'remove':
            assert root.snapshot(handoff.OWNER) is None
        else:
            owner = json.loads(root.read_bytes(handoff.OWNER))
            assert owner['state'] == 'dedicated'
        assert root.read_bytes(handoff.RUNTIME) == runtime
        expected = b'# BOX only fixture\n' if mode == 'legacy' else b'# BOX + WA fixture\n'
        assert root.read_bytes(DISPATCHER) == expected
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'
        assert not any('global' in call or 'box' in call for call in provider.calls)


def test_upgrade_keeps_previous_epoch_until_processes_and_journals_drain(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path, 'upgrade')
    with root:
        previous_source = root.read_bytes(handoff.RECEIVER)
        record = process(provider.proc)
        assert advance(root, plan, payloads, provider, until='retiring')['phase'] == 'retiring'
        expected = {**plan['previous_owner'], 'state': 'retiring'}
        assert json.loads(root.read_bytes(handoff.OWNER)) == expected
        assert advance(root, plan, payloads, provider)['pending']
        assert root.read_bytes(handoff.RECEIVER) == previous_source
        for child in record.iterdir(): child.unlink()
        record.rmdir()
        provider.terminals = False
        assert advance(root, plan, payloads, provider)['pending']
        assert json.loads(root.read_bytes(handoff.OWNER)) == expected
        provider.terminals = True
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'
        assert json.loads(root.read_bytes(handoff.OWNER)) == plan['owner']
        assert root.read_bytes(handoff.RECEIVER) == NEW
        assert 'observe:previous' in provider.calls and not provider.locked


@pytest.mark.parametrize('target', ['retiring', 'previous_drained', 'transitioning', 'installed',
                                  'recovery_armed', 'owner_dedicated', 'verified'])
@pytest.mark.parametrize('when', ['before-', 'after-'])
def test_upgrade_interruptions_resume_forward_with_exact_owner(tmp_path, target, when):
    root, plan, payloads, provider = fixture(tmp_path, 'upgrade')
    triggered = False
    def crash(event, journal):
        nonlocal triggered
        if event == when + target and not triggered:
            triggered = True
            raise RuntimeError('synthetic upgrade interruption')
    with root:
        with pytest.raises(RuntimeError, match='synthetic upgrade'):
            advance(root, plan, payloads, provider, fault=crash)
        assert triggered and not provider.locked
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'
        assert json.loads(root.read_bytes(handoff.OWNER)) == plan['owner']
        assert root.read_bytes(DISPATCHER) == b'# BOX + WA fixture\n'


@pytest.mark.parametrize('checkpoint', ['journal-staging', 'staged-file', 'journal-prepared', 'intent-file'])
@pytest.mark.parametrize('blocker', ['process', 'journal'])
def test_upgrade_unpublished_epoch_reobserves_after_interrupted_owner_write(tmp_path, checkpoint, blocker):
    root, plan, payloads, provider = fixture(tmp_path, 'upgrade')
    class FaultFilesystem:
        validate_manifest = staticmethod(filesystem.validate_manifest)
        resume = staticmethod(filesystem.resume)
        @staticmethod
        def reconcile(*args, **kwargs):
            def crash(event, detail):
                if (kwargs['operation_id'] == handoff._operation(plan, 'owner-transitioning')
                        and event == checkpoint):
                    raise RuntimeError('interrupted upgrade epoch publication')
            return filesystem.reconcile(*args, **kwargs, fault=crash)
    with root:
        assert advance(root, plan, payloads, provider, until='previous_drained')['phase'] == 'previous_drained'
        with pytest.raises(RuntimeError, match='interrupted upgrade epoch'):
            handoff.handoff(root, plan, payloads, provider, filesystem=FaultFilesystem)
        previous = {**plan['previous_owner'], 'state': 'retiring'}
        assert json.loads(root.read_bytes(handoff.OWNER)) == previous
        # Retiring still admits old-generation recovery. It may appear after
        # the interrupted observation; the durable intent is not a new census.
        running = process(provider.proc) if blocker == 'process' else None
        provider.terminals = blocker != 'journal'
        provider.calls.clear()
        result = handoff.handoff(root, plan, payloads, provider)
        assert result['pending'] and result['phase'] == 'previous_drained'
        assert 'observe:previous' in provider.calls
        assert json.loads(root.read_bytes(handoff.OWNER)) == previous
        assert root.read_bytes(handoff.RECEIVER) != NEW
        if running is not None:
            for child in running.iterdir(): child.unlink()
            running.rmdir()
        provider.terminals = True
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'
        assert json.loads(root.read_bytes(handoff.OWNER)) == plan['owner']
        assert root.read_bytes(handoff.RUNTIME) == b'# preserved active runtime\n'
        assert root.read_bytes(DISPATCHER) == b'# BOX + WA fixture\n'


@pytest.mark.parametrize('checkpoint', ['replaced-file', 'completed-file'])
def test_upgrade_published_epoch_resumes_forward_without_reopening_previous_owner(tmp_path, checkpoint):
    root, plan, payloads, provider = fixture(tmp_path, 'upgrade')
    class FaultFilesystem:
        validate_manifest = staticmethod(filesystem.validate_manifest)
        resume = staticmethod(filesystem.resume)
        @staticmethod
        def reconcile(*args, **kwargs):
            def crash(event, detail):
                if (kwargs['operation_id'] == handoff._operation(plan, 'owner-transitioning')
                        and event == checkpoint):
                    raise RuntimeError('interrupted published upgrade epoch')
            return filesystem.reconcile(*args, **kwargs, fault=crash)
    with root:
        advance(root, plan, payloads, provider, until='previous_drained')
        with pytest.raises(RuntimeError, match='interrupted published upgrade epoch'):
            handoff.handoff(root, plan, payloads, provider, filesystem=FaultFilesystem)
        closed = {**plan['owner'], 'state': 'transitioning'}
        assert json.loads(root.read_bytes(handoff.OWNER)) == closed
        result = handoff.handoff(root, plan, payloads, provider)
        assert result['phase'] == 'transitioning' and not result['pending']
        assert json.loads(root.read_bytes(handoff.OWNER)) == closed
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'
        assert json.loads(root.read_bytes(handoff.OWNER)) == plan['owner']


@pytest.mark.parametrize('change', ['absent-owner', 'reused-epoch', 'missing-census'])
def test_upgrade_rejects_incomplete_owner_or_process_contract_before_writes(tmp_path, change):
    root, plan, payloads, provider = fixture(tmp_path, 'upgrade')
    if change == 'absent-owner': plan['previous_owner'] = None
    elif change == 'reused-epoch': plan['owner']['epoch'] = plan['previous_owner']['epoch']
    else: plan['evidence_digests'].pop('previous')
    with root, pytest.raises(handoff.HandoffError):
        handoff.handoff(root, plan, payloads, provider)
    assert not (provider.root / 'var/lib/develative-host-lifecycle').exists()


def test_unknown_invokers_fail_before_every_filesystem_write(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path)
    provider.admitted = False
    with root, pytest.raises(handoff.HandoffError, match='mapping'):
        handoff.handoff(root, plan, payloads, provider)
    assert not (provider.root / 'var/lib/develative-host-lifecycle').exists()
    assert not (provider.root / handoff.OWNER.lstrip('/')).exists()


def test_guard_preserves_import_and_future_but_closes_new_execution():
    guarded = handoff.guarded_legacy_source(SOURCE, hashlib.sha256(SOURCE).hexdigest())
    namespace = {'__name__': 'imported_old_recovery'}
    exec(compile(guarded, '<synthetic>', 'exec'), namespace)
    assert namespace['VALUE'] == 7
    with pytest.raises(SystemExit, match='admission closed'):
        exec(compile(guarded, '<synthetic>', 'exec'), {'__name__': '__main__'})
    with pytest.raises(handoff.HandoffError, match='approved digest'):
        handoff.guarded_legacy_source(SOURCE + b'# changed', hashlib.sha256(SOURCE).hexdigest())


def test_live_scoped_process_defers_without_cut_or_lock_held(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path)
    with root:
        advance(root, plan, payloads, provider, until='ingress_closed')
        record = process(provider.proc)
        result = advance(root, plan, payloads, provider)
        assert result['pending'] and result['phase'] == 'ingress_closed' and not provider.locked
        assert root.read_bytes(DISPATCHER) == b'# BOX + WA fixture\n'
        for child in record.iterdir(): child.unlink()
        record.rmdir()
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'


def test_unfinished_journal_never_cuts_dispatcher(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path)
    provider.terminals = False
    with root:
        result = advance(root, plan, payloads, provider)
        assert result['pending'] and result['phase'] == 'ingress_closed'
        assert json.loads(root.read_bytes(handoff.OWNER))['state'] == 'transitioning'
        assert root.read_bytes(DISPATCHER) == b'# BOX + WA fixture\n'
        provider.terminals = True
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'


def test_stale_evidence_fails_before_zero_inference_or_mutation(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path)
    provider.expired = True
    with root, pytest.raises(evidence.EvidenceError, match='stale'):
        handoff.handoff(root, plan, payloads, provider)
    assert not (provider.root / 'var/lib/develative-host-lifecycle').exists()


@pytest.mark.parametrize('target', ['transitioning', 'ingress_closed', 'dispatcher_cut', 'installed', 'recovery_armed', 'owner_dedicated'])
@pytest.mark.parametrize('when', ['before-', 'after-'])
def test_crash_after_durable_intent_resumes_only_forward(tmp_path, target, when):
    root, plan, payloads, provider = fixture(tmp_path)
    triggered = False
    def crash(event, journal):
        nonlocal triggered
        if event == when + target and not triggered:
            triggered = True
            raise RuntimeError('synthetic crash')
    with root:
        with pytest.raises(RuntimeError, match='synthetic crash'):
            advance(root, plan, payloads, provider, fault=crash)
        assert triggered
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'
        assert root.read_bytes(handoff.RECEIVER) == NEW
        assert root.read_bytes(DISPATCHER) == b'# BOX only fixture\n'


def test_fresh_recovery_observation_failure_preserves_intent_then_resumes_forward(tmp_path):
    from host.lifecycle.services import (RECOVERY_EMPTY_PROPERTIES, RECOVERY_PROPERTIES,
        RECOVERY_ENTRYPOINT, RecoveryServices, WA_RECOVERY)
    root, plan, payloads, provider = fixture(tmp_path, 'fresh')
    operations = []
    readable = False
    def reader(argv, **kwargs):
        if argv[0] == '/usr/bin/busctl':
            if not readable:
                raise filesystem.LifecycleError('Synthetic missing typed response')
            _, signature, empty = RECOVERY_EMPTY_PROPERTIES[argv[-1]]
            return json.dumps({'type': signature, 'data': empty}).encode()
        unit = argv[-1]
        values = {key: '' for key in RECOVERY_PROPERTIES[unit] if key not in RECOVERY_EMPTY_PROPERTIES}
        values.update(Id=unit, LoadState='loaded', NeedDaemonReload='no',
            FragmentPath='/etc/systemd/system/'+unit, Job='', ActiveState='inactive', SubState='dead')
        if unit == WA_RECOVERY[1]:
            armed = 'start-wa-recovery' in operations
            values.update(ActiveState='active' if armed else 'inactive',
                UnitFileState='enabled' if armed else 'disabled', Unit=WA_RECOVERY[0],
                TimersMonotonic='{ OnUnitInactiveUSec=1min; next=2; }\nTimersMonotonic={ OnBootUSec=45s; next=1; }')
        else:
            values.update(MainPID='0', ControlPID='0', Type='oneshot', User='root', KillMode='control-group',
                RemainAfterExit='no', Restart='no', TimeoutStartUSec='10min',
                ExecStart='{ path=/usr/bin/python3; argv[]=/usr/bin/python3 -I -B '+RECOVERY_ENTRYPOINT+' recovery; }')
        return '\n'.join(key+'='+value for key, value in values.items()).encode()
    with root:
        advance(root, plan, payloads, provider, until='installed')
        runtime = root.read_bytes(handoff.RUNTIME)
        dispatcher = root.read_bytes(DISPATCHER)
        unit_manifest = manifest()
        for unit in WA_RECOVERY:
            path = '/etc/systemd/system/'+unit
            write(root.base, path, (ROOT/'plugins/whatsapp/deploy'/unit).read_bytes())
            unit_manifest['files'][path] = {**root.snapshot(path), 'retention': 'managed'}
        controller = RecoveryServices(root, reader=reader,
            runner=lambda operation, **kwargs: operations.append(operation))
        provider.activate_recovery = lambda plan: controller.activate(unit_manifest)
        with pytest.raises(filesystem.LifecycleError, match='missing typed response'):
            advance(root, plan, payloads, provider)
        journal = json.loads(root.read_bytes(plan['journal']['path']))
        assert journal['phase'] == 'installed' and journal['intent'] == 'recovery_armed'
        assert not operations and not provider.locked
        assert json.loads(root.read_bytes(handoff.OWNER))['state'] != 'dedicated'
        readable = True
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'
        assert operations == ['reload-definitions', 'enable-wa-recovery', 'start-wa-recovery']
        assert json.loads(root.read_bytes(handoff.OWNER)) == plan['owner']
        assert root.read_bytes(handoff.RUNTIME) == runtime
        assert root.read_bytes(DISPATCHER) == dispatcher
        assert controller.verify(unit_manifest)['dedicated_recovery_verified']


def test_late_parent_after_prior_drain_blocks_install(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path)
    with root:
        advance(root, plan, payloads, provider, until='legacy_drained')
        process(provider.proc)
        receipt = handoff.handoff(root, plan, payloads, provider)
        assert receipt['pending'] and receipt['phase'] == 'legacy_drained'
        assert root.read_bytes(handoff.RECEIVER) != NEW


def test_new_boot_requires_fresh_census_and_does_not_assume_no_processes(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path)
    with root:
        advance(root, plan, payloads, provider, until='dispatcher_cut')
        (provider.proc/'sys/kernel/random/boot_id').write_text('22222222-2222-4222-8222-222222222222\n')
        process(provider.proc)
        assert handoff.handoff(root, plan, payloads, provider)['pending']


def test_plan_change_never_silently_reuses_existing_journal(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path)
    with root:
        handoff.handoff(root, plan, payloads, provider)
        plan['owner']['epoch'] = 'f' * 32
        with pytest.raises(handoff.HandoffError, match='identity'):
            handoff.handoff(root, plan, payloads, provider)


def test_permanent_launcher_validates_paths_then_executes_only_dedicated_entry(tmp_path, monkeypatch):
    entry = write(tmp_path, '/legacy/github_release.py', NEW)
    bootstrap = write(tmp_path, '/bootstrap/release_entry.py', b'# fixture')
    write(tmp_path, '/bootstrap/release_admin.py', b'# fixture')
    python = write(tmp_path, '/bin/python', b'# fixture')
    for name, value in {'ENTRY': entry, 'BOOTSTRAP': bootstrap, 'PYTHON': python, '_TRUST_ROOT': tmp_path,
                        '__file__': str(entry)}.items():
        monkeypatch.setattr(launcher, name, value)
    monkeypatch.setattr(launcher, '_trusted_uid', lambda uid: uid == os.getuid())
    calls = []
    monkeypatch.setattr(launcher.os, 'execv', lambda exe, argv: calls.append((exe, argv)))
    launcher.main(['--synthetic'])
    assert calls == [(str(python), [str(python), '-I', '-B', str(bootstrap), 'receiver', '--synthetic'])]
    bootstrap.chmod(0o666)
    with pytest.raises(RuntimeError, match='protection'):
        launcher.main([])
    assert len(calls) == 1


def test_already_compiled_legacy_child_survives_replacement_and_requires_drain(tmp_path):
    """A real owned child proves atomic replacement alone does not revoke code."""
    source = tmp_path / 'old.py'; source.write_bytes(SOURCE)
    child = subprocess.Popen([sys.executable, '-I', '-B', '-c',
        'import pathlib,sys; code=compile(pathlib.Path(sys.argv[1]).read_bytes(),sys.argv[1],"exec");'
        'print("loaded",flush=True);sys.stdin.readline();exec(code,{"__name__":"__main__"})', str(source)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'loaded'
        replacement = tmp_path/'replacement'; replacement.write_bytes(handoff.guarded_legacy_source(SOURCE, hashlib.sha256(SOURCE).hexdigest()))
        replacement.replace(source)
        output, errors = child.communicate('\n', timeout=5)
        assert child.returncode == 0 and output.strip() == 'old work' and errors == ''
        fresh = subprocess.run([sys.executable, '-I', '-B', str(source)], capture_output=True, text=True, timeout=5)
        assert fresh.returncode != 0 and 'admission closed' in fresh.stderr
    finally:
        if child.poll() is None: child.kill(); child.wait(timeout=5)


@pytest.mark.parametrize('event', ['journal-staging', 'staged-file', 'journal-prepared', 'intent-file', 'replaced-file', 'completed-file'])
@pytest.mark.parametrize('phase', ['initial', 'installed'])
def test_control_checkpoint_crash_recovers_same_inline_bytes_before_new_evidence(tmp_path, event, phase):
    root, plan, payloads, provider = fixture(tmp_path, 'fresh')
    if phase == 'installed':
        advance(root, plan, payloads, provider, until='installed')
    class FaultFilesystem:
        validate_manifest = staticmethod(filesystem.validate_manifest)
        resume = staticmethod(filesystem.resume)
        triggered = False
        @classmethod
        def reconcile(cls, *args, **kwargs):
            controlled = plan['journal']['path'] in kwargs['after']['files']
            def crash(at, detail):
                if controlled and not cls.triggered and at == event:
                    cls.triggered = True
                    raise RuntimeError('checkpoint crash')
            return filesystem.reconcile(*args, **kwargs, fault=crash)
    with root:
        with pytest.raises(RuntimeError, match='checkpoint crash'):
            handoff.handoff(root, plan, payloads, provider, filesystem=FaultFilesystem)
        assert FaultFilesystem.triggered
        assert 'arm-whatsapp' not in provider.calls
        # The provider clock and receipt have changed; pending durable payload
        # must be recovered first, never reconstructed from the fresh receipt.
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'


def test_removal_requires_exact_invoker_absence_before_any_managed_removal(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path, 'remove')
    with root:
        advance(root, plan, payloads, provider, until='retired')
        def absent(plan):
            raise handoff.HandoffError('An external invoker is still present')
        provider.verify_invokers_absent = absent
        with pytest.raises(handoff.HandoffError, match='invoker'):
            handoff.handoff(root, plan, payloads, provider)
        assert root.snapshot(handoff.RECEIVER) is not None
        assert json.loads(root.read_bytes(handoff.OWNER))['state'] == 'retired'


def interrupted_two_reference_removal(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path, 'remove')
    second = '/etc/systemd/system/develative-whatsapp-recovery.service'
    content = b'# exact synthetic recovery reference\n'
    write(provider.root, second, content)
    # Distinct snapshots avoid aliasing an earlier action while declaring the
    # second managed reference in every observation and publication boundary.
    for name, selected in list(plan['actions'].items()):
        selected = copy.deepcopy(selected)
        selected['before']['files'][second] = file_spec(content)
        if name == 'close_invokers':
            selected['after']['files'][second] = file_spec(content)
        selected['allowed_paths'] = sorted(set(selected['allowed_paths']) | {second})
        plan['actions'][name] = selected
    for stage, item in list(provider.inventories.items()):
        item = copy.deepcopy(item)
        item['manifest']['files'][second] = file_spec(content)
        provider.inventories[stage] = item
        plan['evidence_digests'][stage] = evidence.digest_inventory(item['scope'], item['manifest'], {})
    runtime_completion(provider.root,plan)
    advance(root, plan, payloads, provider, until='retired')
    class InterruptedFilesystem:
        validate_manifest = staticmethod(filesystem.validate_manifest)
        inspect_operation = staticmethod(filesystem.inspect_operation)
        resume = staticmethod(filesystem.resume)
        @staticmethod
        def reconcile(*args, **kwargs):
            def crash(event, detail):
                if (kwargs['operation_id'] == handoff._operation(plan, 'action-remove')
                        and event == 'removed-file' and detail['path'] == second):
                    raise RuntimeError('partial removal crash')
            return filesystem.reconcile(*args, **kwargs, fault=crash)
    with pytest.raises(RuntimeError, match='partial removal crash'):
        handoff.handoff(root, plan, payloads, provider, filesystem=InterruptedFilesystem)
    assert root.snapshot(second) is None and root.snapshot(handoff.RECEIVER) is not None
    journal = json.loads(root.read_bytes(plan['journal']['path']))
    assert journal['phase'] == 'retired' and journal['intent'] == 'removed'
    return root, plan, payloads, provider, second


def test_partial_removal_replays_exact_intent_before_after_reference_checkpoint(tmp_path):
    root, plan, payloads, provider, second = interrupted_two_reference_removal(tmp_path)
    original = provider.verify_invokers_absent
    def references(plan, *, after_removal=False, resuming_removal=False):
        if not after_removal and not resuming_removal:
            # The original before-state is no longer valid after this crash.
            assert root.snapshot(second) is not None
        if after_removal:
            assert root.snapshot(second) is None and root.snapshot(handoff.RECEIVER) is None
            assert json.loads(root.read_bytes(handoff.OWNER))['state'] == 'retired'
        original(plan, after_removal=after_removal, resuming_removal=resuming_removal)
    provider.verify_invokers_absent = references
    with root:
        provider.calls.clear()
        result = handoff.handoff(root, plan, payloads, provider)
        assert result['phase'] == 'removed'
        assert provider.calls == ['verify-runtime', 'verify-absent-resuming', 'verify-runtime', 'verify-absent-after']
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'
        assert root.snapshot(handoff.OWNER) is None


@pytest.mark.parametrize('tamper', ['invalid-progress', 'different-approved-action'])
def test_resume_removal_validates_exact_engine_intent_before_reference_delegation(tmp_path, tamper):
    root, plan, payloads, provider, _ = interrupted_two_reference_removal(tmp_path)
    path = handoff._engine_journal(plan, 'action-remove')
    record = json.loads(root.read_bytes(path))
    if tamper == 'invalid-progress':
        record['done'] = ['/unapproved-target']
    else:
        record['before']['files'][handoff.RECEIVER]['sha256'] = '0' * 64
        record['plan_sha256'] = hashlib.sha256(filesystem.encoded({
            key: record[key] for key in ('before', 'after', 'allowed_paths')})).hexdigest()
    write(provider.root, path, handoff.encoded(record))
    provider.calls.clear()
    with root, pytest.raises((filesystem.LifecycleError, handoff.HandoffError)):
        handoff.handoff(root, plan, payloads, provider)
    assert 'verify-absent-resuming' not in provider.calls
    assert (provider.root / handoff.RECEIVER.lstrip('/')).exists()


def test_after_reference_failure_keeps_removal_intent_and_retired_owner(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path, 'remove')
    original = provider.verify_invokers_absent
    def fail_after(plan, *, after_removal=False, resuming_removal=False):
        original(plan, after_removal=after_removal, resuming_removal=resuming_removal)
        if after_removal:
            raise handoff.HandoffError('Invariant reference drift')
    with root:
        advance(root, plan, payloads, provider, until='retired')
        provider.verify_invokers_absent = fail_after
        with pytest.raises(handoff.HandoffError, match='reference drift'):
            handoff.handoff(root, plan, payloads, provider)
        journal = json.loads(root.read_bytes(plan['journal']['path']))
        assert journal['phase'] == 'retired' and journal['intent'] == 'removed'
        assert json.loads(root.read_bytes(handoff.OWNER))['state'] == 'retired'
        assert root.snapshot(handoff.RECEIVER) is None
        provider.verify_invokers_absent = original
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'


def test_owner_or_journal_permissions_drift_is_not_repaired(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path)
    with root:
        advance(root, plan, payloads, provider, until='transitioning')
        (provider.root / handoff.OWNER.lstrip('/')).chmod(0o666)
        with pytest.raises(handoff.HandoffError, match='protection'):
            handoff.handoff(root, plan, payloads, provider)
        assert (provider.root / handoff.OWNER.lstrip('/')).stat().st_mode & 0o777 == 0o666


def test_sigkill_owned_handoff_after_inline_intent_can_resume_from_cold_process(tmp_path):
    """Real SIGKILL, real durable engine state; managers and /proc are synthetic."""
    child_code = '''
import os, signal, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1]);sys.path.insert(0, sys.argv[2])
sys.path.insert(0, str(Path(sys.argv[1])/'plugins/whatsapp'))
from tools.testing.installation_fixture import select_legacy
select_legacy()
from test_admin_handoff import fixture, handoff, filesystem
root,plan,payloads,provider=fixture(Path(sys.argv[3]),'fresh')
class Crash:
 validate_manifest=staticmethod(filesystem.validate_manifest)
 resume=staticmethod(filesystem.resume)
 @staticmethod
 def reconcile(*args,**kwargs):
  def fault(event,detail):
   if event=='journal-staging': os.kill(os.getpid(),signal.SIGKILL)
  return filesystem.reconcile(*args,**kwargs,fault=fault)
handoff.handoff(root,plan,payloads,provider,filesystem=Crash)
'''
    script_dir = str(Path(__file__).parent)
    child = subprocess.run([sys.executable, '-I', '-B', '-c', child_code, str(ROOT), script_dir, str(tmp_path)],
                           capture_output=True, timeout=10)
    assert child.returncode == -signal.SIGKILL, child.stderr.decode()
    # Reconstruct the explicit plan in a separate fresh fixture, preserving the
    # killed child's root and durable operation bytes unchanged.
    other = tmp_path / 'model'; other.mkdir()
    reference, plan, payloads, model = fixture(other, 'fresh')
    reference.close()
    root_path = tmp_path / 'root'; proc_path = tmp_path / 'proc'
    provider = Provider(root_path, proc_path, plan, model.inventories)
    with filesystem.Root(root_path) as root:
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'


@pytest.mark.parametrize('target', ['retiring', 'invokers_closed', 'recovery_closed', 'retired', 'removed', 'owner_removed'])
@pytest.mark.parametrize('when', ['before-', 'after-'])
def test_retirement_crashes_do_not_reopen_admission_or_leave_owner_tombstone(tmp_path, target, when):
    root, plan, payloads, provider = fixture(tmp_path, 'remove')
    fired = False
    def crash(event, journal):
        nonlocal fired
        if event == when + target and not fired:
            fired = True
            raise RuntimeError('retirement crash')
    with root:
        with pytest.raises(RuntimeError, match='retirement crash'):
            advance(root, plan, payloads, provider, fault=crash)
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'
        assert root.snapshot(handoff.OWNER) is None and root.snapshot(handoff.RECEIVER) is None
        assert 'arm-whatsapp' not in provider.calls
        assert list((provider.root/'etc/develative-deploy/recovery-owners').glob('*.quarantine'))


def test_owner_publication_rechecks_freshness_after_slow_preflight(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path)
    with root:
        advance(root, plan, payloads, provider, until='recovery_armed')
        verify = provider.verify_installation
        def slow(plan):
            verify(plan)
            provider.expired = True
        provider.verify_installation = slow
        with pytest.raises(evidence.EvidenceError, match='stale'):
            handoff.handoff(root, plan, payloads, provider)
        assert json.loads(root.read_bytes(handoff.OWNER))['state'] == 'transitioning'


def test_owner_publication_rechecks_freshness_after_intent_fsync(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path)
    with root:
        advance(root, plan, payloads, provider, until='recovery_armed')
        def expire(event, journal):
            if event == 'before-owner_dedicated':
                provider.expired = True
        with pytest.raises(evidence.EvidenceError, match='stale'):
            handoff.handoff(root, plan, payloads, provider, fault=expire)
        assert json.loads(root.read_bytes(handoff.OWNER))['state'] == 'transitioning'
        provider.expired = False
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'


def test_incomplete_owner_admission_transaction_requires_new_process_gate(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path)
    class FaultFilesystem:
        validate_manifest = staticmethod(filesystem.validate_manifest)
        resume = staticmethod(filesystem.resume)
        @staticmethod
        def reconcile(*args, **kwargs):
            owner_write = handoff.OWNER in kwargs['after']['files']
            def crash(event, detail):
                if owner_write and event == 'journal-staging':
                    raise RuntimeError('owner publication crash')
            return filesystem.reconcile(*args, **kwargs, fault=crash)
    with root:
        advance(root, plan, payloads, provider, until='recovery_armed')
        with pytest.raises(RuntimeError, match='owner publication crash'):
            handoff.handoff(root, plan, payloads, provider, filesystem=FaultFilesystem)
        process(provider.proc)
        result = handoff.handoff(root, plan, payloads, provider)
        assert result['pending'] and result['phase'] == 'recovery_armed'
        assert json.loads(root.read_bytes(handoff.OWNER))['state'] == 'transitioning'


@pytest.mark.parametrize('mutation', ['generation', 'cut-path', 'install-path', 'control-path', 'runtime'])
def test_closed_path_policy_rejects_unrelated_files_before_actions(tmp_path, mutation):
    root, plan, payloads, provider = fixture(tmp_path)
    if mutation == 'generation':
        plan['owner']['generation'] = '/root/arbitrary'
    elif mutation == 'control-path':
        plan['control_directories']['/root/arbitrary'] = next(iter(plan['control_directories'].values()))
    else:
        name = 'cut_dispatcher' if mutation == 'cut-path' else 'install'
        path = handoff.RUNTIME if mutation == 'runtime' else '/root/arbitrary'
        spec = file_spec(b'changed')
        plan['actions'][name]['after']['files'][path] = spec
        plan['actions'][name]['allowed_paths'].append(path)
        payloads[name][path] = b'changed'
    with root, pytest.raises(handoff.HandoffError):
        handoff.handoff(root, plan, payloads, provider)
    assert not (provider.root / 'var/lib/develative-host-lifecycle').exists()


def test_existing_dedicated_owner_stays_open_for_recovery_until_journals_terminal(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path)
    plan['previous_owner'] = copy.deepcopy(plan['owner'])
    write(provider.root, handoff.OWNER, handoff.encoded(plan['previous_owner']))
    with root:
        handoff.handoff(root, plan, payloads, provider)
        provider.terminals = False
        with pytest.raises(handoff.Pending):
            handoff.handoff(root, plan, payloads, provider)
        assert json.loads(root.read_bytes(handoff.OWNER)) == plan['previous_owner']
        assert root.read_bytes(handoff.RECEIVER) == SOURCE


def test_admin_removal_can_explicitly_retain_required_application_runtime(tmp_path):
    root, plan, payloads, provider = fixture(tmp_path, 'remove')
    runtime = file_spec(b'# preserved active runtime\n')
    removal = copy.deepcopy(plan['actions']['remove'])
    plan['actions']['remove'] = removal
    for key in ('before', 'after'):
        removal[key]['files'][handoff.RUNTIME] = runtime
    removal['allowed_paths'].append(handoff.RUNTIME)
    runtime_completion(provider.root,plan)
    with root:
        before = root.snapshot(handoff.RUNTIME)
        assert advance(root, plan, payloads, provider)['phase'] == 'verified'
        assert root.snapshot(handoff.RUNTIME) == before


@pytest.mark.parametrize('keep_dependency', [False, True])
def test_admin_removal_preserves_adjacent_layout_of_retained_runtime(tmp_path, keep_dependency):
    root, plan, payloads, provider = fixture(tmp_path, 'remove')
    removal = copy.deepcopy(plan['actions']['remove'])
    plan['actions']['remove'] = removal
    dependency = str(Path(handoff.RUNTIME).with_name('installation_layout.py'))
    for key in ('before', 'after'):
        removal[key]['files'][handoff.RUNTIME] = file_spec(b'# retained runtime\n')
    removal['before']['files'][dependency] = file_spec(b'# retained layout\n')
    if keep_dependency:
        removal['after']['files'][dependency] = removal['before']['files'][dependency]
    removal['allowed_paths'].extend((handoff.RUNTIME, dependency))
    with root:
        if keep_dependency:
            handoff.validate_plan(plan, payloads, filesystem)
        else:
            with pytest.raises(handoff.HandoffError, match='unchanged installation dependency'):
                handoff.validate_plan(plan, payloads, filesystem)


@pytest.mark.parametrize('damage',['missing','admin-plan','operation','phase','intent','mode','extra'])
def test_admin_payloads_stay_installed_until_exact_runtime_retirement_verified(tmp_path,damage):
    root,plan,payloads,provider = fixture(tmp_path,'remove')
    with root:
        advance(root,plan,payloads,provider,until='retired')
        operation = plan['runtime_retirement']['operation_id']
        path = provider.root/(actual_host.STATE+'/runtime-retirement-'+operation+'.json').lstrip('/')
        record = json.loads(path.read_bytes())
        if damage == 'missing': path.unlink()
        elif damage == 'mode': path.chmod(0o640)
        else:
            if damage == 'admin-plan': record['admin_plan_sha256'] = '0'*64
            elif damage == 'operation': record['operation_id'] = '0'*32
            elif damage == 'phase': record['phase'] = 'files_removed'
            elif damage == 'intent': record['intent'] = 'verified'
            else: record['unknown'] = True
            path.write_bytes(handoff.encoded(record))
        with pytest.raises(filesystem.LifecycleError,match='[Rr]untime'):
            handoff.handoff(root,plan,payloads,provider)
        assert root.snapshot(handoff.RECEIVER) is not None
        assert json.loads(root.read_bytes(handoff.OWNER))['state'] == 'retired'
        journal = json.loads(root.read_bytes(plan['journal']['path']))
        assert journal['phase'] == 'retired' and journal['intent'] is None


def test_partial_admin_removal_rechecks_runtime_proof_before_replaying_payloads(tmp_path):
    root,plan,payloads,provider,_ = interrupted_two_reference_removal(tmp_path)
    with root:
        operation = plan['runtime_retirement']['operation_id']
        path = provider.root/(actual_host.STATE+'/runtime-retirement-'+operation+'.json').lstrip('/')
        path.unlink()
        with pytest.raises(filesystem.LifecycleError,match='runtime retirement'):
            handoff.handoff(root,plan,payloads,provider)
        assert root.snapshot(handoff.RECEIVER) is not None
        assert json.loads(root.read_bytes(plan['journal']['path']))['intent'] == 'removed'
        runtime_completion(provider.root,plan)
        assert advance(root,plan,payloads,provider)['phase'] == 'verified'
