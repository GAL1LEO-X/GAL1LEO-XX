"""Known legacy transition in real fixture files, finite simulated systemd only."""
import copy
import json
import os
from pathlib import Path
import time
import types

import pytest
from test_host_qos_applicator import BASE, case, installed_whatsapp_identity, qos


@pytest.fixture
def adoption_case(case):
    root, base, policy, kernel, accounts, _ = case
    for name, item in json.loads((BASE / 'tools/tests/fixtures/qos/synthetic-legacy-files.json').read_bytes()).items():
        path = base / name.lstrip('/'); path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(item['content']); path.chmod(item['mode'])
    for record in policy['initial_consumers'].values():
        if record['owner'] != 'whatsapp': continue
        for name, content in qos.consumer_dropins(record)['administrative'].items():
            legacy = content.replace(b'host resource priority', b'WhatsApp resource priority').replace(
                b'develative-host-qos.service', b'whatsapp-resource-priority.service')
            path = base / name.lstrip('/'); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(legacy); path.chmod(0o644)
    (base / (qos.STATE + '/adoption.lock').lstrip('/')).touch(mode=0o600)
    proc = base / 'proc'; (proc / 'sys/kernel/random').mkdir(parents=True)
    (proc / 'sys/kernel/random/boot_id').write_text('01234567-89ab-cdef-0123-456789abcdef\n')
    operation = 'c' * 32; now = time.time_ns()
    evidence_path = '/etc/develative-host-qos/admission-evidence/' + operation + '.json'
    evidence = {'format': 1, 'kind': 'administrative-attestation', 'authority': 'host-administrator',
        'operation_id': operation, 'method': 'externally-verified-priority-admission-suspension',
        'scope': {'script_paths': sorted(qos.adoption.ENTRYPOINTS), 'unmapped_ssh_priority_launches': 'suspended'},
        'observed_ns': now}
    path = base / evidence_path.lstrip('/'); path.parent.mkdir(parents=True)
    path.write_bytes(qos.canonical(evidence)); path.chmod(0o600)
    admission_path = '/etc/develative-host-qos/adoption-' + operation + '.json'
    admission = {'format': 1, 'operation_id': operation, 'script_paths': sorted(qos.adoption.ENTRYPOINTS),
        'manual_freeze': 'until-adoption-complete', 'ssh_admission': 'externally-fenced',
        'ssh_fence_evidence': {'path': evidence_path, 'sha256': qos.sha(qos.canonical(evidence))},
        'issued_ns': now, 'expires_ns': now + 300 * 10**9}
    (base / admission_path.lstrip('/')).write_bytes(qos.canonical(admission))
    states, calls = {}, []
    def state(unit):
        return {**dict.fromkeys(qos.adoption.PROPERTIES, ''), 'Id': unit, 'LoadState': 'loaded',
            'ActiveState': 'active', 'SubState': 'exited', 'MainPID': '0', 'Job': '',
            'NeedDaemonReload': 'no', 'UnitFileState': 'enabled', 'ExecMainStatus': '0',
            'FragmentPath': '/etc/systemd/system/' + unit}
    for unit in qos.adoption.LEGACY:
        states[unit] = {**state(unit), 'ExecStart': 'legacy apply', 'ExecReload': 'legacy apply',
                        'ExecStop': 'legacy remove' if unit.startswith('box') else ''}
    for item in policy['initial_consumers'].values():
        if item['owner'] == 'whatsapp':
            unit = f"user@{item['uid']}.service"
            states[unit] = {**state(unit), 'MainPID': str(item['uid'] + 3000), 'InvocationID': 'e' * 32,
                'SubState': 'running', 'CPUWeight': '800', 'IOWeight': '800',
                'Requires': 'system.slice whatsapp-resource-priority.service', 'After': 'basic.target whatsapp-resource-priority.service'}
    states[qos.adoption.HOST_UNIT] = {**state(qos.adoption.HOST_UNIT), 'ActiveState': 'inactive', 'UnitFileState': 'disabled'}
    class Services:
        def __init__(self, *args): pass
        def show(self, unit): return copy.deepcopy(states[unit])
        def command(self, operation, unit=None):
            calls.append((operation, unit))
            if operation == 'reload':
                for old in qos.adoption.LEGACY:
                    states[old].update(ExecStart='path=/usr/bin/true', ExecReload='path=/usr/bin/true', ExecStop='')
                for name in states:
                    if name.startswith('user@'):
                        for field in ('Requires', 'After'):
                            states[name][field] = states[name][field].replace('whatsapp-resource-priority.service', qos.adoption.HOST_UNIT)
            elif operation == 'stop':
                assert unit in qos.adoption.LEGACY and states[unit]['ExecStop'] == ''
                states[unit].update(ActiveState='inactive', SubState='dead')
            elif operation == 'disable': states[unit]['UnitFileState'] = 'disabled'
            elif operation == 'enable': states[unit]['UnitFileState'] = 'enabled'
            elif operation == 'start': states[unit].update(ActiveState='active', SubState='exited')
            else: raise AssertionError(operation)
        def ready(self):
            assert states[qos.adoption.HOST_UNIT]['ActiveState'] == 'active'
        def wait_ready(self): self.ready()
    def lookup(name):
        item = accounts[name]
        return types.SimpleNamespace(pw_name=name, pw_uid=item['uid'], pw_gid=item['gid'], pw_dir=item['home'], pw_shell=item['shell'])
    def run(**extra):
        entry = '/usr/local/lib/develative-host-components/' + 'a' * 64
        return qos.adoption.adopt(qos, root, policy_path=qos.POLICY, expected_sha256=qos.sha(qos.canonical(policy)),
            operation_id=operation, entrypoint=entry + '/host/qos/applicator.py', sources_manifest=entry + '/qos-sources.json',
            sources_sha256='b' * 64, kernel_factory=kernel.factory, service_factory=Services, lookup=lookup,
            census=lambda: [lookup(name) for name in accounts], admission_path=admission_path,
            admission_sha256=qos.sha((base / admission_path.lstrip('/')).read_bytes()), proc_root=proc, **extra)
    return root, base, kernel, states, calls, run, admission_path, proc


@pytest.mark.parametrize('phase', ['prepared', 'published', 'reloaded', 'legacy-retired', 'kernel-adopted', 'activated', 'committed'])
def test_adoption_every_phase_resumes_with_no_legacy_destructive_stop_or_manager_restart(adoption_case, phase):
    root, base, kernel, states, calls, run, _, _ = adoption_case
    identities = {key: (value['MainPID'], value['InvocationID']) for key, value in states.items() if key.startswith('user@')}
    original_tc, original_io = copy.deepcopy(kernel.state['tc']), kernel.state['io']
    def crash(event, detail):
        if event == 'adoption-' + phase: raise RuntimeError('interrupted adoption')
    with pytest.raises(RuntimeError): run(fault=crash)
    assert run()['status'] == 'complete'
    assert kernel.calls == ['nft']
    assert kernel.state['tc'] == original_tc and kernel.state['io'] == original_io
    assert identities == {key: (value['MainPID'], value['InvocationID']) for key, value in states.items() if key.startswith('user@')}
    assert all(unit in qos.adoption.LEGACY for action, unit in calls if action in ('stop', 'disable'))
    assert all('restart' != action for action, _ in calls)
    for path in qos.adoption.ENTRYPOINTS:
        assert root.read_bytes(path) == qos.adoption.GUARD


@pytest.mark.parametrize('phase', ['prepared', 'published', 'kernel-adopted', 'committed'])
def test_adoption_rechecks_current_or_pending_identity_before_any_publication(adoption_case, monkeypatch, phase):
    root, base, kernel, states, calls, run, admission_path, _ = adoption_case
    marker, _, cold = installed_whatsapp_identity(base, monkeypatch)
    def crash(event, detail):
        if event == 'adoption-' + phase: raise RuntimeError('pending adoption')
    with pytest.raises(RuntimeError): run(fault=crash)
    marker.unlink(); cold()
    # Even a valid renewed admission must not update a committed journal before
    # the still-active consumers' installed identities are checked.
    admission_file = base / admission_path.lstrip('/')
    admission = json.loads(admission_file.read_bytes())
    admission['expires_ns'] -= 1
    admission_file.write_bytes(qos.canonical(admission))
    before = (copy.deepcopy(kernel.state), list(kernel.calls), list(calls))
    journal = qos.STATE + '/operations/adopt-' + 'c' * 32 + '.json'
    intent = root.read_bytes(journal)
    with pytest.raises(ValueError, match='identity is missing'): run()
    assert before == (kernel.state, kernel.calls, calls)
    assert root.read_bytes(journal) == intent


def test_committed_adoption_can_be_rechecked_after_whatsapp_retirement(adoption_case, case, monkeypatch):
    root, base, kernel, states, calls, run, _, _ = adoption_case
    marker, _, cold = installed_whatsapp_identity(base, monkeypatch)
    assert run()['status'] == 'complete'
    operate = case[-1]
    for index, name in enumerate(('whatsapp.personal', 'whatsapp.secondary'), 2):
        operate('retire-consumer', str(index) * 32, consumer_id=name)
    marker.unlink(); cold()
    before = (copy.deepcopy(kernel.state), list(kernel.calls), list(calls))
    assert run()['status'] == 'complete'
    assert before == (kernel.state, kernel.calls, calls)


@pytest.mark.parametrize('phase', ['prepared', 'kernel-ready', 'published'])
def test_pending_fresh_activation_rechecks_initial_identity_before_resume(case, monkeypatch, phase):
    root, base, policy, kernel, accounts, _ = case
    marker, _, cold = installed_whatsapp_identity(base, monkeypatch)
    (base / (qos.STATE + '/adoption.lock').lstrip('/')).touch(mode=0o600)
    kernel.state.update(tc={'qdisc': [], 'filter': []}, nft={}, io=None)
    calls = []
    class Services:
        def __init__(self, *args): pass
        def show(self, unit): return {'LoadState': 'not-found', 'ActiveState': 'inactive', 'MainPID': '0', 'Job': ''}
        def command(self, operation, unit=None): calls.append((operation, unit))
        def wait_ready(self): pass
        def ready(self): pass
    def lookup(name):
        item = accounts[name]
        return types.SimpleNamespace(pw_name=name, pw_uid=item['uid'], pw_gid=item['gid'],
                                     pw_dir=item['home'], pw_shell=item['shell'])
    entry = '/usr/local/lib/develative-host-components/' + 'a' * 64
    def run(**extra):
        return qos.adoption.activate_fresh(qos, root, operation_id='c' * 32,
            entrypoint=entry + '/host/qos/applicator.py', sources_manifest=entry + '/qos-sources.json',
            sources_sha256='b' * 64, service_factory=Services, proc_root=base / 'retirement-proc',
            policy_path=qos.POLICY, expected_sha256=qos.sha(qos.canonical(policy)), kernel_factory=kernel.factory,
            lookup=lookup, census=lambda: [lookup(name) for name in accounts], **extra)
    def crash(event, detail):
        if event == 'fresh-' + phase: raise RuntimeError('pending fresh activation')
    with pytest.raises(RuntimeError): run(fault=crash)
    marker.unlink(); cold()
    before = (copy.deepcopy(kernel.state), list(kernel.calls), list(calls))
    journal = qos.STATE + '/operations/activate-' + 'c' * 32 + '.json'
    intent = root.read_bytes(journal)
    with pytest.raises(ValueError, match='identity is missing'): run()
    assert before == (kernel.state, kernel.calls, calls)
    assert root.read_bytes(journal) == intent


def test_unknown_ssh_is_blocked_before_any_file_publication_or_service_mutation(adoption_case):
    root, base, kernel, states, calls, run, admission_path, _ = adoption_case
    path = base / admission_path.lstrip('/'); value = qos.decode(path.read_bytes())
    value.update(ssh_admission='unknown', ssh_fence_evidence=None); path.write_bytes(qos.canonical(value))
    original = root.read_bytes('/usr/local/sbin/box-network-priority')
    with pytest.raises(qos.QoSError, match='unknown'): run()
    assert calls == [] and kernel.calls == []
    assert root.read_bytes('/usr/local/sbin/box-network-priority') == original
    assert root.snapshot('/etc/systemd/system/' + qos.adoption.HOST_UNIT) is None


def test_preloaded_legacy_process_is_persisted_and_blocks_even_before_guards(adoption_case):
    root, base, kernel, states, calls, run, _, proc = adoption_case
    child = proc / '101'; child.mkdir()
    (child / 'stat').write_text('101 (legacy) ' + ' '.join(['S', '1', '101', '101'] + ['0'] * 15 + ['999'] + ['0'] * 4))
    (child / 'cmdline').write_bytes(b'python3\0/usr/local/sbin/box-network-priority\0remove\0')
    (child / 'cgroup').write_text('0::/manual\n'); (child / 'cwd').symlink_to('/')
    with pytest.raises(qos.processes.ProcessesBusy): run()
    journal = qos.read_control(root, qos.STATE + '/operations/adopt-' + 'c' * 32 + '.json')
    assert journal['process_prior'][0]['pid'] == 101
    assert kernel.calls == calls == []
    assert root.read_bytes('/usr/local/sbin/box-network-priority') != qos.adoption.GUARD


def test_prepare_is_purely_filesystem_resumable_and_never_adopts_unmanaged_policy(tmp_path):
    (tmp_path / 'etc').mkdir(); (tmp_path / 'var/lib').mkdir(parents=True)
    raw = (BASE / 'tools/tests/fixtures/qos/synthetic-policy.json').read_bytes()
    with qos.engine.Root(tmp_path) as root:
        result = qos.prepare(root, policy_bytes=raw, expected_sha256=qos.sha(raw), operation_id='a' * 32)
        assert result['kernel_mutated'] is False and result['status'] == 'prepared'
        assert root.snapshot(qos.LOCK)['mode'] == 0o600
        assert root.directory(qos.STATE)['mode'] == 0o700
        assert qos.prepare(root, policy_bytes=raw, expected_sha256=qos.sha(raw), operation_id='a' * 32) == result
        with pytest.raises(qos.engine.LifecycleError):
            qos.prepare(root, policy_bytes=raw, expected_sha256=qos.sha(raw), operation_id='b' * 32)


@pytest.mark.parametrize('phase', ['prepared', 'kernel-ready', 'published', 'activated', 'committed'])
def test_fresh_empty_registry_without_box_accounts_installs_unit_and_enrolls_first_wa(case, phase):
    root, base, policy, kernel, accounts, _ = case
    policy['initial_consumers'] = {}
    for name in ('boxproxy', 'whatsappbridge', 'wa-secondary'): accounts.pop(name, None)
    raw = qos.canonical(policy); (base / qos.POLICY.lstrip('/')).write_bytes(raw)
    (base / (qos.STATE + '/adoption.lock').lstrip('/')).touch(mode=0o600)
    proc = base / 'proc'; (proc / 'sys/kernel/random').mkdir(parents=True)
    (proc / 'sys/kernel/random/boot_id').write_text('01234567-89ab-cdef-0123-456789abcdef\n')
    kernel.state.update(tc={'qdisc': [], 'filter': []}, nft={}, io=None)
    calls = []
    class Services:
        def __init__(self, *args): pass
        def show(self, unit): return {'LoadState': 'not-found', 'ActiveState': 'inactive', 'MainPID': '0', 'Job': ''}
        def command(self, operation, unit=None):
            assert operation == 'reload' or unit == qos.adoption.HOST_UNIT
            calls.append((operation, unit))
        def wait_ready(self): pass
        def ready(self): pass
    def lookup(name):
        item = accounts[name]
        return types.SimpleNamespace(pw_name=name, pw_uid=item['uid'], pw_gid=item['gid'], pw_dir=item['home'], pw_shell=item['shell'])
    common = dict(policy_path=qos.POLICY, expected_sha256=qos.sha(raw), kernel_factory=kernel.factory,
                  lookup=lookup, census=lambda: [lookup(name) for name in accounts])
    entry = '/usr/local/lib/develative-host-components/' + 'a' * 64
    def run(**extra):
        return qos.adoption.activate_fresh(qos, root, operation_id='c' * 32,
            entrypoint=entry + '/host/qos/applicator.py', sources_manifest=entry + '/qos-sources.json',
            sources_sha256='b' * 64, service_factory=Services, proc_root=proc, **common, **extra)
    def crash(event, detail):
        if event == 'fresh-' + phase: raise RuntimeError('lost supervisor')
    with pytest.raises(RuntimeError): run(fault=crash)
    assert run()['status'] == 'complete'
    assert qos.read_control(root, qos.REGISTRY)['consumers'] == {}
    result = qos.operate(root, action='register-consumer', operation_id='d' * 32,
        consumer_id='whatsapp.new', account='wa-new', unit='whatsapp-new.service', **common)
    assert result['consumer_status'] == 'active'
    assert set(qos.read_control(root, qos.REGISTRY)['consumers']) == {'whatsapp.new'}
    assert not any(operation in ('stop', 'disable', 'restart') for operation, unit in calls)
    assert b'--boot' in root.read_bytes('/etc/systemd/system/' + qos.adoption.HOST_UNIT)


def test_effective_registration_reloads_without_changing_manager_and_rejects_legacy_dependency():
    record = {'uid': 4242, 'unit': 'whatsapp-new.service', 'account': 'wa-new'}
    manager = {'Id': 'user@4242.service', 'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'running',
        'MainPID': '99', 'InvocationID': 'a' * 32, 'Job': '', 'NeedDaemonReload': 'no',
        'CPUWeight': '800', 'IOWeight': '800', 'Requires': qos.adoption.HOST_UNIT, 'After': qos.adoption.HOST_UNIT}
    bridge = {**manager, 'Id': record['unit'], 'User': 'wa-new', 'FragmentPath': '/etc/systemd/system/' + record['unit']}
    services = object.__new__(qos.adoption.Systemd); services.qos = qos; services.units = set()
    commands = []; services.command = lambda operation: commands.append(operation)
    services.show = lambda unit: copy.deepcopy(manager if unit.startswith('user@') else bridge)
    original = services.registration_state(record)
    services.registration_ready(record, original, reload=True)
    assert commands == ['reload']
    manager['Requires'] += ' whatsapp-resource-priority.service'
    with pytest.raises(qos.QoSError): services.registration_ready(record, original)
    manager['Requires'] = qos.adoption.HOST_UNIT; manager['MainPID'] = '100'
    with pytest.raises(qos.QoSError): services.registration_ready(record, original)
