"""Exact acquired-policy projections and isolated forward-resume; no kernel calls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import types

import pytest

BASE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('qos_applicator_tested', BASE / 'host/qos/applicator.py')
qos = importlib.util.module_from_spec(spec); spec.loader.exec_module(qos)
PROFILE = BASE / 'tools/tests/fixtures/qos/synthetic-policy.json'
OBSERVATION = BASE / 'tools/tests/fixtures/qos/synthetic-kernel-observation.json'


class FakeKernel:
    def __init__(self, state):
        self.state = copy.deepcopy(state); self.calls = []; self.syntax_calls = []; self.crash_tc = None
    def factory(self, root, policy, descriptor):
        self.policy = policy
        os.fstat(descriptor)
        return self
    def ready(self): return None
    def registration_state(self, record): return {'MainPID': '0', 'InvocationID': '', 'ActiveState': 'inactive', 'SubState': 'dead'}
    def registration_ready(self, record, previous=None, *, reload=False): return None
    def observe(self): return copy.deepcopy(self.state)
    def syntax(self, content): self.syntax_calls.append(content)
    def mutate(self, step):
        if step['kind'] != 'tc':
            self.calls.append(step['kind']); self.state = copy.deepcopy(step['after']); return
        while True:
            progress = qos.tc_progress(self.policy, self.state['tc'])
            if progress == 8: return
            self.calls.append(('tc', progress))
            expected = self.policy['parameters']['tc']
            if progress == 0:
                self.state['tc'] = {'qdisc': [copy.deepcopy(q) for q in expected['qdisc'] if q.get('root')], 'filter': []}
            elif progress <= 3:
                self.state['tc']['qdisc'].append(copy.deepcopy(next(q for q in expected['qdisc'] if q.get('parent') == f'b040:{progress}')))
            else:
                proto, pref = [('ip', 10), ('ip', 20), ('ipv6', 11), ('ipv6', 21)][progress - 4]
                self.state['tc']['filter'].append(copy.deepcopy(next(q for q in expected['filter'] if q['protocol'] == proto and q['pref'] == pref)))
            self.state['tc'] = qos.normalize_tc(self.state['tc']['qdisc'], self.state['tc']['filter'])
            if self.crash_tc == progress:
                self.crash_tc = None; raise RuntimeError('process lost between exact TC commands')


@pytest.fixture
def case(tmp_path):
    policy = json.loads(PROFILE.read_bytes()); raw = qos.canonical(policy)
    for path in ('etc/develative-host-qos', 'var/lib/develative-host-qos/operations'):
        (tmp_path / path).mkdir(parents=True)
    (tmp_path / qos.STATE.lstrip('/')).chmod(0o700)
    lock = tmp_path / qos.LOCK.lstrip('/'); lock.touch(); lock.chmod(0o600)
    (tmp_path / qos.POLICY.lstrip('/')).write_bytes(raw)
    kernel = FakeKernel(json.loads(OBSERVATION.read_bytes()))
    accounts = {**policy['parameters']['essential_accounts'], 'boxproxy': policy['parameters']['box_account']}
    for item in policy['initial_consumers'].values():
        accounts[item['account']] = {**item, 'shell': '/usr/sbin/nologin'}
    accounts['wa-new'] = {'uid': os.getuid(), 'gid': os.getgid(), 'home': '/var/lib/whatsapp-new-waha', 'shell': '/usr/sbin/nologin'}
    home = tmp_path / 'var/lib/whatsapp-new-waha'; home.mkdir()
    bridge = tmp_path / 'etc/systemd/system/whatsapp-new.service'; bridge.parent.mkdir(parents=True)
    bridge.write_text('[Service]\nUser=wa-new\nExecStart=/synthetic/bridge\n'); bridge.chmod(0o644)
    proc = tmp_path / 'retirement-proc'; (proc / 'sys/kernel/random').mkdir(parents=True)
    (proc / 'sys/kernel/random/boot_id').write_text('01234567-89ab-cdef-0123-456789abcdef\n')
    def lookup(name):
        item = accounts[name]
        return types.SimpleNamespace(pw_name=name, pw_uid=item['uid'], pw_gid=item['gid'], pw_dir=item['home'], pw_shell=item['shell'])
    with qos.engine.Root(tmp_path) as root:
        def run(action='apply', operation_id='a' * 32, **extra):
            return qos.operate(root, policy_path=qos.POLICY, expected_sha256=qos.sha(raw), action=action,
                operation_id=operation_id, kernel_factory=kernel.factory, lookup=lookup,
                census=lambda: [lookup(name) for name in accounts], proc_root=proc, **extra)
        yield root, tmp_path, policy, kernel, accounts, run


def installed_whatsapp_identity(base, monkeypatch, profile=None):
    """Protected synthetic identity; independent cold modules never read real /etc."""
    source = BASE / 'host/installation.py'
    def fresh():
        spec = importlib.util.spec_from_file_location('qos_fixture_installation', source)
        layout = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, spec.name, layout); spec.loader.exec_module(layout)
        return layout
    layout = fresh()
    selected = layout.Installation.legacy() if profile is None else layout.Installation.from_dict(profile)
    marker = base / layout.IDENTITY.relative_to('/')
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_bytes(layout.identity_bytes(selected)); marker.chmod(0o600)
    if profile is not None:
        locator = base / layout.PROFILE.relative_to('/')
        locator.write_bytes(selected._encoded); locator.chmod(0o600)
    layout.activate_installation(root=base, trusted_uid=os.getuid())
    monkeypatch.setattr(qos, 'installation_profile', layout.active)
    def cold():
        independent = fresh()
        def active():
            return independent.activate_installation(root=base, trusted_uid=os.getuid())
        monkeypatch.setattr(qos, 'installation_profile', active)
    return marker, layout, cold


def republish_fixture_policy(case):
    """Publish an explicitly chosen synthetic policy before its first operation."""
    root, base, policy, kernel, accounts, _ = case
    raw = qos.canonical(policy); (base / qos.POLICY.lstrip('/')).write_bytes(raw)
    def lookup(name):
        item = accounts[name]
        return types.SimpleNamespace(pw_name=name, pw_uid=item['uid'], pw_gid=item['gid'],
                                     pw_dir=item['home'], pw_shell=item['shell'])
    def run(action='apply', operation_id='a' * 32, **extra):
        return qos.operate(root, policy_path=qos.POLICY, expected_sha256=qos.sha(raw), action=action,
            operation_id=operation_id, kernel_factory=kernel.factory, lookup=lookup,
            census=lambda: [lookup(name) for name in accounts], proc_root=base / 'retirement-proc', **extra)
    return run


def assert_cold_consumer_check(case, consumer_id):
    """Import the whole provider in a fresh interpreter, with no selected identity."""
    _, base, policy, kernel, accounts, _ = case
    code = '''import json,os,sys,types
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from host.qos import applicator as qos
base=Path(sys.argv[2]); state,accounts=json.loads(sys.argv[3]); consumer=sys.argv[4]
identity=qos.installation_profile.__globals__
assert identity['_selected'] is None
read=identity['read_installation']
identity['read_installation']=lambda:read(root=base,trusted_uid=os.getuid())
def lookup(name):
    item=accounts[name]
    return types.SimpleNamespace(pw_name=name,pw_uid=item['uid'],pw_gid=item['gid'],pw_dir=item['home'],pw_shell=item['shell'])
class Kernel:
    def __init__(self,root,policy,descriptor):os.fstat(descriptor)
    def ready(self):pass
    def observe(self):return state
    def mutate(self,step):raise AssertionError('read-only check mutated kernel')
with qos.engine.Root(base) as root:
    receipt=qos.operate(root,policy_path=qos.POLICY,expected_sha256=qos.sha(root.read_bytes(qos.POLICY)),action='check',
        consumer_id=consumer,kernel_factory=Kernel,lookup=lookup,census=lambda:[lookup(name) for name in accounts])
assert receipt['consumer_status']=='active'
if consumer.startswith('box.'):
    assert identity['_selected'] is None
print('cold check complete')
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(BASE), str(base),
                             json.dumps([kernel.state, accounts]), consumer_id],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'cold check complete'


@pytest.mark.parametrize('mode', ['legacy', 'configured'])
def test_retired_whatsapp_does_not_bind_box_or_host_to_removed_identity(case, monkeypatch, mode):
    root, base, policy, kernel, accounts, run = case
    profile = None
    if mode == 'configured':
        profile = json.loads((BASE / 'plugins/whatsapp/deploy/installation.example.json').read_bytes())
        profile['accounts']['secondary'] = profile['accounts'].pop('team')
        profile['ports']['secondary'] = profile['ports'].pop('team')
    marker, layout, cold = installed_whatsapp_identity(base, monkeypatch, profile)
    if mode == 'configured':
        selected = layout.active()
        for name, item in policy['initial_consumers'].items():
            if item['owner'] != 'whatsapp': continue
            old = accounts.pop(item['account'])
            slug = name.split('.')[1]
            item.update(account=selected.account(slug), unit=selected.service(slug) + '.service',
                        home=selected.instance_paths(slug)['gateway'])
            accounts[item['account']] = {**old, **item}
        run = republish_fixture_policy(case)
    original_policy = root.read_bytes(qos.POLICY)
    original_tc, original_io = copy.deepcopy(kernel.state['tc']), kernel.state['io']
    assert run()['status'] == 'complete'
    for index, name in enumerate(('whatsapp.personal', 'whatsapp.secondary'), 2):
        assert run('retire-consumer', str(index) * 32, consumer_id=name)['consumer_status'] == 'retired'
        accounts.pop(policy['initial_consumers'][name]['account'])
    assert run('check', None, consumer_id='box.proxy')['consumer_status'] == 'active'
    marker.unlink()
    if profile is not None: (base / layout.PROFILE.relative_to('/')).unlink()
    assert_cold_consumer_check(case, 'box.proxy')
    cold()
    assert run('check', None, consumer_id='box.proxy')['consumer_status'] == 'active'
    # Both a new host operation and its committed historical preimage remain usable.
    assert run('apply', '4' * 32)['status'] == 'complete'
    assert run('apply', 'a' * 32)['status'] == 'complete'
    assert run('retire-consumer', '3' * 32, consumer_id='whatsapp.secondary')['consumer_status'] == 'retired'
    assert run('retire-consumer', '5' * 32, consumer_id='box.proxy')['consumer_status'] == 'retired'
    assert run('check', None)['status'] == 'complete'
    assert root.read_bytes(qos.POLICY) == original_policy
    assert kernel.state['tc'] == original_tc and kernel.state['io'] == original_io
    assert all(call == 'nft' for call in kernel.calls)


@pytest.mark.parametrize('state', ['initial', 'active', 'one-retired'])
def test_active_whatsapp_identity_loss_blocks_before_any_effect(case, monkeypatch, state):
    root, base, policy, kernel, accounts, run = case
    marker, _, cold = installed_whatsapp_identity(base, monkeypatch)
    if state != 'initial': run()
    if state == 'one-retired': run('retire-consumer', '2' * 32, consumer_id='whatsapp.personal')
    marker.unlink(); cold()
    before = (copy.deepcopy(kernel.state), list(kernel.calls), root.snapshot(qos.REGISTRY))
    with pytest.raises(ValueError, match='identity is missing'):
        run('apply', '3' * 32)
    assert before == (kernel.state, kernel.calls, root.snapshot(qos.REGISTRY))
    assert root.snapshot(qos.STATE + '/operations/' + '3' * 32 + '.json') is None


@pytest.mark.parametrize('phase', ['prepared', 'mutated', 'kernel-complete', 'registry'])
def test_pending_last_retirement_requires_identity_even_after_registry_publication(case, monkeypatch, phase):
    root, base, policy, kernel, accounts, run = case
    marker, _, cold = installed_whatsapp_identity(base, monkeypatch)
    run(); run('retire-consumer', '2' * 32, consumer_id='whatsapp.personal')
    def crash(event, detail):
        if event == phase: raise RuntimeError('retirement interrupted')
    with pytest.raises(RuntimeError):
        run('retire-consumer', '3' * 32, consumer_id='whatsapp.secondary', fault=crash)
    marker.unlink(); cold()
    before = (copy.deepcopy(kernel.state), list(kernel.calls), root.snapshot(qos.REGISTRY))
    journal = qos.STATE + '/operations/' + '3' * 32 + '.json'; intent = root.read_bytes(journal)
    with pytest.raises(ValueError, match='identity is missing'):
        run('retire-consumer', '3' * 32, consumer_id='whatsapp.secondary')
    with pytest.raises(ValueError, match='identity is missing'):
        run('check', None, consumer_id='box.proxy')
    assert before == (kernel.state, kernel.calls, root.snapshot(qos.REGISTRY))
    assert root.read_bytes(journal) == intent


@pytest.mark.parametrize('mode', ['legacy', 'configured'])
def test_retired_box_identity_files_do_not_affect_whatsapp_operations(case, monkeypatch, mode):
    root, base, policy, kernel, accounts, run = case
    wa_marker, _, wa_cold = installed_whatsapp_identity(base, monkeypatch)
    box_root = Path(os.environ.get('BOX_ADMIN_SOURCE', str(BASE.parent / 'BOX')))
    source = box_root / 'projects/box/bin/installation_layout.py'
    if not source.is_file(): pytest.skip('Independent BOX checkout required for real identity format')
    spec = importlib.util.spec_from_file_location('qos_fixture_box_identity', source)
    box = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, box); spec.loader.exec_module(box)
    profile = None
    if mode == 'configured':
        profile = json.loads((box_root / 'projects/box/deploy/fresh/installation.example.json').read_bytes())
        # Preserve the acquired proxy account/unit, with a configured home.
        # QoS does not import BOX's private runtime.
        profile['service_prefix'] = 'box'
        profile['accounts']['release']['proxy'] = 'boxproxy'
    selected = box.Installation.legacy() if profile is None else box.Installation.from_dict(profile)
    if profile is not None:
        home = selected.mapped('/var/lib/box-proxy')
        policy['parameters']['box_account']['home'] = home
        policy['initial_consumers']['box.proxy']['home'] = home
        accounts['boxproxy']['home'] = home
        run = republish_fixture_policy(case)
    marker = base / box.IDENTITY.relative_to('/')
    marker.write_bytes(box.identity_bytes(selected)); marker.chmod(0o600)
    locator = base / box.PROFILE.relative_to('/')
    if profile is not None:
        locator.write_bytes(selected._encoded); locator.chmod(0o600)
    assert box.read_installation(root=base, uid=os.getuid()).sha256 == selected.sha256
    original_policy = root.read_bytes(qos.POLICY)
    original_tc, original_io = copy.deepcopy(kernel.state['tc']), kernel.state['io']
    assert run()['status'] == 'complete'
    assert run('retire-consumer', '2' * 32, consumer_id='box.proxy')['consumer_status'] == 'retired'
    accounts.pop('boxproxy')
    marker.unlink()
    if profile is not None: locator.unlink()
    with pytest.raises(ValueError, match='identity is missing'):
        box.read_installation(root=base, uid=os.getuid())
    assert_cold_consumer_check(case, 'whatsapp.personal')
    wa_cold()
    assert wa_marker.exists()
    assert run('check', None, consumer_id='whatsapp.personal')['consumer_status'] == 'active'
    assert run('apply', '3' * 32)['status'] == 'complete'
    assert run('apply', 'a' * 32)['status'] == 'complete'
    for index, name in enumerate(('whatsapp.personal', 'whatsapp.secondary'), 4):
        assert run('retire-consumer', str(index) * 32, consumer_id=name)['consumer_status'] == 'retired'
    assert run('check', None)['status'] == 'complete'
    assert root.read_bytes(qos.POLICY) == original_policy
    assert kernel.state['tc'] == original_tc and kernel.state['io'] == original_io
    assert all(call == 'nft' for call in kernel.calls)


def test_new_whatsapp_registration_requires_identity_after_all_old_consumers_retire(case, monkeypatch):
    root, base, policy, kernel, accounts, run = case
    marker, _, cold = installed_whatsapp_identity(base, monkeypatch)
    run()
    for index, name in enumerate(('whatsapp.personal', 'whatsapp.secondary'), 2):
        run('retire-consumer', str(index) * 32, consumer_id=name)
    marker.unlink(); cold()
    before = (list(kernel.calls), root.read_bytes(qos.REGISTRY))
    with pytest.raises(ValueError, match='identity is missing'):
        run('register-consumer', '4' * 32, consumer_id='whatsapp.new', account='wa-new', unit='whatsapp-new.service')
    assert before == (kernel.calls, root.read_bytes(qos.REGISTRY))
    assert root.snapshot(qos.STATE + '/operations/' + '4' * 32 + '.json') is None


@pytest.mark.parametrize('field,value', [('account', 'another-account'), ('unit', 'another.service'), ('home', '/var/lib/another-home')])
def test_active_registry_tuple_tamper_is_not_admitted_by_historical_validation(case, monkeypatch, field, value):
    root, base, policy, kernel, accounts, run = case
    installed_whatsapp_identity(base, monkeypatch)
    run()
    registry = qos.read_control(root, qos.REGISTRY)
    registry['consumers']['whatsapp.personal'][field] = value
    (base / qos.REGISTRY.lstrip('/')).write_bytes(qos.canonical(registry))
    before = list(kernel.calls)
    with pytest.raises(ValueError, match='WhatsApp account binding'):
        run('apply', '4' * 32)
    assert kernel.calls == before


@pytest.mark.parametrize('field,value', [('account', 'root'), ('unit', '../foreign.service'), ('home', '/var/lib/../foreign'), ('home', '/var/lib/x\ninvalid')])
def test_retired_historical_tuples_still_require_finite_structure(field, value, monkeypatch):
    policy = json.loads(PROFILE.read_bytes())
    registry = {'format': 1, 'policy_sha256': 'a' * 64, 'consumers': copy.deepcopy(policy['initial_consumers'])}
    for item in registry['consumers'].values(): item['status'] = 'retired'
    registry['consumers']['whatsapp.personal'][field] = value
    def forbidden(): raise AssertionError('historical validation read live installation')
    monkeypatch.setattr(qos, 'installation_profile', forbidden)
    with pytest.raises(ValueError, match='historical WhatsApp identity'):
        qos.validate_registry(registry, policy)


def test_pinned_sources_and_typed_projection_equal_the_acquired_actual_policy():
    policy = qos.validate_policy(json.loads(PROFILE.read_bytes()))
    observed = json.loads(OBSERVATION.read_bytes())
    assert qos.expected_tc() == observed['tc']
    text, nft = qos.nft_policy(policy, policy['initial_consumers'], legacy=True)
    assert nft == observed['nft']
    assert b'priority -141' in text and b'priority -140' in text
    assert text.index(b'meta skuid 2300') < text.index(b'tcp sport {22,53,10000,20000}')
    assert b'meta skuid 33' not in text and b'meta skuid 108' not in text
    assert qos.tc_commands(policy)[0][-16:] == ['2'] * 16
    assert not any('mq' in command for command in qos.tc_commands(policy))


def test_migration_preserves_tc_io_then_register_and_retire_keep_other_consumers(case):
    root, base, policy, kernel, accounts, run = case
    original = kernel.observe()
    assert run()['status'] == 'complete'
    assert kernel.calls == ['nft']
    registry = qos.decode(root.read_bytes(qos.REGISTRY))
    assert registry['consumers'] == policy['initial_consumers']
    registered = run('register-consumer', 'b' * 32, consumer_id='whatsapp.new', account='wa-new', unit='whatsapp-new.service')
    assert registered['uid'] == os.getuid() and registered['consumer_status'] == 'active' and registered['status'] == 'complete'
    for index, name in enumerate(('box.proxy', 'whatsapp.new', 'whatsapp.personal', 'whatsapp.secondary')):
        assert run('retire-consumer', str(index + 2) * 32, consumer_id=name)['consumer_status'] == 'retired'
    assert kernel.state['tc'] == original['tc'] and kernel.state['io'] == original['io']
    assert all(call == 'nft' for call in kernel.calls)
    _, expected = qos.nft_policy(policy, qos.decode(root.read_bytes(qos.REGISTRY))['consumers'])
    assert kernel.state['nft'] == expected
    assert len(expected[qos.TABLES[0]]['nftables']) > 7  # Essential rules/counters survive the last app.
    assert root.read_bytes(qos.POLICY) == qos.canonical(policy)
    assert run('check', None)['status'] == 'complete'


@pytest.mark.parametrize('phase', ['prepared', 'intent', 'mutated', 'observed', 'kernel-complete', 'registry', 'committed'])
def test_each_durable_phase_resumes_forward_without_duplicate_kernel_mutation(case, phase):
    root, base, policy, kernel, accounts, run = case
    kernel.state['io'] = kernel.state['io'].replace('enable=1', 'enable=0')
    def crash(event, detail):
        if event == phase: raise RuntimeError('simulated supervisor interruption')
    with pytest.raises(RuntimeError): run(fault=crash)
    assert run()['status'] == 'complete'
    assert kernel.calls.count('nft') == 1 and kernel.calls.count('io') == 1
    assert qos.decode(root.read_bytes(qos.STATE + '/operations/' + 'a' * 32 + '.json'))['phase'] == 'committed'


@pytest.mark.parametrize('command', range(8))
def test_fresh_boot_resumes_every_tc_command_without_resetting_completed_classes(case, command):
    root, base, policy, kernel, accounts, run = case
    kernel.state['tc'] = {'qdisc': [{'kind': 'mq', 'handle': '0:', 'root': True}], 'filter': []}
    kernel.state['nft'] = {}
    kernel.crash_tc = command
    with pytest.raises(RuntimeError): run()
    assert run()['status'] == 'complete'
    assert [call for call in kernel.calls if isinstance(call, tuple)] == [('tc', number) for number in range(8)]
    assert kernel.state['tc'] == qos.expected_tc()
    assert run('check', None)['status'] == 'complete'


def test_empty_boot_is_allowed_but_unjournaled_partial_ets_and_arbitrary_root_are_not(case):
    root, base, policy, kernel, accounts, run = case
    kernel.state['tc'] = {'qdisc': [{'kind': 'ets', 'handle': 'b040:', 'root': True,
        'options': {'bands': 3, 'strict': 1, 'quanta': [12000, 1500], 'priomap': [2] * 16}}], 'filter': []}
    with pytest.raises(qos.QoSError): run()
    assert kernel.calls == [] and not (base / (qos.STATE + '/operations/' + 'a' * 32 + '.json').lstrip('/')).exists()
    kernel.state['tc'] = {'qdisc': [{'kind': 'cake', 'handle': '0:', 'root': True}], 'filter': []}
    with pytest.raises(qos.QoSError): run()
    kernel.state['tc'] = {'qdisc': [], 'filter': []}; kernel.state['nft'] = {}
    assert run()['status'] == 'complete'


@pytest.mark.parametrize('change', ['tc', 'io', 'nft', 'source', 'account'])
def test_all_preconditions_precede_kernel_and_registry_mutation(case, change):
    root, base, policy, kernel, accounts, run = case
    if change == 'tc': kernel.state['tc']['qdisc'][0]['kind'] = 'cake'
    elif change == 'io': kernel.state['io'] = kernel.state['io'].replace('rlat=5000', 'rlat=1')
    elif change == 'nft': kernel.state['nft']['box_priority']['nftables'].append({'rule': {'unknown': True}})
    elif change == 'source':
        path = base / qos.POLICY.lstrip('/'); value = qos.decode(path.read_bytes()); value['sources']['network']['base64'] = 'eA=='
        path.write_bytes(qos.canonical(value))
    else: accounts['boxproxy']['uid'] = 444
    with pytest.raises(qos.QoSError): run()
    assert kernel.calls == [] and root.snapshot(qos.REGISTRY) is None


def test_pending_operation_rejects_external_kernel_drift_and_different_request(case):
    root, base, policy, kernel, accounts, run = case
    def crash(event, detail):
        if event == 'prepared': raise RuntimeError('intent retained')
    with pytest.raises(RuntimeError): run(fault=crash)
    kernel.state['nft']['box_priority']['nftables'].clear()
    with pytest.raises(qos.QoSError): run()
    with pytest.raises(qos.QoSError): run('retire-consumer', consumer_id='box.proxy')
    assert kernel.calls == []


def test_registry_and_account_enrolment_are_exact_and_policy_hash_does_not_change(case):
    root, base, policy, kernel, accounts, run = case
    run(); before = root.read_bytes(qos.POLICY)
    with pytest.raises(qos.QoSError):
        run('register-consumer', 'b' * 32, consumer_id='whatsapp.new', account='boxproxy', unit='whatsapp-new.service')
    accounts['wa-new']['shell'] = '/bin/bash'
    with pytest.raises(qos.QoSError):
        run('register-consumer', 'b' * 32, consumer_id='whatsapp.new', account='wa-new', unit='whatsapp-new.service')
    assert root.read_bytes(qos.POLICY) == before and kernel.calls == ['nft']


def test_real_kernel_backend_refuses_fixture_root_before_any_program(case):
    root, _, policy, _, _, _ = case
    with qos.lease(root) as descriptor:
        with pytest.raises(qos.QoSError): qos.Kernel(root, policy, descriptor)


def test_foreign_dscp_writer_is_not_silently_ignored():
    value = {'nftables': [{'chain': {'family': 'inet', 'table': 'foreign', 'name': 'out', 'hook': 'output'}},
        {'rule': {'family': 'inet', 'table': 'foreign', 'chain': 'out', 'expr': [
            {'mangle': {'key': {'payload': {'protocol': 'ip', 'field': 'dscp'}}, 'value': 'cs6'}}]}}]}
    with pytest.raises(qos.QoSError): qos.scoped_nft(value)


@pytest.mark.parametrize('alias_uid', [33, 108])
def test_full_account_census_rejects_alias_to_apache_or_mail_before_any_publication(case, alias_uid):
    root, base, policy, kernel, accounts, run = case
    run(); original_calls = list(kernel.calls)
    accounts['wa-new']['uid'] = alias_uid
    accounts['www-data' if alias_uid == 33 else 'postfix'] = {'uid': alias_uid, 'gid': alias_uid,
        'home': '/unrelated', 'shell': '/usr/sbin/nologin'}
    with pytest.raises(qos.QoSError, match='shared'):
        run('register-consumer', 'b' * 32, consumer_id='whatsapp.new', account='wa-new', unit='whatsapp-new.service')
    assert kernel.calls == original_calls
    assert not (base / 'etc/systemd/system/whatsapp-new.service.d').exists()


def test_boot_absent_io_initializes_only_enable_and_preserves_explicit_observed_tuning(case):
    root, base, policy, kernel, accounts, run = case
    kernel.state['io'] = None
    assert run()['status'] == 'complete'
    assert kernel.calls == ['io', 'nft']
    assert kernel.state['io'] == policy['parameters']['io_qos']


def test_pending_registry_publication_blocks_new_mutation_until_same_operation_commits(case):
    root, base, policy, kernel, accounts, run = case
    def crash(event, detail):
        if event == 'registry': raise RuntimeError('registry published before final receipt')
    with pytest.raises(RuntimeError): run(fault=crash)
    with pytest.raises(qos.QoSError, match='resumed'):
        run('retire-consumer', 'b' * 32, consumer_id='box.proxy')
    assert run()['status'] == 'complete'
    assert run('retire-consumer', 'b' * 32, consumer_id='box.proxy')['consumer_status'] == 'retired'


def test_registration_dropins_have_host_journals_and_resume_after_publication(case):
    root, base, policy, kernel, accounts, run = case
    run()
    def crash(event, detail):
        if event == 'dropins': raise RuntimeError('published templates before nft')
    args = {'consumer_id': 'whatsapp.new', 'account': 'wa-new', 'unit': 'whatsapp-new.service'}
    with pytest.raises(RuntimeError): run('register-consumer', 'b' * 32, fault=crash, **args)
    assert run('register-consumer', 'b' * 32, **args)['status'] == 'complete'
    home = base / 'var/lib/whatsapp-new-waha'
    assert not (home / 'var').exists()
    assert not (home / '.develative-host-lifecycle').exists()
    assert (home / '.config/systemd/user/app.slice.d/60-whatsapp-priority.conf').read_text().endswith('IOWeight=800\n')
    assert 'Requires=develative-host-qos.service' in (base / f'etc/systemd/system/user@{os.getuid()}.service.d/60-whatsapp-priority.conf').read_text()
    assert run('check', None, consumer_id='whatsapp.new')['consumer_status'] == 'active'


def test_account_dropin_parent_symlink_and_legacy_preimage_are_rejected_before_admin_writes(case):
    root, base, policy, kernel, accounts, run = case
    run()
    home = base / 'var/lib/whatsapp-new-waha'; victim = base / 'victim'; victim.mkdir()
    (home / '.config').symlink_to(victim, target_is_directory=True)
    with pytest.raises((qos.QoSError, qos.engine.LifecycleError)):
        run('register-consumer', 'b' * 32, consumer_id='whatsapp.new', account='wa-new', unit='whatsapp-new.service')
    assert list(victim.iterdir()) == [] and not (base / 'etc/systemd/system/whatsapp-new.service.d').exists()


def test_indirect_foreign_dscp_writer_in_regular_chain_is_refused():
    value = {'nftables': [{'chain': {'family': 'inet', 'table': 'foreign', 'name': 'out', 'hook': 'output'}},
        {'rule': {'family': 'inet', 'table': 'foreign', 'chain': 'out', 'expr': [{'jump': {'target': 'helper'}}]}},
        {'chain': {'family': 'inet', 'table': 'foreign', 'name': 'helper'}},
        {'rule': {'family': 'inet', 'table': 'foreign', 'chain': 'helper', 'expr': [
            {'mangle': {'key': {'payload': {'protocol': 'ip', 'field': 'dscp'}}, 'value': 'cs6'}}]}}]}
    with pytest.raises(qos.QoSError): qos.scoped_nft(value)


@pytest.mark.parametrize('changed', [False, True])
def test_initial_active_consumer_adopts_only_exact_user_dropin_preimages_and_resumes(case, changed):
    root, base, policy, kernel, accounts, _ = case
    def lookup(name):
        item = accounts[name]
        return types.SimpleNamespace(pw_name=name, pw_uid=item['uid'], pw_gid=item['gid'], pw_dir=item['home'], pw_shell=item['shell'])
    record = qos.account_record('whatsapp.new', 'wa-new', 'whatsapp-new.service', lookup)
    policy['initial_consumers']['whatsapp.new'] = record
    raw = qos.canonical(policy); (base / qos.POLICY.lstrip('/')).write_bytes(raw)
    kernel.state['nft'] = qos.nft_policy(policy, policy['initial_consumers'], legacy=True)[1]
    common = dict(policy_path=qos.POLICY, expected_sha256=qos.sha(raw), kernel_factory=kernel.factory,
                  lookup=lookup, census=lambda: [lookup(name) for name in accounts])
    qos.operate(root, action='apply', operation_id='a' * 32, **common)
    for path, content in qos.consumer_dropins(record)['account'].items():
        target = base / path.lstrip('/'); target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.replace(b'# Managed by host resource priority.', b'# Managed by WhatsApp resource priority.'))
        target.chmod(0o644)
    def register(**extra):
        return qos.operate(root, action='register-consumer', operation_id='b' * 32,
            consumer_id='whatsapp.new', account='wa-new', unit='whatsapp-new.service', **common, **extra)
    def crash(event, detail):
        if event == 'prepared': raise RuntimeError('durable preimages before publication')
    with pytest.raises(RuntimeError): register(fault=crash)
    target = base / next(iter(qos.consumer_dropins(record)['account'])).lstrip('/')
    if changed:
        target.write_bytes(target.read_bytes() + b'# external change\n')
        with pytest.raises((qos.QoSError, qos.engine.LifecycleError)): register()
        assert target.read_bytes().endswith(b'# external change\n')
        assert not (base / 'etc/systemd/system/whatsapp-new.service.d').exists()
    else:
        assert register()['status'] == 'complete'
        for path, content in qos.consumer_dropins(record)['account'].items():
            assert (base / path.lstrip('/')).read_bytes() == content
        assert register()['status'] == 'complete'


def test_noninitial_consumer_cannot_adopt_legacy_user_dropin(case):
    root, base, policy, kernel, accounts, run = case
    run()
    target = base / 'var/lib/whatsapp-new-waha/.config/systemd/user/app.slice.d/60-whatsapp-priority.conf'
    target.parent.mkdir(parents=True); target.write_bytes(b'# Managed by WhatsApp resource priority.\n[Slice]\nCPUWeight=800\nIOWeight=800\n')
    target.chmod(0o644)
    with pytest.raises(qos.QoSError):
        run('register-consumer', 'b' * 32, consumer_id='whatsapp.new', account='wa-new', unit='whatsapp-new.service')
    assert not (base / 'etc/systemd/system/whatsapp-new.service.d').exists()
