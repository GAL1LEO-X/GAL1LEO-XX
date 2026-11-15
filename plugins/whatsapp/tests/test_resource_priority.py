import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from sally_whatsapp import tenancy

PLUGIN = Path(__file__).parents[1]


@pytest.fixture
def priority(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location('resource_priority', PLUGIN/'scripts/resource_priority.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, 'CONFIG', tmp_path/'config.json')
    monkeypatch.setattr(mod, 'BACKUPS', tmp_path/'backups')
    monkeypatch.setattr(mod, 'CGROUP', tmp_path/'cgroup')
    mod.CGROUP.mkdir()
    (mod.CGROUP/'io.cost.qos').write_text('')
    monkeypatch.setattr(mod, 'account_details', lambda user: {
        'user': user, 'uid': 2345 if user == 'wa-first' else 2346,
        'home': tmp_path/user, 'base': 'whatsapp-'+user[3:]})
    return mod


def config():
    return {'format': 1, 'interface': 'eth0', 'io_device': '/dev/sda', 'users': ['wa-first']}


def test_future_tenant_inherits_priorities_with_original_cpu_ram_limits(monkeypatch):
    monkeypatch.setattr(tenancy, 'ROOT', PLUGIN)
    target = tenancy.Instance('new-user', 'Synthetic', '11111111-1111-4111-8111-111111111111', 8824)
    files = tenancy.deployment_artifacts(target)
    for name, memory in (('bridge', '1G'), ('gateway', '4G')):
        assert 'CPUWeight=800\nIOWeight=800' in files[name]
        assert 'CPUQuota=200%' in files[name]
        assert 'MemoryMax='+memory in files[name]
    assert 'CPUAffinity=0-3' in files['gateway']
    # Portable rendering must not assume an installed foreign Apache module.
    assert 'BoxPriorityDSCP' not in files['apache']


def test_manager_competes_with_box_and_delegates_io_without_changing_caps(priority):
    files = priority.unit_files(priority.account_details('wa-first'))
    manager = next(text for path, text in files.items() if 'user@' in str(path))
    assert 'Slice=system.slice' in manager
    assert 'Delegate=cpu io memory pids' in manager
    assert 'Requires=whatsapp-resource-priority.service' in manager
    for text in files.values():
        assert 'CPUWeight=800' in text and 'IOWeight=800' in text
        assert all(term not in text for term in ('CPUQuota=', 'MemoryMax=', 'CPUAffinity=', 'OOMScoreAdjust='))


def test_network_marks_only_enrolled_users_before_essential_promotion(priority):
    cfg = config()
    script = priority.nft_script(cfg, exists=True)
    assert 'delete table inet whatsapp_priority' in script
    assert 'delete table inet box_priority' not in script
    assert 'priority -141' in script and 'dscp set af41' in script
    assert script.count('meta skuid 2345') == 2
    assert '2346' not in script and 'cs6' not in script
    cfg['users'].append('wa-second')
    assert priority.nft_script(cfg, exists=False).count('meta skuid 2346') == 2


def test_unknown_queue_and_unowned_table_are_never_overwritten(priority, monkeypatch):
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=json.dumps([{'root': True, 'kind': 'mq'}]))
    monkeypatch.setattr(priority, 'run', run)
    with pytest.raises(ValueError, match='three-class BOX'): priority.check_network(config())
    assert len(calls) == 1
    monkeypatch.setattr(priority, 'run', lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps({'nftables': [{'table': {'comment': 'another owner'}}]})))
    with pytest.raises(ValueError, match='unowned'): priority.nft_exists()


@pytest.mark.parametrize('old', ['', '8:0 enable=0 ctrl=user rpct=95.00 rlat=70000'])
def test_policy_plan_is_read_only_and_apply_preserves_qos_tuning(priority, monkeypatch, old):
    path = priority.CGROUP/'io.cost.qos'
    path.write_text(old)
    monkeypatch.setattr(priority, 'device_number', lambda cfg: '8:0')
    monkeypatch.setattr(priority, 'check_network', lambda cfg: (False, 'synthetic-rules'))
    calls=[]
    monkeypatch.setattr(priority, 'run', lambda *a, **k: calls.append((a,k)) or SimpleNamespace(returncode=0, stdout=''))
    assert not priority.apply_policy(config())['mutated']
    assert path.read_text() == old and calls == []
    priority.apply_policy(config(), apply=True)
    assert path.read_text() == '8:0 enable=1\n'
    assert calls == [(('nft','-f','-'), {'input':'synthetic-rules'})]


def test_failed_network_apply_restores_disabled_io_state(priority, monkeypatch):
    monkeypatch.setattr(priority, 'device_number', lambda cfg: '8:0')
    monkeypatch.setattr(priority, 'check_network', lambda cfg: (False, 'synthetic-rules'))
    def fail(*args, **kwargs): raise RuntimeError('synthetic nft failure')
    monkeypatch.setattr(priority, 'run', fail)
    with pytest.raises(RuntimeError, match='synthetic'): priority.apply_policy(config(), apply=True)
    assert (priority.CGROUP/'io.cost.qos').read_text() == '8:0 enable=0\n'


@pytest.fixture
def enrollment(priority, monkeypatch, tmp_path):
    priority.CONFIG.write_text(json.dumps(config()))
    paths = {tmp_path/'units/priority.conf': priority.MARKER+'[Service]\nCPUWeight=800\nIOWeight=800\n'}
    monkeypatch.setattr(priority, 'unit_files', lambda account: dict(paths))
    monkeypatch.setattr(priority, 'device_number', lambda cfg: '8:0')
    monkeypatch.setattr(priority, 'check_network', lambda cfg: (False, 'synthetic-rules'))
    calls=[]
    def run(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout='/user.slice/user-2346.slice/user@2346.service\n' if 'show' in args else '')
    monkeypatch.setattr(priority, 'run', run)
    return priority, paths, calls


def test_enrollment_plan_writes_nothing_and_enrollment_is_idempotent(enrollment):
    mod, files, calls = enrollment
    before = mod.CONFIG.read_bytes()
    assert not mod.enroll(config(), 'wa-second')['mutated']
    assert mod.CONFIG.read_bytes() == before and not next(iter(files)).exists() and calls == []
    result = mod.enroll(config(), 'wa-second', apply=True)
    assert result['manager_restart_required']
    cfg=json.loads(mod.CONFIG.read_text())
    assert cfg['users'] == ['wa-first','wa-second']
    assert all('restart' not in call for call in calls)
    assert ('systemctl','reload-or-restart','whatsapp-resource-priority.service') in calls
    second = mod.enroll(cfg, 'wa-second', apply=True)
    assert second['changed'] == [] and second['backup'] is None


def test_enrollment_rolls_back_files_if_service_reload_fails(enrollment, monkeypatch):
    mod, files, _ = enrollment
    before=mod.CONFIG.read_bytes()
    def run(*args, **kwargs):
        if 'reload-or-restart' in args and kwargs.get('check',True): raise RuntimeError('synthetic reload failure')
        return SimpleNamespace(returncode=0,stdout='')
    monkeypatch.setattr(mod, 'run', run)
    with pytest.raises(RuntimeError, match='synthetic'): mod.enroll(config(), 'wa-second', apply=True)
    assert mod.CONFIG.read_bytes() == before and not next(iter(files)).exists()


def test_enrollment_does_not_adopt_an_existing_unowned_file(enrollment):
    mod, files, calls = enrollment
    target=next(iter(files));target.parent.mkdir();target.write_text('Unrelated config')
    before=mod.CONFIG.read_bytes()
    with pytest.raises(ValueError, match='unowned'): mod.enroll(config(), 'wa-second', apply=True)
    assert target.read_text() == 'Unrelated config' and mod.CONFIG.read_bytes() == before and calls == []


@pytest.fixture
def network_profile(priority, monkeypatch):
    qdiscs = [{'root': True, 'kind': 'ets', 'handle': 'b040:', 'options': {
        'bands': 3, 'strict': 1, 'quanta': [12000, 1500], 'priomap': [2]*16}}]
    filters = []
    for protocol, eth_type in [('ip', 'ipv4'), ('ipv6', 'ipv6')]:
        for tos, cls in [(0x88, 'b040:2'), (0xc0, 'b040:1')]:
            item = {'protocol': protocol, 'pref': len(filters)+1, 'kind': 'flower', 'chain': 0}
            filters.append(dict(item))  # iproute2 preference header
            filters.append({**item, 'options': {'classid': cls, 'skip_hw': True, 'not_in_hw': True,
                'keys': {'eth_type': eth_type, 'ip_tos': tos, 'ip_tos_mask': 'fc'}}})
    nft = {'nftables': [{'chain': {'family': 'inet', 'table': 'box_priority', 'name': 'output',
        'type': 'route', 'hook': 'output', 'prio': -140, 'policy': 'accept'}}] + [
        {'rule': {'expr': [{'mangle': {'key': {'payload': {'protocol': proto, 'field': 'dscp'}},
                                      'value': 'cs6'}}]}} for proto in ('ip', 'ip6')]}
    calls = []
    def run(*args, **kwargs):
        calls.append((args, kwargs))
        code = 0
        if args[:3] == ('tc', '-j', 'qdisc'): value = qdiscs
        elif args[:3] == ('tc', '-j', 'filter'): value = filters
        elif args == ('nft', '-j', 'list', 'table', 'inet', 'box_priority'): value = nft
        elif args == ('nft', '-j', 'list', 'table', 'inet', 'whatsapp_priority'): value, code = {}, 1
        else: value = {}
        return SimpleNamespace(returncode=code, stdout=json.dumps(value))
    monkeypatch.setattr(priority, 'run', run)
    monkeypatch.setattr(priority, 'device_number', lambda cfg: '8:0')
    return SimpleNamespace(qdiscs=qdiscs, filters=filters, nft=nft, calls=calls)


def test_verified_ipv4_ipv6_classifier_preserves_essential_and_ordinary_classes(priority, network_profile):
    result = priority.apply_policy(config(), apply=True)
    assert result['network_class'] == 'AF41 / b040:2'
    assert (priority.CGROUP/'io.cost.qos').read_text() == '8:0 enable=1\n'
    mutations = [call for call in network_profile.calls if call[0][:3] == ('nft', '-f', '-')]
    assert len(mutations) == 1
    assert 'delete table inet box_priority' not in mutations[0][1]['input']
    assert all(call[0][:2] != ('tc', 'filter') for call in network_profile.calls)


@pytest.mark.parametrize('drift', ['missing', 'ipv6_missing', 'wrong_af41_class', 'wrong_cs6_class',
    'ecn_mask', 'restricted_flow', 'competing_filter', 'skb_override', 'rewrite_dscp',
    'early_box_hook', 'missing_essential', 'wrong_weights', 'ordinary_default', 'not_strict'])
def test_classifier_drift_fails_before_policy_mutations(priority, network_profile, drift):
    p = network_profile
    actual = [item for item in p.filters if 'options' in item]
    if drift == 'missing': p.filters.clear()
    elif drift == 'ipv6_missing': p.filters.remove(actual[2])
    elif drift == 'wrong_af41_class': actual[0]['options']['classid'] = 'b040:3'
    elif drift == 'wrong_cs6_class': actual[1]['options']['classid'] = 'b040:2'
    elif drift == 'ecn_mask': actual[0]['options']['keys']['ip_tos_mask'] = 'ff'
    elif drift == 'restricted_flow': actual[0]['options']['keys']['ip_proto'] = 'tcp'
    elif drift == 'competing_filter': p.filters.insert(0, {'kind': 'matchall', 'options': {'classid': 'b040:3'}})
    elif drift == 'skb_override': p.nft['nftables'].append({'rule': {'expr': [
        {'mangle': {'key': {'meta': {'key': 'priority'}}, 'value': 'b040:3'}}]}})
    elif drift == 'rewrite_dscp': p.nft['nftables'][1]['rule']['expr'][0]['mangle']['value'] = 'cs0'
    elif drift == 'early_box_hook': p.nft['nftables'][0]['chain']['prio'] = -142
    elif drift == 'missing_essential': p.nft['nftables'].pop()
    elif drift == 'wrong_weights': p.qdiscs[0]['options']['quanta'] = [1500, 12000]
    elif drift == 'ordinary_default': p.qdiscs[0]['options']['priomap'] = [0]*16
    elif drift == 'not_strict': p.qdiscs[0]['options']['strict'] = 0
    before = (priority.CGROUP/'io.cost.qos').read_bytes()
    with pytest.raises(ValueError): priority.apply_policy(config(), apply=True)
    assert (priority.CGROUP/'io.cost.qos').read_bytes() == before
    assert not any(args[:3] == ('nft', '-f', '-') for args, _ in p.calls)


@pytest.fixture
def real_user_files(priority, monkeypatch, tmp_path):
    home = tmp_path/'home'
    (home/'.config').mkdir(parents=True)
    home.chmod(0o700)
    (home/'.config').chmod(0o700)
    account = {'user': 'wa-local', 'uid': os.geteuid(), 'gid': os.getegid(), 'base': 'whatsapp-local', 'home': home}
    files = {path if path.is_relative_to(home) else tmp_path/'host'/path.relative_to('/'):
             text for path, text in priority.unit_files(account).items()}
    monkeypatch.setattr(priority, 'account_details', lambda user: account)
    monkeypatch.setattr(priority, 'unit_files', lambda account: dict(files))
    monkeypatch.setattr(priority, 'device_number', lambda cfg: '8:0')
    monkeypatch.setattr(priority, 'check_network', lambda cfg: (False, 'synthetic'))
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        if args[0] == 'runuser':
            assert args[2] == account['user']
            if not os.access(args[-1], os.R_OK if args[-2] == '-r' else os.X_OK):
                raise RuntimeError('Synthetic user cannot read/traverse path')
        return SimpleNamespace(returncode=0, stdout='')
    monkeypatch.setattr(priority, 'run', run)
    return SimpleNamespace(home=home, account=account, files=files, calls=calls)


def test_new_user_directories_ignore_admin_umask_and_keep_home_private(priority, real_user_files):
    f = real_user_files
    previous = os.umask(0o077)
    try: result = priority.enroll(config(), 'wa-local', apply=True)
    finally: os.umask(previous)
    for path in priority.user_directories(f.account, f.files):
        assert priority.directory_metadata(path) == {'uid': os.geteuid(), 'gid': os.getegid(), 'mode': 0o700}
    assert priority.directory_metadata(f.home)['mode'] == 0o700
    assert priority.directory_metadata(f.home/'.config')['mode'] == 0o700
    assert len([args for args in f.calls if args[0] == 'runuser' and '-r' in args]) == 2
    assert len(result['directories_changed']) == 4


def test_repeat_enrollment_repairs_metadata_without_rewriting_content(priority, real_user_files):
    f = real_user_files
    priority.enroll(config(), 'wa-local', apply=True)
    cfg = json.loads(priority.CONFIG.read_text())
    directory = f.home/'.config/systemd/user/app.slice.d'
    directory.chmod(0o755)
    contents = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in f.files}
    result = priority.enroll(cfg, 'wa-local', apply=True)
    assert result['changed'] == [] and result['directories_changed'] == [str(directory)]
    assert priority.directory_metadata(directory)['mode'] == 0o700
    assert contents == {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in f.files}
    third = priority.enroll(cfg, 'wa-local', apply=True)
    assert third['changed'] == [] and third['directories_changed'] == [] and third['backup'] is None


def test_failed_enrollment_restores_directory_permissions_and_contents(priority, real_user_files, monkeypatch):
    f = real_user_files
    priority.enroll(config(), 'wa-local', apply=True)
    cfg = json.loads(priority.CONFIG.read_text())
    directory = f.home/'.config/systemd/user/app.slice.d'
    directory.chmod(0o755)
    path = directory/'60-whatsapp-priority.conf'
    path.write_text(priority.MARKER+'old synthetic settings')
    before = path.read_bytes()
    def run(*args, **kwargs):
        if 'reload-or-restart' in args and kwargs.get('check', True):
            raise RuntimeError('synthetic service reload failure')
        return SimpleNamespace(returncode=0, stdout='')
    monkeypatch.setattr(priority, 'run', run)
    with pytest.raises(RuntimeError): priority.enroll(cfg, 'wa-local', apply=True)
    assert priority.directory_metadata(directory)['mode'] == 0o755
    assert path.read_bytes() == before
