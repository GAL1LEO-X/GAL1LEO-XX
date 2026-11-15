"""Attempt ownership/recovery on real temporary files with synthetic OS identities.

No user, service, mount, credentials or external account is created by this suite.
All administrative commands are forbidden except the explicitly injected fake.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


ATTEMPT = 'a' * 32
PLAN = 'b' * 64
SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/provisioning_attempt.py'


class Interrupted(BaseException):
    pass


class StopAt:
    def __init__(self, boundary):
        self.boundary = boundary
        self.fired = False

    def __call__(self, actual):
        if actual == self.boundary and not self.fired:
            self.fired = True
            raise Interrupted(actual)


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('synthetic_provisioning_attempt', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    registry_paths = {name: tmp_path / Path(name).name for name in module.SUBORDINATE_REGISTRIES}
    for path in registry_paths.values():
        path.write_text('')
    original_path = module.Path
    monkeypatch.setattr(module, 'Path', lambda value: registry_paths.get(str(value), original_path(value)))
    project = tmp_path / 'project'
    # mkdir(parents=True) applies mode only to the leaf: protect every
    # administrative parent explicitly, independent of the runner's umask.
    for directory in (project, project / 'private', project / 'private/tenants'):
        directory.mkdir(mode=0o700)
    roots = tmp_path / 'runtime'
    roots.mkdir(mode=0o700)
    profile = SimpleNamespace(compatibility=False, sha256='c' * 64, roster_sha256='d' * 64)
    instance = SimpleNamespace(project_root=project, slug='later', service_user='wa-fixture-later',
        auth_mode='external-oidc', _installation_identity=profile,
        config_dir=roots / 'config', state_dir=roots / 'state', gateway_home=roots / 'gateway',
        private_dir=project / 'private/tenants/later', base='wa-fixture-later',
        record=lambda: {'slug': 'later', 'subject': 'synthetic-owner', 'hostname': 'later.example.test'})
    instance.wrapper = instance.private_dir / 'as-user'
    host = SimpleNamespace(plan_digest=PLAN, plan={'operation_id': 'e' * 32})
    resources = [instance.config_dir, instance.state_dir, instance.gateway_home,
                 instance.private_dir, roots / 'service.unit']
    monkeypatch.setattr(module.Attempt, 'resource_roots', lambda self: list(resources))
    accounts, groups, calls = {}, {}, []
    def get_account(name):
        if name not in accounts:
            raise KeyError(name)
        return accounts[name]
    def get_group(name):
        if name not in groups:
            raise KeyError(name)
        return groups[name]
    def get_gid(gid):
        for value in groups.values():
            if value.gr_gid == gid:
                return value
        raise KeyError(gid)
    monkeypatch.setattr(module.pwd, 'getpwnam', get_account)
    monkeypatch.setattr(module.pwd, 'getpwall', lambda: list(accounts.values()))
    monkeypatch.setattr(module.grp, 'getgrnam', get_group)
    monkeypatch.setattr(module.grp, 'getgrgid', get_gid)
    monkeypatch.setattr(module.grp, 'getgrall', lambda: list(groups.values()))
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: pytest.fail('Real administrative command forbidden'))
    def run(args):
        calls.append(list(args))
        assert args[0] == 'useradd'
        assert '--no-create-home' in args and '--create-home' not in args
        assert args[-1] == instance.service_user
        accounts[instance.service_user] = SimpleNamespace(
            pw_name=instance.service_user, pw_uid=61001, pw_gid=61002,
            pw_dir=str(instance.gateway_home), pw_shell='/usr/sbin/nologin',
            pw_gecos=args[args.index('--comment') + 1])
        groups[instance.service_user] = SimpleNamespace(gr_name=instance.service_user, gr_gid=61002, gr_mem=[])
    class FakeSystem:
        def __init__(self):
            self.checked = 0
            self.removed = []
        def quiescent(self, account, paths):
            self.checked += 1
            assert all(Path(path).is_relative_to(tmp_path) for path in paths)
            if account is not None:
                assert module.account_identity(account['name']) == account
        def remove_subordinate(self, account, path, entry):
            selected = module.Path(path)
            assert selected.is_relative_to(tmp_path)
            rows = selected.read_text().splitlines()
            if entry in rows:
                selected.write_text('\n'.join(line for line in rows if line != entry) + '\n')
            self.removed.append(('subordinate', str(path), entry))
        def remove_user(self, account):
            actual = module.account_identity(account['name'])
            assert actual is None or actual == account
            if actual is not None:
                self.removed.append(('account', account['name']))
                accounts.pop(account['name'])
        def remove_group(self, account):
            if account['group'] in groups:
                self.removed.append(('group', account['group']))
                groups.pop(account['group'])
    system = FakeSystem()
    return SimpleNamespace(module=module, instance=instance, host=host, accounts=accounts,
        groups=groups, calls=calls, run=run, system=system, roots=resources, tmp=tmp_path,
        open=lambda **kw: module.Attempt(instance, host, ATTEMPT, **kw))


def publish_directory(attempt, path):
    attempt.publish(path, uid=os.geteuid(), gid=os.getegid())


def publish_file(attempt, path, content=b'owned synthetic bytes'):
    attempt.publish(path, content=content, mode=0o600, uid=os.geteuid(), gid=os.getegid())


def prepare_files(fixture):
    with fixture.open() as attempt:
        publish_directory(attempt, fixture.instance.config_dir)
        publish_file(attempt, fixture.instance.config_dir / 'data')


@pytest.mark.parametrize('kind', ['file', 'directory'])
@pytest.mark.parametrize('boundary', ['staged', 'published', 'recorded'])
def test_publication_crash_resumes_exact_inode_then_cancels(fixture, kind, boundary):
    target = fixture.instance.config_dir
    if kind == 'file':
        with fixture.open() as attempt:
            publish_directory(attempt, target)
        target /= 'data'
    stop = StopAt(boundary + ':' + str(target))
    with pytest.raises(Interrupted):
        with fixture.open(fault=stop) as attempt:
            (publish_file if kind == 'file' else publish_directory)(attempt, target)
    assert stop.fired
    receipt = fixture.module.read_private(fixture.module.root_for(fixture.instance) / (ATTEMPT + '.json'))
    expected = next(row['identity'] for row in receipt['resources'] if row['path'] == str(target))
    with fixture.open() as attempt:
        (publish_file if kind == 'file' else publish_directory)(attempt, target)
        assert fixture.module.identity(target) == expected
        assert attempt.cancel(fixture.system)['state'] == 'cancelled'
    assert not target.exists()
    assert fixture.system.removed == []


@pytest.mark.parametrize('which', ['file', 'directory'])
@pytest.mark.parametrize('boundary', ['before-remove', 'after-remove', 'removed'])
def test_compensation_crash_resumes_without_double_removal(fixture, which, boundary):
    prepare_files(fixture)
    path = fixture.instance.config_dir / 'data' if which == 'file' else fixture.instance.config_dir
    stop = StopAt(boundary + ':' + str(path))
    with pytest.raises(Interrupted):
        with fixture.open(fault=stop) as attempt:
            attempt.cancel(fixture.system)
    assert stop.fired
    with fixture.open() as attempt:
        assert attempt.cancel(fixture.system)['state'] == 'cancelled'
        before = attempt.status()
        assert attempt.cancel(fixture.system) == before
    assert not fixture.instance.config_dir.exists()


@pytest.mark.parametrize('resource', ['config', 'state', 'gateway', 'private', 'unit'])
def test_first_attempt_never_adopts_preexisting_paths(fixture, resource):
    target = fixture.roots[['config', 'state', 'gateway', 'private', 'unit'].index(resource)]
    if resource == 'unit':
        target.write_bytes(b'preexisting service')
    else:
        target.mkdir()
        (target / 'existing').write_bytes(b'preexisting data')
    before = fixture.module.identity(target)
    with pytest.raises(ValueError, match='Preexisting runtime'):
        with fixture.open():
            pytest.fail('Preexisting resource was admitted')
    assert fixture.module.identity(target) == before
    assert fixture.calls == []


def test_preexisting_account_or_group_is_preserved(fixture):
    fixture.run(['useradd', '--no-create-home', '--comment', 'not-an-attempt', fixture.instance.service_user])
    fixture.calls.clear()
    before = copy.deepcopy(fixture.module.account_identity(fixture.instance.service_user))
    with pytest.raises(ValueError, match='Preexisting account'):
        with fixture.open():
            pass
    assert fixture.module.account_identity(fixture.instance.service_user) == before
    fixture.accounts.clear()
    with pytest.raises(ValueError, match='Preexisting group'):
        with fixture.open():
            pass
    assert fixture.groups[fixture.instance.service_user].gr_gid == before['gid']
    assert fixture.calls == []


@pytest.mark.parametrize('change', ['bytes', 'mode', 'inode', 'foreign-child'])
def test_changed_or_foreign_data_is_preserved_before_any_cleanup(fixture, change):
    prepare_files(fixture)
    path = fixture.instance.config_dir / 'data'
    if change == 'bytes':
        path.write_bytes(b'changed by someone else')
    elif change == 'mode':
        path.chmod(0o640)
    elif change == 'inode':
        replacement = fixture.tmp / 'replacement'
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(path)
    else:
        (fixture.instance.config_dir / 'foreign').write_bytes(b'unrelated bytes')
    before = {str(item): item.read_bytes() for item in fixture.instance.config_dir.iterdir()}
    with fixture.open() as attempt:
        result = attempt.cancel(fixture.system)
        assert result['state'] == 'recovery_required'
        assert result['residuals']
    assert {str(item): item.read_bytes() for item in fixture.instance.config_dir.iterdir()} == before
    assert fixture.system.removed == []


@pytest.mark.parametrize('link', ['symlink', 'hardlink'])
def test_aliases_are_rejected_and_external_bytes_preserved(fixture, link):
    prepare_files(fixture)
    path = fixture.instance.config_dir / 'data'
    outside = fixture.tmp / 'unrelated'
    outside.write_bytes(b'unrelated bytes')
    path.unlink()
    if link == 'symlink':
        path.symlink_to(outside)
    else:
        os.link(outside, path)
    with pytest.raises(ValueError, match='Symlink|Hardlinked'):
        with fixture.open() as attempt:
            attempt.cancel(fixture.system)
    assert outside.read_bytes() == b'unrelated bytes'
    assert path.exists()
    assert fixture.system.removed == []


def test_scope_cannot_publish_another_instance_resource(fixture):
    sibling = fixture.tmp / 'unrelated'
    with fixture.open() as attempt:
        with pytest.raises(ValueError, match='outside this instance'):
            publish_file(attempt, sibling)
    assert not sibling.exists()


def test_mutation_lock_excludes_second_attempt_context(fixture):
    with fixture.open() as first:
        with pytest.raises(BlockingIOError):
            with fixture.open():
                pytest.fail('Concurrent journal context was admitted')
        assert first.status()['state'] == 'preparing'
    with fixture.open() as resumed:
        assert resumed.status()['attempt_id'] == ATTEMPT


@pytest.mark.parametrize('alteration', ['plan', 'operation', 'instance', 'allocation'])
def test_resume_requires_original_immutable_binding(fixture, alteration):
    with fixture.open():
        pass
    if alteration == 'plan':
        fixture.host.plan_digest = '0' * 64
    elif alteration == 'operation':
        fixture.host.plan['operation_id'] = '0' * 32
    elif alteration == 'instance':
        fixture.instance.record = lambda: {'slug': 'later', 'subject': 'other'}
    else:
        fixture.instance._installation_identity.roster_sha256 = '0' * 64
    with pytest.raises(ValueError, match='different inputs'):
        with fixture.open():
            pass


def test_another_attempt_cannot_take_existing_instance_gate(fixture):
    with fixture.open():
        pass
    with pytest.raises(ValueError, match='already has'):
        with fixture.module.Attempt(fixture.instance, fixture.host, 'f' * 32):
            pass


@pytest.mark.parametrize('state', ['preparing', 'cancelling', 'recovery_required', 'cancelled'])
def test_incomplete_or_cancelled_attempt_fences_activation(fixture, state):
    with fixture.open() as attempt:
        attempt.data['state'] = state
        attempt.save('test-state')
    with pytest.raises(ValueError, match='fenced'):
        fixture.module.guard_activation(fixture.instance)


def test_prepared_attempt_allows_activation_but_not_cancellation(fixture):
    prepare_files(fixture)
    with fixture.open() as attempt:
        attempt.finish()
        fixture.module.guard_activation(fixture.instance)
        with pytest.raises(ValueError, match='Completed instances'):
            attempt.cancel(fixture.system)
    assert (fixture.instance.config_dir / 'data').read_bytes() == b'owned synthetic bytes'


@pytest.mark.parametrize('boundary', ['before:account', 'after:account', 'done:account'])
def test_useradd_crash_recovers_marked_identity_without_duplicate_creation(fixture, boundary):
    stop = StopAt(boundary)
    with pytest.raises(Interrupted):
        with fixture.open(fault=stop) as attempt:
            attempt.create_account(fixture.run)
    with fixture.open() as attempt:
        account = attempt.create_account(fixture.run)
        assert account.pw_name == fixture.instance.service_user
        assert account.pw_gecos == 'wa-attempt-' + ATTEMPT + '-' + PLAN[:16]
        assert len(fixture.calls) == 1
        assert attempt.cancel(fixture.system)['state'] == 'cancelled'
    assert fixture.accounts == {} and fixture.groups == {}


def test_cancel_reconciles_useradd_success_before_receipt(fixture):
    with pytest.raises(Interrupted):
        with fixture.open(fault=StopAt('after:account')) as attempt:
            attempt.create_account(fixture.run)
    with fixture.open() as attempt:
        result = attempt.cancel(fixture.system)
        assert result['state'] == 'cancelled'
    assert fixture.accounts == {} and fixture.groups == {}
    assert len(fixture.calls) == 1


@pytest.mark.parametrize('changed', ['marker', 'uid', 'gid', 'group-member'])
def test_account_reuse_or_changed_group_blocks_before_files_are_deleted(fixture, changed):
    prepare_files(fixture)
    with fixture.open() as attempt:
        attempt.create_account(fixture.run)
    account = fixture.accounts[fixture.instance.service_user]
    if changed == 'marker':
        account.pw_gecos = 'belongs-to-another-attempt'
    elif changed == 'uid':
        account.pw_uid += 1
    elif changed == 'gid':
        account.pw_gid += 1
        fixture.groups[fixture.instance.service_user].gr_gid += 1
    else:
        fixture.groups[fixture.instance.service_user].gr_mem.append('other-user')
    with pytest.raises(ValueError, match='Account identity changed'):
        with fixture.open() as attempt:
            attempt.cancel(fixture.system)
    assert (fixture.instance.config_dir / 'data').exists()
    assert fixture.system.removed == []


def test_useradd_without_marker_is_not_adopted_after_interruption(fixture):
    with pytest.raises(Interrupted):
        with fixture.open(fault=StopAt('after:account')) as attempt:
            attempt.create_account(fixture.run)
    fixture.accounts[fixture.instance.service_user].pw_gecos = 'foreign'
    with pytest.raises(ValueError, match='Unattributed account'):
        with fixture.open() as attempt:
            attempt.cancel(fixture.system)
    assert fixture.instance.service_user in fixture.accounts
    assert fixture.system.removed == []


@pytest.mark.parametrize('boundary', ['before', 'after', 'done'])
def test_subordinate_allocation_recovers_same_range_and_preserves_other_rows(fixture, boundary):
    path = fixture.tmp / 'subuid'
    initial = 'other-a:100000:65536\nother-b:200000:65536\n'
    path.write_text(initial)
    calls = []
    def run(args):
        calls.append(args)
        assert args[0:2] == ['usermod', '--add-subuids']
        start, end = map(int, args[2].split('-'))
        with path.open('a') as stream:
            stream.write(f'{args[-1]}:{start}:{end - start + 1}\n')
    with fixture.open() as attempt:
        attempt.create_account(fixture.run)
    stop = StopAt(boundary + ':subid:' + str(path))
    with pytest.raises(Interrupted):
        with fixture.open(fault=stop) as attempt:
            attempt.subordinate(path, '--add-subuids', run)
    with fixture.open() as attempt:
        attempt.subordinate(path, '--add-subuids', run)
        assert len(calls) == 1
        assert path.read_text().startswith(initial)
        with path.open('a') as stream:
            stream.write('other-c:400000:65536\n')
        assert attempt.cancel(fixture.system)['state'] == 'cancelled'
    assert path.read_text() == initial + 'other-c:400000:65536\n'


def test_nonrecoverable_unknown_external_outcome_is_not_replayed(fixture):
    calls = []
    with pytest.raises(Interrupted):
        with fixture.open(fault=StopAt('after:opaque')) as attempt:
            attempt.effect('opaque', lambda: calls.append('effect'))
    with fixture.open() as attempt:
        with pytest.raises(ValueError, match='reconciliation'):
            attempt.effect('opaque', lambda: calls.append('duplicate'))
        assert attempt.status()['state'] == 'recovery_required'
        assert attempt.status()['effects']['opaque'] == 'pending'
        assert attempt.cancel(fixture.system)['state'] == 'recovery_required'
    assert calls == ['effect']


def test_recoverable_host_protocol_uses_same_intent_after_lost_result(fixture):
    observed = set()
    calls = []
    def idempotent_protocol():
        calls.append(PLAN)
        observed.add(PLAN)
    with pytest.raises(Interrupted):
        with fixture.open(fault=StopAt('after:host')) as attempt:
            attempt.effect('host', idempotent_protocol, recoverable=True)
    with fixture.open() as attempt:
        attempt.effect('host', idempotent_protocol, recoverable=True)
        attempt.effect('host', idempotent_protocol, recoverable=True)
        attempt.finish()
        assert attempt.status()['state'] == 'prepared'
    assert calls == [PLAN, PLAN] and observed == {PLAN}


def test_completed_external_step_requires_exact_recovery_instead_of_fake_cancellation(fixture):
    prepare_files(fixture)
    with fixture.open() as attempt:
        attempt.effect('frontend', lambda: None, recoverable=True)
        result = attempt.cancel(fixture.system)
    assert result['state'] == 'recovery_required'
    assert result['residuals'] == ['frontend']
    assert (fixture.instance.config_dir / 'data').read_bytes() == b'owned synthetic bytes'
    assert fixture.system.removed == []


@pytest.mark.parametrize('which', ['user', 'group'])
@pytest.mark.parametrize('boundary', ['before-remove', 'after-remove', 'removed'])
def test_user_and_group_removal_crashes_resume_separately(fixture, which, boundary):
    with fixture.open() as attempt:
        attempt.create_account(fixture.run)
    stop = StopAt(boundary + ':' + which)
    with pytest.raises(Interrupted):
        with fixture.open(fault=stop) as attempt:
            attempt.cancel(fixture.system)
    assert stop.fired
    with fixture.open() as attempt:
        assert attempt.cancel(fixture.system)['state'] == 'cancelled'
    assert fixture.accounts == {} and fixture.groups == {}
    assert fixture.system.removed.count(('account', fixture.instance.service_user)) == 1
    assert fixture.system.removed.count(('group', fixture.instance.service_user)) == 1


def test_cancel_owns_recorded_staging_file_inside_its_directory(fixture):
    with fixture.open() as attempt:
        publish_directory(attempt, fixture.instance.config_dir)
    target = fixture.instance.config_dir / 'data'
    with pytest.raises(Interrupted):
        with fixture.open(fault=StopAt('staged:' + str(target))) as attempt:
            publish_file(attempt, target)
    assert not target.exists()
    with fixture.open() as attempt:
        assert attempt.cancel(fixture.system)['state'] == 'cancelled'
    assert not fixture.instance.config_dir.exists()


def test_subid_rechecks_collision_after_persisting_intent(fixture):
    path = fixture.tmp / 'subuid'
    path.write_text('')
    with fixture.open() as attempt:
        attempt.create_account(fixture.run)
    def competing_allocator(boundary):
        if boundary == 'before:subid:' + str(path):
            path.write_text('foreign:100000:65536\n')
    def forbidden_mutation(args):
        pytest.fail('Attempt tried allocating an already occupied subordinate range')
    with fixture.open(fault=competing_allocator) as attempt:
        with pytest.raises(ValueError, match='another account|collision|changed'):
            attempt.subordinate(path, '--add-subuids', forbidden_mutation)
    assert path.read_text() == 'foreign:100000:65536\n'


def test_staged_bytes_changed_before_publish_are_not_accepted(fixture):
    with fixture.open() as attempt:
        publish_directory(attempt, fixture.instance.config_dir)
    target = fixture.instance.config_dir / 'data'
    def alter_stage(boundary):
        if boundary == 'staged:' + str(target):
            record = fixture.module.read_private(fixture.module.root_for(fixture.instance) / (ATTEMPT + '.json'))
            staged = next(Path(row['staging']) for row in record['resources'] if row['path'] == str(target))
            staged.write_bytes(b'not the staged bytes')
    with fixture.open(fault=alter_stage) as attempt:
        with pytest.raises(ValueError, match='changed|replaced|identity'):
            publish_file(attempt, target)
    assert not target.exists()


def test_resource_replaced_after_remove_intent_is_preserved(fixture):
    prepare_files(fixture)
    target = fixture.instance.config_dir / 'data'
    def competing_writer(boundary):
        if boundary == 'before-remove:' + str(target):
            target.write_bytes(b'foreign update after deletion intent')
    with fixture.open(fault=competing_writer) as attempt:
        with pytest.raises(ValueError, match='changed|replaced|identity'):
            attempt.cancel(fixture.system)
    assert target.read_bytes() == b'foreign update after deletion intent'
    assert fixture.system.removed == []


@pytest.mark.parametrize('blocker', ['process', 'mount', 'linger'])
def test_system_quiescence_requires_no_process_mount_or_linger(fixture, monkeypatch, blocker):
    with fixture.open() as attempt:
        attempt.create_account(fixture.run)
        account = copy.deepcopy(attempt.data['account'])
    proc = fixture.tmp / 'proc'
    (proc / 'self').mkdir(parents=True)
    (proc / 'self/mountinfo').write_text('')
    linger = fixture.tmp / 'linger'
    linger.mkdir()
    original_path = fixture.module.Path
    def mapped_path(value):
        value = str(value)
        if value == '/proc':
            return proc
        if value == '/proc/self/mountinfo':
            return proc / 'self/mountinfo'
        if value == '/var/lib/systemd/linger':
            return linger
        return original_path(value)
    monkeypatch.setattr(fixture.module, 'Path', mapped_path)
    if blocker == 'process':
        (proc / '123').mkdir()
        (proc / '123/status').write_text('Name:\tsynthetic\nUid:\t0\t61001\t0\t0\n')
    elif blocker == 'mount':
        mounted = str(fixture.instance.gateway_home / 'volume')
        (proc / 'self/mountinfo').write_text('24 23 0:21 / ' + mounted + ' rw - tmpfs tmpfs rw\n')
    else:
        (linger / account['name']).write_text('')
    system = fixture.module.System(runner=lambda *a, **k: pytest.fail('No OS mutation allowed'))
    with pytest.raises(ValueError, match='processes|mount|Linger'):
        system.quiescent(account, fixture.roots)


@pytest.mark.parametrize('reuse', ['primary-user', 'new-gid', 'member'])
def test_system_will_not_remove_group_now_used_by_others(fixture, monkeypatch, reuse):
    with fixture.open() as attempt:
        attempt.create_account(fixture.run)
        account = copy.deepcopy(attempt.data['account'])
    fixture.accounts.clear()
    if reuse == 'primary-user':
        fixture.accounts['other'] = SimpleNamespace(pw_name='other', pw_gid=account['gid'])
    elif reuse == 'new-gid':
        fixture.groups[account['group']].gr_gid += 1
    else:
        fixture.groups[account['group']].gr_mem.append('other')
    system = fixture.module.System(runner=lambda *a, **k: pytest.fail('No group deletion allowed'))
    with pytest.raises(ValueError, match='Another account|Primary group changed'):
        system.remove_group(account)
    assert account['group'] in fixture.groups


@pytest.mark.parametrize('boundary', ['staged', 'published', 'recorded'])
def test_process_exit_releases_lease_and_preserves_durable_publication(fixture, boundary):
    """A separate process exits without finally/close; the next process resumes."""
    import subprocess
    import sys
    child = r'''
import importlib.util, json, os, sys
from pathlib import Path
from types import SimpleNamespace
spec = importlib.util.spec_from_file_location('child_attempt', sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
v = json.loads(sys.argv[2])
i = SimpleNamespace(**{key: Path(value) for key, value in v['paths'].items()},
    slug='later', service_user='wa-fixture-later', auth_mode='external-oidc', base='wa-fixture-later',
    _installation_identity=SimpleNamespace(compatibility=False, sha256='c'*64, roster_sha256='d'*64),
    record=lambda: {'slug':'later','subject':'synthetic-owner','hostname':'later.example.test'})
h = SimpleNamespace(plan_digest='b'*64, plan={'operation_id':'e'*32})
m.Attempt.resource_roots = lambda self: [Path(path) for path in v['roots']]
m.account_identity = lambda name: None
m.grp.getgrnam = lambda name: (_ for _ in ()).throw(KeyError(name))
target = i.config_dir/'data'
with m.Attempt(i,h,'a'*32) as attempt:
    attempt.publish(i.config_dir,uid=os.geteuid(),gid=os.getegid())
    def crash(actual):
        if actual == v['boundary']+':'+str(target):
            os._exit(77)
    attempt.fault = crash
    attempt.publish(target,content=b'process-created bytes',mode=0o600,uid=os.geteuid(),gid=os.getegid())
raise AssertionError('Expected process termination was not reached')
'''
    paths = {key: str(getattr(fixture.instance, key)) for key in
             ('project_root', 'config_dir', 'state_dir', 'gateway_home', 'private_dir')}
    parameters = {'paths': paths, 'roots': [str(path) for path in fixture.roots], 'boundary': boundary}
    process = subprocess.Popen([sys.executable, '-B', '-c', child, str(SCRIPT), json.dumps(parameters)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate(timeout=20)
    assert process.returncode == 77, (stdout, stderr)
    target = fixture.instance.config_dir / 'data'
    with fixture.open() as attempt:
        publish_file(attempt, target, b'process-created bytes')
        assert target.read_bytes() == b'process-created bytes'
        assert attempt.cancel(fixture.system)['state'] == 'cancelled'
    assert not target.exists()


@pytest.mark.parametrize('registry', ['subuid', 'subgid'])
def test_named_subordinate_reservation_blocks_account_creation_and_cancel(fixture, registry):
    path = fixture.tmp / registry
    original = 'foreign:100000:65536\n' + fixture.instance.service_user + ':900000:65536\n'
    path.write_text(original)
    with fixture.open() as attempt:
        with pytest.raises(ValueError, match='Preexisting subordinate'):
            attempt.create_account(fixture.run)
        assert attempt.cancel(fixture.system)['state'] == 'recovery_required'
    assert fixture.accounts == {} and fixture.calls == [] and fixture.system.removed == []
    assert path.read_text() == original


@pytest.mark.parametrize('registry', ['subuid', 'subgid'])
@pytest.mark.parametrize('owner', ['61001', '00061001', '+61001', ' 61001'])
def test_numeric_uid_reservation_blocks_new_account_before_subordinate_allocation(fixture, registry, owner):
    path = fixture.tmp / registry
    original = owner + ':100000:65536\n'
    path.write_text(original)
    with fixture.open() as attempt:
        with pytest.raises(ValueError, match='subordinate allocations|subordinate allocations requiring'):
            attempt.create_account(fixture.run)
        assert attempt.cancel(fixture.system)['state'] == 'recovery_required'
        assert not any(name.startswith('subid:') for name in attempt.data['effects'])
    assert path.read_text() == original and fixture.system.removed == []


@pytest.mark.parametrize('registry', ['subuid', 'subgid'])
@pytest.mark.parametrize('owner', ['name', 'uid', 'zero-padded-uid'])
def test_unrecorded_subordinate_rows_block_cleanup_before_any_file_is_removed(fixture, registry, owner):
    prepare_files(fixture)
    with fixture.open() as attempt:
        attempt.create_account(fixture.run)
    name = fixture.instance.service_user if owner == 'name' else '61001' if owner == 'uid' else '00061001'
    path = fixture.tmp / registry
    original = name + ':900000:65536\n'
    path.write_text(original)
    before = (fixture.instance.config_dir / 'data').read_bytes()
    for _ in range(2):
        with fixture.open() as attempt:
            result = attempt.cancel(fixture.system)
            assert result['state'] == 'recovery_required'
            assert 'account-dependencies' in result['residuals']
        assert (fixture.instance.config_dir / 'data').read_bytes() == before
        assert path.read_text() == original and fixture.system.removed == []
    assert fixture.instance.service_user in fixture.accounts


@pytest.mark.parametrize('point', ['before:account', 'before-remove:file', 'before-remove:user'])
def test_subordinate_row_arriving_after_intent_is_preserved(fixture, point):
    target = fixture.instance.config_dir / 'data'
    if point == 'before-remove:file':
        prepare_files(fixture)
    if point != 'before:account':
        with fixture.open() as attempt:
            attempt.create_account(fixture.run)
    boundary = 'before-remove:' + str(target) if point == 'before-remove:file' else point
    path = fixture.tmp / 'subgid'
    original = fixture.instance.service_user + ':900000:65536\n'
    def arrive(actual):
        if actual == boundary:
            path.write_text(original)
    with fixture.open(fault=arrive) as attempt:
        if point == 'before:account':
            with pytest.raises(ValueError, match='changed before account'):
                attempt.create_account(fixture.run)
        else:
            assert attempt.cancel(fixture.system)['state'] == 'recovery_required'
    assert path.read_text() == original and fixture.system.removed == []
    if point == 'before-remove:file':
        assert target.read_bytes() == b'owned synthetic bytes'


@pytest.mark.parametrize('registry', ['subuid', 'subgid'])
def test_userdel_boundary_refuses_unrecorded_numeric_rows(fixture, monkeypatch, registry):
    with fixture.open() as attempt:
        attempt.create_account(fixture.run)
        account = copy.deepcopy(attempt.data['account'])
    path = fixture.tmp / registry
    original = '00061001:900000:65536\n'
    path.write_text(original)
    system = fixture.module.System(runner=lambda *a, **k: pytest.fail('userdel would remove an unattributed row'))
    monkeypatch.setattr(system, 'quiescent', fixture.system.quiescent)
    with pytest.raises(ValueError, match='lack exact attempt provenance'):
        system.remove_user(account)
    assert path.read_text() == original and fixture.instance.service_user in fixture.accounts


@pytest.mark.parametrize('phase', ['before-create', 'after-create', 'before-cancel'])
def test_supplementary_memberships_are_neither_inherited_nor_compensated(fixture, phase):
    name = fixture.instance.service_user
    foreign = SimpleNamespace(gr_name='foreign-data', gr_gid=62001, gr_mem=[name])
    if phase == 'before-create':
        fixture.groups['foreign-data'] = foreign
    prepare_files(fixture)
    def run(argv):
        fixture.run(argv)
        if phase == 'after-create':
            fixture.groups['foreign-data'] = foreign
    with fixture.open() as attempt:
        if phase == 'before-cancel':
            attempt.create_account(run)
            fixture.groups['foreign-data'] = foreign
        else:
            with pytest.raises(ValueError, match='reconciliation'):
                attempt.create_account(run)
        assert attempt.cancel(fixture.system)['state'] == 'recovery_required'
    assert (fixture.instance.config_dir / 'data').read_bytes() == b'owned synthetic bytes'
    assert foreign.gr_mem == [name] and fixture.system.removed == []
    if phase == 'before-create':
        assert fixture.calls == []


def test_same_uid_login_cannot_hide_subordinate_allocation(fixture):
    with fixture.open() as attempt:
        attempt.create_account(fixture.run)
        fixture.accounts['alias'] = SimpleNamespace(pw_name='alias', pw_uid=61001, pw_gid=62002)
        path = fixture.tmp / 'subuid'
        path.write_text('alias:900000:65536\n')
        with pytest.raises(ValueError, match='Preexisting subordinate'):
            attempt.subordinate(path, '--add-subuids', lambda argv: pytest.fail('Alias UID must not be allocated'))
        assert attempt.cancel(fixture.system)['state'] == 'recovery_required'
    assert path.read_text() == 'alias:900000:65536\n' and fixture.system.removed == []


@pytest.mark.parametrize('boundary', ['before', 'after'])
def test_other_registry_drift_during_allocation_requires_recovery(fixture, boundary):
    prepare_files(fixture)
    path, other = fixture.tmp / 'subuid', fixture.tmp / 'subgid'
    original = '00061001:900000:65536\n'
    commands = []
    def arrive(actual):
        if actual == boundary + ':subid:' + str(path):
            other.write_text(original)
    def run(argv):
        commands.append(argv)
        assert argv == ['usermod', '--add-subuids', '100000-165535', fixture.instance.service_user]
        path.write_text(fixture.instance.service_user + ':100000:65536\n')
    with fixture.open(fault=arrive) as attempt:
        attempt.create_account(fixture.run)
        with pytest.raises(ValueError, match='Account dependencies changed'):
            attempt.subordinate(path, '--add-subuids', run)
        assert attempt.data['effects']['subid:' + str(path)]['state'] == 'pending'
        assert attempt.cancel(fixture.system)['state'] == 'recovery_required'
    assert len(commands) == (boundary == 'after')
    assert other.read_text() == original and fixture.system.removed == []
    assert (fixture.instance.config_dir / 'data').read_bytes() == b'owned synthetic bytes'


def test_late_supplementary_membership_cannot_finish_preparation(fixture):
    with fixture.open() as attempt:
        attempt.create_account(fixture.run)
        foreign = SimpleNamespace(gr_name='foreign', gr_gid=62001, gr_mem=[fixture.instance.service_user])
        fixture.groups['foreign'] = foreign
        with pytest.raises(ValueError, match='Account dependencies require reconciliation'):
            attempt.finish()
        assert attempt.data['state'] == 'recovery_required'
        assert 'account-dependencies' in attempt.data['residuals']
        with pytest.raises(ValueError, match='fenced'):
            fixture.module.guard_activation(fixture.instance)
    assert foreign.gr_mem == [fixture.instance.service_user]


def test_native_userdel_rechecks_dependencies_after_quiescence(fixture, monkeypatch):
    other = fixture.tmp / 'subgid'
    original = '00061001:900000:65536\n'
    system = fixture.module.System(runner=lambda *a, **k: pytest.fail('Foreign row forbids userdel'))
    with fixture.open() as attempt:
        attempt.create_account(fixture.run)
        def quiescent(account, roots):
            fixture.system.quiescent(account, roots)
            if attempt.data['effects']['account']['state'] == 'removing_user':
                other.write_text(original)
        monkeypatch.setattr(system, 'quiescent', quiescent)
        assert attempt.cancel(system)['state'] == 'recovery_required'
        assert attempt.data['effects']['account']['state'] == 'removing_user'
    assert other.read_text() == original and fixture.instance.service_user in fixture.accounts
