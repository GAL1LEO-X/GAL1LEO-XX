"""Real bounded proc-shaped files; no ambient /proc scan or host tools."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys

import pytest

SOURCE = Path(__file__).resolve().parents[2] / 'host/qos/processes.py'
spec = importlib.util.spec_from_file_location('tested_qos_processes', SOURCE)
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
BOOT = '01234567-89ab-cdef-0123-456789abcdef'
OTHER_BOOT = 'fedcba98-7654-3210-fedc-ba9876543210'
SCRIPT = '/usr/local/sbin/box-network-priority'
SCOPE = {'script_paths': [SCRIPT, '/usr/sbin/tc', '/usr/sbin/nft'],
         'cgroups': ['/system.slice/box-network-priority.service']}


@pytest.fixture
def proc(tmp_path):
    root = tmp_path / 'proc'; (root / 'sys/kernel/random').mkdir(parents=True)
    (root / 'sys/kernel/random/boot_id').write_text(BOOT + '\n')
    return root


def put(proc, pid=101, *, start=1000, ppid=1, pgrp=None, session=None, argv=None,
        group='/', state='S', cwd='/', comm='worker ) ( private'):
    directory = proc / str(pid); directory.mkdir(exist_ok=True)
    values = [state, str(ppid), str(pid if pgrp is None else pgrp),
              str(pid if session is None else session)] + ['0'] * 15 + [str(start)] + ['0'] * 4
    (directory / 'stat').write_text(f'{pid} ({comm}) ' + ' '.join(values) + '\n')
    args = ['/usr/bin/python3', SCRIPT, '--private-token=DO-NOT-REPORT'] if argv is None else argv
    (directory / 'cmdline').write_bytes(b'\x00'.join(item.encode() for item in args) + (b'\x00' if args else b''))
    (directory / 'cgroup').write_text('0::' + group + '\n')
    link = directory / 'cwd'
    if link.is_symlink(): link.unlink()
    link.symlink_to(cwd)
    return directory


def collect(proc, priors=()):
    return p.collect(SCOPE, priors, proc_root=proc, clock_ns=lambda: 100)


def quiet(receipt, priors=(), **extra):
    return p.require_quiet(receipt, scope=SCOPE, prior_records=priors, now_ns=100, **extra)


def test_empty_scope_snapshot_is_bound_fresh_and_quiet(proc):
    receipt = collect(proc)
    assert quiet(receipt) is receipt
    assert receipt['records'] == [] and len(receipt['snapshots']) == 2
    assert receipt['boot_id'] == BOOT and all(item['process_count'] == 0 for item in receipt['snapshots'])


def test_exact_script_is_busy_and_receipt_contains_no_private_command(proc):
    put(proc)
    receipt = collect(proc)
    with pytest.raises(p.ProcessesBusy): quiet(receipt)
    record = receipt['records'][0]
    assert (record['pid'], record['start_ticks'], record['ppid'], record['pgrp'], record['session']) == (101, 1000, 1, 101, 101)
    assert set(record) == p.RECORD_FIELDS
    assert 'DO-NOT-REPORT' not in repr(receipt) and 'private' not in repr(receipt)


def test_path_match_is_exact_and_cgroup_prefix_is_segment_bounded(proc):
    put(proc, argv=['python3', SCRIPT + '-unrelated'], group='/system.slice/box-network-priority.service-extra')
    quiet(collect(proc))
    put(proc, argv=['unrelated'], group='/system.slice/box-network-priority.service/worker')
    with pytest.raises(p.ProcessesBusy): quiet(collect(proc))


def test_relative_source_uses_proc_cwd_and_path_tool_basename_is_conservative(proc):
    put(proc, argv=['python3', './box-network-priority'], cwd='/usr/local/sbin')
    with pytest.raises(p.ProcessesBusy): quiet(collect(proc))
    put(proc, argv=['tc', 'monitor'])
    assert any(value == 'path:/usr/sbin/tc' for value in collect(proc)['records'][0]['scope_ids'])


def test_descendants_transitive_and_orphan_prior_survive_parent_exit(proc):
    put(proc, pid=101)
    put(proc, pid=102, ppid=101, pgrp=101, session=101, argv=['bounded-client'])
    put(proc, pid=103, ppid=102, pgrp=101, session=101, argv=['bounded-child'])
    first = collect(proc)
    assert [value['pid'] for value in first['records']] == [101, 102, 103]
    shutil.rmtree(proc / '101'); shutil.rmtree(proc / '102')
    put(proc, pid=103, ppid=1, pgrp=103, session=103, argv=['bounded-child'])
    second = collect(proc, first['records'])
    assert [value['pid'] for value in second['records']] == [103]
    with pytest.raises(p.ProcessesBusy): quiet(second, first['records'])
    shutil.rmtree(proc / '103')
    quiet(collect(proc, second['records']), second['records'])


def test_prior_owned_session_detects_new_orphan_child(proc):
    put(proc, pid=101)
    first = collect(proc); shutil.rmtree(proc / '101')
    put(proc, pid=102, ppid=1, pgrp=101, session=101, argv=['client-with-no-script-path'])
    second = collect(proc, first['records'])
    assert [value['pid'] for value in second['records']] == [102]
    with pytest.raises(p.ProcessesBusy): quiet(second, first['records'])


def test_prior_shared_session_does_not_claim_all_root_processes(proc):
    put(proc, pid=101, pgrp=50, session=50)
    first = collect(proc); shutil.rmtree(proc / '101')
    put(proc, pid=50, argv=['unrelated-administrator'])
    quiet(collect(proc, first['records']), first['records'])


def test_pid_reuse_and_new_boot_do_not_reuse_old_identity(proc):
    put(proc); first = collect(proc)
    put(proc, start=2000, argv=['different-process'])
    quiet(collect(proc, first['records']), first['records'])
    put(proc, start=1000, argv=['different-process'])
    (proc / 'sys/kernel/random/boot_id').write_text(OTHER_BOOT)
    quiet(collect(proc, first['records']), first['records'])


def test_zombie_itself_is_not_writer_but_live_descendant_still_blocks(proc):
    put(proc, state='Z')
    quiet(collect(proc))
    put(proc, pid=102, ppid=101, argv=['child'])
    with pytest.raises(p.ProcessesBusy): quiet(collect(proc))


def test_early_kernel_thread_with_zero_start_tick_is_not_malformed(proc):
    put(proc, pid=2, ppid=0, pgrp=0, session=0, start=0, argv=[])
    quiet(collect(proc))


@pytest.mark.parametrize('member', ['cmdline', 'cgroup', 'stat'])
def test_missing_file_of_extant_pid_is_incomplete_not_absence(proc, member):
    directory = put(proc); (directory / member).unlink()
    with pytest.raises(p.ProcessesError, match='incomplete'): collect(proc)


def test_symlink_pid_and_required_file_are_rejected(proc, tmp_path):
    directory = put(proc)
    other = tmp_path / 'outside'; other.mkdir()
    shutil.rmtree(directory); directory.symlink_to(other)
    with pytest.raises(p.ProcessesError): collect(proc)
    directory.unlink(); directory = put(proc)
    (directory / 'stat').unlink(); (directory / 'stat').symlink_to(other / 'stat')
    with pytest.raises(p.ProcessesError): collect(proc)


def test_fifo_evidence_is_rejected_without_waiting_for_a_writer(proc):
    directory = put(proc)
    (directory / 'cmdline').unlink(); os.mkfifo(directory / 'cmdline')
    with pytest.raises(p.ProcessesError, match='regular'): collect(proc)


@pytest.mark.parametrize('member,content', [('cmdline', b'not-nul-terminated'), ('cgroup', b'incomplete\n'), ('stat', b'101 (broken) S 1')])
def test_malformed_evidence_blocks(proc, member, content):
    (put(proc) / member).write_bytes(content)
    with pytest.raises(p.ProcessesError): collect(proc)


def test_individual_and_total_byte_bounds_and_cardinality(proc, monkeypatch):
    put(proc)
    monkeypatch.setattr(p, 'MAX_CMDLINE_BYTES', 8)
    with pytest.raises(p.ProcessesError, match='bound'): collect(proc)
    monkeypatch.setattr(p, 'MAX_CMDLINE_BYTES', 512 * 1024)
    monkeypatch.setattr(p, 'MAX_TOTAL_BYTES', 64)
    with pytest.raises(p.ProcessesError, match='bound'): collect(proc)
    monkeypatch.setattr(p, 'MAX_TOTAL_BYTES', 32 * 1024 * 1024)
    monkeypatch.setattr(p, 'MAX_PROCESSES', 0)
    with pytest.raises(p.ProcessesError, match='bound'): collect(proc)


def test_process_appearing_between_snapshots_blocks(proc, monkeypatch):
    original = p._snapshot; count = 0
    def after_first(*args):
        nonlocal count
        result = original(*args); count += 1
        if count == 1: put(proc)
        return result
    monkeypatch.setattr(p, '_snapshot', after_first)
    receipt = collect(proc)
    assert receipt['snapshots'][0]['records'] == [] and receipt['snapshots'][1]['records']
    with pytest.raises(p.ProcessesBusy): quiet(receipt)


def test_disappearing_process_can_be_absent_only_when_pid_directory_is_gone(proc, monkeypatch):
    directory = put(proc)
    original = p._read_at
    def read(parent, name, *args):
        if name == 'cmdline' and directory.exists():
            shutil.rmtree(directory)
        return original(parent, name, *args)
    monkeypatch.setattr(p, '_read_at', read)
    quiet(collect(proc))


def test_identity_change_during_same_pid_read_is_rejected(proc, monkeypatch):
    put(proc); original = p._read_at; count = 0
    def read(parent, name, *args):
        nonlocal count
        if name == 'stat':
            count += 1
            if count == 2: put(proc, start=2000)
        return original(parent, name, *args)
    monkeypatch.setattr(p, '_read_at', read)
    with pytest.raises(p.ProcessesError, match='identity changed'): collect(proc)


def test_receipt_tampering_scope_prior_and_clock_are_rejected(proc):
    good = collect(proc)
    bad = copy.deepcopy(good); bad['finished_ns'] = 101
    with pytest.raises(p.ProcessesError): quiet(bad)
    with pytest.raises(p.ProcessesError): p.require_quiet(good, scope=SCOPE, now_ns=6_000_000_101)
    with pytest.raises(p.ProcessesError): p.require_quiet(good, scope={'script_paths':[SCRIPT], 'cgroups':[]}, now_ns=100)
    bad = copy.deepcopy(good); bad['snapshots'] = bad['snapshots'][:1]
    with pytest.raises(p.ProcessesError): quiet(bad)
    put(proc); busy = collect(proc)
    bad = copy.deepcopy(busy); bad['records'] = []
    with pytest.raises(p.ProcessesError, match='differ'): quiet(bad)
    with pytest.raises(p.ProcessesError): quiet(good, busy['records'])


def test_invalid_scope_prior_and_boot_are_rejected(proc):
    with pytest.raises(p.ProcessesError): p.collect({'script_paths':[], 'cgroups':[]}, proc_root=proc)
    with pytest.raises(p.ProcessesError): p.collect({'script_paths':['/a/../b'], 'cgroups':[]}, proc_root=proc)
    with pytest.raises(p.ProcessesError): collect(proc, [{'pid':101}])
    (proc / 'sys/kernel/random/boot_id').write_text('invalid')
    with pytest.raises(p.ProcessesError): collect(proc)


def test_own_loaded_legacy_process_is_busy_after_guard_until_it_exits(proc, tmp_path):
    """Only this child's three proc files are copied; no ambient process scan.

    The pinned helper calls a recording run function, never tc/nft or services.
    """
    source = (Path(__file__).parent / 'fixtures/qos/legacy-network-policy.py.txt').read_bytes()
    assert hashlib.sha256(source).hexdigest() == '2331c08bc3a0a857e3a2d0a97673200b8ff6cf2462033157a880489730770603'
    helper = tmp_path / 'legacy.py'; helper.write_bytes(source)
    loader = '''
import json, sys, types
from pathlib import Path
namespace = {'__name__':'loaded_legacy', '__file__':sys.argv[1]}
exec(compile(Path(sys.argv[1]).read_bytes(), sys.argv[1], 'exec'), namespace)
class FixturePath:
    def __init__(self, name):
        assert name == '/etc/box-network-priority.json'
    def read_text(self):
        return json.dumps({'interface':'fixture0','proxy_user':'boxproxy'})
calls = []
def run(*argv, **kwargs):
    calls.append(list(argv))
    output = json.dumps([{'kind':'ets','handle':'b040:','root':True}]) if 'show' in argv else ''
    return types.SimpleNamespace(returncode=0,stdout=output,stderr='')
namespace['Path'] = FixturePath
namespace['pwd'] = types.SimpleNamespace(getpwnam=lambda name: types.SimpleNamespace(pw_uid={'boxproxy':2300,'_apt':42,'bind':104,'systemd-timesync':991}[name]))
namespace['run'] = run
print('loaded',flush=True)
assert sys.stdin.readline().strip() == 'resume'
sys.argv = ['legacy.py','remove']
namespace['main']()
print(json.dumps(calls),flush=True)
'''
    child = subprocess.Popen([sys.executable, '-I', '-B', '-c', loader, str(helper)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert select.select([child.stdout], [], [], 5)[0]
        assert child.stdout.readline() == b'loaded\n'
        helper.write_text('raise SystemExit("Neutral host guard")\n')
        fresh = subprocess.run([sys.executable, '-I', '-B', str(helper)], capture_output=True, timeout=5)
        assert fresh.returncode != 0 and child.poll() is None
        observed = proc / str(child.pid); observed.mkdir()
        for member in ('stat', 'cmdline', 'cgroup'):
            (observed / member).write_bytes((Path('/proc') / str(child.pid) / member).read_bytes())
        scope = {'script_paths': [str(helper)], 'cgroups': []}
        receipt = p.collect(scope, proc_root=proc)
        assert [record['pid'] for record in receipt['records']] == [child.pid]
        with pytest.raises(p.ProcessesBusy): p.require_quiet(receipt, scope=scope)
        stdout, stderr = child.communicate(b'resume\n', timeout=5)
        assert child.returncode == 0, stderr
        assert ['tc', 'qdisc', 'replace', 'dev', 'fixture0', 'root', 'mq'] in json.loads(stdout)
        shutil.rmtree(observed)
        prior = receipt['records']
        p.require_quiet(p.collect(scope, prior, proc_root=proc), scope=scope, prior_records=prior)
    finally:
        if child.poll() is None:
            child.kill(); child.communicate(timeout=5)


def put_uid(proc, pid=201, *, uids=(2300, 2300, 2300, 2300), **kwargs):
    directory = put(proc, pid=pid, argv=['unrelated-relay', '--private=DO-NOT-REPORT'], **kwargs)
    (directory / 'status').write_text('Name:\tPRIVATE\nUid:\t' + '\t'.join(map(str, uids)) + '\nGid:\t44\t44\t44\t44\n')
    return directory


def uid_quiet(proc, uid=2300):
    return p.require_uid_quiet(uid, proc_root=proc, clock_ns=lambda: 100)


def test_uid_quiet_observes_all_processes_without_cmdline_or_cgroup(proc):
    directory = put_uid(proc, uids=(42, 42, 42, 42))
    (directory / 'cmdline').unlink(); (directory / 'cgroup').unlink()
    result = uid_quiet(proc)
    assert result['uid'] == 2300 and result['records'] == []
    assert len(result['snapshots']) == 2
    assert all(item['process_count'] == 1 for item in result['snapshots'])
    assert 'PRIVATE' not in repr(result)


@pytest.mark.parametrize('credential', range(4))
def test_uid_any_credential_outside_application_scope_blocks(proc, credential):
    uids = [42] * 4; uids[credential] = 2300
    put_uid(proc, uids=uids, group='/unrelated-relay')
    with pytest.raises(p.ProcessesBusy) as failure:
        uid_quiet(proc)
    result = failure.value.receipt
    assert result['records'] == [{'boot_id': BOOT, 'pid': 201, 'start_ticks': 1000, 'uids': uids}]
    assert 'DO-NOT-REPORT' not in repr(result) and 'PRIVATE' not in repr(result)


def test_uid_zombie_also_blocks_until_directory_disappears(proc):
    directory = put_uid(proc, state='Z')
    with pytest.raises(p.ProcessesBusy): uid_quiet(proc)
    shutil.rmtree(directory)
    assert uid_quiet(proc)['records'] == []


def test_uid_parses_only_our_real_child_credentials_and_requires_its_exit(proc):
    child = subprocess.Popen([sys.executable, '-I', '-B', '-c',
                              'import sys; print("ready", flush=True); sys.stdin.readline()'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert select.select([child.stdout], [], [], 5)[0]
        assert child.stdout.readline() == b'ready\n'
        observed = proc / str(child.pid); observed.mkdir()
        # Read only this child, never enumerate ambient /proc.
        for member in ('stat', 'status'):
            (observed / member).write_bytes((Path('/proc') / str(child.pid) / member).read_bytes())
        with pytest.raises(p.ProcessesBusy) as failure:
            uid_quiet(proc, os.getuid())
        assert failure.value.receipt['records'][0]['pid'] == child.pid
        child.communicate(b'exit\n', timeout=5)
        assert child.returncode == 0
        shutil.rmtree(observed)
        assert uid_quiet(proc, os.getuid())['records'] == []
    finally:
        if child.poll() is None:
            child.kill(); child.communicate(timeout=5)


@pytest.mark.parametrize('content', [b'Name: unrelated\n', b'Uid: 1 2 3\n', b'Uid: 1 2 3 4 5\n',
                                    b'Uid: 1 2 -1 4\n', b'Uid: 1 2 3 4294967295\n',
                                    b'Uid: 1 2 3 4\nUid: 1 2 3 4\n', b'Uid: 1 2 3 ' + b'9' * 6000])
def test_uid_incomplete_or_ambiguous_status_blocks_even_unrelated_process(proc, content):
    (put_uid(proc, uids=(42,) * 4) / 'status').write_bytes(content)
    with pytest.raises(p.ProcessesError): uid_quiet(proc)


@pytest.mark.parametrize('member', ['stat', 'status'])
def test_uid_missing_required_file_is_not_quiescence(proc, member):
    (put_uid(proc) / member).unlink()
    with pytest.raises(p.ProcessesError, match='incomplete'): uid_quiet(proc)


def test_uid_status_symlink_and_fifo_are_rejected(proc, tmp_path):
    directory = put_uid(proc); (directory / 'status').unlink()
    outside = tmp_path / 'status'; outside.write_text('Uid: 1 1 1 1\n')
    (directory / 'status').symlink_to(outside)
    with pytest.raises(p.ProcessesError): uid_quiet(proc)
    (directory / 'status').unlink(); os.mkfifo(directory / 'status')
    with pytest.raises(p.ProcessesError, match='regular'): uid_quiet(proc)


def test_uid_process_exit_during_read_needs_actual_directory_absence(proc, monkeypatch):
    directory = put_uid(proc)
    original = p._read_at
    def read(parent, name, *args):
        if name == 'status' and directory.exists(): shutil.rmtree(directory)
        return original(parent, name, *args)
    monkeypatch.setattr(p, '_read_at', read)
    assert uid_quiet(proc)['records'] == []


def test_uid_process_appearing_between_observations_blocks(proc, monkeypatch):
    original = p._uid_snapshot; count = 0
    def snapshot(*args):
        nonlocal count
        result = original(*args); count += 1
        if count == 1: put_uid(proc)
        return result
    monkeypatch.setattr(p, '_uid_snapshot', snapshot)
    with pytest.raises(p.ProcessesBusy) as failure: uid_quiet(proc)
    assert failure.value.receipt['snapshots'][0]['records'] == []
    assert len(failure.value.receipt['snapshots'][1]['records']) == 1


def test_uid_first_observation_match_cannot_be_erased_by_exit_or_reuse(proc, monkeypatch):
    put_uid(proc)
    original = p._uid_snapshot; count = 0
    def snapshot(*args):
        nonlocal count
        result = original(*args); count += 1
        if count == 1: put_uid(proc, start=2000, uids=(42,) * 4)
        return result
    monkeypatch.setattr(p, '_uid_snapshot', snapshot)
    with pytest.raises(p.ProcessesBusy) as failure: uid_quiet(proc)
    assert failure.value.receipt['records'][0]['start_ticks'] == 1000


def test_uid_pid_identity_or_boot_change_fails_closed(proc, monkeypatch):
    put_uid(proc, uids=(42,) * 4); original = p._read_at; count = 0
    def read(parent, name, *args):
        nonlocal count
        if name == 'stat':
            count += 1
            if count == 2: put_uid(proc, start=2000, uids=(42,) * 4)
        return original(parent, name, *args)
    monkeypatch.setattr(p, '_read_at', read)
    with pytest.raises(p.ProcessesError, match='identity changed'): uid_quiet(proc)
    monkeypatch.setattr(p, '_read_at', original)
    original_snapshot = p._uid_snapshot
    def snapshot(*args):
        result = original_snapshot(*args)
        (proc / 'sys/kernel/random/boot_id').write_text(OTHER_BOOT)
        return result
    monkeypatch.setattr(p, '_uid_snapshot', snapshot)
    with pytest.raises(p.ProcessesError, match='Boot changed'): uid_quiet(proc)


def test_uid_bounds_permission_and_clock_fail_closed(proc, monkeypatch):
    put_uid(proc, uids=(42,) * 4)
    for key, limit in [('MAX_PROCESSES', 0), ('MAX_STATUS_BYTES', 8), ('MAX_TOTAL_BYTES', 64)]:
        with monkeypatch.context() as change:
            change.setattr(p, key, limit)
            with pytest.raises(p.ProcessesError, match='bound'): uid_quiet(proc)
    with monkeypatch.context() as change:
        original = p._read_at
        def denied(parent, name, *args):
            if name == 'status': raise PermissionError(13, 'fixture denied')
            return original(parent, name, *args)
        change.setattr(p, '_read_at', denied)
        with pytest.raises(p.ProcessesError, match='safely'): uid_quiet(proc)
    times = iter([0, 5_000_000_001])
    with pytest.raises(p.ProcessesError, match='stale'):
        p.require_uid_quiet(2300, proc_root=proc, clock_ns=lambda: next(times))


@pytest.mark.parametrize('uid', [True, -1, 2**32 - 1, '2300', None])
def test_uid_invalid_argument_rejected_before_census(proc, uid):
    with pytest.raises(p.ProcessesError, match='Invalid UID'): uid_quiet(proc, uid)
