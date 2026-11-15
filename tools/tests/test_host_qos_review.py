"""Independent integration checks of QoS recovery barriers and scoped files."""
import copy
import os
from pathlib import Path
import shutil

import pytest

from test_host_qos_applicator import case, qos
from test_host_qos_adoption import adoption_case


def test_expired_admission_can_be_renewed_without_replacing_published_intent(adoption_case, monkeypatch):
    root, base, kernel, states, calls, run, admission_path, proc = adoption_case
    def crash(event, detail):
        if event == 'adoption-published': raise RuntimeError('after guarded publication')
    with pytest.raises(RuntimeError): run(fault=crash)
    path = base / admission_path.lstrip('/')
    original = qos.decode(path.read_bytes()); original_sha = qos.sha(path.read_bytes())
    next_time = original['expires_ns'] + 1
    monkeypatch.setattr(qos.adoption.time, 'time_ns', lambda: next_time)
    with pytest.raises(qos.QoSError, match='expired'): run()
    assert kernel.calls == calls == []
    renewed = copy.deepcopy(original)
    renewed.update(issued_ns=next_time, expires_ns=next_time + 300 * 10**9)
    evidence_path = base / renewed['ssh_fence_evidence']['path'].lstrip('/')
    evidence = qos.decode(evidence_path.read_bytes()); evidence['observed_ns'] = next_time
    evidence_path.write_bytes(qos.canonical(evidence))
    renewed['ssh_fence_evidence']['sha256'] = qos.sha(evidence_path.read_bytes())
    path.write_bytes(qos.canonical(renewed))
    assert run()['status'] == 'complete'
    journal = qos.read_control(root, qos.STATE + '/operations/adopt-' + 'c'*32 + '.json')
    assert journal['phase'] == 'committed'
    assert journal['admission_sha256s'] == [original_sha, qos.sha(path.read_bytes())]
    assert 'admission_sha256' not in journal['request']
    assert kernel.calls == ['nft']


def process(proc, pid, *, ppid=1, args=None, group=101, session=101):
    folder = proc / str(pid); folder.mkdir(exist_ok=True)
    fields = ['S', str(ppid), str(group), str(session)] + ['0'] * 15 + [str(pid*100)] + ['0']*4
    (folder/'stat').write_text(f'{pid} (controlled) ' + ' '.join(fields))
    (folder/'cmdline').write_bytes(b'\x00'.join(args or [b'python3', b'/usr/local/sbin/box-network-priority']) + b'\x00')
    (folder/'cgroup').write_text('0::/manual\n')
    return folder


def test_loaded_helper_after_guard_and_orphan_block_until_observed_drain(adoption_case):
    root, base, kernel, states, calls, run, admission_path, proc = adoption_case
    def crash(event, detail):
        if event == 'adoption-published': raise RuntimeError('guard published before census retry')
    with pytest.raises(RuntimeError): run(fault=crash)
    assert root.read_bytes('/usr/local/sbin/box-network-priority') == qos.adoption.GUARD
    parent = process(proc, 101)
    with pytest.raises(qos.processes.ProcessesBusy): run()
    assert calls == kernel.calls == []
    journal_path = qos.STATE + '/operations/adopt-' + 'c'*32 + '.json'
    assert [record['pid'] for record in qos.read_control(root, journal_path)['process_prior']] == [101]
    shutil.rmtree(parent)
    orphan = process(proc, 102, args=[b'bounded-client-without-helper-path'])
    with pytest.raises(qos.processes.ProcessesBusy): run()
    assert calls == kernel.calls == []
    assert {record['pid'] for record in qos.read_control(root, journal_path)['process_prior']} == {101, 102}
    shutil.rmtree(orphan)
    assert run()['status'] == 'complete'
    assert kernel.calls == ['nft']
    assert all(unit in qos.adoption.LEGACY for action, unit in calls if action in ('stop', 'disable'))


def test_account_directory_resume_after_chown_uses_exact_final_metadata(tmp_path):
    """Real target files; only unavailable second UID is an authority-number seam."""
    host = tmp_path/'host'; host.mkdir()
    home = host/'account'; home.mkdir()
    target_directory = home/'.config'; target_directory.mkdir(mode=0o700)
    with qos.engine.Root(host) as control, qos.engine.Root(home) as target:
        # The actual test UID owns target. Production host authority is root;
        # bypass no file/manifest check, and perform no privileged chown here.
        control.uid = 0 if target.uid != 0 else 1
        view = qos.adoption._account_engine(qos, target, control, '/account')
        expected = {'uid': target.uid, 'gid': target.gid, 'mode': 0o700}
        # _continue/_mkdir pass the directory manifest, including retention.
        view._finish_directory('/.config', {**expected, 'retention': 'retain'})
        assert target.directory('/.config') == expected
        target_directory.chmod(0o755)
        with pytest.raises(qos.engine.LifecycleError, match='protected'):
            view._finish_directory('/.config', {**expected, 'retention': 'retain'})
        assert target.directory('/.config')['mode'] == 0o755


def test_account_preflight_distinct_real_uids_keeps_host_authority_and_finite_scope(tmp_path):
    """Read-only host Root metadata plus an owned temporary home; no host writes."""
    home = tmp_path/'account'; home.mkdir(mode=0o700)
    (home/'.config/systemd/user').mkdir(parents=True, mode=0o700)
    with qos.engine.Root('/') as control, qos.engine.Root(home) as target:
        if control.uid == target.uid:
            pytest.skip('Distinct actual directory UIDs require the unprivileged test environment')
        # This container can expose its administrative root as UID 65534;
        # the meaningful condition is actual distinct inode ownership.
        assert control.uid != target.uid and target.uid == os.getuid()
        view = qos.adoption._account_engine(qos, target, control, '/fixture-account')
        assert view.uid == control.uid
        assert control._directory_uid('/.config') == control.uid
        assert view._directory_uid(qos.engine.STATE + '/host/operations') == control.uid
        assert view._directory_uid('/.config/systemd/user') == target.uid
        spec = {**target.directory('/.config'), 'retention': 'retain'}
        manifest = qos.engine.validate_manifest({'format': 1, 'owner': 'host', 'files': {},
                                                 'directories': {'/.config': spec}})
        qos.engine._preflight(view, manifest, manifest, 'a'*32)
        with pytest.raises(qos.engine.LifecycleError, match='administrative authority'):
            qos.engine._preflight(control, manifest, manifest, 'a'*32)
        for path in ('/outside', '/.config/systemd/elsewhere', '/.config/systemd/user/../escape'):
            with pytest.raises((qos.QoSError, qos.engine.LifecycleError)):
                view._directory_uid(path)
        (home/'.config/systemd/user/linked').symlink_to(tmp_path)
        with pytest.raises((OSError, qos.QoSError, qos.engine.LifecycleError)):
            view.snapshot('/.config/systemd/user/linked/escape')
        assert not (home/'var').exists()  # No lifecycle control state is routed into the home.


def test_account_preflight_partial_root_directory_requires_exact_persisted_intent(tmp_path, monkeypatch):
    """Physical roots; one metadata seam models a mkdir before its privileged chown."""
    home = tmp_path/'account'; home.mkdir(mode=0o700)
    (home/'.config').mkdir(mode=0o700)
    with qos.engine.Root('/') as control, qos.engine.Root(home) as target:
        if control.uid == target.uid:
            pytest.skip('Distinct actual directory UIDs require the unprivileged test environment')
        view = qos.adoption._account_engine(qos, target, control, '/fixture-account')
        desired = {'uid': target.uid, 'gid': target.gid, 'mode': 0o700, 'retention': 'retain'}
        before = qos.engine.validate_manifest({'format': 1, 'owner': 'host', 'files': {}, 'directories': {}})
        after = {**before, 'directories': {'/.config': desired}}
        original = view.directory
        monkeypatch.setattr(view, 'directory', lambda path: {'uid': control.uid, 'gid': control.gid, 'mode': 0o700}
                            if path == '/.config' else original(path))
        with pytest.raises(qos.engine.LifecycleError, match='directory differs'):
            qos.engine._preflight(view, before, after, 'b'*32)
        journal = {'directory_intent': '/.config', 'new_directories': ['/.config'], 'directories_done': []}
        qos.engine._preflight(view, before, after, 'b'*32, journal=journal)
        with pytest.raises(qos.engine.LifecycleError, match='directory differs'):
            qos.engine._preflight(view, before, after, 'b'*32,
                                  journal={**journal, 'directory_intent': '/.config/systemd'})


def test_registration_home_replacement_after_publication_is_rejected(case):
    root, base, policy, kernel, accounts, run = case
    run()
    def crash(event, detail):
        if event == 'dropins': raise RuntimeError('dropins published')
    args = {'consumer_id': 'whatsapp.new', 'account': 'wa-new', 'unit': 'whatsapp-new.service'}
    with pytest.raises(RuntimeError): run('register-consumer', 'b'*32, fault=crash, **args)
    home = base/'var/lib/whatsapp-new-waha'; retained = home.with_name(home.name+'-retained')
    before = home.stat().st_ino; home.rename(retained); home.mkdir()
    assert home.stat().st_ino != before
    calls = list(kernel.calls)
    with pytest.raises(qos.QoSError, match='Physical account root changed'):
        run('register-consumer', 'b'*32, **args)
    assert kernel.calls == calls and list(home.iterdir()) == []
    assert (retained/'.config/systemd/user/app.slice.d/60-whatsapp-priority.conf').is_file()


def test_registration_home_replaced_between_path_check_and_open_is_rejected_before_target_write(case, monkeypatch):
    root, base, policy, kernel, accounts, run = case
    run()
    def crash(event, detail):
        if event == 'prepared': raise RuntimeError('registration planned before effects')
    args = {'consumer_id': 'whatsapp.new', 'account': 'wa-new', 'unit': 'whatsapp-new.service'}
    with pytest.raises(RuntimeError): run('register-consumer', 'b'*32, fault=crash, **args)
    home = base/'var/lib/whatsapp-new-waha'; retained = home.with_name(home.name+'-retained')
    original_root = qos.engine.Root
    swapped = False
    class ConcurrentRoot(original_root):
        def __init__(self, selected):
            nonlocal swapped
            if Path(selected) == home and not swapped:
                home.rename(retained); home.mkdir(); swapped = True
            super().__init__(selected)
    monkeypatch.setattr(qos.engine, 'Root', ConcurrentRoot)
    calls = list(kernel.calls)
    with pytest.raises(qos.QoSError, match='Opened account root differs'):
        run('register-consumer', 'b'*32, **args)
    assert swapped and list(home.iterdir()) == [] and list(retained.iterdir()) == []
    assert kernel.calls == calls
