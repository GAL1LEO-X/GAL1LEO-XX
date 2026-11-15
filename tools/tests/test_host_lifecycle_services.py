import fcntl
import os
from pathlib import Path
import subprocess
import sys
import json
import time

import pytest

from host.lifecycle.filesystem import LifecycleBusy, LifecycleError, Root
from host.lifecycle.services import (BOX_LOCKS, WA_LOCKS, SERVICE_LEASE, WA_RECOVERY, RECOVERY_PROPERTIES,
                                     RECOVERY_ENTRYPOINT, RECOVERY_EMPTY_PROPERTIES, RecoveryServices,
                                     recovery_empty_argv, recovery_read_runner,
                                     _bounded, raw_locks, service_argv, service_lease, recovery_show_argv)


@pytest.fixture
def tree(tmp_path):
    tmp_path.chmod(0o700)
    for logical in (*WA_LOCKS, *BOX_LOCKS):
        path = tmp_path / logical.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in path.parents:
            if parent == tmp_path:
                break
            parent.chmod(0o700)
    with Root(tmp_path) as root:
        yield root


def test_other_application_lock_does_not_block(tree):
    with raw_locks(tree, owner='box'):
        with raw_locks(tree, owner='whatsapp') as descriptors:
            assert len(descriptors) == 2


def test_busy_lock_returns_immediately_and_releases_first_lock(tree):
    tenant = tree.base / WA_LOCKS[1].lstrip('/')
    with tenant.open('a') as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(LifecycleBusy):
            with raw_locks(tree, owner='whatsapp'):
                pytest.fail('Tenant lock bypassed')
        publication = tree.base / WA_LOCKS[0].lstrip('/')
        with publication.open('a') as available:
            fcntl.flock(available, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with raw_locks(tree, owner='whatsapp'):
        pass


def test_lock_inode_and_content_survive_every_acquisition(tree):
    path = tree.base / WA_LOCKS[0].lstrip('/')
    path.write_bytes(b'existing diagnostic marker')
    path.chmod(0o600)
    before = path.stat().st_ino
    with raw_locks(tree, owner='whatsapp'):
        pass
    assert path.stat().st_ino == before
    assert path.read_bytes() == b'existing diagnostic marker'


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'writable'])
def test_untrusted_lock_refused(tree, kind):
    path = tree.base / WA_LOCKS[0].lstrip('/')
    target = tree.base / 'target'
    target.write_bytes(b'preserve')
    target.chmod(0o600)
    if kind == 'symlink':
        path.symlink_to(target)
    elif kind == 'hardlink':
        os.link(target, path)
    else:
        path.write_bytes(b'preserve')
        path.chmod(0o666)
    with pytest.raises((LifecycleError, OSError)):
        with raw_locks(tree, owner='whatsapp'):
            pytest.fail('Unsafe lock accepted')
    assert target.read_bytes() == b'preserve'


def test_timer_sequence_is_finite_and_preserves_running_service(tree, installed_recovery):
    calls = []
    def runner(operation, *, pass_fds):
        assert len(pass_fds) == 1
        calls.append(operation)
    def reader(argv, **kwargs):
        values = recovery_properties(argv[-1])
        if 'stop-wa-recovery' in calls and argv[-1].endswith('.timer'):
            values.update(ActiveState='inactive', SubState='dead', UnitFileState='disabled')
        return ('\n'.join(key+'='+value for key, value in values.items())+'\n').encode()
    controller = RecoveryServices(tree, runner=runner, reader=reader)
    controller.activate(installed_recovery)
    controller.close(installed_recovery)
    argv = [service_argv(operation) for operation in calls]
    assert len(argv) == 5
    assert not any('develative-release-recovery.timer' in item for item in argv)
    assert not any('develative-whatsapp-recovery.service' in item for item in argv)
    assert argv[-1] == ['/usr/bin/systemctl', '--no-block', 'stop', '--',
                       'develative-whatsapp-recovery.timer']
    with pytest.raises(LifecycleError):
        service_argv('stop-box')
    with pytest.raises(LifecycleError):
        RecoveryServices(tree)


def test_bounded_runner_does_not_reveal_child_stderr():
    assert _bounded([sys.executable, '-c', 'print("ok")']).strip() == 'ok'
    with pytest.raises(LifecycleError) as caught:
        _bounded([sys.executable, '-c', 'import sys;sys.stderr.write("private");sys.exit(2)'])
    assert 'private' not in str(caught.value)
    with pytest.raises(LifecycleError, match='bound'):
        _bounded([sys.executable, '-c', 'print("x"*1000000)'], max_bytes=1024)
    with pytest.raises(LifecycleError, match='timed out'):
        _bounded([sys.executable, '-c', 'import time;time.sleep(2)'], timeout=0.05)


def test_existing_lease_can_be_reused_and_survives_controller_context(tree, installed_recovery):
    calls = []
    controller = RecoveryServices(tree, runner=lambda operation, **kwargs: calls.append(operation),
        reader=lambda argv, **kwargs: ('\n'.join(key+'='+value for key, value in recovery_properties(argv[-1]).items())+'\n').encode())
    with service_lease(tree) as lease:
        with raw_locks(tree, owner='whatsapp'):
            controller.activate(installed_recovery, lease_fds=lease)
        with pytest.raises(LifecycleBusy):
            with service_lease(tree):
                pytest.fail('Lease was released by nested control operation')
        with raw_locks(tree, owner='box'):
            pass
    assert calls == ['reload-definitions', 'enable-wa-recovery', 'start-wa-recovery']


def test_new_lock_fsync_failure_does_not_leak_descriptor(tree, monkeypatch):
    import host.lifecycle.services as services
    opened = []
    original = os.open
    def tracked_open(path, flags, *args, **kwargs):
        fd = original(path, flags, *args, **kwargs)
        if flags & os.O_CREAT: opened.append(fd)
        return fd
    monkeypatch.setattr(services.os, 'open', tracked_open)
    monkeypatch.setattr(services.os, 'fsync', lambda fd: (_ for _ in ()).throw(OSError('injected fsync error')))
    with pytest.raises((OSError, LifecycleError)):
        with service_lease(tree): pass
    assert len(opened) == 1
    with pytest.raises(OSError): os.fstat(opened[0])


def test_mutating_client_holds_service_lease_after_controller_exits(tree, tmp_path):
    # Parent exits after its real child confirms the inherited descriptor. Only
    # synthetic Python processes and temporary files are involved, never systemctl.
    from host.installation import IDENTITY, Installation, identity_bytes
    marker = tree.base / IDENTITY.relative_to('/')
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_bytes(identity_bytes(Installation.legacy()))
    marker.chmod(0o600)
    ready, release, done = (tmp_path/name for name in ('child-ready', 'child-release', 'child-done'))
    child = '''import os, pathlib, sys, time
fd, ready, release, done = int(sys.argv[1]), *map(pathlib.Path, sys.argv[2:])
os.fstat(fd)
ready.write_text(str(os.getpid()))
deadline=time.monotonic()+5
while not release.exists() and time.monotonic()<deadline: time.sleep(0.01)
os.close(fd)
done.write_text('finished')
'''
    parent = '''import os, pathlib, sys, threading, time
from host import installation
installation.select(installation.read_installation(root=pathlib.Path(sys.argv[1]),trusted_uid=os.getuid()))
from host.lifecycle.filesystem import Root
from host.lifecycle.services import service_lease, _bounded
root_path, ready, release, done, child = sys.argv[1:]
def leave_when_child_ready():
    deadline=time.monotonic()+4
    while not pathlib.Path(ready).exists() and time.monotonic()<deadline: time.sleep(0.01)
    os._exit(73)
with Root(root_path) as root, service_lease(root) as lease:
    threading.Thread(target=leave_when_child_ready,daemon=True).start()
    _bounded([sys.executable,'-c',child,str(lease[0]),ready,release,done],pass_fds=lease)
'''
    proc = subprocess.Popen([sys.executable, '-c', parent, str(tree.base), str(ready), str(release), str(done), child],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert proc.wait(timeout=5) == 73
        assert ready.exists()
        with pytest.raises(LifecycleBusy):
            with service_lease(tree): pytest.fail('Live child lease lost after controller death')
        # BOX remains independently operable while this WA client drains.
        with raw_locks(tree, owner='box'): pass
        release.write_text('finish')
        deadline = time.monotonic()+5
        while not done.exists() and time.monotonic()<deadline: time.sleep(0.01)
        assert done.exists()
        with service_lease(tree): pass
    finally:
        release.write_text('finish')
        if proc.poll() is None: proc.kill(); proc.wait()


def recovery_properties(unit):
    values = {key: '' for key in RECOVERY_PROPERTIES[unit]}
    values.update(Id=unit, LoadState='loaded', NeedDaemonReload='no',
                  FragmentPath='/etc/systemd/system/'+unit, Job='0', ActiveState='inactive', SubState='dead')
    if unit.endswith('.timer'):
        values.update(ActiveState='active', UnitFileState='enabled', Unit=WA_RECOVERY[0],
            TimersMonotonic='{ OnBootUSec=45s; next_elapse=1; } { OnUnitInactiveUSec=1min; next_elapse=2; }')
    else:
        values.update(MainPID='0', ControlPID='0', Type='oneshot', User='root', KillMode='control-group', RemainAfterExit='no',
            Restart='no', TimeoutStartUSec='10min',
            ExecStart='{ path=/usr/bin/python3; argv[]=/usr/bin/python3 -I -B '+RECOVERY_ENTRYPOINT+' recovery; ignore_errors=no; }')
    return values


@pytest.fixture
def installed_recovery(tree):
    manifest = {'format': 1, 'owner': 'whatsapp', 'files': {}, 'directories': {}}
    deploy = Path(__file__).resolve().parents[2]/'plugins/whatsapp/deploy'
    for unit in WA_RECOVERY:
        logical = '/etc/systemd/system/'+unit
        path = tree.base/logical.lstrip('/'); path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((deploy/unit).read_bytes()); path.chmod(0o600)
        manifest['files'][logical] = {**tree.snapshot(logical), 'retention': 'managed'}
    return manifest


def test_effective_recovery_verification_reads_only_exact_units_and_source_templates(tree, installed_recovery):
    calls = []
    def reader(argv, **kwargs):
        unit = argv[-1]
        assert argv == recovery_show_argv(unit)
        calls.append(unit)
        return ('\n'.join(key+'='+value for key, value in recovery_properties(unit).items())+'\n').encode()
    controller = RecoveryServices(tree, runner=lambda *a, **k: pytest.fail('must only read'), reader=reader)
    assert controller.verify(installed_recovery)['dedicated_recovery_verified']
    assert calls == list(WA_RECOVERY) * 2


@pytest.mark.parametrize('enabled', [True, False])
def test_omitted_structured_empty_properties_require_typed_proof(tree, installed_recovery, enabled):
    calls = []
    def reader(argv, **kwargs):
        calls.append(argv)
        assert kwargs == {'timeout': 5.0, 'max_bytes': 256 * 1024}
        if argv[0] == '/usr/bin/busctl':
            field = argv[-1]
            unit = WA_RECOVERY[1] if field == 'TimersCalendar' else WA_RECOVERY[0]
            assert argv == recovery_empty_argv(unit, field)
            _, signature, empty = RECOVERY_EMPTY_PROPERTIES[field]
            return json.dumps({'type': signature, 'data': empty}).encode()
        unit = argv[-1]
        values = recovery_properties(unit)
        # systemd 257.13: Job/DropInPaths/RestartForceExitStatus are explicit,
        # auxiliary Exec* and TimersCalendar are absent; timer bases repeat.
        values['Job'] = ''
        if unit == WA_RECOVERY[1]:
            values['TimersMonotonic'] = ('{ OnUnitInactiveUSec=1min; next_elapse=2; }\n'
                'TimersMonotonic={ OnBootUSec=45s; next_elapse=1; }')
        if not enabled and unit == WA_RECOVERY[1]:
            values.update(ActiveState='inactive', SubState='dead', UnitFileState='disabled')
        return '\n'.join(key+'='+value for key, value in values.items()
                         if key not in RECOVERY_EMPTY_PROPERTIES).encode()
    controller = RecoveryServices(tree, runner=lambda *a, **k: pytest.fail('must only read'), reader=reader)
    assert controller.verify(installed_recovery, enabled=enabled)['enabled'] is enabled
    assert len(calls) == 2 * (2 + len(RECOVERY_EMPTY_PROPERTIES))


@pytest.mark.parametrize('field', list(RECOVERY_EMPTY_PROPERTIES))
@pytest.mark.parametrize('damage', ['nonempty', 'wrong-type', 'missing-data', 'duplicate', 'invalid-json', 'oversize', 'unavailable'])
def test_omission_is_not_evidence_of_an_empty_value(tree, installed_recovery, field, damage):
    def reader(argv, **kwargs):
        if argv[0] == '/usr/bin/systemctl':
            values = recovery_properties(argv[-1]); values.pop(field, None)
            return '\n'.join(key+'='+value for key, value in values.items()).encode()
        assert argv[-1] == field
        _, signature, empty = RECOVERY_EMPTY_PROPERTIES[field]
        value = {'type': signature, 'data': empty}
        if damage == 'unavailable': raise LifecycleError('Synthetic unavailable D-Bus property')
        if damage == 'oversize': return b' ' * (256 * 1024 + 1)
        if damage == 'invalid-json': return b'not json'
        if damage == 'duplicate': return b'{"type":"wrong","type":"a(sst)","data":[]}'
        if damage == 'nonempty': value['data'] = [['unexpected']]
        if damage == 'wrong-type': value['type'] = 'as'
        if damage == 'missing-data': del value['data']
        return json.dumps(value).encode()
    calls = []
    controller = RecoveryServices(tree, runner=lambda *a, **k: calls.append(a), reader=reader)
    with pytest.raises(LifecycleError): controller.activate(installed_recovery)
    assert not calls


@pytest.mark.parametrize('unit', WA_RECOVERY)
def test_required_recovery_identity_cannot_be_defaulted(tree, installed_recovery, unit):
    for field in set(RECOVERY_PROPERTIES[unit]) - set(RECOVERY_EMPTY_PROPERTIES):
        def reader(argv, **kwargs):
            assert argv[0] == '/usr/bin/systemctl'
            values = recovery_properties(argv[-1])
            if argv[-1] == unit: del values[field]
            return '\n'.join(key+'='+value for key, value in values.items()).encode()
        controller = RecoveryServices(tree, runner=lambda *a, **k: pytest.fail('must only read'), reader=reader)
        with pytest.raises(LifecycleError, match='Incomplete dedicated recovery identity'):
            controller.verify(installed_recovery)


def test_recovery_typed_reader_is_finite_and_keeps_bounds(monkeypatch):
    import host.lifecycle.services as services
    calls = []
    monkeypatch.setattr(services, '_bounded', lambda argv, **kw: calls.append((argv, kw)) or 'response')
    for unit in WA_RECOVERY:
        for field in RECOVERY_PROPERTIES[unit]:
            if field in RECOVERY_EMPTY_PROPERTIES:
                argv = recovery_empty_argv(unit, field)
                assert recovery_read_runner(argv) == b'response'
                assert calls[-1] == (argv, {'timeout': 5.0, 'max_bytes': 256 * 1024})
    valid = recovery_empty_argv(WA_RECOVERY[0], 'ExecStartPre')
    for index, replacement in [(0, '/bin/sh'), (1, '--user'), (3, 'call'),
                               (4, 'org.example'), (5, '/foreign'), (6, 'org.example'), (7, 'ExecStart')]:
        argv = valid.copy(); argv[index] = replacement
        with pytest.raises(LifecycleError): recovery_read_runner(argv)
    for unit, field in [('box.service', 'ExecStartPre'), (WA_RECOVERY[0], 'TimersCalendar'),
                        (WA_RECOVERY[1], 'ExecStartPre'), (WA_RECOVERY[0], 'Id')]:
        with pytest.raises(LifecycleError): recovery_empty_argv(unit, field)


@pytest.mark.parametrize('unit_index,field,value', [
    (1, 'ActiveState', 'inactive'), (1, 'UnitFileState', 'disabled'), (1, 'Unit', 'box.service'),
    (1, 'TimersMonotonic', '{ OnBootUSec=45s; next=1; }'), (1, 'TimersCalendar', '*-*-* 00:00:00'),
    (0, 'Type', 'simple'), (0, 'User', 'www-data'), (0, 'KillMode', 'process'),
    (0, 'Restart', 'always'), (0, 'TimeoutStartUSec', 'infinity'),
    (0, 'ExecStartPost', '{ path=/wrong; argv[]=/wrong; }'),
    (0, 'ExecStart', '{ path=/usr/bin/python3; argv[]=/usr/bin/python3 /wrong.py recovery; }'),
    (0, 'DropInPaths', '/etc/systemd/system/override.conf'), (0, 'NeedDaemonReload', 'yes')])
def test_effective_runtime_drift_blocks_even_when_installed_hashes_match(tree, installed_recovery, unit_index, field, value):
    def reader(argv, **kwargs):
        unit = argv[-1]; properties = recovery_properties(unit)
        if unit == WA_RECOVERY[unit_index]: properties[field] = value
        return ('\n'.join(key+'='+item for key, item in properties.items())+'\n').encode()
    controller = RecoveryServices(tree, runner=lambda *a, **k: pytest.fail('must only read'), reader=reader)
    with pytest.raises(LifecycleError): controller.verify(installed_recovery)


@pytest.mark.parametrize('operation', ['activate', 'close'])
@pytest.mark.parametrize('queued_when', ['before', 'after'])
def test_manager_job_is_not_mistaken_for_completed_client(tree, installed_recovery, operation, queued_when):
    calls = []
    def reader(argv, **kwargs):
        unit = argv[-1]
        values = recovery_properties(unit)
        if calls and operation == 'close' and unit == WA_RECOVERY[1]:
            values.update(ActiveState='inactive', SubState='dead', UnitFileState='disabled')
        if unit == WA_RECOVERY[1] and ((queued_when == 'before' and not calls) or (queued_when == 'after' and calls)):
            values['Job'] = '55 /org/freedesktop/systemd1/job/55'
        return ('\n'.join(key+'='+value for key, value in values.items())+'\n').encode()
    controller = RecoveryServices(tree, runner=lambda action, **k: calls.append(action), reader=reader)
    with pytest.raises(LifecycleBusy, match='manager job'):
        getattr(controller, operation)(installed_recovery)
    assert bool(calls) == (queued_when == 'after')
    assert all('whatsapp-recovery.service' not in service_argv(item) for item in calls)


@pytest.mark.parametrize('field,value', [('ActiveState', 'active'), ('UnitFileState', 'enabled'), ('SubState', 'waiting')])
def test_close_requires_effective_disabled_inactive_timer(tree, installed_recovery, field, value):
    calls = []
    def reader(argv, **kwargs):
        unit = argv[-1]; properties = recovery_properties(unit)
        if calls and unit.endswith('.timer'):
            properties.update(ActiveState='inactive', SubState='dead', UnitFileState='disabled')
            properties[field] = value
        return ('\n'.join(key+'='+item for key, item in properties.items())+'\n').encode()
    controller = RecoveryServices(tree, runner=lambda action, **k: calls.append(action), reader=reader)
    with pytest.raises(LifecycleError, match='completed disable and stop'):
        controller.close(installed_recovery)
    assert calls == ['disable-wa-recovery', 'stop-wa-recovery']


def test_close_reports_running_service_without_signalling_it(tree, installed_recovery):
    calls = []
    def reader(argv, **kwargs):
        unit = argv[-1]; properties = recovery_properties(unit)
        if unit == WA_RECOVERY[0]:
            properties.update(ActiveState='active', SubState='running', MainPID='321')
        elif calls:
            properties.update(ActiveState='inactive', SubState='dead', UnitFileState='disabled')
        return ('\n'.join(key+'='+item for key, item in properties.items())+'\n').encode()
    controller = RecoveryServices(tree, runner=lambda action, **k: calls.append(action), reader=reader)
    result = controller.close(installed_recovery)
    assert result['enabled'] is False and result['main_pid'] == 321 and result['service_state'] == 'active'
    assert calls == ['disable-wa-recovery', 'stop-wa-recovery']


def test_mutating_runner_launches_protected_supervisor_with_finite_operation(monkeypatch):
    import host.lifecycle.services as services
    from types import SimpleNamespace
    calls = []
    # Only the launch wiring is under test; no privileged command is executed.
    actual_lstat = Path.lstat
    monkeypatch.setattr(services.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(Path, 'lstat', lambda path: SimpleNamespace(
        st_uid=0, st_mode=actual_lstat(path).st_mode & ~0o022))
    monkeypatch.setattr(services, '_bounded', lambda argv, **kwargs: calls.append((argv, kwargs)))
    services.service_runner('stop-wa-recovery', pass_fds=(99,))
    argv, limits = calls[0]
    assert argv[1:3] == ['-I', '-B']
    assert Path(argv[3]) == Path(services.__file__).with_name('service_client.py')
    assert argv[4:] == ['whatsapp', 'stop-wa-recovery', '99']
    assert limits == {'pass_fds': (99,), 'timeout': 30, 'preserve_child': True}


def test_supervisor_cli_command_contract_is_finite_and_owner_scoped(tmp_path):
    from host.lifecycle import service_client
    from host.installation import IDENTITY, Installation, identity_bytes
    marker = tmp_path / IDENTITY.relative_to('/')
    marker.parent.mkdir(parents=True)
    marker.write_bytes(identity_bytes(Installation.legacy()))
    marker.chmod(0o600)
    import hashlib
    box_profile = b'{"format":"box-installation-legacy-v1"}\n'
    box_marker = marker.with_name('box-installation-identity.json')
    box_marker.write_text(json.dumps({'format': 'box-installation-identity-v1', 'mode': 'legacy',
        'installation_sha256': hashlib.sha256(box_profile).hexdigest()}) + '\n')
    box_marker.chmod(0o600)
    for operation in ('reload-definitions', 'enable-wa-recovery', 'start-wa-recovery',
                      'disable-wa-recovery', 'stop-wa-recovery'):
        assert service_client.command('whatsapp', operation, root=tmp_path,
            authority=os.getuid()) == service_argv(operation)
    for owner, operation in (('whatsapp', 'stop-box-recovery'), ('box', 'stop-wa-recovery'),
                             ('unknown', 'reload-definitions'), ('whatsapp', 'shell')):
        with pytest.raises(service_client.SupervisionError):
            service_client.command(owner, operation, root=tmp_path, authority=os.getuid())
