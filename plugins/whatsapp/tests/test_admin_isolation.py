"""Real admission paths with synthetic files and no network or service actions."""
import importlib.util
import io
import json
from pathlib import Path
import signal
import sys
from types import SimpleNamespace

import pytest

from test_release_admin import SCRIPTS, admin, declare, entry, installation


HELPERS = ('github_release_common', 'release_build', 'release_database',
           'release_transaction', 'backup_validation', 'release_backup',
           'github_release')


@pytest.fixture
def receiver_installation(installation, monkeypatch):
    root, owner = installation
    # The entire import closure is copied from the candidate, not reconstructed.
    for name in HELPERS:
        (root/(name+'.py')).write_bytes((SCRIPTS/(name+'.py')).read_bytes())
    declare(root, owner)
    monkeypatch.setattr(sys, 'dont_write_bytecode', True)
    monkeypatch.setattr(sys, 'path', [str(root), *sys.path])
    for name in HELPERS:
        monkeypatch.delitem(sys.modules, name, raising=False)
    modules = {}
    for name in HELPERS:
        spec = importlib.util.spec_from_file_location(name, root/(name+'.py'))
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, module)
        spec.loader.exec_module(module)
        modules[name] = module
    # Preserve the process running pytest; production signal/umask changes are
    # unrelated to admission, all path/hash/owner/lock checks remain real.
    monkeypatch.setattr(signal, 'signal', lambda *args: None)
    monkeypatch.setattr(signal, 'alarm', lambda *args: None)
    monkeypatch.setattr(modules['github_release_common'].os, 'umask', lambda *args: None)
    monkeypatch.setattr(modules['github_release_common'].os, 'geteuid', lambda: 0)
    monkeypatch.setattr(entry, '_admin_module', lambda: admin)
    monkeypatch.setattr(sys, 'argv', ['synthetic-receiver'])
    return root, owner, modules


class UntouchedInput:
    def __init__(self):
        self.buffer = self
        self.reads = 0

    def readline(self, *_):
        self.reads += 1
        pytest.fail('request input was read before administrative admission')


@pytest.mark.parametrize('change', ['missing', 'transitioning', 'retiring', 'retired', 'epoch'])
def test_loaded_receiver_rechecks_owner_before_request_or_external_io(
        receiver_installation, monkeypatch, capsys, change):
    root, owner, modules = receiver_installation
    common = modules['github_release_common']
    admin.pin_generation(admin.load_generation())
    if change == 'missing':
        owner.unlink()
    else:
        declare(root, owner, state=change if change != 'epoch' else 'dedicated',
                epoch='b'*32 if change == 'epoch' else 'a'*32)
    incoming = UntouchedInput()
    monkeypatch.setattr(sys, 'stdin', incoming)
    monkeypatch.setattr(common, 'GitHub', lambda *_: pytest.fail('network client created'))
    monkeypatch.setattr(common, 'run', lambda *_: pytest.fail('external command started'))
    with pytest.raises(SystemExit) as stopped:
        common.main('whatsapp', lambda *_: pytest.fail('receiver handler entered'))
    assert stopped.value.code == 1
    assert json.loads(capsys.readouterr().out)['status'] == 'blocked'
    assert incoming.reads == 0 and not admin.PUBLICATION_LOCK.exists()


def test_real_entry_and_receiver_accept_current_generation_before_request_validation(
        receiver_installation, monkeypatch, capsys):
    root, owner, modules = receiver_installation
    incoming = SimpleNamespace(buffer=io.BytesIO(b'not-json\n'))
    monkeypatch.setattr(sys, 'stdin', incoming)
    monkeypatch.setattr(modules['github_release_common'], 'GitHub',
                        lambda *_: pytest.fail('invalid request reached network'))
    before = owner.read_bytes()
    with pytest.raises(SystemExit) as stopped:
        entry.main(['receiver'])
    assert stopped.value.code == 1
    assert json.loads(capsys.readouterr().out) == {'status': 'blocked', 'reason': 'Invalid release request'}
    assert admin._PINNED.path == root and owner.read_bytes() == before
    assert not admin.PUBLICATION_LOCK.exists()


def test_real_entry_closed_owner_never_executes_receiver(receiver_installation, monkeypatch):
    root, owner, _ = receiver_installation
    declare(root, owner, state='transitioning')
    incoming = UntouchedInput()
    monkeypatch.setattr(sys, 'stdin', incoming)
    with pytest.raises(admin.AdminError):
        entry.main(['receiver'])
    assert incoming.reads == 0 and not admin.PUBLICATION_LOCK.exists()


@pytest.mark.parametrize('change', ['missing', 'transitioning', 'retiring', 'retired', 'epoch'])
def test_direct_receiver_checks_owner_before_request_or_restore_registry(
        receiver_installation, monkeypatch, capsys, change):
    root, owner, modules = receiver_installation
    admin.pin_generation(admin.load_generation())
    if change == 'missing':
        owner.unlink()
    else:
        declare(root, owner, state=change if change != 'epoch' else 'dedicated',
                epoch='b'*32 if change == 'epoch' else 'a'*32)
    incoming = UntouchedInput()
    monkeypatch.setattr(sys, 'stdin', incoming)
    monkeypatch.setattr(modules['github_release'], 'instances',
                        lambda *_: pytest.fail('restore registry read before owner admission'))
    with pytest.raises(SystemExit) as stopped:
        modules['github_release'].receive()
    assert stopped.value.code == 1
    assert json.loads(capsys.readouterr().out)['status'] == 'blocked'
    assert incoming.reads == 0 and not admin.PUBLICATION_LOCK.exists()


@pytest.mark.parametrize('raw', [b'not-json\n', b'[]\n', b'', b'x'*16385,
    b'{}\n', b'{"tag":"whatsapp/v0.8.0","dry_run":"true"}\n',
    b'{"tag":"whatsapp/v0.8.0","dry_run":true,"unknown":1}\n',
    b'{"tag":"whatsapp/v0.8.0","dry_run":true,"release_id":true}\n'])
def test_direct_receiver_rejects_invalid_request_before_restore_registry(
        receiver_installation, monkeypatch, capsys, raw):
    _, _, modules = receiver_installation
    monkeypatch.setattr(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(raw)))
    monkeypatch.setattr(modules['github_release'], 'instances',
                        lambda *_: pytest.fail('restore registry read before request validation'))
    with pytest.raises(SystemExit) as stopped:
        modules['github_release'].receive()
    assert stopped.value.code == 1
    assert json.loads(capsys.readouterr().out)['status'] == 'blocked'
    assert not admin.PUBLICATION_LOCK.exists()


@pytest.mark.parametrize('during_admission', [False, True])
def test_direct_receiver_restore_gate_precedes_configuration_network_and_work(
        receiver_installation, monkeypatch, capsys, tmp_path, during_admission):
    from contextlib import contextmanager
    _, _, modules = receiver_installation
    release, common = modules['github_release'], modules['github_release_common']
    configuration = tmp_path/'tenant-config'
    configuration.mkdir()
    marker = configuration/'restore-maintenance.json'
    request = b'{"tag":"whatsapp/v0.8.0","dry_run":true}\n'
    monkeypatch.setattr(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(request)))
    monkeypatch.setattr(release, 'instances', lambda *_: [{'config': configuration/'config.toml'}])
    monkeypatch.setattr(common, 'checkout', lambda *_: pytest.fail('checkout before restore gate'))
    if during_admission:
        settings = tmp_path/'receiver-config'
        settings.mkdir()
        (settings/'whatsapp.json').write_text('{"enabled":true}')
        monkeypatch.setattr(common, 'installation_path', lambda path: str(settings))
        monkeypatch.setattr(common, 'GitHub', lambda *_: object())
        monkeypatch.setattr(common, 'verify_request', lambda *_: {})
        original_lock = admin.publication_lock
        @contextmanager
        def publication_lock(*args, **kwargs):
            with original_lock(*args, **kwargs) as generation:
                marker.write_text('{}')
                yield generation
        monkeypatch.setattr(admin, 'publication_lock', publication_lock)
    else:
        marker.write_text('{}')
        monkeypatch.setattr(common, 'installation_path',
                            lambda *_: pytest.fail('configuration before restore gate'))
        monkeypatch.setattr(common, 'GitHub', lambda *_: pytest.fail('network before restore gate'))
    with pytest.raises(SystemExit) as stopped:
        release.receive()
    assert stopped.value.code == 1
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'blocked' and 'Restore maintenance' in result['reason']
    assert not (admin.STATE/'work').exists()


class NoRegistryAccess:
    def __truediv__(self, _):
        pytest.fail('tenant registry was accessed before verifying the worker pin')


class RegistryBoundaryReached(RuntimeError):
    pass


@pytest.mark.parametrize('worker', ['inherited', 'managed'])
@pytest.mark.parametrize('pin_kind', ['missing', 'stale-epoch', 'stale-path', 'stale-manifest'])
def test_backup_worker_pin_rejected_before_registry_or_service_actions(
        receiver_installation, monkeypatch, worker, pin_kind):
    root, _, modules = receiver_installation
    spec = importlib.util.spec_from_file_location('isolated_backup_runtime', SCRIPTS/'backup_runtime.py')
    backup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backup)
    generation = admin.load_generation()
    # Bootstrap loading is separately exercised in cold processes. Here the
    # actual CLI pin comparison consumes an honestly attested real generation.
    monkeypatch.setattr(backup, 'recovery_helpers', lambda: (
        modules['release_backup'], modules['github_release'], admin, generation))
    monkeypatch.setattr(backup, 'ROOT', NoRegistryAccess())
    monkeypatch.setattr(backup, 'backup', lambda *_args, **_kw: pytest.fail('backup started'))
    monkeypatch.setattr(backup, 'subprocess', SimpleNamespace(
        run=lambda *_args, **_kw: pytest.fail('external service command started')))
    arguments = ['backup_runtime.py', '--all']
    arguments += ['--lock-fd', '99999', '--recovery-id', 'f'*32] if worker == 'inherited' else ['--managed-child']
    if pin_kind != 'missing':
        pin = {'epoch': generation.epoch, 'path': str(root), 'manifest': generation.manifest_sha256}
        key = {'stale-epoch': 'epoch', 'stale-path': 'path', 'stale-manifest': 'manifest'}[pin_kind]
        pin[key] = {'epoch': 'b'*32, 'path': str(root.parent/'old'), 'manifest': '0'*64}[key]
        arguments += ['--admin-pin', json.dumps(pin)]
    monkeypatch.setattr(sys, 'argv', arguments)
    with pytest.raises(RuntimeError, match='generation'):
        backup.main()
    assert not admin.PUBLICATION_LOCK.exists()


@pytest.mark.parametrize('worker', ['inherited', 'managed'])
def test_current_worker_pin_reaches_registry_boundary(receiver_installation, monkeypatch, worker):
    root, _, modules = receiver_installation
    spec = importlib.util.spec_from_file_location('isolated_backup_runtime', SCRIPTS/'backup_runtime.py')
    backup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backup)
    generation = admin.load_generation()
    monkeypatch.setattr(backup, 'recovery_helpers', lambda: (
        modules['release_backup'], modules['github_release'], admin, generation))
    class Boundary:
        def __truediv__(self, name):
            assert name == 'private/tenants.json'
            raise RegistryBoundaryReached()
    monkeypatch.setattr(backup, 'ROOT', Boundary())
    pin = {'epoch': generation.epoch, 'path': str(root), 'manifest': generation.manifest_sha256}
    arguments = ['backup_runtime.py', '--all', '--admin-pin', json.dumps(pin)]
    arguments += ['--lock-fd', '99999', '--recovery-id', 'f'*32] if worker == 'inherited' else ['--managed-child']
    monkeypatch.setattr(sys, 'argv', arguments)
    with pytest.raises(RegistryBoundaryReached):
        backup.main()


def test_backup_receiver_propagates_pin_and_tenant_fd_to_recovery(
        receiver_installation, monkeypatch):
    root, _, modules = receiver_installation
    release = modules['github_release']
    recovery = modules['release_backup']
    generation = admin.load_generation()
    plan = {'id': 'f'*32, 'servicesRestored': True, 'copies': {'synthetic': {'complete': True}}}
    seen = []
    monkeypatch.setattr(recovery, 'verify_prerequisites', lambda _root: None)
    monkeypatch.setattr(release, 'backup_components', lambda _rows: ['synthetic-service'])
    monkeypatch.setattr(recovery, 'begin', lambda *_: plan)
    def run_backup(command, _root, lock_fd):
        pin = json.loads(command[command.index('--admin-pin')+1])
        assert pin == {'epoch': generation.epoch, 'path': str(root), 'manifest': generation.manifest_sha256}
        assert lock_fd == 71 and command[command.index('--lock-fd')+1] == '71'
        seen.append('backup')
        return 'synthetic-output'
    monkeypatch.setattr(release, 'run_backup_process', run_backup)
    def verify_backups(output, selected, *, auth_modes):
        assert output == 'synthetic-output' and selected == ['synthetic']
        assert auth_modes == {'synthetic': 'managed-authelia'}
        return ['synthetic-backup']
    monkeypatch.setattr(release, 'verify_backups', verify_backups)
    def restore(parts, version, *, lock_fd):
        assert (parts, version, lock_fd) == (['synthetic-service'], '0.4.9', 71)
        seen.append('restore')
        return []
    monkeypatch.setattr(release, 'restore_backup_components', restore)
    def recover(_root, _rows, callback):
        assert callback(['synthetic-service'], '0.4.9') == []
        return plan
    monkeypatch.setattr(recovery, 'recover', recover)
    assert release.runtime_backups(root, [{'slug': 'synthetic'}], 71, '0.4.9') == ['synthetic-backup']
    assert seen == ['backup', 'restore']


def test_old_loaded_backup_receiver_blocks_before_preflight(receiver_installation, monkeypatch):
    root, owner, modules = receiver_installation
    admin.pin_generation(admin.load_generation())
    declare(root, owner, epoch='b'*32)
    monkeypatch.setattr(modules['release_backup'], 'verify_prerequisites',
                        lambda *_: pytest.fail('old receiver reached backup preflight'))
    with pytest.raises(admin.AdminError):
        modules['github_release'].runtime_backups(root, [], 71, '0.4.9')
