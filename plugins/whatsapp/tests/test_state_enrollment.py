"""Enrollment supervisor: synthetic databases, owned subprocesses, no host units."""
from contextlib import closing, contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import github_release as release
import github_release_common as common
import release_backup as journal
import release_recover
import release_transaction as transaction
import release_admin as administration
import state_enrollment as enrollment
from sally_whatsapp import state_continuity
from sally_whatsapp.store import SCHEMA_7

REAL_COMPONENT_ACTIVITY = enrollment.component_activity


def installed_legacy_identity(root):
    """Protected installation fixture for an independently started worker."""
    from installation_layout import IDENTITY, Installation, identity_bytes
    marker = root / IDENTITY.relative_to('/')
    marker.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker.write_bytes(identity_bytes(Installation.legacy()))
    marker.chmod(0o600)


@pytest.fixture
def database_case(environment, tmp_path):
    config_dir = tmp_path / 'config'; config_dir.mkdir()
    data = tmp_path / 'data'; data.mkdir()
    settings = replace(environment[0], database=data / 'archive.sqlite',
                       state_identity_file=config_dir / 'technical-state.json')
    config = config_dir / 'config.toml'
    names = ('database', 'public_url', 'issuer', 'owner_subject', 'webhook_secret_file',
             'encryption_key_file', 'public_key_file', 'oauth_client_ids', 'session')
    config.write_text('[bridge]\n' + '\n'.join(name + '=' + json.dumps(
        str(value) if isinstance(value, Path) else value)
        for name in names for value in [getattr(settings, name)]))
    with closing(sqlite3.connect(settings.database)) as db:
        db.executescript(SCHEMA_7)
        db.execute("INSERT INTO state VALUES ('keep','private')")
        db.commit()
    info = settings.database.stat()
    tenant = hashlib.sha256(json.dumps([settings.owner_subject, settings.public_url, settings.session],
                                      separators=(',', ':')).encode()).hexdigest()
    request = {'slug': 'synthetic', 'config': str(config), 'database': str(settings.database),
               'marker': str(settings.state_identity_file), 'expected': None, 'tenant': tenant,
               'uid': os.getuid(), 'gid': os.getgid(), 'user': 'synthetic',
               'inode': [info.st_dev, info.st_ino]}
    return settings, request, tmp_path / 'staged-marker.json'


def stored_identity(path):
    with closing(sqlite3.connect(path)) as db:
        row = db.execute('SELECT value FROM state WHERE key=?', (enrollment.KEY,)).fetchone()
        return json.loads(row[0]) if row else None


def test_existing_database_registration_preserves_schema_data_and_legacy_config(database_case, monkeypatch):
    settings, request, staged = database_case
    original = Path(request['config']).read_bytes()
    assert enrollment.database_child({**request, 'action': 'inspect'})['identity'] is None
    result = enrollment.database_child({**request, 'action': 'enroll', 'temporary_marker': str(staged)})
    value = result['identity']
    assert stored_identity(settings.database) == value
    assert not settings.state_identity_file.exists()
    monkeypatch.setattr(enrollment, 'administrative', lambda path: None)
    checked = []
    def validate(path):
        assert not settings.state_identity_file.exists()
        assert path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o777 == 0o640
        enrollment.database_child({**request, 'expected': value, 'action': 'validate-staged',
                                   'temporary_marker': str(path)})
        checked.append(path)
    enrollment.publish_marker(settings.state_identity_file, value, os.getuid(), os.getgid(), validate)
    assert checked
    assert enrollment.database_child({**request, 'expected': value, 'action': 'verify'})['identity'] == value
    assert Path(request['config']).read_bytes() == original
    with closing(sqlite3.connect(settings.database)) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 7
        assert db.execute("SELECT value FROM state WHERE key='keep'").fetchone()[0] == 'private'


def test_commit_before_marker_failure_preserves_identity_and_refuses_implicit_resume(database_case, monkeypatch):
    settings, request, staged = database_case
    monkeypatch.setattr(state_continuity, '_write_marker', lambda *args: (_ for _ in ()).throw(OSError('fault')))
    with pytest.raises(state_continuity.StateContinuityError):
        enrollment.database_child({**request, 'action': 'enroll', 'temporary_marker': str(staged)})
    committed = stored_identity(settings.database)
    assert committed and not staged.exists() and not settings.state_identity_file.exists()
    for action in ('inspect', 'enroll'):
        with pytest.raises(RuntimeError, match='Partial'):
            enrollment.database_child({**request, 'action': action, 'temporary_marker': str(staged)})
    assert stored_identity(settings.database) == committed


@pytest.mark.parametrize('fault', ['chown', 'validate', 'link'])
def test_marker_failure_never_publishes_unprotected_file(database_case, monkeypatch, fault):
    settings, request, staged = database_case
    value = enrollment.database_child({**request, 'action': 'enroll', 'temporary_marker': str(staged)})['identity']
    monkeypatch.setattr(enrollment, 'administrative', lambda path: None)
    def fail(*args, **kwargs): raise OSError('synthetic ' + fault)
    validate = fail if fault == 'validate' else lambda path: None
    if fault == 'chown': monkeypatch.setattr(enrollment.os, 'fchown', fail)
    if fault == 'link': monkeypatch.setattr(enrollment.os, 'link', fail)
    with pytest.raises(OSError):
        enrollment.publish_marker(settings.state_identity_file, value, os.getuid(), os.getgid(), validate)
    assert not settings.state_identity_file.exists()
    assert stored_identity(settings.database) == value
    assert not list(settings.state_identity_file.parent.glob('.state-enrollment-*'))


@pytest.mark.parametrize('damage', ['wrong-marker', 'wrong-inode', 'symlink', 'busy-send', 'root'])
def test_database_child_rejects_unsafe_state_before_registration(database_case, monkeypatch, damage):
    settings, request, staged = database_case
    if damage == 'wrong-marker': request['expected'] = {'protocol': 1, 'id': 'a' * 32, 'tenant': request['tenant']}
    elif damage == 'wrong-inode': request['inode'][1] += 1
    elif damage == 'symlink':
        actual = settings.database.with_suffix('.actual'); settings.database.rename(actual); settings.database.symlink_to(actual)
    elif damage == 'busy-send':
        with closing(sqlite3.connect(settings.database)) as db:
            db.execute("INSERT INTO sends VALUES('key','owner','hash','sending',NULL,1,1)"); db.commit()
    else: monkeypatch.setattr(enrollment.os, 'geteuid', lambda: 0)
    with pytest.raises(RuntimeError):
        enrollment.database_child({**request, 'action': 'enroll', 'temporary_marker': str(staged)})
    assert not staged.exists() and not settings.state_identity_file.exists()
    assert stored_identity(settings.database) is None


def test_as_bridge_uses_candidate_interpreter_and_propagates_lock(database_case, monkeypatch):
    settings, request, staged = database_case
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps({'schema': 7, 'inode': request['inode'], 'identity': None}))
    monkeypatch.setattr(enrollment.subprocess, 'run', run)
    enrollment.as_bridge(request, Path('/trusted/candidate/.venv/bin/python'), 17, 'inspect')
    argv, options = calls[0]
    assert argv[:4] == ['runuser', '-u', 'synthetic', '--']
    assert argv[4:7] == ['/trusted/candidate/.venv/bin/python', '-I', '-B']
    assert options['pass_fds'] == (17,) and options['timeout'] == 30


def test_helper_trust_is_checked_before_import_or_path_change(tmp_path, monkeypatch):
    helpers = tmp_path / 'helpers'; helpers.mkdir()
    module = helpers / 'github_release.py'; module.write_text('raise AssertionError("unsafe import")')
    before = list(sys.path)
    def administrative(path):
        if Path(path) == module: raise RuntimeError('untrusted module')
    monkeypatch.setattr(enrollment, 'administrative', administrative)
    with pytest.raises(RuntimeError, match='untrusted module'): enrollment.load_helpers(helpers)
    assert sys.path == before


@pytest.mark.parametrize('provided', ['omitted', 'physical', 'alias', 'unrelated'])
def test_optional_helpers_only_asserts_verified_physical_generation(tmp_path, provided):
    directory = tmp_path / 'immutable-generation'; directory.mkdir()
    generation = SimpleNamespace(path=directory)
    alias = tmp_path / 'current'; alias.symlink_to(directory, target_is_directory=True)
    supplied = {'omitted': None, 'physical': directory, 'alias': alias,
                'unrelated': tmp_path / 'legacy-shared'}[provided]
    if provided in ('alias', 'unrelated'):
        with pytest.raises(RuntimeError, match='attested physical'):
            enrollment.selected_helpers(generation, supplied)
    else:
        assert enrollment.selected_helpers(generation, supplied) == directory


@pytest.fixture
def admission(tmp_path, monkeypatch):
    directory = tmp_path / 'generation'; directory.mkdir()
    root = tmp_path / 'runtime'; (root / 'private').mkdir(parents=True)
    generation = SimpleNamespace(path=directory, epoch='7' * 32, state='dedicated', manifest_sha256='a' * 64)
    events = []
    @contextmanager
    def publication(path, *, expected):
        assert path == enrollment.__file__ and expected is generation
        events.append('publication-acquired')
        try:
            yield generation
        finally:
            events.append('publication-released')
    def attest(path, *, expected=None):
        assert path == enrollment.__file__ and expected in (None, generation)
        events.append('attest')
        return generation
    admin = SimpleNamespace(require_current=attest, publication_lock=publication,
                            pin_generation=lambda value: events.append('pin'))
    row = {'slug': 'synthetic'}
    def helpers(path):
        assert path == directory and events[-1] == 'attest'
        events.append('helpers')
        return SimpleNamespace(), SimpleNamespace(ROOT=root, instances=lambda path: [row])
    monkeypatch.setattr(enrollment, 'load_administration', lambda: admin)
    monkeypatch.setattr(enrollment, 'load_helpers', helpers)
    monkeypatch.setattr(enrollment, 'validate_candidate', lambda *args: events.append('candidate') or Path('/candidate/python'))
    monkeypatch.setattr(enrollment, 'supervise', lambda *args: events.append('supervise') or {'synthetic': True})
    monkeypatch.setattr(enrollment.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(enrollment.os, 'umask', lambda value: None)
    monkeypatch.setattr(enrollment.signal, 'signal', lambda *args: None)
    monkeypatch.setattr(sys, 'argv', [enrollment.__file__, '--worker', '--candidate', '/candidate',
                                    '--manifest', '/manifest', '--user', 'synthetic',
                                    '--owner-epoch', generation.epoch, '--helper-generation', str(directory),
                                    '--helper-manifest-sha256', generation.manifest_sha256])
    return SimpleNamespace(admin=admin, generation=generation, events=events, root=root)


def test_enrollment_attests_dedicated_generation_under_lock_before_mutations(admission):
    enrollment.main()
    assert admission.events == ['attest', 'pin', 'publication-acquired', 'attest', 'helpers',
                                'attest', 'candidate', 'supervise', 'publication-released']


@pytest.mark.parametrize('boundary', ['initial', 'publication', 'tenant'])
def test_stale_owner_or_epoch_blocks_enrollment_without_fallback(admission, boundary):
    calls = 0
    def changed(path, *, expected=None):
        nonlocal calls
        calls += 1
        admission.events.append('attest')
        if calls == {'initial': 1, 'publication': 2, 'tenant': 3}[boundary]:
            raise RuntimeError('dedicated owner epoch changed')
        return admission.generation
    admission.admin.require_current = changed
    with pytest.raises(RuntimeError, match='epoch changed'):
        enrollment.main()
    assert 'candidate' not in admission.events and 'supervise' not in admission.events
    if boundary == 'initial':
        assert not (admission.root / 'private/tenant-admin.lock').exists()


def test_explicit_shared_helpers_fails_before_lock_or_helper_import(admission, monkeypatch):
    monkeypatch.setattr(sys, 'argv', [*sys.argv, '--helpers', '/legacy/shared'])
    with pytest.raises(RuntimeError, match='attested physical'):
        enrollment.main()
    assert admission.events == ['attest']
    assert not (admission.root / 'private/tenant-admin.lock').exists()


@pytest.mark.parametrize('component', ['owner-epoch', 'helper-generation', 'helper-manifest-sha256', 'missing'])
def test_worker_rejects_missing_or_superseded_pin_before_helper_loading(admission, monkeypatch, component):
    argv = list(sys.argv)
    if component == 'missing':
        offset = argv.index('--owner-epoch')
        del argv[offset:]
    else:
        argv[argv.index('--' + component) + 1] = '/superseded' if component == 'helper-generation' else '0' * 64
    monkeypatch.setattr(sys, 'argv', argv)
    with pytest.raises(RuntimeError, match='pin|no longer current'):
        enrollment.main()
    assert not any(item in admission.events for item in ('pin', 'helpers', 'publication-acquired', 'supervise'))


def test_parent_attests_before_launch_and_passes_pin_to_private_worker(admission, monkeypatch):
    argv = [enrollment.__file__, '--candidate', '/candidate', '--manifest', '/manifest', '--user', 'synthetic']
    monkeypatch.setattr(sys, 'argv', argv)
    calls = []
    def launch(args, **kwargs):
        assert admission.events == ['attest', 'pin']
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(enrollment.subprocess, 'run', launch)
    with pytest.raises(SystemExit) as stopped:
        enrollment.main()
    assert stopped.value.code == 0
    args, options = calls[0]
    assert args[args.index('--owner-epoch') + 1] == admission.generation.epoch
    assert args[args.index('--helper-generation') + 1] == str(admission.generation.path)
    assert args[args.index('--helper-manifest-sha256') + 1] == admission.generation.manifest_sha256
    assert options == {'start_new_session': True, 'timeout': 900}


def test_worker_loads_only_stable_bootstrap_source_without_bytecode(tmp_path, monkeypatch):
    bootstrap = tmp_path / 'bootstrap'; bootstrap.mkdir()
    source = bootstrap / 'release_admin.py'; source.write_text('loaded_from_stable_bootstrap = True\n')
    monkeypatch.setattr(enrollment, 'BOOTSTRAP', bootstrap)
    trusted = []
    monkeypatch.setattr(enrollment, 'administrative', lambda path: trusted.append(Path(path)))
    monkeypatch.delitem(sys.modules, 'release_admin')
    loaded = enrollment.load_administration()
    assert loaded.loaded_from_stable_bootstrap
    assert Path(loaded.__file__) == source
    assert trusted == [Path(enrollment.__file__), source]
    assert enrollment.load_administration() is loaded
    assert not (bootstrap / '__pycache__').exists()


def test_stable_bootstrap_rejects_cached_global_or_generation_core(tmp_path, monkeypatch):
    bootstrap = tmp_path / 'bootstrap'; bootstrap.mkdir()
    (bootstrap / 'release_admin.py').write_text('raise AssertionError("must not execute")\n')
    monkeypatch.setattr(enrollment, 'BOOTSTRAP', bootstrap)
    monkeypatch.setattr(enrollment, 'administrative', lambda path: None)
    monkeypatch.setitem(sys.modules, 'release_admin', SimpleNamespace(__file__='/legacy/shared/release_admin.py'))
    with pytest.raises(RuntimeError, match='stable WhatsApp bootstrap'):
        enrollment.load_administration()


def test_tenant_preflight_rejects_legacy_config_changes_and_group_changes(database_case, monkeypatch):
    settings, request, staged = database_case
    row = {'slug': 'synthetic', 'config': request['config'], 'unit': 'synthetic.service'}
    monkeypatch.setattr(enrollment, 'administrative', lambda path: None)
    monkeypatch.setattr(enrollment.pwd, 'getpwnam', lambda name: SimpleNamespace(
        pw_name='synthetic', pw_uid=os.getuid(), pw_gid=os.getgid()))
    def command(args, *more, **kwargs):
        return 'synthetic' if '--property=User' in args else ''
    monkeypatch.setattr(enrollment, 'command', command)
    result = enrollment.tenant_info(row, Path('/trusted/candidate'), 17)
    assert result['marker'] == request['marker'] and result['expected'] is None
    monkeypatch.setattr(enrollment, 'command', lambda args, *more, **kwargs:
                        'synthetic' if '--property=User' in args else str(os.getgid() + 1))
    with pytest.raises(RuntimeError, match='group differs'):
        enrollment.tenant_info(row, Path('/trusted/candidate'), 17)
    with Path(request['config']).open('a') as stream:
        stream.write('\nstate_identity_file=' + json.dumps(str(settings.state_identity_file)))
    with pytest.raises(RuntimeError, match='legacy'):
        enrollment.tenant_info(row, Path('/trusted/candidate'), 17)


def test_staged_marker_is_validated_before_publication_and_cannot_replace_existing(database_case, monkeypatch):
    settings, request, staged = database_case
    value = enrollment.database_child({**request, 'action': 'enroll', 'temporary_marker': str(staged)})['identity']
    monkeypatch.setattr(enrollment, 'administrative', lambda path: None)
    original = {'protocol': 1, 'id': 'c' * 32, 'tenant': request['tenant']}
    settings.state_identity_file.write_text(json.dumps(original))
    settings.state_identity_file.chmod(0o640)
    def validate(path):
        assert settings.state_identity_file.read_text() == json.dumps(original)
        enrollment.database_child({**request, 'expected': value, 'action': 'validate-staged',
                                   'temporary_marker': str(path)})
    with pytest.raises(RuntimeError, match='Existing marker'):
        enrollment.publish_marker(settings.state_identity_file, value, os.getuid(), os.getgid(), validate)
    assert json.loads(settings.state_identity_file.read_text()) == original


def test_existing_coherent_enrollment_only_verifies_without_marker_rewrite(database_case, monkeypatch):
    settings, request, staged = database_case
    value = enrollment.database_child({**request, 'action': 'enroll', 'temporary_marker': str(staged)})['identity']
    settings.state_identity_file.write_text(json.dumps(value)); settings.state_identity_file.chmod(0o640)
    original = settings.state_identity_file.read_bytes(), settings.state_identity_file.stat().st_ino
    calls = []
    def as_bridge(info, python, lock_fd, action, **extra):
        calls.append(action)
        return enrollment.database_child({**info, 'action': action, **extra})
    monkeypatch.setattr(enrollment, 'as_bridge', as_bridge)
    enrollment.enroll_one({**request, 'expected': value}, Path('/candidate/python'), 17)
    assert calls == ['verify']
    assert original == (settings.state_identity_file.read_bytes(), settings.state_identity_file.stat().st_ino)


def test_common_command_propagates_a_real_lock_descriptor_to_owned_child(tmp_path):
    import fcntl
    lock_path = tmp_path / 'owned.lock'
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        code = 'import os,sys;print(os.fstat(int(sys.argv[1])).st_ino)'
        result = common.run([sys.executable, '-I', '-B', '-c', code, str(lock.fileno())], pass_fds=(lock.fileno(),))
        assert int(result) == lock_path.stat().st_ino


def test_common_command_child_keeps_lock_after_owned_caller_sigkill(tmp_path):
    import fcntl
    installed_legacy_identity(tmp_path)
    lock_path = tmp_path / 'owned.lock'; ready = tmp_path / 'ready.json'
    child_code = """
import os,sys,json,signal
from pathlib import Path
fd=int(sys.argv[1]); info=os.fstat(fd)
start=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
Path(sys.argv[2]).write_text(json.dumps({'pid':os.getpid(),'start':start,'inode':info.st_ino}))
signal.alarm(15);signal.pause()
"""
    parent_code = """
import sys,fcntl,os
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import installation_layout as layout
layout.activate_installation(root=Path(sys.argv[2]).parent,trusted_uid=os.getuid())
import github_release_common as common
with Path(sys.argv[2]).open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 common.run([sys.executable,'-I','-B','-c',sys.argv[4],str(lock.fileno()),sys.argv[3]],pass_fds=(lock.fileno(),),timeout=20)
"""
    parent = subprocess.Popen([sys.executable, '-I', '-B', '-c', parent_code, str(SCRIPTS),
                               str(lock_path), str(ready), child_code], start_new_session=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    owned = None
    try:
        for _ in range(250):
            if ready.exists(): break
            assert parent.poll() is None
            time.sleep(.02)
        owned = json.loads(ready.read_text())
        assert owned['inode'] == lock_path.stat().st_ino
        parent.kill(); parent.communicate(timeout=5)
        with lock_path.open('a') as observer:
            with pytest.raises(BlockingIOError): fcntl.flock(observer, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        if parent.poll() is None: parent.kill(); parent.communicate(timeout=5)
        if owned:
            info = Path('/proc') / str(owned['pid']) / 'stat'
            if info.exists() and info.read_text().rsplit(')', 1)[1].split()[19] == owned['start']:
                os.kill(owned['pid'], signal.SIGKILL)


@pytest.fixture
def operation(tmp_path, monkeypatch):
    root = tmp_path / 'project'; (root / 'private').mkdir(parents=True); (root / 'sally_whatsapp').mkdir()
    (root / 'private/tenants.json').write_text('{}')
    (root / 'sally_whatsapp/__init__.py').write_text('__version__="0.4.9"')
    state = tmp_path / 'state'; state.mkdir()
    monkeypatch.setattr(journal, 'JOURNAL', state / 'backup.json')
    monkeypatch.setattr(transaction, 'JOURNAL', state / 'transaction.json')
    monkeypatch.setattr(transaction, 'GATE', state / 'gate')
    transaction.JOURNAL.write_text('{"phase":"published"}')
    monkeypatch.setattr(journal, 'verify_prerequisites', lambda root: None)
    rows = []; components = []; infos = {}
    for i, slug in enumerate(('enabled', 'suspended')):
        config = root / (slug + '.toml'); config.write_text('synthetic')
        wrapper = root / (slug + '-wrapper'); wrapper.write_text('synthetic')
        row = {'slug': slug, 'unit': 'whatsapp-' + slug + '.service', 'base': 'whatsapp-' + slug,
               'config': config, 'wrapper': wrapper, 'port': 8822 + 2 * i}
        rows.append(row)
        infos[slug] = {'slug': slug, 'database': str(root / (slug + '.sqlite')),
                       'marker': str(root / (slug + '.json')), 'inode': [1, i + 1]}
        for kind, argv, unit, port in [('gateway', [str(wrapper), 'systemctl', '--user'], 'whatsapp-waha.service', row['port'] + 1),
                                       ('bridge', ['systemctl'], row['unit'], row['port'])]:
            components.append({'name': slug + '.' + kind, 'kind': kind, 'command': argv, 'unit': unit,
                               'port': port, 'config': config, 'active': slug == 'enabled'})
    monkeypatch.setattr(enrollment, 'tenant_info', lambda row, *args: infos[row['slug']])
    monkeypatch.setattr(enrollment, 'as_bridge', lambda *args, **kwargs: {})
    monkeypatch.setattr(enrollment, 'component_activity', lambda selected, fd: [x for x in components if x['name'].split('.')[0] in {r['slug'] for r in selected}])
    monkeypatch.setattr(journal, 'attach_worker', lambda operation_id: None)
    calls = []
    monkeypatch.setattr(enrollment, 'stop_components', lambda *args: calls.append('stop'))
    monkeypatch.setattr(enrollment, 'enroll_one', lambda info, *args: calls.append('enroll:' + info['slug']))
    def restore(parts, version, **kwargs):
        assert version == '0.4.9' and kwargs['lock_fd'] == 17
        calls.extend('start:' + part['name'] for part in parts if part['active'])
        return []
    api = SimpleNamespace(literal=lambda *args: '0.4.9', restore_backup_components=restore)
    return SimpleNamespace(root=root, state=state, rows=rows, components=components, infos=infos, calls=calls, api=api)


def supervise(p, selected=None):
    return enrollment.supervise(p.root, p.rows, selected or p.rows, Path('/candidate/.venv/bin/python'), 17, journal, p.api)


def test_enrollment_journal_never_claims_backup_and_restores_only_prior_activity(operation):
    p = operation
    supervise(p)
    assert p.calls == ['stop', 'enroll:enabled', 'enroll:suspended', 'start:enabled.gateway', 'start:enabled.bridge']
    plan = journal.read()
    assert plan['servicesRestored'] and all(item == {'path': None, 'complete': False} for item in plan['copies'].values())


def test_single_tenant_does_not_enroll_or_restart_other_tenant(operation):
    p = operation; supervise(p, [p.rows[1]])
    assert p.calls == ['stop', 'enroll:suspended']
    assert journal.read()['selected'] == ['suspended']


@pytest.mark.parametrize('active,sub,job', [('activating', 'start', '0'), ('deactivating', 'stop', '0'),
                                         ('active', 'running', '12'), ('failed', 'failed', '13')])
def test_transitional_activity_refuses_before_journal_or_service_mutation(operation, monkeypatch, active, sub, job):
    p = operation
    monkeypatch.setattr(enrollment, 'component_activity', REAL_COMPONENT_ACTIVITY)
    monkeypatch.setattr(enrollment, 'command', lambda *args, **kwargs:
                        'LoadState=loaded\nActiveState=' + active + '\nSubState=' + sub + '\nJob=' + job)
    with pytest.raises(RuntimeError, match='transitional'): supervise(p)
    assert not journal.JOURNAL.exists() and not p.calls


def test_stable_activity_snapshot_preserves_masked_inactive_gateway(operation, monkeypatch):
    p = operation
    def command(args, fd, **kwargs):
        assert fd == 17
        if '--user' in args: return 'LoadState=masked\nActiveState=inactive\nSubState=dead\nJob=0'
        return 'LoadState=loaded\nActiveState=active\nSubState=running\nJob=0'
    monkeypatch.setattr(enrollment, 'command', command)
    parts = REAL_COMPONENT_ACTIVITY([p.rows[0]], 17)
    assert [(item['kind'], item['active']) for item in parts] == [('gateway', False), ('bridge', True)]


@pytest.mark.parametrize('fault', ['begin', 'stop', 'enroll', 'restore'])
def test_failures_preserve_recovery_and_never_retry_enrollment(operation, monkeypatch, fault):
    p = operation
    def failed(*args, **kwargs): raise RuntimeError('synthetic failure')
    if fault == 'begin': monkeypatch.setattr(journal, 'save', failed)
    elif fault == 'stop': monkeypatch.setattr(enrollment, 'stop_components', failed)
    elif fault == 'enroll': monkeypatch.setattr(enrollment, 'enroll_one', failed)
    else: p.api.restore_backup_components = lambda *args, **kwargs: ['enabled.bridge.readiness']
    with pytest.raises((RuntimeError, common.ReleaseError)): supervise(p)
    if fault == 'begin':
        assert p.calls == [] and not journal.JOURNAL.exists()
    else:
        plan = journal.read()
        assert plan['servicesRestored'] == (fault != 'restore')
        assert all(not item['complete'] for item in plan['copies'].values())
        assert not any(call.startswith('enroll:') for call in p.calls) if fault != 'restore' else True


def test_stop_requires_finished_jobs_and_empty_cgroup(monkeypatch):
    item = {'command': ['synthetic'], 'unit': 'fake.service', 'kind': 'bridge', 'active': True}
    calls = []; responses = ['5', '0']
    def command(args, fd, **kwargs):
        calls.append(args)
        if 'stop' in args: return ''
        return 'ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=' + responses.pop(0) + '\nControlGroup=/synthetic'
    monkeypatch.setattr(enrollment, 'command', command)
    monkeypatch.setattr(enrollment, 'cgroup_empty', lambda group: True)
    monkeypatch.setattr(enrollment.time, 'sleep', lambda seconds: None)
    enrollment.stop_components([item], 17)
    assert len(calls) == 3


def test_restore_optional_lock_reaches_start_and_status_without_changing_default(monkeypatch):
    item = {'name': 'synthetic.gateway', 'kind': 'gateway', 'command': ['synthetic'], 'unit': 'fake.service',
            'port': 1, 'config': Path('/synthetic/config.toml'), 'active': True}
    starts = []; status = []
    monkeypatch.setattr(release, 'run', lambda args, **kwargs: starts.append(kwargs))
    monkeypatch.setattr(release.subprocess, 'run', lambda args, **kwargs: status.append(kwargs) or SimpleNamespace(returncode=0))
    monkeypatch.setattr(Path, 'read_text', lambda self: 'synthetic-key')
    monkeypatch.setattr(release, 'get_json', lambda *args: {})
    assert release.restore_backup_components([item], '0.4.9') == []
    assert 'pass_fds' not in starts[-1] and 'pass_fds' not in status[-1]
    assert release.restore_backup_components([item], '0.4.9', lock_fd=17) == []
    assert starts[-1]['pass_fds'] == status[-1]['pass_fds'] == (17,)


CHILD = r'''
import json,sys,signal,sqlite3,os,fcntl
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import installation_layout as layout
layout.activate_installation(root=Path(sys.argv[2]),trusted_uid=os.getuid())
import state_enrollment as enrollment,release_backup as journal,release_transaction as transaction
from types import SimpleNamespace
root=Path(sys.argv[2]);state=Path(sys.argv[3]);point=sys.argv[4]
journal.JOURNAL=state/'backup.json';transaction.JOURNAL=state/'transaction.json';transaction.GATE=state/'gate'
record=json.loads((root/'fixture.json').read_text());rows=record['rows'];parts=record['components']
for row in rows:row['config']=Path(row['config']);row['wrapper']=Path(row['wrapper'])
for part in parts:part['config']=Path(part['config'])
def boundary(name):
 if name==point:
  print('READY',flush=True);signal.pause()
journal.verify_prerequisites=lambda root:None
begin=journal.begin
def started(*args):
 result=begin(*args);boundary('journal');return result
journal.begin=started
attach=journal.attach_worker
def attached(operation):attach(operation);boundary('worker')
journal.attach_worker=attached
enrollment.tenant_info=lambda row,*args:record['infos'][row['slug']]
enrollment.as_bridge=lambda *args,**kwargs:{}
enrollment.component_activity=lambda *args:parts
enrollment.stop_components=lambda *args:boundary('stop')
def enroll(info,*args):
 with sqlite3.connect(info['database']) as db:
  db.execute('CREATE TABLE IF NOT EXISTS state(key TEXT,value TEXT)')
  db.execute('INSERT INTO state VALUES(?,?)',(enrollment.KEY,json.dumps({'protocol':1,'id':'a'*32,'tenant':'b'*64})))
 boundary('database-commit')
 Path(info['marker']).write_text('synthetic-marker')
 boundary('marker')
enrollment.enroll_one=enroll
api=SimpleNamespace(literal=lambda *args:'0.4.9',restore_backup_components=lambda *args,**kwargs:[])
with (state/'publication.lock').open('a') as publication,(root/'private/tenant-admin.lock').open('a') as lock:
 fcntl.flock(publication,fcntl.LOCK_EX);fcntl.flock(lock,fcntl.LOCK_EX)
 enrollment.supervise(root,rows,rows,Path('/candidate/.venv/bin/python'),lock.fileno(),journal,api)
'''


@pytest.mark.parametrize('point', ['journal', 'worker', 'stop', 'database-commit', 'marker'])
def test_real_sigkill_independent_recovery_never_replays_enrollment(operation, monkeypatch, point):
    p = operation
    installed_legacy_identity(p.root)
    serialize = lambda rows: [{key: str(value) if isinstance(value, Path) else value for key, value in row.items()} for row in rows]
    (p.root / 'fixture.json').write_text(json.dumps({'rows': serialize(p.rows), 'components': serialize(p.components), 'infos': p.infos}))
    child = subprocess.Popen([sys.executable, '-B', '-c', CHILD, str(SCRIPTS), str(p.root), str(p.state), point],
                             start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([child.stdout], [], [], 10)[0]
        assert child.stdout.readline().strip() == 'READY'
        # Exercise the real dedicated publication flock. Only the external
        # root-owned generation metadata is synthetic in this non-root test.
        generation = administration.Generation(SCRIPTS, 'b' * 32, 'dedicated', 'c' * 64, {})
        monkeypatch.setattr(administration, 'STATE', p.state)
        monkeypatch.setattr(administration, 'PUBLICATION_LOCK', p.state / 'publication.lock')
        monkeypatch.setattr(administration, 'require_current', lambda *a, **k: generation)
        monkeypatch.setattr(administration, 'trusted_path', lambda path, **kwargs: Path(path))
        monkeypatch.setattr(administration, '_trusted_uid', lambda uid: uid == os.getuid())
        monkeypatch.setattr(administration, '_PINNED', None)
        monkeypatch.setattr(release, 'ROOT', p.root)
        monkeypatch.setattr(release, 'instances', lambda root: p.rows)
        starts = []
        monkeypatch.setattr(release, 'restore_backup_components', lambda components, version, **kwargs: starts.extend(
            item['name'] for item in components if item['active']) or [])
        release_recover.recover_project('whatsapp')
        assert not starts
        child.kill(); child.communicate(timeout=5)
        assert child.returncode == -signal.SIGKILL
        release_recover.recover_project('whatsapp')
        assert starts == ['enabled.gateway', 'enabled.bridge']
        assert journal.read()['servicesRestored']
        assert all(item == {'path': None, 'complete': False} for item in journal.read()['copies'].values())
        assert not Path(p.infos['suspended']['database']).exists()
        if point in ('database-commit', 'marker'):
            before = Path(p.infos['enabled']['database']).read_bytes()
            release_recover.recover_project('whatsapp')
            assert Path(p.infos['enabled']['database']).read_bytes() == before
        assert Path(p.infos['enabled']['marker']).exists() == (point == 'marker')
    finally:
        if child.poll() is None: child.kill(); child.communicate(timeout=5)
