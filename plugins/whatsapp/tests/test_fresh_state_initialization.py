"""First-install administration with synthetic files and no host commands."""
from contextlib import closing
from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

from sally_whatsapp.config import Settings
from sally_whatsapp import state_initialization as initialization
from sally_whatsapp.server import Service
from sally_whatsapp.state_continuity import StateContinuity, StateContinuityError, STATE_KEY, register_external_identity
from sally_whatsapp.store import Store
from sally_whatsapp.tenancy import Instance, render_config, ISSUER


PLUGIN = Path(__file__).parents[1]


def load_script(name):
    if str(PLUGIN/'scripts') not in sys.path: sys.path.insert(0,str(PLUGIN/'scripts'))
    spec = importlib.util.spec_from_file_location(name, PLUGIN/'scripts'/f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    import socket
    def forbidden(*args, **kwargs):
        pytest.fail('first-install tests must not contact a real service')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)


@pytest.fixture
def fresh(environment, tmp_path, monkeypatch):
    state = tmp_path/'data'
    config = tmp_path/'configuration'
    state.mkdir()
    config.mkdir()
    settings = replace(environment[0], database=state/'archive.sqlite',
                       state_identity_file=config/'technical-state.json')
    ownership = []
    # Check intended root/service ownership without changing real Unix owners.
    monkeypatch.setattr(initialization, '_administrative_directory',
                        lambda path: path.stat().st_uid == os.geteuid() and not path.stat().st_mode & 0o022)
    monkeypatch.setattr(initialization, 'os', SimpleNamespace(**{
        **{key: getattr(os, key) for key in dir(os) if not key.startswith('__')},
        'fchown': lambda fd, uid, gid: ownership.append(('database', uid, gid)),
        'chown': lambda path, uid, gid, **kwargs: ownership.append((path, uid, gid)),
    }))
    return settings, ownership


@pytest.mark.parametrize('owner,mode,accepted', [(0, 0o750, True), (0, 0o700, True),
                                               (1234, 0o750, False), (0, 0o770, False), (0, 0o757, False)])
def test_staging_requires_root_owned_directory_without_shared_write(owner, mode, accepted):
    path = SimpleNamespace(stat=lambda: SimpleNamespace(st_uid=owner, st_mode=mode))
    assert initialization._administrative_directory(path) is accepted


def contents(root):
    return {str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob('*') if path.is_file() and not path.is_symlink()}


def test_first_install_creates_schema_identity_permissions_and_starts(fresh, environment):
    settings, ownership = fresh
    initialization.initialize_new(settings, 1234, 5678)
    assert ownership == [('database', 1234, 5678), (settings.state_identity_file, 0, 5678)]
    assert settings.database.stat().st_mode & 0o777 == 0o600
    assert settings.state_identity_file.stat().st_mode & 0o777 == 0o640
    assert sorted(path.name for path in settings.database.parent.iterdir()) == ['archive.sqlite']
    marker = settings.state_identity_file.read_bytes()
    with closing(sqlite3.connect(settings.database)) as db:
        assert db.execute('PRAGMA user_version').fetchone() == (8,)
        assert json.loads(db.execute('SELECT value FROM state WHERE key=?', (STATE_KEY,)).fetchone()[0]) == json.loads(marker)
    running = Service(settings, gateway=environment[2], event_transport=environment[1])
    assert settings.state_identity_file.read_bytes() == marker
    assert running.continuity.expected == json.loads(marker)
    assert environment[2].sent == []


@pytest.mark.parametrize('entry', ['database', 'marker', 'sibling', 'wal', 'shm', 'journal'])
@pytest.mark.parametrize('kind', ['file', 'dangling_symlink', 'directory'])
def test_first_install_never_adopts_existing_paths(fresh, tmp_path, entry, kind):
    settings, ownership = fresh
    paths = {'database': settings.database, 'marker': settings.state_identity_file,
             'sibling': settings.database.with_name('archive.sqlite.identity.json'),
             **{name: settings.database.with_name('archive.sqlite-'+name) for name in ('wal', 'shm', 'journal')}}
    path = paths[entry]
    if kind == 'file':
        path.write_bytes(b'synthetic preserved state')
    elif kind == 'dangling_symlink':
        path.symlink_to(tmp_path/'missing-target')
    else:
        path.mkdir()
    before = contents(tmp_path)
    with pytest.raises(StateContinuityError):
        initialization.initialize_new(settings, 1234, 5678)
    assert contents(tmp_path) == before and not ownership
    assert path.is_symlink() if kind == 'dangling_symlink' else path.exists()


@pytest.mark.parametrize('invalid', ['no_marker', 'inside_data', 'normalized_inside_data',
                                    'missing_database_parent', 'missing_marker_parent',
                                    'database_parent_symlink', 'marker_parent_symlink'])
def test_first_install_requires_separate_real_prepared_directories(fresh, tmp_path, invalid):
    settings, ownership = fresh
    if invalid == 'no_marker':
        settings = replace(settings, state_identity_file=None)
    elif invalid == 'inside_data':
        settings = replace(settings, state_identity_file=settings.database.parent/'identity.json')
    elif invalid == 'normalized_inside_data':
        settings = replace(settings, state_identity_file=settings.state_identity_file.parent/'..'/'data'/'identity.json')
    elif invalid == 'missing_database_parent':
        settings = replace(settings, database=tmp_path/'missing'/'archive.sqlite')
    elif invalid == 'missing_marker_parent':
        settings = replace(settings, state_identity_file=tmp_path/'missing'/'identity.json')
    else:
        alias = tmp_path/'alias'
        alias.symlink_to(settings.database.parent if invalid.startswith('database') else settings.state_identity_file.parent,
                         target_is_directory=True)
        settings = replace(settings, **({'database': alias/'archive.sqlite'} if invalid.startswith('database')
                                        else {'state_identity_file': alias/'identity.json'}))
    with pytest.raises(StateContinuityError):
        initialization.initialize_new(settings, 1234, 5678)
    assert not settings.database.exists() and not ownership


def test_exclusive_reservation_refuses_a_database_appearing_after_preflight(fresh, monkeypatch):
    settings, ownership = fresh
    original = initialization._new_paths
    def racing(config):
        paths = original(config)
        settings.database.write_bytes(b'concurrent administrative state')
        return paths
    monkeypatch.setattr(initialization, '_new_paths', racing)
    with pytest.raises(StateContinuityError):
        initialization.initialize_new(settings, 1234, 5678)
    assert settings.database.read_bytes() == b'concurrent administrative state'
    assert not settings.state_identity_file.exists() and not ownership


def test_final_path_replacement_cannot_redirect_root_sqlite_writes(fresh, tmp_path, monkeypatch):
    settings, ownership = fresh
    unrelated = tmp_path/'unrelated.sqlite'
    unrelated.write_bytes(b'preserved unrelated administrative file')
    original = initialization.Store
    stages = []
    def racing(staged):
        assert staged.parent.parent == settings.state_identity_file.parent
        assert staged.parent.stat().st_mode & 0o777 == 0o700
        stages.append(staged)
        original(staged)
        settings.database.unlink()
        settings.database.symlink_to(unrelated)
    monkeypatch.setattr(initialization, 'Store', racing)
    with pytest.raises(StateContinuityError):
        initialization.initialize_new(settings, 1234, 5678)
    assert stages and unrelated.read_bytes() == b'preserved unrelated administrative file'
    assert not ownership
    assert settings.state_identity_file.exists()  # Partial setup requires explicit recovery.


@pytest.mark.parametrize('failure', ['schema', 'registration'])
def test_interrupted_initialization_preserves_files_and_cannot_retry(fresh, monkeypatch, failure):
    settings, ownership = fresh
    def interrupted(*args, **kwargs):
        raise RuntimeError('synthetic interrupted installation')
    target = 'Store' if failure == 'schema' else 'register_external_identity'
    with monkeypatch.context() as patch:
        patch.setattr(initialization, target, interrupted)
        with pytest.raises(RuntimeError, match='interrupted'):
            initialization.initialize_new(settings, 1234, 5678)
    before = settings.database.read_bytes()
    assert settings.database.exists() and not settings.state_identity_file.exists()
    with pytest.raises(StateContinuityError):
        initialization.initialize_new(settings, 1234, 5678)
    assert settings.database.read_bytes() == before and not ownership


@pytest.mark.parametrize('route', ['fresh', 'schema7'])
def test_fresh_and_upgrade_share_startup_and_idempotency_contract(fresh, environment, route):
    settings, _ = fresh
    if route == 'fresh':
        initialization.initialize_new(settings, 1234, 5678)
    else:
        with closing(sqlite3.connect(settings.database)) as db:
            db.executescript((PLUGIN/'scripts/backup_schemas/7.sql').read_text())
        register_external_identity(settings)
    marker = settings.state_identity_file.read_bytes()
    running = Service(settings, gateway=environment[2], event_transport=environment[1])
    running.store.reserve_send('inflight-before-restart', settings.owner_subject, {'text': 'synthetic'})
    restarted = Service(settings, gateway=environment[2], event_transport=environment[1])
    assert restarted.store.send_status('inflight-before-restart')['state'] == 'uncertain'
    created, status = restarted.store.reserve_send('inflight-before-restart', settings.owner_subject, {'text': 'synthetic'})
    assert not created and status['state'] == 'uncertain'
    with restarted.store.db() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
    assert settings.state_identity_file.read_bytes() == marker
    assert environment[2].sent == []


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    admin = load_script('tenant_admin')
    import tenant_database as secure
    # Protected host metadata is represented by a private temporary root.
    # SQLite verification still runs in the real isolated child as this UID.
    monkeypatch.setattr(secure, '_TRUST_ROOT', tmp_path)
    monkeypatch.setattr(secure, '_TRUST_UID', os.getuid())
    class SyntheticInstance(Instance):
        @property
        def config_dir(self): return tmp_path/'configuration'
        @property
        def state_dir(self): return tmp_path/'data'
        @property
        def gateway_home(self): return tmp_path/'gateway'
        @property
        def private_dir(self): return tmp_path/'private'
    instance = SyntheticInstance('fixture', 'Synthetic', '11111111-1111-4111-8111-111111111111', 8824)
    commands = []
    monkeypatch.setattr(admin, 'deployment_artifacts', lambda _: {'bridge': 'synthetic bridge', 'gateway': 'synthetic gateway'})
    monkeypatch.setattr(admin, 'ROOT', tmp_path/'source')
    monkeypatch.setattr(pwd, 'getpwnam', lambda _: SimpleNamespace(pw_dir=str(instance.gateway_home),
                                                                pw_shell='/usr/sbin/nologin', pw_uid=os.getuid(), pw_gid=os.getgid()))
    real_path = Path
    monkeypatch.setattr(admin, 'Path', lambda value: tmp_path/str(value).lstrip('/')
                        if str(value).startswith('/etc/') else real_path(value))
    for name in ('subuid', 'subgid'):
        target = tmp_path/'etc'/name
        target.parent.mkdir(exist_ok=True)
        target.write_text(instance.service_user+':100000:65536\n')
    monkeypatch.setattr(admin, 'os', SimpleNamespace(chown=lambda *a, **k: None, chmod=os.chmod, replace=os.replace))
    monkeypatch.setattr(admin, 'run', lambda args, **kwargs: commands.append([str(v) for v in args]))
    monkeypatch.setattr(admin, 'subprocess', SimpleNamespace(run=lambda *a, **k: SimpleNamespace(returncode=0)))
    monkeypatch.setattr(admin, 'httpx', SimpleNamespace(get=lambda *a, **k: SimpleNamespace(raise_for_status=lambda:None,json=lambda: {
        'issuer':ISSUER,'jwks_uri':ISSUER+'/jwks.json',
        'authorization_endpoint': ISSUER+'/authorize', 'token_endpoint': ISSUER+'/token'})))
    monkeypatch.setattr(admin, 'phase', lambda *a, **k: None)
    return admin, instance, commands


def save_config(instance):
    instance.config_dir.mkdir(exist_ok=True)
    path = instance.config_dir/'config.toml'
    path.write_text(render_config(instance, authorize_url=ISSUER+'/authorize', token_url=ISSUER+'/token'))
    return path


def test_prepare_runtime_initializes_only_after_new_config_before_services(runtime, fresh, environment, monkeypatch):
    admin, instance, commands = runtime
    real_initialize = initialization.initialize_new
    def initialize(settings, uid, gid):
        assert (instance.config_dir/'config.toml').is_file()
        assert settings.state_identity_file == instance.config_dir/'technical-state.json'
        assert not (instance.private_dir/'as-user').exists()
        assert not any('systemctl' in command or 'loginctl' in command for command in commands)
        real_initialize(settings, uid, gid)
        commands.append(['initialized'])
    monkeypatch.setattr(admin, 'initialize_new', initialize)
    admin.prepare_runtime(instance,host=SimpleNamespace(enroll_runtime=lambda account:commands.append(['host-qos'])))
    loaded = Settings.load(instance.config_dir/'config.toml')
    StateContinuity(loaded, allow_bootstrap=False)
    # Explicit compatibility retains its preexisting add-user capabilities.
    assert instance._installation_identity.compatibility
    assert all(getattr(loaded, name) for name in ('live_account_enabled', 'link_enabled',
               'send_enabled', 'allow_all_destinations', 'account_actions_enabled'))
    assert loaded.state_identity_file == instance.config_dir/'technical-state.json'
    assert commands.index(['initialized']) < commands.index(['loginctl', 'enable-linger', instance.service_user])
    assert ['initialized'] in commands
    marker = loaded.state_identity_file.read_bytes()
    Service(loaded, gateway=environment[2], event_transport=environment[1], recover_inflight=False)
    Service(loaded, gateway=environment[2], event_transport=environment[1])
    assert loaded.state_identity_file.read_bytes() == marker and environment[2].sent == []


@pytest.mark.parametrize('partial', ['config_only', 'database_only', 'marker_only', 'mismatch'])
def test_existing_config_failure_precedes_all_runtime_side_effects(runtime, fresh, monkeypatch, partial):
    admin, instance, commands = runtime
    cfgpath = save_config(instance)
    settings = Settings.load(cfgpath)
    instance.state_dir.mkdir(exist_ok=True)
    if partial == 'database_only':
        Store(settings.database)
    elif partial in ('marker_only', 'mismatch'):
        initialization.initialize_new(settings, 1234, 5678)
        if partial == 'marker_only':
            settings.database.unlink()
        else:
            marker = json.loads(settings.state_identity_file.read_text())
            marker['id'] = '0'*32
            settings.state_identity_file.write_text(json.dumps(marker))
    before = contents(cfgpath.parent.parent)
    def forbidden(*args, **kwargs):
        pytest.fail('existing inconsistent state must fail before any side effect')
    monkeypatch.setattr(admin, 'initialize_new', forbidden)
    monkeypatch.setattr(admin, 'write_private', forbidden)
    monkeypatch.setattr(admin.httpx, 'get', forbidden)
    # A missing protected file fails before SQLite starts; a changed marker is
    # rejected by the UID worker. Account lookup itself is read-only.
    expected = subprocess.CalledProcessError if partial == 'mismatch' else FileNotFoundError
    with pytest.raises(expected):
        admin.prepare_runtime(instance,host=SimpleNamespace(enroll_runtime=lambda account:commands.append(['host-qos'])))
    assert commands == [] and contents(cfgpath.parent.parent) == before


def test_existing_runtime_preserves_schema7_config_identity_and_inflight(runtime, fresh, monkeypatch):
    admin, instance, commands = runtime
    import tenant_database as secure
    original_run = secure.subprocess.run
    workers = []
    def run_worker(command, **options):
        assert command[:5] == [sys.executable, '-I', '-B', '-', 'verify']
        assert options['cwd'] == '/' and options['env'] == {}
        workers.append(command)
        return original_run(command, **options)
    monkeypatch.setattr(secure.subprocess, 'run', run_worker)
    cfgpath = save_config(instance)
    settings = Settings.load(cfgpath)
    instance.state_dir.mkdir(exist_ok=True)
    with closing(sqlite3.connect(settings.database)) as db:
        db.executescript((PLUGIN/'scripts/backup_schemas/7.sql').read_text())
        db.execute("INSERT INTO sends(key,owner,payload_hash,state,created,updated) VALUES('legacy',?,'digest','sending',1,1)",
                   (settings.owner_subject,))
        db.commit()
    register_external_identity(settings)
    original = cfgpath.read_bytes(), settings.state_identity_file.read_bytes(), settings.database.read_bytes()
    monkeypatch.setattr(admin, 'initialize_new', lambda *a: pytest.fail('must not initialize an existing runtime'))
    admin.prepare_runtime(instance,host=SimpleNamespace(enroll_runtime=lambda account:commands.append(['host-qos'])))
    assert (cfgpath.read_bytes(), settings.state_identity_file.read_bytes(), settings.database.read_bytes()) == original
    assert len(workers) == 1
    with closing(sqlite3.connect(settings.database)) as db:
        assert db.execute('PRAGMA user_version').fetchone() == (7,)
        assert db.execute("SELECT state FROM sends WHERE key='legacy'").fetchone() == ('sending',)
    assert commands


def test_config_appearing_during_prepare_is_not_overwritten_or_enrolled(runtime, fresh, monkeypatch):
    admin, instance, commands = runtime
    original_render = admin.render_config
    def concurrent(*args, **kwargs):
        rendered = original_render(*args, **kwargs)
        (instance.config_dir/'config.toml').write_text('synthetic concurrent config')
        return rendered
    monkeypatch.setattr(admin, 'render_config', concurrent)
    monkeypatch.setattr(admin, 'initialize_new', lambda *a: pytest.fail('must not enroll concurrently created config'))
    with pytest.raises(FileExistsError):
        admin.prepare_runtime(instance,host=SimpleNamespace(enroll_runtime=lambda account:commands.append(['host-qos'])))
    assert (instance.config_dir/'config.toml').read_text() == 'synthetic concurrent config'
    assert not (instance.state_dir/'archive.sqlite').exists()
    assert not (instance.config_dir/'technical-state.json').exists()
    assert not any('systemctl' in command or 'loginctl' in command for command in commands)


def test_provisioning_rejects_dangling_config_before_any_side_effect(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(PLUGIN/'scripts'))
    script = load_script('provision_host')
    conf = tmp_path/'configuration'
    conf.mkdir()
    (conf/'config.toml').symlink_to(tmp_path/'missing-config')
    monkeypatch.setattr(script, 'CONF', conf)
    monkeypatch.setattr(script, 'os', SimpleNamespace(geteuid=lambda: 0))
    def forbidden(*args, **kwargs):
        pytest.fail('preexisting config must fail before any provisioning side effect')
    monkeypatch.setattr(script, 'register_subject', forbidden)
    monkeypatch.setattr(script, 'initialize_new', forbidden)
    monkeypatch.setattr(script, 'subprocess', SimpleNamespace(run=forbidden))
    with pytest.raises(SystemExit, match='Configuration already exists'):
        script.main(['--host-plan','/synthetic.json','--host-plan-sha256','0'*64])
    assert (conf/'config.toml').is_symlink() and not (tmp_path/'missing-config').exists()
