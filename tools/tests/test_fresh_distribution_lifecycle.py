"""Cold configured setup on real private files; privileged effects are explicit fakes.

This complements the admission/upgrade/retirement suites. It does not certify
systemd, Unix ownership/ACLs, containers, DNS/TLS or an actual OIDC/WAHA service.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


REPOSITORY = Path(__file__).resolve().parents[2]
PLUGIN = REPOSITORY / 'plugins/whatsapp'
CAPABILITIES = ('live_account_enabled', 'link_enabled', 'send_enabled',
                'allow_all_destinations', 'account_actions_enabled')


def _cold_materialization(root, name):
    """Child-only harness: no conftest-selected legacy identity can enter it."""
    from contextlib import closing, nullcontext
    import grp
    import pwd
    import shutil
    import sqlite3
    from types import SimpleNamespace

    root = Path(root)
    sys.path[:0] = [str(PLUGIN), str(PLUGIN / 'scripts')]
    forbidden = ('/etc/whatsapp-installation', '/etc/box-installation',
                 '/srv/openai-codex', '/var/lib/sally-browser')
    logical_roots = ()
    database_workers = []
    allowed_databases = {}

    def audit(event, args):
        if event == 'subprocess.Popen':
            executable, argv, cwd, environment = args
            assert executable == sys.executable and list(argv[:5]) == [sys.executable, '-I', '-B', '-', 'verify']
            assert len(argv) == 6 and cwd == '/' and environment == {}
            selected_database = json.loads(argv[5])
            assert selected_database['database'] in allowed_databases
            assert selected_database['expected'] == allowed_databases[selected_database['database']]
            assert selected_database['uid'] == os.getuid() > 0
            assert selected_database['gid'] == os.getgid() > 0
            assert selected_database['groups'] == os.getgroups()
            database_workers.append(selected_database['database'])
        if event in ('socket.connect', 'socket.bind'):
            raise AssertionError('Fresh fixture attempted a real network operation')
        if event == 'open' and isinstance(args[0], str) and args[0].startswith(forbidden):
            raise AssertionError('Fresh fixture attempted a legacy or installed-identity read')
        if event in ('open', 'sqlite3.connect', 'os.mkdir', 'os.remove', 'os.rmdir',
                     'os.rename', 'os.chmod', 'os.chown', 'os.link', 'os.symlink',
                     'os.truncate', 'os.utime') and any(
                argument == path or argument.startswith(path + '/')
                for argument in args if isinstance(argument, str) for path in logical_roots):
            raise AssertionError('Fresh fixture attempted I/O outside the projected physical root')
    sys.addaudithook(audit)

    import installation_layout as layout
    from sally_whatsapp import installation as backend_layout
    assert 'sally_whatsapp.tenancy' not in sys.modules
    value = json.loads((PLUGIN / 'deploy/installation.example.json').read_bytes())
    value['paths'] = {'project': '/srv/fresh-' + name + '/application',
        'configuration': '/etc/fresh-' + name, 'state': '/var/lib/fresh-' + name + '-state',
        'gateway': '/var/lib/fresh-' + name + '-gateway', 'backup': '/opt/fresh-' + name + '-backup',
        'administration_code': '/opt/fresh-' + name + '-administration',
        'administration_state': '/var/lib/fresh-' + name + '-administration'}
    value['services'] = {'prefix': name + '-wa', 'recovery': name + '-recover'}
    value['accounts'] = {'personal': name + '-owner', 'team': name + '-colleague'}
    first_port = 19301 if name == 'alpha' else 28321
    value['ports'] = {'personal': {'bridge': first_port, 'gateway': first_port + 8},
                      'team': {'bridge': first_port + 31, 'gateway': first_port + 48}}
    selected = layout.Installation.from_dict(value)
    logical_roots = tuple(value['paths'].values())
    # Reproduce the CI failure as a pathname validation case without requiring
    # writes under /home. Neither volatile nor ProtectHome-hidden paths become
    # valid installation profiles merely because a fixture uses that location.
    for rejected_root in ('/home/runner/work/PLUGINS/PLUGINS/work/fresh', '/tmp/fresh'):
        rejected = {**value, 'paths': {field: rejected_root + '/' + field for field in value['paths']}}
        for module in (layout, backend_layout):
            with pytest.raises(ValueError, match='Installation roots must be durable'):
                module.Installation.from_dict(rejected)
    host_root = root / 'host'
    etc = host_root / 'etc'
    etc.mkdir(parents=True, mode=0o700)
    (etc / 'systemd/system').mkdir(parents=True)
    marker = host_root / layout.IDENTITY.relative_to('/')
    locator = host_root / layout.PROFILE.relative_to('/')
    marker.write_bytes(layout.identity_bytes(selected)); marker.chmod(0o600)
    locator.write_bytes(selected._encoded); locator.chmod(0o600)
    layout.activate_installation(root=host_root, trusted_uid=os.getuid())
    backend_layout.activate_installation(root=host_root, trusted_uid=os.getuid())
    # Fixture-only filesystem projection. The admitted profile bytes, digest,
    # constructor and canonical-path validator remain the production versions.
    # Rendered runtime paths and actual I/O use this physical test root until
    # the separate logical-render assertion at the end restores these methods.
    original_paths = {module: module.Installation.path for module in (layout, backend_layout)}
    for module, original in original_paths.items():
        def projected_path(profile, field, original=original):
            assert not profile.compatibility
            return str(host_root / Path(original(profile, field)).relative_to('/'))
        module.Installation.path = projected_path
    physical_paths = {field: Path(selected.path(field)) for field in value['paths']}
    for path in physical_paths.values():
        path.mkdir(parents=True, mode=0o700)
    project = physical_paths['project']
    (project / 'scripts').mkdir()
    (project / 'private').mkdir(mode=0o700)
    shutil.copytree(PLUGIN / 'deploy', project / 'deploy')
    for name_ in ('subuid', 'subgid'):
        (etc / name_).write_text(''.join(account + ':' + str(100000 + i * 65536) + ':65536\n'
            for i, account in enumerate(value['accounts'].values())))

    import tenant_admin as admin
    import tenant_database as database_admin
    import provision_host as provision
    from sally_whatsapp.config import Settings
    from sally_whatsapp import state_initialization as initialization
    from sally_whatsapp.state_continuity import StateContinuity, STATE_KEY
    from sally_whatsapp.tenancy import Instance

    commands, ownership, frontend, enrollments, network = [], [], [], [], []
    # Host admission and physical root ownership have separate integration tests.
    # Here only real private paths are allowed, and ownership intents are recorded.
    def fixture_preflight():
        assert layout.active().sha256 == selected.sha256
        assert layout.active().as_dict() == backend_layout.active().as_dict() == value
        for path in physical_paths.values():
            assert path.resolve(strict=True) == path
            assert path.is_relative_to(host_root)
            assert path.stat().st_uid == os.getuid()
            assert not path.stat().st_mode & 0o022
    layout.preflight_roots = fixture_preflight
    os_adapter = SimpleNamespace(**{key: getattr(os, key) for key in dir(os) if not key.startswith('__')})
    os_adapter.chown = lambda path, uid, gid, **kwargs: ownership.append((str(path), uid, gid))
    os_adapter.fchown = lambda fd, uid, gid: ownership.append(('database-fd', uid, gid))
    os_adapter.geteuid = lambda: 0
    initialization.os = os_adapter
    initialization._administrative_directory = lambda path: (
        path.stat().st_uid == os.getuid() and not path.stat().st_mode & 0o022)
    provision.os = admin.os = os_adapter
    original_path = Path
    def administrative_path(path):
        path = original_path(path)
        return host_root / path.relative_to('/') if str(path).startswith('/etc/') else path
    provision.Path = admin.Path = administrative_path
    identities = {account: SimpleNamespace(pw_uid=4101 + i, pw_gid=5101 + i,
        pw_dir=str(physical_paths['gateway'] / slug), pw_shell='/usr/sbin/nologin')
        for i, (slug, account) in enumerate(value['accounts'].items())}
    pwd.getpwnam = identities.__getitem__
    grp.getgrgid = lambda gid: SimpleNamespace(gr_name=next(
        account for account, row in identities.items() if row.pw_gid == gid))
    # The filesystem belongs to this unprivileged test runner. Project only
    # the helper's trust root and account lookup; keep its actual protected
    # path checks, parent admission, worker source, SQLite and identity checks.
    database_admin._TRUST_ROOT = host_root
    database_admin._TRUST_UID = os.getuid()
    def database_account(account):
        assert account in identities
        return SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
    database_admin.pwd = SimpleNamespace(getpwnam=database_account)
    worker_source = Path(database_admin.__file__).read_bytes()
    verified_databases = []
    def database_process(argv, **options):
        assert options['input'] == worker_source
        assert options['close_fds'] is True and options['check'] is True
        assert options['stdout'] == options['stderr'] == subprocess.DEVNULL
        result = subprocess.run(argv, **options)
        verified_databases.append(json.loads(argv[-1])['database'])
        return result
    database_admin.subprocess = SimpleNamespace(run=database_process, DEVNULL=subprocess.DEVNULL)
    loaded_bridges = {}
    def command(args, **kwargs):
        commands.append([str(item) for item in args])
        if args[:2] == ['systemctl', 'restart']:
            slug = next(slug for slug in value['accounts'] if args[2] == selected.service(slug) + '.service')
            loaded_bridges[slug] = Settings.load(physical_paths['configuration'] / slug / 'config.toml')
        return SimpleNamespace(returncode=1 if 'inspect' in args else 0, stdout=b'', stderr=b'')
    provision.run = admin.run = admin.command = command
    provision.grant_project_access = admin.grant_project_access = lambda instance: commands.append(['acl-project', instance.service_user])
    provision.grant_runtime_access = admin.grant_runtime_access = lambda instance: commands.append(['acl-runtime', instance.service_user])
    provision.runtime_admission = lambda *args: nullcontext()
    admin.admit_runtime = lambda: nullcontext()
    def context(instance, *args):
        return SimpleNamespace(begin_runtime=lambda: None, close=lambda: None,
            resumes_runtime=lambda: False,
            enroll_runtime=lambda account: enrollments.append(account.pw_uid),
            ensure_https=lambda text: (frontend.append(text) or {'qos_frontend': False}))
    provision.load_host_context = admin.load_host_context = context
    admin.socket = SimpleNamespace(socket=lambda: nullcontext(SimpleNamespace(bind=lambda address: None)))

    issuer = 'https://identity-' + name + '.example.net/realm'
    jwks = 'https://keys-' + name + '.example.net/public.json'
    def response(payload):
        return SimpleNamespace(is_success=True, status_code=200, raise_for_status=lambda: None, json=lambda: payload)
    def discovery(url, **kwargs):
        assert url == issuer + '/.well-known/openid-configuration'
        network.append(('discovery', url))
        return response({'issuer': issuer, 'jwks_uri': jwks,
            'authorization_endpoint': issuer + '/authorize', 'token_endpoint': issuer + '/token'})
    sessions = {}
    class Gateway:
        def __init__(self, *, base_url, headers=None, **kwargs):
            self.slug, self.kind = next((slug, kind) for slug, ports in value['ports'].items()
                for kind in ('gateway', 'bridge') if base_url == 'http://127.0.0.1:' + str(ports[kind]))
            if self.kind == 'gateway':
                assert headers == {'X-Api-Key': (physical_paths['configuration'] / self.slug / 'waha.key').read_text().strip()}
            else:
                assert headers is None

        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, path, **kwargs):
            if self.kind == 'bridge':
                assert path in ('/healthz', '/connect')
                loaded = loaded_bridges[self.slug]
                assert loaded.live_account_enabled and loaded.link_enabled
                network.append(('bridge-readiness', self.slug, path))
                return response({'readiness': {'ready': True, 'workers': {'portal': True}}})
            assert path in ('/api/version', '/api/sessions')
            network.append(('get', self.slug, path))
            return response(sessions.get(self.slug, []) if path == '/api/sessions' else {})
        def post(self, path, *, json):
            assert self.kind == 'gateway'
            assert path == '/api/sessions' and json['start'] is False
            assert self.slug not in sessions
            webhook = json['config']['webhooks'][0]
            assert webhook['url'] == 'http://10.0.2.2:' + str(value['ports'][self.slug]['bridge']) + '/webhooks/waha'
            assert 'engine.event' in webhook['events']
            assert webhook['hmac']['key'] == (physical_paths['configuration'] / self.slug / 'webhook.key').read_text().strip()
            sessions[self.slug] = [{'name': 'default'}]
            network.append(('create-unstarted-session', self.slug))
            return response({})
    admin.httpx = SimpleNamespace(get=discovery, Client=Gateway, HTTPError=RuntimeError)

    def arguments(slug):
        return ['--hostname', name + '-' + slug + '.example.org', '--issuer', issuer,
            '--jwks-url', jwks, '--subject', name + '|owner|' + slug,
            '--oauth-client-id', name + '-' + slug + '-mcp', '--link-client-id', name + '-' + slug + '-pair',
            '--chatgpt-callback', 'https://client-' + name + '.example.net/oauth/callback',
            '--auth-mode', 'external-oidc', '--host-plan', '/synthetic-reviewed-host-plan.json',
            '--host-plan-sha256', 'a' * 64]
    # A multi-instance profile must not silently choose its legacy-looking slug.
    # Reject ambiguity before discovery, account preparation or private writes.
    before_selection = {str(path): path.read_bytes() for path in root.rglob('*') if path.is_file()}
    with pytest.raises(ValueError, match='Select --user explicitly'):
        provision.main(['--name', 'Synthetic primary', *arguments('personal')])
    assert {str(path): path.read_bytes() for path in root.rglob('*') if path.is_file()} == before_selection
    assert not any((commands, ownership, frontend, enrollments, network, sessions))
    provision.main(['--user', 'personal', '--name', 'Synthetic primary', *arguments('personal')])
    admin.main(['add', '--apply', '--user', 'team', '--name', 'Synthetic colleague', *arguments('team')])
    registry = admin.registry()
    assert set(registry['instances']) == {'personal', 'team'}
    assert all(row['phase'] == 'prepared' for row in registry['instances'].values())
    assert not sessions
    assert not any('whatsapp-waha.service' in cmd or ('--now' in cmd) for cmd in commands)
    markers, keys = [], []
    for slug, row in registry['instances'].items():
        assert row['spec']['installation'] == value
        instance = Instance(**row['spec'])
        config = Settings.load(instance.config_dir / 'config.toml')
        assert all(getattr(config, flag) is False for flag in CAPABILITIES)
        assert config.database == instance.state_dir / 'archive.sqlite'
        assert config.issuer == issuer and config.jwks_url == jwks
        assert (instance.config_dir / 'config.toml').stat().st_mode & 0o777 == 0o640
        assert config.database.stat().st_mode & 0o777 == 0o600
        assert config.state_identity_file.stat().st_mode & 0o777 == 0o640
        identity = json.loads(config.state_identity_file.read_bytes())
        with closing(sqlite3.connect(config.database)) as db:
            assert db.execute('PRAGMA user_version').fetchone() == (8,)
            assert json.loads(db.execute('SELECT value FROM state WHERE key=?', (STATE_KEY,)).fetchone()[0]) == identity
            assert db.execute('SELECT count(*) FROM action_jobs').fetchone() == (0,)
            assert db.execute('SELECT count(*) FROM subscriptions').fetchone() == (0,)
        assert StateContinuity(config, allow_bootstrap=False).expected == identity
        markers.append(identity)
        allowed_databases[str(config.database)] = identity
        keys.extend((instance.config_dir / file).read_bytes() for file in ('waha.key', 'webhook.key', 'encryption.key'))
        assert all((instance.config_dir / file).stat().st_mode & 0o777 == 0o640
                   for file in ('waha.key', 'webhook.key', 'encryption.key'))
        assert list((instance.gateway_home / 'sessions').iterdir()) == []
        unit = (etc / 'systemd/system' / (instance.base + '.service')).read_text()
        quadlet = (instance.gateway_home / '.config/containers/systemd/whatsapp-waha.container').read_text()
        assert 'User=' + instance.service_user in unit and 'WorkingDirectory=' + str(project) in unit
        assert str(config.database.parent) in unit and 'CPUAffinity=' not in quadlet
        assert 'PublishPort=127.0.0.1:' + str(instance.gateway_port) + ':3000' in quadlet
        assert str(instance.gateway_home / 'sessions') in quadlet
        assert instance.service_user in instance.wrapper.read_text()
    assert len({row['id'] for row in markers}) == len({row['tenant'] for row in markers}) == 2
    assert len(set(keys)) == 6
    assert set(enrollments) == {4101, 4102} and len(frontend) == 2 and ownership

    # Adding the already prepared tenant does not activate it or rewrite its state.
    original = {str(path): path.read_bytes() for path in root.rglob('*') if path.is_file()}
    before_commands = list(commands)
    admin.main(['add', '--apply', '--user', 'team', *arguments('team')])
    assert commands == before_commands
    assert {path: Path(path).read_bytes() for path in original} == original

    # A copied marker from the other tenant is rejected before any service action.
    team = Instance(**registry['instances']['team']['spec'])
    team_marker = team.config_dir / 'technical-state.json'
    original_marker = team_marker.read_bytes()
    team_marker.write_bytes(json.dumps(markers[0]).encode())
    with pytest.raises(RuntimeError, match='Tenant database identity or filesystem safety check failed'):
        admin.main(['enable-linking', '--apply', '--user', 'team', *arguments('team')])
    assert commands == before_commands and not sessions
    team_marker.write_bytes(original_marker)

    for slug in ('personal', 'team'):
        # Read-only is an explicit selection; the other tenant exercises the
        # complete default profile without legacy write-enabling flags.
        capabilities = ['--capabilities', 'read-only'] if slug == 'personal' else []
        admin.main(['enable-linking', '--apply', '--user', slug, *arguments(slug), *capabilities])
        instance = Instance(**registry['instances'][slug]['spec'])
        config = Settings.load(instance.config_dir / 'config.toml')
        assert config.live_account_enabled and config.link_enabled
        assert all(getattr(config, flag) is (slug == 'team') for flag in CAPABILITIES[2:])
        assert json.loads(config.state_identity_file.read_bytes()) == markers[0 if slug == 'personal' else 1]
    assert set(sessions) == {'personal', 'team'}
    assert sum(event[0] == 'create-unstarted-session' for event in network) == 2
    # Reconciliation preserves observed sessions; it cannot recreate or pair them.
    admin.main(['enable-linking', '--apply', '--user', 'personal', *arguments('personal'), '--capabilities', 'full'])
    for slug in ('personal', 'team'):
        config = Settings.load(physical_paths['configuration'] / slug / 'config.toml')
        assert all(getattr(config, flag) is True for flag in CAPABILITIES)
        assert set(config.oauth_allowed_scopes) == {'whatsapp:read', 'whatsapp:send', 'whatsapp:events'}
        assert config.oauth_consent_scopes == config.oauth_allowed_scopes
        assert all(getattr(loaded_bridges[slug], flag) is True for flag in CAPABILITIES)
    assert len(database_workers) == len(verified_databases) == 3
    assert set(verified_databases) == set(allowed_databases)
    assert len([event for event in network if event[0] == 'bridge-readiness']) == 6
    assert sum(event[0] == 'create-unstarted-session' for event in network) == 2
    assert not (etc / 'box-installation-identity.json').exists()
    for module, original in original_paths.items():
        module.Installation.path = original
    from sally_whatsapp.tenancy import deployment_artifacts
    for row in registry['instances'].values():
        instance = Instance(**row['spec'])
        artifacts = deployment_artifacts(instance, template_root=project / 'deploy')
        assert 'WorkingDirectory=' + value['paths']['project'] + '\n' in artifacts['bridge']
        assert str(instance.config_dir / 'config.toml') in artifacts['bridge']
        assert str(instance.state_dir) in artifacts['bridge']
        assert str(instance.gateway_home / 'sessions') in artifacts['gateway']
        assert all(str(host_root) not in content for content in artifacts.values())
    assert layout.active().as_dict() == backend_layout.active().as_dict() == value
    print(json.dumps({'fixture': name, 'real_database_schema': 8, 'distinct_tenants': 2,
        'configured_identity': selected.sha256, 'real_materialized_files': True,
        'logical_profile_and_rendering_verified': True, 'physical_paths_projected_for_fixture': True,
        'home_and_tmp_profiles_rejected': True,
        'unprivileged_database_worker_verified': True,
        'host_admission_ownership_acl_systemd_network': 'simulated', 'real_host_changed': False}))


@pytest.mark.skipif(os.name != 'posix', reason='Protected identity fixtures require POSIX')
@pytest.mark.parametrize('name', ['alpha', 'bravo'])
def test_cold_two_tenant_fresh_setup_and_explicit_activation(name, tmp_path):
    # Host paths stay logical; the pytest temporary root may live anywhere,
    # including /tmp or a /home/runner checkout hidden by production hardening.
    driver = 'import runpy,sys; runpy.run_path(sys.argv[1])["_cold_materialization"](sys.argv[2],sys.argv[3])'
    result = subprocess.run([sys.executable, '-I', '-B', '-c', driver,
        str(Path(__file__).resolve()), str(tmp_path), name], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr + result.stdout
    receipt = json.loads(result.stdout.splitlines()[-1])
    assert receipt['real_database_schema'] == 8 and receipt['distinct_tenants'] == 2
    assert receipt['logical_profile_and_rendering_verified'] is True
    assert receipt['physical_paths_projected_for_fixture'] is True
    assert receipt['home_and_tmp_profiles_rejected'] is True
    assert receipt['unprivileged_database_worker_verified'] is True
    assert receipt['host_admission_ownership_acl_systemd_network'] == 'simulated'
    assert receipt['real_host_changed'] is False
