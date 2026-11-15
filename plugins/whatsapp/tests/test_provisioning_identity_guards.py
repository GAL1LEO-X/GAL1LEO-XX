"""Synthetic provisioning admission: no OS users, services, DNS or accounts."""
from contextlib import contextmanager, nullcontext
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from test_standalone_setup import arguments, discovery, external, load_script
from sally_whatsapp import tenancy


def registry(*instances):
    return {'format': 1, 'instances': {item.slug: {
        'spec': item.record(), 'phase': 'prepared', 'enabled': True,
    } for item in instances}}


def additional(**changes):
    return external(slug='later', bridge_port=8824,
        public_hostname='later.example.org', oauth_client_id='later-mcp',
        pairing_client_id='later-pairing', **changes)


@pytest.mark.parametrize('changed', ['hostname', 'mcp', 'cross-client'])
def test_add_rejects_domain_and_client_collisions_before_host_effects(tmp_path, monkeypatch, changed):
    admin = load_script('tenant_admin', monkeypatch)
    first = external()
    second = additional()
    if changed == 'hostname':
        second = replace(second, public_hostname=first.hostname)
    elif changed == 'mcp':
        second = replace(second, oauth_client_id=first.chatgpt_client)
    else:
        second = replace(second, pairing_client_id=first.chatgpt_client)
    monkeypatch.setattr(admin, 'os', SimpleNamespace(geteuid=lambda: 0, umask=lambda _: None))
    monkeypatch.setattr(admin, 'admit_runtime', lambda: nullcontext())
    monkeypatch.setattr(admin, 'registry', lambda: registry(first))
    monkeypatch.setattr(admin, 'socket', SimpleNamespace(socket=lambda: nullcontext(SimpleNamespace(bind=lambda _: None))))
    monkeypatch.setattr(admin, 'deployment_artifacts', lambda *_: pytest.fail('collision passed admission'))
    with pytest.raises(ValueError, match='already assigned'):
        admin.main(['add', '--user', second.slug, '--name', second.display_name,
                    '--bridge-port', str(second.bridge_port), '--apply', *arguments(second)])


def test_resource_validation_keeps_same_owner_and_distinct_issuer_clients_valid(monkeypatch):
    admin = load_script('tenant_admin', monkeypatch)
    first, second = external(), additional()
    assert first.subject == second.subject  # Same owner may have separate instances.
    admin.validate_instance_resources(second, registry(first))
    different_issuer = replace(second, issuer='https://other-identity.example.net',
                              oauth_client_id=first.chatgpt_client)
    admin.validate_instance_resources(different_issuer, registry(first))
    admin.validate_instance_resources(first, registry(first))


def test_initial_provisioning_rejects_registry_changed_while_waiting_for_lease(tmp_path, monkeypatch):
    script = load_script('provision_host', monkeypatch)
    source = tmp_path / 'source'
    monkeypatch.setattr(script, 'ROOT', source)
    monkeypatch.setattr(script, 'CONF', tmp_path / 'config')
    monkeypatch.setattr(script, 'os', SimpleNamespace(geteuid=lambda: 0))
    monkeypatch.setattr(script, 'deployment_artifacts', lambda _: {})
    monkeypatch.setattr(script, 'discovery_for', lambda item: tenancy.oidc_endpoints(item, discovery(item)))
    @contextmanager
    def admission(_):
        path = source / 'private/tenants.json'
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(registry(additional())))
        yield
    monkeypatch.setattr(script, 'runtime_admission', admission)
    monkeypatch.setattr(script, 'load_host_context', lambda *_: pytest.fail('stale registry reached host mutation'))
    with pytest.raises(ValueError, match='registry changed'):
        script.main(['--host-plan', '/synthetic.json', '--host-plan-sha256', '0' * 64, *arguments()])
    assert json.loads((source / 'private/tenants.json').read_text()) == registry(additional())


@pytest.mark.parametrize('slug', ['administration', 'backup'])
def test_initial_profile_rejects_same_reserved_resources_as_added_roster(slug):
    from pathlib import Path
    from sally_whatsapp.installation import Installation
    profile = json.loads((Path(__file__).resolve().parents[1] / 'deploy/installation.example.json').read_bytes())
    profile['accounts'][slug] = profile['accounts'].pop('team')
    profile['ports'][slug] = profile['ports'].pop('team')
    with pytest.raises(ValueError, match='administrative'):
        Installation.from_dict(profile)


from test_fresh_state_initialization import runtime, fresh


def test_configured_custom_initial_slug_prepares_and_repeats_with_isolated_database(runtime, fresh, monkeypatch):
    """Real config/SQLite initialization; OS users/services and discovery are substituted."""
    from pathlib import Path
    import grp
    from sally_whatsapp.installation import Installation
    from sally_whatsapp.config import Settings
    from sally_whatsapp.state_continuity import StateContinuity
    admin, original, commands = runtime
    profile = json.loads((Path(__file__).resolve().parents[1] / 'deploy/installation.example.json').read_bytes())
    profile['accounts'] = {'fixture': original.service_user}
    profile['ports'] = {'fixture': {'bridge': 22001, 'gateway': 22009}}
    profile = Installation.from_dict(profile)
    monkeypatch.setattr(tenancy, 'active', lambda: profile)
    monkeypatch.setattr(admin, 'installation_profile', lambda: profile)
    instance = replace(original, installation=profile.as_dict(), bridge_port=22001,
        public_hostname='custom.example.test', auth_mode='external-oidc',
        jwks_url=original.effective_jwks_url, oauth_client_id='custom-mcp', pairing_client_id='custom-link')
    monkeypatch.setattr(grp, 'getgrgid', lambda _: SimpleNamespace(gr_name=instance.service_user))
    monkeypatch.setattr(admin, 'grant_project_access', lambda _: None)
    monkeypatch.setattr(admin, 'grant_runtime_access', lambda _: None)
    host = SimpleNamespace(enroll_runtime=lambda account: commands.append(['host-enrollment']))
    admin.prepare_runtime(instance, host=host)
    settings = Settings.load(instance.config_dir / 'config.toml')
    assert not any(getattr(settings, name) for name in (
        'live_account_enabled', 'link_enabled', 'send_enabled', 'allow_all_destinations', 'account_actions_enabled'))
    assert settings.listen_port == 22001 and settings.waha_url == 'http://127.0.0.1:22009'
    StateContinuity(settings, allow_bootstrap=False)
    before = (settings.database.read_bytes(), settings.state_identity_file.read_bytes(),
              (instance.config_dir / 'config.toml').read_bytes())
    admin.prepare_runtime(instance, host=host)
    assert before == (settings.database.read_bytes(), settings.state_identity_file.read_bytes(),
                      (instance.config_dir / 'config.toml').read_bytes())
    assert not any('whatsapp-waha.service' in call or instance.base + '.service' in call for call in commands)


@pytest.mark.parametrize('explicit', [False, True])
def test_fresh_cli_selects_custom_configured_slug_and_preserves_other_rows(tmp_path, monkeypatch, explicit):
    """Exercise main/registry/config rendering; host provisioning remains substituted."""
    from pathlib import Path
    from sally_whatsapp.installation import Installation
    script = load_script('provision_host', monkeypatch)
    data = json.loads((Path(__file__).resolve().parents[1] / 'deploy/installation.example.json').read_bytes())
    data['accounts'] = {'alpha': 'messages-alpha'}
    data['ports'] = {'alpha': {'bridge': 23001, 'gateway': 23009}}
    if explicit:
        data['accounts']['beta'] = 'messages-beta'
        data['ports']['beta'] = {'bridge': 24001, 'gateway': 24009}
    profile = Installation.from_dict(data)
    monkeypatch.setattr(tenancy, 'active', lambda: profile)
    monkeypatch.setattr(script, 'installation_profile', lambda: profile)
    monkeypatch.setitem(script.setup_instance.__globals__, 'installation_profile', lambda: profile)
    monkeypatch.setattr(script, 'ROOT', tmp_path / 'source')
    monkeypatch.setattr(script, 'os', SimpleNamespace(geteuid=lambda: 0))
    monkeypatch.setattr(script, 'runtime_admission', lambda _: nullcontext())
    monkeypatch.setattr(script, 'deployment_artifacts', lambda _: {})
    monkeypatch.setattr(script, 'discovery_for', lambda item: tenancy.oidc_endpoints(item, discovery(item)))
    calls = []
    host = SimpleNamespace(begin_runtime=lambda: calls.append('begin'), close=lambda: calls.append('close'))
    monkeypatch.setattr(script, 'load_host_context', lambda *_: host)
    monkeypatch.setattr(script, 'provision', lambda instance, artifacts, cfg, actual_host: calls.append((instance, cfg)))
    def write_registry(path, content):
        assert path == tmp_path / 'source/private/tenants.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    monkeypatch.setattr(script, 'write_private', write_registry)
    preserved = None
    if explicit:
        other = external(slug='beta', bridge_port=24001, public_hostname='beta.example.org',
            oauth_client_id='beta-mcp', pairing_client_id='beta-link', installation=profile.as_dict())
        preserved = registry(other)['instances']['beta']
        write_registry(script.ROOT / 'private/tenants.json', json.dumps(registry(other)))
    script.main(['--host-plan', '/synthetic.json', '--host-plan-sha256', '0' * 64,
                 *(['--user', 'alpha'] if explicit else []), *arguments()])
    current = json.loads((script.ROOT / 'private/tenants.json').read_text())['instances']
    assert current['alpha']['phase'] == 'prepared'
    assert set(current) == ({'alpha', 'beta'} if explicit else {'alpha'})
    if preserved:
        assert current['beta'] == preserved
    instance, cfg = calls[1]
    assert instance.slug == 'alpha' and instance.bridge_port == 23001 and instance.gateway_port == 23009
    assert str(instance.wrapper) == profile.path('project') + '/private/tenants/alpha/as-user'
    import tomllib
    config = tomllib.loads(cfg)['bridge']
    assert config['database'] == profile.instance_paths('alpha')['state'] + '/archive.sqlite'
    assert config['public_url'] == external().public_url
    assert not config['live_account_enabled'] and not config['link_enabled']


def test_configured_fresh_cli_requires_explicit_selection_for_multiple_instances(monkeypatch):
    from pathlib import Path
    from sally_whatsapp.installation import Installation
    script = load_script('provision_host', monkeypatch)
    profile = Installation.from_dict(json.loads((Path(__file__).resolve().parents[1] / 'deploy/installation.example.json').read_bytes()))
    monkeypatch.setattr(script, 'installation_profile', lambda: profile)
    monkeypatch.setattr(script, 'os', SimpleNamespace(geteuid=lambda: 0))
    monkeypatch.setattr(script, 'discovery_for', lambda *_: pytest.fail('ambiguous selection reached discovery'))
    with pytest.raises(ValueError, match='Select --user explicitly'):
        script.main(['--host-plan', '/synthetic.json', '--host-plan-sha256', '0' * 64, *arguments()])


def test_configured_provision_writes_only_selected_private_wrapper(runtime, fresh, monkeypatch, tmp_path):
    from pathlib import Path
    import grp
    import os
    from sally_whatsapp.installation import Installation
    from sally_whatsapp.config import Settings
    from sally_whatsapp.state_continuity import StateContinuity
    _, original, _ = runtime
    script = load_script('provision_host', monkeypatch)
    values = json.loads((Path(__file__).resolve().parents[1] / 'deploy/installation.example.json').read_bytes())
    values['accounts'] = {'fixture': original.service_user}
    values['ports'] = {'fixture': {'bridge': 22001, 'gateway': 22009}}
    profile = Installation.from_dict(values)
    monkeypatch.setattr(tenancy, 'active', lambda: profile)
    class IsolatedInstance(type(original)):
        @property
        def project_root(self):
            return tmp_path / 'source'
    fields = original.record() | {'installation':profile.as_dict(), 'bridge_port':22001,
        'public_hostname':'custom.example.test', 'auth_mode':'external-oidc',
        'jwks_url':original.effective_jwks_url, 'oauth_client_id':'custom-mcp', 'pairing_client_id':'custom-link'}
    instance = IsolatedInstance(**fields)
    old_wrapper = instance.project_root / 'scripts/as-user'
    old_wrapper.parent.mkdir(parents=True)
    old_wrapper.write_bytes(b'preserved wrapper for another instance')
    monkeypatch.setattr(script, 'os', SimpleNamespace(chown=lambda *_: None, chmod=os.chmod, umask=lambda *_: None))
    monkeypatch.setattr(grp, 'getgrgid', lambda _: SimpleNamespace(gr_name=instance.service_user))
    monkeypatch.setattr(script, 'grant_project_access', lambda _: None)
    monkeypatch.setattr(script, 'grant_runtime_access', lambda _: None)
    real_path = Path
    monkeypatch.setattr(script, 'Path', lambda value: tmp_path / str(value).lstrip('/')
                        if str(value).startswith('/etc/') else real_path(value))
    (tmp_path / 'etc/systemd/system').mkdir(parents=True)
    commands = []
    def run(args, **kwargs):
        commands.append([str(arg) for arg in args])
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(script, 'run', run)
    host = SimpleNamespace(enroll_runtime=lambda _: None, ensure_https=lambda _: {'qos_frontend':'not-configured'})
    cfg = tenancy.render_config(instance, authorize_url=instance.issuer+'/authorize', token_url=instance.issuer+'/token', live_enabled=False)
    script.provision(instance, {'bridge':'synthetic bridge', 'gateway':'synthetic gateway', 'apache':'synthetic apache'}, cfg, host)
    assert old_wrapper.read_bytes() == b'preserved wrapper for another instance'
    assert instance.wrapper != old_wrapper and instance.wrapper.is_file()
    assert instance.wrapper.stat().st_mode & 0o777 == 0o700
    assert any(command[0] == str(instance.wrapper) for command in commands)
    assert not any(command[0] == str(old_wrapper) for command in commands)
    StateContinuity(Settings.load(instance.config_dir/'config.toml'), allow_bootstrap=False)
