"""Fresh compiler + actual filesystem/adapter on temporary roots, no services."""
import json
import importlib.util
from pathlib import Path
import sys

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]


def load(name, relative, **injected):
    scope = {'__name__': name, '__file__': str(REPOSITORY / relative), **injected}
    exec(compile((REPOSITORY / relative).read_bytes(), str(REPOSITORY / relative), 'exec'), scope)
    return type('Module', (), scope)


fresh = load('fresh_test', 'host/frontend/fresh_profile.py')
provider = load('fresh_provider_test', 'host/frontend/provider.py')
engine = load('fresh_engine_test', 'host/lifecycle/filesystem.py')
adapter = load('fresh_adapter_test', 'host/frontend/adapter.py', _PINNED_PROVIDER=provider)
builder = load('fresh_bundle_test', 'host/build_bundle.py')
installer = load('fresh_install_test', 'host/install_bundle.py')
_spec = importlib.util.spec_from_file_location('fresh_fixture_installation', REPOSITORY / 'host/installation.py')
installation = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = installation
_spec.loader.exec_module(installation)
# Historical fixture identity is explicit; absence of a real host locator is
# never used to authorize the test or to reintroduce a production fallback.
installation.select(installation.Installation.legacy())


def directory(base, name, mode=0o755):
    target = base / name.lstrip('/')
    missing = []
    current = target
    while current != base and not current.exists(): missing.append(current); current = current.parent
    for item in reversed(missing): item.mkdir(); item.chmod(0o755)
    target.chmod(mode)
    return target


def put(root, name, data, mode=0o644):
    selected = root.base / name.lstrip('/')
    directory(root.base, str(Path(name).parent))
    selected.write_bytes(data); selected.chmod(mode)
    return selected


class Commands:
    def __init__(self): self.calls = []
    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if Path(argv[0]).name == 'dig':
            assert argv[1] in ('@127.0.0.1', '@192.0.2.53')
            assert argv[2:] == ['chat.example.test', 'A', '+short']
            return b'192.0.2.42\n'
        if '-t' in argv:
            body = Path(argv[argv.index('-f') + 1]).read_text()
            assert 'BoxPriorityDSCP' not in body and 'box_priority_module' not in body
            assert 'ServerName chat.example.test' in body
            assert '%O' not in body
            return b'Syntax accepted by synthetic command fixture, not real Apache\n'
        assert argv[1:] == ['reload', 'apache2.service']
        assert kwargs['pass_fds']
        return b''


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, 'installation_layout', installation)
    monkeypatch.setitem(sys.modules, 'sally_whatsapp.installation', installation)
    base = tmp_path / 'root'; base.mkdir(); base.chmod(0o700)
    with engine.Root(base) as root:
        for selected in fresh.PREREQUISITES: directory(base, selected)
        bundle = tmp_path / 'bundle'
        metadata = builder.build(REPOSITORY, bundle, source_revision='a' * 40)
        loaded = installer.load_bundle(bundle, builder.sha(builder.encoded(metadata)))
        installer.install(root, loaded, engine)
        generation = {'path': metadata['destination'], 'sha256': metadata['generation']}
        dependencies = {}
        for name in set(fresh.MODULE_PATHS) | set(fresh.TOOLS.values()) | {fresh.LOCK_SOURCE, '/etc/mime.types'}:
            put(root, name, ('public package fixture: ' + name + '\n').encode(),
                0o755 if name in fresh.TOOLS.values() else 0o644)
            dependencies[name] = root.snapshot(name)
        tools = {}
        for name, selected in {**fresh.INTEGRATION_TOOLS, 'python': '/usr/bin/python3.13'}.items():
            put(root, selected, b'public tool fixture; never executed\n', 0o755)
            tools[name] = {'path': selected, 'metadata': root.snapshot(selected)}
        config = {'format': 1, 'operation_id': 'a' * 32, 'apache': {'user': 'www-data', 'group': 'www-data'},
            'package_main': None, 'dependencies': dependencies, 'integration_tools': tools,
            'instance': {'slug': 'team', 'account': 'wa-team', 'hostname': 'chat.example.test',
                         'bridge_port': 8822, 'gateway_port': 8823},
            'dns': {'address': '192.0.2.42', 'zone': 'example.test', 'local_resolver': '127.0.0.1',
                    'public_resolver': '192.0.2.53'}}
        yield root, config, generation, metadata


def compile_profile(prepared):
    root, config, generation, _ = prepared
    return fresh.build(root, config, generation=generation, provider=provider, adapter=adapter,
                       engine=engine, installation=installation)


def publish(root, result, commands):
    adapter._prepare_state(root, engine)
    host = adapter.HostAdapter(root, engine, result['registry'], result['profile'], runner=commands)
    with host.lease():
        return adapter.apply_configuration(host, operation_id=result['frontend_operation_id'],
            before=result['before'], pinned_artifacts=result['pinned_artifacts'])


def test_fresh_empty_registry_actual_publication_and_cold_replay(prepared):
    root, config, generation, metadata = prepared
    result = compile_profile(prepared)
    assert result['registry']['consumers'] == result['registry']['lineages'] == {}
    assert result['profile']['includes'][0]['targets'] == []
    assert result['host_plan']['qos'] is None
    assert result['host_plan']['frontend']['dns_mode'] == 'preconfigured'
    assert set(result['host_plan']['tools']) == {'dig', 'certbot', 'python'}
    assert not root.snapshot(provider.REGISTRY)
    assert metadata['entrypoints']['frontend_fresh'].endswith('/host/frontend/fresh_profile.py')
    assert metadata['bootstrap']['frontend_fresh']['path'].endswith('/frontend-fresh-sources.json')
    commands = Commands()
    assert publish(root, result, commands)['phase'] == 'complete'
    assert root.read_bytes(provider.REGISTRY) == provider.encoded(result['registry'])
    assert root.read_bytes(adapter.PROFILE) == provider.encoded(result['profile'])
    assert all(root.link(name)['target'] == item['target'] for name, item in result['registry']['links'].items())
    with engine.Root(root.base) as cold:
        assert publish(cold, result, commands)['phase'] == 'complete'
    assert sum(call[1:] == ['reload', 'apache2.service'] for call in commands.calls) == 1
    assert not (root.base / 'etc/box').exists() and not (root.base / 'etc/develative-host-qos').exists()


def test_named_package_main_before_is_exact_and_replaced_only_by_explicit_apply(prepared):
    root, config, _, _ = prepared
    original = b'# nominated fresh package main\n'
    put(root, fresh.MAIN, original)
    config['package_main'] = root.snapshot(fresh.MAIN)
    result = compile_profile(prepared)
    assert root.read_bytes(fresh.MAIN) == original
    assert result['before']['files'][fresh.MAIN]['sha256'] == fresh.sha(original)
    assert publish(root, result, Commands())['phase'] == 'complete'
    assert root.read_bytes(fresh.MAIN) == result['pinned_artifacts'][fresh.MAIN]


def test_package_preimage_drift_after_compile_cannot_publish(prepared):
    root, config, _, _ = prepared
    put(root, fresh.MAIN, b'original\n'); config['package_main'] = root.snapshot(fresh.MAIN)
    result = compile_profile(prepared)
    put(root, fresh.MAIN, b'drift\n')
    commands = Commands()
    with pytest.raises(ValueError): publish(root, result, commands)
    assert root.read_bytes(fresh.MAIN) == b'drift\n'
    assert not root.snapshot(provider.REGISTRY)
    assert not any(call[1:] == ['reload', 'apache2.service'] for call in commands.calls)


@pytest.mark.parametrize('fault', ('unattested-main', 'wrong-main', 'hook-collision', 'foreign-route',
    'dependency-drift', 'dependency-missing', 'tool-drift', 'invalid-user', 'invalid-hostname',
    'invalid-port', 'unknown-key', 'prior-registry', 'prior-renewal-hook'))
def test_invalid_or_existing_environment_stops_read_only(prepared, fault):
    root, config, _, _ = prepared
    if fault == 'unattested-main': put(root, fresh.MAIN, b'not nominated\n')
    elif fault == 'wrong-main':
        put(root, fresh.MAIN, b'one\n'); config['package_main'] = root.snapshot(fresh.MAIN)
        put(root, fresh.MAIN, b'two\n')
    elif fault == 'hook-collision': put(root, fresh.HOOK_ROOT + '/legacy-post', b'prior hook\n', 0o700)
    elif fault == 'foreign-route': put(root, '/etc/apache2/sites-enabled/unmanaged.conf', b'foreign\n')
    elif fault == 'dependency-drift': put(root, next(iter(fresh.MODULE_PATHS)), b'changed\n')
    elif fault == 'dependency-missing': config['dependencies'].pop(next(iter(fresh.MODULE_PATHS)))
    elif fault == 'tool-drift': put(root, '/usr/bin/dig', b'changed\n', 0o755)
    elif fault == 'invalid-user': config['apache']['user'] = 'www-data\nLoadModule injected'
    elif fault == 'invalid-hostname': config['instance']['hostname'] = 'https://example.test/path'
    elif fault == 'invalid-port': config['instance']['bridge_port'] = True
    elif fault == 'unknown-key': config['qos'] = None
    elif fault == 'prior-registry': put(root, provider.REGISTRY, b'{}\n', 0o600)
    elif fault == 'prior-renewal-hook': put(root, '/etc/letsencrypt/renewal-hooks/post/foreign', b'foreign\n')
    before = {str(p.relative_to(root.base)): p.read_bytes() for p in root.base.rglob('*') if p.is_file()}
    with pytest.raises((ValueError, OSError)): compile_profile(prepared)
    assert before == {str(p.relative_to(root.base)): p.read_bytes() for p in root.base.rglob('*') if p.is_file()}


def test_package_exclusive_write_hashes_no_activation(prepared):
    root, _, _, _ = prepared
    built = compile_profile(prepared)
    receipt = fresh.write_package(root, '/etc/fresh-review', built)
    assert receipt['activated'] is False and receipt['private_material_read'] is False
    for name, digest in receipt['files'].items():
        assert fresh.sha(root.read_bytes('/etc/fresh-review/' + name)) == digest
    assert not root.snapshot(provider.REGISTRY)
    with pytest.raises(ValueError): fresh.write_package(root, '/etc/fresh-review', built)
    assert json.loads(root.read_bytes('/etc/fresh-review/package.json')) == receipt


def test_duplicate_json_cannot_select_a_second_origin():
    with pytest.raises(ValueError, match='Duplicate'):
        fresh.decode(b'{"hostname":"one.example.test","hostname":"two.example.test"}')


def test_generated_plan_is_accepted_by_actual_standalone_integration(prepared):
    from sally_whatsapp import tenancy
    from sally_whatsapp.tenancy import Instance
    assert Path(tenancy.__file__).resolve() == REPOSITORY / 'plugins/whatsapp/sally_whatsapp/tenancy.py'
    integration = load('fresh_wa_integration_test', 'plugins/whatsapp/scripts/host_integration.py')
    root, config, _, _ = prepared
    built = compile_profile(prepared); publish(root, built, Commands())
    instance = Instance('team', 'Team', 'oidc-subject', 8822, public_hostname='chat.example.test',
        issuer='https://login.example.test', jwks_url='https://login.example.test/jwks',
        chatgpt_callback='https://client.example.test/callback', auth_mode='external-oidc',
        oauth_client_id='mcp-client', pairing_client_id='pairing-client')
    plan = built['host_plan']
    host = integration.Integration(instance, plan, fresh.sha(fresh.encoded(plan)), root_path=root.base,
                                   runner=Commands())
    assert host.preflight() is host
    assert host.plan['frontend']['registry']['consumers'] == {}
    assert 'virtualmin' not in host.plan['tools']
    host.root.close()


def test_incomplete_template_has_no_invented_package_identity(prepared):
    root, _, generation, _ = prepared
    candidate = fresh.input_template()
    assert all(value['sha256'] is None for value in candidate['dependencies'].values())
    with pytest.raises(ValueError):
        fresh.build(root, candidate, generation=generation, provider=provider, adapter=adapter,
                    engine=engine, installation=installation)


@pytest.mark.parametrize('slug,bridge,gateway', [('x', 8822, 8823), ('bad--slug', 8822, 8823),
    ('a' * 21, 8822, 8823), ('team', 8820, 8821), ('personal', 8822, 8823),
    ('team', 8823, 8824), ('team', 9000, 9001), ('team', 8822, 8825)])
def test_impossible_instance_is_rejected_before_plan_generation(prepared, slug, bridge, gateway):
    _, config, _, _ = prepared
    config['instance'].update(slug=slug, bridge_port=bridge, gateway_port=gateway,
        account='whatsappbridge' if slug == 'personal' else 'wa-' + slug)
    with pytest.raises(ValueError): compile_profile(prepared)
