"""Offline runtime compiler: cold configured inputs, no host/legacy dependencies."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest


REPOSITORY = Path(__file__).resolve().parents[2]
PLUGIN = REPOSITORY / 'plugins/whatsapp'
SCRIPT = PLUGIN / 'scripts/compile_runtime_retirement.py'


def sha(content):
    return hashlib.sha256(content).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def invoke(profile, action, output, *args):
    driver = '''import runpy,sys
def audit(event,args):
    if event in ('subprocess.Popen','socket.connect','socket.bind'):
        raise AssertionError('Offline compiler attempted a host action')
    if event=='open' and isinstance(args[0],str) and args[0].startswith((
        '/etc/whatsapp-installation','/etc/box-installation','/srv/openai-codex','/var/lib/sally-browser')):
        raise AssertionError('Offline compiler consulted a legacy or installed identity')
sys.addaudithook(audit)
sys.argv=sys.argv[1:]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    return subprocess.run([sys.executable, '-I', '-B', '-c', driver, str(SCRIPT), action,
        '--profile', str(profile), '--profile-sha256', sha(profile.read_bytes()),
        '--output', str(output), *map(str, args)], capture_output=True, text=True, timeout=30)


@pytest.fixture(params=['alpha', 'bravo'])
def prepared(tmp_path, request):
    value = json.loads((PLUGIN / 'deploy/installation.example.json').read_bytes())
    name = request.param
    value['paths'] = {'project': '/srv/' + name + '/application',
        'configuration': '/etc/' + name, 'state': '/var/lib/' + name + '-state',
        'gateway': '/var/lib/' + name + '-gateway', 'backup': '/opt/' + name + '-backup',
        'administration_code': '/opt/' + name + '-helpers',
        'administration_state': '/var/lib/' + name + '-administration'}
    value['services'] = {'prefix': name, 'recovery': name + '-recovery'}
    value['accounts'] = {'personal': name + '-owner', 'team': name + '-team'}
    if name == 'bravo':
        value['ports'] = {'personal': {'bridge': 23401, 'gateway': 23907},
                          'team': {'bridge': 25301, 'gateway': 25907}}
    profile = tmp_path / 'profile.json'; profile.write_bytes(encoded(value))
    output = tmp_path / 'template'
    result = invoke(profile, 'template', output, '--tenant', 'personal', '--tenant', 'team')
    assert result.returncode == 0, result.stderr
    inputs = json.loads((output / 'inputs.json').read_bytes())
    return profile, value, inputs


def complete_observation(inputs):
    inputs = copy.deepcopy(inputs)
    inputs['operation_id'] = 'a' * 32
    for index, item in enumerate(inputs['observation_tenants']):
        uid = 5101 + index
        item.update(uid=uid, gid=6101 + index,
            gateway_cgroup='/user.slice/user-' + str(uid) + '.slice/user@' + str(uid) + '.service/app.slice/whatsapp-waha.service')
        item['wrapper'] = {'sha256': sha(('synthetic wrapper ' + str(index)).encode()), 'mode': 0o700, 'uid': 0, 'gid': 0}
        for path in item['sources']:
            quadlet = path.endswith('.container')
            item['sources'][path] = {'sha256': sha(('synthetic file ' + path).encode()),
                'mode': 0o600 if quadlet else 0o644, 'uid': uid if quadlet else 0,
                'gid': item['gid'] if quadlet else 0}
    return inputs


def test_template_never_invents_live_inventory_or_completeness(prepared, tmp_path):
    profile, value, inputs = prepared
    assert inputs['complete'] is False and inputs['operation_id'] is None
    assert inputs['manual_policy'] is None and inputs['external_references'] is None
    assert inputs['application_files'] is None and inputs['directories'] is None
    assert inputs['tenant_registry']['path'] == value['paths']['project'] + '/private/tenants.json'
    assert inputs['qos_policy']['sha256'] is None  # Operator must choose observed policy or null.
    assert all(item['uid'] is None and item['gateway_cgroup'] is None for item in inputs['observation_tenants'])
    input_path = tmp_path / 'incomplete.json'; input_path.write_bytes(encoded(inputs))
    output = tmp_path / 'must-not-exist'
    result = invoke(profile, 'compile', output, '--inputs', input_path,
        '--inputs-sha256', sha(input_path.read_bytes()), '--inventory-root', tmp_path,
        '--source-revision', 'b' * 40)
    assert result.returncode != 0 and 'complete inventoried scope' in result.stderr
    assert not output.exists()


def test_observation_preparation_binds_scope_and_both_sources_without_host_reads(prepared, tmp_path):
    profile, _, inputs = prepared
    inputs = complete_observation(inputs)
    inputs['complete'] = True  # Preparing a request must clear an old assertion.
    input_path = tmp_path / 'inputs.json'; input_path.write_bytes(encoded(inputs))
    output = tmp_path / 'observation'
    result = invoke(profile, 'prepare-observation', output, '--inputs', input_path,
        '--inputs-sha256', sha(input_path.read_bytes()))
    assert result.returncode == 0, result.stderr
    request_raw = (output / 'request.json').read_bytes()
    request = json.loads(request_raw)
    provenance_raw = (output / 'provenance.json').read_bytes()
    provenance = json.loads(provenance_raw)
    next_inputs = json.loads((output / 'inputs.next.json').read_bytes())
    assert next_inputs['complete'] is False
    assert next_inputs['observation_request']['sha256'] == sha(request_raw)
    assert request['tenants'] == inputs['observation_tenants']
    assert request['provenance']['sha256'] == sha(provenance_raw)
    assert provenance['tenant_scope_sha256'] == sha(encoded(request['tenants']))
    assert request['source']['sha256'] == provenance['source_sha256'] == sha((PLUGIN / 'scripts/runtime_lifecycle.py').read_bytes())
    assert request['layout_source']['sha256'] == provenance['layout_sha256'] == sha((PLUGIN / 'scripts/installation_layout.py').read_bytes())
    assert json.loads(result.stdout)['host_changed'] is False
    for path in output.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('fault', ['duplicate-uid', 'foreign-wrapper', 'wrong-cgroup', 'foreign-source',
                                  'missing-quadlet', 'overlapping-documents', 'document-in-data'])
def test_observation_rejects_inconsistent_scope_before_outputs(prepared, tmp_path, fault):
    profile, _, inputs = prepared
    inputs = complete_observation(inputs)
    first, second = inputs['observation_tenants']
    if fault == 'duplicate-uid': second['uid'] = first['uid']
    elif fault == 'foreign-wrapper': first['wrapper']['uid'] = first['uid']
    elif fault == 'wrong-cgroup': first['bridge_cgroup'] = '/system.slice/other.service'
    elif fault == 'foreign-source': first['sources']['/etc/systemd/system/other.service'] = first['wrapper']
    elif fault == 'overlapping-documents': inputs['attestation_path'] = inputs['observation_request']['path']
    elif fault == 'document-in-data': inputs['attestation_path'] = '/var/lib/runtime-data/archive.json'
    else: first['sources'] = {path: spec for path, spec in first['sources'].items() if not path.endswith('.container')}
    input_path = tmp_path / 'inputs.json'; input_path.write_bytes(encoded(inputs))
    output = tmp_path / 'rejected'
    result = invoke(profile, 'prepare-observation', output, '--inputs', input_path,
        '--inputs-sha256', sha(input_path.read_bytes()))
    assert result.returncode != 0 and not output.exists()


def _cold_complete(directory, name):
    """Real compiler chain; service observation/ownership are synthetic facts."""
    import runpy
    directory = Path(directory)
    factory = runpy.run_path(str(REPOSITORY / 'tools/tests/test_admin_compile.py'))['make_fixture']
    admin_inputs, bundle, profile, _, _ = factory(directory, name, 'remove')
    import admin_compile
    admin_raw = admin_compile.compile_operation(bundle, source_revision='a' * 40,
        metadata_sha256=sha((bundle / 'bundle.json').read_bytes()), input_bytes=encoded(admin_inputs),
        inputs_sha256=sha(encoded(admin_inputs)), mode='remove')['operation.json']
    import compile_runtime_retirement as compiler
    selected, runtime = compiler.modules(profile.read_bytes())
    from host.frontend import provider, adapter
    inputs = complete_observation(compiler.template(selected, runtime, ['personal', 'team']))
    inputs['operation_id'] = admin_inputs['runtime_retirement']['operation_id']
    input_path = directory / 'runtime-inputs.json'; input_path.write_bytes(encoded(inputs))
    observed_output = directory / 'prepared-observation'
    result = invoke(profile, 'prepare-observation', observed_output, '--inputs', input_path,
        '--inputs-sha256', sha(input_path.read_bytes()))
    assert result.returncode == 0, result.stderr
    inputs = json.loads((observed_output / 'inputs.next.json').read_bytes())
    root = directory / 'inventory'; root.mkdir(mode=0o700)
    def publish(logical, raw):
        target = root / logical.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw); target.chmod(0o600)
        return {'path': logical, 'sha256': sha(raw)}
    inputs['admin_operation'] = publish(inputs['admin_operation']['path'], admin_raw)
    request_raw = (observed_output / 'request.json').read_bytes()
    request = json.loads(request_raw)
    publish(inputs['observation_request']['path'], request_raw)
    publish(request['provenance']['path'], (observed_output / 'provenance.json').read_bytes())
    receipt = {'format': 'whatsapp-runtime-observation-receipt-v2', 'operation_id': inputs['operation_id'],
        'request_sha256': sha(request_raw), 'source_sha256': request['source']['sha256'],
        'layout_sha256': request['layout_source']['sha256'], 'provenance_sha256': request['provenance']['sha256'],
        'mutations': False, 'invoker_completeness_proven': False,
        'lifecycle_contract': 'whatsapp-rootless-quadlet-cleanup-v1', 'units': {}}
    for item in request['tenants']:
        wanted = runtime.layout(item['slug'])
        for component in ('bridge', 'gateway'):
            definition = {key: '' for key in runtime.DEFINITION}
            definition.update(Id=wanted[component + '_unit'], LoadState='loaded', NeedDaemonReload='no',
                FragmentPath=wanted['bridge_source'] if component == 'bridge' else
                    '/run/user/' + str(item['uid']) + '/systemd/generator/whatsapp-waha.service',
                SourcePath='' if component == 'bridge' else wanted['quadlet'],
                User=wanted['account'] if component == 'bridge' else '', Restart='on-failure', KillMode='control-group')
            for key in runtime.EXEC_PROPERTIES: definition[key] = []
            if component == 'bridge':
                argv = [runtime.PROJECT + '/.venv/bin/python', '-m', 'sally_whatsapp.cli', '--config',
                    selected.instance_paths(item['slug'])['configuration'] + '/config.toml', 'serve']
            else:
                cid = '/run/user/' + str(item['uid']) + '/whatsapp-waha.cid'
                argv = ['/usr/bin/podman', 'run', '--name', 'whatsapp-waha', '--cidfile=' + cid, '--rm', 'synthetic-image']
                for key, ignore in (('ExecStop', False), ('ExecStopPost', True)):
                    definition[key] = [{'path': '/usr/bin/podman',
                        'argv': ['/usr/bin/podman', 'rm', '-v', '-f', '-i', '--cidfile=' + cid], 'ignore_errors': ignore}]
            definition['ExecStart'] = [{'path': argv[0], 'argv': argv, 'ignore_errors': False}]
            runtime.validate_unit_effects({**item, **wanted}, component, definition)
            receipt['units'][item['slug'] + ':' + component] = {'definition': runtime.unit_definition(definition),
                'state': {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0', 'ControlPID': '0',
                          'Job': '', 'ControlGroup': '', 'UnitFileState': 'disabled' if component == 'bridge' else 'generated'}}
    inputs['observation_receipt'] = publish(inputs['observation_receipt']['path'], encoded(receipt))
    registry = {'format': 1, 'instances': {slug: {'spec': {'slug': slug, 'installation': selected.as_dict()},
        'phase': 'prepared' if slug == 'personal' else 'ready', 'enabled': slug == 'personal'} for slug in ('personal', 'team')}}
    inputs['tenant_registry'] = publish(inputs['tenant_registry']['path'], encoded(registry))
    inputs['registry_metadata'] = {'sha256': inputs['tenant_registry']['sha256'], 'mode': 0o600, 'uid': 0, 'gid': 0}
    for spec in inputs['helper_metadata'].values(): spec.update(mode=0o644, uid=0, gid=0)
    apache = '/etc/apache2/apache2.conf'
    vhosts = {slug: '/etc/apache2/sites-enabled/' + name + '-' + slug + '.conf' for slug in ('personal', 'team')}
    frontend = {'format': 1, 'provider': provider.PROVIDER, 'version': provider.VERSION, 'owner': 'host',
        'apache': {'unit': 'apache2.service', 'config_path': apache},
        'scheduler': {'owner': 'host', 'unit': 'certbot.timer'},
        'artifacts': {path: {'sha256': sha(('synthetic ' + path).encode()), 'mode': 0o644, 'uid': 0, 'gid': 0,
                            'retention': 'retain' if path == apache else 'managed'} for path in (apache, *vhosts.values())},
        'directories': {}, 'links': {}, 'host_files': [apache], 'lineages': {}, 'legacy_hooks': {},
        'consumers': {'whatsapp.' + slug: {'owner': 'whatsapp', 'status': 'pending_tls',
            'domains': [name + '-' + slug + '.example.org'], 'vhosts': [path], 'lineages': []} for slug, path in vhosts.items()}}
    # Fresh provider compatibility slots contain neutral no-op hooks, with no
    # historical application paths or source dependency.
    for event, path in provider.LEGACY_HOOKS.items():
        digest = sha(b'#!/bin/sh\nexit 0\n')
        frontend['legacy_hooks'][event] = {'path': path, 'sha256': digest}
        frontend['host_files'].append(path)
        frontend['artifacts'][path] = {'sha256': digest, 'mode': 0o700, 'uid': 0, 'gid': 0, 'retention': 'retain'}
    front_profile = {'format': 1, 'apache': {'server_root': '/etc/apache2', 'config_path': apache, 'unit': 'apache2.service'},
        'tools': {key: {'path': path, 'sha256': 'b' * 64} for key, path in
                  (('apache', '/usr/sbin/apache2'), ('systemctl', '/usr/bin/systemctl'), ('openssl', '/usr/bin/openssl'))},
        'environment': {}, 'config_files': [apache, *vhosts.values()], 'includes': [], 'tls': [],
        'dependencies': {}, 'lineages': {}, 'certbot_lock': {'directory': '/etc/letsencrypt',
            'protocol': 'posix-lockf-unlink-before-close-v1', 'source': {'path': '/usr/lib/python3/dist-packages/certbot/util.py', 'sha256': 'b' * 64}}}
    inputs['frontend'] = {'registry': publish(adapter.REGISTRY, encoded(frontend)),
                          'profile': publish(adapter.PROFILE, encoded(front_profile))}
    inputs.update(complete=True, manual_policy='unregistered-runtime-starts-frozen', external_references={},
                  qos_policy=None, application_files={}, directories={})
    input_path.write_bytes(encoded(inputs))
    output = directory / 'compiled'
    result = invoke(profile, 'compile', output, '--inputs', input_path, '--inputs-sha256', sha(input_path.read_bytes()),
                    '--inventory-root', root, '--source-revision', 'a' * 40)
    assert result.returncode == 0, result.stderr
    operation = json.loads((output / 'operation.json').read_bytes())
    attestation = json.loads((output / 'attestation.json').read_bytes())
    report = json.loads((output / 'compilation.json').read_bytes())
    assert runtime.validate_plan(operation['plan']) == sha(encoded(operation['plan']))
    assert operation['admin_operation'] == inputs['admin_operation']
    assert operation['sources'] == {relative: sha((REPOSITORY / relative).read_bytes()) for relative in runtime.STANDALONE_SOURCES}
    assert operation['plan']['attestation']['sha256'] == sha((output / 'attestation.json').read_bytes())
    assert attestation['references'][runtime.PROJECT + '/private/tenants.json'] == inputs['registry_metadata']
    assert set(tenant['slug'] for tenant in operation['plan']['tenants']) == {'personal', 'team'}
    assert report['host_observed'] is False and report['completeness_proven_by_compiler'] is False
    assert report['operation_sha256'] == sha((output / 'operation.json').read_bytes())
    assert not any('box' in path or '/srv/openai-codex' in path for path in operation['plan']['before']['files'])
    original_outputs = {p.name: p.read_bytes() for p in output.iterdir()}
    mutations = []
    def changed(change):
        value = copy.deepcopy(inputs); change(value); mutations.append(value)
    changed(lambda v: v.update(complete=False))
    changed(lambda v: v.update(manual_policy=None))
    changed(lambda v: v['registry_metadata'].update(sha256='0' * 64))
    changed(lambda v: v['observation_receipt'].update(sha256='0' * 64))
    changed(lambda v: v['admin_operation'].update(sha256='0' * 64))
    changed(lambda v: v['frontend']['profile'].update(path=adapter.REGISTRY))
    changed(lambda v: v['helper_metadata'][runtime.HELPER_LAYOUT].update(sha256='0' * 64))
    changed(lambda v: v.update(application_files=None))
    changed(lambda v: v['observation_tenants'].pop())
    changed(lambda v: v.update(attestation_path=v['admin_operation']['path']))
    # Every generated document must stay disjoint from immutable evidence,
    # including an external reference that explicitly requires its absence.
    destinations = (inputs['observation_request']['path'], inputs['observation_provenance_path'],
                    inputs['observation_receipt']['path'], inputs['attestation_path'])
    collision_count = 0
    for destination in destinations:
        for category in ('admin_operation', 'tenant_registry', 'frontend_profile', 'frontend_registry',
                         'qos_policy', 'external_present', 'external_absent', 'helper_metadata',
                         'application_files', 'directories', 'source'):
            damaged = copy.deepcopy(inputs)
            if category in ('admin_operation', 'tenant_registry'):
                damaged[category]['path'] = destination
            elif category.startswith('frontend_'):
                damaged['frontend'][category.removeprefix('frontend_')]['path'] = destination
            elif category == 'qos_policy':
                damaged['qos_policy'] = {'path': destination, 'sha256': 'b' * 64}
            elif category.startswith('external_'):
                damaged['external_references'][destination] = (
                    None if category == 'external_absent' else damaged['registry_metadata'])
            elif category == 'source':
                damaged['observation_tenants'][0]['sources'][destination] = damaged['registry_metadata']
            else:
                damaged[category][destination] = damaged['registry_metadata']
            with pytest.raises(ValueError, match='cannot overlap immutable inventory references'):
                compiler.observation(damaged, runtime)
            collision_count += 1
    for index, damaged in enumerate(mutations):
        input_path.write_bytes(encoded(damaged))
        rejected = directory / ('rejected-' + str(index))
        result = invoke(profile, 'compile', rejected, '--inputs', input_path,
            '--inputs-sha256', sha(input_path.read_bytes()), '--inventory-root', root, '--source-revision', 'a' * 40)
        assert result.returncode != 0 and not rejected.exists(), result.stdout
    assert {p.name: p.read_bytes() for p in output.iterdir()} == original_outputs
    print(json.dumps({'profile': name, 'compiled': True, 'negative_inputs': len(mutations),
                      'document_inventory_collisions_rejected': collision_count,
                      'real_host_observed': False, 'real_retirement_executed': False}))


@pytest.mark.parametrize('name', ['alpha', 'bravo'])
def test_cold_complete_compilation_with_validated_admin_removal_and_two_tenants(name):
    work = REPOSITORY / 'work'; work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='runtime-compiler-', dir=work) as directory:
        driver = 'import runpy,sys; runpy.run_path(sys.argv[1])["_cold_complete"](sys.argv[2],sys.argv[3])'
        result = subprocess.run([sys.executable, '-I', '-B', '-c', driver,
            str(Path(__file__).resolve()), directory, name], capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)['real_retirement_executed'] is False
