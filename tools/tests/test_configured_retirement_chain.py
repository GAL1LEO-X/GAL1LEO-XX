"""Compiled configured retirement, real journals/files/frontend, simulated managers.

Each profile runs in a cold interpreter. No administrative cutpoint or runtime
completion is fabricated. Account lookup/systemd/proc and the runuser ownership
boundary are explicit fixtures; retained data and quarantines are real files.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / 'plugins/whatsapp'
REVISION = 'a' * 40


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def put(base, logical, content, mode=0o600):
    path = base / logical.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)
    return {'path': logical, 'sha256': sha(content)}


class RecoveryManager:
    """Only exact dedicated recovery operations; no actual command execution."""
    def __init__(self, services):
        self.services, self.armed, self.calls = services, True, []

    def run(self, operation, **kwargs):
        assert kwargs['pass_fds']
        assert operation in ('reload-definitions', 'enable-wa-recovery', 'start-wa-recovery',
                             'disable-wa-recovery', 'stop-wa-recovery')
        self.calls.append(operation)
        if operation == 'stop-wa-recovery': self.armed = False
        if operation == 'start-wa-recovery': self.armed = True

    def read(self, argv, **kwargs):
        services = self.services
        unit = argv[-1]
        assert argv == services.recovery_show_argv(unit)
        value = {key: '' for key in services.RECOVERY_PROPERTIES[unit]}
        value.update(Id=unit, LoadState='loaded', NeedDaemonReload='no', Job='0',
            FragmentPath='/etc/systemd/system/' + unit, ActiveState='inactive', SubState='dead')
        if unit.endswith('.timer'):
            value.update(ActiveState='active' if self.armed else 'inactive',
                UnitFileState='enabled' if self.armed else 'disabled', Unit=services.WA_RECOVERY[0],
                TimersMonotonic='{ OnBootUSec=45s; next=1; } { OnUnitInactiveUSec=60s; next=2; }')
        else:
            value.update(MainPID='0', ControlPID='0', Type='oneshot', User='root',
                KillMode='control-group', RemainAfterExit='no', Restart='no', TimeoutStartUSec='600s',
                ExecStart='{ path=/usr/bin/python3; argv[]=/usr/bin/python3 -I -B '
                    + services.RECOVERY_ENTRYPOINT + ' recovery; }')
        return ('\n'.join(key + '=' + item for key, item in value.items()) + '\n').encode()


class RuntimeManager:
    """Finite two-tenant systemd model plus actual UID-helper file mutations."""
    def __init__(self, runtime, selected, root, tenants):
        self.runtime, self.selected, self.root, self.tenants = runtime, selected, root, tenants
        self.values, self.calls = {}, []
        for tenant in tenants:
            for component in ('bridge', 'gateway'):
                value = {key: '' for key in runtime.DEFINITION}
                value.update(Id=tenant[component + '_unit'], LoadState='loaded', NeedDaemonReload='no',
                    FragmentPath=tenant['bridge_source'] if component == 'bridge' else
                        '/run/user/' + str(tenant['uid']) + '/systemd/generator/whatsapp-waha.service',
                    SourcePath='' if component == 'bridge' else tenant['quadlet'],
                    User=tenant['account'] if component == 'bridge' else '',
                    Restart='on-failure', KillMode='control-group')
                for key in runtime.EXEC_PROPERTIES: value[key] = []
                if component == 'bridge':
                    argv = [runtime.PROJECT + '/.venv/bin/python', '-m', 'sally_whatsapp.cli', '--config',
                        selected.instance_paths(tenant['slug'])['configuration'] + '/config.toml', 'serve']
                else:
                    cid = '/run/user/' + str(tenant['uid']) + '/whatsapp-waha.cid'
                    argv = ['/usr/bin/podman', 'run', '--name', 'whatsapp-waha', '--cidfile=' + cid,
                            '--rm', 'synthetic-image']
                    for key, ignore in (('ExecStop', False), ('ExecStopPost', True)):
                        value[key] = [{'path': '/usr/bin/podman', 'argv':
                            ['/usr/bin/podman', 'rm', '-v', '-f', '-i', '--cidfile=' + cid],
                            'ignore_errors': ignore}]
                value['ExecStart'] = [{'path': argv[0], 'argv': argv, 'ignore_errors': False}]
                runtime.validate_unit_effects(tenant, component, value)
                value.update(ActiveState='active', SubState='running', MainPID='321', ControlPID='0',
                    Job='', ControlGroup=tenant[component + '_cgroup'],
                    UnitFileState='enabled' if component == 'bridge' else 'generated')
                self.values[tenant['slug'] + ':' + component] = value

    def lookup(self, name):
        tenant = next(item for item in self.tenants if item['account'] == name)
        return SimpleNamespace(pw_uid=tenant['uid'], pw_gid=tenant['gid'], pw_dir=tenant['home'])

    def read(self, argv):
        runtime = self.runtime
        for tenant in self.tenants:
            for component in ('bridge', 'gateway'):
                value = self.values[tenant['slug'] + ':' + component]
                if argv == runtime.command(tenant, component, 'show'):
                    return ('\n'.join(key + '=' + item for key, item in value.items()
                        if key not in runtime.EXEC_PROPERTIES) + '\n').encode()
                for key in runtime.EXEC_PROPERTIES:
                    if argv == runtime.command(tenant, component, key):
                        records = [[item['path'], item['argv'], item['ignore_errors'], 1, 2, 3, 4, 321, 0, 0]
                                   for item in value[key]]
                        return encoded({'type': 'a(sasbttttuii)', 'data': records})
        raise AssertionError('Unmodelled runtime read: ' + repr(argv))

    def run(self, argv, *, lease):
        assert len(lease) == 1
        runtime = self.runtime
        self.calls.append(argv)
        if len(argv) == 14 and argv[5] in ('_check-quadlet', '_retire-quadlet', '_check-retired-quadlet'):
            tenant = next(item for item in self.tenants if item['slug'] == argv[6])
            assert argv[0] == tenant['wrapper'] and argv[4] == runtime.HELPER and argv[12] == 'quadlet'
            assert argv[13] == self.root.snapshot(runtime.HELPER_LAYOUT)['sha256']
            # Explicit simulation of runuser's UID boundary. Files are owned by
            # the test user; the real helper still performs its exact snapshot,
            # parent, hash, atomic rename and quarantine checks on those bytes.
            physical = self.root.base / tenant['quadlet'].lstrip('/')
            expected = {**tenant['quadlet_metadata'], 'uid': os.getuid(), 'gid': os.getgid()}
            result = runtime.quadlet_retire(self.root.base / tenant['home'].lstrip('/'), argv[7], expected,
                check_only=argv[5] != '_retire-quadlet', retired=argv[5] == '_check-retired-quadlet')
            if argv[5] == '_retire-quadlet': assert not physical.exists()
            return result
        if argv == runtime.command(self.tenants[0], 'bridge', 'reload'):
            # A system manager reload refreshes every named bridge definition.
            for tenant in self.tenants:
                if self.root.snapshot(tenant['bridge_source']) is None:
                    self.values[tenant['slug'] + ':bridge'].update(
                        LoadState='not-found', UnitFileState='', FragmentPath='')
            return
        for tenant in self.tenants:
            for component, operation in (('bridge', 'disable'), ('bridge', 'stop'),
                                         ('gateway', 'stop'), ('gateway', 'mask'), ('gateway', 'reload')):
                if argv != runtime.command(tenant, component, operation): continue
                value = self.values[tenant['slug'] + ':' + component]
                if operation == 'disable': value['UnitFileState'] = 'disabled'
                elif operation == 'mask': value.update(LoadState='masked', UnitFileState='masked', FragmentPath='/dev/null')
                elif operation == 'stop': value.update(ActiveState='inactive', SubState='dead', MainPID='0',
                    ControlPID='0', ControlGroup='')
                return
        raise AssertionError('Unmodelled runtime effect: ' + repr(argv))


def frontend_fixture(root, name):
    import test_host_frontend as ft
    registry, raw = ft.registry.__wrapped__()
    old = registry['consumers'].pop('whatsapp.owner')
    old_vhost, old_lineage = old['vhosts'][0], old['lineages'][0]
    registry['artifacts'].pop(old_vhost); raw.pop(old_vhost); registry['lineages'].pop(old_lineage)
    for slug in ('personal', 'team'):
        consumer, domain = 'whatsapp.' + slug, name + '-' + slug + '.example.test'
        vhost, lineage = '/etc/apache2/sites-enabled/' + name + '-' + slug + '.conf', '/etc/letsencrypt/live/' + domain
        raw[vhost] = ('<VirtualHost *:443>\nServerName ' + domain + '\n</VirtualHost>\n').encode()
        registry['artifacts'][vhost] = ft.spec(raw[vhost])
        registry['consumers'][consumer] = {'owner': 'whatsapp', 'status': 'active',
            'domains': [domain], 'vhosts': [vhost], 'lineages': [lineage]}
        registry['lineages'][lineage] = {'domains': [domain], 'consumers': [consumer],
            'source': {'certificate': lineage + '/fullchain.pem', 'key': lineage + '/privkey.pem'},
            'destinations': [{'consumer': consumer, 'mode': 'copy',
                'certificate': '/etc/tls/' + name + '-' + slug + '-cert.pem',
                'key': '/etc/tls/' + name + '-' + slug + '-key.pem',
                'uid': root.uid, 'gid': root.gid, 'certificate_mode': 0o640, 'key_mode': 0o600}]}
    registry, raw, profile, runner, adapter = ft.staged_setup((registry, raw), root)
    with adapter.lease():
        ft.finite.apply_configuration(adapter, operation_id='1' * 32, before=ft.empty(), pinned_artifacts=raw)
    for item in profile['lineages'].values():
        put(root.base, item['renewal']['path'], b'renewal fixture\n')
    put(root.base, ft.finite.PROFILE, encoded(profile))
    return ft, registry, profile, runner, adapter


def exercise(directory, name):
    sys.path[:0] = [str(ROOT), str(ROOT / 'tools/tests')]
    from test_admin_compile import make_fixture
    directory = Path(directory)
    inputs, bundle, profile_path, old, _ = make_fixture(directory, name, 'remove', uid=os.getuid(), gid=os.getgid())
    import admin_compile, admin_install, admin_handoff, admin_host
    import compile_runtime_retirement as compiler
    from host.lifecycle import filesystem, services
    selected, runtime = compiler.modules(profile_path.read_bytes())
    admin_files = admin_compile.compile_operation(bundle, source_revision=REVISION,
        metadata_sha256=sha((bundle / 'bundle.json').read_bytes()), input_bytes=encoded(inputs),
        inputs_sha256=sha(encoded(inputs)), mode='remove', uid=os.getuid(), gid=os.getgid())
    admin, admin_payloads, _ = admin_install.decode_operation(admin_files['operation.json'], sha(admin_files['operation.json']))
    base = directory / 'root'; base.mkdir(mode=0o700)
    for logical, spec in old['manifest']['directories'].items():
        path = base / logical.lstrip('/'); path.mkdir(parents=True, exist_ok=True); path.chmod(spec['mode'])
    for logical, content in old['payloads'].items(): put(base, logical, content, old['manifest']['files'][logical]['mode'])
    for logical in (runtime.STATE + '/handoff', runtime.PROJECT + '/private'):
        (base / logical.lstrip('/')).mkdir(parents=True, exist_ok=True, mode=0o700)
    put(base, admin_handoff.OWNER, encoded(inputs['previous_owner']))
    for filename, logical in json.loads(admin_files['compilation.json'])['attestation_destinations'].items():
        put(base, logical, admin_files[filename])
    proc = directory / 'proc'; (proc / 'sys/kernel/random').mkdir(parents=True)
    (proc / 'sys/kernel/random/boot_id').write_text('11111111-2222-3333-4444-555555555555\n')
    with filesystem.Root(base) as root:
        recovery = RecoveryManager(services)
        provider = admin_host.AdminHost(root, admin['profile'], proc_root=proc,
            readonly_runner=recovery.read, service_runner=recovery.run, clock_ns=lambda: 100)
        runtime_inputs = compiler.template(selected, runtime, ['personal', 'team'])
        runtime_inputs['operation_id'] = inputs['runtime_retirement']['operation_id']
        tenants, preserved = [], {}
        for index, item in enumerate(runtime_inputs['observation_tenants']):
            wanted = runtime.layout(item['slug'])
            uid, gid = 5101 + index, 6101 + index
            item.update(uid=uid, gid=gid,
                gateway_cgroup='/user.slice/user-' + str(uid) + '.slice/user@' + str(uid) + '.service/app.slice/whatsapp-waha.service')
            wrapper = ('#!/bin/sh\nset -eu\ncd ' + wanted['home'] + '\nexec runuser -u ' + wanted['account']
                + ' -- env HOME=' + wanted['home'] + ' XDG_RUNTIME_DIR=/run/user/' + str(uid)
                + ' DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(uid) + '/bus "$@"\n').encode()
            put(base, wanted['wrapper'], wrapper, 0o700); item['wrapper'] = root.snapshot(wanted['wrapper'])
            put(base, wanted['bridge_source'], ('# synthetic bridge ' + item['slug'] + '\n').encode(), 0o644)
            put(base, wanted['quadlet'], ('[Container]\nImage=synthetic-' + item['slug'] + '\n').encode())
            item['sources'] = {wanted['bridge_source']: root.snapshot(wanted['bridge_source']),
                wanted['quadlet']: {**root.snapshot(wanted['quadlet']), 'uid': uid, 'gid': gid}}
            tenants.append({**item, **wanted, 'quadlet_metadata': item['sources'][wanted['quadlet']]})
            paths = selected.instance_paths(item['slug'])
            for logical, content in ((paths['state'] + '/archive.sqlite', b'synthetic later messages/revokes/uncertain sends'),
                                     (wanted['home'] + '/sessions/personal-session', b'synthetic linked account state'),
                                     (paths['configuration'] + '/config.toml', b'# retained tenant configuration')):
                put(base, logical, content); preserved[logical] = content
        manager = RuntimeManager(runtime, selected, root, tenants)
        for logical in runtime_inputs['helper_metadata']:
            runtime_inputs['helper_metadata'][logical] = root.snapshot(logical)
        request_raw, provenance = compiler.observation(runtime_inputs, runtime, authority_uid=root.uid)
        request = json.loads(request_raw)
        runtime_inputs['observation_request'] = put(base, runtime_inputs['observation_request']['path'], request_raw)
        put(base, request['provenance']['path'], provenance)
        # Effective definitions are parsed by the actual finite unit reader.
        # Linux account ownership in this receipt remains explicitly simulated.
        receipt = {'format': 'whatsapp-runtime-observation-receipt-v2', 'operation_id': runtime_inputs['operation_id'],
            'request_sha256': sha(request_raw), 'source_sha256': request['source']['sha256'],
            'layout_sha256': request['layout_source']['sha256'], 'provenance_sha256': sha(provenance),
            'mutations': False, 'invoker_completeness_proven': False,
            'lifecycle_contract': 'whatsapp-rootless-quadlet-cleanup-v1', 'units': {}}
        for tenant in tenants:
            for component in ('bridge', 'gateway'):
                value = runtime.read_unit(tenant, component, manager.read)
                runtime.validate_unit_effects(tenant, component, value)
                receipt['units'][tenant['slug'] + ':' + component] = {'definition': runtime.unit_definition(value),
                    'state': {key: value[key] for key in ('ActiveState', 'SubState', 'MainPID', 'ControlPID',
                        'Job', 'ControlGroup', 'UnitFileState')}}
        runtime_inputs['observation_receipt'] = put(base, runtime_inputs['observation_receipt']['path'], encoded(receipt))
        runtime_inputs['admin_operation'] = put(base, runtime_inputs['admin_operation']['path'], admin_files['operation.json'])
        registry = {'format': 1, 'instances': {tenant['slug']: {'spec': {'slug': tenant['slug'],
            'installation': selected.as_dict()}, 'phase': 'prepared' if tenant['slug'] == 'personal' else 'ready',
            'enabled': tenant['slug'] != 'personal'} for tenant in tenants}}
        runtime_inputs['tenant_registry'] = put(base, runtime_inputs['tenant_registry']['path'], encoded(registry))
        runtime_inputs['registry_metadata'] = root.snapshot(runtime_inputs['tenant_registry']['path'])
        ft, frontend_registry, front_profile, apache, frontend = frontend_fixture(root, name)
        runtime_inputs['frontend'] = {key: {'path': path, 'sha256': root.snapshot(path)['sha256']}
            for key, path in (('registry', ft.finite.REGISTRY), ('profile', ft.finite.PROFILE))}
        runtime_inputs.update(complete=True, manual_policy='unregistered-runtime-starts-frozen',
            external_references={}, qos_policy=None, application_files={}, directories={})
        runtime_files = compiler.compile_operation(runtime_inputs, runtime, inventory_root=base,
            source_revision=REVISION, authority_uid=root.uid)
        operation = json.loads(runtime_files['operation.json'])
        runtime_plan = operation['plan']
        put(base, runtime_plan['attestation']['path'], runtime_files['attestation.json'])
        unrelated = {logical: root.read_bytes(logical) for logical in (
            '/etc/apache2/apache2.conf', *frontend_registry['consumers']['box.web']['vhosts'],
            *frontend_registry['consumers']['host.sally']['vhosts'],
            front_profile['lineages']['/etc/letsencrypt/live/web.example.test']['renewal']['path'])}
        host = runtime.RuntimeHost(root, runtime_plan, admin_plan=admin['plan'], admin_provider=provider,
            frontend_adapter=frontend, reader=manager.read, runner=manager.run,
            lookup=manager.lookup, proc_root=proc)
        with pytest.raises((ValueError, RuntimeError), match='completed administrative retirement'):
            host.advance()
        assert root.snapshot(host.journal_path) is None and not manager.calls
        phases = {'administration': [], 'runtime': []}
        for _ in range(20):
            result = admin_handoff.handoff(root, admin['plan'], admin_payloads, provider)
            assert not result['pending']; phases['administration'].append(result['phase'])
            if result['phase'] == 'retired': break
        assert phases['administration'][-1] == 'retired'
        assert not recovery.armed and not manager.calls
        with pytest.raises((ValueError, RuntimeError)):
            admin_handoff.handoff(root, admin['plan'], admin_payloads, provider)
        assert root.snapshot(admin_handoff.RECEIVER) is not None
        # Data written after compilation and the first administrative phases
        # must survive; a pre-intervention snapshot is not restored over it.
        for logical in preserved:
            if logical.endswith('archive.sqlite'):
                preserved[logical] += b'\nsynthetic post-plan revocation and uncertain-send status'
                put(base, logical, preserved[logical])
        for _ in range(10):
            result = host.advance(); phases['runtime'].append(result['phase'])
            if result['complete']: break
        assert phases['runtime'] == list(runtime.PHASES)
        assert host.advance()['complete']
        journal = json.loads(root.read_bytes(host.journal_path))
        assert journal['phase'] == 'verified' and journal['intent'] is None
        assert journal['receipts']['frontend']['phase'] == 'complete'
        for _ in range(10):
            result = admin_handoff.handoff(root, admin['plan'], admin_payloads, provider)
            assert not result['pending']; phases['administration'].append(result['phase'])
            if result['phase'] == 'verified': break
        assert phases['administration'] == list(admin_handoff.PHASES['remove'])
        assert admin_handoff.handoff(root, admin['plan'], admin_payloads, provider)['phase'] == 'verified'
        assert root.snapshot(admin_handoff.OWNER) is None and root.snapshot(admin_handoff.RECEIVER) is None
        for logical, content in {**preserved, **unrelated}.items(): assert root.read_bytes(logical) == content
        for tenant in tenants:
            assert root.snapshot(tenant['bridge_source']) is None
            assert root.snapshot(tenant['quadlet']) is None
            quarantine = tenant['quadlet'] + '.retired-' + runtime_plan['operation_id'] + '.quarantine'
            assert root.read_bytes(quarantine).startswith(b'[Container]')
            assert root.snapshot(tenant['wrapper']) is not None
            assert manager.values[tenant['slug'] + ':gateway']['LoadState'] == 'masked'
            assert root.snapshot('/etc/apache2/sites-enabled/' + name + '-' + tenant['slug'] + '.conf') is None
            assert root.snapshot('/etc/letsencrypt/renewal/' + name + '-' + tenant['slug'] + '.example.test.conf') is None
        assert root.snapshot(runtime.HELPER) is not None and root.snapshot(runtime.HELPER_LAYOUT) is not None
        assert len([call for call in apache.calls if 'reload' in call]) == 2  # Initial fixture + owner retirement.
        print(json.dumps({'profile': name, 'phases': phases, 'tenants': len(tenants),
            'real_filesystem': True, 'real_frontend_adapter': True, 'live_managers': False,
            'admin_completion_fabricated': False, 'runtime_completion_fabricated': False}))


@pytest.mark.parametrize('name', ['alpha', 'bravo'])
def test_full_configured_retirement_chain_with_real_compiled_administration(name):
    work = ROOT / 'work'; work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='configured-retirement-', dir=work) as directory:
        result = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()), directory, name],
            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report['tenants'] == 2 and report['real_frontend_adapter']


if __name__ == '__main__':
    exercise(*sys.argv[1:])
