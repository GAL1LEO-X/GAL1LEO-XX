"""Runtime retirement with real filesystem journals, synthetic services and own files."""
from contextlib import contextmanager
import copy
import importlib.util
import os
from pathlib import Path
import sys
import json
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from host.lifecycle import evidence, filesystem

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
SPEC = importlib.util.spec_from_file_location('runtime_lifecycle_test_module', SCRIPTS/'runtime_lifecycle.py')
runtime = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(runtime)
BOOT = '11111111-2222-3333-4444-555555555555'


def write(root, name, content, mode=0o644):
    target = root/name.lstrip('/'); target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content); target.chmod(mode)
    return target


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    root_path = tmp_path/'root'; root_path.mkdir()
    root = filesystem.Root(root_path)
    from host.installation import IDENTITY, Installation, identity_bytes
    write(root_path, str(IDENTITY), identity_bytes(Installation.legacy()))
    for name in (runtime.STATE, runtime.PROJECT+'/private', '/etc/systemd/system'):
        (root_path/name.lstrip('/')).mkdir(parents=True, exist_ok=True)
    proc = tmp_path/'proc'; (proc/'sys/kernel/random').mkdir(parents=True)
    (proc/'sys/kernel/random/boot_id').write_text(BOOT)
    tenant = {'slug': 'personal', 'uid': 1001, 'gid': 1001, **runtime.layout('personal'),
        'bridge_dropins': {}, 'gateway_dropins': {},
        'bridge_cgroup': '/system.slice/whatsapp-personal.service',
        'gateway_cgroup': '/user.slice/user-1001.slice/user@1001.service/app.slice/whatsapp-waha.service'}
    wrapper = ('#!/bin/sh\nset -eu\ncd '+tenant['home']+'\nexec runuser -u '+tenant['account']+
        ' -- env HOME='+tenant['home']+' XDG_RUNTIME_DIR=/run/user/1001 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus "$@"\n').encode()
    contents = {runtime.HELPER: (SCRIPTS/'runtime_lifecycle.py').read_bytes(),
        runtime.HELPER_LAYOUT: (SCRIPTS/'installation_layout.py').read_bytes(), tenant['wrapper']: wrapper,
        tenant['bridge_source']: (SCRIPTS.parent/'deploy/whatsapp-personal.service').read_bytes(),
        runtime.PROJECT+'/sally_whatsapp/example_runtime.py': b'# synthetic active source\n'}
    for name, content in contents.items(): write(root_path, name, content, 0o755 if name == tenant['wrapper'] else 0o644)
    quadlet = write(root_path, tenant['quadlet'], (SCRIPTS.parent/'deploy/whatsapp-waha.container').read_bytes(), 0o600)
    quadlet_spec = root.snapshot(tenant['quadlet'])
    tenant['quadlet_metadata'] = {**quadlet_spec, 'uid': 1001, 'gid': 1001}
    values = {}
    for component in ('bridge', 'gateway'):
        definition = {key: '' for key in runtime.DEFINITION}
        definition.update(Id=tenant[component+'_unit'], LoadState='loaded', NeedDaemonReload='no',
            FragmentPath=tenant['bridge_source'] if component == 'bridge' else '/run/user/1001/systemd/generator/whatsapp-waha.service',
            SourcePath='' if component == 'bridge' else tenant['quadlet'], User=tenant['account'] if component == 'bridge' else '',
            Restart='on-failure', KillMode='control-group')
        for key in runtime.EXEC_PROPERTIES: definition[key] = []
        if component == 'bridge':
            argv = [runtime.PROJECT+'/.venv/bin/python', '-m', 'sally_whatsapp.cli', '--config', '/etc/whatsapp-personal/config.toml', 'serve']
        else:
            argv = ['/usr/bin/podman', 'run', '--name', 'whatsapp-waha', '--cidfile=/run/user/1001/whatsapp-waha.cid', '--replace', '--rm', 'fixture-image']
            for key, ignore in (('ExecStop', False), ('ExecStopPost', True)):
                definition[key] = [{'path': '/usr/bin/podman', 'argv': ['/usr/bin/podman', 'rm', '-v', '-f', '-i', '--cidfile=/run/user/1001/whatsapp-waha.cid'], 'ignore_errors': ignore}]
        definition['ExecStart'] = [{'path': argv[0], 'argv': argv, 'ignore_errors': False}]
        tenant[component+'_definition'] = runtime.unit_definition(definition)
        values[component] = {**definition, 'ActiveState': 'active', 'SubState': 'running',
            'MainPID': '321', 'ControlPID': '0', 'Job': '', 'ControlGroup': tenant[component+'_cgroup'],
            'UnitFileState': 'enabled' if component == 'bridge' else 'generated'}
    before = {'format': 1, 'owner': 'whatsapp', 'files': {
        name: {**root.snapshot(name), 'retention': 'managed'} for name in contents}, 'directories': {}, 'links': {}}
    after = {**before, 'files': {name: before['files'][name] for name in
        (runtime.HELPER, runtime.HELPER_LAYOUT, tenant['wrapper'])}}
    admin_source = '/opt/wa-admin/receiver.py'; write(root_path, admin_source, b'# synthetic retired receiver\n')
    admin_manifest = {'format': 1, 'owner': 'whatsapp', 'files': {
        admin_source: {**root.snapshot(admin_source), 'retention': 'managed'}}, 'directories': {}}
    admin_scope = {'cgroups': [], 'script_roots': [], 'script_paths': [admin_source]}
    admin_plan = {'mode': 'remove', 'runtime_retirement': {'operation_id': 'd'*32}, 'id': 'a'*32, 'owner': {'protocol': 1, 'epoch': 'b'*32,
        'generation': '/opt/wa-generation', 'manifest_sha256': 'c'*64},
        'journal': {'path': runtime.STATE+'/admin-handoff.json', 'mode': 0o600, 'uid': root.uid, 'gid': root.gid}}
    admin_digest = runtime.digest(runtime.encoded(admin_plan))
    write(root_path, runtime.OWNER, runtime.encoded({**admin_plan['owner'], 'state': 'retired'}), 0o600)
    admin_record = {'format': 'whatsapp-admin-handoff-v1', 'plan_digest': admin_digest,
        'phase': 'retired', 'intent': None, 'sequence': 7, 'processes': [], 'evidence': {}}
    write(root_path, admin_plan['journal']['path'], runtime.encoded(admin_record), 0o600)
    class Admin:
        profile_digest = 'b'*64
        pending = False
        def journals_terminal(self, selected):
            assert selected == admin_plan
            if self.pending: raise runtime.Pending('Synthetic nonterminal backup journal')
        def observe(self, selected, prior, *, phase):
            assert selected == admin_plan and phase == 'removal'
            context = {'format': 1, 'authority': 'root-inventory', 'plan_digest': admin_digest,
                'invocation_id': admin_plan['id'], 'generation_id': 'c'*64,
                'inventory_digest': evidence.digest_inventory(admin_scope, admin_manifest, {}, prior_processes=prior),
                'boot_id': BOOT}
            receipt = evidence.observe(admin_scope, admin_manifest, context=context, units={},
                fs_root=root, proc_root=proc, runner=lambda *_a, **_k: pytest.fail('no admin unit calls'),
                clock_ns=lambda: 100, prior_processes=prior)
            return {'receipt': receipt, 'context': context, 'now_ns': 100}
        def now_ns(self): return 101
    admin = Admin()
    reference = '/etc/fixture/retired-runtime-invokers.json'
    write(root_path, reference, b'{"automatic_runtime_starts":[]}\n')
    registry_path = runtime.PROJECT + '/private/tenants.json'
    write(root_path, registry_path, runtime.encoded({'format': 1, 'instances': {
        'personal': {'spec': {'slug': 'personal'}, 'phase': 'ready', 'enabled': True}}}), 0o600)
    attestation = {'format': 1, 'operation_id': 'd'*32, 'tenant_slugs': ['personal'],
        'manual_policy': 'unregistered-runtime-starts-frozen', 'references': {
            reference: root.snapshot(reference), registry_path: root.snapshot(registry_path)}}
    attest_path = '/etc/fixture/runtime-inventory.json'
    write(root_path, attest_path, runtime.encoded(attestation), 0o600)
    plan = {'format': runtime.FORMAT, 'operation_id': 'd'*32,
        'source_sha256': before['files'][runtime.HELPER]['sha256'], 'admin_plan_sha256': admin_digest,
        'admin_profile_sha256': admin.profile_digest,
        'attestation': {'path': attest_path, 'sha256': root.snapshot(attest_path)['sha256']},
        'tenants': [tenant], 'scope': {'cgroups': [tenant['bridge_cgroup'], tenant['gateway_cgroup']],
                                     'script_roots': [], 'script_paths': []},
        'generation_id': 'e'*64, 'before': before, 'after': after,
        'qos_policy': {'path': '/etc/develative-host-qos/policy.json', 'sha256': 'f'*64}}
    calls = []
    def reader(argv):
        component = 'bridge' if argv[0] in ('/usr/bin/systemctl', '/usr/bin/busctl') else 'gateway'
        if argv[-1] in runtime.EXEC_PROPERTIES:
            key = argv[-1]; assert argv == runtime.command(tenant, component, key)
            records = [[item['path'], item['argv'], item['ignore_errors'], 1, 2, 3, 4, 321, 0, 0] for item in values[component][key]]
            return runtime.encoded({'type': 'a(sasbttttuii)', 'data': records})
        assert argv == runtime.command(tenant, component, 'show')
        return ('\n'.join(key+'='+value for key, value in values[component].items() if key not in runtime.EXEC_PROPERTIES)+'\n').encode()
    def runner(argv, *, lease):
        assert len(lease) == 1
        calls.append(argv)
        if '_retire-quadlet' in argv or '_check-quadlet' in argv or '_check-retired-quadlet' in argv:
            action = argv[5]
            assert len(argv) == 14 and argv[-1] == plan['before']['files'][runtime.HELPER_LAYOUT]['sha256']
            # Own filesystem helper is exercised separately with the real UID.
            # This is the explicit simulated runuser identity boundary.
            result = runtime.quadlet_retire(root_path/tenant['home'].lstrip('/'), plan['operation_id'],
                quadlet_spec, check_only=action != '_retire-quadlet', retired=action == '_check-retired-quadlet')
            return result
        component = 'bridge' if argv[0] == '/usr/bin/systemctl' else 'gateway'
        expected = next((operation for operation in ('disable', 'mask', 'stop', 'reload')
            if (operation != 'disable' or component == 'bridge') and (operation != 'mask' or component == 'gateway')
            and argv == runtime.command(tenant, component, operation)), None)
        assert expected is not None
        value = values[component]
        if expected == 'disable': value['UnitFileState'] = 'disabled'
        elif expected == 'mask': value.update(LoadState='masked', UnitFileState='masked', FragmentPath='/dev/null')
        elif expected == 'stop': value.update(ActiveState='inactive', SubState='dead', MainPID='0', ControlPID='0', ControlGroup='')
        elif expected == 'reload' and component == 'bridge' and root.snapshot(tenant['bridge_source']) is None:
            value.update(LoadState='not-found', UnitFileState='', FragmentPath='')
    class Frontend:
        retired = False
        @contextmanager
        def lease(self): yield
        def retire_application(self, *, owner, operation_id):
            assert owner == 'whatsapp'; self.retired = True
            return {'phase': 'complete', 'retirement': {'owner': owner, 'status': 'retired', 'retained_consumers': ['box']}}
        def retire_renewals(self, *, owner, operation_id):
            assert self.retired and owner == 'whatsapp'; return {'phase': 'complete'}
        def retirement_status(self, owner):
            return {'status': 'retired' if self.retired else 'active', 'owner': owner}
    class QoS:
        __name__ = 'fixture_qos'
        retired = False
        def operate(self, selected, *, action, consumer_id, **kwargs):
            assert selected is root and consumer_id == 'whatsapp.personal'
            if action == 'retire-consumer': self.retired = True
            else: assert action == 'check'
            return {'status': 'complete', 'consumer_status': 'retired' if self.retired else 'active',
                'consumer_id': consumer_id, 'uid': 1001}
    frontend, qos = Frontend(), QoS()
    def create(**changes):
        options = dict(admin_plan=admin_plan, admin_provider=admin, frontend_adapter=frontend,
            qos_module=qos, reader=reader, runner=runner,
            lookup=lambda name: SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_dir=tenant['home']), proc_root=proc)
        options.update(changes)
        return runtime.RuntimeHost(root, plan, **options)
    result = SimpleNamespace(root=root, path=root_path, proc=proc, plan=plan, tenant=tenant,
        admin=admin, admin_record=admin_record, admin_plan=admin_plan, calls=calls, values=values,
        frontend=frontend, qos=qos, create=create, reference=reference, quadlet=quadlet)
    yield result
    root.close()


def finish(fixture):
    results = []
    for _ in range(8):
        result = fixture.create().advance(); results.append(result)
        if result['complete']: return results
    pytest.fail('runtime retirement did not finish')


def qos_membership(fixture, *, own='retired', other=True, phase=None):
    """Public host records only; no kernel policy or application identity lookup."""
    fixture.plan['qos_policy'] = None
    policy = runtime.encoded({'synthetic_immutable_policy': True})
    registry = {'format': 1, 'policy_sha256': runtime.digest(policy), 'consumers': {
        'whatsapp.personal': {'owner': 'whatsapp', 'account': 'wa-personal', 'uid': 1001, 'gid': 1001,
            'home': '/var/lib/wa-personal', 'unit': 'wa-personal.service', 'status': own}}}
    if other:
        registry['consumers']['box.proxy'] = {'owner': 'box', 'account': 'boxproxy', 'uid': 1002, 'gid': 1002,
            'home': '/var/lib/boxproxy', 'unit': 'box-proxy.service', 'status': 'active'}
    paths = {'policy': '/etc/develative-host-qos/policy.json',
             'registry': '/etc/develative-host-qos/registry.json',
             'pointer': '/var/lib/develative-host-qos/active-operation.json',
             'journal': '/var/lib/develative-host-qos/operations/'+'a'*32+'.json'}
    write(fixture.path, paths['policy'], policy, 0o600)
    write(fixture.path, paths['registry'], runtime.encoded(registry), 0o600)
    if phase is not None:
        request = {'policy_sha256': registry['policy_sha256'], 'action': 'retire-consumer',
            'operation_id': 'a'*32, 'consumer_id': 'whatsapp.personal', 'account': None, 'unit': None}
        previous = copy.deepcopy(registry); previous['consumers']['whatsapp.personal']['status'] = 'active'
        write(fixture.path, paths['pointer'], runtime.encoded({'format': 1, 'request': request}), 0o600)
        write(fixture.path, paths['journal'], runtime.encoded({'format': 1, 'request': request,
            'phase': phase, 'before_registry': previous, 'after_registry': registry,
            'registration': None, 'registration_state': None, 'frontend_retirement': None,
            'steps': [], 'done': 0, 'initial_state': {}}), 0o600)
    return paths, registry


@pytest.mark.parametrize('problem', ('active', 'owner-mismatch', 'ambiguous-status', 'policy-only',
    'registry-only', 'policy-drift', 'pending-retirement', 'missing-journal', 'pointer-mismatch',
    'unprotected', 'duplicate-field', 'nonfinite', 'incomplete-committed', 'registry-commit-drift'))
def test_null_qos_rejects_active_ambiguous_or_pending_membership_before_commands(fixture, problem):
    paths, registry = qos_membership(fixture, phase='committed')
    if problem == 'active': registry['consumers']['whatsapp.personal']['status'] = 'active'
    elif problem == 'owner-mismatch': registry['consumers']['whatsapp.personal']['owner'] = 'box'
    elif problem == 'ambiguous-status': registry['consumers']['whatsapp.personal']['status'] = None
    if problem in ('active', 'owner-mismatch', 'ambiguous-status'):
        write(fixture.path, paths['registry'], runtime.encoded(registry), 0o600)
    elif problem == 'policy-only': (fixture.path/paths['registry'].lstrip('/')).unlink()
    elif problem == 'registry-only': (fixture.path/paths['policy'].lstrip('/')).unlink()
    elif problem == 'policy-drift': write(fixture.path, paths['policy'], b'changed', 0o600)
    elif problem == 'pending-retirement':
        record = runtime.decode(fixture.root.read_bytes(paths['journal'])); record['phase'] = 'kernel-complete'
        write(fixture.path, paths['journal'], runtime.encoded(record), 0o600)
    elif problem == 'missing-journal': (fixture.path/paths['journal'].lstrip('/')).unlink()
    elif problem == 'pointer-mismatch':
        record = runtime.decode(fixture.root.read_bytes(paths['journal'])); record['request']['consumer_id'] = 'box.proxy'
        write(fixture.path, paths['journal'], runtime.encoded(record), 0o600)
    elif problem == 'unprotected': (fixture.path/paths['registry'].lstrip('/')).chmod(0o666)
    elif problem == 'duplicate-field':
        write(fixture.path, paths['registry'], b'{"format":1,"format":1}', 0o600)
    elif problem == 'nonfinite':
        write(fixture.path, paths['pointer'], b'{"format":1,"request":{"x":NaN}}', 0o600)
    elif problem in ('incomplete-committed', 'registry-commit-drift'):
        record = runtime.decode(fixture.root.read_bytes(paths['journal']))
        if problem == 'incomplete-committed': record['done'] = 1
        else: record['after_registry']['consumers']['box.proxy']['status'] = 'retired'
        write(fixture.path, paths['journal'], runtime.encoded(record), 0o600)
    with pytest.raises((runtime.RuntimeError, ValueError)):
        fixture.create(qos_module=None).advance()
    assert not fixture.calls and not fixture.frontend.retired and not fixture.qos.retired
    assert fixture.quadlet.exists()


@pytest.mark.parametrize('committed_history', (False, True))
def test_null_qos_preserves_retired_history_and_other_product_without_loading_qos(fixture, committed_history):
    paths, _ = qos_membership(fixture, phase='committed' if committed_history else None)
    snapshots = {name: fixture.root.snapshot(path) for name, path in paths.items()}
    assert not any(path.startswith('host/qos/') for path in runtime.source_paths(fixture.plan))
    assert not (fixture.path/'etc/box-installation-identity.json').exists()
    assert fixture.create(qos_module=None).qos is None
    assert finish(fixture)[-1]['complete']
    assert snapshots == {name: fixture.root.snapshot(path) for name, path in paths.items()}
    assert not fixture.qos.retired


def test_null_qos_with_no_host_records_remains_standalone(fixture):
    fixture.plan['qos_policy'] = None
    assert finish(fixture)[-1]['complete'] and not fixture.qos.retired
    assert not (fixture.path/'etc/develative-host-qos').exists()


@pytest.mark.parametrize('phase', ('prepared', 'services_closed', 'verified'))
def test_null_qos_membership_drift_blocks_each_later_phase_before_further_effects(fixture, phase):
    paths, registry = qos_membership(fixture)
    while fixture.create().advance()['phase'] != phase:
        pass
    calls = list(fixture.calls)
    registry['consumers']['whatsapp.personal']['status'] = 'active'
    write(fixture.path, paths['registry'], runtime.encoded(registry), 0o600)
    with pytest.raises(runtime.RuntimeError, match='active WhatsApp'):
        fixture.create(qos_module=None).advance()
    assert calls == fixture.calls and not fixture.qos.retired


def test_null_qos_detects_membership_race_during_its_read_only_observation(fixture, monkeypatch):
    paths, registry = qos_membership(fixture, phase='committed')
    original = fixture.root.read_bytes
    def read(path, **options):
        raw = original(path, **options)
        if path == paths['journal']:
            registry['consumers']['whatsapp.personal']['status'] = 'active'
            write(fixture.path, paths['registry'], runtime.encoded(registry), 0o600)
        return raw
    monkeypatch.setattr(fixture.root, 'read_bytes', read)
    with pytest.raises(runtime.RuntimeError, match='membership changed'):
        fixture.create(qos_module=None).advance()
    assert not fixture.calls and not fixture.frontend.retired


def test_runtime_retirement_preserves_data_accounts_and_other_application(fixture):
    data = write(fixture.path, '/var/lib/whatsapp-personal/archive.sqlite', b'synthetic-preserved-data')
    session = write(fixture.path, fixture.tenant['home']+'/sessions/phone-state', b'preserved-session')
    box = write(fixture.path, '/etc/systemd/system/box.service', b'box-stays-cold-bootable')
    assert [item['phase'] for item in finish(fixture)] == list(runtime.PHASES)
    assert data.read_bytes() == b'synthetic-preserved-data' and session.read_bytes() == b'preserved-session'
    assert box.read_bytes() == b'box-stays-cold-bootable'
    assert fixture.root.snapshot(fixture.tenant['bridge_source']) is None
    assert not fixture.quadlet.exists()
    assert fixture.quadlet.with_name(runtime._quarantine_name(fixture.plan['operation_id'])).exists()
    assert fixture.root.snapshot(fixture.tenant['wrapper']) is not None
    assert fixture.values['bridge']['LoadState'] == 'not-found'
    assert fixture.values['gateway']['LoadState'] == 'masked'
    flattened = ' '.join(arg for argv in fixture.calls for arg in argv)
    assert all(word not in flattened for word in ('podman', 'userdel', 'loginctl', 'sally-auth', 'box.service'))


def test_runtime_retirement_cannot_quarantine_the_retained_helpers_layout(fixture):
    fixture.plan['after']['files'].pop(runtime.HELPER_LAYOUT)
    with pytest.raises(runtime.RuntimeError, match='helper/wrappers must remain'):
        runtime.validate_plan(fixture.plan, authority_uid=fixture.root.uid)
    assert not fixture.calls


@pytest.mark.parametrize('phase,enabled', [('ready', True), ('ready', False), ('preparing', True), ('prepared', False)])
def test_partial_tenant_retirement_cannot_remove_whole_frontend(fixture, phase, enabled):
    registry_path = runtime.PROJECT + '/private/tenants.json'
    registry = runtime.decode(fixture.root.read_bytes(registry_path))
    registry['instances']['team'] = {'spec': {'slug': 'team'}, 'phase': phase, 'enabled': enabled}
    write(fixture.path, registry_path, runtime.encoded(registry), 0o600)
    attestation_path = fixture.plan['attestation']['path']
    attestation = runtime.decode(fixture.root.read_bytes(attestation_path))
    attestation['references'][registry_path] = fixture.root.snapshot(registry_path)
    write(fixture.path, attestation_path, runtime.encoded(attestation), 0o600)
    fixture.plan['attestation']['sha256'] = fixture.root.snapshot(attestation_path)['sha256']
    with pytest.raises(runtime.RuntimeError, match='every registered tenant'):
        fixture.create().advance()
    assert not fixture.calls and not fixture.frontend.retired
    assert fixture.root.snapshot(fixture.tenant['bridge_source']) is not None
    assert fixture.quadlet.exists()


def test_runtime_retirement_requires_registry_reference_even_with_manual_attestation(fixture):
    path = fixture.plan['attestation']['path']
    attestation = runtime.decode(fixture.root.read_bytes(path))
    del attestation['references'][runtime.PROJECT + '/private/tenants.json']
    write(fixture.path, path, runtime.encoded(attestation), 0o600)
    fixture.plan['attestation']['sha256'] = fixture.root.snapshot(path)['sha256']
    with pytest.raises(runtime.RuntimeError, match='protected tenant registry'):
        fixture.create().advance()
    assert not fixture.calls and not fixture.frontend.retired


def test_prepared_tenant_is_admitted_when_the_registry_is_complete(fixture):
    registry_path = runtime.PROJECT + '/private/tenants.json'
    registry = runtime.decode(fixture.root.read_bytes(registry_path))
    registry['instances']['personal'].update(phase='prepared', enabled=False)
    write(fixture.path, registry_path, runtime.encoded(registry), 0o600)
    attestation_path = fixture.plan['attestation']['path']
    attestation = runtime.decode(fixture.root.read_bytes(attestation_path))
    attestation['references'][registry_path] = fixture.root.snapshot(registry_path)
    write(fixture.path, attestation_path, runtime.encoded(attestation), 0o600)
    fixture.plan['attestation']['sha256'] = fixture.root.snapshot(attestation_path)['sha256']
    assert fixture.create()._admission()
    assert not fixture.calls and not fixture.frontend.retired


def test_registry_drift_during_retirement_blocks_before_further_effects(fixture):
    fixture.create().advance()
    fixture.create().advance()
    calls_before = list(fixture.calls)
    registry_path = runtime.PROJECT + '/private/tenants.json'
    registry = runtime.decode(fixture.root.read_bytes(registry_path))
    registry['instances']['team'] = {'spec': {'slug': 'team'}, 'phase': 'preparing', 'enabled': True}
    write(fixture.path, registry_path, runtime.encoded(registry), 0o600)
    with pytest.raises(runtime.RuntimeError, match='external reference changed'):
        fixture.create().advance()
    assert fixture.calls == calls_before and not fixture.frontend.retired
    assert fixture.quadlet.exists()


@pytest.mark.parametrize('event', ['after-services_closed', 'after-quadlets_retired', 'after-consumers_retired',
                                  'before-files_removed', 'after-files_removed', 'after-verified'])
def test_each_effect_can_resume_forward_after_controller_failure(fixture, event):
    def fault(name, value):
        if name == event: raise OSError('synthetic controller loss')
    with pytest.raises(OSError):
        for _ in range(8): fixture.create(fault=fault).advance()
    assert finish(fixture)[-1]['complete']


@pytest.mark.parametrize('fault', ['retiring-owner', 'admin-not-retired', 'pending-backup', 'wrapper-drift', 'external-reference-drift'])
def test_incomplete_admission_stops_before_service_changes(fixture, fault):
    if fault == 'retiring-owner':
        write(fixture.path, runtime.OWNER, runtime.encoded({**fixture.admin_plan['owner'], 'state': 'retiring'}), 0o600)
    elif fault == 'admin-not-retired':
        fixture.admin_record['phase'] = 'drained'
        write(fixture.path, fixture.admin_plan['journal']['path'], runtime.encoded(fixture.admin_record), 0o600)
    elif fault == 'pending-backup': fixture.admin.pending = True
    elif fault == 'wrapper-drift': write(fixture.path, fixture.tenant['wrapper'], b'#!/bin/sh\nexit 0\n')
    else: write(fixture.path, fixture.reference, b'new invoker')
    with pytest.raises((runtime.RuntimeError, ValueError)): fixture.create().advance()
    assert not fixture.calls


def test_queued_job_and_late_scoped_process_block_cleanup(fixture):
    fixture.create().advance()
    fixture.values['gateway']['Job'] = '9 /org/freedesktop/systemd1/job/9'
    with pytest.raises(runtime.Pending, match='manager job'): fixture.create().advance()
    fixture.values['gateway']['Job'] = ''
    fixture.create().advance()
    pid = fixture.proc/'900'; pid.mkdir()
    (pid/'stat').write_text('900 (synthetic) S 1 900 900 '+'0 '*15+'100\n')
    (pid/'cgroup').write_text('0::'+fixture.tenant['gateway_cgroup']+'\n')
    (pid/'cmdline').write_bytes(b'fixture\0')
    with pytest.raises(runtime.Pending, match='process'): fixture.create().advance()
    assert fixture.quadlet.exists()


def test_final_observation_rejects_a_late_job_or_reactivated_consumer(fixture):
    finish(fixture)
    fixture.values['bridge']['Job'] = '8 /job/8'
    with pytest.raises(runtime.Pending): fixture.create().advance()
    fixture.values['bridge']['Job'] = ''
    fixture.qos.retired = False
    with pytest.raises(runtime.RuntimeError, match='QoS consumer'): fixture.create().advance()


def test_named_source_or_unit_scope_cannot_target_another_application(fixture):
    plan = copy.deepcopy(fixture.plan)
    plan['tenants'][0]['bridge_unit'] = 'box.service'
    with pytest.raises(runtime.RuntimeError): runtime.validate_plan(plan)
    plan = copy.deepcopy(fixture.plan)
    plan['before']['files']['/etc/box.conf'] = next(iter(plan['before']['files'].values()))
    with pytest.raises(runtime.RuntimeError, match='outside'): runtime.validate_plan(plan)


@pytest.mark.parametrize('fault', ['symlink', 'hardlink', 'changed', 'target-collision', 'parent-writable'])
def test_quadlet_helper_refuses_unsafe_state_without_touching_other_files(tmp_path, fault):
    home = tmp_path/'home'; parent = home/'.config/containers/systemd'; parent.mkdir(parents=True)
    source = parent/'whatsapp-waha.container'; source.write_text('[Container]\nImage=fixture\n'); source.chmod(0o600)
    expected = {'sha256': runtime.digest(source.read_bytes()), 'mode': 0o600, 'uid': os.geteuid(), 'gid': os.getegid()}
    other = tmp_path/'other'; other.write_text('preserve')
    if fault == 'symlink': source.unlink(); source.symlink_to(other)
    elif fault == 'hardlink': os.link(source, tmp_path/'alias')
    elif fault == 'changed': source.write_text('changed')
    elif fault == 'target-collision': (parent/runtime._quarantine_name('a'*32)).write_text('foreign quarantine')
    else: parent.chmod(0o777)
    with pytest.raises((runtime.RuntimeError, OSError)):
        runtime.quadlet_retire(home, 'a'*32, expected)
    assert other.read_text() == 'preserve' and source.exists()


def test_uid_quadlet_helper_is_readonly_then_atomic_and_idempotent(tmp_path):
    home = tmp_path/'home'; parent = home/'.config/containers/systemd'; parent.mkdir(parents=True)
    source = parent/'whatsapp-waha.container'; source.write_text('[Container]\nImage=fixture\n'); source.chmod(0o600)
    expected = {'sha256': runtime.digest(source.read_bytes()), 'mode': 0o600, 'uid': os.geteuid(), 'gid': os.getegid()}
    assert runtime.quadlet_retire(home, 'a'*32, expected, check_only=True)['status'] == 'present'
    assert source.exists()
    first = runtime.quadlet_retire(home, 'a'*32, expected)
    assert runtime.quadlet_retire(home, 'a'*32, expected) == first
    assert runtime.quadlet_retire(home, 'a'*32, expected, check_only=True, retired=True)['status'] == 'retired'


def real_providers(fixture):
    """Real neutral state machines, journals and adapters; only external I/O is simulated."""
    def module(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        loaded = importlib.util.module_from_spec(spec); spec.loader.exec_module(loaded)
        return loaded
    base = SCRIPTS.parents[2]
    qt = module('wa_runtime_qos_fixture', base/'tools/tests/test_host_qos_applicator.py')
    ft = module('wa_runtime_frontend_fixture', base/'tools/tests/test_host_frontend.py')
    qos = qt.qos
    policy = json.loads(qt.PROFILE.read_bytes())
    policy['initial_consumers'].pop('whatsapp.secondary')
    policy['initial_consumers']['whatsapp.personal'].update(uid=1001, gid=1001)
    raw = qos.canonical(policy)
    write(fixture.path, qos.POLICY, raw)
    (fixture.path/qos.STATE.lstrip('/')).mkdir(parents=True, mode=0o700)
    (fixture.path/(qos.STATE+'/operations').lstrip('/')).mkdir()
    write(fixture.path, qos.LOCK, b'', 0o600)
    state = json.loads(qt.OBSERVATION.read_bytes())
    state['nft'] = qos.nft_policy(policy, policy['initial_consumers'], legacy=True)[1]
    kernel = qt.FakeKernel(state)
    accounts = {**policy['parameters']['essential_accounts'], 'boxproxy': policy['parameters']['box_account']}
    for value in policy['initial_consumers'].values(): accounts[value['account']] = {**value, 'shell': '/usr/sbin/nologin'}
    def lookup(name):
        value = accounts[name]
        return SimpleNamespace(pw_name=name, pw_uid=value['uid'], pw_gid=value['gid'], pw_dir=value['home'], pw_shell=value['shell'])
    options = {'kernel_factory': kernel.factory, 'lookup': lookup, 'census': lambda: [lookup(name) for name in accounts], 'proc_root': fixture.proc}
    qos.operate(fixture.root, policy_path=qos.POLICY, expected_sha256=qos.sha(raw), action='apply', operation_id='1'*32, **options)
    registry, artifacts, profile, frontend_runner, adapter = ft.staged_setup(ft.registry.__wrapped__(), fixture.root)
    with adapter.lease():
        ft.finite.apply_configuration(adapter, operation_id='2'*32, before=ft.empty(), pinned_artifacts=artifacts)
    for item in profile['lineages'].values(): write(fixture.path, item['renewal']['path'], b'renewal fixture\n')
    fixture.plan['qos_policy'] = {'path': qos.POLICY, 'sha256': qos.sha(raw)}
    return qos, options, adapter, kernel, frontend_runner, ft


def test_real_neutral_providers_retire_runtime_while_preserving_box_frontend_tc_and_io(fixture):
    qos, options, frontend, kernel, runner, _ = real_providers(fixture)
    initial = kernel.observe()
    for _ in range(8):
        result = fixture.create(qos_module=qos, qos_options=options, frontend_adapter=frontend).advance()
        if result['complete']: break
    assert result['complete']
    registry = qos.decode(fixture.root.read_bytes(qos.REGISTRY))
    assert registry['consumers']['whatsapp.personal']['status'] == 'retired'
    assert registry['consumers']['box.proxy']['status'] == 'active'
    assert kernel.state['tc'] == initial['tc'] and kernel.state['io'] == initial['io']
    assert fixture.root.snapshot('/etc/apache2/sites-enabled/owner.conf') is None
    assert fixture.root.snapshot('/etc/apache2/sites-enabled/web.conf') is not None
    assert fixture.root.snapshot('/etc/apache2/sites-enabled/sally.conf') is not None
    assert fixture.root.snapshot('/etc/letsencrypt/renewal/owner.example.test.conf') is None
    assert fixture.root.snapshot('/etc/letsencrypt/renewal/web.example.test.conf') is not None


def cli_operation(fixture, tmp_path):
    import admin_install
    import test_admin_handoff as helpers
    qos, options, frontend, kernel, runner, ft = real_providers(fixture)
    (tmp_path/'admin').mkdir()
    admin_root, plan, payloads, provider = helpers.fixture(tmp_path/'admin', mode='remove')
    try:
        profile = {'format': 'whatsapp-host-inventory-v1',
            'attestation': {'path': '/etc/develative-deploy/inventory/initial.json', 'sha256': 'a'*64},
            'retirement_attestation': {'path': '/etc/develative-deploy/inventory/retired.json', 'sha256': 'b'*64},
            'stages': {name: {**value, 'units': {}} for name, value in provider.inventories.items()},
            'final_manifest': plan['actions']['remove']['after'], 'retained_manifest': helpers.manifest(),
            'invokers': [], 'generation_id': 'c'*64}
        plan['inventory_digest'] = evidence.digest(profile)
        plan['runtime_retirement'] = {'operation_id': fixture.plan['operation_id']}
        admin_raw, admin_hash = admin_install.encode_operation(plan, profile, payloads, source_revision='a'*40)
    finally: admin_root.close()
    admin_path = '/etc/develative-deploy/inventory/admin-operation.json'
    write(fixture.path, admin_path, admin_raw)
    fixture.plan['admin_plan_sha256'] = runtime.digest(runtime.encoded(plan))
    fixture.plan['admin_profile_sha256'] = evidence.digest(profile)
    front = {'profile': {'path': ft.finite.PROFILE, 'sha256': fixture.root.snapshot(ft.finite.PROFILE)['sha256']},
        'registry': {'path': ft.front.REGISTRY, 'sha256': fixture.root.snapshot(ft.front.REGISTRY)['sha256']}}
    raw = runtime.encode_operation(fixture.plan, admin_operation={'path': admin_path, 'sha256': admin_hash},
        frontend=front, source_revision='a'*40)
    write(fixture.path, '/runtime-operation.json', raw)
    return raw


def test_cold_cli_inspects_protected_complete_operation_without_mutation(fixture, tmp_path):
    raw = cli_operation(fixture, tmp_path)
    before = {str(path): path.read_bytes() for path in fixture.path.rglob('*') if path.is_file()}
    argv = [sys.executable, '-I', '-B', str(SCRIPTS/'runtime_lifecycle.py'), 'inspect',
        '--root', str(fixture.path), '--operation', '/runtime-operation.json', '--sha256', runtime.digest(raw)]
    result = subprocess.run(argv, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report['mutations'] is False and report['ssh_inventory_proven'] is False
    assert report['required_admin_phase'] == 'retired'
    assert before == {str(path): path.read_bytes() for path in fixture.path.rglob('*') if path.is_file()}
    argv[4] = 'advance'
    assert subprocess.run(argv, capture_output=True).returncode != 0


@pytest.mark.parametrize('dependency', ['host/frontend/provider.py', 'plugins/whatsapp/scripts/installation_layout.py'])
def test_cli_rejects_tampered_dependency_before_any_import(fixture, tmp_path, dependency):
    raw = cli_operation(fixture, tmp_path)
    checkout = tmp_path/'checkout'
    for relative in runtime.SOURCES:
        target = checkout/relative; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(runtime.SOURCE_ROOT/relative, target)
    marker = tmp_path/'unreviewed-source-executed'
    (checkout/dependency).write_text('from pathlib import Path\nPath('+repr(str(marker))+').touch()\n')
    result = subprocess.run([sys.executable, '-I', '-B', str(checkout/'plugins/whatsapp/scripts/runtime_lifecycle.py'),
        'inspect', '--root', str(fixture.path), '--operation', '/runtime-operation.json', '--sha256', runtime.digest(raw)],
        capture_output=True)
    assert result.returncode != 0 and not marker.exists()


def test_bridge_dropins_are_exactly_pinned_and_quarantined(fixture):
    for name in ('60-whatsapp-priority.conf', '70-release-runtime.conf'):
        path = fixture.tenant['bridge_source']+'.d/'+name
        write(fixture.path, path, b'[Service]\n# synthetic reviewed drop-in\n')
        spec = fixture.root.snapshot(path)
        fixture.tenant['bridge_dropins'][path] = spec
        fixture.plan['before']['files'][path] = {**spec, 'retention': 'managed'}
    text = ' '.join(sorted(fixture.tenant['bridge_dropins']))
    fixture.tenant['bridge_definition']['DropInPaths'] = text
    fixture.values['bridge']['DropInPaths'] = text
    old_create = fixture.create
    def create(**extra):
        host = old_create(**extra); original = host.runner
        def runner(argv, **kwargs):
            result = original(argv, **kwargs)
            if argv == runtime.command(fixture.tenant, 'bridge', 'reload'):
                fixture.values['bridge']['DropInPaths'] = ''
            return result
        host.runner = runner
        return host
    fixture.create = create
    assert finish(fixture)[-1]['complete']
    assert all(fixture.root.snapshot(path) is None for path in fixture.tenant['bridge_dropins'])


def test_effective_unit_observer_hashes_commands_and_rejects_unknown_or_changing_state(fixture):
    secret = '/synthetic/command token=fixture-never-exported'
    fixture.values['gateway']['ExecStart'][0]['argv'].append(secret)
    observed = fixture.create().observe_units()
    serialized = runtime.encoded(observed)
    assert secret.encode() not in serialized and b'fixture-never-exported' not in serialized
    assert observed['units']['personal:gateway']['definition']['ExecStart'] == 'sha256:' + runtime.digest(runtime.encoded(fixture.values['gateway']['ExecStart']))
    assert observed['mutations'] is False and observed['invoker_completeness_proven'] is False
    assert not fixture.calls
    fixture.values['gateway'].pop('SourcePath')
    with pytest.raises(runtime.RuntimeError, match='Incomplete'): fixture.create().observe_units()


def test_gateway_priority_is_retained_and_rechecked_behind_mask(fixture):
    path = fixture.tenant['home']+'/.config/systemd/user/whatsapp-waha.service.d/60-whatsapp-priority.conf'
    content = b'# Managed by WhatsApp resource priority.\n[Service]\nCPUWeight=800\nIOWeight=800\n'
    retained = write(fixture.path, path, content)
    # Current fixture UID models administrative authority; real PRO8 file is 0:0.
    spec = fixture.root.snapshot(path)
    fixture.tenant['gateway_dropins'][path] = spec
    fixture.tenant['gateway_definition']['DropInPaths'] = path
    fixture.values['gateway']['DropInPaths'] = path
    old_create = fixture.create
    def create(**extra):
        host = old_create(**extra); previous = host.runner
        def runner(argv, **kwargs):
            if argv[-2] == 'gateway-priority':
                assert argv[5] == '_check-quadlet'
                assert argv[-1] == fixture.plan['before']['files'][runtime.HELPER_LAYOUT]['sha256']
                return runtime.quadlet_retire(fixture.path/fixture.tenant['home'].lstrip('/'),
                    fixture.plan['operation_id'], spec, check_only=True, artifact='gateway-priority')
            result = previous(argv, **kwargs)
            if argv == runtime.command(fixture.tenant, 'gateway', 'mask'):
                fixture.values['gateway']['DropInPaths'] = ''
            return result
        host.runner = runner
        return host
    fixture.create = create
    assert finish(fixture)[-1]['complete']
    assert retained.read_bytes() == content and fixture.root.snapshot(path) == spec
    assert not list(retained.parent.glob('*.quarantine'))
    retained.write_bytes(content+b'ExecStart=/unexpected\n')
    with pytest.raises(runtime.RuntimeError, match='unsupported effects'): fixture.create().advance()


def test_retained_priority_helper_has_no_mutating_mode(tmp_path):
    home = tmp_path/'home'; parent = home/'.config/systemd/user/whatsapp-waha.service.d'; parent.mkdir(parents=True)
    source = parent/'60-whatsapp-priority.conf'; source.write_bytes(b'[Service]\nCPUWeight=800\nIOWeight=800\n'); source.chmod(0o644)
    spec = {'sha256': runtime.digest(source.read_bytes()), 'mode': 0o644, 'uid': os.geteuid(), 'gid': os.getegid()}
    with pytest.raises(runtime.RuntimeError, match='read-only'):
        runtime.quadlet_retire(home, 'a'*32, spec, artifact='gateway-priority')
    assert runtime.quadlet_retire(home, 'a'*32, spec, artifact='gateway-priority', check_only=True)['status'] == 'retained'


def test_runtime_journal_is_bound_to_administrative_removal(fixture):
    fixture.create().advance()
    path = fixture.create().journal_path
    journal = runtime.decode(fixture.root.read_bytes(path))
    assert journal['operation_id'] == fixture.plan['operation_id']
    assert journal['admin_plan_sha256'] == runtime.digest(runtime.encoded(fixture.admin_plan))
    journal['admin_plan_sha256'] = '0'*64
    write(fixture.path, path, runtime.encoded(journal), 0o600)
    fixture.calls.clear()
    with pytest.raises(runtime.RuntimeError, match='identity'): fixture.create().advance()
    assert not fixture.calls


def test_captured_qos_closure_includes_process_observer_and_operates_without_sibling_bootstrap(fixture):
    qos, options, frontend, kernel, runner, _ = real_providers(fixture)
    assert set(qos.SOURCES) <= set(runtime.SOURCES)
    captured = {name: (runtime.SOURCE_ROOT/name).read_bytes() for name in runtime.SOURCES}
    previous = dict(sys.modules)
    try:
        modules = runtime._compile_sources(captured, '/unavailable-reviewed-source-tree')
        pinned = modules['host.qos.applicator']
        assert pinned.processes is modules['host.qos.processes']
        pinned.bootstrap = lambda *a, **kw: pytest.fail('must not reread a sibling after captured compile')
        value = pinned.operate(fixture.root, policy_path=fixture.plan['qos_policy']['path'],
            expected_sha256=fixture.plan['qos_policy']['sha256'], action='check',
            consumer_id='whatsapp.personal', **options)
        assert value['status'] == 'complete' and value['consumer_status'] == 'active'
    finally:
        for name in set(sys.modules)-set(previous): del sys.modules[name]
        sys.modules.update(previous)


RUNTIME_SUPERVISOR_PROBE = r'''
import ctypes, fcntl, importlib.util, os, pathlib, signal, subprocess, sys, time
root, source = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
sys.path.insert(0, str(source.parents[3]))
sys.path.insert(0, str(source.parents[1]))
from tools.testing.installation_fixture import select_legacy
select_legacy()
spec=importlib.util.spec_from_file_location('runtime',source)
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
lock, ready, release, supervisor_pid = [root/name for name in ('lease','ready','release','supervisor')]
lock.write_text('stable lease inode'); inode=lock.stat().st_ino
client=root/'client.py'
client.write_text("""import os,pathlib,sys,time
child=os.fork()
if child: os._exit(0)
os.setsid()
os.closerange(0,65536)
# The final path is the readiness signal: publish only after the PID is complete.
ready=pathlib.Path(sys.argv[1]);pending=ready.with_suffix('.pending')
pending.write_text(str(os.getpid()))
pending.replace(ready)
end=time.monotonic()+8
while not pathlib.Path(sys.argv[2]).exists() and time.monotonic()<end: time.sleep(.01)
os._exit(0)
""")
controller=os.fork()
if controller==0:
    fd=os.open(lock,os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX)
    supervisor=os.fork()
    if supervisor==0:
        supervisor_pid.write_text(str(os.getpid()))
        try:
            runtime.supervise_runtime_client([sys.executable,'-I','-B',str(client),str(ready),str(release)],(fd,),timeout=3)
            os._exit(0)
        except BaseException: os._exit(71)
    end=time.monotonic()+4
    while not ready.exists() and time.monotonic()<end: time.sleep(.01)
    os._exit(73 if ready.exists() else 74)
supervisor=descendant=None
try:
    assert os.waitpid(controller,0)[1]==73<<8
    supervisor=int(supervisor_pid.read_text());descendant=int(ready.read_text())
    # The direct client exited; only our subreaper supervises the setsid helper.
    time.sleep(.05)
    assert pathlib.Path('/proc',str(descendant)).exists()
    with lock.open('r+') as stream:
        try: fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: pass
        else: raise AssertionError('lease lost before detached UID helper was reaped')
    with (root/'box-unrelated-lease').open('w') as stream: fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
    release.write_text('finish')
    pid,status=os.waitpid(supervisor,0);supervisor=None
    assert os.waitstatus_to_exitcode(status)==0
    assert not pathlib.Path('/proc',str(descendant)).exists();descendant=None
    with lock.open('r+') as stream: fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
    assert lock.stat().st_ino==inode
    print('detached-helper-reaped-before-lease-release')
finally:
    release.write_text('finish')
    for pid in (descendant,supervisor):
        if pid:
            try: os.kill(pid,signal.SIGKILL)
            except ProcessLookupError: pass
    end=time.monotonic()+2
    while time.monotonic()<end:
        try: pid,_=os.waitpid(-1,os.WNOHANG)
        except ChildProcessError: break
        if not pid: time.sleep(.01)
'''


def test_runtime_supervisor_retains_lease_after_parent_and_direct_client_exit(tmp_path):
    completed = subprocess.run([sys.executable, '-I', '-B', '-c', RUNTIME_SUPERVISOR_PROBE,
        str(tmp_path), str(SCRIPTS/'runtime_lifecycle.py')], capture_output=True, text=True, timeout=12)
    assert completed.returncode == 0, completed.stderr
    assert 'detached-helper-reaped-before-lease-release' in completed.stdout


@pytest.mark.parametrize('field', ['OnFailure', 'OnSuccess', 'PropagatesStopTo', 'BoundBy', 'ConsistsOf', 'RequiredBy', 'RequisiteOf', 'Triggers'])
def test_loaded_cross_application_effects_block_before_any_service_action(fixture, field):
    fixture.values['gateway'][field] = 'box-browser.service'
    # Even an externally approved hash cannot widen the executable contract.
    fixture.tenant['gateway_definition'] = runtime.unit_definition(fixture.values['gateway'])
    with pytest.raises(runtime.RuntimeError, match='propagate'): fixture.create().advance()
    assert not fixture.calls


@pytest.mark.parametrize('fault', ['arbitrary-stop', 'wrong-container', 'auxiliary', 'unlinked-start'])
def test_effective_commands_require_finite_local_lifecycle_semantics(fixture, fault):
    value = fixture.values['gateway']
    if fault == 'arbitrary-stop': value['ExecStopPost'][0]['path'] = '/usr/sbin/userdel'
    elif fault == 'wrong-container': value['ExecStop'][0]['argv'][-1] = '--cidfile=/run/user/1001/box.cid'
    elif fault == 'auxiliary': value['ExecCondition'] = value['ExecStart']
    else: value['ExecStart'][0]['argv'][3] = 'box'
    fixture.tenant['gateway_definition'] = runtime.unit_definition(value)
    with pytest.raises(runtime.RuntimeError): fixture.create().advance()
    assert not fixture.calls


def test_exec_observation_preserves_argument_boundaries_and_ignores_runtime_timestamps():
    argv = ['/usr/bin/podman', 'rm', '-v', '-f', '-i', '--cidfile=/run/user/1001/whatsapp-waha.cid']
    first = {'type': 'a(sasbttttuii)', 'data': [['/usr/bin/podman', argv, False, 1, 2, 3, 4, 321, 0, 0]]}
    later = copy.deepcopy(first); later['data'][0][3:] = [8, 9, 10, 11, 999, 1, 0]
    assert runtime.exec_commands(runtime.encoded(first)) == runtime.exec_commands(runtime.encoded(later))
    altered = copy.deepcopy(first); altered['data'][0][1] = [' '.join(argv)]
    assert runtime.exec_commands(runtime.encoded(first)) != runtime.exec_commands(runtime.encoded(altered))


def test_existing_engine_directory_with_missing_journal_remains_closed(fixture):
    def fault(name, value):
        if name == 'before-files_removed': raise OSError('crash before engine creation')
    with pytest.raises(OSError):
        for _ in range(8): fixture.create(fault=fault).advance()
    host = fixture.create()
    path = fixture.path/(filesystem.STATE+'/whatsapp/operations/'+host._files_id()).lstrip('/')
    path.mkdir(parents=True, mode=0o700)
    with pytest.raises(filesystem.LifecycleError): host.advance()
    assert fixture.root.snapshot(fixture.tenant['bridge_source']) is not None


def test_pending_manager_job_on_pre_engine_resume_blocks_before_quarantine(fixture):
    def fault(name, value):
        if name == 'before-files_removed': raise OSError('crash before engine creation')
    with pytest.raises(OSError):
        for _ in range(8): fixture.create(fault=fault).advance()
    fixture.values['bridge']['Job'] = '8 /org/freedesktop/systemd1/job/8'
    with pytest.raises(runtime.Pending): fixture.create().advance()
    assert fixture.root.snapshot(fixture.tenant['bridge_source']) is not None
    fixture.values['bridge']['Job'] = ''
    assert finish(fixture)[-1]['complete']


@pytest.fixture
def initial_observation(tmp_path):
    """Only initial named sources exist; no administration or installed helper.

    The temporary root's real UID models administrative authority. The same UID
    owns the fixture Quadlet; production separately requires the gateway UID.
    """
    root_path = tmp_path/'initial-root'; root_path.mkdir()
    root = filesystem.Root(root_path)
    from host.installation import IDENTITY, Installation, identity_bytes
    write(root_path, str(IDENTITY), identity_bytes(Installation.legacy()))
    uid, gid = os.getuid(), os.getgid()
    assert uid > 0 and gid > 0
    tenant = {'slug': 'personal', 'uid': uid, 'gid': gid, **runtime.layout('personal'),
        'bridge_cgroup': '/system.slice/whatsapp-personal.service',
        'gateway_cgroup': f'/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/whatsapp-waha.service'}
    wrapper = ('#!/bin/sh\nset -eu\ncd '+tenant['home']+'\nexec runuser -u '+tenant['account']+
        f' -- env HOME={tenant["home"]} XDG_RUNTIME_DIR=/run/user/{uid} DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus "$@"\n').encode()
    write(root_path, tenant['wrapper'], wrapper, 0o755)
    write(root_path, tenant['bridge_source'], (SCRIPTS.parent/'deploy/whatsapp-personal.service').read_bytes())
    write(root_path, tenant['quadlet'], b'[Container]\nImage=fixture-secret-not-exported\n', 0o600)
    item = {key: tenant[key] for key in ('slug', 'uid', 'gid', 'bridge_cgroup', 'gateway_cgroup')}
    item.update(wrapper=root.snapshot(tenant['wrapper']), sources={path: root.snapshot(path)
        for path in (tenant['bridge_source'], tenant['quadlet'])})
    request = {'format': 'whatsapp-runtime-observation-v2', 'operation_id': 'd'*32,
        'source': {'path': str(SCRIPTS/'runtime_lifecycle.py'), 'sha256': runtime.digest((SCRIPTS/'runtime_lifecycle.py').read_bytes())},
        'layout_source': {'path': str(SCRIPTS/'installation_layout.py'), 'sha256': runtime.digest((SCRIPTS/'installation_layout.py').read_bytes())},
        'provenance': {'path': '/etc/fixture/initial-provenance.json', 'sha256': ''}, 'tenants': [item]}
    def bind():
        provenance = {'format': 2, 'operation_id': request['operation_id'],
            'source_sha256': request['source']['sha256'], 'layout_sha256': request['layout_source']['sha256'],
            'tenant_scope_sha256': runtime.digest(runtime.encoded(request['tenants']))}
        raw = runtime.encoded(provenance)
        write(root_path, request['provenance']['path'], raw, 0o600)
        request['provenance']['sha256'] = runtime.digest(raw)
        return runtime.encoded(request)
    bind()
    values = {}
    for component in ('bridge', 'gateway'):
        value = {key: '' for key in runtime.PROPERTIES}
        value.update(Id=tenant[component+'_unit'], LoadState='loaded', NeedDaemonReload='no',
            FragmentPath=tenant['bridge_source'] if component == 'bridge' else f'/run/user/{uid}/systemd/generator/whatsapp-waha.service',
            SourcePath='' if component == 'bridge' else tenant['quadlet'], User=tenant['account'] if component == 'bridge' else '',
            Restart='on-failure', KillMode='control-group', ActiveState='active', SubState='running',
            MainPID='321', ControlPID='0', ControlGroup=tenant[component+'_cgroup'],
            UnitFileState='enabled' if component == 'bridge' else 'generated')
        for key in runtime.EXEC_PROPERTIES: value[key] = []
        if component == 'bridge':
            argv = [runtime.PROJECT+'/.venv/bin/python', '-m', 'sally_whatsapp.cli', '--config', '/etc/whatsapp-personal/config.toml', 'serve']
        else:
            argv = ['/usr/bin/podman', 'run', '--name', 'whatsapp-waha', f'--cidfile=/run/user/{uid}/whatsapp-waha.cid', '--replace', '--rm', 'secret-image-argument']
            for key, ignore in (('ExecStop', False), ('ExecStopPost', True)):
                value[key] = [{'path': '/usr/bin/podman', 'argv': ['/usr/bin/podman', 'rm', '-v', '-f', '-i', f'--cidfile=/run/user/{uid}/whatsapp-waha.cid'], 'ignore_errors': ignore}]
        value['ExecStart'] = [{'path': argv[0], 'argv': argv, 'ignore_errors': False}]
        values[component] = value
    calls = []
    def reader(argv):
        calls.append(argv)
        component = 'bridge' if argv[0] in ('/usr/bin/systemctl', '/usr/bin/busctl') else 'gateway'
        key = argv[-1]
        operation = key if key in runtime.EXEC_PROPERTIES else 'show'
        assert argv == runtime.command(tenant, component, operation)
        if operation != 'show':
            records = [[item['path'], item['argv'], item['ignore_errors'], 1, 2, 3, 4, 321, 0, 0] for item in values[component][key]]
            return runtime.encoded({'type': 'a(sasbttttuii)', 'data': records})
        return ('\n'.join(key+'='+value for key, value in values[component].items() if key not in runtime.EXEC_PROPERTIES)+'\n').encode()
    def collect(*, selected_reader=reader, lookup=None):
        raw = runtime.encoded(request)
        return runtime.collect_units(root_path, raw, runtime.digest(raw), reader=selected_reader,
            lookup=lookup or (lambda name: SimpleNamespace(pw_uid=uid, pw_gid=gid, pw_dir=tenant['home'])))
    yield SimpleNamespace(path=root_path, root=root, request=request, tenant=tenant, bind=bind,
        values=values, reader=reader, calls=calls, collect=collect)
    root.close()


def test_initial_collector_has_no_retirement_or_installed_helper_dependency(initial_observation, monkeypatch):
    item = initial_observation
    forbidden = (runtime.HELPER, runtime.OWNER, runtime.STATE, '/etc/develative-host-qos', '/etc/develative-host-frontend')
    assert all(not (item.path/name.lstrip('/')).exists() for name in forbidden)
    before = {str(path.relative_to(item.path)): path.read_bytes() for path in item.path.rglob('*') if path.is_file()}
    import builtins
    original_import = builtins.__import__
    def guarded_import(name, *args, **kwargs):
        assert not name.startswith(('host', 'admin_')), 'initial observation must not import operational providers'
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded_import)
    result = item.collect()
    assert result['format'] == 'whatsapp-runtime-observation-receipt-v2'
    assert result['layout_sha256'] == item.request['layout_source']['sha256']
    after = {str(path.relative_to(item.path)): path.read_bytes() for path in item.path.rglob('*') if path.is_file()}
    assert before == after and all(not (item.path/name.lstrip('/')).exists() for name in forbidden)
    assert result['mutations'] is False and result['invoker_completeness_proven'] is False
    assert set(result['units']) == {'personal:bridge', 'personal:gateway'}
    assert len(item.calls) == 28
    serialized = json.dumps(result)
    assert all(secret not in serialized for secret in ('secret-image-argument', 'fixture-secret-not-exported', 'argv', 'Environment'))
    assert all('Environment' not in ' '.join(argv) for argv in item.calls)
    assert all(result['units']['personal:gateway']['definition'][key].startswith('sha256:') for key in runtime.EXEC_PROPERTIES)
    assert 'sha256:' not in json.dumps(item.request)


@pytest.mark.parametrize('fault', ['source_pin', 'layout_pin', 'layout_path', 'provenance_binding', 'account', 'wrapper', 'source_path', 'source_hash', 'quadlet_owner', 'symlink', 'unprotected_parent'])
def test_initial_collector_rejects_untrusted_scope_before_command(initial_observation, fault):
    item = initial_observation
    selected = item.request['tenants'][0]
    if fault == 'source_pin': item.request['source']['sha256'] = '0'*64; item.bind()
    elif fault == 'layout_pin': item.request['layout_source']['sha256'] = '0'*64; item.bind()
    elif fault == 'layout_path': item.request['layout_source']['path'] = '/other/installation_layout.py'; item.bind()
    elif fault == 'provenance_binding': item.request['operation_id'] = 'e'*32
    elif fault == 'wrapper':
        path = item.path/item.tenant['wrapper'].lstrip('/'); path.write_bytes(path.read_bytes()+b'# drift\n')
    elif fault == 'source_path': selected['sources']['/etc/systemd/system/box.service'] = selected['sources'][item.tenant['bridge_source']]; item.bind()
    elif fault == 'source_hash': selected['sources'][item.tenant['quadlet']]['sha256'] = '0'*64; item.bind()
    elif fault == 'quadlet_owner': selected['sources'][item.tenant['quadlet']]['uid'] += 1; item.bind()
    elif fault == 'symlink':
        target = item.path/item.tenant['quadlet'].lstrip('/'); target.rename(target.with_suffix('.original')); target.symlink_to(target.with_suffix('.original').name)
    elif fault == 'unprotected_parent': (item.path/item.tenant['home'].lstrip('/')).chmod(0o777)
    options = {'lookup': lambda _: SimpleNamespace(pw_uid=999999, pw_gid=999999, pw_dir=item.tenant['home'])} if fault == 'account' else {}
    with pytest.raises((runtime.RuntimeError, OSError)): item.collect(**options)
    assert item.calls == []


@pytest.mark.parametrize('fault', ['unit_drift', 'source_drift', 'provenance_drift', 'extra_dropin', 'unsafe_stop'])
def test_initial_collector_requires_stable_sources_and_effective_unit_contract(initial_observation, fault):
    item = initial_observation
    def read(argv):
        result = item.reader(argv)
        if len(item.calls) == 14:
            if fault == 'unit_drift': item.values['bridge']['MainPID'] = '322'
            elif fault == 'source_drift':
                path = item.path/item.tenant['quadlet'].lstrip('/'); path.write_bytes(path.read_bytes()+b'# changed\n')
            elif fault == 'provenance_drift':
                path = item.path/item.request['provenance']['path'].lstrip('/'); path.write_bytes(path.read_bytes()+b' ')
        return result
    if fault == 'extra_dropin': item.values['bridge']['DropInPaths'] = '/etc/systemd/system/whatsapp-personal.service.d/other.conf'
    if fault == 'unsafe_stop': item.values['gateway']['ExecStop'][0]['argv'][-1] = '--all'
    with pytest.raises(runtime.RuntimeError): item.collect(selected_reader=read)


@pytest.mark.parametrize('command', [[], ['collect-units']])
def test_initial_collector_is_standalone_stdlib_cli(tmp_path, command):
    target = tmp_path/'source/plugins/whatsapp/scripts/runtime_lifecycle.py'
    target.parent.mkdir(parents=True); target.write_bytes((SCRIPTS/'runtime_lifecycle.py').read_bytes())
    result = subprocess.run([sys.executable, '-I', '-B', str(target), *command, '--help'],
        capture_output=True, timeout=10, check=False)
    assert result.returncode == 0
    assert (b'--request' in result.stdout) == bool(command)
    assert not result.stderr


def test_cold_cli_ignores_an_ambient_foreign_installation_cache(fixture, tmp_path):
    raw = cli_operation(fixture, tmp_path)
    code = '''import runpy,sys,types
foreign=types.ModuleType('installation_layout');foreign.FORMAT='box-installation-v1'
def forbidden(*args,**kwargs):raise AssertionError('Ambient layout was consulted')
foreign.active=foreign.mapped=foreign.activate_installation=forbidden
sys.modules['installation_layout']=foreign
sys.argv=sys.argv[1:]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(SCRIPTS/'runtime_lifecycle.py'),
        'inspect', '--root', str(fixture.path), '--operation', '/runtime-operation.json', '--sha256', runtime.digest(raw)],
        capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['mutations'] is False


def test_captured_controller_binds_installed_layout_before_other_modules(fixture, monkeypatch):
    captured = {name: (runtime.SOURCE_ROOT/name).read_bytes() for name in runtime.SOURCES}
    captured['host/__init__.py'] = b"raise AssertionError('Other captured module executed too early')\n"
    plan = copy.deepcopy(fixture.plan)
    plan['before']['files'][runtime.HELPER_LAYOUT]['sha256'] = '0'*64
    monkeypatch.setattr(runtime, 'installation_profile', lambda: pytest.fail('ambient profile consulted'))
    previous = dict(sys.modules)
    try:
        with pytest.raises(runtime.RuntimeError, match='Installed UID layout and captured controller layout must match'):
            runtime._compile_sources(captured, runtime.SOURCE_ROOT, installation_root=fixture.path, plan=plan)
    finally:
        for name in set(sys.modules)-set(previous): del sys.modules[name]
        sys.modules.update(previous)


@pytest.mark.parametrize('fault', ['layout_pin', 'provenance_layout_pin'])
def test_collector_rejects_unbound_layout_before_executing_it(initial_observation, tmp_path, monkeypatch, fault):
    item = initial_observation
    checkout = tmp_path/'checkout'
    source = checkout/'plugins/whatsapp/scripts/runtime_lifecycle.py'
    source.parent.mkdir(parents=True)
    source.write_bytes((SCRIPTS/'runtime_lifecycle.py').read_bytes())
    sentinel = tmp_path/'unreviewed-layout-executed'
    layout_source = source.with_name('installation_layout.py')
    layout_source.write_text('from pathlib import Path\nPath('+repr(str(sentinel))+').touch()\n')
    item.request['source']['path'] = str(source)
    item.request['layout_source']['path'] = str(layout_source)
    item.bind()
    if fault == 'provenance_layout_pin':
        item.request['layout_source']['sha256'] = runtime.digest(layout_source.read_bytes())
    monkeypatch.setattr(runtime, '__file__', str(source))
    monkeypatch.setattr(runtime, 'SOURCE_ROOT', checkout)
    with pytest.raises(runtime.RuntimeError): item.collect()
    assert not sentinel.exists() and item.calls == []


def test_collector_preserves_caller_installation_selection(initial_observation):
    selected = runtime.installation_profile()
    cached = sys.modules['installation_layout']
    state = dict(cached.__dict__)
    initial_observation.collect()
    assert sys.modules['installation_layout'] is cached
    assert cached.__dict__ == state
    assert runtime.installation_profile() is selected


@pytest.mark.parametrize('fault', ['v1', 'missing_layout', 'missing_marker'])
def test_collector_requires_v2_and_explicit_installed_identity(initial_observation, fault):
    item = initial_observation
    if fault == 'v1': item.request['format'] = 'whatsapp-runtime-observation-v1'
    elif fault == 'missing_layout': del item.request['layout_source']
    else: (item.path/'etc/whatsapp-installation-identity.json').unlink()
    with pytest.raises(ValueError): item.collect()
    assert item.calls == []


def stdlib_runtime_namespace(monkeypatch):
    """Exercise the real __main__ definitions with argparse exiting before I/O."""
    source = SCRIPTS/'runtime_lifecycle.py'
    namespace = {'__name__': '__main__', '__file__': str(source)}
    with monkeypatch.context() as context:
        context.setattr(sys, 'argv', [str(source), '--help'])
        with pytest.raises(SystemExit) as exited:
            exec(compile(source.read_bytes(), str(source), 'exec'), namespace)
        assert exited.value.code == 0
    assert 'installation_profile' not in namespace
    return namespace


@pytest.mark.parametrize('fault', ['wrong_pin', 'tampered_layout', 'missing_pin', 'missing_marker'])
def test_uid_helper_rejects_untrusted_layout_before_account_or_artifact_access(fixture, tmp_path, monkeypatch, fault):
    namespace = stdlib_runtime_namespace(monkeypatch)
    pin = fixture.plan['before']['files'][runtime.HELPER_LAYOUT]['sha256']
    sentinel = tmp_path/'unreviewed-uid-layout-executed'
    if fault == 'wrong_pin': pin = '0'*64
    elif fault == 'tampered_layout':
        (fixture.path/runtime.HELPER_LAYOUT.lstrip('/')).write_text('from pathlib import Path\nPath('+repr(str(sentinel))+').touch()\n')
    elif fault == 'missing_marker': (fixture.path/'etc/whatsapp-installation-identity.json').unlink()
    args = ['_check-quadlet', 'personal', 'd'*32, 'a'*64, str(0o600), str(os.getuid()), str(os.getgid()), 'quadlet', pin]
    if fault == 'missing_pin': args.pop()
    monkeypatch.setattr(namespace['pwd'], 'getpwnam', lambda _: pytest.fail('account accessed before layout admission'))
    namespace['quadlet_retire'] = lambda *a, **kw: pytest.fail('artifact accessed before layout admission')
    with pytest.raises(ValueError):
        namespace['uid_helper'](args, installation_root=fixture.path, helper_path=runtime.HELPER)
    assert not sentinel.exists()


def test_uid_helper_uses_captured_layout_and_protected_fixture_identity(fixture, monkeypatch):
    namespace = stdlib_runtime_namespace(monkeypatch)
    selected = runtime.installation_profile()
    pin = fixture.plan['before']['files'][runtime.HELPER_LAYOUT]['sha256']
    args = ['_check-quadlet', 'personal', 'd'*32, 'a'*64, str(0o600), str(os.getuid()), str(os.getgid()), 'quadlet', pin]
    monkeypatch.setattr(namespace['pwd'], 'getpwnam', lambda name: SimpleNamespace(
        pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=fixture.tenant['home']))
    calls = []
    namespace['quadlet_retire'] = lambda *a, **kw: calls.append((a, kw))
    namespace['uid_helper'](args, installation_root=fixture.path, helper_path=runtime.HELPER)
    assert len(calls) == 1 and calls[0][0][0] == fixture.tenant['home']
    assert calls[0][1] == {'check_only': True, 'retired': False, 'artifact': 'quadlet'}
    assert runtime.installation_profile() is selected
    (fixture.path/'etc/whatsapp-installation-identity.json').unlink()
    with pytest.raises(ValueError, match='identity is missing'): namespace['installation_profile']()
