"""Synthetic deploy-v1 files, native flock and source admission; no live services."""
import copy
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import admin_deployment as deployment
import restore_runtime as restore
from test_restore_runtime import host


def write(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    path.write_bytes(data if isinstance(data, bytes) else deployment.encoded(data))
    path.chmod(mode)


@pytest.fixture
def deployed(tmp_path, monkeypatch):
    root = tmp_path / 'protected'
    root.mkdir(mode=0o700)
    monkeypatch.setattr(deployment, '_TRUST_ROOT', root)
    monkeypatch.setattr(deployment, '_TRUST_UID', os.getuid())
    project, configdir, engine_root = root / 'project', root / 'configuration', root / 'deploy'
    project.mkdir(); engine_root.mkdir()
    accounts = {'first': 'wa-first', 'second': 'wa-second'}
    paths = lambda slug: {'configuration': str(configdir / slug), 'state': str(root / 'data' / slug),
                          'gateway': str(root / 'gateways' / slug)}
    ports = {'first': {'bridge': 18001, 'gateway': 18002}, 'second': {'bridge': 18003, 'gateway': 18004}}
    profile = SimpleNamespace(compatibility=False, accounts=lambda: accounts, account=accounts.__getitem__,
        mapped=lambda value: value,
        instance_paths=paths, instance_ports=ports.__getitem__, service=lambda slug: 'wa-' + slug,
        path=lambda key: str({'project': project, 'configuration': configdir}[key]),
        as_dict=lambda: {'services': {'prefix': 'wa'}})
    entrypoint = root / 'host' / 'whatsapp_runtime.py'
    write(entrypoint, (Path(__file__).parents[1] / 'scripts/deploy_runtime.py').read_bytes())
    config = {'format': 'whatsapp-deploy-profile-v1', 'cutover_verified': True, 'app': 'whatsapp',
              'schema': 8, 'target_id': 'synthetic-host', 'engine_root': str(engine_root),
              'current': str(engine_root / 'current'), 'runtime_entrypoint': str(entrypoint),
              'gate': str(root / 'gate'), 'python': '/usr/bin/python3.13', 'instances': []}
    for index, slug in enumerate(accounts):
        config['instances'].append({'slug': slug, 'user': accounts[slug], 'uid': 21000 + index,
            'gid': 22000 + index, 'unit': 'wa-' + slug + '.service',
            'config': paths(slug)['configuration'] + '/config.toml',
            'database': paths(slug)['state'] + '/archive.sqlite', 'provider_state': paths(slug)['gateway'],
            'port': ports[slug]['bridge'], 'gateway_port': ports[slug]['gateway']})
    engine = {'format': 'gal1leo-deploy-config-v1', 'app': 'whatsapp', 'repository': 'GAL1LEO-X/GAL1LEO-XX',
              'root': str(engine_root), 'target_id': config['target_id'], 'bootstrap': None,
              'host_lock': str(root / 'host.lock')}
    engine_file = root / 'engine.json'
    monkeypatch.setattr(deployment, 'ENGINE_CONFIG', engine_file)
    write(configdir / 'deploy-hooks.json', config, 0o600); write(engine_file, engine, 0o600)
    write(root / 'host.lock', b'', 0o600); write(engine_root / 'deploy.lock', b'', 0o600)
    release = engine_root / 'releases' / ('b' * 64)
    commit = 'c' * 40
    manifest = {'format': 'gal1leo-deploy-v1', 'app': 'whatsapp', 'version': '0.8.14', 'commit': commit,
                'data': {'schema': 8, 'readable_schemas': [8]}}
    write(release / 'manifest.json', manifest)
    write(release / 'release.json', {'id': release.name, 'package_sha256': release.name, 'path': str(release),
                                   'commit': commit, 'manifest': manifest})
    write(release / 'payload/application.json', {'name': 'whatsapp', 'version': '0.8.14', 'schema': 8, 'commit': commit})
    write(release / 'runtime/venv/bin/python', b'synthetic interpreter; never execute', 0o755)
    (release / 'runtime/venv/lib').mkdir()
    (release / 'runtime/venv/lib64').symlink_to('lib')
    write(release / 'runtime/venv/pyvenv.cfg', b'include-system-site-packages = false\n')
    write(release / 'runtime/qualified.json', {'commit': commit, 'package_sha256': release.name,
          'files': deployment.runtime_inventory(release / 'runtime')})
    (engine_root / 'current').symlink_to(release)
    (project / '.venv').symlink_to(release / 'runtime/venv')
    write(engine_root / 'current.json', {'release_id': release.name, 'schema': 8,
                                       'previous_id': None, 'operation_id': 'a' * 64}, 0o600)
    return SimpleNamespace(root=root, profile=profile, project=project, config=config, configdir=configdir,
        engine=engine, engine_file=engine_file, engine_root=engine_root, release=release)


def test_real_qualification_and_exact_two_instance_commands(deployed):
    with deployment.leases(deployed.profile) as fds:
        assert len(fds) == 2
        first = deployment.load(deployed.profile, 'first')
        second = deployment.load(deployed.profile, 'second')
    assert first.binding == second.binding and first.version == '0.8.14'
    assert first.command()[1:3] == ['-I', '-B']
    assert first.command()[5] != second.command()[5]
    assert first.command()[-1] == str(deployed.engine_root / 'current/payload/application.json')
    deployment.validate_binding(first.binding)


@pytest.mark.parametrize('damage', ['wrong-app', 'wrong-root', 'wrong-instance', 'foreign-port', 'duplicate-uid',
    'wrong-entrypoint', 'current-escape', 'current-record', 'manifest', 'application', 'qualification',
    'runtime-bytes', 'runtime-writable', 'runtime-hardlink', 'runtime-symlink', 'missing-file', 'pending'])
def test_deployment_drift_is_refused_without_repair(deployed, damage):
    d = deployed
    if damage in ('wrong-app', 'wrong-root'):
        v = copy.deepcopy(d.engine); v['app' if damage == 'wrong-app' else 'root'] = 'tesla' if damage == 'wrong-app' else str(d.root)
        write(d.engine_file, v, 0o600)
    elif damage in ('wrong-instance', 'foreign-port', 'duplicate-uid'):
        v = copy.deepcopy(d.config)
        if damage == 'wrong-instance': v['instances'][0]['user'] = 'wa-second'
        elif damage == 'foreign-port': v['instances'][0]['port'] = v['instances'][1]['port']
        else: v['instances'][0]['uid'] = v['instances'][1]['uid']
        write(d.configdir / 'deploy-hooks.json', v, 0o600)
    elif damage == 'wrong-entrypoint': write(Path(d.config['runtime_entrypoint']), b'unreviewed code')
    elif damage == 'current-escape':
        (d.engine_root / 'current').unlink(); (d.engine_root / 'current').symlink_to(d.root)
    elif damage == 'current-record': write(d.engine_root / 'current.json', {'release_id': 'd' * 64, 'schema': 8})
    elif damage == 'manifest': write(d.release / 'manifest.json', {'app': 'tesla'})
    elif damage == 'application': write(d.release / 'payload/application.json', {'version': '9.0.0'})
    elif damage == 'qualification': write(d.release / 'runtime/qualified.json', {'commit': 'd' * 40})
    elif damage == 'runtime-bytes': write(d.release / 'runtime/venv/bin/python', b'changed', 0o755)
    elif damage == 'runtime-writable': (d.release / 'runtime/venv/bin/python').chmod(0o777)
    elif damage == 'runtime-hardlink': os.link(d.release / 'runtime/venv/bin/python', d.root / 'extra-link')
    elif damage == 'runtime-symlink': (d.release / 'runtime/venv/escape').symlink_to(d.root)
    elif damage == 'missing-file': (d.release / 'runtime/venv/pyvenv.cfg').unlink()
    else: write(d.engine_root / 'pending.json', {'operation_id': 'e' * 64}, 0o600)
    before = sorted(str(p.relative_to(d.root)) for p in d.root.rglob('*'))
    with pytest.raises((ValueError, OSError)):
        with deployment.leases(d.profile): deployment.load(d.profile, 'first')
    assert sorted(str(p.relative_to(d.root)) for p in d.root.rglob('*')) == before


def test_present_invalid_profile_does_not_fall_back_to_legacy(deployed):
    write(deployed.configdir / 'deploy-hooks.json', b'{invalid')
    with pytest.raises(ValueError): deployment.configuration(deployed.profile)


def test_legacy_without_profile_does_not_acquire_deployment_locks():
    legacy = SimpleNamespace(compatibility=True)
    assert deployment.configuration(legacy) is None
    with deployment.leases(legacy) as fds: assert fds == ()


@pytest.mark.parametrize('lock', ['host.lock', 'deploy.lock'])
def test_busy_native_lease_refuses_before_runtime_reads(deployed, lock):
    path = deployed.root / lock if lock == 'host.lock' else deployed.engine_root / lock
    with path.open('rb') as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ValueError, match='in progress'):
            with deployment.leases(deployed.profile): pytest.fail('must not admit')


def test_lease_descriptors_can_be_inherited_by_child(deployed):
    with deployment.leases(deployed.profile) as fds:
        code = 'import os,sys; [os.fstat(int(fd)) for fd in sys.argv[1:]]'
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code, *map(str, fds)],
                                pass_fds=fds, capture_output=True, timeout=5)
        assert result.returncode == 0


def test_runtime_file_and_byte_bounds(deployed, monkeypatch):
    monkeypatch.setattr(deployment, 'MAX_FILES', 2)
    with pytest.raises(ValueError, match='file bound'): deployment.load(deployed.profile, 'first')
    monkeypatch.setattr(deployment, 'MAX_FILES', 20000)
    monkeypatch.setattr(deployment, 'MAX_RUNTIME_BYTES', 1)
    with pytest.raises(ValueError, match='byte bound'): deployment.load(deployed.profile, 'first')


def test_qualification_rejects_deep_or_duplicate_json():
    for value in (b'[' * 10000 + b'0' + b']' * 10000, b'{"commit":1,"commit":2}'):
        with pytest.raises(ValueError, match='Invalid deployment metadata'): deployment.decode(value)


def start_values():
    return {name: '' for name in deployment.START_CONTEXT}


def test_missing_structured_property_uses_typed_empty_evidence():
    values = start_values(); values.pop('EnvironmentFiles')
    calls = []
    def reader(argv):
        calls.append(argv)
        return ('\n'.join(k+'='+v for k,v in values.items())+'\n').encode() if len(calls) == 1 else b'{"type":"a(sb)","data":[]}'
    assert deployment.read_start_context('wa-first.service', reader) == start_values()
    assert calls[1][-1] == 'EnvironmentFiles' and calls[1][0] == '/usr/bin/busctl'


@pytest.mark.parametrize('typed', [b'{}', b'{"type":"s","data":""}', b'{"type":"a(sb)","data":[["/untrusted",false]]}',
                                  b'{"type":"a(sb)","data":[],"extra":true}'])
def test_omitted_property_is_never_assumed_empty(typed):
    values = start_values(); values.pop('EnvironmentFiles')
    def reader(argv):
        return ('\n'.join(k+'='+v for k,v in values.items())+'\n').encode() if argv[0].endswith('systemctl') else typed
    with pytest.raises(ValueError, match='verified empty'): deployment.read_start_context('wa-first.service', reader)


@pytest.mark.parametrize('field', ['User', 'WorkingDirectory', 'NoNewPrivileges'])
def test_missing_scalar_property_is_refused_without_dbus_fallback(field):
    values = start_values(); values.pop(field)
    def reader(argv):
        assert argv[0].endswith('systemctl')
        return ('\n'.join(k+'='+v for k,v in values.items())+'\n').encode()
    with pytest.raises(ValueError, match='Incomplete'): deployment.read_start_context('wa-first.service', reader)


def test_restore_start_context_is_pinned_and_cannot_add_privileges(deployed):
    runtime = deployment.load(deployed.profile, 'first')
    values = start_values()
    values.update(WorkingDirectory=str(runtime.current), User='wa-first', Group='wa-first',
                  DynamicUser='no', NoNewPrivileges='yes', SupplementaryGroups='wa-transcription')
    ctx = SimpleNamespace(project=deployed.project, deployment=runtime, profile=deployed.profile,
                          start_context_sha256=restore.sha(restore.encoded(values)))
    plan = {'account': {'name': 'wa-first', 'group': 'wa-first'}}
    restore.validate_start_context(values, ctx, plan)
    for key, value in [('User', 'wa-second'), ('NoNewPrivileges', 'no'), ('Environment', 'PYTHONPATH=/tmp'),
                       ('SupplementaryGroups', 'wa-second'), ('SupplementaryGroups', 'wa-transcription sudo')]:
        changed = {**values, key: value}
        ctx.start_context_sha256 = restore.sha(restore.encoded(changed))
        with pytest.raises(ValueError, match='source-finite'): restore.validate_start_context(changed, ctx, plan)
    ctx.start_context_sha256 = '0' * 64
    with pytest.raises(ValueError, match='approved plan'): restore.validate_start_context(values, ctx, plan)


def test_extracted_administrative_bundle_contains_executed_restore_dependencies(host, tmp_path, monkeypatch):
    import build_admin_bundle
    import admin_manifest
    bundle = tmp_path / 'bundle'
    plugin = Path(__file__).parents[1]
    build_admin_bundle.build_bundle(plugin, bundle, source_sha='a' * 40)
    admin_manifest.load_bundle(bundle, 'a' * 40, uid=os.getuid(), gid=os.getgid())
    installed = bundle / 'project-scripts/restore_runtime.py'
    assert installed.read_bytes() == Path(restore.__file__).read_bytes()
    # Execute the qualified helper against synthetic files, resolving every
    # on-disk sibling from the bundle instead of the complete source checkout.
    monkeypatch.setattr(restore, '__file__', str(installed))
    result = restore.apply(host.plan, administration=host.admin)
    assert result['state'] == 'completed' and result['services_started'] is False
    assert result['preimages_retained'] is True
    assert (host.ctx.state / host.plan['id'] / 'old/state/newer-than-backup.txt').is_file()


def test_inventory_matches_existing_deployment_seal_order(deployed):
    import deploy_hooks
    runtime = deployed.release / 'runtime'
    write(runtime / 'package/child.py', b'pass')
    write(runtime / 'package.py', b'pass')
    assert deployment.runtime_inventory(runtime) == deploy_hooks.runtime_inventory(runtime, trusted_uid=os.getuid())


@pytest.mark.parametrize('name', ['release.json', 'manifest.json', 'payload/application.json'])
def test_binding_refuses_metadata_changes_after_admission(deployed, name):
    runtime = deployment.load(deployed.profile, 'first')
    path = deployed.release / name
    value = deployment.decode(path.read_bytes()); value['unexpected'] = True
    write(path, value)
    with pytest.raises(ValueError, match='Pinned deployment changed'): runtime.check_current()


@pytest.fixture
def startup_deployment(deployed, monkeypatch):
    import installation_layout
    import runtime_lifecycle
    d = deployed
    monkeypatch.setattr(restore, '_TRUST_ROOT', d.root)
    monkeypatch.setattr(restore, '_TRUST_UID', os.getuid())
    monkeypatch.setattr(installation_layout, 'active', lambda: d.profile)
    monkeypatch.setattr(runtime_lifecycle, 'installation_profile', lambda: d.profile)
    monkeypatch.setattr(runtime_lifecycle, 'PROJECT', str(d.project))
    account = SimpleNamespace(pw_name='wa-first', pw_uid=21000, pw_gid=22000)
    monkeypatch.setattr(restore.pwd, 'getpwnam', lambda name: account)
    monkeypatch.setattr(restore.grp, 'getgrgid', lambda gid: SimpleNamespace(gr_name='wa-first'))
    for target in (d.project / 'sally_whatsapp', d.release / 'runtime/venv/lib/python3.13/site-packages/sally_whatsapp'):
        for name in restore.RESTORE_GATE_SOURCES:
            write(target / name, (Path(__file__).parents[1] / 'sally_whatsapp' / name).read_bytes())
    tenant = runtime_lifecycle.layout('first')
    wrapper = ('#!/bin/sh\nset -eu\ncd '+tenant['home']+'\nexec runuser -u '+tenant['account']+
        ' -- env HOME='+tenant['home']+' XDG_RUNTIME_DIR=/run/user/21000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/21000/bus "$@"\n')
    write(Path(tenant['wrapper']), wrapper.encode())
    proof_path = d.release / 'runtime/qualified.json'
    proof = deployment.decode(proof_path.read_bytes())
    proof['files'] = deployment.runtime_inventory(d.release / 'runtime'); write(proof_path, proof)
    runtime = deployment.load(d.profile, 'first')
    observation = {key: '' for key in runtime_lifecycle.PROPERTIES}
    observation.update(Id='wa-first.service', LoadState='loaded', NeedDaemonReload='no',
        FragmentPath=tenant['bridge_source'], User='wa-first', Restart='on-failure', KillMode='control-group')
    for key in runtime_lifecycle.EXEC_PROPERTIES: observation[key] = []
    observation['ExecStart'] = [{'path': runtime.command()[0], 'argv': runtime.command(), 'ignore_errors': False}]
    values = start_values()
    values.update(WorkingDirectory=str(runtime.current), User='wa-first', Group='wa-first',
                  DynamicUser='no', NoNewPrivileges='yes', SupplementaryGroups='wa-transcription')
    monkeypatch.setattr(restore, 'service_observation', lambda *args: observation)
    calls = []
    def reader(argv):
        calls.append(argv)
        if argv[0] == '/usr/bin/busctl':
            assert argv[-1] == 'ExecStartEx'
            return deployment.encoded({'type':'a(sasasttttuii)',
                'data':[[runtime.command()[0], runtime.command(), [], 0,0,0,0,0,0,0]]})
        assert argv[0] == '/usr/bin/systemctl'
        if argv[1] == 'show-environment': return b'LANG=C\n'
        assert argv[1] == 'show'
        return ''.join(k+'='+v+'\n' for k,v in values.items()).encode()
    monkeypatch.setattr(restore.subprocess, 'run', lambda argv, **kwargs: SimpleNamespace(stdout=reader(argv)))
    return SimpleNamespace(deployed=d, runtime=runtime, observation=observation, values=values, reader=reader, calls=calls)


def test_readonly_inspection_exercises_complete_start_contract(startup_deployment):
    s = startup_deployment
    result = restore.inspect_runtime('first', reader=s.reader)
    assert result['version'] == '0.8.14' and result['startup_contract_verified'] is True
    assert result['runtime_seal_verified'] is True and result['source_gate_verified'] is True
    assert not result['restore_executed'] and not result['data_opened'] and not result['services_changed']
    assert all(call[0] in ('/usr/bin/systemctl', '/usr/bin/busctl') for call in s.calls)
    assert not any(p.name == 'restore-maintenance.json' for p in s.deployed.root.rglob('*'))


@pytest.mark.parametrize('damage', ['foreign-config', 'argv-extra', 'other-user', 'source-pin', 'old-interpreter'])
def test_inspection_refuses_incompatible_runtime_without_mutating_it(startup_deployment, damage):
    s = startup_deployment
    if damage == 'foreign-config': s.observation['ExecStart'][0]['argv'][5] = '/etc/other/config.toml'
    elif damage == 'argv-extra': s.observation['ExecStart'][0]['argv'].append('--unsafe')
    elif damage == 'other-user': s.observation['User'] = 'wa-second'
    elif damage == 'source-pin': write(s.deployed.project / 'sally_whatsapp/server.py', b'changed')
    else:
        (s.deployed.project / '.venv').unlink()
        (s.deployed.project / '.venv').symlink_to(s.deployed.root)
    with pytest.raises(ValueError): restore.inspect_runtime('first', reader=s.reader)
    assert not any(p.name == 'restore-maintenance.json' for p in s.deployed.root.rglob('*'))


def test_deploy_plan_requires_exact_start_binding(host, deployed):
    plan = copy.deepcopy(host.plan)
    plan['format'] = restore.DEPLOY_FORMAT
    plan['runtime'] = {'deployment': deployment.load(deployed.profile, 'first').binding,
                       'start_context_sha256': 'd' * 64}
    assert restore.validate(plan) == plan
    for change in ('missing-runtime', 'extra-runtime', 'short-digest', 'missing-binding'):
        broken = copy.deepcopy(plan)
        if change == 'missing-runtime': broken.pop('runtime')
        elif change == 'extra-runtime': broken['runtime']['automatic_recovery'] = True
        elif change == 'short-digest': broken['runtime']['start_context_sha256'] = 'bad'
        else: broken['runtime']['deployment'].pop('current_sha256')
        with pytest.raises(ValueError): restore.validate(broken)


def test_isolated_deployment_does_not_import_historical_project_backups(startup_deployment):
    s = startup_deployment
    historical = s.deployed.root / 'historical-runtime'
    historical.mkdir()
    write(historical / 'sitecustomize.py', b'raise RuntimeError("must never import")', 0o666)
    archived = s.deployed.project / 'work/previous'
    archived.mkdir(parents=True)
    (archived / '.venv').symlink_to(historical)
    assert restore.inspect_runtime('first', reader=s.reader)['startup_contract_verified'] is True
    assert (historical / 'sitecustomize.py').read_bytes() == b'raise RuntimeError("must never import")'


def test_child_keeps_deployment_lease_when_parent_scope_closes(deployed):
    child = None
    try:
        with deployment.leases(deployed.profile) as descriptors:
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c',
                'import sys; print("ready",flush=True); sys.stdin.buffer.read(1)'],
                pass_fds=descriptors, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert child.stdout.readline() == b'ready\n'
        with pytest.raises(ValueError, match='in progress'):
            with deployment.leases(deployed.profile): pytest.fail('child still owns lease')
        child.communicate(b'x', timeout=5)
        assert child.returncode == 0
        with deployment.leases(deployed.profile): pass
    finally:
        if child is not None and child.poll() is None:
            child.kill(); child.communicate(timeout=5)


def test_metadata_shape_has_explicit_interpreter_independent_bounds(monkeypatch):
    monkeypatch.setattr(deployment, 'MAX_JSON_DEPTH', 2)
    with pytest.raises(ValueError, match='Invalid deployment metadata'):
        deployment.decode(b'[[[[0]]]]')
    monkeypatch.setattr(deployment, 'MAX_JSON_NODES', 3)
    with pytest.raises(ValueError, match='Invalid deployment metadata'):
        deployment.decode(b'[1,2,3,4]')
