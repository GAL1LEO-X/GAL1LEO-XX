"""Standalone host contracts on temporary real files; no service/network calls."""
import builtins
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from test_host_integration import (setup, root, integration, put, tenancy,
    SYNTHETIC_MODULE_PATH, REPOSITORY)
from test_host_frontend import registry as original_registry
import test_host_frontend as frontend_fixture
from test_runtime_lifecycle import fixture, runtime, finish, cli_operation


@pytest.fixture
def registry(monkeypatch):
    value, raw = original_registry.__wrapped__()
    # A new frontend has no application consumers, BOX files or certificates.
    for name in set(value['artifacts']) - set(value['host_files']):
        del value['artifacts'][name]
        raw.pop(name)
    value['consumers'] = {}; value['lineages'] = {}
    # Fake Apache's staged Include observer requires one physical included file.
    name = '/etc/apache2/sites-enabled/host-empty.conf'
    raw[name] = b'# empty host configuration; no application consumer\n'
    value['artifacts'][name] = dict(value['artifacts'][value['apache']['config_path']],
        sha256=integration.sha(raw[name]))
    value['host_files'].append(name)
    original_profile = frontend_fixture.finite_profile
    def empty_profile(value, root):
        profile = original_profile(value, root)
        profile['config_files'].append(name)
        profile['includes'][0]['targets'].append(name)
        return profile
    monkeypatch.setattr(frontend_fixture, 'finite_profile', empty_profile)
    return value, raw


def standalone(setup):
    root, instance, plan, runner, _ = setup
    plan = copy.deepcopy(plan)
    plan['qos'] = None
    front = plan['frontend']; value, profile = front['registry'], front['profile']
    apache = value['apache']['config_path']
    content = root.read_bytes(apache)
    directive = ('LoadModule box_priority_module ' + SYNTHETIC_MODULE_PATH + '\n').encode()
    assert content.count(directive) == 1
    content = content.replace(directive, b'')
    put(root, apache, content, value['artifacts'][apache]['mode'])
    value['artifacts'][apache]['sha256'] = integration.sha(content)
    del value['artifacts'][SYNTHETIC_MODULE_PATH]
    value['host_files'].remove(SYNTHETIC_MODULE_PATH)
    profile['modules'] = []
    for name in list(value['directories']):
        if name.startswith('/usr/local/lib/develative-host-qos'):
            del value['directories'][name]
    shutil.rmtree(root.base/'usr/local/lib/develative-host-qos')
    put(root, integration.REGISTRY, integration.encoded(value), root.snapshot(integration.REGISTRY)['mode'])
    put(root, integration.PROFILE, integration.encoded(profile), root.snapshot(integration.PROFILE)['mode'])
    previous = plan['generation']['path']
    # The installed generation truly has no QoS modules/profile metadata.
    names = ('host/installation.py', 'host/lifecycle/filesystem.py', 'host/frontend/provider.py',
             'host/frontend/adapter.py', 'frontend-sources.json')
    sources = {name: root.read_bytes(previous+'/'+name) for name in names}
    manifest = integration.encoded({'format': 1, 'owner': 'host',
        'files': {name: integration.sha(body) for name, body in sources.items()}})
    digest = integration.sha(manifest)
    generation = integration.GENERATION_ROOT+'/'+digest
    for name, body in {**sources, 'manifest.json': manifest}.items():
        put(root, generation+'/'+name, body)
    shutil.rmtree(root.base/previous.lstrip('/'))
    plan['generation'] = {'path': generation, 'sha256': digest}
    return root, instance, plan, runner


def context(parts):
    root, instance, plan, runner = parts
    return integration.Integration(instance, plan, integration.sha(integration.encoded(plan)),
        root_path=root.base, runner=runner)


def account(instance, **changes):
    value = dict(pw_name=instance.service_user, pw_dir=str(instance.gateway_home),
        pw_shell='/usr/sbin/nologin', pw_uid=1234, pw_gid=1234)
    return SimpleNamespace(**(value | changes))


def test_fresh_without_qos_module_or_box_preserves_frontend_and_account_checks(setup):
    parts = standalone(setup)
    root, instance, plan, runner = parts
    assert not plan['frontend']['registry']['consumers']
    assert not (root.base/'usr/local/lib/develative-host-qos').exists()
    current = context(parts)
    try:
        current.preflight()
        with pytest.raises(ValueError, match='Service account differs'):
            current.enroll_runtime(account(instance, pw_shell='/bin/sh'))
        current.begin_runtime()
        enrolled = current.enroll_runtime(account(instance))
        assert enrolled['status'] == 'not-configured'
        canonical = tenancy.render_apache(instance)
        ready = current.ensure_https(canonical)
        assert ready['qos_frontend'] == 'not-configured'
        assert ready['frontend_traffic_verified'] is False
        published = root.read_bytes('/etc/apache2/sites-available/'+instance.base+'-https.conf').decode()
        assert published == canonical.replace('    BoxPriorityDSCP 34\n', '')
        assert 'BoxPriority' not in published
        current.ensure_https(canonical)
        assert runner.issued == 1
        assert not any(Path(argv[0]).name == 'python3' for argv in runner.calls)
        assert current._read_record()['phase'] == 'tls-ready'
    finally:
        current.close()


@pytest.mark.parametrize('qos', [{}, {'policy': integration.QOS_POLICY}, False, 'absent'])
def test_explicit_invalid_qos_never_becomes_standalone(setup, qos):
    parts = list(standalone(setup)); parts[2]['qos'] = qos
    with pytest.raises(ValueError, match='QoS'):
        context(parts)
    assert not parts[3].calls


def test_explicit_qos_requires_its_source_closure(setup):
    parts = list(standalone(setup))
    parts[2]['qos'] = {'policy': integration.QOS_POLICY, 'sha256': 'b'*64}
    with pytest.raises(ValueError, match='source closure'):
        context(parts)
    assert not parts[3].calls


@pytest.mark.parametrize('host', ['messages.team.example.test','team.example.test'])
def test_zone_is_explicit_and_hostname_scoped_without_hardcoded_deployment(setup, host):
    parts = list(standalone(setup)); previous = parts[1]
    parts[1] = SimpleNamespace(**{key: getattr(previous, key) for key in
        ('slug', 'service_user', 'bridge_port', 'gateway_port', 'gateway_home', 'base', 'project_root',
         '_installation_identity')}, hostname=host)
    parts[2]['instance']['hostname'] = host
    front = parts[2]['frontend']; front['zone'] = 'team.example.test'
    front.update(lineage='/etc/letsencrypt/live/'+host, archive='/etc/letsencrypt/archive/'+host,
        renewal='/etc/letsencrypt/renewal/'+host+'.conf')
    runner = parts[3]
    runner.instance = parts[1]
    previous_run = runner.run
    def domain_commands(argv, **kwargs):
        if Path(argv[0]).name == 'virtualmin':
            assert argv[1:] == ['modify-dns', '--domain', front['zone'], '--add-record', host+'. A 192.0.2.42']
            runner.calls.append(list(map(str, argv))); runner.local = True
            return b''
        return previous_run(argv, **kwargs)
    runner.run = domain_commands
    current = context(parts)
    try:
        current.preflight()
        assert ('ServerName '+host+'\n').encode() in current._http()
        assert not runner.calls
        result = current.ensure_https(tenancy.render_apache(parts[1]))
        assert result['hostname'] == host and result['qos_frontend'] == 'not-configured'
        value = integration.decode(parts[0].read_bytes(integration.REGISTRY))
        assert value['consumers']['whatsapp.fixture']['domains'] == [host]
        assert '/etc/letsencrypt/live/'+host in value['lineages']
        assert runner.issued == 1
        assert all('example.invalid' not in arg for argv in runner.calls for arg in argv)
    finally: current.close()


@pytest.mark.parametrize('zone', ['example.test.evil', '.example.invalid', 'example.invalid.',
                                 'Example.invalid', 'example.invalid\nHeader: bad', '*'])
def test_invalid_or_unrelated_zone_rejected_before_effects(setup, zone):
    parts = list(standalone(setup)); parts[2]['frontend']['zone'] = zone
    with pytest.raises(ValueError, match='DNS/TLS'):
        context(parts)
    assert not parts[3].calls


def test_standalone_retirement_keeps_all_other_lifecycle_gates(fixture, monkeypatch):
    fixture.plan['qos_policy'] = None
    original = builtins.__import__
    def guarded(name, *args, **kwargs):
        assert not name.startswith('host.qos'), 'Standalone retirement imported QoS'
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded)
    create = fixture.create
    fixture.create = lambda **options: create(qos_module=None, **options)
    fixture.admin.pending = True
    with pytest.raises(runtime.Pending, match='nonterminal backup'):
        fixture.create().advance()
    assert not fixture.calls
    fixture.admin.pending = False
    outcomes = finish(fixture)
    assert [value['phase'] for value in outcomes] == list(runtime.PHASES)
    assert fixture.frontend.retired and not fixture.qos.retired
    assert fixture.root.snapshot(fixture.tenant['bridge_source']) is None
    assert fixture.values['gateway']['LoadState'] == 'masked'


def test_standalone_cold_source_closure_physically_omits_qos(fixture, tmp_path):
    original = json.loads(cli_operation(fixture, tmp_path))
    fixture.plan['qos_policy'] = None
    raw = runtime.encode_operation(fixture.plan, admin_operation=original['admin_operation'],
        frontend=original['frontend'], source_revision=original['source_revision'])
    (fixture.path/'runtime-operation.json').write_bytes(raw)
    operation = json.loads(raw)
    assert not any(name.startswith('host/qos/') for name in operation['sources'])
    checkout = tmp_path/'standalone-code'
    for relative in operation['sources']:
        target = checkout/relative; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(runtime.SOURCE_ROOT/relative, target)
    result = subprocess.run([sys.executable, '-I', '-B',
        str(checkout/'plugins/whatsapp/scripts/runtime_lifecycle.py'), 'inspect',
        '--root', str(fixture.path), '--operation', '/runtime-operation.json', '--sha256', runtime.digest(raw)],
        capture_output=True, text=True, env={'PYTHONDONTWRITEBYTECODE': '1'}, timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['mutations'] is False


def test_missing_qos_key_is_not_an_implicit_opt_out(setup):
    parts = list(standalone(setup)); del parts[2]['qos']
    with pytest.raises(ValueError, match='exact host integration plan'):
        context(parts)
    assert not parts[3].calls


def test_explicit_provider_failure_never_falls_back(setup):
    root, instance, plan, runner, _ = setup
    original = runner.run
    def unavailable(argv, **kwargs):
        if Path(argv[0]).name == 'python3':
            raise FileNotFoundError('synthetic missing explicit QoS policy')
        return original(argv, **kwargs)
    runner.run = unavailable
    current = context((root, instance, plan, runner))
    try:
        with pytest.raises(FileNotFoundError, match='explicit QoS policy'):
            current.preflight()
        assert not current.checked
        assert current._read_record() is None
        assert not runner.calls
    finally: current.close()


def test_standalone_does_not_migrate_registered_qos_vhost(setup):
    root, instance, plan, runner = parts = standalone(setup)
    current = context(parts)
    try:
        current.preflight(); current.ensure_https(tenancy.render_apache(instance))
    finally: current.close()
    plan['operation_id'] = 'c'*32
    front = plan['frontend']
    front['registry'] = integration.decode(root.read_bytes(integration.REGISTRY))
    front['profile'] = integration.decode(root.read_bytes(integration.PROFILE))
    name = '/etc/apache2/sites-available/'+instance.base+'-https.conf'
    body = root.read_bytes(name)
    # A previously configured QoS vhost is explicitly inventoried, not silently converted.
    body = body.replace(b'    ServerName ', b'    BoxPriorityDSCP 34\n    ServerName ', 1)
    put(root, name, body, front['registry']['artifacts'][name]['mode'])
    front['registry']['artifacts'][name]['sha256'] = integration.sha(body)
    for entry in front['profile']['tls']:
        if entry['file'] == name: entry['line'] += 1
    put(root, integration.REGISTRY, integration.encoded(front['registry']), root.snapshot(integration.REGISTRY)['mode'])
    put(root, integration.PROFILE, integration.encoded(front['profile']), root.snapshot(integration.PROFILE)['mode'])
    runner.calls.clear()
    selected = context(parts)
    try:
        with pytest.raises(ValueError, match='null is not a migration'):
            selected.preflight()
        assert root.read_bytes(name) == body
        assert selected._read_record() is None
        assert not runner.calls
    finally: selected.close()


@pytest.mark.parametrize('line', ['    BoxPriorityDSCP 48\n', '    BoxPriorityDSCP 34',
                                '    BoxPriorityDSCP 34\n    BoxPriorityDSCP 34\n'])
def test_only_exact_canonical_optional_qos_directive_is_removed(setup, line):
    parts = standalone(setup); current = context(parts)
    try:
        current.preflight()
        body = tenancy.render_apache(parts[1]).replace('<VirtualHost *:443>\n', '<VirtualHost *:443>\n' + line, 1)
        with pytest.raises(ValueError, match='Unexpected QoS directive'):
            current._candidate(body, tls=True)
        assert current._read_record() is None
    finally: current.close()


@pytest.mark.parametrize('value', [{}, False, {'path': '/etc/invalid', 'sha256': 'invalid'}])
def test_retirement_invalid_explicit_qos_is_not_skipped(fixture, value):
    fixture.plan['qos_policy'] = value
    with pytest.raises(runtime.RuntimeError):
        fixture.create()
    assert not fixture.calls and not fixture.frontend.retired


def test_retirement_missing_qos_selection_is_rejected(fixture):
    del fixture.plan['qos_policy']
    with pytest.raises(runtime.RuntimeError, match='fields differ'):
        fixture.create()
    assert not fixture.calls


def preconfigured(setup):
    parts = standalone(setup)
    parts[2]['frontend']['dns_mode'] = 'preconfigured'
    del parts[2]['tools']['virtualmin']
    (parts[0].base/'usr/sbin/virtualmin').unlink()
    parts[3].local = True
    return parts


def test_preconfigured_dns_needs_no_virtualmin_and_keeps_tls_gate(setup):
    root, instance, plan, runner = parts = preconfigured(setup)
    current = context(parts)
    try:
        current.preflight()
        assert all(Path(argv[0]).name == 'dig' for argv in runner.calls)
        result = current.ensure_https(tenancy.render_apache(instance))
        assert result['phase'] == 'https_ready'
        assert not (root.base/'usr/sbin/virtualmin').exists()
        assert all(Path(argv[0]).name not in ('virtualmin','python3') for argv in runner.calls)
        assert runner.issued == 1
    finally: current.close()


@pytest.mark.parametrize('failure', ['local-missing','public-missing','local-different','public-different'])
def test_preconfigured_dns_mismatch_blocks_before_managed_writes(setup, failure):
    root, instance, plan, runner = parts = preconfigured(setup)
    prior = runner.run
    selected = '@'+plan['frontend']['local_resolver' if failure.startswith('local') else 'public_resolver']
    def dns(argv, **kwargs):
        if Path(argv[0]).name == 'dig' and selected in argv:
            runner.calls.append(list(map(str,argv)))
            return b'' if failure.endswith('missing') else b'192.0.2.99\n'
        return prior(argv, **kwargs)
    runner.run = dns
    before = root.read_bytes(integration.REGISTRY)
    current = context(parts)
    try:
        with pytest.raises(ValueError, match='Preconfigured DNS'):
            current.preflight()
        assert not current.checked and current._read_record() is None
        assert root.read_bytes(integration.REGISTRY) == before
        assert all(Path(argv[0]).name == 'dig' for argv in runner.calls)
        assert runner.issued == 0
    finally: current.close()


@pytest.mark.parametrize('mode', [None,False,'auto','pre-configured'])
def test_invalid_dns_mode_does_not_enable_fallback(setup, mode):
    parts = preconfigured(setup)
    parts[2]['frontend']['dns_mode'] = mode
    with pytest.raises(ValueError, match='DNS mode'):
        context(parts)
    assert not parts[3].calls


def test_preconfigured_dns_refuses_extra_virtualmin_tool(setup):
    parts = preconfigured(setup)
    parts[2]['tools']['virtualmin'] = {'path':integration.TOOLS['virtualmin'],'sha256':'a'*64}
    with pytest.raises(ValueError, match='finite tools'):
        context(parts)
    assert not parts[3].calls


def test_preconfigured_dns_is_rechecked_before_certificate_issuance(setup):
    root, instance, plan, runner = parts = preconfigured(setup)
    current = context(parts)
    try:
        current.preflight()
        runner.public = False
        with pytest.raises(ValueError, match='Preconfigured DNS'):
            current.ensure_https(tenancy.render_apache(instance))
        assert runner.issued == 0
        assert current._read_record()['phase'] == 'http-ready'
        assert all(Path(argv[0]).name != 'virtualmin' for argv in runner.calls)
    finally: current.close()


@pytest.mark.parametrize('metadata,tamper,error', [
    ('frontend-fresh-sources.json',False,None),
    ('frontend-fresh-sources.json',True,'source differs'),
    ('unreviewed-sources.json',False,'source path'),
])
def test_fresh_generation_metadata_is_optional_but_exact_and_pinned(setup, metadata, tamper, error):
    parts = preconfigured(setup)
    root, _, plan, runner = parts
    previous = plan['generation']['path']
    manifest = integration.decode(root.read_bytes(previous+'/manifest.json'))
    sources = {name:root.read_bytes(previous+'/'+name) for name in manifest['files']}
    sources[metadata] = integration.encoded({'format':1,'sources':{name:integration.sha(body)
        for name,body in sources.items() if name.startswith('host/')}})
    raw = integration.encoded({'format':1,'owner':'host','files':{
        name:integration.sha(body) for name,body in sources.items()}})
    digest = integration.sha(raw); generation = integration.GENERATION_ROOT+'/'+digest
    for name, body in {**sources,'manifest.json':raw}.items():
        put(root,generation+'/'+name,body)
    if tamper: put(root,generation+'/'+metadata,b'changed optional metadata\n')
    plan['generation'] = {'path':generation,'sha256':digest}
    if error:
        with pytest.raises(ValueError,match=error): context(parts)
        assert not runner.calls
    else:
        current = context(parts)
        try: current.preflight()
        finally: current.close()


def test_preconfigured_cold_frontend_closure_without_virtualmin_file(setup, tmp_path):
    root, instance, plan, runner = preconfigured(setup)
    from installation_layout import IDENTITY, Installation, identity_bytes
    put(root, str(IDENTITY), identity_bytes(Installation.legacy()), 0o600)
    raw = integration.encoded(plan)
    path = tmp_path/'cold-plan.json'; path.write_bytes(raw)
    # The cold child loads only this adapter and the protected installed generation;
    # its finite DNS seam cannot dispatch services, ACME or an arbitrary executable.
    code = '''import importlib.util,json,os,sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(sys.argv[1]).parent))
import installation_layout
installation_layout.select(installation_layout.read_installation(root=Path(sys.argv[2]),trusted_uid=os.getuid()))
spec=importlib.util.spec_from_file_location("cold_integration",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
plan=json.loads(Path(sys.argv[3]).read_bytes())
instance=SimpleNamespace(**plan["instance"],service_user=plan["instance"]["account"],
 _installation_identity=installation_layout.active(),
 base=installation_layout.Installation.legacy().service(plan["instance"]["slug"]))
class DNS:
 def run(self,argv,**kwargs):
  assert Path(argv[0]).name=="dig"
  assert argv[1] in ("@127.0.0.1","@1.1.1.1")
  assert argv[2:]==[instance.hostname,"A","+short"]
  return b"192.0.2.42\\n"
assert not (Path(sys.argv[2])/"usr/sbin/virtualmin").exists()
context=module.Integration(instance,plan,module.sha(module.encoded(plan)),root_path=sys.argv[2],runner=DNS())
try:
 context.preflight()
 assert context.checked
 assert not any(name.startswith("host.qos") for name in sys.modules)
 print("standalone-preconfigured-ready")
finally:context.close()
'''
    result = subprocess.run([sys.executable,'-I','-B','-c',code,integration.__file__,str(root.base),str(path)],
        capture_output=True,text=True,timeout=15,env={'PYTHONDONTWRITEBYTECODE':'1'})
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'standalone-preconfigured-ready\n'
