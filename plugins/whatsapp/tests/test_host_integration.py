"""Actual installed frontend/engine on temporary files; no host or network I/O."""
import copy
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sally_whatsapp import tenancy
from host import build_bundle

REPOSITORY = Path(__file__).parents[3]
PLUGIN = Path(__file__).parents[1]
sys.path.insert(0, str(REPOSITORY/'tools/tests'))
from test_host_frontend import registry, root, staged_setup, empty, finite
from test_host_lifecycle_integration import staged_whatsapp
import test_host_lifecycle_integration as lifecycle

spec = importlib.util.spec_from_file_location('whatsapp_host_integration', PLUGIN/'scripts/host_integration.py')
integration = importlib.util.module_from_spec(spec); spec.loader.exec_module(integration)
SYNTHETIC_MODULE = b'isolated foreign-module fixture; never loaded as a DSO\n'
SYNTHETIC_MODULE_SHA = integration.sha(SYNTHETIC_MODULE)
SYNTHETIC_MODULE_PATH = '/usr/local/lib/develative-host-qos/foreign/sha256-'+SYNTHETIC_MODULE_SHA+'/mod_box_priority.so'


def put(root, name, content, mode=0o644):
    target = root.base/name.lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content); target.chmod(mode)
    return target


def certificate(host):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(42)
    cert = cert.not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1))
    cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False).sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


class Commands:
    def __init__(self, root, instance, frontend_runner):
        self.root, self.instance, self.frontend_runner = root, instance, frontend_runner
        self.calls, self.local, self.public = [], False, True
        self.lose_issuance_reply = False
        self.issued = 0

    def issue(self):
        cert, key = certificate(self.instance.hostname)
        for prefix, body, mode in [('fullchain', cert, 0o644), ('privkey', key, 0o600)]:
            archive = '/etc/letsencrypt/archive/' + self.instance.hostname + '/' + prefix + '1.pem'
            put(self.root, archive, body, mode)
            link = self.root.base/'etc/letsencrypt/live'/self.instance.hostname/(prefix+'.pem')
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to('../../archive/'+self.instance.hostname+'/'+prefix+'1.pem')
        put(self.root, '/etc/letsencrypt/renewal/'+self.instance.hostname+'.conf', b'synthetic exact renewal\n', 0o600)
        self.issued += 1

    def run(self, argv, **kwargs):
        self.calls.append(list(map(str, argv)))
        name = Path(argv[0]).name
        if name == 'python3':
            source_index = argv.index('--sources-manifest')
            pinned = Path(argv[source_index + 1])
            assert pinned.name == 'qos-sources.json'
            assert argv[source_index + 2:source_index + 4] == [
                '--expected-sources-sha256', integration.sha(pinned.read_bytes())]
            assert source_index < min(argv.index(action) for action in ('check','register-consumer','register-frontend') if action in argv)
            if 'check' in argv:
                return integration.encoded({'provider':'develative-host-qos','status':'complete','version':'0.1.0'})
            if 'register-frontend' in argv:
                return integration.encoded({'status':'configuration-bound','consumer_id':'whatsapp.'+self.instance.slug,
                    'frontend_operation_id':argv[argv.index('--frontend-operation-id')+1], 'runtime_verified':False,
                    'policy_sha256':argv[argv.index('--expected-sha256')+1],
                    'receipt_sha256':argv[argv.index('--frontend-receipt-sha256')+1]})
            assert 'register-consumer' in argv
            return integration.encoded({'status':'complete','consumer_id':'whatsapp.'+self.instance.slug,
                'account':self.instance.service_user,'uid':1234,'unit':self.instance.base+'.service'})
        if name == 'dig':
            assert argv[-3:] == [self.instance.hostname, 'A', '+short']
            return b'192.0.2.42\n' if (self.local if argv[1]=='@127.0.0.1' else self.public) else b''
        if name == 'virtualmin':
            assert argv[1:] == ['modify-dns','--domain','example.invalid','--add-record',self.instance.hostname+'. A 192.0.2.42']
            self.local = True
            return b''
        if name == 'certbot':
            assert argv[-4:] == ['--cert-name',self.instance.hostname,'-d',self.instance.hostname]
            self.issue()
            if self.lose_issuance_reply: raise RuntimeError('synthetic lost issuance reply')
            return b''
        if name == 'openssl':
            result = subprocess.run(argv, input=kwargs.get('input_bytes'), capture_output=True,
                                    timeout=kwargs['timeout'], check=True)
            return result.stdout
        assert name in ('apache2','systemctl'), argv
        return self.frontend_runner.run(argv, **kwargs)


@pytest.fixture
def setup(registry, root, monkeypatch):
    monkeypatch.setattr(tenancy, 'ROOT', PLUGIN)
    instance = tenancy.Instance('fixture','Synthetic','11111111-1111-4111-8111-111111111111',8824)
    value, raw, profile, frontend_runner, adapter = staged_setup(registry, root)
    # Actual binding validation below reads these exact bytes; the binary is
    # synthetic and the fake Apache never loads it or opens a listener.
    apache = value['apache']['config_path']
    directive = 'LoadModule box_priority_module ' + SYNTHETIC_MODULE_PATH
    raw[apache] += (directive+'\n').encode()
    value['artifacts'][apache]['sha256'] = integration.sha(raw[apache])
    raw[SYNTHETIC_MODULE_PATH] = SYNTHETIC_MODULE
    value['artifacts'][SYNTHETIC_MODULE_PATH] = {'sha256':SYNTHETIC_MODULE_SHA,'uid':root.uid,
        'gid':root.gid,'mode':0o644,'retention':'retain'}
    value['host_files'].append(SYNTHETIC_MODULE_PATH)
    profile['modules'] = [{'file':apache,'line':2,'text':directive,'path':SYNTHETIC_MODULE_PATH,
                           'identifier':'box_priority_module'}]
    for parent in Path(SYNTHETIC_MODULE_PATH).parents:
        if str(parent)=='/': continue
        value['directories'].setdefault(str(parent),{**(root.directory(str(parent)) or
            {'mode':0o755,'uid':root.uid,'gid':root.gid}),'retention':'retain'})
    openssl = root.base/'usr/bin/openssl'
    shutil.copyfile('/usr/bin/openssl', openssl); openssl.chmod(0o700)
    profile['tools']['openssl']['sha256'] = integration.sha(openssl.read_bytes())
    adapter = finite.HostAdapter(root, adapter.engine, value, profile, runner=frontend_runner)
    with adapter.lease():
        finite.apply_configuration(adapter, operation_id='f'*32, before=empty(), pinned_artifacts=raw)
    (root.base/'etc/apache2/sites-available').mkdir(exist_ok=True)
    (root.base/('var/www/'+instance.base+'-acme')).mkdir(parents=True)
    (root.base/'var/lib/develative-deploy').mkdir(parents=True)
    bundle_path = root.base/'actual-host-bundle'
    bundle = build_bundle.build(REPOSITORY,bundle_path,source_revision='0'*40)
    generation = bundle['destination']
    manifest = (bundle_path/'manifest.json').read_bytes()
    for name in [*integration.decode(manifest)['files'], 'manifest.json']:
        put(root,generation+'/'+name,(bundle_path/name).read_bytes())
    tools = {}
    for name, path in integration.TOOLS.items():
        content = b'#!/bin/sh\n# synthetic only\n'
        put(root, path, content, 0o700)
        tools[name] = {'path':path,'sha256':integration.sha(content)}
    plan = {'format':1,'operation_id':'a'*32,
        'instance':{'slug':instance.slug,'account':instance.service_user,'hostname':instance.hostname,
                    'bridge_port':instance.bridge_port,'gateway_port':instance.gateway_port},
        'generation':{'path':generation,'sha256':integration.sha(manifest)},
        'qos':{'policy':integration.QOS_POLICY,'sha256':'b'*64},'tools':tools,
        'frontend':{'registry':value,'profile':profile,'address':'192.0.2.42','zone':'example.invalid',
            'local_resolver':'127.0.0.1','public_resolver':'1.1.1.1','webroot':'/var/www/'+instance.base+'-acme',
            'lineage':'/etc/letsencrypt/live/'+instance.hostname,'archive':'/etc/letsencrypt/archive/'+instance.hostname,
            'renewal':'/etc/letsencrypt/renewal/'+instance.hostname+'.conf'}}
    path = '/etc/develative-deploy/fixture-host-plan.json'
    content = integration.encoded(plan); put(root,path,content,0o600)
    runner = Commands(root,instance,frontend_runner)
    def load():
        return integration.load(instance,path,integration.sha(content),root_path=root.base,runner=runner).preflight()
    return root, instance, plan, runner, load


def test_new_consumer_uses_real_registry_engine_then_validated_tls_without_legacy(setup):
    root, instance, plan, runner, load = setup
    before = copy.deepcopy(plan['frontend']['registry'])
    context = load()
    try:
        context.begin_runtime()
        account = SimpleNamespace(pw_name=instance.service_user,pw_dir=str(instance.gateway_home),
                                  pw_shell='/usr/sbin/nologin',pw_uid=1234,pw_gid=1234)
        context.enroll_runtime(account)
        result = context.ensure_https(tenancy.render_apache(instance))
        assert result['phase']=='https_ready' and runner.issued==1
        assert result['qos_frontend']=='configuration-bound' and result['frontend_traffic_verified'] is False
        current = integration.decode(root.read_bytes(integration.REGISTRY))
        for key,item in before['consumers'].items(): assert current['consumers'][key]==item
        for key,item in before['artifacts'].items(): assert root.snapshot(key)['sha256']==item['sha256']
        assert current['consumers']['whatsapp.fixture']['status']=='active'
        assert context._read_record()['phase']=='tls-ready'
        assert not any('resource_priority' in str(call) or 'a2ensite' in str(call) for call in runner.calls)
        context.ensure_https(tenancy.render_apache(instance))
        assert runner.issued==1
    finally: context.close()


def test_whatsapp_frontend_survives_retired_box_sources_physically_absent(setup):
    root, instance, plan, runner, _ = setup
    value = copy.deepcopy(plan['frontend']['registry'])
    value['consumers']['box.web']['status'] = 'retired'
    profile = copy.deepcopy(plan['frontend']['profile'])
    retired = set(value['consumers']['box.web']['vhosts'])
    profile['config_files'] = [name for name in profile['config_files'] if name not in retired]
    for item in profile['includes']:
        item['targets'] = [name for name in item['targets'] if name not in retired]
    for name in retired: (root.base / name.lstrip('/')).unlink()
    plan = copy.deepcopy(plan)
    plan['frontend']['registry'], plan['frontend']['profile'] = value, profile
    put(root, integration.REGISTRY, integration.encoded(value), 0o600)
    put(root, integration.PROFILE, integration.encoded(profile), 0o600)
    context = integration.Integration(instance, plan, integration.sha(integration.encoded(plan)),
        root_path=root.base, runner=runner).preflight()
    try:
        assert context.ensure_https(tenancy.render_apache(instance))['phase'] == 'https_ready'
        assert all(root.snapshot(name) is None for name in retired)
        current = integration.decode(root.read_bytes(integration.REGISTRY))
        assert current['consumers']['box.web'] == value['consumers']['box.web']
    finally: context.close()


def test_existing_tenant_upgrade_preserves_relative_links_and_never_issues_certificate(setup):
    root, instance, plan, runner, load = setup
    first = load()
    try: first.ensure_https(tenancy.render_apache(instance))
    finally: first.close()
    plan = copy.deepcopy(plan)
    current = integration.decode(root.read_bytes(integration.REGISTRY))
    profile = integration.decode(root.read_bytes(integration.PROFILE))
    own = current['consumers']['whatsapp.fixture']
    for name in own['vhosts']:
        if name in current['links']:
            relative = '../sites-available/' + Path(name).name
            current['links'][name]['target'] = relative
            current['links'][name]['resolved_target'] = name.replace('sites-enabled','sites-available')
            target = root.base / name.lstrip('/')
            target.unlink(); target.symlink_to(relative)
    put(root, integration.REGISTRY, integration.encoded(current), 0o600)
    plan['frontend']['registry'], plan['frontend']['profile'] = current, profile
    plan['operation_id'] = 'b' * 32
    runner.calls.clear()
    context = integration.Integration(instance,plan,integration.sha(integration.encoded(plan)),
        root_path=root.base,runner=runner).preflight()
    try:
        rendered = tenancy.render_apache(instance) + '\n# synthetic approved update\n'
        assert context.ensure_https(rendered)['phase'] == 'https_ready'
        assert not any(Path(call[0]).name in ('certbot','dig','virtualmin') for call in runner.calls)
        assert runner.issued == 1
        new = integration.decode(root.read_bytes(integration.REGISTRY))
        for name in own['vhosts']:
            if name in current['links']:
                assert new['links'][name] == current['links'][name]
                assert root.link(name)['target'] == current['links'][name]['target']
    finally: context.close()


def test_completed_frontend_receipt_is_rechecked_against_actual_vhost(setup):
    root,instance,_,runner,load = setup
    first = load()
    try: first.ensure_https(tenancy.render_apache(instance))
    finally: first.close()
    name = '/etc/apache2/sites-available/' + instance.base + '-https.conf'
    drifted = root.read_bytes(name) + b'\n# unexpected external drift\n'
    put(root,name,drifted)
    retry = load()
    try:
        with pytest.raises(ValueError,match='Active configuration'):
            retry.ensure_https(tenancy.render_apache(instance))
        assert root.read_bytes(name) == drifted and runner.issued == 1
    finally: retry.close()


def test_frontend_binding_failure_is_not_complete_and_retry_never_reissues(setup):
    _,instance,_,runner,load = setup
    run = runner.run
    attempts = []
    def fail_binding(argv,**kwargs):
        if 'register-frontend' in argv:
            attempts.append(list(argv))
            raise RuntimeError('synthetic binding interrupted')
        return run(argv,**kwargs)
    runner.run = fail_binding
    first = load()
    try:
        with pytest.raises(RuntimeError,match='binding interrupted'):
            first.ensure_https(tenancy.render_apache(instance))
        assert first._read_record()['phase'] == 'issuing'
    finally: first.close()
    runner.run = run
    resumed = load()
    try:
        result = resumed.ensure_https(tenancy.render_apache(instance))
        assert result['qos_frontend'] == 'configuration-bound' and not result['frontend_traffic_verified']
        assert resumed._read_record()['phase'] == 'tls-ready'
    finally: resumed.close()
    assert len(attempts) == 1 and runner.issued == 1


def test_actual_qos_binding_accepts_http_and_tls_publication_then_new_upgrade_receipt(setup,monkeypatch):
    root,instance,plan,runner,_ = setup
    location = root.base/(plan['generation']['path']+'/host/qos/applicator.py').lstrip('/')
    spec = importlib.util.spec_from_file_location('installed_qos_binding_test', location)
    qos = importlib.util.module_from_spec(spec); spec.loader.exec_module(qos)
    installed_identity = qos.installation_profile.__globals__
    installed_identity['select'](installed_identity['Installation'].legacy())
    # Substitute the explicitly synthetic acquired binary identity, never its
    # validator, registry, completed frontend receipt or real filesystem reads.
    monkeypatch.setattr(qos,'MODULE_SHA256',SYNTHETIC_MODULE_SHA)
    monkeypatch.setattr(qos,'MODULE_DESTINATION',SYNTHETIC_MODULE_PATH)
    policy = json.loads((REPOSITORY/'tools/tests/fixtures/qos/synthetic-policy.json').read_bytes())
    policy['foreign_module'].update(destination=SYNTHETIC_MODULE_PATH,sha256=SYNTHETIC_MODULE_SHA)
    policy_bytes = qos.canonical(policy)
    plan = copy.deepcopy(plan); plan['qos']['sha256'] = qos.sha(policy_bytes)
    qos.prepare(root,policy_bytes=policy_bytes,expected_sha256=plan['qos']['sha256'],operation_id='d'*32)
    consumers = copy.deepcopy(policy['initial_consumers'])
    consumers['whatsapp.fixture'] = {'owner':'whatsapp','account':instance.service_user,'uid':1234,'gid':1234,
        'home':str(instance.gateway_home),'unit':instance.base+'.service','status':'active'}
    uid_registry = {'format':1,'policy_sha256':plan['qos']['sha256'],'consumers':consumers}
    put(root,qos.REGISTRY,qos.canonical(uid_registry),0o600)
    accounts = copy.deepcopy(policy['parameters']['essential_accounts'])
    accounts.update({record['account']:{**record,'shell':'/usr/sbin/nologin'} for record in consumers.values()})
    def lookup(name):
        record = accounts[name]
        return SimpleNamespace(pw_name=name,pw_uid=record['uid'],pw_gid=record['gid'],
            pw_dir=record['home'],pw_shell=record['shell'])
    observed_kernel = {'tc':policy['parameters']['tc'],'io':policy['parameters']['io_qos'],
        'nft':qos.nft_policy(policy,consumers)[1]}
    def kernel_factory(actual_root,actual_policy,descriptor):
        assert actual_root is root and actual_policy == policy
        os.fstat(descriptor)
        return SimpleNamespace(ready=lambda:None,observe=lambda:copy.deepcopy(observed_kernel))
    run = runner.run; observed = []
    def checked(argv,**kwargs):
        if 'register-frontend' in argv:
            get = lambda key: argv[argv.index(key)+1]
            value = qos.frontend_binding(root,consumer_id=get('--consumer-id'),
                operation_id=get('--frontend-operation-id'),receipt_sha256=get('--frontend-receipt-sha256'))
            observed.append(value)
            assert value['status']=='configuration-bound' and value['runtime_verified'] is False
            receipt = qos.register_frontend(root,policy_path=get('--policy'),expected_sha256=get('--expected-sha256'),
                operation_id=get('--operation-id'),consumer_id=get('--consumer-id'),
                frontend_operation_id=get('--frontend-operation-id'),
                frontend_receipt_sha256=get('--frontend-receipt-sha256'),kernel_factory=kernel_factory,
                lookup=lookup,census=lambda:[lookup(name) for name in accounts])
            return qos.canonical(receipt)
        return run(argv,**kwargs)
    runner.run = checked
    first = integration.Integration(instance,plan,integration.sha(integration.encoded(plan)),
        root_path=root.base,runner=runner).preflight()
    try: first.ensure_https(tenancy.render_apache(instance))
    finally: first.close()
    new_plan = copy.deepcopy(plan)
    new_plan['operation_id'] = 'c'*32
    new_plan['frontend']['registry'] = integration.decode(root.read_bytes(integration.REGISTRY))
    new_plan['frontend']['profile'] = integration.decode(root.read_bytes(integration.PROFILE))
    upgrade = integration.Integration(instance,new_plan,integration.sha(integration.encoded(new_plan)),
        root_path=root.base,runner=runner).preflight()
    try:
        rendered = tenancy.render_apache(instance)+'\n# reviewed synthetic update\n'
        upgrade.ensure_https(rendered)
        upgrade.ensure_https(rendered)  # Committed binding is reobserved, not blindly accepted.
    finally: upgrade.close()
    assert len(observed)==3 and runner.issued==1
    assert observed[0]['frontend_operation_id'] != observed[1]['frontend_operation_id']
    assert observed[0]['vhosts'] != observed[1]['vhosts']
    assert observed[1] == observed[2]
    bindings = qos.decode(root.read_bytes(qos.FRONTENDS))
    assert bindings['bindings']['whatsapp.fixture'] == observed[-1]
    assert qos.decode(root.read_bytes(qos.REGISTRY)) == uid_registry


def test_fresh_named_acme_directory_is_created_after_readonly_preflight(setup):
    root,instance,plan,_,load = setup
    path = root.base/plan['frontend']['webroot'].lstrip('/')
    path.rmdir()
    context = load()
    try:
        assert not path.exists()
        context.begin_runtime()
        assert path.is_dir() and path.stat().st_mode & 0o777 == 0o755
        context.begin_runtime()
        assert context.ensure_https(tenancy.render_apache(instance))['phase'] == 'https_ready'
    finally: context.close()


@pytest.fixture
def admission(staged_whatsapp):
    host, bundle, manifest, payloads = staged_whatsapp
    lifecycle.apply(host,'a'*32,lifecycle.empty('whatsapp'),manifest,payloads)
    lifecycle.select_fixture_generation(host,bundle)
    admin = integration.load_administration(root_path=host)
    admin._TRUST_ROOT = host
    admin._trusted_uid = lambda uid: uid == os.getuid()
    admin.STATE = host/'var/lib/develative-deploy/whatsapp'
    admin.PUBLICATION_LOCK = admin.STATE/'publication.lock'
    admin.OWNER = host/'etc/develative-deploy/recovery-owners/whatsapp.json'
    admin.BOOTSTRAP = host/integration.BOOTSTRAP.lstrip('/')
    admin.ENTRYPOINT = admin.BOOTSTRAP/'release_entry.py'
    admin.GENERATIONS = host/'usr/local/lib/develative-deploy/whatsapp-generations'
    project = host/'srv/openai-codex/projects/whatsapp-personal'
    (project/'private').mkdir(parents=True,exist_ok=True,mode=0o700)
    return host,admin,project


@pytest.mark.parametrize('state',['transitioning','retiring','retired'])
def test_actual_owner_rejects_runtime_changes_before_tenant_lock(admission,state):
    _,admin,project = admission
    owner = json.loads(admin.OWNER.read_bytes()); owner['state'] = state
    admin.OWNER.write_bytes(integration.encoded(owner))
    with pytest.raises(admin.AdminError):
        with integration.runtime_admission(project,administration=admin): pytest.fail('closed owner admitted writes')
    assert not (project/'private/tenant-admin.lock').exists()


def test_actual_publication_then_tenant_leases_are_nonblocking_and_inherited(admission):
    _,admin,project = admission
    child = None
    try:
        with integration.runtime_admission(project,administration=admin) as descriptor:
            with pytest.raises(admin.AdminBusy):
                with integration.runtime_admission(project,administration=admin): pytest.fail('publication lease was bypassed')
            child = subprocess.Popen([sys.executable,'-B','-c',
                'import os,sys;os.fstat(int(sys.argv[1]));print("ready",flush=True);sys.stdin.read(1)',str(descriptor)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,**integration.command_options())
            assert child.stdout.readline().strip() == 'ready'
        with pytest.raises(RuntimeError,match='Tenant administration is already'):
            with integration.runtime_admission(project,administration=admin): pytest.fail('inherited tenant lease was bypassed')
        child.communicate('x',timeout=5)
        with integration.runtime_admission(project,administration=admin): pass
    finally:
        if child is not None and child.poll() is None:
            child.kill();child.wait(timeout=5)


def test_bootstrap_protection_precedes_execution(admission):
    host,admin,_ = admission
    path = admin.BOOTSTRAP/'release_admin.py'
    marker = host/'unexpected-execution'
    path.write_text('from pathlib import Path\nPath('+repr(str(marker))+').touch()\n')
    path.chmod(0o666)
    with pytest.raises(ValueError,match='not protected'):
        integration.load_administration(root_path=host)
    assert not marker.exists()


@pytest.mark.parametrize('action',['add','enable-linking','suspend','resume'])
def test_tenant_cli_mutations_enter_dedicated_admission_before_any_effect(admission,monkeypatch,action):
    monkeypatch.syspath_prepend(str(PLUGIN/'scripts'))
    _,admin,project = admission
    owner = json.loads(admin.OWNER.read_bytes()); owner['state'] = 'retired'
    admin.OWNER.write_bytes(integration.encoded(owner))
    spec = importlib.util.spec_from_file_location('tenant_admission_test', PLUGIN/'scripts/tenant_admin.py')
    tenant = importlib.util.module_from_spec(spec);spec.loader.exec_module(tenant)
    monkeypatch.setattr(tenant,'os',SimpleNamespace(geteuid=lambda:0,umask=lambda value:None))
    monkeypatch.setattr(tenant,'admit_runtime',lambda:integration.runtime_admission(project,administration=admin))
    monkeypatch.setattr(tenant,'registry',lambda:pytest.fail('registry access bypassed closed admission'))
    monkeypatch.setattr(tenant,'load_host_context',lambda *a:pytest.fail('provider access bypassed closed admission'))
    with pytest.raises(admin.AdminError): tenant.main([action,'--user','fixture','--apply'])


@pytest.mark.parametrize('script',['tenant_admin','provision_host'])
def test_old_runtime_interpreter_rejects_new_admin_scripts_before_state_imports(monkeypatch,script):
    import sally_whatsapp
    monkeypatch.syspath_prepend(str(PLUGIN/'scripts'))
    monkeypatch.setattr(sally_whatsapp,'__version__','0.4.9')
    spec = importlib.util.spec_from_file_location('old_runtime_'+script, PLUGIN/'scripts'/f'{script}.py')
    module = importlib.util.module_from_spec(spec)
    with pytest.raises(ValueError,match='copying scripts does not upgrade'):
        spec.loader.exec_module(module)
    assert 'StateContinuity' not in module.__dict__


def test_dns_pending_is_registered_http_and_resumes_same_operation(setup):
    root, instance, _, runner, load = setup
    runner.public=False
    first=load()
    try:
        with pytest.raises(ValueError,match='Public DNS'):
            first.ensure_https(tenancy.render_apache(instance))
        record=integration.decode(root.read_bytes(integration.REGISTRY))
        assert record['consumers']['whatsapp.fixture']['status']=='pending_tls'
        assert record['consumers']['whatsapp.fixture']['lineages']==[] and runner.issued==0
    finally: first.close()
    runner.public=True
    resumed=load()
    try: assert resumed.ensure_https(tenancy.render_apache(instance))['phase']=='https_ready'
    finally: resumed.close()
    assert runner.issued==1


def test_successful_issuance_lost_reply_resumes_without_new_certificate(setup):
    _,instance,_,runner,load=setup
    runner.lose_issuance_reply=True
    first=load()
    try:
        with pytest.raises(RuntimeError,match='lost issuance'):
            first.ensure_https(tenancy.render_apache(instance))
        assert first._read_record()['phase']=='issuing'
    finally:first.close()
    resumed=load()
    try:assert resumed.ensure_https(tenancy.render_apache(instance))['phase']=='https_ready'
    finally:resumed.close()
    assert runner.issued==1


def test_other_consumer_registry_change_is_preserved_before_any_frontend_publication(setup):
    root,instance,_,runner,load=setup
    context=load()
    try:
        context.begin_runtime()
        current=integration.decode(root.read_bytes(integration.REGISTRY))
        current['consumers']['box.web']['status']='retired'
        changed=integration.encoded(current); put(root,integration.REGISTRY,changed,0o600)
        with pytest.raises(ValueError,match='outside this exact tenant'):
            context.ensure_https(tenancy.render_apache(instance))
        assert root.read_bytes(integration.REGISTRY)==changed and runner.issued==0
    finally:context.close()


def test_partial_http_registry_publication_resumes_exact_provider_operation(setup,monkeypatch):
    root,instance,_,runner,load=setup
    first=load()
    reconcile=first.engine.reconcile
    fired=False
    def interrupted(*args,**kwargs):
        def fault(event,detail):
            nonlocal fired
            if event=='replaced-file' and detail['path']==integration.PROFILE and not fired:
                fired=True
                raise RuntimeError('synthetic partial profile publication')
        return reconcile(*args,**kwargs,fault=fault)
    monkeypatch.setattr(first.engine,'reconcile',interrupted)
    try:
        with pytest.raises(RuntimeError,match='partial profile'):
            first.ensure_https(tenancy.render_apache(instance))
        assert first._read_record()['phase']=='prepared' and runner.issued==0
        assert integration.decode(root.read_bytes(integration.REGISTRY))['consumers'].get('whatsapp.fixture') is None
    finally:first.close()
    resumed=load()
    try:assert resumed.ensure_https(tenancy.render_apache(instance))['phase']=='https_ready'
    finally:resumed.close()
    assert runner.issued==1


def test_ambiguous_issuance_without_lineage_never_retries_blindly(setup):
    _,instance,_,runner,load=setup
    run=runner.run
    attempts=[]
    def fail(argv,**kwargs):
        if Path(argv[0]).name=='certbot':
            attempts.append(argv)
            raise RuntimeError('synthetic issuer disappeared')
        return run(argv,**kwargs)
    runner.run=fail
    first=load()
    try:
        with pytest.raises(RuntimeError,match='issuer disappeared'):
            first.ensure_https(tenancy.render_apache(instance))
    finally:first.close()
    resumed=load()
    try:
        with pytest.raises(ValueError,match='issuance was interrupted'):
            resumed.ensure_https(tenancy.render_apache(instance))
        assert resumed._read_record()['phase']=='issuing'
    finally:resumed.close()
    assert len(attempts)==1


@pytest.mark.parametrize('failure',['source','writable-plan','tenant','digest'])
def test_preflight_rejects_untrusted_or_mismatched_inputs_without_commands(setup,failure):
    root,instance,plan,runner,load=setup
    if failure=='source':
        put(root,plan['generation']['path']+'/host/frontend/provider.py',b'raise AssertionError("must not compile")\n')
    elif failure=='writable-plan':
        (root.base/'etc/develative-deploy/fixture-host-plan.json').chmod(0o666)
    elif failure=='tenant':
        plan['instance']['bridge_port']+=2
        put(root,'/etc/develative-deploy/fixture-host-plan.json',integration.encoded(plan),0o600)
    else:
        put(root,'/etc/develative-deploy/fixture-host-plan.json',b'{}\n',0o600)
    with pytest.raises(ValueError):
        if failure=='tenant':
            integration.load(instance,'/etc/develative-deploy/fixture-host-plan.json',integration.sha(integration.encoded(plan)),
                             root_path=root.base,runner=runner)
        else:load()
    assert runner.calls==[]


def test_isolated_certificate_plan_waits_for_host_issuance_without_shared_fallback(setup):
    root, instance, original, runner, _ = setup
    plan=copy.deepcopy(original)
    front=plan['frontend'];front['certificates']='isolated'
    for key in ('lineage','archive','renewal'):
        front[key]=front[key].replace('/etc/letsencrypt','/etc/develative-certificates')
    context=integration.Integration(instance,plan,integration.sha(integration.encoded(plan)),root_path=root.base,runner=runner)
    try:
        context.preflight();context.begin_runtime()
        with pytest.raises(ValueError,match='isolated host certificate service'):
            context.ensure_https(tenancy.render_apache(instance))
        assert runner.issued==0
        assert not any(Path(call[0]).name=='certbot' for call in runner.calls)
        # Synthetic issued material: model the independent host certificate
        # operation, with no ACME/network or production source involved.
        runner.issue()
        for kind in ('live','archive'):
            source=root.base/('etc/letsencrypt/'+kind+'/'+instance.hostname)
            target=root.base/('etc/develative-certificates/'+kind+'/'+instance.hostname)
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copytree(source,target,symlinks=True)
        put(root,front['renewal'],b'synthetic isolated renewal metadata\n',0o600)
        assert context.ensure_https(tenancy.render_apache(instance))['phase']=='https_ready'
        body=root.read_bytes('/etc/apache2/sites-available/'+instance.base+'-https.conf')
        assert (front['lineage']+'/fullchain.pem').encode() in body
        assert ('/etc/letsencrypt/live/'+instance.hostname).encode() not in body
    finally:context.close()
