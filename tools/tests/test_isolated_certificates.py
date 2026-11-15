"""Real private files/crypto, simulated ACME/systemd; no production access."""
import copy
import datetime
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from test_host_frontend import registry, root, staged_setup, finite, front, empty, FiniteCommands, engine
from test_fresh_frontend_profile import put, directory

BASE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('certificate_tests', BASE/'host/frontend/certificates.py')
certs = importlib.util.module_from_spec(spec); spec.loader.exec_module(certs)
NAMES = ('wa-owner.example.test', 'wa-secondary.example.test', 'auth.example.test')
OWNERS = ('whatsapp.personal', 'whatsapp.secondary', 'host.auth')
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def renewal(plan, name):
    prefix = certs.CONFIG
    body = '\n'.join(k+' = '+v for k,v in {
        'version':'4.0.0','archive_dir':prefix+'/archive/'+name,'cert':prefix+'/live/'+name+'/cert.pem',
        'privkey':prefix+'/live/'+name+'/privkey.pem','chain':prefix+'/live/'+name+'/chain.pem',
        'fullchain':prefix+'/live/'+name+'/fullchain.pem'}.items())
    return (body+'\n[renewalparams]\naccount = '+plan['account']+'\nserver = '+certs.SERVER+
        '\nauthenticator = webroot\ninstaller = None\nwebroot_path = '+plan['lineages'][name]['webroot']+
        ',\n[[webroot_map]]\n'+name+' = '+plan['lineages'][name]['webroot']+'\n').encode()


def issue(root, plan, name, generation=1, extra_san=None, expired=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    dn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = x509.CertificateBuilder().subject_name(dn).issuer_name(dn).public_key(KEY.public_key()).serial_number(generation)
    builder = builder.not_valid_before(now-datetime.timedelta(days=30) if expired else now-datetime.timedelta(minutes=1)).not_valid_after(now-datetime.timedelta(days=1) if expired else now+datetime.timedelta(days=30))
    builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in [name, *([extra_san] if extra_san else [])]]), critical=False)
    body = builder.sign(KEY, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    key = KEY.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    for kind, content in [('cert',body),('chain',body),('fullchain',body),('privkey',key)]:
        put(root,certs.CONFIG+'/archive/'+name+'/'+kind+str(generation)+'.pem',content,0o600)
        directory(root.base,certs.CONFIG+'/live/'+name)
        path = root.base/(certs.CONFIG+'/live/'+name+'/'+kind+'.pem').lstrip('/')
        if path.is_symlink():path.unlink()
        path.symlink_to('../../archive/'+name+'/'+kind+str(generation)+'.pem')
    put(root,certs.CONFIG+'/renewal/'+name+'.conf',renewal(plan,name),0o600)


class Commands(FiniteCommands):
    def __init__(self, root, plan):
        super().__init__(); self.root,self.plan = root,plan
        self.network = []; self.interrupt = False; self.no_change = False; self.active = False; self.fail_reload = False
    def run(self, argv, **kwargs):
        name = Path(argv[0]).name
        if name == 'systemd-run':
            self.calls.append(argv); self.network.append(argv)
            assert 'TemporaryFileSystem=/etc/letsencrypt:ro /var/lib/letsencrypt:ro /var/log/letsencrypt:ro' in argv
            assert 'Environment=HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent PATH=/usr/bin:/bin' in argv
            assert '--no-directory-hooks' in argv
            for option in ('--pre-hook','--post-hook','--deploy-hook'):
                assert argv[argv.index(option)+1] == ''
            hostname = argv[argv.index('--cert-name')+1]
            assert argv[argv.index('--config-dir')+1] == certs.CONFIG
            assert argv[argv.index('--config')+1] == certs.CONFIG+'/cli.ini'
            if not self.no_change:
                live=self.root.link(certs.CONFIG+'/live/'+hostname+'/fullchain.pem')
                generation=1 if live is None else int(Path(live['target']).stem.replace('fullchain',''))+1
                issue(self.root,self.plan,hostname,generation)
            if self.interrupt: raise RuntimeError('lost client response')
            return b''
        if name == 'openssl':
            self.calls.append(argv)
            return subprocess.run(argv,input=kwargs.get('input_bytes'),capture_output=True,check=True).stdout
        if name == 'systemctl' and argv[1] == 'list-units':
            self.calls.append(argv)
            return (argv[-1]+' loaded active running Synthetic\n').encode() if self.active else b''
        if name == 'systemctl' and self.fail_reload: raise RuntimeError('lost reload response')
        # The runner refuses every command except TLS validation and exact
        # Apache reload. No shell/hook/mail/Webmin command can execute here.
        assert name in ('apache2','systemctl'), argv
        if name=='systemctl': assert argv[1:] == ['reload','apache2.service']
        return super().run(argv,**kwargs)


@pytest.fixture
def configured(registry, root):
    value, raw, profile, _, _ = staged_setup(registry,root)
    for name in ('/etc/letsencrypt','/var/lib/letsencrypt','/var/log/letsencrypt',certs.CONFIG,certs.WORK,certs.LOGS,certs.WORK+'/operations',certs.CONFIG+'/renewal',
                 certs.CONFIG+'/accounts/acme-v02.api.letsencrypt.org/directory/'+'a'*32,
                 *(certs.CONFIG+'/renewal-hooks/'+n for n in ('pre','post','deploy'))):
        directory(root.base,name,0o700)
    put(root,certs.CONFIG+'/cli.ini',b'',0o600)
    plan={'format':1,'account':'a'*32,'lineages':{},'tools':{}}
    for key,path in certs.TOOLS.items():
        if root.snapshot(path) is None:put(root,path,b'#!/bin/sh\nexit 0\n',0o700)
        plan['tools'][key]={'path':path,'sha256':root.snapshot(path)['sha256']}
    openssl=root.base/'usr/bin/openssl';shutil.copyfile('/usr/bin/openssl',openssl);openssl.chmod(0o700)
    profile['tools']['openssl']['sha256']=certs.sha(openssl.read_bytes())
    for name,consumer in zip(NAMES,OWNERS):
        webroot='/var/www/'+consumer.replace('.','-')+'-acme';directory(root.base,webroot)
        plan['lineages'][name]={'consumer':consumer,'webroot':webroot}
        vhost='/etc/apache2/sites-enabled/'+consumer.replace('.','-')+'.conf'
        raw[vhost]=('<VirtualHost *:443>\nServerName '+name+'\n</VirtualHost>\n').encode()
        value['artifacts'][vhost]={'sha256':certs.sha(raw[vhost]),'mode':0o640,'uid':root.uid,'gid':root.gid,'retention':'managed'}
        lineage=certs.CONFIG+'/live/'+name
        value['consumers'][consumer]={'owner':consumer.split('.')[0],'status':'active','domains':[name],'vhosts':[vhost],'lineages':[lineage]}
        source={'certificate':lineage+'/fullchain.pem','key':lineage+'/privkey.pem'}
        value['lineages'][lineage]={'domains':[name],'consumers':[consumer],'source':source,
            'destinations':[{'consumer':consumer,'mode':'direct',**source,'uid':root.uid,'gid':root.gid,'certificate_mode':0o644,'key_mode':0o600}]}
        profile['lineages'][lineage]={'archive_directory':certs.CONFIG+'/archive/'+name,
            'renewal':{'path':certs.CONFIG+'/renewal/'+name+'.conf','sha256':certs.sha(renewal(plan,name))}}
        profile['config_files'].append(vhost);profile['includes'][0]['targets'].append(vhost)
    profile['includes'][0]['targets'].sort()
    runner=Commands(root,plan);adapter=finite.HostAdapter(root,engine,value,profile,runner=runner)
    with adapter.lease():finite.apply_configuration(adapter,operation_id='a'*32,before=empty(),pinned_artifacts=raw)
    runner.calls.clear()
    worker=certs.Certificates(adapter,plan)
    return root,adapter,worker,runner,plan


def test_initial_and_mixed_store_renewals_reload_only_apache_for_all_three(configured):
    root,adapter,worker,runner,plan=configured
    foreign={name:root.read_bytes(name) for name in adapter.registry['host_files']}
    # The global directory hooks and renewal are deliberately hostile sentinels.
    for name in ('/etc/letsencrypt/renewal-hooks/deploy/50-develative-services',
                 '/etc/letsencrypt/renewal-hooks/post/90-develative-services',
                 '/etc/letsencrypt/cli.ini','/etc/letsencrypt/renewal/mail.example.test.conf'):
        put(root,name,b'post-hook = restart mail Webmin Usermin\n',0o700)
        foreign[name]=root.read_bytes(name)
    with adapter.lease():
        for name in NAMES:assert worker.run(name,'issue')['status']=='complete'
        for name in NAMES:assert worker.run(name,'renew')['status']=='complete'
    assert len(runner.network)==6
    assert all(root.read_bytes(name)==body for name,body in foreign.items())
    assert all('mail.example.test' not in call for call in runner.network)
    assert not any('50-develative-services' in ' '.join(call) or '90-develative-services' in ' '.join(call) for call in runner.calls)


@pytest.mark.parametrize('fault',['foreign-renewal','hook-directory','persisted-hook','mixed-san','mixed-webroot','installer','account','cli'])
def test_foreign_mixed_or_hooked_private_store_fails_before_acme(configured,fault):
    root,adapter,worker,runner,plan=configured
    name=NAMES[0];issue(root,plan,name)
    path=certs.CONFIG+'/renewal/'+name+'.conf'
    if fault=='foreign-renewal':put(root,certs.CONFIG+'/renewal/foreign.conf',b'foreign\n',0o600)
    elif fault=='hook-directory':put(root,certs.CONFIG+'/renewal-hooks/post/foreign',b'foreign\n',0o700)
    elif fault=='mixed-san':issue(root,plan,name,extra_san='foreign.example.test')
    elif fault=='cli':put(root,certs.CONFIG+'/cli.ini',b'post-hook = foreign\n',0o600)
    else:
        body=root.read_bytes(path)
        if fault=='persisted-hook':body=body.replace(b'[renewalparams]',b'[renewalparams]\ndeploy_hook = foreign')
        elif fault=='mixed-webroot':body+=b'foreign.example.test = /var/www/foreign\n'
        elif fault=='installer':body=body.replace(b'installer = None',b'installer = apache')
        elif fault=='account':body=body.replace(b'account = '+b'a'*32,b'account = '+b'b'*32)
        put(root,path,body,0o600)
    with adapter.lease(),pytest.raises(ValueError):worker.run(name,'renew')
    assert not runner.network


def test_lost_issue_reply_resumes_certificate_without_second_acme_call(configured):
    root,adapter,worker,runner,plan=configured
    runner.interrupt=True
    with adapter.lease(),pytest.raises(RuntimeError):worker.run(NAMES[0],'issue')
    runner.interrupt=False
    with adapter.lease():assert worker.run(NAMES[0],'issue')['status']=='complete'
    assert len(runner.network)==1


def test_active_detached_unit_and_unchanged_uncertain_result_block_retry(configured):
    root,adapter,worker,runner,plan=configured
    runner.interrupt=True;runner.no_change=True
    with adapter.lease(),pytest.raises(RuntimeError):worker.run(NAMES[0],'issue')
    runner.active=True
    with adapter.lease(),pytest.raises(ValueError,match='running'):worker.run(NAMES[0],'issue')
    runner.active=False
    with adapter.lease(),pytest.raises(ValueError,match='uncertain'):worker.run(NAMES[0],'issue')
    assert len(runner.network)==1


def test_lost_reload_reply_retries_only_deployment(configured):
    root,adapter,worker,runner,plan=configured
    runner.fail_reload=True
    with adapter.lease(),pytest.raises(RuntimeError):worker.run(NAMES[0],'issue')
    runner.fail_reload=False
    with adapter.lease():assert worker.run(NAMES[0],'issue')['status']=='complete'
    assert len(runner.network)==1


def test_exact_renewal_pin_refresh_is_durable_and_keeps_foreign_profile(configured):
    root,adapter,worker,runner,plan=configured
    name=NAMES[0];issue(root,plan,name)
    path=certs.CONFIG+'/renewal/'+name+'.conf'
    put(root,path,root.read_bytes(path)+b'# metadata rewritten by Certbot\n',0o600)
    original=copy.deepcopy(adapter.profile)
    with adapter.lease():worker.run(name,'renew')
    # The simulated Certbot rewrites to its normal bytes; inject a harmless
    # version-comment rewrite after issuance to exercise the exact pin update.
    put(root,path,root.read_bytes(path)+b'# public audited metadata\n',0o600)
    record=worker._load(name);record['phase']='deployment-pending';worker._save(name,record)
    with adapter.lease():worker.run(name,'renew')
    current=json.loads(root.read_bytes('/etc/develative-host-frontend/profile.json'))
    expected=copy.deepcopy(original);expected['lineages'][certs.CONFIG+'/live/'+name]['renewal']['sha256']=root.snapshot(path)['sha256']
    assert current==expected


def test_retired_consumer_is_not_renewed_and_unknown_names_cannot_request(configured):
    root,adapter,worker,runner,plan=configured
    adapter.registry['consumers'][OWNERS[0]]['status']='retired'
    put(root,front.REGISTRY,front.encoded(adapter.registry),0o600)
    with adapter.lease():
        assert worker.run(NAMES[0],'renew')['status']=='skipped-retired'
        with pytest.raises(ValueError):worker.run('foreign.example.test','issue')
    assert not runner.network


def test_rendered_timer_is_scoped_and_never_changes_global_certbot():
    units=certs.render_units('/usr/local/lib/develative-host-components/'+'a'*64,'b'*64,certs.CONFIG+'/plan.json','c'*64)
    assert len(units)==2
    assert 'certbot.timer' not in ''.join(units.values())
    assert 'certificates.py renew' in units['develative-isolated-certificates.service']
    assert '--plan-sha256 '+'c'*64 in units['develative-isolated-certificates.service']


def test_global_lineage_with_same_name_is_never_migrated_implicitly(configured):
    root,adapter,worker,runner,plan=configured
    name=NAMES[0]
    path='/etc/letsencrypt/renewal/'+name+'.conf'
    put(root,path,b'old scheduled lineage\n',0o600)
    with adapter.lease(),pytest.raises(ValueError,match='global Certbot'):worker.run(name,'issue')
    assert root.read_bytes(path)==b'old scheduled lineage\n' and not runner.network


def test_auth_renewal_does_not_require_retired_whatsapp_webroots(configured):
    root,adapter,worker,runner,plan=configured
    with adapter.lease():
        for name in NAMES:worker.run(name,'issue')
    with adapter.lease():
        assert adapter.retire_application(owner='whatsapp',operation_id='e'*32)['phase']=='complete'
    current=json.loads(root.read_bytes(front.REGISTRY))
    profile=json.loads(root.read_bytes('/etc/develative-host-frontend/profile.json'))
    adapter=finite.HostAdapter(root,engine,current,profile,runner=runner)
    worker=certs.Certificates(adapter,plan)
    for name in NAMES[:2]:shutil.rmtree(root.base/plan['lineages'][name]['webroot'].lstrip('/'))
    with adapter.lease():
        for name in NAMES[:2]:assert worker.run(name,'renew')['status']=='skipped-retired'
        assert worker.run(NAMES[2],'renew')['status']=='complete'
    assert len(runner.network)==4


def test_renewal_metadata_update_retries_without_second_acme_after_filesystem_failure(configured,monkeypatch):
    root,adapter,worker,runner,plan=configured
    name=NAMES[0];issue(root,plan,name)
    path=certs.CONFIG+'/renewal/'+name+'.conf'
    original_run=runner.run
    def rewrite(argv,**kwargs):
        result=original_run(argv,**kwargs)
        if Path(argv[0]).name=='systemd-run':put(root,path,root.read_bytes(path)+b'# changed\n',0o600)
        return result
    runner.run=rewrite
    reconcile=adapter.engine.reconcile
    def fail(*args,**kwargs):raise RuntimeError('pin publication failed')
    monkeypatch.setattr(adapter.engine,'reconcile',fail)
    with adapter.lease(),pytest.raises(RuntimeError,match='pin publication'):worker.run(name,'renew')
    monkeypatch.setattr(adapter.engine,'reconcile',reconcile)
    with adapter.lease():assert worker.run(name,'renew')['status']=='complete'
    assert len(runner.network)==1


def test_journal_write_failure_prevents_acme_request(configured,monkeypatch):
    root,adapter,worker,runner,plan=configured
    def fail(*args):raise OSError('journal unavailable')
    monkeypatch.setattr(worker,'_save',fail)
    with adapter.lease(),pytest.raises(OSError):worker.run(NAMES[0],'issue')
    assert not runner.network



def test_zero_exit_without_certificate_never_claims_success(configured):
    root,adapter,worker,runner,plan=configured
    name=NAMES[0];runner.no_change=True
    with adapter.lease(),pytest.raises(ValueError,match='without a verified lineage'):
        worker.run(name,'issue')
    assert worker._load(name)['phase']=='requesting' and len(runner.network)==1



def test_first_issue_before_binding_does_not_invent_active_consumer_or_reload(configured):
    root,adapter,_,runner,plan=configured
    name=NAMES[2];lineage=certs.CONFIG+'/live/'+name
    value=copy.deepcopy(adapter.registry);profile=copy.deepcopy(adapter.profile)
    value['consumers'][OWNERS[2]].update(status='pending_tls',lineages=[])
    value['lineages'].pop(lineage);profile['lineages'].pop(lineage)
    put(root,front.REGISTRY,front.encoded(value),0o600)
    put(root,'/etc/develative-host-frontend/profile.json',front.encoded(profile),0o600)
    adapter=finite.HostAdapter(root,engine,value,profile,runner=runner)
    worker=certs.Certificates(adapter,plan)
    with adapter.lease():assert worker.run(name,'issue')=={'status':'issued-unbound','domain':name}
    assert json.loads(root.read_bytes(front.REGISTRY))['consumers'][OWNERS[2]]['status']=='pending_tls'
    assert not any(Path(call[0]).name=='systemctl' and call[1]=='reload' for call in runner.calls)



def test_one_acme_failure_does_not_starve_other_names_but_is_reported(configured):
    root,adapter,worker,runner,plan=configured
    original=runner.run
    def fail_auth(argv,**kwargs):
        if Path(argv[0]).name=='systemd-run' and argv[argv.index('--cert-name')+1]==NAMES[2]:
            runner.network.append(argv)
            raise RuntimeError('simulated ACME failure before issuance')
        return original(argv,**kwargs)
    runner.run=fail_auth
    with adapter.lease():results,failed=worker.run_many([NAMES[2],*NAMES[:2]],'issue')
    assert failed and [item['status'] for item in results]==['blocked','complete','complete']
    assert results[0]=={'domain':NAMES[2],'status':'blocked','errorType':'RuntimeError'}
    assert len(runner.network)==3 and worker._load(NAMES[2])['phase']=='requesting'


def test_pending_apache_publication_blocks_other_acme_effects(configured):
    root,adapter,worker,runner,plan=configured
    runner.fail_reload=True
    with adapter.lease():results,failed=worker.run_many(NAMES,'issue')
    assert failed and [item['status'] for item in results]==['blocked']*3
    assert len(runner.network)==1



def real_certbot_serialization(root, argv, monkeypatch):
    """Real 4.0.0 parser/hooks/storage; only namespace filesystem is a fixture.

    The production argv is unchanged except the location of its empty config
    file. Certbot's real webroot filesystem validator sees the corresponding
    temporary directory, and the parser receives the original logical path.
    Default config lookup is empty, modeling the unit's masked global/home dirs.
    No parser, argument-source logic, relevant_values or writer is mocked.
    """
    import importlib.metadata
    import socket
    from certbot._internal import cli, constants, storage, hooks
    from certbot._internal.plugins import disco, webroot
    assert importlib.metadata.version('certbot')=='4.0.0'
    args=argv[argv.index('/usr/bin/certbot')+1:].copy()
    args[args.index('--config')+1]=str(root.base/(certs.CONFIG+'/cli.ini').lstrip('/'))
    validate_webroot=webroot._validate_webroot
    def in_namespace(value):
        validate_webroot(str(root.base/value.lstrip('/')))
        return value
    def forbidden(*args,**kwargs):raise AssertionError('No ACME/network or hook command permitted')
    with monkeypatch.context() as guard:
        guard.setitem(constants.CLI_DEFAULTS,'config_files',[])
        guard.setattr(webroot,'_validate_webroot',in_namespace)
        guard.setattr(socket.socket,'connect',forbidden)
        guard.setattr(hooks,'_run_hook',forbidden)
        config=cli.prepare_and_parse_args(disco.PluginsRegistry.find_all(),args)
        assert config.pre_hook==config.post_hook==config.renew_hook==''
        if args[0]=='renew':assert config.random_sleep_on_renew is False
        hooks.pre_hook(config);hooks.post_hook(config,[config.certname])
        hooks.deploy_hook(config,[config.certname],certs.CONFIG+'/live/'+config.certname)
        hooks.renew_hook(config,[config.certname],certs.CONFIG+'/live/'+config.certname)
        values=storage.relevant_values(config)
        assert {key:values[key] for key in ('pre_hook','post_hook','renew_hook')}==dict.fromkeys(('pre_hook','post_hook','renew_hook'),'')
        output=root.base/(certs.CONFIG+'/renewal/'+config.certname+'.conf').lstrip('/')
        storage.write_renewal_config(str(output)+'.absent',str(output),certs.CONFIG+'/archive/'+config.certname,
            {kind:certs.CONFIG+'/live/'+config.certname+'/'+kind+'.pem' for kind in storage.ALL_FOUR},values)
        return values,output.read_bytes()


@pytest.mark.parametrize('action',['issue','renew'])
def test_real_certbot40_argv_to_storage_to_audit_and_successful_resume(configured,monkeypatch,action):
    root,adapter,worker,runner,plan=configured
    name=NAMES[0]
    if action=='renew':issue(root,plan,name)
    original=runner.run
    serialized=[]
    def real_storage(argv,**kwargs):
        result=original(argv,**kwargs)
        if Path(argv[0]).name=='systemd-run':serialized.append(real_certbot_serialization(root,argv,monkeypatch))
        return result
    runner.run=real_storage
    with adapter.lease():
        assert worker.run(name,action)['status']=='complete'
        worker.audit()
    assert len(serialized)==1
    assert b'pre_hook = ""' in serialized[0][1] and b'post_hook = ""' in serialized[0][1]
    assert worker._load(name)['phase']=='complete'
    # Force a recovery after actual serialized metadata existed; no second ACME.
    record=worker._load(name);record['phase']='deployment-pending';worker._save(name,record)
    with adapter.lease():assert worker.run(name,action)['status']=='complete'
    assert len(runner.network)==1


@pytest.mark.parametrize('key',['pre_hook','post_hook','renew_hook'])
def test_actual_serialized_empty_hook_cannot_be_replaced_with_command(configured,monkeypatch,key):
    root,adapter,worker,runner,plan=configured
    name=NAMES[0];issue(root,plan,name)
    _,body=real_certbot_serialization(root,worker.command(name,'renew','develative-certificates-client-'+'a'*32),monkeypatch)
    path=certs.CONFIG+'/renewal/'+name+'.conf'
    assert (key+' = ""').encode() in body
    put(root,path,body.replace((key+' = ""').encode(),(key+' = /bin/false').encode()),0o600)
    with adapter.lease(),pytest.raises(ValueError,match='persisted certificate hooks'):worker.run(name,'renew')
    assert not runner.network


@pytest.mark.parametrize('action',['issue','renew'])
def test_expired_previous_pair_can_be_renewed_but_never_deployed_as_new(configured,action):
    root,adapter,worker,runner,plan=configured
    name=NAMES[0];issue(root,plan,name,expired=True)
    with adapter.lease():
        previous=worker._fingerprint(name,previous=True)
        with pytest.raises(ValueError,match='validity'):worker._fingerprint(name)
        assert worker.run(name,action)['status']=='complete'
        assert worker._fingerprint(name)!=previous
    assert len(runner.network)==1


@pytest.mark.parametrize('action',['issue','renew'])
def test_unchanged_expired_pair_after_client_success_is_not_accepted(configured,action):
    root,adapter,worker,runner,plan=configured
    name=NAMES[0];issue(root,plan,name,expired=True);runner.no_change=True
    with adapter.lease(),pytest.raises(ValueError,match='validity'):worker.run(name,action)
    assert worker._load(name)['phase']=='requesting'
    assert not any(Path(call[0]).name=='systemctl' and call[1]=='reload' for call in runner.calls)


def test_old_expired_pair_still_requires_matching_key_and_exact_san(configured):
    root,adapter,worker,runner,plan=configured
    name=NAMES[0];issue(root,plan,name,expired=True,extra_san='foreign.example.test')
    with adapter.lease(),pytest.raises(ValueError,match='SAN set'):worker.run(name,'renew')
    issue(root,plan,name,expired=True)
    other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    put(root,certs.CONFIG+'/archive/'+name+'/privkey1.pem',other.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),0o600)
    with adapter.lease(),pytest.raises(ValueError,match='do not match'):worker.run(name,'renew')
    assert not runner.network


def test_timer_owns_randomization_and_certbot_renew_has_full_runtime_budget(configured,monkeypatch):
    root,adapter,worker,runner,plan=configured
    name=NAMES[0]
    argv=worker.command(name,'renew','develative-certificates-client-'+'a'*32)
    assert '--no-random-sleep-on-renew' in argv and 'RuntimeMaxSec=600' in argv
    real_certbot_serialization(root,argv,monkeypatch)
    units=certs.render_units('/usr/local/lib/develative-host-components/'+'a'*64,'b'*64,certs.CONFIG+'/plan.json','c'*64)
    assert 'RandomizedDelaySec=1800' in units['develative-isolated-certificates.timer']



def test_different_but_expired_post_client_certificate_is_rejected(configured):
    root,adapter,worker,runner,plan=configured
    name=NAMES[0];issue(root,plan,name)
    original=runner.run
    def expired_result(argv,**kwargs):
        result=original(argv,**kwargs)
        if Path(argv[0]).name=='systemd-run':issue(root,plan,name,generation=3,expired=True)
        return result
    runner.run=expired_result
    with adapter.lease(),pytest.raises(ValueError,match='validity'):worker.run(name,'renew')
    assert worker._load(name)['phase']=='requesting' and len(runner.network)==1
    assert not any(Path(call[0]).name=='systemctl' and call[1]=='reload' for call in runner.calls)
