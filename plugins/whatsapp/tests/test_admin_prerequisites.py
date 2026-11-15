from dataclasses import asdict,replace
from contextlib import nullcontext
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
from types import SimpleNamespace

import pytest

from sally_whatsapp.auth import JWTVerifier
from sally_whatsapp.config import Settings
from sally_whatsapp import tenancy

PLUGIN=Path(__file__).parents[1]


def load_script(name):
    if str(PLUGIN/'scripts') not in sys.path: sys.path.insert(0,str(PLUGIN/'scripts'))
    spec=importlib.util.spec_from_file_location(name,PLUGIN/'scripts'/f'{name}.py')
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


def personal():
    return tenancy.Instance('personal','Synthetic','11111111-1111-4111-8111-111111111111',8820)


def configured_clients():
    instance=personal()
    cfg={'identity_providers':{'oidc':{'authorization_policies':{},'scopes':{},'clients':[]}}}
    users={'users':{instance.username:{'password':'synthetic-hash','disabled':False}}}
    cfg,users=tenancy.idp_candidate(cfg,users,instance,None)
    return instance,cfg,users


@pytest.mark.parametrize('empty',[[],None,''])
def test_empty_oauth_allowlist_fails_with_configuration_diagnostic(environment,empty):
    with pytest.raises(ValueError,match='oauth_client_ids is required'):
        replace(environment[0],oauth_client_ids=empty)
    data=asdict(environment[0]);data.pop('oauth_client_ids')
    with pytest.raises(ValueError,match='oauth_client_ids is required'): Settings(**data)


def test_client_identity_is_required_and_allowlist_cannot_fail_open(environment):
    settings,_,_,token=environment
    verifier=JWTVerifier(settings)
    assert verifier._verify(token()) is not None
    assert verifier._verify(token(_omit=('azp',),client_id='test-client')) is not None
    for supplied in (token(_omit=('azp',)),token(azp='other-client'),token(azp='other-client',client_id='test-client')):
        assert verifier._verify(supplied) is None
    settings.oauth_client_ids.clear()  # Defensive check if a caller mutates the contained list.
    assert verifier._verify(token()) is None


def test_legacy_callback_reconciliation_preserves_valid_registrations():
    instance,cfg,users=configured_clients()
    extra='https://chatgpt.com/fixture-additional-callback'
    clients=cfg['identity_providers']['oidc']['clients']
    clients[0]['redirect_uris']=[instance.public_url+'/oauth/setup-callback',extra]
    clients.append({'client_id':'unrelated','redirect_uris':['https://unrelated.example/callback']})
    original=copy.deepcopy(cfg)
    result,updated_users=tenancy.idp_candidate(cfg,users,instance,None)
    assert cfg==original and updated_users==users
    updated=result['identity_providers']['oidc']['clients']
    assert updated[0]['redirect_uris']==[tenancy.CHATGPT_CALLBACK,extra]
    assert updated[0]['client_id']==clients[0]['client_id']
    assert updated[1:]==clients[1:]
    assert tenancy.idp_candidate(result,users,instance,None)==(result,users)


@pytest.mark.parametrize('client_index',[0,1])
def test_unknown_callback_disagreement_fails_without_mutating_registration(client_index):
    instance,cfg,users=configured_clients()
    cfg['identity_providers']['oidc']['clients'][client_index]['redirect_uris']=['https://fixture.example/unknown-callback']
    original=copy.deepcopy(cfg)
    with pytest.raises(ValueError,match='redirect_uris differ'): tenancy.idp_candidate(cfg,users,instance,None)
    assert cfg==original


@pytest.fixture
def subject_admin(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(PLUGIN/'scripts'))
    admin=load_script('tenant_admin')
    database=tmp_path/'auth.sqlite'
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE user_opaque_identifier(service TEXT,sector_id TEXT,username TEXT,identifier TEXT UNIQUE,UNIQUE(service,sector_id,username))')
    instance=SimpleNamespace(username='synthetic-user',subject=personal().subject,private_dir=tmp_path/'private')
    instance.private_dir.mkdir()
    monkeypatch.setattr(admin,'AUTH_DATABASE',database)
    monkeypatch.setattr(admin,'write_private',lambda path,data,**kwargs:path.write_bytes(data.encode() if isinstance(data,str) else data))
    commands=[]
    def run(args,**kwargs):
        commands.append(args)
        with sqlite3.connect(database) as db:
            db.execute('INSERT INTO user_opaque_identifier VALUES(?,?,?,?)',('openid','',instance.username,instance.subject))
        return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
    monkeypatch.setattr(admin,'subprocess',SimpleNamespace(run=run))
    return admin,instance,database,commands


def test_subject_registration_is_idempotent_and_rechecks_stale_receipts(subject_admin):
    admin,instance,database,commands=subject_admin
    admin.register_subject(instance);admin.register_subject(instance)
    assert len(commands)==1
    with sqlite3.connect(database) as db: db.execute('DELETE FROM user_opaque_identifier')
    admin.register_subject(instance)
    assert len(commands)==2
    assert admin.subject_registered(instance)
    assert json.loads((instance.private_dir/'subject-registered.json').read_text())['subject']==instance.subject


def test_existing_subject_without_local_receipt_is_preserved(subject_admin):
    admin,instance,database,commands=subject_admin
    with sqlite3.connect(database) as db:
        db.execute('INSERT INTO user_opaque_identifier VALUES(?,?,?,?)',('openid','',instance.username,instance.subject))
    admin.register_subject(instance)
    assert not commands and admin.subject_registered(instance)


@pytest.mark.parametrize('conflict',['owner','identifier'])
def test_subject_conflicts_never_reassign_identities(subject_admin,conflict):
    admin,instance,database,commands=subject_admin
    row=('openid','',instance.username,'22222222-2222-4222-8222-222222222222') if conflict=='owner' else ('openid','','unrelated',instance.subject)
    with sqlite3.connect(database) as db: db.execute('INSERT INTO user_opaque_identifier VALUES(?,?,?,?)',row)
    with pytest.raises(ValueError,match='mapping differs'): admin.register_subject(instance)
    assert not commands
    with sqlite3.connect(database) as db: assert db.execute('SELECT * FROM user_opaque_identifier').fetchall()==[row]


def test_missing_subject_storage_fails_closed_without_creating_database(subject_admin,monkeypatch,tmp_path):
    admin,instance,_,commands=subject_admin
    missing=tmp_path/'missing.sqlite';monkeypatch.setattr(admin,'AUTH_DATABASE',missing)
    with pytest.raises(RuntimeError,match='Cannot verify'): admin.register_subject(instance)
    assert not missing.exists() and not commands


def test_provider_success_without_mapping_is_not_accepted(subject_admin,monkeypatch):
    admin,instance,_,_=subject_admin
    monkeypatch.setattr(admin,'subprocess',SimpleNamespace(run=lambda *a,**k:SimpleNamespace(returncode=0,stdout=b'',stderr=b'')))
    with pytest.raises(RuntimeError,match='not verified'): admin.register_subject(instance)
    assert not (instance.private_dir/'subject-registered.json').exists()


def test_deployment_renders_from_versioned_templates_without_prepared_directory(monkeypatch):
    monkeypatch.setattr(tenancy,'ROOT',PLUGIN)
    target=tenancy.Instance('fixture','Synthetic',personal().subject,8824)
    rendered=tenancy.deployment_artifacts(target)
    assert target.hostname in rendered['apache'] and '__DOMAIN__' not in rendered['apache']
    assert '8824' in rendered['apache'] and '8825' in rendered['gateway']
    assert str(target.gateway_home) in rendered['gateway']
    assert json.loads((PLUGIN/'deploy/images.lock.json').read_text())['waha_image'] in rendered['gateway']
    assert 'CPUAffinity=0-3' in rendered['gateway']
    assert 'User='+target.service_user in rendered['bridge']


def test_admin_preflights_templates_before_any_mutation(tmp_path,monkeypatch):
    admin=load_script('tenant_admin')
    monkeypatch.setattr(tenancy,'ROOT',tmp_path)
    def mutation(*args,**kwargs): pytest.fail('mutation before template preflight')
    monkeypatch.setattr(admin,'run',mutation)
    monkeypatch.setattr(admin,'install_auth',mutation)
    monkeypatch.setattr(admin,'write_private',mutation)
    for action in (admin.prepare_runtime,admin.enable_existing_link,admin.install_https):
        with pytest.raises(FileNotFoundError): action(personal())


@pytest.mark.skipif(os.name!='posix',reason='POSIX provisioning module uses pwd and Unix account paths')
def test_initial_provisioning_verifies_subject_before_creating_services(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(PLUGIN/'scripts'))
    script=load_script('provision_host')
    monkeypatch.setattr(script,'runtime_admission',lambda project:nullcontext())
    root=tmp_path/'source';(root/'private').mkdir(parents=True)
    (root/'private/identity.json').write_text(json.dumps({'username':personal().username,'subject':personal().subject}))
    shutil.copytree(PLUGIN/'deploy',root/'deploy')
    monkeypatch.setattr(script,'ROOT',root);monkeypatch.setattr(tenancy,'ROOT',root)
    monkeypatch.setattr(script,'CONF',tmp_path/'config')
    monkeypatch.setattr(script,'os',SimpleNamespace(geteuid=lambda:0,umask=lambda _:None))
    calls=[]
    def check_subject(instance):
        calls.append(instance.subject)
        raise ValueError('synthetic mapping conflict')
    monkeypatch.setattr(script,'register_subject',check_subject)
    monkeypatch.setattr(script,'load_host_context',lambda *a:SimpleNamespace(begin_runtime=lambda:None,close=lambda:None))
    monkeypatch.setattr(script,'subprocess',SimpleNamespace(run=lambda *a,**k:pytest.fail('service mutation before subject verification')))
    with pytest.raises(ValueError,match='mapping conflict'): script.main(['--auth-mode','managed-authelia','--host-plan','/synthetic.json','--host-plan-sha256','0'*64])
    assert calls==[personal().subject] and not script.CONF.exists()
    (root/'deploy/whatsapp-waha.container').unlink()
    with pytest.raises(FileNotFoundError): script.main(['--auth-mode','managed-authelia','--host-plan','/synthetic.json','--host-plan-sha256','0'*64])
    assert calls==[personal().subject]


@pytest.mark.skipif(os.name!='posix',reason='POSIX provisioning module uses pwd and Unix account paths')
def test_initial_provisioning_uses_rendered_templates_in_a_synthetic_host(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(PLUGIN/'scripts'))
    script=load_script('provision_host')
    monkeypatch.setattr(script,'runtime_admission',lambda project:nullcontext())
    root=tmp_path/'source';(root/'private').mkdir(parents=True);(root/'scripts').mkdir()
    (root/'private/identity.json').write_text(json.dumps({'username':personal().username,'subject':personal().subject}))
    shutil.copytree(PLUGIN/'deploy',root/'deploy')
    host=tmp_path/'host';(host/'etc/systemd/system').mkdir(parents=True)
    for name in ('subuid','subgid'): (host/'etc'/name).write_text('whatsappbridge:100000:65536\n')
    conf=host/'etc/whatsapp-personal';gateway=host/'var/lib/whatsapp-personal-waha'
    monkeypatch.setattr(script,'ROOT',root);monkeypatch.setattr(tenancy,'ROOT',root)
    monkeypatch.setattr(script,'CONF',conf);monkeypatch.setattr(script,'GATEWAY_HOME',gateway)
    monkeypatch.setattr(tenancy.Instance,'config_dir',property(lambda _:conf))
    monkeypatch.setattr(tenancy.Instance,'gateway_home',property(lambda _:gateway))
    monkeypatch.setattr(tenancy.Instance,'state_dir',property(lambda _:host/'var/lib/whatsapp-personal'))
    monkeypatch.setattr(script,'Path',lambda value:host/str(value).lstrip('/'))
    monkeypatch.setattr(script,'os',SimpleNamespace(geteuid=lambda:0,umask=lambda _:None,chown=lambda *a:None,chmod=os.chmod))
    monkeypatch.setattr(script,'pwd',SimpleNamespace(getpwnam=lambda _:SimpleNamespace(pw_dir=str(gateway),pw_uid=1000,pw_gid=1000)))
    sequence=[]
    monkeypatch.setattr(script,'register_subject',lambda instance:sequence.append('subject'))
    monkeypatch.setattr(script,'load_host_context',lambda *a:SimpleNamespace(begin_runtime=lambda:None,close=lambda:None,
        enroll_runtime=lambda account:sequence.append(['host-qos',account.pw_uid]),
        ensure_https=lambda apache:(sequence.append(['host-https',apache]) or {'qos_frontend':'configuration-bound'})))
    monkeypatch.setattr(script,'initialize_new',lambda settings,uid,gid:sequence.append(('initialized',settings.database,settings.state_identity_file,uid,gid)))
    def command(args,**kwargs):
        sequence.append(args)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(script,'subprocess',SimpleNamespace(run=command))
    # Provisioning delegates ACL construction to the tenant helper. Capture
    # that helper's OS seam as well; this fixture never runs host setfacl.
    monkeypatch.setitem(script.grant_project_access.__globals__,'run',command)
    monkeypatch.setitem(script.grant_project_access.__globals__,'ROOT',root)
    script.main(['--auth-mode','managed-authelia','--host-plan','/synthetic.json','--host-plan-sha256','0'*64])
    assert sequence[0]=='subject'
    config=Settings.load(conf/'config.toml')
    assert config.owner_subject==personal().subject and config.oauth_client_ids==[personal().chatgpt_client]
    assert not config.live_account_enabled
    initialization=('initialized',config.database,conf/'technical-state.json',1000,1000)
    assert initialization in sequence
    assert sequence.index(initialization)<sequence.index(['systemctl','enable','--now','whatsapp-personal.service'])
    assert 'Image=' in (gateway/'.config/containers/systemd/whatsapp-waha.container').read_text()
    assert (host/'etc/systemd/system/whatsapp-personal.service').is_file()
    enrollment=['host-qos',1000]
    assert enrollment in sequence
    assert sequence.index(enrollment)<sequence.index(['loginctl','enable-linger','whatsappbridge'])
    assert any(isinstance(item,list) and item[0]=='host-https' for item in sequence)
    assert not any('resource_priority.py' in str(item) or 'a2ensite' in str(item) for item in sequence)
