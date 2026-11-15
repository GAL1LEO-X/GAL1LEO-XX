"""Fresh administrative setup with synthetic domains and an external OIDC provider."""
from pathlib import Path
import tomllib

from sally_whatsapp.tenancy import Instance, render_config


def external(**overrides):
    values = dict(slug='personal', display_name='Example Owner', subject='provider|opaque-owner',
                  bridge_port=8820, public_hostname='messages.example.org',
                  issuer='https://identity.example.net/realms/personal',
                  jwks_url='https://identity.example.net/realms/personal/certs',
                  auth_mode='external-oidc', oauth_client_id='assigned-mcp-client',
                  pairing_client_id='assigned-pairing-client')
    return Instance(**(values | overrides))


def test_fresh_domain_and_external_identity_are_setup_inputs():
    item = external()
    config = tomllib.loads(render_config(item,
        authorize_url=item.issuer+'/authorize', token_url=item.issuer+'/token'))['bridge']
    assert item.public_url == 'https://messages.example.org'
    assert config['issuer'] == item.issuer and config['jwks_url'] == item.jwks_url
    assert config['owner_subject'] == 'provider|opaque-owner'
    assert config['oauth_client_ids'] == ['assigned-mcp-client']
    assert config['link_client_id'] == 'assigned-pairing-client'
    assert config['allowed_hosts'][0] == item.hostname
    assert item.public_details()['callback'] == 'https://chatgpt.com/connector_platform_oauth_redirect'

import argparse
from contextlib import nullcontext
from dataclasses import replace
import importlib.util
import json
import sys
import time
from types import SimpleNamespace
import urllib.error
import zipfile

import jwt
import pytest

from sally_whatsapp import tenancy
from sally_whatsapp.auth import JWTVerifier
from sally_whatsapp.config import Settings

PLUGIN=Path(__file__).resolve().parents[1]


def load_script(name,monkeypatch):
    monkeypatch.syspath_prepend(str(PLUGIN/'scripts'))
    spec=importlib.util.spec_from_file_location('standalone_'+name,PLUGIN/'scripts'/f'{name}.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def arguments(item=None):
    item=item or external()
    return ['--hostname',item.hostname,'--issuer',item.issuer,'--jwks-url',item.effective_jwks_url,
            '--subject',item.subject,'--oauth-client-id',item.chatgpt_client,
            '--link-client-id',item.link_client,'--chatgpt-callback',item.chatgpt_callback]


def discovery(item=None,**changes):
    item=item or external()
    return {'issuer':item.issuer,'jwks_uri':item.effective_jwks_url,
            'authorization_endpoint':item.issuer+'/authorize',
            'token_endpoint':item.issuer+'/token'} | changes


@pytest.mark.parametrize('hostname',['messages.example.org','wa.team.example.test','wa.xn--bcher-kva.example'])
def test_cli_to_config_proxy_certificate_and_portable_export(tmp_path,monkeypatch,hostname):
    admin=load_script('tenant_admin',monkeypatch)
    parser=argparse.ArgumentParser();admin.add_setup_arguments(parser)
    item=admin.setup_instance(parser.parse_args(arguments(external(public_hostname=hostname))),
                              'personal','Example Owner',8820)
    config=tenancy.render_config(item,**tenancy.oidc_endpoints(item,discovery(item)))
    path=tmp_path/'config.toml';path.write_text(config)
    settings=Settings.load(path)
    assert (settings.public_url,settings.issuer,settings.jwks_url,settings.owner_subject)==(
        item.public_url,item.issuer,item.effective_jwks_url,item.subject)
    assert settings.link_authorize_url==item.issuer+'/authorize'
    assert settings.link_client_id==item.link_client
    assert settings.allowed_hosts==[hostname,'127.0.0.1:8820','10.0.2.2:8820']
    assert settings.callback_hosts==['connectors.api.openai.com']
    monkeypatch.setattr(tenancy,'ROOT',PLUGIN)
    apache=tenancy.render_apache(item)
    assert 'ServerName '+hostname in apache
    assert '/etc/letsencrypt/live/'+hostname+'/fullchain.pem' in apache
    assert 'http://127.0.0.1:8820' in apache and '__DOMAIN__' not in apache
    exporter=load_script('export_plugin',monkeypatch)
    output=tmp_path/'plugin.zip';exporter.export(item,output,PLUGIN)
    with zipfile.ZipFile(output) as archive:
        mcp=json.loads(archive.read('mcp.json'))
        assert mcp['mcpServers'][item.base]['url']==item.public_url+'/mcp'
        assert (item.public_url+'/connect').encode() in archive.read('skills/whatsapp-setup/SKILL.md')
        guide=archive.read('CONFIGURATION.md').decode()
        assert item.issuer in guide and item.chatgpt_callback in guide
        assert item.subject not in guide
        assert 'login.sally-browser' not in guide
        assert 'il setup non crea o consegna password' in guide
        assert 'configurazione di un server MCP remoto' in guide
    assert Instance(**item.record())==item


@pytest.mark.parametrize('field,value',[
    ('public_hostname','example.org\nInclude /tmp/x'),('public_hostname','../example.org'),
    ('public_hostname','https://example.org'),('public_hostname','example.org:443'),
    ('public_hostname','127.0.0.1'),('public_hostname','Example.org'),
    ('public_hostname','example.org.'),('public_hostname','*.example.org'),
    ('public_hostname','bücher.example'),('public_hostname','-bad.example'),
    ('issuer','http://identity.example'),('issuer','https://user:pass@identity.example'),
    ('issuer','https://identity.example?token=x'),('issuer','https://identity.example/#x'),
    ('jwks_url','https://identity.example/keys\n'),('jwks_url','file:///tmp/keys'),
    ('subject','owner\nother'),('subject','x'*256),('subject',''),
    ('oauth_client_id','client\nother'),('pairing_client_id','assigned-mcp-client'),
    ('chatgpt_callback','https://chatgpt.com'),('chatgpt_callback','https://client.example/cb#token'),
])
def test_setup_rejects_noncanonical_or_ambiguous_administrative_input(field,value):
    with pytest.raises(ValueError): external(**{field:value})


def test_jwks_can_be_explicitly_on_another_https_origin_and_callback_is_client_owned():
    item=external(jwks_url='https://keys.example.net/custom/rsa.json',
                  chatgpt_callback='https://client.example.com/exact/oauth/callback')
    endpoints=tenancy.oidc_endpoints(item,discovery(item))
    assert endpoints['authorize_url'].startswith(item.issuer)
    assert item.public_details()['callback']=='https://client.example.com/exact/oauth/callback'
    assert not item.public_details()['callback'].startswith(item.public_url)


@pytest.mark.parametrize('change',[
    {'issuer':'https://other.example.net'}, {'jwks_uri':'https://other.example.net/keys'},
    {'authorization_endpoint':'https://other.example.net/authorize'},
    {'token_endpoint':'https://identity.example.net/token?token=secret'},
])
def test_discovery_cannot_rebind_setup_identity_or_pairing_endpoints(change):
    with pytest.raises(ValueError): tenancy.oidc_endpoints(external(),discovery(**change))


def test_configured_issuer_audience_owner_and_client_are_still_enforced(environment):
    settings,_,_,token=environment
    # Keep the fixture's offline RSA key; only configure the resource/identity inputs.
    item=external()
    configured=replace(settings,public_url=item.public_url,issuer=item.issuer,
                       owner_subject=item.subject,oauth_client_ids=[item.chatgpt_client])
    verifier=JWTVerifier(configured)
    claims=dict(iss=item.issuer,aud=item.public_url,sub=item.subject,azp=item.chatgpt_client)
    assert verifier._verify(token(**claims)) is not None
    for key,value in [('iss','https://wrong.example'),('aud','https://wrong.example'),
                      ('sub','another-owner'),('azp',item.link_client)]:
        assert verifier._verify(token(**(claims | {key:value}))) is None


def test_external_auth_never_invokes_local_identity_administration(tmp_path,monkeypatch):
    admin=load_script('tenant_admin',monkeypatch)
    monkeypatch.setattr(admin,'AUTH_CONFIG',tmp_path/'absent-sally')
    monkeypatch.setattr(admin,'AUTH_DATABASE',tmp_path/'absent-sally.sqlite')
    def forbidden(*a,**k): pytest.fail('external identity must not consult/manage local IdP')
    monkeypatch.setattr(admin,'subject_registered',forbidden)
    monkeypatch.setattr(admin,'auth_backup',forbidden)
    monkeypatch.setattr(admin,'write_private',forbidden)
    monkeypatch.setattr(admin,'run',forbidden)
    assert admin.identity_for(external()) is None
    assert admin.install_auth(external()) is None
    assert admin.register_subject(external()) is None
    assert list(tmp_path.iterdir())==[]


def test_external_suspend_and_resume_affect_only_own_runtime(tmp_path,monkeypatch):
    admin=load_script('tenant_admin',monkeypatch)
    item=SimpleNamespace(auth_mode='external-oidc',slug='fixture',base='whatsapp-fixture',
                         state_dir=tmp_path,wrapper=tmp_path/'own-wrapper')
    calls=[]
    monkeypatch.setattr(admin,'run',lambda argv,**kw:calls.append(argv))
    monkeypatch.setattr(admin,'auth_backup',lambda *a:pytest.fail('local IdP touched'))
    monkeypatch.setattr(admin,'suspend_tenant_database',lambda instance:calls.append(['suspend-database',instance.slug]))
    admin.change_enabled(item,False);admin.change_enabled(item,True)
    assert any('disable' in c for c in calls) and any('enable' in c for c in calls)
    assert all('sally' not in str(c) for c in calls)
    assert list(tmp_path.iterdir())==[]


def test_invalid_discovery_fails_before_account_or_runtime_mutations(monkeypatch):
    admin=load_script('tenant_admin',monkeypatch)
    monkeypatch.setattr(admin,'deployment_artifacts',lambda _: {})
    monkeypatch.setattr(admin,'httpx',SimpleNamespace(get=lambda *a,**k:SimpleNamespace(
        raise_for_status=lambda:None,json=lambda:discovery(issuer='https://wrong.example'))))
    monkeypatch.setattr(admin,'run',lambda *a,**k:pytest.fail('mutation before OIDC preflight'))
    import pwd
    monkeypatch.setattr(pwd,'getpwnam',lambda *a:pytest.fail('account access before OIDC preflight'))
    with pytest.raises(ValueError,match='issuer differs'):
        admin.prepare_runtime(external(),host=object())


def test_fresh_provisioning_cli_has_no_private_identity_or_local_idp_dependency(tmp_path,monkeypatch):
    script=load_script('provision_host',monkeypatch)
    monkeypatch.setattr(script,'ROOT',tmp_path/'source')
    monkeypatch.setattr(script,'CONF',tmp_path/'configuration')
    monkeypatch.setattr(script,'os',SimpleNamespace(geteuid=lambda:0))
    monkeypatch.setattr(script,'runtime_admission',lambda _:nullcontext())
    monkeypatch.setattr(script,'deployment_artifacts',lambda _: {'apache':'synthetic'})
    monkeypatch.setattr(script,'discovery_for',lambda item:tenancy.oidc_endpoints(item,discovery(item)))
    records={};calls=[]
    monkeypatch.setattr(script,'write_private',lambda path,data:records.update({str(path):json.loads(data)}))
    host=SimpleNamespace(begin_runtime=lambda:calls.append('begin'),close=lambda:calls.append('close'))
    monkeypatch.setattr(script,'load_host_context',lambda *a:host)
    def provision(item,artifacts,cfg,actual_host):
        settings=tomllib.loads(cfg)['bridge']
        assert item.auth_mode=='external-oidc' and actual_host is host
        assert settings['public_url']==external().public_url
        assert not any(settings[k] for k in ('live_account_enabled','send_enabled','link_enabled','account_actions_enabled'))
        calls.append('provision')
    monkeypatch.setattr(script,'provision',provision)
    script.main(['--host-plan','/approved.json','--host-plan-sha256','0'*64,*arguments()])
    assert calls==['begin','provision','close']
    record=records[str(script.ROOT/'private/tenants.json')]['instances']['personal']
    assert Instance(**record['spec']).public_url==external().public_url
    assert record['phase']=='existing' and not list(tmp_path.iterdir())


def test_registered_setup_cannot_be_silently_changed(monkeypatch):
    admin=load_script('tenant_admin',monkeypatch)
    parser=argparse.ArgumentParser();admin.add_setup_arguments(parser)
    args=parser.parse_args(arguments(external(public_hostname='other.example.org')))
    with pytest.raises(ValueError,match='differs'): admin.verify_setup_arguments(external(),args)


def test_release_health_uses_exact_configured_public_origin_without_suffix_policy(tmp_path,monkeypatch):
    release=load_script('github_release',monkeypatch)
    item=external()
    path=tmp_path/'config.toml'
    path.write_text('[bridge]\npublic_url='+json.dumps(item.public_url)+'\nissuer='+json.dumps(item.issuer)+'\n')
    (tmp_path/'waha.key').write_text('synthetic')
    calls=[]
    def get_json(url,headers=None):
        calls.append(url)
        if url.endswith('/healthz'): return {'process':'running','version':'0.5.0'}
        if url.endswith('/oauth-protected-resource'):
            return {'resource':item.public_url,'authorization_servers':[item.issuer]}
        return {'status':'STOPPED'}
    monkeypatch.setattr(release,'active',lambda _:True)
    monkeypatch.setattr(release,'get_json',get_json)
    def challenge(request,**kw):
        assert request.full_url==item.public_url+'/mcp'
        raise urllib.error.HTTPError(request.full_url,401,'synthetic',{},None)
    monkeypatch.setattr(release.urllib.request,'urlopen',challenge)
    assert release.health({'slug':item.slug,'unit':'fixture.service','port':8820,'config':path},'0.5.0')=='STOPPED'
    assert item.public_url+'/.well-known/oauth-protected-resource' in calls
    path.write_text(path.read_text().replace(item.public_url,item.public_url+'/other'))
    with pytest.raises(release.ReleaseError,match='configured public'): release.health({'slug':item.slug,'unit':'fixture.service','port':8820,'config':path},'0.5.0')


@pytest.mark.parametrize('profile,explicit',[('custom',False),('custom',True),('full',True),('read-only',False)])
def test_activation_defaults_full_and_supports_deliberate_reduced_choices(tmp_path,monkeypatch,profile,explicit):
    admin=load_script('tenant_admin',monkeypatch)
    class SyntheticInstance(Instance):
        @property
        def config_dir(self): return tmp_path
    item=SyntheticInstance(**external().record())
    config=tenancy.render_config(item,**tenancy.oidc_endpoints(item,discovery(item)),live_enabled=False)
    path=tmp_path/'config.toml';path.write_text(config)
    settings=Settings.load(path)
    monkeypatch.setattr(admin,'deployment_artifacts',lambda _: {'apache':'synthetic'})
    monkeypatch.setattr(admin,'verify_existing_config',lambda *a:settings)
    monkeypatch.setattr(admin,'discovery_for',lambda i:tenancy.oidc_endpoints(i,discovery(i)))
    import pwd
    monkeypatch.setattr(pwd,'getpwnam',lambda _:object())
    monkeypatch.setattr(admin,'write_private',lambda p,s,**kw:p.write_text(s))
    starts=[]
    monkeypatch.setattr(admin,'start_runtime',lambda i,**kwargs:starts.append((i,kwargs)))
    monkeypatch.setattr(admin,'run',lambda *a,**kw:pytest.fail('bootstrap runtime must take explicit startup path'))
    host=SimpleNamespace(enroll_runtime=lambda _:None,ensure_https=lambda _:None)
    options={'enable_send':explicit,'allow_all_destinations':explicit,'enable_account_actions':explicit} if profile=='custom' else {}
    if profile!='full': options['capabilities']=profile
    admin.enable_existing_link(item,host=host,**options)
    updated=Settings.load(path)
    assert updated.live_account_enabled and updated.link_enabled
    assert updated.send_enabled==updated.allow_all_destinations==updated.account_actions_enabled==explicit
    assert updated.oauth_client_ids==settings.oauth_client_ids
    assert starts==[(item,{'refresh_bridge':True})]


def test_send_opt_in_without_destination_policy_fails_before_host_effects(tmp_path,monkeypatch):
    admin=load_script('tenant_admin',monkeypatch)
    item=external()
    config=tmp_path/'config.toml'
    config.write_text(tenancy.render_config(item,**tenancy.oidc_endpoints(item,discovery(item)),live_enabled=False))
    monkeypatch.setattr(admin,'deployment_artifacts',lambda _: {})
    monkeypatch.setattr(admin,'verify_existing_config',lambda *a:Settings.load(config))
    monkeypatch.setattr(admin,'discovery_for',lambda *a:pytest.fail('invalid capability input before discovery'))
    with pytest.raises(ValueError,match='chat allowlist'):
        admin.enable_existing_link(item,host=object(),enable_send=True,capabilities='custom')


def test_receiver_uses_registered_authentication_mode_for_backup_validation(tmp_path,monkeypatch):
    release=load_script('github_release',monkeypatch)
    source=tmp_path/'project';(source/'private').mkdir(parents=True)
    registry=source/'private/tenants.json'
    registry.write_text(json.dumps({'format':1,'instances':{'personal':{'spec':external().record()}}}))
    assert release.instances(source)[0]['auth_mode']=='external-oidc'
    invalid=external().record()|{'auth_mode':'missing-provider'}
    registry.write_text(json.dumps({'instances':{'personal':{'spec':invalid}}}))
    with pytest.raises(release.ReleaseError,match='authentication mode'): release.instances(source)
    backup=tmp_path/'backups'/'snapshot';backup.mkdir(parents=True)
    monkeypatch.setattr(release,'BACKUPS',backup.parent)
    observed=[]
    monkeypatch.setattr(release,'validate_snapshot',lambda *a,**kw:observed.append((a,kw)))
    output=json.dumps({'user':'personal','complete':True,'backup':str(backup)})
    assert release.verify_backups(output,['personal'],auth_modes={'personal':'external-oidc'})==[str(backup)]
    assert observed==[((backup,'personal'),{'auth_mode':'external-oidc'})]
    with pytest.raises(release.ReleaseError,match='authentication modes'):
        release.verify_backups(output,['personal'],auth_modes={})


def test_link_setup_retry_after_gateway_failure_preserves_working_session(tmp_path,monkeypatch):
    admin=load_script('tenant_admin',monkeypatch)
    class SyntheticInstance(Instance):
        @property
        def config_dir(self): return tmp_path
    item=SyntheticInstance(**external().record())
    path=tmp_path/'config.toml'
    path.write_text(tenancy.render_config(item,**tenancy.oidc_endpoints(item,discovery(item)),live_enabled=False))
    (tmp_path/'waha.key').write_text('synthetic-private-key')
    monkeypatch.setattr(admin,'deployment_artifacts',lambda _: {'apache':'synthetic'})
    monkeypatch.setattr(admin,'verify_existing_config',lambda *a:Settings.load(path))
    monkeypatch.setattr(admin,'discovery_for',lambda i:tenancy.oidc_endpoints(i,discovery(i)))
    import pwd
    monkeypatch.setattr(pwd,'getpwnam',lambda _:object())
    monkeypatch.setattr(admin,'write_private',lambda p,s,**kw:p.write_text(s))
    commands=[];gets=[];failed=[False]
    monkeypatch.setattr(admin,'run',lambda argv,**kw:commands.append(argv))
    class Client:
        def __init__(self,**kwargs): pass
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def get(self,url,**kwargs):
            gets.append(url)
            if url=='/api/version': return SimpleNamespace(is_success=True)
            if not failed[0]:
                failed[0]=True
                raise admin.httpx.ConnectError('synthetic gateway reply lost')
            return SimpleNamespace(raise_for_status=lambda:None,json=lambda:[{'name':'default','status':'WORKING'}])
        def post(self,*args,**kwargs): pytest.fail('must not recreate, restart, logout or modify existing WORKING session')
    monkeypatch.setattr(admin.httpx,'Client',Client)
    monkeypatch.setattr(admin,'wait_bridge_ready',lambda _:None)
    host=SimpleNamespace(enroll_runtime=lambda _:None,ensure_https=lambda _:None)
    with pytest.raises(admin.httpx.ConnectError):
        admin.enable_existing_link(item,host=host,enable_send=True,allow_all_destinations=True,enable_account_actions=True)
    # Configuration was published before the failed request; retry must not
    # mistake that flag for evidence that gateway/session startup completed.
    assert Settings.load(path).live_account_enabled
    admin.enable_existing_link(item,host=host,enable_send=True,allow_all_destinations=True,enable_account_actions=True)
    assert gets.count('/api/sessions')==2
    assert sum('whatsapp-waha.service' in c for c in commands)==2
    assert commands[-1]==['systemctl','restart','whatsapp-personal.service']


def test_enable_linking_does_not_resume_a_suspended_registry_account(tmp_path,monkeypatch):
    admin=load_script('tenant_admin',monkeypatch)
    monkeypatch.setattr(admin,'os',SimpleNamespace(geteuid=lambda:0,umask=lambda _:None))
    monkeypatch.setattr(admin,'admit_runtime',lambda:nullcontext())
    monkeypatch.setattr(admin,'registry',lambda:{'format':1,'instances':{
        'personal':{'spec':external().record(),'phase':'ready','enabled':False}}})
    monkeypatch.setattr(admin,'deployment_artifacts',lambda *a:pytest.fail('suspended account before effects'))
    with pytest.raises(ValueError,match='suspended'):
        admin.main(['enable-linking','--user','personal','--apply'])
