"""Capability selection, authorization equivalence and runtime reload; no real services."""
import copy
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from conftest import call
from test_standalone_setup import external, load_script
from test_tenancy import legacy_chatgpt_config
from test_oauth_contract import challenged, grant, headers
from sally_whatsapp.capabilities import capabilities
from sally_whatsapp.config import MCP_SCOPES, Settings
from sally_whatsapp.operations import OPERATIONS, require_action, validate_operation
from sally_whatsapp.server import create_app
from sally_whatsapp.tenancy import Instance, idp_candidate, render_config


def test_full_selection_is_explicit_complete_and_does_not_claim_consent(environment,monkeypatch):
    admin=load_script('tenant_admin',monkeypatch)
    settings=environment[0]
    unchanged,summary=admin.capability_selection(settings,capabilities='custom')
    assert unchanged=={} and not summary['send_enabled']
    updates,summary=admin.capability_selection(settings)
    selected=replace(settings,live_account_enabled=True,**updates)
    assert selected.send_enabled and selected.account_actions_enabled and selected.allow_all_destinations
    assert selected.oauth_allowed_scopes==selected.oauth_consent_scopes==list(MCP_SCOPES)
    assert summary['destination_policy']=='all'
    assert not summary['oauth_consent_verified'] and not summary['whatsapp_connected_verified']
    rows=capabilities(selected,list(MCP_SCOPES))
    assert len(rows)==120
    assert all(row['permission_enabled'] for row in rows if row['capability']!='unsupported_gows')
    assert sum(row['capability']=='unsupported_gows' for row in rows)==5
    candidate=[row for row in rows if row['capability']=='gows_ab_v1']
    assert len(candidate)==8 and all(not row['engine_available'] for row in candidate)
    assert all(row['authorization_rules'] for row in rows)


def test_full_selection_preserves_explicit_allowlist_and_read_only_is_reversible(environment,monkeypatch):
    admin=load_script('tenant_admin',monkeypatch)
    settings=replace(environment[0],send_chat_ids=['fixture@g.us'])
    updates,summary=admin.capability_selection(settings,capabilities='custom',enable_send=True,enable_account_actions=True)
    full=replace(settings,live_account_enabled=True,**updates)
    assert summary['destination_policy']=='allowlist' and full.send_chat_ids==['fixture@g.us']
    assert not full.allow_all_destinations
    updates,summary=admin.capability_selection(full,capabilities='read-only')
    selected=replace(full,**updates)
    assert not selected.send_enabled and not selected.account_actions_enabled
    assert selected.oauth_allowed_scopes==['whatsapp:read','whatsapp:events']
    assert selected.send_chat_ids==full.send_chat_ids
    with pytest.raises(ValueError,match='conflicts'):
        admin.capability_selection(full,capabilities='read-only',enable_send=True)
    with pytest.raises(ValueError,match='local whatsapp:send'):
        admin.capability_selection(replace(settings,oauth_allowed_scopes=['whatsapp:read']),capabilities='custom',enable_send=True)


@pytest.mark.parametrize('scopes',[None,'whatsapp:send',['whatsapp:link'],['whatsapp:read']*2,[{}]])
def test_consent_selection_is_validated(environment,scopes):
    with pytest.raises(ValueError,match='oauth_consent_scopes'):
        replace(environment[0],oauth_consent_scopes=scopes)
    with pytest.raises(ValueError,match='oauth_consent_scopes'):
        replace(environment[0],oauth_allowed_scopes=['whatsapp:read'],oauth_consent_scopes=['whatsapp:send'])


def test_full_consent_challenge_is_one_request_but_never_grants_permissions(environment):
    settings,receiver,gateway,token=environment
    settings=replace(settings,oauth_consent_scopes=list(MCP_SCOPES),live_account_enabled=True,
                     send_enabled=True,allow_all_destinations=True,account_actions_enabled=True)
    app=create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False)
    with TestClient(app) as client:
        client.headers.update(headers(grant(token,['whatsapp:read'])))
        assert challenged(call(client,'check_event_authorization')['result'])==list(MCP_SCOPES)
        catalog=call(client,'get_capabilities')['result']['structuredContent']['operations']
        assert all(not row['permission_enabled'] for row in catalog if not row['readonly'])
        client.headers.update(headers(grant(token,list(MCP_SCOPES))))
        assert call(client,'check_event_authorization')['result']['structuredContent']['authorized']
        assert all(row['scope_granted'] for row in call(client,'get_capabilities')['result']['structuredContent']['operations'])
        client.headers.update(headers(grant(token,list(MCP_SCOPES),sub='other-owner')))
        assert client.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':'tools/list'}).status_code==401
    assert not receiver.requests and not gateway.sent


def test_default_full_profile_executes_supported_actions_through_mcp_with_fake_provider(environment,monkeypatch):
    admin=load_script('tenant_admin',monkeypatch)
    settings,receiver,gateway,token=environment
    selected,summary=admin.capability_selection(settings)
    settings=replace(settings,live_account_enabled=True,**selected)
    assert summary['profile']=='full' and summary['destination_policy']=='all'
    assert settings.send_chat_ids==[]
    requests=[]
    def request(method,path,**kwargs):
        requests.append((method,path,kwargs))
        if method == 'POST' and path == '/api/default/groups':
            return {'id':'120363000000007@g.us'}
        return {'id':'synthetic-provider-result','success':True}
    gateway.request=request
    app=create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False)
    actions=[
        ('profile_set_profile_name',{'body':{'name':'Synthetic Owner'}}),
        ('groups_create_group',{'body':{'name':'Synthetic group','participants':[{'id':'new-contact@c.us'}]}}),
        ('groups_set_subject',{'path':{'id':'new-group@g.us'},'body':{'subject':'Synthetic subject'}}),
        ('chats_edit_message',{'path':{'chatId':'new-group@g.us','messageId':'synthetic-message'},'body':{'text':'Synthetic edit'}}),
        ('chats_read_chat_messages',{'path':{'chatId':'new-group@g.us'}}),
        ('presence_set_presence',{'body':{'chatId':'new-contact@c.us','presence':'typing'}}),
        ('presence_set_presence',{'body':{'presence':'online'}}),
    ]
    with TestClient(app) as client:
        service=app.state.service
        client.headers.update(headers(grant(token,list(MCP_SCOPES))))
        sent=call(client,'send_text',{'chat_id':'never-listed-contact@c.us','text':'Synthetic only',
                                     'idempotency_key':'full-profile-direct-001'})['result']['structuredContent']
        assert sent['state']=='submitted' and sent['state']!='delivered'
        assert gateway.sent==[('never-listed-contact@c.us','Synthetic only')]
        for index,(operation,arguments) in enumerate(actions):
            key=f'full-profile-action-{index:03d}'
            payload={'operation':operation,'arguments':arguments,'idempotency_key':key}
            queued=call(client,'write_whatsapp',payload)['result']['structuredContent']
            assert queued['state']=='queued'
            assert service.process_action()
            status=call(client,'get_send_status',{'idempotency_key':key})['result']['structuredContent']
            assert status['state']=='submitted' and status['state']!='delivered'
            assert call(client,'write_whatsapp',payload)['result']['structuredContent']['state']=='submitted'
            assert not service.process_action()  # Same identity never sends twice.
        assert len(requests)==len(actions)
        assert any(path=='/api/default/groups' for _,path,_ in requests)
        assert requests[3][2]['json']['linkPreview'] is False
        client.headers.update(headers(grant(token,['whatsapp:read'])))
        for index,(operation,arguments) in enumerate(actions):
            denied=call(client,'write_whatsapp',{'operation':operation,'arguments':arguments,
                'idempotency_key':f'full-profile-denied-{index:03d}'})['result']
            assert set(challenged(denied))==set(MCP_SCOPES)
        denied=call(client,'send_text',{'chat_id':'another-new@c.us','text':'Synthetic denied',
                                     'idempotency_key':'full-profile-denied-text'})['result']
        assert set(challenged(denied))==set(MCP_SCOPES)
        assert not service.process_action()
        client.headers.update(headers(grant(token,list(MCP_SCOPES),sub='other-owner')))
        response=client.post('/mcp',json={'jsonrpc':'2.0','id':99,'method':'tools/call',
            'params':{'name':'write_whatsapp','arguments':{'operation':actions[0][0],
                'arguments':actions[0][1],'idempotency_key':'full-profile-alien-001'}}})
        assert response.status_code==401
        assert not service.process_action()
    assert len(requests)==len(actions) and len(gateway.sent)==1 and receiver.requests==[]


@pytest.mark.parametrize('name,arguments',[
    ('messages_start_typing',{'body':{'chatId':'fixture@g.us'}}),
    ('messages_stop_typing',{'body':{'chatId':'fixture@g.us'}}),
    ('presence_set_presence',{'body':{'chatId':'fixture@g.us','presence':'typing'}}),
    ('presence_set_presence',{'body':{'chatId':'fixture@g.us','presence':'recording'}}),
    ('presence_set_presence',{'body':{'chatId':'fixture@g.us','presence':'paused'}}),
    ('messages_send_seen',{'body':{'chatId':'fixture@g.us'}}),
    ('chats_read_chat_messages',{'path':{'chatId':'fixture@g.us'}}),
    ('chats_edit_message',{'path':{'chatId':'fixture@g.us','messageId':'fixture'},'body':{'text':'synthetic'}}),
])
def test_equivalent_chat_effects_share_destination_policy(environment,name,arguments):
    op,args=validate_operation(name,arguments,readonly=False)
    disabled=replace(environment[0],live_account_enabled=True,account_actions_enabled=True)
    for settings in (disabled,replace(disabled,send_enabled=True,send_chat_ids=['other@g.us'])):
        with pytest.raises(ValueError,match='not allowed'): require_action(settings,op,args)
    require_action(replace(disabled,send_enabled=True,send_chat_ids=['fixture@g.us'],account_actions_enabled=False),op,args)


@pytest.mark.parametrize('body',[{'presence':'typing'},{'presence':'recording'},{'presence':'paused'},
    {'presence':'online','chatId':'fixture@g.us'},{'presence':'offline','chatId':'fixture@g.us'}])
def test_presence_cannot_omit_or_mix_destination(body):
    with pytest.raises(ValueError,match='Chat presence'):
        validate_operation('presence_set_presence',{'body':body},readonly=False)


def test_global_presence_keeps_separate_account_policy(environment):
    op,args=validate_operation('presence_set_presence',{'body':{'presence':'online'}},readonly=False)
    settings=replace(environment[0],live_account_enabled=True,account_actions_enabled=True)
    require_action(settings,op,args)
    rows=capabilities(settings,['whatsapp:read','whatsapp:send'],'presence')
    row=next(row for row in rows if row['operation']=='presence_set_presence')
    assert row['destination_policy']=='depends_on_arguments'
    assert not row['permission_enabled']  # Not every branch is authorized.
    assert [rule['permission_enabled'] for rule in row['authorization_rules']]==[False,True]


def test_managed_full_scopes_are_only_expanded_explicitly_and_mfa_is_preserved():
    target,cfg,users,identity=legacy_chatgpt_config()
    oidc=cfg['identity_providers']['oidc']
    oidc['clients'][0]['scopes']=['openid','profile','email','whatsapp:read']
    policy=oidc['authorization_policies'][target.policy]
    assert policy['rules'][0]['policy']=='two_factor'
    ordinary,_=idp_candidate(cfg,users,target,identity)
    assert ordinary['identity_providers']['oidc']['clients'][0]['scopes']==oidc['clients'][0]['scopes']
    full,_=idp_candidate(cfg,users,target,identity,required_mcp_scopes=MCP_SCOPES)
    assert set(MCP_SCOPES)<=set(full['identity_providers']['oidc']['clients'][0]['scopes'])
    assert set(MCP_SCOPES)<=set(full['identity_providers']['oidc']['scopes'])
    assert full['identity_providers']['oidc']['clients'][1]['scopes']==['openid','profile','whatsapp:link']
    assert cfg['identity_providers']['oidc']['clients'][0]['scopes']==oidc['clients'][0]['scopes']
    for alteration in ('one_factor','wrong_owner','implicit_consent'):
        changed=copy.deepcopy(cfg)
        current=changed['identity_providers']['oidc']
        if alteration=='implicit_consent': current['clients'][0]['consent_mode']='implicit'
        elif alteration=='wrong_owner': current['authorization_policies'][target.policy]['rules'][0]['subject']=[['user:other']]
        else: current['authorization_policies'][target.policy]['rules'][0]['policy']='one_factor'
        with pytest.raises(ValueError): idp_candidate(changed,users,target,identity,required_mcp_scopes=MCP_SCOPES)


@pytest.mark.parametrize('initially_active',[False,True])
def test_activation_reloads_process_even_when_previous_disk_flag_was_false(tmp_path,monkeypatch,initially_active):
    admin=load_script('tenant_admin',monkeypatch)
    (tmp_path/'waha.key').write_text('synthetic-key')
    item=SimpleNamespace(config_dir=tmp_path,wrapper=tmp_path/'wrapper',gateway_port=8821,
                         project_root=tmp_path/'project',slug='synthetic',
                         bridge_port=8820,base='synthetic',public_details=lambda:{})
    process={'active':initially_active,'link_enabled':False}
    commands=[]
    def run(argv,**kwargs):
        commands.append(argv)
        if argv==['systemctl','restart','synthetic.service']:
            process.update(active=True,link_enabled=True)
    monkeypatch.setattr(admin,'run',run)
    class Client:
        def __init__(self,**kwargs): pass
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def get(self,url,**kwargs):
            if url=='/api/version': return SimpleNamespace(is_success=True)
            if url=='/api/sessions': return SimpleNamespace(raise_for_status=lambda:None,json=lambda:[{'name':'default','status':'WORKING'}])
            if url=='/healthz': return SimpleNamespace(is_success=True,json=lambda:{'readiness':{'ready':process['active'],'workers':{'portal':process['link_enabled']}}})
            if url=='/connect': return SimpleNamespace(status_code=200 if process['link_enabled'] else 404)
            pytest.fail('Unexpected endpoint '+url)
        def post(self,*args,**kwargs): pytest.fail('Existing WhatsApp session must remain untouched')
    monkeypatch.setattr(admin.httpx,'Client',Client)
    monkeypatch.setattr(admin.time,'sleep',lambda _:pytest.fail('Expected immediate readiness'))
    admin.start_runtime(item,refresh_bridge=True)
    assert process=={'active':True,'link_enabled':True}
    assert ['systemctl','restart','synthetic.service'] in commands



@pytest.mark.parametrize('blocker', ['preparing', 'cancelling', 'recovery_required', 'cancelled', 'restore'])
def test_direct_runtime_activation_obeys_persistent_administrative_fences(tmp_path,monkeypatch,blocker):
    admin=load_script('tenant_admin',monkeypatch)
    item=SimpleNamespace(config_dir=tmp_path,project_root=tmp_path/'project',slug='synthetic')
    if blocker=='restore':
        (tmp_path/'restore-maintenance.json').write_text('{}')
    else:
        directory=item.project_root/'private/provisioning-attempts'
        directory.mkdir(parents=True,mode=0o700)
        gate=directory/'gate-synthetic.json'
        gate.write_text(json.dumps({'state':blocker}))
        gate.chmod(0o600)
    monkeypatch.setattr(admin,'run',lambda *args,**kwargs:pytest.fail('Fenced activation invoked a host command'))
    monkeypatch.setattr(admin.httpx,'Client',lambda *args,**kwargs:pytest.fail('Fenced activation contacted a provider'))
    with pytest.raises(ValueError,match='fenced|reconciliation'):
        admin.start_runtime(item,refresh_bridge=True)


def test_ready_bridge_without_portal_cannot_report_activation_success(monkeypatch):
    admin=load_script('tenant_admin',monkeypatch)
    class Client:
        def __init__(self,**kwargs): pass
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def get(self,url,**kwargs):
            return SimpleNamespace(is_success=True,json=lambda:{'readiness':{'ready':True,'workers':{}}})
    monkeypatch.setattr(admin.httpx,'Client',Client)
    monkeypatch.setattr(admin.time,'sleep',lambda _:None)
    with pytest.raises(RuntimeError,match='activation remains incomplete'):
        admin.wait_bridge_ready(SimpleNamespace(bridge_port=8820))


@pytest.mark.parametrize('slug,port,legacy_file,hash_matches',[
    ('personal',8820,False,True),('personal',8820,True,True),
    ('synthetic-second',8822,False,True),('synthetic-second',8822,False,False)])
def test_managed_full_activation_reuses_registered_identity(tmp_path,monkeypatch,slug,port,legacy_file,hash_matches):
    admin=load_script('tenant_admin',monkeypatch)
    registered,cfg,users,identity=legacy_chatgpt_config(slug,port)
    if not hash_matches: identity['password_hash']='synthetic-mismatched-hash'
    class SyntheticInstance(Instance):
        @property
        def config_dir(self): return tmp_path/'configuration'
        @property
        def private_dir(self): return tmp_path/'tenant'
        @property
        def project_root(self): return tmp_path/'project'
    item=SyntheticInstance(**registered.record())
    item.config_dir.mkdir()
    identity_path=(item.project_root/'private/identity.json' if legacy_file else item.private_dir/'identity.json')
    identity_path.parent.mkdir(parents=True)
    identity_path.write_text(json.dumps(identity))
    original_identity=identity_path.read_bytes()
    endpoints={'authorize_url':item.issuer+'/authorize','token_url':item.issuer+'/token'}
    path=item.config_dir/'config.toml'
    path.write_text(render_config(item,**endpoints,live_enabled=False))
    monkeypatch.setattr(admin,'deployment_artifacts',lambda _: {'apache':'synthetic'})
    monkeypatch.setattr(admin,'verify_existing_config',lambda *a:Settings.load(path))
    monkeypatch.setattr(admin,'discovery_for',lambda _:endpoints)
    monkeypatch.setattr(admin,'register_subject',lambda _:None)
    monkeypatch.setattr(admin,'write_private',lambda p,data,**kwargs:p.write_text(data))
    monkeypatch.setattr(admin,'run',lambda *a,**kw:pytest.fail('No credential generation or real commands'))
    import pwd
    monkeypatch.setattr(pwd,'getpwnam',lambda _:object())
    installed=[]
    def install(actual,loaded,**kwargs):
        assert actual is item and loaded==identity
        # Use the real policy reconciliation, including the secondary tenant's
        # strict password-hash ownership check; only host effects are simulated.
        candidate,updated_users=idp_candidate(cfg,users,actual,loaded,**kwargs)
        assert updated_users==users
        assert set(MCP_SCOPES)<=set(candidate['identity_providers']['oidc']['clients'][0]['scopes'])
        installed.append(candidate)
    monkeypatch.setattr(admin,'install_auth',install)
    starts=[]
    monkeypatch.setattr(admin,'start_runtime',lambda actual,**kwargs:starts.append(kwargs))
    host=SimpleNamespace(enroll_runtime=lambda _:None,ensure_https=lambda _:None)
    if not hash_matches:
        with pytest.raises(ValueError,match='Refuse to adopt'):
            admin.enable_existing_link(item,host=host)
        assert not installed and not starts and not Settings.load(path).live_account_enabled
        assert identity_path.read_bytes()==original_identity
        return
    admin.enable_existing_link(item,host=host)
    updated=Settings.load(path)
    assert updated.send_enabled and updated.allow_all_destinations and updated.account_actions_enabled
    assert updated.oauth_consent_scopes==list(MCP_SCOPES)
    assert starts==[{'refresh_bridge':True}] and len(installed)==1
    assert identity_path.read_bytes()==original_identity


@pytest.mark.parametrize('fault',['missing','wrong_subject','wrong_username','missing_hash','symlink'])
def test_managed_enable_rejects_unregistered_identity_before_effects(tmp_path,monkeypatch,fault):
    admin=load_script('tenant_admin',monkeypatch)
    registered,_,_,identity=legacy_chatgpt_config('synthetic-second',8822)
    class SyntheticInstance(Instance):
        @property
        def config_dir(self): return tmp_path/'configuration'
        @property
        def private_dir(self): return tmp_path/'tenant'
    item=SyntheticInstance(**registered.record())
    item.config_dir.mkdir();item.private_dir.mkdir()
    path=item.config_dir/'config.toml'
    path.write_text(render_config(item,authorize_url=item.issuer+'/authorize',token_url=item.issuer+'/token',live_enabled=False))
    original_config=path.read_bytes()
    if fault=='wrong_subject': identity['subject']='other-owner'
    if fault=='wrong_username': identity['username']='other-user'
    if fault=='missing_hash': identity.pop('password_hash')
    if fault=='symlink':
        target=tmp_path/'other-identity.json';target.write_text(json.dumps(identity))
        (item.private_dir/'identity.json').symlink_to(target)
    elif fault!='missing': (item.private_dir/'identity.json').write_text(json.dumps(identity))
    monkeypatch.setattr(admin,'deployment_artifacts',lambda _: {'apache':'synthetic'})
    monkeypatch.setattr(admin,'verify_existing_config',lambda *a:Settings.load(path))
    def forbidden(*args,**kwargs): pytest.fail('Identity failure must precede credential or host effects')
    for function in ('discovery_for','install_auth','register_subject','write_private','run','start_runtime'):
        monkeypatch.setattr(admin,function,forbidden)
    with pytest.raises(ValueError,match='[Ii]dentity'):
        admin.enable_existing_link(item,host=SimpleNamespace(enroll_runtime=forbidden,ensure_https=forbidden))
    assert path.read_bytes()==original_config
