from dataclasses import replace
import copy
import json
from pathlib import Path
import secrets
import time
import tomllib
import uuid

from cryptography.fernet import Fernet
import pytest
from starlette.testclient import TestClient

from conftest import attachment_payload, install_attachment_readback, call,message,rpc,Receiver,FakeGateway
from sally_whatsapp.config import Settings
from sally_whatsapp.server import create_app,OperationAction
from sally_whatsapp.tenancy import Instance,idp_candidate,render_config


def instance(slug='sample-user',port=8822): return Instance(slug,'Sample User',str(uuid.uuid4()),port)


@pytest.mark.parametrize('slug',['../other','Upper','x','--root','root/escape','x'*30,'two--users'])
def test_instance_names_cannot_escape_runtime_paths(slug):
    with pytest.raises(ValueError): instance(slug)


def test_new_instance_config_separates_every_sensitive_resource(tmp_path):
    first,second=instance(),instance('additional',8824)
    configs=[]
    for item in (first,second):
        config=render_config(item,authorize_url='https://identity.example.invalid/api/oidc/authorization',token_url='https://identity.example.invalid/api/oidc/token')
        path=tmp_path/(item.slug+'.toml');path.write_text(config,encoding='utf-8')
        assert Settings.load(str(path)).owner_subject==item.subject
        configs.append(tomllib.loads(config)['bridge'])
    for key in ('database','owner_subject','encryption_key_file','webhook_secret_file','waha_key_file','public_url','waha_url','media_gateway_origin','link_client_id','oauth_client_ids','listen_port'):
        assert configs[0][key]!=configs[1][key]
    assert first.service_user!=second.service_user
    assert first.state_dir!=second.state_dir
    assert first.gateway_home!=second.gateway_home
    assert configs[0]['send_enabled'] and configs[0]['account_actions_enabled']
    assert configs[0]['oauth_consent_scopes']==['whatsapp:read','whatsapp:events','whatsapp:send']


def test_auth_update_is_additive_and_same_user_replay_is_idempotent():
    target=instance()
    cfg={'unrelated':{'preserved':True},'identity_providers':{'oidc':{'jwks':[{'key':'existing-secret'}],
        'clients':[{'client_id':'unrelated','redirect_uris':['https://existing.example/callback']}],
        'authorization_policies':{'unrelated':{'default_policy':'deny'}},'scopes':{'whatsapp:read':{'claims':[]}}}}}
    users={'users':{'existing':{'password':'preserved-hash','groups':['existing']}}}
    identity={'username':target.username,'subject':target.subject,'password_hash':'new-synthetic-hash'}
    old_cfg,old_users=copy.deepcopy(cfg),copy.deepcopy(users)
    new_cfg,new_users=idp_candidate(cfg,users,target,identity)
    assert cfg==old_cfg and users==old_users
    assert new_cfg['identity_providers']['oidc']['clients'][0]==cfg['identity_providers']['oidc']['clients'][0]
    assert new_users['users']['existing']==users['users']['existing']
    assert new_users['users'][target.username]['groups']==[target.base]
    clients=new_cfg['identity_providers']['oidc']['clients'][1:]
    assert clients[1]['scopes']==['openid','profile','whatsapp:link']
    assert clients[0]['audience']==clients[1]['audience']==[target.public_url]
    assert idp_candidate(new_cfg,new_users,target,identity)==(new_cfg,new_users)
    hostile=copy.deepcopy(new_cfg)
    hostile['identity_providers']['oidc']['clients'][1]['audience']=['https://another.example']
    with pytest.raises(ValueError): idp_candidate(hostile,new_users,target,identity)


@pytest.mark.parametrize('slug,port',[('personal',8820),('sample-user',8822)])
def test_chatgpt_clients_allow_oidc_email_without_expanding_link_permissions(slug,port):
    target=instance(slug,port)
    cfg={'identity_providers':{'oidc':{'authorization_policies':{},'scopes':{},'clients':[]}}}
    identity={'username':target.username,'subject':target.subject,'password_hash':'synthetic-hash'}
    result,_=idp_candidate(cfg,{'users':{}},target,identity)
    oidc=result['identity_providers']['oidc']
    chatgpt,link=oidc['clients']
    # ChatGPT requests the OIDC identity scopes in addition to the MCP scopes.
    assert chatgpt['scopes']==['openid','profile','email','offline_access',
                              'whatsapp:read','whatsapp:events','whatsapp:send']
    assert link['scopes']==['openid','profile','whatsapp:link']
    assert 'email' not in oidc['scopes']  # Built-in OIDC scope, not a custom MCP permission.


def legacy_chatgpt_config(slug='personal',port=8820):
    target=instance(slug,port)
    cfg={'identity_providers':{'oidc':{'authorization_policies':{},'scopes':{},'clients':[]}}}
    identity={'username':target.username,'subject':target.subject,'password_hash':'synthetic-hash'}
    cfg,users=idp_candidate(cfg,{'users':{}},target,identity)
    client=cfg['identity_providers']['oidc']['clients'][0]
    client['scopes']=['openid','profile','offline_access','whatsapp:read',
                      'whatsapp:events','whatsapp:send','custom:retained']
    client['redirect_uris'].append('https://chatgpt.com/fixture-additional-callback')
    return target,cfg,users,identity


@pytest.mark.parametrize('slug,port',[('personal',8820),('sample-user',8822)])
def test_existing_chatgpt_client_gains_only_email_and_replay_is_idempotent(slug,port):
    target,cfg,users,identity=legacy_chatgpt_config(slug,port)
    clients=cfg['identity_providers']['oidc']['clients']
    clients.append({'client_id':'whatsapp-other-chatgpt','scopes':['openid','profile']})
    original,original_users=copy.deepcopy(cfg),copy.deepcopy(users)
    expected=copy.deepcopy(cfg)
    expected['identity_providers']['oidc']['clients'][0]['scopes'].append('email')
    result,updated_users=idp_candidate(cfg,users,target,identity)
    assert (cfg,users)==(original,original_users)
    assert (result,updated_users)==(expected,users)
    assert idp_candidate(result,updated_users,target,identity)==(result,updated_users)


@pytest.mark.parametrize('scopes',[None,'openid profile',{},[],['openid',None],['openid','']])
def test_invalid_existing_chatgpt_scopes_fail_without_mutation(scopes):
    target,cfg,users,identity=legacy_chatgpt_config()
    cfg['identity_providers']['oidc']['clients'][0]['scopes']=scopes
    original=copy.deepcopy(cfg)
    with pytest.raises(ValueError,match='scopes'):
        idp_candidate(cfg,users,target,identity)
    assert cfg==original


def test_export_contains_only_the_selected_users_public_configuration(tmp_path):
    import importlib.util
    import zipfile
    source=Path(__file__).resolve().parents[1]
    spec=importlib.util.spec_from_file_location('export_plugin',source/'scripts/export_plugin.py')
    exporter=importlib.util.module_from_spec(spec);spec.loader.exec_module(exporter)
    target=instance();output=tmp_path/'sample-user.zip'
    exporter.export(target,output,source)
    with zipfile.ZipFile(output) as archive:
        assert set(archive.namelist())=={
            'plugin.json','mcp.json','assets/whatsapp-gpt.png','CONFIGURATION.md',
            'LICENSE','NOTICE','THIRD_PARTY_NOTICES.md',
            'skills/whatsapp-setup/SKILL.md','skills/whatsapp-use/SKILL.md',
            'skills/whatsapp-transcription/SKILL.md',
            'skills/whatsapp-use/references/reading.md',
            'skills/whatsapp-use/references/actions-and-events.md'}
        mcp=json.loads(archive.read('mcp.json'))
        assert mcp['mcpServers']=={target.base:{'type':'streamable-http','url':target.public_url+'/mcp'}}
        skill=archive.read('skills/whatsapp-setup/SKILL.md').decode()
        assert target.public_url+'/connect' in skill and 'https://whatsapp.example.invalid' not in skill
        assert target.subject.encode() not in b''.join(archive.read(name) for name in archive.namelist())
    with pytest.raises(FileExistsError): exporter.export(target,output,source)


def test_three_isolated_instances_reject_cross_user_tokens_files_and_webhooks(environment,tmp_path):
    base,_,_,token=environment
    apps=[];clients=[];gateways=[];transfers=[]
    try:
        for index in range(3):
            folder=tmp_path/('tenant'+str(index));folder.mkdir()
            enc=folder/'encryption.key';enc.write_bytes(Fernet.generate_key())
            hook=folder/'webhook.key';hook.write_text(secrets.token_hex(32))
            url='https://user'+str(index)+'.example'
            settings=replace(base,database=folder/'archive.sqlite',encryption_key_file=enc,webhook_secret_file=hook,
                             owner_subject='owner'+str(index),public_url=url,allowed_hosts=['user'+str(index)+'.example'],
                             live_account_enabled=True,send_enabled=True,allow_all_destinations=True,
                             oauth_client_ids=['client'+str(index)],profile_name='WhatsApp '+str(index))
            gateway=FakeGateway();gateway.requests=[]
            def request(method,path,_gateway=gateway,**kwargs):
                _gateway.requests.append((method,path,kwargs));return {'id':'provider-synthetic'}
            gateway.request=request
            app=create_app(settings,gateway=gateway,event_transport=Receiver(),start_worker=False)
            client=TestClient(app,base_url=url);client.__enter__()
            client.headers.update({'Authorization':'Bearer '+token(sub=settings.owner_subject,aud=url,azp='client'+str(index)),
                                   'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28'})
            identifier='false_group-1@g.us_SAMEID'
            envelope=message(identifier,text='private-'+str(index))
            payload=attachment_payload(identifier,'group-1@g.us',gateway.media_bytes)
            payload['body']=envelope['payload']['body']
            envelope['payload']=payload
            install_attachment_readback(gateway,payload)
            app.state.service.store.ingest(envelope)
            job=app.state.service.media.enqueue(settings.owner_subject,{'kind':'gateway','message_id':identifier,'chat_id':'group-1@g.us','media':payload['media']})
            app.state.service.media.process_one()
            transfers.append(app.state.service.media.status(job['id'],settings.owner_subject))
            apps.append(app);clients.append(client);gateways.append(gateway)
        profiles=[call(client,'get_profile')['result']['structuredContent'] for client in clients]
        assert len({p['id'] for p in profiles})==3
        for index,client in enumerate(clients):
            service=apps[index].state.service
            assert call(client,'get_message',{'message_id':'false_group-1@g.us_SAMEID'})['result']['structuredContent']['message']['body']=='private-'+str(index)
            other=(index+1)%3
            original=client.headers['Authorization']
            client.headers['Authorization']=clients[other].headers['Authorization']
            assert client.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':'tools/list'}).status_code==401
            # Even a correctly signed token for this audience cannot select another owner.
            client.headers['Authorization']='Bearer '+token(sub='owner'+str(other),aud=service.settings.public_url,azp='client'+str(index))
            assert client.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':'tools/list'}).status_code==401
            client.headers['Authorization']=original
            alien_grant=transfers[other]['download_url'].split('/files/')[1]
            assert client.get('/files/'+alien_grant).status_code==404
            with pytest.raises(ValueError): service.media.status(transfers[other]['id'],service.settings.owner_subject)
            import hmac
            body=json.dumps(message('cross-webhook')).encode()
            signature=hmac.digest(apps[other].state.service.webhook_key,body,'sha512').hex()
            assert client.post('/webhooks/waha',content=body,headers={'X-Webhook-Hmac-Algorithm':'sha512','X-Webhook-Hmac':signature}).status_code==401
            args=OperationAction(operation='messages_send_text',arguments={'body':{'chatId':'synthetic@g.us','text':'tenant '+str(index)}},idempotency_key='same-key-isolated-0001')  # gitleaks:allow -- synthetic idempotency key, not a credential
            service.operation(args,service.settings.owner_subject)
            assert service.process_action()
            assert len(gateways[index].requests)==1
            assert gateways[index].requests[0][2]['json']['text']=='tenant '+str(index)
    finally:
        for client in clients: client.__exit__(None,None,None)
