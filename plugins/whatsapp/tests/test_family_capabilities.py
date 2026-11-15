"""Application API parity with pinned WAHA/GOWS; every provider is synthetic."""
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys

import httpx
import pytest
from starlette.testclient import TestClient

from conftest import call, message
from test_standalone_setup import load_script
from test_oauth_contract import headers, grant, challenged
from test_operation_audit_fixes import generator_source
from sally_whatsapp.config import MCP_SCOPES
from sally_whatsapp.gateway import GatewayUnavailable, Waha
from sally_whatsapp.media import copy_bounded
from sally_whatsapp.operations import OPERATIONS, validate_operation
from sally_whatsapp.server import create_app


GROUP='199999999@g.us'
CONTACT='199999998@c.us'
PARTICIPANTS={'participants':[{'id':CONTACT},{'id':'199999997@lid'}]}
ADDITIONS={
    'groups_set_member_share_history_mode','groups_get_member_share_history_mode',
    'chats_post_chats_overview','sessions_fetch_message_capping','sessions_fetch_reachout_timelock'}


def family_openapi_source():
    """Minimal OpenAPI transcription of pinned controllers/DTOs, not a server dump.

    WAHA 90ba445: groups.controller.ts:350-385/groups.dto.ts:34-37,
    chats.controller.ts:82-98/chats.dto.ts:263-305,
    sessions.controller.ts:104-135. Includes excluded session operations to
    ensure the added read family cannot accidentally expose admin lifecycle.
    """
    source=generator_source()
    schemas=source['components']['schemas']
    schemas.update({
        'SettingsMemberShareHistoryMode':{'type':'object','properties':{
            'membersCanShareHistory':{'type':'boolean','default':True}},'required':['membersCanShareHistory']},
        'GetChatsOverviewParams':{'type':'object','properties':{
            'merge':{'type':'boolean','default':True},'limit':{'type':'number','default':20},'offset':{'type':'number'}}},
        'OverviewFilter':{'type':'object','properties':{'ids':{'type':'array','items':{'type':'string'},'description':'Filter by chat ids'}}},
        'OverviewBodyRequest':{'type':'object','properties':{
            'pagination':{'$ref':'#/components/schemas/GetChatsOverviewParams'},
            'filter':{'$ref':'#/components/schemas/OverviewFilter'}},'required':['pagination']},
    })
    session={'name':'session','in':'path','required':True,'schema':{'type':'string'}}
    group={'name':'id','in':'path','required':True,'schema':{'type':'string'}}
    def endpoint(controller,action,summary,parameters,body=None):
        return {'operationId':controller+'_'+action,'summary':summary,'parameters':parameters,
                **({'requestBody':{'content':{'application/json':{'schema':{'$ref':'#/components/schemas/'+body}}}}} if body else {})}
    source['paths']={
        '/api/{session}/groups/{id}/settings/security/member-share-history-mode':{
            'get':endpoint('GroupsController','getMemberShareHistoryMode',
                'Get settings - members can send message history to new members',[session,group]),
            'put':endpoint('GroupsController','setMemberShareHistoryMode',
                'Update settings - members can send message history to new members',[session,group],'SettingsMemberShareHistoryMode')},
        '/api/{session}/chats/overview':{'post':endpoint('ChatsController','postChatsOverview',
            'Get chats overview. Use POST if you have too many "ids" params - GET can limit it',[session],'OverviewBodyRequest')},
        '/api/sessions/{session}/capping':{'get':endpoint('SessionsController','fetchMessageCapping',
            'Fetch the account new-chat message capping (per-cycle quota)',[session])},
        '/api/sessions/{session}/timelock':{'get':endpoint('SessionsController','fetchReachoutTimelock',
            'Fetch the account reachout timelock state',[session])},
        '/api/sessions/{session}/start':{'post':endpoint('SessionsController','start','Start session',[session])},
        '/api/sessions/{session}/logout':{'post':endpoint('SessionsController','logout','Logout session',[session])},
        '/api/sessions':{'get':endpoint('SessionsController','list','List all sessions',[])},
        '/api/sessions/{session}':{'get':endpoint('SessionsController','fetchMessageCapping','Unexpected route',[session])},
    }
    return source


def test_generator_preserves_added_family_contracts_without_admin_lifecycle(tmp_path):
    source=tmp_path/'openapi.json'
    target=tmp_path/'catalog.json'
    source.write_text(json.dumps(family_openapi_source()))
    result=subprocess.run([sys.executable,str(Path(__file__).parents[1]/'scripts/build_operations.py'),
                           str(source),'--output',str(target)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    regenerated=json.loads(target.read_text())
    assert set(regenerated)==ADDITIONS
    for name,operation in regenerated.items():
        assert operation==OPERATIONS[name]


def test_generator_keeps_location_bounds_and_pinned_label_selector_contract(tmp_path):
    source=generator_source()
    source['components']['schemas'].update({
        'MessageLocation':{'type':'object','properties':{
            'chatId':{'type':'string'},'latitude':{'type':'number'},'longitude':{'type':'number'},
            'title':{'type':'string'},'session':{'type':'string'}},'required':['chatId','latitude','longitude','title']},
        'LabelBody':{'type':'object','properties':{
            'name':{'type':'string'},'colorHex':{'type':'string'},'color':{'type':'number'}},'required':['name']}})
    source['paths']={
        '/api/sendLocation':{'post':{'operationId':'ChattingController_sendLocation','requestBody':{
            'content':{'application/json':{'schema':{'$ref':'#/components/schemas/MessageLocation'}}}}}},
        '/api/{session}/labels':{'post':{'operationId':'LabelsController_create','requestBody':{
            'content':{'application/json':{'schema':{'$ref':'#/components/schemas/LabelBody'}}}}}},
        '/api/{session}/labels/{labelId}':{'put':{'operationId':'LabelsController_update','requestBody':{
            'content':{'application/json':{'schema':{'$ref':'#/components/schemas/LabelBody'}}}}}},
    }
    input_file,output_file=tmp_path/'openapi.json',tmp_path/'catalog.json'
    input_file.write_text(json.dumps(source))
    result=subprocess.run([sys.executable,str(Path(__file__).parents[1]/'scripts/build_operations.py'),
                           str(input_file),'--output',str(output_file)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    regenerated=json.loads(output_file.read_text())
    location=regenerated['messages_send_location']['schema']['properties']['body']['properties']
    assert location['latitude']=={'type':'number','minimum':-90,'maximum':90}
    assert location['longitude']=={'type':'number','minimum':-180,'maximum':180}
    for name in ('labels_create','labels_update'):
        body=regenerated[name]['schema']['properties']['body']
        assert body['oneOf']==[{'required':['color']},{'required':['colorHex']}]
        assert body['properties']['colorHex']['enum']==OPERATIONS[name]['schema']['properties']['body']['properties']['colorHex']['enum']
        assert len(body['properties']['colorHex']['enum'])==20


@pytest.mark.parametrize('operation,arguments',[
    ('groups_set_member_share_history_mode',{'path':{'id':GROUP},'body':{}}),
    ('groups_set_member_share_history_mode',{'path':{'id':GROUP},'body':{'membersCanShareHistory':'false'}}),
    ('groups_get_member_share_history_mode',{'path':{'id':GROUP,'session':'other-owner'}}),
    ('chats_post_chats_overview',{'body':{}}),
    ('chats_post_chats_overview',{'body':{'pagination':{'limit':101}}}),
    ('chats_post_chats_overview',{'body':{'pagination':{'offset':-1}}}),
    ('chats_post_chats_overview',{'body':{'pagination':{},'filter':{'ids':[123]}}}),
    ('chats_post_chats_overview',{'body':{'pagination':{},'session':'other-owner'}}),
])
def test_added_families_reject_missing_or_invalid_arguments(operation,arguments):
    with pytest.raises(ValueError,match='Invalid operation arguments'):
        validate_operation(operation,arguments,readonly=operation!='groups_set_member_share_history_mode')


@pytest.fixture
def full_family_client(environment,monkeypatch):
    settings,receiver,_,token=environment
    updates,_=load_script('tenant_admin',monkeypatch).capability_selection(settings)
    settings=replace(settings,live_account_enabled=True,**updates)
    gateway=Waha(settings)
    gateway.client.close()
    requests=[]
    response={'value':{'success':True}}
    def handle(request):
        requests.append(request)
        return httpx.Response(response.get('status',200),json=response['value'])
    gateway.client=httpx.Client(base_url=settings.waha_url,transport=httpx.MockTransport(handle))
    gateway.attachment_to_file=lambda media,target,maximum:copy_bounded(iter([b'synthetic-image']),target,maximum)
    app=create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False)
    with TestClient(app) as client:
        client.headers.update(headers(grant(token,list(MCP_SCOPES))))
        yield app.state.service,client,requests,response,token
    assert not receiver.requests


# Literal API routes and bodies come from the pinned controllers/DTOs, rather
# than deriving expected requests from the production catalog under test.
GROUP_WRITES=[
    ('groups_create_group',{}, {'name':'Synthetic group',**PARTICIPANTS},'POST',''),
    ('groups_join_group',{}, {'code':'https://chat.whatsapp.com/SYNTHETIC'},'POST','/join'),
    ('groups_refresh_groups',{}, {},'POST','/refresh'),
    ('groups_leave_group',{'id':GROUP},{},'POST','/'+GROUP+'/leave'),
    ('groups_set_description',{'id':GROUP},{'description':'Synthetic description'},'PUT','/'+GROUP+'/description'),
    ('groups_set_subject',{'id':GROUP},{'subject':'Synthetic subject'},'PUT','/'+GROUP+'/subject'),
    ('groups_set_info_admin_only',{'id':GROUP},{'adminsOnly':True},'PUT','/'+GROUP+'/settings/security/info-admin-only'),
    ('groups_set_messages_admin_only',{'id':GROUP},{'adminsOnly':False},'PUT','/'+GROUP+'/settings/security/messages-admin-only'),
    ('groups_set_member_add_mode',{'id':GROUP},{'membersCanAddNewMember':True},'PUT','/'+GROUP+'/settings/security/member-add-mode'),
    ('groups_set_member_share_history_mode',{'id':GROUP},{'membersCanShareHistory':False},'PUT','/'+GROUP+'/settings/security/member-share-history-mode'),
    ('groups_set_membership_approval_mode',{'id':GROUP},{'newMembersApprovalRequired':True},'PUT','/'+GROUP+'/settings/security/membership-approval'),
    ('groups_approve_group_join_requests',{'id':GROUP},PARTICIPANTS,'POST','/'+GROUP+'/participants/join-requests/approve'),
    ('groups_reject_group_join_requests',{'id':GROUP},PARTICIPANTS,'POST','/'+GROUP+'/participants/join-requests/reject'),
    ('groups_revoke_invite_code',{'id':GROUP},{},'POST','/'+GROUP+'/invite-code/revoke'),
    ('groups_get_invite_code',{'id':GROUP},{},'GET','/'+GROUP+'/invite-code'),
    ('groups_add_participants',{'id':GROUP},PARTICIPANTS,'POST','/'+GROUP+'/participants/add'),
    ('groups_remove_participants',{'id':GROUP},PARTICIPANTS,'POST','/'+GROUP+'/participants/remove'),
    ('groups_promote_to_admin',{'id':GROUP},PARTICIPANTS,'POST','/'+GROUP+'/admin/promote'),
    ('groups_demote_to_admin',{'id':GROUP},PARTICIPANTS,'POST','/'+GROUP+'/admin/demote'),
    ('groups_delete_picture',{'id':GROUP},{},'DELETE','/'+GROUP+'/picture'),
]


@pytest.mark.parametrize('operation,path,body,method,suffix',GROUP_WRITES,ids=[row[0] for row in GROUP_WRITES])
def test_full_group_actions_pass_mcp_queue_and_pinned_http_route(full_family_client,operation,path,body,method,suffix):
    service,client,requests,response,token=full_family_client
    assert service.settings.allow_all_destinations and service.settings.send_chat_ids==[]
    payload={'operation':operation,'arguments':{'path':path,'body':body},'idempotency_key':'family-group-action-0001'}
    client.headers.update(headers(grant(token,['whatsapp:read'])))
    assert set(challenged(call(client,'write_whatsapp',payload)['result']))==set(MCP_SCOPES)
    assert requests==[] and not service.process_action()
    client.headers.update(headers(grant(token,list(MCP_SCOPES))))
    if 'invite_code' in operation: response['value']='SYNTHETIC-INVITE-CODE'
    if operation=='groups_create_group': response['value']={'JID':GROUP,'Name':'Synthetic group'}
    if operation=='groups_join_group': response['value']=GROUP
    if operation in ('groups_approve_group_join_requests','groups_reject_group_join_requests'):
        response['value']=[{'requesterId':CONTACT,'success':True}]
    queued=call(client,'write_whatsapp',payload)['result']
    assert not queued.get('isError') and queued['structuredContent']['state']=='queued'
    assert requests==[] and service.process_action()
    assert len(requests)==1
    actual=requests[0]
    assert actual.method==method and actual.url.path=='/api/default/groups'+suffix
    assert (json.loads(actual.content) if actual.content else {})==body
    status=call(client,'get_send_status',{'idempotency_key':payload['idempotency_key']})['result']['structuredContent']
    assert status['state']=='submitted'
    if 'invite_code' in operation: assert status['result']=='SYNTHETIC-INVITE-CODE'
    assert call(client,'write_whatsapp',payload)['result']['structuredContent']['state']=='submitted'
    assert not service.process_action() and len(requests)==1
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM history_jobs').fetchone()[0]==0


@pytest.mark.parametrize('operation,suffix,result',[
    ('groups_get_group_participants','/participants/v2',[{'id':CONTACT,'pn':CONTACT,'role':'admin'},
                                                     {'id':'199999997@lid','role':'participant'}]),
    ('groups_get_group_join_requests','/participants/join-requests',[{'requesterId':CONTACT,'parentGroupId':GROUP,
                                                                   'requestMethod':'linked_group_join','timestamp':123}]),
    ('groups_get_member_share_history_mode','/settings/security/member-share-history-mode',{'membersCanShareHistory':True}),
    ('groups_get_member_add_mode','/settings/security/member-add-mode',{'membersCanAddNewMember':True}),
    ('groups_get_info_admin_only','/settings/security/info-admin-only',{'adminsOnly':True}),
    ('groups_get_messages_admin_only','/settings/security/messages-admin-only',{'adminsOnly':False}),
    ('groups_get_membership_approval_mode','/settings/security/membership-approval',{'newMembersApprovalRequired':True}),
])
def test_group_reads_preserve_roles_requests_and_settings_without_send_scope(full_family_client,operation,suffix,result):
    service,client,requests,response,token=full_family_client
    client.headers.update(headers(grant(token,['whatsapp:read'])))
    response['value']=result
    actual=call(client,'read_whatsapp',{'operation':operation,'arguments':{'path':{'id':GROUP}}})['result']
    projected = actual['structuredContent']
    assert projected['result'] == result
    if operation == 'groups_get_member_add_mode':
        assert projected['freshness'] == {'state': 'unverified', 'may_be_stale_after_mutation': True,
                                          'refresh_operation': 'groups_refresh_groups'}
    else:
        assert projected == {'result': result}
    assert requests[0].method=='GET' and requests[0].url.path=='/api/default/groups/'+GROUP+suffix
    assert not service.process_action()


@pytest.mark.parametrize('operation,arguments,method,path',[
    ('contacts_put',{'path':{'chatId':CONTACT},'body':{'firstName':'Synthetic','lastName':'Contact'}},'PUT','/api/default/contacts/'+CONTACT),
    ('profile_set_profile_name',{'body':{'name':'Synthetic Owner'}},'PUT','/api/default/profile/name'),
    ('profile_set_profile_status',{'body':{'status':'Synthetic about'}},'PUT','/api/default/profile/status'),
    ('profile_delete_profile_picture',{},'DELETE','/api/default/profile/picture'),
    ('calendar_send_event',{'body':{'chatId':GROUP,'event':{'name':'Synthetic event','description':'Synthetic',
        'startTime':2000000000,'endTime':2000003600,'location':{'name':'Synthetic place'},'extraGuestsAllowed':True}}},'POST','/api/default/events'),
])
def test_full_contact_profile_and_calendar_fields_reach_provider(full_family_client,operation,arguments,method,path):
    service,client,requests,response,_=full_family_client
    response['value']={'id':'synthetic-sent-id','success':True}
    payload={'operation':operation,'arguments':arguments,'idempotency_key':'family-other-action-0001'}
    assert call(client,'write_whatsapp',payload)['result']['structuredContent']['state']=='queued'
    assert service.process_action()
    assert requests[0].method==method and requests[0].url.path==path
    body=json.loads(requests[0].content) if requests[0].content else {}
    expected=arguments.get('body',{})
    if operation.startswith('messages_'): expected={**expected,'session':'default'}
    assert body==expected
    assert call(client,'get_send_status',{'idempotency_key':payload['idempotency_key']})['result']['structuredContent']['state']=='submitted'


@pytest.mark.parametrize('operation,path',[
    ('profile_set_profile_picture','/api/default/profile/picture'),
    ('groups_set_picture','/api/default/groups/'+GROUP+'/picture')])
def test_full_group_profile_photos_use_ready_owned_transfer(full_family_client,operation,path):
    service,client,requests,_,_=full_family_client
    from conftest import ready_external_media
    job=ready_external_media(service,name='synthetic.png',mimetype='image/png')
    payload={'operation':operation,'arguments':{'path':{'id':GROUP}} if operation.startswith('groups') else {},
             'transfer_id':job['id'],'idempotency_key':'family-photo-action-0001'}
    assert call(client,'send_media',payload)['result']['structuredContent']['state']=='queued'
    assert service.process_action()
    assert requests[0].method=='PUT' and requests[0].url.path==path
    body=json.loads(requests[0].content)
    assert body['file']['mimetype']=='image/png' and '/files/' in body['file']['url']


def test_batch_overview_post_is_readonly_and_retains_revocation_projection(full_family_client):
    service,client,requests,response,token=full_family_client
    deleted='false_'+GROUP+'_SYNTHETIC'
    service.store.ingest(message(deleted,chat=GROUP,text='Synthetic revoked'))
    service.store.ingest({'id':'synthetic-revoke','event':'message.revoked','payload':{'revokedMessageId':deleted}})
    response['value']=[{'id':GROUP,'name':'Synthetic group','lastMessage':{'id':deleted,'body':'Synthetic revoked'}},
                       {'id':CONTACT,'lastMessage':{'id':'synthetic-visible','body':'Synthetic visible'}}]
    client.headers.update(headers(grant(token,['whatsapp:read'])))
    ids=[GROUP,CONTACT,*[str(300000+i)+'@c.us' for i in range(300)]]
    body={'pagination':{'limit':100,'offset':0,'merge':True},'filter':{'ids':ids}}
    actual=call(client,'read_whatsapp',{'operation':'chats_post_chats_overview','arguments':{'body':body}})['result']
    assert not actual.get('isError')
    assert actual['structuredContent']['source']=='live_gateway'
    assert 'Synthetic revoked' not in json.dumps(actual) and 'Synthetic visible' in json.dumps(actual)
    assert requests[0].method=='POST' and requests[0].url.path=='/api/default/chats/overview'
    assert json.loads(requests[0].content)==body and requests[0].url.query==b''
    assert not service.process_action()


def test_added_group_setting_cannot_cross_owner_or_be_read_as_action(full_family_client):
    service,client,requests,_,token=full_family_client
    args={'operation':'groups_set_member_share_history_mode','arguments':{'path':{'id':GROUP},'body':{'membersCanShareHistory':True}},
          'idempotency_key':'family-isolation-0001'}  # gitleaks:allow -- synthetic idempotency identifier, not a credential
    client.headers.update(headers(grant(token,list(MCP_SCOPES),sub='other-owner')))
    response=client.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':'tools/call',
        'params':{'name':'write_whatsapp','arguments':args}})
    assert response.status_code==401
    client.headers.update(headers(grant(token,list(MCP_SCOPES))))
    assert call(client,'read_whatsapp',{k:v for k,v in args.items() if k!='idempotency_key'})['result']['isError']
    assert requests==[] and not service.process_action()


@pytest.mark.parametrize('path,message',[
    ('/api/default/chats/overview','WAHA read request failed'),
    ('/api/default/channels/search/by-view','WAHA read request failed'),
    ('/api/default/channels/search/by-text','WAHA read request failed'),
    ('/api/default/groups','outbound outcome may be uncertain'),
])
def test_readonly_post_errors_do_not_claim_uncertain_outbound_send(full_family_client,path,message):
    service,_,requests,response,_=full_family_client
    response['status']=503
    response['value']={'error':'synthetic upstream failure'}
    with pytest.raises(GatewayUnavailable,match=message):
        service.gateway.request('POST',path,json={})
    assert len(requests)==1
