"""Pinned GOWS forwarding with synthetic source reads and no real WhatsApp actions."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import quote

import pytest
from starlette.testclient import TestClient

from conftest import call, message
from test_linked_device_visibility import event
from test_clearchat_coverage import clear
from test_operation_audit_fixes import generator_source
from sally_whatsapp.operations import OPERATIONS
from sally_whatsapp.server import OperationAction, Service, create_app


CHAT='15550001111@c.us'
OTHER='15550009999@c.us'
GROUP='15550003333@g.us'
LID='15550002222@lid'
SOURCE=f'false_{CHAT}_SOURCE'
KEY='synthetic-forward-0001'  # gitleaks:allow -- synthetic idempotency identifier, not a credential
LIFETIME={'IsViewOnce':False,'IsViewOnceV2':False,'IsViewOnceV2Extension':False,'IsEphemeral':False}


def observed(source=SOURCE,chat=CHAT,**kwargs):
    payload=message(source,chat,timestamp=kwargs.pop('timestamp',1000),**kwargs)['payload']
    return {**payload,'_data':{**LIFETIME,'Message':{'conversation':payload['body']}}}


def action(source=SOURCE, destination=OTHER, key=KEY):
    return OperationAction(operation='messages_forward_message',
        arguments={'body':{'chatId':destination,'messageId':source}}, idempotency_key=key)


def enabled(environment, **changes):
    settings, receiver, gateway, _=environment
    settings=replace(settings,live_account_enabled=True,send_enabled=True,
                     allow_all_destinations=True,**changes)
    gateway.requests=[]
    gateway.observation=observed()
    gateway.before_read=None
    def request(method,path,**kwargs):
        gateway.requests.append((method,path,kwargs))
        if method=='GET':
            if gateway.before_read: gateway.before_read()
            return copy.deepcopy(gateway.observation)
        assert method=='POST' and path=='/api/forwardMessage'
        if gateway.timeout: raise TimeoutError('Synthetic lost response')
        return {'id':f'true_{OTHER}_FORWARDED','body':'never retain provider content'}
    gateway.request=request
    return Service(settings,gateway=gateway,event_transport=receiver),gateway


def posts(gateway):
    return [entry for entry in gateway.requests if entry[0]=='POST']


def test_rejected_forward_retains_verified_view_once_restriction(environment):
    service,gateway=enabled(environment)
    gateway.observation['_data']['IsViewOnce']=True
    with pytest.raises(ValueError,match='temporary'): service.operation(action(),'test-owner')
    assert service.store.message_state(SOURCE)['state']=='view_once'
    gateway.observation=observed()
    with pytest.raises(ValueError,match='removed'): service.operation(action(),'test-owner')
    assert len(gateway.requests)==1 and not posts(gateway)
    assert service.store.search()['messages']==[]


def test_forward_lifetime_evidence_never_attaches_to_wrong_provider_identity(environment):
    service,gateway=enabled(environment)
    gateway.observation=observed(f'false_{OTHER}_SOURCE',OTHER)
    gateway.observation['_data']['IsViewOnce']=True
    with pytest.raises(ValueError,match='identity'): service.operation(action(),'test-owner')
    assert service.store.message_state(SOURCE)['state']=='unknown'


def alter_source(service,kind,source=SOURCE,chat=CHAT):
    if kind=='revoke':
        service.store.ingest({'event':'message.revoked','payload':{'revokedMessageId':source}})
    elif kind=='edit':
        from_me=source.startswith('true_')
        service.store.ingest({'event':'message.edited','payload':{
            'id':f'{str(from_me).lower()}_{chat}_EDIT','editedMessageId':source,'from':chat,
            'to':'self@c.us','fromMe':from_me,'timestamp':1500,'body':'New edited content'}})
    else:
        service.store.ingest(event(kind,chat=chat,raw='SOURCE',
            refs=[('SOURCE',False)] if kind=='ClearChat' else None))


@pytest.mark.parametrize('chat,destination,from_me',[(CHAT,OTHER,False),(GROUP,CHAT,False),(CHAT,GROUP,True)])
def test_forward_revalidates_source_and_sends_once_without_import_or_seen(environment,chat,destination,from_me):
    service,gateway=enabled(environment)
    source=f'{str(from_me).lower()}_{chat}_SOURCE'+('_15550004444@c.us' if chat==GROUP else '')
    gateway.observation=observed(source,chat,from_me=from_me)
    args=action(source,destination)
    assert service.operation(args,'test-owner')['state']=='queued'
    assert service.operation(args,'test-owner')['state']=='queued'  # No repeated GET on retry.
    assert service.process_action()
    assert service.operation(args,'test-owner')['state']=='submitted'
    assert not service.process_action()
    assert [entry[0] for entry in gateway.requests]==['GET','GET','POST']
    for _,path,kwargs in gateway.requests[:2]:
        assert path==f'/api/default/chats/{quote(chat,safe="")}/messages/{quote(source,safe="")}'
        assert kwargs['params']=={'downloadMedia':'false'} and 'json' not in kwargs
        assert kwargs['timeout']==15
    assert posts(gateway)[0][2]['json']=={'chatId':destination,'messageId':source,'session':'default'}
    assert service.store.search()['messages']==[]
    assert not gateway.sent and not environment[1].requests
    assert 'never retain provider content' not in json.dumps(service.store.send_status(KEY))


@pytest.mark.parametrize('kind',['revoke','DeleteForMe','DeleteChat','ClearChat','ClearUnknown'])
@pytest.mark.parametrize('stage',['before_queue','before_worker','during_worker_read'])
def test_removed_or_uncertain_source_never_forwards(environment,kind,stage):
    service,gateway=enabled(environment)
    # The known source time makes a prior DeleteChat an exact exclusion.
    if kind=='DeleteChat': service.store.ingest(message(SOURCE,CHAT,timestamp=1000))
    def remove():
        if kind=='ClearUnknown': service.store.ingest(event('ClearChat',chat=CHAT))
        else: alter_source(service,kind)
    if stage=='before_queue':
        remove()
        with pytest.raises(ValueError,match='removed|visibility'): service.operation(action(),'test-owner')
        assert gateway.requests==[] and service.store.send_status(KEY) is None
        return
    service.operation(action(),'test-owner')
    if stage=='before_worker': remove()
    else: gateway.before_read=remove
    assert service.process_action()
    assert service.store.send_status(KEY)['state']=='failed_before_send'
    assert not posts(gateway)
    assert service.operation(action(),'test-owner')['state']=='failed_before_send'
    assert not service.process_action()


@pytest.mark.parametrize('stage',['before_queue','before_worker'])
@pytest.mark.parametrize('observation',[None,[],{},
    message(f'false_{OTHER}_SOURCE',OTHER,timestamp=1000)['payload'],
    message(f'true_{CHAT}_SOURCE',CHAT,from_me=True,timestamp=1000)['payload'],
    {**message(SOURCE,CHAT,timestamp=1000)['payload'],'fromMe':0},
    {**message(SOURCE,CHAT,timestamp=1000)['payload'],'timestamp':float('nan')}])
def test_wrong_or_malformed_provider_identity_is_not_forwarded(environment,observation,stage):
    service,gateway=enabled(environment)
    if stage=='before_worker': service.operation(action(),'test-owner')
    gateway.observation=observation
    if stage=='before_queue':
        with pytest.raises(ValueError,match='verified'): service.operation(action(),'test-owner')
        assert service.store.send_status(KEY) is None
    else:
        assert service.process_action()
        assert service.store.send_status(KEY)['state']=='failed_before_send'
    assert not posts(gateway)


def test_group_raw_collision_with_other_participant_is_rejected(environment):
    service,gateway=enabled(environment)
    wanted=f'false_{GROUP}_SOURCE_15550004444@c.us'
    collision=f'false_{GROUP}_SOURCE_15550005555@c.us'
    gateway.observation=observed(collision,GROUP)
    with pytest.raises(ValueError,match='identity'): service.operation(action(wanted),'test-owner')
    assert not posts(gateway)


def test_verified_alias_is_accepted_but_alias_removal_during_read_wins(environment):
    service,gateway=enabled(environment)
    alias_source=f'false_{LID}_SOURCE'
    service.store.bind_chat_alias(LID,CHAT)
    assert service.operation(action(alias_source),'test-owner')['state']=='queued'
    gateway.before_read=lambda: alter_source(service,'DeleteForMe',alias_source,LID)
    assert service.process_action()
    assert service.store.send_status(KEY)['state']=='failed_before_send' and not posts(gateway)


def test_alias_binding_during_read_exposes_existing_revocation(environment):
    service,gateway=enabled(environment)
    alias_source=f'false_{LID}_SOURCE'
    gateway.observation=observed(alias_source,LID)
    alter_source(service,'revoke')
    gateway.before_read=lambda: service.store.bind_chat_alias(LID,CHAT)
    with pytest.raises(ValueError,match='removed'): service.operation(action(alias_source),'test-owner')
    assert not posts(gateway)


@pytest.mark.parametrize('stage',['before_queue','during_worker_read','after_action_ready'])
def test_known_edit_cannot_forward_the_old_provider_copy(environment,monkeypatch,stage):
    service,gateway=enabled(environment)
    if stage=='before_queue':
        alter_source(service,'edit')
        with pytest.raises(ValueError,match='latest observed edit'): service.operation(action(),'test-owner')
    else:
        service.operation(action(),'test-owner')
        if stage=='during_worker_read': gateway.before_read=lambda: alter_source(service,'edit')
        else:
            ready=service.store.action_ready
            def changed(key):
                result=ready(key)
                alter_source(service,'edit')
                return result
            monkeypatch.setattr(service.store,'action_ready',changed)
        assert service.process_action()
        assert service.store.send_status(KEY)['state']=='failed_before_send'
    assert not posts(gateway)


def test_provider_current_edit_can_forward_without_archiving_source(environment):
    service,gateway=enabled(environment)
    alter_source(service,'edit')
    gateway.observation['body']='New edited content'
    assert service.operation(action(),'test-owner')['state']=='queued'
    assert service.process_action() and len(posts(gateway))==1
    assert service.store.message(SOURCE) is None


@pytest.mark.parametrize('kind',['DeleteChat','ClearChat'])
@pytest.mark.parametrize('timestamp',[1000,2000])
def test_live_source_after_known_chat_boundary_needs_no_archive(environment,kind,timestamp):
    service,gateway=enabled(environment)
    service.store.ingest(event('DeleteChat',chat=CHAT) if kind=='DeleteChat'
                         else clear(chat=CHAT,through=1200,anchors=()))
    gateway.observation['timestamp']=timestamp
    if timestamp==1000:
        with pytest.raises(ValueError,match='removed|visibility'): service.operation(action(),'test-owner')
        assert not posts(gateway)
    else:
        assert service.operation(action(),'test-owner')['state']=='queued'
        assert service.process_action() and len(posts(gateway))==1
    assert service.store.search()['messages']==[]


@pytest.mark.parametrize('flag',list(LIFETIME)+['missing','malformed'])
@pytest.mark.parametrize('stage',['before_queue','before_worker'])
def test_temporary_or_unverified_lifetime_source_is_never_forwarded(environment,flag,stage):
    service,gateway=enabled(environment)
    if stage=='before_worker': service.operation(action(),'test-owner')
    if flag=='missing': gateway.observation.pop('_data')
    elif flag=='malformed': gateway.observation['_data']['IsViewOnce']='false'
    else: gateway.observation['_data'][flag]=True
    if stage=='before_queue':
        with pytest.raises(ValueError,match='lifetime|temporary'): service.operation(action(),'test-owner')
    else:
        assert service.process_action()
        assert service.store.send_status(KEY)['state']=='failed_before_send'
    assert not posts(gateway)


def test_group_participant_alias_is_verified_without_rewriting_requested_source(environment):
    service,gateway=enabled(environment)
    service.store.bind_chat_alias(LID,CHAT)
    source=f'false_{GROUP}_SOURCE_{LID}'
    gateway.observation=observed(f'false_{GROUP}_SOURCE_{CHAT}',GROUP)
    assert service.operation(action(source),'test-owner')['state']=='queued'
    assert service.process_action()
    assert posts(gateway)[0][2]['json']['messageId']==source


@pytest.mark.parametrize('field',['Message','RawMessage'])
@pytest.mark.parametrize('content',[
    {'extendedTextMessage':{'text':'temporary','contextInfo':{'expiration':86400}}},
    {'imageMessage':{'contextInfo':{'ephemeralSettingTimestamp':1500}}},
    {'documentMessage':{'contextInfo':{'disappearingMode':{'initiator':0}}}},
    {'ephemeralMessage':{'message':{'conversation':'temporary'}}},
    {'viewOnceMessageV2':{'message':{'imageMessage':{'caption':'temporary'}}}},
    {'imageMessage':{'caption':'temporary','viewOnce':True}},
])
def test_raw_content_lifetime_is_checked_even_when_wrapper_flags_are_false(environment,field,content):
    service,gateway=enabled(environment)
    service.operation(action(),'test-owner')
    gateway.observation['_data'][field]=content
    assert service.process_action() and not posts(gateway)
    assert service.store.send_status(KEY)['state']=='failed_before_send'


def test_original_quote_lifetime_does_not_block_non_temporary_source(environment):
    service,gateway=enabled(environment)
    gateway.observation['_data']['Message']={'extendedTextMessage':{'text':'source',
        'contextInfo':{'quotedMessage':{'ephemeralMessage':{'message':{'conversation':'old quote'}}}}}}
    service.operation(action(),'test-owner')
    assert service.process_action() and len(posts(gateway))==1
    assert 'old quote' not in json.dumps(posts(gateway))


@pytest.mark.parametrize('edit_chat',[GROUP,'15550007777@g.us'])
def test_unattributed_group_edit_blocks_only_its_source_conversation(environment,edit_chat):
    service,gateway=enabled(environment)
    source=f'false_{GROUP}_SOURCE_15550004444@c.us'
    gateway.observation=observed(source,GROUP)
    service.store.ingest({'event':'message.edited','payload':{'id':f'false_{edit_chat}_EDIT',
        'editedMessageId':'SOURCE','from':edit_chat,'to':'self@c.us','fromMe':False,
        'timestamp':1500,'body':'new edit without verified participant'}})
    if edit_chat==GROUP:
        with pytest.raises(ValueError,match='ambiguous observed edit'): service.operation(action(source),'test-owner')
        assert not posts(gateway)
    else:
        service.operation(action(source),'test-owner')
        assert service.process_action() and len(posts(gateway))==1


def test_allowed_destination_does_not_require_account_actions(environment):
    service,gateway=enabled(environment)
    service.settings=replace(service.settings,allow_all_destinations=False,send_chat_ids=[OTHER],account_actions_enabled=False)
    assert service.operation(action(),'test-owner')['state']=='queued'
    assert service.process_action() and len(posts(gateway))==1


@pytest.mark.parametrize('stage',['before_queue','before_worker'])
def test_source_read_failure_is_never_an_outbound_attempt(environment,stage):
    service,gateway=enabled(environment)
    if stage=='before_worker': service.operation(action(),'test-owner')
    def unavailable(): raise TimeoutError('Synthetic source read timeout')
    gateway.before_read=unavailable
    if stage=='before_queue':
        with pytest.raises(TimeoutError): service.operation(action(),'test-owner')
    else:
        assert service.process_action()
        assert service.store.send_status(KEY)['state']=='failed_before_send'
    assert not posts(gateway)


def test_raw_id_is_not_a_source_identity(environment):
    service,gateway=enabled(environment)
    with pytest.raises(ValueError,match='complete provider'): service.operation(action('SOURCE'),'test-owner')
    assert not gateway.requests


@pytest.mark.parametrize('changed', [{'send_enabled':False}, {'allow_all_destinations':False,'send_chat_ids':[CHAT]}])
def test_destination_policy_is_checked_before_source_read_and_again_in_worker(environment,changed):
    service,gateway=enabled(environment)
    original=service.settings
    service.settings=replace(original,**changed)
    with pytest.raises(ValueError,match='not allowed'): service.operation(action(),'test-owner')
    assert not gateway.requests
    service.settings=original
    service.operation(action(),'test-owner')
    service.settings=replace(original,**changed)
    assert service.process_action() and not posts(gateway)
    assert service.store.send_status(KEY)['state']=='failed_before_send'


def test_uncertain_forward_is_never_retried_even_after_source_removal(environment):
    service,gateway=enabled(environment)
    service.operation(action(),'test-owner')
    gateway.timeout=True
    assert service.process_action()
    alter_source(service,'revoke')
    assert service.operation(action(),'test-owner')['state']=='uncertain'
    assert not service.process_action() and len(posts(gateway))==1
    with pytest.raises(ValueError,match='another payload'):
        service.operation(action(destination=GROUP),'test-owner')


def test_forward_receipt_tracks_only_new_provider_id_and_matching_destination(environment):
    from test_delivery_receipts import receipt
    service,gateway=enabled(environment)
    service.operation(action(),'test-owner')
    assert service.process_action()
    result=service.store.send_status(KEY)
    assert result['state']=='submitted' and result['delivery']['status']=='not_observed'
    receipt(service.store,3,provider=SOURCE,chat=CHAT)
    assert service.store.send_status(KEY)['delivery']['status']=='not_observed'
    receipt(service.store,2,provider=result['provider_id'],chat=OTHER)
    result=service.store.send_status(KEY)
    assert result['state']=='submitted' and result['delivery']['status']=='observed'
    assert set(result['delivery']['evidence'])=={'delivered'}
    assert len(posts(gateway))==1


def test_forward_mcp_requires_send_scope_and_correct_owner(environment):
    service,gateway=enabled(environment)
    app=create_app(service.settings,gateway=gateway,event_transport=environment[1],start_worker=False)
    with TestClient(app) as client:
        client.headers.update({'Authorization':'Bearer '+environment[3](scope='whatsapp:read'),
                              'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28'})
        assert call(client,'write_whatsapp',action().model_dump())['result']['isError'] is True
        assert not gateway.requests
        client.headers['Authorization']='Bearer '+environment[3](sub='different-owner')
        response=client.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':'tools/call',
            'params':{'name':'write_whatsapp','arguments':action().model_dump()}})
        assert response.status_code==401 and not gateway.requests
        client.headers['Authorization']='Bearer '+environment[3]()
        assert call(client,'write_whatsapp',action().model_dump())['result']['structuredContent']['state']=='queued'
        assert app.state.service.process_action() and len(posts(gateway))==1


def test_generator_preserves_verified_forward_capability(tmp_path):
    source=generator_source()
    source['paths']['/api/forwardMessage']={'post':{'operationId':'ChattingController_forwardMessage',
        'requestBody':{'content':{'application/json':{'schema':{'type':'object','properties':{
            'chatId':{'type':'string'},'id':{'type':'string','description':'Pre-generated message id'},
            'messageId':{'type':'string'},'session':{'type':'string'}},'required':['chatId','messageId','session']}}}}}}
    incoming,target=tmp_path/'openapi.json',tmp_path/'operations.json'
    incoming.write_text(json.dumps(source))
    subprocess.run([sys.executable,str(Path(__file__).parents[1]/'scripts/build_operations.py'),
                    str(incoming),'--output',str(target)],check=True,capture_output=True,text=True)
    assert json.loads(target.read_text())['messages_forward_message']==OPERATIONS['messages_forward_message']
