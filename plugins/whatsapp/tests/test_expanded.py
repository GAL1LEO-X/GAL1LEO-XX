from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import time
from urllib.parse import urlsplit

import httpx
import pytest
from starlette.testclient import TestClient

from conftest import attachment_payload, call, message, ready_external_media, rpc, subscribe
from sally_whatsapp.gateway import Waha
from sally_whatsapp.history_sync import HistorySync
from sally_whatsapp.media import Media,copy_bounded,download_public
from sally_whatsapp.operations import OPERATIONS,validate_operation,execute
from sally_whatsapp.server import Service,OperationAction,MediaAction,create_app
from sally_whatsapp.store import Store,canonical


def enabled(environment,*,actions=False):
    settings,receiver,gateway,_=environment
    settings=replace(settings,live_account_enabled=True,send_enabled=True,allow_all_destinations=True,
                     account_actions_enabled=actions)
    gateway.requests=[]
    def request(method,path,**kwargs):
        gateway.requests.append((method,path,kwargs))
        if gateway.timeout: raise TimeoutError()
        if method=='POST' and path=='/api/default/groups':
            return {'JID':'199999999@g.us','Name':'Synthetic group'}
        return {'id':'synthetic-provider-result','_data':{'secret':'never return'},'value':True}
    gateway.request=request
    return Service(settings,gateway=gateway,event_transport=receiver),gateway


def test_native_file_input_contract(app_client):
    _,client=app_client
    tools=rpc(client,'tools/list')['result']['tools']
    tool=next(t for t in tools if t['name']=='prepare_file')
    assert tool['_meta']['openai/fileParams']==['file']
    schema=tool['inputSchema']['$defs']['OpenAIFile']
    assert set(schema['required'])=={'download_url','file_id'}
    assert set(schema['properties'])=={'download_url','file_id','mime_type','file_name'}
    assert all(p['type']=='string' for p in schema['properties'].values())


@pytest.mark.parametrize('method', ['server/discover', 'initialize'])
def test_icon_valid_and_available_without_account_data(app_client, method):
    _,client=app_client
    response=client.get('/assets/whatsapp-gpt.png')
    assert response.status_code==200
    assert response.headers['content-type']=='image/png'
    assert response.content[:8]==b'\x89PNG\r\n\x1a\n'
    assert len(response.content)<5*1024*1024
    assert response.content[12:16] == b'IHDR'
    width, height = struct.unpack('>II', response.content[16:24])
    if method == 'server/discover':
        from mcp_types import SERVER_INFO_META_KEY
        metadata = rpc(client, method)['result']['_meta'][SERVER_INFO_META_KEY]
    else:
        initialized = client.post('/mcp', headers={'MCP-Protocol-Version': '2025-11-25', 'mcp-method': method},
            json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': {
                'protocolVersion': '2025-11-25', 'capabilities': {},
                'clientInfo': {'name': 'synthetic-icon-check', 'version': '1'}}})
        assert initialized.status_code == 200
        metadata = initialized.json()['result']['serverInfo']
    icon = metadata['icons'][0]
    assert icon['sizes'] == [f'{width}x{height}']
    assert icon['mimeType'] == response.headers['content-type']
    assert urlsplit(icon['src']).path == '/assets/whatsapp-gpt.png'


def test_only_application_catalog_no_admin_escape():
    assert len(OPERATIONS)==120
    diagnostic_reads={'sessions_fetch_message_capping':'/api/sessions/{session}/capping',
                      'sessions_fetch_reachout_timelock':'/api/sessions/{session}/timelock'}
    for name,op in OPERATIONS.items():
        if name in diagnostic_reads:
            assert op['path']==diagnostic_reads[name] and op['method']=='GET' and op['readonly']
            assert op['inject_session']==['path']
        else:
            assert not any(s in op['path'] for s in ('/api/keys','/api/server','/api/apps','/auth/','/api/sessions'))
    with pytest.raises(ValueError):
        validate_operation('server_stop',{},readonly=False)
    with pytest.raises(ValueError):
        validate_operation('groups_get_group',{'path':{'id':'../../sessions/default'}},readonly=True)
    with pytest.raises(ValueError):
        validate_operation('groups_get_group',{'path':{'id':'one@g.us'},'query':{'session':'other'}},readonly=True)


def test_groups_have_validated_participants_and_fixed_session(environment):
    service,gateway=enabled(environment,actions=True)
    args=OperationAction(operation='groups_create_group',arguments={'body':{'name':'Synthetic group','participants':[{'id':'123@c.us'}]}},idempotency_key='test-groups-create-0001')
    assert service.operation(args,'test-owner')['state']=='queued'
    service.process_action()
    assert gateway.requests[0][1]=='/api/default/groups'
    assert gateway.requests[0][2]['json']['participants']==[{'id':'123@c.us'}]
    result=service.store.send_status(args.idempotency_key)
    assert result['state']=='submitted'
    assert '_data' not in result['result']
    service.operation(args,'test-owner')
    assert service.process_action() is False
    assert len(gateway.requests)==1
    with pytest.raises(ValueError):
        service.operation(args.model_copy(update={'arguments':{'body':{'name':'bad','participants':[{'phone':'123'}]}}}),'test-owner')


def test_send_enabled_all_destinations_without_enabling_group_changes(environment):
    service,gateway=enabled(environment)
    args=OperationAction(operation='messages_send_text',arguments={'body':{'chatId':'new-contact@c.us','text':'Synthetic'}},idempotency_key='all-destination-0001')
    assert service.operation(args,'test-owner')['state']=='queued'
    service.process_action()
    assert gateway.requests[0][2]['json']['chatId']=='new-contact@c.us'
    with pytest.raises(ValueError,match='await authorization'):
        service.operation(OperationAction(operation='groups_create_group',arguments={'body':{'name':'x','participants':[]}},idempotency_key='unauthorized-group-0001'),'test-owner')


def test_action_race_restarts_and_uncertainty_no_duplicate(environment):
    service,gateway=enabled(environment)
    args=OperationAction(operation='messages_send_text',arguments={'body':{'chatId':'group@g.us','text':'Synthetic parallel action'}},idempotency_key='parallel-text-0001')
    with ThreadPoolExecutor(max_workers=6) as pool:
        results=list(pool.map(lambda _:service.operation(args,'test-owner'),range(6)))
    assert all(r['state']=='queued' for r in results)
    restored=Service(service.settings,gateway=gateway,event_transport=environment[1])
    gateway.timeout=True
    restored.process_action()
    assert restored.store.send_status(args.idempotency_key)['state']=='uncertain'
    assert restored.operation(args,'test-owner')['state']=='uncertain'
    assert restored.process_action() is False
    assert len(gateway.requests)==1
    assert Service(service.settings,gateway=gateway,event_transport=environment[1]).process_action() is False


def test_permission_revocation_before_worker_stops_queued_action(environment):
    service,gateway=enabled(environment)
    args=OperationAction(operation='messages_send_text',arguments={'body':{'chatId':'group@g.us','text':'test'}},idempotency_key='revoke-before-send-0001')
    service.operation(args,'test-owner')
    restored=Service(replace(service.settings,send_enabled=False),gateway=gateway,event_transport=environment[1])
    restored.process_action()
    assert restored.store.send_status(args.idempotency_key)['state']=='failed_before_send'
    assert not gateway.requests


def test_reject_raw_file_url_and_known_unsupported_operation():
    with pytest.raises(ValueError):
        validate_operation('messages_send_file',{'body':{'chatId':'group@g.us','file':{'url':'http://127.0.0.1'}}},readonly=False,transfer='a')
    with pytest.raises(ValueError,match='not supported'):
        validate_operation('chats_clear_messages',{'path':{'chatId':'x@g.us'}},readonly=False)
    # Archive is now an additive A/B operation. It still fails closed without
    # a successful provider compatibility probe, before any execution.
    with pytest.raises(ValueError,match='qualified GOWS A/B provider'):
        validate_operation('chats_archive_chat',{'path':{'chatId':'x@g.us'}},readonly=False)


def test_media_pipeline_above_old_limit_and_expired_grant(environment):
    settings,receiver,gateway,token=environment
    gateway.media_bytes=b'SYNTHETIC\n'*(400000)
    app=create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False)
    with TestClient(app) as client:
        client.headers.update({'Authorization':'Bearer '+token(),'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28'})
        identifier='false_group-1@g.us_LARGESYNTHETIC'
        event=message(identifier)
        event['payload']=attachment_payload(identifier,'group-1@g.us',gateway.media_bytes,
                                            name='report.txt',mimetype='text/plain')
        gateway.request=lambda *args,**kwargs: event['payload']
        app.state.service.store.ingest(event)
        queued=call(client,'get_attachment',{'message_id':identifier})['result']['structuredContent']
        app.state.service.media.process_one()
        ready=call(client,'get_transfer_status',{'transfer_id':queued['id']})['result']['structuredContent']
        assert ready['size']>1024*1024 and ready['state']=='ready'
        assert ready['sha256']==hashlib.sha256(gateway.media_bytes).hexdigest()
        client.headers.pop('Authorization')
        response=client.get(ready['download_url'])
        assert response.status_code==200 and response.content==gateway.media_bytes
        assert response.headers['cache-control']=='private, no-store'
        assert client.get(ready['download_url']+'tamper').status_code==404
        with app.state.service.store.db() as db:
            db.execute('UPDATE media_jobs SET expires=0 WHERE id=?',(queued['id'],))
        assert client.get(ready['download_url']).status_code==404
        app.state.service.media.clean()
        assert not app.state.service.media.path(queued['id']).exists()


def test_stream_full_512_mib_without_buffering(tmp_path):
    chunk=b'x'*(1024*1024)
    target=tmp_path/'large-synthetic.bin'
    total,digest=copy_bounded((chunk for _ in range(512)),target,512*1024*1024,str(512*1024*1024))
    assert total==target.stat().st_size==536870912
    assert len(digest)==64
    target.unlink()


@pytest.mark.parametrize('chunks,header',[(iter([b'a'*9,b'b'*9]),None),(iter([b'abc']),'8'),(iter([b'abc']),'100')])
def test_transfer_bound_and_truncation_remove_partial_file(tmp_path,chunks,header):
    target=tmp_path/'partial'
    with pytest.raises(ValueError): copy_bounded(chunks,target,10,header)
    assert not target.exists()


@pytest.mark.parametrize('url',['http://example.com/a','https://user:secret@example.com/file','https://example.com:8821/file','https://127.0.0.1/file','https://169.254.169.254/latest/meta-data'])
def test_external_download_blocks_private_sources_and_credentials(tmp_path,url):
    with pytest.raises(ValueError): download_public(url,tmp_path/'blocked',1024)
    assert not (tmp_path/'blocked').exists()


def test_source_url_is_encrypted_and_transfer_owner_isolated(environment):
    service,_=enabled(environment)
    url='https://files.example/private?token=synthetic-secret'
    job=service.media.enqueue('test-owner',{'kind':'external','file_id':'file-synthetic','download_url':url},'../file.pdf')
    with service.store.db() as db:
        raw=db.execute('SELECT source FROM media_jobs WHERE id=?',(job['id'],)).fetchone()[0]
    assert url.encode() not in raw
    assert 'synthetic-secret' not in canonical(job)
    with pytest.raises(ValueError,match='not found'): service.media.status(job['id'],'someone-else')
    refreshed=service.media.enqueue('test-owner',{'kind':'external','file_id':'file-synthetic','download_url':'https://files.example/new-token'},'../file.pdf')
    assert refreshed['id']==job['id']


def test_ready_media_send_only_internal_scoped_url_and_idempotency(environment):
    service,gateway=enabled(environment)
    job=ready_external_media(service,name='file.pdf',mimetype='application/pdf')
    args=MediaAction(operation='messages_send_file',arguments={'body':{'chatId':'group@g.us','caption':'test'}},transfer_id=job['id'],idempotency_key='file-send-unique-0001')
    assert service.operation(args,'test-owner',transfer_id=job['id'])['state']=='queued'
    service.process_action()
    sent=gateway.requests[0][2]['json']
    assert sent['file']['url'].startswith('http://10.0.2.2:8820/files/')
    assert 'data' not in sent['file'] and 'download_url' not in sent['file']
    assert service.store.send_status(args.idempotency_key)['state']=='submitted'
    with service.store.db() as db: db.execute('UPDATE media_jobs SET expires=0')
    assert service.operation(args,'test-owner',transfer_id=job['id'])['state']=='submitted'
    assert service.process_action() is False


def test_lazy_gateway_media_recovery(environment):
    service,gateway=enabled(environment)
    seen=[]
    identifier='false_group@g.us_ONE'
    observed=attachment_payload(identifier,'group@g.us',gateway.media_bytes,name='audio.ogg',
                                mimetype='audio/ogg',kind='audioMessage')
    def get_message(method,path,**kwargs):
        seen.append(kwargs['params']['downloadMedia'])
        return observed
    gateway.request=get_message
    job=service.media.enqueue('test-owner',{'kind':'gateway','media':{'has_media':True},'chat_id':'group@g.us','message_id':identifier})
    service.media.process_one()
    ready=service.media.status(job['id'],'test-owner')
    assert ready['state']=='ready' and ready['filename']=='audio.ogg'
    assert seen==['false','true']


def test_history_all_chats_restart_no_events_and_full_page_resume(environment):
    service,gateway=enabled(environment)
    gateway.history_chats=lambda offset:[{'id':'group-1@g.us'},{'id':'group-2@g.us'}] if offset==0 else []
    fetched=[]
    def messages(chat,since,until,offset,limit=100):
        fetched.append((chat,offset))
        count=100 if offset==0 else 3
        return [message(chat+'-'+str(offset+i),chat=chat,timestamp=100,text='old synthetic')['payload'] for i in range(count)]
    gateway.messages=messages
    job=service.history.start('test-owner','full-history-0001',until=200)
    service.history.process_one()
    service.history.process_one()
    restored=Service(service.settings,gateway=gateway,event_transport=environment[1])
    for _ in range(5): restored.history.process_one()
    result=restored.history.status(job['id'],'test-owner')
    assert result['state']=='completed' and result['messages_inserted']==206 and result['completed_chats']==2
    assert result['history_complete'] is False and result['available_source_exhausted'] is True
    assert fetched==[('group-1@g.us',0),('group-1@g.us',100),('group-2@g.us',0),('group-2@g.us',100)]
    assert restored.store.state()['deliveries']=={}
    assert restored.history.start('test-owner','full-history-0001',until=200)['id']==job['id']
    with pytest.raises(ValueError): restored.history.start('test-owner','full-history-0001',until=201)


def test_history_failure_pause_cancel_and_owner_isolation(environment):
    service,gateway=enabled(environment)
    def fail(*args,**kwargs): raise RuntimeError('secret provider detail')
    gateway.messages=fail
    job=service.history.start('test-owner','recover-history-0001',['group-1@g.us'])
    service.history.process_one()
    assert service.history.status(job['id'],'test-owner')['state']=='failed'
    assert 'secret' not in canonical(service.history.status(job['id'],'test-owner'))
    service.history.control(job['id'],'test-owner','resume')
    service.history.control(job['id'],'test-owner','pause')
    assert service.history.process_one() is False
    service.history.control(job['id'],'test-owner','cancel')
    with pytest.raises(ValueError): service.history.control(job['id'],'test-owner','resume')
    with pytest.raises(ValueError): service.history.status(job['id'],'different-owner')


def test_all_chat_events_and_no_implicit_global_subscription(app_client):
    app,client=app_client
    import base64
    params={'name':'message.received','arguments':{},'delivery':{'mode':'webhook','url':'https://receiver.example/callback','secret':'whsec_'+base64.b64encode(b'x'*32).decode()}}
    assert rpc(client,'events/subscribe',params,expected_status=400)['error']['code']==-32602
    params['arguments']={'all_chats':True,'chat_ids':['group-1@g.us']}
    assert rpc(client,'events/subscribe',params,expected_status=400)['error']['code']==-32602
    assert 'result' in subscribe(client,arguments={'all_chats':True,'contains':'TEST-MARKER'})
    app.state.service.store.ingest(message('all-chats-hit',chat='unlisted@g.us',text='TEST-MARKER'))
    app.state.service.store.ingest(message('all-chats-no-hit',chat='unlisted@g.us',text='ordinary message'))
    assert app.state.service.store.state()['deliveries']=={'pending':1}
