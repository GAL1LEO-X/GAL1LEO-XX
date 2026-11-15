"""Preview policy and legacy queues against synthetic HTTP/provider fixtures."""
import base64
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys

import httpx
import pytest

from conftest import attachment_payload, message
from sally_whatsapp.gateway import Waha
from sally_whatsapp.operations import OPERATIONS, validate_operation
from sally_whatsapp.server import MediaAction, OperationAction, Service
from sally_whatsapp.store import Store, canonical


PREVIEW_OPERATIONS=('messages_send_text','chats_edit_message','status_send_text_status')
PNG=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aXioAAAAASUVORK5CYII=')
IMAGE_ID='false_fixture@g.us_SYNTHETICIMAGE'


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def fail(*args,**kwargs): pytest.fail('Unexpected network in preview policy test')
    monkeypatch.setattr(socket,'getaddrinfo',fail)
    monkeypatch.setattr(socket.socket,'connect',fail)


@pytest.fixture
def preview_service(environment,monkeypatch):
    import sally_whatsapp.events as events
    monkeypatch.setattr(events,'public_addresses',lambda host:[('synthetic-public',)])
    settings=replace(environment[0],live_account_enabled=True,send_enabled=True,
                     account_actions_enabled=True,send_chat_ids=['fixture@g.us'])
    gateway=Waha(settings)
    gateway.client.close()
    requests=[]
    def handler(request):
        requests.append(request)
        if request.method=='GET':
            if '/messages/' in request.url.path:
                return httpx.Response(200,json=attachment_payload(
                    IMAGE_ID,'fixture@g.us',PNG,name='synthetic.png',mimetype='image/png',kind='imageMessage'))
            return httpx.Response(200,headers={'Content-Length':str(len(PNG))},stream=httpx.ByteStream(PNG))
        return httpx.Response(200,json={'id':'synthetic-provider-id'})
    gateway.client=httpx.Client(base_url=settings.waha_url,transport=httpx.MockTransport(handler),
                                follow_redirects=False,trust_env=False)
    service=Service(settings,gateway=gateway,event_transport=environment[1])
    yield service,requests
    gateway.close()


def arguments(name):
    body={'text':'Sintetico http://127.0.0.1/private'}
    path={}
    if name=='chats_edit_message':
        path={'chatId':'fixture@g.us','messageId':'synthetic-message'}
    elif name=='status_send_text_status':
        body.update(backgroundColor='#FFFFFF',font=1,contacts=['fixture@g.us'])
    else:
        body['chatId']='fixture@g.us'
    return {'path':path,'query':{},'body':body}


def custom_arguments():
    return {'path':{},'query':{},'body':{'chatId':'fixture@g.us','text':'https://public.example/a',
            'preview':{'url':'https://public.example/a','title':'synthetic','description':'synthetic'}}}


def image_transfer(service):
    envelope=message(IMAGE_ID,chat='fixture@g.us')
    envelope['payload']=attachment_payload(IMAGE_ID,'fixture@g.us',PNG,name='synthetic.png',
                                           mimetype='image/png',kind='imageMessage')
    service.store.ingest(envelope)
    job=service.media.enqueue('test-owner',{'kind':'gateway','message_id':IMAGE_ID,
        'chat_id':'fixture@g.us','media':{'url':service.settings.waha_url+'/api/files/synthetic.png'}},
        'synthetic.png','image/png')
    assert service.media.process_one()
    assert service.media.ready(job['id'],'test-owner')['state']=='ready'
    return job['id']


def ledger(service,key):
    with service.store.db() as db:
        row=db.execute('SELECT payload_hash FROM sends WHERE key=?',(key,)).fetchone()
        return row[0] if row else None


@pytest.mark.parametrize('name',PREVIEW_OPERATIONS)
@pytest.mark.parametrize('value',['omitted',False])
def test_ordinary_preview_wire_is_false_without_changing_idempotency(preview_service,name,value):
    service,requests=preview_service
    args=arguments(name)
    if value is False:
        args['body'].update(linkPreview=False,linkPreviewHighQuality=False)
    request=OperationAction(operation=name,arguments=args,idempotency_key='synthetic-preview-policy-0001')
    assert service.operation(request,'test-owner')['state']=='queued'
    digest=ledger(service,request.idempotency_key)
    assert service.process_action()
    wire=json.loads(requests[0].content)
    assert wire['linkPreview'] is False and wire['linkPreviewHighQuality'] is False
    assert len(requests)==1
    assert ledger(service,request.idempotency_key)==digest
    assert service.operation(request,'test-owner')['state']=='submitted'
    assert not service.process_action() and len(requests)==1
    # Merely sending a URL as text must not initiate DNS in the bridge.
    assert wire['text']=='Sintetico http://127.0.0.1/private'


@pytest.mark.parametrize('name',PREVIEW_OPERATIONS)
@pytest.mark.parametrize('flag',['linkPreview','linkPreviewHighQuality'])
@pytest.mark.parametrize('value',[True,1,None])
def test_ordinary_true_or_nonboolean_is_rejected_before_queue(preview_service,name,flag,value):
    service,requests=preview_service
    args=arguments(name)
    args['body'][flag]=value
    request=OperationAction(operation=name,arguments=args,idempotency_key='synthetic-preview-denied-0001')
    with pytest.raises(ValueError,match='Invalid operation arguments'):
        service.operation(request,'test-owner')
    assert ledger(service,request.idempotency_key) is None and not requests


@pytest.mark.parametrize('name',PREVIEW_OPERATIONS)
@pytest.mark.parametrize('flag',['linkPreview','linkPreviewHighQuality'])
@pytest.mark.parametrize('state',['queued','submitted','uncertain'])
def test_legacy_true_does_not_send_or_change_hash(preview_service,name,flag,state):
    service,requests=preview_service
    args=arguments(name)
    args['body'][flag]=True
    key='synthetic-legacy-preview-0001'
    # Historical input bypasses new validation, as a queue persisted by 0.4.9.
    service.store.queue_action(key,'test-owner',name,args)
    if state!='queued': service.store.finish_send(key,state,'synthetic-provider-id')
    digest=ledger(service,key)
    service.store=Store(service.settings.database,recover_inflight=True)
    assert service.process_action() is (state=='queued')
    assert service.store.send_status(key)['state']==('failed_before_send' if state=='queued' else state)
    assert ledger(service,key)==digest and not requests
    assert not service.process_action()


def test_custom_requires_transfer_before_enqueue(preview_service):
    service,requests=preview_service
    request=OperationAction(operation='messages_send_link_custom_preview',arguments=custom_arguments(),
                            idempotency_key='synthetic-custom-missing-0001')
    with pytest.raises(ValueError,match='ready transfer_id'):
        service.operation(request,'test-owner')
    assert ledger(service,request.idempotency_key) is None and not requests


@pytest.mark.parametrize('state',['queued','submitted','uncertain'])
def test_custom_legacy_missing_image_preparation_failure_only(preview_service,state):
    service,requests=preview_service
    key='synthetic-custom-legacy-0001'
    service.store.queue_action(key,'test-owner','messages_send_link_custom_preview',custom_arguments())
    if state!='queued': service.store.finish_send(key,state,'synthetic-provider-id')
    digest=ledger(service,key)
    assert service.process_action() is (state=='queued')
    assert service.store.send_status(key)['state']==('failed_before_send' if state=='queued' else state)
    assert not requests and ledger(service,key)==digest


@pytest.mark.parametrize('high_quality',[True,False])
def test_custom_uses_owned_transfer_internal_url_and_preserves_explicit_quality(preview_service,high_quality):
    service,requests=preview_service
    transfer=image_transfer(service)
    requests.clear()
    args=custom_arguments()
    args['body']['linkPreviewHighQuality']=high_quality
    request=MediaAction(operation='messages_send_link_custom_preview',arguments=args,
                        transfer_id=transfer,idempotency_key='synthetic-custom-ready-0001')
    assert service.operation(request,'test-owner',transfer_id=transfer)['state']=='queued'
    assert service.process_action()
    wire=json.loads(requests[0].content)
    assert set(wire['preview']['image'])=={'url'}
    assert wire['preview']['image']['url'].startswith(service.settings.media_gateway_origin+'/files/')
    assert wire['linkPreviewHighQuality'] is high_quality
    assert len(requests)==1


@pytest.mark.parametrize('reason',['queued','expired','other-owner','revoked','missing-file'])
@pytest.mark.parametrize('when',['before-queue','after-queue'])
def test_custom_revalidates_transfer_before_queue_and_worker(preview_service,reason,when):
    service,requests=preview_service
    transfer=image_transfer(service)
    requests.clear()
    request=MediaAction(operation='messages_send_link_custom_preview',arguments=custom_arguments(),
                        transfer_id=transfer,idempotency_key='synthetic-custom-recheck-0001')
    if when=='after-queue':
        assert service.operation(request,'test-owner',transfer_id=transfer)['state']=='queued'
    if reason=='revoked':
        service.store.ingest({'id':'synthetic-revoke','event':'message.revoked',
                             'payload':{'revokedMessageId':IMAGE_ID}})
    elif reason=='missing-file':
        service.media.path(transfer).unlink()
    else:
        field,value={'queued':('state','queued'),'expired':('expires',0),
                     'other-owner':('owner','different-owner')}[reason]
        with service.store.db() as db:
            db.execute(f'UPDATE media_jobs SET {field}=? WHERE id=?',(value,transfer))
    if when=='before-queue':
        with pytest.raises(ValueError):
            service.operation(request,'test-owner',transfer_id=transfer)
        assert ledger(service,request.idempotency_key) is None
    else:
        assert service.process_action()
        assert service.store.send_status(request.idempotency_key)['state']=='failed_before_send'
    assert not requests


def test_custom_does_not_allow_manual_image_url(preview_service):
    service,requests=preview_service
    args=custom_arguments()
    args['body']['preview']['image']={'url':'https://outside.example/synthetic'}
    with pytest.raises(ValueError,match='Invalid operation arguments'):
        validate_operation('messages_send_link_custom_preview',args,readonly=False,transfer='synthetic')
    assert not requests


@pytest.mark.parametrize('state',['submitted','uncertain'])
@pytest.mark.parametrize('change',['expired','revoked'])
def test_custom_terminal_replay_preserves_state_after_transfer_lost(preview_service,state,change):
    service,requests=preview_service
    transfer=image_transfer(service)
    requests.clear()
    args=custom_arguments()
    request=MediaAction(operation='messages_send_link_custom_preview',arguments=args,
                        transfer_id=transfer,idempotency_key='synthetic-custom-replay-0001')
    service.operation(request,'test-owner',transfer_id=transfer)
    service.store.finish_send(request.idempotency_key,state,'synthetic-provider-id')
    digest=ledger(service,request.idempotency_key)
    if change=='expired':
        with service.store.db() as db:
            db.execute('UPDATE media_jobs SET expires=0 WHERE id=?',(transfer,))
    else:
        service.store.ingest({'id':'synthetic-revoke','event':'message.revoked',
                             'payload':{'revokedMessageId':IMAGE_ID}})
    assert service.operation(request,'test-owner',transfer_id=transfer)['state']==state
    assert not service.process_action()
    assert not requests and ledger(service,request.idempotency_key)==digest
    changed=request.model_copy(deep=True)
    changed.arguments['body']['text']+=' changed'
    with pytest.raises(ValueError,match='Idempotency key'):
        service.operation(changed,'test-owner',transfer_id=transfer)
    with pytest.raises(ValueError):
        service.operation(request,'other-owner',transfer_id=transfer)
    assert service.store.send_status(request.idempotency_key)['state']==state


@pytest.mark.parametrize('name',(*PREVIEW_OPERATIONS,'messages_send_link_custom_preview'))
@pytest.mark.parametrize('state',['queued','sending','submitted','uncertain'])
def test_schema7_upgrade_preserves_legacy_preview_ledger(environment,name,state):
    settings,receiver,gateway,_=environment
    settings=replace(settings,live_account_enabled=True,send_enabled=True,account_actions_enabled=True,
                     send_chat_ids=['fixture@g.us'])
    args=custom_arguments() if name=='messages_send_link_custom_preview' else arguments(name)
    if name!='messages_send_link_custom_preview':
        args['body'].update(linkPreview=True,linkPreviewHighQuality=True)
    key='synthetic-schema7-preview-0001'
    digest=hashlib.sha256(canonical({'operation':name,'arguments':args,'transfer_id':None}).encode()).hexdigest()
    schema=Path(__file__).parents[1]/'scripts/backup_schemas/7.sql'
    with sqlite3.connect(settings.database) as db:
        db.executescript(schema.read_text())
        db.execute('INSERT INTO sends VALUES(?,?,?,?,?,?,?)',
                   (key,'test-owner',digest,state,'synthetic-provider-id' if state!='queued' else None,1,1))
        db.execute('INSERT INTO action_jobs VALUES(?,?,?,?)',(key,name,canonical(args),None))
        assert db.execute('PRAGMA user_version').fetchone()[0]==7
    calls=[]
    def unexpected_request(*args,**kwargs):
        calls.append((args,kwargs))
        pytest.fail('A legacy invalid or uncertain job must not reach the provider')
    gateway.request=unexpected_request
    service=Service(settings,gateway=gateway,event_transport=receiver)
    assert service.process_action() is (state=='queued')
    expected='failed_before_send' if state=='queued' else 'uncertain' if state=='sending' else state
    assert service.store.send_status(key)['state']==expected
    assert ledger(service,key)==digest and not calls
    with service.store.db() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==8


def test_generator_policy_matches_packaged_catalog(tmp_path):
    fixture=Path(__file__).with_name('fixtures')/'waha_2026_9_2_preview_openapi.json'
    target=tmp_path/'operations.json'
    subprocess.run([sys.executable,str(Path(__file__).parents[1]/'scripts/build_operations.py'),
                    str(fixture),'--output',str(target)],capture_output=True,text=True,check=True)
    generated=json.loads(target.read_text())
    for name in PREVIEW_OPERATIONS:
        for flag in ('linkPreview','linkPreviewHighQuality'):
            prop=generated[name]['schema']['properties']['body']['properties'][flag]
            assert prop==OPERATIONS[name]['schema']['properties']['body']['properties'][flag]
            assert prop['const'] is False
    custom=generated['messages_send_link_custom_preview']
    assert custom['media_required'] is True
    assert custom['media_path']==OPERATIONS['messages_send_link_custom_preview']['media_path']==['preview','image']
    assert 'image' not in custom['schema']['properties']['body']['properties']['preview']['properties']
    assert len(OPERATIONS)==120
