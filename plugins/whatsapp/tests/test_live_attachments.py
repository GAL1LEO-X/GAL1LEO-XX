"""Live attachment lifecycle with a synthetic provider and real signed downloads."""
import base64
import copy
import hashlib
import json
import time
from dataclasses import replace
from urllib.parse import quote

import pytest
from starlette.testclient import TestClient

from conftest import call, message, rpc
from test_clearchat_coverage import clear
from test_linked_device_visibility import event
from sally_whatsapp.server import AttachmentId, Service, create_app
from sally_whatsapp.store import canonical

CHAT='15550001111@c.us'
OTHER='15550009999@c.us'
GROUP='15550003333@g.us'
LID='15550002222@lid'
SOURCE=f'false_{CHAT}_SOURCE'
FLAGS={'IsViewOnce':False,'IsViewOnceV2':False,'IsViewOnceV2Extension':False,'IsEphemeral':False}
DIGEST=base64.b64encode(hashlib.sha256(b'synthetic attachment').digest()).decode()


def observed(identifier=SOURCE,chat=CHAT,*,timestamp=1000):
    return {**message(identifier,chat,timestamp=timestamp)['payload'],
            'hasMedia':True,'media':{'url':'http://127.0.0.1:8821/api/files/synthetic-private',
                                   'filename':'fixture.pdf','mimetype':'application/pdf'},
            '_data':{**FLAGS,'Message':{'documentMessage':{'fileSHA256':DIGEST}}}}


def enabled(environment,**changes):
    settings,receiver,gateway,_=environment
    settings=replace(settings,live_account_enabled=True,**changes)
    gateway.observation=observed()
    gateway.requests=[]
    gateway.downloads=[]
    gateway.before_read=None
    gateway.before_download=None
    original_download=gateway.attachment_to_file
    def request(method,path,**kwargs):
        assert method=='GET'
        gateway.requests.append((method,path,kwargs))
        if gateway.before_read: gateway.before_read()
        return copy.deepcopy(gateway.observation)
    def download(media,target,maximum):
        gateway.downloads.append((media,maximum))
        result=original_download(media,target,maximum)
        if gateway.before_download: gateway.before_download()
        return result
    gateway.request=request
    gateway.attachment_to_file=download
    return Service(settings,gateway=gateway,event_transport=receiver),gateway


def args(identifier=SOURCE):
    return AttachmentId(message_id=identifier,source='live')


def prepare(service):
    queued=service.attachment(args(),'test-owner')
    assert service.media.process_one()
    result=service.media.status(queued['id'],'test-owner')
    assert result['state']=='ready'
    return result


def remove(service,kind):
    if kind=='revoke':
        service.store.ingest({'event':'message.revoked','payload':{'revokedMessageId':SOURCE}})
    elif kind=='clear': service.store.ingest(clear())
    elif kind=='clear_unknown': service.store.ingest(clear(through=None))
    else: service.store.ingest(event(kind,raw='SOURCE'))


def test_live_attachment_mcp_to_signed_download_without_import_seen_or_send(environment):
    service,gateway=enabled(environment,send_enabled=False)
    app=create_app(service.settings,gateway=gateway,event_transport=environment[1],start_worker=False)
    with TestClient(app) as client:
        client.headers.update({'Authorization':'Bearer '+environment[3](scope='whatsapp:read'),
                               'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28'})
        archive=call(client,'get_attachment',{'message_id':SOURCE})['result']
        assert archive['isError'] and 'acquired archive' in json.dumps(archive)
        assert gateway.requests==[]
        queued=call(client,'get_attachment',{'message_id':SOURCE,'source':'live'})['result']['structuredContent']
        assert queued['state']=='queued'
        assert app.state.service.media.process_one()
        ready=call(client,'get_transfer_status',{'transfer_id':queued['id']})['result']['structuredContent']
        assert ready['state']=='ready' and ready['sha256']==hashlib.sha256(gateway.media_bytes).hexdigest()
        client.headers.pop('Authorization')
        response=client.get(ready['download_url'])
        assert response.status_code==200 and response.content==gateway.media_bytes
        assert response.headers['cache-control']=='private, no-store'
        assert [r[2]['params'] for r in gateway.requests]==[
            {'downloadMedia':'false'},{'downloadMedia':'false'},{'downloadMedia':'true'},
            {'downloadMedia':'false'},{'downloadMedia':'false'}]
        for method,path,options in gateway.requests:
            assert method=='GET' and path==f'/api/default/chats/{quote(CHAT,safe="")}/messages/{quote(SOURCE,safe="")}'
            assert options['timeout']==15
        assert app.state.service.store.search()['messages']==[]
        with service.store.db() as db:
            assert db.execute('SELECT count(*) FROM messages').fetchone()[0]==0
            stored=db.execute('SELECT source FROM media_jobs WHERE id=?',(queued['id'],)).fetchone()[0]
        source=json.loads(service.media.cipher.decrypt(stored))
        assert set(source)=={'kind','provenance','message_id','chat_id','timestamp','lifetime','media_identity'}
        assert 'synthetic-private' not in canonical(source) and 'Riunione' not in canonical(source)
        assert not gateway.sent and not environment[1].requests


def test_live_attachment_owner_and_read_scope_checked_before_provider(environment):
    service,gateway=enabled(environment)
    app=create_app(service.settings,gateway=gateway,event_transport=environment[1],start_worker=False)
    with TestClient(app) as client:
        client.headers.update({'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28'})
        client.headers['Authorization']='Bearer '+environment[3](sub='different-owner')
        rpc(client,'tools/call',{'name':'get_attachment','arguments':{
            'message_id':SOURCE,'source':'live'}},expected_status=401)
        client.headers['Authorization']='Bearer '+environment[3](scope='whatsapp:send')
        result=rpc(client,'tools/call',{'name':'get_attachment','arguments':{
            'message_id':SOURCE,'source':'live'}},expected_status=403)
        assert result['error']=='insufficient_scope'
        assert not gateway.requests


@pytest.mark.parametrize('kind',['revoke','DeleteForMe','DeleteChat','clear','clear_unknown'])
@pytest.mark.parametrize('stage',['before_queue','before_worker','during_worker_read','during_download','after_ready','during_resolve'])
def test_local_removals_stop_live_bytes_at_every_gate(environment,kind,stage):
    service,gateway=enabled(environment)
    if stage=='before_queue':
        remove(service,kind)
        with pytest.raises(ValueError): service.attachment(args(),'test-owner')
        assert not gateway.downloads
        return
    queued=service.attachment(args(),'test-owner')
    if stage=='before_worker': remove(service,kind)
    elif stage=='during_worker_read': gateway.before_read=lambda:remove(service,kind)
    elif stage=='during_download': gateway.before_download=lambda:remove(service,kind)
    service.media.process_one()
    if stage in ('after_ready','during_resolve'):
        ready=service.media.status(queued['id'],'test-owner')
        grant=ready['download_url'].split('/files/',1)[1]
        if stage=='after_ready': remove(service,kind)
        else: gateway.before_read=lambda:remove(service,kind)
        with pytest.raises(ValueError): service.media.resolve(grant)
    else:
        assert service.media.row(queued['id'])['state']!='ready'
        assert not service.media.path(queued['id']).exists()
        if stage!='during_download': assert not gateway.downloads


@pytest.mark.parametrize('kind',['DeleteChat','clear'])
def test_new_unarchived_attachment_after_known_deletion_boundary_still_works(environment,kind):
    service,gateway=enabled(environment)
    remove(service,kind)
    gateway.observation['timestamp']=2000
    ready=prepare(service)
    assert service.media.resolve(ready['download_url'].split('/files/',1)[1])[0].read_bytes()==gateway.media_bytes
    assert service.store.search()['messages']==[]


@pytest.mark.parametrize('chat,provider_chat,participant',[(CHAT,CHAT,''),(LID,CHAT,''),(GROUP,GROUP,'_15550004444@c.us')])
def test_live_source_alias_and_group_identity(environment,chat,provider_chat,participant):
    service,gateway=enabled(environment)
    service.store.bind_chat_alias(LID,CHAT)
    identifier=f'false_{chat}_SOURCE{participant}'
    gateway.observation=observed(f'false_{provider_chat}_SOURCE{participant}',provider_chat)
    queued=service.attachment(args(identifier),'test-owner')
    assert service.media.process_one()
    assert service.media.status(queued['id'],'test-owner')['state']=='ready'


def test_group_same_raw_id_other_participant_cannot_supply_attachment(environment):
    service,gateway=enabled(environment)
    requested=f'false_{GROUP}_SOURCE_15550004444@c.us'
    gateway.observation=observed(f'false_{GROUP}_SOURCE_15550005555@c.us',GROUP)
    with pytest.raises(ValueError,match='identity'): service.attachment(args(requested),'test-owner')
    assert not gateway.downloads


def test_new_alias_binding_does_not_hide_a_removal_during_live_read(environment):
    service,gateway=enabled(environment)
    identifier=f'false_{LID}_SOURCE'
    gateway.observation=observed(identifier,LID)
    queued=service.attachment(args(identifier),'test-owner')
    def bind_and_remove():
        service.store.bind_chat_alias(LID,CHAT)
        remove(service,'revoke')
    gateway.before_read=bind_and_remove
    assert service.media.process_one()
    assert service.media.row(queued['id'])['state']=='cancelled'
    assert not gateway.downloads


def test_raw_reference_requires_full_live_identity_before_provider(environment):
    service,gateway=enabled(environment)
    with pytest.raises(ValueError,match='complete provider'): service.attachment(args('SOURCE'),'test-owner')
    assert not gateway.requests


@pytest.mark.parametrize('bad',[None,[],{},observed(f'false_{OTHER}_SOURCE',OTHER),
    {**observed(),'fromMe':True},{**observed(),'timestamp':float('nan')},
    {**observed(),'_data':{}},{**observed(),'hasMedia':False},
    {**observed(),'media':[]}])
def test_wrong_or_incomplete_provider_observation_never_downloads(environment,bad):
    service,gateway=enabled(environment)
    gateway.observation=bad
    with pytest.raises(ValueError): service.attachment(args(),'test-owner')
    assert not gateway.downloads


@pytest.mark.parametrize('variant',['view_once','view_once_media','ephemeral_expired','ephemeral_uncertain'])
@pytest.mark.parametrize('stage',['before_queue','before_worker','after_ready'])
def test_live_lifetime_blocks_even_with_cache_or_all_false_flags(environment,variant,stage):
    service,gateway=enabled(environment)
    if stage=='before_worker': queued=service.attachment(args(),'test-owner')
    elif stage=='after_ready': ready=prepare(service)
    if variant=='view_once': gateway.observation['_data']['IsViewOnce']=True
    elif variant=='view_once_media': gateway.observation['_data']['Message']['documentMessage']['viewOnce']=True
    elif variant=='ephemeral_expired':
        gateway.observation['_data']['Message']['documentMessage']['contextInfo']={'expiration':30}
    else: gateway.observation['_data']['IsEphemeral']=True
    if stage=='before_queue':
        with pytest.raises(ValueError): service.attachment(args(),'test-owner')
        assert not gateway.downloads
    elif stage=='before_worker':
        assert service.media.process_one()
        assert service.media.row(queued['id'])['state']=='cancelled'
        assert not gateway.downloads
    else:
        with pytest.raises(ValueError): service.media.resolve(ready['download_url'].split('/files/',1)[1])
        assert not service.media.path(ready['id']).exists()


def test_active_ephemeral_attachment_expires_with_its_message(environment,monkeypatch):
    service,gateway=enabled(environment)
    now=int(time.time())
    gateway.observation=observed(timestamp=now-20)
    gateway.observation['_data']['Message']['documentMessage']['contextInfo']={'expiration':30}
    ready=prepare(service)
    assert ready['expires']==now+10
    grant=ready['download_url'].split('/files/',1)[1]
    assert service.media.resolve(grant)[0].exists()
    monkeypatch.setattr(time,'time',lambda:now+11)
    with pytest.raises(ValueError): service.media.resolve(grant)
    service.media.clean()
    assert not service.media.path(ready['id']).exists()
    assert service.store.message_state(SOURCE)['state']=='expired'


def test_shortened_verified_lifetime_updates_status_and_signed_grant_together(environment):
    service,gateway=enabled(environment)
    now=int(time.time())
    gateway.observation=observed(timestamp=now)
    gateway.observation['_data']['Message']['documentMessage']['contextInfo']={'expiration':100}
    ready=prepare(service)
    gateway.observation['_data']['Message']['documentMessage']['contextInfo']['expiration']=50
    updated=service.media.status(ready['id'],'test-owner')
    grant=updated['download_url'].split('/files/',1)[1]
    decoded=json.loads(service.media.cipher.decrypt(grant.encode()))
    assert updated['expires']==decoded['expires']==now+50


def test_ready_live_grant_rejects_wrong_owner_and_provider_replacement(environment):
    service,gateway=enabled(environment)
    ready=prepare(service)
    with pytest.raises(ValueError,match='not found'): service.media.status(ready['id'],'different-owner')
    grant=ready['download_url'].split('/files/',1)[1]
    data=json.loads(service.media.cipher.decrypt(grant.encode()))
    data['owner']='different-owner'
    forged=service.media.cipher.encrypt(canonical(data).encode()).decode()
    with pytest.raises(ValueError,match='grant'): service.media.resolve(forged)
    gateway.observation=observed(f'false_{OTHER}_SOURCE',OTHER)
    with pytest.raises(ValueError,match='reverified'): service.media.resolve(grant)


@pytest.mark.parametrize('kind',['imageMessage','audioMessage','videoMessage','documentMessage','stickerMessage','ptvMessage'])
def test_typed_media_hash_binds_original_bytes_without_including_caption(environment,kind):
    service,gateway=enabled(environment)
    gateway.observation['_data']['Message']={kind:{'fileSHA256':DIGEST,'caption':'First caption'}}
    ready=prepare(service)
    gateway.observation['_data']['Message'][kind]['caption']='Changed caption'
    path,_=service.media.resolve(ready['download_url'].split('/files/',1)[1])
    assert path.read_bytes()==gateway.media_bytes


@pytest.mark.parametrize('content',[
    {'templateMessage':{'hydratedTemplate':{'imageMessage':{'fileSHA256':DIGEST}}}},
    {'templateMessage':{'hydratedTemplate':{'videoMessage':{'fileSHA256':DIGEST}}}},
    {'templateMessage':{'interactiveMessageTemplate':{'header':{'imageMessage':{'fileSHA256':DIGEST}}}}},
    {'templateMessage':{'interactiveMessageTemplate':{'header':{'videoMessage':{'fileSHA256':DIGEST}}}}},
    {'templateMessage':{'interactiveMessageTemplate':{'header':{'documentMessage':{'fileSHA256':DIGEST}}}}},
    {'associatedChildMessage':{'message':{'audioMessage':{'fileSHA256':DIGEST}}}},
    {'documentWithCaptionMessage':{'message':{'documentMessage':{'fileSHA256':DIGEST,'caption':'Synthetic'}}}},
])
def test_pinned_waha_template_and_associated_child_media_paths(environment,content):
    service,gateway=enabled(environment)
    gateway.observation['_data']['Message']=content
    ready=prepare(service)
    assert service.media.resolve(ready['download_url'].split('/files/',1)[1])[0].read_bytes()==gateway.media_bytes


def test_quote_hash_does_not_substitute_for_attachment_hash(environment):
    service,gateway=enabled(environment)
    gateway.observation['_data']['Message']={'documentMessage':{
        'contextInfo':{'quotedMessage':{'documentMessage':{'fileSHA256':DIGEST}}}}}
    with pytest.raises(ValueError,match='hash'): service.attachment(args(),'test-owner')
    assert not gateway.downloads


@pytest.mark.parametrize('stage',['before_worker','during_download_read','after_ready'])
@pytest.mark.parametrize('replacement',[None,'not-a-digest',base64.b64encode(b'X'*32).decode()])
def test_changed_or_missing_source_hash_never_serves_previous_attachment(environment,stage,replacement):
    service,gateway=enabled(environment)
    def replace_media():
        gateway.observation['_data']['Message']['documentMessage']['fileSHA256']=replacement
    if stage=='after_ready':
        ready=prepare(service)
        replace_media()
        with pytest.raises(ValueError,match='changed'): service.media.resolve(ready['download_url'].split('/files/',1)[1])
        assert service.media.row(ready['id'])['state']=='cancelled'
        assert not service.media.path(ready['id']).exists()
        return
    queued=service.attachment(args(),'test-owner')
    if stage=='before_worker': replace_media()
    else:
        def during_media_read():
            if gateway.requests[-1][2]['params']=={'downloadMedia':'true'}: replace_media()
        gateway.before_read=during_media_read
    assert service.media.process_one()
    assert service.media.row(queued['id'])['state']=='failed'
    assert not gateway.downloads and not service.media.path(queued['id']).exists()


@pytest.mark.parametrize('digest',[None,True,'',DIGEST.rstrip('='),'A'*44,base64.b64encode(b'x'*31).decode()])
def test_initial_missing_or_malformed_sha256_blocks_unverifiable_live_file(environment,digest):
    service,gateway=enabled(environment)
    gateway.observation['_data']['Message']['documentMessage']['fileSHA256']=digest
    with pytest.raises(ValueError,match='hash'): service.attachment(args(),'test-owner')
    assert not gateway.downloads


def test_provider_file_bytes_must_match_verified_message_sha256(environment):
    service,gateway=enabled(environment)
    queued=service.attachment(args(),'test-owner')
    gateway.media_bytes=b'different bytes at same synthetic provider URL'
    assert service.media.process_one()
    row=service.media.row(queued['id'])
    assert row['state']=='failed' and 'differs' in row['error']
    assert not service.media.path(queued['id']).exists()


def test_remote_failure_during_signed_download_is_private_404(environment):
    service,gateway=enabled(environment)
    ready=prepare(service)
    from sally_whatsapp.gateway import GatewayUnavailable
    def unreachable(*args,**kwargs): raise GatewayUnavailable('Synthetic private provider detail',status_code=503)
    gateway.request=unreachable
    app=create_app(service.settings,gateway=gateway,event_transport=environment[1],start_worker=False)
    with TestClient(app) as client:
        response=client.get(ready['download_url'])
    assert response.status_code==404 and response.json()=={'error':'file_unavailable_or_expired'}
    assert 'Synthetic private' not in response.text


def test_live_transfer_survives_service_restart_with_only_encrypted_provenance(environment):
    service,gateway=enabled(environment)
    ready=prepare(service)
    restored=Service(service.settings,gateway=gateway,event_transport=environment[1])
    path,row=restored.media.resolve(ready['download_url'].split('/files/',1)[1])
    assert path.read_bytes()==gateway.media_bytes and row['owner']=='test-owner'
    assert len(gateway.requests)==5
