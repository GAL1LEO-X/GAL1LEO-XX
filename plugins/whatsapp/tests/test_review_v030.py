from dataclasses import replace
import json
import time
import pytest
from sally_whatsapp.server import Service,create_app
from sally_whatsapp.store import Store
from conftest import message,subscribe


def event(kind,identifier,payload,when):
    return {'event':kind,'id':identifier,'payload':payload,'timestamp':when*1000}


def test_early_revocation_cannot_be_resurrected_by_history(app_client):
    app,client=app_client
    store=app.state.service.store
    subscribe(client)
    store.ingest(event('message.revoked','revoke-first',{'revokedMessageId':'later'},time.time()-1))
    store.ingest(message('later',text='content must stay hidden'),historical=True)
    assert store.message('later') is None
    assert store.search(query='hidden')['messages']==[]
    with store.db() as db: assert db.execute('SELECT count(*) FROM deliveries').fetchone()[0]==0


def test_edits_out_of_order_before_and_after_original(app_client):
    app,_=app_client
    store=app.state.service.store
    now=time.time()
    store.ingest(event('message.edited','newest',{'editedMessageId':'later','from':'group-1@g.us','fromMe':False,'body':'latest'},now))
    store.ingest(event('message.edited','older',{'editedMessageId':'later','from':'group-1@g.us','fromMe':False,'body':'obsolete'},now-10))
    store.ingest(message('later',text='original'),historical=True)
    assert store.message('later')['body']=='latest'
    assert store.search(query='obsolete')['messages']==[]
    store.ingest(event('message.revoked','revoked',{'revokedMessageId':'later'},now+1))
    store.ingest(event('message.edited','late-edit',{'editedMessageId':'later','body':'no resurrection'},now+2))
    assert store.message('later') is None


def test_revocation_cancels_unsent_message_notification(app_client):
    app,client=app_client
    store=app.state.service.store
    subscribe(client)
    store.ingest(message('waiting'))
    store.ingest(event('message.revoked','revoked-waiting',{'revokedMessageId':'waiting'},time.time()))
    assert app.state.service.events.dispatch_one() is False
    with store.db() as db: assert db.execute('SELECT state FROM deliveries').fetchone()[0]=='cancelled'


def test_configuration_check_does_not_mutate_inflight_work(environment):
    settings,receiver,gateway,_=environment
    store=Store(settings.database)
    store.reserve_send('diagnostic-key-0001','test-owner',{'text':'synthetic'})
    app=create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False,recover_inflight=False)
    assert store.send_status('diagnostic-key-0001')['state']=='sending'
    Service(settings,gateway=gateway,event_transport=receiver)
    assert store.send_status('diagnostic-key-0001')['state']=='uncertain'


def test_queued_file_reference_can_receive_fresh_download_url(environment):
    settings,receiver,gateway,_=environment
    media=Service(settings,gateway=gateway,event_transport=receiver).media
    first=media.enqueue('test-owner',{'kind':'external','file_id':'stable-file','download_url':'https://public.example/expired'})
    second=media.enqueue('test-owner',{'kind':'external','file_id':'stable-file','download_url':'https://public.example/fresh'})
    assert first['id']==second['id']
    row=media.row(first['id'],'test-owner')
    assert json.loads(media.cipher.decrypt(row['source']))['download_url'].endswith('/fresh')


def test_gows_outgoing_null_to_is_archived_once_without_notification(app_client):
    app,client=app_client
    subscribe(client)
    identifier='true_group-1@g.us_SYNTHETIC'
    envelope=message(identifier,from_me=True)
    envelope['payload'].update({'to':None,'from':'group-1@g.us'})
    store=app.state.service.store
    assert not store.ingest(envelope)['duplicate']
    assert store.ingest(envelope)['duplicate']
    row=store.message(identifier)
    assert row['chat_id']=='group-1@g.us' and row['from_me']==1 and row['sender'] is None
    with store.db() as db: assert db.execute('SELECT count(*) FROM deliveries').fetchone()[0]==0
    envelope['id']='other-receipt'
    envelope['payload']['from']='another@g.us'
    with pytest.raises(ValueError): store.ingest(envelope)


def test_gows_null_to_also_works_in_history_import(environment):
    from sally_whatsapp.server import SyncChat
    settings,receiver,gateway,_=environment
    service=Service(settings,gateway=gateway,event_transport=receiver)
    now=int(time.time())
    payload=message('true_group-1@g.us_HISTORY',from_me=True,timestamp=now)['payload']
    payload.update({'to':None,'from':'group-1@g.us'})
    gateway.pages=[[payload]]
    result=service.sync(SyncChat(chat_id='group-1@g.us',since=now-10,until=now))
    assert result['inserted']==1 and result['window_complete'] is True


@pytest.mark.parametrize('historical',[False,True])
def test_gows_group_outgoing_uses_group_not_sender(app_client,historical):
    app,client=app_client
    subscribe(client)
    identifier='true_group-1@g.us_GROUPTEST_self@c.us'
    envelope=message(identifier,from_me=True)
    envelope['payload'].update({'from':'group-1@g.us','to':'self@c.us','participant':'self@c.us'})
    store=app.state.service.store
    assert not store.ingest(envelope,historical=historical)['duplicate']
    assert store.ingest(envelope,historical=historical)['duplicate']
    row=store.message(identifier)
    assert row['chat_id']=='group-1@g.us' and row['sender']=='self@c.us' and row['from_me']==1
    assert store.search(chat_id='group-1@g.us')['messages'][0]['id']==identifier
    with store.db() as db: assert db.execute('SELECT count(*) FROM deliveries').fetchone()[0]==0


def test_outgoing_group_serialized_id_must_match_a_payload_address(environment):
    from sally_whatsapp.account_events import message_chat
    assert message_chat({'id':'true_group-1@g.us_TEST','fromMe':True,'from':'self@c.us','to':'other@g.us'}) is None


@pytest.mark.parametrize('status',[404,410])
def test_expired_gateway_media_is_refreshed_once(environment,status):
    from conftest import attachment_payload
    import hashlib
    from sally_whatsapp.gateway import GatewayUnavailable
    settings,receiver,gateway,_=environment
    service=Service(settings,gateway=gateway,event_transport=receiver)
    seen=[]
    identifier='false_group-1@g.us_MESSAGE1'
    payload=attachment_payload(identifier,'group-1@g.us',b'OggS synthetic test',name='',
                               mimetype='audio/ogg; codecs=opus',kind='audioMessage',url='old')
    reads=[]
    def fetch(media,target,maximum):
        seen.append(media['url'])
        if media['url']=='old': raise GatewayUnavailable('expired',status_code=status)
        target.write_bytes(b'OggS synthetic test')
        return len(b'OggS synthetic test'),hashlib.sha256(b'OggS synthetic test').hexdigest()
    def regenerate(method,path,**kwargs):
        reads.append(kwargs['params']['downloadMedia'])
        if reads.count('true')==2: payload['media']['url']='fresh'
        return payload
    gateway.attachment_to_file=fetch
    gateway.request=regenerate
    job=service.media.enqueue(settings.owner_subject,{'kind':'gateway','chat_id':'group-1@g.us','message_id':identifier,'media':{'url':'old','mimetype':'audio/ogg; codecs=opus'}})
    assert service.media.process_one()
    result=service.media.status(job['id'],settings.owner_subject)
    assert seen==['old','fresh'] and result['state']=='ready' and result['mimetype']=='audio/ogg; codecs=opus'
    assert reads==['false','true','true']
    assert result['filename']=='attachment.ogg'


def test_gateway_media_failure_does_not_retry_non_expiry_errors(environment):
    from conftest import attachment_payload
    from sally_whatsapp.gateway import GatewayUnavailable
    settings,receiver,gateway,_=environment
    service=Service(settings,gateway=gateway,event_transport=receiver)
    reads=[];downloads=[]
    identifier='false_group-1@g.us_MESSAGE1'
    payload=attachment_payload(identifier,'group-1@g.us',gateway.media_bytes)
    def fail(media,target,maximum):
        downloads.append(media['url'])
        raise GatewayUnavailable('forbidden',status_code=403)
    gateway.attachment_to_file=fail
    def request(method,path,**kwargs):
        reads.append(kwargs['params']['downloadMedia'])
        return payload
    gateway.request=request
    job=service.media.enqueue(settings.owner_subject,{'kind':'gateway','chat_id':'group-1@g.us','message_id':identifier,'media':{'url':'old'}})
    service.media.process_one()
    assert service.media.status(job['id'],settings.owner_subject)['state']=='failed'
    assert reads==['false','true'] and len(downloads)==1


def test_audio_mime_parameters_and_header_injection():
    from sally_whatsapp.media import mime
    assert mime('audio/ogg; codecs=opus','')=='audio/ogg; codecs=opus'
    assert mime('audio/ogg\r\nX-Extra: unsafe','')=='application/octet-stream'


def test_location_and_contact_survive_archiving_and_revocation(app_client):
    app,client=app_client
    subscribe(client)
    store=app.state.service.store
    envelope=message('structured-content',text='')
    card='BEGIN:VCARD\nVERSION:3.0\nFN:Synthetic Test\nTEL:00000\nEND:VCARD'
    envelope['payload'].update({'location':{'latitude':'45.5','longitude':'12.25','live':False,'thumbnail':'must-not-be-stored'},'vCards':[card]})
    store.ingest(envelope)
    result=store.public_message(store.message('structured-content'))
    assert result['location']=={'latitude':45.5,'longitude':12.25,'live':False}
    assert result['vCards']==[card] and 'thumbnail' not in json.dumps(result)
    assert store.search()['messages'][0]['vCards']==[card]
    with store.db() as db:
        assert json.loads(db.execute('SELECT body FROM deliveries').fetchone()[0])['data']['preview']=='[Location]'
    store.ingest(event('message.revoked','structured-revoked',{'revokedMessageId':'structured-content'},time.time()))
    assert store.message('structured-content') is None
    with store.db() as db: assert db.execute('SELECT count(*) FROM message_content').fetchone()[0]==0
    envelope['id']='late-history'
    store.ingest(envelope,historical=True)
    with store.db() as db: assert db.execute('SELECT count(*) FROM message_content').fetchone()[0]==0


def test_existing_messages_can_gain_structured_content_without_notifications(app_client):
    app,client=app_client
    subscribe(client)
    store=app.state.service.store
    original=message('old-contact',from_me=True,text='')
    store.ingest(original)
    original['id']='new-history-receipt'
    original['payload']['vCards']=['BEGIN:VCARD\nFN:Test\nEND:VCARD']
    assert store.ingest(original,historical=True)['duplicate']
    assert store.public_message(store.message('old-contact'))['vCards']==original['payload']['vCards']
    with store.db() as db: assert db.execute('SELECT count(*) FROM deliveries').fetchone()[0]==0


def test_structured_content_is_bounded_and_rejects_invalid_coordinates():
    from sally_whatsapp.account_events import message_content
    result=message_content({'location':{'latitude':'NaN','longitude':'999'},'vCards':['x'*32769,'BEGIN:VCARD\nFN:OK\nEND:VCARD']})
    assert 'location' not in result and result['content_truncated'] is True
    assert len(result['vCards'])==1


def test_lid_messages_share_phone_archive_and_subscription(app_client):
    import hmac
    app,client=app_client
    service=app.state.service
    lookups=[]
    def resolve(lid): lookups.append(lid);return '20002@c.us'
    service.gateway.phone_for_lid=resolve
    subscribe(client,arguments={'chat_ids':['20002@c.us']})
    service.store.ingest(message('old-lid',chat='10001@lid'),historical=True)
    envelope=message('new-lid',chat='10001@lid')
    raw=json.dumps(envelope).encode()
    signature=hmac.digest(service.webhook_key,raw,'sha512').hex()
    headers={'X-Webhook-Hmac-Algorithm':'sha512','X-Webhook-Hmac':signature}
    assert client.post('/webhooks/waha',content=raw,headers=headers).status_code==200
    assert client.post('/webhooks/waha',content=raw,headers=headers).status_code==200
    assert lookups==['10001@lid']
    assert len(service.store.search(chat_id='20002@c.us')['messages'])==2
    assert len(service.store.search(chat_id='10001@lid')['messages'])==2
    assert all(c['id']!='10001@lid' for c in service.store.chats()['chats'])
    with service.store.db() as db:
        deliveries=db.execute('SELECT body FROM deliveries').fetchall()
        assert len(deliveries)==1 and json.loads(deliveries[0][0])['data']['chat_id']=='20002@c.us'
    with pytest.raises(ValueError): service.store.bind_chat_alias('10001@lid','30003@c.us')


def test_sync_accepts_verified_lid_for_requested_phone(environment):
    from sally_whatsapp.server import SyncChat
    settings,receiver,gateway,_=environment
    gateway.phone_for_lid=lambda lid:'20002@c.us'
    service=Service(settings,gateway=gateway,event_transport=receiver)
    now=int(time.time())
    gateway.pages=[[message('history-lid',chat='10001@lid',timestamp=now)['payload']]]
    result=service.sync(SyncChat(chat_id='20002@c.us',since=now-10,until=now))
    assert result['inserted']==1 and result['window_complete']
    assert service.store.message('history-lid')['chat_id']=='20002@c.us'


def test_unresolved_lid_keeps_message_and_limits_failed_lookups(environment):
    from sally_whatsapp.gateway import GatewayUnavailable
    settings,receiver,gateway,_=environment
    lookups=[]
    def missing(lid): lookups.append(lid);raise GatewayUnavailable('No mapping')
    gateway.phone_for_lid=missing
    service=Service(settings,gateway=gateway,event_transport=receiver)
    service.ingest(message('unmapped-1',chat='10001@lid'))
    service.ingest(message('unmapped-2',chat='10001@lid'))
    assert len(lookups)==1 and len(service.store.search(chat_id='10001@lid')['messages'])==2
    assert service.store.state()['recovery_required']
