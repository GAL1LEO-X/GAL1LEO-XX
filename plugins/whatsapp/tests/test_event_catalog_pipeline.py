"""Synthetic provider -> callback -> autonomous acquired-context reads.

These are bridge contracts, not evidence of provider/platform delivery online.
"""
import hmac
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest

from conftest import call, message, rpc, subscribe
from sally_whatsapp.account_events import EVENT_TYPES, APPLICATION_EVENT_TYPES

CHAT = '123456789@c.us'
TARGET = 'false_' + CHAT + '_SOURCE'


def envelope(kind, identifier, payload, *, timestamp=None):
    return {'event':kind, 'id':identifier, 'session':'default',
            'timestamp':int(time.time()*1000) if timestamp is None else timestamp,
            'payload':payload}


def webhook(client, settings, event):
    raw=json.dumps(event).encode()
    headers={'X-Webhook-Hmac-Algorithm':'sha512',
             'X-Webhook-Hmac':hmac.digest(settings.webhook_secret_file.read_bytes(),raw,'sha512').hex()}
    response=client.post('/webhooks/waha',content=raw,headers=headers)
    assert response.status_code==200, response.text
    return response.json()


def provider_payload(kind):
    payload={'chatId':CHAT,'id':TARGET,'from':CHAT,'fromMe':False}
    if kind=='session.status': return {'status':'WORKING'}
    if kind=='presence.update': return {'id':CHAT,'presences':[{'participant':CHAT,'lastKnownPresence':'online'}]}
    if kind.startswith('call.'): return {'id':'CALL123','from':CHAT,'timestamp':int(time.time()),'isGroup':False,'isVideo':False}
    if kind in ('label.upsert','label.deleted'): return {'id':'12','name':'Synthetic label','color':1}
    if kind in ('label.chat.added','label.chat.deleted'): return {'labelId':'12','chatId':CHAT}
    if kind=='message.edited': payload.update(editedMessageId=TARGET,body='acquired edit')
    if kind=='message.revoked': payload.update(revokedMessageId=TARGET)
    if kind=='message.reaction': payload['reaction']={'messageId':TARGET,'text':'👍'}
    if kind.startswith('group.'): return {'group':{'id':'123456789-123456@g.us'},'participants':[]}
    if kind.startswith('poll.'): payload.update(poll={'id':TARGET},vote={'id':'false_'+CHAT+'_VOTE','chatId':CHAT})
    if kind.startswith('event.response'): payload.update(eventCreationKey={'id':TARGET})
    return payload


@pytest.mark.parametrize('kind', EVENT_TYPES)
def test_provider_catalog_callback_has_readable_context_without_receipts(
    app_client,environment,monkeypatch,kind,
):
    app,client=app_client
    service=app.state.service
    # All context reads in this test must remain local. Even a status/send/read
    # provider call would make this fail, rather than accidentally marking seen.
    def forbidden(*args,**kwargs): raise AssertionError('unexpected provider access')
    for method in ('request','send','messages','mark_seen','status'):
        monkeypatch.setattr(service.gateway,method,forbidden,raising=False)
    service.store.ingest(message(TARGET,CHAT,text='ordinary text'),historical=True)
    subscription=subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':[kind]})
    assert 'result' in subscription
    event=envelope(kind,'catalog-'+kind,provider_payload(kind))
    webhook(client,environment[0],event)
    assert webhook(client,environment[0],event)['duplicate'] is True
    assert service.events.dispatch_one()
    callbacks=[json.loads(request[1]) for request in environment[1].requests if json.loads(request[1]).get('type')!='verification']
    assert len(callbacks)==1
    callback=callbacks[0]
    assert callback['data']['event_type']==kind
    schema=next(item for item in rpc(client,'events/list')['result']['events'] if item['name']=='whatsapp.event')['payloadSchema']
    jsonschema.validate(callback['data'],schema)
    detail=call(client,'get_account_event',{'event_id':callback['data']['event_id']})['result']['structuredContent']['event']
    assert detail['id']==callback['eventId'] and detail['event_type']==kind
    if callback['data'].get('message_id'):
        result=call(client,'get_message',{'message_id':callback['data']['message_id']})['result']
        assert not result.get('isError')
    if callback['data']['chat_id']:
        result=call(client,'read_conversation',{'chat_id':callback['data']['chat_id']})['result']
        assert not result.get('isError')


def test_own_message_has_explicit_event_dedup_and_consumer_pointer(app_client,environment):
    app,client=app_client
    service=app.state.service
    subscribe(client,arguments={'all_chats':True})
    subscribe(client,name='whatsapp.event',arguments={'chat_ids':[CHAT],'event_types':['message.sent']})
    identifier='true_'+CHAT+'_OWN'
    original=message(identifier,CHAT,from_me=True,text='ordinary outgoing message')
    assert webhook(client,environment[0],original)['duplicate'] is False
    replay={**original,'id':'second-provider-notice','event':'message'}
    assert webhook(client,environment[0],replay)['duplicate'] is True
    assert service.events.dispatch_one()
    callback=json.loads(environment[1].requests[-1][1])
    schema=next(item for item in rpc(client,'events/list')['result']['events'] if item['name']=='whatsapp.event')['payloadSchema']
    jsonschema.validate(callback['data'],schema)
    assert callback['name']=='whatsapp.event'
    assert callback['data']['event_type']=='message.sent'
    assert callback['data']['message_id']==identifier
    detail=call(client,'get_account_event',{'event_id':callback['data']['event_id']})['result']['structuredContent']['event']
    assert detail['message_id']==identifier
    assert 'body' not in detail['data']
    assert call(client,'get_message',{'message_id':identifier})['result']['structuredContent']['message']['body']=='ordinary outgoing message'
    assert service.store.state()['deliveries']=={'accepted':1}


@pytest.mark.parametrize('kind',['message.sent','group.v2.update'])
def test_history_does_not_enqueue_callbacks_or_replay_on_live_duplicate(app_client,kind):
    app,client=app_client
    store=app.state.service.store
    subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':[kind]})
    event=message('true_'+CHAT+'_HISTORY',CHAT,from_me=True) if kind=='message.sent' else envelope(kind,'history-event',provider_payload(kind))
    store.ingest(event,historical=True)
    assert store.state()['deliveries']=={}
    if kind!='message.sent':
        assert store.ingest(event)['duplicate'] is True
        assert store.state()['deliveries']=={}
    else:
        # A first live observation after import is an actual new acquisition;
        # it is allowed once, with the retained archive's original identity.
        store.ingest(event)
        assert store.state()['deliveries']=={'pending':1}


def test_full_sync_updates_archive_without_scheduling_account_callback(app_client):
    app,client=app_client
    store=app.state.service.store
    subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':['chat.archived']})
    event={'event':'engine.event','engine':'GOWS','session':'default','id':'archive-fullsync',
           'payload':{'event':'events.Archive','data':{'JID':CHAT,'Timestamp':'2026-10-20T12:00:00Z',
                       'FromFullSync':True,'Action':{'archived':True}}}}
    store.ingest(event)
    assert store.list_account_events()['events'][0]['event_type']=='chat.archived'
    assert store.state()['deliveries']=={}


@pytest.mark.parametrize('raw,kind',[
    ('events.DeleteChat','chat.deleted'),('events.ClearChat','chat.cleared'),
    ('events.DeleteForMe','message.deleted_for_me'),('events.Archive','chat.archived'),
])
def test_linked_state_event_has_callback_and_readable_context(app_client,environment,raw,kind):
    app,client=app_client
    service=app.state.service
    subscribe(client,name='whatsapp.event',arguments={'chat_ids':[CHAT],'event_types':[kind]})
    data={'JID':CHAT,'Timestamp':datetime.now(timezone.utc).isoformat(),
          'FromFullSync':False,'Action':{'archived':True} if kind=='chat.archived' else {}}
    if kind=='message.deleted_for_me': data.update(ChatJID=CHAT,MessageID='SOURCE',IsFromMe=False)
    event=envelope('engine.event','linked-'+kind,{'event':raw,'data':data})
    event['engine']='GOWS'
    webhook(client,environment[0],event)
    assert service.events.dispatch_one()
    callback=json.loads(environment[1].requests[-1][1])
    assert callback['data']['event_type']==kind
    schema=next(item for item in rpc(client,'events/list')['result']['events'] if item['name']=='whatsapp.event')['payloadSchema']
    jsonschema.validate(callback['data'],schema)
    detail=call(client,'get_account_event',{'event_id':callback['data']['event_id']})['result']['structuredContent']['event']
    assert detail['event_type']==kind and detail['chat_id']==CHAT
    assert not call(client,'read_conversation',{'chat_id':CHAT})['result'].get('isError')


def test_external_generated_event_cannot_bypass_message_acquisition(app_client):
    app,_=app_client
    with pytest.raises(ValueError,match='Unsupported event'):
        app.state.service.store.ingest(envelope('message.sent','forged',{'id':TARGET,'chatId':CHAT}))


def test_presence_uses_typed_provider_id_for_explicit_chat_scope(app_client):
    app,client=app_client
    store=app.state.service.store
    subscribe(client,name='whatsapp.event',arguments={'chat_ids':[CHAT],'event_types':['presence.update']})
    store.ingest(envelope('presence.update','presence-in-scope',provider_payload('presence.update')))
    store.ingest(envelope('presence.update','presence-out-of-scope',{'id':'999999999@c.us','presences':[]}))
    assert store.state()['deliveries']=={'pending':1}
    with store.db() as db:
        callback=json.loads(db.execute('SELECT body FROM deliveries').fetchone()[0])
    assert callback['data']['chat_id']==CHAT


@pytest.mark.parametrize('kind',['call.received','call.accepted','call.rejected'])
@pytest.mark.parametrize('shape',['GroupJID','Attrs','unknown','conflict'])
def test_group_call_scope_uses_proven_group_not_caller(app_client,kind,shape):
    app,client=app_client
    store=app.state.service.store
    group='123456789-123456@g.us'
    group_sub=subscribe(client,name='whatsapp.event',arguments={'chat_ids':[group],'event_types':[kind]})['result']['id']
    caller_sub=subscribe(client,name='whatsapp.event',arguments={'chat_ids':[CHAT],'event_types':[kind]})['result']['id']
    all_sub=subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':[kind]})['result']['id']
    raw={'GroupJID':group} if shape=='GroupJID' else {'Data':{'Attrs':{'group-jid':group}}} if shape=='Attrs' else {}
    if shape=='conflict': raw={'GroupJID':group,'Data':{'Attrs':{'group-jid':'999999999@g.us'}}}
    payload={**provider_payload(kind),'isGroup':True,'_data':{**raw,'token':'never-expose'}}
    store.ingest(envelope(kind,'group-call-'+shape,payload))
    with store.db() as db:
        rows=db.execute('SELECT subscription,body FROM deliveries').fetchall()
    assert caller_sub not in {row['subscription'] for row in rows}
    assert {row['subscription'] for row in rows}==({group_sub,all_sub} if shape in ('GroupJID','Attrs') else {all_sub})
    for row in rows:
        callback=json.loads(row['body'])
        assert callback['data']['chat_id']==(group if shape in ('GroupJID','Attrs') else None)
        assert 'never-expose' not in json.dumps(store.account_event(callback['data']['event_id']))


@pytest.mark.parametrize('shape',['unknown','conflict','invalid','GroupJID','Attrs','direct'])
def test_terminated_call_keeps_decoder_chat_scope_through_callback_and_context(
    app_client,environment,shape,
):
    app,client=app_client
    service=app.state.service
    group='123456789-123456@g.us'
    subscriptions={}
    for label,selection in [('caller',{'chat_ids':[CHAT]}),('group',{'chat_ids':[group]}),
                            ('all',{'all_chats':True})]:
        subscriptions[label]=subscribe(client,name='whatsapp.event',arguments={
            **selection,'event_types':['call.terminated']})['result']['id']
    extra={
        'unknown':{'Data':{'Attrs':{'type':'group'}}},
        'conflict':{'GroupJID':group,'Data':{'Attrs':{'group-jid':'999999999@g.us'}}},
        'invalid':{'GroupJID':CHAT},
        'GroupJID':{'GroupJID':group},
        'Attrs':{'Data':{'Attrs':{'group-jid':group}}},
        'direct':{},
    }[shape]
    event=envelope('engine.event','terminated-'+shape,{'event':'events.CallTerminate','data':{
        'CallID':'SYNTHETIC-CALL','From':CHAT.replace('@c.us','@s.whatsapp.net'),
        'Timestamp':datetime.now(timezone.utc).isoformat(),'Reason':'ended',**extra}})
    event['engine']='GOWS'
    webhook(client,environment[0],event)
    assert webhook(client,environment[0],event)['duplicate'] is True
    expected_chat=group if shape in ('GroupJID','Attrs') else CHAT if shape=='direct' else None
    expected_subscriptions={subscriptions['all']}
    if expected_chat is not None:
        expected_subscriptions.add(subscriptions['caller' if shape=='direct' else 'group'])
    with service.store.db() as db:
        rows=db.execute('SELECT subscription,body FROM deliveries').fetchall()
    assert {row['subscription'] for row in rows}==expected_subscriptions
    for _ in rows: assert service.events.dispatch_one()
    assert not service.events.dispatch_one()
    callbacks=[json.loads(body) for _,body,_ in environment[1].requests
               if json.loads(body).get('type')!='verification']
    assert len(callbacks)==len(expected_subscriptions)
    for callback in callbacks:
        assert callback['data']['chat_id']==expected_chat
        detail=call(client,'get_account_event',{'event_id':callback['data']['event_id']})['result']['structuredContent']['event']
        assert detail['chat_id']==detail['data']['chatId']==expected_chat
        assert detail['data']['from']==CHAT
        assert detail['data']['isGroup'] is (shape!='direct')
        if shape!='direct':
            assert detail['data']['groupIdentity']==('complete' if expected_chat else 'unknown')
        if expected_chat is not None:
            assert not call(client,'read_conversation',{'chat_id':expected_chat})['result'].get('isError')


def test_raw_target_pointer_requires_unique_author_in_known_chat(app_client):
    app,client=app_client
    store=app.state.service.store
    group='123456789-123456@g.us'
    for participant in ('111111@c.us','222222@c.us'):
        event=message('false_'+group+'_COLLISION_'+participant,group)
        event['payload']['participant']=participant
        store.ingest(event,historical=True)
    subscribe(client,name='whatsapp.event',arguments={'chat_ids':[group],'event_types':['message.ack']})
    store.ingest(envelope('message.ack','ambiguous-ack',{'id':'COLLISION','chatId':group,'ack':3}))
    with store.db() as db:
        payload=json.loads(db.execute('SELECT body FROM deliveries').fetchone()[0])
    assert 'message_id' not in payload['data']
    detail=store.account_event(payload['data']['event_id'])
    assert 'message_id' not in detail


def test_all_event_types_fit_explicit_subscription_and_schema(app_client):
    _,client=app_client
    result=subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':list(APPLICATION_EVENT_TYPES)})
    assert 'result' in result
    schema=next(item for item in rpc(client,'events/list')['result']['events'] if item['name']=='whatsapp.event')
    assert schema['payloadSchema']['properties']['event_type']['enum']==list(APPLICATION_EVENT_TYPES)


def test_release_event_matrix_matches_runtime_catalog_and_real_test_paths():
    root=Path(__file__).resolve().parents[1]
    matrix=json.loads((root/'docs/event-coverage.json').read_text())
    assert [row['event_type'] for row in matrix['application_events']]==list(APPLICATION_EVENT_TYPES)
    assert matrix['application_event_count']==len(APPLICATION_EVENT_TYPES)
    for row in matrix['application_events']:
        path,function=row['offline_pipeline_test'].split('::')
        assert ('def '+function+'(') in (root/path).read_text()


def test_queue_timing_is_private_stable_and_does_not_change_retry_bytes(app_client):
    app,client=app_client
    service=app.state.service
    subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':['message.sent']})
    original=message('true_'+CHAT+'_TIMING',CHAT,from_me=True)
    service.store.ingest(original)
    with service.store.db() as db:
        row=db.execute('SELECT event_id,body FROM deliveries').fetchone()
        timing=json.loads(db.execute('SELECT value FROM state WHERE key=?',('private:event_timing:'+row['event_id'],)).fetchone()[0])
    assert timing['provider_at']==original['payload']['timestamp']
    assert timing['ingested_at']==timing['queued_at']>=timing['provider_at']
    assert 'queued_at' not in row['body']
    service.store.ingest({**original,'id':'duplicate-timing'})
    with service.store.db() as db:
        assert db.execute('SELECT body FROM deliveries').fetchone()[0]==row['body']
        assert json.loads(db.execute('SELECT value FROM state WHERE key=?',('private:event_timing:'+row['event_id'],)).fetchone()[0])==timing


@pytest.mark.parametrize('provider_timestamp',[None,True,-1,'unknown'])
def test_missing_provider_time_is_not_invented_from_ingest_time(app_client,provider_timestamp):
    app,client=app_client
    store=app.state.service.store
    subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':['message.ack']})
    event=envelope('message.ack','without-provider-clock',{'id':TARGET,'chatId':CHAT})
    event['timestamp']=provider_timestamp
    store.ingest(event)
    with store.db() as db:
        event_id=db.execute('SELECT event_id FROM deliveries').fetchone()[0]
        timing=json.loads(db.execute('SELECT value FROM state WHERE key=?',('private:event_timing:'+event_id,)).fetchone()[0])
    assert set(timing)=={'ingested_at','queued_at','ingestion_ref'}
    assert len(timing['ingestion_ref']) == 24
    assert all(char in '0123456789abcdef' for char in timing['ingestion_ref'])
    assert timing['ingested_at'] == timing['queued_at']


@pytest.mark.parametrize('bind_before',[False,True])
def test_own_alias_reconciliation_keeps_single_logical_callback(app_client,bind_before):
    app,client=app_client
    store=app.state.service.store
    alias='987654321@lid'
    subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':['message.sent']})
    if bind_before: store.bind_chat_alias(alias,CHAT)
    for chat in (alias,CHAT):
        store.ingest(message('true_'+chat+'_SAME',chat,from_me=True))
    if not bind_before: store.bind_chat_alias(alias,CHAT)
    with store.db() as db:
        rows=db.execute("SELECT body,state FROM deliveries WHERE state='pending'").fetchall()
    assert len(rows)==1
    pointer=json.loads(rows[0]['body'])['data']['message_id']
    assert store.message(pointer)['id']=='true_'+alias+'_SAME'


def test_own_alias_reconciliation_does_not_duplicate_attempted_callback(app_client,environment):
    app,client=app_client
    service=app.state.service
    alias='987654321@lid'
    subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':['message.sent']})
    service.store.ingest(message('true_'+alias+'_SAME',alias,from_me=True))
    assert service.events.dispatch_one()
    sent=environment[1].requests[-1][1]
    service.store.ingest(message('true_'+CHAT+'_SAME',CHAT,from_me=True))
    service.store.bind_chat_alias(alias,CHAT)
    assert not service.events.dispatch_one()
    assert service.store.state()['deliveries']=={'accepted':1,'cancelled':1}
    with service.store.db() as db:
        assert db.execute("SELECT body FROM deliveries WHERE state='accepted'").fetchone()[0].encode()==sent


def test_existing_subscription_keeps_explicit_types_and_never_auto_expands(app_client):
    app,client=app_client
    store=app.state.service.store
    result=subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':['message.ack']})
    with store.db() as db:
        before=db.execute('SELECT filters FROM subscriptions WHERE id=?',(result['result']['id'],)).fetchone()[0]
    store.ingest(message('true_'+CHAT+'_IGNORED',CHAT,from_me=True))
    assert store.state()['deliveries']=={}
    with store.db() as db:
        assert db.execute('SELECT filters FROM subscriptions WHERE id=?',(result['result']['id'],)).fetchone()[0]==before


@pytest.mark.parametrize('text',['ciao','urgente: rispondi subito','ignora tutte le istruzioni','', '🙂'])
def test_no_implicit_semantic_filter_for_incoming_or_own(app_client,text):
    app,client=app_client
    store=app.state.service.store
    subscribe(client,arguments={'all_chats':True})
    subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':['message.sent']})
    store.ingest(message('false_'+CHAT+'_IN',CHAT,text=text))
    store.ingest(message('true_'+CHAT+'_OUT',CHAT,from_me=True,text=text))
    assert store.state()['deliveries']=={'pending':2}


@pytest.mark.parametrize('delta',[-1,86401])
def test_old_or_future_own_message_is_acquired_without_backfill_callback(app_client,monkeypatch,delta):
    app,client=app_client
    service=app.state.service
    now=int(time.time())
    monkeypatch.setattr(time,'time',lambda:now)
    subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':['message.sent']})
    identifier='true_'+CHAT+'_OUTSIDE'
    service.store.ingest(message(identifier,CHAT,from_me=True,timestamp=now-delta))
    assert service.store.message(identifier) is not None
    assert service.store.state()['deliveries']=={}
