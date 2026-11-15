import json
import time

from conftest import call, message, rpc, subscribe


def change(kind, identifier, payload):
    return {'event':kind,'id':identifier,'session':'default','timestamp':int(time.time()*1000), 'payload':payload}


def test_edits_and_revokes_update_search_without_new_message_notifications(app_client):
    app,client=app_client
    store=app.state.service.store
    store.ingest(message('original',text='obsolete content'))
    subscribe(client)
    store.ingest(change('message.edited','edit-1',{'editedMessageId':'original','from':'group-1@g.us','fromMe':False,'body':'updated content','timestamp':100}))
    assert store.search('obsolete')['messages']==[]
    assert store.search('updated')['messages'][0]['body']=='updated content'
    assert store.state()['deliveries']=={}
    store.ingest(change('message.revoked','delete-1',{'revokedMessageId':'original','before':'malformed optional field'}))
    assert store.message('original') is None
    assert store.search('updated')['messages']==[]
    assert store.chats()['chats'][0]['archived_messages']==0


def test_event_type_chat_filter_deduplication_safe_payload_and_unsubscribe(app_client):
    app,client=app_client
    store=app.state.service.store
    params={'name':'whatsapp.event','arguments':{'chat_ids':['group-1@g.us'],'event_types':['group.v2.update','message.reaction']}}
    first=subscribe(client,**params)['result']['id']
    params['arguments']['event_types'].reverse()
    assert subscribe(client,**params)['result']['id']==first
    event=change('group.v2.update','group-change-1',{'group':{'id':'group-1@g.us','subject':'Synthetic group'},'_data':{'secret':'hidden'},'mediaKey':'hidden','nested':{'token':'hidden'}})
    assert store.ingest(event)['recorded'] is True
    assert store.ingest(event)['duplicate'] is True
    store.ingest(change('group.v2.update','other-group',{'group':{'id':'group-2@g.us'}}))
    store.ingest(change('message.ack','wrong-type',{'from':'group-1@g.us','id':'another'}))
    assert store.state()['deliveries']=={'pending':1}
    listed=call(client,'list_account_events',{'event_types':['group.v2.update'],'chat_id':'group-1@g.us'})['result']['structuredContent']['events']
    assert len(listed)==1
    detail=call(client,'get_account_event',{'event_id':listed[0]['id']})['result']['structuredContent']['event']
    assert 'hidden' not in json.dumps(detail)
    assert detail['data']['group']['subject']=='Synthetic group'
    with store.db() as db:
        body=json.loads(db.execute('SELECT body FROM deliveries').fetchone()[0])
    assert set(body['data'])=={'event_id','event_type','chat_id'}
    params['delivery']={'mode':'webhook','url':'https://receiver.example/callback'}
    assert rpc(client,'events/unsubscribe',params)['result']['resultType']=='complete'
    assert store.state()['active_subscriptions']==0


def test_session_events_never_store_authentication_challenges(app_client):
    app,client=app_client
    store=app.state.service.store
    subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':['session.status']})
    store.ingest(change('session.status','auth-change',{'status':'PASSKEY_REQUIRED','challenge':'secret-authentication-data','qr':'secret-qr'}))
    items=store.list_account_events()['events']
    detail=store.account_event(items[0]['id'])
    assert detail['data']=={'status':'PASSKEY_REQUIRED'}
    assert store.state()['deliveries']=={'pending':1}


def test_generic_events_require_explicit_types(app_client):
    _,client=app_client
    params={'name':'whatsapp.event','arguments':{'all_chats':True},'delivery':{'mode':'webhook','url':'https://receiver.example/callback','secret':'whsec_'+'eA=='}}
    assert rpc(client,'events/subscribe',params,expected_status=400)['error']['code']==-32602


def test_history_reports_unsupported_channel_without_losing_regular_chats(environment):
    from dataclasses import replace
    from sally_whatsapp.server import Service
    settings,receiver,gateway,_=environment
    service=Service(replace(settings,live_account_enabled=True),gateway=gateway,event_transport=receiver)
    gateway.messages=lambda *args,**kwargs:[]
    job=service.history.start('test-owner','history-mixed-0001',['1@newsletter','group-1@g.us'],until=200)
    for _ in range(3): service.history.process_one()
    status=service.history.status(job['id'],'test-owner')
    assert status['state']=='completed' and status['completed_chats']==1
    assert len(status['skipped_chats'])==1 and status['history_complete'] is False
