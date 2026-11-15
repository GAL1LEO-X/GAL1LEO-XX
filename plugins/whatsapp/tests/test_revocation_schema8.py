"""Pinned WAHA payload shapes, local HMAC/MCP, and restartable schema-eight repair."""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
import sqlite3
import time

import pytest

from conftest import call, message, subscribe
from sally_whatsapp.event_recovery import EventRecovery
from sally_whatsapp.server import Service
from sally_whatsapp.store import Store, SCHEMA_7, EVENT_REFS_REPAIR_KEY, canonical

PN='393331112222@c.us'
LID='555001@lid'
MID=f'false_{PN}_SOURCE1'
MARKER='synthetic-choice-only'


def derivative(kind='poll.vote', suffix=''):
    # devlikeapro/waha@90ba445a: session.gows.core.ts toPollVotePayload /
    # toEventResponsePayload. Neither fixture invents an event title/body.
    key={'id':MID,'from':PN,'fromMe':False}
    own=f'false_{PN}_DERIVATIVE1'
    if kind.startswith('poll.'):
        payload={'poll':key,'vote':{'id':own,'from':PN,'fromMe':False,'to':None,
                   'participant':None,'selectedOptions':[MARKER],'timestamp':int(time.time()*1000)}}
        if kind.endswith('.failed'): payload['vote']['selectedOptions']=None
    else:
        payload={'id':own,'timestamp':int(time.time()),'from':PN,'fromMe':False,'to':None,
                 'participant':None,'body':None,'hasMedia':False,'media':None,
                 'eventCreationKey':key,'eventResponse':{'response':'GOING','timestampMs':int(time.time()*1000),'extraGuestCount':3}}
        if kind.endswith('.failed'): payload['eventResponse']=None
    return {'id':'event-'+kind+suffix,'event':kind,'timestamp':int(time.time()*1000),'payload':payload}


def revoke(identifier=MID):
    return {'id':'revoke-'+identifier,'event':'message.revoked','timestamp':int(time.time()*1000),
            'payload':{'revokedMessageId':identifier}}


def webhook(service,client,envelope):
    body=canonical({'session':'default',**envelope}).encode()
    response=client.post('/webhooks/waha',content=body,headers={
        'content-type':'application/json','x-webhook-hmac-algorithm':'sha512',
        'x-webhook-hmac':hmac.digest(service.webhook_key,body,'sha512').hex()})
    assert response.status_code==200,response.text
    return response.json()


def event_id(envelope):
    return 'change_'+hashlib.sha256(envelope['id'].encode()).hexdigest()


@pytest.mark.parametrize('early',[False,True])
def test_delete_for_me_resolves_validated_lid_through_signed_webhook(app_client,early):
    app,client=app_client
    service=app.state.service
    lookups=[]
    service.gateway.phone_for_lid=lambda lid:lookups.append(lid) or PN
    delete={'event':'engine.event','engine':'GOWS','id':'engine-delete','session':'default',
            'payload':{'event':'events.DeleteForMe','session':'default','data':{
                'ChatJID':LID,'MessageID':'SOURCE1','IsFromMe':False,'SenderJID':'',
                'Timestamp':datetime.now(timezone.utc).isoformat(),'FromFullSync':False,'Action':{}}}}
    if early: webhook(service,client,delete)
    webhook(service,client,message(MID,PN,text=MARKER))
    if not early: webhook(service,client,delete)
    assert lookups==[LID]
    assert webhook(service,client,delete)=={'duplicate':True}
    assert call(client,'get_message',{'message_id':MID})['result']['structuredContent']['message'] is None
    assert not service.store.search(MARKER)['messages']
    with service.store.db() as db:
        assert db.execute('SELECT body,deleted FROM messages WHERE id=?',(MID,)).fetchone()[:]==(MARKER,0)
    restarted=Service(service.settings,gateway=service.gateway,event_transport=service.events.transport)
    assert restarted.store.message_state(MID)['state']=='deleted_for_me'


@pytest.mark.parametrize('kind',['poll.vote','poll.vote.failed','event.response','event.response.failed'])
@pytest.mark.parametrize('early',[False,True])
@pytest.mark.parametrize('role',['target','self'])
def test_typed_derivative_revocations_before_after_and_restart(app_client,kind,early,role):
    app,client=app_client
    service=app.state.service
    original=message(MID,PN,text='independent-original')
    webhook(service,client,original)
    item=derivative(kind)
    target=MID if role=='target' else f'false_{PN}_DERIVATIVE1'
    if early: webhook(service,client,revoke(target))
    webhook(service,client,item)
    if not early: webhook(service,client,revoke(target))
    assert webhook(service,client,item)=={'duplicate':True}
    expected={'message_id':target,'revoked':True}
    assert call(client,'get_account_event',{'event_id':event_id(item)})['result']['structuredContent']['event']['data']==expected
    with service.store.db() as db:
        assert json.loads(db.execute('SELECT data FROM account_events WHERE id=?',(event_id(item),)).fetchone()[0])==expected
        refs=db.execute('SELECT role,resolution FROM event_source_refs WHERE event_id=? ORDER BY role',(event_id(item),)).fetchall()
        assert [tuple(r) for r in refs]==[('self','resolved'),('target','resolved')]
    restarted=Store(service.store.path)
    assert restarted.account_event(event_id(item))['data']==expected
    if role=='self': assert restarted.message(MID) is not None


@pytest.mark.parametrize('kind',['poll.vote','event.response'])
def test_valid_derivatives_preserved_and_unknown_fields_never_become_sources(tmp_path,kind):
    store=Store(tmp_path/'archive.sqlite')
    item=derivative(kind)
    item['payload']['unrelated_text']='false_399999999999@c.us_REVOKED'
    store.ingest(revoke('false_399999999999@c.us_REVOKED'))
    store.ingest(item)
    assert store.account_event(event_id(item))['data']==item['payload']
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM event_source_refs WHERE event_id=?',(event_id(item),)).fetchone()[0]==2


def test_unresolved_target_withholds_only_ambiguous_event_and_does_not_mark_revoked(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    valid=derivative('poll.vote','-valid')
    invalid=derivative('poll.vote','-invalid')
    invalid['payload']['poll']['id']={'unexpected':'shape'}
    store.ingest(valid);store.ingest(invalid)
    assert store.account_event(event_id(valid))['data']==valid['payload']
    data=store.account_event(event_id(invalid))['data']
    assert data=={'message_id':None,'unavailable':True,'reason':'source_reference_unresolved'}
    assert store.message_state(MID)['state']=='unknown'
    with store.db() as db:
        assert json.loads(db.execute('SELECT data FROM account_events WHERE id=?',(event_id(invalid),)).fetchone()[0])==invalid['payload']
    store.ingest(revoke(f'false_{PN}_DERIVATIVE1'))
    assert store.account_event(event_id(invalid))['data']=={'message_id':f'false_{PN}_DERIVATIVE1','revoked':True}


def test_revocation_notification_delivered_and_recovery_permitted(app_client):
    app,client=app_client
    service=app.state.service
    subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':['message.revoked']})
    webhook(service,client,revoke())
    with service.store.db() as db:
        row=db.execute('SELECT * FROM deliveries').fetchone()
        db.execute("UPDATE deliveries SET state='failed',attempts=?,last_status=503 WHERE id=?",(service.settings.max_callback_attempts,row['id']))
    recovery=EventRecovery(service.store,service.settings)
    preview=recovery.preview(row['subscription'],[row['id']])
    assert preview['eligible']
    recovery.execute(row['subscription'],[row['id']],fingerprint=preview['fingerprint'],request_id='synthetic-recovery-0001')
    assert service.events.dispatch_one()
    posted=[json.loads(body) for _,body,_ in service.events.transport.requests if json.loads(body).get('type')!='verification']
    assert len(posted)==1 and posted[0]['data']['event_type']=='message.revoked'
    assert posted[0]['eventId']==event_id(revoke())
    assert posted[0]['data']=={'event_id':posted[0]['eventId'],'event_type':'message.revoked',
                               'chat_id':PN,'message_id':MID}
    assert call(client,'get_message',{'message_id':posted[0]['data']['message_id']})['result']['structuredContent']['message'] is None
    assert service.store.state()['deliveries']=={'accepted':1}


def test_legacy_schema7_null_refs_read_defensively_and_backfill_bounded(tmp_path,monkeypatch):
    path=tmp_path/'archive.sqlite'
    with sqlite3.connect(path) as db:
        db.executescript(SCHEMA_7)
        db.execute("INSERT INTO message_mutations VALUES(?,'revoked',NULL,?)",(MID,time.time()))
        for n in range(205):
            item=derivative('poll.vote',str(n))
            db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,NULL)',
                       (event_id(item),item['event'],PN,time.time()-90*86400,canonical(item['payload'])))
        # Structural migration alone is not admission/preparation.
        from pathlib import Path
        db.executescript((Path(__file__).parents[1]/'sally_whatsapp/migrations/7-8.sql').read_text())
    checked=Store(path,migrate_schema=False)
    assert checked.account_event(event_id(derivative('poll.vote','0')))['data']=={'message_id':MID,'revoked':True}
    with checked.db() as db:
        assert not db.execute('SELECT 1 FROM event_source_refs').fetchone()
    original=Store._save_event_references
    count=0
    def interrupt(self,db,row,data):
        nonlocal count
        count+=1
        if count==101: raise RuntimeError('synthetic-interruption')
        return original(self,db,row,data)
    monkeypatch.setattr(Store,'_save_event_references',interrupt)
    with pytest.raises(RuntimeError,match='synthetic-interruption'): checked._prepare_serving()
    with checked.db() as db:
        progress=json.loads(db.execute('SELECT value FROM state WHERE key=?',(EVENT_REFS_REPAIR_KEY,)).fetchone()[0])
        assert progress['after']==100 and progress['complete'] is False
        assert db.execute('SELECT count(DISTINCT event_id) FROM event_source_refs').fetchone()[0]==100
    monkeypatch.setattr(Store,'_save_event_references',original)
    restarted=Store(path)
    with restarted.db() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==8
        assert db.execute('SELECT count(DISTINCT event_id) FROM event_source_refs').fetchone()[0]==205
        assert all(json.loads(row[0])=={'message_id':MID,'revoked':True} for row in db.execute('SELECT data FROM account_events'))
        assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        assert not db.execute('PRAGMA foreign_key_check').fetchall()
    restarted._prepare_serving()


def test_same_provider_ids_do_not_cross_tenants_and_raw_scopes(tmp_path):
    first,second=Store(tmp_path/'first.sqlite'),Store(tmp_path/'second.sqlite')
    item=derivative()
    for store in (first,second):store.ingest(item)
    first.ingest({'id':'raw-revoke','event':'message.revoked','payload':{'revokedMessageId':'SOURCE1','chatId':PN}})
    assert first.account_event(event_id(item))['data']=={'message_id':MID,'revoked':True}
    assert second.account_event(event_id(item))['data']==item['payload']


@pytest.mark.parametrize('bind_early',[True,False])
def test_event_alias_rebind_scrubs_refs_even_without_acquired_message(tmp_path,bind_early):
    store=Store(tmp_path/'archive.sqlite')
    item=derivative('event.response')
    item['payload']['eventCreationKey']={'id':f'false_{LID}_SOURCE1','from':LID,'fromMe':False}
    if bind_early: store.bind_chat_alias(LID,PN)
    store.ingest(item)
    store.ingest(revoke())
    if not bind_early: store.bind_chat_alias(LID,PN)
    value=store.account_event(event_id(item))['data']
    assert value=={'message_id':f'false_{LID}_SOURCE1','revoked':True}
    with store.db() as db:
        target=db.execute("SELECT message_id,canonical_id,chat_id FROM event_source_refs WHERE event_id=? AND role='target'",(event_id(item),)).fetchone()
        assert tuple(target)==(f'false_{LID}_SOURCE1',MID,PN)
        assert json.loads(db.execute('SELECT data FROM account_events WHERE id=?',(event_id(item),)).fetchone()[0])==value


def test_fresh_and_schema7_upgrade_have_same_behavior_and_schema(tmp_path,monkeypatch):
    fresh=Store(tmp_path/'fresh.sqlite')
    legacy=tmp_path/'legacy.sqlite'
    item=derivative('event.response')
    with sqlite3.connect(legacy) as db:
        db.executescript(SCHEMA_7)
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,NULL)',
                   (event_id(item),item['event'],PN,time.time(),canonical(item['payload'])))
        db.execute("INSERT INTO message_mutations VALUES(?,'revoked',NULL,?)",(MID,time.time()))
    fresh.ingest(item);fresh.ingest(revoke())
    upgraded=Store(legacy)
    assert upgraded.account_event(event_id(item))['data']==fresh.account_event(event_id(item))['data']
    for store in (fresh,upgraded):
        store.ingest(message(MID,PN,text='late-synthetic-content'),historical=True)
        assert store.message(MID) is None and store.search('late-synthetic-content')['messages']==[]
    with fresh.db() as a,upgraded.db() as b:
        from pathlib import Path
        monkeypatch.syspath_prepend(str(Path(__file__).parents[1]/'scripts'))
        from release_database import schema
        assert schema(a)==schema(b)
        refs='SELECT role,message_id,canonical_id,chat_id,resolution FROM event_source_refs WHERE event_id=? ORDER BY role'
        assert [tuple(row) for row in a.execute(refs,(event_id(item),))]==[tuple(row) for row in b.execute(refs,(event_id(item),))]


def test_missing_revocation_target_never_exposes_before_payload(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    item={'id':'missing-revoke-target','event':'message.revoked','payload':{'before':{'body':MARKER}}}
    store.ingest(item)
    assert store.account_event(event_id(item))['data']=={'unavailable':True,'reason':'revocation_target_unavailable'}
    with store.db() as db:
        assert MARKER not in db.execute('SELECT data FROM account_events WHERE id=?',(event_id(item),)).fetchone()[0]


@pytest.mark.parametrize('kind',['poll.vote','event.response'])
def test_local_exclusion_projection_retains_refs_for_later_permanent_revocation(tmp_path,kind):
    store=Store(tmp_path/'archive.sqlite')
    from test_linked_device_visibility import event
    store.ingest(event('DeleteForMe',chat=PN,raw='SOURCE1'))
    item=derivative(kind)
    store.ingest(item)
    assert store.account_event(event_id(item))['data']=={'message_id':MID,'unavailable':True}
    with store.db() as db:
        assert json.loads(db.execute('SELECT data FROM account_events WHERE id=?',(event_id(item),)).fetchone()[0])==item['payload']
    store.ingest(revoke())
    assert store.account_event(event_id(item))['data']=={'message_id':MID,'revoked':True}
    with store.db() as db:
        assert json.loads(db.execute('SELECT data FROM account_events WHERE id=?',(event_id(item),)).fetchone()[0])=={'message_id':MID,'revoked':True}


@pytest.mark.parametrize('kind',['poll.vote','event.response'])
def test_local_exclusion_is_only_projection_across_restart_and_late_alias_binding(tmp_path,kind):
    from test_linked_device_visibility import event
    store=Store(tmp_path/'archive.sqlite')
    store.ingest(event('DeleteForMe',chat=LID,raw='SOURCE1'))
    item=derivative(kind)
    store.ingest(item)
    assert store.account_event(event_id(item))['data']==item['payload']
    store.bind_chat_alias(LID,PN)
    assert store.account_event(event_id(item))['data']=={'message_id':MID,'unavailable':True}
    restarted=Store(store.path)
    with restarted.db() as db:
        assert json.loads(db.execute('SELECT data FROM account_events WHERE id=?',(event_id(item),)).fetchone()[0])==item['payload']
        # Synthetic removal of visibility evidence proves reversibility only;
        # there is no new provider or administrative restore operation.
        db.execute("DELETE FROM state WHERE key LIKE 'private:linked_visibility:%'")
    assert restarted.account_event(event_id(item))['data']==item['payload']
    restarted.ingest(revoke())
    with restarted.db() as db:
        assert json.loads(db.execute('SELECT data FROM account_events WHERE id=?',(event_id(item),)).fetchone()[0])=={'message_id':MID,'revoked':True}


@pytest.mark.parametrize('permanent',[False,True])
def test_retained_edit_quote_distinguishes_local_visibility_from_known_revocation(tmp_path,permanent):
    from test_linked_device_visibility import edited,event
    store=Store(tmp_path/'archive.sqlite')
    store.ingest(message(MID,PN,text='synthetic quoted source'))
    store.ingest(revoke() if permanent else event('DeleteForMe',chat=PN,raw='SOURCE1'))
    item=edited('OTHER',chat=PN,quote={'id':'SOURCE1','body':MARKER})
    store.ingest(item)
    public=store.account_event(event_id(item))['data']
    assert MARKER not in canonical(public)
    with store.db() as db:
        retained=json.loads(db.execute('SELECT data FROM account_events WHERE id=?',(event_id(item),)).fetchone()[0])
        assert (MARKER in canonical(retained)) is (not permanent)
        if permanent:
            assert retained['replyTo']=={'id':'SOURCE1','content_state':'revoked'}
        else:
            db.execute("DELETE FROM state WHERE key LIKE 'private:linked_visibility:%'")
    if not permanent:
        assert store.account_event(event_id(item))['data']['replyTo']==item['payload']['replyTo']
