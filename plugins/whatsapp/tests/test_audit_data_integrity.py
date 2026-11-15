"""WA-04/05/06 boundaries, using only synthetic archives and callback transport."""
from contextlib import contextmanager
import json
import time

import pytest

from conftest import message, subscribe
from sally_whatsapp import visibility
from sally_whatsapp.event_recovery import EventRecovery
from sally_whatsapp.events import CallbackError
from sally_whatsapp.store import Store, EVENT_REFS_REPAIR_KEY, canonical
from test_linked_device_visibility import edited, event
from test_revocation_schema8 import event_id

PN='15550111111@c.us'
LID='15550222222@lid'
OTHER='15550333333@c.us'
MID=f'false_{PN}_SOURCE'
MARKER='synthetic quoted material'


def revoked(identifier=MID, *, chat=None):
    return {'id':'revoke-'+identifier+'-'+str(chat),'event':'message.revoked',
            'payload':{'revokedMessageId':identifier,**({'chatId':chat} if chat else {})}}


def retained(store, identifier):
    with store.db() as db:
        return json.loads(db.execute('SELECT data FROM account_events WHERE id=?',(identifier,)).fetchone()[0])


@pytest.mark.parametrize('method',['search','chats'])
def test_global_visibility_uses_chat_index_and_bounded_sql_work(tmp_path,monkeypatch,method):
    store=Store(tmp_path/'archive.sqlite')
    with store.db() as db:
        db.executemany('INSERT INTO chats VALUES(?,NULL)',[(f'{i+10000}@c.us',) for i in range(100)])
        db.executemany('INSERT INTO messages VALUES(?,?,NULL,?,0,?,NULL,0,?,0)',[
            (f'false_{i%100+10000}@c.us_M{i}',f'{i%100+10000}@c.us',i,'Synthetic body','test')
            for i in range(10000)])
    store.search()  # Prepare cursor signing state outside the measured reads.
    original=store.db
    instructions=[]
    plans=[]

    @contextmanager
    def measured():
        with original() as db:
            db.set_progress_handler(lambda:instructions.append(1000) and 0,1000)
            yield db

    monkeypatch.setattr(store,'db',measured)
    before=getattr(store,method)(limit=50)
    baseline=sum(instructions)
    with original() as db:
        visibility.apply(db,[{'kind':'message','chat_id':OTHER,'raw_id':str(i),
            'from_me':False,'reason':'deleted_for_me','event_at':20000} for i in range(1000)],Store._canonical_chat)
        plans=[row[3] for row in db.execute('EXPLAIN QUERY PLAN SELECT id FROM messages m WHERE '+visibility.visible_sql())]
    instructions.clear()
    after=getattr(store,method)(limit=50)
    assert after[method if method=='chats' else 'messages']==before[method if method=='chats' else 'messages']
    assert any('SEARCH v USING AUTOMATIC' in item and '(chat_id=?)' in item for item in plans),plans
    # Count VM instructions, not wall time: unrelated exclusions add linear
    # materialization work rather than 10,000 repeated scans of 1,000 records.
    assert sum(instructions)<baseline*2
    assert len(after['chats' if method=='chats' else 'messages'])==50
    if method=='search':
        page=store.search(limit=50,cursor=after['next_cursor'])
        assert not {m['id'] for m in after['messages']} & {m['id'] for m in page['messages']}


def queued_alias_event(app_client,name):
    app,client=app_client
    service=app.state.service
    filters={'all_chats':True}
    if name=='whatsapp.event': filters['event_types']=['message.edited']
    subscription=subscribe(client,name=name,arguments=filters)['result']['id']
    if name=='message.received': service.store.ingest(message(f'false_{LID}_SOURCE',LID))
    else: service.store.ingest(edited('SOURCE',chat=LID,when=int(time.time())))
    return service,subscription


@pytest.mark.parametrize('name',['message.received','whatsapp.event'])
@pytest.mark.parametrize('outcome',['http_503','ambiguous_timeout'])
@pytest.mark.parametrize('binding',['pending','sending'])
def test_alias_binding_preserves_attempted_callback_bytes(app_client,monkeypatch,name,outcome,binding):
    service,_=queued_alias_event(app_client,name)
    sent=[]

    def callback(url,body,headers):
        sent.append((body,headers))
        if len(sent)==1:
            if binding=='sending': service.store.bind_chat_alias(LID,PN)
            if outcome=='ambiguous_timeout': raise CallbackError('synthetic timeout after receipt')
            return 503,b''
        return 200,b''

    monkeypatch.setattr(service.events.transport,'post',callback)
    assert service.events.dispatch_one()
    if binding=='pending': service.store.bind_chat_alias(LID,PN)
    with service.store.db() as db:
        row=db.execute('SELECT * FROM deliveries').fetchone()
        assert row['attempts']==1 and row['state']=='pending'
        assert row['body'].encode()==sent[0][0]
        db.execute('UPDATE deliveries SET next_attempt=0')
    assert service.events.dispatch_one()
    assert len(sent)==2 and sent[0][0]==sent[1][0]
    assert json.loads(sent[1][0])['data']['chat_id']==LID
    assert service.store.state()['deliveries']=={'accepted':1}


@pytest.mark.parametrize('name',['message.received','whatsapp.event'])
def test_unattempted_alias_notification_uses_resolved_chat(app_client,name):
    service,_=queued_alias_event(app_client,name)
    service.store.bind_chat_alias(LID,PN)
    with service.store.db() as db:
        row=db.execute('SELECT * FROM deliveries').fetchone()
        assert row['attempts']==0 and json.loads(row['body'])['data']['chat_id']==PN


@pytest.mark.parametrize('name',['message.received','whatsapp.event'])
def test_administrative_retry_recognizes_verified_alias_without_rewriting_body(app_client,name):
    service,subscription=queued_alias_event(app_client,name)
    with service.store.db() as db:
        db.execute("UPDATE deliveries SET state='failed',attempts=?,last_status=503",(service.settings.max_callback_attempts,))
        old=dict(db.execute('SELECT * FROM deliveries').fetchone())
    service.store.bind_chat_alias(LID,PN)
    recovery=EventRecovery(service.store,service.settings)
    preview=recovery.preview(subscription,[old['id']])
    assert preview['eligible']
    recovery.execute(subscription,[old['id']],fingerprint=preview['fingerprint'],request_id='synthetic-alias-retry')
    assert service.events.dispatch_one()
    delivered=service.events.transport.requests[-1][1]
    assert delivered==old['body'].encode()
    with service.store.db() as db:
        db.execute("UPDATE deliveries SET state='failed',last_status=503")
        body=json.loads(old['body'])
        body['data']['chat_id']=OTHER
        db.execute('UPDATE deliveries SET body=?',(canonical(body),))
    assert recovery.preview(subscription,[old['id']])['deliveries'][0]['reason']=='source_changed'


@pytest.mark.parametrize('quote_id',['SOURCE',MID])
@pytest.mark.parametrize('early',[True,False])
@pytest.mark.parametrize('permanent',[True,False])
def test_quote_removal_checks_retained_json_both_orders_and_restart(tmp_path,quote_id,early,permanent):
    store=Store(tmp_path/'archive.sqlite')
    store.ingest(message(MID,PN))
    removal=revoked() if permanent else event('DeleteForMe',chat=PN,raw='SOURCE')
    item=edited('OTHER',chat=PN,quote={'id':quote_id,'body':MARKER,'unknownContent':MARKER})
    if early: store.ingest(removal)
    store.ingest(item)
    if not early: store.ingest(removal)
    assert MARKER not in canonical(store.account_event(event_id(item))['data'])
    for instance in (store,Store(store.path)):
        data=retained(instance,event_id(item))
        assert data['body']=='Synthetic edited body'
        assert (MARKER in canonical(data)) is not permanent
        if permanent: assert data['replyTo']=={'id':quote_id,'content_state':'revoked'}


@pytest.mark.parametrize('quote_id',['SOURCE',f'false_{LID}_SOURCE'])
def test_late_quote_alias_binding_removes_retained_payload_without_original_row(tmp_path,quote_id):
    store=Store(tmp_path/'archive.sqlite')
    item=edited('OTHER',chat=LID,quote={'id':quote_id,'body':MARKER})
    store.ingest(item)
    store.ingest(revoked('SOURCE',chat=PN))
    assert MARKER in canonical(retained(store,event_id(item)))
    store.bind_chat_alias(LID,PN)
    data=retained(store,event_id(item))
    assert data['body']=='Synthetic edited body'
    assert data['replyTo']=={'id':quote_id,'content_state':'revoked'}
    assert retained(Store(store.path),event_id(item))==data


def test_quote_refs_are_scoped_bounded_and_nested_revocation_preserves_outer_content(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    quote={'id':'OUTER','body':'independent quote','replyTo':{'id':'SOURCE','body':MARKER}}
    item=edited('OTHER',chat=PN,quote=quote)
    store.ingest(item)
    store.ingest(revoked('SOURCE',chat=OTHER))
    assert retained(store,event_id(item))['replyTo']==quote
    store.ingest(revoked('SOURCE',chat=PN))
    saved=retained(store,event_id(item))['replyTo']
    assert saved['body']=='independent quote' and saved['replyTo']=={'id':'SOURCE','content_state':'revoked'}
    deep={'id':'LEAF','body':'unreachable'}
    for n in range(12): deep={'id':'LEVEL'+str(n),'replyTo':deep}
    item=edited('DEEP',chat=PN,quote=deep)
    store.ingest(item)
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM event_source_refs WHERE event_id=? AND role LIKE 'quote:%'",(event_id(item),)).fetchone()[0]==9
    assert 'unreachable' not in canonical(retained(store,event_id(item)))


def test_new_checkpoint_repairs_existing_completed_v1_quote_rows_only_on_admission(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    item=edited('OTHER',chat=PN,quote={'id':'SOURCE','body':MARKER})
    store.ingest(item)
    store.ingest(revoked('SOURCE',chat=PN))
    with store.db() as db:
        # Reproduce a schema-eight database already prepared by the old decoder.
        db.execute('UPDATE account_events SET data=? WHERE id=?',(canonical(item['payload']),event_id(item)))
        db.execute("DELETE FROM event_source_refs WHERE role LIKE 'quote:%'")
        db.execute('DELETE FROM state WHERE key=?',(EVENT_REFS_REPAIR_KEY,))
        Store._state(db,'private:event_source_refs:v1',{'complete':True,'after':2,'through':2})
    checked=Store(store.path,migrate_schema=False)
    assert MARKER in canonical(retained(checked,event_id(item)))
    assert MARKER not in canonical(checked.account_event(event_id(item))['data'])
    restarted=Store(store.path)
    assert retained(restarted,event_id(item))['replyTo']=={'id':'SOURCE','content_state':'revoked'}
    with restarted.db() as db:
        assert json.loads(db.execute('SELECT value FROM state WHERE key=?',(EVENT_REFS_REPAIR_KEY,)).fetchone()[0])['complete']
        assert db.execute('PRAGMA user_version').fetchone()[0]==8
        assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'


@pytest.mark.parametrize('bind_early',[True,False])
def test_group_quote_participant_alias_does_not_revoke_another_participant(tmp_path,bind_early):
    store=Store(tmp_path/'archive.sqlite')
    group='15550444444@g.us'
    if bind_early: store.bind_chat_alias(LID,PN)
    selected=edited('SELECTED',chat=group,quote={'id':f'false_{group}_SOURCE_{LID}','body':MARKER})
    independent=edited('INDEPENDENT',chat=group,quote={'id':f'false_{group}_SOURCE_{OTHER}','body':MARKER})
    store.ingest(selected)
    store.ingest(independent)
    store.ingest(revoked(f'false_{group}_SOURCE_{PN}'))
    if not bind_early: store.bind_chat_alias(LID,PN)
    assert MARKER not in canonical(retained(store,event_id(selected)))
    assert MARKER in canonical(retained(store,event_id(independent)))


def test_quote_v2_checkpoint_commits_each_batch_and_resumes_after_interruption(tmp_path,monkeypatch):
    store=Store(tmp_path/'archive.sqlite')
    items=[edited('TARGET'+str(n),chat=PN,quote={'id':'SOURCE','body':MARKER}) for n in range(205)]
    for item in items: store.ingest(item)
    store.ingest(revoked('SOURCE',chat=PN))
    with store.db() as db:
        db.executemany('UPDATE account_events SET data=? WHERE id=?',
                       [(canonical(item['payload']),event_id(item)) for item in items])
        db.execute("DELETE FROM event_source_refs WHERE role LIKE 'quote:%'")
        db.execute('DELETE FROM state WHERE key=?',(EVENT_REFS_REPAIR_KEY,))
        Store._state(db,'private:event_source_refs:v1',{'complete':True,'after':206,'through':206})
    original=Store._save_event_references
    count=0

    def interrupt(self,db,row,data):
        nonlocal count
        count+=1
        if count==101: raise RuntimeError('synthetic interruption')
        return original(self,db,row,data)

    with monkeypatch.context() as patch:
        patch.setattr(Store,'_save_event_references',interrupt)
        with pytest.raises(RuntimeError,match='synthetic interruption'): store._repair_event_references()
    with store.db() as db:
        progress=json.loads(db.execute('SELECT value FROM state WHERE key=?',(EVENT_REFS_REPAIR_KEY,)).fetchone()[0])
        assert progress['after']==100 and not progress['complete']
        assert db.execute('SELECT count(*) FROM account_events WHERE data LIKE ?',('%'+MARKER+'%',)).fetchone()[0]==105
    restarted=Store(store.path)
    with restarted.db() as db:
        assert db.execute('SELECT count(*) FROM account_events WHERE data LIKE ?',('%'+MARKER+'%',)).fetchone()[0]==0
        assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        assert not db.execute('PRAGMA foreign_key_check').fetchall()
