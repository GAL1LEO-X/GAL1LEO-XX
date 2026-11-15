from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import sqlite3
import sys
from threading import Barrier
import time

import pytest

from conftest import call,message,subscribe
from sally_whatsapp import cli,event_recovery
from sally_whatsapp.event_recovery import EventRecovery
from sally_whatsapp.store import Store,canonical


def failed(app_client,identifiers=('recover-1',),status=503):
    app,client=app_client
    service=app.state.service
    sub=subscribe(client)['result']['id']
    for identifier in identifiers: service.store.ingest(message(identifier))
    with service.store.db() as db:
        db.execute("UPDATE deliveries SET state='failed',attempts=?,last_status=?",(service.settings.max_callback_attempts,status))
        ids=[row[0] for row in db.execute('SELECT id FROM deliveries ORDER BY id')]
    return service,EventRecovery(service.store,service.settings),sub,ids


def rows(store):
    with store.db() as db: return [dict(row) for row in db.execute('SELECT * FROM deliveries ORDER BY id')]


@pytest.mark.parametrize('status',[0,408,429,500,503])
def test_preview_execute_one_extra_attempt_preserves_identity_and_audit(app_client,status):
    service,recovery,sub,ids=failed(app_client,status=status)
    original=rows(service.store)
    preview=recovery.preview(sub,ids)
    assert preview['eligible'] and preview['fingerprint']
    assert rows(service.store)==original
    queued=recovery.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='recovery-request-1')
    assert queued['delivery_confirmed'] is False
    current=rows(service.store)
    assert len(current)==1 and current[0]['state']=='pending'
    assert [(row['id'],row['event_id'],row['body'],row['attempts']) for row in current]==[(row['id'],row['event_id'],row['body'],row['attempts']) for row in original]
    with service.store.db() as db:
        assert event_recovery.attempt_limit(db,ids[0])==original[0]['attempts']+1
    restarted=EventRecovery(Store(service.store.path,migrate_schema=False),service.settings)
    assert restarted.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='recovery-request-1')==queued
    service.events.transport.responses=[(503,b'')]
    assert service.events.dispatch_one()
    assert not service.events.dispatch_one()
    after=rows(service.store)[0]
    assert after['state']=='failed' and after['attempts']==original[0]['attempts']+1
    assert restarted.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='recovery-request-1')==queued
    assert rows(service.store)[0]==after
    audit=restarted.audit('recovery-request-1')
    assert audit['execution']==queued and audit['current_deliveries'][0]['attempts']==after['attempts']
    exposed=canonical(audit)+canonical(preview)+canonical(queued)
    assert original[0]['body'] not in exposed and 'Riunione' not in exposed and 'receiver.example' not in exposed
    assert not any(key.startswith(event_recovery.PREFIX) for key in service.store.state())


@pytest.mark.parametrize('state,status,attempts,reason',[
    ('accepted',204,8,'state_not_recoverable'),('cancelled',503,8,'state_not_recoverable'),
    ('pending',503,8,'state_not_recoverable'),('sending',503,8,'state_not_recoverable'),
    ('failed',410,8,'terminal_status'),('failed',413,8,'terminal_status'),
    ('failed',403,8,'terminal_status'),('failed',302,8,'terminal_status'),
    ('failed',None,8,'terminal_status'),('failed',503,1,'attempts_not_exhausted')])
def test_non_recoverable_states_and_statuses_never_requeue(app_client,state,status,attempts,reason):
    service,recovery,sub,ids=failed(app_client)
    with service.store.db() as db:
        db.execute('UPDATE deliveries SET state=?,last_status=?,attempts=?',(state,status,attempts))
    before=rows(service.store)
    preview=recovery.preview(sub,ids)
    assert not preview['eligible'] and preview['fingerprint'] is None
    assert preview['deliveries'][0]['reason']==reason
    with pytest.raises(ValueError): recovery.execute(sub,ids,fingerprint='0'*64,request_id='blocked-request')
    assert rows(service.store)==before


@pytest.mark.parametrize('change',['revocation','unsubscribe','expiry','owner','renewal','accepted','body','source','age'])
def test_preview_invalidated_by_concurrent_change_atomically(app_client,change):
    service,recovery,sub,ids=failed(app_client,('recover-1','recover-2'))
    preview=recovery.preview(sub,ids)
    with service.store.db() as db:
        if change=='revocation': db.execute("INSERT INTO message_mutations VALUES('recover-2','revoked',NULL,?)",(time.time(),))
        elif change=='unsubscribe': db.execute('UPDATE subscriptions SET active=0')
        elif change=='expiry': db.execute('UPDATE subscriptions SET expires=0')
        elif change=='owner': db.execute("UPDATE subscriptions SET owner='different-owner'")
        elif change=='renewal': db.execute('UPDATE subscriptions SET expires=expires+1')
        elif change=='accepted': db.execute("UPDATE deliveries SET state='accepted' WHERE id=?",(ids[1],))
        elif change=='body': db.execute("UPDATE deliveries SET body=replace(body,'Riunione','Changed') WHERE id=?",(ids[1],))
        elif change=='source': db.execute("UPDATE messages SET body='changed' WHERE id='recover-2'")
        elif change=='age': db.execute("UPDATE messages SET timestamp=1 WHERE id='recover-2'")
    before=rows(service.store)
    with pytest.raises(ValueError): recovery.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='atomic-recovery')
    assert rows(service.store)==before
    with pytest.raises(ValueError,match='Unknown'): recovery.audit('atomic-recovery')
    assert all(row['state']!='pending' for row in rows(service.store))


@pytest.mark.parametrize('same_request',[True,False])
def test_concurrent_execution_has_one_commit_and_persistent_dedup(app_client,same_request):
    service,recovery,sub,ids=failed(app_client)
    preview=recovery.preview(sub,ids)
    barrier=Barrier(2)
    def execute(index):
        barrier.wait(timeout=5)
        instance=EventRecovery(Store(service.store.path,migrate_schema=False),service.settings)
        try: return instance.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='parallel-'+str(0 if same_request else index))
        except ValueError: return None
    with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(execute,range(2)))
    assert len([result for result in results if result])==(2 if same_request else 1)
    if same_request: assert results[0]==results[1]
    assert rows(service.store)[0]['attempts']==service.settings.max_callback_attempts
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM state WHERE key LIKE ?',(event_recovery.PREFIX+'%',)).fetchone()[0]==1


def test_request_binding_budget_and_private_capability(app_client,monkeypatch):
    service,recovery,sub,ids=failed(app_client,('recover-1','recover-2'))
    monkeypatch.setattr(event_recovery,'MAX_REQUESTS',1)
    preview=recovery.preview(sub,[ids[0]])
    queued=recovery.execute(sub,[ids[0]],fingerprint=preview['fingerprint'],request_id='bounded-request')
    assert recovery.preview(sub,[ids[1]])['deliveries'][0]['reason']=='audit_capacity_reached'
    assert recovery.execute(sub,[ids[0]],fingerprint=preview['fingerprint'],request_id='bounded-request')==queued
    with pytest.raises(ValueError,match='different recovery'):
        recovery.execute(sub,[ids[1]],fingerprint=preview['fingerprint'],request_id='bounded-request')
    other=EventRecovery(service.store,replace(service.settings,owner_subject='different-owner'))
    assert other.preview(sub,ids)['deliveries']==[{'delivery_id':identifier,'eligible':False,'reason':'subscription_unavailable'} for identifier in ids]
    with pytest.raises(ValueError,match='Unknown'): other.audit('bounded-request')
    status=call(app_client[1],'connection_status')['result']['structuredContent']
    assert not status['event_replay_supported'] and status['local_event_recovery']['available']
    assert 'bounded-request' not in canonical(status) and event_recovery.PREFIX not in canonical(status)


def test_expired_missing_changed_and_unsupported_sources_are_rejected(app_client):
    service,recovery,sub,ids=failed(app_client)
    with service.store.db() as db:
        row=db.execute('SELECT body FROM deliveries').fetchone()
        body=json.loads(row[0]);body['timestamp']='2000-01-01T00:00:00Z'
        db.execute('UPDATE deliveries SET body=?',(canonical(body),))
    assert recovery.preview(sub,ids)['deliveries'][0]['reason']=='event_expired'
    with service.store.db() as db:
        db.execute("UPDATE subscriptions SET name='message.digest'")
    assert recovery.preview(sub,ids)['deliveries'][0]['reason']=='unsupported_event'


def test_account_event_can_recover_without_exposing_content(app_client):
    app,client=app_client;service=app.state.service
    sub=subscribe(client,name='whatsapp.event',arguments={'all_chats':True,'event_types':['message.edited']})['result']['id']
    now=time.time()
    service.store.ingest({'id':'synthetic-edit','event':'message.edited','timestamp':now,'payload':{'editedMessageId':'not-yet-imported','body':'private current content'}})
    with service.store.db() as db:
        db.execute("UPDATE deliveries SET state='failed',attempts=?,last_status=503",(service.settings.max_callback_attempts,))
        identifier=db.execute('SELECT id FROM deliveries').fetchone()[0]
    recovery=EventRecovery(service.store,service.settings)
    preview=recovery.preview(sub,[identifier])
    assert preview['eligible']
    result=recovery.execute(sub,[identifier],fingerprint=preview['fingerprint'],request_id='account-recovery')
    assert 'private current content' not in canonical(result)


def test_cli_preview_execute_and_audit_do_not_issue_http(app_client,monkeypatch,capsys):
    service,recovery,sub,ids=failed(app_client)
    monkeypatch.setattr(cli.Settings,'load',lambda path:service.settings)
    calls=len(service.events.transport.requests)
    argv=['sally-whatsapp','--config','synthetic.toml','event-recovery']
    selection=['--subscription',sub,'--delivery-id',str(ids[0])]
    monkeypatch.setattr(sys,'argv',argv+['preview']+selection)
    cli.main();preview=json.loads(capsys.readouterr().out)
    monkeypatch.setattr(sys,'argv',argv+['execute']+selection+['--fingerprint',preview['fingerprint'],'--request-id','cli-recovery'])
    cli.main();queued=json.loads(capsys.readouterr().out)
    monkeypatch.setattr(sys,'argv',argv+['audit','--request-id','cli-recovery'])
    cli.main();audit=json.loads(capsys.readouterr().out)
    assert audit['execution']==queued and len(service.events.transport.requests)==calls


def test_cli_recovery_refuses_legacy_schema_without_migration(environment,monkeypatch):
    from test_revocation_and_live_events import legacy_database
    settings=environment[0];legacy_database(settings.database)
    with sqlite3.connect(settings.database) as db: before='\n'.join(db.iterdump())
    monkeypatch.setattr(cli.Settings,'load',lambda path:settings)
    monkeypatch.setattr(sys,'argv',['sally-whatsapp','--config','synthetic.toml','event-recovery','preview','--subscription','sub_'+'a'*64,'--delivery-id','1'])
    with pytest.raises(RuntimeError,match='schema upgrade required'): cli.main()
    with sqlite3.connect(settings.database) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==6 and '\n'.join(db.iterdump())==before


def test_fault_before_ledger_commit_rolls_back_queue_and_attempt_permit(app_client,monkeypatch):
    service,recovery,sub,ids=failed(app_client,('recover-1','recover-2'))
    preview=recovery.preview(sub,ids)
    original=rows(service.store)
    write=service.store._state
    def failing_write(db,key,value):
        if key.startswith(event_recovery.PREFIX): raise RuntimeError('synthetic commit failure')
        write(db,key,value)
    monkeypatch.setattr(service.store,'_state',failing_write)
    with pytest.raises(RuntimeError,match='synthetic commit failure'):
        recovery.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='interrupted-request')
    assert rows(service.store)==original
    with service.store.db() as db:
        assert all(event_recovery.attempt_limit(db,identifier) is None for identifier in ids)
    with pytest.raises(ValueError,match='Unknown'): recovery.audit('interrupted-request')


@pytest.mark.parametrize('identifiers',[[],list(range(1,22)),[1,1],[True],[-1],[2**63],['1']])
def test_selection_is_explicit_and_bounded(app_client,identifiers):
    _,recovery,sub,_=failed(app_client)
    with pytest.raises(ValueError): recovery.preview(sub,identifiers)


def test_expiry_rechecked_after_waiting_for_database_write_lock(app_client,monkeypatch):
    from threading import Event
    service,recovery,sub,ids=failed(app_client)
    preview=recovery.preview(sub,ids)
    now=time.time();waiting=Event()
    def execute():
        waiting.set()
        return recovery.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='waited-request')
    with service.store.db() as locked:
        locked.execute('BEGIN IMMEDIATE')
        with ThreadPoolExecutor(max_workers=1) as pool:
            job=pool.submit(execute)
            assert waiting.wait(timeout=5)
            monkeypatch.setattr(event_recovery.time,'time',lambda:now+service.settings.subscription_ttl+1)
            locked.commit()
            with pytest.raises(ValueError): job.result(timeout=5)
    assert rows(service.store)[0]['state']=='failed'


@pytest.mark.parametrize('extra',[
    {'sender_ids':['person@c.us']},{'mention_ids':['person@c.us']},{'attachments':'with'},
    {'text_all':['Riunione']},{'text_any':['Riunione']},{'text_none':['ignore']},
    {'digest_window_seconds':60},{'future_policy':True}])
def test_advanced_or_unknown_content_filters_fail_closed(app_client,extra):
    service,recovery,sub,ids=failed(app_client)
    with service.store.db() as db:
        filters=json.loads(db.execute('SELECT filters FROM subscriptions').fetchone()[0])
        db.execute('UPDATE subscriptions SET filters=?',(canonical({**filters,**extra}),))
    preview=recovery.preview(sub,ids)
    assert not preview['eligible'] and preview['deliveries'][0]['reason']=='unsupported_filters'


def test_quiet_hours_binding_is_retained_for_worker_without_extending_expiry(app_client):
    service,recovery,sub,ids=failed(app_client)
    with service.store.db() as db:
        filters=json.loads(db.execute('SELECT filters FROM subscriptions').fetchone()[0])
        filters['quiet_hours']={'timezone':'Europe/Berlin','start':'22:00','end':'08:00'}
        db.execute('UPDATE subscriptions SET filters=?',(canonical(filters),))
        expires=db.execute('SELECT expires FROM subscriptions').fetchone()[0]
    preview=recovery.preview(sub,ids)
    assert preview['eligible']
    recovery.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='quiet-hours-recovery')
    with service.store.db() as db:
        row=db.execute('SELECT filters,expires FROM subscriptions').fetchone()
        assert json.loads(row['filters'])==filters and row['expires']==expires


def test_accepted_delivery_never_requeued_by_a_repeated_administrative_request(app_client):
    service,recovery,sub,ids=failed(app_client)
    preview=recovery.preview(sub,ids)
    first=recovery.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='successful-recovery')
    assert service.events.dispatch_one()
    assert rows(service.store)[0]['state']=='accepted'
    requests=len(service.events.transport.requests)
    assert recovery.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='successful-recovery')==first
    assert not recovery.preview(sub,ids)['eligible']
    assert not service.events.dispatch_one() and len(service.events.transport.requests)==requests


def test_worker_attempt_limit_survives_larger_global_budget(app_client):
    service,recovery,sub,ids=failed(app_client)
    preview=recovery.preview(sub,ids)
    recovery.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='global-budget-change')
    service.events.settings=replace(service.settings,max_callback_attempts=20)
    service.events.transport.responses=[(503,b'')]
    assert service.events.dispatch_one()
    assert rows(service.store)[0]['state']=='failed'
    assert rows(service.store)[0]['attempts']==service.settings.max_callback_attempts+1
    assert not service.events.dispatch_one(now=time.time()+3600)


def test_worker_claim_crash_consumes_permit_without_automatic_resend(app_client):
    service,recovery,sub,ids=failed(app_client)
    preview=recovery.preview(sub,ids)
    recovery.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='interrupted-worker')
    transport=service.events.transport
    class Crash:
        def post(self,*args): raise RuntimeError('synthetic process crash after claim')
    service.events.transport=Crash()
    with pytest.raises(RuntimeError,match='synthetic process crash'): service.events.dispatch_one()
    assert rows(service.store)[0]['state']=='sending'
    service.events.transport=transport
    requests=len(transport.requests)
    assert service.events.dispatch_one(now=time.time()+121)
    assert rows(service.store)[0]['state']=='failed'
    assert rows(service.store)[0]['last_status']==0
    assert len(transport.requests)==requests
    assert not service.events.dispatch_one(now=time.time()+122)


@pytest.mark.parametrize('change',['age','source','revocation','unsubscribe','expiry','policy'])
def test_worker_rechecks_recovered_delivery_before_callback(app_client,change):
    service,recovery,sub,ids=failed(app_client)
    preview=recovery.preview(sub,ids)
    recovery.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='worker-recheck')
    now=time.time()
    with service.store.db() as db:
        if change=='source': db.execute("UPDATE messages SET body='changed' WHERE id='recover-1'")
        elif change=='revocation': db.execute("INSERT INTO message_mutations VALUES('recover-1','revoked',NULL,?)",(now,))
        elif change=='unsubscribe': db.execute('UPDATE subscriptions SET active=0')
        elif change=='expiry': db.execute('UPDATE subscriptions SET expires=0')
        elif change=='policy': db.execute('UPDATE subscriptions SET filters=?',(canonical({'all_chats':True,'sender_ids':['other@c.us']}),))
        else: service.events.settings=replace(service.settings,event_max_age_seconds=60)
    requests=len(service.events.transport.requests)
    service.events.dispatch_one(now=now+61 if change=='age' else now)
    assert len(service.events.transport.requests)==requests
    row=rows(service.store)[0]
    assert row['state']=='cancelled' and row['attempts']==service.settings.max_callback_attempts


@pytest.mark.parametrize('change',['source','policy','revocation'])
def test_recovered_delivery_rechecks_source_and_policy_after_claim(app_client,monkeypatch,change):
    service,recovery,sub,ids=failed(app_client)
    preview=recovery.preview(sub,ids)
    recovery.execute(sub,ids,fingerprint=preview['fingerprint'],request_id='post-claim-change')
    receiver=service.events.transport
    initial=len(receiver.requests)
    decrypt=service.events.cipher.decrypt
    changed=False
    def change_after_claim(value):
        nonlocal changed
        if not changed:
            changed=True
            if change=='source':
                service.store.ingest({'id':'changed-after-claim','event':'message.edited',
                    'payload':{'editedMessageId':'recover-1','body':'current source changed'}})
            elif change=='revocation':
                service.store.ingest({'id':'revoked-after-claim','event':'message.revoked',
                    'payload':{'revokedMessageId':'recover-1'}})
            else:
                with service.store.db() as db:
                    old=json.loads(db.execute('SELECT filters FROM subscriptions WHERE id=?',(sub,)).fetchone()[0])
                    db.execute('UPDATE subscriptions SET filters=? WHERE id=?',
                        (canonical({**old,'sender_ids':['other@c.us']}),sub))
        return decrypt(value)
    monkeypatch.setattr(service.events.cipher,'decrypt',change_after_claim)
    assert service.events.dispatch_one()
    assert len(receiver.requests)==initial
    with service.store.db() as db:
        row=db.execute('SELECT state,attempts FROM deliveries WHERE id=?',(ids[0],)).fetchone()
        assert row['state']=='cancelled' and row['attempts']==service.settings.max_callback_attempts+1
