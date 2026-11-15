"""Synthetic policy, durable aggregation and calendar tests; no network callbacks."""
import base64
from datetime import datetime
import hashlib
import json
import time

import pytest

from conftest import message, rpc, subscribe
from sally_whatsapp.event_policies import Filters, message_mentions, normalize_filters, quiet_until
from sally_whatsapp.server import Service
from sally_whatsapp.store import canonical
from test_revocation_and_live_events import revoke

LEGACY = {'chat_ids':['group-1@g.us'], 'all_chats':False, 'contains':'', 'event_types':[]}


def deliveries(store):
    with store.db() as db:
        return [dict(r) for r in db.execute('SELECT * FROM deliveries ORDER BY id')]


def batch(client, **changes):
    return subscribe(client, name='message.digest', arguments={**LEGACY, 'digest_window_seconds':60, **changes})


def rejected(client, arguments, name='message.received'):
    return rpc(client,'events/subscribe',{'name':name,'arguments':arguments,
        'delivery':{'mode':'webhook','url':'https://receiver.example/callback','secret':'whsec_'+base64.b64encode(b'x'*32).decode()}},expected_status=400)


def direct_subscribe(service, filters, name='message.received'):
    return service.events.subscribe('test-owner', name, filters, {'url':'https://receiver.example/callback',
        'secret':'whsec_'+base64.b64encode(b'x'*32).decode()})


def instant(text):
    return datetime.fromisoformat(text).timestamp()


def test_legacy_identity_and_explicit_neutral_defaults(app_client):
    app, client = app_client
    service = app.state.service
    expected = 'sub_' + hashlib.sha256(canonical(['test-owner','message.received',LEGACY,'https://receiver.example/callback']).encode()).hexdigest()
    first = subscribe(client)['result']['id']
    assert first == expected
    service.store.ingest(message())
    explicit = subscribe(client, arguments=Filters(**LEGACY).model_dump())['result']['id']
    assert explicit == expected
    assert len(deliveries(service.store)) == 1
    with service.store.db() as db:
        assert json.loads(db.execute('SELECT filters FROM subscriptions').fetchone()[0]) == LEGACY
    assert rpc(client,'events/unsubscribe',{'name':'message.received','arguments':Filters(**LEGACY).model_dump(),
        'delivery':{'mode':'webhook','url':'https://receiver.example/callback'}})['result']['resultType'] == 'complete'
    assert deliveries(service.store)[0]['state'] == 'cancelled'


@pytest.mark.parametrize('changes', [
    {'sender_ids':['Display Name']}, {'mention_ids':['@12345']}, {'text_any':['']},
    {'text_all':['x'*201]}, {'text_none':['x']*21}, {'sender_ids':['12345@c.us']*101},
    {'attachments':'image'}, {'quiet_hours':{'timezone':'invalid/synthetic','start':'22:00','end':'08:00'}},
    {'quiet_hours':{'timezone':'UTC','start':'08:00','end':'08:00'}},
    {'quiet_hours':{'timezone':'UTC','start':'24:00','end':'08:00'}},
    {'digest_window_seconds':59}, {'digest_window_seconds':True},
])
def test_invalid_filters_fail_before_challenge(app_client, environment, changes):
    _, client = app_client
    assert 'error' in rejected(client, {**LEGACY, **changes})
    assert not environment[1].requests


def test_generic_rejects_message_policies(app_client):
    _, client = app_client
    for field in ({'text_any':['hello']}, {'quiet_hours':{'timezone':'UTC','start':'22:00','end':'08:00'}}, {'digest_window_seconds':60}):
        assert 'error' in rejected(client, {**LEGACY,'event_types':['message.edited'],**field}, name='whatsapp.event')
    assert 'error' in rejected(client, {**LEGACY,'digest_window_seconds':0}, name='message.digest')


@pytest.mark.parametrize('kind', ['extendedTextMessage','imageMessage','videoMessage','documentMessage','audioMessage','stickerMessage'])
def test_primary_mentions_only(kind):
    real = {'_data':{'Message':{kind:{'contextInfo':{'mentionedJID':['12345@s.whatsapp.net','67890@lid']}}}}}
    assert message_mentions(real) == {'12345@c.us','67890@lid'}
    assert not message_mentions({'body':'@12345', 'mentions':['12345@c.us']})
    assert not message_mentions({'_data':{'Message':{kind:{'contextInfo':{'quotedMessage':real['_data']['Message']}}}}})
    assert not message_mentions({'_data':{'Message':{kind:{'contextInfo':{'mentionedJid':['12345@c.us']}}}}})
    assert not message_mentions({'_data':{'Message':{kind:{'contextInfo':{'mentionedJID':['12345@c.us']*1001}}}}})


@pytest.mark.parametrize('attachments,media,expected', [('with',True,1),('with',False,0),('without',True,0),('without',False,1),('any',True,1)])
def test_filter_intersection_structured_identity_alias_literal(app_client, attachments, media, expected):
    app, client = app_client
    store = app.state.service.store
    store.bind_chat_alias('67890@lid','12345@c.us')
    assert 'result' in subscribe(client, arguments={**LEGACY,'sender_ids':['12345@c.us'],'mention_ids':['12345@c.us'],
        'attachments':attachments,'contains':'urgente','text_all':['STRASSE','[ok]'], 'text_any':['A+B','other'], 'text_none':['nope']})
    incoming = message(text='Urgente Straße [ok] a+b')
    incoming['payload'].update(participant='67890@lid',hasMedia=media,
        _data={'Message':{'extendedTextMessage':{'contextInfo':{'mentionedJID':['67890@lid']}}}})
    store.ingest(incoming)
    assert len(deliveries(store)) == expected
    # No private engine blob is retained in the message archive.
    with store.db() as db:
        assert '_data' not in str(db.execute('SELECT * FROM messages').fetchone()[:])
    for n, change in enumerate([{'participant':'Display Name'}, {'participant':None}, {'body':'urgente strasse [ok] a+b NOPE'},
                               {'_data':{},'body':'urgente strasse [ok] a+b @12345'}]):
        item = json.loads(json.dumps(incoming)); item.update(id='receipt-'+str(n)); item['payload'].update(id='negative-'+str(n), **change)
        store.ingest(item)
    assert len(deliveries(store)) == expected


def test_direct_sender_filter_does_not_use_group_or_display_name(app_client):
    app, client = app_client
    assert 'result' in subscribe(client, arguments={'all_chats':True,'sender_ids':['12345@c.us']})
    for number, chat in enumerate(['12345@c.us','12345@g.us','67890@c.us']):
        item=message(str(number), chat); item['payload']['pushName']='12345@c.us'
        app.state.service.store.ingest(item)
    assert len(deliveries(app.state.service.store)) == 1


def test_digest_chunking_restart_dedup_and_no_early_flush(app_client, environment, monkeypatch):
    app, client = app_client
    now=int(time.time()//60)*60+1
    monkeypatch.setattr(time,'time',lambda:now)
    store=app.state.service.store
    assert 'result' in batch(client)
    for n in range(101):
        item=message('batch-'+str(n)); store.ingest(item); store.ingest(item)
    rows=deliveries(store)
    assert [len(json.loads(row['body'])['data']['message_ids']) for row in rows]==[50,50,1]
    assert [row['state'] for row in rows]==['collecting']*3
    assert store.state()['deliveries']['collecting']==3
    second=Service(environment[0],gateway=environment[2],event_transport=environment[1])
    assert not second.events.dispatch_one(now=now+58)
    for _ in rows: assert second.events.dispatch_one(now=now+59)
    assert not second.events.dispatch_one(now=now+59)
    posted=[json.loads(r[1]) for r in environment[1].requests if json.loads(r[1]).get('name')=='message.digest']
    assert len(posted)==3
    assert sum((p['data']['message_ids'] for p in posted),[])==['batch-'+str(n) for n in range(101)]
    assert all(set(p['data'])=={'message_ids'} for p in posted)


@pytest.mark.parametrize('action', ['unsubscribe','expiry','wrong-owner','revoke'])
def test_collecting_terminal_lifecycle(app_client, action, monkeypatch):
    app,client=app_client; service=app.state.service
    now=int(time.time()//60)*60+1; monkeypatch.setattr(time,'time',lambda:now)
    batch(client); service.store.ingest(message())
    if action=='unsubscribe':
        service.events.unsubscribe('test-owner','message.digest',{**LEGACY,'digest_window_seconds':60},'https://receiver.example/callback')
    elif action=='revoke': service.store.ingest(revoke('synthetic-1'))
    else:
        with service.store.db() as db:
            db.execute('UPDATE subscriptions SET '+('expires=0' if action=='expiry' else "owner='other'"))
    assert not service.events.dispatch_one(now=now+60)
    assert deliveries(service.store)[0]['state']=='cancelled'
    batch(client)
    assert deliveries(service.store)[0]['state']=='cancelled'


def test_digest_revoked_members_removed_before_first_attempt(app_client, monkeypatch):
    app,client=app_client; service=app.state.service
    now=int(time.time()//60)*60+1; monkeypatch.setattr(time,'time',lambda:now)
    batch(client)
    service.store.ingest(message('a')); service.store.ingest(message('b')); service.store.ingest(revoke('a'))
    assert json.loads(deliveries(service.store)[0]['body'])['data']['message_ids']==['b']
    assert service.events.dispatch_one(now=now+60)
    assert deliveries(service.store)[0]['state']=='accepted'
    service.store.ingest(revoke('b'))
    row=deliveries(service.store)[0]
    assert row['state']=='accepted' and not json.loads(row['body'])['data']['message_ids']


@pytest.mark.parametrize('during', [False,True])
def test_digest_revocation_after_attempt_cancels_without_reaggregating(app_client, environment, monkeypatch, during):
    app,client=app_client; service=app.state.service
    now=int(time.time()//60)*60+1; monkeypatch.setattr(time,'time',lambda:now)
    batch(client); service.store.ingest(message('a')); service.store.ingest(message('b'))
    if during:
        def callback(*args):
            service.store.ingest(revoke('a')); return 503,b''
        monkeypatch.setattr(environment[1],'post',callback)
    else: environment[1].responses.append((503,b''))
    assert service.events.dispatch_one(now=now+60)
    if not during: service.store.ingest(revoke('a'))
    rows=deliveries(service.store)
    assert len(rows)==1 and rows[0]['state']=='cancelled'
    assert json.loads(rows[0]['body'])['data']['message_ids']==['b']
    assert 'digest_cancelled_after_attempt' in service.store.state()['recovery_reasons']
    assert not service.events.dispatch_one(now=now+600)


def test_revoked_chunk_identity_never_reused(app_client, monkeypatch):
    app,client=app_client; service=app.state.service
    now=int(time.time()//60)*60+1; monkeypatch.setattr(time,'time',lambda:now)
    batch(client); service.store.ingest(message('a')); service.store.ingest(revoke('a')); service.store.ingest(message('b'))
    rows=deliveries(service.store)
    assert rows[0]['event_id']!=rows[1]['event_id']
    assert rows[0]['state']=='cancelled' and rows[1]['state']=='collecting'


@pytest.mark.parametrize('start,end,stamp,expected', [
    ('22:00','08:00','2026-10-12T21:30:00+00:00','2026-10-13T06:00:00+00:00'),
    ('22:00','08:00','2026-10-12T06:00:00+00:00','2026-10-12T06:00:00+00:00'),
    ('01:00','03:30','2026-03-29T00:30:00+00:00','2026-03-29T01:30:00+00:00'),
    ('01:00','02:30','2026-03-29T00:30:00+00:00','2026-03-29T01:00:00+00:00'),
    ('01:00','03:00','2026-10-25T00:30:00+00:00','2026-10-25T02:00:00+00:00'),
    ('02:00','02:30','2026-10-25T00:10:00+00:00','2026-10-25T00:30:00+00:00'),
    ('02:00','02:30','2026-10-25T01:10:00+00:00','2026-10-25T01:30:00+00:00'),
    ('23:30','00:15','2026-10-12T21:59:30+00:00','2026-10-12T22:15:00+00:00'),
])
def test_quiet_hours_dst_boundaries(start,end,stamp,expected):
    assert quiet_until(instant(stamp),{'timezone':'Europe/Berlin','start':start,'end':end})==instant(expected)


def test_quiet_hours_defer_retry_and_respect_expiry(app_client, environment, monkeypatch):
    app,client=app_client; service=app.state.service
    now=instant('2026-10-12T20:59:30+00:00'); monkeypatch.setattr(time,'time',lambda:now)
    q={'timezone':'UTC','start':'21:00','end':'21:02'}
    direct_subscribe(service, {**LEGACY,'quiet_hours':q})
    service.store.ingest(message()); environment[1].responses.append((503,b''))
    assert service.events.dispatch_one(now=now)
    assert service.events.dispatch_one(now=now+60)  # gate advances due; no HTTP
    assert len(environment[1].requests)==2  # challenge + first attempt
    row=deliveries(service.store)[0]
    assert row['attempts']==1 and row['next_attempt']==instant('2026-10-12T21:02:00+00:00')
    with service.store.db() as db: db.execute('UPDATE subscriptions SET expires=?',(now+100,))
    assert not service.events.dispatch_one(now=now+150)
    assert deliveries(service.store)[0]['state']=='cancelled'


def test_digest_rotated_secret_refresh_preserves_collecting(app_client, environment, monkeypatch):
    app,client=app_client; service=app.state.service
    now=int(time.time()//60)*60+1; monkeypatch.setattr(time,'time',lambda:now)
    first=batch(client)['result']['id']; service.store.ingest(message())
    refreshed=subscribe(client,name='message.digest',arguments={**LEGACY,'digest_window_seconds':60},
        delivery={'mode':'webhook','url':'https://receiver.example/callback','secret':'whsec_'+base64.b64encode(b'y'*32).decode()})
    assert refreshed['result']['id']==first
    assert len(deliveries(service.store))==1
    assert service.events.dispatch_one(now=now+59)
    assert len(environment[1].requests[-1][2]['webhook-signature'].split())==2


def test_event_expiry_is_not_extended_by_quiet_hours(app_client, monkeypatch):
    app,client=app_client; service=app.state.service
    now=instant('2026-10-12T20:00:00+00:00'); monkeypatch.setattr(time,'time',lambda:now)
    service.store.event_max_age_seconds=60
    direct_subscribe(service,{**LEGACY,'quiet_hours':{'timezone':'UTC','start':'20:00','end':'20:02'}})
    service.store.ingest(message())
    assert service.events.dispatch_one(now=now+120)
    assert deliveries(service.store)[0]['state']=='cancelled'
    assert 'callback_event_outside_age_window' in service.store.state()['recovery_reasons']


def test_digest_history_and_own_messages_excluded(app_client):
    app,client=app_client; store=app.state.service.store
    batch(client); store.ingest(message('historical'),historical=True); store.ingest(message('own',from_me=True))
    assert not deliveries(store)
    store.ingest(message('historical')); store.ingest(message('historical'))
    assert len(json.loads(deliveries(store)[0]['body'])['data']['message_ids'])==1


def test_discovery_additive_no_tool_operation_growth(app_client):
    _,client=app_client
    names=[e['name'] for e in rpc(client,'events/list')['result']['events']]
    assert names==['message.received','whatsapp.event','message.digest']
    assert len(rpc(client,'tools/list')['result']['tools'])==27


def test_digest_window_cannot_equal_event_age(app_client, environment):
    _,client=app_client
    assert 'error' in rejected(client,{**LEGACY,'digest_window_seconds':86400},name='message.digest')
    assert not environment[1].requests


def test_quiet_hours_checked_again_after_claim_before_http(app_client, environment, monkeypatch):
    app,_=app_client; service=app.state.service
    now=instant('2026-10-12T21:59:59+00:00'); monkeypatch.setattr(time,'time',lambda:now)
    direct_subscribe(service,{**LEGACY,'quiet_hours':{'timezone':'UTC','start':'22:00','end':'22:02'}})
    service.store.ingest(message())
    decrypt=service.events.cipher.decrypt
    def cross_boundary(value):
        monkeypatch.setattr(time,'time',lambda:now+2)
        return decrypt(value)
    monkeypatch.setattr(service.events.cipher,'decrypt',cross_boundary)
    assert service.events.dispatch_one(now=now)
    row=deliveries(service.store)[0]
    assert row['state']=='pending' and row['attempts']==0
    assert row['next_attempt']==instant('2026-10-12T22:02:00+00:00')
    assert len(environment[1].requests)==1


def test_digest_quiet_window_and_expired_renewal_no_resurrection(app_client, environment, monkeypatch):
    app,_=app_client; service=app.state.service
    now=instant('2026-10-12T20:00:01+00:00'); monkeypatch.setattr(time,'time',lambda:now)
    filters={**LEGACY,'digest_window_seconds':60,'quiet_hours':{'timezone':'UTC','start':'20:00','end':'20:05'}}
    sub=direct_subscribe(service,filters,'message.digest')
    service.store.ingest(message('a'))
    assert not service.events.dispatch_one(now=now+100)
    assert deliveries(service.store)[0]['next_attempt']==instant('2026-10-12T20:05:00+00:00')
    with service.store.db() as db: db.execute('UPDATE subscriptions SET expires=0')
    assert direct_subscribe(service,filters,'message.digest')['id']==sub['id']
    service.store.ingest(message('b'))
    assert [r['state'] for r in deliveries(service.store)]==['cancelled','collecting']
    assert service.events.dispatch_one(now=now+300)
    posted=json.loads(environment[1].requests[-1][1])
    assert posted['data']['message_ids']==['b']


def test_digest_retry_body_is_immutable_and_lease_survives_restart(app_client, environment, monkeypatch):
    app,client=app_client; service=app.state.service
    now=int(time.time()//60)*60+1; monkeypatch.setattr(time,'time',lambda:now)
    batch(client); service.store.ingest(message())
    environment[1].responses.append((503,b''))
    assert service.events.dispatch_one(now=now+60)
    first=environment[1].requests[-1][1]
    with service.store.db() as db: db.execute("UPDATE deliveries SET state='sending',lease_until=?",(now+120,))
    second=Service(environment[0],gateway=environment[2],event_transport=environment[1])
    assert not second.events.dispatch_one(now=now+110)
    assert second.events.dispatch_one(now=now+121)
    assert first==environment[1].requests[-1][1]
    assert deliveries(service.store)[0]['attempts']==2


def test_digest_payload_bytes_bounded_without_early_flush(app_client, monkeypatch):
    app,client=app_client; service=app.state.service
    now=int(time.time()//60)*60+1; monkeypatch.setattr(time,'time',lambda:now)
    batch(client)
    for n in range(3):
        item=message(str(n)+'x'*100000); item['id']='bounded-receipt-'+str(n); service.store.ingest(item)
    rows=deliveries(service.store)
    assert len(rows)==2
    assert all(len(row['body'].encode())<=262144 and row['state']=='collecting' for row in rows)
    item=message('x'*300000); item['id']='too-large-receipt'; service.store.ingest(item)
    assert len(deliveries(service.store))==2
    assert 'event_payload_too_large' in service.store.state()['recovery_reasons']


def test_malformed_attachment_flag_never_matches_presence_filter(app_client):
    app,client=app_client
    subscribe(client,arguments={**LEGACY,'attachments':'with'})
    item=message(); item['payload']['hasMedia']='false'
    app.state.service.store.ingest(item)
    assert not deliveries(app.state.service.store)


def test_digest_pending_first_attempt_revocation_and_tombstone_before_message(app_client, monkeypatch):
    app,client=app_client; service=app.state.service
    now=int(time.time()//60)*60+1; monkeypatch.setattr(time,'time',lambda:now)
    batch(client); service.store.ingest(revoke('never')); service.store.ingest(message('never'))
    assert not deliveries(service.store)
    service.store.ingest(message('a')); service.store.ingest(message('b'))
    with service.store.db() as db: db.execute("UPDATE deliveries SET state='pending'")
    service.store.ingest(revoke('a'))
    assert deliveries(service.store)[0]['state']=='pending'
    assert service.events.dispatch_one(now=now+60)
    assert json.loads(deliveries(service.store)[0]['body'])['data']['message_ids']==['b']


def test_digest_collection_cancelled_by_tenant_suspend(app_client, tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path
    from types import SimpleNamespace
    import sqlite3
    app,client=app_client; service=app.state.service
    batch(client); service.store.ingest(message())
    # The administrative function is tested against a fresh synthetic copy;
    # service-management commands and auth backup are stubs, never host actions.
    copied=tmp_path/'suspend'; copied.mkdir()
    with service.store.db() as source, sqlite3.connect(copied/'archive.sqlite') as target:
        source.backup(target)
    spec=importlib.util.spec_from_file_location('synthetic_tenant_admin',Path(__file__).parents[1]/'scripts/tenant_admin.py')
    admin=importlib.util.module_from_spec(spec); spec.loader.exec_module(admin)
    auth=tmp_path/'auth'; auth.mkdir()
    (auth/'users.yml').write_text(json.dumps({'users':{'synthetic':{'disabled':False}}}))
    monkeypatch.setattr(admin,'AUTH_CONFIG',auth)
    monkeypatch.setattr(admin,'auth_backup',lambda *_:None)
    monkeypatch.setattr(admin,'write_private',lambda path,data,**kwargs:path.write_text(data))
    monkeypatch.setattr(admin,'run',lambda *args,**kwargs:None)
    instance=SimpleNamespace(slug='synthetic',username='synthetic',base='synthetic',state_dir=copied,wrapper=copied/'wrapper')
    from test_tenant_database import suspend_fixture
    monkeypatch.setattr(admin,'suspend_tenant_database',suspend_fixture)
    admin.change_enabled(instance,False); admin.change_enabled(instance,True)
    with sqlite3.connect(copied/'archive.sqlite') as db:
        assert db.execute('SELECT state FROM deliveries').fetchone()[0]=='cancelled'
        assert db.execute('SELECT active FROM subscriptions').fetchone()[0]==0


def test_clock_regression_does_not_send_future_event(app_client, monkeypatch):
    app,client=app_client; service=app.state.service
    now=time.time(); monkeypatch.setattr(time,'time',lambda:now)
    subscribe(client); service.store.ingest(message(timestamp=int(now)))
    with service.store.db() as db: db.execute('UPDATE deliveries SET next_attempt=0')
    assert service.events.dispatch_one(now=now-60)
    assert deliveries(service.store)[0]['state']=='cancelled'
    assert 'callback_event_outside_age_window' in service.store.state()['recovery_reasons']


@pytest.mark.parametrize('attempted', [False, True])
def test_digest_age_prunes_only_before_first_http(app_client, environment, monkeypatch, attempted):
    app,client=app_client; service=app.state.service
    now=int(time.time()//60)*60+1; monkeypatch.setattr(time,'time',lambda:now)
    service.store.event_max_age_seconds=120
    batch(client)
    service.store.ingest(message('old',timestamp=now-110))
    service.store.ingest(message('fresh',timestamp=now))
    initial=deliveries(service.store)[0]
    if attempted:
        # A prior attempt is deliberately synthetic; no payload is sent early.
        with service.store.db() as db: db.execute("UPDATE deliveries SET state='pending',attempts=1")
    assert service.events.dispatch_one(now=now+59)
    row=deliveries(service.store)[0]
    assert row['event_id']==initial['event_id']
    if attempted:
        assert row['state']=='cancelled' and row['body']==initial['body']
        assert len(environment[1].requests)==1
    else:
        assert row['state']=='accepted'
        assert json.loads(environment[1].requests[-1][1])['data']['message_ids']==['fresh']
    assert 'callback_event_outside_age_window' in service.store.state()['recovery_reasons']


@pytest.mark.parametrize('event_name', ['message.received','message.digest'])
def test_event_age_checked_again_after_claim_before_http(app_client, environment, monkeypatch, event_name):
    app,client=app_client; service=app.state.service
    now=int(time.time()//60)*60+1; monkeypatch.setattr(time,'time',lambda:now)
    service.store.event_max_age_seconds=120
    if event_name=='message.digest': batch(client)
    else: subscribe(client)
    service.store.ingest(message(timestamp=now-60))
    decrypt=service.events.cipher.decrypt
    def cross_boundary(value):
        monkeypatch.setattr(time,'time',lambda:now+61)
        return decrypt(value)
    monkeypatch.setattr(service.events.cipher,'decrypt',cross_boundary)
    before=deliveries(service.store)[0]['body']
    assert service.events.dispatch_one(now=now+59)
    row=deliveries(service.store)[0]
    assert row['state']=='cancelled' and row['body']==before
    assert len(environment[1].requests)==1
    assert 'callback_event_outside_age_window' in service.store.state()['recovery_reasons']
