"""Synthetic device state: explicit deletions, no absence-based inference."""
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time

import pytest

from conftest import message,subscribe
from sally_whatsapp.store import Store


CHAT = '15550001111@c.us'
LID = '15550002222@lid'
GROUP = '15550003333@g.us'


def event(kind='DeleteChat', *, chat=CHAT, when=1500, raw='OLD', from_me=False, refs=None, identifier=None):
    data = {'Timestamp': datetime.fromtimestamp(when, timezone.utc).isoformat(),
            'FromFullSync': False}
    if kind == 'DeleteForMe':
        data.update(ChatJID=chat.replace('@c.us','@s.whatsapp.net'), SenderJID='',
                    IsFromMe=from_me, MessageID=raw, Action={'messageTimestamp': 1000})
    else:
        data.update(JID=chat.replace('@c.us','@s.whatsapp.net'), DeleteMedia=False, Action=None)
        if refs is not None:
            data['Action'] = {'messageRange': {'lastMessageTimestamp': 9999, 'messages': [
                {'key': {'remoteJID': data['JID'], 'fromMe': direction, 'ID': mid}, 'timestamp': 1000}
                for mid, direction in refs]}}
    return {'id': identifier or f'{kind}-{chat}-{when}-{raw}', 'event':'engine.event', 'engine':'GOWS',
            'session':'default', 'payload': {'event':'events.'+kind, 'session':'default', 'data':data}}


def acquired(store, raw='OLD', *, chat=CHAT, when=1000, from_me=False, historical=False):
    identifier = f'{str(from_me).lower()}_{chat}_{raw}'
    envelope = message(identifier, chat, timestamp=when, from_me=from_me, text='Synthetic retained content '+raw)
    store.ingest(envelope, historical=historical)
    return identifier


def test_delete_chat_reversible_projection_and_new_activity(tmp_path):
    store = Store(tmp_path/'archive.sqlite')
    old = acquired(store)
    boundary = acquired(store, 'BOUNDARY', when=1500)
    new = acquired(store, 'NEW', when=1600)
    store.ingest(event())
    assert store.message(old) is None
    assert store.message_state(old)['state']=='chat_deleted'
    assert [m['id'] for m in store.search()['messages']]==[new,boundary]
    assert store.chats()['chats'][0]['archived_messages']==2
    # Visibility is not forensic deletion and does not destroy idempotency data.
    with store.db() as db:
        assert db.execute('SELECT body,deleted FROM messages WHERE id=?',(old,)).fetchone()['body']
        assert db.execute('SELECT count(*) FROM message_search WHERE id=?',(old,)).fetchone()[0]==1
        db.execute("DELETE FROM state WHERE key LIKE 'private:linked_visibility:%'")
    assert store.message(old) is not None


def test_clear_chat_unknown_boundary_holds_anchor_without_inventing_cutoff(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    old=acquired(store)
    kept=acquired(store,'KEPT')
    store.ingest(event('ClearChat',refs=[('OLD',False)]))
    assert store.message(old) is None
    assert store.message_state(old)['state']=='clear_chat_coverage_uncertain'
    assert store.message(kept) is not None
    store.ingest(event('ClearChat',when=1700,refs=None))
    assert store.message(kept) is not None
    with store.db() as db:
        metadata=json.loads(db.execute("SELECT data FROM account_events WHERE event_type='chat.cleared' ORDER BY timestamp DESC LIMIT 1").fetchone()[0])
    assert metadata['coverage']=='uncertain'
    assert metadata['clearCoverage']['boundaryUnknown'] is True


@pytest.mark.parametrize('chat', [CHAT,GROUP])
def test_delete_for_me_tuple_direction_and_late_replay(tmp_path,chat):
    store=Store(tmp_path/'archive.sqlite')
    incoming=acquired(store,chat=chat)
    outgoing=acquired(store,chat=chat,from_me=True)
    store.ingest(event('DeleteForMe',chat=chat))
    assert store.message(incoming) is None
    assert store.message(outgoing) is not None
    assert store.message_state(incoming)['state']=='deleted_for_me'
    # A refreshed history page never overrides an explicit state event.
    acquired(store,chat=chat,historical=True)
    assert store.message(incoming) is None
    assert store.search(query='retained')['messages'][0]['id']==outgoing


def test_delete_for_me_outgoing_group_without_sender_does_not_guess_self(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    identifier=f'true_{GROUP}_RAW_15550004444@c.us'
    store.ingest(message(identifier,GROUP,from_me=True,timestamp=1000))
    store.ingest(event('DeleteForMe',chat=GROUP,raw='RAW',from_me=True))
    assert store.message(identifier) is None
    assert store.message_state(identifier)['state']=='deleted_for_me'


@pytest.mark.parametrize('kind',['DeleteChat','ClearChat','DeleteForMe'])
@pytest.mark.parametrize('bind_before',[True,False])
def test_verified_alias_binding_preserves_exclusions(tmp_path,kind,bind_before):
    store=Store(tmp_path/'archive.sqlite')
    alias_message=acquired(store,chat=LID)
    if bind_before: store.bind_chat_alias(LID,CHAT)
    store.ingest(event(kind,chat=LID,refs=[('OLD',False)]))
    if not bind_before: store.bind_chat_alias(LID,CHAT)
    assert store.message(alias_message) is None
    assert store.message_state(alias_message)['state']!='unknown'
    assert store.search(chat_id=LID)['messages']==store.search(chat_id=CHAT)['messages']==[]
    # Different provider ID, same verified chat/raw identity, still excluded.
    phone_message=acquired(store,chat=CHAT)
    assert store.message(phone_message) is None
    assert store.message_state(phone_message)['state']!='unknown'


def test_existing_cursor_and_edit_never_resurrect_excluded_content(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    old=acquired(store,'OLD',when=1000)
    acquired(store,'NEW',when=1600)
    page=store.search(limit=1)
    assert page['next_cursor']
    store.ingest(event())
    store.ingest({'id':'edit-old','event':'message.edited','payload':{'editedMessageId':old,'body':'Synthetic replacement'}})
    assert store.search(cursor=page['next_cursor'],limit=1)['messages']==[]
    assert store.search(query='replacement')['messages']==[]
    assert store.message(old) is None


def test_delayed_history_before_cutoff_and_new_messages_afterward(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    store.ingest(event())
    old=acquired(store,historical=True)
    new=acquired(store,'NEW',when=1501)
    assert store.message(old) is None
    assert [r['id'] for r in store.search()['messages']]==[new]


def test_full_sync_and_out_of_order_delete_chat_are_monotone(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    old=acquired(store,when=1400)
    store.ingest(event(when=1500))
    older=event(when=1200)
    older['payload']['data']['FromFullSync']=True
    store.ingest(older)
    store.ingest(older)
    assert store.message(old) is None
    assert store.message_state(old)['state']=='chat_deleted'


def test_other_accounts_and_chats_are_isolated(tmp_path):
    one,two=Store(tmp_path/'one.sqlite'),Store(tmp_path/'two.sqlite')
    identifier=acquired(one)
    acquired(two)
    other=acquired(one,chat='15550009999@c.us')
    one.ingest(event('DeleteForMe'))
    assert one.message(identifier) is None
    assert two.message(identifier) is not None
    assert one.message(other) is not None


def test_malformed_and_unknown_engine_events_never_mutate_visibility(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    identifier=acquired(store)
    invalid=event()
    invalid['payload']['data']['Timestamp']='not-a-time'
    with pytest.raises(ValueError): store.ingest(invalid)
    unknown=event()
    unknown['payload']['event']='events.Unrecognized'
    assert store.ingest(unknown)['ignored']
    # Internal names cannot masquerade as provider-specific authenticated data.
    with pytest.raises(ValueError): store.ingest({'event':'chat.deleted','payload':{'chatId':CHAT,'before':1500}})
    assert store.message(identifier) is not None
    with store.db() as db:
        assert not db.execute("SELECT 1 FROM state WHERE key LIKE 'private:linked_visibility:%'").fetchone()


def test_known_message_event_is_redacted_after_local_deletion(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    identifier=acquired(store)
    store.ingest({'id':'edit','event':'message.edited','payload':{'editedMessageId':identifier,'body':'Synthetic edit'}})
    with store.db() as db:
        event_id=db.execute("SELECT id FROM account_events WHERE event_type='message.edited'").fetchone()[0]
    store.ingest(event('DeleteForMe'))
    assert store.account_event(event_id)['data']=={'message_id':identifier,'unavailable':True}


def test_delete_and_history_writer_race_is_serialized(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    barrier=threading.Barrier(2)
    def insert():
        barrier.wait()
        return acquired(store,historical=True)
    def exclude():
        barrier.wait()
        store.ingest(event('DeleteForMe'))
    with ThreadPoolExecutor(max_workers=2) as executor:
        a,b=executor.submit(insert),executor.submit(exclude)
        identifier=a.result(timeout=10)
        b.result(timeout=10)
    assert store.message(identifier) is None
    assert store.search()['messages']==[]


def edited(raw='OLD', *, chat=CHAT, when=1700, quote=None):
    notice=message(f'false_{chat}_EDITNOTICE',chat,timestamp=when,text='Synthetic edited body')
    notice.update(id='edit-'+raw,event='message.edited')
    notice['payload']['editedMessageId']=raw
    if quote is not None: notice['payload']['replyTo']=quote
    return notice


def latest_edit(store):
    with store.db() as db:
        identifier=db.execute("SELECT id FROM account_events WHERE event_type='message.edited' ORDER BY timestamp DESC LIMIT 1").fetchone()[0]
    return store.account_event(identifier)


def test_actual_raw_edit_target_updates_acquired_message_not_notice(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    identifier=acquired(store)
    store.ingest(edited())
    assert store.message(identifier)['body']=='Synthetic edited body'
    assert store.search(query='retained')['messages']==[]
    assert store.search(query='edited')['messages'][0]['id']==identifier


@pytest.mark.parametrize('kind',['DeleteChat','DeleteForMe'])
def test_actual_raw_edit_cannot_expose_excluded_or_unverified_target(tmp_path,kind):
    store=Store(tmp_path/'archive.sqlite')
    store.ingest(event(kind))
    store.ingest(edited())
    result=latest_edit(store)
    assert 'Synthetic edited body' not in json.dumps(result)
    assert result['data']['unavailable'] is True
    assert 'OLD' in result['data']['message_id']
    # The edit's later notice timestamp must not prove original availability.
    assert store.message_state(result['data']['message_id'])['state']!='unknown'


@pytest.mark.parametrize('hide_after_edit',[False,True])
@pytest.mark.parametrize('kind',['DeleteForMe','revoke'])
def test_actual_raw_quoted_reference_is_redacted_on_event_read(tmp_path,hide_after_edit,kind):
    store=Store(tmp_path/'archive.sqlite')
    target=acquired(store)
    new=acquired(store,'NEW',when=1600)
    def hide():
        if kind=='revoke':
            store.ingest({'id':'revoke-old','event':'message.revoked','payload':{'revokedMessageId':target}})
        else: store.ingest(event('DeleteForMe'))
    if not hide_after_edit: hide()
    store.ingest(edited('NEW',quote={'id':'OLD','participant':CHAT,'body':'Synthetic hidden quote'}))
    if hide_after_edit: hide()
    result=latest_edit(store)
    assert result['data']['body']=='Synthetic edited body'
    assert 'Synthetic hidden quote' not in json.dumps(result)
    assert result['data']['replyTo']['content_state']!='unknown'
    assert store.message(new) is not None


def test_unknown_quote_after_chat_deletion_is_qualified_without_hiding_new_message(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    store.ingest(event())
    acquired(store,'NEW',when=1600)
    store.ingest(edited('NEW',quote={'id':'UNACQUIRED','body':'Synthetic unverified quote'}))
    result=latest_edit(store)['data']
    assert result['body']=='Synthetic edited body'
    assert result['replyTo']=={'id':'UNACQUIRED','content_state':'unverified_reference'}


def test_raw_reference_resolution_does_not_search_other_chats(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    target=acquired(store)
    store.ingest({'id':'revoke-old','event':'message.revoked','payload':{'revokedMessageId':target}})
    other='15550009999@c.us'
    assert store.message_state('OLD',chat_id=other)['state']=='unknown'
    assert store.message_state('OLD',chat_id=CHAT)['state']=='revoked'


def revoke_raw(raw='OLD', *, chat=CHAT):
    notice=message(f'false_{chat}_REVOKENOTICE',chat,timestamp=1700,text='')
    return {'id':'revoke-'+chat,'event':'message.revoked',
            'payload':{'revokedMessageId':raw,'before':None,'after':notice['payload']}}


@pytest.mark.parametrize('revoke_first',[False,True])
def test_actual_raw_revocation_scoped_to_chat_and_prevents_resurrection(tmp_path,revoke_first):
    store=Store(tmp_path/'archive.sqlite')
    other='15550009999@c.us'
    other_id=acquired(store,chat=other)
    if revoke_first: store.ingest(revoke_raw())
    target=acquired(store)
    if not revoke_first: store.ingest(revoke_raw())
    assert store.message(target) is None
    assert store.message_state(target)['state']=='revoked'
    assert store.message_state('OLD',chat_id=CHAT)['state']=='revoked'
    assert store.message_state('OLD',chat_id=other)['state']=='unknown'
    assert store.message(other_id) is not None
    acquired(store,historical=True)
    assert store.message(target) is None
    with store.db() as db:
        row=db.execute('SELECT body,media,deleted FROM messages WHERE id=?',(target,)).fetchone()
    assert row['body']=='' and row['media'] is None and row['deleted']==1


def test_legacy_unattributed_raw_revocation_does_not_suppress_other_chat_quote(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    store.ingest({'event':'message.revoked','payload':{'revokedMessageId':'SAME'}})
    assert store.message_state('SAME',chat_id=CHAT)['state']=='unknown'


@pytest.mark.parametrize('bind_before',[True,False])
def test_raw_revocation_alias_is_applied_on_binding_and_late_history(tmp_path,bind_before):
    store=Store(tmp_path/'archive.sqlite')
    target=acquired(store,chat=LID)
    if bind_before: store.bind_chat_alias(LID,CHAT)
    store.ingest(revoke_raw(chat=CHAT))
    if not bind_before: store.bind_chat_alias(LID,CHAT)
    assert store.message(target) is None
    assert store.message_state(target)['state']=='revoked'
    assert store.message(acquired(store,chat=LID,historical=True)) is None


def test_provisioning_names_and_internal_events_are_separate():
    from sally_whatsapp.account_events import EVENT_TYPES,APPLICATION_EVENT_TYPES,STATE_EVENT_TYPES,PROVIDER_EVENT_TYPES
    assert set(STATE_EVENT_TYPES)<=set(APPLICATION_EVENT_TYPES)
    assert not set(STATE_EVENT_TYPES)&set(EVENT_TYPES)
    assert not set(STATE_EVENT_TYPES)&set(PROVIDER_EVENT_TYPES)
    assert PROVIDER_EVENT_TYPES.count('engine.event')==1


def test_signed_engine_event_ingress_and_invalid_signature(app_client):
    import hmac
    app,client=app_client
    identifier=acquired(app.state.service.store)
    body=json.dumps(event('DeleteForMe')).encode()
    response=client.post('/webhooks/waha',content=body,headers={'x-webhook-hmac-algorithm':'sha512','x-webhook-hmac':'0'*128})
    assert response.status_code==401
    assert app.state.service.store.message(identifier) is not None
    signature=hmac.digest(app.state.service.webhook_key,body,'sha512').hex()
    response=client.post('/webhooks/waha',content=body,headers={'x-webhook-hmac-algorithm':'sha512','x-webhook-hmac':signature})
    assert response.status_code==200
    assert app.state.service.store.message(identifier) is None


@pytest.mark.parametrize('bind_before',[True,False])
def test_raw_edit_target_keeps_verified_aliases_and_future_history_consistent(tmp_path,bind_before):
    store=Store(tmp_path/'archive.sqlite')
    target=acquired(store,chat=LID)
    if bind_before: store.bind_chat_alias(LID,CHAT)
    store.ingest(edited(chat=LID))
    if not bind_before: store.bind_chat_alias(LID,CHAT)
    assert store.message(target)['body']=='Synthetic edited body'
    future=acquired(store,chat=CHAT,historical=True)
    assert store.message(future)['body']=='Synthetic edited body'


def test_raw_edit_cancels_stale_received_preview_without_retrying_or_rewriting(app_client):
    app,client=app_client
    service=app.state.service
    subscribe(client,arguments={'chat_ids':[CHAT]})
    identifier=acquired(service.store,when=int(time.time())-1)
    with service.store.db() as db:
        before=dict(db.execute('SELECT * FROM deliveries').fetchone())
    service.store.ingest(edited(when=int(time.time())))
    with service.store.db() as db:
        after=dict(db.execute('SELECT * FROM deliveries').fetchone())
    assert after['state']=='cancelled'
    assert after['body']==before['body'] and after['attempts']==before['attempts']==0
    assert after['event_id']==before['event_id']
    assert service.store.message(identifier)['body']=='Synthetic edited body'
    assert not service.events.dispatch_one()


@pytest.mark.parametrize('kind',['DeleteChat','ClearChat','DeleteForMe'])
@pytest.mark.parametrize('revoke_first',[True,False])
def test_irreversible_raw_revocation_dominates_reversible_exclusions(tmp_path,kind,revoke_first):
    store=Store(tmp_path/'archive.sqlite')
    if revoke_first: store.ingest(revoke_raw(raw='ID0'))
    store.ingest(event(kind,raw='ID0',refs=[('ID0',False)]))
    if not revoke_first: store.ingest(revoke_raw(raw='ID0'))
    identifier=acquired(store,'ID0',historical=True)
    assert store.message_state(identifier)['state']=='revoked'
    with store.db() as db:
        assert store.is_revoked(db,identifier)
        row=db.execute('SELECT body,media,deleted FROM messages WHERE id=?',(identifier,)).fetchone()
    assert row['body']=='' and row['media'] is None and row['deleted']==1


@pytest.mark.parametrize('repair',[False,True])
def test_legacy_raw_edit_source_stays_redacted_before_and_during_repair(tmp_path,repair):
    from sally_whatsapp.store import REVOCATION_REPAIR_KEY
    store=Store(tmp_path/'legacy.sqlite')
    data=edited()['payload']
    with store.db() as db:
        db.execute("INSERT INTO message_mutations VALUES('OLD','revoked',NULL,1000)")
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,?)',
                   ('legacy-edit','message.edited',CHAT,1700,json.dumps(data),'OLD'))
        db.execute('DELETE FROM state WHERE key=?',(REVOCATION_REPAIR_KEY,))
    if repair: store._repair_revocation_derivatives()
    assert store.account_event('legacy-edit')['data']=={'message_id':'OLD','revoked':True}


@pytest.mark.parametrize('bind_before',[True,False])
def test_serialized_revocation_reaches_verified_alias_rows_and_existing_cursors(tmp_path,bind_before):
    store=Store(tmp_path/'archive.sqlite')
    target=acquired(store,chat=LID)
    acquired(store,'NEW',chat=LID,when=1600)
    if bind_before: store.bind_chat_alias(LID,CHAT)
    cursor=store.search(limit=1)['next_cursor']
    store.ingest({'id':'serialized-pn-revoke','event':'message.revoked',
                  'payload':{'revokedMessageId':f'false_{CHAT}_OLD'}})
    if not bind_before: store.bind_chat_alias(LID,CHAT)
    assert store.message(target) is None
    assert store.search(query='OLD')['messages']==[]
    assert all(row['id']!=target for row in store.search()['messages'])
    if bind_before:
        assert store.search(cursor=cursor,limit=1)['messages']==[]
    assert store.search(chat_id=LID)['messages']==store.search(chat_id=CHAT)['messages']
    with store.db() as db:
        row=db.execute('SELECT deleted,body FROM messages WHERE id=?',(target,)).fetchone()
    assert row['deleted']==1 and row['body']==''


@pytest.mark.parametrize('cross_bucket', [False, True])
def test_real_delete_for_me_preserves_other_digest_member(app_client, monkeypatch, cross_bucket):
    app,client=app_client
    service=app.state.service
    subscribe(client,name='message.digest',arguments={'chat_ids':[CHAT],'digest_window_seconds':60})
    # Digest membership uses acquisition time. Control the minute boundary so
    # scheduler speed cannot silently turn one digest into two distinct batches.
    clock=[int(time.time()//60)*60+59]
    monkeypatch.setattr(time,'time',lambda:clock[0])
    removed=acquired(service.store,'A',when=clock[0])
    if cross_bucket:
        clock[0]+=1
    expected=acquired(service.store,'B',when=clock[0])
    with service.store.db() as db:
        batches=db.execute('SELECT body FROM deliveries ORDER BY id').fetchall()
    assert [json.loads(row['body'])['data']['message_ids'] for row in batches] == (
        [[removed],[expected]] if cross_bucket else [[removed,expected]])
    service.events.transport.requests.clear()
    service.store.ingest(event('DeleteForMe',raw='A',when=clock[0]))
    clock[0]+=60
    if cross_bucket:
        # The first dispatch cancels the now-empty first batch; the next keeps
        # the unrelated batch. Neither needs a new event ID or a retry.
        assert service.events.dispatch_one()
        assert service.events.transport.requests == []
        with service.store.db() as db:
            first=db.execute('SELECT state,attempts FROM deliveries ORDER BY id LIMIT 1').fetchone()
        assert tuple(first)==('cancelled',0)
    assert service.events.dispatch_one()
    posted=service.events.transport.requests
    assert len(posted)==1
    assert json.loads(posted[0][1])['data']['message_ids']==[expected]
    assert not service.events.dispatch_one()


@pytest.mark.parametrize('bind_before',[True,False])
@pytest.mark.parametrize('acquired_alias',[True,False])
def test_group_serialized_revocation_uses_only_verified_participant_alias(tmp_path,bind_before,acquired_alias):
    store=Store(tmp_path/'archive.sqlite')
    author=LID if acquired_alias else CHAT
    reference=CHAT if acquired_alias else LID
    target=f'false_{GROUP}_RAW_{author}'
    other=f'false_{GROUP}_RAW_15550008888@c.us'
    for identifier,participant in ((target,author),(other,'15550008888@c.us')):
        item=message(identifier,GROUP,timestamp=1000)
        item['payload']['participant']=participant
        store.ingest(item)
    if bind_before: store.bind_chat_alias(LID,CHAT)
    store.ingest({'id':'group-serialized-revoke','event':'message.revoked',
                  'payload':{'revokedMessageId':f'false_{GROUP}_RAW_{reference}'}})
    if not bind_before: store.bind_chat_alias(LID,CHAT)
    assert store.message(target) is None
    assert store.message(other) is not None
    assert [row['id'] for row in store.search(chat_id=GROUP)['messages']]==[other]
    with store.db() as db:
        assert store.is_revoked(db,target)
        assert not store.is_revoked(db,other)
        assert db.execute('SELECT deleted FROM messages WHERE id=?',(target,)).fetchone()[0]==1
    # A future import under either serialization must remain revoked.
    late=message(f'false_{GROUP}_RAW_{reference}',GROUP,timestamp=1000)
    late['payload']['participant']=reference
    store.ingest(late,historical=True)
    assert store.message(late['payload']['id']) is None


@pytest.mark.parametrize('bind_before',[True,False])
@pytest.mark.parametrize('acquired_alias',[True,False])
def test_group_raw_edit_is_applied_when_participant_alias_becomes_verified(tmp_path,bind_before,acquired_alias):
    store=Store(tmp_path/'archive.sqlite')
    author=LID if acquired_alias else CHAT
    reference=CHAT if acquired_alias else LID
    identifier=f'false_{GROUP}_RAW_{author}'
    original=message(identifier,GROUP,timestamp=1000,text='Synthetic original')
    original['payload']['participant']=author
    store.ingest(original)
    if bind_before: store.bind_chat_alias(LID,CHAT)
    notice=edited('RAW',chat=GROUP)
    notice['payload']['id']=f'false_{GROUP}_NOTICE_{reference}'
    notice['payload']['participant']=reference
    store.ingest(notice)
    if not bind_before: store.bind_chat_alias(LID,CHAT)
    assert store.message(identifier)['body']=='Synthetic edited body'
    assert store.search(query='original')['messages']==[]
    assert store.search(query='edited')['messages'][0]['id']==identifier


@pytest.mark.parametrize('kind',['edit','revoke'])
def test_group_mutations_follow_all_verified_lids_of_same_participant(tmp_path,kind):
    store=Store(tmp_path/'archive.sqlite')
    another_lid='15550004444@lid'
    store.bind_chat_alias(LID,CHAT)
    target=f'false_{GROUP}_RAW_{LID}'
    original=message(target,GROUP,timestamp=1000,text='Synthetic original')
    original['payload']['participant']=LID
    store.ingest(original)
    if kind=='edit':
        notice=edited('RAW',chat=GROUP)
        notice['payload']['id']=f'false_{GROUP}_NOTICE_{another_lid}'
        notice['payload']['participant']=another_lid
    else:
        notice={'id':'another-lid-revoke','event':'message.revoked',
                'payload':{'revokedMessageId':f'false_{GROUP}_RAW_{another_lid}'}}
    store.ingest(notice)
    store.bind_chat_alias(another_lid,CHAT)
    if kind=='revoke':
        assert store.message(target) is None
        assert store.search()['messages']==[]
    else:
        assert store.message(target)['body']=='Synthetic edited body'
        assert store.search(query='original')['messages']==[]


@pytest.mark.parametrize('revoked_alias',[True,False])
@pytest.mark.parametrize('acquired_alias',[True,False])
@pytest.mark.parametrize('historical',[True,False])
def test_group_revocation_before_acquisition_persists_verified_identity(tmp_path,revoked_alias,acquired_alias,historical):
    store=Store(tmp_path/'archive.sqlite')
    store.bind_chat_alias(LID,CHAT)
    reference=LID if revoked_alias else CHAT
    author=LID if acquired_alias else CHAT
    identifier=f'false_{GROUP}_RAW_{author}'
    store.ingest({'id':'revoke-before-acquisition','event':'message.revoked',
                  'payload':{'revokedMessageId':f'false_{GROUP}_RAW_{reference}'}})
    # The revocation must cover future imports and live ingestion, even when
    # no acquired row existed to discover the other serialization.
    item=message(identifier,GROUP,text='Synthetic revoked body')
    item['payload']['participant']=author
    store.ingest(item,historical=historical)
    other=f'false_{GROUP}_RAW_15550008888@c.us'
    item=message(other,GROUP,text='Synthetic retained other participant')
    item['payload']['participant']='15550008888@c.us'
    store.ingest(item,historical=historical)
    assert store.message(identifier) is None
    assert store.message_state(identifier)['state']=='revoked'
    assert [row['id'] for row in store.search(chat_id=GROUP)['messages']]==[other]
    assert store.search(query='revoked')['messages']==[]
    with store.db() as db:
        row=db.execute('SELECT deleted,body,media FROM messages WHERE id=?',(identifier,)).fetchone()
        assert tuple(row)==(1,'',None)
        assert db.execute('SELECT 1 FROM message_search WHERE id=?',(identifier,)).fetchone() is None
        assert not store.is_revoked(db,other)
