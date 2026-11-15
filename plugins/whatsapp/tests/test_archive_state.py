"""Organizational chat state from synthetic authenticated GOWS events/cache."""
import copy
from datetime import datetime, timezone
import json

import pytest

from conftest import message
from sally_whatsapp.linked_state import decode_engine_event
from sally_whatsapp.store import Store

CHAT='15550001111@c.us'
LID='15550002222@lid'
OTHER='15550009999@c.us'


def archive_event(archived=True, *, chat=CHAT, when=1500, identifier=None, full_sync=False):
    return {'id':identifier or f'archive-{chat}-{when}-{archived}',
            'event':'engine.event','engine':'GOWS','session':'synthetic',
            'payload':{'event':'events.Archive','session':'synthetic','data':{
                'JID':chat.replace('@c.us','@s.whatsapp.net'),
                'Timestamp':datetime.fromtimestamp(when,timezone.utc).isoformat(),
                'FromFullSync':full_sync,'Action':{'archived':archived}}}}


def snapshot(known=True, archived=True):
    return {'known':known,'archived':archived,
            'source':'whatsmeow_chat_settings_cache','phoneFresh':False}


@pytest.mark.parametrize('archived',[True,False])
@pytest.mark.parametrize('chat',[CHAT,LID,'15550003333@g.us'])
def test_archive_event_minimal_typed_projection_without_content_or_ranges(archived,chat):
    envelope=archive_event(archived,chat=chat)
    envelope['payload']['data']['Action']['messageRange']={'messages':[{'body':'synthetic private content'}]}
    before=copy.deepcopy(envelope)
    projected=decode_engine_event(envelope)
    assert projected=={'event':'chat.archived','payload':{
        'chatId':chat,'archived':archived,'eventAt':1500.0,'fromFullSync':False,
        'source':'gows_archive_event','phoneFresh':False},'exclusions':[]}
    assert envelope==before
    assert 'synthetic private content' not in json.dumps(projected)


@pytest.mark.parametrize('action',[None,{},[],{'archived':None},{'archived':0},{'archived':'false'}])
def test_missing_archive_value_is_unknown_rejected_not_implicit_false(action):
    envelope=archive_event()
    envelope['payload']['data']['Action']=action
    with pytest.raises(ValueError,match='^Invalid GOWS linked-state event$'):
        decode_engine_event(envelope)


def test_unknown_engine_and_wrong_inner_session_cannot_produce_state(tmp_path):
    store=Store(tmp_path/'one.sqlite')
    event=archive_event()
    event['engine']='NOWEB'
    assert store.ingest(event)['ignored']
    assert store.chat_archive_state(CHAT)['known'] is False
    event=archive_event()
    event['payload']['session']='another-account'
    with pytest.raises(ValueError): store.ingest(event)
    with pytest.raises(ValueError): store.ingest({'event':'chat.archived','payload':{'chatId':CHAT,'archived':True}})
    assert store.chat_archive_state(CHAT)['archived'] is None


def test_order_duplicate_conflict_and_newer_observation_survive_restart(tmp_path):
    path=tmp_path/'one.sqlite'
    store=Store(path)
    assert store.chat_archive_state(CHAT)=={
        'chat_id':CHAT,'known':False,'archived':None,'source':None,
        'event_at':None,'observed_at':None,'phone_fresh':False,
        'coverage_scope':'chat_archived_flag_only','proves_missing_messages':False}
    assert store.ingest(archive_event())['recorded']
    first=store.chat_archive_state(CHAT)
    assert first['known'] and first['archived'] is True and first['event_at']==1500
    assert first['source']=='gows_archive_event' and first['phone_fresh'] is False
    assert store.ingest(archive_event())['duplicate']
    store.ingest(archive_event(False,when=1400,full_sync=True))
    assert store.chat_archive_state(CHAT)==first
    store.ingest(archive_event(False,when=1500))
    conflicted=store.chat_archive_state(CHAT)
    assert conflicted['known'] is False and conflicted['archived'] is None
    assert conflicted['reason']=='conflicting_same_timestamp'
    store.ingest(archive_event(True,when=1500,identifier='same-time-again'))
    assert store.chat_archive_state(CHAT)['known'] is False
    store=Store(path)
    assert store.chat_archive_state(CHAT)['known'] is False
    store.ingest(archive_event(False,when=1600))
    current=store.chat_archive_state(CHAT)
    assert current['known'] and current['archived'] is False and current['event_at']==1600
    assert 'reason' not in current


def test_archive_does_not_change_messages_exclusions_or_history_coverage(tmp_path):
    store=Store(tmp_path/'one.sqlite')
    identifier=f'false_{CHAT}_ORIGINAL'
    store.ingest(message(identifier,CHAT,timestamp=1000,text='synthetic retained body'))
    before_message=store.message(identifier)
    before_search=store.search()
    before_chats=store.chats()
    with store.db() as db:
        before_exclusions=list(db.execute("SELECT key,value FROM state WHERE key LIKE 'private:linked_visibility:%'"))
    store.ingest(archive_event(True))
    store.ingest(archive_event(False,when=1600))
    assert store.message(identifier)==before_message
    assert store.search()==before_search
    assert store.chats()==before_chats
    with store.db() as db:
        assert list(db.execute("SELECT key,value FROM state WHERE key LIKE 'private:linked_visibility:%'"))==before_exclusions
        assert db.execute('PRAGMA user_version').fetchone()[0]==8
    assert store.list_account_events(event_types=['chat.archived'])['events']


@pytest.mark.parametrize('bind_before',[True,False])
def test_verified_alias_account_chat_and_restart_isolation(tmp_path,bind_before):
    one,two=Store(tmp_path/'one.sqlite'),Store(tmp_path/'two.sqlite')
    if bind_before: one.bind_chat_alias(LID,CHAT)
    one.ingest(archive_event(True,chat=LID))
    if not bind_before: one.bind_chat_alias(LID,CHAT)
    state=one.chat_archive_state(CHAT)
    assert state['known'] and state['archived'] is True and state['chat_id']==CHAT
    assert one.chat_archive_state(LID)==state
    assert one.chat_archive_state(OTHER)['known'] is False
    assert two.chat_archive_state(CHAT)['known'] is False
    assert Store(tmp_path/'one.sqlite').chat_archive_state(CHAT)==state
    assert not any(key.startswith('private:chat_archive:') for key in one.state())


def test_cache_snapshot_unknown_and_observed_separate_from_ordered_events(tmp_path):
    store=Store(tmp_path/'one.sqlite')
    unknown=store.observe_chat_archive_cache(CHAT,snapshot(False,True),observed_at=1600)
    assert unknown['known'] is False and unknown['archived'] is None
    cached=store.observe_chat_archive_cache(CHAT,snapshot(True,False),observed_at=1700)
    assert cached['known'] and cached['archived'] is False
    assert cached['source']=='whatsmeow_chat_settings_cache' and cached['event_at'] is None
    assert cached['phone_fresh'] is False
    store.ingest(archive_event(True,when=1500))
    observed=store.chat_archive_state(CHAT)
    store.observe_chat_archive_cache(CHAT,snapshot(True,False),observed_at=1800)
    assert store.chat_archive_state(CHAT)==observed
    store.require_recovery('connection_interrupted')
    assert store.chat_archive_state(CHAT)['known'] is False
    store.observe_chat_archive_cache(CHAT,snapshot(True,False),observed_at=1900)
    assert store.chat_archive_state(CHAT)['known'] is False
    store.ingest(archive_event(False,when=1600))
    assert store.chat_archive_state(CHAT)['known']
    assert store.chat_archive_state(CHAT)['archived'] is False


def test_restart_invalidates_state_without_replaying_an_intent(tmp_path):
    path=tmp_path/'one.sqlite'
    store=Store(path)
    store.ingest(archive_event())
    store=Store(path,recover_inflight=True)
    state=store.chat_archive_state(CHAT)
    assert state['known'] is False and state['reason']=='event_stream_restart'
    store.ingest(archive_event(True,identifier='old-full-sync',full_sync=True))
    assert store.chat_archive_state(CHAT)['known'] is False
    store.ingest(archive_event(False,when=1600))
    assert store.chat_archive_state(CHAT)['known']
    assert store.chat_archive_state(CHAT)['archived'] is False


@pytest.mark.parametrize('change',[
    {'known':1},{'archived':None},{'source':'phone'}, {'phoneFresh':True},
    {'phone_fresh':True}, {'phoneFresh':None},
])
def test_cache_contract_rejects_untyped_or_phone_fresh_claims(tmp_path,change):
    store=Store(tmp_path/'one.sqlite')
    with pytest.raises(ValueError): store.observe_chat_archive_cache(CHAT,{**snapshot(),**change})
    assert not store.chat_archive_state(CHAT)['known']


def test_old_cache_completion_does_not_regress_later_snapshot(tmp_path):
    store=Store(tmp_path/'one.sqlite')
    latest=store.observe_chat_archive_cache(CHAT,snapshot(True,False),observed_at=1700)
    assert store.observe_chat_archive_cache(CHAT,snapshot(True,True),observed_at=1600)==latest


def test_alias_merge_preserves_newer_event_and_equal_conflict(tmp_path):
    store=Store(tmp_path/'one.sqlite')
    store.ingest(archive_event(True,when=1600))
    store.ingest(archive_event(False,chat=LID,when=1500))
    store.bind_chat_alias(LID,CHAT)
    assert store.chat_archive_state(CHAT)['archived'] is True
    store.ingest(archive_event(False,chat=LID,when=1600))
    assert store.chat_archive_state(CHAT)['known'] is False


def test_only_authenticated_matching_session_webhook_records_archive(app_client):
    import hmac
    app,client=app_client
    service=app.state.service
    service.resolve_chat=lambda value:value
    event=archive_event()
    event['session']=service.settings.session
    event['payload']['session']=service.settings.session
    body=json.dumps(event).encode()
    invalid=client.post('/webhooks/waha',content=body,headers={
        'x-webhook-hmac-algorithm':'sha512','x-webhook-hmac':'0'*128})
    assert invalid.status_code==401
    assert service.store.chat_archive_state(CHAT)['known'] is False
    signature=hmac.digest(service.webhook_key,body,'sha512').hex()
    accepted=client.post('/webhooks/waha',content=body,headers={
        'x-webhook-hmac-algorithm':'sha512','x-webhook-hmac':signature})
    assert accepted.status_code==200
    assert service.store.chat_archive_state(CHAT)['archived'] is True
    event['session']='other-owner'
    event['payload']['session']='other-owner'
    event['id']='signed-other-session'
    body=json.dumps(event).encode()
    signature=hmac.digest(service.webhook_key,body,'sha512').hex()
    rejected=client.post('/webhooks/waha',content=body,headers={
        'x-webhook-hmac-algorithm':'sha512','x-webhook-hmac':signature})
    assert rejected.status_code==400
    assert service.store.chat_archive_state(CHAT)['event_at']==1500


@pytest.mark.parametrize('restart',[False,True])
def test_pre_gap_cache_completion_cannot_restore_unknown(tmp_path,monkeypatch,restart):
    path=tmp_path/'one.sqlite'
    store=Store(path)
    store.observe_chat_archive_cache(CHAT,snapshot(True,True),observed_at=1700)
    monkeypatch.setattr('sally_whatsapp.store.time.time',lambda:1850)
    if restart: store=Store(path,recover_inflight=True)
    else: store.require_recovery('connection_interrupted')
    old=store.observe_chat_archive_cache(CHAT,snapshot(True,False),observed_at=1800)
    assert old['known'] is False and old['archived'] is None
    assert old['invalidated_at']==1850
    fresh=store.observe_chat_archive_cache(CHAT,snapshot(True,False),observed_at=1900)
    assert fresh['known'] is True and fresh['archived'] is False
    assert fresh['source']=='whatsmeow_chat_settings_cache' and fresh['phone_fresh'] is False


def test_conflicting_cache_reads_without_order_remain_unknown(tmp_path):
    store=Store(tmp_path/'one.sqlite')
    store.observe_chat_archive_cache(CHAT,snapshot(True,True),observed_at=1700)
    conflict=store.observe_chat_archive_cache(CHAT,snapshot(True,False),observed_at=1700)
    assert conflict['known'] is False and conflict['reason']=='conflicting_cache_observation_time'
    assert store.observe_chat_archive_cache(CHAT,snapshot(True,True),observed_at=1700)['known'] is False
    assert store.observe_chat_archive_cache(CHAT,snapshot(True,False),observed_at=1800)['known'] is True


@pytest.mark.parametrize('restart',[False,True])
def test_first_cache_request_started_before_gap_stays_unknown(tmp_path,monkeypatch,restart):
    path=tmp_path/'one.sqlite'
    store=Store(path)
    assert not store.chat_archive_state(CHAT)['known']
    monkeypatch.setattr('sally_whatsapp.store.time.time',lambda:1850)
    if restart: store=Store(path,recover_inflight=True)
    else: store.require_recovery('connection_interrupted')
    # The GET began at 1800, before the interruption; no per-chat row existed.
    stale=store.observe_chat_archive_cache(CHAT,snapshot(True,True),observed_at=1800)
    assert stale['known'] is False and stale['archived'] is None
    assert stale['invalidated_at']==1850
    assert stale['reason']==('event_stream_restart' if restart else 'event_stream_gap')
    current=store.observe_chat_archive_cache(CHAT,snapshot(True,False),observed_at=1900)
    assert current['known'] is True and current['archived'] is False
    # An even later completion of the original GET cannot regress the new GET.
    assert store.observe_chat_archive_cache(CHAT,snapshot(True,True),observed_at=1800)==current


def test_first_cache_completion_after_gap_cannot_overwrite_later_event(tmp_path,monkeypatch):
    store=Store(tmp_path/'one.sqlite')
    monkeypatch.setattr('sally_whatsapp.store.time.time',lambda:1850)
    store.require_recovery('connection_interrupted')
    store.ingest(archive_event(False,when=1900))
    observed=store.chat_archive_state(CHAT)
    stale=store.observe_chat_archive_cache(CHAT,snapshot(True,True),observed_at=1800)
    assert stale==observed
    assert stale['known'] and stale['archived'] is False
    assert stale['source']=='gows_archive_event' and stale['event_at']==1900


def test_global_gap_barrier_survives_restart_and_alias_resolution(tmp_path,monkeypatch):
    path=tmp_path/'one.sqlite'
    store=Store(path)
    monkeypatch.setattr('sally_whatsapp.store.time.time',lambda:1850)
    store.require_recovery('connection_interrupted')
    store=Store(path)
    store.bind_chat_alias(LID,CHAT)
    stale=store.observe_chat_archive_cache(LID,snapshot(True,True),observed_at=1800)
    assert stale['chat_id']==CHAT and not stale['known']
    assert store.chat_archive_state(CHAT)==stale
    # Moving the local clock back must not lower the persisted barrier.
    monkeypatch.setattr('sally_whatsapp.store.time.time',lambda:1700)
    store.require_recovery('connection_interrupted')
    stale=store.observe_chat_archive_cache(OTHER,snapshot(True,True),observed_at=1800)
    assert not stale['known'] and stale['invalidated_at']==1850
