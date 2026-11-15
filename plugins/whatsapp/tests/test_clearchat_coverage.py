"""ClearChat ranges are uncertainty evidence, not per-message deletion proofs."""
from datetime import datetime, timezone
import json

import pytest

from conftest import message
from sally_whatsapp.store import Store
from sally_whatsapp.linked_state import decode_engine_event
from sally_whatsapp.linked_state_reads import project_live_read

CHAT='15550001111@c.us'
LID='15550002222@lid'
UNCERTAIN='clear_chat_coverage_uncertain'


def acquired(store,raw,when,chat=CHAT,**extra):
    identifier=f'false_{chat}_{raw}'
    item=message(identifier,chat,timestamp=when,text='Synthetic retained '+raw)
    item['payload'].update(extra)
    store.ingest(item)
    return identifier


def clear(*,chat=CHAT,when=1500,through=1200,system=None,anchors=('C',),action_extra=None):
    interval={'messages':[{'key':{'ID':raw,'fromMe':False,'remoteJID':chat},
                           'timestamp':1200} for raw in anchors]}
    if through is not None: interval['lastMessageTimestamp']=through
    if system is not None: interval['lastSystemMessageTimestamp']=system
    action={'messageRange':interval,**(action_extra or {})}
    return {'event':'engine.event','engine':'GOWS','session':'default',
            'payload':{'event':'events.ClearChat','session':'default','data':{
                'JID':chat,'Timestamp':datetime.fromtimestamp(when,timezone.utc).isoformat(),
                'Action':action,'FromFullSync':False,'DeleteMedia':False}}}


def test_one_anchor_does_not_leave_other_range_members_as_current(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    before=acquired(store,'B',1100)
    anchor=acquired(store,'C',1200)
    later=acquired(store,'F',1300)
    cursor=store.search(limit=1)['next_cursor']
    store.ingest(clear())
    for identifier in (before,anchor):
        assert store.message(identifier) is None
        assert store.message_state(identifier)['state']==UNCERTAIN
    assert store.message(later) is not None
    assert store.search(cursor=cursor)['messages']==[]
    result=store.search()
    assert [row['id'] for row in result['messages']]==[later]
    assert result['clear_chat_coverage']['certainty']=='uncertain'
    with store.db() as db:
        assert all(tuple(db.execute('SELECT deleted,body FROM messages WHERE id=?',(i,)).fetchone())==
                   (0,'Synthetic retained '+raw) for i,raw in ((before,'B'),(anchor,'C')))
        assert db.execute('SELECT count(*) FROM message_search').fetchone()[0]==3


@pytest.mark.parametrize('flags',[{}, {'starred':True}, {'keep':True}, {'starred':True,'keep':True}])
def test_starred_kept_and_anchor_are_uncertain_not_deleted(tmp_path,flags):
    store=Store(tmp_path/'archive.sqlite')
    identifier=acquired(store,'C',1200,**flags)
    store.ingest(clear(action_extra={'keepStarred':True}))
    assert store.message_state(identifier)['state']==UNCERTAIN
    with store.db() as db:
        assert not store.is_revoked(db,identifier)
        assert db.execute('SELECT deleted FROM messages WHERE id=?',(identifier,)).fetchone()[0]==0


def test_system_range_is_preserved_separately_not_a_global_maximum(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    old=acquired(store,'B',1100)
    later=acquired(store,'F',1300)
    source=clear(system=1400)
    decoded=decode_engine_event(source)
    assert decoded['payload']['clearCoverage']['range']=={
        'lastMessageTimestamp':1200,'lastSystemMessageTimestamp':1400}
    store.ingest(source)
    assert store.message_state(old)['state']==UNCERTAIN
    assert store.message(later) is not None
    assert store.search()['clear_chat_coverage']['system_range_unresolved'] is True


@pytest.mark.parametrize('through',[None,1700])
def test_missing_or_inconsistent_range_never_uses_event_time_cutoff(tmp_path,through):
    store=Store(tmp_path/'archive.sqlite')
    before=acquired(store,'B',1100)
    later=acquired(store,'F',1600)
    store.ingest(clear(through=through))
    assert store.message(before) is not None
    assert store.message(later) is not None
    result=store.search()
    assert result['clear_chat_coverage']['boundary_unknown'] is True
    assert all(row['current_state']==UNCERTAIN for row in result['messages'])


def test_delayed_clear_and_late_history_do_not_shrink_or_resurrect(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    store.ingest(clear())
    delayed=clear(when=1300,through=1000,anchors=())
    delayed['payload']['data']['FromFullSync']=True
    store.ingest(delayed)
    store.ingest(delayed)
    identifier=acquired(store,'B',1100)
    later=acquired(store,'F',1300)
    assert store.message_state(identifier)['state']==UNCERTAIN
    assert store.message(later) is not None


@pytest.mark.parametrize('bind_before',[True,False])
def test_aliases_share_uncertain_range_without_affecting_other_chat(tmp_path,bind_before):
    store=Store(tmp_path/'archive.sqlite')
    identifier=acquired(store,'B',1100,chat=LID)
    other=acquired(store,'OTHER',1100,chat='15550009999@c.us')
    if bind_before: store.bind_chat_alias(LID,CHAT)
    store.ingest(clear(chat=CHAT))
    if not bind_before: store.bind_chat_alias(LID,CHAT)
    assert store.message_state(identifier)['state']==UNCERTAIN
    assert store.message(other) is not None


def test_positive_live_cache_does_not_resolve_uncertainty(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    store.ingest(clear())
    identifier=f'false_{CHAT}_B'
    for _ in range(2):
        result=project_live_read(store,'chats_get_chat_message',{'path':{'chatId':CHAT}},
                                 {'id':identifier,'timestamp':1100,'body':'Synthetic stale cache'})
        assert result['result']=={'id':identifier,'content_state':UNCERTAIN}
    later=f'false_{CHAT}_F'
    result=project_live_read(store,'chats_get_chat_message',{'path':{'chatId':CHAT}},
                             {'id':later,'timestamp':1300,'body':'Synthetic new reception'})
    assert result['result']['body']=='Synthetic new reception'


def test_legacy_event_cannot_reconstruct_range_and_is_not_current_evidence(tmp_path):
    path=tmp_path/'archive.sqlite'
    store=Store(path)
    before=acquired(store,'B',1100)
    later=acquired(store,'F',1600)
    legacy={'chatId':CHAT,'reason':'chat_cleared','eventAt':1500,'fromFullSync':False,
            'coverage':'explicit_messages','excludedReferences':1}
    with store.db() as db:
        db.execute('DELETE FROM state WHERE key=?',('private:clear_coverage_repair:v1',))
        db.execute('INSERT INTO account_events(id,event_type,chat_id,timestamp,data,source_message_id) VALUES(?,?,?,?,?,?)',
                   ('legacy-clear','chat.cleared',CHAT,1500,json.dumps(legacy),''))
    store=Store(path)
    result=store.search()
    assert {row['id'] for row in result['messages']}=={before,later}
    assert result['clear_chat_coverage']['boundary_unknown'] is True
    assert all(row['current_state']==UNCERTAIN for row in result['messages'])
    assert store.message(before)['clear_chat_coverage']['boundary_unknown'] is True
    with store.db() as db:
        assert json.loads(db.execute('SELECT value FROM state WHERE key=?',
                                    ('private:clear_coverage_repair:v1',)).fetchone()[0]) is True


def test_revocation_still_wins_over_a_later_uncertain_clear(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    identifier=acquired(store,'B',1100)
    store.ingest({'event':'message.revoked','payload':{'revokedMessageId':identifier}})
    store.ingest(clear())
    assert store.message_state(identifier)['state']=='revoked'


def test_clear_summary_does_not_reveal_text_matches_of_withheld_content(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    acquired(store,'B',1100)
    store.ingest(clear())
    one=store.search(query='retained')
    two=store.search(query='unmatched')
    assert one['messages']==two['messages']==[]
    assert one['clear_chat_coverage']==two['clear_chat_coverage']


def test_system_only_range_does_not_become_an_ordinary_message_cutoff(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    identifier=acquired(store,'B',1100)
    store.ingest(clear(through=None,system=1400,anchors=()))
    assert store.message(identifier) is not None
    result=store.search()
    assert result['current_state']==UNCERTAIN
    assert result['clear_chat_coverage']['boundary_unknown'] is True
    assert result['clear_chat_coverage']['system_range_unresolved'] is True


def test_unknown_live_timestamp_is_withheld_without_claiming_deletion(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    store.ingest(clear())
    result=project_live_read(store,'chats_get_chat_message',{'path':{'chatId':CHAT}},
                             {'id':f'false_{CHAT}_B','body':'Synthetic cache without timestamp'})
    assert result['result']=={'id':f'false_{CHAT}_B','content_state':UNCERTAIN}


def test_legacy_anchor_is_uncertain_and_other_rows_warn_without_a_guessed_cutoff(tmp_path):
    from sally_whatsapp import visibility
    store=Store(tmp_path/'archive.sqlite')
    anchor=acquired(store,'C',1200)
    before=acquired(store,'B',1100)
    with store.db() as db:
        visibility.apply(db,[{'kind':'message','chat_id':CHAT,'raw_id':'C','from_me':False,
                             'reason':'chat_cleared','event_at':1500}],store._canonical_chat)
    assert store.message_state(anchor)['state']==UNCERTAIN
    assert store.message(anchor) is None
    assert store.message(before)['body']=='Synthetic retained B'
    assert store.search()['messages'][0]['current_state']==UNCERTAIN
    live=project_live_read(store,'chats_get_chat_message',{'path':{'chatId':CHAT}},
                           {'id':before,'timestamp':1100,'body':'Synthetic cache'})
    assert live['result']['current_state']==live['current_state']==UNCERTAIN
    assert live['clear_chat_coverage']['boundary_unknown'] is True


def test_semantic_repair_is_skipped_for_nonmigrating_checks(tmp_path):
    from sally_whatsapp import visibility
    path=tmp_path/'archive.sqlite'
    store=Store(path)
    with store.db() as db:
        db.execute('DELETE FROM state WHERE key=?',(visibility.CLEAR_REPAIR,))
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,?)',
                   ('legacy','chat.cleared',CHAT,1500,json.dumps({'chatId':CHAT,'eventAt':1500}),''))
    store=Store(path,migrate_schema=False,recover_inflight=False)
    with store.db() as db:
        assert not db.execute('SELECT 1 FROM state WHERE key=?',(visibility.CLEAR_REPAIR,)).fetchone()
        assert visibility.clear_coverage(db,CHAT,store._canonical_chat) is None


def test_semantic_repair_failure_rolls_back_observations_and_marker(tmp_path,monkeypatch):
    from sally_whatsapp import visibility
    path=tmp_path/'archive.sqlite'
    store=Store(path)
    with store.db() as db:
        db.execute('DELETE FROM state WHERE key=?',(visibility.CLEAR_REPAIR,))
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,?)',
                   ('legacy','chat.cleared',CHAT,1500,json.dumps({'chatId':CHAT,'eventAt':1500}),''))
    original=visibility.apply
    def interrupt(*args,**kwargs):
        original(*args,**kwargs)
        raise RuntimeError('Synthetic repair interruption')
    with monkeypatch.context() as patch:
        patch.setattr(visibility,'apply',interrupt)
        with pytest.raises(RuntimeError,match='Synthetic repair interruption'):
            Store(path)
    with store.db() as db:
        assert not db.execute('SELECT 1 FROM state WHERE key=?',(visibility.CLEAR_REPAIR,)).fetchone()
        assert visibility.clear_coverage(db,CHAT,store._canonical_chat) is None
    repaired=Store(path)
    assert repaired.clear_chat_coverage(CHAT)['boundary_unknown'] is True


def test_clear_and_history_write_serialize_without_resurrection(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    store=Store(tmp_path/'archive.sqlite')
    locked,release=Event(),Event()
    def delayed_history():
        with store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            locked.set()
            assert release.wait(5)
            store.ingest(message(f'false_{CHAT}_B',CHAT,timestamp=1100,text='Synthetic late history'),
                         historical=True,db=db)
    with ThreadPoolExecutor(max_workers=2) as pool:
        history=pool.submit(delayed_history)
        assert locked.wait(5)
        clearing=pool.submit(store.ingest,clear())
        release.set()
        history.result(timeout=5)
        clearing.result(timeout=5)
    assert store.message(f'false_{CHAT}_B') is None
    assert store.message_state(f'false_{CHAT}_B')['state']==UNCERTAIN
    assert acquired(store,'F',1300) in [row['id'] for row in store.search()['messages']]


@pytest.mark.parametrize('through',[None,1200])
def test_mcp_get_message_and_chat_counts_explain_clear_coverage(app_client,through):
    from conftest import call
    app,client=app_client
    store=app.state.service.store
    before=acquired(store,'B',1100)
    acquired(store,'F',1600)
    store.ingest(clear(through=through))
    result=call(client,'get_message',{'message_id':before})['result']['structuredContent']
    assert result['current_state']==UNCERTAIN
    assert result['clear_chat_coverage']['certainty']=='uncertain'
    if through is None:
        assert result['message']['body']=='Synthetic retained B'
        assert result['message']['content_state']=='acquired_current_unverified'
    else:
        assert result['message'] is None
    chat=next(item for item in store.chats()['chats'] if item['id']==CHAT)
    assert chat['message_count_scope']=='visible_acquired_only'
    assert chat['clear_chat_coverage']['certainty']=='uncertain'


def test_raw_anchor_does_not_hide_acquired_opposite_direction(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    store.ingest(message('C',CHAT,timestamp=2000,text='Synthetic outgoing',from_me=True))
    store.ingest(clear(through=None))
    assert store.message_state('C')['state']=='unknown'
    assert store.message('C') is not None
    assert [row['id'] for row in store.search()['messages']]==['C']


def test_legacy_account_event_does_not_assert_certified_deletion_members(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    legacy={'chatId':CHAT,'reason':'chat_cleared','eventAt':1500,'fromFullSync':False,
            'coverage':'explicit_messages','excludedReferences':1}
    with store.db() as db:
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,?)',
                   ('legacy','chat.cleared',CHAT,1500,json.dumps(legacy),''))
    result=store.account_event('legacy')
    assert result['id']=='legacy' and result['timestamp']==1500
    assert result['data']['reason']==UNCERTAIN
    assert result['data']['coverage']=='uncertain'
    assert result['data']['excludedReferences']==0
    assert result['data']['clearCoverage']['legacyRangeUnavailable'] is True
    with store.db() as db:
        assert json.loads(db.execute('SELECT data FROM account_events WHERE id=?',('legacy',)).fetchone()[0])==legacy
