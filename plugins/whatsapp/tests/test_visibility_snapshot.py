"""Synthetic transaction-scoped visibility, including concurrent WAL writers."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import random

import pytest

from conftest import message
from sally_whatsapp import visibility
from sally_whatsapp.store import Store


CHAT = '15550111111@c.us'
OTHER = '15550222222@c.us'
LID = '15550333333@lid'
GROUP = '15550444444@g.us'


def exclusion(raw='TARGET', *, chat=CHAT, reason='deleted_for_me', direction=False):
    return {'kind':'message','chat_id':chat,'raw_id':raw,'from_me':direction,
            'reason':reason,'event_at':2000}


def clear(*, chat=CHAT, through=None):
    return {'kind':'clear','chat_id':chat,'reason':visibility.CLEAR_UNCERTAIN,
            'event_at':3000,'through':through,'system_through':9000,
            'anchors':[{'raw_id':'ANCHOR','from_me':False}],'range':{},'before':0}


def projection(db, identifier, chat=CHAT, timestamp=1500):
    return visibility.state(db,identifier,chat,timestamp,Store._canonical_chat)


def scans(statements):
    return sum(sql.startswith('SELECT key,value FROM state WHERE key>=') for sql in statements)


def test_repeated_projection_loads_and_sorts_records_once(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    with store.db() as db:
        visibility.apply(db,[clear(),exclusion(),exclusion(chat=OTHER)],Store._canonical_chat)
    with store.db() as db:
        statements=[]
        db.set_trace_callback(statements.append)
        with visibility.read_snapshot(db):
            assert db.in_transaction
            for _ in range(20):
                assert projection(db,f'false_{CHAT}_TARGET')['state']=='deleted_for_me'
                result=visibility.clear_coverage(db,CHAT,Store._canonical_chat)
                assert result['boundary_unknown'] is True
                # Returned metadata cannot mutate the cached projection.
                result['boundary_unknown']=False
            assert scans(statements)==1
        statements.clear()
        visibility.records(db)
        visibility.records(db)
        assert scans(statements)==2


def test_scoped_and_uncached_states_match_mixed_visibility_and_aliases(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    randomizer=random.Random(508)
    items=[exclusion(f'M{i:03}',chat=randomizer.choice([CHAT,OTHER,GROUP]),
                     reason=randomizer.choice(['deleted_for_me','revoked']),
                     direction=randomizer.choice([False,True,None])) for i in range(60)]
    items.extend([clear(chat=CHAT,through=1050),clear(chat=OTHER),
                  exclusion('GROUP',chat=GROUP,direction=True),
                  exclusion('RAW',chat=LID),
                  {'kind':'chat','chat_id':OTHER,'reason':'chat_deleted',
                   'event_at':2000,'before':1100}])
    cases=[(f'{str(direction).lower()}_{chat}_M{i:03}',chat,1000+i*10)
           for chat in (CHAT,OTHER,GROUP,LID) for direction in (False,True) for i in range(60)]
    cases.extend([(f'true_{GROUP}_GROUP_{CHAT}',GROUP,1200),('RAW',CHAT,None),
                  (f'false_{CHAT}_RAW',CHAT,None),(f'false_{LID}_RAW',LID,None),
                  (f'false_{CHAT}_ANCHOR',CHAT,9999),('unserialized',OTHER,None)])
    with store.db() as db:
        db.execute('INSERT INTO chat_aliases VALUES(?,?)',(LID,CHAT))
        visibility.apply(db,items,Store._canonical_chat)
        expected=[projection(db,*case) for case in cases]
        expected_coverage=[visibility.clear_coverage(db,chat,Store._canonical_chat)
                           for chat in (None,CHAT,OTHER,GROUP,LID)]
        with visibility.read_snapshot(db):
            assert [projection(db,*case) for case in cases]==expected
            assert [visibility.clear_coverage(db,chat,Store._canonical_chat)
                    for chat in (None,CHAT,OTHER,GROUP,LID)]==expected_coverage


def test_local_writes_and_alias_binding_invalidate_cached_projection(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    with store.db() as db, visibility.read_snapshot(db):
        assert projection(db,f'false_{LID}_TARGET',LID)['state']=='unknown'
        assert visibility.clear_coverage(db,CHAT,Store._canonical_chat) is None
        visibility.apply(db,[exclusion(chat=LID),clear(chat=LID)],Store._canonical_chat)
        assert projection(db,f'false_{LID}_TARGET',LID)['state']=='deleted_for_me'
        assert projection(db,f'false_{CHAT}_TARGET')['state']=='unknown'
        db.execute('INSERT INTO chat_aliases VALUES(?,?)',(LID,CHAT))
        visibility.bind_alias(db,LID,CHAT)
        assert projection(db,f'false_{CHAT}_TARGET')['state']=='deleted_for_me'
        assert visibility.clear_coverage(db,CHAT,Store._canonical_chat)['boundary_unknown'] is True
        # Other state writers do not need to know about the visibility cache.
        db.execute('DELETE FROM state WHERE key>=? AND key<?',(visibility.PREFIX,visibility.PREFIX+'~'))
        assert projection(db,f'false_{CHAT}_TARGET')['state']=='unknown'
        assert visibility.clear_coverage(db,CHAT,Store._canonical_chat) is None


def test_legacy_clear_repair_invalidates_prior_empty_projection(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    with store.db() as db, visibility.read_snapshot(db):
        assert visibility.clear_coverage(db,CHAT,Store._canonical_chat) is None
        db.execute('DELETE FROM state WHERE key=?',(visibility.CLEAR_REPAIR,))
        db.execute('INSERT INTO account_events(id,event_type,chat_id,timestamp,data) VALUES(?,?,?,?,?)',
                   ('legacy-clear','chat.cleared',CHAT,2000,json.dumps({'eventAt':2000,'chatId':CHAT})))
        visibility.repair_clear_coverage(db,Store._canonical_chat)
        assert visibility.clear_coverage(db,CHAT,Store._canonical_chat)['boundary_unknown'] is True


def test_nested_connections_and_exception_do_not_share_or_retain_cache(tmp_path):
    one,two=Store(tmp_path/'one.sqlite'),Store(tmp_path/'two.sqlite')
    with one.db() as db:
        visibility.apply(db,[exclusion()],Store._canonical_chat)
    with one.db() as first, two.db() as second:
        with pytest.raises(RuntimeError,match='synthetic exit'):
            with visibility.read_snapshot(first):
                assert projection(first,f'false_{CHAT}_TARGET')['state']=='deleted_for_me'
                with visibility.read_snapshot(second):
                    assert projection(second,f'false_{CHAT}_TARGET')['state']=='unknown'
                    assert projection(first,f'false_{CHAT}_TARGET')['state']=='deleted_for_me'
                raise RuntimeError('synthetic exit')
        assert visibility._read_scopes.get()==()
        first.rollback()
        with visibility.read_snapshot(first):
            assert projection(first,f'false_{CHAT}_TARGET')['state']=='deleted_for_me'


def test_writer_commit_preserves_read_snapshot_but_next_page_sees_revocation(tmp_path):
    store=Store(tmp_path/'archive.sqlite')
    identifier=f'false_{CHAT}_TARGET'
    store.ingest(message(identifier,CHAT,timestamp=1500))

    def revoke():
        with store.db() as db:
            visibility.apply(db,[exclusion(reason='revoked')],Store._canonical_chat)

    with store.db() as reader:
        with visibility.read_snapshot(reader):
            assert projection(reader,identifier)['state']=='unknown'
            with ThreadPoolExecutor(max_workers=1) as executor:
                executor.submit(revoke).result(timeout=10)
            assert projection(reader,identifier)['state']=='unknown'
            assert reader.execute('SELECT id FROM messages m WHERE '+visibility.visible_sql()).fetchone()[0]==identifier
        reader.commit()
        # Same connection, distinct transaction/page: no inherited exclusion list.
        with visibility.read_snapshot(reader):
            assert projection(reader,identifier)['state']=='revoked'
            assert reader.execute('SELECT id FROM messages m WHERE '+visibility.visible_sql()).fetchone() is None


@pytest.mark.parametrize('method',['search','message','chats','message_state','clear_chat_coverage',
                                   'account_event','send_status'])
def test_store_read_paths_use_one_explicit_visibility_snapshot(tmp_path,monkeypatch,method):
    store=Store(tmp_path/'archive.sqlite')
    identifier=f'false_{CHAT}_TARGET'
    store.ingest(message(identifier,CHAT,timestamp=1500))
    with store.db() as db:
        visibility.apply(db,[clear()],Store._canonical_chat)
        db.execute('INSERT INTO account_events(id,event_type,chat_id,timestamp,data,source_message_id) VALUES(?,?,?,?,?,?)',
                   ('edit','message.edited',CHAT,1600,json.dumps({'id':identifier,'body':'Synthetic edit'}),identifier))
        db.execute('INSERT INTO sends VALUES(?,?,?,?,?,?,?)',
                   ('synthetic-key','synthetic-owner','synthetic-hash','submitted',identifier,1600,1600))
    statements=[]
    original=store.db

    @contextmanager
    def traced():
        with original() as db:
            db.set_trace_callback(statements.append)
            yield db

    monkeypatch.setattr(store,'db',traced)
    arguments={'message':(identifier,),'message_state':(identifier,),
               'clear_chat_coverage':(CHAT,),'account_event':('edit',),'send_status':('synthetic-key',)}
    assert getattr(store,method)(*arguments.get(method,())) is not None
    assert scans(statements)==1
    assert 'BEGIN' in statements
    assert visibility._read_scopes.get()==()
