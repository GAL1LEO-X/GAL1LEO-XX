"""A quoted raw stanza ID must not resurrect through another representation."""
import json

import pytest

from conftest import message
from sally_whatsapp import lifetime
from sally_whatsapp.linked_state_reads import project_live_read
from sally_whatsapp.operations import public_result
from sally_whatsapp.store import Store

CHAT='15550001111@c.us'
GROUP='15550002222@g.us'
OTHER_GROUP='15550003333@g.us'
PARTICIPANT='15550004444@c.us'
OTHER_PARTICIPANT='15550005555@c.us'
ALIAS='15550006666@lid'
NOW=1802880000
BODY='Synthetic source whose view-once lifetime must be preserved'


def observe_quote(store, chat, *, live=False, participant=None, direction=None):
    quote={'id':'RAW','body':BODY,'_data':{'imageMessage':{'caption':BODY,'viewOnce':True}}}
    if participant is not None: quote['participant']=participant
    if direction is not None: quote['fromMe']=direction
    parent=message(f'false_{chat}_PARENT',chat,timestamp=NOW,text='Ordinary parent')
    parent['payload']['replyTo']=quote
    if live:
        return project_live_read(store,'chats_get_chat_messages',{'path':{'chatId':chat}},
                                 [public_result(parent['payload'])])
    return store.ingest(parent)


@pytest.mark.parametrize('live',[False,True])
def test_raw_view_once_reference_blocks_serialized_replay_only_in_its_chat(tmp_path,monkeypatch,live):
    monkeypatch.setattr(lifetime.time,'time',lambda:NOW)
    store=Store(tmp_path/'state.sqlite')
    observe_quote(store,CHAT,live=live)
    target=f'false_{CHAT}_RAW'
    other=f'false_15550007777@c.us_RAW'
    store.ingest(message(target,CHAT,timestamp=NOW,text=BODY),historical=True)
    store.ingest(message(other,'15550007777@c.us',timestamp=NOW,text='Ordinary other chat'))
    assert store.message(target) is None
    assert store.message_state(target)['state']=='lifetime_unknown'
    assert store.message(other)['body']=='Ordinary other chat'
    projected=project_live_read(store,'chats_get_chat_message',{'path':{'chatId':CHAT,'messageId':target}},
                                public_result(message(target,CHAT,timestamp=NOW,text=BODY)['payload']))
    assert BODY not in json.dumps(projected)
    restarted=Store(store.path)
    assert restarted.message(target) is None and restarted.message(other) is not None


@pytest.mark.parametrize('live',[False,True])
def test_known_group_participant_and_direction_survive_live_projection_and_alias(tmp_path,monkeypatch,live):
    monkeypatch.setattr(lifetime.time,'time',lambda:NOW)
    store=Store(tmp_path/'state.sqlite')
    observe_quote(store,GROUP,live=live,participant=ALIAS,direction=False)
    store.bind_chat_alias(ALIAS,PARTICIPANT)
    identities=[(f'false_{GROUP}_RAW_{PARTICIPANT}',GROUP,False,False),
                (f'false_{GROUP}_RAW_{OTHER_PARTICIPANT}',GROUP,False,True),
                (f'true_{GROUP}_RAW_{PARTICIPANT}',GROUP,True,True),
                (f'false_{OTHER_GROUP}_RAW_{PARTICIPANT}',OTHER_GROUP,False,True)]
    for identifier,chat,direction,visible in identities:
        store.ingest(message(identifier,chat,from_me=direction,timestamp=NOW,text=BODY),historical=True)
        assert (store.message(identifier) is not None)==visible
        assert (store.message_state(identifier)['state']=='unknown')==visible
    assert len(store.search(query='view-once')['messages'])==3


def test_ambiguous_raw_reference_withholds_but_does_not_destructively_purge_candidates(tmp_path,monkeypatch):
    monkeypatch.setattr(lifetime.time,'time',lambda:NOW)
    store=Store(tmp_path/'state.sqlite')
    target=f'false_{GROUP}_RAW_{PARTICIPANT}'
    store.ingest(message(target,GROUP,timestamp=NOW,text=BODY))
    observe_quote(store,GROUP)
    assert store.message(target) is None
    assert store.message_state(target)['state']=='lifetime_unknown'
    with store.db() as db:
        assert db.execute('SELECT body,deleted FROM messages WHERE id=?',(target,)).fetchone()['body']==BODY
        assert not db.execute("SELECT 1 FROM message_mutations WHERE message_id=? AND kind='revoked'",(target,)).fetchone()


def test_raw_quote_does_not_purge_an_equal_legacy_id_from_another_chat(tmp_path,monkeypatch):
    monkeypatch.setattr(lifetime.time,'time',lambda:NOW)
    store=Store(tmp_path/'state.sqlite')
    store.ingest(message('RAW',OTHER_GROUP,timestamp=NOW,text='Ordinary other legacy chat'))
    observe_quote(store,GROUP)
    assert store.message('RAW')['body']=='Ordinary other legacy chat'
    assert store.search(chat_id=OTHER_GROUP)['messages'][0]['body']=='Ordinary other legacy chat'


def test_raw_legacy_row_with_known_opposite_direction_is_preserved(tmp_path,monkeypatch):
    monkeypatch.setattr(lifetime.time,'time',lambda:NOW)
    store=Store(tmp_path/'state.sqlite')
    store.ingest(message('RAW',CHAT,from_me=True,timestamp=NOW,text='Ordinary outgoing legacy message'))
    observe_quote(store,CHAT,direction=False)
    assert store.message('RAW')['body']=='Ordinary outgoing legacy message'
    assert store.message_state('RAW')['state']=='unknown'
