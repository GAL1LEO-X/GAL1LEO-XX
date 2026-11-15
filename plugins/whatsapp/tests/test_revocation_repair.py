"""Synthetic repair of data written by the pre-fix schema-7 application."""
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3

import pytest

from sally_whatsapp.server import create_app
from sally_whatsapp.store import Store,SCHEMA,canonical,REVOCATION_REPAIR_KEY,REVOCATION_REPAIR_BATCH


def old_store(path):
    with sqlite3.connect(path) as db: db.executescript(SCHEMA)
    return Store(path,migrate_schema=False)


def reaction_row(db,identifier,data,source='wrong-reaction-id'):
    db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,?)',
               (identifier,'message.reaction','synthetic@g.us',100,canonical(data),source))


def payload(target='original'):
    return {'id':'wrong-reaction-id','reaction':{'messageId':target,'text':'synthetic reaction'}}


def media_row(db,identifier,*,state='ready',source='original',error=None):
    db.execute('INSERT INTO media_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (identifier,'synthetic-owner','identity-'+identifier,state,b'synthetic encrypted source',
                'sensitive synthetic filename.txt','text/plain',48,'a'*64,100,9999999999,error,source))


def tombstone(db,identifier='original'):
    db.execute("INSERT INTO message_mutations VALUES(?,'revoked',NULL,100)",(identifier,))


def rows(store,table):
    with store.db() as db: return [tuple(row) for row in db.execute('SELECT * FROM '+table+' ORDER BY rowid')]


def test_repair_rolls_back_every_batch_and_marker_then_retries_completely(tmp_path,monkeypatch):
    path=tmp_path/'schema7.sqlite';store=old_store(path)
    count=2*REVOCATION_REPAIR_BATCH+3
    with store.db() as db:
        tombstone(db)
        for index in range(count): reaction_row(db,f'reaction-{index}',payload())
        media_row(db,'terminal',state='cancelled')
    before_events=rows(store,'account_events');before_media=rows(store,'media_jobs')
    original=Store._state
    def reject_completion(db,key,value):
        if key==REVOCATION_REPAIR_KEY:
            # All pages and the media correction were already calculated/written.
            assert db.execute("SELECT count(*) FROM account_events WHERE source_message_id='original'").fetchone()[0]==count
            assert db.execute('SELECT filename FROM media_jobs').fetchone()[0]==''
            raise RuntimeError('synthetic completion failure')
        return original(db,key,value)
    monkeypatch.setattr(Store,'_state',staticmethod(reject_completion))
    with pytest.raises(RuntimeError,match='synthetic completion failure'):
        Store(path,migrate_schema=True)
    assert rows(store,'account_events')==before_events and rows(store,'media_jobs')==before_media
    assert rows(store,'state')==[]
    # Defensive reads remain safe even though the failed transaction repaired nothing.
    assert store.account_event('reaction-0')['data']=={'message_id':'original','revoked':True}
    monkeypatch.setattr(Store,'_state',staticmethod(original))
    restarted=Store(path,migrate_schema=True)
    with restarted.db() as db:
        assert db.execute("SELECT count(*) FROM account_events WHERE source_message_id='original'").fetchone()[0]==count
        assert json.loads(db.execute('SELECT value FROM state WHERE key=?',(REVOCATION_REPAIR_KEY,)).fetchone()[0]) is True
        assert db.execute('SELECT filename,mimetype,size,sha256 FROM media_jobs').fetchone()[:]==('','',None,None)
        assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    assert REVOCATION_REPAIR_KEY not in restarted.state()


def test_successful_repair_is_not_rescanned_on_second_start(tmp_path,monkeypatch):
    path=tmp_path/'schema7.sqlite';store=old_store(path)
    with store.db() as db:
        tombstone(db);reaction_row(db,'reaction',payload());media_row(db,'file')
    Store(path)
    statements=[];original=Store.db
    @contextmanager
    def traced_db(self):
        with original(self) as db:
            db.set_trace_callback(statements.append)
            yield db
    monkeypatch.setattr(Store,'db',traced_db)
    Store(path)
    assert not any(sql.startswith('SELECT * FROM account_events') or sql.startswith('SELECT * FROM media_jobs') for sql in statements)
    assert not any(sql.startswith('UPDATE account_events') or sql.startswith('UPDATE media_jobs') for sql in statements)


def test_check_and_maintenance_skip_existing_schema7_repair(environment):
    settings,receiver,gateway,_=environment;store=old_store(settings.database)
    with store.db() as db:
        tombstone(db);reaction_row(db,'reaction',payload());media_row(db,'old-ready',state='cancelled',source=None,
            error='Transfer invalidated by schema upgrade; request the file again')
    before={table:rows(store,table) for table in ('account_events','media_jobs','state')}
    app=create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False,recover_inflight=False)
    assert app.state.service.store.account_event('reaction')['data']=={'message_id':'original','revoked':True}
    assert {table:rows(store,table) for table in before}==before


@pytest.mark.parametrize('state',['queued','downloading','ready','cancelled','failed','expired'])
def test_targeted_revoke_redacts_media_including_terminal_rows(tmp_path,state):
    store=old_store(tmp_path/'schema7.sqlite')
    with store.db() as db:
        media_row(db,'target',state=state)
        media_row(db,'external',source=None)
    before=rows(store,'media_jobs')[1]
    store.ingest({'id':'synthetic-revoke','event':'message.revoked','payload':{'revokedMessageId':'original'}})
    with store.db() as db:
        row=db.execute('SELECT * FROM media_jobs WHERE id=?',('target',)).fetchone()
        assert (row['state'],row['source'],row['filename'],row['mimetype'],row['size'],row['sha256'])==('cancelled',b'','','',None,None)
        assert (row['id'],row['owner'],row['source_message_id'])==('target','synthetic-owner','original')
    assert rows(store,'media_jobs')[1]==before


def test_startup_media_repair_is_precise_and_keeps_external_uploads(tmp_path):
    path=tmp_path/'schema7.sqlite';store=old_store(path)
    with store.db() as db:
        tombstone(db)
        for index,state in enumerate(('ready','cancelled','failed','expired')):
            media_row(db,'revoked-'+str(index),state=state)
        media_row(db,'legacy-ready',state='cancelled',source=None,error='Transfer invalidated by schema upgrade; request the file again')
        media_row(db,'legacy-unknown',state='cancelled',source='',error='Source unavailable after upgrade; request the file again')
        media_row(db,'prior-revoke',state='cancelled',source=None,error='Source message revoked')
        media_row(db,'external-ready',source=None)
        media_row(db,'external-cancelled',state='cancelled',source=None,error='Synthetic unrelated cancellation')
        media_row(db,'unrelated',source='alive')
    before={row[0]:row for row in rows(store,'media_jobs')}
    repaired=Store(path)
    for row in rows(repaired,'media_jobs'):
        if row[0] in ('external-ready','external-cancelled','unrelated'):
            assert row==before[row[0]]
        else:
            assert row[3:9]==('cancelled',b'','','',None,None)
            assert row[0:3]==before[row[0]][0:3] and row[12]==before[row[0]][12]


@pytest.mark.parametrize('data',[None,[],{'id':'original'}, {'id':'original','reaction':False},
                                {'id':'original','reaction':{'messageId':42}},
                                {'id':'original','reaction':{'messageId':''}}])
def test_malformed_reactions_do_not_invent_a_target_or_redact_unrelated_data(tmp_path,data):
    path=tmp_path/'schema7.sqlite';store=old_store(path)
    with store.db() as db:
        tombstone(db);reaction_row(db,'malformed',data,source='original')
    original_data=rows(store,'account_events')[0][4]
    repaired=Store(path)
    with repaired.db() as db:
        row=db.execute('SELECT data,source_message_id FROM account_events').fetchone()
        assert row[0]==original_data and row[1] is None
    assert repaired.account_event('malformed')['data']!=(repaired.redacted_event('original'))


def test_invalid_json_repair_does_not_crash_and_preserves_existing_tombstones(tmp_path):
    path=tmp_path/'schema7.sqlite';store=old_store(path)
    redacted={'message_id':'already-gone','revoked':True}
    with store.db() as db:
        reaction_row(db,'invalid',{},source='original')
        db.execute("UPDATE account_events SET data='{' WHERE id='invalid'")
        reaction_row(db,'redacted',redacted,source='already-gone')
        reaction_row(db,'missing-source',redacted,source=None)
    repaired=Store(path)
    assert repaired.account_event('invalid')['data']=={}
    for identifier in ('redacted','missing-source'):
        assert repaired.account_event(identifier)['data']==redacted
        with repaired.db() as db:
            assert db.execute('SELECT source_message_id FROM account_events WHERE id=?',(identifier,)).fetchone()[0]=='already-gone'


def test_revoking_stale_stored_id_does_not_redact_a_different_reaction_target(tmp_path):
    store=old_store(tmp_path/'schema7.sqlite')
    data=payload('alive')
    with store.db() as db: reaction_row(db,'mislinked',data,source='original')
    store.ingest({'id':'synthetic-revoke','event':'message.revoked','payload':{'revokedMessageId':'original'}})
    assert store.account_event('mislinked')['data']==data
    assert json.loads(rows(store,'account_events')[0][4])==data
    restarted=Store(store.path)
    assert rows(restarted,'account_events')[0][5]=='alive'


def test_declared_schema6_repair_handles_malformed_reactions_and_clears_ready_metadata(tmp_path,monkeypatch):
    import release_database
    path=tmp_path/'schema6.sqlite'
    with sqlite3.connect(path) as db:
        db.executescript((Path(__file__).parent/'fixtures/schema6.sql').read_text())
        tombstone(db)
        for identifier,data in [('invalid','{'),('typed',canonical({'id':'original','reaction':{'messageId':42}})),
                                ('correct',canonical(payload()))]:
            db.execute('INSERT INTO account_events VALUES(?,?,?,?,?)',(identifier,'message.reaction','synthetic@g.us',100,data))
        db.execute('INSERT INTO media_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                   ('legacy','synthetic-owner','identity','ready',b'','private.txt','text/plain',48,'a'*64,100,9999999999,None))
    steps=[];execute_script=release_database.execute_script
    def traced_script(db,sql):
        before=db.execute('PRAGMA user_version').fetchone()[0]
        execute_script(db,sql)
        if before>=6:
            steps.append((before,db.execute('PRAGMA user_version').fetchone()[0]))
    monkeypatch.setattr(release_database,'execute_script',traced_script)
    assert release_database.migrate(path,Path(__file__).resolve().parents[1])=={
        'fromSchema':6,'toSchema':8,'integrity':'ok','recordIdentitiesPreserved':True}
    assert steps==[(6,7),(7,8)]
    checked=Store(path,migrate_schema=False)
    with checked.db() as db:
        assert db.execute('SELECT filename,mimetype,size,sha256 FROM media_jobs').fetchone()[:]==('','',None,None)
        assert db.execute("SELECT source_message_id FROM account_events WHERE id='typed'").fetchone()[0] is None
        assert db.execute("SELECT source_message_id FROM account_events WHERE id='invalid'").fetchone()[0] is None
    assert checked.account_event('correct')['data']=={'message_id':'original','revoked':True}
    assert rows(checked,'state')==[]
