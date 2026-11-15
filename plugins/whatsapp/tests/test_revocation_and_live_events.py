"""Revocation races and historical/live acquisition, using synthetic fixtures only."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from threading import Barrier
from types import SimpleNamespace
import time

import pytest

from conftest import attachment_payload, install_attachment_readback, call, message, subscribe
from sally_whatsapp.gateway import GatewayUnavailable
from sally_whatsapp.server import Service, create_app
from sally_whatsapp.store import Store, canonical

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def revoke(identifier, before=None):
    return {'id':'revoke-'+identifier,'event':'message.revoked','session':'default',
            'timestamp':int(time.time()*1000),'payload':{'revokedMessageId':identifier,'before':before or {}}}


def edit(identifier, body, suffix=''):
    return {'id':'edit-'+identifier+suffix,'event':'message.edited','timestamp':int(time.time()*1000),
            'payload':{'editedMessageId':identifier,'body':body}}


def attachment(service, identifier='false_group-1@g.us_ATTACHMENT'):
    envelope=message(identifier)
    envelope['payload']=attachment_payload(identifier,'group-1@g.us',service.gateway.media_bytes,
        name='synthetic.txt',mimetype='text/plain')
    install_attachment_readback(service.gateway,envelope['payload'])
    service.store.ingest(envelope)
    return service.media.enqueue(service.settings.owner_subject,{'kind':'gateway','message_id':identifier,
        'chat_id':'group-1@g.us','media':envelope['payload']['media']},'synthetic.txt')


def test_revoked_events_are_redacted_before_and_after_original(app_client):
    app,client=app_client
    store=app.state.service.store
    subscribe(client)
    envelope=message('redacted',text='original secret')
    envelope['payload']['vCards']=['synthetic vcard secret']
    store.ingest(envelope)
    store.ingest(edit('redacted','edited secret'))
    store.ingest(revoke('redacted',envelope['payload']))
    store.ingest(edit('redacted','late edit secret','-late'))
    assert call(client,'get_message',{'message_id':'redacted'})['result']['structuredContent']['message'] is None
    for event in store.list_account_events()['events']:
        detail=call(client,'get_account_event',{'event_id':event['id']})['result']['structuredContent']['event']
        assert detail['data']=={'message_id':'redacted','revoked':True}
        assert 'source_message_id' not in detail
    with store.db() as db:
        assert db.execute("SELECT body,media FROM messages WHERE id='redacted'").fetchone()[:]==('',None)
        assert not db.execute("SELECT * FROM message_content WHERE message_id='redacted'").fetchall()
        assert all('secret' not in r[0] for r in db.execute('SELECT body FROM deliveries'))
    store.ingest(revoke('before-original'))
    store.ingest(edit('before-original','secret before original'))
    store.ingest(message('before-original',text='late original secret'),historical=True)
    assert store.message('before-original') is None
    assert store.search('secret')['messages']==[]


def test_revoke_during_callback_cancels_retry(environment,app_client):
    app,client=app_client
    service,receiver=app.state.service,environment[1]
    subscribe(client)
    service.store.ingest(message('in-flight',text='private preview'))
    original=receiver.post
    def post(url,body,headers):
        service.store.ingest(revoke('in-flight'))
        receiver.responses=[(503,b'')]
        return original(url,body,headers)
    receiver.post=post
    assert service.events.dispatch_one()
    receiver.post=original
    assert not service.events.dispatch_one(now=time.time()+120)
    assert service.store.state()['deliveries']=={'cancelled':1}
    with service.store.db() as db:
        assert json.loads(db.execute('SELECT body FROM deliveries').fetchone()[0])['data']['preview']==''


def test_revoke_before_restart_cancels_abandoned_delivery(environment,app_client):
    app,client=app_client
    service=app.state.service
    subscribe(client)
    service.store.ingest(message('lease'))
    with service.store.db() as db:
        db.execute("UPDATE deliveries SET state='sending',lease_until=?,attempts=1",(time.time()-1,))
    service.store.ingest(revoke('lease'))
    restarted=Service(environment[0],gateway=environment[2],event_transport=environment[1])
    assert not restarted.events.dispatch_one()
    assert restarted.store.state()['deliveries']=={'cancelled':1}


@pytest.mark.parametrize('stage',['queued','ready'])
def test_revoke_invalidates_attachment_and_existing_grant(environment,app_client,stage):
    app,client=app_client
    service=app.state.service
    transfer=attachment(service)
    grant=None
    if stage=='ready':
        assert service.media.process_one()
        grant=service.media.status(transfer['id'],'test-owner')['download_url']
        assert client.get(grant).status_code==200
    service.store.ingest(revoke('false_group-1@g.us_ATTACHMENT'))
    assert service.media.status(transfer['id'],'test-owner')['state']=='cancelled'
    assert not service.media.process_one()
    if grant: assert client.get(grant).status_code==404
    assert not service.media.path(transfer['id']).exists()
    with pytest.raises(ValueError,match='revoked'):
        service.media.enqueue('test-owner',{'kind':'gateway','message_id':'false_group-1@g.us_ATTACHMENT','chat_id':'group-1@g.us'})


@pytest.mark.parametrize('outcome',['success','failure','expired-source'])
def test_revoke_during_download_wins_over_completion_and_retry(environment,app_client,outcome):
    app,_=app_client
    service,gateway=app.state.service,environment[2]
    transfer=attachment(service)
    calls=[]
    records=[]
    service.media.diagnostics=SimpleNamespace(emit=lambda event,*args,**fields: records.append((event,fields)))
    def download(media,target,maximum):
        calls.append('download')
        target.write_bytes(b'synthetic bytes')
        service.store.ingest(revoke('false_group-1@g.us_ATTACHMENT'))
        if outcome=='expired-source': raise GatewayUnavailable('synthetic 404',status_code=404)
        if outcome=='failure': raise ValueError('synthetic failure')
        return 15,hashlib.sha256(b'synthetic bytes').hexdigest()
    gateway.attachment_to_file=download
    gateway.message=lambda *a,**kw: pytest.fail('A revoked source must not be fetched again')
    assert service.media.process_one()
    assert calls==['download']
    assert service.media.status(transfer['id'],'test-owner')['state']=='cancelled'
    assert not service.media.path(transfer['id']).exists()
    assert [fields['state'] for event,fields in records if event=='transfer.finished']==['cancelled']


def test_revoke_is_scoped_to_source_and_instance(environment,tmp_path):
    settings,receiver,gateway,_=environment
    first=Service(settings,gateway=gateway,event_transport=receiver)
    second=Service(replace(settings,database=tmp_path/'other'/'archive.sqlite',owner_subject='other-owner'),gateway=gateway,event_transport=receiver)
    a=attachment(first,'same-id');b=attachment(second,'same-id');unrelated=attachment(first,'other-id')
    external=first.media.enqueue('test-owner',{'kind':'external','file_id':'file-synthetic','download_url':'https://public.example/synthetic'})
    first.store.ingest(revoke('same-id'))
    assert first.media.status(a['id'],'test-owner')['state']=='cancelled'
    assert second.media.status(b['id'],'other-owner')['state']=='queued'
    assert first.media.status(unrelated['id'],'test-owner')['state']=='queued'
    assert first.media.status(external['id'],'test-owner')['state']=='queued'
    with pytest.raises(ValueError,match='not found'): second.media.status(b['id'],'test-owner')


@pytest.mark.parametrize('same_envelope',[True,False])
def test_history_first_live_webhook_notifies_exactly_once(app_client,same_envelope):
    app,client=app_client
    service=app.state.service
    subscribe(client)
    envelope=message('historical-first')
    service.store.ingest(envelope,historical=True)
    assert service.store.state()['deliveries']=={}
    if not same_envelope: envelope['id']='new-webhook-envelope'
    assert service.store.ingest(envelope)['duplicate'] is True
    assert service.store.ingest(envelope)['duplicate'] is True
    envelope['id']='another-webhook-envelope'
    service.store.ingest(envelope)
    assert service.store.state()['archive_messages']==1
    assert service.store.state()['deliveries']=={'pending':1}


def test_history_live_race_and_current_mutation_are_preserved(app_client):
    app,client=app_client
    store=app.state.service.store
    subscribe(client)
    for index in range(8):
        envelope=message('concurrent-'+str(index))
        barrier=Barrier(2)
        def ingest(historical):
            barrier.wait(timeout=5)
            return store.ingest(envelope,historical=historical)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(ingest,value) for value in (True,False)]
            for future in futures: future.result(timeout=10)
    assert store.state()['archive_messages']==8
    assert store.state()['deliveries']=={'pending':8}
    envelope=message('edited-import',text='obsolete')
    store.ingest(envelope,historical=True)
    store.ingest(edit('edited-import','current'))
    store.ingest(envelope)
    with store.db() as db:
        last=json.loads(db.execute('SELECT body FROM deliveries ORDER BY id DESC LIMIT 1').fetchone()[0])
    assert last['data']['preview']=='current'


def test_live_observation_without_subscription_never_replays_later(app_client):
    app,client=app_client
    store=app.state.service.store
    envelope=message('before-subscription')
    store.ingest(envelope,historical=True)
    store.ingest(envelope)
    subscribe(client)
    envelope['id']='repeated-after-subscription'
    store.ingest(envelope)
    assert store.state()['deliveries']=={}


def legacy_database(path):
    path.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(path) as db:
        db.executescript((Path(__file__).parent/'fixtures/schema6.sql').read_text())


def test_declared_migration_matches_packaged_sql_and_preserves_source_copy(tmp_path):
    from release_database import migrate,snapshot
    plugin=Path(__file__).resolve().parents[1]
    assert (plugin/'deploy/6-7.sql').read_bytes()==(plugin/'sally_whatsapp/migrations/6-7.sql').read_bytes()
    source=tmp_path/'old'/'archive.sqlite';legacy_database(source)
    with sqlite3.connect(source) as db:
        db.execute("INSERT INTO messages(id,chat_id,timestamp,from_me,body,source,observed_at) VALUES('existing','group-1@g.us',?,0,'preserved','webhook',?)",(int(time.time()),time.time()))
        db.execute("INSERT INTO account_events VALUES('event','message.edited',NULL,?,'{\"editedMessageId\":\"existing\",\"body\":\"preserved\"}')",(time.time(),))
    before=source.read_bytes()
    target=tmp_path/'copy.sqlite';snapshot(source,target)
    assert migrate(target,plugin)['toSchema']==8
    assert source.read_bytes()==before
    upgraded=Store(target)
    assert upgraded.message('existing')['body']=='preserved'
    with upgraded.db() as db:
        assert db.execute('SELECT message_id FROM message_live_receipts').fetchall()[0][0]=='existing'
        assert db.execute('SELECT source_message_id FROM account_events').fetchone()[0]=='existing'


def test_legacy_media_backfill_revocation_and_upload_preservation(environment,tmp_path):
    settings,receiver,gateway,_=environment
    legacy_database(settings.database)
    from cryptography.fernet import Fernet
    cipher=Fernet(settings.encryption_key_file.read_bytes())
    def transfer(db,index,state,source):
        identifier='media_'+str(index)*32
        db.execute('INSERT INTO media_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(identifier,'test-owner',str(index),state,
            cipher.encrypt(canonical(source).encode()) if source else b'','synthetic.txt','text/plain',None,None,time.time(),time.time()+3600,None))
        return identifier
    with sqlite3.connect(settings.database) as db:
        db.execute("INSERT INTO message_mutations VALUES('deleted','revoked',NULL,?)",(time.time(),))
        ready=transfer(db,1,'ready',None)
        queued=transfer(db,2,'queued',{'kind':'gateway','message_id':'deleted','chat_id':'group-1@g.us'})
        external=transfer(db,3,'queued',{'kind':'external','file_id':'synthetic','download_url':'https://public.example/file'})
        db.execute("INSERT INTO account_events VALUES('old-edit','message.edited',NULL,?,'{\"editedMessageId\":\"deleted\",\"body\":\"old private text\"}')",(time.time(),))
    root=settings.database.parent/'media-cache';root.mkdir()
    (root/(ready+'.bin')).write_bytes(b'synthetic legacy cache')
    service=Service(settings,gateway=gateway,event_transport=receiver)
    old_grant=cipher.encrypt(canonical({'purpose':'media-download','id':ready,'expires':time.time()+3000}).encode()).decode()
    with pytest.raises(ValueError,match='not ready'): service.media.resolve(old_grant)
    assert service.media.status(ready,'test-owner')['state']=='cancelled'
    assert not service.media.path(ready).exists()
    assert service.media.status(queued,'test-owner')['state']=='cancelled'
    assert service.media.status(external,'test-owner')['state']=='queued'
    assert service.store.account_event('old-edit')['data']=={'message_id':'deleted','revoked':True}
    with service.store.db() as db:
        assert db.execute('SELECT source_message_id FROM media_jobs WHERE id=?',(external,)).fetchone()[0] is None


def test_check_refuses_legacy_migration_without_touching_jobs(environment):
    settings,receiver,gateway,_=environment
    legacy_database(settings.database)
    with sqlite3.connect(settings.database) as db:
        db.execute("INSERT INTO media_jobs VALUES('media_11111111111111111111111111111111','test-owner','identity','ready',X'','synthetic','text/plain',NULL,NULL,0,9999999999,NULL)")
    with pytest.raises(RuntimeError,match='schema upgrade required'):
        create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False,recover_inflight=False)
    with sqlite3.connect(settings.database) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==6
        assert db.execute('SELECT state FROM media_jobs').fetchone()[0]=='ready'


def test_recovery_reconciliation_does_not_implicitly_upgrade_legacy_database(environment,monkeypatch):
    from sally_whatsapp import cli
    settings=environment[0]
    legacy_database(settings.database)
    with sqlite3.connect(settings.database) as db:
        db.execute("INSERT INTO state VALUES('recovery_required','true')")
        db.execute("INSERT INTO media_jobs VALUES('media_11111111111111111111111111111111','test-owner','identity','ready',X'','synthetic','text/plain',NULL,NULL,0,9999999999,NULL)")
    monkeypatch.setattr(cli.Settings,'load',lambda path:settings)
    monkeypatch.setattr(sys,'argv',['sally-whatsapp','--config','synthetic.toml','reconcile-recovery',
                                    '--reason','legacy_unknown','--last-seen','unknown'])
    with pytest.raises(RuntimeError,match='schema upgrade required'):
        cli.main()
    with sqlite3.connect(settings.database) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==6
        assert db.execute("SELECT value FROM state WHERE key='recovery_required'").fetchone()[0]=='true'
        assert db.execute('SELECT state FROM media_jobs').fetchone()[0]=='ready'


@pytest.mark.parametrize('version',[0,1,2,3,4,5,6])
def test_store_accepts_old_version_numbers_on_complete_schema6_fixture(tmp_path,version):
    # The v6 layout is a fixed historical fixture; this does not certify every
    # layout ever used by versions 0..5, which bootstrap missing tables as before.
    path=tmp_path/'legacy.sqlite';legacy_database(path)
    with sqlite3.connect(path) as db: db.execute('PRAGMA user_version='+str(version))
    store=Store(path)
    with store.db() as db: assert db.execute('PRAGMA user_version').fetchone()[0]==8


def test_check_does_not_backfill_or_clean_existing_schema7_jobs(environment):
    settings,receiver,gateway,_=environment
    store=Store(settings.database)
    identifier='media_'+'4'*32
    with store.db() as db:
        db.execute('INSERT INTO media_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (identifier,'test-owner','synthetic','queued',b'encrypted legacy source',
                    'synthetic.txt','text/plain',None,None,time.time(),time.time()+100,None,''))
    create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False,recover_inflight=False)
    with store.db() as db:
        assert db.execute('SELECT state,source_message_id,source FROM media_jobs WHERE id=?',(identifier,)).fetchone()[:]==('queued','',b'encrypted legacy source')
