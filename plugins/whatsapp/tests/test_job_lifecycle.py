from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
from threading import Barrier,Event,current_thread
from types import SimpleNamespace

import pytest

from sally_whatsapp.server import Service
from conftest import message


def service_for(environment):
    settings,receiver,gateway,_=environment
    return Service(settings,gateway=gateway,event_transport=receiver)


@pytest.mark.parametrize('terminal',['cancelled','completed'])
def test_terminal_history_cannot_be_reactivated(environment,terminal):
    service=service_for(environment);history=service.history
    job=history.start('test-owner','terminal-history',['fixture@g.us'],until=100)
    if terminal=='cancelled': history.control(job['id'],'test-owner','cancel')
    else:
        history.process_one();history.process_one()
    assert history.status(job['id'],'test-owner')['state']==terminal
    for action in ('pause','resume'):
        with pytest.raises(ValueError,match='terminal'): history.control(job['id'],'test-owner',action)
    for _ in range(2): assert history.control(job['id'],'test-owner','cancel')['state']==terminal
    assert history.start('test-owner','terminal-history',['fixture@g.us'],until=100)['state']==terminal
    with pytest.raises(ValueError,match='not found'): history.control(job['id'],'other-owner','cancel')
    assert history.process_one() is False


def test_repeated_controls_and_worker_cancellation(environment):
    service=service_for(environment);history=service.history
    job=history.start('test-owner','repeated-history',['fixture@g.us'],until=100)
    for action,state in [('pause','paused'),('pause','paused'),('resume','running'),('resume','running')]:
        assert history.control(job['id'],'test-owner',action)['state']==state
    def messages(*args):
        history.control(job['id'],'test-owner','cancel')
        return []
    service.gateway.messages=messages
    history.process_one()
    assert history.status(job['id'],'test-owner')['state']=='cancelled'


@pytest.mark.parametrize('action,state',[('pause','paused'),('cancel','cancelled')])
@pytest.mark.parametrize('phase',['fetch','resolve'])
def test_inflight_page_is_discarded_after_control(environment,action,state,phase):
    service=service_for(environment);history=service.history
    job=history.start('test-owner','inflight-history',['fixture@g.us'],until=100)
    page=[message('inflight-'+str(i),chat='fixture@g.us',timestamp=50)['payload'] for i in range(2)]
    stopped=False
    def stop():
        nonlocal stopped
        if not stopped:
            history.control(job['id'],'test-owner',action)
            stopped=True
    def fetch(*args):
        if phase=='fetch': stop()
        return page
    def resolve(chat):
        if phase=='resolve': stop()
        return service.resolve_chat(chat)
    service.gateway.messages=fetch;history.resolve_chat=resolve
    assert history.process_one()
    status=history.status(job['id'],'test-owner')
    assert status['state']==state and status['messages_scanned']==status['messages_inserted']==0
    assert status['message_offset']==status['chat_index']==0
    assert service.store.state()['archive_messages']==0
    with service.store.db() as db: assert db.execute('SELECT count(*) FROM receipts').fetchone()[0]==0
    if action=='pause':
        history.control(job['id'],'test-owner','resume')
        assert history.process_one()
        assert history.status(job['id'],'test-owner')['messages_inserted']==2
        assert service.store.state()['archive_messages']==2


@pytest.mark.parametrize('action,state',[('pause','paused'),('cancel','cancelled')])
def test_control_during_page_commit_preserves_matching_archive_and_counters(environment,monkeypatch,action,state):
    service=service_for(environment);history=service.history
    job=history.start('test-owner','committing-history',['fixture@g.us'],until=100)
    service.gateway.pages=[[message('committing-'+str(i),chat='fixture@g.us',timestamp=50)['payload'] for i in range(2)]]
    first_written=Event();release=Event();control_started=Event()
    original_ingest=service.store.ingest;original_db=service.store.db
    def ingest(*args,**kwargs):
        outcome=original_ingest(*args,**kwargs)
        if not first_written.is_set():
            first_written.set()
            assert release.wait(timeout=5)
        return outcome
    @contextmanager
    def observed_db():
        with original_db() as db:
            if current_thread().name.startswith('history-control'):
                db.set_trace_callback(lambda sql:control_started.set() if sql=='BEGIN IMMEDIATE' else None)
            yield db
    monkeypatch.setattr(service.store,'ingest',ingest)
    monkeypatch.setattr(service.store,'db',observed_db)
    with ThreadPoolExecutor(max_workers=1) as workers,ThreadPoolExecutor(max_workers=1,thread_name_prefix='history-control') as controls:
        worker=workers.submit(history.process_one)
        try:
            assert first_written.wait(timeout=5)
            control=controls.submit(history.control,job['id'],'test-owner',action)
            assert control_started.wait(timeout=5)
            assert not control.done()
            assert service.store.state()['archive_messages']==0
        finally: release.set()
        assert worker.result(timeout=5)
        status=control.result(timeout=5)
    assert status['state']==state
    assert status['messages_scanned']==status['messages_inserted']==2
    assert service.store.state()['archive_messages']==2
    assert history.process_one() is False


def test_invalid_page_rolls_back_messages_receipts_and_progress(environment):
    service=service_for(environment);history=service.history
    job=history.start('test-owner','invalid-page-history',['fixture@g.us'],until=100)
    page=[message('rollback-'+str(i),chat='fixture@g.us',timestamp=50)['payload'] for i in range(2)]
    page[1]['fromMe']='invalid'
    service.gateway.pages=[page]
    assert history.process_one()
    status=history.status(job['id'],'test-owner')
    assert status['state']=='failed' and status['messages_scanned']==status['messages_inserted']==0
    assert status['message_offset']==status['chat_index']==0
    assert service.store.state()['archive_messages']==0
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM receipts').fetchone()[0]==0
        assert db.execute('SELECT count(*) FROM message_search').fetchone()[0]==0
    page[1]['fromMe']=False;service.gateway.pages=[page]
    history.control(job['id'],'test-owner','resume')
    assert history.process_one()
    assert history.status(job['id'],'test-owner')['messages_inserted']==2
    assert service.store.state()['archive_messages']==2


def test_concurrent_workers_cannot_overwrite_committed_page_progress(environment):
    service=service_for(environment);history=service.history
    job=history.start('test-owner','concurrent-page-history',['fixture@g.us'],until=100)
    fetched=Barrier(2)
    def messages(*args):
        fetched.wait(timeout=5)
        return [message('shared-page',chat='fixture@g.us',timestamp=50)['payload']]
    service.gateway.messages=messages
    with ThreadPoolExecutor(max_workers=2) as workers:
        first=workers.submit(history.process_one);second=workers.submit(history.process_one)
        assert first.result(timeout=5) and second.result(timeout=5)
    status=history.status(job['id'],'test-owner')
    assert status['messages_scanned']==status['messages_inserted']==1
    assert status['completed_chats']==1 and service.store.state()['archive_messages']==1


def test_concurrent_resume_and_cancel_always_end_cancelled(environment):
    history=service_for(environment).history
    with ThreadPoolExecutor(max_workers=2) as executor:
        for attempt in range(12):
            job=history.start('test-owner','race-history-'+str(attempt),['fixture@g.us'],until=100)
            history.control(job['id'],'test-owner','pause')
            barrier=Barrier(2)
            def control(action):
                barrier.wait(timeout=5)
                try: history.control(job['id'],'test-owner',action)
                except ValueError:
                    if action!='resume': raise
            resume=executor.submit(control,'resume');cancel=executor.submit(control,'cancel')
            resume.result(timeout=10);cancel.result(timeout=10)
            assert history.status(job['id'],'test-owner')['state']=='cancelled'


@pytest.mark.parametrize('history_state',['running','paused','failed'])
@pytest.mark.parametrize('media_state',['queued','downloading'])
def test_suspension_cancels_pending_jobs_across_resume_and_restart(environment,tmp_path,monkeypatch,history_state,media_state):
    settings,receiver,gateway,_=environment
    settings=replace(settings,database=tmp_path/'archive.sqlite')
    service=Service(settings,gateway=gateway,event_transport=receiver)
    job=service.history.start('test-owner','suspended-history',['fixture@g.us'],until=100)
    transfer=service.media.enqueue('test-owner',{'kind':'gateway','media':{'url':'https://fixture.example/media'}},'fixture.txt')
    ready=service.media.enqueue('test-owner',{'kind':'gateway','media':{'url':'https://fixture.example/ready'}},'ready.txt')
    with service.store.db() as db:
        db.execute('UPDATE history_jobs SET state=? WHERE id=?',(history_state,job['id']))
        db.execute('UPDATE media_jobs SET state=? WHERE id=?',(media_state,transfer['id']))
        db.execute("UPDATE media_jobs SET state='ready' WHERE id=?",(ready['id'],))
    service.store.queue_action('suspended-send','test-owner','messages_send_text',{'body':{'chatId':'fixture@g.us','text':'synthetic'}})
    spec=importlib.util.spec_from_file_location('tenant_admin',Path(__file__).parents[1]/'scripts/tenant_admin.py')
    admin=importlib.util.module_from_spec(spec);spec.loader.exec_module(admin)
    auth=tmp_path/'auth';auth.mkdir()
    (auth/'users.yml').write_text(json.dumps({'users':{'fixture':{'disabled':False},'unrelated':{'disabled':False}}}))
    instance=SimpleNamespace(slug='fixture',username='fixture',base='fixture',state_dir=tmp_path,wrapper=tmp_path/'wrapper')
    monkeypatch.setattr(admin,'AUTH_CONFIG',auth)
    monkeypatch.setattr(admin,'auth_backup',lambda *_:None)
    monkeypatch.setattr(admin,'write_private',lambda path,data,**kwargs:path.write_text(data))
    commands=[]
    monkeypatch.setattr(admin,'run',lambda args,**kwargs:commands.append(args))
    from test_tenant_database import suspend_fixture
    monkeypatch.setattr(admin,'suspend_tenant_database',suspend_fixture)
    admin.change_enabled(instance,False)
    assert any('disable' in args for args in commands) and any('mask' in args for args in commands)
    assert not json.loads((auth/'users.yml').read_text())['users']['unrelated']['disabled']
    admin.change_enabled(instance,True)
    restored=Service(settings,gateway=gateway,event_transport=receiver)
    assert restored.history.status(job['id'],'test-owner')['state']=='cancelled'
    assert restored.history.start('test-owner','suspended-history',['fixture@g.us'],until=100)['state']=='cancelled'
    for action in ('pause','resume'):
        with pytest.raises(ValueError): restored.history.control(job['id'],'test-owner',action)
    assert restored.media.status(transfer['id'],'test-owner')['state']=='cancelled'
    assert 'next_tool' not in restored.media.status(transfer['id'],'test-owner')
    with restored.store.db() as db:
        assert db.execute('SELECT source FROM media_jobs WHERE id=?',(transfer['id'],)).fetchone()[0]==b''
        assert db.execute('SELECT state FROM media_jobs WHERE id=?',(ready['id'],)).fetchone()[0]=='ready'
    assert restored.store.send_status('suspended-send')['state']=='failed_before_send'
    assert restored.history.process_one() is False
    assert restored.media.process_one() is False
    with pytest.raises(ValueError): restored.history.status(job['id'],'other-owner')
    with pytest.raises(ValueError): restored.media.status(transfer['id'],'other-owner')
