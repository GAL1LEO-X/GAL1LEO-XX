from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
from threading import Barrier,Event,current_thread

import pytest

from conftest import call,message,rpc
from sally_whatsapp.server import Service,SyncChat
from sally_whatsapp.store import canonical


def service_for(environment):
    settings,receiver,gateway,_=environment
    return Service(settings,gateway=gateway,event_transport=receiver)


def finish(history,job,owner='test-owner'):
    for _ in range(20):
        if history.status(job['id'],owner)['state']!='running': break
        history.process_one()
    return history.status(job['id'],owner)


def detail(history,job,**kwargs):
    return history.status(job['id'],'test-owner',**kwargs)['chat_coverage']


def test_multiple_chats_empty_source_and_unsupported_are_distinct(environment):
    service=service_for(environment);history=service.history
    service.gateway.history_chats=lambda offset:[{'id':chat} for chat in ['one@g.us','empty@g.us','1@newsletter']]
    service.gateway.messages=lambda chat,*args:[message('old',chat=chat,timestamp=10)['payload'],message('new',chat=chat,timestamp=90)['payload']] if chat=='one@g.us' else []
    job=history.start('test-owner','coverage-multiple',until=100)
    state=finish(history,job)
    assert state['state']=='completed' and state['history_complete'] is False
    records={entry['requested_chat_id']:entry for entry in state['chat_coverage']}
    assert records['one@g.us']['requested_interval']=={'since':0,'until':100}
    assert records['one@g.us']['observed_interval']=={'since':10,'until':90}
    empty=records['empty@g.us']
    assert empty['source_exhausted'] is True and empty['observed_interval'] is None
    assert empty['pages_committed']==1 and empty['messages_scanned']==0 and empty['exhausted_at']
    skipped=records['1@newsletter']
    assert skipped['acquisition_state']=='unsupported' and skipped['source_exhausted'] is None
    for entry in records.values():
        assert entry['job_state']=='completed' and entry['history_complete'] is False
        assert entry['gap_status']=='unknown' and 'observed_bounds_do_not_prove_continuity' in entry['limitations']
    chats={row['id']:row for row in service.store.chats()['chats']}
    assert chats['empty@g.us']['archived_messages']==0
    assert chats['empty@g.us']['first_message_at'] is None
    assert chats['empty@g.us']['history_coverage']['attempts'][0]['source_exhausted'] is True


def test_pause_restart_resume_keeps_exact_page_evidence(environment):
    service=service_for(environment);history=service.history
    first=[message(f'page-{i}',chat='one@g.us',timestamp=100)['payload'] for i in range(100)]
    service.gateway.pages=[first]
    job=history.start('test-owner','coverage-restart',['one@g.us'],until=200)
    history.process_one();history.control(job['id'],'test-owner','pause')
    before=detail(history,job)[0]
    assert before['pages_committed']==1 and before['source_exhausted'] is False
    restored=service_for(environment)
    assert detail(restored.history,job)[0]==before
    restored.gateway.pages=[[first[0],message('second-page',chat='one@g.us',timestamp=50)['payload']]]
    restored.history.control(job['id'],'test-owner','resume')
    state=finish(restored.history,job)
    entry=state['chat_coverage'][0]
    assert entry['pages_committed']==2 and entry['messages_scanned']==102 and entry['messages_inserted']==101
    assert entry['observed_interval']=={'since':50,'until':100}
    assert entry['first_request_at']==before['first_request_at'] and entry['exhausted_at']
    assert state['messages_inserted']==101 and restored.store.state()['deliveries']=={}


def test_different_overlapping_windows_remain_separate_attempts(environment):
    service=service_for(environment);history=service.history
    cases=[('coverage-one',0,100,[('a',10),('b',60)]),
           ('coverage-two',50,150,[('b',60),('c',120)]),
           ('coverage-empty',200,300,[])]
    jobs=[]
    for key,since,until,items in cases:
        service.gateway.pages=[[message(identifier,chat='one@g.us',timestamp=ts)['payload'] for identifier,ts in items]]
        job=history.start('test-owner',key,['one@g.us'],since=since,until=until)
        finish(history,job);jobs.append(job)
    summary=service.store.chats()['chats'][0]['history_coverage']
    assert summary['total_attempts']==3 and summary['truncated'] is False
    records={item['job_id']:item for item in summary['attempts']}
    assert records[jobs[0]['id']]['requested_interval']=={'since':0,'until':100}
    assert records[jobs[1]['id']]['requested_interval']=={'since':50,'until':150}
    assert records[jobs[1]['id']]['messages_scanned']==2 and records[jobs[1]['id']]['messages_inserted']==1
    assert records[jobs[2]['id']]['observed_interval'] is None
    assert 'covered_interval' not in summary and summary['gap_status']=='unknown'


def test_summary_limits_attempts_and_filters_authenticated_owner(app_client):
    app,client=app_client;service=app.state.service;history=service.history
    service.store.ingest(message('known-chat',chat='one@g.us',timestamp=1),historical=True)
    jobs=[]
    for index in range(12):
        job=history.start('test-owner',f'coverage-{index}',['one@g.us'],until=100)
        history.control(job['id'],'test-owner','cancel');jobs.append(job['id'])
    foreign=history.start('other-owner','coverage-foreign',['one@g.us'],until=100)
    response=call(client,'list_chats')['result']['structuredContent']
    summary=response['chats'][0]['history_coverage']
    assert summary['total_attempts']==12 and len(summary['attempts'])==10 and summary['truncated'] is True
    assert all(item['job_id'] in jobs and item['job_state']=='cancelled' for item in summary['attempts'])
    assert call(client,'get_history_sync',{'job_id':foreign['id']})['result']['isError']


def remove_tracking(store,job):
    with store.db() as db:
        row=db.execute('SELECT progress FROM history_jobs WHERE id=?',(job['id'],)).fetchone()
        progress=json.loads(row[0]);progress.pop('coverage_version');progress.pop('chat_coverage')
        db.execute('UPDATE history_jobs SET progress=? WHERE id=?',(canonical(progress),job['id']))


def test_legacy_job_never_derives_source_evidence_from_archive(environment):
    service=service_for(environment);history=service.history
    service.gateway.pages=[[message('old',chat='one@g.us',timestamp=50)['payload']]]
    job=history.start('test-owner','coverage-legacy',['one@g.us'],until=100)
    finish(history,job);remove_tracking(service.store,job)
    before=canonical(service.store.state())
    entry=detail(history,job)[0]
    assert entry['tracking_scope']=='legacy_unknown' and entry['source_exhausted'] is None
    assert entry['observed_interval'] is None and entry['messages_scanned'] is None
    assert entry['job_state']=='completed' and entry['history_complete'] is False
    assert service.store.chats()['chats'][0]['history_coverage']['attempts'][0]['tracking_scope']=='legacy_unknown'
    assert canonical(service.store.state())==before
    with service.store.db() as db:
        assert 'chat_coverage' not in json.loads(db.execute('SELECT progress FROM history_jobs WHERE id=?',(job['id'],)).fetchone()[0])


def test_legacy_resume_records_only_newly_observed_suffix(environment):
    service=service_for(environment);history=service.history
    service.gateway.pages=[[message(f'old-{i}',chat='one@g.us',timestamp=90)['payload'] for i in range(100)]]
    job=history.start('test-owner','coverage-legacy-resume',['one@g.us'],until=100)
    history.process_one();history.control(job['id'],'test-owner','pause');remove_tracking(service.store,job)
    service.gateway.pages=[[message('new-suffix',chat='one@g.us',timestamp=10)['payload']]]
    history.control(job['id'],'test-owner','resume');state=finish(history,job)
    entry=state['chat_coverage'][0]
    assert entry['tracking_scope']=='legacy_suffix' and entry['tracking_started_offset']==100
    assert entry['pages_committed']==1 and entry['messages_scanned']==1 and state['messages_scanned']==101
    assert entry['observed_interval']=={'since':10,'until':10} and entry['source_exhausted'] is True
    assert entry['history_complete'] is False


def test_archive_and_legacy_sync_have_no_invented_job_coverage(environment):
    service=service_for(environment)
    service.gateway.pages=[[message('legacy-sync',chat='one@g.us',timestamp=50)['payload']]]
    result=service.sync(SyncChat(chat_id='one@g.us',since=0,until=100))
    assert result['window_complete'] and result['history_coverage_recorded'] is False
    row=service.store.chats()['chats'][0]
    assert row['first_message_at']==row['last_message_at']==50
    assert row['history_coverage']['attempts']==[] and row['history_coverage']['total_attempts']==0
    assert row['history_coverage']['history_complete'] is False


def test_revocations_do_not_rewrite_observed_evidence_or_claim_visible_content(environment):
    service=service_for(environment);history=service.history
    service.ingest({'id':'revoked-first','event':'message.revoked','payload':{'revokedMessageId':'revoked'}})
    service.gateway.pages=[[message('revoked',chat='one@g.us',timestamp=10)['payload'],message('visible',chat='one@g.us',timestamp=90)['payload']]]
    job=history.start('test-owner','coverage-revocations',['one@g.us'],until=100)
    finish(history,job)
    observed=detail(history,job)[0]
    assert observed['observed_interval']=={'since':10,'until':90}
    row=service.store.chats()['chats'][0]
    assert row['archived_messages']==1 and row['first_message_at']==90
    service.ingest({'id':'revoked-later','event':'message.revoked','payload':{'revokedMessageId':'visible'}})
    assert detail(history,job)[0]==observed
    row=service.store.chats()['chats'][0]
    assert row['archived_messages']==0 and row['first_message_at'] is None


def test_invalid_page_rolls_back_coverage_with_messages_and_counters(environment):
    service=service_for(environment);history=service.history
    page=[message(f'rollback-{i}',chat='one@g.us',timestamp=50)['payload'] for i in range(2)]
    page[1]['fromMe']='invalid';service.gateway.pages=[page]
    job=history.start('test-owner','coverage-rollback',['one@g.us'],until=100)
    history.process_one();entry=detail(history,job)[0]
    assert entry['job_state']=='failed' and entry['pages_committed']==0 and entry['observed_interval'] is None
    assert entry['last_page_at'] is None and service.store.state()['archive_messages']==0
    with service.store.db() as db: assert db.execute('SELECT count(*) FROM receipts').fetchone()[0]==0
    page[1]['fromMe']=False;service.gateway.pages=[page]
    history.control(job['id'],'test-owner','resume');finish(history,job)
    assert detail(history,job)[0]['messages_inserted']==2


def test_save_failure_after_evidence_calculation_preserves_previous_page(environment,monkeypatch):
    service=service_for(environment);history=service.history
    service.gateway.pages=[[message(f'saved-{index}',chat='one@g.us',timestamp=90)['payload'] for index in range(100)]]
    job=history.start('test-owner','coverage-save-rollback',['one@g.us'],until=100)
    history.process_one();before=detail(history,job)[0]
    service.gateway.pages=[[message('rollback-later-page',chat='one@g.us',timestamp=10)['payload']]]
    original_save=history._save
    def reject_page(row,progress,state='running',*,db=None):
        return False if db is not None else original_save(row,progress,state)
    monkeypatch.setattr(history,'_save',reject_page);history.process_one()
    after=detail(history,job)[0]
    for key in ('pages_committed','messages_scanned','messages_inserted','observed_interval','source_exhausted','last_page_at'):
        assert after[key]==before[key]
    assert after['job_state']=='failed' and service.store.state()['archive_messages']==100
    assert service.store.message('rollback-later-page') is None
    monkeypatch.setattr(history,'_save',original_save)
    service.gateway.pages=[[message('rollback-later-page',chat='one@g.us',timestamp=10)['payload']]]
    history.control(job['id'],'test-owner','resume');finish(history,job)
    assert detail(history,job)[0]['messages_scanned']==101


def test_discovery_pause_exposes_no_uncommitted_chat_evidence(environment):
    service=service_for(environment);history=service.history
    job=history.start('test-owner','coverage-discovery',until=100)
    assert job['chat_coverage']==[] and job['gap_status']=='unknown' and job['limitations']
    def discover(offset):
        history.control(job['id'],'test-owner','pause')
        return [{'id':'one@g.us','name':'Synthetic group'}]
    service.gateway.history_chats=discover;history.process_one()
    paused=history.status(job['id'],'test-owner')
    assert paused['chat_coverage_total']==0 and paused['chats_discovered']==0
    assert service.store.chats()['chats']==[]
    service.gateway.history_chats=lambda offset:[{'id':'one@g.us','name':'Synthetic group'}]
    history.control(job['id'],'test-owner','resume');history.process_one()
    pending=detail(history,job)[0]
    assert pending['acquisition_state']=='pending' and pending['pages_committed']==0
    assert pending['source_exhausted'] is None
    assert service.store.chats()['chats'][0]['history_coverage']['attempts'][0]['acquisition_state']=='pending'


@pytest.mark.parametrize('action',['pause','cancel'])
def test_page_returning_after_control_has_no_coverage(environment,action):
    service=service_for(environment);history=service.history
    job=history.start('test-owner','coverage-inflight',['one@g.us'],until=100)
    def fetch(*args):
        history.control(job['id'],'test-owner',action)
        return [message('inflight',chat='one@g.us',timestamp=50)['payload']]
    service.gateway.messages=fetch;history.process_one()
    entry=detail(history,job)[0]
    assert entry['job_state']==('paused' if action=='pause' else 'cancelled')
    assert entry['pages_committed']==0 and entry['observed_interval'] is None
    assert service.store.state()['archive_messages']==0


@pytest.mark.parametrize('action',['pause','cancel'])
def test_control_during_commit_keeps_coverage_and_archive_atomic(environment,monkeypatch,action):
    service=service_for(environment);history=service.history
    job=history.start('test-owner','coverage-commit-race',['one@g.us'],until=100)
    service.gateway.pages=[[message('committing',chat='one@g.us',timestamp=50)['payload']]]
    first_written=Event();release=Event();control_started=Event()
    original_ingest=service.store.ingest;original_db=service.store.db
    def ingest(*args,**kwargs):
        outcome=original_ingest(*args,**kwargs);first_written.set()
        assert release.wait(timeout=5)
        return outcome
    @contextmanager
    def observed_db():
        with original_db() as db:
            if current_thread().name.startswith('coverage-control'):
                db.set_trace_callback(lambda sql:control_started.set() if sql=='BEGIN IMMEDIATE' else None)
            yield db
    monkeypatch.setattr(service.store,'ingest',ingest);monkeypatch.setattr(service.store,'db',observed_db)
    with ThreadPoolExecutor(max_workers=1) as workers,ThreadPoolExecutor(max_workers=1,thread_name_prefix='coverage-control') as controls:
        worker=workers.submit(history.process_one)
        try:
            assert first_written.wait(timeout=5)
            control=controls.submit(history.control,job['id'],'test-owner',action)
            assert control_started.wait(timeout=5) and not control.done()
            assert detail(history,job)[0]['pages_committed']==0
            assert service.store.state()['archive_messages']==0
        finally: release.set()
        assert worker.result(timeout=5)
        control.result(timeout=5)
    entry=detail(history,job)[0]
    assert entry['pages_committed']==entry['messages_inserted']==1
    assert entry['job_state']==('paused' if action=='pause' else 'cancelled')
    assert service.store.state()['archive_messages']==1


def test_two_workers_do_not_count_same_page_twice(environment):
    service=service_for(environment);history=service.history
    job=history.start('test-owner','coverage-workers',['one@g.us'],until=100)
    barrier=Barrier(2)
    def fetch(*args):
        barrier.wait(timeout=5)
        return [message('shared',chat='one@g.us',timestamp=50)['payload']]
    service.gateway.messages=fetch
    with ThreadPoolExecutor(max_workers=2) as workers:
        first=workers.submit(history.process_one);second=workers.submit(history.process_one)
        assert first.result(timeout=5) and second.result(timeout=5)
    entry=detail(history,job)[0]
    assert entry['pages_committed']==entry['messages_scanned']==entry['messages_inserted']==1


def test_tool_contract_paginates_filters_and_preserves_24_tools(app_client):
    app,client=app_client;service=app.state.service;history=service.history
    chats=[f'group-{index:03}@g.us' for index in range(120)]
    job=history.start('test-owner','coverage-paging',chats,until=100)
    first=call(client,'get_history_sync',{'job_id':job['id'],'chat_limit':2})['result']['structuredContent']
    assert first['chat_coverage_total']==120 and first['chat_coverage_next_offset']==2
    following=call(client,'get_history_sync',{'job_id':job['id'],'chat_limit':2,'chat_offset':2})['result']['structuredContent']
    assert [item['chat_id'] for item in following['chat_coverage']]==chats[2:4]
    selected=call(client,'get_history_sync',{'job_id':job['id'],'chat_id':chats[10]})['result']['structuredContent']
    assert selected['chat_coverage_total']==1 and selected['chat_coverage_next_offset'] is None
    assert call(client,'get_history_sync',{'job_id':job['id'],'chat_limit':0})['result']['isError']
    tools=rpc(client,'tools/list')['result']['tools']
    assert len(tools)==27
    schema=next(tool['inputSchema'] for tool in tools if tool['name']=='get_history_sync')
    assert schema['required']==['job_id']
    assert {'job_id','chat_id','chat_limit','chat_offset'}<=set(schema['properties'])


def test_verified_aliases_correlate_evidence_without_merging_attempts(environment):
    service=service_for(environment);history=service.history
    service.store.bind_chat_alias('10001@lid','20002@c.us')
    service.gateway.pages=[[message('via-alias',chat='20002@c.us',timestamp=50)['payload']]]
    job=history.start('test-owner','coverage-alias',['10001@lid'],until=100)
    finish(history,job)
    entry=detail(history,job,chat_id='20002@c.us')[0]
    assert entry['requested_chat_id']=='10001@lid' and entry['chat_id']=='20002@c.us'
    row=service.store.chats()['chats'][0]
    assert row['id']=='20002@c.us' and row['history_coverage']['attempts'][0]['job_id']==job['id']
