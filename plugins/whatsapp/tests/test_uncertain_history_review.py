"""Explicit historical acknowledgment, isolated from action state/idempotence."""
import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from sally_whatsapp import uncertain_review as review
from sally_whatsapp.action_diagnostics import summary, list_uncertain
from sally_whatsapp.store import Store

OWNER = 'synthetic-owner'
KEYS = [f'synthetic-history-{n:02}' for n in range(7)]


def seed(store, keys=KEYS, owner=OWNER):
    for key in keys:
        store.queue_action(key, owner, 'messages_set_star', {'body':{'private':'do-not-export'}})
        store.finish_send(key,'uncertain',result={'success':True})


def snapshot(store):
    with store.db() as db:
        return {table:[tuple(r) for r in db.execute('SELECT * FROM '+table+' ORDER BY rowid')]
                for table in ('sends','action_jobs','operation_results','action_job_metadata','action_job_sources')}


def plan(store, keys=KEYS, **kwargs):
    with store.db() as db:
        return review.prepare(db,OWNER,list(keys),**kwargs)


def apply(store, value):
    with store.db() as db:
        return review.apply(db,value,review.digest(value))


def classification(store, key=KEYS[0]):
    with store.db() as db:
        return review.status(db,OWNER,key)


def test_seven_acknowledgments_preserve_ledger_and_retry_guards(tmp_path):
    store = Store(tmp_path/'one.db'); seed(store)
    original = snapshot(store)
    value = plan(store)
    assert snapshot(store) == original
    assert apply(store,value)['state'] == 'applied'
    assert apply(store,value)['state'] == 'already_applied'
    with store.db() as db:
        status = summary(db,owner=OWNER)
        assert status['uncertain_total'] == status['uncertain_known_history'] == 7
        assert status['uncertain_active'] == 0 and not status['repeat_alert_eligible']
        listed = list_uncertain(db,OWNER)
        assert listed['total'] == 7 and all(r['state']=='uncertain' for r in listed['actions'])
        assert all(not r['diagnostic_review']['requires_attention'] for r in listed['actions'])
        assert list_uncertain(db,'different-owner')['actions'] == []
        raw = ''.join(r[0] for r in db.execute('SELECT value FROM state WHERE key GLOB ?',('private:uncertain_review*',)))
        assert 'do-not-export' not in raw and KEYS[0] not in raw and OWNER not in raw
        assert db.execute('PRAGMA user_version').fetchone()[0] == 8
    # The exact original request remains the uncertain request, never new work.
    assert store.queue_action(KEYS[0],OWNER,'messages_set_star',{'body':{'private':'do-not-export'}})['state']=='uncertain'
    with pytest.raises(ValueError,match='Idempotency'):
        store.queue_action(KEYS[0],OWNER,'messages_set_star',{'body':{'different':True}})
    assert snapshot(store) == original
    assert store.state(owner=OWNER)['uncertain_sends'] == 7  # Compatibility: historical total.
    assert store.state(owner=OWNER)['uncertain_active'] == 0
    assert store.send_status(KEYS[0],owner=OWNER)['diagnostic_review']['classification']=='known_historical_unverifiable'


def test_new_operation_same_date_or_type_is_active_and_updated_evidence_reopens(tmp_path):
    store = Store(tmp_path/'one.db'); seed(store); apply(store,plan(store))
    seed(store,['new-distinct-key'])
    with store.db() as db:
        # No cutoff date: even an older distinct operation remains active.
        db.execute('UPDATE sends SET created=0 WHERE key=?',('new-distinct-key',))
        assert summary(db,owner=OWNER)['uncertain_active']==1
        db.execute('UPDATE operation_results SET result=? WHERE key=?',('{"result":false}',KEYS[0]))
    assert classification(store)['classification']=='reopened_evidence_changed'
    with store.db() as db:
        assert summary(db,owner=OWNER)['uncertain_active']==2


def test_new_exact_receipt_reopens_without_reclassifying_the_original_outcome(tmp_path):
    from test_delivery_receipts import reserve, receipt
    store = Store(tmp_path/'one.db'); reserve(store)
    key='synthetic-receipt-request'
    with store.db() as db:
        db.execute("UPDATE sends SET state='uncertain',owner=? WHERE key=?",(OWNER,key))
    apply(store,plan(store,[key])); receipt(store,3)
    assert classification(store,key)['classification']=='reopened_evidence_changed'
    assert store.send_status(key,owner=OWNER)['state']=='uncertain'


def test_plan_is_bound_to_owner_database_and_exact_unchanged_rows(tmp_path):
    one,two=Store(tmp_path/'one.db'),Store(tmp_path/'two.db')
    seed(one);seed(two); value=plan(one)
    with pytest.raises(ValueError,match='this database'):
        apply(two,value)
    altered=copy.deepcopy(value);altered['owner']='different-owner'
    with pytest.raises(ValueError,match='Exact uncertain action'):
        apply(one,altered)
    with one.db() as db:
        db.execute('UPDATE sends SET updated=updated+1 WHERE key=?',(KEYS[-1],))
    with pytest.raises(ValueError,match='evidence or prior review changed'):
        apply(one,value)
    with one.db() as db:
        assert not db.execute('SELECT 1 FROM state WHERE key GLOB ?',('private:uncertain_review*',)).fetchone()


def test_explicit_reopen_and_stale_acknowledgment_cannot_hide_consequences(tmp_path):
    store=Store(tmp_path/'one.db');seed(store);first=plan(store);apply(store,first)
    stale=plan(store)
    reopened=plan(store,[KEYS[0]],mode='reopen',evidence_ref='a'*64)
    apply(store,reopened)
    assert classification(store)['classification']=='reopened_explicitly'
    assert apply(store,first)['state']=='already_applied'
    assert classification(store)['requires_attention']
    with pytest.raises(ValueError,match='prior review changed'):
        apply(store,stale)
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM state WHERE key GLOB ?',(review.AUDIT+'*',)).fetchone()[0]==2


def test_crash_rollback_and_corrupt_or_copied_review_fail_open(tmp_path):
    one=Store(tmp_path/'one.db');seed(one);value=plan(one)
    with pytest.raises(RuntimeError):
        with one.db() as db:
            review.apply(db,value,review.digest(value))
            raise RuntimeError('simulate failure before commit')
    assert classification(one)['classification']=='unreviewed'
    apply(one,value)
    copied=tmp_path/'copy.db';one.backup(copied)
    two=Store(copied,migrate_schema=False)
    assert classification(two)['classification']=='review_unverifiable'
    with one.db() as db:
        db.execute('UPDATE state SET value=? WHERE key GLOB ?',('{"private":"never-reflect"}',review.AUDIT+'*'))
    result=classification(one)
    assert result['requires_attention'] and result['repeat_alert_eligible']
    assert 'never-reflect' not in json.dumps(result)


def test_plan_cli_prepare_is_readonly_and_apply_is_explicit(tmp_path):
    store=Store(tmp_path/'one.db');seed(store);before=store.path.read_bytes()
    keys=tmp_path/'keys.json';keys.write_text(json.dumps(KEYS))
    output=tmp_path/'plan.json'
    script=Path(__file__).parents[1]/'scripts/review_uncertain.py'
    base=[sys.executable,str(script),'--database',str(store.path)]
    prepared=subprocess.run([*base,'prepare','--owner',OWNER,'--keys',str(keys),'--output',str(output)],
                            capture_output=True,text=True,check=True,timeout=15)
    result=json.loads(prepared.stdout)
    assert result['database_changes']==0 and before==store.path.read_bytes()
    assert output.stat().st_mode & 0o077 == 0
    rejected=subprocess.run([*base,'apply','--plan',str(output),'--plan-sha256','0'*64],capture_output=True,text=True,timeout=15)
    assert rejected.returncode==2 and classification(store)['classification']=='unreviewed'
    applied=subprocess.run([*base,'apply','--plan',str(output),'--plan-sha256',result['plan_sha256']],
                           capture_output=True,text=True,check=True,timeout=15)
    assert json.loads(applied.stdout)['count']==7
    assert classification(store)['classification']=='known_historical_unverifiable'
