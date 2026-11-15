"""Linux filesystem transactions with real SQLite and simulated service readiness."""
from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import time
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import release_transaction as transaction
import tenant_database as secure
from github_release_common import ReleaseError

pytestmark=pytest.mark.skipif(os.name!='posix',reason='POSIX ownership and symlink transaction; runs on Linux CI')


@pytest.mark.parametrize('existing_directory', [False, True])
def test_maintenance_gate_remains_visible_with_private_admin_umask(tmp_path, monkeypatch, existing_directory):
    gate=tmp_path/'gates/whatsapp'
    monkeypatch.setattr(transaction,'GATE',gate)
    if existing_directory:
        gate.parent.mkdir(mode=0o700)
    previous=os.umask(0o077)
    try:
        transaction.gate_on()
        # Service identities must stat the marker without permission to alter it.
        assert gate.parent.stat().st_mode & 0o777 == 0o755
        assert gate.stat().st_mode & 0o777 == 0o644
        transaction.gate_off()
        assert not gate.exists()
        assert gate.parent.stat().st_mode & 0o777 == 0o755
    finally:
        os.umask(previous)


def test_database_replacement_never_follows_predictable_staging_symlink(tmp_path):
    source=tmp_path/'source.sqlite';source.write_bytes(b'synthetic-reviewed-snapshot')
    destination=tmp_path/'archive.sqlite';destination.write_bytes(b'synthetic-original')
    other=tmp_path/'other-tenant.sqlite';other.write_bytes(b'other-tenant-unchanged')
    trap=destination.with_name(destination.name+'.release-pending');trap.symlink_to(other)
    transaction.replace_database(source,destination)
    assert destination.read_bytes()==source.read_bytes()
    assert other.read_bytes()==b'other-tenant-unchanged'
    assert trap.is_symlink()


@pytest.mark.parametrize('which',['database','parent'])
def test_database_replacement_rejects_foreign_symlink(tmp_path,which):
    source=tmp_path/'source.sqlite';source.write_bytes(b'synthetic-reviewed-snapshot')
    owner=tmp_path/'owner';owner.mkdir()
    other=tmp_path/'other';other.mkdir()
    destination=owner/'archive.sqlite';destination.write_bytes(b'original')
    foreign=other/'archive.sqlite';foreign.write_bytes(b'other-tenant-unchanged')
    if which=='database':
        destination.unlink();destination.symlink_to(foreign)
    else:
        destination.unlink();owner.rmdir();owner.symlink_to(other,target_is_directory=True)
    with pytest.raises((OSError,ReleaseError)):
        transaction.replace_database(source,destination)
    assert foreign.read_bytes()==b'other-tenant-unchanged'


@pytest.fixture
def sandbox(tmp_path,monkeypatch):
    monkeypatch.setattr(secure,'_TRUST_ROOT',tmp_path)
    monkeypatch.setattr(secure,'_TRUST_UID',os.getuid())
    monkeypatch.setattr(secure.pwd,'getpwnam',lambda name:SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid()))
    root=tmp_path/'runtime';root.mkdir()
    candidate=tmp_path/'candidate';candidate.mkdir()
    for directory,marker in [(root,'old'),(candidate,'new')]:
        for name in transaction.ENTRIES:
            if name in ('.venv','sally_whatsapp'):
                (directory/name).mkdir();(directory/name/'marker').write_text(marker)
            else:(directory/name).write_text(marker)
    instances=[]
    for slug in ['one','two']:
        path=tmp_path/slug/'state/archive.sqlite';path.parent.mkdir(parents=True)
        config=tmp_path/slug/'configuration/config.toml';config.parent.mkdir()
        config.write_text('[bridge]\n'+'\n'.join(key+' = '+json.dumps(value) for key,value in {
            'database':str(path),'owner_subject':'owner-'+slug,'public_url':'https://'+slug+'.example.test'}.items()))
        identity={'protocol':1,'id':('a' if slug=='one' else 'b')*32,'tenant':hashlib.sha256(json.dumps(
            ['owner-'+slug,'https://'+slug+'.example.test','default'],separators=(',', ':')).encode()).hexdigest()}
        (config.parent/'technical-state.json').write_text(json.dumps(identity))
        with closing(sqlite3.connect(path)) as db:
            db.executescript('CREATE TABLE messages(id TEXT PRIMARY KEY,body TEXT);CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT);PRAGMA user_version=6;')
            db.execute('INSERT INTO state VALUES (?,?)',(secure.KEY,json.dumps(identity)))
            db.execute('INSERT INTO messages VALUES(?,?)',(slug,'preserve'));db.commit()
        instances.append({'slug':slug,'base':slug,'unit':slug+'.service','config':str(config),'path':path})
    # Same schema validation still occurs on copies; inject a minimal fixture contract.
    (candidate/'deploy').mkdir()
    (candidate/'deploy/migrations.json').write_text(json.dumps({'schemaVersion':7,'migrations':[{'from':6,'to':7,'sql':'6-7.sql'}]}))
    (candidate/'deploy/6-7.sql').write_text('ALTER TABLE messages ADD COLUMN extra TEXT;PRAGMA user_version=7;')
    (candidate/'sally_whatsapp/store.py').write_text('SCHEMA='+repr('CREATE TABLE messages(id TEXT PRIMARY KEY,body TEXT,extra TEXT);CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT);PRAGMA user_version=7;'))
    monkeypatch.setattr(transaction,'GATE',tmp_path/'gates/whatsapp')
    monkeypatch.setattr(transaction,'JOURNAL',tmp_path/'state/transaction.json')
    monkeypatch.setattr(transaction,'STATE',tmp_path/'state')
    monkeypatch.setattr(transaction,'dbpath',lambda item:Path(item['path']))
    monkeypatch.setattr(transaction,'SYSTEMD',tmp_path/'systemd')
    monkeypatch.setattr(transaction.os,'chown',lambda *args,**kwargs:None)
    commands=[]
    monkeypatch.setattr(transaction,'run',lambda args,**kwargs:commands.append(args))
    healthy=Mock()
    record=tmp_path/'record'
    def activate():
        return transaction.activate(root,candidate,instances,instances,{'one':'WORKING','two':'WORKING'},
            '0.3.1','0.3.2',record,healthy,lambda items:None,lambda copies:None,source_commit='a'*40)
    return root,candidate,instances,healthy,activate,commands


def assert_old(root,instances):
    assert (root/'.venv/marker').read_text()=='old'
    assert (root/'sally_whatsapp/marker').read_text()=='old'
    for item in instances:
        with closing(sqlite3.connect(item['path'])) as db:
            assert db.execute('PRAGMA user_version').fetchone()[0]==6
            assert db.execute('SELECT id,body FROM messages').fetchall()==[(item['slug'],'preserve')]


def test_success_commits_all_instances_and_opens_gate(sandbox):
    root,candidate,instances,healthy,activate,commands=sandbox
    plan=activate()
    assert plan['phase']=='published'
    assert not transaction.GATE.exists()
    assert (root/'.venv').resolve()==candidate/'.venv'
    assert [call.kwargs for call in healthy.call_args_list]==[{'maintenance':True},{'require_ready':True}]
    assert set(commands[0][2:])=={'one.service','two.service'}


def test_one_instance_failure_restores_all_databases_code_and_dependencies(sandbox):
    root,candidate,instances,healthy,activate,commands=sandbox
    healthy.side_effect=[ReleaseError('second instance failed'),None]
    with pytest.raises(ReleaseError,match='second instance'):activate()
    assert_old(root,instances)
    assert json.loads(transaction.JOURNAL.read_text())['phase']=='rolled-back'
    assert not transaction.GATE.exists()


def test_failed_candidate_start_limit_does_not_block_rollback(sandbox, monkeypatch):
    root,candidate,instances,healthy,activate,commands=sandbox
    limited=set()
    def run(args, **kwargs):
        commands.append(args)
        if args[1]=='reset-failed':
            limited.difference_update(args[2:])
        elif args[1]=='start' and limited.intersection(args[2:]):
            raise ReleaseError('start request repeated too quickly')
    def readiness(*args, **kwargs):
        if kwargs.get('maintenance'):
            limited.update(item['unit'] for item in instances)
            raise ReleaseError('candidate startup failed')
    monkeypatch.setattr(transaction,'run',run)
    healthy.side_effect=readiness
    with pytest.raises(ReleaseError,match='candidate startup failed'):
        activate()
    assert_old(root,instances)
    assert json.loads(transaction.JOURNAL.read_text())['phase']=='rolled-back'
    assert not limited and not transaction.GATE.exists()


@pytest.mark.parametrize('phase', ['committed','rollback-committed'])
def test_recovery_clears_start_limit_only_for_previously_active_units(tmp_path, monkeypatch, phase):
    monkeypatch.setattr(transaction,'GATE',tmp_path/'gates/whatsapp')
    monkeypatch.setattr(transaction,'JOURNAL',tmp_path/'state/transaction.json')
    monkeypatch.setattr(transaction,'STATE',tmp_path/'state')
    transaction.gate_on()
    plan={'phase':phase,'activeUnits':['enabled.service'],
          'allUnits':['enabled.service','suspended.service'],
          'selected':[],'before':{},'version':'0.3.2','previousVersion':'0.3.1',
          'sourceCommit':'a'*40,'candidate':str(tmp_path/'candidate'),'record':str(tmp_path/'record')}
    commands=[]
    limited={'enabled.service','suspended.service'}
    def run(args, **kwargs):
        commands.append(args)
        if args[1]=='reset-failed':limited.difference_update(args[2:])
        if args[1]=='start' and limited.intersection(args[2:]):
            raise ReleaseError('start request repeated too quickly')
    monkeypatch.setattr(transaction,'run',run)
    transaction.recover(plan,Mock())
    assert commands==[['systemctl','reset-failed','enabled.service'],
                      ['systemctl','start','enabled.service']]
    assert limited=={'suspended.service'}
    assert plan['phase']==('published' if phase=='committed' else 'rolled-back')


def test_empty_recovery_snapshot_never_resets_all_systemd_units(monkeypatch):
    command=Mock()
    monkeypatch.setattr(transaction,'run',command)
    with pytest.raises(ReleaseError,match='No previously active'):
        transaction.start_recovered_units([])
    command.assert_not_called()


def test_failure_during_second_database_switch_restores_first(sandbox,monkeypatch):
    root,candidate,instances,healthy,activate,commands=sandbox
    original=transaction.replace_database;count=0
    def fail_once(source,destination):
        nonlocal count
        count+=1
        if count==2:raise OSError('interrupted switch')
        original(source,destination)
    monkeypatch.setattr(transaction,'replace_database',fail_once)
    with pytest.raises(OSError):activate()
    assert_old(root,instances)


def test_committed_recovery_never_restores_new_messages(sandbox):
    root,candidate,instances,healthy,activate,commands=sandbox
    plan=activate();plan['phase']='committed'
    with closing(sqlite3.connect(instances[0]['path'])) as db:
        db.execute("INSERT INTO messages VALUES('new','received after publication',NULL)");db.commit()
    transaction.gate_on();transaction.recover(plan,healthy)
    assert (root/'.venv/marker').read_text()=='new'
    with closing(sqlite3.connect(instances[0]['path'])) as db:
        assert db.execute("SELECT body FROM messages WHERE id='new'").fetchone()[0]=='received after publication'
    assert not transaction.GATE.exists()


def test_postgate_failure_is_durable_without_retry_or_old_data_restore(sandbox):
    root,candidate,instances,healthy,activate,commands=sandbox
    failure=ReleaseError('synthetic readiness failure')
    def readiness(*args,**kwargs):
        if kwargs.get('require_ready'):
            assert not transaction.GATE.exists()
            assert json.loads(transaction.JOURNAL.read_text())['phase']=='committed'
            for item in instances:
                with closing(sqlite3.connect(item['path'])) as db:
                    db.execute("INSERT INTO messages VALUES('after-open','preserve',NULL)");db.commit()
            raise failure
    healthy.side_effect=readiness
    with pytest.raises(ReleaseError) as caught:activate()
    assert caught.value is failure
    plan=json.loads(transaction.JOURNAL.read_text())
    assert plan['phase']=='committed' and plan['activationError']=='activation_not_verified'
    # Both old and new helpers reserve these phases for no-old-data recovery.
    assert plan['phase'] in ('committed','published')
    assert healthy.call_count==2  # No inline recovery retry concealing failure.
    assert not transaction.GATE.exists() and not (transaction.STATE/'whatsapp/current.json').exists()
    assert (root/'.venv/marker').read_text()=='new'
    assert [command[1] for command in commands].count('stop')==1
    for item in instances:
        with closing(sqlite3.connect(item['path'])) as db:
            assert db.execute('PRAGMA user_version').fetchone()[0]==7
            assert db.execute("SELECT body FROM messages WHERE id='after-open'").fetchone()[0]=='preserve'
    healthy.side_effect=None;healthy.reset_mock();commands.clear()
    transaction.recover(plan,healthy)
    assert healthy.call_args.kwargs=={'require_ready':True}
    assert plan['phase']=='published' and 'activationError' not in plan
    assert not any(command[1]=='stop' for command in commands)


@pytest.mark.parametrize('phase',['committed','published'])
@pytest.mark.parametrize('gate_present',[False,True])
def test_recovery_never_accepts_failed_readiness_or_restores_new_data(sandbox,phase,gate_present):
    root,candidate,instances,healthy,activate,commands=sandbox
    plan=activate();plan['phase']=phase
    for item in instances:
        with closing(sqlite3.connect(item['path'])) as db:
            db.execute("INSERT INTO messages VALUES('after-open','preserve',NULL)");db.commit()
    if gate_present:transaction.gate_on()
    failure=ReleaseError('required worker not ready')
    def readiness(*args,**kwargs):
        if kwargs.get('require_ready'):
            assert not transaction.GATE.exists()
            raise failure
        assert kwargs=={'maintenance':True} and transaction.GATE.exists()
    healthy.reset_mock();healthy.side_effect=readiness;commands.clear()
    with pytest.raises(ReleaseError) as caught:transaction.recover(plan,healthy)
    assert caught.value is failure and plan['phase']=='committed'
    assert healthy.call_count==(2 if gate_present else 1)
    assert not transaction.GATE.exists() and not any(command[1]=='stop' for command in commands)
    assert (root/'.venv/marker').read_text()=='new'
    for item in instances:
        with closing(sqlite3.connect(item['path'])) as db:
            assert db.execute("SELECT body FROM messages WHERE id='after-open'").fetchone()[0]=='preserve'


@pytest.mark.parametrize('crash_stage',['after-gate','after-ready'])
def test_crash_window_after_commit_recovers_candidate_only(sandbox,monkeypatch,crash_stage):
    root,candidate,instances,healthy,activate,commands=sandbox
    complete=transaction.complete_activation
    def interrupt(plan,wait_health):
        transaction.gate_off()
        if crash_stage=='after-ready':
            wait_health(plan['selected'],plan['version'],plan['before'],require_ready=True)
        for item in instances:
            with closing(sqlite3.connect(item['path'])) as db:
                db.execute("INSERT INTO messages VALUES('after-open','preserve',NULL)");db.commit()
        raise SystemExit('synthetic publisher termination')
    monkeypatch.setattr(transaction,'complete_activation',interrupt)
    with pytest.raises(SystemExit):activate()
    plan=json.loads(transaction.JOURNAL.read_text())
    assert plan['phase']=='committed' and not transaction.GATE.exists()
    assert not (transaction.STATE/'whatsapp/current.json').exists()
    monkeypatch.setattr(transaction,'complete_activation',complete)
    commands.clear();healthy.reset_mock();transaction.recover(plan,healthy)
    assert healthy.call_args.kwargs=={'require_ready':True} and plan['phase']=='published'
    assert not any(command[1]=='stop' for command in commands)
    for item in instances:
        with closing(sqlite3.connect(item['path'])) as db:
            assert db.execute("SELECT body FROM messages WHERE id='after-open'").fetchone()[0]=='preserve'


def test_failure_journal_write_does_not_mask_original_readiness_error(sandbox,monkeypatch):
    root,candidate,instances,healthy,activate,commands=sandbox
    failure=ReleaseError('readiness unavailable')
    healthy.side_effect=[None,failure]
    checkpoint=transaction.checkpoint
    def fail_checkpoint(plan,phase):
        if phase=='committed' and plan.get('activationError'):raise OSError('synthetic storage error with private content')
        checkpoint(plan,phase)
    monkeypatch.setattr(transaction,'checkpoint',fail_checkpoint)
    with pytest.raises(ReleaseError) as caught:activate()
    assert caught.value is failure and healthy.call_count==2
    assert 'private content' not in str(caught.value.__notes__)
    assert json.loads(transaction.JOURNAL.read_text())['phase']=='committed'
    assert not transaction.GATE.exists() and (root/'.venv/marker').read_text()=='new'


def test_published_checkpoint_failure_is_recoverable_without_rollback(sandbox,monkeypatch):
    root,candidate,instances,healthy,activate,commands=sandbox
    checkpoint=transaction.checkpoint
    def fail_once(plan,phase):
        if phase=='published':raise OSError('synthetic checkpoint failure')
        checkpoint(plan,phase)
    monkeypatch.setattr(transaction,'checkpoint',fail_once)
    with pytest.raises(OSError,match='checkpoint failure'):activate()
    plan=json.loads(transaction.JOURNAL.read_text())
    assert plan['phase']=='committed' and not transaction.GATE.exists()
    assert json.loads((transaction.STATE/'whatsapp/current.json').read_text())['version']=='0.3.2'
    monkeypatch.setattr(transaction,'checkpoint',checkpoint);commands.clear()
    transaction.recover(plan,healthy)
    assert plan['phase']=='published' and not any(command[1]=='stop' for command in commands)


def test_interrupted_switch_replays_durable_journal_once(sandbox,monkeypatch):
    root,candidate,instances,healthy,activate,commands=sandbox
    replace=transaction.replace_database;recover=transaction.recover;count=0
    def interrupt(source,destination):
        nonlocal count
        count+=1
        if count==2:raise OSError('simulated loss of publisher')
        replace(source,destination)
    monkeypatch.setattr(transaction,'replace_database',interrupt)
    # Simulate a process that cannot run its exception handler (SIGKILL/reboot).
    monkeypatch.setattr(transaction,'recover',lambda *args:None)
    with pytest.raises(OSError):activate()
    plan=json.loads(transaction.JOURNAL.read_text())
    assert plan['phase']=='frozen' and transaction.GATE.exists()
    monkeypatch.setattr(transaction,'replace_database',replace)
    recover(plan,healthy)
    assert_old(root,instances)
    commands.clear();recover(plan,healthy)
    assert commands==[]


def test_rollback_committed_recovery_does_not_restore_twice(sandbox):
    root,candidate,instances,healthy,activate,commands=sandbox
    healthy.side_effect=[ReleaseError('candidate'),None]
    with pytest.raises(ReleaseError):activate()
    plan=json.loads(transaction.JOURNAL.read_text());plan['phase']='rollback-committed'
    with closing(sqlite3.connect(instances[0]['path'])) as db:
        db.execute("INSERT INTO messages VALUES('after-rollback','keep')");db.commit()
    healthy.side_effect=None
    transaction.recover(plan,healthy)
    with closing(sqlite3.connect(instances[0]['path'])) as db:
        assert db.execute("SELECT body FROM messages WHERE id='after-rollback'").fetchone()[0]=='keep'


@pytest.mark.parametrize('maintenance',[False,True])
def test_runtime_recovers_interrupted_jobs_only_on_ordinary_restart(tmp_path,monkeypatch,maintenance):
    import release_runtime as runtime
    import sally_whatsapp.config as configuration
    import sally_whatsapp.server as server
    import uvicorn
    from types import SimpleNamespace
    gate=tmp_path/'maintenance'
    if maintenance:gate.touch()
    monkeypatch.setattr(runtime,'runtime_gate',lambda:gate)
    monkeypatch.setattr(sys,'argv',['runtime','--config','synthetic'])
    monkeypatch.setattr(configuration.Settings,'load',lambda path:SimpleNamespace(listen_port=8820))
    received=[]
    monkeypatch.setattr(server,'create_app',lambda settings,**kwargs:received.append(kwargs))
    monkeypatch.setattr(uvicorn,'run',lambda *args,**kwargs:None)
    runtime.main()
    assert received[0]['recover_inflight'] is not maintenance
    assert received[0]['maintenance_gate'] == gate


@pytest.mark.parametrize('failure',[False,True])
def test_activation_and_inline_rollback_keep_optional_tenant_descriptor(sandbox,monkeypatch,failure):
    root,candidate,instances,healthy,activate,commands=sandbox
    observed=[]
    monkeypatch.setattr(transaction,'run',lambda args,**kwargs:observed.append((args,kwargs)))
    if failure:healthy.side_effect=[ReleaseError('synthetic readiness'),None]
    with (root/'owned.lock').open('a') as lock:
        def apply():
            return transaction.activate(root,candidate,instances,instances,{'one':'WORKING','two':'WORKING'},
                '0.3.1','0.3.2',root.parent/'record',healthy,lambda items:None,lambda copies:None,
                source_commit='a'*40,lock_fd=lock.fileno())
        if failure:
            with pytest.raises(ReleaseError,match='synthetic readiness'):apply()
        else:apply()
        assert observed and all(kwargs['pass_fds']==(lock.fileno(),) for _,kwargs in observed)
        if failure:assert any(args[1]=='reset-failed' for args,_ in observed)


RECOVERY_FD_CHILD = r'''
import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import installation_layout as layout
layout.activate_installation(root=Path(sys.argv[2]),trusted_uid=os.getuid())
import release_transaction as transaction
from github_release_common import run
root=Path(sys.argv[2]);fd=int(sys.argv[3]);phase=sys.argv[4]
transaction.GATE=root/'gate';transaction.JOURNAL=root/'transaction.json'
descendant="import os,signal;from pathlib import Path;Path("+repr(str(root/'descendant.pid'))+").write_text(str(os.getpid()));signal.pause()"
def synthetic_command(args,**kwargs):
    return run([sys.executable,'-B','-c',descendant],**kwargs)
transaction.run=synthetic_command
plan={'phase':phase,'root':str(root),'record':str(root),'activeUnits':['synthetic.service'],'allUnits':['synthetic.service']}
transaction.recover(plan,lambda *args,**kwargs:None,lock_fd=fd)
'''


@pytest.mark.parametrize('phase',['prepared','committed','rollback-committed'])
def test_transaction_command_keeps_lock_after_recovery_parent_sigkill(tmp_path,phase):
    from installation_layout import IDENTITY, Installation, identity_bytes
    marker=tmp_path/IDENTITY.relative_to('/')
    marker.parent.mkdir(mode=0o700,parents=True)
    marker.write_bytes(identity_bytes(Installation.legacy()));marker.chmod(0o600)
    lock_path=tmp_path/'tenant-admin.lock';lock=lock_path.open('a')
    fcntl.flock(lock,fcntl.LOCK_EX)
    child=subprocess.Popen([sys.executable,'-B','-c',RECOVERY_FD_CHILD,
        str(Path(transaction.__file__).parent),str(tmp_path),str(lock.fileno()),phase],
        pass_fds=(lock.fileno(),),start_new_session=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    lock.close()
    try:
        deadline=time.monotonic()+10
        while not (tmp_path/'descendant.pid').exists() and child.poll() is None and time.monotonic()<deadline:
            time.sleep(.01)
        if not (tmp_path/'descendant.pid').exists():
            # Preserve the actual startup failure before cleanup changes the
            # exit code. A surviving descendant may keep the captured pipes
            # open, so stop this synthetic process group before reading them.
            startup_returncode=child.poll()
            deadline_expired=time.monotonic()>=deadline
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            output,error=child.communicate(timeout=5)
            pytest.fail('synthetic recovery command did not start; '
                        f'phase={phase!r}; returncode={startup_returncode!r}; '
                        f'deadline_expired={deadline_expired}; '
                        f'stdout={output[-8192:]!r}; stderr={error[-8192:]!r}')
        descendant=int((tmp_path/'descendant.pid').read_text())
        child.kill();child.wait(timeout=5)
        assert child.returncode == -signal.SIGKILL
        os.kill(descendant,0)
        with lock_path.open('a') as contender:
            with pytest.raises(BlockingIOError):fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
    finally:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        child.communicate(timeout=5)
