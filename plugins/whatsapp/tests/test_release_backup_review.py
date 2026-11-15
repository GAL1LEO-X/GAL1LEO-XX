"""Independent recovery review: only owned synthetic files/processes, no services."""
from contextlib import nullcontext
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
import github_release as release
import github_release_common as common
import release_backup as journal
import release_recover
import release_admin as admin
import release_transaction as transaction


def test_prerequisite_failure_prevents_activity_snapshot_journal_and_child(tmp_path, monkeypatch):
    # Admission has its own generation tests; isolate the subsequent preflight
    # failure and retain every assertion that forbids journal/service effects.
    monkeypatch.setattr(admin,'require_current',lambda *args,**kwargs:None)
    def fail(*args):
        raise common.ReleaseError('synthetic installed-protocol mismatch')
    monkeypatch.setattr(release.backup_recovery,'verify_prerequisites',fail)
    for name in ('backup_components','run_backup_process'):
        monkeypatch.setattr(release,name,lambda *args:pytest.fail('side effect after failed preflight'))
    monkeypatch.setattr(release.backup_recovery,'begin',lambda *args:pytest.fail('journal after failed preflight'))
    with pytest.raises(common.ReleaseError,match='protocol mismatch'):
        release.runtime_backups(tmp_path,[],0,'0.4.9')


# Invoke backup() itself. The first real subprocess.run used for stop is
# redirected to an owned descendant that pauses instead of touching systemd.
CHILD_IDENTITY = r'''
import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
sys.path.insert(0,str(Path(sys.argv[1]).parent))
root=Path(sys.argv[2]);identity_root=root/'host'
import installation_layout as installation
marker=identity_root/installation.IDENTITY.relative_to('/')
marker.parent.mkdir(parents=True,exist_ok=True)
marker.write_bytes(installation.identity_bytes(installation.Installation.legacy()));marker.chmod(0o600)
installation.activate_installation(root=identity_root,trusted_uid=os.getuid())
from sally_whatsapp import installation as application_installation
application_installation.activate_installation(root=identity_root,trusted_uid=os.getuid())
'''

BACKUP_CHILD = CHILD_IDENTITY + r'''
import json,os,signal,subprocess,sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1])
import backup_runtime as backup
backup._INSTALLATION_ROOT=identity_root;backup._INSTALLATION_UID=os.getuid()
root=Path(sys.argv[2]);lock_fd=int(sys.argv[3])
original_run=subprocess.run
descendant="import os,signal;from pathlib import Path;Path("+repr(str(root/'descendant.pid'))+").write_text(str(os.getpid()));signal.pause()"
def synthetic_run(args,**kwargs):
 if 'is-active' in args:return SimpleNamespace(returncode=0)
 if 'stop' in args:
  (root/'backup.pid').write_text(str(os.getpid()))
  return original_run([sys.executable,'-B','-c',descendant],**kwargs)
 raise AssertionError('unexpected synthetic command')
backup.subprocess=SimpleNamespace(run=synthetic_run)
backup.Path=lambda path:root/'host'/str(path).lstrip('/')
recovery=SimpleNamespace(before_stop=lambda *args:(root/'durable-before-stop').write_text('recorded'))
instance=SimpleNamespace(slug='synthetic',base='whatsapp-synthetic',wrapper=root/'wrapper')
backup.backup(instance,recovery_id='synthetic',recovery=recovery,lock_fd=lock_fd)
'''


def test_backup_descendant_keeps_tenant_lock_after_receiver_and_backup_exit(tmp_path):
    lock_path=tmp_path/'tenant-admin.lock'
    lock=lock_path.open('a')
    fcntl.flock(lock,fcntl.LOCK_EX)
    child=subprocess.Popen([sys.executable,'-B','-c',BACKUP_CHILD,str(SCRIPTS),str(tmp_path),str(lock.fileno())],
                           pass_fds=(lock.fileno(),),start_new_session=True,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    # Closing our copy models loss of the receiver; the actual backup child
    # still owns the inherited open-file-description lock at this point.
    lock.close()
    try:
        deadline=time.monotonic()+10
        while not (tmp_path/'descendant.pid').exists() and child.poll() is None and time.monotonic()<deadline:
            time.sleep(.01)
        assert (tmp_path/'durable-before-stop').exists()
        assert (tmp_path/'descendant.pid').exists(), 'synthetic stop did not start'
        descendant=int((tmp_path/'descendant.pid').read_text())
        os.kill(descendant,0)
        child.kill()
        child.wait(timeout=5)
        assert child.returncode == -signal.SIGKILL
        os.kill(descendant,0)  # The delayed stop is still alive, not completed.
        with lock_path.open('a') as independent_recovery:
            with pytest.raises(BlockingIOError):
                fcntl.flock(independent_recovery,fcntl.LOCK_EX|fcntl.LOCK_NB)
    finally:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        child.communicate(timeout=5)


SESSION_CHILD = CHILD_IDENTITY + r'''
import os,subprocess,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import release_backup as journal
root=Path(sys.argv[2]);lock_fd=int(sys.argv[3])
journal.JOURNAL=root/'backup.json'
journal.attach_worker(journal.read()['id'])
descendant="import os,signal;from pathlib import Path;os.close("+str(lock_fd)+");Path("+repr(str(root/'descendant.pid'))+").write_text(str(os.getpid()));signal.pause()"
subprocess.run([sys.executable,'-B','-c',descendant],pass_fds=(lock_fd,))
'''


def test_surviving_session_member_that_closes_lock_defers_recovery(tmp_path, monkeypatch):
    monkeypatch.setattr(journal,'JOURNAL',tmp_path/'backup.json')
    # Context is separately tested against actual registry/config/wrapper files;
    # this probe isolates the real process identity fence before restore().
    monkeypatch.setattr(journal,'activation_idle',lambda:None)
    monkeypatch.setattr(journal,'validate_context',lambda *args:None)
    common.save(journal.JOURNAL,{'format':journal.FORMAT,'id':'a'*32,'phase':'prepared',
        'servicesRestored':False,'copies':{},'components':[],'worker':None,'version':'0.4.9'})
    lock_path=tmp_path/'tenant-admin.lock'
    lock=lock_path.open('a')
    fcntl.flock(lock,fcntl.LOCK_EX)
    child=subprocess.Popen([sys.executable,'-B','-c',SESSION_CHILD,str(SCRIPTS),str(tmp_path),str(lock.fileno())],
                           pass_fds=(lock.fileno(),),start_new_session=True,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    lock.close()
    descendant_fd=None
    try:
        deadline=time.monotonic()+10
        while not (tmp_path/'descendant.pid').exists() and child.poll() is None and time.monotonic()<deadline:
            time.sleep(.01)
        assert (tmp_path/'descendant.pid').exists(), 'synthetic detached-lock member did not start'
        descendant=int((tmp_path/'descendant.pid').read_text())
        # Pin this process while it is alive, rather than inferring exit from
        # SIGKILL delivery, its leader's wait(), or a reusable numeric PID.
        descendant_fd=os.pidfd_open(descendant)
        child.kill();child.wait(timeout=5)
        os.kill(descendant,0)
        with lock_path.open('a') as independent_recovery:
            # A wrapper can close its descriptor, so the lock alone is insufficient.
            fcntl.flock(independent_recovery,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with pytest.raises(common.ReleaseError,match='session is still active'):
                journal.recover(tmp_path,[],lambda *args:pytest.fail('premature service restart'))
            assert journal.read()['phase']=='prepared'
    finally:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        try:
            child.communicate(timeout=5)
            if descendant_fd is not None:
                exited=select.poll()
                exited.register(descendant_fd,select.POLLIN)
                assert any(events & (select.POLLIN | select.POLLHUP)
                           for _,events in exited.poll(5000)), 'owned descendant did not exit'
        finally:
            if descendant_fd is not None:os.close(descendant_fd)
    assert journal.recover(tmp_path,[],lambda *args:[])['servicesRestored']


def test_restored_backup_does_not_roll_back_committed_activation(tmp_path, monkeypatch):
    generation=object()
    monkeypatch.setattr(admin,'publication_lock',lambda *args,**kwargs:nullcontext(generation))
    monkeypatch.setattr(admin,'require_current',lambda *args,**kwargs:generation)
    state=tmp_path/'state';(state/'whatsapp').mkdir(parents=True)
    root=tmp_path/'root';(root/'private').mkdir(parents=True)
    monkeypatch.setattr(common,'STATE',state)
    monkeypatch.setattr(release,'ROOT',root)
    monkeypatch.setattr(release,'instances',lambda *args:[])
    monkeypatch.setattr(journal,'JOURNAL',state/'whatsapp/backup.json')
    monkeypatch.setattr(transaction,'STATE',state)
    monkeypatch.setattr(transaction,'JOURNAL',state/'whatsapp/transaction.json')
    monkeypatch.setattr(transaction,'GATE',state/'gate')
    common.save(journal.JOURNAL,{'format':journal.FORMAT,'id':'b'*32,'phase':'restored',
        'servicesRestored':True,'copies':{},'components':[]})
    plan={'phase':'committed','record':str(state/'record'),'version':'0.5.0',
          'sourceCommit':'candidate','candidate':str(tmp_path/'candidate'),
          'activeUnits':['enabled.service'],'selected':[],'before':{}}
    common.save(transaction.JOURNAL,plan)
    transaction.GATE.touch()
    starts=[];health=[]
    monkeypatch.setattr(transaction,'run',lambda args,**kwargs:starts.append(args))
    monkeypatch.setattr(release,'wait_health',lambda *args,**kwargs:health.append(kwargs))
    monkeypatch.setattr(release,'restore_backup_components',lambda *args:pytest.fail('closed backup reopened'))
    monkeypatch.setattr(transaction,'replace_database',lambda *args:pytest.fail('post-commit data rollback'))
    release_recover.recover_project('whatsapp')
    assert starts==[['systemctl','reset-failed','enabled.service'],['systemctl','start','enabled.service']]
    assert health==[{'maintenance':True},{'require_ready':True}]
    assert not transaction.GATE.exists()
    assert json.loads(transaction.JOURNAL.read_text())['phase']=='published'
    assert json.loads((state/'whatsapp/current.json').read_text())['version']=='0.5.0'
