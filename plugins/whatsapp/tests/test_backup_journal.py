"""Crash-safe backup coordination: synthetic files, owned children, no services."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
from types import SimpleNamespace

import pytest

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
import backup_runtime
import github_release as release
import github_release_common as common
import release_backup as journal
import release_recover
import release_admin as admin
import release_transaction as transaction


@pytest.fixture
def recovery(tmp_path,monkeypatch):
    root=tmp_path/'project';(root/'private').mkdir(parents=True);(root/'sally_whatsapp').mkdir()
    (root/'private/tenants.json').write_text('{"synthetic":true}')
    (root/'sally_whatsapp/__init__.py').write_text('__version__="0.4.9"')
    rows=[];components=[]
    for index,slug in enumerate(('enabled','suspended')):
        config=tmp_path/(slug+'.toml');config.write_text('[bridge]\n')
        wrapper=tmp_path/(slug+'-wrapper');wrapper.write_text('synthetic-wrapper')
        item={'slug':slug,'base':'whatsapp-'+slug,'unit':'whatsapp-'+slug+'.service',
              'port':8822+index*2,'config':config,'wrapper':wrapper}
        rows.append(item)
        for kind,command,unit,port in [('gateway',[str(wrapper),'systemctl','--user'],'whatsapp-waha.service',item['port']+1),
                                       ('bridge',['systemctl'],item['unit'],item['port'])]:
            components.append({'name':slug+'.'+kind,'kind':kind,'command':command,'unit':unit,
                               'port':port,'config':config,'active':slug=='enabled'})
    state=tmp_path/'state';state.mkdir()
    monkeypatch.setattr(journal,'JOURNAL',state/'backup.json')
    monkeypatch.setattr(transaction,'JOURNAL',state/'transaction.json')
    monkeypatch.setattr(transaction,'GATE',state/'gate')
    transaction.JOURNAL.write_text('{"phase":"published"}')
    generation=SimpleNamespace(path=SCRIPTS,epoch='e'*32,manifest_sha256='d'*64)
    @contextmanager
    def publication_lock(path,**kwargs):
        with (state/'publication.lock').open('a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise admin.AdminBusy('synthetic busy') from None
            yield generation
    # Admission is separately covered with real generation manifests; this
    # fixture preserves the real publication/tenant ordering for crash probes.
    monkeypatch.setattr(admin,'publication_lock',publication_lock)
    monkeypatch.setattr(admin,'require_current',lambda *args,**kwargs:generation)
    return SimpleNamespace(root=root,rows=rows,components=components,state=state)


def begin(p):return journal.begin(p.root,p.rows,p.components,'0.4.9')


def test_copy_and_service_completion_are_independent_and_recovery_is_idempotent(recovery):
    p=recovery;plan=begin(p)
    journal.before_stop(plan['id'],'enabled',p.root/'snapshot',True,True)
    journal.copy_complete(plan['id'],'enabled')
    stored=journal.read()
    assert stored['copies']['enabled']['complete'] and not stored['servicesRestored']
    calls=[]
    def restore(components,version):
        calls.extend(item['name'] for item in components if item['active'])
        return []
    result=journal.recover(p.root,p.rows,restore)
    assert calls==['enabled.gateway','enabled.bridge']
    assert result['servicesRestored'] and result['copies']['enabled']['complete']
    assert result['copies']['suspended']=={'path':None,'complete':False}
    journal.recover(p.root,p.rows,restore)
    assert len(calls)==2


@pytest.mark.parametrize('change',['config','registry','wrapper','commands','gate','unfinished'])
def test_changed_context_or_activation_refuses_any_start(recovery,change):
    p=recovery;begin(p)
    if change in ('config','wrapper'):Path(p.rows[0][change]).write_text('changed')
    elif change=='registry':(p.root/'private/tenants.json').write_text('changed')
    elif change=='commands':
        plan=journal.read();plan['components'][0]['command']=['unrelated'];common.save(journal.JOURNAL,plan)
    elif change=='gate':transaction.GATE.touch()
    else:transaction.JOURNAL.write_text('{"phase":"committed"}')
    called=[]
    with pytest.raises(common.ReleaseError):journal.recover(p.root,p.rows,lambda *args:called.append(args))
    assert not called


def test_failed_readiness_preserves_retryable_journal_and_never_marks_copy_complete(recovery):
    p=recovery;begin(p)
    with pytest.raises(common.ReleaseError,match='administrator attention'):
        journal.recover(p.root,p.rows,lambda *args:['enabled.gateway.readiness'])
    plan=journal.read()
    assert plan['phase']=='recovery-failed' and not plan['servicesRestored']
    assert all(not item['complete'] for item in plan['copies'].values())
    assert journal.recover(p.root,p.rows,lambda *args:[])['phase']=='restored'


def test_corrupt_journal_and_unfinished_operation_fail_closed(recovery):
    p=recovery;begin(p)
    with pytest.raises(common.ReleaseError,match='must be recovered'):begin(p)
    journal.JOURNAL.write_text('{partial')
    with pytest.raises(ValueError):journal.recover(p.root,p.rows,lambda *args:pytest.fail('service call'))


@pytest.mark.parametrize('field,value',[
    ('boot','not-a-uuid'),('boot','A'*8+'-aaaa-aaaa-aaaa-'+'a'*12),
    ('boot','a'*32),('boot',None),('pid',True),('pid',0),('session',True),
    ('session',2),('start','١'),('start','-1'),('start',1),
])
def test_malformed_worker_identity_never_counts_as_a_reboot(recovery,field,value):
    p=recovery;plan=begin(p)
    plan['worker']={'pid':1,'session':1,'start':'1',
                    'boot':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'}
    plan['worker'][field]=value
    common.save(journal.JOURNAL,plan)
    with pytest.raises(common.ReleaseError,match='Invalid backup worker identity'):
        journal.recover(p.root,p.rows,lambda *args:pytest.fail('service call'))
    assert journal.read()['phase']=='prepared'


def test_canonical_different_boot_allows_recovery_after_host_restart(recovery,monkeypatch):
    p=recovery;plan=begin(p)
    current_boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    other_boot='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    assert current_boot!=other_boot
    plan['worker']={'pid':1,'session':1,'start':'1','boot':other_boot}
    common.save(journal.JOURNAL,plan)
    assert journal.recover(p.root,p.rows,lambda *args:[])['servicesRestored']


def test_failed_durable_write_prevents_the_first_stop(recovery,monkeypatch):
    from test_backup_runtime import prepare_installation
    p=recovery;plan=begin(p);commands=[]
    prepare_installation(backup_runtime, p.root/'host', monkeypatch)
    monkeypatch.setattr(backup_runtime,'Path',lambda value:p.root/'host'/str(value).lstrip('/'))
    monkeypatch.setattr(backup_runtime,'subprocess',SimpleNamespace(run=lambda args,**kw:commands.append(args) or SimpleNamespace(returncode=0)))
    monkeypatch.setattr(journal,'save',lambda *args:(_ for _ in ()).throw(OSError('synthetic fsync failure')))
    instance=SimpleNamespace(slug='enabled',base='whatsapp-enabled',wrapper=p.rows[0]['wrapper'])
    with pytest.raises(OSError):backup_runtime.backup(instance,recovery_id=plan['id'],recovery=journal)
    assert commands and all('stop' not in args for args in commands)


def test_prior_published_transaction_does_not_skip_backup_recovery(recovery,monkeypatch):
    p=recovery;begin(p);called=[]
    monkeypatch.setattr(common,'STATE',p.state)
    monkeypatch.setattr(release,'ROOT',p.root)
    monkeypatch.setattr(release,'instances',lambda root:p.rows)
    monkeypatch.setattr(release,'restore_backup_components',lambda *args,**kwargs:called.append(args) or [])
    monkeypatch.setattr(transaction,'recover',lambda *args:pytest.fail('old activation recovery'))
    release_recover.recover_project('whatsapp')
    assert len(called)==1 and journal.read()['servicesRestored']


CHILD='''
import json,os,signal,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
sys.path.insert(0,str(Path(sys.argv[1]).parents[2]))
from tools.testing.installation_fixture import select_legacy
select_legacy()
import release_backup as journal
import release_transaction as transaction
root=Path(sys.argv[2]);state=Path(sys.argv[3])
journal.JOURNAL=state/'backup.json';transaction.JOURNAL=state/'transaction.json';transaction.GATE=state/'gate'
plan=journal.read()
with (root/'private/tenant-admin.lock').open('a') as lock:
 import fcntl
 fcntl.flock(lock,fcntl.LOCK_EX)
 journal.attach_worker(plan['id'])
 journal.before_stop(plan['id'],'enabled',root/'snapshot',True,True)
 (root/'mock-services-stopped').touch()
 if sys.argv[4]=='after-copy':journal.copy_complete(plan['id'],'enabled')
 print('READY',flush=True)
 try:signal.pause()
 finally:(root/'child-finally').touch()
'''


@pytest.mark.parametrize('point',['during-copy','after-copy'])
def test_sigkill_then_independent_recovery_preserves_copy_fact_and_activity(recovery,monkeypatch,point):
    p=recovery;begin(p);calls=[]
    child=subprocess.Popen([sys.executable,'-B','-c',CHILD,str(SCRIPTS),str(p.root),str(p.state),point],
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
    try:
        assert select.select([child.stdout],[],[],10)[0]
        assert child.stdout.readline().strip()=='READY'
        monkeypatch.setattr(common,'STATE',p.state)
        monkeypatch.setattr(release,'ROOT',p.root)
        monkeypatch.setattr(release,'instances',lambda root:p.rows)
        def restore(components,version,**kwargs):
            calls.extend(item['name'] for item in components if item['active'])
            return []
        monkeypatch.setattr(release,'restore_backup_components',restore)
        # A surviving backup child owns the tenant lock even if its caller died.
        release_recover.recover_project('whatsapp')
        assert not calls
        child.kill();child.communicate(timeout=5)
        assert child.returncode==-signal.SIGKILL and not (p.root/'child-finally').exists()
        release_recover.recover_project('whatsapp')
        assert calls==['enabled.gateway','enabled.bridge']
        result=journal.read()
        assert result['servicesRestored'] and result['copies']['enabled']['complete']==(point=='after-copy')
        release_recover.recover_project('whatsapp')
        assert len(calls)==2
    finally:
        if child.poll() is None:child.kill();child.communicate(timeout=5)


def test_hash_uses_streaming_and_preserves_digest(tmp_path,monkeypatch):
    path=tmp_path/'snapshot.sqlite';chunk=b'synthetic-block'*4096;digest=hashlib.sha256()
    with path.open('wb') as stream:
        for _ in range(128):stream.write(chunk);digest.update(chunk)
    monkeypatch.setattr(Path,'read_bytes',lambda self:pytest.fail('whole-file allocation'))
    assert common.sha(path)==digest.hexdigest()


@pytest.fixture
def prerequisite(tmp_path,monkeypatch):
    generation=SimpleNamespace(path=tmp_path/'generation',epoch='e'*32,manifest_sha256='d'*64)
    entry=tmp_path/'bootstrap/release_entry.py'
    monkeypatch.setattr(admin,'ENTRYPOINT',entry)
    monkeypatch.setattr(admin,'require_current',lambda *args,**kwargs:generation)
    trusted=[]
    monkeypatch.setattr(admin,'trusted_path',lambda path:trusted.append(Path(path)) or Path(path))
    common_properties={'LoadState':'loaded','NeedDaemonReload':'no','FragmentPath':'/synthetic/unit',
                       'DropInPaths':''}
    timer={**common_properties,'ActiveState':'active','UnitFileState':'enabled',
           'Unit':journal.RECOVERY_SERVICE,
           'TimersMonotonic':'{ OnBootUSec=45s ; next_elapse=45s } { OnUnitInactiveUSec=1min ; next_elapse=2min }'}
    service={**common_properties,'Type':'oneshot','User':'root','KillMode':'control-group',
             'RemainAfterExit':'no','Restart':'no','RestartForceExitStatus':'','TimeoutStartUSec':'10min',
             'ExecStart':f'{{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B {entry} recovery ; ignore_errors=no ; }}',
             **dict.fromkeys(('ExecStartPre','ExecStartPost','ExecStop','ExecStopPost','ExecCondition'),'')}
    backup={**journal.capabilities(),'helper':str(generation.path/'release_backup.py')}
    recovery={**journal.capabilities(),'project':'whatsapp','generation':str(generation.path),
              'epoch':generation.epoch,'manifestSha256':generation.manifest_sha256,'entrypoint':str(entry)}
    calls=[]
    def run(args,**kwargs):
        calls.append(list(map(str,args)))
        if '--check-recovery' in args:return json.dumps(backup)
        if '--check' in args:return json.dumps(recovery)
        assert args[:2]==['systemctl','show']
        fields=args[-1].removeprefix('--property=').split(',')
        props=timer if args[2]==journal.RECOVERY_TIMER else service
        return '\n'.join(key+'='+props[key] for key in fields)
    monkeypatch.setattr(journal,'run',run)
    return SimpleNamespace(root=tmp_path,generation=generation,entry=entry,timer=timer,service=service,
                           backup=backup,recovery=recovery,calls=calls,trusted=trusted)


def test_prerequisite_reads_only_the_dedicated_installed_chain(prerequisite):
    p=prerequisite
    assert journal.verify_prerequisites(p.root)==journal.capabilities()
    assert len(p.calls)==4
    assert all('start' not in args and 'restart' not in args and 'enable' not in args for args in p.calls)
    assert all('develative-release-recovery' not in ' '.join(args) for args in p.calls)
    assert p.entry in p.trusted and p.entry.parent/'release_admin.py' in p.trusted


@pytest.mark.parametrize('section,field,value',[
    ('timer','ActiveState','inactive'),('timer','UnitFileState','disabled'),
    ('timer','UnitFileState','enabled-runtime'),('timer','Unit','unrelated.service'),
    ('timer','LoadState','not-found'),('timer','NeedDaemonReload','yes'),
    ('timer','TimersMonotonic',''),('timer','TimersMonotonic','{ OnBootUSec=45s ; next_elapse=45s }'),
    ('timer','TimersMonotonic','{ OnBootUSec=45s ; next_elapse=45s } { OnUnitInactiveUSec=1h ; next_elapse=2h }'),
    ('service','LoadState','not-found'),('service','NeedDaemonReload','yes'),
    ('service','Type','simple'),('service','User','nobody'),('service','KillMode','process'),
    ('service','RemainAfterExit','yes'),('service','Restart','on-failure'),
    ('service','RestartForceExitStatus','SIGKILL'),('service','TimeoutStartUSec','infinity'),
    ('service','TimeoutStartUSec','30s'),
    ('service','ExecStart','{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /global/release_recover.py ; }'),
    ('service','ExecStartPost','{ argv[]=/synthetic/helper ; }'),
    ('service','ExecStop','{ argv[]=/synthetic/helper ; }'),
    ('backup','helper','/legacy/helpers/release_backup.py'),('backup','protocol',0),
    ('backup','protocol',True),('recovery','protocol',True),
    ('recovery','project','unrelated'),('recovery','epoch','f'*32),
    ('recovery','generation','/different/generation'),('recovery','manifestSha256','f'*64),
    ('recovery','entrypoint','/different/entry.py'),('recovery','independentRecovery',False),
])
def test_prerequisite_rejects_mismatched_effective_chain_before_any_mutation(prerequisite,section,field,value):
    p=prerequisite;getattr(p,section)[field]=value
    with pytest.raises(common.ReleaseError):journal.verify_prerequisites(p.root)
    assert all(args[:2]==['systemctl','show'] or '--check' in args or '--check-recovery' in args for args in p.calls)


def test_prerequisite_rechecks_owner_after_child_attestation(prerequisite,monkeypatch):
    calls=[]
    def current(path,**kwargs):
        calls.append(kwargs)
        if kwargs:raise admin.AdminError('synthetic epoch changed')
        return prerequisite.generation
    monkeypatch.setattr(admin,'require_current',current)
    with pytest.raises(admin.AdminError,match='epoch changed'):
        journal.verify_prerequisites(prerequisite.root)
    assert calls==[{}, {'expected':prerequisite.generation}]


def test_recovery_capability_check_never_acquires_locks_or_recovers(monkeypatch,tmp_path):
    generation=SimpleNamespace(path=tmp_path,epoch='e'*32,manifest_sha256='d'*64)
    calls=[]
    monkeypatch.setattr(admin,'require_current',lambda path,**kwargs:calls.append((path,kwargs)) or generation)
    monkeypatch.setattr(admin,'publication_lock',lambda *args:pytest.fail('lock in read-only check'))
    monkeypatch.setattr(journal,'read',lambda:pytest.fail('journal read in capability check'))
    result=release_recover.check()
    assert result=={**journal.capabilities(),'project':'whatsapp','generation':str(tmp_path),
                    'epoch':'e'*32,'manifestSha256':'d'*64,'entrypoint':str(admin.ENTRYPOINT)}
    assert calls==[(release_recover.__file__,{'states':release_recover.RECOVERY_OWNER_STATES}),
                   (journal.__file__,{'expected':generation,'states':release_recover.RECOVERY_OWNER_STATES})]


def test_recovery_refuses_other_projects_without_lock_or_state(monkeypatch):
    monkeypatch.setattr(admin,'publication_lock',lambda *args:pytest.fail('unexpected lock'))
    with pytest.raises(common.ReleaseError,match='only WhatsApp'):
        release_recover.recover_project('unrelated')


def test_effective_timer_multiple_property_lines_are_parsed(prerequisite,monkeypatch):
    run=journal.run
    def multiline(args,**kwargs):
        return run(args,**kwargs).replace('} { OnUnitInactiveUSec=', '}\nTimersMonotonic={ OnUnitInactiveUSec=')
    monkeypatch.setattr(journal,'run',multiline)
    assert journal.verify_prerequisites(prerequisite.root)==journal.capabilities()
