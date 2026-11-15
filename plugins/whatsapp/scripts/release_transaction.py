"""Durable multi-instance release transaction. Never restore after traffic reopens."""
import sys as _installation_sys
from pathlib import Path as _InstallationPath
import types as _installation_types
if 'installation_layout' not in _installation_sys.modules:
    _installation_source=_InstallationPath(__file__).with_name('installation_layout.py')
    _installation_module=_installation_types.ModuleType('installation_layout')
    _installation_module.__file__=str(_installation_source)
    _installation_sys.modules['installation_layout']=_installation_module
    try:
        exec(compile(_installation_source.read_bytes(),str(_installation_source),'exec'),_installation_module.__dict__)
    except BaseException:
        _installation_sys.modules.pop('installation_layout',None)
        raise
if getattr(_installation_sys.modules['installation_layout'], 'FORMAT', None) != 'whatsapp-installation-v1':
    raise ImportError('The whatsapp entry point cannot reuse another product installation layout')
from installation_layout import active as installation_profile, mapped as installation_path
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import time
import tempfile

from github_release_common import require, run, save, sha, file_map, STATE
from release_database import migrate
from tenant_database import registered_tenant, snapshot_tenant_database, physical_directory

GATE=Path(installation_path('/var/lib/develative-release-gates/whatsapp'))
JOURNAL=STATE/'whatsapp/transaction.json'
ENTRIES=('.venv','sally_whatsapp','pyproject.toml','requirements.lock')
RUNTIME=Path(installation_path('/usr/local/lib/develative-deploy/whatsapp/release_runtime.py'))
SYSTEMD=Path('/etc/systemd/system')
COMMITTED_PHASES=('committed','published')


def sync_directory(path):
    fd=os.open(path,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def checkpoint(plan, phase):
    plan['phase']=phase
    save(Path(plan['record'])/'transaction.json',plan)
    save(JOURNAL,plan)
    sync_directory(JOURNAL.parent)


def write_configuration(path,text):
    path.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile('w',dir=path.parent,delete=False) as stream:
        stream.write(text);stream.flush();os.fsync(stream.fileno());name=stream.name
    os.chmod(name,0o644);os.replace(name,path);sync_directory(path.parent)


def prepare_gate_directory():
    GATE.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
    # The publisher uses umask 077, but service users must stat this marker.
    # chmod also repairs a directory left private by an earlier publication.
    GATE.parent.chmod(0o755)


def gate_on():
    prepare_gate_directory()
    with GATE.open('w') as stream:
        stream.write('Release validation in progress\n');stream.flush();os.fsync(stream.fileno())
    GATE.chmod(0o644);sync_directory(GATE.parent)


def gate_off():
    GATE.unlink(missing_ok=True);sync_directory(GATE.parent)


def dbpath(instance):
    import tomllib
    path=Path(tomllib.loads(Path(instance['config']).read_text())['bridge']['database'])
    expected=Path(installation_profile().instance_paths(instance['slug'])['state'])/'archive.sqlite'
    require(path == expected, 'Unexpected instance database path')
    return path


def tenant(instance):
    return registered_tenant(Path(instance['config']),dbpath(instance),installation_profile().account(instance['slug']))


def snapshot_registered(instance,destination,**options):
    snapshot_tenant_database(tenant(instance),destination,**options)


def replace_database(source, destination):
    destination=Path(destination)
    # Never reopen a predictable name in a service-writable directory as root.
    # Pin the physical directory, exclusively reserve an unpredictable file,
    # and keep copying/chown/chmod/fsync on its descriptor until publication.
    with physical_directory(destination.parent) as directory:
        before=os.stat(destination.name,dir_fd=directory,follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1, 'Unexpected database file')
        temporary=destination.name+'.release-pending-'+secrets.token_hex(16)
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        try:
            with Path(source).open('rb') as incoming,os.fdopen(os.dup(fd),'wb') as output:
                shutil.copyfileobj(incoming,output,length=1024*1024)
            os.fchown(fd,before.st_uid,before.st_gid);os.fchmod(fd,before.st_mode&0o777)
            os.fsync(fd)
            expected=os.fstat(fd)
            current=os.stat(destination.name,dir_fd=directory,follow_symlinks=False)
            staged=os.stat(temporary,dir_fd=directory,follow_symlinks=False)
            require((before.st_dev,before.st_ino)==(current.st_dev,current.st_ino)
                    and (expected.st_dev,expected.st_ino)==(staged.st_dev,staged.st_ino),
                    'Database changed during administrative replacement')
            for suffix in ('-wal','-shm'):
                try:os.unlink(destination.name+suffix,dir_fd=directory)
                except FileNotFoundError:pass
            os.replace(temporary,destination.name,src_dir_fd=directory,dst_dir_fd=directory)
            published=os.stat(destination.name,dir_fd=directory,follow_symlinks=False)
            require((expected.st_dev,expected.st_ino)==(published.st_dev,published.st_ino),
                    'Database changed during administrative publication')
            os.fsync(directory)
        finally:
            os.close(fd)
            try:os.unlink(temporary,dir_fd=directory)
            except FileNotFoundError:pass


def start_recovered_units(units, *, lock_fd=None):
    command_kwargs = {'pass_fds': (lock_fd,)} if lock_fd is not None else {}
    # A crashing candidate can exhaust StartLimitBurst before rollback.
    # Reset only units that were active before this transaction.
    require(bool(units), 'No previously active WhatsApp bridge to recover')
    run(['systemctl','reset-failed',*units], **command_kwargs)
    run(['systemctl','start',*units],timeout=120, **command_kwargs)


def complete_activation(plan, wait_health, *, recovering=False, lock_fd=None):
    """The durable commit forbids restoring old data, even if readiness fails."""
    inherited = {'lock_fd': lock_fd} if lock_fd is not None else {}
    try:
        if recovering:
            start_recovered_units(plan['activeUnits'], **inherited)
            if GATE.exists():
                wait_health(plan['selected'],plan['version'],plan['before'],maintenance=True)
        gate_off()
        wait_health(plan['selected'],plan['version'],plan['before'],require_ready=True)
        save(STATE/'whatsapp/current.json',{'version':plan['version'],'sourceCommit':plan['sourceCommit'],'release':plan['candidate']})
        plan.pop('activationError',None)
        checkpoint(plan,'published')
    except BaseException as error:
        # Do not retry inline or turn this into an old-data rollback. Preserve
        # the original exception, including if the failure journal cannot save.
        # Keep a legacy-recognized post-commit phase: an older recovery helper
        # must never interpret this failure as permission to restore old data.
        plan['activationError']='activation_not_verified'
        try:
            checkpoint(plan,'committed')
        except Exception:
            error.add_note('Activation failure journal could not be saved; inspect the committed transaction')
        raise


def recover(plan, wait_health, *, lock_fd=None):
    """Idempotent after SIGKILL/reboot under WhatsApp publication and tenant locks."""
    inherited = {'lock_fd': lock_fd} if lock_fd is not None else {}
    command_kwargs = {'pass_fds': (lock_fd,)} if lock_fd is not None else {}
    if plan['phase'] in COMMITTED_PHASES:
        complete_activation(plan,wait_health,recovering=True, **inherited)
        return
    if plan['phase']=='rolled-back':return
    if plan['phase']=='rollback-committed':
        gate_off()
        start_recovered_units(plan['activeUnits'], **inherited)
        wait_health(plan['selected'],plan['previousVersion'],plan['before'])
        checkpoint(plan,'rolled-back');return
    gate_on()
    root,record=Path(plan['root']),Path(plan['record'])
    run(['systemctl','stop',*plan['allUnits']],timeout=120, **command_kwargs)
    try:
        if plan.get('frozen'):
            for item in plan['databases']:
                backup=record/item['backup']
                require(sha(backup)==item['sha256'],'Frozen database backup changed')
                replace_database(backup,item['path'])
        for name in ENTRIES:
            saved=record/'previous'/name
            if saved.exists() or saved.is_symlink():
                current=root/name
                if current.is_symlink():
                    require(current.resolve()==(Path(plan['candidate'])/name).resolve(), 'Runtime pointer was changed outside the transaction')
                    current.unlink()
                elif current.exists():
                    candidate=Path(plan['candidate'])/name
                    require((file_map(current)==file_map(candidate)) if current.is_dir() else sha(current)==sha(candidate),
                            'Runtime entry was changed outside the transaction')
                    failed=record/'failed';failed.mkdir(exist_ok=True,mode=0o700)
                    os.replace(current,failed/name)
                os.replace(saved,current)
        for entry in plan['dropins']:
            path=Path(entry['path'])
            if entry['before'] is None:path.unlink(missing_ok=True)
            else:write_configuration(path,entry['before'])
        sync_directory(root)
        run(['systemctl','daemon-reload'], **command_kwargs)
        # Restored old versions may predate maintenance support. DB restore and
        # code restoration are complete before they are allowed to run.
        checkpoint(plan,'rollback-committed')
        gate_off()
        start_recovered_units(plan['activeUnits'], **inherited)
        wait_health(plan['selected'],plan['previousVersion'],plan['before'])
        checkpoint(plan,'rolled-back')
    except BaseException:
        if plan['phase'] != 'rollback-committed':
            gate_on();checkpoint(plan,'rollback-failed')
        raise


def activate(root,candidate,registered,selected,before,old_version,version,record,
             wait_health,queues_idle,probe_databases,*,source_commit,lock_fd=None):
    inherited = {'lock_fd': lock_fd} if lock_fd is not None else {}
    command_kwargs = {'pass_fds': (lock_fd,)} if lock_fd is not None else {}
    require(not JOURNAL.exists() or json.loads(JOURNAL.read_text())['phase'] in ('published','rolled-back'),
            'An unfinished WhatsApp release must be recovered first')
    record.mkdir(parents=True,mode=0o700)
    (record/'previous').mkdir(mode=0o700)
    prepared=record/'prepared';prepared.mkdir(mode=0o700)
    # Keep the administration/backup layout stable. Only the non-relocatable
    # environment is a pointer; source and lock files remain ordinary entries.
    for name in ENTRIES:
        if name=='.venv':(prepared/name).symlink_to(candidate/name,target_is_directory=True)
        elif (candidate/name).is_dir():shutil.copytree(candidate/name,prepared/name)
        else:shutil.copyfile(candidate/name,prepared/name)
    serial=lambda items:[{k:str(v) if isinstance(v,Path) else v for k,v in item.items()} for item in items]
    plan={'root':str(root),'candidate':str(candidate),'record':str(record),'version':version,'sourceCommit':source_commit,
          'previousVersion':old_version,'selected':serial(selected),'registered':serial(registered),
          'before':before,'activeUnits':[item['unit'] for item in selected],
          'allUnits':[item['unit'] for item in registered],'databases':[],'dropins':[],'frozen':False}
    for item in registered:
        path=SYSTEMD/(item['unit']+'.d')/'70-release-runtime.conf'
        plan['dropins'].append({'path':str(path),'before':path.read_text() if path.exists() else None})
    checkpoint(plan,'prepared')
    try:
        gate_on()
        run(['systemctl','stop',*plan['allUnits']],timeout=120, **command_kwargs)
        queues_idle(registered)
        checkpoint(plan,'stopped')
        for item in registered:
            database=dbpath(item)
            backup=record/(item['slug']+'-before.sqlite')
            snapshot_registered(item,backup,**({'lock_fd':lock_fd} if lock_fd is not None else {}))
            migrated=record/(item['slug']+'-candidate.sqlite')
            shutil.copyfile(backup,migrated);migrated.chmod(0o600)
            evidence=migrate(migrated,candidate)
            plan['databases'].append({'path':str(database),'backup':backup.name,'sha256':sha(backup),
                                      'migrated':migrated.name,'migration':evidence})
        # All original DBs are intact. Validate every fresh frozen copy together.
        probe_databases([record/item['migrated'] for item in plan['databases']])
        plan['frozen']=True;checkpoint(plan,'frozen')
        for item in plan['databases']:
            replace_database(record/item['migrated'],item['path'])
        for name in ENTRIES:
            os.replace(root/name,record/'previous'/name)
            os.replace(prepared/name,root/name)
        for item,entry in zip(registered,plan['dropins']):
            path=Path(entry['path']);path.parent.mkdir(parents=True,exist_ok=True)
            write_configuration(path,'[Service]\nExecStart=\nExecStart='+str(root/'.venv/bin/python')+' '+str(RUNTIME)+' --config '+str(item['config'])+'\n')
        sync_directory(root);checkpoint(plan,'switched')
        run(['systemctl','daemon-reload'], **command_kwargs)
        run(['systemctl','start',*plan['activeUnits']],timeout=120, **command_kwargs)
        wait_health(selected,version,before,maintenance=True)
        checkpoint(plan,'committed')
        complete_activation(plan,wait_health, **inherited)
        return plan
    except BaseException:
        if plan['phase'] not in COMMITTED_PHASES:
            recover(plan,wait_health, **inherited)
        raise
