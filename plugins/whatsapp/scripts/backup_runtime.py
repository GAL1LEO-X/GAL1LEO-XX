"""Consistent root-only backup of a selected user, or all registered users.

Briefly stops only the selected instance. Credentials included: never publish.
Managed Authelia includes its shared authentication snapshot; an explicitly
configured external OIDC provider remains outside this application's backup.
"""
import sys as _installation_sys
# Standalone callers may omit -B; admitted generations must remain source-only.
_installation_sys.dont_write_bytecode = True
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
from installation_layout import (active as installation_profile, mapped as installation_path,
    read_installation, _read_protected, identity_record, Installation, IDENTITY, PROFILE,
    encoded as installation_encoded, roster_pointer_record)
import argparse
from contextlib import closing, ExitStack
from datetime import datetime,UTC
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import signal
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
import types

import httpx
from sally_whatsapp.tenancy import Instance,ROOT

BOOTSTRAP_ADMIN = Path(installation_path('/usr/local/lib/develative-deploy/whatsapp-bootstrap/release_admin.py'))
# Filesystem fixtures override these module constants, never CLI/request input.
_INSTALLATION_ROOT = Path('/')
_INSTALLATION_UID = 0


def snapshot_tenant_database(*args, **kwargs):
    # Keep executable generation dependencies behind recovery_helpers' owner
    # admission and complete source-hash validation, just like the validator.
    from tenant_database import snapshot_tenant_database as snapshot
    return snapshot(*args, **kwargs)


def validate_snapshot(*args, **kwargs):
    # The validator belongs to the verified administration generation, which
    # main() selects through recovery_helpers before any backup can start.
    # Importing it at module load would require a duplicate project helper.
    from backup_validation import validate_snapshot as validate
    return validate(*args, **kwargs)


def installation_snapshot():
    """Capture the protected public identity before creating a backup or stopping services."""
    profile = read_installation(root=_INSTALLATION_ROOT, trusted_uid=_INSTALLATION_UID)
    expected = identity_record(profile)
    if profile.selection != installation_profile().selection:
        raise ValueError('Backup installation differs from the active identity')
    files = {}
    captured = {}
    for logical in (IDENTITY, *((PROFILE,) if not profile.compatibility else ())):
        physical = _INSTALLATION_ROOT / logical.relative_to('/')
        raw = _read_protected(physical, trusted_uid=_INSTALLATION_UID, trust_root=_INSTALLATION_ROOT)
        value = json.loads(raw, object_pairs_hook=_unique_installation_fields)
        if logical == IDENTITY:
            if value != expected:
                raise ValueError('Backup installation marker changed during capture')
        elif identity_record(Installation.from_dict(value)) != expected:
            raise ValueError('Backup installation locator changed during capture')
        captured[physical] = raw
        files[str(logical)] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    if profile.roster is not None:
        for logical, expected_bytes in (
            (PurePosixPath(profile.roster_pointer()), installation_encoded(roster_pointer_record(profile))),
            (PurePosixPath(profile.roster_snapshot(profile.roster_sha256)), profile._roster),
        ):
            physical = _INSTALLATION_ROOT / logical.relative_to('/')
            raw = _read_protected(physical, trusted_uid=_INSTALLATION_UID, trust_root=_INSTALLATION_ROOT)
            if raw != expected_bytes:
                raise ValueError('Backup allocation changed during capture')
            captured[physical] = raw
            files[str(logical)] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    if read_installation(root=_INSTALLATION_ROOT, trusted_uid=_INSTALLATION_UID).selection != profile.selection:
        raise ValueError('Backup installation identity changed during capture')
    binding = {'identity': expected, 'files': files}
    if profile.roster is not None:
        binding['roster_sha256'] = profile.roster_sha256
    return binding, captured


def _unique_installation_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate installation snapshot field')
        result[key] = value
    return result


def recovery_helpers():
    # The installed bootstrap is the only authority. Compile its protected
    # source rather than accepting an importable stale bytecode/project copy.
    path = BOOTSTRAP_ADMIN
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise RuntimeError('Install the dedicated WhatsApp administration bootstrap first')
    layout_path=path.with_name('installation_layout.py')
    for item in (path, layout_path, *path.parents):
        metadata = item.lstat()
        expected = stat.S_ISREG if item in (path,layout_path) else stat.S_ISDIR
        if not expected(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise RuntimeError('The WhatsApp administration bootstrap is not protected')
    layout=types.ModuleType('installation_layout')
    layout.__file__=str(layout_path)
    sys.modules['installation_layout']=layout
    try:exec(compile(layout_path.read_bytes(),str(layout_path),'exec'),layout.__dict__)
    except BaseException:
        sys.modules.pop('installation_layout',None)
        raise
    administration = sys.modules.get('release_admin')
    if administration is None:
        administration = types.ModuleType('release_admin')
        administration.__file__ = str(path)
        sys.modules['release_admin'] = administration
        try:
            exec(compile(path.read_bytes(), str(path), 'exec'), administration.__dict__)
        except BaseException:
            sys.modules.pop('release_admin', None)
            raise
    elif Path(administration.__file__) != path:
        raise RuntimeError('A different administration bootstrap is already loaded')
    generation = administration.load_generation()
    administration.pin_generation(generation)
    sys.path.insert(0, str(generation.path))
    import release_backup
    import github_release
    if (Path(release_backup.__file__) != generation.path/'release_backup.py'
            or Path(github_release.__file__) != generation.path/'github_release.py'):
        raise RuntimeError('A different recovery generation is already loaded')
    return release_backup, github_release, administration, generation


class BackupError(RuntimeError):
    def __init__(self,complete,failures):
        self.complete,self.failures=complete,failures
        # Keep provider details available to the caller without printing secrets.
        summary=', '.join(stage+' ('+type(error).__name__+')' for stage,error in failures)
        super().__init__(('Snapshot completed' if complete else 'Snapshot incomplete')+'; failures: '+summary)


def restore_components(instance,running_gateway,running_bridge,*,lock_fd=None):
    components=[]
    if running_gateway:
        components.append(('gateway',[str(instance.wrapper),'systemctl','--user','start','whatsapp-waha.service'],
                           f'http://127.0.0.1:{instance.gateway_port}/api/version'))
    if running_bridge:
        components.append(('bridge',['systemctl','start',instance.base+'.service'],
                           f'http://127.0.0.1:{instance.bridge_port}/healthz'))
    failures=[]
    for name,command,_ in components:
        try: subprocess.run(command,check=True,**({'pass_fds':(lock_fd,)} if lock_fd is not None else {}))
        except Exception as error: failures.append((name+'.start',error))
    if not components: return failures
    try:
        with httpx.Client(timeout=2,trust_env=False,follow_redirects=False) as client:
            for name,_,url in components:
                try:
                    headers={'X-Api-Key':(instance.config_dir/'waha.key').read_text().strip()} if name=='gateway' else {}
                    for attempt in range(30):
                        try:
                            if client.get(url,headers=headers).is_success: break
                        except httpx.HTTPError: pass
                        if attempt<29: time.sleep(1)
                    else: raise RuntimeError('HTTP readiness did not recover')
                except Exception as error: failures.append((name+'.readiness',error))
    except Exception as error:
        failures.append(('readiness.client',error))
    return failures


def snapshot_database(source,target):
    with closing(sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True)) as db,closing(sqlite3.connect(target)) as snapshot:
        db.backup(snapshot)
        if snapshot.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise RuntimeError('Backup integrity check failed')
        # The online backup inherits WAL mode. Checkpoint and close explicitly so
        # the manifest cannot include transient -wal/-shm files later removed.
        snapshot.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        if snapshot.execute('PRAGMA journal_mode=DELETE').fetchone()[0]!='delete':
            raise RuntimeError('Backup must be a standalone SQLite database')


def authentication_mode(instance):
    """An absent legacy field remains managed; only explicit external can omit IdP assets."""
    mode=getattr(instance,'auth_mode','managed-authelia')
    if mode not in ('managed-authelia','external-oidc'):
        raise ValueError('Invalid backup authentication mode')
    if mode=='external-oidc':
        config=tomllib.loads((instance.config_dir/'config.toml').read_text()).get('bridge')
        expected={'public_url':instance.public_url,'issuer':instance.issuer,
                  'owner_subject':instance.subject,'jwks_url':instance.effective_jwks_url,
                  'oauth_client_ids':[instance.chatgpt_client],'link_client_id':instance.link_client}
        if not isinstance(config,dict) or any(config.get(key)!=value for key,value in expected.items()):
            raise ValueError('External OIDC backup configuration differs from its registered identity')
    return mode


def registered_instances(registry,administration):
    """Read the administrative registry under its caller's publication/tenant leases."""
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value: raise ValueError('Duplicate backup registry field')
            value[key]=item
        return value
    registry=administration.trusted_path(registry)
    value=json.loads(registry.read_text(),object_pairs_hook=unique)
    if not isinstance(value,dict) or value.get('format')!=1 or type(value.get('format')) is not int:
        raise ValueError('Invalid backup registry format')
    rows=value.get('instances')
    if not isinstance(rows,dict) or not rows:
        raise ValueError('An explicit instance registry is required for backup')
    instances={key:Instance(**row['spec']) for key,row in rows.items()}
    if any(key!=instance.slug for key,instance in instances.items()):
        raise ValueError('Backup registry identity differs')
    return instances


def backup(instance, *, recovery_id=None, recovery=None, lock_fd=None):
    auth_mode=authentication_mode(instance)
    installation, installation_files = installation_snapshot()
    stamp=datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')
    target=(Path('/var/backups')/instance.base if installation_profile().compatibility
            else Path(installation_profile().path('backup'))/instance.slug)/'snapshots'/stamp
    target.mkdir(parents=True,mode=0o700)
    bridge=['systemctl'];gateway=[str(instance.wrapper),'systemctl','--user']
    inherited={'pass_fds':(lock_fd,)} if lock_fd is not None else {}
    bridge_state=subprocess.run([*bridge,'is-active','--quiet',instance.base+'.service'],**inherited).returncode
    gateway_state=subprocess.run([*gateway,'is-active','--quiet','whatsapp-waha.service'],**inherited).returncode
    if bridge_state not in (0,3,4) or gateway_state not in (0,3,4):
        raise RuntimeError('Cannot establish prior backup service activity')
    running_bridge=bridge_state==0
    running_gateway=gateway_state==0
    completed=False
    failures=[]
    if recovery_id is not None:
        recovery.before_stop(recovery_id, instance.slug, target, running_gateway, running_bridge)
    try:
        if running_bridge: subprocess.run([*bridge,'stop',instance.base+'.service'],check=True,**inherited)
        if running_gateway: subprocess.run([*gateway,'stop','whatsapp-waha.service'],check=True,**inherited)
        snapshot_tenant_database(instance,target/'archive.sqlite',
                                 **({'lock_fd':lock_fd} if lock_fd is not None else {}))
        if auth_mode=='managed-authelia':
            snapshot_database('/var/lib/sally-browser/stack/authelia/db.sqlite3',target/'shared-authelia.sqlite3')
        paths=[instance.config_dir,instance.gateway_home/'sessions',instance.gateway_home/'media',instance.private_dir,
               ROOT/'private/tenants.json',Path('/etc/systemd/system')/(instance.base+'.service'),
               # The release runtime and resource policy are applied through
               # drop-ins. Saving only the base unit loses the effective
               # service configuration after a clean restore.
               Path('/etc/systemd/system')/(instance.base+'.service.d'),
               Path('/etc/apache2/sites-available')/(instance.base+'-http.conf'),
               Path('/etc/apache2/sites-available')/(instance.base+'-https.conf'),
               instance.gateway_home/'.config/containers/systemd/whatsapp-waha.container',
               instance.gateway_home/'.config/systemd/user/whatsapp-waha.service.d',
               instance.state_dir/'media-cache',instance.state_dir/'diagnostics',
               instance.state_dir/'archive.sqlite.identity.json']
        if auth_mode=='managed-authelia':
            paths.extend([Path('/var/lib/sally-browser/stack/config/authelia.yml'),
                          Path('/var/lib/sally-browser/stack/config/users.yml')])
        configuration=instance.config_dir/'config.toml'
        if configuration.exists():
            marker=tomllib.loads(configuration.read_text()).get('bridge',{}).get('state_identity_file')
            if marker:
                marker=Path(marker)
                if not marker.is_absolute() or not marker.is_file():
                    raise RuntimeError('Configured technical-state identity marker is missing')
                if not marker.is_relative_to(instance.config_dir): paths.append(marker)
        if instance.slug=='personal': paths.extend([ROOT/'private/identity.json',ROOT/'scripts/as-user'])
        with tarfile.open(target/'private-runtime.tar.gz','w:gz') as archive:
            for path, raw in installation_files.items():
                member = tarfile.TarInfo(str(path).lstrip('/'))
                member.size = len(raw)
                member.mode = 0o600
                archive.addfile(member, io.BytesIO(raw))
            for path in paths:
                if path.exists(): archive.add(path,arcname=str(path).lstrip('/'))
        subprocess.run([str(ROOT/'.venv/bin/python'),str(ROOT/'scripts/package_source.py'),str(target/'source.tar.gz')],check=True,capture_output=True,**inherited)
        manifest={'format':'whatsapp-isolated-backup-v6' if 'roster_sha256' in installation else 'whatsapp-isolated-backup-v5','user':instance.slug,'created_utc':stamp,
                  'sqlite_integrity':'ok','includes_credentials':True,'files':{},
                  'auth_mode':auth_mode,'installation':installation}
        for path in target.iterdir():
            if path.is_file():
                with path.open('rb') as stream: checksum=hashlib.file_digest(stream,'sha256').hexdigest()
                manifest['files'][path.name]={'sha256':checksum,'bytes':path.stat().st_size}
        (target/'manifest.json').write_text(json.dumps(manifest,indent=2))
        for path in target.iterdir():
            if path.is_file():
                with path.open('rb') as stream: os.fsync(stream.fileno())
        directory_fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
        parent_fd=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent_fd)
        finally:os.close(parent_fd)
        # The same complete contract used by the release gate must accept the
        # artifact before its durable journal or receipt can declare success.
        validate_snapshot(target,instance.slug,runtime_prefix=_INSTALLATION_ROOT,auth_mode=auth_mode)
        if recovery_id is not None: recovery.copy_complete(recovery_id,instance.slug)
        completed=True
    except Exception as error:
        failures.append(('snapshot',error))
    finally:
        failures.extend(restore_components(instance,running_gateway,running_bridge,
                                           **({'lock_fd':lock_fd} if lock_fd is not None else {})))
    if failures: raise BackupError(completed,failures)
    return {'user':instance.slug,'backup':str(target),'complete':completed,'credentials_included':True}


def interrupted(signum, frame):
    # The receiver allows a grace period for the active snapshot's finally.
    raise RuntimeError('Backup interrupted; restoring previous service activity')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--user',default='personal')
    group.add_argument('--all',action='store_true')
    parser.add_argument('--lock-fd',type=int,help=argparse.SUPPRESS)
    parser.add_argument('--recovery-id',help=argparse.SUPPRESS)
    parser.add_argument('--managed-child',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--admin-pin',help=argparse.SUPPRESS)
    parser.add_argument('--check-recovery',action='store_true',help='Read-only installed recovery protocol check')
    args=parser.parse_args()
    recovery,release,administration,generation=recovery_helpers()
    pin={'epoch':generation.epoch,'path':str(generation.path),'manifest':generation.manifest_sha256}
    if args.admin_pin is not None and json.loads(args.admin_pin)!=pin:
        raise RuntimeError('Administration generation changed before the backup worker started')
    if args.check_recovery:
        print(json.dumps({**recovery.capabilities(),'helper':str(Path(recovery.__file__).resolve())}))
        return
    if os.geteuid()!=0: raise SystemExit('Run as the authorized server administrator')
    os.umask(0o077)
    if args.lock_fd is None and not args.managed_child:
        # A private session bounds surviving descendants without involving the
        # interactive administrator's shell or unrelated process groups.
        process=subprocess.run([sys.executable,'-B',str(Path(__file__).resolve()),*sys.argv[1:],
                                '--managed-child','--admin-pin',json.dumps(pin,separators=(',',':'))],start_new_session=True)
        raise SystemExit(process.returncode)
    if (args.managed_child or args.lock_fd is not None) and args.admin_pin is None:
        raise RuntimeError('The backup worker requires its verified generation')
    signal.signal(signal.SIGTERM, interrupted)
    registry=ROOT/'private/tenants.json'
    import fcntl
    lock_path=ROOT/'private/tenant-admin.lock'
    with ExitStack() as stack:
        if args.lock_fd is not None:
            # The receiver holds publication first. Its inherited tenant lock
            # also prevents independent recovery while this child survives it.
            supplied=os.fstat(args.lock_fd)
            expected=lock_path.stat()
            if (supplied.st_dev,supplied.st_ino)!=(expected.st_dev,expected.st_ino):
                raise RuntimeError('Invalid inherited tenant administration lock')
            lock=stack.enter_context(os.fdopen(os.dup(args.lock_fd),'a'))
            if not args.recovery_id: raise RuntimeError('Inherited backup requires its durable operation')
            administration.require_current(recovery.__file__, expected=generation)
        else:
            if args.recovery_id: raise RuntimeError('Recovery operation requires an inherited lock')
            # Same order as publication/recovery, never tenant -> publication.
            stack.enter_context(administration.publication_lock(expected=generation))
            lock=stack.enter_context(lock_path.open('a'))
        fcntl.flock(lock,fcntl.LOCK_EX)
        administration.require_current(recovery.__file__, expected=generation)
        # Re-read the registry under the tenant lock (it may have changed while waiting).
        instances=registered_instances(registry,administration)
        registered=release.instances(ROOT)
        selected=list(instances.values()) if args.all else [instances[args.user]]
        for instance in selected:
            if instance.auth_mode=='external-oidc':
                administration.trusted_path(instance.config_dir/'config.toml')
                authentication_mode(instance)
        rows=[item for item in registered if item['slug'] in {instance.slug for instance in selected}]
        if args.recovery_id:
            plan=recovery.require_id(args.recovery_id)
            recovery.validate_context(plan,ROOT,registered)
            if set(plan['selected'])!={item['slug'] for item in rows}:
                raise RuntimeError('Backup selection differs from its durable operation')
        else:
            recovery.verify_prerequisites(ROOT)
            plan=recovery.begin(ROOT,rows,release.backup_components(rows),
                                release.literal(ROOT/'sally_whatsapp/__init__.py','__version__'))
        recovery.attach_worker(plan['id'])
        try:
            for instance in selected:
                print(json.dumps(backup(instance,recovery_id=plan['id'],recovery=recovery,lock_fd=lock.fileno())),flush=True)
        finally:
            recovery.recover(ROOT,registered,
                             lambda parts,version: release.restore_backup_components(parts,version,lock_fd=lock.fileno()))


if __name__=='__main__': main()
