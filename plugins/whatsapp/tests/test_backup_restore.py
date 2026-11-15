"""Offline data-recovery rehearsal. Every host path, identity and service is synthetic."""
import base64
from contextlib import ExitStack,closing
from dataclasses import asdict,replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path,PurePosixPath
import pwd
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
from types import SimpleNamespace

from cryptography.fernet import Fernet,InvalidToken
import httpx
import pytest

# The host-path mapper and Unix permission assertions require POSIX semantics.
# On Windows a rooted path can discard the temporary-directory prefix.
pytestmark=pytest.mark.skipif(sys.platform=='win32',reason='POSIX synthetic-host path and permission rehearsal')

from conftest import message,Receiver
from test_backup_runtime import prepare_installation
from sally_whatsapp.auth import JWTVerifier
from sally_whatsapp.admin import RuntimeAdminOperations
from sally_whatsapp.config import Settings
from sally_whatsapp.server import Service
from sally_whatsapp.state_continuity import register_external_identity
from sally_whatsapp import tenancy

PLUGIN=Path(__file__).parents[1]
sys.path.insert(0, str(PLUGIN/'scripts'))
from backup_validation import validate_snapshot
import backup_validation as validation
import installation_layout as layout
import tenant_database as secure
AUTH_DB=Path('/var/lib/sally-browser/stack/authelia/db.sqlite3')
PROJECT=Path('/srv/openai-codex/projects/whatsapp-personal')


def digest(data): return hashlib.sha256(data).hexdigest()


def database_digest(path):
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as db:
        assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        assert not db.execute('PRAGMA foreign_key_check').fetchall()
        return digest('\n'.join(db.iterdump()).encode())


def write(path,data,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    path.write_bytes(data.encode() if isinstance(data,str) else data)
    path.chmod(mode)


def save_settings(settings,path):
    fields={key:str(value) if isinstance(value,Path) else value for key,value in asdict(settings).items() if value is not None}
    write(path,'[bridge]\n'+'\n'.join(key+' = '+json.dumps(value) for key,value in fields.items())+'\n')


def restore_fixture(snapshots,destination,source_host,instances):
    """Test-only reconstruction into a NEW empty directory; never installs services.

    Validate the complete synthetic batch before writing. The source host prefix
    exists only because backup_runtime is exercised against a temporary host tree.
    """
    if destination.exists(): raise ValueError('Restore destination must not exist')
    files={};directories={}
    def include(name,data,mode):
        name=PurePosixPath(name)
        if name.is_absolute() or '..' in name.parts or str(name)=='.':
            raise ValueError('Unsafe snapshot member')
        previous=files.get(name)
        if previous is not None and previous!=(data,mode):
            raise ValueError('Snapshots disagree on shared data')
        files[name]=(data,mode)
    for slug,snapshot in snapshots.items():
        instance=instances[slug]
        auth_mode=getattr(instance,'auth_mode','managed-authelia')
        validate_snapshot(snapshot, slug, runtime_prefix=source_host,auth_mode=auth_mode)
        include((instance.state_dir/'archive.sqlite').relative_to(source_host),
                (snapshot/'archive.sqlite').read_bytes(),0o600)
        if auth_mode=='managed-authelia':
            include(str(AUTH_DB).lstrip('/'),(snapshot/'shared-authelia.sqlite3').read_bytes(),0o600)
        for name in ('private-runtime.tar.gz','source.tar.gz'):
            with tarfile.open(snapshot/name,'r:gz') as archive:
                for member in archive.getmembers():
                    original=PurePosixPath(member.name)
                    if original.is_absolute() or '..' in original.parts or not (member.isfile() or member.isdir()):
                        raise ValueError('Unsafe snapshot member')
                    if name=='private-runtime.tar.gz':
                        try: relative=original.relative_to(str(source_host).lstrip('/'))
                        except ValueError: raise ValueError('Runtime member outside synthetic host') from None
                    else: relative=PurePosixPath(str(getattr(instance,'source_project',PROJECT)).lstrip('/'))/original
                    if member.isdir(): directories[relative]=member.mode&0o777
                    else: include(relative,archive.extractfile(member).read(),member.mode&0o777)
    if any(parent in files for name in files for parent in name.parents) or set(files)&set(directories):
        raise ValueError('Snapshot path types conflict')
    destination.mkdir(mode=0o700)
    for name in sorted(directories,key=lambda value:len(value.parts)):
        (destination/name).mkdir(parents=True,exist_ok=True,mode=0o700)
    for name,(data,mode) in files.items(): write(destination/name,data,mode)
    for name,mode in directories.items(): (destination/name).chmod(mode)
    return destination


@pytest.fixture
def rehearsal(environment,tmp_path,monkeypatch,request):
    def no_network(*args,**kwargs):
        raise AssertionError('The recovery rehearsal must not open network connections')
    monkeypatch.setattr(socket.socket,'connect',no_network)
    monkeypatch.setattr(socket.socket,'connect_ex',no_network)
    monkeypatch.setattr(socket,'create_connection',no_network)
    configured=getattr(request,'param','legacy')=='configured-v5'
    source_project=Path('/srv/synthetic-messages/app') if configured else PROJECT
    host=tmp_path/'source-host';project=host/str(source_project).lstrip('/')
    profile=layout.Installation.legacy()
    if configured:
        value=json.loads((PLUGIN/'deploy/installation.example.json').read_bytes())
        value['paths']['project']=str(source_project)
        value['accounts']={'alpha':'messages-alpha','bravo':'messages-bravo'}
        value['ports']={'alpha':{'bridge':19001,'gateway':19009},'bravo':{'bridge':21005,'gateway':21013}}
        profile=layout.Installation.from_dict(value)
    monkeypatch.setattr(validation,'installation_profile',lambda:profile)
    project.mkdir(parents=True)
    for name in ('sally_whatsapp','tests','scripts','deploy','plugin','docs','qa'):
        shutil.copytree(PLUGIN/name,project/name,ignore=shutil.ignore_patterns('__pycache__','.pytest_cache','*.pyc'))
    for name in ('pyproject.toml','requirements.lock','requirements-test.lock','README.md'):
        shutil.copy2(PLUGIN/name,project/name)
    spec=importlib.util.spec_from_file_location('synthetic_backup_runtime',PLUGIN/'scripts/backup_runtime.py')
    backup=importlib.util.module_from_spec(spec);spec.loader.exec_module(backup)
    def host_path(value):
        path=Path(value)
        return path if path.is_relative_to(host) else host/str(path).lstrip('/')
    monkeypatch.setattr(backup,'ROOT',project)
    monkeypatch.setattr(backup,'Path',host_path)
    prepare_installation(backup, host, monkeypatch,profile)
    original_snapshot=backup.snapshot_database
    def snapshot(source,target):
        source=host_path(source)
        assert source.is_relative_to(host) and target.is_relative_to(host)
        original_snapshot(source,target)
    monkeypatch.setattr(backup,'snapshot_database',snapshot)
    monkeypatch.setattr(secure,'_TRUST_ROOT',host)
    monkeypatch.setattr(secure,'_TRUST_UID',os.getuid())
    monkeypatch.setattr(tenancy,'ROOT',project)
    commands=[]
    def run(args,**kwargs):
        args=list(map(str,args));commands.append(args)
        if args[0]=='systemctl' or args[0].startswith(str(project)) and 'systemctl' in args:
            return SimpleNamespace(returncode=0)
        assert args[1]==str(project/'scripts/package_source.py') and len(args)==3
        return subprocess.run([sys.executable,*args[1:]],**kwargs)
    monkeypatch.setattr(backup,'subprocess',SimpleNamespace(run=run))
    class Readiness:
        def __init__(self,**kwargs): pass
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def get(self,url,**kwargs):
            assert url.startswith('http://127.0.0.1:')
            return SimpleNamespace(is_success=True)
    monkeypatch.setattr(backup,'httpx',SimpleNamespace(Client=Readiness,HTTPError=httpx.HTTPError))
    instances={};settings={};jobs={};transfers={};tokens={};foreign_owner_tokens={};admin_requests={}
    owners=['11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222']
    auth=host_path(AUTH_DB);auth.parent.mkdir(parents=True)
    with ExitStack() as stack:
        db=stack.enter_context(closing(sqlite3.connect(auth)))
        db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
        db.execute('CREATE TABLE user_opaque_identifier(service TEXT,sector_id TEXT,username TEXT,identifier TEXT UNIQUE)')
        db.execute('INSERT INTO user_opaque_identifier VALUES(?,?,?,?)',('openid','','unrelated','33333333-3333-4333-8333-333333333333'))
        for index,slug in enumerate(('alpha','bravo') if configured else ('personal','fixture')):
            options={'public_hostname':slug+'.fixture.example','issuer':'https://issuer.example',
                'jwks_url':'https://issuer.example/keys','auth_mode':'external-oidc',
                'oauth_client_id':slug+'-mcp','pairing_client_id':slug+'-pairing',
                'installation':profile.as_dict()} if configured else {}
            port=profile.instance_ports(slug)['bridge'] if configured else 8820+index*2
            logical=tenancy.Instance(slug,'Synthetic '+slug,owners[index],port,**options)
            paths={name:host_path(getattr(logical,name)) for name in ('config_dir','state_dir','gateway_home','private_dir','wrapper')}
            instance=SimpleNamespace(slug=slug,base=logical.base,bridge_port=logical.bridge_port,
                gateway_port=logical.gateway_port,auth_mode=logical.auth_mode,source_project=source_project,
                issuer=logical.issuer,effective_jwks_url=logical.effective_jwks_url,
                chatgpt_client=logical.chatgpt_client,link_client=logical.link_client,**paths)
            instances[slug]=instance
            for path in paths.values():
                if path!=instance.wrapper: path.mkdir(parents=True,exist_ok=True,mode=0o700)
            for name in ('webhook.key','waha.key'): write(instance.config_dir/name,(slug+'-synthetic-')*4)
            write(instance.config_dir/'encryption.key',Fernet.generate_key())
            write(instance.config_dir/'issuer-public.pem',environment[0].public_key_file.read_bytes())
            cfg=replace(environment[0],database=instance.state_dir/'archive.sqlite',owner_subject=logical.subject,
                public_url='https://'+slug+'.fixture.example',oauth_client_ids=[logical.chatgpt_client],
                webhook_secret_file=instance.config_dir/'webhook.key',encryption_key_file=instance.config_dir/'encryption.key',
                public_key_file=None if configured else instance.config_dir/'issuer-public.pem',waha_key_file=instance.config_dir/'waha.key',
                listen_port=logical.bridge_port,waha_url=f'http://127.0.0.1:{logical.gateway_port}',
                **({'issuer':logical.issuer,'jwks_url':logical.effective_jwks_url,
                    'link_client_id':logical.link_client} if configured else {}))
            instance.subject=cfg.owner_subject; instance.public_url=cfg.public_url
            instance.service_user=pwd.getpwuid(os.getuid()).pw_name
            settings[slug]=cfg;save_settings(cfg,instance.config_dir/'config.toml')
            tokens[slug]=environment[3](sub=cfg.owner_subject,aud=cfg.public_url,azp=logical.chatgpt_client)
            foreign_owner_tokens[slug]=environment[3](sub=owners[1-index],aud=cfg.public_url,azp=logical.chatgpt_client)
            service=Service(cfg,event_transport=Receiver())
            held=stack.enter_context(closing(sqlite3.connect(cfg.database)))
            held.execute('PRAGMA journal_mode=WAL')
            held.execute('PRAGMA wal_autocheckpoint=0')
            service.store.bind_chat_alias('10001@lid','20002@c.us')
            service.store.ingest(message(slug+'-message',chat='10001@lid',text=slug+' synthetic archive',timestamp=100),historical=True)
            service.store.ingest({'event':'message.revoked','payload':{'revokedMessageId':slug+'-revoked'}})
            service.store.ingest(message(slug+'-revoked',text='must stay revoked'),historical=True)
            service.events.subscribe(cfg.owner_subject,'message.received',{'chat_ids':['20002@c.us']},
                {'url':'https://receiver.example/callback','secret':'whsec_'+base64.b64encode(bytes([index+1])*32).decode()})
            service.store.reserve_send(slug+'-inflight',cfg.owner_subject,{'synthetic':True})
            service.store.reserve_send(slug+'-accepted',cfg.owner_subject,{'synthetic':True})
            service.store.finish_send(slug+'-accepted','submitted',provider_id=slug+'-provider')
            job=service.history.start(cfg.owner_subject,slug+'-history',['20002@c.us'],until=100)
            service.history.control(job['id'],cfg.owner_subject,'cancel');jobs[slug]=job['id']
            request={'id':format(index+1,'032x'),'operation':'history.cancel','target':job['id'],
                     'arguments':{},'confirmation':'history.cancel:'+job['id']}
            admin_requests[slug]=request
            assert RuntimeAdminOperations(service).execute(request)['state']=='completed'
            source={'kind':'external','file_id':slug+'-file','download_url':'https://files.fixture.example/synthetic'}
            ready=service.media.enqueue(cfg.owner_subject,source,'synthetic.txt')
            data=(slug+' synthetic file').encode();write(service.media.path(ready['id']),data)
            with service.store.db() as state:
                state.execute("UPDATE media_jobs SET state='ready',size=?,sha256=? WHERE id=?",(len(data),digest(data),ready['id']))
            transfers[slug]=(ready['id'],source,data)
            write(instance.gateway_home/'sessions/default/session.json',json.dumps({'synthetic_only':True,'owner':cfg.owner_subject}))
            write(instance.gateway_home/'media/fixture.bin',data)
            write(instance.private_dir/'identity.json',json.dumps({'username':logical.username,'subject':logical.subject,'synthetic_only':True}))
            write(instance.wrapper,'#!/bin/sh\nexit 99\n',0o700)
            if slug=='personal': write(project/'private/identity.json',(instance.private_dir/'identity.json').read_bytes())
            rendered=tenancy.deployment_artifacts(logical,template_root=project/'deploy')
            write(host_path('/etc/systemd/system')/(instance.base+'.service'),rendered['bridge'],0o644)
            write(host_path('/etc/systemd/system')/(instance.base+'.service.d/70-release-runtime.conf'),
                '[Service]\nExecStart=\nExecStart=/synthetic/release-runtime\n',0o644)
            write(instance.gateway_home/'.config/systemd/user/whatsapp-waha.service.d/60-whatsapp-priority.conf',
                '[Service]\nCPUWeight=50\n',0o644)
            write(instance.gateway_home/'.config/containers/systemd/whatsapp-waha.container',rendered['gateway'])
            for protocol in ('http','https'):
                write(host_path('/etc/apache2/sites-available')/(instance.base+'-'+protocol+'.conf'),rendered['apache'],0o644)
            write(instance.state_dir/'diagnostics/rehearsal.jsonl','{"synthetic_only":true}\n')
            held.execute('INSERT INTO state VALUES(?,?)',('restore-wal-evidence',json.dumps(slug)))
            held.commit()
            # Same existing UUID, conventional config-directory marker. The
            # legacy configuration stays loadable before the backend upgrade.
            register_external_identity(replace(cfg,state_identity_file=instance.config_dir/'technical-state.json'))
            db.execute('INSERT INTO user_opaque_identifier VALUES(?,?,?,?)',('openid','',logical.username,logical.subject))
        db.commit()
        write(project/'private/tenants.json',json.dumps({'synthetic_only':True,'owners':owners}))
        write(host_path('/var/lib/sally-browser/stack/config/authelia.yml'),json.dumps({'synthetic_only':True,'issuer':'https://issuer.example'}))
        write(host_path('/var/lib/sally-browser/stack/config/users.yml'),json.dumps({'users':list(instances)+['unrelated']}))
        expected_db={slug:database_digest(cfg.database) for slug,cfg in settings.items()}
        expected_auth=database_digest(auth)
        assert all(Path(str(path)+'-wal').stat().st_size>0 for path in [auth,*[cfg.database for cfg in settings.values()]])
        expected_files={path.relative_to(host):(digest(path.read_bytes()),path.stat().st_mode&0o777)
                        for path in host.rglob('*') if path.is_file() and path not in [auth,*[cfg.database for cfg in settings.values()]]
                        and not path.name.endswith(('-wal','-shm'))
                        and not (configured and path.is_relative_to(host_path('/var/lib/sally-browser')))}
        snapshots={}
        for slug,instance in instances.items():
            result=backup.backup(instance)
            assert result['complete'] and result['credentials_included']
            target=tmp_path/'off-host'/slug
            shutil.copytree(result['backup'],target);snapshots[slug]=target
        assert sum('stop' in args for args in commands)==4 and sum('start' in args for args in commands)==4
    # The restoration cannot silently fall back to any original data or keys.
    host.rename(tmp_path/'retired-source-host')
    yield SimpleNamespace(host=host,instances=instances,settings=settings,snapshots=snapshots,
        expected_files=expected_files,expected_db=expected_db,expected_auth=expected_auth,configured=configured,
        jobs=jobs,transfers=transfers,tokens=tokens,foreign_owner_tokens=foreign_owner_tokens,admin_requests=admin_requests,
        destination=tmp_path/'restored-host')


@pytest.mark.parametrize('rehearsal',['legacy','configured-v5'],indirect=True)
def test_complete_synthetic_backup_roundtrip_preserves_isolation_and_idempotency(rehearsal):
    case=rehearsal
    restored=restore_fixture(case.snapshots,case.destination,case.host,case.instances)
    assert not case.host.exists()
    for relative,(checksum,mode) in case.expected_files.items():
        path=restored/relative
        assert path.is_file(),relative
        assert digest(path.read_bytes())==checksum,relative
        assert path.stat().st_mode&0o777==mode,relative
    if not case.configured:
        assert database_digest(restored/str(AUTH_DB).lstrip('/'))==case.expected_auth
    else:
        assert not (restored/str(AUTH_DB).lstrip('/')).exists()
        for snapshot in case.snapshots.values():
            manifest=json.loads((snapshot/'manifest.json').read_bytes())
            assert manifest['format']=='whatsapp-isolated-backup-v5'
            assert 'roster_sha256' not in manifest['installation']
            assert manifest['auth_mode']=='external-oidc'
    for slug,instance in case.instances.items():
        relative=instance.config_dir.relative_to(case.host)
        cfg=Settings.load(restored/relative/'config.toml')
        paths={name:restored/getattr(cfg,name).relative_to(case.host)
               for name in ('database','webhook_secret_file','encryption_key_file','public_key_file','waha_key_file')
               if getattr(cfg,name) is not None}
        cfg=replace(cfg,**paths)
        assert database_digest(cfg.database)==case.expected_db[slug]
        receiver=Receiver();service=Service(cfg,event_transport=receiver)
        assert not service.worker_running and not cfg.live_account_enabled and not cfg.send_enabled
        assert service.store.canonical_chat('10001@lid')=='20002@c.us'
        assert len(service.store.search(slug)['messages'])==1
        assert service.store.message(slug+'-revoked') is None
        assert not service.store.search('revoked')['messages']
        assert service.store.ingest(message(slug+'-message',chat='10001@lid',text=slug+' synthetic archive',timestamp=100),historical=True)['duplicate']
        assert service.store.send_status(slug+'-inflight')['state']=='uncertain'
        fresh,receipt=service.store.reserve_send(slug+'-inflight',cfg.owner_subject,{'synthetic':True})
        assert not fresh and receipt['state']=='uncertain'
        assert service.store.send_status(slug+'-accepted')['state']=='submitted'
        assert service.history.status(case.jobs[slug],cfg.owner_subject)['state']=='cancelled'
        with pytest.raises(ValueError): service.history.control(case.jobs[slug],cfg.owner_subject,'resume')
        administration=RuntimeAdminOperations(service)
        previous=administration.records()
        assert len(previous)==1 and previous[0]['state']=='completed'
        assert administration.execute(case.admin_requests[slug])['id']==previous[0]['id']
        assert administration.records()==previous
        identifier,source,data=case.transfers[slug]
        assert service.media.path(identifier).read_bytes()==data
        with service.store.db() as db:
            encrypted=db.execute('SELECT source FROM media_jobs WHERE id=?',(identifier,)).fetchone()[0]
            assert json.loads(service.media.cipher.decrypt(encrypted))==source
            subscription=db.execute('SELECT owner,secret FROM subscriptions').fetchone()
            assert subscription['owner']==cfg.owner_subject
            assert service.events.cipher.decrypt(subscription['secret']).startswith(b'whsec_')
        other=next(name for name in case.instances if name!=slug)
        assert service.store.message(other+'-message') is None
        with pytest.raises(ValueError): service.media.status(identifier,case.settings[other].owner_subject)
        with pytest.raises(InvalidToken):
            Fernet((restored/case.settings[other].encryption_key_file.relative_to(case.host)).read_bytes()).decrypt(encrypted)
        # The external issuer is represented by its captured synthetic public
        # key; this checks owner/audience isolation without any JWKS network call.
        verification=replace(cfg,jwks_url=None,public_key_file=restored/relative/'issuer-public.pem')
        verifier=JWTVerifier(verification)
        assert verifier._verify(case.tokens[slug]) is not None
        assert verifier._verify(case.tokens[other]) is None
        assert verifier._verify(case.foreign_owner_tokens[slug]) is None
        assert not receiver.requests


@pytest.mark.parametrize('damage',['missing','corrupt','incomplete','identity'])
def test_invalid_snapshot_stops_before_restoration(rehearsal,damage):
    case=rehearsal;snapshot=case.snapshots['personal']
    manifest_path=snapshot/'manifest.json';manifest=json.loads(manifest_path.read_text())
    if damage=='missing': (snapshot/'private-runtime.tar.gz').unlink()
    elif damage=='corrupt':
        with (snapshot/'archive.sqlite').open('ab') as stream: stream.write(b'corruption')
    elif damage=='incomplete': manifest['files'].pop('source.tar.gz')
    else: manifest['user']='different-owner'
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError): restore_fixture(case.snapshots,case.destination,case.host,case.instances)
    assert not case.destination.exists()


def test_restore_never_overwrites_an_existing_destination(rehearsal):
    case=rehearsal;case.destination.mkdir()
    sentinel=case.destination/'keep.txt';sentinel.write_text('preserve concurrent work')
    with pytest.raises(ValueError,match='must not exist'):
        restore_fixture(case.snapshots,case.destination,case.host,case.instances)
    assert sentinel.read_text()=='preserve concurrent work'


def test_conflicting_shared_identity_snapshots_stop_before_restoration(rehearsal):
    case=rehearsal;snapshot=case.snapshots['fixture']
    database=snapshot/'shared-authelia.sqlite3'
    with closing(sqlite3.connect(database)) as db:
        db.execute('DELETE FROM user_opaque_identifier WHERE username=?',('unrelated',))
        db.commit()
    # A valid, internally consistent backup from another instant must not
    # silently replace the shared identities selected for the first instance.
    manifest_path=snapshot/'manifest.json';manifest=json.loads(manifest_path.read_text())
    manifest['files'][database.name]={'sha256':digest(database.read_bytes()),'bytes':database.stat().st_size}
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='disagree on shared data'):
        restore_fixture(case.snapshots,case.destination,case.host,case.instances)
    assert not case.destination.exists()
