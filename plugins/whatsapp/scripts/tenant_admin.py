"""Root-only, repeatable administration of isolated WhatsApp users.

Actions default to a printed plan; writes need --apply. No WhatsApp logout/delete
or outbound messages are implemented here. Credentials stay in private storage.
"""
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
import argparse
from contextlib import closing,contextmanager,ExitStack
from datetime import datetime,UTC
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import time
import tomllib
import uuid

import httpx
from cryptography.fernet import Fernet
from host_integration import require_runtime_version
require_runtime_version()
from sally_whatsapp.config import Settings
from sally_whatsapp.state_initialization import initialize_new
from sally_whatsapp.tenancy import Instance,ROOT,ISSUER,CHATGPT_CALLBACK,oidc_endpoints,idp_candidate,render_config,render_apache,deployment_artifacts
from sally_whatsapp.account_events import PROVIDER_EVENT_TYPES
from tenant_database import verify_tenant_database, suspend_tenant_database

REGISTRY=ROOT/'private/tenants.json'
AUTH_CONFIG=Path('/var/lib/sally-browser/stack/config')
AUTH_DATABASE=Path('/var/lib/sally-browser/stack/authelia/db.sqlite3')
AUTH_WRAPPER='/srv/openai-codex/projects/sally-browser/bin/as-user'


def add_setup_arguments(parser):
    parser.add_argument('--hostname',help='Public ASCII DNS hostname; HTTPS origin is derived')
    parser.add_argument('--issuer',help='Exact externally registered HTTPS OIDC issuer')
    parser.add_argument('--jwks-url',help='Exact issuer discovery jwks_uri')
    parser.add_argument('--subject',help='Exact stable owner sub returned by the configured issuer')
    parser.add_argument('--oauth-client-id',help='Registered public MCP OAuth client')
    parser.add_argument('--link-client-id',help='Separate registered public pairing OAuth client')
    parser.add_argument('--chatgpt-callback',help='Exact callback supplied by the MCP client')
    parser.add_argument('--auth-mode',choices=['external-oidc','managed-authelia'],default=None,
                        help='Fresh setup uses an already configured external OIDC provider')


def setup_instance(args,slug,name,port):
    profile=installation_profile()
    if not profile.compatibility:
        configured_port=profile.instance_ports(slug)['bridge']
        if port!=configured_port:
            raise ValueError('Port differs from the installation profile')
    mode=args.auth_mode or 'external-oidc'
    if mode=='external-oidc':
        required=('hostname','issuer','jwks_url','subject','oauth_client_id','link_client_id')
        if any(not getattr(args,key,None) for key in required):
            raise ValueError('Fresh external OIDC setup requires --hostname, --issuer, --jwks-url, '
                             '--subject, --oauth-client-id and --link-client-id')
    return Instance(slug,name,args.subject or str(uuid.uuid4()),port,
                    public_hostname=args.hostname,issuer=args.issuer or ISSUER,jwks_url=args.jwks_url,
                    chatgpt_callback=args.chatgpt_callback or CHATGPT_CALLBACK,auth_mode=mode,
                    oauth_client_id=args.oauth_client_id,pairing_client_id=args.link_client_id,
                    installation=None if profile.compatibility else profile.as_dict())


def verify_setup_arguments(instance,args):
    selected=installation_profile()
    if not selected.compatibility and selected.sha256!=instance._installation_identity.sha256:
        raise ValueError('Registered instance belongs to another installation profile; use a reviewed migration')
    if args.auth_mode is not None and args.auth_mode!=instance.auth_mode:
        raise ValueError('Authentication mode differs from the registered instance')
    for arg,field in (('hostname','hostname'),('issuer','issuer'),('jwks_url','effective_jwks_url'),
                      ('subject','subject'),('oauth_client_id','chatgpt_client'),
                      ('link_client_id','link_client'),('chatgpt_callback','chatgpt_callback')):
        value=getattr(args,arg,None)
        if value is not None and value!=getattr(instance,field):
            raise ValueError('Setup input differs from the registered instance: '+arg)


def validate_instance_resources(instance, data):
    """Pure registry admission, repeated while holding the tenant mutation lease.

    An owner may intentionally operate more than one isolated account. Domains,
    local resources and OAuth clients within the same issuer cannot be shared.
    This inventory does not prove DNS, IdP registration or live port availability.
    """
    if (not isinstance(data, dict) or type(data.get('format')) is not int or data['format'] != 1
            or not isinstance(data.get('instances'), dict)):
        raise ValueError('A valid tenant registry is required')
    resources = {instance.config_dir, instance.state_dir, instance.gateway_home, instance.private_dir}
    clients = {instance.chatgpt_client, instance.link_client}
    ports = {instance.bridge_port, instance.gateway_port}
    for slug, row in data['instances'].items():
        if not isinstance(row, dict) or not isinstance(row.get('spec'), dict):
            raise ValueError('A valid tenant registry record is required')
        other = Instance(**row['spec'])
        if slug != other.slug:
            raise ValueError('Tenant registry key differs from its instance identity')
        if slug == instance.slug:
            if other.record() != instance.record():
                raise ValueError('Instance identity differs from its registered setup')
            continue
        if instance.hostname == other.hostname:
            raise ValueError('Hostname is already assigned to another instance')
        if ports.intersection((other.bridge_port, other.gateway_port)):
            raise ValueError('Loopback port is already assigned to another instance')
        if instance.service_user == other.service_user or resources.intersection(
                (other.config_dir, other.state_dir, other.gateway_home, other.private_dir)):
            raise ValueError('Runtime resource is already assigned to another instance')
        if instance.issuer == other.issuer and clients.intersection((other.chatgpt_client, other.link_client)):
            raise ValueError('OAuth client is already assigned to another instance at this issuer')


def discovery_for(instance):
    response=httpx.get(instance.issuer.rstrip('/')+'/.well-known/openid-configuration',
                       timeout=10,follow_redirects=False,trust_env=False)
    response.raise_for_status()
    return oidc_endpoints(instance,response.json())


def verify_existing_config(instance,path):
    settings=Settings.load(path)
    if (settings.public_url,settings.issuer,settings.owner_subject,settings.jwks_url,
            settings.oauth_client_ids)!=(instance.public_url,instance.issuer,instance.subject,
                                        instance.effective_jwks_url,[instance.chatgpt_client]):
        raise ValueError('Existing runtime identity/endpoints differ from the registered setup')
    verify_tenant_database(instance)
    return settings


def load_host_context(instance,path,digest):
    from host_integration import load
    context=load(instance,path,digest)
    try: return context.preflight()
    except BaseException:
        context.close()
        raise


def admit_runtime():
    from host_integration import runtime_admission
    return runtime_admission(ROOT)


def phase(name,**data):
    print(json.dumps({'phase':name,**data},ensure_ascii=False),flush=True)


def command(args,**kwargs):
    from host_integration import command_options
    return subprocess.run([str(v) for v in args],**command_options(kwargs))


def run(args,**kwargs):
    result=command(args,capture_output=True,**kwargs)
    if result.returncode:
        # Provider logs can contain credentials; do not print stdout/stderr on failure.
        output=result.stdout+result.stderr
        write_private(ROOT/'private/tenant-command-failure.log',output)
        raise RuntimeError('Command failed: '+Path(str(args[0])).name+'; inspect private diagnostic receipt')
    return result


def write_private(path,data,*,mode=0o600,uid=0,gid=0):
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.candidate-'+secrets.token_hex(4))
    temporary.write_bytes(data.encode() if isinstance(data,str) else data)
    os.chmod(temporary,mode)
    os.chown(temporary,uid,gid)
    os.replace(temporary,path)


def registry():
    if REGISTRY.exists(): return json.loads(REGISTRY.read_text())
    if not installation_profile().compatibility: return {'format':1,'instances':{}}
    path=Path(installation_path('/etc/whatsapp-personal/config.toml'))
    if not path.exists() and not path.is_symlink(): return {'format':1,'instances':{}}
    cfg=tomllib.loads(path.read_text())['bridge']
    original=Instance('personal','GAL1LEO',cfg['owner_subject'],8820)
    if cfg['public_url']!=original.public_url or cfg['waha_url']!='http://127.0.0.1:8821':
        raise ValueError('Existing instance does not match the known deployment')
    return {'format':1,'instances':{'personal':{'spec':original.record(),'phase':'existing','enabled':True}}}


def save_registry(data):
    write_private(REGISTRY,json.dumps(data,indent=2))


def stamp(): return datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')


def auth_backup(label):
    target=Path(installation_path('/var/backups/whatsapp-personal'))/(label+'-'+stamp())
    target.mkdir(parents=True,mode=0o700)
    for name in ('authelia.yml','users.yml'): shutil.copy2(AUTH_CONFIG/name,target/name)
    with sqlite3.connect('file:'+str(AUTH_DATABASE)+'?mode=ro',uri=True) as source,sqlite3.connect(target/'authelia.sqlite3') as dest:
        source.backup(dest)
        if dest.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise RuntimeError('Auth snapshot failed')
    return target


def install_auth(instance,identity=None,*,required_mcp_scopes=()):
    if instance.auth_mode=='external-oidc': return
    import pwd
    old_config=(AUTH_CONFIG/'authelia.yml').read_bytes()
    old_users=(AUTH_CONFIG/'users.yml').read_bytes()
    cfg,users=idp_candidate(json.loads(old_config),json.loads(old_users),instance,identity,
                           required_mcp_scopes=required_mcp_scopes)
    candidate=json.dumps(cfg,indent=2).encode()
    user_data=json.dumps(users,indent=2).encode()
    if json.loads(old_config)==cfg and json.loads(old_users)==users:
        return
    backup=auth_backup('before-user-'+instance.slug)
    write_private(instance.private_dir/'auth-backup.txt',str(backup))
    account=pwd.getpwnam('sallybrowser')
    staging=Path(account.pw_dir)/('whatsapp-auth-candidate-'+secrets.token_hex(8)+'.json')
    write_private(staging,candidate,uid=account.pw_uid,gid=account.pw_gid)
    try:
        run([AUTH_WRAPPER,'podman','cp',staging,'sally-auth:/tmp/whatsapp-auth-candidate.json'])
        check=command([AUTH_WRAPPER,'podman','exec','sally-auth','authelia','validate-config','--config','/tmp/whatsapp-auth-candidate.json'],capture_output=True)
        write_private(instance.private_dir/'auth-validation.log',check.stdout+check.stderr)
        if check.returncode: raise RuntimeError('Authelia candidate rejected; current configuration preserved')
    finally:
        staging.unlink(missing_ok=True)
    stats={name:(AUTH_CONFIG/name).stat() for name in ('authelia.yml','users.yml')}
    for name,data in (('authelia.yml',candidate),('users.yml',user_data)):
        s=stats[name]
        write_private(AUTH_CONFIG/name,data,mode=s.st_mode&0o777,uid=s.st_uid,gid=s.st_gid)
    try:
        run([AUTH_WRAPPER,'systemctl','--user','restart','sally-auth.service'])
        with httpx.Client(timeout=3,follow_redirects=False,trust_env=False) as client:
            for _ in range(20):
                try:
                    response=client.get(instance.issuer.rstrip('/')+'/.well-known/openid-configuration')
                    if response.is_success and response.json().get('issuer')==instance.issuer: break
                except (httpx.HTTPError,ValueError): pass
                time.sleep(1)
            else: raise RuntimeError('Authentication discovery did not recover')
    except Exception:
        for name,data in (('authelia.yml',old_config),('users.yml',old_users)):
            s=stats[name]
            write_private(AUTH_CONFIG/name,data,mode=s.st_mode&0o777,uid=s.st_uid,gid=s.st_gid)
        run([AUTH_WRAPPER,'systemctl','--user','restart','sally-auth.service'])
        raise
    phase('authentication_configured',user=instance.slug,backup=str(backup))


def identity_for(instance,*,existing_only=False):
    if instance.auth_mode=='external-oidc': return None
    path=instance.private_dir/'identity.json'
    if existing_only and instance.slug=='personal' and not (path.exists() or path.is_symlink()):
        # The initial personal bootstrap persisted this identity before the
        # per-tenant registry existed. Read it only at its known private path.
        path=instance.project_root/'private/identity.json'
    if path.is_symlink():
        raise ValueError('Managed identity must be a regular registered file')
    if path.exists():
        try: identity=json.loads(path.read_text())
        except (OSError,ValueError):
            raise ValueError('Registered managed identity cannot be read') from None
        if (not isinstance(identity,dict) or identity.get('username')!=instance.username
                or identity.get('subject')!=instance.subject
                or not isinstance(identity.get('password_hash'),str) or not identity['password_hash']):
            raise ValueError('Managed identity mismatch')
        return identity
    if existing_only:
        raise ValueError('Registered managed identity is missing; activation never creates credentials or adopts users')
    existing=json.loads((AUTH_CONFIG/'users.yml').read_text())['users']
    if instance.username in existing: raise ValueError('Identity exists outside the managed registry; refusing adoption')
    answer=run([AUTH_WRAPPER,'podman','exec','sally-auth','authelia','crypto','hash','generate','argon2','--random','--random.length','40'],text=True)
    password=re.search(r'^Random Password: (.+)$',answer.stdout,re.M)
    password_hash=re.search(r'^Digest: (.+)$',answer.stdout,re.M)
    if not password or not password_hash: raise RuntimeError('Credential generator output unrecognized')
    identity={'username':instance.username,'subject':instance.subject,'display_name':instance.display_name,
              'password':password.group(1),'password_hash':password_hash.group(1)}
    write_private(path,json.dumps(identity,indent=2))
    return identity


def subject_registered(instance):
    # Read-only lookup of the pinned Authelia 4.39 schema. Never write its internal DB.
    # Fail closed on an unavailable/changed schema, including a missing initial DB.
    try:
        with closing(sqlite3.connect(AUTH_DATABASE.as_uri()+'?mode=ro',uri=True)) as db:
            rows=db.execute("SELECT service,sector_id,username,identifier FROM user_opaque_identifier "
                            "WHERE (service='openid' AND sector_id='' AND username=?) OR identifier=?",
                            (instance.username,instance.subject)).fetchall()
    except sqlite3.Error:
        raise RuntimeError('Cannot verify the Authelia subject mapping; inspect the configured storage/schema') from None
    if not rows: return False
    if rows!=[('openid','',instance.username,instance.subject)]:
        raise ValueError('Existing OAuth subject mapping differs; no identity will be replaced')
    return True


def register_subject(instance):
    if getattr(instance,'auth_mode','managed-authelia')=='external-oidc':
        # The configured subject is an administrative input, not proof of a live IdP registration.
        return
    # A local receipt is evidence of a past run, not proof of the current IdP mapping.
    if not subject_registered(instance):
        result=command([AUTH_WRAPPER,'podman','exec','sally-auth','authelia','storage','user','identifiers','add',instance.username,
                               '--identifier',instance.subject,'--service','openid','--sector','',
                               '--config','/config/configuration.yml'],capture_output=True)
        write_private(instance.private_dir/'subject-registration.log',result.stdout+result.stderr)
        # Recheck even on error: another administrator may have inserted the same mapping.
        if not subject_registered(instance):
            raise RuntimeError('Subject registration not verified; no identifier overwritten')
    write_private(instance.private_dir/'subject-registered.json',json.dumps({'registered':True,'subject':instance.subject}))


def directory(path,uid,gid,mode=0o700):
    path.mkdir(parents=True,exist_ok=True)
    os.chown(path,uid,gid)
    os.chmod(path,mode)


def project_access_paths(instance):
    """Only the selected physical code tree and its traversal parents."""
    return tuple(reversed([path for path in instance.project_root.parents if path!=Path('/')]))


def grant_project_access(instance):
    if instance._installation_identity.compatibility:
        run(['setfacl','-m',f'u:{instance.service_user}:--x','/srv/openai-codex','/srv/openai-codex/projects'])
        run(['setfacl','-m',f'u:{instance.service_user}:r-x',ROOT])
        return
    for path in (*project_access_paths(instance),instance.project_root):
        if path!=path.resolve(strict=True) or not path.is_dir():
            raise ValueError('Project access requires a physical code tree')
    parents=project_access_paths(instance)
    if parents:
        run(['setfacl','-m',f'u:{instance.service_user}:--x',*parents])
    run(['setfacl','-m',f'u:{instance.service_user}:r-x',instance.project_root])


def grant_runtime_access(instance):
    """Traversal only through configured roots; private leaves remain isolated."""
    profile=instance._installation_identity
    if profile.compatibility:return
    selected=set()
    for field in ('configuration','state','gateway'):
        root=Path(profile.path(field))
        selected.update(path for path in (root,*root.parents) if path!=Path('/'))
    for path in sorted(selected,key=lambda item:len(item.parts)):
        if path!=path.resolve(strict=True) or not path.is_dir():
            raise ValueError('Runtime roots must be physical directories')
        info=path.stat()
        if info.st_uid!=0 or info.st_mode&0o022:
            raise ValueError('Runtime root ancestors must be administratively protected')
    if selected:run(['setfacl','-m',f'u:{instance.service_user}:--x',*sorted(selected)])


def prepare_runtime(instance,*,host=None):
    artifacts=deployment_artifacts(instance)
    if host is None: raise ValueError('A preflighted neutral host plan is required for runtime preparation')
    cfgpath=instance.config_dir/'config.toml'
    new_config=not (cfgpath.exists() or cfgpath.is_symlink())
    if not new_config:
        # An existing configuration is never a first-install authorization,
        # including after a crash between config creation and initialization.
        verify_existing_config(instance,cfgpath)
    endpoints=discovery_for(instance)
    import pwd
    try: account=pwd.getpwnam(instance.service_user)
    except KeyError:
        options=[] if instance._installation_identity.compatibility else ['--user-group']
        run(['useradd','--system',*options,'--create-home','--home-dir',instance.gateway_home,'--shell','/usr/sbin/nologin',instance.service_user])
        account=pwd.getpwnam(instance.service_user)
    if account.pw_dir!=str(instance.gateway_home) or account.pw_shell!='/usr/sbin/nologin':
        raise ValueError('Service user belongs to an unexpected runtime')
    uid,gid=account.pw_uid,account.pw_gid
    if not instance._installation_identity.compatibility:
        import grp
        if uid<=0 or gid<=0 or grp.getgrgid(gid).gr_name!=instance.service_user:
            raise ValueError('A dedicated non-root service UID and primary group are required')
    for filename,flag in (('/etc/subuid','--add-subuids'),('/etc/subgid','--add-subgids')):
        entries=[line.split(':') for line in Path(filename).read_text().splitlines() if line]
        if not any(row[0]==instance.service_user for row in entries):
            start=max([100000]+[int(row[1])+int(row[2]) for row in entries])
            run(['usermod',flag,f'{start}-{start+65535}',instance.service_user])
    grant_project_access(instance)
    directory(instance.config_dir,0,gid,0o750)
    for path in (instance.state_dir,instance.gateway_home,instance.gateway_home/'sessions',instance.gateway_home/'media',
                 instance.gateway_home/'.config',instance.gateway_home/'.config/containers',instance.gateway_home/'.config/containers/systemd'):
        directory(path,uid,gid)
    grant_runtime_access(instance)
    for name in ('webhook.key','encryption.key','waha.key'):
        path=instance.config_dir/name
        if not path.exists():
            write_private(path,Fernet.generate_key() if name=='encryption.key' else secrets.token_hex(32),mode=0o640,gid=gid)
    config=render_config(instance,**endpoints,live_enabled=instance._installation_identity.compatibility)
    if new_config:
        # Exclusive creation also rejects a configuration that appeared after
        # preflight; do not enroll or overwrite concurrent administrative work.
        with cfgpath.open('x') as stream: stream.write(config)
        os.chown(cfgpath,0,gid)
        os.chmod(cfgpath,0o640)
        initialize_new(Settings.load(cfgpath),uid,gid)
    write_private(instance.wrapper,f'#!/bin/sh\nset -eu\ncd {instance.gateway_home}\nexec runuser -u {instance.service_user} -- env HOME={instance.gateway_home} XDG_RUNTIME_DIR=/run/user/{uid} DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus "$@"\n',mode=0o700)
    write_private(Path('/etc/systemd/system')/(instance.base+'.service'),artifacts['bridge'],mode=0o644)
    write_private(instance.gateway_home/'.config/containers/systemd/whatsapp-waha.container',artifacts['gateway'],uid=uid,gid=gid)
    # The independently installed host provider registers this exact UID and
    # unit before the user manager starts; no application-owned policy fallback.
    host.enroll_runtime(account)
    run(['loginctl','enable-linger',instance.service_user])
    run(['systemctl','start',f'user@{uid}.service'])
    for name,source in (('whatsapp-waha-api-key',instance.config_dir/'waha.key'),('whatsapp-waha-disabled-ui-key',None)):
        exists=command([str(instance.wrapper),'podman','secret','inspect',name],capture_output=True).returncode==0
        if not exists:
            data=source.read_bytes() if source else secrets.token_hex(32).encode()
            run([instance.wrapper,'podman','secret','create',name,'-'],input=data)
    run(['systemctl','daemon-reload'])
    run([instance.wrapper,'systemctl','--user','daemon-reload'])
    phase('isolated_runtime_prepared',user=instance.slug,service_user=instance.service_user)


def install_https(instance,*,host=None):
    apache=render_apache(instance)
    if host is None: raise ValueError('A preflighted neutral host plan is required for HTTPS')
    receipt=host.ensure_https(apache)
    phase('https_ready',hostname=instance.hostname,qos_frontend=receipt['qos_frontend'],frontend_traffic_verified=False)


def wait_bridge_ready(instance):
    """Observe the restarted process, including the configured portal worker.

    This never follows an OAuth redirect, authenticates, or requests pairing.
    """
    with httpx.Client(base_url=f'http://127.0.0.1:{instance.bridge_port}',timeout=4,
                      follow_redirects=False,trust_env=False) as client:
        for _ in range(40):
            try:
                response=client.get('/healthz')
                ready=response.json().get('readiness',{}) if response.is_success else {}
                if ready.get('ready') is True and ready.get('workers',{}).get('portal') is True:
                    portal=client.get('/connect')
                    if portal.status_code==200: return
            except (httpx.HTTPError,ValueError): pass
            time.sleep(1)
    raise RuntimeError('Bridge readiness and pairing portal were not verified; activation remains incomplete')


def start_runtime(instance,*,refresh_bridge=False):
    from provisioning_attempt import guard_activation
    guard_activation(instance)
    run([instance.wrapper,'systemctl','--user','start','whatsapp-waha.service'])
    key=(instance.config_dir/'waha.key').read_text().strip()
    with httpx.Client(base_url=f'http://127.0.0.1:{instance.gateway_port}',headers={'X-Api-Key':key},timeout=4,trust_env=False) as client:
        for _ in range(40):
            try:
                if client.get('/api/version').is_success: break
            except httpx.HTTPError: pass
            time.sleep(1)
        else: raise RuntimeError('New gateway did not become ready')
        response=client.get('/api/sessions',params={'all':'true'})
        response.raise_for_status()
        sessions=response.json()
        if not any(s.get('name')=='default' for s in sessions):
            response=client.post('/api/sessions',json={'name':'default','start':False,'config':{
                'debug':False,'gows':{'storage':{'messages':True,'groups':True,'chats':True,'contacts':True}},
                'webhooks':[{'url':f'http://10.0.2.2:{instance.bridge_port}/webhooks/waha','events':['message.any',*PROVIDER_EVENT_TYPES],
                             'hmac':{'key':(instance.config_dir/'webhook.key').read_text().strip()},
                             'retries':{'delaySeconds':2,'attempts':15,'policy':'linear'}}]}})
            if not response.is_success: raise RuntimeError('New session configuration was rejected')
    if refresh_bridge:
        # restart starts a stopped unit and reloads an active unit. Never use a
        # previous disk flag as evidence of the running process configuration.
        run(['systemctl','enable',instance.base+'.service'])
        run(['systemctl','restart',instance.base+'.service'])
        wait_bridge_ready(instance)
    else:
        run(['systemctl','enable','--now',instance.base+'.service'])
    phase('new_user_ready_for_human_linking',**instance.public_details())


def capability_selection(settings,*,capabilities='full',enable_send=False,allow_all_destinations=False,enable_account_actions=False):
    """Pure activation selection; full is the explicitly requested product default."""
    from sally_whatsapp.config import MCP_SCOPES
    if capabilities not in ('custom','full','read-only'):
        raise ValueError('Unknown capability profile')
    if capabilities=='read-only' and any((enable_send,allow_all_destinations,enable_account_actions)):
        raise ValueError('Read-only profile conflicts with write capability options')
    if capabilities=='full': enable_send=enable_account_actions=allow_all_destinations=True
    if allow_all_destinations and not enable_send:
        raise ValueError('--allow-all-destinations requires --enable-send or --capabilities full')
    if enable_send and not (allow_all_destinations or settings.allow_all_destinations or settings.send_chat_ids):
        raise ValueError('Sending requires an existing chat allowlist or explicit --allow-all-destinations')
    updates={}
    if capabilities=='full':
        updates.update(oauth_allowed_scopes=list(MCP_SCOPES),oauth_consent_scopes=list(MCP_SCOPES))
    if capabilities=='read-only':
        updates.update(send_enabled=False,allow_all_destinations=False,account_actions_enabled=False,
                       oauth_allowed_scopes=['whatsapp:read','whatsapp:events'],oauth_consent_scopes=[])
    if enable_send: updates['send_enabled']=True
    if allow_all_destinations: updates['allow_all_destinations']=True
    if enable_account_actions: updates['account_actions_enabled']=True
    effective=lambda key:updates.get(key,getattr(settings,key))
    if (effective('send_enabled') or effective('account_actions_enabled')) and 'whatsapp:send' not in effective('oauth_allowed_scopes'):
        raise ValueError('Write capabilities require local whatsapp:send scope; select --capabilities full or reconcile the scope policy')
    summary={'profile':capabilities,
             'send_enabled':effective('send_enabled'),'account_actions_enabled':effective('account_actions_enabled'),
             'destination_policy':'disabled' if not effective('send_enabled') else 'all' if effective('allow_all_destinations') else 'allowlist',
             'required_mcp_scopes':effective('oauth_allowed_scopes'),
             'oauth_consent_verified':False,'whatsapp_connected_verified':False}
    return updates,summary


def enable_existing_link(instance,*,host=None,enable_send=False,allow_all_destinations=False,enable_account_actions=False,capabilities='full'):
    rendered=deployment_artifacts(instance)
    if host is None: raise ValueError('A preflighted neutral host plan is required for linking upgrade')
    path=instance.config_dir/'config.toml'
    settings=verify_existing_config(instance,path)
    selected,summary=capability_selection(settings,capabilities=capabilities,enable_send=enable_send,
        allow_all_destinations=allow_all_destinations,enable_account_actions=enable_account_actions)
    identity=identity_for(instance,existing_only=True)
    endpoints=discovery_for(instance)
    import pwd
    host.enroll_runtime(pwd.getpwnam(instance.service_user))
    install_auth(instance,identity,required_mcp_scopes=summary['required_mcp_scopes'] if capabilities=='full' else ())
    register_subject(instance)
    path=instance.config_dir/'config.toml'
    original=path.read_text()
    updates={'listen_port':instance.bridge_port,'live_account_enabled':True,'link_enabled':True,'link_client_id':instance.link_client,
             'link_authorize_url':endpoints['authorize_url'],'link_token_url':endpoints['token_url'],
             'oauth_client_ids':[instance.chatgpt_client]}
    updates.update(selected)
    for key,value in updates.items():
        line=key+' = '+json.dumps(value)
        pattern=r'^'+re.escape(key)+r'\s*=.*$'
        original=re.sub(pattern,line,original,flags=re.M) if re.search(pattern,original,re.M) else original+'\n'+line+'\n'
    stat=path.stat()
    write_private(path,original,mode=stat.st_mode&0o777,uid=stat.st_uid,gid=stat.st_gid)
    host.ensure_https(rendered['apache'])
    # Reconcile the gateway even after a prior attempt published config but
    # stopped before startup. Existing sessions are neither recreated nor logged out.
    start_runtime(instance,refresh_bridge=True)
    phase('pairing_portal_enabled',user=instance.slug,url=instance.public_url+'/connect',capabilities=summary)


def change_enabled(instance,enabled):
    if getattr(instance,'auth_mode','managed-authelia')=='managed-authelia':
        auth_backup(('enable-' if enabled else 'disable-')+instance.slug)
        path=AUTH_CONFIG/'users.yml'
        data=json.loads(path.read_text())
        if instance.username not in data['users']: raise ValueError('Managed identity missing')
        data['users'][instance.username]['disabled']=not enabled
        stat=path.stat()
        write_private(path,json.dumps(data,indent=2),mode=stat.st_mode&0o777,uid=stat.st_uid,gid=stat.st_gid)
    if not enabled:
        run(['systemctl','disable','--now',instance.base+'.service'])
        run([instance.wrapper,'systemctl','--user','mask','--now','whatsapp-waha.service'])
        suspend_tenant_database(instance)
    if getattr(instance,'auth_mode','managed-authelia')=='managed-authelia':
        run([AUTH_WRAPPER,'systemctl','--user','restart','sally-auth.service'])
    if enabled:
        run([instance.wrapper,'systemctl','--user','unmask','whatsapp-waha.service'])
        run([instance.wrapper,'systemctl','--user','start','whatsapp-waha.service'])
        run(['systemctl','enable','--now',instance.base+'.service'])
    phase('user_enabled' if enabled else 'user_suspended',user=instance.slug,data_preserved=True)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['list','plan','add','enable-linking','suspend','resume'])
    parser.add_argument('--user')
    parser.add_argument('--name')
    parser.add_argument('--bridge-port',type=int)
    add_setup_arguments(parser)
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--enable-send',action='store_true',help='Explicitly enable sending when enabling the pairing portal')
    parser.add_argument('--allow-all-destinations',action='store_true',help='Explicitly permit all destinations with --enable-send')
    parser.add_argument('--enable-account-actions',action='store_true',help='Explicitly enable account actions when enabling the portal')
    parser.add_argument('--capabilities',choices=['full','read-only','custom'],help='Activation profile: full by default, including all destinations; reductions are optional')
    parser.add_argument('--host-plan')
    parser.add_argument('--host-plan-sha256')
    parser.add_argument('--attempt-id', help='Exact durable attempt ID for new configured provisioning')
    args=parser.parse_args(argv)
    if os.geteuid()!=0: raise SystemExit('Run as the authorized server administrator')
    require_runtime_version()
    from installation_layout import preflight_roots
    preflight_roots()
    if args.attempt_id and args.action!='add':
        raise ValueError('--attempt-id belongs only to new provisioning')
    if any((args.enable_send,args.allow_all_destinations,args.enable_account_actions,args.capabilities)) and args.action!='enable-linking':
        raise ValueError('Capability options belong only to enable-linking')
    os.umask(0o077)
    with ExitStack() as resources:
        if args.apply and args.action not in ('list','plan'):
            resources.enter_context(admit_runtime())
        data=registry()
        if args.action=='list':
            print(json.dumps([{'phase':row['phase'],'enabled':row['enabled'],**Instance(**row['spec']).public_details()} for row in data['instances'].values()],indent=2))
            return
        if not args.user: raise SystemExit('--user is required')
        found=data['instances'].get(args.user)
        if found:
            instance=Instance(**found['spec'])
            verify_setup_arguments(instance,args)
            if args.name and args.name!=instance.display_name: raise SystemExit('Display name differs from registered identity')
            if args.bridge_port and args.bridge_port!=instance.bridge_port: raise SystemExit('Port differs from registered identity')
        else:
            if args.action not in ('plan','add') or not args.name: raise SystemExit('Use add with --name for a new user')
            used={row['spec']['bridge_port'] for row in data['instances'].values()}
            selected=installation_profile()
            port=args.bridge_port or (next(p for p in range(8822,8999,2) if p not in used)
                                      if selected.compatibility else selected.instance_ports(args.user)['bridge'])
            if port in used: raise SystemExit('Port is already assigned to another user')
            gateway=port+1 if selected.compatibility else selected.instance_ports(args.user)['gateway']
            for p in (port,gateway):
                with socket.socket() as probe:
                    try: probe.bind(('127.0.0.1',p))
                    except OSError: raise SystemExit('A configured loopback port is already in use') from None
            instance=setup_instance(args,args.user,args.name,port)
        from provisioning_attempt import guard_activation, guard_preparation
        if args.action in ('enable-linking','resume'):
            guard_activation(instance)
        if args.action=='add':
            guard_preparation(instance,args.attempt_id)
        if args.action in ('plan','add','enable-linking'):
            validate_instance_resources(instance,data)
        if not args.apply or args.action=='plan':
            details={}
            if args.action=='enable-linking':
                _,details['capabilities']=capability_selection(verify_existing_config(instance,instance.config_dir/'config.toml'),
                    capabilities=args.capabilities or 'full',enable_send=args.enable_send,
                    allow_all_destinations=args.allow_all_destinations,enable_account_actions=args.enable_account_actions)
            phase('plan_only',action=args.action,**instance.public_details(),**details)
            return
        if args.action=='enable-linking' and found and not found['enabled']:
            raise ValueError('Account is suspended; use explicit resume before enabling the pairing portal')
        if args.action in ('add','enable-linking'): deployment_artifacts(instance)
        host=None
        if args.action in ('add','enable-linking'):
            host=load_host_context(instance,args.host_plan,args.host_plan_sha256)
            resources.callback(host.close)
        if args.action=='add' and args.attempt_id:
            from provisioning_attempt import Attempt, prepare
            artifacts=deployment_artifacts(instance)
            config=render_config(instance,**discovery_for(instance),live_enabled=False)
            with Attempt(instance,host,args.attempt_id) as attempt:
                data['instances'].setdefault(instance.slug,{'spec':instance.record(),'phase':'preparing','enabled':True})
                save_registry(data)
                receipt=prepare(instance,artifacts,config,host,attempt,run=run,command=command)
                data['instances'][instance.slug]['phase']='prepared'
                save_registry(data)
                print(json.dumps(receipt))
            return
        instance.private_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
        if args.action=='add':
            if instance.slug=='personal': raise SystemExit('Use enable-linking to preserve the current instance')
            if found and (found['phase']=='ready' or
                          (not instance._installation_identity.compatibility and found['phase']=='prepared')):
                phase('already_provisioned',**instance.public_details());return
            host.begin_runtime()
            data['instances'].setdefault(instance.slug,{'spec':instance.record(),'phase':'preparing','enabled':True})
            save_registry(data)
            identity=identity_for(instance)
            prepare_runtime(instance,host=host)
            install_auth(instance,identity)
            register_subject(instance)
            install_https(instance,host=host)
            if instance._installation_identity.compatibility:
                start_runtime(instance)
                data['instances'][instance.slug]['phase']='ready'
            else:
                data['instances'][instance.slug]['phase']='prepared'
                phase('isolated_runtime_prepared_for_activation',**instance.public_details())
        elif args.action=='enable-linking':
            enable_existing_link(instance,host=host,enable_send=args.enable_send,
                                 allow_all_destinations=args.allow_all_destinations,
                                 enable_account_actions=args.enable_account_actions,capabilities=args.capabilities or 'full')
            data['instances'][instance.slug]['phase']='ready'
        else:
            change_enabled(instance,args.action=='resume')
            data['instances'][instance.slug]['enabled']=args.action=='resume'
        save_registry(data)


if __name__=='__main__':
    try: main()
    except Exception as error:
        # Do not expose provider exceptions, credential generator output or OAuth payloads.
        print(json.dumps({'error':str(error) if isinstance(error,(ValueError,RuntimeError)) else type(error).__name__,
                          'completed':False}),flush=True)
        raise SystemExit(1) from None
