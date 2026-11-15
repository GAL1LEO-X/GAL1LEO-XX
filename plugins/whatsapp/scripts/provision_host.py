"""Install an authorized standalone bridge, initially with WhatsApp disabled.

External OIDC identity is configured explicitly and verified by runtime tokens.
The optional local IdP adapter verifies/registers its managed subject.
Run once as root from the deployed project virtual environment.
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
from pathlib import Path
import argparse
import json
import os
import pwd
import secrets
import subprocess
import sys
from cryptography.fernet import Fernet
from host_integration import runtime_admission,command_options,require_runtime_version
require_runtime_version()
from sally_whatsapp.config import Settings
from sally_whatsapp.state_initialization import initialize_new
from sally_whatsapp.state_continuity import StateContinuity
from sally_whatsapp.tenancy import Instance,deployment_artifacts,render_config
from tenant_admin import (register_subject,load_host_context,add_setup_arguments,setup_instance,
                          verify_setup_arguments,verify_existing_config,discovery_for,write_private,
                          validate_instance_resources)
from tenant_admin import grant_project_access,grant_runtime_access

ROOT = Path(installation_path('/srv/openai-codex/projects/whatsapp-personal'))
GATEWAY_HOME = Path(installation_path('/var/lib/whatsapp-personal-waha'))
CONF = Path(installation_path('/etc/whatsapp-personal'))
USER = 'whatsappbridge'


def run(args, **kwargs):
    return subprocess.run(args, **command_options(kwargs))

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user',help='Configured instance slug; required when the profile has multiple instances')
    parser.add_argument('--name',help='Display name for the owner')
    add_setup_arguments(parser)
    parser.add_argument('--host-plan',required=True)
    parser.add_argument('--host-plan-sha256',required=True)
    parser.add_argument('--attempt-id',help='Exact durable attempt ID for new configured provisioning')
    args=parser.parse_args(argv)
    if os.geteuid()!=0: raise SystemExit('Run as the authorized server administrator')
    require_runtime_version()
    from installation_layout import preflight_roots
    preflight_roots()
    profile=installation_profile()
    if not profile.compatibility and args.auth_mode=='managed-authelia':
        raise ValueError('General installation requires the configured external OIDC provider')
    if profile.compatibility:
        slug=args.user or 'personal'
        if slug!='personal':
            raise ValueError('Legacy initial provisioning uses personal; add other users with tenant_admin')
    else:
        accounts=profile.accounts()
        if not args.user and len(accounts)!=1:
            raise ValueError('Select --user explicitly when the configured profile has multiple instances')
        slug=args.user or next(iter(accounts))
        profile.account(slug)
    cfgpath=(CONF if profile.compatibility else Path(profile.instance_paths(slug)['configuration']))/'config.toml'
    # Resolve every required input before creating accounts, keys, units or mappings.
    if cfgpath.is_symlink():
        raise SystemExit('Configuration already exists; inspect before changing it')
    registry_path=ROOT/'private/tenants.json'
    registry_snapshot=registry_path.read_bytes() if registry_path.exists() else None
    data=json.loads(registry_snapshot) if registry_snapshot is not None else {'format':1,'instances':{}}
    found=data['instances'].get(slug)
    if found:
        instance=Instance(**found['spec'])
        verify_setup_arguments(instance,args)
        if args.name and args.name!=instance.display_name:
            raise ValueError('Display name differs from the registered identity')
    elif args.auth_mode=='managed-authelia':
        # Optional adapter for an explicitly selected existing local IdP.
        identity=json.loads((ROOT/'private/identity.json').read_text())
        instance=Instance(slug,args.name or 'GAL1LEO',identity['subject'],8820)
        if identity['username']!=instance.username: raise ValueError('Personal identity username differs')
        verify_setup_arguments(instance,args)
    else:
        port=8820 if profile.compatibility else profile.instance_ports(slug)['bridge']
        instance=setup_instance(args,slug,args.name or 'WhatsApp',port)
    artifacts=deployment_artifacts(instance)
    if cfgpath.exists(): verify_existing_config(instance,cfgpath)
    if instance.auth_mode=='external-oidc':
        endpoints=discovery_for(instance)
        cfg=render_config(instance,**endpoints,live_enabled=False)
    else:
        cfg=(ROOT/'deploy/bridge.example.toml').read_text()
        cfg=cfg.replace('https://YOUR-OAUTH-ISSUER.example/.well-known/jwks.json',instance.effective_jwks_url)
        cfg=cfg.replace('https://YOUR-OAUTH-ISSUER.example',instance.issuer)
        cfg=cfg.replace('REPLACE_WITH_EXACT_OAUTH_SUBJECT',instance.subject)
    with runtime_admission(ROOT):
        current_registry=registry_path.read_bytes() if registry_path.exists() else None
        if current_registry!=registry_snapshot:
            raise ValueError('Tenant registry changed while acquiring admission; inspect and retry with current inputs')
        validate_instance_resources(instance,data)
        from provisioning_attempt import guard_preparation
        guard_preparation(instance,args.attempt_id)
        host = load_host_context(instance,args.host_plan,args.host_plan_sha256)
        try:
            if args.attempt_id:
                from provisioning_attempt import Attempt, prepare
                from tenant_admin import run as tenant_run, command as tenant_command
                with Attempt(instance,host,args.attempt_id) as attempt:
                    data['instances'].setdefault(slug,{'spec':instance.record(),'phase':'preparing','enabled':True})
                    write_private(registry_path,json.dumps(data,indent=2))
                    receipt=prepare(instance,artifacts,cfg,host,attempt,run=tenant_run,command=tenant_command)
                    data['instances'][slug]['phase']='prepared'
                    write_private(registry_path,json.dumps(data,indent=2))
                    print(json.dumps(receipt))
                return
            if cfgpath.exists():
                if not host.resumes_runtime():
                    raise SystemExit('Configuration already exists; inspect before changing it')
                StateContinuity(Settings.load(cfgpath),allow_bootstrap=False)
            host.begin_runtime()
            if instance.auth_mode=='external-oidc' and not found:
                data['instances'][slug]={'spec':instance.record(),'phase':'preparing','enabled':True}
                write_private(registry_path,json.dumps(data,indent=2))
            provision(instance,artifacts,cfg,host)
            if instance.auth_mode=='external-oidc':
                data['instances'][slug]['phase']=('existing' if instance._installation_identity.compatibility else 'prepared')
                write_private(registry_path,json.dumps(data,indent=2))
        finally:
            host.close()


def provision(instance,artifacts,cfg,host):
    ROOT, GATEWAY_HOME, CONF, USER = (instance.project_root,instance.gateway_home,
                                     instance.config_dir,instance.service_user)
    os.umask(0o077)
    register_subject(instance)
    try:
        account = pwd.getpwnam(USER)
    except KeyError:
        options=[] if instance._installation_identity.compatibility else ['--user-group']
        run(['useradd', '--system', *options, '--create-home', '--home-dir', str(GATEWAY_HOME),
                        '--shell', '/usr/sbin/nologin', USER], check=True)
        account = pwd.getpwnam(USER)
    if account.pw_dir != str(GATEWAY_HOME):
        raise SystemExit('Existing service user has unexpected home')
    uid, gid = account.pw_uid, account.pw_gid
    if not instance._installation_identity.compatibility:
        import grp
        if (uid<=0 or gid<=0 or account.pw_shell!='/usr/sbin/nologin'
                or grp.getgrgid(gid).gr_name!=USER):
            raise ValueError('Existing service identity is not the dedicated configured runtime')
    # Grant this one service traversal through the otherwise root-only project area.
    # Other project directories and this project's private/ directory remain closed.
    grant_project_access(instance)
    for path, flag in [('/etc/subuid', '--add-subuids'), ('/etc/subgid', '--add-subgids')]:
        ranges = [line.split(':') for line in Path(path).read_text().splitlines() if line]
        if not any(v[0] == USER for v in ranges):
            start = max([100000] + [int(v[1]) + int(v[2]) for v in ranges])
            run(['usermod', flag, f'{start}-{start + 65535}', USER], check=True)

    for path, mode in [(CONF, 0o750), (instance.state_dir, 0o700),
                       (GATEWAY_HOME, 0o700), (GATEWAY_HOME / 'sessions', 0o700), (GATEWAY_HOME / 'media', 0o700),
                       (GATEWAY_HOME / '.config', 0o700), (GATEWAY_HOME / '.config/containers', 0o700),
                       (GATEWAY_HOME / '.config/containers/systemd', 0o700)]:
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, 0 if path == CONF else uid, gid)
        os.chmod(path, mode)
    grant_runtime_access(instance)
    for name in ['webhook.key', 'encryption.key', 'waha.key']:
        path = CONF / name
        if not path.exists():
            path.write_text(Fernet.generate_key().decode() if name == 'encryption.key' else secrets.token_hex(32))
        os.chown(path, 0, gid)
        os.chmod(path, 0o640)
    cfgpath = CONF / 'config.toml'
    if not cfgpath.exists():
        with cfgpath.open('x') as stream: stream.write(cfg)
        os.chown(cfgpath, 0, gid)
        os.chmod(cfgpath, 0o640)
        initialize_new(Settings.load(cfgpath), uid, gid)
    else:
        StateContinuity(Settings.load(cfgpath),allow_bootstrap=False)

    wrapper = instance.wrapper
    if not instance._installation_identity.compatibility:
        wrapper.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    wrapper.write_text(f'#!/bin/sh\nset -eu\ncd {GATEWAY_HOME}\nexec runuser -u {USER} -- env HOME={GATEWAY_HOME} XDG_RUNTIME_DIR=/run/user/{uid} DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus "$@"\n')
    os.chmod(wrapper, 0o755 if instance._installation_identity.compatibility else 0o700)
    unit = Path('/etc/systemd/system')/(instance.base+'.service')
    unit.write_text(artifacts['bridge'])
    os.chmod(unit, 0o644)
    quadlet = GATEWAY_HOME / '.config/containers/systemd/whatsapp-waha.container'
    quadlet.write_text(artifacts['gateway'])
    os.chown(quadlet, uid, gid)
    os.chmod(quadlet, 0o600)
    host.enroll_runtime(account)
    run(['loginctl', 'enable-linger', USER], check=True)
    run(['systemctl', 'start', f'user@{uid}.service'], check=True)
    for name,source in [('whatsapp-waha-api-key',str(CONF/'waha.key')),('whatsapp-waha-disabled-ui-key','-')]:
        exists=run([str(wrapper),'podman','secret','inspect',name],capture_output=True).returncode==0
        if not exists:
            run([str(wrapper),'podman','secret','create',name,source],check=True,capture_output=True,
                           **({'input':secrets.token_hex(32),'text':True} if source=='-' else {}))
    run(['systemctl', 'daemon-reload'], check=True)
    if instance._installation_identity.compatibility:
        run(['systemctl', 'enable', '--now', instance.base+'.service'], check=True)
    run([str(wrapper), 'systemctl', '--user', 'daemon-reload'], check=True)
    https=host.ensure_https(artifacts['apache'])
    print(json.dumps({'service_user': USER, 'uid': uid, 'bridge_started': instance._installation_identity.compatibility,
                      'whatsapp_account_enabled': False, 'waha_started': False,
                      'qos_frontend': https['qos_frontend'], 'frontend_traffic_verified': False}))


if __name__=='__main__': main()
