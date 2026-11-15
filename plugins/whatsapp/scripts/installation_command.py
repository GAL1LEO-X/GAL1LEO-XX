"""Compile a configured WhatsApp installation locally; never operate a host."""
import argparse
import hashlib
import json
from pathlib import Path
import os
import ipaddress
import re
import stat
import sys

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
from installation_layout import Installation, MAX_PROFILE_BYTES, identity_bytes, select, unique_fields


def public_json(path):
    path=Path(path).absolute()
    if path.resolve(strict=True)!=path:raise ValueError('Public compiler inputs must be physical files')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):raise ValueError('Public input must be a regular file')
        raw=stream.read(MAX_PROFILE_BYTES+1);after=os.fstat(stream.fileno())
    signature=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    if len(raw)>MAX_PROFILE_BYTES or signature(before)!=signature(after) or signature(after)!=signature(path.lstat()):
        raise ValueError('Public compiler input changed or exceeded its bound')
    return json.loads(raw,object_pairs_hook=unique_fields)


def host_plan(instance,context):
    """Pure plan compilation; installed sources and live prerequisites are later verified."""
    if not isinstance(context,dict) or set(context) not in ({'operation_id','generation','dns','tools','qos'}, {'operation_id','generation','dns','tools','qos','certificates'}):
        raise ValueError('Declare the complete public host context')
    if not re.fullmatch('[a-f0-9]{32}',context['operation_id']):raise ValueError('Invalid host operation identity')
    generation=context['generation']
    if (not isinstance(generation,dict) or set(generation)!={'path','sha256'}
            or not re.fullmatch('[a-f0-9]{64}',generation['sha256'])
            or generation['path']!='/usr/local/lib/develative-host-components/'+generation['sha256']):
        raise ValueError('Select an exact independently installed host generation')
    dns=context['dns']
    if not isinstance(dns,dict) or set(dns)!={'address','zone','local_resolver','public_resolver'}:
        raise ValueError('Declare the DNS target, zone and resolvers')
    from sally_whatsapp.tenancy import validate_hostname
    validate_hostname(dns['zone'])
    if not (instance.hostname==dns['zone'] or instance.hostname.endswith('.'+dns['zone'])):
        raise ValueError('Instance lies outside the explicit DNS zone')
    if str(ipaddress.IPv4Address(dns['address']))!=dns['address']:raise ValueError('Use a canonical IPv4 target')
    for key in ('local_resolver','public_resolver'):
        if str(ipaddress.ip_address(dns[key]))!=dns[key]:raise ValueError('Use literal DNS resolver addresses')
    tools=context['tools'];programs={'dig':'/usr/bin/dig','certbot':'/usr/bin/certbot','python':'/usr/bin/python3'}
    if not isinstance(tools,dict) or set(tools)!=set(programs):raise ValueError('Declare the finite host tools')
    for name,item in tools.items():
        if (not isinstance(item,dict) or set(item)!={'path','sha256'} or not re.fullmatch('[a-f0-9]{64}',item['sha256'])
                or not (item['path']==programs[name] or name=='python' and re.fullmatch(r'/usr/bin/python3\.1[0-9]',item['path']))):
            raise ValueError('Unexpected host tool or missing source pin')
    qos=context['qos']
    if qos is not None and (not isinstance(qos,dict) or set(qos)!={'policy','sha256'}
            or qos['policy']!='/etc/develative-host-qos/policy.json' or not re.fullmatch('[a-f0-9]{64}',qos['sha256'])):
        raise ValueError('QoS must be null or a separately reviewed installed policy')
    certificates=context.get('certificates','shared')
    if certificates not in ('shared','isolated'):raise ValueError('Unknown certificate store')
    certificate_root='/etc/develative-certificates' if certificates=='isolated' else '/etc/letsencrypt'
    allocation=instance._installation_identity.roster_sha256
    return {'format':1,'operation_id':context['operation_id'],'generation':generation,'qos':qos,'tools':tools,
        **({'allocation_sha256':allocation} if allocation is not None else {}),
        'instance':{'slug':instance.slug,'account':instance.service_user,'hostname':instance.hostname,
                    'bridge_port':instance.bridge_port,'gateway_port':instance.gateway_port},
        'frontend':{'registry':'/etc/develative-host-frontend/registry.json','profile':'/etc/develative-host-frontend/profile.json',
            **dns,**({'certificates':'isolated'} if certificates=='isolated' else {}),'dns_mode':'preconfigured','webroot':'/var/www/'+instance.base+'-acme',
            'lineage':certificate_root+'/live/'+instance.hostname,'archive':certificate_root+'/archive/'+instance.hostname,
            'renewal':certificate_root+'/renewal/'+instance.hostname+'.conf'}}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    choice=parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--profile',type=Path)
    choice.add_argument('--legacy',action='store_true',help='Explicit fixed-layout compatibility; never inferred from missing files')
    parser.add_argument('--profile-sha256')
    parser.add_argument('--roster',type=Path,help='Explicit reviewed allocation snapshot for local compilation')
    parser.add_argument('--roster-sha256')
    commands=parser.add_subparsers(dest='command',required=True)
    commands.add_parser('validate')
    identity=commands.add_parser('render-identity')
    identity.add_argument('--output',type=Path,required=True)
    runtime=commands.add_parser('render-runtime')
    runtime.add_argument('--instance',type=Path,required=True,help='Public external-OIDC Instance fields')
    runtime.add_argument('--discovery',type=Path,required=True,help='Reviewed public OIDC discovery JSON')
    runtime.add_argument('--output',type=Path,required=True)
    plan=commands.add_parser('render-host-plan')
    plan.add_argument('--instance',type=Path,required=True)
    plan.add_argument('--context',type=Path,required=True)
    plan.add_argument('--output',type=Path,required=True)
    administration=commands.add_parser('build-administration')
    administration.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[1])
    administration.add_argument('--source-sha',required=True)
    administration.add_argument('--output',type=Path,required=True)
    fresh=commands.add_parser('compile-fresh-administration')
    fresh.add_argument('arguments',nargs=argparse.REMAINDER)
    update=commands.add_parser('compile-administration')
    update.add_argument('arguments',nargs=argparse.REMAINDER)
    args=parser.parse_args(argv)
    # This input authorizes local compilation only. Installed operational entry
    # points use the protected /etc locator and the admitted generation digest.
    if args.legacy:
        if args.profile_sha256 is not None:
            raise ValueError('Legacy selection has no external profile digest')
        if args.roster is not None or args.roster_sha256 is not None:
            raise ValueError('Legacy compilation has no allocation roster')
        profile=select(Installation.legacy())
    else:
        if args.profile!=args.profile.absolute() or args.profile.resolve(strict=True)!=args.profile:
            raise ValueError('Select a physical absolute public profile file')
        with os.fdopen(os.open(args.profile,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):raise ValueError('Public profile must be a regular file')
            raw=stream.read(MAX_PROFILE_BYTES+1)
            after=os.fstat(stream.fileno())
        signature=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        if (len(raw)>MAX_PROFILE_BYTES or hashlib.sha256(raw).hexdigest()!=args.profile_sha256
                or signature(before)!=signature(after) or signature(after)!=signature(args.profile.lstat())):
            raise ValueError('Public profile differs from its bounded reviewed digest')
        profile=Installation.from_dict(json.loads(raw,object_pairs_hook=unique_fields))
        if args.roster is not None:
            roster=public_json(args.roster)
            profile=profile.with_roster(roster)
            if profile.roster_sha256!=args.roster_sha256:
                raise ValueError('Allocation snapshot differs from its reviewed canonical digest')
        elif args.roster_sha256 is not None:
            raise ValueError('A roster digest requires an explicit snapshot')
        profile=select(profile)
    if args.command=='validate':
        print(json.dumps({'format':profile.as_dict()['format'],'installation_sha256':profile.sha256,
                          'instances':sorted(profile.accounts() if not profile.compatibility else {}),
                          'roster_sha256':profile.roster_sha256,'host_changed':False}))
    elif args.command=='render-identity':
        # The operator reviews and installs this public marker independently of
        # the locator before admitting helpers; this command only creates output.
        with args.output.open('xb') as stream:stream.write(identity_bytes(profile))
        print(json.dumps({'output':str(args.output),'installation_sha256':profile.sha256,'host_changed':False}))
    elif args.command in ('render-runtime','render-host-plan'):
        if profile.compatibility:raise ValueError('Runtime and host-plan compilation require a configured profile')
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        # Both copies use the same reviewed public input during this local
        # compilation. Importing tenancy must not consult the executing host's
        # installation before the application copy has that explicit identity.
        from sally_whatsapp import installation as application_installation
        selected=application_installation.Installation.from_dict(profile.as_dict())
        if profile.roster is not None:selected=selected.with_roster(profile.roster)
        application_installation.select(selected)
        from sally_whatsapp.tenancy import Instance,deployment_artifacts,render_config,oidc_endpoints
        spec=public_json(args.instance)
        if 'installation' in spec:raise ValueError('Installation identity comes from the separately pinned profile')
        instance=Instance(**spec,installation=profile.as_dict())
        if args.command=='render-host-plan':
            value=host_plan(instance,public_json(args.context))
            with args.output.open('x') as stream:stream.write(json.dumps(value,sort_keys=True,indent=2)+'\n')
            print(json.dumps({'output':str(args.output),'host_changed':False,'live_preflight_performed':False}))
            return
        discovery=public_json(args.discovery)
        artifacts=deployment_artifacts(instance,template_root=Path(__file__).resolve().parents[1]/'deploy')
        artifacts['configuration']=render_config(instance,**oidc_endpoints(instance,discovery),live_enabled=False)
        if args.output.exists() or args.output.is_symlink():raise ValueError('Runtime compilation output must be new')
        args.output.mkdir(mode=0o700)
        for name,text in artifacts.items():(args.output/(name+'.txt')).write_text(text)
        (args.output/'instance.json').write_text(json.dumps(instance.record(),sort_keys=True,indent=2)+'\n')
        print(json.dumps({'output':str(args.output),'installation_sha256':profile.sha256,'host_changed':False}))
    elif args.command=='build-administration':
        # Isolated Python omits the script directory from sys.path. Resolve
        # compiler dependencies from this checkout, never an ambient install.
        sys.path.insert(0,str(Path(__file__).resolve().parent))
        import build_admin_bundle
        result=build_admin_bundle.build_bundle(args.source,args.output,source_sha=args.source_sha)
        print(json.dumps({'format':result['format'],'installation_sha256':profile.sha256,
                          'output':str(args.output),'host_changed':False}))
    else:
        sys.path.insert(0,str(Path(__file__).resolve().parent))
        sys.path.insert(0,str(Path(__file__).resolve().parents[3]))
        from host import installation as host_installation
        selected=host_installation.Installation.legacy() if profile.compatibility else host_installation.Installation.from_dict(profile.as_dict())
        if profile.roster is not None:selected=selected.with_roster(profile.roster)
        host_installation.select(selected)
        if args.command == 'compile-administration':
            import admin_compile as compiler
        else:
            import fresh_admin as compiler
        arguments=args.arguments[1:] if args.arguments and args.arguments[0]=='--' else args.arguments
        compiler.main(arguments)


if __name__=='__main__':
    main()
