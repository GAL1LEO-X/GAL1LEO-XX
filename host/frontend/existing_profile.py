"""Compile an explicitly inventoried Apache host without changing foreign sites.

This path is independent from fresh_profile's empty-host guards and from the
historical PRO8 collector. No discovery, certificate issuance or service action
occurs. Every existing Include, hook and dependency must be explicitly pinned.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat

HOOK_ROOT='/usr/local/lib/develative-host-frontend'
HOOKS={'deploy':'/etc/letsencrypt/renewal-hooks/deploy/60-develative-host-frontend',
       'post':'/etc/letsencrypt/renewal-hooks/post/95-develative-host-frontend'}
SOURCES=('host/frontend/existing_profile.py','host/frontend/provider.py',
         'host/frontend/adapter.py','host/lifecycle/filesystem.py')


def require(value,message):
    if not value:raise ValueError(message)


def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(value):return hashlib.sha256(value).hexdigest()


def decode(raw):
    def unique(pairs):
        result={}
        for name,value in pairs:
            require(name not in result,'Duplicate compiler input field')
            result[name]=value
        return result
    def constant(value):raise ValueError('Non-finite compiler input')
    return json.loads(raw,object_pairs_hook=unique,parse_constant=constant)


def protected_bytes(selected):
    """Read physical root-protected code/input before compiling any sibling."""
    selected=Path(selected).absolute()
    require(selected==selected.resolve(strict=True),'Compiler source must be physical')
    for item in (selected,*selected.parents):
        info=item.lstat()
        require(info.st_uid==0 and not info.st_mode&0o022,'Compiler source must be root-protected')
    descriptor=os.open(selected,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as stream:
        initial=os.fstat(stream.fileno())
        require(stat.S_ISREG(initial.st_mode) and initial.st_size<=16*1024*1024,'Unbounded compiler source')
        body=stream.read(16*1024*1024+1);final=os.fstat(stream.fileno())
    identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    require(len(body)<=16*1024*1024 and identity(initial)==identity(final)==identity(selected.lstat()),
            'Compiler source changed')
    return body


def bootstrap(manifest_path,expected_sha256):
    raw=protected_bytes(manifest_path)
    require(sha(raw)==expected_sha256,'Existing compiler manifest digest differs')
    manifest=decode(raw)
    require(isinstance(manifest,dict) and set(manifest)=={'format','sources'}
            and type(manifest['format']) is int and manifest['format']==1
            and isinstance(manifest['sources'],dict) and set(manifest['sources'])==set(SOURCES),
            'Exact existing compiler source closure required')
    base=Path(__file__).absolute().parents[2]
    source={name:protected_bytes(base/name) for name in SOURCES}
    require(all(sha(body)==manifest['sources'][name] for name,body in source.items()),
            'Existing compiler source drift')
    modules={}
    for label,relative in (('provider','host/frontend/provider.py'),
            ('engine','host/lifecycle/filesystem.py'),('adapter','host/frontend/adapter.py')):
        scope={'__name__':'existing_frontend_'+label,'__file__':str(base/relative)}
        if label=='adapter':scope['_PINNED_PROVIDER']=modules['provider']
        exec(compile(source[relative],str(base/relative),'exec'),scope)
        modules[label]=type('Module',(),scope)
    content=protected_bytes(base/'manifest.json')
    return modules,{'path':str(base),'sha256':sha(content)}


def names(root,directory):
    if root.directory(directory) is None:return []
    with root._parent(directory) as (parent,leaf):
        descriptor=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:return sorted(os.listdir(descriptor))
        finally:os.close(descriptor)


def build(root,inputs,*,provider,adapter,engine,generation):
    """Read an approved public inventory and return a reversible finite plan.

    Existing artifacts are retained with exact bytes and metadata. Only the
    source-owned neutral hook namespace and two unoccupied registrations may
    be added. Unknown or changed files stop compilation before any output.
    """
    require(isinstance(inputs,dict) and set(inputs)=={'format','registry','profile','hook_inventory','python'}
            and type(inputs['format']) is int and inputs['format']==1,'Invalid existing-host compiler inputs')
    registry=copy.deepcopy(inputs['registry']);profile=copy.deepcopy(inputs['profile'])
    require(registry.get('legacy_hooks')=={},'Initial adoption must preserve existing hooks in place')
    require(isinstance(inputs['hook_inventory'],dict) and set(inputs['hook_inventory'])==set(HOOKS),
            'Both complete existing hook inventories are required')
    require(isinstance(generation,dict) and set(generation)=={'path','sha256'}
            and re.fullmatch('[a-f0-9]{64}',generation['sha256'])
            and generation['path']=='/usr/local/lib/develative-host-components/'+generation['sha256'],
            'An exact independently installed host generation is required')
    manifest_raw=root.read_bytes(generation['path']+'/manifest.json')
    require(sha(manifest_raw)==generation['sha256'],'Host source generation changed')
    manifest=json.loads(manifest_raw)
    runtime=('host/frontend/adapter.py','host/frontend/provider.py','host/lifecycle/filesystem.py')
    expected={'format':1,'sources':{name:manifest['files'][name] for name in runtime}}
    runtime_raw=root.read_bytes(generation['path']+'/frontend-sources.json')
    require(json.loads(runtime_raw)==expected and manifest['files'].get('frontend-sources.json')==sha(runtime_raw),
            'Neutral frontend source closure differs')
    for name in runtime:
        require(sha(root.read_bytes(generation['path']+'/'+name))==manifest['files'][name],
                'Installed neutral frontend source differs')
    python=inputs['python']
    require(isinstance(python,dict) and set(python)=={'path','sha256'}
            and re.fullmatch(r'/usr/bin/python3(?:\.\d+)?',python['path']), 'Use an explicit physical system Python')
    python_info=root.snapshot(python['path'])
    require(python_info is not None and python_info['sha256']==python['sha256']
            and python_info['uid']==root.uid and not python_info['mode']&0o022
            and python_info['mode']&0o100,
            'Python tool differs from the approved inventory')
    before={'format':1,'owner':'host','files':{},'links':{},'directories':{}}
    raw={}
    require(root.snapshot(provider.REGISTRY) is None and root.snapshot(adapter.PROFILE) is None,
            'An installed neutral frontend must use its existing registry, not initial adoption')
    for name,spec in registry['directories'].items():
        require(spec.get('retention')=='retain' and root.directory(name)=={k:spec[k] for k in ('mode','uid','gid')},
                'Existing directory inventory differs')
        before['directories'][name]=copy.deepcopy(spec)
    for name,spec in registry['artifacts'].items():
        require(spec.get('retention')=='retain','Existing foreign files must be retained')
        actual=root.snapshot(name)
        require(actual=={k:spec[k] for k in ('sha256','mode','uid','gid')},'Existing public artifact changed: '+name)
        raw[name]=root.read_bytes(name)
        before['files'][name]=copy.deepcopy(spec)
    for name,spec in registry['links'].items():
        actual=root.link(name)
        fields=('target','uid','gid')+(('resolved_target',) if 'resolved_target' in spec else ())
        require(spec.get('retention')=='retain' and actual=={k:spec[k] for k in fields},
                'Existing foreign link changed: '+name)
        before['links'][name]=copy.deepcopy(spec)
    for event,hook in HOOKS.items():
        directory=str(Path(hook).parent)
        observed=names(root,directory)
        require(observed==inputs['hook_inventory'][event], 'Hook directory differs from the complete explicit inventory')
        require(all(directory+'/'+name in set(registry['artifacts'])|set(registry['links']) for name in observed),
                'An existing hook has no pinned ownership and source identity')
        require(root.snapshot(hook) is None and root.link(hook) is None,'Neutral hook registration collides with an existing hook')
        legacy=HOOK_ROOT+'/legacy-'+event;wrapper=HOOK_ROOT+'/'+event+'-hook'
        for name in (legacy,wrapper):
            require(root.snapshot(name) is None and root.link(name) is None,'Neutral hook namespace already exists')
        raw[legacy]=b'#!/bin/sh\n# Foreign hooks remain registered in their original locations.\nexit 0\n'
        raw[wrapper]=('#!/bin/sh\nexec '+python['path']+' -I -B '+generation['path']
            +'/host/frontend/adapter.py '+event+'-hook --source-manifest '+generation['path']
            +'/frontend-sources.json --source-sha256 '+sha(runtime_raw)+'\n').encode()
        for name in (legacy,wrapper):
            registry['artifacts'][name]={'sha256':sha(raw[name]),'mode':0o700,'uid':root.uid,'gid':root.gid,'retention':'managed'}
            registry['host_files'].append(name)
        registry['links'][hook]={'target':wrapper,'uid':root.uid,'gid':root.gid,'retention':'managed'}
        registry['host_files'].append(hook)
        registry['legacy_hooks'][event]={'path':legacy,'sha256':sha(raw[legacy])}
    for name in set(registry['artifacts'])|set(registry['links'])|{provider.REGISTRY,adapter.PROFILE}:
        for parent in Path(name).parents:
            if parent==Path('/'):continue
            selected=str(parent);actual=root.directory(selected)
            if actual is not None:
                require(actual['uid']==root.uid and not actual['mode']&0o022,'Unprotected frontend parent')
                item={**actual,'retention':'retain'};before['directories'][selected]=item
            else:item={'mode':0o755,'uid':root.uid,'gid':root.gid,'retention':'retain'}
            if selected in registry['directories']:
                require(registry['directories'][selected]==item,'Directory inventory differs')
            registry['directories'][selected]=item
    provider.validate_registry(registry);adapter.validate_profile(profile,registry)
    for name,spec in profile['dependencies'].items():
        require(root.snapshot(name)==spec,'Pinned Apache dependency changed')
    for spec in profile['tools'].values():
        actual=root.snapshot(spec['path'])
        require(actual is not None and actual['sha256']==spec['sha256'] and actual['uid']==root.uid
                and not actual['mode']&0o022,'Pinned frontend tool changed')
    lock=profile['certbot_lock']['source']
    require(root.snapshot(lock['path'])['sha256']==lock['sha256'],'Pinned Certbot lock implementation changed')
    host=adapter.HostAdapter(root,engine,registry,profile)
    # Graph validation also detects unlisted glob targets, missing directives,
    # cycles and unreachable sources. This does not execute configtest or TLS.
    host._graph(provider.managed_manifest(registry),raw,active=True)
    return {'before':before,'registry':registry,'profile':profile,'pinned_artifacts':raw,
            'runtime_verified':False,'foreign_artifacts_preserved':True,
            'frontend_operation_id':sha(encoded({'generation':generation,'inputs':inputs}))[:32]}


def write_package(root,output,built):
    """Publish a new local preparation package under protected ancestors."""
    with root._parent(output) as (parent,leaf):os.mkdir(leaf,0o700,dir_fd=parent)
    base=root.base/output.lstrip('/')
    payloads={name+'.json':encoded(built[name]) for name in ('before','registry','profile')}
    payloads.update({'artifacts'+name:body for name,body in built['pinned_artifacts'].items()})
    for name,body in payloads.items():
        selected=base/name;selected.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with selected.open('xb') as stream:
            os.fchmod(stream.fileno(),0o600);stream.write(body);stream.flush();os.fsync(stream.fileno())
    receipt={'format':1,'activated':False,'private_material_read':False,
        'frontend_operation_id':built['frontend_operation_id'],
        'files':{name:sha(body) for name,body in sorted(payloads.items())}}
    with (base/'package.json').open('xb') as stream:
        os.fchmod(stream.fileno(),0o600);stream.write(encoded(receipt));stream.flush();os.fsync(stream.fileno())
    for selected in [*(item for item in base.rglob('*') if item.is_dir()),base]:
        descriptor=os.open(selected,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    with root._parent(output) as (parent,_):os.fsync(parent)
    return receipt


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-manifest',type=Path,required=True)
    parser.add_argument('--source-sha256',required=True)
    parser.add_argument('--inputs',type=Path,required=True);parser.add_argument('--inputs-sha256',required=True)
    parser.add_argument('--generation',required=True);parser.add_argument('--generation-sha256',required=True)
    parser.add_argument('--root',type=Path,default=Path('/'));parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    modules,own_generation=bootstrap(args.source_manifest,args.source_sha256)
    require(own_generation=={'path':args.generation,'sha256':args.generation_sha256},
            'Compiler and target generation differ')
    raw=protected_bytes(args.inputs)
    require(len(raw)<=1024*1024 and sha(raw)==args.inputs_sha256,'Public input digest or bound differs')
    with modules['engine'].Root(args.root) as root:
        result=build(root,decode(raw),**modules,generation=own_generation)
        write_package(root,args.output.as_posix(),result)
    print(json.dumps({'output':str(args.output),'host_changed':False,'runtime_verified':False}))


if __name__=='__main__':main()
