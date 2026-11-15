"""Immutable runtime directory links on real isolated filesystems and owned processes.

No app payload, service, network operation, account or private state is used.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

SOURCE = Path(__file__).resolve().parents[2] / 'host/lifecycle/filesystem.py'
spec = importlib.util.spec_from_file_location('runtime_tree_filesystem', SOURCE)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)
RUNTIME = '/usr/local/lib/box-browser'
EMPTY = {'format': 1, 'owner': 'box', 'files': {}, 'directories': {}, 'links': {}}


def plan(previous=None, version='1'):
    """Declare one synthetic release; retained historical releases are explicit."""
    before = copy.deepcopy(EMPTY if previous is None else previous)
    after = copy.deepcopy(before)
    target = RUNTIME + '/releases/' + version * 64
    directory = {'uid': os.getuid(), 'gid': os.getgid(), 'mode': 0o755, 'retention': 'retain'}
    for path in (RUNTIME, RUNTIME + '/releases', target, target + '/lib'):
        after['directories'][path] = directory.copy()
    content = {target + '/server.mjs': ('throw new Error("never execute ' + version + '");\n').encode(),
               target + '/lib/manifest.json': json.dumps({'version': version}).encode()}
    for path, raw in content.items():
        after['files'][path] = {'sha256': hashlib.sha256(raw).hexdigest(), 'mode': 0o644,
                               'uid': os.getuid(), 'gid': os.getgid(), 'retention': 'managed'}
    after['links'][RUNTIME + '/current'] = {'target': target, 'uid': os.getuid(),
                                          'gid': os.getgid(), 'retention': 'managed'}
    allowed = sorted({path for state in (before, after) for kind in ('files', 'directories', 'links')
                      for path in state[kind]})
    return {'before': before, 'after': after, 'payloads': content, 'allowed_paths': allowed, 'tree': target}


@pytest.fixture
def host(tmp_path):
    base=tmp_path/'root';base.mkdir(mode=0o700)
    for name in ('usr/local/lib','var/lib/box-private','var/lib/whatsapp-private'):
        (base/name).mkdir(parents=True,mode=0o755)
    for folder in ('box-private','whatsapp-private'):
        (base/'var/lib'/folder/'state.sqlite').write_bytes(b'private revocations/session/current jobs')
    with engine.Root(base) as root:yield root,base

def apply(root,p,operation='a'*32,fault=None):
    return engine.reconcile(root,operation_id=operation,**{key:p[key] for key in ('before','after','payloads','allowed_paths')},fault=fault)
def current(base):
    path=base/(RUNTIME+'/current').lstrip('/')
    return os.readlink(path) if path.is_symlink() else None
def assert_tree(root,p):
    for path,spec in p['after']['files'].items():assert root.snapshot(path)=={k:v for k,v in spec.items() if k!='retention'}




def test_fresh_then_upgrade_publish_only_complete_trees_and_preserve_private_state(host):
    root,base=host;first=plan();events=[]
    apply(root,first,fault=lambda name,detail:events.append((name,detail)))
    assert current(base)==first['tree'];assert_tree(root,first)
    old={p:(base/p.lstrip('/')).stat().st_ino for p in first['after']['files']}
    second=plan(first['after'],'2');receipt=apply(root,second,'b'*32)
    assert current(base)==second['tree'];assert_tree(root,second)
    assert all((base/p.lstrip('/')).stat().st_ino==ino for p,ino in old.items())
    assert os.readlink(base/receipt['quarantine'][RUNTIME+'/current'].lstrip('/'))==first['tree']
    replaced=[d['path'] for n,d in events if n=='replaced-file']
    assert replaced[-1]==RUNTIME+'/current'
    for folder in ('box-private','whatsapp-private'):
        assert (base/'var/lib'/folder/'state.sqlite').read_bytes()==b'private revocations/session/current jobs'


@pytest.mark.parametrize('event',['journal-staging','staged-file','journal-prepared','journal-applying',
 'intent-directory','created-directory','completed-directory','intent-file','replaced-file','completed-file','journal-committed'])
def test_crash_replay_is_forward_and_never_publishes_an_incomplete_tree(host,event):
    root,base=host;first=plan();apply(root,first)
    second=plan(first['after'],'2')
    fired=[]
    def crash(name,detail):
        if name==event and not fired:
            fired.append(name);raise RuntimeError('synthetic power loss')
    with pytest.raises(RuntimeError):apply(root,second,'b'*32,crash)
    assert current(base) in (first['tree'],second['tree'])
    if current(base)==second['tree']:assert_tree(root,second)
    # Staging may still need caller-pinned payloads, as in the existing engine.
    engine.resume(root,owner='box',operation_id='b'*32,allowed_paths=second['allowed_paths'],payloads=second['payloads'])
    assert current(base)==second['tree'];assert_tree(root,second)


@pytest.mark.parametrize('intruder',['file','directory','symlink','hardlink','mode','bytes'])
def test_unclosed_or_changed_candidate_cannot_replace_current(host,intruder):
    root,base=host;first=plan();apply(root,first);second=plan(first['after'],'2')
    target=base/second['tree'].lstrip('/')
    def mutate(event,detail):
        if event=='intent-file' and detail.get('intent')==RUNTIME+'/current':
            if intruder=='file':(target/'extra').write_bytes(b'unknown')
            elif intruder=='directory':(target/'extra').mkdir()
            elif intruder=='symlink':(target/'extra').symlink_to('/never-followed')
            elif intruder=='hardlink':os.link(target/'server.mjs',target/'extra')
            elif intruder=='mode':(target/'server.mjs').chmod(0o666)
            else:(target/'server.mjs').write_bytes(b'drift')
    with pytest.raises(engine.LifecycleError):apply(root,second,'b'*32,mutate)
    assert current(base)==first['tree']




def test_published_generation_cannot_be_modified_in_place(host):
    root,base=host;p=plan();apply(root,p)
    before=p['after'];after=copy.deepcopy(before);path=next(iter(after['files']))
    after['files'][path]['sha256']=hashlib.sha256(b'changed').hexdigest()
    with pytest.raises(engine.LifecycleError,match='immutable'):
        engine.reconcile(root,operation_id='b'*32,before=before,after=after,payloads={path:b'changed'},allowed_paths=p['allowed_paths'])
    assert current(base)==p['tree'];assert_tree(root,p)


def test_parent_symlink_is_refused_without_following_it(host,tmp_path):
    root,base=host;p=plan();outside=tmp_path/'outside';outside.mkdir()
    (base/'usr/local/lib/box-browser').symlink_to(outside,target_is_directory=True)
    with pytest.raises(engine.LifecycleError):apply(root,p)
    assert list(outside.iterdir())==[]


def test_committed_replay_rechecks_tree_closure(host):
    root,base=host;p=plan();apply(root,p)
    (base/p['tree'].lstrip('/')/'extra').write_bytes(b'drift')
    with pytest.raises(engine.LifecycleError):apply(root,p)


def test_two_processes_same_owner_are_serialized_but_whatsapp_is_independent(host):
    root,base=host;p=plan();apply(root,p)
    command='''import importlib.util,sys
s=importlib.util.spec_from_file_location("e",sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
with m.Root(sys.argv[2]) as r:
 with m._lock(r,"box"):
  print("locked",flush=True);sys.stdin.readline()
'''
    child=subprocess.Popen([sys.executable,'-B','-c',command,str(SOURCE),str(base)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    try:
        assert child.stdout.readline().strip()=='locked'
        with pytest.raises(engine.LifecycleBusy):apply(root,plan(p['after'],'2'),'b'*32)
        with engine._lock(root,'whatsapp'):pass
    finally:
        child.communicate('\n',timeout=10)
    assert child.returncode==0 and current(base)==p['tree']


def test_actual_sigkill_worker_releases_owner_lock_and_recovery_finishes_forward(host,tmp_path):
    import base64, select
    root,base=host;first=plan();apply(root,first);second=plan(first['after'],'2')
    request=tmp_path/'request.json'
    serialized={**second,'payloads':{k:base64.b64encode(v).decode() for k,v in second['payloads'].items()}}
    request.write_text(json.dumps(serialized))
    command='''import base64,importlib.util,json,signal,sys
s=importlib.util.spec_from_file_location("e",sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
p=json.load(open(sys.argv[3]));p['payloads']={k:base64.b64decode(v) for k,v in p['payloads'].items()}
def fault(event,detail):
 if event=='replaced-file' and detail['path']==p['tree']+'/server.mjs':
  print('candidate-written',flush=True);signal.pause()
with m.Root(sys.argv[2]) as r:
 m.reconcile(r,operation_id='b'*32,**{k:p[k] for k in ('before','after','payloads','allowed_paths')},fault=fault)
'''
    child=subprocess.Popen([sys.executable,'-B','-c',command,str(SOURCE),str(base),str(request)],stdout=subprocess.PIPE,text=True)
    try:
        assert select.select([child.stdout],[],[],10)[0]
        assert child.stdout.readline().strip()=='candidate-written'
        assert current(base)==first['tree']
        with pytest.raises(engine.LifecycleBusy):engine.resume(root,owner='box',operation_id='b'*32,allowed_paths=second['allowed_paths'])
        child.kill();child.communicate(timeout=10)
        assert child.returncode<0
        engine.resume(root,owner='box',operation_id='b'*32,allowed_paths=second['allowed_paths'])
        assert current(base)==second['tree'];assert_tree(root,second)
    finally:
        if child.poll() is None:child.kill();child.communicate(timeout=10)


def test_fresh_and_upgrade_active_projection_match_and_retirement_is_named(host,tmp_path):
    root,base=host;first=plan();apply(root,first);upgrade=plan(first['after'],'2');apply(root,upgrade,'b'*32)
    fresh=plan(version='2')
    assert fresh['tree']==upgrade['tree']
    prefix=fresh['tree']+'/'
    for kind in ('files','directories'):
        active=lambda p:{k:v for k,v in p['after'][kind].items() if k==fresh['tree'] or k.startswith(prefix)}
        assert active(fresh)==active(upgrade)
    assert fresh['after']['links']==upgrade['after']['links']
    retired={**upgrade['after'],'files':{},'links':{}}
    receipt=engine.reconcile(root,operation_id='c'*32,before=upgrade['after'],after=retired,payloads={},allowed_paths=upgrade['allowed_paths'])
    assert current(base) is None
    assert all(root.snapshot(path) is None for path in upgrade['after']['files'])
    assert all(root.snapshot(receipt['quarantine'][path]) is not None for path in upgrade['after']['files'])
    assert all(root.directory(path) is not None for path in retired['directories'])
    for folder in ('box-private','whatsapp-private'):
        assert (base/'var/lib'/folder/'state.sqlite').read_bytes()==b'private revocations/session/current jobs'


def test_existing_published_generation_cannot_gain_undeclared_files(host):
    root,base=host;p=plan();apply(root,p)
    after=copy.deepcopy(p['after']);path=p['tree']+'/injected.js'
    after['files'][path]={'sha256':hashlib.sha256(b'x').hexdigest(),'mode':0o644,'uid':os.getuid(),'gid':os.getgid(),'retention':'managed'}
    with pytest.raises(engine.LifecycleError,match='immutable'):
        engine.reconcile(root,operation_id='b'*32,before=p['after'],after=after,payloads={path:b'x'},allowed_paths=[*p['allowed_paths'],path])
    assert not (base/path.lstrip('/')).exists()


@pytest.mark.parametrize('mutation',['change','add','remove'])
def test_switch_refuses_mutation_of_previous_current_tree_before_any_write(host,mutation):
    root,base=host;first=plan();apply(root,first);second=plan(first['after'],'2')
    path=next(iter(first['after']['files']))
    if mutation=='change':
        second['after']['files'][path]['sha256']=hashlib.sha256(b'mutated active source').hexdigest()
        second['payloads'][path]=b'mutated active source'
    elif mutation=='add':
        path=first['tree']+'/injected.js'
        second['after']['files'][path]={**next(iter(first['after']['files'].values())), 'sha256':hashlib.sha256(b'addition').hexdigest()}
        second['payloads'][path]=b'addition';second['allowed_paths'].append(path)
    else:del second['after']['files'][path]
    events=[]
    with pytest.raises(engine.LifecycleError,match='previous directory link tree'):
        apply(root,second,'b'*32,lambda event,detail:events.append((event,detail)))
    assert events==[]
    assert current(base)==first['tree'];assert_tree(root,first)
    assert not (base/'var/lib/develative-host-lifecycle/box/operations'/('b'*32)).exists()


def test_directory_target_requires_an_explicit_directory_manifest(host):
    root, base = host
    target = '/usr/local/lib/unmanaged-release'
    (base / target.lstrip('/')).mkdir(mode=0o755)
    before = copy.deepcopy(EMPTY)
    after = copy.deepcopy(EMPTY)
    link = '/usr/local/lib/current'
    after['links'][link] = {'target': target, 'uid': root.uid, 'gid': root.gid, 'retention': 'managed'}
    with pytest.raises(engine.LifecycleError, match='not a regular file'):
        engine.reconcile(root, operation_id='a' * 32, before=before, after=after,
                         payloads={}, allowed_paths={link, target})
    assert root.link(link) is None
    assert not (base / 'var/lib/develative-host-lifecycle').exists()


def test_relative_current_literal_is_preserved_for_a_closed_directory_tree(host):
    root, base = host
    value = plan()
    value['after']['links'][RUNTIME + '/current'].update(
        target='releases/' + '1' * 64, resolved_target=value['tree'])
    apply(root, value)
    assert current(base) == 'releases/' + '1' * 64
    assert_tree(root, value)


def test_external_hardlink_without_extra_candidate_name_blocks_publication(host):
    root, base = host
    first = plan()
    apply(root, first)
    second = plan(first['after'], '2')
    target = base / second['tree'].lstrip('/')

    def fault(event, detail):
        if event == 'intent-file' and detail.get('intent') == RUNTIME + '/current':
            os.link(target / 'server.mjs', base / 'usr/local/lib/external-link')

    with pytest.raises(engine.LifecycleError, match='nonregular'):
        apply(root, second, 'b' * 32, fault)
    assert current(base) == first['tree']


def test_oversized_candidate_directory_has_an_explicit_scan_bound(host):
    root, base = host
    first = plan()
    apply(root, first)
    second = plan(first['after'], '2')
    target = base / second['tree'].lstrip('/')

    def fault(event, detail):
        if event == 'intent-file' and detail.get('intent') == RUNTIME + '/current':
            for number in range(engine.MAX_FILES + 1):
                (target / ('extra-' + str(number))).touch()

    with pytest.raises(engine.LifecycleError, match='entry bound'):
        apply(root, second, 'b' * 32, fault)
    assert current(base) == first['tree']


@pytest.mark.parametrize('drift', ['writable', 'foreign-uid'])
def test_directory_payload_must_be_administratively_immutable_before_writes(host, drift):
    root, base = host
    value = plan()
    spec = next(iter(value['after']['files'].values()))
    spec['mode' if drift == 'writable' else 'uid'] = 0o666 if drift == 'writable' else root.uid + 1
    with pytest.raises(engine.LifecycleError, match='administratively immutable'):
        apply(root, value)
    assert current(base) is None
    assert not (base / 'var/lib/develative-host-lifecycle').exists()
