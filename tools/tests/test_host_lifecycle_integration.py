"""Cross-component filesystem/process tests; never operate on host services.

These tests retain real manifests, bytes, journal writes, flock and cold Python
entrypoints. Temporary trust roots/UIDs and service effects are the only seams.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import shutil
import subprocess
import sys

import pytest


REPOSITORY = Path(__file__).resolve().parents[2]
PLUGIN = REPOSITORY/'plugins/whatsapp'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sys.path.insert(0, str(REPOSITORY))
from host.lifecycle import filesystem
builder = load('integration_wa_builder', PLUGIN/'scripts/build_admin_bundle.py')


def empty(owner):
    return {'format': 1, 'owner': owner, 'files': {}, 'directories': {}}


def sha(value):
    return hashlib.sha256(value).hexdigest()


def metadata(content, *, retention='managed'):
    return {'sha256': sha(content), 'mode': 0o644, 'uid': os.getuid(),
            'gid': os.getgid(), 'retention': retention}


def physical(root, logical):
    return root/logical.lstrip('/')


def manifest_from_bundle(directory, bundle):
    manifest = empty('whatsapp')
    payloads = {}
    for name, artifact in bundle['artifacts'].items():
        content = (directory/name).read_bytes()
        assert sha(content) == artifact['sha256']
        target = artifact['destination']
        manifest['files'][target] = {**metadata(content), 'mode': int(artifact['mode'], 8)}
        payloads[target] = content
    for item in bundle['directories'].values():
        manifest['directories'][item['destination']] = {'mode': int(item['mode'], 8),
            'uid': os.getuid(), 'gid': os.getgid(), 'retention': 'retain'}
    return manifest, payloads


def prepare_host_parents(root, manifest):
    (root/'var/lib').mkdir(parents=True, exist_ok=True)
    declared = set(manifest['directories'])
    for logical in [*manifest['files'], *declared]:
        for parent in reversed(Path(logical).parents):
            if str(parent) == '/' or str(parent) in declared:
                continue
            if any(str(ancestor) in declared for ancestor in parent.parents):
                continue
            target = physical(root, str(parent))
            if not target.exists():
                target.mkdir(parents=True)
                target.chmod(0o755)


@pytest.fixture
def staged_whatsapp(tmp_path):
    output = tmp_path/'bundle'
    bundle = builder.build_bundle(PLUGIN, output, source_sha='a'*40)
    compiler = load('integration_manifest_compiler', PLUGIN/'scripts/admin_manifest.py')
    compiled = compiler.load_bundle(output, 'a'*40, uid=os.getuid(), gid=os.getgid(),
                                    expected_metadata_sha256=sha((output/'bundle.json').read_bytes()))
    prepared = compiler.prepare_action(compiled, empty('whatsapp'),
                                       adopted_sha256=compiler.manifest_digest(empty('whatsapp')))
    manifest, payloads = prepared['action']['after'], prepared['payloads']
    host = tmp_path/'host'; host.mkdir(mode=0o700)
    from host.installation import IDENTITY, Installation, identity_bytes
    marker = host / IDENTITY.relative_to('/')
    marker.parent.mkdir(parents=True)
    marker.write_bytes(identity_bytes(Installation.legacy())); marker.chmod(0o600)
    prepare_host_parents(host, manifest)
    return host, bundle, manifest, payloads


def apply(root, operation, before, after, payloads, fault=None):
    allowed = sorted(set(before['files']) | set(before['directories']) |
                     set(after['files']) | set(after['directories']))
    with filesystem.Root(root) as mapped:
        return filesystem.reconcile(mapped, operation_id=operation, before=before,
            after=after, payloads=payloads, allowed_paths=allowed, fault=fault)


def select_fixture_generation(host, bundle):
    # Simulate the separately authorized owner commit only after filesystem
    # publication. Full handoff gates are tested through their real adapter below.
    owner = host/'etc/develative-deploy/recovery-owners/whatsapp.json'
    owner.parent.mkdir(parents=True, exist_ok=True)
    value = {'protocol': 1, 'epoch': 'b'*32, 'state': 'dedicated',
             'generation': str(physical(host, bundle['generation']['destination'])),
             'manifest_sha256': bundle['generation']['manifest_sha256']}
    owner.write_text(json.dumps(value)); owner.chmod(0o600)
    (host/'var/lib/develative-deploy/whatsapp').mkdir(parents=True, exist_ok=True)


COLD_WA = r'''
import importlib.util,json,os,sys
from pathlib import Path
root=Path(sys.argv[1]);bootstrap=root/'usr/local/lib/develative-deploy/whatsapp-bootstrap'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
    return module
layout=load('installation_layout',bootstrap/'installation_layout.py')
layout.activate_installation(root=root,trusted_uid=os.getuid())
admin=load('release_admin',bootstrap/'release_admin.py')
for name,value in {'_TRUST_ROOT':root,'STATE':root/'var/lib/develative-deploy/whatsapp',
 'OWNER':root/'etc/develative-deploy/recovery-owners/whatsapp.json',
 'BOOTSTRAP':bootstrap,'ENTRYPOINT':bootstrap/'release_entry.py',
 'GENERATIONS':root/'usr/local/lib/develative-deploy/whatsapp-generations'}.items():
    setattr(admin,name,value)
admin.PUBLICATION_LOCK=admin.STATE/'publication.lock'
admin._trusted_uid=lambda uid:uid==os.getuid()
# Logical owner paths come from the real handoff; only this namespace adapter
# maps them into the temporary root. It does not change stored control bytes.
read_json=admin._read_json
def mapped_json(path,limit):
    value,encoded=read_json(path,limit)
    if path==admin.OWNER and not value['generation'].startswith(str(root)+'/'):
        value={**value,'generation':str(root/value['generation'].lstrip('/'))}
    return value,encoded
admin._read_json=mapped_json
entry=load('isolated_release_entry',bootstrap/'release_entry.py')
entry._TRUST_ROOT=root;entry._trusted_uid=admin._trusted_uid
# The real bootstrap recompiles its protected layout before each admission.
# Retain all those checks, then bind its fresh loader to the same synthetic
# filesystem root before generation code runs; never read the host's /etc.
original_admin_module=entry._admin_module
def rooted_admin_module():
    result=original_admin_module()
    sys.modules['installation_layout'].activate_installation(root=root,trusted_uid=os.getuid())
    return result
entry._admin_module=rooted_admin_module
os.geteuid=lambda:0
entry.main(['recovery','--check'])
'''


def cold_whatsapp(host):
    result = subprocess.run([sys.executable, '-I', '-B', '-c', COLD_WA, str(host)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value['project'] == 'whatsapp' and value['epoch'] == 'b'*32
    return value


def test_real_whatsapp_bundle_is_published_by_engine_and_boots_from_installed_bytes(staged_whatsapp):
    host, bundle, manifest, payloads = staged_whatsapp
    result = apply(host, '1'*32, empty('whatsapp'), manifest, payloads)
    assert result['phase'] == 'committed' and result['manifest'] == filesystem.validate_manifest(manifest)
    with filesystem.Root(host) as root:
        for path, expected in manifest['files'].items():
            assert root.snapshot(path) == {key: value for key, value in expected.items() if key != 'retention'}
    select_fixture_generation(host, bundle)
    check = cold_whatsapp(host)
    assert check['manifestSha256'] == bundle['generation']['manifest_sha256']
    assert check['generation'] == str(physical(host, bundle['generation']['destination']))
    assert not list(host.rglob('*.pyc'))


def test_removal_quarantine_preserves_real_store_revocations_jobs_and_current_data(staged_whatsapp):
    host, bundle, manifest, payloads = staged_whatsapp
    apply(host, '1'*32, empty('whatsapp'), manifest, payloads)
    # Use the actual schema/runtime to distinguish retained current state from
    # a toy database. The engine must never make this file a managed artifact.
    sys.path.insert(0, str(PLUGIN))
    from sally_whatsapp.store import Store
    data = host/'private-state'; data.mkdir()
    paths = []
    for tenant in ('first', 'second'):
        path = data/(tenant+'.sqlite'); store = Store(path)
        for state in ('submitted', 'uncertain'):
            key = tenant+'-'+state
            store.queue_action(key, tenant, 'messages_send_text',
                {'body': {'chatId': '393331112222@c.us', 'text': 'synthetic-current-'+key}})
            store.finish_send(key, state, 'true_393331112222@c.us_'+key)
        store.ingest({'id': 'synthetic-revocation-'+tenant, 'event': 'message.revoked',
                      'payload': {'revokedMessageId': 'true_393331112222@c.us_'+tenant+'-submitted'}})
        with store.db() as db:
            db.execute("INSERT INTO state(key,value) VALUES('post-snapshot','\"current\"')")
        paths.append(path)
    original = {path: path.read_bytes() for path in paths}
    removed = {'format': 1, 'owner': 'whatsapp', 'files': {}, 'directories': manifest['directories']}
    receipt = apply(host, '2'*32, manifest, removed, {})
    assert all(not physical(host, path).exists() for path in manifest['files'])
    assert all(physical(host, quarantine).is_file() for quarantine in receipt['quarantine'].values())
    assert {path: path.read_bytes() for path in paths} == original
    for tenant, path in zip(('first', 'second'), paths):
        with sqlite3.connect(path) as database:
            assert database.execute("SELECT value FROM state WHERE key='post-snapshot'").fetchone() == ('"current"',)
            assert database.execute('SELECT state FROM sends ORDER BY key').fetchall() == [('submitted',), ('uncertain',)]
            arguments = dict(database.execute('SELECT key,arguments FROM action_jobs'))
            assert arguments[tenant+'-submitted'] == '{}'
            assert 'synthetic-current-'+tenant+'-uncertain' in arguments[tenant+'-uncertain']


def test_other_owner_lock_is_real_and_does_not_block_whatsapp_publication(staged_whatsapp, tmp_path):
    host, bundle, manifest, payloads = staged_whatsapp
    lock = host/'var/lib/develative-host-lifecycle/box/lock'
    # parents=True applies mode only to the leaf; the control root also needs
    # its declared 0700 protection independently of the runner's umask.
    lock.parent.parent.mkdir(mode=0o700)
    lock.parent.mkdir(mode=0o700)
    lock.write_bytes(b''); lock.chmod(0o600)
    process = subprocess.Popen([sys.executable, '-I', '-B', '-c',
        'import fcntl,sys;f=open(sys.argv[1],"r+");fcntl.flock(f,fcntl.LOCK_EX);print("locked",flush=True);sys.stdin.readline()',
        str(lock)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert process.stdout.readline().strip() == 'locked'
        result = apply(host, '3'*32, empty('whatsapp'), manifest, payloads)
        assert result['phase'] == 'committed' and process.poll() is None
        select_fixture_generation(host, bundle)
        cold_whatsapp(host)
    finally:
        process.communicate('\n', timeout=10)


CRASH_RECONCILE = r'''
import base64,importlib.util,json,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('filesystem',sys.argv[1]);fs=importlib.util.module_from_spec(spec);spec.loader.exec_module(fs)
root,request,event=Path(sys.argv[2]),json.loads(Path(sys.argv[3]).read_text()),sys.argv[4]
request['payloads']={key:base64.b64decode(value) for key,value in request['payloads'].items()}
def crash(name,detail):
    if name==event:os._exit(73)
with fs.Root(root) as mapped:fs.reconcile(mapped,**request,fault=crash)
'''


@pytest.mark.parametrize('event', ['journal-staging', 'staged-file', 'journal-prepared',
    'journal-applying', 'created-directory', 'intent-file', 'replaced-file', 'completed-file', 'journal-committed'])
def test_whatsapp_install_crash_resumes_real_bundle_without_fresh_reset(staged_whatsapp, tmp_path, event):
    import base64
    host, bundle, manifest, payloads = staged_whatsapp
    allowed = sorted({*manifest['files'], *manifest['directories']})
    request = {'operation_id': '4'*32, 'before': empty('whatsapp'), 'after': manifest,
               'allowed_paths': allowed, 'payloads': {path: base64.b64encode(value).decode() for path, value in payloads.items()}}
    source = tmp_path/'request.json'; source.write_text(json.dumps(request))
    child = subprocess.run([sys.executable, '-I', '-B', '-c', CRASH_RECONCILE,
        str(REPOSITORY/'host/lifecycle/filesystem.py'), str(host), str(source), event],
        capture_output=True, text=True, timeout=20)
    assert child.returncode == 73, child.stderr
    journal = host/'var/lib/develative-host-lifecycle/whatsapp/operations'/('4'*32)/'journal.json'
    before = json.loads(journal.read_text())
    assert before['operation_id'] == '4'*32
    with filesystem.Root(host) as root:
        result = filesystem.resume(root, owner='whatsapp', operation_id='4'*32,
            allowed_paths=allowed, payloads=payloads)
    assert result['phase'] == 'committed'
    select_fixture_generation(host, bundle)
    cold_whatsapp(host)


ORPHAN_BARRIER = r'''
import ctypes,fcntl,hashlib,importlib.util,json,os,signal,subprocess,sys,time
from pathlib import Path
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module
sys.path.insert(0,str(Path(sys.argv[1]).resolve().parents[2]))
from host.lifecycle import evidence,filesystem
root=Path(sys.argv[3])
# This helper alone becomes a subreaper. Orphan fixture children are reaped
# here; pytest, unrelated processes and the host service manager are untouched.
assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
root.mkdir();(root/'var/lib').mkdir(parents=True);(root/'box').mkdir()
worker=root/'legacy.py';lock=root/'tenant.lock';lock.write_bytes(b'')
worker.write_text('import fcntl,json,os,subprocess,sys\n'
 'lock=open(sys.argv[1],"r+");fcntl.flock(lock,fcntl.LOCK_EX)\n'
 'child=subprocess.Popen([sys.executable,"-I","-B","-c","import os,sys;os.read(int(sys.argv[1]),1)",sys.argv[2]],pass_fds=(lock.fileno(),int(sys.argv[2])),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n'
 'print(json.dumps({"child":child.pid}),flush=True)\n'
 'sys.stdin.readline();os._exit(0)\n')
reader,writer=os.pipe();parent=None;child=None
try:
    # The final token carries the fixture's logical source path. The executed
    # source is the same physical file; PID/start/session/cgroup remain real.
    parent=subprocess.Popen([sys.executable,'-I','-B',str(worker),str(lock),str(reader),'/legacy.py'],
       stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,pass_fds=(reader,),start_new_session=True)
    child=json.loads(parent.stdout.readline())['child']
    view=root/'proc';(view/'sys/kernel/random').mkdir(parents=True)
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    (view/'sys/kernel/random/boot_id').write_text(boot)
    # A restricted view reads real /proc bytes for only our two children.
    # No unrelated cmdline is inspected and no process identity is fabricated.
    for pid in (parent.pid,child):(view/str(pid)).symlink_to(Path('/proc')/str(pid),target_is_directory=True)
    info=worker.stat();manifest={'format':1,'owner':'whatsapp','files':{'/legacy.py':{
       'sha256':hashlib.sha256(worker.read_bytes()).hexdigest(),'mode':info.st_mode&0o777,
       'uid':info.st_uid,'gid':info.st_gid,'retention':'managed'}},'directories':{}}
    scope={'cgroups':[],'script_roots':[],'script_paths':['/legacy.py']}
    def observe(prior=()):
       context={'format':1,'authority':'root-inventory','plan_digest':'a'*64,'invocation_id':'own-child-test',
         'generation_id':'b'*64,'inventory_digest':evidence.digest_inventory(scope,manifest,{},prior_processes=prior),'boot_id':boot}
       receipt=evidence.observe(scope,manifest,context=context,units={},fs_root=root,proc_root=view,
         runner=lambda *_args,**_kw:(_ for _ in ()).throw(AssertionError('no unit calls permitted')),prior_processes=prior)
       return receipt,context
    initial,context=observe()
    assert {row['pid'] for row in initial['snapshots'][-1]['processes']['processes']}=={parent.pid,child}
    try:evidence.require_quiescent(initial,context=context,now_ns=time.monotonic_ns())
    except evidence.EvidenceError:pass
    else:raise AssertionError('live worker was admitted')
    parent.communicate('\n',timeout=5);(view/str(parent.pid)).unlink()
    prior=initial['snapshots'][-1]['processes']['processes']
    orphan,context=observe(prior)
    assert [row['pid'] for row in orphan['snapshots'][-1]['processes']['processes']]==[child]
    try:evidence.require_quiescent(orphan,context=context,now_ns=time.monotonic_ns())
    except evidence.EvidenceError:pass
    else:raise AssertionError('late orphan was admitted')
    with lock.open('r+') as probe:
       try:fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
       except BlockingIOError:pass
       else:raise AssertionError('orphan lost the inherited tenant FD')
    # While the WA barrier is blocked, BOX still completes a real filesystem
    # transaction; no host/global publication lock is hidden in the observer.
    content=b'synthetic independent BOX generation\n';path='/box/generation.txt'
    before={'format':1,'owner':'box','files':{},'directories':{}}
    after={**before,'files':{path:{'sha256':hashlib.sha256(content).hexdigest(),'mode':0o644,
        'uid':os.getuid(),'gid':os.getgid(),'retention':'managed'}}}
    with filesystem.Root(root) as mapped:
       done=filesystem.reconcile(mapped,operation_id='5'*32,before=before,after=after,
           payloads={path:content},allowed_paths=[path])
    assert done['phase']=='committed' and (root/'box/generation.txt').read_bytes()==content
    os.write(writer,b'x');os.waitpid(child,0);(view/str(child)).unlink();child=None
    clear,context=observe(prior)
    assert evidence.require_quiescent(clear,context=context,now_ns=time.monotonic_ns())['quiescent']
    with lock.open('r+') as probe:fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
    print(json.dumps({'blocked_parent':True,'blocked_orphan':True,'inherited_lock':True,
                      'survivor_transaction':'committed','quiescent_after_exit':True}))
finally:
    os.close(reader);os.close(writer)
    if parent is not None and parent.poll() is None:
       parent.kill();parent.wait()
    if child is not None:
       try:os.kill(child,signal.SIGKILL)
       except ProcessLookupError:pass
       try:os.waitpid(child,0)
       except ChildProcessError:pass
'''


def test_real_orphan_inherited_lock_blocks_barrier_while_other_owner_completes(tmp_path):
    result = subprocess.run([sys.executable, '-I', '-B', '-c', ORPHAN_BARRIER,
        str(REPOSITORY/'host/lifecycle/evidence.py'), str(REPOSITORY/'host/lifecycle/filesystem.py'),
        str(tmp_path/'host')], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {'blocked_parent': True, 'blocked_orphan': True,
        'inherited_lock': True, 'survivor_transaction': 'committed', 'quiescent_after_exit': True}


def test_handoff_staged_checkpoint_survives_new_observation_on_resume(tmp_path):
    # Focused fault regression: the phase fixture substitutes host services,
    # while its evidence collector, real engine and durable journal stay intact.
    contract = load('integration_handoff_contract', PLUGIN/'tests/test_admin_handoff.py')
    root, plan, payloads, provider = contract.fixture(tmp_path, mode='fresh')
    class Crash(BaseException):
        pass
    class InterruptedFilesystem:
        validate_manifest = staticmethod(contract.filesystem.validate_manifest)
        resume = staticmethod(contract.filesystem.resume)
        @staticmethod
        def reconcile(*args, **kwargs):
            def crash(event, detail):
                if event == 'staged-file' and detail['path'] == plan['journal']['path']:
                    raise Crash()
            return contract.filesystem.reconcile(*args, **kwargs, fault=crash)
    with root:
        contract.advance(root, plan, payloads, provider, until='installed')
        with pytest.raises(Crash):
            contract.handoff.handoff(root, plan, payloads, provider, filesystem=InterruptedFilesystem)
        assert json.loads(root.read_bytes(plan['journal']['path']))['phase'] == 'installed'
        assert 'arm-whatsapp' not in provider.calls
        assert contract.advance(root, plan, payloads, provider)['phase'] == 'verified'


def real_handoff_fixture(host, bundle, manifest, payloads, temporary):
    """Actual adapter, gate, evidence, locks and bundle; only systemd is local.

    The process census is an explicitly empty synthetic boot. The earlier own
    orphan test independently exercises the collector against actual processes.
    """
    from host.lifecycle import evidence, services
    sys.path.insert(0, str(PLUGIN/'scripts'))
    handoff = load('admin_handoff', PLUGIN/'scripts/admin_handoff.py')
    adapter = load('integration_complete_adapter', PLUGIN/'scripts/admin_host.py')
    proc = temporary/'processes'
    boot = proc/'sys/kernel/random/boot_id'; boot.parent.mkdir(parents=True)
    boot.write_text('11111111-2222-3333-4444-555555555555\n')
    for logical in services.WA_LOCKS:
        physical(host, logical).parent.mkdir(parents=True, exist_ok=True)
    physical(host, '/var/lib/develative-deploy/whatsapp').chmod(0o700)
    attestation = '/etc/develative-deploy/inventory/integration.json'
    attested = evidence.canonical({'format': 2, 'complete': True, 'invokers': [],
        'manual_policy': {'operation_id': '6'*32, 'unregistered_root_commands': 'frozen-for-operation'}})
    target = physical(host, attestation); target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(attested); target.chmod(0o600)
    scope = {'cgroups': ['/isolated-whatsapp'], 'script_paths': [], 'script_roots': []}
    initial = empty('whatsapp')
    initial['directories'] = {path: spec for path, spec in manifest['directories'].items()
                              if physical(host, path).exists()}
    profile = {'format': 'whatsapp-host-inventory-v1', 'attestation': {
        'path': attestation, 'sha256': sha(attested)}, 'retirement_attestation': None,
        'stages': {'inventory': {'scope': scope, 'manifest': initial, 'units': {}},
                   'installed': {'scope': scope, 'manifest': manifest, 'units': {}}},
        'final_manifest': manifest, 'retained_manifest': empty('whatsapp'),
        'invokers': [], 'generation_id': bundle['generation']['manifest_sha256']}
    private = {'mode': 0o700, 'uid': os.getuid(), 'gid': os.getgid(), 'retention': 'retain'}
    plan = {'format': handoff.FORMAT, 'id': '6'*32, 'mode': 'fresh',
        'inventory_digest': evidence.digest(profile), 'evidence_digests': {
            stage: evidence.digest_inventory(item['scope'], item['manifest'], item['units'])
            for stage, item in profile['stages'].items()},
        'owner': {'protocol': 1, 'epoch': 'b'*32, 'state': 'dedicated',
                  'generation': bundle['generation']['destination'],
                  'manifest_sha256': bundle['generation']['manifest_sha256']},
        'previous_owner': None, 'owner_metadata': {'mode': 0o600, 'uid': os.getuid(), 'gid': os.getgid()},
        'journal': {'path': '/var/lib/develative-deploy/whatsapp/handoff/'+('6'*32)+'.json',
                    'mode': 0o600, 'uid': os.getuid(), 'gid': os.getgid()},
        'control_directories': {path: private for path in (
            '/etc/develative-deploy/recovery-owners', '/var/lib/develative-deploy/whatsapp/handoff')},
        'actions': {'install': {'before': initial, 'after': manifest,
            'allowed_paths': sorted({*initial['directories'], *manifest['directories'], *manifest['files']})}}}
    calls = []
    effective = {'armed': False, 'enabled': False}
    def systemd(operation, *, pass_fds):
        # Assert the real lease descriptor remains open during the finite call.
        assert len(pass_fds) == 1
        os.fstat(pass_fds[0]); calls.append(operation)
        if operation == 'start-wa-recovery': effective['armed'] = True
        if operation == 'stop-wa-recovery': effective['armed'] = False
        if operation == 'enable-wa-recovery': effective['enabled'] = True
        if operation == 'disable-wa-recovery': effective['enabled'] = False
    def read_systemd(argv, **limits):
        unit = argv[-1]
        assert unit in services.WA_RECOVERY
        result = {key: '' for key in services.RECOVERY_PROPERTIES[unit]}
        result.update(Id=unit, LoadState='loaded', NeedDaemonReload='no',
                      FragmentPath='/etc/systemd/system/'+unit, Job='0')
        if unit.endswith('.timer'):
            result.update(ActiveState='active' if effective['armed'] else 'inactive',
                SubState='waiting' if effective['armed'] else 'dead',
                UnitFileState='enabled' if effective['enabled'] else 'disabled', Unit=services.WA_RECOVERY[0],
                TimersMonotonic='{ OnBootUSec=45s; next_elapse=0 } { OnUnitInactiveUSec=1min; next_elapse=0 }')
        else:
            result.update(Type='oneshot', User='root', KillMode='control-group', RemainAfterExit='no',
                Restart='no', TimeoutStartUSec='10min', ActiveState='inactive', SubState='dead',
                MainPID='0', ControlPID='0',
                ExecStart='{ path=/usr/bin/python3; argv[]=/usr/bin/python3 -I -B '+services.RECOVERY_ENTRYPOINT+' recovery; }')
        return ''.join(key+'='+value+'\n' for key, value in result.items()).encode()
    root = filesystem.Root(host)
    provider = adapter.AdminHost(root, profile, proc_root=proc,
        readonly_runner=read_systemd, service_runner=systemd)
    return root, handoff, plan, {'install': payloads}, provider, calls


def test_complete_real_adapter_handoff_admits_installed_bundle_only_after_service_verification(staged_whatsapp, tmp_path):
    host, bundle, manifest, payloads = staged_whatsapp
    root, handoff, plan, actions, provider, calls = real_handoff_fixture(host, bundle, manifest, payloads, tmp_path)
    states = []
    with root:
        for _ in range(15):
            result = handoff.handoff(root, plan, actions, provider)
            assert not result['pending']
            states.append(result['phase'])
            owner = root.snapshot(handoff.OWNER)
            if owner is not None:
                expected = 'dedicated' if result['phase'] in ('owner_dedicated', 'verified') else 'transitioning'
                assert json.loads(root.read_bytes(handoff.OWNER))['state'] == expected
            if result['phase'] == 'verified': break
        assert states == list(handoff.PHASES['fresh'])
        assert calls == ['reload-definitions', 'enable-wa-recovery', 'start-wa-recovery']
        assert handoff.handoff(root, plan, actions, provider)['phase'] == 'verified'
        assert len(calls) == 3
    check = cold_whatsapp(host)
    assert check['manifestSha256'] == bundle['generation']['manifest_sha256']


DEFAULT_BOX_REPOSITORY = REPOSITORY/'work/BOX-admin-separation'
# Reviewed configurable pair, including the protected installation identity and
# controller/layout closure. These cases attest installed administration.
EXPECTED_BOX_REVISION = 'de083bcb3d5dd661c7eeda58359be9751a28d1c8'


@pytest.fixture(scope='module')
def box_source():
    """Only cross-repository cases require the separately prepared BOX tree."""
    explicit = os.environ.get('BOX_ADMIN_SOURCE')
    if explicit is not None and not explicit.strip():
        pytest.fail('BOX_ADMIN_SOURCE must name a prepared BOX repository, not an empty path', pytrace=False)
    candidate = os.environ.get('BOX_ADMIN_CANDIDATE_SHA')
    if candidate is not None and (explicit is None or re.fullmatch('[a-f0-9]{40}', candidate) is None):
        pytest.fail('Candidate mode requires BOX_ADMIN_SOURCE and an explicit 40-character BOX_ADMIN_CANDIDATE_SHA',
                    pytrace=False)
    expected_revision = candidate if candidate is not None else EXPECTED_BOX_REVISION
    repository = Path(explicit).absolute() if explicit is not None else DEFAULT_BOX_REPOSITORY
    source = repository/'projects/box'
    if not source.is_dir():
        if explicit is not None:
            pytest.fail('BOX_ADMIN_SOURCE has no projects/box directory: ' + str(repository), pytrace=False)
        pytest.skip('Cross-repository lifecycle case requires a prepared BOX checkout; set BOX_ADMIN_SOURCE')
    missing = [name for name in ('bin/build_admin_bundle.py', 'bin/release_recover.py')
               if not (source/name).is_file()]
    if missing:
        pytest.fail('Prepared BOX checkout is incomplete: ' + ', '.join(missing), pytrace=False)
    try:
        revision = subprocess.run(['git', '--no-pager', '-C', str(repository), 'rev-parse', 'HEAD'],
                                  capture_output=True, text=True, timeout=10)
        if revision.returncode != 0 or revision.stdout.strip() != expected_revision:
            pytest.fail('BOX checkout must be at pinned revision ' + expected_revision, pytrace=False)
        clean = subprocess.run(['git', '--no-pager', '-C', str(repository), 'diff', '--no-ext-diff',
                                '--quiet', expected_revision, '--'], capture_output=True, timeout=10)
        if clean.returncode != 0:
            pytest.fail('BOX checkout has tracked changes or cannot be verified against its pinned revision', pytrace=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        pytest.fail('Cannot verify the prepared BOX checkout with local Git: ' + str(error), pytrace=False)
    return source


def box_payload(host, source, output):
    """Use real builder bytes; remap only absolute config/manifest fixture paths."""
    # A combined suite already has the WhatsApp layout in the canonical slot.
    # Give the BOX compiler its own explicit offline identity for this build,
    # then restore the previous module even if import or compilation fails.
    previous = sys.modules.get('installation_layout')
    try:
        layout = load('installation_layout', source/'bin/installation_layout.py')
        layout.select(layout.Installation.legacy())
        box_builder = load('integration_box_builder', source/'bin/build_admin_bundle.py')
        bundle = box_builder.build_bundle(source, output, source_sha='a'*40, enabled=True)
    finally:
        if previous is None:
            sys.modules.pop('installation_layout', None)
        else:
            sys.modules['installation_layout'] = previous
    marker = host / layout.IDENTITY.relative_to('/')
    marker.parent.mkdir(parents=True, exist_ok=True)
    expected_identity = layout.identity_bytes(layout.Installation.legacy())
    if marker.exists():
        assert not marker.is_symlink() and marker.read_bytes() == expected_identity
    else:
        marker.write_bytes(expected_identity); marker.chmod(0o600)
    manifest = json.loads(json.dumps(bundle['filesystem_manifest']))
    for collection in ('files', 'directories'):
        for spec in manifest[collection].values():
            spec.update(uid=os.getuid(), gid=os.getgid())
    payloads = {item['destination']: (output/name).read_bytes() for name, item in bundle['artifacts'].items()}
    config_path = '/etc/develative-deploy/box.json'
    config = json.loads(payloads[config_path])
    config['controller'] = str(physical(host, config['controller']))
    payloads[config_path] = box_builder.encoded(config)
    admission_path = bundle['admission']['manifest']
    admission = json.loads(payloads[admission_path])
    admission['controller'] = config['controller']
    admission['files'] = {str(physical(host, path)): sha(payloads[path]) for path in admission['files']}
    payloads[admission_path] = box_builder.encoded(admission)
    for path, data in payloads.items(): manifest['files'][path]['sha256'] = sha(data)
    bundle['admission']['manifest_sha256'] = sha(payloads[admission_path])
    return bundle, manifest, payloads


def select_box_fixture_owner(host, bundle):
    target = physical(host, bundle['admission']['owner'])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o700)
    target.write_text(json.dumps({'protocol': 1, 'epoch': 'a'*32, 'state': 'dedicated',
                                  'manifest_sha256': bundle['admission']['manifest_sha256']}))
    target.chmod(0o600)


COLD_BOX = r'''
import importlib.util,json,os,sys
from pathlib import Path
root=Path(sys.argv[1]);helpers=root/'usr/local/lib/develative-deploy/box'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
    return module
layout=load('installation_layout',helpers/'installation_layout.py')
layout.activate_installation(root=root,uid=os.getuid())
admin=load('release_admin',helpers/'release_admin.py')
for name in ('HELPERS','OWNER','MANIFEST','CONFIG','RECOVERY','CONTROLLERS','PUBLICATION_LOCK'):
    setattr(admin,name,root/str(getattr(admin,name)).lstrip('/'))
admin._TRUST_ROOT=root;admin._trusted_uid=lambda uid:uid==os.getuid()
os.geteuid=lambda:0
recovery=load('isolated_box_recovery',admin.RECOVERY)
recovery.HELPERS=admin.HELPERS;recovery.CONFIG=admin.CONFIG
sys.argv=[str(admin.RECOVERY),'--check']
assert recovery.main()==0
'''


def cold_box(host):
    result = subprocess.run([sys.executable, '-I', '-B', '-c', COLD_BOX, str(host)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value['project'] == 'box' and value['epoch'] == 'a'*32
    return value


def quarantine_application_roots(host, owner, quarantine):
    # This is a test of total absence after nominal removal, not an uninstall
    # implementation. Never move shared parents or another consumer's state.
    paths = (['/usr/local/lib/develative-deploy/whatsapp',
              '/usr/local/lib/develative-deploy/whatsapp-bootstrap',
              '/usr/local/lib/develative-deploy/whatsapp-generations',
              '/srv/openai-codex/projects/whatsapp-personal',
              '/var/lib/develative-deploy/whatsapp',
              '/etc/develative-deploy/recovery-owners/whatsapp.json'] if owner == 'whatsapp' else
             ['/usr/local/lib/develative-deploy/box', '/var/lib/box-release-channels',
              '/var/lib/develative-deploy/box', '/etc/develative-deploy/box.json',
              '/etc/develative-deploy/recovery-owners/box.json',
              '/etc/develative-deploy/recovery-owners/box-files.json'])
    quarantine.mkdir()
    moved = []
    for index, path in enumerate(paths):
        source = physical(host, path)
        if source.exists():
            source.rename(quarantine/str(index)); moved.append(source)
    return moved


@pytest.mark.parametrize('removed', ['whatsapp', 'box'])
@pytest.mark.parametrize('partial', [False, True])
def test_bidirectional_real_bundle_survival_partial_removal_absence_and_update(box_source, staged_whatsapp, tmp_path, removed, partial):
    host, wa_bundle, wa_manifest, wa_payloads = staged_whatsapp
    box_bundle, box_manifest, box_payloads = box_payload(host, box_source, tmp_path/'box-bundle')
    prepare_host_parents(host, box_manifest)
    apply(host, '7'*32, empty('box'), box_manifest, box_payloads)
    select_box_fixture_owner(host, box_bundle)
    apply(host, '8'*32, empty('whatsapp'), wa_manifest, wa_payloads)
    select_fixture_generation(host, wa_bundle)
    cold_box(host); cold_whatsapp(host)
    manifests = {'box': box_manifest, 'whatsapp': wa_manifest}
    target = manifests[removed]
    survivor = 'box' if removed == 'whatsapp' else 'whatsapp'
    check = cold_box if survivor == 'box' else cold_whatsapp
    # Existing lock identity is independent of helper and owner lifecycles.
    lock = physical(host, '/var/lib/develative-deploy/'+('publication.lock' if survivor == 'box' else 'whatsapp/publication.lock'))
    lock.write_bytes(b'preserve inode'); lock.chmod(0o600); inode = lock.stat().st_ino
    after = {**target, 'files': {path: spec for path, spec in target['files'].items() if spec['retention'] == 'retain'}}
    class Crash(BaseException): pass
    def fault(event, detail):
        if event == 'removed-file': raise Crash()
    if partial:
        with pytest.raises(Crash): apply(host, '9'*32, target, after, {}, fault=fault)
        assert any(physical(host, path).exists() for path in target['files'] if path not in after['files'])
        assert any(not physical(host, path).exists() for path in target['files'] if path not in after['files'])
        check(host)
        with filesystem.Root(host) as root:
            filesystem.resume(root, owner=removed, operation_id='9'*32,
                allowed_paths=sorted({*target['files'], *target['directories']}))
    else:
        apply(host, '9'*32, target, after, {})
    absent = quarantine_application_roots(host, removed, tmp_path/'quarantined-application')
    check(host)
    # A genuine code update is built and reconciled while the other application
    # is physically absent. Only source/config namespace mapping is synthetic.
    source = tmp_path/'updated-source'; source.mkdir()
    original = box_source if survivor == 'box' else PLUGIN
    for folder in (('bin', 'deploy') if survivor == 'box' else ('scripts', 'deploy')):
        shutil.copytree(original/folder, source/folder)
    probe = source/('bin/release_probe.mjs' if survivor == 'box' else 'scripts/release_probe.py')
    with probe.open('ab') as stream: stream.write(b'\n')
    if survivor == 'box':
        updated, wanted, content = box_payload(host, source, tmp_path/'updated-bundle')
    else:
        updated = builder.build_bundle(source, tmp_path/'updated-bundle', source_sha='c'*40)
        wanted, content = manifest_from_bundle(tmp_path/'updated-bundle', updated)
        wanted['directories'] = {**manifests[survivor]['directories'], **wanted['directories']}
        for path, spec in manifests[survivor]['files'].items():
            if path not in wanted['files']:
                wanted['files'][path] = {**spec, 'retention': 'retain'}
    apply(host, 'a'*32, manifests[survivor], wanted, content)
    (select_box_fixture_owner if survivor == 'box' else select_fixture_generation)(host, updated)
    check(host)
    assert lock.stat().st_ino == inode and lock.read_bytes() == b'preserve inode'
    assert all(not path.exists() for path in absent)


LOADED_LEGACY_PARENT = r'''
import os,subprocess,sys
from pathlib import Path
path=Path(sys.argv[1]);source=compile(path.read_bytes(),str(path),'exec')
real_run=subprocess.run
def controlled(argv,**kwargs):
    if argv[-1]=='box':
        print('loaded-before-cut',flush=True)
        assert sys.stdin.readline().strip()=='resume'
        return subprocess.CompletedProcess(argv,0,'','')
    result=real_run(argv,**kwargs)
    assert argv[-1]=='whatsapp' and result.returncode==0 and not result.stdout and not result.stderr
    print('late-whatsapp-noop',flush=True)
    return result
subprocess.run=controlled;os.geteuid=lambda:0;sys.argv=[str(path)]
exec(source,{'__name__':'__main__','__file__':str(path)})
'''


def test_real_adapter_legacy_handoff_drains_loaded_parent_and_late_whatsapp_exec(box_source, staged_whatsapp, tmp_path):
    from host.lifecycle import evidence
    host, bundle, manifest, payloads = staged_whatsapp
    root, handoff, plan, actions, provider, calls = real_handoff_fixture(host, bundle, manifest, payloads, tmp_path)
    legacy = (Path(__file__).parent/'fixtures/legacy_shared_recover_04164aa.py').read_bytes()
    assert sha(legacy) == 'd4d6072354caeb75f7f4e38b850c9b57de56000493e066dc712cd8c76f5c49b7'
    replacement = (box_source/'bin/release_recover.py').read_bytes()
    receiver = b'"""Synthetic already-installed receiver."""\nVALUE=1\n'
    guard = handoff.guarded_legacy_source(receiver, sha(receiver))
    fixture_names = {handoff.BACKUP_ENTRY: 'backup_runtime_049.py.txt',
        handoff.TENANT_ENTRY: 'tenant_admin_pro8_20261017.py.txt',
        handoff.PROVISION_ENTRY: 'provision_host_pro8_20261017.py.txt'}
    old_destinations = {path: (PLUGIN/'tests/fixtures'/name).read_bytes() for path, name in fixture_names.items()}
    closed_destinations = {path: handoff.guarded_legacy_destination(path, content)
                           for path, content in old_destinations.items()}
    for logical, data in {handoff.DISPATCHER: legacy, handoff.RECEIVER: receiver,
                          **old_destinations, handoff.RUNTIME: payloads[handoff.RUNTIME]}.items():
        path = physical(host, logical); path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data); path.chmod(0o644)
    # Existing helper directory matches the explicitly inventoried layout.
    physical(host, handoff.RECEIVER).parent.chmod(0o755)
    physical(host, handoff.BACKUP_ENTRY).parent.chmod(0o755)
    def small(files, owner='whatsapp'):
        return {**empty(owner), 'files': {path: metadata(data) for path, data in files.items()}}
    before = small({handoff.RECEIVER: receiver, **old_destinations})
    gated = small({handoff.RECEIVER: guard, **closed_destinations})
    dispatcher_before = small({handoff.DISPATCHER: legacy}, owner='box')
    dispatcher_after = small({handoff.DISPATCHER: replacement}, owner='box')
    def action(first, last):
        return {'before': first, 'after': last,
                'allowed_paths': sorted({*first['files'], *last['files'], *first['directories'], *last['directories']})}
    installed_before = {**gated, 'files': {**gated['files'], handoff.RUNTIME: manifest['files'][handoff.RUNTIME]},
        'directories': {path: spec for path, spec in manifest['directories'].items() if physical(host, path).exists()}}
    plan['mode'] = 'legacy'
    plan['actions'] = {'guard_ingress': action(before, gated),
        'cut_dispatcher': action(dispatcher_before, dispatcher_after), 'install': action(installed_before, manifest)}
    actions = {'guard_ingress': {handoff.RECEIVER: guard, **closed_destinations},
               'cut_dispatcher': {handoff.DISPATCHER: replacement}, 'install': payloads}
    work_scope = {'script_paths': [handoff.RECEIVER, *old_destinations], 'script_roots': [], 'cgroups': []}
    all_scope = {'script_paths': [handoff.RECEIVER, *old_destinations, handoff.DISPATCHER], 'script_roots': [], 'cgroups': []}
    profile = json.loads(json.dumps(provider.profile))
    profile['stages'] = {
        'inventory': {'scope': all_scope, 'manifest': small({handoff.RECEIVER: receiver, **old_destinations, handoff.DISPATCHER: legacy}), 'units': {}},
        'legacy_work': {'scope': work_scope, 'manifest': small({handoff.RECEIVER: guard, **closed_destinations, handoff.DISPATCHER: legacy}), 'units': {}},
        'legacy_all': {'scope': all_scope, 'manifest': small({handoff.RECEIVER: guard, **closed_destinations, handoff.DISPATCHER: replacement}), 'units': {}},
        'installed': {'scope': {'script_paths': list(old_destinations), 'script_roots': [], 'cgroups': ['/isolated-whatsapp']},
                       'manifest': json.loads(json.dumps(manifest)), 'units': {}}}
    # Real public unit bytes, with observed inverse deliberately empty. The
    # destination guard closes every main invocation; inverse-cache presence
    # is neither used nor fabricated as proof of complete admission.
    backup_units = {}
    for name in ('whatsapp-personal-backup.timer', 'whatsapp-personal-backup.service'):
        logical = '/etc/systemd/system/' + name
        content = (PLUGIN/'deploy'/name).read_bytes()
        selected = physical(host, logical); selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_bytes(content); selected.chmod(0o644)
        expected = {'fragment_path': logical, 'drop_in_paths': [], 'scope_cgroup': None,
            'references': {key: [] for key in evidence.REFERENCE_PROPERTIES},
            'state': {'ActiveState': 'inactive', 'SubState': 'dead'}}
        if name.endswith('.timer'):
            expected['references']['Triggers'] = ['whatsapp-personal-backup.service']
            expected['state']['UnitFileState'] = 'disabled'
        else:
            expected['execution'] = sys.modules[provider.__class__.__module__].backup_execution_contract()
        backup_units[name] = expected
        for stage in profile['stages'].values():
            stage['manifest']['files'][logical] = {**metadata(content), 'retention': 'retain'}
            stage['units'][name] = expected
    plan['actions']['install'] = action(installed_before, manifest)
    unit = 'develative-release-recovery.service'
    unit_path = '/etc/systemd/system/'+unit
    reference = '/etc/develative-deploy/inventory/receiver-reference.json'
    unit_bytes = ('[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -I '+handoff.DISPATCHER+'\n').encode()
    for logical, value in ((unit_path, unit_bytes), (reference, b'{"synthetic_receiver_binding":true}\n')):
        selected = physical(host, logical); selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_bytes(value); selected.chmod(0o644)
    physical(host, unit_path).parent.chmod(0o755)
    inventory = profile['stages']['inventory']
    inventory['manifest']['files'][unit_path] = metadata(unit_bytes)
    inventory['manifest']['files'][reference] = metadata(physical(host, reference).read_bytes())
    inventory['scope']['cgroups'] = ['/system.slice/'+unit]
    inventory['units'][unit] = {'fragment_path': unit_path, 'drop_in_paths': [],
        'references': {name: [] for name in evidence.REFERENCE_PROPERTIES}, 'scope_cgroup': '/system.slice/'+unit}
    profile['invokers'] = [
        {'id': 'synthetic-receiver', 'kind': 'ssh-forced-command', 'executable': '/usr/bin/python3',
         'argv_sha256': sha(('/usr/bin/python3 -I '+handoff.RECEIVER).encode()), 'reference': reference,
         'role': 'legacy-receiver', 'entrypoint': handoff.RECEIVER, 'launch_mode': 'python-main',
         'gate': {'mechanism': 'legacy-main-guard', 'path': handoff.RECEIVER}},
        {'id': 'synthetic-global-recovery', 'kind': 'systemd', 'executable': '/usr/bin/python3',
         'argv_sha256': sha(('/usr/bin/python3 -I '+handoff.DISPATCHER).encode()), 'reference': unit_path,
         'role': 'global-recovery', 'entrypoint': handoff.DISPATCHER, 'launch_mode': 'python-main',
         'gate': {'mechanism': 'dispatcher-cut', 'path': handoff.DISPATCHER}}]
    attested = evidence.canonical({'format': 2, 'complete': True, 'invokers': profile['invokers'],
        'manual_policy': {'operation_id': plan['id'], 'unregistered_root_commands': 'frozen-for-operation'}})
    physical(host, profile['attestation']['path']).write_bytes(attested)
    profile['attestation']['sha256'] = sha(attested)
    original_reader = provider.runner
    def read_with_global(argv, **limits):
        if argv[0] == '/usr/bin/busctl':
            commands = []
            if argv[-1] == 'ExecStart':
                commands = [['/usr/bin/flock', ['/usr/bin/flock', '-n', '/run/lock/whatsapp-personal-backup.lock',
                    '/srv/openai-codex/projects/whatsapp-personal/.venv/bin/python', handoff.BACKUP_ENTRY],
                    False, 0, 0, 0, 0, 0, 0, 0]]
            return json.dumps({'type': 'a(sasbttttuii)', 'data': commands}).encode()
        if argv[-1] in backup_units:
            name = argv[-1]; expected = backup_units[name]
            values = {key: '' for key in evidence.unit_properties(name)}
            values.update(Id=name, LoadState='loaded', ActiveState='inactive', SubState='dead',
                Job='0', FragmentPath=expected['fragment_path'], NeedDaemonReload='no',
                UnitFileState='disabled')
            if name.endswith('.service'): values.update(MainPID='0', ControlPID='0')
            else: values['Triggers'] = 'whatsapp-personal-backup.service'
            return ''.join(key+'='+value+'\n' for key, value in values.items()).encode()
        if argv[-1] != unit: return original_reader(argv, **limits)
        values = {name: '' for name in evidence.unit_properties(unit)}
        values.update(Id=unit, LoadState='loaded', ActiveState='inactive', SubState='dead',
            Job='0', FragmentPath=unit_path, NeedDaemonReload='no')
        if unit.endswith('.service'):
            values.update(MainPID='0', ControlPID='0', ControlGroup='')
        return ''.join(key+'='+value+'\n' for key, value in values.items()).encode()
    provider.runner = read_with_global
    plan['inventory_digest'] = evidence.digest(profile)
    plan['evidence_digests'] = {stage: evidence.digest_inventory(item['scope'], item['manifest'], item['units'])
                               for stage, item in profile['stages'].items()}
    provider.profile = profile; provider.profile_digest = plan['inventory_digest']
    # Real boot identity and ONLY our own child /proc directory. No other
    # process command lines are inspected by this fixture.
    boot = provider.proc_root/'sys/kernel/random/boot_id'
    boot.write_bytes(Path('/proc/sys/kernel/random/boot_id').read_bytes())
    parent = None
    try:
        with root:
            assert handoff.handoff(root, plan, actions, provider)['phase'] == 'prepared'
            parent = subprocess.Popen([sys.executable, '-I', '-B', '-c', LOADED_LEGACY_PARENT,
                str(physical(host, handoff.DISPATCHER)), handoff.DISPATCHER], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert parent.stdout.readline().strip() == 'loaded-before-cut'
            (provider.proc_root/str(parent.pid)).symlink_to(Path('/proc')/str(parent.pid), target_is_directory=True)
            for expected in ('transitioning', 'ingress_closed', 'legacy_reconciled', 'dispatcher_cut'):
                result = handoff.handoff(root, plan, actions, provider)
                assert result['phase'] == expected and not result['pending']
            assert physical(host, handoff.DISPATCHER).read_bytes() == replacement
            blocked = handoff.handoff(root, plan, actions, provider)
            assert blocked['phase'] == 'dispatcher_cut' and blocked['pending']
            assert json.loads(root.read_bytes(handoff.OWNER))['state'] == 'transitioning'
            assert calls == []
            output, errors = parent.communicate('resume\n', timeout=10)
            assert parent.returncode == 0 and output.strip() == 'late-whatsapp-noop' and not errors
            (provider.proc_root/str(parent.pid)).unlink()
            for _ in range(10):
                result = handoff.handoff(root, plan, actions, provider)
                assert not result['pending']
                if result['phase'] == 'verified': break
            assert result['phase'] == 'verified'
            assert root.read_bytes(handoff.RUNTIME) == payloads[handoff.RUNTIME]
        cold_whatsapp(host)
    finally:
        if parent is not None and parent.poll() is None:
            parent.kill(); parent.communicate(timeout=10)


def test_real_whatsapp_removal_handoff_keeps_box_cold_bootable_at_every_phase(box_source, staged_whatsapp, tmp_path):
    from host.lifecycle import evidence
    host, bundle, manifest, content = staged_whatsapp
    box_bundle, box_manifest, box_content = box_payload(host, box_source, tmp_path/'box-bundle')
    prepare_host_parents(host, box_manifest)
    apply(host, '7'*32, empty('box'), box_manifest, box_content)
    select_box_fixture_owner(host, box_bundle)
    root, handoff, install, actions, provider, calls = real_handoff_fixture(host, bundle, manifest, content, tmp_path)
    with root:
        for _ in range(15):
            if handoff.handoff(root, install, actions, provider)['phase'] == 'verified': break
        cold_whatsapp(host); cold_box(host)
        current_owner = json.loads(root.read_bytes(handoff.OWNER))
        retained = {**manifest, 'files': {handoff.RUNTIME: manifest['files'][handoff.RUNTIME]}}
        removable = {**manifest, 'files': {path: spec for path, spec in manifest['files'].items()
                                           if path != handoff.RUNTIME}}
        plan = json.loads(json.dumps(install))
        plan.update(id='c'*32, mode='remove', previous_owner=current_owner)
        plan['runtime_retirement'] = {'operation_id': 'd'*32}
        plan['journal']['path'] = '/var/lib/develative-deploy/whatsapp/handoff/'+('c'*32)+'.json'
        allowed = sorted({*removable['files'], *removable['directories']})
        plan['actions'] = {'close_invokers': {'before': removable, 'after': removable, 'allowed_paths': allowed},
                           'remove': {'before': removable, 'after': {**removable, 'files': {}}, 'allowed_paths': allowed}}
        actions = {'close_invokers': {}, 'remove': {}}
        final = '/etc/develative-deploy/inventory/retired.json'
        absence = evidence.canonical({'format': 3, 'complete': True, 'invokers': [],
                                      'operation_id': plan['id'], 'epoch': current_owner['epoch'],
                                      'references': {}})
        physical(host, final).write_bytes(absence); physical(host, final).chmod(0o600)
        profile = json.loads(json.dumps(provider.profile))
        initial_attested = evidence.canonical({'format': 2, 'complete': True, 'invokers': [],
            'manual_policy': {'operation_id': plan['id'], 'unregistered_root_commands': 'frozen-for-operation'}})
        physical(host, profile['attestation']['path']).write_bytes(initial_attested)
        profile['attestation']['sha256'] = sha(initial_attested)
        profile['retirement_attestation'] = {'path': final, 'sha256': sha(absence)}
        stage = {'scope': {'cgroups': ['/isolated-whatsapp'], 'script_paths': [], 'script_roots': []},
                 'manifest': manifest, 'units': {}}
        profile['stages'] = {'inventory': stage, 'removal': stage}
        profile['final_manifest'] = retained
        plan['inventory_digest'] = evidence.digest(profile)
        plan['evidence_digests'] = {name: evidence.digest_inventory(item['scope'], item['manifest'], {})
                                   for name, item in profile['stages'].items()}
        provider.profile = profile; provider.profile_digest = plan['inventory_digest']
        # This fixture has no application workload. Publish its explicit,
        # completed runtime receipt only after binding the final admin plan;
        # the actual AdminHost verifier remains in the path.
        with pytest.raises(ValueError):
            provider.verify_runtime_retirement(plan)
        runtime = {'format': 'whatsapp-runtime-retirement-v1', 'operation_id': 'd'*32,
            'admin_plan_sha256': handoff.digest(plan), 'plan_sha256': 'e'*64,
            'phase': 'verified', 'intent': None, 'processes': [],
            'receipts': {'frontend': {'phase': 'complete'}, 'renewals': {'status': 'retired'}}}
        runtime_path = physical(host, '/var/lib/develative-deploy/whatsapp/runtime-retirement-' + 'd'*32 + '.json')
        runtime_path.write_bytes(handoff.encoded(runtime)); runtime_path.chmod(0o600)
        provider.verify_runtime_retirement(plan)
        phases = []
        for _ in range(15):
            result = handoff.handoff(root, plan, actions, provider)
            assert not result['pending']
            phases.append(result['phase'])
            cold_box(host)
            if result['phase'] == 'verified': break
        assert phases == list(handoff.PHASES['remove'])
        assert root.snapshot(handoff.OWNER) is None
        assert root.read_bytes(handoff.RUNTIME) == content[handoff.RUNTIME]
        assert calls == ['reload-definitions', 'enable-wa-recovery', 'start-wa-recovery',
                         'disable-wa-recovery', 'stop-wa-recovery']
    absent = quarantine_application_roots(host, 'whatsapp', tmp_path/'quarantined-whatsapp')
    cold_box(host)
    assert all(not path.exists() for path in absent)
