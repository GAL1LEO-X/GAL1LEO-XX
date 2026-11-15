"""Actual SQLite backup/recovery from installed WA bytes with BOX absent.

Only namespace/UID attestation, service activity and HTTP readiness are synthetic.
Archive creation, SQLite backup, hashing, journal writes, admission, flock,
process sessions and the independent recovery entrypoint are real.
"""
from contextlib import closing
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tarfile

import pytest

REPOSITORY = Path(__file__).resolve().parents[3]
PLUGIN = REPOSITORY / 'plugins/whatsapp'
sys.path.insert(0, str(REPOSITORY/'tools/tests'))
from test_host_lifecycle_integration import (staged_whatsapp, apply, empty,
                                             physical, select_fixture_generation)


SURVIVOR = r'''
import fcntl,hashlib,importlib.util,json,os,pwd,signal,subprocess,sys
from pathlib import Path
from types import SimpleNamespace
host,plugin,operation=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
sys.path.insert(0,str(plugin))
bootstrap=host/'usr/local/lib/develative-deploy/whatsapp-bootstrap'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
    return module
installation=load('installation_layout',bootstrap/'installation_layout.py')
installation.activate_installation(root=host,trusted_uid=os.getuid())
from sally_whatsapp import installation as application_installation
application_installation.activate_installation(root=host,trusted_uid=os.getuid())
admin=load('release_admin',bootstrap/'release_admin.py')
for name,value in {'_TRUST_ROOT':host,'STATE':host/'var/lib/develative-deploy/whatsapp',
 'OWNER':host/'etc/develative-deploy/recovery-owners/whatsapp.json',
 'BOOTSTRAP':bootstrap,'ENTRYPOINT':bootstrap/'release_entry.py',
 'GENERATIONS':host/'usr/local/lib/develative-deploy/whatsapp-generations'}.items():setattr(admin,name,value)
admin.PUBLICATION_LOCK=admin.STATE/'publication.lock'
admin._trusted_uid=lambda uid:uid==os.getuid()
generation=admin.load_generation(states=('dedicated','retiring'))
admin.pin_generation(generation);sys.path.insert(0,str(generation.path))
import github_release as release
import github_release_common as common
import release_backup as journal
import release_transaction as transaction
import release_recover as recovery
project=host/'srv/openai-codex/projects/whatsapp-personal'
common.STATE=host/'var/lib/develative-deploy';release.ROOT=project;release.STATE=common.STATE
transaction.JOURNAL=admin.STATE/'transaction.json';transaction.GATE=host/'var/lib/develative-release-gates/whatsapp'
journal.JOURNAL=admin.STATE/'backup.json'
runtime=load('survivor_backup_runtime',project/'scripts/backup_runtime.py');runtime.ROOT=project
runtime._INSTALLATION_ROOT=host;runtime._INSTALLATION_UID=os.getuid()
import tenant_database as secure
secure._TRUST_ROOT=host;secure._TRUST_UID=os.getuid()
# Namespace translation changes only hardcoded filesystem roots. The installed
# helper's SQL backup, tar creation, manifest hashes and fsync remain untouched.
real_path=Path
def mapped(value):
    path=real_path(value)
    if path.is_absolute() and not path.is_relative_to(host):
        assert str(path).startswith(('/etc/','/var/')),str(path)
        return host/str(path).lstrip('/')
    return path
runtime.Path=mapped
snapshot=runtime.snapshot_database
runtime.snapshot_database=lambda source,target:snapshot(mapped(source),target)
state_file=host/'service-fixture.json';calls_file=host/'service-calls.jsonl'
rows=[];instances=[]
for slug,port in [('first',8820),('second',8822)]:
    base='whatsapp-'+slug;wrapper=project/'private/tenants'/slug/'as-user'
    config=host/'etc'/base/'config.toml'
    rows.append({'slug':slug,'unit':base+'.service','base':base,'port':port,'config':config,'wrapper':wrapper,
        'auth_mode':'managed-authelia'})
    instances.append(SimpleNamespace(slug=slug,base=base,wrapper=wrapper,state_dir=host/'var/lib'/base,
        config_dir=config.parent,gateway_home=host/'home'/base,private_dir=project/'private/tenants'/slug,
        bridge_port=port,gateway_port=port+1,auth_mode='managed-authelia',
        service_user=pwd.getpwuid(os.getuid()).pw_name,subject='synthetic-'+slug,
        public_url='https://'+slug+'.example.test'))
# Registry row construction needs only namespace translation; content hashes,
# selected tenant/component identity and context validation use real functions.
real_instances=release.instances
def registered(root):
    values=real_instances(root)
    for item in values:item['config']=mapped(item['config'])
    return values
release.instances=registered
assert registered(project)==rows
real_run=subprocess.run
calls=[]
def run(args,**kwargs):
    args=list(map(str,args));assert not any('box' in part.lower() for part in args),args
    if len(args)==3 and args[1]==str(project/'scripts/package_source.py'):
        return real_run([sys.executable,'-I','-B',args[1],args[2]],capture_output=True,text=True,check=True,
                        pass_fds=kwargs.get('pass_fds',()),timeout=10)
    # No other child command may escape this exact fixture service allowlist.
    if args[0]=='systemctl':
        unit=args[-1];assert unit in ('whatsapp-first.service','whatsapp-second.service')
        key=unit.removesuffix('.service').removeprefix('whatsapp-')+'.bridge'
    else:
        matches=[row for row in rows if str(row['wrapper'])==args[0]];assert len(matches)==1,args
        assert args[1:3]==['systemctl','--user'] and args[-1]=='whatsapp-waha.service',args
        key=matches[0]['slug']+'.gateway'
    action='is-active' if 'is-active' in args else 'stop' if 'stop' in args else 'start' if 'start' in args else None
    assert action is not None,args
    for fd in kwargs.get('pass_fds',()):os.fstat(fd)
    state=json.loads(state_file.read_text())
    if action=='is-active':return subprocess.CompletedProcess(args,0 if state[key] else 3,stdout='',stderr='')
    # The before-stop record must already be durable before the fake service
    # effect, exactly as it would be before the real systemctl invocation.
    if action=='stop':
        plan=journal.read();assert plan['phase']=='copying' and plan['copies'][key.split('.')[0]]['path'] is not None
    state[key]=action=='start';state_file.write_text(json.dumps(state))
    with calls_file.open('a') as output:output.write(json.dumps({'action':action,'component':key,'fd':bool(kwargs.get('pass_fds'))})+'\n')
    if action=='stop' and operation=='kill-before-copy':os.kill(os.getpid(),signal.SIGKILL)
    return subprocess.CompletedProcess(args,0,stdout='',stderr='')
release.subprocess=SimpleNamespace(run=run)
release.run=lambda args,**kwargs:run(args,check=True,**kwargs).stdout
runtime.subprocess=SimpleNamespace(run=run)
ready={'process':'running','version':'0.5.0','readiness':{'state':'ready','ready':True,
       'workers':{key:True for key in ('events','transfers','history','actions')}}}
release.get_json=lambda url,headers=None:ready if url.endswith('/healthz') else {'version':'synthetic'}
class Client:
    def __init__(self,**kwargs):pass
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def get(self,url,**kwargs):
        assert url.startswith('http://127.0.0.1:'),url
        return SimpleNamespace(is_success=True)
runtime.httpx=SimpleNamespace(Client=Client)
if operation in ('backup','kill-before-copy'):
    # This is the same dedicated admission and lock order used by the public
    # standalone main; no BOX path or other owner's lock exists in the fixture.
    with admin.publication_lock(expected=generation):
        with (project/'private/tenant-admin.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            admin.require_current(journal.__file__,expected=generation)
            selected=registered(project)
            plan=journal.begin(project,selected,release.backup_components(selected),'0.5.0')
            journal.attach_worker(plan['id'])
            results=[runtime.backup(instance,recovery_id=plan['id'],recovery=journal,lock_fd=lock.fileno()) for instance in instances]
            journal.recover(project,selected,lambda components,version:release.restore_backup_components(components,version,lock_fd=lock.fileno()))
    print(json.dumps({'backups':results,'journal':journal.read()}))
elif operation=='recover':
    recovery.recover_project()
    print(json.dumps({'journal':journal.read()}))
elif operation=='reject-new-backup':
    try:
        with admin.publication_lock(expected=generation):raise AssertionError('retiring admitted a new backup')
    except admin.AdminError:print(json.dumps({'new_backup_blocked':True}))
else:raise AssertionError(operation)
'''


@pytest.fixture
def survivor(staged_whatsapp):
    host, bundle, manifest, payloads = staged_whatsapp
    apply(host, '1'*32, empty('whatsapp'), manifest, payloads)
    select_fixture_generation(host, bundle)
    import installation_layout as installation
    marker = host/installation.IDENTITY.relative_to('/')
    expected = installation.identity_bytes(installation.Installation.legacy())
    if not marker.exists():
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_bytes(expected); marker.chmod(0o600)
    assert marker.read_bytes() == expected
    assert not (host/'etc/box-installation-identity.json').exists()
    assert not (host/'etc/box-installation.json').exists()
    project = physical(host, '/srv/openai-codex/projects/whatsapp-personal')
    (project/'private').mkdir(parents=True, exist_ok=True)
    (project/'sally_whatsapp').mkdir()
    (project/'sally_whatsapp/__init__.py').write_text("__version__ = '0.5.0'\n")
    (project/'sally_whatsapp/store.py').write_text('# synthetic source fixture\n')
    for name in ('pyproject.toml','requirements.lock'):
        (project/name).write_text('# synthetic source fixture\n')
    registry = {'format': 1, 'instances': {slug: {'spec': {'slug': slug, 'bridge_port': port,
                                                         'auth_mode': 'managed-authelia'}}
                             for slug, port in [('first', 8820), ('second', 8822)]}}
    (project/'private/tenants.json').write_text(json.dumps(registry))
    sys.path.insert(0, str(PLUGIN))
    from sally_whatsapp.store import Store
    for slug in ('first', 'second'):
        config = physical(host, '/etc/whatsapp-'+slug); config.mkdir(parents=True)
        for name in ('waha.key','webhook.key','encryption.key'):
            (config/name).write_text('synthetic-only')
        private = project/'private/tenants'/slug; private.mkdir(parents=True)
        (private/'as-user').write_text('# synthetic exact service wrapper\n')
        state = physical(host, '/var/lib/whatsapp-'+slug); state.mkdir(parents=True)
        (config/'config.toml').write_text('[bridge]\n'+'\n'.join(key+' = '+json.dumps(value) for key,value in {
            'database':str(state/'archive.sqlite'),'owner_subject':'synthetic-'+slug,
            'public_url':'https://'+slug+'.example.test','session':'default'}.items()))
        store = Store(state/'archive.sqlite')
        import hashlib
        technical = {'protocol':1,'id':('a' if slug=='first' else 'b')*32,
            'tenant':hashlib.sha256(json.dumps(['synthetic-'+slug,'https://'+slug+'.example.test','default'],separators=(',', ':')).encode()).hexdigest()}
        (config/'technical-state.json').write_text(json.dumps(technical))
        with store.db() as database:
            database.execute('INSERT INTO state VALUES (?,?)',('private:technical_state_identity:v1',json.dumps(technical)))
        for status in ('submitted', 'uncertain'):
            key = slug+'-'+status
            store.queue_action(key, slug, 'messages_send_text', {'body': {'chatId': 'synthetic@c.us', 'text': key}})
            store.finish_send(key, status, 'synthetic-message-'+key)
        gateway = physical(host, '/home/whatsapp-'+slug)
        (gateway/'sessions').mkdir(parents=True)
        (gateway/'sessions/synthetic-session').write_text('synthetic-only')
    auth = physical(host, '/var/lib/sally-browser/stack/authelia/db.sqlite3'); auth.parent.mkdir(parents=True)
    with closing(sqlite3.connect(auth)) as database:
        database.execute('CREATE TABLE user_opaque_identifier(service TEXT,sector_id TEXT,username TEXT,identifier TEXT)')
        database.execute("INSERT INTO user_opaque_identifier VALUES('synthetic','','fixture','synthetic-identity')")
        database.commit()
    auth_config=physical(host,'/var/lib/sally-browser/stack/config');auth_config.mkdir(parents=True)
    for name in ('authelia.yml','users.yml'):
        (auth_config/name).write_text('synthetic fixture only\n')
    initial = {'first.bridge': True, 'first.gateway': False, 'second.bridge': False, 'second.gateway': True}
    (host/'service-fixture.json').write_text(json.dumps(initial))
    # An old published activation must not skip a newer interrupted backup.
    state = host/'var/lib/develative-deploy/whatsapp'
    (state/'transaction.json').write_text(json.dumps({'phase': 'published'}))
    assert not (host/'var/lib/develative-deploy/box').exists()
    assert not (host/'usr/local/lib/develative-deploy/box').exists()
    assert not (host/'var/lib/develative-deploy/publication.lock').exists()
    return host, initial


def invoke(host, action):
    return subprocess.run([sys.executable, '-I', '-B', '-c', SURVIVOR, str(host), str(PLUGIN), action],
                          capture_output=True, text=True, timeout=25, start_new_session=True)


def calls(host):
    path = host/'service-calls.jsonl'
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_actual_sqlite_backup_and_archives_succeed_with_box_physically_absent(survivor):
    host, initial = survivor
    source = physical(host, '/var/lib/whatsapp-first/archive.sqlite')
    with closing(sqlite3.connect(source)) as live:
        live.execute('PRAGMA journal_mode=WAL')
        live.execute("INSERT INTO state(key,value) VALUES('survivor-current','\"committed-in-wal\"')")
        live.commit()
        result = invoke(host, 'backup')
        assert result.returncode == 0, result.stderr
        value = json.loads(result.stdout)
        assert value['journal']['servicesRestored'] is True
        assert all(item['complete'] for item in value['journal']['copies'].values())
        for item in value['backups']:
            directory = Path(item['backup'])
            with closing(sqlite3.connect('file:'+str(directory/'archive.sqlite')+'?mode=ro', uri=True)) as snapshot:
                assert snapshot.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
                assert snapshot.execute('PRAGMA journal_mode').fetchone()[0] == 'delete'
                assert snapshot.execute('SELECT state FROM sends ORDER BY key').fetchall() == [('submitted',), ('uncertain',)]
                if item['user'] == 'first':
                    assert snapshot.execute("SELECT value FROM state WHERE key='survivor-current'").fetchone() == ('"committed-in-wal"',)
            manifest = json.loads((directory/'manifest.json').read_text())
            assert manifest['format'] == 'whatsapp-isolated-backup-v5'
            assert manifest['auth_mode'] == 'managed-authelia'
            marker = host/'etc/whatsapp-installation-identity.json'
            assert set(manifest['installation']['files']) == {'/etc/whatsapp-installation-identity.json'}
            with tarfile.open(directory/'private-runtime.tar.gz') as archive:
                assert archive.extractfile(str(marker).lstrip('/')).read() == marker.read_bytes()
            import hashlib
            for filename, declared in manifest['files'].items():
                content = (directory/filename).read_bytes()
                assert len(content) == declared['bytes'] and hashlib.sha256(content).hexdigest() == declared['sha256']
            assert {'archive.sqlite', 'shared-authelia.sqlite3', 'private-runtime.tar.gz', 'source.tar.gz'} <= set(manifest['files'])
        assert live.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
    assert json.loads((host/'service-fixture.json').read_text()) == initial
    effects = calls(host)
    assert {item['component'] for item in effects} == {name for name, active in initial.items() if active}
    assert all(item['fd'] for item in effects)
    assert not (host/'var/lib/develative-deploy/publication.lock').exists()
    assert not (host/'etc/box-installation-identity.json').exists()
    assert not (host/'etc/box-installation.json').exists()


def test_cold_actual_recovery_after_worker_sigkill_with_box_absent_and_owner_retiring(survivor):
    host, initial = survivor
    killed = invoke(host, 'kill-before-copy')
    assert killed.returncode == -signal.SIGKILL, killed.stderr
    journal_path = host/'var/lib/develative-deploy/whatsapp/backup.json'
    before = json.loads(journal_path.read_text())
    assert before['phase'] == 'copying' and before['servicesRestored'] is False
    assert before['copies']['first']['complete'] is False and before['copies']['second']['path'] is None
    source = physical(host, '/var/lib/whatsapp-first/archive.sqlite')
    with closing(sqlite3.connect(source)) as database:
        database.execute("INSERT INTO state(key,value) VALUES('after-crash','\"preserve-current\"')")
        database.commit()
    owner_path = host/'etc/develative-deploy/recovery-owners/whatsapp.json'
    owner = json.loads(owner_path.read_text()); owner['state'] = 'retiring'; owner_path.write_text(json.dumps(owner))
    recovered = invoke(host, 'recover')
    assert recovered.returncode == 0, recovered.stderr
    after = json.loads(recovered.stdout)['journal']
    assert after['id'] == before['id'] and after['phase'] == 'restored' and after['servicesRestored'] is True
    assert after['copies'] == before['copies']  # Recovery does not invent a completed backup.
    assert json.loads((host/'service-fixture.json').read_text()) == initial
    with closing(sqlite3.connect(source)) as database:
        assert database.execute("SELECT value FROM state WHERE key='after-crash'").fetchone() == ('"preserve-current"',)
    effects = calls(host)
    assert {item['component'] for item in effects} == {name for name, active in initial.items() if active}
    repeated = invoke(host, 'recover')
    assert repeated.returncode == 0 and calls(host) == effects
    denied = invoke(host, 'reject-new-backup')
    assert denied.returncode == 0 and json.loads(denied.stdout)['new_backup_blocked']
    assert not (host/'var/lib/develative-deploy/box').exists()
    assert not (host/'usr/local/lib/develative-deploy/box').exists()
    assert not (host/'var/lib/develative-deploy/publication.lock').exists()
    assert not (host/'etc/box-installation-identity.json').exists()
    assert not (host/'etc/box-installation.json').exists()
