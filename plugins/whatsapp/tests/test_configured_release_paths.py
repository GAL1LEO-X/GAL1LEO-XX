"""Cold configured receiver checks with real SQLite/archives in temporary roots.

Only absolute filesystem destinations are mapped into the fixture. Installation
identity, config/path admission, queue SQL and snapshot validation remain real;
no service, network, production identity or database is accessed.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Protected identity fixtures require POSIX')


DRIVER = r'''
from contextlib import closing
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tarfile
from types import SimpleNamespace

scripts, root = Path(sys.argv[1]), Path(sys.argv[2])
variant, scenario = sys.argv[3:5]
sys.path.insert(0, str(scripts))
import installation_layout as installation

worker_commands = []

def audit(event, args):
    if event == 'open' and isinstance(args[0], str) and args[0].startswith('/etc/'):
        raise AssertionError('A configured fixture attempted a real host configuration read')
    if event == 'subprocess.Popen' and not scenario.startswith('probe-'):
        command = args[1]
        assert command[:5] == [sys.executable, '-I', '-B', '-', 'idle']
        assert len(command) == 6 and args[2] == '/' and args[3] == {}
        context = json.loads(command[5])
        assert Path(context['database']).is_relative_to(root)
        assert context['uid'] == os.getuid() and context['gid'] == os.getgid()
        worker_commands.append(command)
    if event in ('socket.connect', 'socket.getaddrinfo'):
        raise AssertionError('A receiver path check attempted service or network effects')
sys.addaudithook(audit)

value = json.loads((scripts.parent / 'deploy/installation.example.json').read_text())
if variant == 'alternative':
    value['paths'] = {
        'project': '/opt/chat-bridge/app', 'configuration': '/srv/chat-settings',
        'state': '/srv/chat-state', 'gateway': '/opt/chat-gateway',
        'backup': '/srv/chat-copies', 'administration_code': '/opt/chat-admin',
        'administration_state': '/srv/chat-administration',
    }
    value['services'] = {'prefix': 'chat-bridge', 'recovery': 'chat-recovery'}
    value['accounts'] = {'personal': 'chat-owner', 'team': 'chat-team'}
    value['ports'] = {'personal': {'bridge': 23021, 'gateway': 23131},
                      'team': {'bridge': 24041, 'gateway': 24151}}
profile = installation.Installation.from_dict(value)
identity = root / 'etc'; identity.mkdir(parents=True)
(identity / installation.IDENTITY.name).write_bytes(installation.identity_bytes(profile))
(identity / installation.PROFILE.name).write_bytes(profile._encoded)
installation.activate_installation(root=root, trusted_uid=os.getuid())
import github_release as release
import release_transaction as transaction
import backup_validation as validation
import tenant_database as secure

def mapped(value):
    path = Path(value)
    assert path.is_absolute(), 'The receiver must use explicit absolute paths'
    return path if path.is_relative_to(root) else root / str(path).lstrip('/')

# This is the sole filesystem namespace seam. The functions themselves read
# the protected configured identity and derive every tenant destination.
release.Path = mapped
transaction.Path = mapped
secure._TRUST_ROOT = root
secure._TRUST_UID = os.getuid()
def fixture_account(name):
    assert name in {profile.account(slug) for slug in ('personal', 'team')}
    return SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
secure.pwd.getpwnam = fixture_account
instances = []
for slug in ('personal', 'team'):
    paths = profile.instance_paths(slug)
    config = paths['configuration'] + '/config.toml'
    database = paths['state'] + '/archive.sqlite'
    mapped(config).parent.mkdir(parents=True)
    subject = 'synthetic-owner-' + slug
    public_url = 'https://' + slug + '.example.test'
    # The subprocess sees the real temporary filesystem; both the path gate
    # and the protected configuration must agree on that physical DB path.
    configuration = {'database': str(mapped(database)), 'owner_subject': subject,
                     'public_url': public_url, 'session': 'default'}
    mapped(config).write_text('[bridge]\n' + '\n'.join(
        key + ' = ' + json.dumps(value) for key, value in configuration.items()))
    technical_identity = {'protocol': 1, 'id': ('a' if slug == 'personal' else 'b') * 32,
        'tenant': hashlib.sha256(json.dumps([subject, public_url, 'default'], separators=(',', ':')).encode()).hexdigest()}
    (mapped(config).parent / 'technical-state.json').write_text(json.dumps(technical_identity))
    mapped(database).parent.mkdir(parents=True)
    with closing(sqlite3.connect(mapped(database))) as db:
        db.executescript('CREATE TABLE sends(state TEXT);'
            'CREATE TABLE media_jobs(state TEXT);'
            'CREATE TABLE history_jobs(state TEXT);'
            'CREATE TABLE deliveries(lease_until REAL);'
            'CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT);')
        db.execute('INSERT INTO state VALUES (?,?)', (secure.KEY, json.dumps(technical_identity)))
        db.commit()
    instances.append({'slug': slug, 'base': profile.service(slug), 'config': config})

def receipt(path, slug='personal'):
    return json.dumps({'user': slug, 'backup': str(path), 'complete': True})

def reject(action, exception, fragment=None):
    try:
        action()
    except exception as error:
        if fragment is not None:
            assert fragment in str(error), str(error)
        return
    raise AssertionError('The invalid configured operation was accepted')

def archive(path, files):
    with tarfile.open(path, 'w:gz') as output:
        for name, content in files.items():
            item = tarfile.TarInfo(name); item.size = len(content)
            output.addfile(item, io.BytesIO(content))

def snapshot(slug):
    path = mapped(profile.path('backup')) / slug / 'snapshots' / '20261019T000000000000Z'
    path.mkdir(parents=True)
    with closing(sqlite3.connect(path / 'archive.sqlite')) as db:
        db.executescript((scripts / 'backup_schemas/8.sql').read_text())
    config = profile.instance_paths(slug)['configuration'].lstrip('/')
    files = {config + '/' + name: b'synthetic fixture only' for name in
             ('config.toml', 'encryption.key', 'webhook.key', 'waha.key')}
    identity_files = {str(installation.IDENTITY): installation.identity_bytes(profile),
                      str(installation.PROFILE): profile._encoded}
    files.update({name.lstrip('/'): raw for name, raw in identity_files.items()})
    archive(path / 'private-runtime.tar.gz', files)
    archive(path / 'source.tar.gz', {name: b'# synthetic source\n' for name in
        ('pyproject.toml', 'requirements.lock', 'sally_whatsapp/__init__.py', 'sally_whatsapp/store.py')})
    manifest = {'format': validation.IDENTITY_FORMAT, 'user': slug,
        'created_utc': path.name, 'sqlite_integrity': 'ok', 'includes_credentials': True,
        'auth_mode': 'external-oidc', 'files': {},
        'installation': {'identity': installation.identity_record(profile), 'files': {
            name: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
            for name, raw in identity_files.items()}}}
    for name in validation.EXTERNAL_FILES:
        content = (path / name).read_bytes()
        manifest['files'][name] = {'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
    (path / 'manifest.json').write_text(json.dumps(manifest))
    return path

if scenario == 'idle':
    release.queues_idle(instances)
    assert len(worker_commands) == 2
elif scenario.startswith('busy-'):
    kind = scenario.removeprefix('busy-')
    statement = {'send': "INSERT INTO sends VALUES ('sending')",
                 'media': "INSERT INTO media_jobs VALUES ('downloading')",
                 'history': "INSERT INTO history_jobs VALUES ('running')",
                 'delivery': 'INSERT INTO deliveries VALUES (99999999999)'}[kind]
    database = mapped(profile.instance_paths('team')['state'] + '/archive.sqlite')
    with closing(sqlite3.connect(database)) as db:
        db.execute(statement); db.commit()
    reject(lambda: release.queues_idle(instances), release.ReleaseError, 'work in flight')
elif scenario == 'wrong-database-tenant':
    wrong = profile.instance_paths('team')['state'] + '/archive.sqlite'
    mapped(instances[0]['config']).write_text('[bridge]\ndatabase = ' + json.dumps(wrong) + '\n')
    reject(lambda: release.queues_idle(instances), release.ReleaseError, 'Unexpected instance database path')
elif scenario == 'missing-database':
    path = mapped(profile.instance_paths('team')['state'] + '/archive.sqlite'); path.unlink()
    reject(lambda: release.queues_idle(instances), FileNotFoundError)
    assert not path.exists(), 'A missing database must never be created by the release check'
elif scenario in ('linked-tenant-database', 'foreign-database-identity'):
    source = mapped(profile.instance_paths('personal')['state'] + '/archive.sqlite')
    other = mapped(profile.instance_paths('team')['state'] + '/archive.sqlite')
    before = other.read_bytes()
    source.unlink()
    if scenario == 'linked-tenant-database':
        source.symlink_to(other)
        reject(lambda: release.queues_idle(instances), OSError)
        assert not worker_commands
    else:
        source.write_bytes(before)
        reject(lambda: release.queues_idle(instances), release.ReleaseError, 'database safety check failed')
        assert len(worker_commands) == 1
    assert other.read_bytes() == before
elif scenario == 'backups':
    paths = {slug: snapshot(slug) for slug in ('personal', 'team')}
    before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns)
              for path in paths.values() for p in path.iterdir()}
    output = '\n'.join(receipt(path, slug) for slug, path in paths.items())
    assert release.verify_backups(output, list(paths),
        auth_modes={slug: 'external-oidc' for slug in paths}) == list(map(str, paths.values()))
    assert before == {str(p): (p.read_bytes(), p.stat().st_mtime_ns)
                      for path in paths.values() for p in path.iterdir()}
else:
    path = snapshot('personal')
    if scenario == 'backup-other-tenant':
        moved = mapped(profile.path('backup')) / 'team' / 'snapshots' / path.name
        moved.parent.mkdir(parents=True); path.rename(moved); path = moved
    elif scenario == 'backup-outside-root':
        moved = root / 'other-backup' / path.name
        moved.parent.mkdir(); path.rename(moved); path = moved
    elif scenario == 'backup-linked-parent':
        parent = path.parent; moved = root / 'retained-copy'
        parent.rename(moved); parent.symlink_to(moved, target_is_directory=True)
    elif scenario == 'backup-linked-snapshot':
        moved = path.with_name('saved'); path.rename(moved); path.symlink_to(moved, target_is_directory=True)
    elif scenario == 'backup-relative':
        # A relative path is refused by our namespace seam as well as production.
        # Use the actual pathlib constructor for this no-access rejection only.
        release.Path = Path
        reject(lambda: release.verify_backups(receipt(Path('relative-copy')), ['personal'],
            auth_modes={'personal': 'external-oidc'}), release.ReleaseError, 'configured backup directory')
        print(json.dumps({'variant': variant, 'scenario': scenario, 'passed': True})); sys.exit(0)
    elif scenario == 'backup-corrupt':
        (path / 'archive.sqlite').write_bytes(b'corrupt synthetic database')
    elif scenario == 'backup-unregistered':
        reject(lambda: release.verify_backups(receipt(path, 'absent'), ['absent'],
            auth_modes={'absent': 'external-oidc'}), release.ReleaseError, 'absent from the installation profile')
        print(json.dumps({'variant': variant, 'scenario': scenario, 'passed': True})); sys.exit(0)
    else:
        raise AssertionError('Unknown fixture scenario')
    fragment = 'backup validation failed' if scenario == 'backup-corrupt' else 'configured backup directory'
    reject(lambda: release.verify_backups(receipt(path), ['personal'],
        auth_modes={'personal': 'external-oidc'}), release.ReleaseError, fragment)

print(json.dumps({'variant': variant, 'scenario': scenario, 'passed': True}))
'''


def check(tmp_path, variant, scenario):
    result = subprocess.run([sys.executable, '-I', '-B', '-c', DRIVER,
        str(SCRIPTS), str(tmp_path / 'host'), variant, scenario],
        capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {'variant': variant, 'scenario': scenario, 'passed': True}


@pytest.mark.parametrize('variant', ['example', 'alternative'])
@pytest.mark.parametrize('scenario', ['idle', 'busy-send', 'busy-media', 'busy-history',
    'busy-delivery', 'wrong-database-tenant', 'missing-database',
    'linked-tenant-database', 'foreign-database-identity'])
def test_configured_queue_gate_reads_every_exact_tenant_database(tmp_path, variant, scenario):
    check(tmp_path, variant, scenario)


@pytest.mark.parametrize('variant', ['example', 'alternative'])
@pytest.mark.parametrize('scenario', ['backups', 'backup-other-tenant', 'backup-outside-root',
    'backup-linked-parent', 'backup-linked-snapshot', 'backup-relative', 'backup-corrupt', 'backup-unregistered'])
def test_configured_backup_gate_keeps_tenant_boundaries_and_full_validation(tmp_path, variant, scenario):
    check(tmp_path, variant, scenario)


PROBE_DRIVER = DRIVER.split('# This is the sole filesystem namespace seam.', 1)[0] + r"""
import pwd
import subprocess
from types import SimpleNamespace
import release_admin as admin

generations = mapped(profile.path('administration_code')) / 'whatsapp-generations'
generation = generations / ('a' * 64); generation.mkdir(parents=True)
names = ('github_release.py', 'release_probe.py', 'release_runtime.py', 'installation_layout.py')
sources = {name: (scripts / name).read_bytes() for name in names}
for name, content in sources.items():
    (generation / name).write_bytes(content)
manifest = installation.encoded({'protocol': 1, 'installation_sha256': profile.sha256,
    'files': {name: hashlib.sha256(content).hexdigest() for name, content in sources.items()}})
(generation / 'manifest.json').write_bytes(manifest)
owner = mapped(profile.path('configuration')) / 'administration/recovery-owners/whatsapp.json'
owner.parent.mkdir(parents=True)
owner.write_bytes(installation.encoded({'protocol': 1, 'epoch': 'b' * 32, 'state': 'dedicated',
    'generation': str(generation), 'manifest_sha256': hashlib.sha256(manifest).hexdigest()}))
admin._TRUST_ROOT = root
admin.GENERATIONS = generations
admin.OWNER = owner
admin._trusted_uid = lambda uid: uid == os.getuid()
release.__file__ = str(generation / 'github_release.py')
candidate = mapped(profile.path('administration_state')) / 'builds/whatsapp/candidate'
candidate.mkdir(parents=True)
shutil.copytree(scripts.parent / 'sally_whatsapp', candidate / 'sally_whatsapp',
                ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
database = root / 'snapshot.sqlite'
with closing(sqlite3.connect(database)) as db:
    db.executescript((scripts / 'backup_schemas/8.sql').read_text())
before = database.read_bytes()
pwd.getpwnam = lambda name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
sentinel = root / 'UNAPPROVED-HELPER-EXECUTED'
tampered = ('from pathlib import Path\nPath(' + repr(str(sentinel)) + ').write_text("executed")\n').encode()
invocations = []

def sandbox(candidate_path, command, *, timeout):
    invocations.append(command)
    assert candidate_path == candidate
    probe = Path(command[2]); checks = probe.parent
    assert checks.parent == candidate and checks.name.startswith('.database-check-')
    assert command[:2] == [str(candidate / '.venv/bin/python'), '-B']
    assert len(command) == 4 and Path(command[3]) == checks / '0.sqlite'
    assert Path(command[3]).read_bytes() == before
    assert {item.name for item in checks.iterdir()} == {
        '0.sqlite', 'release_probe.py', 'release_runtime.py', 'installation_layout.py'}
    for name in ('release_probe.py', 'release_runtime.py', 'installation_layout.py'):
        assert (checks / name).read_bytes() == sources[name]
    if scenario == 'probe-sandbox-failure':
        raise release.ReleaseError('synthetic sandbox failure')
    # Real cold probe/app/SQLite. The real systemd namespace is represented by
    # refusing any access to original helpers or installed identities; this is
    # not a claim that systemd mount or service behavior was exercised here.
    runner = '''import os,runpy,sys
from pathlib import Path
candidate,probe,original=map(Path,sys.argv[1:4])
def audit(event,args):
    if event=="open" and isinstance(args[0],str):
        path=Path(args[0])
        if path.is_relative_to(original) or args[0].startswith(("/etc/whatsapp-installation","/etc/box-installation")):
            raise AssertionError("Offline probe read a host administration source or identity")
    if event in ("socket.connect","socket.getaddrinfo","subprocess.Popen"):
        raise AssertionError("Offline probe attempted an external effect")
sys.addaudithook(audit)
sys.path[:0]=[str(probe.parent),str(candidate)]
import sally_whatsapp
assert Path(sally_whatsapp.__file__).is_relative_to(candidate)
sys.argv=[str(probe),*sys.argv[4:]]
runpy.run_path(str(probe),run_name="__main__")
assert Path(sys.modules["release_runtime"].__file__).parent==probe.parent
assert Path(sys.modules["installation_layout"].__file__).parent==probe.parent
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', runner,
        str(candidate), str(probe), str(generation), *command[3:]],
        capture_output=True, text=True, timeout=timeout)
    assert result.returncode == 0, result.stderr
    return result.stdout
release.sandbox = sandbox

if scenario == 'probe-valid':
    result = release.probe_databases(candidate, [database])
    assert result['passed'] is True and result['workersGated'] is True
    assert result['offlineDatabases'] == 1 and len(invocations) == 1
elif scenario == 'probe-sandbox-failure':
    try: release.probe_databases(candidate, [database])
    except release.ReleaseError as error: assert str(error) == 'synthetic sandbox failure'
    else: raise AssertionError('Sandbox failure was hidden')
    assert len(invocations) == 1
elif scenario.startswith('probe-tamper-'):
    helper = scenario.removeprefix('probe-tamper-')
    (generation / helper).write_bytes(tampered)
    try: release.probe_databases(candidate, [database])
    except admin.AdminError as error: assert 'hash differs' in str(error)
    else: raise AssertionError('Unadmitted helper bytes were copied or executed')
    assert not invocations
elif scenario == 'probe-capture-race':
    require_current = admin.require_current
    def changed_after_admission(path, **options):
        result = require_current(path, **options)
        if Path(path).name == 'release_probe.py':
            Path(path).write_bytes(tampered)
        return result
    admin.require_current = changed_after_admission
    try: release.probe_databases(candidate, [database])
    except release.ReleaseError as error: assert 'changed during capture' in str(error)
    else: raise AssertionError('Bytes changed after admission were accepted')
    assert not invocations
else:
    raise AssertionError('Unknown probe scenario')
assert not list(candidate.glob('.database-check-*'))
assert not sentinel.exists()
assert database.read_bytes() == before
print(json.dumps({'variant': variant, 'scenario': scenario, 'passed': True}))
"""


@pytest.mark.parametrize('variant', ['example', 'alternative'])
@pytest.mark.parametrize('scenario', ['probe-valid', 'probe-sandbox-failure', 'probe-capture-race',
    'probe-tamper-release_probe.py', 'probe-tamper-release_runtime.py', 'probe-tamper-installation_layout.py'])
def test_configured_probe_captures_admitted_closure_inside_candidate(tmp_path, variant, scenario):
    result = subprocess.run([sys.executable, '-I', '-B', '-c', PROBE_DRIVER,
        str(SCRIPTS), str(tmp_path / 'host'), variant, scenario],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {'variant': variant, 'scenario': scenario, 'passed': True}
