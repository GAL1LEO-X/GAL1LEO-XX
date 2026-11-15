"""Fault injection at the public release boundary; no operational services."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import github_release as release
import github_release_common as common
import release_transaction as transaction
import release_admin as administration
import tenant_database as secure
from test_release_backup_review import CHILD_IDENTITY


@pytest.fixture
def publication(tmp_path, monkeypatch):
    # Protected administrative metadata belongs to this isolated fixture root.
    # Tenant snapshots use the real credential-checked subprocess worker.
    monkeypatch.setattr(secure, '_TRUST_ROOT', tmp_path)
    monkeypatch.setattr(secure, '_TRUST_UID', os.getuid())
    monkeypatch.setattr(administration, '_TRUST_ROOT', tmp_path)
    monkeypatch.setattr(administration, '_trusted_uid', lambda uid: uid == os.getuid())
    # Generation admission belongs to the bootstrap; retain the real protected
    # filesystem guard at the receiver's publication-directory boundary.
    monkeypatch.setattr(administration, 'require_current', lambda *args, **kwargs: None)
    monkeypatch.setattr(secure.pwd, 'getpwnam', lambda name: SimpleNamespace(
        pw_uid=os.getuid(), pw_gid=os.getgid()))
    runtime, checkout, state = tmp_path/'runtime', tmp_path/'checkout', tmp_path/'state'
    source = checkout/'plugins/whatsapp'
    for root, version in [(runtime, '0.3.1'), (source, '0.3.2')]:
        (root/'sally_whatsapp').mkdir(parents=True)
        (root/'sally_whatsapp/__init__.py').write_text(f'__version__ = {version!r}\n')
        schema = ('CREATE TABLE messages(id TEXT PRIMARY KEY,body TEXT' +
                  (',extra TEXT' if version == '0.3.2' else '') + ');'
                  'CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT);PRAGMA user_version=' +
                  ('7' if version == '0.3.2' else '6') + ';')
        (root/'sally_whatsapp/store.py').write_text('SCHEMA = '+repr(schema)+'\n')
        (root/'.venv').mkdir()
        (root/'.venv/marker').write_text(version)
        (root/'requirements.lock').write_text('synthetic==1\n')
        (root/'pyproject.toml').write_text('[build-system]\nrequires=[]\n[project]\n'
            f'version="{version}"\ndependencies=[]\nrequires-python=">=3.13"\n')
    (runtime/'private').mkdir()
    (runtime/'private/tenants.json').write_text('{"synthetic": true}\n')
    (runtime/'work').mkdir()
    (source/'deploy').mkdir()
    (source/'deploy/migrations.json').write_text(json.dumps({'schemaVersion':7,
        'migrations':[{'from':6,'to':7,'sql':'6-7.sql'}]}))
    (source/'deploy/6-7.sql').write_text('ALTER TABLE messages ADD COLUMN extra TEXT;PRAGMA user_version=7;')
    selected=[]
    for slug in ('enabled','suspended'):
        config=tmp_path/slug/'configuration/config.toml';config.parent.mkdir(parents=True)
        database=tmp_path/slug/'state/archive.sqlite';database.parent.mkdir()
        owner='synthetic-owner-'+slug
        origin='https://'+slug+'.example.test'
        config.write_text('[bridge]\n'+'\n'.join(key+' = '+json.dumps(value) for key,value in {
            'database':str(database),'owner_subject':owner,'public_url':origin,'session':'default'}.items()))
        identity={'protocol':1,'id':('a' if slug=='enabled' else 'b')*32,
            'tenant':hashlib.sha256(json.dumps([owner,origin,'default'],separators=(',',':')).encode()).hexdigest()}
        (config.parent/'technical-state.json').write_text(json.dumps(identity))
        with sqlite3.connect(database) as db:
            db.executescript('CREATE TABLE messages(id TEXT PRIMARY KEY,body TEXT);'
                            'CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT);PRAGMA user_version=6;')
            db.execute('INSERT INTO state VALUES (?,?)',(secure.KEY,json.dumps(identity)))
            db.execute('INSERT INTO messages VALUES(?,?)',(slug,'preserved'))
        selected.append({'slug':slug,'unit':slug+'.service','config':config,'database':database})
    common.save(state/'whatsapp/current.json', {'version': '0.3.1', 'commit': 'b'*40})
    commands, backups = [], []
    monkeypatch.setattr(release, 'ROOT', runtime)
    monkeypatch.setattr(release, 'STATE', state)
    monkeypatch.setattr(release, 'instances', lambda root: selected)
    monkeypatch.setattr(release, 'active', lambda unit: unit == 'enabled.service')
    monkeypatch.setattr(release, 'health', lambda *args,**kwargs: 'WORKING')
    monkeypatch.setattr(release, 'wait_health', lambda *args,**kwargs: None)
    monkeypatch.setattr(release, 'queues_idle', lambda *args: None)
    monkeypatch.setattr(release, 'runtime_backups', lambda *args: backups.append(args) or ['synthetic'])
    monkeypatch.setattr(release, 'run', lambda args, **kwargs: commands.append(args) or '')
    monkeypatch.setattr(release,'dbpath',lambda item:Path(item['database']))
    monkeypatch.setattr(transaction,'dbpath',lambda item:Path(item['database']))
    monkeypatch.setattr(transaction,'STATE',state)
    monkeypatch.setattr(transaction,'JOURNAL',state/'whatsapp/transaction.json')
    monkeypatch.setattr(transaction,'GATE',tmp_path/'gates/whatsapp')
    monkeypatch.setattr(transaction,'SYSTEMD',tmp_path/'systemd')
    monkeypatch.setattr(transaction,'run',lambda *args,**kwargs:release.run(*args,**kwargs))
    monkeypatch.setattr(transaction.os,'chown',lambda *args,**kwargs:None)
    builds=[]
    def build(package):
        candidate=tmp_path/('build-'+str(len(builds)))
        shutil.copytree(package,candidate);builds.append(candidate);return candidate
    monkeypatch.setattr(release,'build_backend',build)
    monkeypatch.setattr(release,'seal',release.tree_hashes)
    monkeypatch.setattr(release,'probe_databases',lambda *args:{'passed':True,'workersGated':True})
    monkeypatch.setattr(release,'verify_service_access',lambda *args:None)
    return SimpleNamespace(root=runtime, checkout=checkout, state=state, source=source,
        target={'version': '0.3.2', 'commit': 'a'*40, 'dryRun': False}, commands=commands, backups=backups)


@pytest.mark.parametrize('dry_run', [False, True])
def test_inaccessible_runtime_blocks_before_backups_or_service_changes(publication, monkeypatch, dry_run):
    p = publication
    def denied(*args):
        raise common.ReleaseError('Service cannot access runtime')
    monkeypatch.setattr(release, 'verify_service_access', denied)
    with pytest.raises(common.ReleaseError, match='cannot access runtime'):
        release.publish(p.checkout, {**p.target, 'dryRun': dry_run}, {})
    assert not p.backups
    assert not p.commands
    assert not (p.state / 'whatsapp/pending.json').exists()


@pytest.mark.parametrize('failed_name', ['result.json', 'current.json'])
def test_record_failure_keeps_recoverable_evidence_and_retry_repairs_without_activation(publication, failed_name):
    p = publication
    def fail_save(path, value):
        if Path(path).name == failed_name:
            raise OSError('synthetic storage failure')
        common.save(path, value)
    with patch.object(release, 'save', side_effect=fail_save), pytest.raises(common.ReleaseError, match='Backend is active'):
        release.publish(p.checkout, p.target, {})
    pending = json.loads((p.state/'whatsapp/pending.json').read_text())
    assert pending['commit'] == p.target['commit']
    assert common.file_map(p.root/'sally_whatsapp') == common.file_map(p.source/'sally_whatsapp')
    assert json.loads((p.state/'whatsapp/current.json').read_text())['version'] == '0.3.2'
    result = release.publish(p.checkout, p.target, {})
    assert result['status'] == 'already-active' and not result['activationPerformed']
    assert json.loads((p.state/'whatsapp/current.json').read_text())['version'] == '0.3.2'
    assert json.loads((Path(pending['previousCode'])/'result.json').read_text())['status'] == 'published'
    assert not (p.state/'whatsapp/pending.json').exists()
    # Reconciliation rechecks the original transaction; start is idempotent for
    # an already active service and must not become a restart or rollback.
    assert [x for x in p.commands if x[1]=='start'] == [['systemctl','start','enabled.service']]*2
    assert len(p.backups) == 1


def test_pending_journal_failure_prevents_any_activation(publication):
    p = publication
    def fail_save(path, value):
        if Path(path).name == 'pending.json':
            raise OSError('synthetic storage failure')
        common.save(path, value)
    with patch.object(release, 'save', side_effect=fail_save), pytest.raises(OSError):
        release.publish(p.checkout, p.target, {})
    assert p.commands == []
    assert release.literal(p.root/'sally_whatsapp/__init__.py', '__version__') == '0.3.1'


def test_unfinished_release_cannot_be_adopted_by_another_commit(publication):
    p = publication
    with patch.object(release, 'record_publication', side_effect=common.ReleaseError('synthetic')):
        with pytest.raises(common.ReleaseError): release.publish(p.checkout, p.target, {})
    with pytest.raises(common.ReleaseError, match='original release'):
        release.publish(p.checkout, {**p.target, 'commit': 'c'*40}, {})
    assert len([x for x in p.commands if x[1]=='start']) == 1


def test_retry_after_code_rollback_takes_new_backups(publication):
    p = publication
    with patch.object(release, 'wait_health', side_effect=[None, None, common.ReleaseError('synthetic'), None]):
        with pytest.raises(common.ReleaseError, match='synthetic'):
            release.publish(p.checkout, p.target, {})
    assert release.literal(p.root/'sally_whatsapp/__init__.py', '__version__') == '0.3.1'
    assert release.publish(p.checkout, p.target, {})['status'] == 'published'
    assert len(p.backups) == 2
    assert not (p.state/'whatsapp/pending.json').exists()


def test_dry_run_never_reconciles_or_activates(publication):
    p = publication
    before = (p.state/'whatsapp/current.json').read_bytes()
    assert release.publish(p.checkout, {**p.target, 'dryRun': True}, {})['status'] == 'verified'
    assert (p.state/'whatsapp/current.json').read_bytes() == before and p.commands == [] and p.backups == []
    assert not (p.state/'whatsapp/transaction.json').exists()
    assert not (p.state/'whatsapp/pending.json').exists()


@pytest.mark.parametrize('gate_present',[False,True])
def test_same_pending_candidate_cannot_bypass_application_readiness(publication,monkeypatch,gate_present):
    p=publication
    with patch.object(release,'record_publication',side_effect=common.ReleaseError('interrupted records')):
        with pytest.raises(common.ReleaseError):release.publish(p.checkout,p.target,{})
    if gate_present:transaction.gate_on()
    calls=[]
    def readiness(*args,**kwargs):
        calls.append(kwargs)
        if kwargs.get('require_ready'):raise common.ReleaseError('synthetic worker not ready')
    # No legacy MCP 401 check may block reconciliation before the readiness
    # protocol can run: waiting/failed candidates admit only a 503 challenge.
    monkeypatch.setattr(release,'health',lambda *args,**kwargs:pytest.fail('premature legacy health'))
    monkeypatch.setattr(release,'wait_health',readiness)
    p.commands.clear()
    with pytest.raises(common.ReleaseError,match='worker not ready'):
        release.publish(p.checkout,p.target,{})
    assert calls==([{'maintenance':True}] if gate_present else [])+[{'require_ready':True}]
    assert json.loads(transaction.JOURNAL.read_text())['phase']=='committed'
    assert (p.state/'whatsapp/pending.json').exists() and not transaction.GATE.exists()
    assert not any(command[1]=='stop' for command in p.commands) and len(p.backups)==1
    calls.clear();monkeypatch.setattr(release,'wait_health',lambda *args,**kwargs:calls.append(kwargs))
    result=release.publish(p.checkout,p.target,{})
    assert result['status']=='already-active' and not result['activationPerformed']
    assert calls==[{'require_ready':True}]
    assert json.loads(transaction.JOURNAL.read_text())['phase']=='published'
    assert not (p.state/'whatsapp/pending.json').exists()


@pytest.mark.parametrize('change',[{'sourceCommit':'c'*40},{'phase':'switched'},
                                 {'activeUnits':['other.service']}])
def test_same_pending_candidate_requires_matching_committed_journal(publication,change):
    p=publication
    with patch.object(release,'record_publication',side_effect=common.ReleaseError('interrupted records')):
        with pytest.raises(common.ReleaseError):release.publish(p.checkout,p.target,{})
    plan=json.loads(transaction.JOURNAL.read_text());plan.update(change)
    common.save(transaction.JOURNAL,plan);p.commands.clear()
    with pytest.raises(common.ReleaseError,match='journal does not match'):
        release.publish(p.checkout,p.target,{})
    assert p.commands==[] and (p.state/'whatsapp/pending.json').exists()


@pytest.mark.parametrize('current_contents', [None, '{invalid', '[]'])
def test_already_active_repairs_missing_or_damaged_record(publication, current_contents):
    p = publication
    release.publish(p.checkout, p.target, {})
    current = p.state/'whatsapp/current.json'
    if current_contents is None: current.unlink()
    else: current.write_text(current_contents)
    result = release.publish(p.checkout, p.target, {})
    assert result['status'] == 'already-active'
    assert json.loads(current.read_text())['filesSha256'] == common.file_map(p.source/'sally_whatsapp')
    assert len([x for x in p.commands if x[1]=='start']) == 1 and len(p.backups) == 1


def ci_run(**changes):
    return {'id': 123, 'run_attempt': 1, 'head_sha': 'a'*40, 'head_branch': 'main', 'event': 'push',
            'status': 'completed', 'conclusion': 'success', 'html_url': 'https://example.invalid/ci', **changes}


def ci_api(responses):
    calls = []
    def get(path):
        calls.append(path)
        if '/jobs?' in path:
            return {'jobs': [{'name': name, 'conclusion': 'success'} for name in
                            ['development (3.13)', 'development (3.14)', 'secrets']]}
        return {'workflow_runs': responses.pop(0) if len(responses) > 1 else responses[0]}
    return SimpleNamespace(get=get), calls


@pytest.mark.parametrize('first', [[], [ci_run(event='pull_request')], [ci_run(status='queued')],
                                  [ci_run(), ci_run(run_attempt=2, status='in_progress')]])
def test_waits_for_exact_latest_branch_ci(first):
    api, calls = ci_api([first, [ci_run(run_attempt=2)]])
    with patch.object(common.time, 'sleep') as sleep:
        result = common.verify_ci(api, 'whatsapp', 'a'*40, {'channel': 'whatsapp', 'branch': 'main'})
    assert result[0]['attempt'] == 2 and len(calls) == 3
    sleep.assert_called_once_with(10)


@pytest.mark.parametrize('runs', [[], [ci_run(head_sha='b'*40)], [ci_run(head_branch='other')]])
def test_missing_exact_ci_expires_without_accepting_other_success(runs):
    api, calls = ci_api([runs])
    with patch.object(common.time, 'sleep') as sleep, pytest.raises(common.ReleaseError, match='No branch CI'):
        common.verify_ci(api, 'whatsapp', 'a'*40, {'channel': 'whatsapp', 'branch': 'main'})
    assert len(calls) == 31 and sleep.call_count == 30


def test_completed_failed_latest_ci_is_rejected_immediately():
    api, calls = ci_api([[ci_run(id=122), ci_run(conclusion='failure')]])
    with patch.object(common.time, 'sleep') as sleep, pytest.raises(common.ReleaseError, match='not succeeded'):
        common.verify_ci(api, 'whatsapp', 'a'*40, {'channel': 'whatsapp', 'branch': 'main'})
    assert len(calls) == 1
    sleep.assert_not_called()


@pytest.mark.parametrize('cooperative', [True, False])
def test_real_child_timeout_attempts_finally_then_reaps_group(tmp_path, cooperative):
    child = tmp_path/'child.py'
    child.write_text('''
import os, signal, sys, time
from pathlib import Path
root = Path(sys.argv[1])
def interrupted(*args):
    raise RuntimeError('synthetic timeout')
signal.signal(signal.SIGTERM, interrupted if sys.argv[2] == 'True' else signal.SIG_IGN)
(root/'pid').write_text(str(os.getpid()))
try:
    (root/'stopped').touch()
    time.sleep(30)
finally:
    (root/'restored').touch()
''')
    with (tmp_path/'lock').open('w') as lock, pytest.raises(common.ReleaseError):
        release.run_backup_process([sys.executable, child, tmp_path, str(cooperative)], tmp_path,
                                   lock.fileno(), timeout=1, grace=0.2)
    assert (tmp_path/'stopped').exists()
    assert (tmp_path/'restored').exists() == cooperative
    with pytest.raises(ProcessLookupError): os.kill(int((tmp_path/'pid').read_text()), 0)


def components(tmp_path):
    (tmp_path/'waha.key').write_text('synthetic-only')
    return [{'name': slug+'.'+kind, 'kind': kind, 'command': [slug, kind], 'unit': kind,
             'port': 8821 if kind == 'gateway' else 8820, 'config': tmp_path/'config.toml', 'active': active}
            for slug, active in [('enabled', True), ('suspended', False)] for kind in ('gateway', 'bridge')]


def synthetic_backup_journal(monkeypatch, saved):
    # These tests isolate the legacy process/readiness behavior. Durable journal
    # and crash/restart coverage is exercised separately in test_backup_journal.
    # Actual generation admission is covered by test_release_admin/isolation.
    import release_admin as administration
    generation=SimpleNamespace(path=Path('/synthetic/generation'),epoch='e'*32,manifest_sha256='d'*64)
    monkeypatch.setattr(administration,'require_current',lambda *args,**kwargs:generation)
    monkeypatch.setattr(release.backup_recovery,'verify_prerequisites',lambda root:None)
    monkeypatch.setattr(release.backup_recovery,'begin',lambda *args:{'id':'synthetic'})
    def recover(root, registered, restore):
        failures=restore(saved,'0.3.1')
        if failures:
            raise common.ReleaseError('Backup service recovery requires administrator attention: '+', '.join(failures))
    monkeypatch.setattr(release.backup_recovery,'recover',recover)


@pytest.mark.parametrize('failure', ['process', 'manifest'])
def test_backup_failure_recovers_only_originally_running_components(tmp_path, monkeypatch, failure):
    saved = components(tmp_path)
    synthetic_backup_journal(monkeypatch,saved)
    starts = []
    monkeypatch.setattr(release, 'backup_components', lambda rows: saved)
    monkeypatch.setattr(release, 'run_backup_process', lambda *args: '' if failure == 'manifest' else
                        (_ for _ in ()).throw(common.ReleaseError('synthetic timeout')))
    monkeypatch.setattr(release, 'run', lambda args, **kwargs: starts.append(args))
    monkeypatch.setattr(release.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=0))
    monkeypatch.setattr(release, 'get_json', lambda *args: {'process': 'running', 'version': '0.3.1'})
    with pytest.raises(common.ReleaseError, match='restored and verified'):
        release.runtime_backups(tmp_path, [{'slug': 'enabled'}], 5, '0.3.1')
    assert starts == [['enabled', 'gateway', 'start', 'gateway'], ['enabled', 'bridge', 'start', 'bridge']]


def test_recovery_attempts_every_start_and_every_readiness_check(tmp_path, monkeypatch):
    saved, starts, reads = components(tmp_path), [], []
    def start(args, **kwargs):
        starts.append(args)
        raise common.ReleaseError('secret diagnostic must not escape')
    def get(url, *args):
        reads.append(url)
        raise common.ReleaseError('synthetic unready')
    monkeypatch.setattr(release, 'run', start)
    monkeypatch.setattr(release.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=0))
    monkeypatch.setattr(release, 'get_json', get)
    monkeypatch.setattr(release.time, 'sleep', lambda *args: None)
    assert release.restore_backup_components(saved, '0.3.1') == [
        'enabled.gateway.start', 'enabled.bridge.start', 'enabled.gateway.readiness', 'enabled.bridge.readiness']
    assert len(starts) == 2 and len(reads) == 60


def test_receiver_reports_every_unrecovered_component(tmp_path, monkeypatch):
    synthetic_backup_journal(monkeypatch,[])
    monkeypatch.setattr(release, 'backup_components', lambda rows: [])
    def fail(*args): raise common.ReleaseError('secret provider details')
    monkeypatch.setattr(release, 'run_backup_process', fail)
    monkeypatch.setattr(release, 'restore_backup_components', lambda *args,**kwargs: [
        'one.gateway.start', 'one.gateway.readiness', 'two.bridge.readiness'])
    with pytest.raises(common.ReleaseError) as error:
        release.runtime_backups(tmp_path, [], 5, '0.3.1')
    assert str(error.value) == ('Backup service recovery requires administrator attention: '
                               'one.gateway.start, one.gateway.readiness, two.bridge.readiness')


def test_receiver_holds_administration_lock_during_backup_and_activation(publication, monkeypatch):
    p = publication
    def assert_locked(*args, **kwargs):
        # A separate process cannot obtain the lock while backup/activation runs.
        code = ('import fcntl,sys; f=open(sys.argv[1],"a"); '
                'fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB)')
        result = subprocess.run([sys.executable, '-c', code, p.root/'private/tenant-admin.lock'], capture_output=True)
        assert result.returncode != 0 and b'BlockingIOError' in result.stderr
        return ['synthetic']
    monkeypatch.setattr(release, 'runtime_backups', assert_locked)
    monkeypatch.setattr(release, 'run', assert_locked)
    assert release.publish(p.checkout, p.target, {})['status'] == 'published'


@pytest.mark.parametrize('valid_fd', [True, False])
def test_backup_accepts_only_the_inherited_administration_lock(tmp_path, valid_fd):
    import fcntl
    root = tmp_path/'runtime'
    (root/'private').mkdir(parents=True)
    (root/'private/tenants.json').write_text(json.dumps({'format':1,'instances': {'synthetic': {'spec': {
        'slug': 'synthetic', 'display_name': 'Synthetic', 'subject': '11111111-1111-4111-8111-111111111111',
        'bridge_port': 8822}}}}))
    code = CHILD_IDENTITY + '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import backup_runtime as backup
from types import SimpleNamespace
backup.ROOT = Path(sys.argv[2])
backup.os.geteuid = lambda: 0
backup.backup = lambda instance,**kwargs: {'synthetic_backup_called': True}
recovery=SimpleNamespace(__file__='synthetic-release-backup.py',require_id=lambda value:{'id':value,'selected':['synthetic']},
    validate_context=lambda *args:None,recover=lambda *args:None,attach_worker=lambda *args:None)
release=SimpleNamespace(instances=lambda root:[{'slug':'synthetic'}],restore_backup_components=None)
generation=SimpleNamespace(epoch='e'*32,path=Path('/synthetic/generation'),manifest_sha256='d'*64)
administration=SimpleNamespace(require_current=lambda *args,**kwargs:generation,
    trusted_path=lambda path,**kwargs:Path(path))
backup.recovery_helpers=lambda:(recovery,release,administration,generation)
sys.argv = ['backup_runtime', '--all', '--lock-fd', sys.argv[3], '--recovery-id','synthetic',
    '--admin-pin', __import__('json').dumps({'epoch':generation.epoch,'path':str(generation.path),'manifest':generation.manifest_sha256})]
backup.main()
'''
    with (root/'private/tenant-admin.lock').open('a') as lock, (tmp_path/'other-lock').open('a') as other:
        fcntl.flock(lock, fcntl.LOCK_EX)
        inherited = lock if valid_fd else other
        result = subprocess.run([sys.executable, '-c', code, SCRIPTS, root, str(inherited.fileno())],
            pass_fds=(inherited.fileno(),), capture_output=True, text=True, timeout=3)
    assert (result.returncode == 0) == valid_fd
    assert ('synthetic_backup_called' in result.stdout) == valid_fd
    if not valid_fd: assert 'Invalid inherited' in result.stderr


def test_timeout_allows_actual_backup_finally_to_restore_synthetic_components(tmp_path, monkeypatch):
    import signal
    import time

    real_popen = release.subprocess.Popen

    def ready_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        deadline = time.monotonic() + 10
        try:
            while not (tmp_path/'snapshot-entered').exists():
                if process.poll() is not None:
                    raise AssertionError('Synthetic backup exited before snapshot entry')
                if time.monotonic() >= deadline:
                    raise AssertionError('Synthetic backup did not enter snapshot within startup budget')
                time.sleep(0.01)
            return process
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate(timeout=5)
            raise

    monkeypatch.setattr(release.subprocess, 'Popen', ready_popen)
    code = CHILD_IDENTITY + '''
import signal, sys, time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
import backup_runtime as backup
backup._INSTALLATION_ROOT=identity_root;backup._INSTALLATION_UID=os.getuid()
root = Path(sys.argv[2])
backup.ROOT = root/'runtime'
backup.Path = lambda value: root/'host'/str(value).lstrip('/')
instance = SimpleNamespace(base='synthetic', slug='synthetic', wrapper=root/'wrapper', state_dir=root/'state')
def command(args, **kwargs):
    if 'stop' in args: (root/'stopped').touch()
    return SimpleNamespace(returncode=0)
def snapshot(*args):
    (root/'snapshot-entered').touch()
    time.sleep(30)
def restore(instance, gateway, bridge):
    assert gateway and bridge
    (root/'both-restored').touch()
    return []
backup.subprocess.run = command
backup.snapshot_database = snapshot
backup.snapshot_tenant_database = lambda instance,target,**kw:snapshot(instance.state_dir/'archive.sqlite',target)
backup.restore_components = restore
signal.signal(signal.SIGTERM, backup.interrupted)
backup.backup(instance)
'''
    with (tmp_path/'lock').open('a') as lock, pytest.raises(common.ReleaseError):
        release.run_backup_process([sys.executable, '-c', code, SCRIPTS, tmp_path],
                                   tmp_path, lock.fileno(), timeout=1, grace=1)
    assert (tmp_path/'snapshot-entered').exists() and (tmp_path/'both-restored').exists()
