"""Real file swaps/SQLite under a temporary host; no host or account mutations."""
from contextlib import contextmanager, closing
import copy
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tarfile
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import restore_runtime as restore
import backup_validation
import host_integration
import installation_layout


def write(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    path.chmod(mode)


def archive(path, values):
    with tarfile.open(path, 'w:gz') as out:
        for name, content in values.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o600
            member.size = len(content)
            out.addfile(member, io.BytesIO(content))


def remanifest(snapshot):
    manifest = json.loads((snapshot / 'manifest.json').read_text())
    for name in manifest['files']:
        raw = (snapshot / name).read_bytes()
        manifest['files'][name] = {'sha256': restore.sha(raw), 'bytes': len(raw)}
    (snapshot / 'manifest.json').write_bytes(restore.encoded(manifest))
    return restore.sha((snapshot / 'manifest.json').read_bytes())


@pytest.fixture
def host(tmp_path, monkeypatch):
    root = tmp_path / 'host'
    root.mkdir(mode=0o700)
    map_path = lambda name: root / name.lstrip('/')
    profile = installation_layout.Installation.legacy()
    monkeypatch.setattr(restore, '_TRUST_ROOT', root)
    monkeypatch.setattr(restore, '_TRUST_UID', os.getuid())
    monkeypatch.setattr(backup_validation, 'installation_profile', lambda: profile)
    monkeypatch.setattr(installation_layout, 'active', lambda: profile)
    instance = SimpleNamespace(slug='fixture', base='whatsapp-fixture', auth_mode='external-oidc',
        state_dir=map_path('/var/lib/whatsapp-fixture'),
        gateway_home=map_path('/var/lib/whatsapp-fixture-waha'),
        config_dir=map_path('/etc/whatsapp-fixture'),
        wrapper=map_path('/srv/project/as-user'), service_user='wa-fixture')
    technical = {'protocol': 1, 'id': 'e' * 32, 'tenant': 'a' * 64}
    ctx = SimpleNamespace(instance=instance, profile=profile, uid=os.getuid(), gid=os.getgid(),
        technical=technical, marker=instance.config_dir / 'technical-state.json',
        state=map_path('/var/lib/develative-deploy/whatsapp/restores'), project=map_path('/srv/project'))
    ctx.state.parent.mkdir(parents=True)
    for key, path in restore.targets(ctx).items():
        write(path / 'newer-than-backup.txt', b'new retained ' + key.encode())
    for name in ('encryption.key', 'webhook.key', 'waha.key'):
        write(instance.config_dir / name, b'synthetic same key ' + name.encode())
    write(ctx.marker, restore.encoded(technical))
    write(instance.config_dir / 'config.toml', b'[bridge]\nadmin_broker_socket="/run/current-only.sock"\n')
    write(instance.wrapper, b'#!/bin/sh\nexit 99\n', 0o700)
    identity = installation_layout.identity_bytes(profile)
    write(map_path(str(installation_layout.IDENTITY)), identity)
    snapshot = map_path('/var/backups/whatsapp-fixture/snapshots/20261021T000000000000Z')
    snapshot.mkdir(parents=True, mode=0o700)
    with closing(sqlite3.connect(snapshot / 'archive.sqlite')) as db:
        db.executescript((Path(__file__).parents[1] / 'scripts/backup_schemas/8.sql').read_text())
        db.execute('INSERT INTO state VALUES (?, ?)', ('private:technical_state_identity:v1', json.dumps(technical)))
        db.execute('INSERT INTO state VALUES (?, ?)', ('restored-evidence', '"snapshot"'))
        for state in ('queued', 'sending', 'submitted'):
            db.execute('INSERT INTO sends(key,owner,payload_hash,state,created,updated) VALUES (?,?,?,?,?,?)',
                       (state, 'synthetic-owner', 'hash', state, 1, 1))
        db.execute('INSERT INTO link_sessions VALUES (?,?,?,?,?)', ('old-session', 'owner', b'never-real', 'csrf', 1))
        db.commit()
    runtime = {str(instance.config_dir / name).lstrip('/'): (instance.config_dir / name).read_bytes()
               for name in ('config.toml', 'encryption.key', 'webhook.key', 'waha.key', 'technical-state.json')}
    runtime[str(map_path(str(installation_layout.IDENTITY))).lstrip('/')] = identity
    runtime[str(instance.state_dir / 'media-cache/old.bin').lstrip('/')] = b'old cached media'
    runtime[str(instance.gateway_home / 'sessions/default/fixture.json').lstrip('/')] = b'synthetic old session'
    runtime[str(instance.gateway_home / 'media/old.bin').lstrip('/')] = b'old gateway media'
    # Unselected admin authority and another tenant's material must never restore.
    runtime[str(map_path('/etc/systemd/system/whatsapp-fixture.service')).lstrip('/')] = b'not installable'
    runtime[str(map_path('/var/lib/whatsapp-other/keep')).lstrip('/')] = b'foreign snapshot content'
    archive(snapshot / 'private-runtime.tar.gz', runtime)
    archive(snapshot / 'source.tar.gz', {name: b'not executable trusted code' for name in (
        'pyproject.toml', 'requirements.lock', 'sally_whatsapp/__init__.py', 'sally_whatsapp/store.py')})
    manifest = {'format': 'whatsapp-isolated-backup-v5', 'user': 'fixture',
        'created_utc': '20261021T000000000000Z', 'sqlite_integrity': 'ok',
        'includes_credentials': True, 'auth_mode': 'external-oidc',
        'installation': {'identity': installation_layout.identity_record(profile),
                         'files': {str(installation_layout.IDENTITY): {'sha256': restore.sha(identity), 'bytes': len(identity)}}},
        'files': {name: {} for name in ('archive.sqlite', 'private-runtime.tar.gz', 'source.tar.gz')}}
    (snapshot / 'manifest.json').write_bytes(restore.encoded(manifest))
    digest = remanifest(snapshot)
    generation = SimpleNamespace(path=map_path('/usr/local/lib/generation'), epoch='b' * 32,
                                 state='dedicated', manifest_sha256='c' * 64)
    admin = SimpleNamespace(load_generation=lambda **kwargs: generation)
    plan = {'format': restore.FORMAT, 'id': '1' * 32, 'instance': 'fixture',
            'installation_sha256': profile.sha256, 'registry_sha256': 'd' * 64,
            'snapshot': {'path': str(snapshot), 'manifest_sha256': digest},
            'current_sha256': restore.current_digest(ctx), 'owner': restore.owner_record(generation),
            'quiesce':'already_stopped','restore_service_state':'remain_stopped',
            'preimage_policy':'exact_digest','service_definitions':None,
            'account':{'name':'wa-fixture','uid':os.getuid(),'gid':os.getgid(),
                       'home':str(instance.gateway_home),'shell':'/usr/sbin/nologin','group':'wa-fixture'}}
    monkeypatch.setattr(restore, 'context', lambda *args: ctx)
    observed = []
    monkeypatch.setattr(restore, 'quiescent', lambda *args: observed.append('quiescent'))
    monkeypatch.setattr(restore, 'service_observation', lambda *args: {
        'LoadState': 'masked', 'ActiveState': 'inactive'})
    lock_path = root / 'tenant.lock'

    @contextmanager
    def admission(*args, **kwargs):
        with lock_path.open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield lock.fileno()
    monkeypatch.setattr(host_integration, 'runtime_admission', admission)
    return SimpleNamespace(root=root, ctx=ctx, plan=plan, admin=admin, snapshot=snapshot,
                           observed=observed, runtime=runtime, admission=admission)


def test_real_restore_preserves_current_data_and_never_installs_authority(host):
    before = restore.current_digest(host.ctx)
    config = (host.ctx.instance.config_dir / 'config.toml').read_bytes()
    result = restore.apply(host.plan, administration=host.admin)
    assert result['state'] == 'completed' and result['services_started'] is False
    assert restore.current_digest(host.ctx) != before
    old = host.ctx.state / host.plan['id'] / 'old'
    for key in restore.targets(host.ctx):
        assert (old / key / 'newer-than-backup.txt').read_bytes() == b'new retained ' + key.encode()
    assert (host.ctx.instance.gateway_home / 'sessions/default/fixture.json').read_bytes() == b'synthetic old session'
    assert (host.ctx.instance.config_dir / 'config.toml').read_bytes() == config
    assert not (host.root / 'etc/systemd/system/whatsapp-fixture.service').exists()
    assert not (host.root / 'var/lib/whatsapp-other').exists()
    with closing(sqlite3.connect(host.ctx.instance.state_dir / 'archive.sqlite')) as db:
        assert dict(db.execute('SELECT key,state FROM sends')) == {
            'queued': 'uncertain', 'sending': 'uncertain', 'submitted': 'submitted'}
        assert db.execute('SELECT count(*) FROM link_sessions').fetchone() == (0,)
        assert db.execute('SELECT value FROM state WHERE key="restored-evidence"').fetchone() == ('"snapshot"',)
    assert len(host.observed) == 6
    assert restore.apply(host.plan, administration=host.admin) == result


@pytest.mark.parametrize('point', ['prepared', 'state:quarantined', 'state:published',
    'sessions:quarantined', 'sessions:published', 'media:quarantined', 'media:published'])
def test_interrupted_swap_resumes_same_plan_without_deleting_preimages(host, monkeypatch, point):
    class Crash(BaseException):
        pass
    def fault(current):
        if point == current:
            raise Crash
    monkeypatch.setattr(restore, '_fault', fault)
    with pytest.raises(Crash):
        restore.apply(host.plan, administration=host.admin)
    monkeypatch.setattr(restore, '_fault', lambda _: None)
    result = restore.apply(host.plan, administration=host.admin)
    assert result['state'] == 'completed'
    for key in restore.targets(host.ctx):
        assert (host.ctx.state / host.plan['id'] / 'old' / key / 'newer-than-backup.txt').exists()


def test_new_writes_after_approval_refuse_before_staging(host):
    write(host.ctx.instance.state_dir / 'after-approval', b'preserved')
    with pytest.raises(ValueError, match='changed after restore approval'):
        restore.apply(host.plan, administration=host.admin)
    assert (host.ctx.instance.state_dir / 'after-approval').read_bytes() == b'preserved'
    assert not (host.ctx.state / host.plan['id']).exists()


def test_different_id_cannot_bypass_unfinished_restore(host, monkeypatch):
    monkeypatch.setattr(restore, '_fault', lambda _: (_ for _ in ()).throw(InterruptedError()))
    with pytest.raises(InterruptedError):
        restore.apply(host.plan, administration=host.admin)
    other = copy.deepcopy(host.plan)
    other['id'] = '2' * 32
    with pytest.raises(ValueError, match='earlier restore'):
        restore.apply(other, administration=host.admin)


def test_modified_staging_refuses_after_crash(host, monkeypatch):
    monkeypatch.setattr(restore, '_fault', lambda _: (_ for _ in ()).throw(InterruptedError()))
    with pytest.raises(InterruptedError):
        restore.apply(host.plan, administration=host.admin)
    write(host.ctx.state / host.plan['id'] / 'new/sessions/injected', b'not approved')
    monkeypatch.setattr(restore, '_fault', lambda _: None)
    with pytest.raises(ValueError, match='staged or retained data changed'):
        restore.apply(host.plan, administration=host.admin)
    assert (host.ctx.instance.gateway_home / 'sessions/newer-than-backup.txt').exists()


def test_same_id_changed_plan_is_rejected(host):
    restore.apply(host.plan, administration=host.admin)
    other = copy.deepcopy(host.plan)
    other['current_sha256'] = 'f' * 64
    with pytest.raises(ValueError, match='another plan'):
        restore.apply(other, administration=host.admin)


def test_concurrent_restore_cannot_acquire_tenant_lease(host):
    with host.admission():
        with pytest.raises(BlockingIOError):
            restore.apply(host.plan, administration=host.admin)
    assert not host.ctx.state.exists()


@pytest.mark.parametrize('part', ['file', 'directory', 'hardlink'])
def test_linked_current_data_cannot_enter_privileged_restore(host, part):
    path = host.ctx.instance.state_dir / 'danger'
    if part == 'hardlink':
        os.link(host.ctx.instance.config_dir / 'webhook.key', path)
    else:
        path.symlink_to(host.ctx.instance.config_dir if part == 'directory' else host.ctx.marker,
                        target_is_directory=part == 'directory')
    with pytest.raises((ValueError, OSError)):
        restore.apply(host.plan, administration=host.admin)


@pytest.mark.parametrize('damage', ['manifest', 'key', 'technical', 'identity', 'foreign-instance', 'path'])
def test_backup_binding_refuses_before_publishing(host, damage):
    if damage == 'manifest':
        (host.snapshot / 'manifest.json').write_text('{}')
    elif damage == 'key':
        write(host.ctx.instance.config_dir / 'webhook.key', b'rotated-current-key')
    elif damage == 'technical':
        with closing(sqlite3.connect(host.snapshot / 'archive.sqlite')) as db:
            db.execute('UPDATE state SET value=? WHERE key=?',
                       (json.dumps({**host.ctx.technical, 'id': 'f' * 32}), 'private:technical_state_identity:v1'))
            db.commit()
        host.plan['snapshot']['manifest_sha256'] = remanifest(host.snapshot)
    elif damage == 'identity':
        value = json.loads((host.snapshot / 'manifest.json').read_text())
        value['installation']['identity']['installation_sha256'] = 'f' * 64
        (host.snapshot / 'manifest.json').write_bytes(restore.encoded(value))
        host.plan['snapshot']['manifest_sha256'] = restore.sha((host.snapshot / 'manifest.json').read_bytes())
    elif damage == 'foreign-instance':
        value = json.loads((host.snapshot / 'manifest.json').read_text())
        value['user'] = 'foreign'
        (host.snapshot / 'manifest.json').write_bytes(restore.encoded(value))
        host.plan['snapshot']['manifest_sha256'] = restore.sha((host.snapshot / 'manifest.json').read_bytes())
    else:
        host.plan['snapshot']['path'] = str(host.snapshot.parent)
    with pytest.raises((ValueError, __import__('subprocess').CalledProcessError)):
        restore.apply(host.plan, administration=host.admin)
    assert (host.ctx.instance.state_dir / 'newer-than-backup.txt').exists()


def test_owner_changed_under_lock_never_publishes(host):
    original = host.admin.load_generation()
    calls = []
    def owner(**kwargs):
        calls.append(None)
        if len(calls) < 2:
            return original
        return SimpleNamespace(**{**vars(original), 'epoch': 'f' * 32})
    host.admin.load_generation = owner
    with pytest.raises(ValueError, match='owner changed under lease'):
        restore.apply(host.plan, administration=host.admin)
    assert not host.ctx.state.exists()


def test_interrupted_staging_retained_and_rebuilt_from_pinned_snapshot(host, monkeypatch):
    original = restore.stage
    def interrupted(plan, ctx, directory, fd):
        write(directory / 'new/partial', b'attributable staged-only data')
        raise InterruptedError
    monkeypatch.setattr(restore, 'stage', interrupted)
    with pytest.raises(InterruptedError):
        restore.apply(host.plan, administration=host.admin)
    monkeypatch.setattr(restore, 'stage', original)
    assert restore.apply(host.plan, administration=host.admin)['state'] == 'completed'
    assert (host.ctx.state / host.plan['id'] / 'incomplete-0/partial').read_bytes() == b'attributable staged-only data'


def test_special_archive_member_never_extracted_even_with_new_hash(host):
    target = host.snapshot / 'private-runtime.tar.gz'
    with tarfile.open(target, 'w:gz') as archive_file:
        member = tarfile.TarInfo(str(host.ctx.instance.gateway_home / 'media/evil').lstrip('/'))
        member.type = tarfile.SYMTYPE
        member.linkname = '/etc/passwd'
        archive_file.addfile(member)
    host.plan['snapshot']['manifest_sha256'] = remanifest(host.snapshot)
    with pytest.raises(ValueError):
        restore.apply(host.plan, administration=host.admin)
    assert not (host.ctx.instance.gateway_home / 'media/evil').exists()


def lifecycle(host, monkeypatch, *, restart='remain_stopped'):
    host.plan.update(quiesce='stop', restore_service_state=restart,
                     preimage_policy='preserve_all_current', current_sha256=None,
                     service_definitions={'bridge': 'b' * 64, 'gateway': 'c' * 64})
    values = {key: {'LoadState': 'loaded', 'ActiveState': 'active',
                   'MainPID': '100', 'ControlPID': '0', 'Job': '', 'UnitFileState': 'enabled'}
              for key in ('bridge', 'gateway')}
    calls = []
    monkeypatch.setattr(restore, 'service_observation', lambda ctx, component, fd: dict(values[component]))
    monkeypatch.setattr(restore, 'verify_definition', lambda ctx, component, value, plan: calls.append(('verify', component)))
    def command(ctx, component, operation, fd):
        calls.append((operation, component))
        if operation == 'stop':
            values[component].update(ActiveState='inactive', MainPID='0')
        elif operation == 'mask':
            values[component].update(LoadState='masked', UnitFileState='masked-runtime')
        elif operation == 'start':
            values[component].update(ActiveState='active', MainPID='101')
        else:
            values[component].update(LoadState='loaded', UnitFileState='enabled')
    monkeypatch.setattr(restore, 'service_command', command)
    def quiescent(ctx, fd):
        assert all(value['ActiveState'] == 'inactive' for value in values.values())
    monkeypatch.setattr(restore, 'quiescent', quiescent)
    monkeypatch.setattr(restore, 'maintenance_health', lambda ctx: calls.append(('health', 'bridge')))
    monkeypatch.setattr(restore, 'verify_start_context', lambda *args: calls.append(('start-context', 'bridge')))
    return values, calls


def test_self_restore_preserves_all_postapproval_writes_and_returns_only_maintenance(host, monkeypatch):
    values, calls = lifecycle(host, monkeypatch, restart='maintenance')
    write(host.ctx.instance.state_dir / 'post-approval-committed', b'newer writes must survive')
    result = restore.apply(host.plan, administration=host.admin)
    assert result['services_started'] is True and result['gateway_started'] is False
    assert values['bridge']['ActiveState'] == 'active'
    assert values['gateway']['ActiveState'] == 'inactive'
    assert ('start', 'gateway') not in calls
    assert (host.ctx.state / host.plan['id'] / 'old/state/post-approval-committed').read_bytes() == b'newer writes must survive'
    fence = host.ctx.instance.config_dir / 'restore-maintenance.json'
    assert json.loads(fence.read_text())['plan_sha256'] == restore.sha(restore.encoded(host.plan))
    assert json.loads(fence.read_text())['phase'] == 'maintenance'
    assert fence.stat().st_mode & 0o777 == 0o644
    count = list(calls)
    assert restore.apply(host.plan, administration=host.admin) == result
    assert calls == count


def test_lost_stop_response_reobserves_instead_of_repeating_stop(host, monkeypatch):
    values, calls = lifecycle(host, monkeypatch)
    original = restore.service_command
    first = True
    def command(ctx, component, operation, fd):
        nonlocal first
        original(ctx, component, operation, fd)
        if first and operation == 'stop':
            first = False
            raise TimeoutError('simulated response loss after stop')
    monkeypatch.setattr(restore, 'service_command', command)
    with pytest.raises(TimeoutError):
        restore.apply(host.plan, administration=host.admin)
    assert restore.apply(host.plan, administration=host.admin)['state'] == 'completed'
    assert calls.count(('stop', 'bridge')) == 1


def test_lost_start_response_observes_running_maintenance_no_duplicate_start(host, monkeypatch):
    values, calls = lifecycle(host, monkeypatch, restart='maintenance')
    original = restore.service_command
    def command(ctx, component, operation, fd):
        original(ctx, component, operation, fd)
        if operation == 'start':
            raise TimeoutError('lost maintenance startup response')
    monkeypatch.setattr(restore, 'service_command', command)
    with pytest.raises(TimeoutError):
        restore.apply(host.plan, administration=host.admin)
    assert restore.apply(host.plan, administration=host.admin)['state'] == 'completed'
    assert calls.count(('start', 'bridge')) == 1


def test_uncertain_failed_start_cannot_be_retried_blindly(host, monkeypatch):
    values, calls = lifecycle(host, monkeypatch, restart='maintenance')
    original = restore.service_command
    def command(ctx, component, operation, fd):
        if operation == 'start':
            calls.append((operation, component))
            raise TimeoutError('outcome unavailable')
        original(ctx, component, operation, fd)
    monkeypatch.setattr(restore, 'service_command', command)
    with pytest.raises(TimeoutError):
        restore.apply(host.plan, administration=host.admin)
    with pytest.raises(ValueError, match='uncertain outcome'):
        restore.apply(host.plan, administration=host.admin)
    assert calls.count(('start', 'bridge')) == 1


def test_source_definition_drift_prevents_any_stop(host, monkeypatch):
    values, calls = lifecycle(host, monkeypatch)
    monkeypatch.setattr(restore, 'verify_definition', lambda *args: (_ for _ in ()).throw(ValueError('definition differs')))
    with pytest.raises(ValueError, match='definition differs'):
        restore.apply(host.plan, administration=host.admin)
    assert not any(item[0] in ('stop', 'mask', 'start') for item in calls)
    assert (host.ctx.instance.state_dir / 'newer-than-backup.txt').exists()


def test_new_authority_cannot_replace_an_existing_maintenance_fence(host):
    write(host.ctx.instance.config_dir / 'restore-maintenance.json', restore.encoded({'id': 'not-this-plan'}), 0o644)
    with pytest.raises(ValueError, match='Another restore maintenance fence'):
        restore.apply(host.plan, administration=host.admin)
    assert (host.ctx.instance.state_dir / 'newer-than-backup.txt').exists()


@pytest.mark.parametrize('field,value', [
    ('restore_service_state', 'previous'), ('restore_service_state', 'start-all'),
    ('preimage_policy', 'ignore-data-loss'), ('quiesce', 'arbitrary-command'),
    ('service_definitions', {'bridge': 'b' * 64}), ('current_sha256', None)])
def test_plan_rejects_unapproved_service_or_data_policy(host, field, value):
    host.plan[field] = value
    with pytest.raises(ValueError):
        restore.apply(host.plan, administration=host.admin)
    assert not host.ctx.state.exists()


def test_service_commands_are_finite_and_never_start_gateway(host, monkeypatch):
    seen = []
    monkeypatch.setattr(restore.subprocess, 'run', lambda argv, **kw: seen.append((argv, kw)))
    restore.service_command(host.ctx, 'bridge', 'stop', 123)
    restore.service_command(host.ctx, 'gateway', 'mask', 123)
    assert seen[0][0] == ['/usr/bin/systemctl', 'stop', '--', 'whatsapp-fixture.service']
    assert seen[1][0] == [str(host.ctx.instance.wrapper), '/usr/bin/systemctl', '--user', '--runtime', 'mask', '--', 'whatsapp-waha.service']
    assert seen[0][1]['pass_fds'] == (123,)
    with pytest.raises(ValueError):
        restore.service_command(host.ctx, 'gateway', 'start', 123)


@pytest.mark.parametrize('field', ['encryption_key_file', 'webhook_secret_file', 'waha_key_file'])
def test_noncanonical_authority_paths_refused_before_restore_effects(host, field):
    config = {'encryption_key_file': str(host.ctx.instance.config_dir / 'encryption.key'),
              'webhook_secret_file': str(host.ctx.instance.config_dir / 'webhook.key'),
              'waha_key_file': str(host.ctx.instance.config_dir / 'waha.key')}
    restore.configured_authority(config, host.ctx.instance)
    config[field] = str(host.root / 'external-keys' / Path(config[field]).name)
    with pytest.raises(ValueError, match='canonical instance key paths'):
        restore.configured_authority(config, host.ctx.instance)
    assert not (host.ctx.instance.config_dir / 'restore-maintenance.json').exists()
    assert not host.ctx.state.exists()


def test_lost_stop_response_with_still_active_service_is_not_replayed(host, monkeypatch):
    values, calls = lifecycle(host, monkeypatch)
    def command(ctx, component, operation, fd):
        calls.append((operation, component))
        raise TimeoutError('uncertain stop')
    monkeypatch.setattr(restore, 'service_command', command)
    with pytest.raises(TimeoutError):
        restore.apply(host.plan, administration=host.admin)
    with pytest.raises(ValueError, match='stop has an uncertain outcome'):
        restore.apply(host.plan, administration=host.admin)
    assert calls.count(('stop', 'bridge')) == 1


def test_unprotected_gateway_parent_cannot_receive_privileged_swap(host):
    host.ctx.instance.gateway_home.chmod(0o777)
    host.plan['current_sha256'] = restore.current_digest(host.ctx)
    with pytest.raises(ValueError, match='parent ownership or protection'):
        restore.apply(host.plan, administration=host.admin)
    assert (host.ctx.instance.gateway_home / 'sessions/newer-than-backup.txt').exists()


def test_swap_rejects_a_symlinked_live_parent(host):
    stage = host.ctx.state.parent / 'stage'
    write(stage / 'data', b'stage')
    alternate = host.root / 'elsewhere'
    alternate.mkdir()
    old = host.ctx.instance.gateway_home
    renamed = old.with_name(old.name + '-retained')
    old.rename(renamed)
    old.symlink_to(alternate, target_is_directory=True)
    with pytest.raises(ValueError, match='Physical restore path'):
        restore.swap(host.ctx, stage, old / 'sessions', old / 'sessions')
    assert (stage / 'data').exists()
    assert not (alternate / 'sessions').exists()


@pytest.mark.parametrize('change', ['uid', 'gid', 'home', 'shell', 'group'])
def test_account_reassignment_refused_before_maintenance_or_service_mutation(host, monkeypatch, change):
    binding = dict(host.plan['account'])
    expected = SimpleNamespace(pw_name=binding['name'], pw_uid=binding['uid'], pw_gid=binding['gid'],
                               pw_dir=binding['home'], pw_shell=binding['shell'])
    group = SimpleNamespace(gr_name=binding['group'])
    monkeypatch.setattr(restore.pwd, 'getpwnam', lambda name: expected)
    monkeypatch.setattr(restore.grp, 'getgrgid', lambda gid: group)
    assert restore.account_binding(host.ctx.instance, host.ctx.profile, host.plan) is expected
    if change == 'uid': expected.pw_uid += 1
    elif change == 'gid': expected.pw_gid += 1
    elif change == 'home': expected.pw_dir += '-other'
    elif change == 'shell': expected.pw_shell = '/bin/bash'
    else: group.gr_name = 'foreign'
    with pytest.raises(ValueError, match='numeric identity, home, shell or group changed'):
        restore.account_binding(host.ctx.instance, host.ctx.profile, host.plan)
    assert not (host.ctx.instance.config_dir / 'restore-maintenance.json').exists()
    assert not host.ctx.state.exists()


@pytest.mark.parametrize('field,value', [('WorkingDirectory', '/tmp/tenant-writable'),
    ('Environment', 'PYTHONPATH=/tmp/tenant-writable'), ('EnvironmentFiles', '/tmp/environment'),
    ('RootDirectory', '/tmp/root'), ('BindPaths', '/tmp/evil:/srv/project'),
    ('User', 'root'), ('Group', 'foreign'), ('PassEnvironment', 'PYTHONPATH'),
    ('SupplementaryGroups', 'sudo'), ('DynamicUser', 'yes'), ('NoNewPrivileges', 'no')])
def test_maintenance_start_rejects_import_environment_or_privilege_drift(host, field, value):
    context = {name: '' for name in restore.START_CONTEXT}
    context.update(WorkingDirectory=str(host.ctx.project), User=host.plan['account']['name'],
                   Group=host.plan['account']['group'], DynamicUser='no', NoNewPrivileges='yes')
    restore.validate_start_context(context, host.ctx, host.plan)
    context[field] = value
    with pytest.raises(ValueError, match='import context is not source-finite'):
        restore.validate_start_context(context, host.ctx, host.plan)


@pytest.mark.parametrize('flags', [['full-privileges'], ['no-setuid'], ['ignore-failure'], ['no-env-expand']])
def test_typed_start_flags_reject_privilege_prefixes(flags):
    expected = [{'path': '/trusted/python', 'argv': ['/trusted/python', '-m', 'sally_whatsapp.cli'],
                 'ignore_errors': False}]
    row = [expected[0]['path'], expected[0]['argv'], [], 0, 0, 0, 0, 0, 0, 0]
    value = {'type': 'a(sasasttttuii)', 'data': [row]}
    restore.validate_start_ex(restore.encoded(value), expected)
    row[2] = flags
    with pytest.raises(ValueError, match='flags or executable identity'):
        restore.validate_start_ex(restore.encoded(value), expected)


@pytest.mark.parametrize('damage', ['legacy-type', 'missing', 'argv', 'multiple'])
def test_typed_start_requires_complete_matching_extended_identity(damage):
    expected = [{'path': '/trusted/python', 'argv': ['/trusted/python'], 'ignore_errors': False}]
    row = ['/trusted/python', ['/trusted/python'], [], 0, 0, 0, 0, 0, 0, 0]
    value = {'type': 'a(sasasttttuii)', 'data': [row]}
    if damage == 'legacy-type': value['type'] = 'a(sasbttttuii)'
    elif damage == 'missing': value['data'] = []
    elif damage == 'argv': row[1].append('/unreviewed/script')
    else: value['data'].append(row)
    with pytest.raises(ValueError):
        restore.validate_start_ex(restore.encoded(value), expected)


@pytest.mark.parametrize('value', [b'PYTHONPATH=/tenant\n', b'PYTHONHOME=/tenant\n', b'LD_PRELOAD=/tenant/evil.so\n'])
def test_manager_environment_cannot_override_python_runtime(value):
    restore.validate_manager_environment(b'LANG=C.UTF-8\nPATH=/usr/bin\n')
    with pytest.raises(ValueError, match='override the reviewed Python'):
        restore.validate_manager_environment(value)


def test_import_guard_failure_precedes_marker_stop_and_data_mutations(host, monkeypatch):
    values, calls = lifecycle(host, monkeypatch)
    monkeypatch.setattr(restore, 'verify_start_context',
                        lambda *args: (_ for _ in ()).throw(ValueError('unreviewed start context')))
    with pytest.raises(ValueError, match='unreviewed start context'):
        restore.apply(host.plan, administration=host.admin)
    assert not any(item[0] in ('stop', 'mask', 'start') for item in calls)
    assert not (host.ctx.instance.config_dir / 'restore-maintenance.json').exists()
    assert (host.ctx.instance.state_dir / 'newer-than-backup.txt').exists()


def test_stopped_without_mask_cannot_skip_the_startup_guard(host, monkeypatch):
    monkeypatch.setattr(restore, 'service_observation', lambda *args: {
        'LoadState': 'loaded', 'ActiveState': 'inactive'})
    with pytest.raises(ValueError, match='both named units masked'):
        restore.apply(host.plan, administration=host.admin)
    assert not (host.ctx.instance.config_dir / 'restore-maintenance.json').exists()


@pytest.mark.parametrize('root', ['source', 'installed'])
def test_reviewed_gate_source_pins_are_independent_of_advertised_version(host, root):
    source = Path(__file__).parents[1] / 'sally_whatsapp'
    paths = {'source': host.ctx.project / 'sally_whatsapp',
             'installed': host.ctx.project / '.venv/lib/python3.13/site-packages/sally_whatsapp'}
    for path in paths.values():
        for name in restore.RESTORE_GATE_SOURCES:
            write(path / name, (source / name).read_bytes())
    restore.verify_gate_sources(host.ctx)
    write(paths[root] / 'server.py', b'__version__="0.8.0"\n# Historical backend without restore admission\n')
    with pytest.raises(ValueError, match='reviewed restoration fence'):
        restore.verify_gate_sources(host.ctx)


def startup_context(host, monkeypatch):
    """Real import tree and admission, with only systemd observations replaced."""
    import runtime_lifecycle
    source = Path(__file__).parents[1] / 'sally_whatsapp'
    package = host.ctx.project / '.venv/lib/python3.13/site-packages/sally_whatsapp'
    for path in (host.ctx.project / 'sally_whatsapp', package):
        for name in restore.RESTORE_GATE_SOURCES:
            write(path / name, (source / name).read_bytes())
    write(host.ctx.project / '.venv/pyvenv.cfg', 'include-system-site-packages = false\n')
    expected = {'path': str(host.ctx.project / '.venv/bin/python'),
                'argv': [str(host.ctx.project / '.venv/bin/python'), '-m', 'sally_whatsapp.cli'],
                'ignore_errors': False}
    row = [expected['path'], expected['argv'], [], 0, 0, 0, 0, 0, 0, 0]
    context = {name: '' for name in restore.START_CONTEXT}
    context.update(WorkingDirectory=str(host.ctx.project), User=host.plan['account']['name'],
                   Group=host.plan['account']['group'], DynamicUser='no', NoNewPrivileges='yes')
    monkeypatch.setattr(restore, 'service_observation', lambda *args: {'ExecStart': [expected]})
    monkeypatch.setattr(restore, 'verify_definition', lambda *args: None)
    monkeypatch.setattr(restore, 'service_tenant', lambda *args: {})
    monkeypatch.setattr(runtime_lifecycle, 'command', lambda *args: ['/usr/bin/busctl', 'ExecStart'])
    calls = []
    def observation(argv, **kwargs):
        calls.append(argv)
        assert kwargs['pass_fds'] == (123,)
        if argv[0] == '/usr/bin/busctl':
            assert argv[-1] == 'ExecStartEx'
            return SimpleNamespace(stdout=restore.encoded({'type': 'a(sasasttttuii)', 'data': [row]}))
        if argv[1] == 'show':
            return SimpleNamespace(stdout=''.join(key+'='+value+'\n' for key, value in context.items()).encode())
        assert argv == ['/usr/bin/systemctl', 'show-environment']
        return SimpleNamespace(stdout=b'LANG=C\n')
    monkeypatch.setattr(restore.subprocess, 'run', observation)
    return SimpleNamespace(package=package, row=row, calls=calls)


@pytest.mark.parametrize('damage', [None, 'flags', 'user-site', 'path-hook', 'old-backend'])
def test_complete_start_context_attests_typed_manager_and_root_import_tree(host, monkeypatch, damage):
    context = startup_context(host, monkeypatch)
    if damage == 'flags': context.row[2] = ['full-privileges']
    elif damage == 'user-site': write(host.ctx.project / '.venv/pyvenv.cfg', 'include-system-site-packages = true\n')
    elif damage == 'path-hook': write(context.package.parent / 'custom.pth', 'import tenant_controlled\n')
    elif damage == 'old-backend': write(context.package / 'server.py', '__version__="0.8.0"\n')
    if damage is None:
        restore.verify_start_context(host.ctx, host.plan, 123)
        assert len(context.calls) == 3
    else:
        with pytest.raises(ValueError):
            restore.verify_start_context(host.ctx, host.plan, 123)
    assert not (host.ctx.instance.config_dir / 'restore-maintenance.json').exists()


@pytest.mark.parametrize('reference', ['absolute', 'relative', 'directory-symlink'])
def test_startup_rejects_passive_pth_with_external_writable_sitecustomize(host, monkeypatch, reference):
    run = restore.subprocess.run
    context = startup_context(host, monkeypatch)
    external = host.root / 'protected-import-directory'
    external.mkdir(mode=0o755)
    write(external / 'sitecustomize.py',
          'import builtins\nbuiltins.RESTORE_SYNTHETIC_HOOK_EXECUTED = True\n', 0o666)
    location = str(external)
    if reference == 'relative':
        location = os.path.relpath(external, context.package.parent)
    elif reference == 'directory-symlink':
        alias = context.package.parent / 'external-imports'
        alias.symlink_to(external, target_is_directory=True)
        location = alias.name
    write(context.package.parent / 'external.pth', location + '\n')
    # Exercise actual Python site startup in an isolated child: a passive .pth
    # can execute this harmless file before the application entry point.
    child = run([sys.executable, '-I', '-S', '-c',
        'import builtins,site,sys;site.addsitedir(sys.argv[1]);site.execsitecustomize();'
        'assert builtins.RESTORE_SYNTHETIC_HOOK_EXECUTED;print("synthetic-hook")',
        str(context.package.parent)], capture_output=True, text=True, check=True)
    assert child.stdout.strip() == 'synthetic-hook'
    with pytest.raises(ValueError, match='escapes.*attested'):
        restore.verify_start_context(host.ctx, host.plan, 123)
    assert not (host.ctx.instance.config_dir / 'restore-maintenance.json').exists()


@pytest.mark.parametrize('reference', ['absolute', 'relative', 'internal-directory-symlink'])
def test_startup_accepts_passive_pth_only_with_fully_attested_internal_directory(host, monkeypatch, reference):
    context = startup_context(host, monkeypatch)
    internal = context.package.parent / 'protected-import-directory'
    internal.mkdir(mode=0o755)
    write(internal / 'example.py', 'value = "synthetic"\n')
    location = str(internal) if reference == 'absolute' else internal.name
    if reference == 'internal-directory-symlink':
        alias = context.package.parent / 'internal-imports'
        alias.symlink_to(internal, target_is_directory=True)
        location = alias.name
    write(context.package.parent / 'internal.pth', location + '\n')
    restore.verify_start_context(host.ctx, host.plan, 123)
    # The target's contents, not only its directory, remain subject to admission.
    (internal / 'example.py').chmod(0o666)
    with pytest.raises(ValueError, match='not protected'):
        restore.verify_start_context(host.ctx, host.plan, 123)


def test_startup_rejects_external_directory_alias_without_pth(host, monkeypatch):
    context = startup_context(host, monkeypatch)
    external = host.root / 'protected-external-package'
    external.mkdir(mode=0o755)
    write(external / '__init__.py', 'value = "synthetic"\n', 0o666)
    (context.package.parent / 'external_package').symlink_to(external, target_is_directory=True)
    with pytest.raises(ValueError, match='Runtime import directory escapes'):
        restore.verify_start_context(host.ctx, host.plan, 123)


def test_startup_rejects_writable_symlinked_import_file(host, monkeypatch):
    context = startup_context(host, monkeypatch)
    external = host.root / 'external_module.py'
    write(external, 'value = "synthetic"\n', 0o666)
    (context.package.parent / 'external_module.py').symlink_to(external)
    with pytest.raises(ValueError, match='not protected'):
        restore.verify_start_context(host.ctx, host.plan, 123)


def test_startup_rejects_writable_working_directory_shadow_before_cli_import(host, monkeypatch):
    run = restore.subprocess.run
    startup_context(host, monkeypatch)
    write(host.ctx.project / 'json.py', 'print("synthetic-cli-shadow");raise SystemExit(42)\n', 0o666)
    # json is imported on CLI line two, before configuration or the restoration
    # fence. No provider or application database is reached by this child.
    child = run([sys.executable, '-S', '-m', 'sally_whatsapp.cli'], cwd=host.ctx.project,
                env={}, capture_output=True, text=True, check=False)
    assert child.returncode == 42 and child.stdout.strip() == 'synthetic-cli-shadow'
    with pytest.raises(ValueError, match='not protected'):
        restore.verify_start_context(host.ctx, host.plan, 123)


@pytest.mark.parametrize('name', ['shadow.pyc', 'shadow.so', 'namespace_package/submodule.py'])
def test_startup_rejects_other_mutable_working_directory_import_candidates(host, monkeypatch, name):
    startup_context(host, monkeypatch)
    write(host.ctx.project / name, b'synthetic never executed', 0o666)
    with pytest.raises(ValueError, match='not protected'):
        restore.verify_start_context(host.ctx, host.plan, 123)


def test_startup_rejects_working_directory_namespace_alias_outside_attested_roots(host, monkeypatch):
    startup_context(host, monkeypatch)
    external = host.root / 'protected-external-namespace'
    write(external / 'nested/module.py', b'synthetic never executed')
    (host.ctx.project / 'namespace_package').symlink_to(external, target_is_directory=True)
    with pytest.raises(ValueError, match='Runtime import directory escapes'):
        restore.verify_start_context(host.ctx, host.plan, 123)


def test_startup_accepts_release_venv_symlink_and_internal_library_alias(host, monkeypatch):
    startup_context(host, monkeypatch)
    venv = host.ctx.project / '.venv'
    release_venv = host.root / 'protected-release-venv'
    venv.rename(release_venv)
    venv.symlink_to(release_venv, target_is_directory=True)
    (release_venv / 'lib64').symlink_to(release_venv / 'lib', target_is_directory=True)
    restore.verify_start_context(host.ctx, host.plan, 123)
