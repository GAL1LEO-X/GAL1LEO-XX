"""Same-schema patch delivery, synthetic services and a real SQLite archive."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tomllib
import zipfile

import pytest

from tesla_plugin import schema_migrations
from tesla_plugin.store import SCHEMA
from test_schema3_update import (adapter_module, rig as schema_rig, OWNER, OWNERS,
                                PREVIOUS, CANDIDATE, sha, sql, add_sample, add_intent)


PATH = Path(__file__).parents[1] / 'deploy' / 'patch_update.py'
HISTORICAL_REQUIREMENTS = Path(__file__).with_name('fixtures') / 'requirements-through-1.0.4.lock'


def candidate_inputs(module):
    root = PATH.parent.parent
    return {name: (HISTORICAL_REQUIREMENTS if name == 'requirements.lock'
                   and module.CANDIDATE_FILES[name] == sha(HISTORICAL_REQUIREMENTS) else root / name).read_bytes()
            for name in module.CANDIDATE_FILES}


@pytest.fixture(params=["patch_update.py", "patch103_update.py", "patch104_update.py", "patch105_update.py"])
def patch_module(request):
    path = PATH.with_name(request.param)
    spec = importlib.util.spec_from_file_location('synthetic_patch_adapter', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.fixture_path = path
    module.fixture_previous_version, module.fixture_candidate_version = {
        "patch_update.py": ("1.0.1", "1.0.2"),
        "patch103_update.py": ("1.0.2", "1.0.3"),
        "patch104_update.py": ("1.0.3", "1.0.4"),
        "patch105_update.py": ("1.0.4", "1.0.5"),
    }[request.param]
    return module


@pytest.fixture
def patch_rig(schema_rig, patch_module, monkeypatch):
    rig = schema_rig
    schema_migrations.initialize_database(rig.database, OWNER, SCHEMA)
    rig.previous_version, rig.candidate_version = patch_module.fixture_previous_version, patch_module.fixture_candidate_version
    path = patch_module.fixture_path
    (rig.previous / 'VERSION').write_text(rig.previous_version+'\n')
    old_store = rig.previous / 'src/tesla_plugin/store.py'
    old_store.parent.mkdir(parents=True)
    old_store.write_text('synthetic reviewed previous Store\n')
    monkeypatch.setattr(patch_module, 'PREVIOUS_STORE', sha(old_store))
    entries = candidate_inputs(patch_module)
    entries.update({'VERSION': (rig.candidate_version+'\n').encode(), 'deploy/'+path.name: path.read_bytes(),
                    'deploy/schema3_update.py': PATH.with_name('schema3_update.py').read_bytes()})
    (rig.previous / 'requirements.lock').write_bytes(HISTORICAL_REQUIREMENTS.read_bytes())
    (rig.previous / 'src/tesla_plugin/schema_migrations.py').write_bytes(entries['src/tesla_plugin/schema_migrations.py'])
    with zipfile.ZipFile(rig.archive, 'w') as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
        archive.writestr('SHA256SUMS.json', json.dumps({name: hashlib.sha256(data).hexdigest()
                                                      for name, data in entries.items()}))
    rig.profile['source_archive_sha256'] = sha(rig.archive)
    rig.adapter = patch_module.Adapter(rig.profile, rig.ops, unit_root=rig.units)
    rig.module = patch_module
    snapshot = rig.adapter.inspect()
    rig.profile.update(expected_owner_digest=snapshot['owner_digest'],
                       expected_intent_digest=snapshot['intent_digest'])
    rig.health_calls = []

    def health(version):
        rig.health_calls.append(version)
        assert sql(rig.database, "SELECT value FROM meta WHERE key='schema'") == [('3',)]
        assert not rig.adapter.hold.exists()
        expected = CANDIDATE if version == rig.candidate_version else PREVIOUS
        for name in OWNERS:
            assert rig.ops.states[name]['ActiveState'] == 'active'
            assert expected in (rig.units / (name + '.service')).read_text()
    monkeypatch.setattr(rig.adapter, '_health', health)
    rig.real_health = health

    def backup_process(arguments):
        assert all(rig.ops.states[name]['ActiveState'] == 'inactive' for name in OWNERS)
        assert all(rig.ops.startup_inhibited(name) for name in OWNERS)
        monkeypatch.setattr(sys, 'argv', ['patch-backup', *arguments[3:]])
        output = io.StringIO()
        with redirect_stdout(output):
            exec(compile(arguments[2], 'synthetic-patch-backup', 'exec'), {})
        return output.getvalue()
    monkeypatch.setattr(rig.adapter, '_schema_process', backup_process)
    return rig


def test_patch_stage_and_activate_preserve_schema_data_settings_and_transports(patch_rig):
    rig = patch_rig
    before = rig.database.read_bytes()
    settings = rig.settings.read_bytes()
    rig.adapter.stage()
    assert rig.database.read_bytes() == before
    assert not any(call[:2] == ['systemctl', 'stop'] for call in rig.ops.calls)
    result = rig.adapter.activate()
    assert result['state'] == 'active' and result['schema'] == 3
    assert result['candidate_writers_may_have_run'] is True
    backup = Path(result['database_backup'])
    assert backup.stat().st_mode & 0o777 == 0o600
    assert sql(backup, 'PRAGMA integrity_check') == [('ok',)]
    assert sql(backup, "SELECT value FROM meta WHERE key='schema'") == [('3',)]
    assert sql(backup, 'SELECT * FROM samples') == sql(rig.database, 'SELECT * FROM samples')
    assert rig.settings.read_bytes() == settings
    assert rig.health_calls == [rig.candidate_version]
    for name in ('tesla-command', 'tesla-telemetry', 'tesla-kafka'):
        assert rig.ops.states[name]['ActiveState'] == 'active'
        assert (rig.units / (name + '.service')).read_bytes() == rig.initial_units[name]


def test_failure_before_candidate_start_restores_original_units_without_replacing_database(patch_rig):
    rig = patch_rig
    rig.adapter.stage()
    original = rig.ops.atomic
    failed = False
    def fail_once(path, value):
        nonlocal failed
        if Path(path) == rig.units / 'tesla-consumer.service' and CANDIDATE in str(value) and not failed:
            failed = True
            raise OSError('synthetic unit replacement failure')
        original(path, value)
    rig.ops.atomic = fail_once
    with pytest.raises(OSError):
        rig.adapter.activate()
    result = json.loads((rig.adapter.recovery / 'activation.json').read_text())
    assert result['state'] == 'rolled_back' and result['schema'] == 3
    assert rig.health_calls == [rig.previous_version]
    for name in OWNERS:
        assert (rig.units / (name + '.service')).read_bytes() == rig.initial_units[name]
        assert rig.ops.states[name]['ActiveState'] == 'active'
    assert sql(rig.database, 'SELECT count(*) FROM samples') == [(1,)]


def test_failure_after_candidate_start_holds_writers_and_keeps_new_samples(patch_rig, monkeypatch):
    rig = patch_rig
    rig.adapter.stage()
    def failed_health(version):
        rig.real_health(version)
        add_sample(rig.database, 'new-candidate-observation')
        raise ValueError('synthetic unhealthy candidate')
    monkeypatch.setattr(rig.adapter, '_health', failed_health)
    with pytest.raises(rig.module.base.RecoveryIncomplete):
        rig.adapter.activate()
    result = json.loads((rig.adapter.recovery / 'activation.json').read_text())
    assert result['state'] == 'recovery_incomplete'
    assert result['forward_recovery_required'] is True
    assert rig.adapter.hold.exists()
    assert sql(rig.database, 'SELECT count(*) FROM samples') == [(2,)]
    assert rig.health_calls == [rig.candidate_version]
    for name in OWNERS:
        assert rig.ops.states[name]['ActiveState'] == 'inactive'
        assert rig.ops.startup_inhibited(name)
    with pytest.raises(rig.module.base.RecoveryIncomplete):
        rig.adapter.recover()
    assert sql(rig.database, 'SELECT count(*) FROM samples') == [(2,)]


def test_post_start_rollback_refuses_before_stopping_healthy_candidate(patch_rig):
    rig = patch_rig
    rig.adapter.stage()
    rig.adapter.activate()
    calls = list(rig.ops.calls)
    with pytest.raises(ValueError, match='forward recovery'):
        rig.adapter.rollback()
    assert rig.ops.calls == calls
    assert not rig.adapter.hold.exists()
    assert all(rig.ops.states[name]['ActiveState'] == 'active' for name in OWNERS)


def test_start_marker_is_durable_before_start_command_even_if_start_result_uncertain(patch_rig):
    rig = patch_rig
    rig.adapter.stage()
    def uncertain(action, arguments):
        if action == 'start':
            receipt = json.loads((rig.adapter.recovery / 'activation.json').read_text())
            assert receipt['candidate_writers_may_have_run'] is True
            raise OSError('synthetic uncertain start')
    rig.ops.before_system = uncertain
    with pytest.raises(rig.module.base.RecoveryIncomplete):
        rig.adapter.activate()
    assert rig.adapter.hold.exists()
    assert all(rig.ops.states[name]['ActiveState'] == 'inactive' for name in OWNERS)


@pytest.mark.parametrize('change', ['archive', 'store', 'manifest', 'previous_version', 'previous_store',
                                  'previous_lock', 'candidate_lock'])
def test_patch_verification_is_exact_and_rejects_drift(patch_rig, change):
    rig = patch_rig
    rig.adapter.stage()
    path = {'archive': rig.archive, 'store': rig.adapter.release / 'src/tesla_plugin/store.py',
            'manifest': rig.adapter.release / 'SHA256SUMS.json',
            'previous_version': rig.previous / 'VERSION',
            'previous_store': rig.previous / 'src/tesla_plugin/store.py',
            'previous_lock': rig.previous / 'requirements.lock',
            'candidate_lock': rig.adapter.release / 'requirements.lock'}[change]
    path.write_bytes(path.read_bytes() + b'synthetic drift')
    with pytest.raises(ValueError):
        rig.adapter._verify_release()


def test_patch_pins_match_candidate_package_and_historical_adapter(patch_module):
    assert {name: hashlib.sha256(data).hexdigest() for name, data in candidate_inputs(patch_module).items()} == patch_module.CANDIDATE_FILES
    assert sha(PATH.with_name('schema3_update.py')) == patch_module.BASE_ADAPTER_SHA256


@pytest.mark.parametrize('patch_module', ['patch105_update.py'], indirect=True)
def test_patch105_stage_uses_exact_reviewed_build_dependency_without_changing_runtime_closure(patch_rig):
    rig = patch_rig
    rig.adapter.stage()
    project = tomllib.loads((rig.adapter.release / 'pyproject.toml').read_text())
    assert project['build-system']['requires'] == [rig.module.BUILD_REQUIREMENT]
    dependency_calls = [call for call in rig.ops.calls if call[1:4] == ['-m', 'pip', 'install'] and '-r' in call]
    assert len(dependency_calls) == 1
    assert dependency_calls[0][-1] == 'setuptools==84.0.0'
    assert (rig.previous / 'requirements.lock').read_bytes() == HISTORICAL_REQUIREMENTS.read_bytes()
    assert (rig.adapter.release / 'requirements.lock').read_bytes() == HISTORICAL_REQUIREMENTS.read_bytes().replace(
        b'opentelemetry-api==1.45.1\n', b'opentelemetry-api==1.45.2\n')


@pytest.mark.parametrize('patch_module', ['patch105_update.py'], indirect=True)
@pytest.mark.parametrize('change', ['extra_dependency', 'missing_otel', 'duplicate_otel', 'old_otel',
                                  'previous_schema', 'candidate_build'])
def test_patch105_rejects_unreviewed_closure_and_schema_before_writer_changes(patch_rig, monkeypatch, change):
    rig = patch_rig
    rig.adapter.stage()
    calls = list(rig.ops.calls)
    if change == 'previous_schema':
        path = rig.previous / 'src/tesla_plugin/schema_migrations.py'
        path.write_bytes(path.read_bytes() + b'\n# drift\n')
    elif change == 'candidate_build':
        path = rig.adapter.release / 'pyproject.toml'
        path.write_bytes(path.read_bytes().replace(b'setuptools==84.0.0', b'setuptools==84.1.0'))
    else:
        path = rig.adapter.release / 'requirements.lock'
        replacement = {'extra_dependency': b'opentelemetry-api==1.45.2\nunreviewed==1.0\n',
                       'missing_otel': b'', 'duplicate_otel': b'opentelemetry-api==1.45.2\nopentelemetry-api==1.45.2\n',
                       'old_otel': b'opentelemetry-api==1.45.1\n'}[change]
        path.write_bytes(path.read_bytes().replace(b'opentelemetry-api==1.45.2\n', replacement))
        # Even repinning a candidate cannot silently widen this transition.
        monkeypatch.setattr(rig.module, 'CANDIDATE_FILES', rig.module.CANDIDATE_FILES | {'requirements.lock': sha(path)})
    with pytest.raises(ValueError):
        rig.adapter._verify_release()
    assert rig.ops.calls == calls
    assert all(rig.ops.states[name]['ActiveState'] == 'active' for name in OWNERS)


def test_crash_before_candidate_start_is_recoverable_without_database_replacement(patch_rig):
    rig = patch_rig
    rig.adapter.stage()
    original = rig.ops.atomic
    def crash(path, value):
        if Path(path) == rig.units / 'tesla-consumer.service' and CANDIDATE in str(value):
            raise SystemExit('synthetic process death')
        original(path, value)
    rig.ops.atomic = crash
    with pytest.raises(SystemExit):
        rig.adapter.activate()
    rig.ops.atomic = original
    assert rig.adapter.hold.exists()
    result = rig.adapter.recover()
    assert result['state'] == 'rolled_back'
    assert rig.health_calls == [rig.previous_version]
    assert sql(rig.database, 'SELECT count(*) FROM samples') == [(1,)]


@pytest.mark.parametrize('marker', [None, True, 1, 'false'])
def test_ambiguous_or_started_marker_never_authorizes_older_binary(patch_rig, marker):
    rig = patch_rig
    rig.adapter.stage()
    receipt = rig.adapter.recovery / 'activation.json'
    receipt.write_text(json.dumps({'state': 'started', 'candidate_writers_may_have_run': marker}))
    with pytest.raises(rig.module.base.RecoveryIncomplete):
        rig.adapter.recover()
    assert rig.adapter.hold.exists()
    assert all(rig.ops.states[name]['ActiveState'] == 'inactive' for name in OWNERS)
    assert rig.health_calls == []


def test_backup_contains_committed_wal_and_retains_every_semantic_marker(patch_rig):
    rig = patch_rig
    import sqlite3
    with sqlite3.connect(rig.database) as writer:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute("INSERT INTO meta VALUES('discovery_sequence','20')")
        writer.execute("INSERT INTO snapshots VALUES(?,?,?,?,?,?)",
                       ('synthetic-vehicle', 'drive_state', '{"shift_state":"P"}', 'rest_time_conflict', 120, 125))
        writer.commit()
        backup = rig.module.backup_database(rig.database, OWNER)
        assert sql(backup, "SELECT value FROM meta WHERE key='discovery_sequence'") == [('20',)]
        assert sql(backup, "SELECT source FROM snapshots WHERE section='drive_state'") == [('rest_time_conflict',)]
        assert sql(backup, 'PRAGMA integrity_check') == [('ok',)]
    assert sql(rig.database, "SELECT source FROM snapshots WHERE section='drive_state'") == [('rest_time_conflict',)]


@pytest.mark.parametrize('change', ['wrong_owner', 'wrong_schema', 'public_mode', 'symlink'])
def test_backup_rejects_unsafe_source_before_creating_recovery_file(patch_rig, change):
    rig = patch_rig
    path = rig.database
    if change == 'wrong_owner':
        sql(path, "UPDATE meta SET value='different-owner' WHERE key='owner'")
    elif change == 'wrong_schema':
        sql(path, "UPDATE meta SET value='4' WHERE key='schema'")
    elif change == 'public_mode':
        path.chmod(0o644)
    else:
        path = path.with_name('alias.sqlite3')
        path.symlink_to(rig.database)
    with pytest.raises(ValueError):
        rig.module.backup_database(path, OWNER)
    assert not list(rig.database.parent.glob('*.pre-patch-*'))


def interrupted_candidate(rig, monkeypatch):
    rig.adapter.stage()
    def failed_health(version):
        rig.real_health(version)
        add_sample(rig.database, 'new-after-candidate-start')
        sql(rig.database, "INSERT INTO meta VALUES('discovery_sequence','21')")
        sql(rig.database, "INSERT INTO snapshots VALUES(?,?,?,?,?,?)",
            ('synthetic-vehicle', 'drive_state', '{"shift_state":"P"}', 'rest_time_conflict', 120, 125))
        raise ValueError('synthetic health problem, subsequently corrected')
    monkeypatch.setattr(rig.adapter, '_health', failed_health)
    with pytest.raises(rig.module.base.RecoveryIncomplete):
        rig.adapter.activate()
    monkeypatch.setattr(rig.adapter, '_health', rig.real_health)


def database_rows(rig):
    return {table: sql(rig.database, 'SELECT * FROM ' + table + ' ORDER BY rowid')
            for table in ('samples', 'snapshots', 'meta', 'intents', 'oauth_states', 'temporary_collections')}


def assert_held(rig):
    assert rig.adapter.hold.exists()
    assert all(rig.ops.states[name]['ActiveState'] == 'inactive' and rig.ops.startup_inhibited(name)
               for name in OWNERS)


def starts(rig):
    return [call for call in rig.ops.calls if call[:2] == ['systemctl', 'start']]


def test_forward_recovery_preserves_new_rows_markers_and_original_failure(patch_rig, monkeypatch):
    rig = patch_rig
    interrupted_candidate(rig, monkeypatch)
    rows = database_rows(rig)
    original = (rig.adapter.recovery / 'activation.json').read_bytes()
    result = rig.adapter.recover_forward()
    assert result['state'] == 'active' and result['phase'] == 'health_verified'
    assert result['database_restored'] is False and result['reconciled_running'] is False
    assert database_rows(rig) == rows
    assert sql(result['database_backup'], 'SELECT * FROM samples ORDER BY rowid') == rows['samples']
    assert (rig.adapter.recovery / 'activation.json').read_bytes() == original
    assert rig.health_calls == [rig.candidate_version, rig.candidate_version]
    assert all(CANDIDATE in (rig.units / (name + '.service')).read_text() for name in OWNERS)
    start_count = len(starts(rig))
    backups = sorted(rig.database.parent.glob('*.pre-patch-*'))
    attempts = sorted(rig.adapter.recovery.glob('forward-recovery-*.json'))
    assert rig.adapter.recover_forward() == result  # Successful retry is read only.
    assert len(starts(rig)) == start_count and database_rows(rig) == rows
    assert sorted(rig.database.parent.glob('*.pre-patch-*')) == backups
    assert sorted(rig.adapter.recovery.glob('forward-recovery-*.json')) == attempts
    with pytest.raises(ValueError, match='forward recovery exists'):
        rig.adapter.recover()
    assert all(rig.ops.states[name]['ActiveState'] == 'active' for name in OWNERS)


@pytest.mark.parametrize('recovery', [False, True])
def test_patch_preserves_additive_readback_fences_and_opaque_metadata(patch_rig, monkeypatch, recovery):
    """Schema-3 maintenance preserves additive metadata, including post-start rows."""
    rig = patch_rig
    if recovery:
        interrupted_candidate(rig, monkeypatch)
    ref = 'synthetic-vehicle'
    metadata = {
        'collection_readback_sequence:' + ref: '43',
        'collection_readback_applied:' + ref: '42',
        'synthetic_future_extension': json.dumps({'observed_at': 1700000010, 'status': 'synthetic-failure',
                                                'attempts': 12}),
    }
    for key, value in metadata.items():
        sql(rig.database, 'INSERT INTO meta VALUES(?,?)', (key, value))
    sql(rig.database, 'INSERT INTO snapshots VALUES(?,?,?,?,?,?)',
        (ref, 'telemetry_remote', json.dumps({'config': {'fields': {'BatteryLevel': {'interval_seconds': 5,
                  'minimum_delta': 1.0}}}, 'synced': True}), 'tesla_api', 1700000000, 1700000000))
    before = database_rows(rig)
    if recovery:
        result = rig.adapter.recover_forward()
    else:
        rig.adapter.stage()
        result = rig.adapter.activate()
    assert result['state'] == 'active' and result['schema'] == 3
    assert database_rows(rig) == before
    backup = result['database_backup']
    for table in before:
        assert sql(backup, 'SELECT * FROM ' + table + ' ORDER BY rowid') == before[table]
    assert sql(rig.database, "SELECT value FROM meta WHERE key='schema'") == [('3',)]


@pytest.mark.parametrize('failure', ['backup', 'start_uncertain', 'health', 'after_start_owner_drift'])
def test_forward_failure_keeps_data_and_holds_both_writers(patch_rig, monkeypatch, failure):
    rig = patch_rig
    interrupted_candidate(rig, monkeypatch)
    rows = database_rows(rig)
    if failure == 'backup':
        monkeypatch.setattr(rig.adapter, '_backup', lambda: (_ for _ in ()).throw(OSError('disk full')))
    elif failure == 'start_uncertain':
        def uncertain(action, arguments):
            if action == 'start':
                receipt = json.loads((rig.adapter.recovery / 'forward-recovery-000001.json').read_text())
                assert receipt['phase'] == 'candidate_start_pending'
                rig.ops.states[OWNERS[0]]['ActiveState'] = 'active'
                add_sample(rig.database, 'written-before-uncertain-start-result')
                raise OSError('unknown start result')
        rig.ops.before_system = uncertain
    else:
        def failed_health(version):
            rig.real_health(version)
            add_sample(rig.database, 'written-before-failed-health')
            if failure == 'after_start_owner_drift':
                sql(rig.database, 'UPDATE trigger_settings SET revision=12')
            else:
                raise ValueError('still unhealthy')
        monkeypatch.setattr(rig.adapter, '_health', failed_health)
    with pytest.raises(rig.module.base.RecoveryIncomplete):
        rig.adapter.recover_forward()
    assert_held(rig)
    current = database_rows(rig)
    assert current['snapshots'] == rows['snapshots'] and current['meta'] == rows['meta']
    assert current['samples'][:len(rows['samples'])] == rows['samples']
    assert len(current['samples']) == len(rows['samples']) + (failure != 'backup')
    receipt = json.loads((rig.adapter.recovery / 'forward-recovery-000001.json').read_text())
    assert receipt['state'] == 'recovery_incomplete' and receipt['writers_stopped']
    assert all(CANDIDATE in (rig.units / (name + '.service')).read_text() for name in OWNERS)


def test_explicit_retry_after_uncertain_start_keeps_attempts_and_does_not_replay_activation(patch_rig, monkeypatch):
    rig = patch_rig
    interrupted_candidate(rig, monkeypatch)
    def uncertain(action, arguments):
        if action == 'start':
            raise OSError('synthetic timeout')
    rig.ops.before_system = uncertain
    with pytest.raises(rig.module.base.RecoveryIncomplete):
        rig.adapter.recover_forward()
    failed = (rig.adapter.recovery / 'forward-recovery-000001.json').read_bytes()
    rig.ops.before_system = None
    assert rig.adapter.recover_forward()['attempt'] == 2
    assert (rig.adapter.recovery / 'forward-recovery-000001.json').read_bytes() == failed
    assert len(starts(rig)) == 3  # Activation + failed attempt + explicit successful attempt.


@pytest.mark.parametrize('phase', ['before_start', 'after_start', 'after_health', 'after_success_receipt'])
def test_forward_crash_restart_reconciles_healthy_runtime_without_restart(patch_rig, monkeypatch, phase):
    rig = patch_rig
    interrupted_candidate(rig, monkeypatch)
    original_atomic, original_health = rig.ops.atomic, rig.adapter._health
    original_process = rig.adapter._schema_process
    def crash_atomic(path, value):
        if Path(path).name == 'forward-recovery-000001.json':
            data = json.loads(value)
            if phase == 'before_start' and data['phase'] == 'candidate_start_pending':
                original_atomic(path, value)
                raise SystemExit('crash with durable marker and hold')
            if phase == 'after_health' and data['state'] == 'active':
                raise SystemExit('health complete, success receipt not committed')
            if phase == 'after_success_receipt' and data['state'] == 'active':
                original_atomic(path, value)
                raise SystemExit('success durable, cleanup interrupted')
        original_atomic(path, value)
    rig.ops.atomic = crash_atomic
    if phase == 'after_start':
        monkeypatch.setattr(rig.adapter, '_health', lambda version: (_ for _ in ()).throw(SystemExit('process death')))
    with pytest.raises(SystemExit):
        rig.adapter.recover_forward()
    before_starts = len(starts(rig))
    rows = database_rows(rig)
    # A new adapter process resumes durable receipts, not in-memory flags.
    rig.ops.atomic = original_atomic
    rig.adapter = rig.module.Adapter(rig.profile, rig.ops, unit_root=rig.units)
    monkeypatch.setattr(rig.adapter, '_health', original_health)
    monkeypatch.setattr(rig.adapter, '_schema_process', original_process)
    rig.ops.reboot()
    result = rig.adapter.recover_forward()
    assert result['state'] == 'active' and database_rows(rig) == rows
    assert len(starts(rig)) == before_starts + (phase == 'before_start')
    assert not rig.adapter.hold.exists()


@pytest.mark.parametrize('change', ['owner', 'schema', 'settings', 'unit', 'release', 'archive', 'generation',
                                   'prepared', 'unknown', 'sending', 'temporary', 'corrupt_database', 'integrity_check'])
def test_forward_preflight_rejects_drift_or_obligations_without_starting(patch_rig, monkeypatch, change):
    rig = patch_rig
    interrupted_candidate(rig, monkeypatch)
    if change in ('owner', 'schema', 'generation'):
        key, value = {'owner': ('owner', 'other'), 'schema': ('schema', '4'),
                      'generation': ('connection_generation', '8')}[change]
        sql(rig.database, 'UPDATE meta SET value=? WHERE key=?', (value, key))
    elif change in ('settings', 'unit', 'release', 'archive'):
        path = {'settings': rig.settings, 'unit': rig.units / 'tesla-consumer.service',
                'release': rig.adapter.release / 'VERSION', 'archive': rig.archive}[change]
        path.write_bytes(path.read_bytes() + b' drift')
    elif change in ('prepared', 'unknown', 'sending'):
        add_intent(rig.database, 'new-operation', change, expires=9_999_999_999)
    elif change == 'temporary':
        sql(rig.database, 'INSERT INTO temporary_collections(intent_id,vehicle,plan,generation,status,updated) VALUES(?,?,?,?,?,?)',
            ('new-window', 'synthetic-vehicle', '{}', 7, 'restore_unknown', 100))
    elif change == 'integrity_check':
        import sqlite3
        with sqlite3.connect(rig.database) as writer:
            writer.execute('CREATE TABLE integrity_probe(value INTEGER CHECK(value > 0))')
            writer.execute('PRAGMA ignore_check_constraints=ON')
            writer.execute('INSERT INTO integrity_probe VALUES(-1)')
        # Ordinary queries and schema/owner checks still succeed; SQLite's real
        # integrity_check finds the persistent defect without mocking SQLite.
        assert sql(rig.database, 'PRAGMA integrity_check') != [('ok',)]
    else:
        rig.database.write_bytes(b'not a SQLite database')
    import sqlite3
    with pytest.raises((ValueError, sqlite3.DatabaseError)):
        rig.adapter.recover_forward()
    assert_held(rig)
    assert len(starts(rig)) == 1
    assert not list(rig.adapter.recovery.glob('forward-recovery-*.json'))


@pytest.mark.parametrize('change', ['missing', 'malformed', 'source_commit', 'marker', 'phase', 'public',
                                   'activation_integrity', 'recovery_integrity', 'rollback_integrity'])
def test_forward_receipts_are_qualified_and_historical_integrity_failure_is_never_cleared(patch_rig, monkeypatch, change):
    rig = patch_rig
    interrupted_candidate(rig, monkeypatch)
    path = rig.adapter.recovery / 'activation.json'
    value = json.loads(path.read_text())
    if change == 'missing':
        path.unlink()
    elif change == 'malformed':
        path.write_text('[]')
    elif change == 'public':
        path.chmod(0o644)
    else:
        if change.endswith('_integrity'):
            value['data_integrity_failed'] = True
            path = rig.adapter.recovery / (change.removesuffix('_integrity') + '.json')
        else:
            key, replacement = {'source_commit': ('source_commit', 'different'),
                                'marker': ('candidate_writers_may_have_run', 1),
                                'phase': ('phase', 'unrecognized')}[change]
            value[key] = replacement
        path.write_text(json.dumps(value))
        path.chmod(0o600)
    contents = path.read_bytes() if path.exists() else None
    with pytest.raises((ValueError, FileNotFoundError)):
        rig.adapter.recover_forward()
    assert not list(rig.adapter.recovery.glob('forward-recovery-*.json'))
    assert len(starts(rig)) == 1
    assert (path.read_bytes() if path.exists() else None) == contents


def test_forward_detects_integrity_failure_after_stop_and_never_clears_it_on_retry(patch_rig, monkeypatch):
    rig = patch_rig
    interrupted_candidate(rig, monkeypatch)
    original = rig.adapter._integrity
    calls = 0
    def fail_after_stop():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise rig.module.base.IntegrityFailure('synthetic integrity failure')
        original()
    monkeypatch.setattr(rig.adapter, '_integrity', fail_after_stop)
    with pytest.raises(rig.module.base.RecoveryIncomplete):
        rig.adapter.recover_forward()
    assert_held(rig)
    monkeypatch.setattr(rig.adapter, '_integrity', original)
    with pytest.raises(ValueError, match='Historical integrity failure'):
        rig.adapter.recover_forward()
    assert len(starts(rig)) == 1


def test_forward_requires_loaded_exact_guard_on_both_writers(patch_rig, monkeypatch):
    rig = patch_rig
    interrupted_candidate(rig, monkeypatch)
    monkeypatch.setattr(rig.adapter, '_restart_condition_loaded', lambda name: name != 'tesla-consumer.service')
    with pytest.raises(rig.module.base.RecoveryIncomplete):
        rig.adapter.recover_forward()
    assert len(starts(rig)) == 1
    assert rig.adapter.hold.exists()
    assert all(rig.ops.states[name]['ActiveState'] == 'inactive' for name in OWNERS)


def test_forward_is_not_a_generic_restart_of_successful_activation(patch_rig):
    rig = patch_rig
    rig.adapter.stage()
    rig.adapter.activate()
    with pytest.raises(ValueError, match='interrupted candidate start'):
        rig.adapter.recover_forward()
    assert len(starts(rig)) == 1 and not rig.adapter.hold.exists()
