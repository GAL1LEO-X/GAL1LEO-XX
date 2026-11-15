"""Explicit cleanup of this patch's guards, with real SQLite and fake services."""
import json
from pathlib import Path

import pytest

from test_patch_update import (patch_module, patch_rig, schema_rig, adapter_module,
                              interrupted_candidate, database_rows, starts)
from test_schema3_update import OWNERS, CANDIDATE, sql, add_intent


def successful_runtime_before_cleanup(rig, monkeypatch, mode='activation'):
    if mode == 'forward':
        interrupted_candidate(rig, monkeypatch)
    else:
        rig.adapter.stage()
    original = rig.ops.atomic
    failed_unit = False

    def crash_after_success(path, value):
        nonlocal failed_unit
        path = Path(path)
        if (mode == 'pre_start_recovery' and not failed_unit
                and path == rig.units / 'tesla-consumer.service' and CANDIDATE in str(value)):
            failed_unit = True
            raise OSError('synthetic unit switch failure before candidate start')
        original(path, value)
        if (path.name == 'activation.json' or path.name.startswith('forward-recovery-')):
            if json.loads(value).get('state') in ('active', 'rolled_back'):
                raise SystemExit('process died after durable success, before cleanup')

    rig.ops.atomic = crash_after_success
    with pytest.raises(SystemExit):
        (rig.adapter.recover_forward if mode == 'forward' else rig.adapter.activate)()
    rig.ops.atomic = original
    assert not rig.adapter.hold.exists()
    assert all(rig.adapter._guard_path(name + '.service').exists() for name in OWNERS)


def originals(rig):
    return {path.name: path.read_bytes() for path in rig.adapter.recovery.glob('*.json')
            if not path.name.startswith('maintenance-cleanup-')}


def reloads(rig):
    return [call for call in rig.ops.calls if call[:2] == ['systemctl', 'daemon-reload']]


def assert_no_operational_side_effects(rig, before_calls, rows, receipts, backups):
    assert database_rows(rig) == rows
    assert originals(rig) == receipts
    assert sorted(rig.database.parent.glob('*.pre-patch-*')) == backups
    assert all(call[0] in ('systemctl', 'busctl') for call in rig.ops.calls[before_calls:])
    assert not any(call[:2] in (['systemctl', 'stop'], ['systemctl', 'start'],
                               ['systemctl', 'enable'], ['systemctl', 'disable'])
                   for call in rig.ops.calls[before_calls:])
    assert all(rig.ops.states[name]['ActiveState'] == 'active' for name in OWNERS)


@pytest.mark.parametrize('mode', ['activation', 'forward', 'pre_start_recovery'])
def test_cleanup_finishes_exact_runtime_success_and_terminal_retry_is_read_only(patch_rig, monkeypatch, mode):
    rig = patch_rig
    successful_runtime_before_cleanup(rig, monkeypatch, mode)
    extra = rig.adapter._guard_path('tesla-personal.service').parent / '50-owner-setting.conf'
    extra.write_text('[Service]\nNice=1\n')
    rows, receipts = database_rows(rig), originals(rig)
    backups = sorted(rig.database.parent.glob('*.pre-patch-*'))
    before_calls = len(rig.ops.calls)
    result = rig.adapter.complete_maintenance()
    assert result['state'] == 'complete' and result['maintenance_cleanup_complete'] is True
    assert result['runtime_version'] == (rig.previous_version if mode == 'pre_start_recovery' else rig.candidate_version)
    assert result['runtime_state'] == 'active' and extra.read_text() == '[Service]\nNice=1\n'
    assert all(not rig.adapter._guard_path(name + '.service').exists() for name in OWNERS)
    reload_count = len(reloads(rig))
    stored = {path.name: path.read_bytes() for path in rig.adapter.recovery.glob('maintenance-cleanup-*.json')}
    assert rig.adapter.complete_maintenance() == result
    assert len(reloads(rig)) == reload_count
    assert {path.name: path.read_bytes() for path in rig.adapter.recovery.glob('maintenance-cleanup-*.json')} == stored
    assert_no_operational_side_effects(rig, before_calls, rows, receipts, backups)


@pytest.mark.parametrize('phase', ['first_unlink', 'before_reload', 'after_reload', 'before_receipt', 'after_receipt'])
def test_cleanup_crash_is_resumable_with_missing_files_and_preserves_original_outcome(patch_rig, monkeypatch, phase):
    rig = patch_rig
    successful_runtime_before_cleanup(rig, monkeypatch)
    rows, receipts = database_rows(rig), originals(rig)
    backups = sorted(rig.database.parent.glob('*.pre-patch-*'))
    before_calls = len(rig.ops.calls)
    original_unlink, original_atomic, original_run = Path.unlink, rig.ops.atomic, rig.ops.run
    original_health, original_process = rig.adapter._health, rig.adapter._schema_process

    def crash_unlink(path, *args, **kwargs):
        original_unlink(path, *args, **kwargs)
        if path == rig.adapter._guard_path('tesla-personal.service') and phase == 'first_unlink':
            raise SystemExit('crash after first unlink')

    def crash_atomic(path, value):
        if Path(path).name == 'maintenance-cleanup-000001.json':
            data = json.loads(value)
            if phase == 'before_receipt' and data['state'] == 'complete':
                raise SystemExit('success not yet durable')
            original_atomic(path, value)
            if phase == 'after_receipt' and data['state'] == 'complete':
                raise SystemExit('success durable')
        else:
            original_atomic(path, value)

    def crash_run(arguments, **kwargs):
        if list(arguments)[:2] == ['systemctl', 'daemon-reload'] and phase == 'before_reload':
            raise SystemExit('reload not performed')
        result = original_run(arguments, **kwargs)
        if list(arguments)[:2] == ['systemctl', 'daemon-reload'] and phase == 'after_reload':
            raise SystemExit('reload result uncertain')
        return result

    monkeypatch.setattr(Path, 'unlink', crash_unlink)
    rig.ops.atomic, rig.ops.run = crash_atomic, crash_run
    with pytest.raises(SystemExit):
        rig.adapter.complete_maintenance()
    first = (rig.adapter.recovery / 'maintenance-cleanup-000001.json').read_bytes()
    prior_reloads = len(reloads(rig))
    monkeypatch.setattr(Path, 'unlink', original_unlink)
    rig.ops.atomic, rig.ops.run = original_atomic, original_run
    rig.adapter = rig.module.Adapter(rig.profile, rig.ops, unit_root=rig.units)
    monkeypatch.setattr(rig.adapter, '_health', original_health)
    monkeypatch.setattr(rig.adapter, '_schema_process', original_process)
    result = rig.adapter.complete_maintenance()
    assert result['state'] == 'complete'
    assert len(reloads(rig)) == prior_reloads + (phase != 'after_receipt')
    assert (rig.adapter.recovery / 'maintenance-cleanup-000001.json').read_bytes() == first
    assert_no_operational_side_effects(rig, before_calls, rows, receipts, backups)


@pytest.mark.parametrize('failure', ['reload', 'still_loaded_personal', 'still_loaded_consumer', 'malformed_bus'])
def test_cleanup_verifies_loaded_state_and_retry_reloads_even_when_files_absent(patch_rig, monkeypatch, failure):
    rig = patch_rig
    successful_runtime_before_cleanup(rig, monkeypatch)
    rows, receipts = database_rows(rig), originals(rig)
    backups = sorted(rig.database.parent.glob('*.pre-patch-*'))
    before_calls = len(rig.ops.calls)
    original_run = rig.ops.run

    def failed_run(arguments, **kwargs):
        args = list(arguments)
        if failure == 'reload' and args[:2] == ['systemctl', 'daemon-reload']:
            raise OSError('synthetic daemon reload failure')
        result = original_run(arguments, **kwargs)
        if args[0] == 'busctl' and 'get-property' in args:
            if failure == 'malformed_bus':
                return json.dumps({'type': 'a(sbbsi)', 'data': [['ConditionPathExists', False, 1, '/unrelated', 0]]})
            target = 'tesla-personal.service' if failure == 'still_loaded_personal' else 'tesla-consumer.service'
            if failure.startswith('still_loaded') and rig.ops.unit_objects[target] in args:
                return json.dumps({'type': 'a(sbbsi)', 'data': [
                    ['ConditionPathExists', False, True, str(rig.adapter.hold), 0]]})
        return result

    rig.ops.run = failed_run
    with pytest.raises(rig.module.base.RecoveryIncomplete):
        rig.adapter.complete_maintenance()
    failed = (rig.adapter.recovery / 'maintenance-cleanup-000001.json').read_bytes()
    assert json.loads(failed)['maintenance_cleanup_complete'] is False
    assert all(not rig.adapter._guard_path(name + '.service').exists() for name in OWNERS)
    before_reloads = len(reloads(rig))
    rig.ops.run = original_run
    result = rig.adapter.complete_maintenance()
    assert result['state'] == 'complete' and result['attempt'] == 2
    assert len(reloads(rig)) == before_reloads + 1
    assert (rig.adapter.recovery / 'maintenance-cleanup-000001.json').read_bytes() == failed
    assert_no_operational_side_effects(rig, before_calls, rows, receipts, backups)


@pytest.mark.parametrize('change', ['foreign_first', 'foreign_second', 'symlink', 'parent_symlink', 'hold',
                                   'hold_symlink', 'owner', 'generation', 'unit', 'release', 'settings',
                                   'archive', 'receipt_identity', 'receipt_integrity', 'pending', 'runtime_health'])
def test_cleanup_preflight_preserves_foreign_files_and_rejects_unsafe_states(patch_rig, monkeypatch, change):
    rig = patch_rig
    successful_runtime_before_cleanup(rig, monkeypatch)
    first = rig.adapter._guard_path('tesla-personal.service')
    second = rig.adapter._guard_path('tesla-consumer.service')
    if change in ('foreign_first', 'foreign_second'):
        (first if change == 'foreign_first' else second).write_text('[Unit]\nConditionPathExists=/owner-file\n')
    elif change == 'symlink':
        second.unlink()
        second.symlink_to(first)
    elif change == 'parent_symlink':
        other = second.parent.with_name('foreign-drop-ins')
        second.parent.rename(other)
        second.parent.symlink_to(other, target_is_directory=True)
    elif change == 'hold':
        rig.adapter.hold.write_text(rig.profile['source_commit'])
    elif change == 'hold_symlink':
        rig.adapter.hold.symlink_to(rig.adapter.recovery / 'missing-hold-target')
    elif change in ('owner', 'generation'):
        sql(rig.database, 'UPDATE meta SET value=? WHERE key=?', ('other', 'owner' if change == 'owner' else 'connection_generation'))
    elif change in ('unit', 'release', 'settings', 'archive'):
        path = {'unit': rig.units / 'tesla-consumer.service', 'release': rig.adapter.release / 'VERSION',
                'settings': rig.settings, 'archive': rig.archive}[change]
        path.write_bytes(path.read_bytes() + b' drift')
    elif change.startswith('receipt_'):
        path = rig.adapter.recovery / 'activation.json'
        value = json.loads(path.read_text())
        value.update({'source_commit': 'different'} if change == 'receipt_identity' else {'data_integrity_failed': True})
        path.write_text(json.dumps(value))
    elif change == 'pending':
        add_intent(rig.database, 'new-owner-operation', 'unknown')
    else:
        monkeypatch.setattr(rig.adapter, '_health', lambda version: (_ for _ in ()).throw(ValueError('unhealthy')))
    contents = first.read_bytes(), second.read_bytes()
    before_reloads, before_starts = len(reloads(rig)), len(starts(rig))
    with pytest.raises(ValueError):
        rig.adapter.complete_maintenance()
    assert (first.read_bytes(), second.read_bytes()) == contents
    assert len(reloads(rig)) == before_reloads and len(starts(rig)) == before_starts
    assert not list(rig.adapter.recovery.glob('maintenance-cleanup-*.json'))


def test_cleanup_checks_second_file_again_after_first_unlink_and_preserves_foreign_change(patch_rig, monkeypatch):
    rig = patch_rig
    successful_runtime_before_cleanup(rig, monkeypatch)
    first = rig.adapter._guard_path('tesla-personal.service')
    second = rig.adapter._guard_path('tesla-consumer.service')
    original = Path.unlink
    def change_other(path, *args, **kwargs):
        original(path, *args, **kwargs)
        if path == first:
            second.write_text('foreign replacement after first unlink\n')
    monkeypatch.setattr(Path, 'unlink', change_other)
    receipts = originals(rig)
    before_starts = len(starts(rig))
    with pytest.raises(rig.module.base.RecoveryIncomplete):
        rig.adapter.complete_maintenance()
    assert second.read_text() == 'foreign replacement after first unlink\n'
    assert originals(rig) == receipts and len(starts(rig)) == before_starts
    assert all(rig.ops.states[name]['ActiveState'] == 'active' for name in OWNERS)


@pytest.mark.parametrize('state', ['staged_only', 'incomplete_activation', 'incomplete_forward'])
def test_cleanup_requires_runtime_success_not_just_a_staged_release(patch_rig, monkeypatch, state):
    rig = patch_rig
    if state == 'staged_only':
        rig.adapter.stage()
    else:
        interrupted_candidate(rig, monkeypatch)
        if state == 'incomplete_forward':
            monkeypatch.setattr(rig.adapter, '_health', lambda version: (_ for _ in ()).throw(ValueError('unhealthy')))
            with pytest.raises(rig.module.base.RecoveryIncomplete):
                rig.adapter.recover_forward()
    before_calls = list(rig.ops.calls)
    with pytest.raises((ValueError, FileNotFoundError)):
        rig.adapter.complete_maintenance()
    assert rig.ops.calls == before_calls
    assert not list(rig.adapter.recovery.glob('maintenance-cleanup-*.json'))


def test_terminal_cleanup_detects_reintroduced_guard_without_removing_or_reloading(patch_rig, monkeypatch):
    rig = patch_rig
    successful_runtime_before_cleanup(rig, monkeypatch)
    rig.adapter.complete_maintenance()
    path = rig.adapter._guard_path('tesla-personal.service')
    path.write_text(rig.adapter._guard_content())
    before_reloads = len(reloads(rig))
    with pytest.raises(ValueError, match='new guard drift'):
        rig.adapter.complete_maintenance()
    assert path.exists() and len(reloads(rig)) == before_reloads


def test_cleanup_accepts_and_preserves_unrelated_loaded_conditions(patch_rig, monkeypatch):
    rig = patch_rig
    successful_runtime_before_cleanup(rig, monkeypatch)
    original_run = rig.ops.run
    foreign = rig.adapter._guard_path('tesla-personal.service').parent / '40-owner-conditions.conf'
    content = '[Unit]\nConditionPathExists=/synthetic-owner/path\n'
    foreign.write_text(content)

    def foreign_condition(arguments, **kwargs):
        result = original_run(arguments, **kwargs)
        if list(arguments)[0] == 'busctl' and 'get-property' in arguments:
            value = json.loads(result)
            value['data'].append(['ConditionPathExists', False, False, '/synthetic-owner/path', 1])
            return json.dumps(value)
        return result

    rig.ops.run = foreign_condition
    assert rig.adapter.complete_maintenance()['maintenance_cleanup_complete'] is True
    assert foreign.read_text() == content
