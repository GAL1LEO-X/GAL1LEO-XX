"""Regression coverage for temporary collection ownership and abandoned consent."""
from copy import deepcopy
import socket

import pytest

from tesla_plugin.collection import Collection
from tesla_plugin.collection_state import CREATE, DELETE
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.service import Service
from tesla_plugin.store import Store
from tesla_plugin.temporary_collection import TemporaryCollection, CHECK_SECONDS
from test_temporary_collection import temporary_setup, prepare, start, writes


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError('This suite uses only the synthetic provider')
    monkeypatch.setattr(socket.socket, 'connect', denied)
    monkeypatch.setattr(socket.socket, 'connect_ex', denied)
    monkeypatch.setattr(socket, 'create_connection', denied)


def test_definitively_rejected_later_pause_preserves_due_restore(temporary_setup, vehicle_ref, fleet, clock, monkeypatch):
    service, manager, remote, provider = temporary_setup
    baseline = deepcopy(remote['config'])
    first = start(temporary_setup, vehicle_ref)
    clock.advance(1)
    later = manager.prepare_change(vehicle_ref, 'pause', manager.view(vehicle_ref)['revision'],
                                   'audit-rejected-later-pause', SCOPES)
    def rejected(name, arguments=None, **kwargs):
        if name == DELETE:
            fleet.calls.append((name, arguments, None))
            raise TeslaError('COMMAND_REJECTED', 'Synthetic definitive rejection')
        return provider(name, arguments, **kwargs)
    monkeypatch.setattr(fleet, 'call', rejected)
    assert service.execute_from_owner(later['id'])['status'] == 'rejected'
    with service.store.db() as db:
        assert db.execute('SELECT status FROM temporary_collections WHERE intent_id=?', (first['id'],)).fetchone()[0] == 'active'
    clock.advance(60)
    assert TemporaryCollection(service).tick()['status'] == 'restore_accepted'
    assert remote['config'] == baseline
    clock.advance(CHECK_SECONDS)
    assert TemporaryCollection(service).tick()['restore_verified']


def test_second_temporary_window_rejected_without_reads_or_lost_baseline(temporary_setup, vehicle_ref, fleet, clock):
    service, manager, remote, _ = temporary_setup
    baseline = deepcopy(remote['config'])
    first = start(temporary_setup, vehicle_ref, duration=120)
    clock.advance(1)
    manager.refresh(vehicle_ref, SCOPES)
    calls = list(fleet.calls)
    with pytest.raises(TeslaError) as exc:
        prepare(temporary_setup, vehicle_ref, duration=60, request_id='audit-overlapping-window')
    assert exc.value.code == 'TEMPORARY_COLLECTION_PENDING'
    assert fleet.calls == calls
    with service.store.db() as db:
        assert db.execute('SELECT COUNT(*) FROM temporary_collections').fetchone()[0] == 1
        assert db.execute('SELECT status FROM temporary_collections WHERE intent_id=?', (first['id'],)).fetchone()[0] == 'active'
    clock.advance(120)
    assert TemporaryCollection(service).tick()['status'] == 'restore_accepted'
    assert remote['config'] == baseline


@pytest.mark.parametrize('status', ['expired', 'cancelled', 'missing'])
def test_unstarted_approval_terminalizes_durably_after_restart(temporary_setup, vehicle_ref, fleet, clock, status):
    service, _, _, _ = temporary_setup
    item = prepare(temporary_setup, vehicle_ref)
    with service.store.db() as db:
        if status == 'missing':
            db.execute('DELETE FROM intents WHERE id=?', (item['id'],))
        else:
            db.execute('UPDATE intents SET status=? WHERE id=?', (status, item['id']))
    restarted = Service(service.settings, store=Store(service.settings, clock=clock), fleet=fleet)
    calls = list(fleet.calls)
    assert TemporaryCollection(restarted).tick() is None
    with restarted.store.db() as db:
        row = db.execute('SELECT status,started FROM temporary_collections WHERE intent_id=?', (item['id'],)).fetchone()
    assert row['status'] == 'cancelled' and row['started'] is None
    assert Collection(restarted).view(vehicle_ref)['temporary_collection']['status'] == 'cancelled'
    assert fleet.calls == calls


def test_later_unknown_pause_blocks_but_retains_original_restore_obligation(temporary_setup, vehicle_ref, fleet, clock, monkeypatch):
    service, manager, _, provider = temporary_setup
    first = start(temporary_setup, vehicle_ref)
    clock.advance(1)
    later = manager.prepare_change(vehicle_ref, 'pause', manager.view(vehicle_ref)['revision'],
                                   'audit-uncertain-later-pause', SCOPES)
    def uncertain(name, arguments=None, **kwargs):
        if name == DELETE:
            fleet.calls.append((name, arguments, None))
            raise TeslaError('OUTCOME_UNKNOWN', 'Synthetic uncertain pause', uncertain=True)
        return provider(name, arguments, **kwargs)
    monkeypatch.setattr(fleet, 'call', uncertain)
    assert service.execute_from_owner(later['id'])['status'] == 'unknown'
    clock.advance(60)
    calls = list(fleet.calls)
    result = TemporaryCollection(service).tick()
    assert result['status'] == 'blocked' and result['last_error'] == 'REVISION_CONFLICT'
    with service.store.db() as db:
        row = db.execute('SELECT started,expires FROM temporary_collections WHERE intent_id=?', (first['id'],)).fetchone()
        assert row['started'] is not None and row['expires'] <= clock()
    assert fleet.calls == calls


def test_expired_later_unconfirmed_pause_no_longer_blocks_due_restore(temporary_setup, vehicle_ref, clock):
    service, manager, remote, _ = temporary_setup
    baseline = deepcopy(remote['config'])
    start(temporary_setup, vehicle_ref)
    clock.advance(1)
    later = manager.prepare_change(vehicle_ref, 'pause', manager.view(vehicle_ref)['revision'],
                                   'audit-expired-later-pause', SCOPES)
    clock.advance(service.settings.intent_ttl_seconds+1)
    assert TemporaryCollection(service).tick()['status'] == 'restore_accepted'
    assert remote['config'] == baseline
    assert service.store.intent(later['id'])['status'] in ('prepared', 'expired')


def test_atomic_registration_rechecks_window_started_after_planning(temporary_setup, vehicle_ref, clock):
    from tesla_plugin.temporary_collection import plan_for
    service, manager, _, _ = temporary_setup
    fields = {'BatteryLevel': {'interval_seconds': 10}}
    planned = plan_for(service, vehicle_ref, manager.view(vehicle_ref), 60, fields, SCOPES)
    first = start(temporary_setup, vehicle_ref)
    clock.advance(1)
    with pytest.raises(TeslaError) as exc:
        service.prepare_profile(vehicle_ref, 'custom', fields, 'audit-register-race-window', SCOPES,
                                temporary_plan=planned)
    assert exc.value.code == 'TEMPORARY_COLLECTION_PENDING'
    with service.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM intents WHERE client_key='audit-register-race-window'").fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM temporary_collections').fetchone()[0] == 1
        assert db.execute('SELECT status FROM temporary_collections WHERE intent_id=?', (first['id'],)).fetchone()[0] == 'active'


@pytest.mark.parametrize('started', [False, True])
def test_prune_retires_only_unstarted_obligations(temporary_setup, vehicle_ref, clock, fleet, started):
    service, _, _, _ = temporary_setup
    item = start(temporary_setup, vehicle_ref) if started else prepare(temporary_setup, vehicle_ref)
    clock.advance(service.settings.history_days*86400+service.settings.intent_ttl_seconds+1)
    calls = list(fleet.calls)
    service.store.prune()
    # The first pruning pass persists intent expiry; the next can remove it.
    service.store.prune()
    with service.store.db() as db:
        row = db.execute('SELECT status,started FROM temporary_collections WHERE intent_id=?', (item['id'],)).fetchone()
        intent = db.execute('SELECT id FROM intents WHERE id=?', (item['id'],)).fetchone()
    assert row['status'] == ('active' if started else 'cancelled')
    assert (row['started'] is not None) is started
    assert (intent is not None) is started
    assert fleet.calls == calls


def legacy_overlapping_windows(setup, ref, clock, monkeypatch):
    """Create the former persisted format, not a newly authorized nested plan."""
    service, manager, remote, _ = setup
    first = start(setup, ref, duration=120, request_id='legacy-window-first-01')
    clock.advance(1)
    manager.refresh(ref, SCOPES)
    with monkeypatch.context() as patch:
        patch.setattr('tesla_plugin.temporary_collection.assert_no_active_window', lambda db, vehicle: None)
        second = manager.prepare_change(ref, 'configure', manager.view(ref)['revision'], 'legacy-window-second-01', SCOPES,
            preset='custom', custom_fields={'BatteryLevel': {'interval_seconds': 10}}, duration_seconds=60)
        service.execute_from_owner(second['id'])
    return first, second


def test_legacy_nested_baseline_blocks_after_restart_without_rewriting_consent(temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, _, remote, _ = temporary_setup
    first, second = legacy_overlapping_windows(temporary_setup, vehicle_ref, clock, monkeypatch)
    current = deepcopy(remote['config'])
    with service.store.db() as db:
        original_plan = db.execute('SELECT plan FROM temporary_collections WHERE intent_id=?', (second['id'],)).fetchone()[0]
    restarted = Service(service.settings, store=Store(service.settings, clock=clock), fleet=fleet)
    count = len(fleet.calls)
    clock.advance(59)
    assert TemporaryCollection(restarted).tick() is None
    clock.advance(1)  # B deadline, still before A's original deadline.
    blocked = TemporaryCollection(restarted).tick()
    assert blocked['status'] == 'blocked'
    assert blocked['last_error'] == 'TEMPORARY_BASELINE_REVIEW_REQUIRED'
    clock.advance(120)  # Also after A's deadline, never restore its expired profile.
    blocked = TemporaryCollection(restarted).tick()
    assert blocked['status'] == 'blocked' and remote['config'] == current
    assert len(fleet.calls) == count
    with restarted.store.db() as db:
        assert db.execute('SELECT plan FROM temporary_collections WHERE intent_id=?', (second['id'],)).fetchone()[0] == original_plan
        assert db.execute('SELECT status FROM temporary_collections WHERE intent_id=?', (first['id'],)).fetchone()[0] == 'superseded'
    manager = Collection(restarted)
    ordinary = manager.prepare_change(vehicle_ref, 'configure', manager.view(vehicle_ref)['revision'], 'legacy-owner-resolution-01', SCOPES,
        preset='custom', custom_fields={'BatteryLevel': {'interval_seconds': 300}})
    restarted.execute_from_owner(ordinary['id'])
    selected = deepcopy(remote['config'])
    clock.advance(60)
    assert TemporaryCollection(restarted).tick() is None
    assert remote['config'] == selected


def test_ordinary_choice_equal_to_old_temporary_is_valid_restore_baseline(temporary_setup, vehicle_ref, clock):
    service, manager, remote, _ = temporary_setup
    start(temporary_setup, vehicle_ref, duration=120)
    old_fields = deepcopy(remote['config']['fields'])
    clock.advance(1)
    ordinary = manager.prepare_change(vehicle_ref, 'configure', manager.view(vehicle_ref)['revision'], 'ordinary-equals-old-window', SCOPES,
        preset='custom', custom_fields=old_fields, customer_alerts='customer' in remote['config'].get('alert_types', []))
    service.execute_from_owner(ordinary['id'])
    clock.advance(1)
    manager.refresh(vehicle_ref, SCOPES)
    baseline = deepcopy(remote['config'])
    later = manager.prepare_change(vehicle_ref, 'configure', manager.view(vehicle_ref)['revision'], 'window-after-ordinary-equal', SCOPES,
        preset='custom', custom_fields={'BatteryLevel': {'interval_seconds': 10}}, duration_seconds=60)
    service.execute_from_owner(later['id'])
    clock.advance(60)
    assert TemporaryCollection(service).tick()['status'] == 'restore_accepted'
    assert remote['config'] == baseline


def test_legacy_lineage_block_survives_predecessor_history_pruning(temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, _, remote, _ = temporary_setup
    first, _ = legacy_overlapping_windows(temporary_setup, vehicle_ref, clock, monkeypatch)
    clock.advance(60)
    assert TemporaryCollection(service).tick()["last_error"] == "TEMPORARY_BASELINE_REVIEW_REQUIRED"
    before = list(fleet.calls)
    selected = deepcopy(remote["config"])
    clock.advance(service.settings.history_days*86400+1)
    service.store.prune()
    with service.store.db() as db:
        assert db.execute("SELECT id FROM intents WHERE id=?", (first["id"],)).fetchone() is None
    restarted = Service(service.settings, store=Store(service.settings, clock=clock), fleet=fleet)
    assert TemporaryCollection(restarted).tick()["last_error"] == "TEMPORARY_BASELINE_REVIEW_REQUIRED"
    assert fleet.calls == before and remote["config"] == selected


def test_prune_records_legacy_lineage_before_deleting_predecessor(temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, _, remote, _ = temporary_setup
    first, second = legacy_overlapping_windows(temporary_setup, vehicle_ref, clock, monkeypatch)
    selected = deepcopy(remote['config'])
    before = list(fleet.calls)
    clock.advance(service.settings.history_days*86400+1)
    service.store.prune()  # No worker/lineage evaluation has happened yet.
    with service.store.db() as db:
        assert db.execute('SELECT id FROM intents WHERE id=?', (first['id'],)).fetchone() is None
        assert db.execute('SELECT intent_id FROM temporary_collections WHERE intent_id=?', (first['id'],)).fetchone() is None
        row = db.execute('SELECT status,error FROM temporary_collections WHERE intent_id=?', (second['id'],)).fetchone()
        assert row['status'] == 'blocked' and row['error'] == 'TEMPORARY_BASELINE_REVIEW_REQUIRED'
    restarted = Service(service.settings, store=Store(service.settings, clock=clock), fleet=fleet)
    assert TemporaryCollection(restarted).tick()['last_error'] == 'TEMPORARY_BASELINE_REVIEW_REQUIRED'
    assert fleet.calls == before and remote['config'] == selected
