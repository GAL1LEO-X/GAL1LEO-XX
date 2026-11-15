"""Collection consent remains coherent across retries, crashes and readbacks."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import sqlite3
import socket
import pytest
from test_collection import prepared_service
from tesla_plugin.collection import Collection
from tesla_plugin.collection_state import CREATE, matches_config
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Synthetic collection tests prohibit network connections")
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


def prepare(manager, ref, key='atomic-collection-request-01', **options):
    return manager.prepare_change(ref, 'configure', manager.view(ref)['revision'], key, SCOPES,
        preset='custom', custom_fields={'BatteryLevel': {'interval_seconds': 60}}, **options)


def test_profile_is_complete_at_first_publication(prepared_service, vehicle_ref, fleet, monkeypatch):
    service, manager = prepared_service, Collection(prepared_service)
    original = service.prepare
    def inspect_published(*args, **kwargs):
        result = original(*args, **kwargs)
        visible = manager.public_view(vehicle_ref, SCOPES)['last_request']
        assert visible['review_complete'] is True
        assert visible['estimate']['active_hours_per_day'] == 24
        with service.store.db() as db:
            db.execute('UPDATE trigger_settings SET revision=revision+1 WHERE vehicle=?', (vehicle_ref,))
        with pytest.raises(TeslaError, match='Events or rules'):
            manager.resolve(vehicle_ref, result['id'], visible['review_digest'], 'confirm', SCOPES)
        return result
    monkeypatch.setattr(service, 'prepare', inspect_published)
    prepare(manager, vehicle_ref, active_hours_per_day=24, expected_trigger_revision=0)
    assert not any(name == CREATE for name, *_ in fleet.calls)


def test_preview_failure_rolls_back_intent_and_reopen(prepared_service, vehicle_ref):
    service, manager = prepared_service, Collection(prepared_service)
    with service.store.db() as db:
        db.execute("CREATE TRIGGER fail_preview BEFORE INSERT ON snapshots WHEN NEW.section GLOB 'telemetry_preview_intent_*' BEGIN SELECT RAISE(ABORT, 'synthetic preview failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match='synthetic preview failure'):
        prepare(manager, vehicle_ref)
    with service.store.db() as db:
        assert db.execute('SELECT COUNT(*) FROM intents').fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM snapshots WHERE section GLOB 'telemetry_preview*'").fetchone()[0] == 0
    from tesla_plugin.store import Store
    reopened = Store(service.store.settings, clock=service.store.clock)
    assert Collection(type(service)(service.settings, store=reopened, fleet=service.fleet)).view(vehicle_ref)['last'] is None


@pytest.mark.parametrize('corruption', ['missing', 'missing_hours', 'wrong_intent', 'missing_dependency'])
def test_incomplete_review_cannot_dispatch_but_can_cancel(prepared_service, vehicle_ref, fleet, corruption):
    service, manager = prepared_service, Collection(prepared_service)
    item = prepare(manager, vehicle_ref)
    with service.store.db() as db:
        section = 'telemetry_preview_'+item['id']
        preview = json.loads(db.execute('SELECT data FROM snapshots WHERE section=?', (section,)).fetchone()[0])
        if corruption == 'missing':
            db.execute('DELETE FROM snapshots WHERE section=?', (section,))
        else:
            if corruption == 'missing_dependency':
                del preview['trigger_revision']
            elif corruption == 'missing_hours':
                del preview['hours']
            else:
                preview['intent_id'] = 'intent_wrong'
            db.execute('UPDATE snapshots SET data=? WHERE section=?', (json.dumps(preview), section))
    review = manager.review(vehicle_ref, item['id'])
    assert review['review_complete'] is False and review['estimate'] is None
    assert service.intent_view(item['id'])['review_complete'] is False
    before = list(fleet.calls)
    for confirm in (lambda: manager.resolve(vehicle_ref, item['id'], review['review_digest'], 'confirm', SCOPES),
                    lambda: service.execute_from_owner(item['id'])):
        with pytest.raises(TeslaError) as error:
            confirm()
        assert error.value.code == 'COLLECTION_REVIEW_INCOMPLETE'
    assert fleet.calls == before
    assert manager.resolve(vehicle_ref, item['id'], review['review_digest'], 'cancel', SCOPES)['status'] == 'cancelled'


@pytest.mark.parametrize('revision_kind', ['original', 'current'])
def test_prepare_retry_recovers_same_request_without_provider(prepared_service, vehicle_ref, fleet, revision_kind):
    manager = Collection(prepared_service)
    original_revision = manager.view(vehicle_ref)['revision']
    first = prepare(manager, vehicle_ref, active_hours_per_day=24)
    before = list(fleet.calls)
    revision = original_revision if revision_kind == 'original' else manager.view(vehicle_ref)['revision']
    again = manager.prepare_change(vehicle_ref, 'configure', revision, 'atomic-collection-request-01', SCOPES,
        preset='custom', custom_fields={'BatteryLevel': {'interval_seconds': 60}}, active_hours_per_day=24)
    assert again['id'] == first['id']
    assert manager.review(vehicle_ref, again['id'])['estimate']['active_hours_per_day'] == 24
    assert fleet.calls == before


@pytest.mark.parametrize('change', [{'active_hours_per_day': 4}, {'custom_fields': {'BatteryLevel': {'interval_seconds': 30}}},
                                  {'duration_seconds': 60}, {'customer_alerts': True}])
def test_prepare_retry_different_request_conflicts_locally(prepared_service, vehicle_ref, fleet, change):
    manager = Collection(prepared_service)
    revision = manager.view(vehicle_ref)['revision']
    first = prepare(manager, vehicle_ref)
    before = list(fleet.calls)
    options = dict(preset='custom', custom_fields={'BatteryLevel': {'interval_seconds': 60}})
    options.update(change)
    with pytest.raises(TeslaError) as error:
        manager.prepare_change(vehicle_ref, 'configure', revision, 'atomic-collection-request-01', SCOPES, **options)
    assert error.value.code == 'IDEMPOTENCY_CONFLICT'
    assert fleet.calls == before
    assert prepared_service.store.intent(first['id'])['status'] == 'prepared'


def test_concurrent_duplicate_profile_keeps_one_bundle(prepared_service, vehicle_ref):
    service = prepared_service
    def request(hours):
        try:
            return service.prepare_profile(vehicle_ref, 'custom', {'BatteryLevel': {'interval_seconds': 60}},
                'atomic-concurrent-cost-01', SCOPES, active_hours_per_day=hours)
        except TeslaError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(request, [8, 24]))
    success = [r for r in results if isinstance(r, dict)]
    assert len(success) == 1 and 'IDEMPOTENCY_CONFLICT' in results
    with service.store.db() as db:
        assert db.execute('SELECT COUNT(*) FROM intents').fetchone()[0] == 1
    assert Collection(service).review(vehicle_ref, success[0]['id'])['estimate'] == success[0]['estimate']


@pytest.mark.parametrize('addition', [{'minimum_delta': 25}, {'resend_interval_seconds': 300}, {'future_option': True}])
def test_config_comparison_rejects_added_options_symmetrically(addition):
    expected = {'fields': {'BatteryLevel': {'interval_seconds': 60}}}
    observed = deepcopy(expected)
    observed['fields']['BatteryLevel'].update(addition)
    assert matches_config(expected, observed) is False
    assert matches_config(observed, expected) is False


def test_config_comparison_normalizes_only_empty_lists_and_order():
    expected = {'fields': {'BatteryLevel': {'interval_seconds': 60, 'include_fields': ['VehicleSpeed', 'Odometer']}}, 'alert_types': ['customer']}
    observed = deepcopy(expected)
    observed['fields']['BatteryLevel']['include_fields'].reverse()
    assert matches_config(expected, observed) is True
    assert matches_config({'fields': {'BatteryLevel': {'interval_seconds': 60}}},
        {'fields': {'BatteryLevel': {'interval_seconds': 60, 'include_fields': []}}, 'alert_types': []}) is True
    observed['delivery_policy'] = 'all'
    assert matches_config(expected, observed) is False


def test_different_readback_does_not_reconcile_uncertain_intent(prepared_service, vehicle_ref, fleet, clock, monkeypatch):
    service, manager = prepared_service, Collection(prepared_service)
    item = prepare(manager, vehicle_ref)
    with service.store.db() as db:
        db.execute("UPDATE intents SET status='unknown' WHERE id=?", (item['id'],))
    observed = deepcopy(item['arguments']['config'])
    observed['fields']['BatteryLevel']['minimum_delta'] = 25
    original = fleet.call
    monkeypatch.setattr(fleet, 'call', lambda name, *a, **kw: {'config': observed, 'synced': True} if name.endswith('config_get') else original(name, *a, **kw))
    clock.advance(1)
    manager.refresh(vehicle_ref, SCOPES)
    assert service.store.intent(item['id'])['status'] == 'unknown'
    assert manager.view(vehicle_ref)['target'] == {}


@pytest.mark.parametrize("status", ["prepared", "acknowledged", "unknown", "rejected", "cancelled"])
def test_replay_preserves_original_cost_and_terminal_state(prepared_service, vehicle_ref, fleet, clock, status):
    manager = Collection(prepared_service)
    item = prepare(manager, vehicle_ref)
    review = manager.review(vehicle_ref, item["id"])
    with prepared_service.store.db() as db:
        db.execute("UPDATE intents SET status=? WHERE id=?", (status, item["id"]))
    clock.advance(600)
    before = list(fleet.calls)
    # An explicit equivalent default and stale membership need no provider read.
    again = manager.prepare_change(vehicle_ref, "configure", "obsolete", "atomic-collection-request-01", SCOPES,
        preset="custom", custom_fields={"BatteryLevel": {"interval_seconds": 60}},
        active_hours_per_day=8.0, customer_alerts=False)
    assert again["id"] == item["id"] and again["status"] == status
    assert manager.review(vehicle_ref, item["id"])["review_digest"] == review["review_digest"]
    assert fleet.calls == before


def test_pause_replay_recovers_without_provider(prepared_service, vehicle_ref, fleet):
    manager = Collection(prepared_service)
    revision = manager.view(vehicle_ref)["revision"]
    first = manager.prepare_change(vehicle_ref, "pause", revision, "atomic-pause-retry-01", SCOPES)
    before = list(fleet.calls)
    again = manager.prepare_change(vehicle_ref, "pause", revision, "atomic-pause-retry-01", SCOPES)
    assert again["id"] == first["id"] and fleet.calls == before


def test_preview_changed_during_preflight_blocks_dispatch(prepared_service, vehicle_ref, fleet, monkeypatch):
    service, manager = prepared_service, Collection(prepared_service)
    item = prepare(manager, vehicle_ref)
    original = fleet.call
    def preflight(name, *args, **kwargs):
        if name == "vehicle_fleet_status":
            with service.store.db() as db:
                db.execute("DELETE FROM snapshots WHERE section=?", ("telemetry_preview_"+item["id"],))
        return original(name, *args, **kwargs)
    monkeypatch.setattr(fleet, "call", preflight)
    with pytest.raises(TeslaError) as error:
        service.execute_from_owner(item["id"])
    assert error.value.code == "COLLECTION_REVIEW_INCOMPLETE"
    assert not any(name == CREATE for name, *_ in fleet.calls)
    assert service.store.intent(item["id"])["status"] == "prepared"


def test_owner_confirmation_binds_dependencies_without_explicit_revision(prepared_service, vehicle_ref, fleet):
    from starlette.testclient import TestClient
    from tesla_plugin.server import create_app
    from test_mcp_portal import login
    service, manager = prepared_service, Collection(prepared_service)
    item = prepare(manager, vehicle_ref)
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        csrf = login(client)
        path = "/tesla/owner/intents/"+item["id"]
        assert 'Confirm collection' in client.get(path).text
        with service.store.db() as db:
            db.execute("UPDATE trigger_settings SET revision=revision+1 WHERE vehicle=?", (vehicle_ref,))
        result = client.post(path, data={"csrf": csrf, "decision": "execute"}, headers={"origin": "https://bridge.example"})
        assert result.status_code == 400 and "Events or rules" in result.text
    assert not any(name == CREATE for name, *_ in fleet.calls)
    # Recovery uses the caller's original request, not a newly captured revision.
    before = list(fleet.calls)
    assert prepare(manager, vehicle_ref)["id"] == item["id"]
    assert fleet.calls == before
