"""Persistent configuration read ordering with synthetic services and no sockets."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import multiprocessing
import socket
import threading

import pytest

from conftest import FakeFleet
from test_collection import prepared_service
from test_temporary_collection import temporary_setup, start, writes
from tesla_plugin.authorization import Authorization
from tesla_plugin.collection import Collection, collection_enabled
from tesla_plugin.collection_state import CREATE, begin_readback, record_readback, read_collection
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.service import Service
from tesla_plugin.store import Store
from tesla_plugin.temporary_collection import TemporaryCollection, CHECK_SECONDS

GET = 'vehicle_fleet_telemetry_config_get'
ACTIVE = {'fields': {'BatteryLevel': {'interval_seconds': 60}}}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('Synthetic readback test attempted network access')
    for name in ('getaddrinfo', 'create_connection'):
        monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked)


def read(service, ref):
    return service.read(GET, {}, ref, SCOPES)


def remote_snapshot(store, ref):
    with store.db() as db:
        row = db.execute("SELECT * FROM snapshots WHERE vehicle=? AND section='telemetry_remote'", (ref,)).fetchone()
        return dict(row) if row else None


def peer_service(store):
    peer = Store(store.settings, clock=store.clock)
    return Service(peer.settings, store=peer, fleet=FakeFleet(peer))


@pytest.mark.parametrize('newer_first', [False, True], ids=['ordered', 'out-of-order'])
def test_two_store_reads_never_replace_newer_applied_configuration(service, vehicle_ref, clock, monkeypatch, newer_first):
    peer = peer_service(service.store)
    service.store.snapshot(vehicle_ref, 'telemetry_target', ACTIVE, 'local_configuration', clock())
    entered = [threading.Event(), threading.Event()]
    released = [threading.Event(), threading.Event()]

    def reply(index, config):
        def call(name, *args, **kwargs):
            assert name == GET
            entered[index].set()
            assert released[index].wait(5)
            return {'synced': True, 'config': deepcopy(config)}
        return call

    monkeypatch.setattr(service.fleet, 'call', reply(0, None))
    monkeypatch.setattr(peer.fleet, 'call', reply(1, ACTIVE))
    with ThreadPoolExecutor(max_workers=2) as pool:
        older = pool.submit(read, service, vehicle_ref)
        assert entered[0].wait(3)
        newer = pool.submit(read, peer, vehicle_ref)
        assert entered[1].wait(3)
        try:
            if not newer_first:
                released[0].set()
                assert older.result(timeout=3)['data']['config'] is None
            released[1].set()
            assert newer.result(timeout=3)['data']['config'] == ACTIVE
            before = remote_snapshot(peer.store, vehicle_ref)
            if newer_first:
                clock.advance(1)
                released[0].set()
                with pytest.raises(TeslaError) as error:
                    older.result(timeout=3)
                assert error.value.code == 'COLLECTION_READBACK_SUPERSEDED'
            assert remote_snapshot(service.store, vehicle_ref) == before
            assert read_collection(service.store, vehicle_ref)['state'] == 'active'
            assert collection_enabled(service.store)
        finally:
            for event in released:
                event.set()


@pytest.mark.parametrize('failure', ['provider_error', 'invalid_response'])
def test_failed_newer_get_does_not_discard_complete_older_read(service, vehicle_ref, monkeypatch, failure):
    peer = peer_service(service.store)

    def fail(name, *args, **kwargs):
        assert name == GET
        if failure == 'provider_error':
            raise TeslaError('PROVIDER_UNAVAILABLE', 'Synthetic failure')
        return {'synced': True, 'config': {'fields': {'BatteryLevel': {'interval_seconds': 0}}}}

    monkeypatch.setattr(peer.fleet, 'call', fail)

    def older(name, *args, **kwargs):
        assert name == GET
        with pytest.raises(TeslaError):
            read(peer, vehicle_ref)
        return {'synced': True, 'config': deepcopy(ACTIVE)}

    monkeypatch.setattr(service.fleet, 'call', older)
    assert read(service, vehicle_ref)['data']['config'] == ACTIVE
    assert json.loads(remote_snapshot(service.store, vehicle_ref)['data'])['config'] == ACTIVE


def test_read_started_before_target_change_cannot_claim_post_change_verification(service, vehicle_ref, clock, monkeypatch):
    def old_response(name, *args, **kwargs):
        assert name == GET
        clock.advance(1)
        service.store.snapshot(vehicle_ref, 'telemetry_target', ACTIVE, 'local_configuration', clock())
        return {'synced': True, 'config': None}

    monkeypatch.setattr(service.fleet, 'call', old_response)
    with pytest.raises(TeslaError) as error:
        read(service, vehicle_ref)
    assert error.value.code == 'COLLECTION_READBACK_SUPERSEDED'
    view = read_collection(service.store, vehicle_ref)
    assert view['state'] == 'starting' and view['remote'] == {}
    assert not view['evidence']['readback_after_request']
    assert collection_enabled(service.store)


@pytest.mark.parametrize('outcome', ['acknowledged', 'unknown', 'rejected'])
def test_read_spanning_actual_config_dispatch_preserves_write_outcome(prepared_service, vehicle_ref, clock, monkeypatch, outcome):
    service = prepared_service
    item = service.prepare_profile(vehicle_ref, 'custom', {'BatteryLevel': {'interval_seconds': 5}},
                                   'vehicle-readback-config-change', SCOPES)
    original = service.fleet.call

    def provider(name, *args, **kwargs):
        if name == CREATE and outcome != 'acknowledged':
            raise TeslaError('OUTCOME_UNKNOWN' if outcome == 'unknown' else 'COMMAND_REJECTED',
                             'Synthetic config outcome', uncertain=outcome == 'unknown')
        if name == GET:
            clock.advance(1)
            service.execute_from_owner(item['id'])
            return {'synced': True, 'config': None}
        return original(name, *args, **kwargs)

    monkeypatch.setattr(service.fleet, 'call', provider)
    if outcome == 'rejected':
        assert read(service, vehicle_ref)['data']['config'] is None
    else:
        with pytest.raises(TeslaError) as error:
            read(service, vehicle_ref)
        assert error.value.code == 'COLLECTION_READBACK_SUPERSEDED'
        assert remote_snapshot(service.store, vehicle_ref) is None
    assert service.store.intent(item['id'])['status'] == outcome


@pytest.mark.parametrize('finish', [False, True], ids=['still-sending', 'finished-rejected'])
def test_read_during_dispatch_preserves_reconciliation_but_fences_a_changed_outcome(prepared_service, vehicle_ref, monkeypatch, finish):
    service = prepared_service
    item = service.prepare_profile(vehicle_ref, 'custom', {'BatteryLevel': {'interval_seconds': 5}},
                                   'vehicle-readback-during-send', SCOPES)
    with service.store.db() as db:
        db.execute("UPDATE intents SET status='sending' WHERE id=?", (item['id'],))

    def provider(name, *args, **kwargs):
        assert name == GET
        if finish:
            with service.store.db() as db:
                db.execute("UPDATE intents SET status='rejected' WHERE id=?", (item['id'],))
        return {'synced': True, 'config': None}

    monkeypatch.setattr(service.fleet, 'call', provider)
    if finish:
        with pytest.raises(TeslaError) as error:
            read(service, vehicle_ref)
        assert error.value.code == 'COLLECTION_READBACK_SUPERSEDED'
        assert remote_snapshot(service.store, vehicle_ref) is None
    else:
        # A sent request may already have applied while its response is delayed.
        # Keep the existing temporary-worker reconciliation path available.
        assert read(service, vehicle_ref)['data']['config'] is None
        assert service.store.intent(item['id'])['status'] == 'sending'


@pytest.mark.parametrize('regrant', [False, True])
def test_revocation_epoch_blocks_late_read_even_after_same_vin_regrant(service, vehicle_ref, monkeypatch, regrant):
    vehicle = service.store.vehicle(vehicle_ref)['data']

    def provider(name, *args, **kwargs):
        assert name == GET
        service.store.save_vehicles([])
        if regrant:
            service.store.save_vehicles([vehicle])
        return {'synced': True, 'config': deepcopy(ACTIVE)}

    monkeypatch.setattr(service.fleet, 'call', provider)
    with pytest.raises(TeslaError) as error:
        read(service, vehicle_ref)
    assert error.value.code == 'AUTHORIZATION_CHANGED'
    assert remote_snapshot(service.store, vehicle_ref) is None


def _process_readback(settings, now, ref):
    """Separate process, real SQLite ordering, no Fleet or networking."""
    store = Store(settings, clock=lambda: now)
    authorization = Authorization.from_row(store, store.connection())
    attempt = begin_readback(store, ref, authorization)
    record_readback(store, ref, {'synced': True, 'config': ACTIVE}, authorization, attempt=attempt)


def test_applied_sequence_survives_other_process_and_store_restart(store, vehicle_ref, clock):
    authorization = Authorization.from_row(store, store.connection())
    older = begin_readback(store, vehicle_ref, authorization)
    context = multiprocessing.get_context('spawn')
    process = context.Process(target=_process_readback, args=(store.settings, clock(), vehicle_ref))
    process.start()
    process.join(timeout=10)
    if process.is_alive():
        process.terminate()
        process.join(timeout=3)
        pytest.fail('Synthetic readback process did not finish')
    assert process.exitcode == 0
    restarted = Store(store.settings, clock=clock)
    before = remote_snapshot(restarted, vehicle_ref)
    with pytest.raises(TeslaError) as error:
        record_readback(restarted, vehicle_ref, {'synced': True, 'config': None}, authorization, attempt=older)
    assert error.value.code == 'COLLECTION_READBACK_SUPERSEDED'
    assert remote_snapshot(restarted, vehicle_ref) == before


def test_superseded_worker_read_preserves_restore_until_new_evidence(temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, manager, remote, provider = temporary_setup
    baseline = deepcopy(remote['config'])
    start(temporary_setup, vehicle_ref)
    clock.advance(60)
    peer = peer_service(service.store)
    monkeypatch.setattr(peer.fleet, 'call', lambda name, *args, **kwargs: deepcopy(remote))
    raced = False

    def late_baseline(name, *args, **kwargs):
        nonlocal raced
        if name == GET and not raced:
            raced = True
            read(peer, vehicle_ref)
            return {'synced': True, 'config': baseline}
        return provider(name, *args, **kwargs)

    monkeypatch.setattr(fleet, 'call', late_baseline)
    first = TemporaryCollection(service).tick()
    assert first['status'] == 'blocked'
    assert first['last_error'] == 'COLLECTION_READBACK_SUPERSEDED'
    assert first['restore_intent_id'] is None and not first['restore_verified']
    assert len(writes(fleet)) == 1
    assert manager.view(vehicle_ref)['remote']['data']['config'] == remote['config']
    clock.advance(CHECK_SECONDS)
    assert TemporaryCollection(service).tick()['status'] == 'restore_accepted'
    assert len(writes(fleet)) == 2
    clock.advance(CHECK_SECONDS)
    assert TemporaryCollection(service).tick()['restore_verified']
