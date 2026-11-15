"""Persistent inventory ordering, using real Fleet parsing and synthetic stores."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import socket
import threading

import httpx
import pytest

from tesla_plugin.errors import TeslaError
from tesla_plugin.fleet import Fleet
from tesla_plugin.store import Store, utc
from tesla_plugin.telemetry import Telemetry

NEW_VIN = 'TEST0000000000002'


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('Synthetic discovery test attempted network access')
    for name in ('getaddrinfo', 'create_connection'):
        monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked)


def client(store, handler):
    return Fleet(store, transport=httpx.MockTransport(handler))


def inventory(store):
    with store.db() as db:
        return [dict(row) for row in db.execute('SELECT * FROM vehicles ORDER BY vin')]


def evidence(store, ref):
    with store.db() as db:
        return {table: [tuple(row) for row in db.execute(f'SELECT * FROM {table} WHERE vehicle=?', (ref,))]
                for table in ('samples', 'latest', 'snapshots', 'rules', 'trigger_settings',
                              'trigger_preferences', 'trigger_buffer', 'trigger_audit', 'latest_provenance')}


@pytest.mark.parametrize('newer_first', [False, True], ids=['ordered', 'out-of-order'])
def test_two_store_discoveries_preserve_newer_inventory_and_ingest(store, vehicle_ref, clock, newer_first):
    store.settings = replace(store.settings, live_enabled=True)
    peer = Store(store.settings, clock=clock)
    old = store.vehicle(vehicle_ref)['data']
    new = {'vin': NEW_VIN, 'display_name': 'Synthetic acquired vehicle'}
    entered = [threading.Event(), threading.Event()]
    released = [threading.Event(), threading.Event()]
    def handler(index, rows):
        def reply(_):
            entered[index].set()
            assert released[index].wait(5)
            return httpx.Response(200, json={'response': rows})
        return reply
    first, second = client(store, handler(0, [old])), client(peer, handler(1, [old, new]))
    auth = store.connection()
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(first.discover)
            assert entered[0].wait(3)
            b = pool.submit(second.discover)
            assert entered[1].wait(3)
            try:
                if not newer_first:
                    released[0].set()
                    assert a.result(timeout=3) is None
                released[1].set()
                assert b.result(timeout=3) is None
                with peer.db() as db:
                    ref = db.execute('SELECT ref FROM vehicles WHERE vin=? AND active=1', (NEW_VIN,)).fetchone()[0]
                packet = {'vin': NEW_VIN, 'createdAt': utc(clock()),
                          'data': [{'key': 'BatteryLevel', 'value': {'doubleValue': 55.0}}]}
                assert Telemetry(peer).ingest('V', packet)['status'] == 'accepted'
                peer.snapshot(ref, 'synthetic', {'value': 55}, 'synthetic', clock())
                before, before_inventory = evidence(peer, ref), inventory(peer)
                if newer_first:
                    clock.advance(1)
                    released[0].set()
                    with pytest.raises(TeslaError) as caught:
                        a.result(timeout=3)
                    assert caught.value.code == 'DISCOVERY_SUPERSEDED'
                assert inventory(peer) == before_inventory
                assert evidence(peer, ref) == before
                assert len(before['samples']) == 1
                assert store.connection() == auth
            finally:
                for event in released:
                    event.set()
    finally:
        first.close(); second.close()


@pytest.mark.parametrize('response', [[], 'invalid', None])
def test_newer_failure_does_not_supersede_complete_older_discovery(store, vehicle_ref, response):
    store.settings = replace(store.settings, live_enabled=True)
    peer = Store(store.settings, clock=store.clock)
    old = store.vehicle(vehicle_ref)['data']
    # For [] a full page followed by missing envelope exercises incomplete paging.
    def fail(request):
        if response == [] and request.url.params['page'] == '1':
            return httpx.Response(200, json={'response': [old] * 100})
        return httpx.Response(200, json={'response': response} if response != [] else {})
    second = client(peer, fail)
    def first_response(_):
        with pytest.raises(TeslaError):
            second.discover()
        return httpx.Response(200, json={'response': [old]})
    first = client(store, first_response)
    try:
        first.discover()
        assert store.vehicle(vehicle_ref)['active'] == 1
    finally:
        first.close(); second.close()


def test_stale_empty_discovery_cannot_revoke_but_current_empty_can(store, vehicle_ref):
    store.settings = replace(store.settings, live_enabled=True)
    peer = Store(store.settings, clock=store.clock)
    old = store.vehicle(vehicle_ref)['data']
    newer = client(peer, lambda _: httpx.Response(200, json={'response': [old]}))
    def late_empty(_):
        newer.discover()
        return httpx.Response(200, json={'response': []})
    stale = client(store, late_empty)
    current = client(peer, lambda _: httpx.Response(200, json={'response': []}))
    try:
        with pytest.raises(TeslaError) as caught:
            stale.discover()
        assert caught.value.code == 'DISCOVERY_SUPERSEDED'
        assert store.vehicle(vehicle_ref)['active'] == 1
        current.discover()
        with pytest.raises(TeslaError, match='currently authorized'):
            store.vehicle(vehicle_ref)
    finally:
        stale.close(); newer.close(); current.close()
