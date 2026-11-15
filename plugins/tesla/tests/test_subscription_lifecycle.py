"""Subscription handshake and cancellation boundaries; all callbacks simulated."""
import base64
import json
import socket

import pytest

from tesla_plugin.config import SCOPES, TESLA_SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.events import Events
from tesla_plugin.store import Store

NAME = 'tesla.vehicle_event'
URL = 'https://receiver.example/callback'
DELIVERY = {'url': URL, 'secret': 'whsec_' + base64.b64encode(b'x' * 32).decode()}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('Synthetic subscription test attempted network access')
    monkeypatch.setattr(socket, 'getaddrinfo', blocked)
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked)


class Callback:
    def __init__(self, hook=None):
        self.hook, self.calls = hook, []

    def post(self, url, body, headers):
        value = json.loads(body)
        self.calls.append(value)
        if value.get('type') == 'verification':
            if self.hook:
                self.hook()
            return 200, json.dumps({'challenge': value['challenge']}).encode()
        return 200, b'{}'


def subscribe(events, ref, clock, *, kinds=None, scopes=SCOPES):
    args = {'vehicle_ref': ref, 'kinds': kinds or ['battery_low']}
    return events.subscribe(NAME, args, DELIVERY, scopes, expires_at=clock()+3600), args


@pytest.mark.parametrize('change', ['remove', 'disconnect', 'consent', 'rotation', 'privacy', 'remove-reacquire', 'unsubscribe'])
def test_handshake_cannot_cross_revoked_lifecycle_or_membership(store, vehicle_ref, clock, change):
    peer = Store(store.settings, clock=clock)
    original = peer.vehicle(vehicle_ref)['data']
    kinds = ['battery_low', 'location_changed'] if change == 'privacy' else ['battery_low']
    args = {'vehicle_ref': vehicle_ref, 'kinds': kinds}
    def mutate():
        if change in ('remove', 'remove-reacquire'):
            peer.save_vehicles([])
            if change == 'remove-reacquire':
                peer.save_vehicles([original])
        elif change == 'disconnect':
            peer.disconnect()
        elif change in ('consent', 'rotation'):
            generation = peer.connection()['generation'] if change == 'rotation' else None
            peer.set_tokens({'access_token': 'synthetic-new', 'refresh_token': 'synthetic-renew', 'expires_in': 3600},
                            TESLA_SCOPES, 'eu', generation=generation)
            peer.save_vehicles([original])
        elif change == 'privacy':
            peer.save_vehicles([original | {'granular_access': {'hide_private': True}}])
        else:
            Events(peer, transport=Callback()).unsubscribe(NAME, args, URL, SCOPES)
    transport = Callback(mutate)
    events = Events(store, transport=transport)
    with pytest.raises(TeslaError):
        subscribe(events, vehicle_ref, clock, kinds=kinds)
    with peer.db() as db:
        assert db.execute('SELECT count(*) FROM subscriptions WHERE active=1').fetchone()[0] == 0
    assert len(transport.calls) == 1


def test_unrelated_inventory_refresh_during_handshake_remains_valid(store, vehicle_ref, clock):
    peer = Store(store.settings, clock=clock)
    row = peer.vehicle(vehicle_ref)['data']
    transport = Callback(lambda: peer.save_vehicles([row, {'vin': 'TEST0000000000002'}]))
    result, _ = subscribe(Events(store, transport=transport), vehicle_ref, clock)
    with peer.db() as db:
        assert db.execute('SELECT active FROM subscriptions WHERE id=?', (result['id'],)).fetchone()[0] == 1


@pytest.mark.parametrize('reduction', ['mcp-location', 'tesla-location', 'vehicle-privacy', 'vehicle-removed', 'disconnected'])
def test_unsubscribe_reduces_consent_after_location_or_membership_loss(store, vehicle_ref, clock, reduction):
    transport = Callback()
    events = Events(store, transport=transport)
    result, args = subscribe(events, vehicle_ref, clock, kinds=['battery_low', 'location_changed'])
    with store.db() as db:
        Events.emit(db, vehicle_ref, 'battery_low', clock(), {}, clock())
    peer = Store(store.settings, clock=clock)
    scopes = SCOPES
    if reduction == 'mcp-location':
        scopes = tuple(scope for scope in SCOPES if scope != 'tesla:location')
    elif reduction == 'tesla-location':
        peer.set_tokens({'access_token': 'synthetic-narrow', 'refresh_token': 'synthetic-renew', 'expires_in': 3600},
                        tuple(scope for scope in TESLA_SCOPES if scope != 'vehicle_location'), 'eu',
                        generation=peer.connection()['generation'])
    elif reduction == 'vehicle-privacy':
        peer.save_vehicles([peer.vehicle(vehicle_ref)['data'] | {'granular_access': {'hide_private': True}}])
    elif reduction == 'vehicle-removed':
        peer.save_vehicles([])
    else:
        peer.disconnect()
    assert Events(peer, transport=transport).unsubscribe(NAME, args, URL, scopes) == {}
    with peer.db() as db:
        row = db.execute('SELECT active FROM subscriptions WHERE id=?', (result['id'],)).fetchone()
        assert row is None or not row[0]
        assert db.execute("SELECT count(*) FROM deliveries WHERE state IN ('pending','sending')").fetchone()[0] == 0
    assert events.dispatch_one() is False
    assert len(transport.calls) == 1


def test_unsubscribe_requires_event_scope_and_exact_owned_subscription_identity(store, vehicle_ref, clock):
    events = Events(store, transport=Callback())
    result, args = subscribe(events, vehicle_ref, clock)
    with pytest.raises(TeslaError) as caught:
        events.unsubscribe(NAME, args, URL, ('tesla:read',))
    assert caught.value.code == 'SCOPE_REQUIRED'
    events.unsubscribe(NAME, args, URL + '/different', SCOPES)
    events.unsubscribe(NAME, args | {'vehicle_ref': 'veh_not_owned'}, URL, SCOPES)
    with store.db() as db:
        assert db.execute('SELECT active FROM subscriptions WHERE id=?', (result['id'],)).fetchone()[0] == 1
    assert events.unsubscribe(NAME, args, URL, SCOPES) == {}
    assert events.unsubscribe(NAME, args, URL, SCOPES) == {}
