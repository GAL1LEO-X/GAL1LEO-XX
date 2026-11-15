"""Adversarial response ordering; synthetic transports and temporary stores only."""
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import fcntl
import json
import threading

import httpx
import pytest

from conftest import VIN
from tesla_plugin.config import SCOPES, TESLA_SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.events import Events
from tesla_plugin.fleet import Fleet
from tesla_plugin.server import create_app
from tesla_plugin.service import Service


class Delivery:
    hook = None
    def post(self, url, body, headers):
        data = json.loads(body)
        if data.get('type') == 'verification':
            return 200, json.dumps({'challenge':data['challenge']}).encode()
        return self.hook() if self.hook else (200,b'{}')


def subscribe(events, ref, clock, *, secret=None):
    secret = secret or 'whsec_'+base64.b64encode(b'x'*32).decode()
    args = {'vehicle_ref':ref,'kinds':['battery_low']}
    delivery = {'url':'https://receiver.example/callback','secret':secret}
    result = events.subscribe('tesla.vehicle_event',args,delivery,SCOPES,expires_at=clock()+3600)
    return result['id'],args,delivery


def token_values(label):
    return {'access_token':'synthetic-'+label,'refresh_token':'synthetic-renew-'+label,'expires_in':3600}


def new_connection(store, *, rotate=False, same_vehicle=False):
    generation = store.connection()['generation'] if rotate else None
    store.set_tokens(token_values('new'),TESLA_SCOPES,'eu',generation=generation)
    new = {'vin':VIN if same_vehicle else 'TEST0000000000002','display_name':'new inventory'}
    store.save_vehicles([new])
    with store.db() as db:
        return db.execute('SELECT ref FROM vehicles WHERE active=1').fetchone()[0]


@pytest.mark.parametrize('change',['disconnect','reconnect'])
def test_discovery_never_restores_obsolete_inventory(store,vehicle_ref,change):
    store.settings=replace(store.settings,live_enabled=True)
    old=store.vehicle(vehicle_ref)['data']
    def reply(_):
        store.disconnect() if change=='disconnect' else new_connection(store)
        return httpx.Response(200,json={'response':[old]})
    client=Fleet(store,transport=httpx.MockTransport(reply))
    try:
        with pytest.raises(TeslaError):
            client.discover()
        with store.db() as db:
            names=[r[0] for r in db.execute('SELECT name FROM vehicles WHERE active=1')]
            assert names == ([] if change == 'disconnect' else ['new inventory'])
    finally: client.close()


@pytest.mark.parametrize('rotate',[False,True],ids=['new-consent','same-generation-token-rotation'])
def test_old_401_preserves_new_authorization_and_work(store,vehicle_ref,clock,rotate):
    store.settings=replace(store.settings,live_enabled=True)
    created={}
    def reply(_):
        ref=new_connection(store,rotate=rotate,same_vehicle=True)
        generation=store.connection()['generation']
        events=Events(store,transport=Delivery())
        created['sub']=subscribe(events,ref,clock)[0]
        with store.db() as db:
            db.execute('INSERT INTO intents VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                ('new-intent','new-client','synthetic-fingerprint',ref,'set_temps','{}','[]',generation,clock(),clock()+300,'prepared',None))
        return httpx.Response(401,json={'error':'synthetic-old-request-unauthorized'})
    client=Fleet(store,transport=httpx.MockTransport(reply))
    try:
        with pytest.raises(TeslaError):client.call('vehicle_list')
        with store.db() as db:
            assert db.execute('SELECT status FROM connection').fetchone()[0]=='active'
            assert db.execute('SELECT status FROM intents WHERE id=?',('new-intent',)).fetchone()[0]=='prepared'
            assert db.execute('SELECT active FROM subscriptions WHERE id=?',(created['sub'],)).fetchone()[0]==1
    finally:client.close()


def test_token_and_connection_cannot_come_from_different_consents(store,monkeypatch):
    store.settings=replace(store.settings,live_enabled=True)
    observed=[]
    def reply(request):
        observed.append(request.headers['Authorization'])
        return httpx.Response(200,json={'response':[]})
    client=Fleet(store,transport=httpx.MockTransport(reply))
    original=client.oauth.authorization
    old_generation=store.connection()['generation']
    def token_then_reauthorize():
        value=original()
        new_connection(store)
        return value
    monkeypatch.setattr(client.oauth,'authorization',token_then_reauthorize)
    try:
        with pytest.raises(TeslaError):
            client.call('vehicle_list')
        assert store.connection()['generation']==old_generation+1
        assert observed==[]
    finally:client.close()


def test_existing_guarded_discovery_rejects_new_consent(store):
    store.settings=replace(store.settings,live_enabled=True)
    generation=store.connection()['generation']
    def reply(_):
        new_connection(store)
        return httpx.Response(200,json={'response':[]})
    client=Fleet(store,transport=httpx.MockTransport(reply))
    try:
        with pytest.raises(TeslaError):client.discover(expected_generation=generation)
        with store.db() as db:
            assert [r[0] for r in db.execute('SELECT name FROM vehicles WHERE active=1')]==['new inventory']
    finally:client.close()


@pytest.mark.parametrize('rotate_secret',[False,True],ids=['same-secret','rotated-secret'])
def test_old_410_preserves_renewal_and_retries_pending_delivery(store,vehicle_ref,clock,rotate_secret):
    transport=Delivery();events=Events(store,transport=transport)
    sub,args,delivery=subscribe(events,vehicle_ref,clock)
    with store.db() as db:
        before=dict(db.execute('SELECT generation,expires,secret FROM subscriptions WHERE id=?',(sub,)).fetchone())
        Events.emit(db,vehicle_ref,'battery_low',clock(),{'synthetic':True},clock())
    def renew_before_old_410():
        clock.advance(1)
        if rotate_secret:delivery['secret']='whsec_'+base64.b64encode(b'y'*32).decode()
        renewed=events.subscribe('tesla.vehicle_event',args,delivery,SCOPES,expires_at=clock()+7200)
        assert renewed['id']==sub
        with store.db() as db:
            new=dict(db.execute('SELECT generation,expires,secret,active FROM subscriptions WHERE id=?',(sub,)).fetchone())
        assert new['generation']==before['generation'] and new['active']==1
        assert new['expires']>before['expires'] and new['secret']!=before['secret']
        return 410,b'{}'
    transport.hook=renew_before_old_410
    assert events.dispatch_one()
    with store.db() as db:
        assert db.execute('SELECT active FROM subscriptions WHERE id=?',(sub,)).fetchone()[0]==1
        assert db.execute('SELECT state FROM deliveries').fetchone()[0]=='pending'
    clock.advance(3)
    transport.hook=lambda: (200,b'{}')
    assert events.dispatch_one()
    with store.db() as db:
        assert db.execute('SELECT state FROM deliveries').fetchone()[0]=='accepted'


@pytest.mark.parametrize('old_status',[200,429,500,410])
def test_old_attempt_cannot_complete_its_successor(store,vehicle_ref,clock,old_status):
    transport=Delivery();events=Events(store,transport=transport)
    sub,_,_=subscribe(events,vehicle_ref,clock)
    with store.db() as db:Events.emit(db,vehicle_ref,'battery_low',clock(),{'synthetic':True},clock())
    first_entered=threading.Event();second_entered=threading.Event()
    first_release=threading.Event();second_release=threading.Event()
    lock=threading.Lock();calls=0
    def block():
        nonlocal calls
        with lock:calls+=1;index=calls
        entered,release=(first_entered,first_release) if index==1 else (second_entered,second_release)
        entered.set()
        assert release.wait(5)
        return (old_status if index==1 else 200),b'{}'
    transport.hook=block
    with ThreadPoolExecutor(max_workers=2) as pool:
        try:
            first=pool.submit(events.dispatch_one)
            assert first_entered.wait(3)
            clock.advance(31)
            second=pool.submit(events.dispatch_one)
            assert second_entered.wait(3)
            first_release.set();assert first.result(timeout=3)
            with store.db() as db:
                row=db.execute('SELECT state,attempts FROM deliveries').fetchone()
                assert tuple(row)==('sending',2)
                assert db.execute('SELECT active FROM subscriptions WHERE id=?',(sub,)).fetchone()[0]==1
            second_release.set();assert second.result(timeout=3)
            with store.db() as db:
                assert db.execute('SELECT state FROM deliveries').fetchone()[0]=='accepted'
        finally:first_release.set();second_release.set()


def test_lifespan_drains_thread_before_releasing_process_lock(service,monkeypatch):
    app=create_app(service.settings,service=service)
    entered=threading.Event();release=threading.Event();finished=threading.Event()
    def block():
        entered.set()
        try:assert release.wait(5)
        finally:finished.set()
    monkeypatch.setattr(app.state.events,'dispatch_one',block)
    async def scenario():
        shutdown_started=asyncio.Event()
        async def application():
            async with app.router.lifespan_context(app):
                assert await asyncio.to_thread(entered.wait,3)
                shutdown_started.set()
        task=asyncio.create_task(application())
        try:
            await shutdown_started.wait()
            await asyncio.sleep(0)
            assert not finished.is_set()
            assert not task.done()
            with open(str(service.store.path)+'.server.lock','a') as handle:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:release.set()
        await asyncio.wait_for(task,3)
        assert finished.is_set()
        with open(str(service.store.path)+'.server.lock','a') as handle:
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.flock(handle,fcntl.LOCK_UN)
    asyncio.run(scenario())


def test_history_same_timestamp_page_can_continue(service,vehicle_ref,clock):
    with service.store.db() as db:
        for n in range(3):
            db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                (f'synthetic-{n}',vehicle_ref,'BatteryLevel',str(n),clock(),clock(),'valid','synthetic'))
    first=service.history(vehicle_ref,['BatteryLevel'],clock()-1,clock()+1,SCOPES,limit=2)
    remaining=service.history(vehicle_ref,['BatteryLevel'],clock()-1,clock()+1,SCOPES,limit=2,cursor=first['next_cursor'])
    assert first['truncated'] and not remaining['truncated']
    assert [s['value'] for s in first['samples']+remaining['samples']]==[0,1,2]


@pytest.mark.parametrize('rotate', [False, True])
def test_discovery_checks_identity_atomically_when_saving(store, vehicle_ref, monkeypatch, rotate):
    store.settings = replace(store.settings, live_enabled=True)
    old = store.vehicle(vehicle_ref)['data']
    original = store.save_vehicles
    def change_before_save(vehicles, **kwargs):
        monkeypatch.setattr(store, 'save_vehicles', original)
        new_connection(store, rotate=rotate)
        return original(vehicles, **kwargs)
    monkeypatch.setattr(store, 'save_vehicles', change_before_save)
    client = Fleet(store, transport=httpx.MockTransport(lambda _: httpx.Response(200, json={'response': [old]})))
    try:
        with pytest.raises(TeslaError):
            client.discover()
        with store.db() as db:
            assert [r[0] for r in db.execute('SELECT name FROM vehicles WHERE active=1')] == ['new inventory']
    finally:
        client.close()


def test_late_cache_write_does_not_cross_new_authorization(store, vehicle_ref, monkeypatch):
    store.settings = replace(store.settings, live_enabled=True)
    client = Fleet(store, transport=httpx.MockTransport(lambda _: httpx.Response(200, json={'response': {'state': 'online'}})))
    service = Service(store.settings, store=store, fleet=client)
    original = store.snapshot
    def change_before_cache(*args, **kwargs):
        new_connection(store, same_vehicle=True)
        return original(*args, **kwargs)
    monkeypatch.setattr(store, 'snapshot', change_before_cache)
    try:
        with pytest.raises(TeslaError):
            service.read('vehicle_vehicle', {}, vehicle_ref, SCOPES)
        with store.db() as db:
            assert db.execute('SELECT count(*) FROM snapshots').fetchone()[0] == 0
    finally:
        client.close()


def test_current_401_still_revokes_current_access(store, vehicle_ref, clock):
    store.settings = replace(store.settings, live_enabled=True)
    sub = subscribe(Events(store, transport=Delivery()), vehicle_ref, clock)[0]
    client = Fleet(store, transport=httpx.MockTransport(lambda _: httpx.Response(401)))
    try:
        with pytest.raises(TeslaError):
            client.call('vehicle_list')
        with store.db() as db:
            assert db.execute('SELECT status FROM connection').fetchone()[0] == 'reauth_required'
            assert db.execute('SELECT active FROM subscriptions WHERE id=?', (sub,)).fetchone()[0] == 0
    finally:
        client.close()


def test_changed_authorization_after_command_is_uncertain_not_replayed(store, vehicle_ref):
    store.settings = replace(store.settings, live_enabled=True)
    calls = []
    def respond(request):
        calls.append(request)
        new_connection(store, same_vehicle=True)
        return httpx.Response(200, json={'response': {'result': True}})
    client = Fleet(store, transport=httpx.MockTransport(respond))
    try:
        with pytest.raises(TeslaError) as caught:
            client.call('set_charge_limit', {'percent': 80}, vehicle=store.vehicle(vehicle_ref))
        assert caught.value.uncertain and len(calls) == 1
        assert store.connection()['status'] == 'active'
    finally:
        client.close()


def test_old_410_cannot_disable_subscription_after_successor_completed(store, vehicle_ref, clock):
    transport = Delivery()
    events = Events(store, transport=transport)
    sub = subscribe(events, vehicle_ref, clock)[0]
    with store.db() as db:
        Events.emit(db, vehicle_ref, 'battery_low', clock(), {'synthetic': True}, clock())
    def successor_completes():
        clock.advance(31)
        transport.hook = lambda: (200, b'{}')
        assert events.dispatch_one()
        return 410, b'{}'
    transport.hook = successor_completes
    assert events.dispatch_one()
    with store.db() as db:
        assert db.execute('SELECT state,attempts FROM deliveries').fetchone()[:] == ('accepted', 2)
        assert db.execute('SELECT active FROM subscriptions WHERE id=?', (sub,)).fetchone()[0] == 1
