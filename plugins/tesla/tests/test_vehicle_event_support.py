"""Real ingestion/dispatch regressions with synthetic data and fake callbacks."""
import base64
import json
import socket

import pytest

from tesla_plugin import event_support
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.events import Events
from tesla_plugin.store import canonical
from tesla_plugin.telemetry import Telemetry
from test_telemetry_events import Delivery, payload


@pytest.fixture(autouse=True)
def isolated_rules_and_network(store, monkeypatch):
    with store.db() as db:
        db.execute('DELETE FROM rules')
    def forbidden(*args, **kwargs):
        raise AssertionError('K3 tests must not use external sockets')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)


def subscribe(store, vehicle_ref, clock, kinds=('battery_low',), *, callback=None, path='callback'):
    callback = callback or Delivery()
    events = Events(store, transport=callback)
    events.subscribe('tesla.vehicle_event', {'vehicle_ref': vehicle_ref, 'kinds': list(kinds)},
                     {'url': 'https://receiver.example/'+path,
                      'secret': 'whsec_'+base64.b64encode(b'synthetic-support-test-key-123456').decode()},
                     SCOPES, expires_at=clock()+3600)
    return events, callback


def crossing(store, vehicle_ref, clock):
    events, callback = subscribe(store, vehicle_ref, clock)
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, 'battery_low', {})
    baseline = clock()
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 25}))
    clock.advance(10)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 19}))
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM deliveries').fetchone()[0] == 1
    return telemetry, events, callback, baseline


def saved(store):
    with store.db() as db:
        return dict(db.execute('SELECT * FROM deliveries').fetchone()), dict(db.execute('SELECT * FROM events').fetchone())


@pytest.mark.parametrize('which', ['current', 'baseline'])
@pytest.mark.parametrize('contradiction', [23, None, True])
def test_exact_support_conflict_cancels_unattempted_without_rewriting_evidence(store, vehicle_ref, clock, which, contradiction):
    telemetry, events, callback, baseline = crossing(store, vehicle_ref, clock)
    before, original_event = saved(store)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': contradiction}, when=baseline if which=='baseline' else clock()))
    after, event = saved(store)
    assert after == before | {'state': 'cancelled', 'last_code': 'support_time_conflict'}
    assert event == original_event
    assert not events.dispatch_one()
    assert len(callback.calls) == 1  # Only subscription verification.
    with store.db() as db:
        state = json.loads(db.execute('SELECT state FROM rules').fetchone()[0])
        if which == 'baseline':
            # The crossing used the old baseline, but the current low latch
            # is independently supported by the newer value 19.
            assert state['latched'] is True and state['value']['BatteryLevel'] == 19
            assert db.execute("SELECT quality FROM latest WHERE field='BatteryLevel'").fetchone()[0] == 'valid'
        else:
            assert state == {}


@pytest.mark.parametrize('later', [24, None])
def test_newer_state_does_not_cancel_a_true_historical_event(store, vehicle_ref, clock, later):
    telemetry, events, callback, _ = crossing(store, vehicle_ref, clock)
    before, original_event = saved(store)
    clock.advance(1)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': later}))
    assert saved(store) == (before, original_event)
    assert events.dispatch_one()
    assert saved(store)[0]['state'] == 'accepted'
    assert len(callback.calls) == 2


def test_equivalent_same_time_numbers_are_not_contradictions(store, vehicle_ref, clock):
    telemetry, events, _, baseline = crossing(store, vehicle_ref, clock)
    before = saved(store)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 25.0}, when=baseline))
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 19.0}))
    assert saved(store) == before
    assert events.dispatch_one()


def test_unrelated_field_conflict_does_not_cancel_event(store, vehicle_ref, clock):
    telemetry, events, _, _ = crossing(store, vehicle_ref, clock)
    before = saved(store)
    telemetry.ingest('V', payload(clock, {'InsideTemp': 20}))
    telemetry.ingest('V', payload(clock, {'InsideTemp': 21}))
    assert saved(store) == before
    assert events.dispatch_one()


def test_late_hysteresis_baseline_conflict_before_crossing_resets_state(store, vehicle_ref, clock):
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, 'battery_low', {})
    baseline = clock()
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 25}))
    clock.advance(5)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 21}))  # Neutral hysteresis region.
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 19}, when=baseline))
    clock.advance(5)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 19}))
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 0
        assert db.execute("SELECT quality FROM latest WHERE field='BatteryLevel'").fetchone()[0] == 'valid'


def test_dispatch_rechecks_cross_row_conflict_in_same_claim_transaction(store, vehicle_ref, clock):
    _, events, callback, baseline = crossing(store, vehicle_ref, clock)
    before, original_event = saved(store)
    # A competing/imported writer has inserted a contradictory historical row
    # without updating latest or invoking the ingestion invalidator.
    with store.db() as db:
        source_at = db.execute("SELECT min(source_at) FROM samples WHERE field='BatteryLevel'").fetchone()[0]
        db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                   ('competing-history-row', vehicle_ref, 'BatteryLevel', '18', source_at, clock(), 'valid', 'payload_created_at'))
    assert events.dispatch_one()
    after, event = saved(store)
    assert after == before | {'state': 'cancelled', 'last_code': 'support_time_conflict'}
    assert event == original_event and len(callback.calls) == 1


@pytest.mark.parametrize('field,value', [('Gear', 'ShiftStateD'), ('Locked', True), ('DriverSeatOccupied', True)])
def test_multisignal_dwell_tracks_each_source_time_and_intermediate_observation(store, vehicle_ref, clock, field, value):
    telemetry = Telemetry(store, monotonic=clock)
    events, callback = subscribe(store, vehicle_ref, clock, ('unlocked_parked',))
    telemetry.configure_rule(vehicle_ref, 'unlocked_parked', {'dwell_seconds': 20})
    active = {'Gear': 'ShiftStateP', 'Locked': False, 'DriverSeatOccupied': False}
    telemetry.ingest('V', payload(clock, active))
    clock.advance(10)
    middle = clock()
    telemetry.ingest('V', payload(clock, active))
    for index, name in enumerate(active):
        clock.advance(10 if index==0 else 1)
        telemetry.ingest('V', payload(clock, {name: active[name]}))
    before, original_event = saved(store)
    assert before['state'] == 'pending'
    support = json.loads(original_event['data'])[event_support.KEY]
    assert set(support['fields']) == set(active)
    telemetry.ingest('V', payload(clock, {field: value}, when=middle))
    assert saved(store)[0]['state'] == 'cancelled'
    assert saved(store)[1] == original_event
    assert not events.dispatch_one() and len(callback.calls) == 1


def test_inactive_observation_before_dwell_is_not_support(store, vehicle_ref, clock):
    telemetry = Telemetry(store, monotonic=clock)
    events, _ = subscribe(store, vehicle_ref, clock, ('unlocked_parked',))
    telemetry.configure_rule(vehicle_ref, 'unlocked_parked', {'dwell_seconds': 10})
    inactive = clock()
    telemetry.ingest('V', payload(clock, {'Gear': 'ShiftStateP', 'Locked': True, 'DriverSeatOccupied': False}))
    for _ in range(2):
        clock.advance(10)
        telemetry.ingest('V', payload(clock, {'Gear': 'ShiftStateP', 'Locked': False, 'DriverSeatOccupied': False}))
    before = saved(store)
    telemetry.ingest('V', payload(clock, {'Locked': False}, when=inactive))
    assert saved(store) == before
    assert events.dispatch_one()


def test_geofence_baseline_conflict_cancels_pending_transition(store, vehicle_ref, clock):
    telemetry = Telemetry(store, monotonic=clock)
    events, _ = subscribe(store, vehicle_ref, clock, ('geofence_enter',))
    telemetry.configure_rule(vehicle_ref, 'geofence', {'latitude': 48.2, 'longitude': 16.3,
                             'radius_m': 100, 'dwell_seconds': 10})
    baseline = clock()
    for latitude in (48.3, 48.2, 48.2):
        telemetry.ingest('V', payload(clock, {'Location': {'latitude': latitude, 'longitude': 16.3}, 'GpsState': True}))
        clock.advance(10)
    assert saved(store)[0]['state'] == 'pending'
    telemetry.ingest('V', payload(clock, {'GpsState': False}, when=baseline))
    assert saved(store)[0]['state'] == 'cancelled'
    assert not events.dispatch_one()


def test_attempted_retry_keeps_body_receipt_and_delivery_identity(store, vehicle_ref, clock):
    telemetry, events, callback, _ = crossing(store, vehicle_ref, clock)
    callback.status = 503
    assert events.dispatch_one()
    before = saved(store)
    first_request = callback.calls[-1]
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 25}))
    assert saved(store) == before
    clock.advance(3)
    callback.status = 200
    assert events.dispatch_one()
    assert callback.calls[-1][1] == first_request[1]
    assert callback.calls[-1][2]['webhook-id'] == first_request[2]['webhook-id']
    assert saved(store)[0]['state'] == 'accepted'


def test_accepted_receipt_is_not_rewritten_after_conflict(store, vehicle_ref, clock):
    telemetry, events, _, _ = crossing(store, vehicle_ref, clock)
    assert events.dispatch_one()
    before = saved(store)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 25}))
    assert saved(store) == before


def test_conflict_after_claim_can_complete_inflight_callback(store, vehicle_ref, clock):
    telemetry, events, callback, _ = crossing(store, vehicle_ref, clock)
    original = callback.post
    def contradict_during_request(*args):
        telemetry.ingest('V', payload(clock, {'BatteryLevel': 25}))
        return original(*args)
    callback.post = contradict_during_request
    assert events.dispatch_one()
    receipt, _ = saved(store)
    assert receipt['state'] == 'accepted' and receipt['attempts'] == 1 and receipt['last_code'] == '200'


def test_conflict_cancels_only_untouched_subscription_of_same_event(store, vehicle_ref, clock):
    telemetry, events, callback, _ = crossing(store, vehicle_ref, clock)
    # Add a second delivery with its own subscription through the normal emit
    # path, before emitting the next crossing.
    subscribe(store, vehicle_ref, clock, callback=callback, path='second')
    clock.advance(5)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 25}))
    clock.advance(5)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 19}))
    with store.db() as db:
        newest = db.execute('SELECT id FROM events ORDER BY occurred DESC LIMIT 1').fetchone()[0]
        chosen = db.execute('SELECT id FROM deliveries WHERE event=? ORDER BY id LIMIT 1', (newest,)).fetchone()[0]
    callback.status = 503
    assert events.dispatch_one(_delivery_id=chosen)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 25}))
    with store.db() as db:
        rows = db.execute('SELECT state,attempts,last_code FROM deliveries WHERE event=? ORDER BY attempts', (newest,)).fetchall()
    assert [tuple(r) for r in rows] == [('cancelled', 0, 'support_time_conflict'), ('pending', 1, '503')]


def test_ingestion_rollback_restores_pending_event_and_rule_state(store, vehicle_ref, clock):
    telemetry, _, _, _ = crossing(store, vehicle_ref, clock)
    before = saved(store)
    frame = payload(clock, {'BatteryLevel': 25})
    frame['data'].append(frame['data'][0])  # Failure after the conflicting insert.
    with pytest.raises(TeslaError, match='repeated'):
        telemetry.ingest('V', frame)
    assert saved(store) == before
    with store.db() as db:
        assert db.execute("SELECT quality FROM latest WHERE field='BatteryLevel'").fetchone()[0] == 'valid'
        assert json.loads(db.execute('SELECT state FROM rules').fetchone()[0])['value']['BatteryLevel'] == 19


def test_legacy_unattempted_rule_event_has_no_invented_support(store, vehicle_ref, clock):
    events, callback = subscribe(store, vehicle_ref, clock)
    with store.db() as db:
        Events.emit(db, vehicle_ref, 'battery_low', clock(), {'rule_id': 'legacy', 'observed': {'BatteryLevel': 19}}, clock())
    original = saved(store)
    assert events.dispatch_one()
    receipt, event = saved(store)
    assert receipt['state'] == 'cancelled' and receipt['last_code'] == 'support_unavailable'
    assert event == original[1] and len(callback.calls) == 1


@pytest.mark.parametrize('explicit_conflict', [False, True])
def test_batch_support_does_not_suppress_an_explicit_conflict_report(store, vehicle_ref, clock, explicit_conflict):
    telemetry = Telemetry(store, monotonic=clock)
    events, callback = subscribe(store, vehicle_ref, clock, ('telemetry_changed',))
    with store.db() as db:
        db.execute('INSERT OR REPLACE INTO trigger_preferences VALUES(?,?,1)', (vehicle_ref, 'field:BatteryLevel'))
        db.execute('UPDATE trigger_settings SET batch_seconds=10 WHERE vehicle=?', (vehicle_ref,))
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 25}))
    instant = clock()
    if explicit_conflict:
        telemetry.ingest('V', payload(clock, {'BatteryLevel': 26}))
    clock.advance(11)
    telemetry.tick()
    if not explicit_conflict:
        telemetry.ingest('V', payload(clock, {'BatteryLevel': 26}, when=instant))
        assert saved(store)[0]['state'] == 'cancelled'
        assert not events.dispatch_one()
    else:
        assert saved(store)[0]['state'] == 'pending'
        assert events.dispatch_one()
        assert len(callback.calls) == 2


def test_legacy_rule_state_is_rebaselined_before_using_new_observation(store, vehicle_ref, clock):
    telemetry = Telemetry(store, monotonic=clock)
    rule = telemetry.configure_rule(vehicle_ref, 'battery_low', {})
    with store.db() as db:
        db.execute('UPDATE rules SET state=? WHERE id=?',
                   (canonical({'value': {'BatteryLevel': 25}, 'latched': False,
                               'source_at': clock()-5, 'received': clock()-5}), rule['id']))
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 19}))
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 0
        state = json.loads(db.execute('SELECT state FROM rules').fetchone()[0])
    assert event_support.known(state[event_support.KEY])
    assert state['latched'] is True


def test_retained_conflict_before_evaluation_cannot_supply_transition_baseline(store, vehicle_ref, clock):
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, 'battery_low', {})
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 25}))
    with store.db() as db:
        source = db.execute("SELECT source_at FROM latest WHERE field='BatteryLevel'").fetchone()[0]
        db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                   ('prior-conflict', vehicle_ref, 'BatteryLevel', '19', source, clock(), 'valid', 'synthetic'))
    clock.advance(10)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 19}))
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 0


def test_support_survives_reopen_and_late_conflict_is_scoped_to_vehicle(store, settings, vehicle_ref, clock):
    from tesla_plugin.store import Store
    telemetry, events, _, baseline = crossing(store, vehicle_ref, clock)
    other_ref = 'synthetic-other-vehicle'
    with store.db() as db:
        db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                   ('other-vehicle', other_ref, 'BatteryLevel', '18', baseline, clock(), 'valid', 'synthetic'))
    reopened = Store(settings, clock=clock)
    telemetry = Telemetry(reopened, monotonic=clock)
    before = saved(store)
    with reopened.db() as db:
        support = json.loads(before[1]['data'])[event_support.KEY]
        assert not event_support.conflicted(db, vehicle_ref, support)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 18}, when=baseline))
    assert saved(reopened)[0]['state'] == 'cancelled'
    assert saved(reopened)[1] == before[1]


def test_dwell_support_size_is_bounded_by_fields_not_observation_count(store, vehicle_ref, clock):
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, 'unlocked_parked', {'dwell_seconds': 1000})
    for _ in range(100):
        telemetry.ingest('V', payload(clock, {'Gear': 'ShiftStateP', 'Locked': False, 'DriverSeatOccupied': False}))
        clock.advance(1)
    with store.db() as db:
        support = json.loads(db.execute('SELECT state FROM rules').fetchone()[0])[event_support.KEY]
    assert len(support['fields']) == 3
    assert all(len(ranges)==1 for ranges in support['fields'].values())
    assert len(canonical(support)) < 500


@pytest.mark.parametrize('via_ingestion', [False, True])
def test_legacy_batch_uses_its_recorded_times_without_rewriting_evidence(store, vehicle_ref, clock, via_ingestion):
    telemetry = Telemetry(store, monotonic=clock)
    events, callback = subscribe(store, vehicle_ref, clock, ('telemetry_changed',))
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 25}))
    with store.db() as db:
        instant = db.execute("SELECT source_at FROM samples WHERE field='BatteryLevel'").fetchone()[0]
    observation = {'value': 25, 'quality': 'valid', 'source_at': instant, 'received_at': instant}
    data = {'changes': {'BatteryLevel': {'before': None, 'after': observation}}}
    with store.db() as db:
        identifier = Events.emit(db, vehicle_ref, 'telemetry_changed', clock(), data, clock())
        # Model a retained 1.0.3 event, whose own observations have exact times
        # but which predates the support metadata. Keep its frozen callback.
        db.execute('UPDATE events SET data=? WHERE id=?', (canonical(data), identifier))
    before, original_event = saved(store)
    if via_ingestion:
        telemetry.ingest('V', payload(clock, {'BatteryLevel': 26}))
        assert not events.dispatch_one()
    else:
        with store.db() as db:
            db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                       ('legacy-batch-conflict', vehicle_ref, 'BatteryLevel', '26', instant, clock(), 'valid', 'synthetic'))
        before, original_event = saved(store)
        assert events.dispatch_one()
    receipt, event = saved(store)
    assert receipt == before | {'state': 'cancelled', 'last_code': 'support_time_conflict'}
    assert event == original_event and len(callback.calls) == 1


def test_legacy_batch_without_recorded_times_cannot_invent_support(store, vehicle_ref, clock):
    events, callback = subscribe(store, vehicle_ref, clock, ('telemetry_changed',))
    with store.db() as db:
        Events.emit(db, vehicle_ref, 'telemetry_changed', clock(),
                    {'changes': {'BatteryLevel': {'before': None, 'after': {'value': 25, 'quality': 'valid'}}}}, clock())
    original = saved(store)
    assert events.dispatch_one()
    receipt, event = saved(store)
    assert receipt['state'] == 'cancelled' and receipt['last_code'] == 'support_unavailable'
    assert event == original[1] and len(callback.calls) == 1


def test_dwell_checks_historical_conflict_before_emission_without_new_ingestion(store, vehicle_ref, clock):
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, 'unlocked_parked', {'dwell_seconds': 20})
    active = {'Gear': 'ShiftStateP', 'Locked': False, 'DriverSeatOccupied': False}
    telemetry.ingest('V', payload(clock, active))
    with store.db() as db:
        origin = db.execute("SELECT source_at FROM samples WHERE field='Gear'").fetchone()[0]
    clock.advance(10)
    telemetry.ingest('V', payload(clock, active))
    with store.db() as db:
        db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                   ('external-dwell-conflict', vehicle_ref, 'Gear', canonical('ShiftStateD'), origin, clock(), 'valid', 'synthetic'))
    clock.advance(10)
    telemetry.ingest('V', payload(clock, active))
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 0
        assert json.loads(db.execute('SELECT state FROM rules').fetchone()[0]) == {}


def test_latched_dwell_frame_does_not_rescan_all_historical_support(store, vehicle_ref, clock):
    from contextlib import contextmanager
    from tesla_plugin.value_semantics import json_equal
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, 'unlocked_parked', {'dwell_seconds': 1})
    active = {'Gear': 'ShiftStateP', 'Locked': False, 'DriverSeatOccupied': False}
    for _ in range(2):
        telemetry.ingest('V', payload(clock, active))
        clock.advance(1)
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 1
        # Retained, already evaluated active history after the event. A late
        # contradiction still resets this state through the ingestion path.
        old = clock()
        db.executemany('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                       [(f'long-dwell-{field}-{i}', vehicle_ref, field, canonical(value), old+i,
                         old+i, 'valid', 'synthetic') for i in range(1000) for field, value in active.items()])
        state = json.loads(db.execute('SELECT state FROM rules').fetchone()[0])
        state[event_support.KEY] = event_support.combine(state[event_support.KEY],
            event_support.points([{'field': field, 'source_at': old+999} for field in active]), span=True)
        state['source_at'], state['received'] = old+999, old+999
        db.execute('UPDATE rules SET state=?', (canonical(state),))
    clock.advance(1000)
    comparisons = []
    original = store.db
    @contextmanager
    def counted():
        with original() as db:
            def equality(field, left, right):
                comparisons.append(field)
                return json_equal(field, left, right)
            db.create_function('telemetry_value_equal', 3, equality)
            yield db
    store.db = counted
    telemetry.ingest('V', payload(clock, active))
    assert len(comparisons) < 30  # Three point groups, independent of 3,000 historical rows.
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 1
