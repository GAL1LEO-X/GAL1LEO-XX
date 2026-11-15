"""Offline regressions for DATA-01/02; payload spellings are not sensor changes."""
import pytest

from conftest import VIN
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.sample_evidence import enrich_history, history_provenance, view
from tesla_plugin.store import Store, utc
from tesla_plugin.telemetry import Telemetry


def frame(clock, field, envelope, *, when=None):
    return {'vin': VIN, 'createdAt': utc(clock() if when is None else when),
            'data': [{'key': field, 'value': envelope}]}


EQUIVALENTS = [
    ('BatteryLevel', {'intValue': 50}, {'doubleValue': 50.0}),
    ('BatteryLevel', {'doubleValue': -0.0}, {'doubleValue': 0.0}),
    ('TpmsHardWarnings', {'tireLocationValue': {'frontLeft': False, 'rearRight': True}},
     {'tire_location_value': {'front_left': False, 'rear_right': True}}),
]


@pytest.mark.parametrize('field,first,second', EQUIVALENTS)
def test_equal_observations_keep_quality_and_provenance_without_rewriting_samples(store, settings, vehicle_ref, clock, field, first, second):
    telemetry = Telemetry(store)
    timestamp = clock()
    telemetry.ingest('V', frame(clock, field, first))
    original = view(store, vehicle_ref, field)['current_observation']
    clock.advance(1)
    telemetry.ingest('V', frame(clock, field, second, when=timestamp))
    restarted = Store(settings, clock=clock)
    result = view(restarted, vehicle_ref, field)
    assert result['current_observation']['quality'] == 'valid'
    assert result['current_observation'] == original | {'age_seconds': pytest.approx(1)}
    assert result['last_valid_observation'] is not None
    with restarted.db() as db:
        rows = db.execute('SELECT * FROM samples WHERE field=? ORDER BY received,id', (field,)).fetchall()
        assert len(rows) == 2
        assert rows[0]['value'] != rows[1]['value']  # Original decoded spelling retained.
        evidence = history_provenance(db, [row['id'] for row in rows])
    history = [enrich_history(row, clock(), evidence[row['id']]) for row in rows]
    assert all(row['quality'] == row['status'] == 'valid' and not row['timestamp_conflict'] for row in history)
    assert all(row['provenance']['status'] == 'recorded' for row in history)


@pytest.mark.parametrize('field,first,second', EQUIVALENTS)
def test_equal_later_observation_emits_neither_field_rule_nor_change_batch(store, vehicle_ref, clock, field, first, second):
    telemetry = Telemetry(store)
    with store.db() as db:
        db.execute('DELETE FROM rules')
        db.execute('UPDATE trigger_preferences SET enabled=0')
        db.execute('INSERT OR REPLACE INTO trigger_preferences VALUES(?,?,1)', (vehicle_ref, 'field:'+field))
    telemetry.configure_rule(vehicle_ref, 'field_changed', {'field': field})
    telemetry.ingest('V', frame(clock, field, first))
    # The initial observation is a legitimate initial batch, not a transition.
    with store.db() as db:
        db.execute('DELETE FROM trigger_buffer')
    clock.advance(1)
    telemetry.ingest('V', frame(clock, field, second))
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM trigger_buffer').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 0
    assert view(store, vehicle_ref, field)['current_observation']['source_timestamp'] == pytest.approx(clock())


@pytest.mark.parametrize('second', [{'doubleValue': 51.0}, {'invalid': True}, {'booleanValue': True}])
def test_real_value_or_quality_conflicts_remain_fail_closed(store, vehicle_ref, clock, second):
    telemetry = Telemetry(store)
    telemetry.ingest('V', frame(clock, 'BatteryLevel', {'doubleValue': 40.0}))
    clock.advance(1)
    telemetry.ingest('V', frame(clock, 'BatteryLevel', {'doubleValue': 50.0}))
    telemetry.ingest('V', frame(clock, 'BatteryLevel', second))
    result = view(store, vehicle_ref, 'BatteryLevel')
    assert result['current_observation']['quality'] == 'time_conflict'
    assert result['current_observation']['value'] is None
    assert result['last_valid_observation']['value'] == 40.0
    # A subsequent equivalent copy cannot repair a real equal-time conflict.
    telemetry.ingest('V', frame(clock, 'BatteryLevel', {'intValue': 50}))
    assert view(store, vehicle_ref, 'BatteryLevel')['current_observation']['quality'] == 'time_conflict'


def test_legacy_equivalent_rows_are_not_rewritten_or_excluded_from_last_valid(store, vehicle_ref, clock):
    with store.db() as db:
        for identifier, value in [('legacy-a', '50'), ('legacy-b', '50.0')]:
            db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                       (identifier, vehicle_ref, 'BatteryLevel', value, clock(), clock(), 'valid', 'payload_created_at'))
    result = view(store, vehicle_ref, 'BatteryLevel')
    assert result['last_valid_observation'] is not None
    assert result['last_valid_observation']['provenance']['status'] == 'unavailable'
    with store.db() as db:
        rows = db.execute('SELECT id,value FROM samples ORDER BY id').fetchall()
        assert [(r['id'], r['value']) for r in rows] == [('legacy-a', '50'), ('legacy-b', '50.0')]
        evidence = history_provenance(db, ['legacy-a', 'legacy-b'])
    assert not any(row['timestamp_conflict'] for row in evidence.values())


def test_cache_preferred_missing_section_does_not_regress_another_fresh_block(service, vehicle_ref, clock):
    service.store.snapshot(vehicle_ref, 'charge_state', {'battery_level': 80, 'timestamp': int(clock()*1000)},
                           'tesla_live', clock())
    before = service.state(vehicle_ref, ['charge_state'], 'cached_only', SCOPES)['data']['charge_state']
    clock.advance(1)
    result = service.state(vehicle_ref, ['charge_state', 'climate_state'], 'cache_preferred', SCOPES)
    assert result['data']['charge_state']['data']['battery_level'] == 80
    assert result['data']['charge_state']['source'] == 'tesla_live'
    assert result['data']['charge_state']['source_timestamp'] == before['source_timestamp']
    assert result['data']['charge_state']['received_at'] == before['received_at']
    assert result['data']['climate_state']['quality'] == 'missing'
    assert [call[0] for call in service.fleet.calls] == ['vehicle_vehicle_data_cached']


def test_rest_snapshot_order_and_unknown_timestamps(store, vehicle_ref, clock):
    timestamp = int(clock()*1000)/1000
    initial = {'battery_level': 80, 'timestamp': timestamp*1000}
    store.snapshot(vehicle_ref, 'charge_state', initial, 'tesla_live', timestamp)
    with store.db() as db:
        original = dict(db.execute("SELECT * FROM snapshots WHERE section='charge_state'").fetchone())
    for value, when in [({'battery_level': 50}, None),
                        ({'battery_level': 50, 'timestamp': 'bad'}, timestamp+1),
                        ({'battery_level': 50, 'timestamp': (timestamp-10)*1000}, timestamp-10),
                        ({'battery_level': 80.0, 'timestamp': timestamp}, timestamp)]:
        clock.advance(1)
        store.snapshot(vehicle_ref, 'charge_state', value, 'tesla_cached', when)
        with store.db() as db:
            assert dict(db.execute("SELECT * FROM snapshots WHERE section='charge_state'").fetchone()) == original
    store.snapshot(vehicle_ref, 'climate_state', {'is_climate_on': True}, 'tesla_cached')
    clock.advance(1)
    store.snapshot(vehicle_ref, 'climate_state', {'is_climate_on': False}, 'tesla_cached')
    with store.db() as db:
        row = db.execute("SELECT * FROM snapshots WHERE section='climate_state'").fetchone()
        assert row['source_at'] is None and row['data'] == '{"is_climate_on":false}'
    store.snapshot(vehicle_ref, 'charge_state', {'battery_level': 81, 'timestamp': clock()*1000}, 'tesla_live', clock())
    with store.db() as db:
        assert db.execute("SELECT json_extract(data,'$.battery_level') FROM snapshots WHERE section='charge_state'").fetchone()[0] == 81


def test_rest_equal_time_contradiction_is_explicit_persistent_and_not_park(service, vehicle_ref, clock):
    timestamp = int(clock()*1000)/1000
    park = {'shift_state': 'P', 'timestamp': timestamp*1000}
    drive = {'shift_state': 'D', 'timestamp': timestamp*1000}
    service.store.snapshot(vehicle_ref, 'drive_state', park, 'tesla_live', timestamp)
    clock.advance(1)
    service.store.snapshot(vehicle_ref, 'drive_state', drive, 'tesla_cached', timestamp)
    # Fresh telemetry P does not resolve a same-time REST contradiction.
    Telemetry(service.store).ingest('V', frame(clock, 'Gear', {'stringValue': 'P'}))
    for data, when in [(park, timestamp), ({'shift_state': 'P'}, None),
                       ({'shift_state': 'P', 'timestamp': (timestamp-1)*1000}, timestamp-1)]:
        service.store.snapshot(vehicle_ref, 'drive_state', data, 'tesla_live', when)
        result = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)
        assert result['data']['drive_state']['quality'] == 'time_conflict'
        assert result['data']['drive_state']['data'] is None
        assert result['park_evidence']['status'] == 'conflicting'
    with service.store.db() as db:
        row = db.execute("SELECT data FROM snapshots WHERE section='rest_conflict:drive_state'").fetchone()
        assert row is not None and 'tesla_live' in row['data'] and 'tesla_cached' in row['data']
    clock.advance(1)
    service.store.snapshot(vehicle_ref, 'drive_state', {'shift_state': 'P', 'timestamp': clock()*1000}, 'tesla_live', clock())
    result = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)
    assert result['data']['drive_state']['quality'] == 'fresh_observed'
    assert result['park_evidence']['status'] == 'verified'
    with service.store.db() as db:
        assert not db.execute("SELECT 1 FROM snapshots WHERE section='rest_conflict:drive_state'").fetchone()


def test_domain_equality_is_exact_and_typed():
    from tesla_plugin.value_semantics import equal, json_equal
    assert equal('BatteryLevel', 50, 50.0)
    assert not equal('BatteryLevel', True, 1)
    assert not equal('BatteryLevel', 50, '50')
    assert not equal('BatteryLevel', 2**53+1, float(2**53))
    assert not equal('BatteryLevel', 50.0, 50.0000000001)
    assert not equal('BatteryLevel', float('nan'), float('nan'))
    assert not json_equal('BatteryLevel', 'broken', 'broken')
    assert not equal('TpmsHardWarnings', {'frontLeft': False}, {'front_left': False, 'rear_left': False})
    assert not equal('DoorState', {'frontLeft': False}, {'front_left': False})


def test_future_rest_timestamp_does_not_poison_cache_order(service, vehicle_ref, clock):
    far_future = clock()+365*86400
    service.store.snapshot(vehicle_ref, 'drive_state', {'shift_state': 'P', 'timestamp': far_future*1000},
                           'tesla_cached', far_future)
    result = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)
    assert result['data']['drive_state']['quality'] == 'future'
    assert result['park_evidence']['status'] != 'verified'
    clock.advance(1)
    service.store.snapshot(vehicle_ref, 'drive_state', {'shift_state': 'D', 'timestamp': clock()*1000},
                           'tesla_live', clock())
    result = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)
    assert result['data']['drive_state']['quality'] == 'fresh_observed'
    assert result['data']['drive_state']['data']['shift_state'] == 'D'
    assert result['park_evidence']['status'] == 'not_park'


def test_conflicting_rest_block_does_not_qualify_a_command_effect(store, vehicle_ref, clock):
    from tesla_plugin.diagnostics import operation_evidence
    timestamp = int(clock()*1000)/1000
    intent = {'id': 'synthetic-acknowledged-action', 'vehicle': vehicle_ref,
              'operation': 'set_charge_limit', 'arguments': {'percent': 80},
              'status': 'acknowledged', 'result': {'completed_at': timestamp-1},
              'generation': store.connection()['generation']}
    store.snapshot(vehicle_ref, 'charge_state', {'charge_limit_soc': 80, 'timestamp': timestamp*1000},
                   'tesla_live', timestamp)
    store.snapshot(vehicle_ref, 'charge_state', {'charge_limit_soc': 90, 'timestamp': timestamp*1000},
                   'tesla_cached', timestamp)
    result = operation_evidence(store, intent)
    assert not result['effect_observed']
    assert result['reason'] == 'observation_timestamp_conflict'


def test_snapshot_conflict_survives_restart_without_changing_guard_thresholds(service, vehicle_ref, clock):
    from tesla_plugin.gear_evidence import view as gear_view
    timestamp = clock()
    for gear in ('P', 'D'):
        service.store.snapshot(vehicle_ref, 'drive_state', {'shift_state': gear, 'timestamp': timestamp*1000},
                               'tesla_live', timestamp)
    reopened = Store(service.settings, clock=clock)
    result = gear_view(reopened, vehicle_ref)
    assert result['status'] == 'conflicting'
    assert [item['max_age_seconds'] for item in result['observations']] == [30, 15]
    clock.advance(31)
    assert gear_view(reopened, vehicle_ref)['status'] != 'verified'


@pytest.mark.parametrize('stored_gear,stored_age,raw_gear,raw_age,conflict', [
    ('D', 0, 'P', 0, True),
    ('D', 5, 'P', 15, False),
    ('R', 5, 'P', 15, False),
    ('N', 5, 'P', 15, False),
    ('P', 5, None, 15, False),
])
def test_command_preflight_keeps_stored_conflicts_and_newer_negative_evidence(service, vehicle_ref, clock, fleet,
                                                                          stored_gear, stored_age, raw_gear, raw_age, conflict):
    at = int((clock()-stored_age)*1000)
    service.store.snapshot(vehicle_ref, 'drive_state', {'shift_state': stored_gear, 'timestamp': at}, 'tesla_live', at/1000)
    if conflict:
        service.store.snapshot(vehicle_ref, 'drive_state', {'shift_state': 'P', 'timestamp': at}, 'tesla_cached', at/1000)
    original = fleet.call
    def response(name, *args, **kwargs):
        result = original(name, *args, **kwargs)
        if name == 'vehicle_vehicle_data':
            result['drive_state'] = {'shift_state': raw_gear, 'timestamp': int((clock()-raw_age)*1000)}
        return result
    fleet.call = response
    intent = service.prepare('window_control', {'command': 'vent'}, vehicle_ref, 'audit-rest-fence-request', SCOPES)
    with pytest.raises(TeslaError, match='.') as refused:
        service.execute_from_owner(intent['id'])
    assert refused.value.code == 'PRECONDITION_FAILED'
    assert not any(name == 'window_control' for name, *_ in fleet.calls)
    if conflict:
        # A genuinely newer response resolves the stored contradiction; no blind
        # command retry is performed by the implementation.
        clock.advance(1)
        fleet.park = 'P'
        fleet.call = original
        assert service.execute_from_owner(intent['id'])['status'] == 'acknowledged'


def test_equal_time_conflict_disqualifies_recorded_effect_but_retains_history(service, vehicle_ref, clock):
    from tesla_plugin.diagnostics import record_operation_observations
    item = service.prepare('set_charge_limit', {'percent': 80}, vehicle_ref, 'audit-recorded-effect-01', SCOPES)
    service.execute_from_owner(item['id'])
    clock.advance(1)
    timestamp = int(clock()*1000)/1000
    service.store.snapshot(vehicle_ref, 'charge_state', {'charge_limit_soc': 80, 'timestamp': timestamp*1000},
                           'tesla_live', timestamp)
    record_operation_observations(service.store, vehicle_ref, 'charge_state')
    assert service.intent_view(item['id'])['verification']['effect_observed']
    service.store.snapshot(vehicle_ref, 'charge_state', {'charge_limit_soc': 90, 'timestamp': timestamp*1000},
                           'tesla_cached', timestamp)
    result = service.intent_view(item['id'])['verification']
    assert not result['effect_observed'] and result['reason'] == 'observation_timestamp_conflict'
    with service.store.db() as db:
        saved = db.execute('SELECT data FROM snapshots WHERE section=?', ('operation_verified_'+item['id'],)).fetchone()[0]
        import json
        historical = json.loads(saved)
        assert historical['effect_observed'] is True
        assert historical['invalidation']['reason'] == 'same_source_time_conflict'
    # Clearing the current conflict must not resurrect the disproven historical
    # qualification after a restart or a later different state.
    clock.advance(1)
    service.store.snapshot(vehicle_ref, 'charge_state', {'charge_limit_soc': 90, 'timestamp': clock()*1000}, 'tesla_live', clock())
    service.store = Store(service.settings, clock=clock)
    assert not service.intent_view(item['id'])['verification']['effect_observed']
    clock.advance(1)
    service.store.snapshot(vehicle_ref, 'charge_state', {'charge_limit_soc': 80, 'timestamp': clock()*1000}, 'tesla_live', clock())
    record_operation_observations(service.store, vehicle_ref, 'charge_state')
    renewed = service.intent_view(item['id'])['verification']
    assert renewed['effect_observed'] and renewed['observation']['source_timestamp'] > timestamp
    assert 'invalidation' not in renewed


def test_normal_later_rest_change_does_not_disqualify_recorded_effect(service, vehicle_ref, clock):
    from tesla_plugin.diagnostics import record_operation_observations
    item = service.prepare('set_charge_limit', {'percent': 80}, vehicle_ref, 'audit-recorded-effect-02', SCOPES)
    service.execute_from_owner(item['id'])
    clock.advance(1)
    service.store.snapshot(vehicle_ref, 'charge_state', {'charge_limit_soc': 80, 'timestamp': clock()*1000}, 'tesla_live', clock())
    record_operation_observations(service.store, vehicle_ref, 'charge_state')
    original = service.intent_view(item['id'])['verification']
    clock.advance(1)
    service.store.snapshot(vehicle_ref, 'charge_state', {'charge_limit_soc': 90, 'timestamp': clock()*1000}, 'tesla_live', clock())
    result = service.intent_view(item['id'])['verification']
    assert result['effect_observed']
    assert result['observation']['source_timestamp'] == original['observation']['source_timestamp']


def test_contradiction_between_effect_calculation_and_persistence_cannot_publish_qualification(service, vehicle_ref, clock, monkeypatch):
    from tesla_plugin import diagnostics
    item = service.prepare('set_charge_limit', {'percent': 80}, vehicle_ref, 'audit-recording-race-01', SCOPES)
    service.execute_from_owner(item['id'])
    clock.advance(1)
    at = int(clock()*1000)/1000
    service.store.snapshot(vehicle_ref, 'charge_state', {'charge_limit_soc': 80, 'timestamp': at*1000}, 'tesla_live', at)
    original = diagnostics.operation_evidence
    def interleaved(store, intent, **kwargs):
        result = original(store, intent, **kwargs)
        assert result['effect_observed']
        # Another writer commits after the observation was matched, before the
        # recording transaction. It cannot invalidate a record not yet present.
        other = Store(service.settings, clock=clock)
        other.snapshot(vehicle_ref, 'charge_state', {'charge_limit_soc': 90, 'timestamp': at*1000}, 'tesla_cached', at)
        return result
    monkeypatch.setattr(diagnostics, 'operation_evidence', interleaved)
    diagnostics.record_operation_observations(service.store, vehicle_ref, 'charge_state')
    with service.store.db() as db:
        assert not db.execute('SELECT 1 FROM snapshots WHERE section=?', ('operation_verified_'+item['id'],)).fetchone()
    assert not original(service.store, service.store.intent(item['id']))['effect_observed']
