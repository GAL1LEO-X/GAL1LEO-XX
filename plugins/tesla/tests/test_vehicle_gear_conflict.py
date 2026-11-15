"""Gear conflict regressions through real ingestion and fake command dispatch."""
from dataclasses import replace
import socket

import pytest

from conftest import Clock, VIN
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.store import utc
from tesla_plugin.telemetry import Telemetry


@pytest.fixture
def clock():
    value = Clock()
    value.value = 1800000000.0
    return value


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('No socket is allowed in this synthetic command test')
    monkeypatch.setattr(socket, 'socket', forbidden)


def ingest(store, when, envelope):
    Telemetry(store).ingest('V', {'vin': VIN, 'createdAt': utc(when),
                                'data': [{'key': 'Gear', 'value': envelope}]})


def conflicting_gear(store, when, order=('P', 'D')):
    for gear in order:
        ingest(store, when, {'shiftStateValue': 'ShiftState'+gear})
    with store.db() as db:
        assert db.execute("SELECT quality FROM latest WHERE field='Gear'").fetchone()[0] == 'time_conflict'


def rest_response(fleet, clock, monkeypatch, gear, age=0, *, timestamp=...):
    original = fleet.call
    def response(name, *args, **kwargs):
        result = original(name, *args, **kwargs)
        if name == 'vehicle_vehicle_data':
            result['drive_state'] = {'shift_state': gear,
                                    'timestamp': (clock()-age)*1000 if timestamp is ... else timestamp}
        return result
    monkeypatch.setattr(fleet, 'call', response)


ARGUMENTS = {'window_control': {'command': 'vent'},
             'actuate_trunk': {'which_trunk': 'front'}, 'remote_start_drive': {}}


def prepare(service, ref, operation):
    service.settings = replace(service.settings, live_enabled=True)
    return service.prepare(operation, ARGUMENTS[operation], ref, 'vehicle-gear-conflict-request', SCOPES)


def execute(service, intent, entry='panel'):
    if entry == 'chat':
        return service.execute_action_from_chat(intent['id'], intent['action_digest'], 'execute', SCOPES)
    return service.execute_from_owner(intent['id'])


def admission(service, intent, *, allowed, entry='panel'):
    if allowed:
        result = execute(service, intent, entry)
        assert result['status'] == 'acknowledged'
        assert result['result']['physical_effect_verified'] is False
        return result['result']['admission']
    with pytest.raises(TeslaError) as refused:
        execute(service, intent, entry)
    assert refused.value.code == 'PRECONDITION_FAILED'
    assert refused.value.details['command_sent'] is False
    assert refused.value.details['dispatch_attempted'] is False
    return refused.value.details['precondition']


@pytest.mark.parametrize('entry', ['chat', 'panel'])
@pytest.mark.parametrize('operation', list(ARGUMENTS))
@pytest.mark.parametrize('rest', ['P', None])
@pytest.mark.parametrize('order', [('P', 'D'), ('D', 'P')])
def test_same_time_gear_conflict_blocks_real_execution_path(
        service, fleet, vehicle_ref, clock, monkeypatch, entry, operation, rest, order):
    conflicting_gear(service.store, clock(), order)
    rest_response(fleet, clock, monkeypatch, rest)
    intent = prepare(service, vehicle_ref, operation)
    result = admission(service, intent, allowed=False, entry=entry)
    assert result['status'] == 'conflicting' and result['reason'] == 'PARK_EVIDENCE_CONFLICT'
    assert result['allows_dispatch'] is False
    gear = result['observations'][1]
    assert gear['quality'] == 'time_conflict' and gear['fresh'] and not gear['usable']
    assert [name for name, *_ in fleet.calls] == ['vehicle_fleet_status', 'vehicle_vehicle_data']
    assert service.store.intent(intent['id'])['status'] == 'prepared'


@pytest.mark.parametrize('operation', ['window_control', 'remote_start_drive'])
@pytest.mark.parametrize('gear_age,rest,rest_age,state,park_allowed', [
    (15, 'P', 30, 'conflicting', False),
    (15, None, 0, 'conflicting', False),
    (15.001, 'P', 30, 'verified', True),
    (15.001, 'P', 30.001, 'stale', False),
    (15.001, None, 0, 'unknown', False),
    (0, 'P', 30.001, 'conflicting', False),
])
def test_conflict_preserves_existing_gear_and_rest_freshness_boundaries(
        service, fleet, vehicle_ref, clock, monkeypatch, operation,
        gear_age, rest, rest_age, state, park_allowed):
    conflicting_gear(service.store, clock()-gear_age)
    rest_response(fleet, clock, monkeypatch, rest, rest_age)
    intent = prepare(service, vehicle_ref, operation)
    allowed = park_allowed or operation == 'remote_start_drive' and state in ('stale', 'unknown')
    result = admission(service, intent, allowed=allowed)
    assert result['status'] == state and result['allows_dispatch'] is allowed
    rest_observed, gear_observed = result['observations'][:2]
    assert rest_observed['max_age_seconds'] == 30 and gear_observed['max_age_seconds'] == 15
    assert rest_observed['fresh'] is (rest_age <= 30)
    assert gear_observed['quality'] == 'time_conflict'
    assert gear_observed['fresh'] is (gear_age <= 15)
    assert not gear_observed['usable']
    assert [name for name, *_ in fleet.calls] == [
        'vehicle_fleet_status', 'vehicle_vehicle_data', *([operation] if allowed else [])]


@pytest.mark.parametrize('operation', ['window_control', 'remote_start_drive'])
@pytest.mark.parametrize('order', [('P', 'D'), ('D', 'P')])
@pytest.mark.parametrize('new_gear', ['P', 'D'])
def test_only_newer_gear_resolves_conflict_before_an_explicit_execution(
        service, fleet, vehicle_ref, clock, monkeypatch, operation, order, new_gear):
    conflict_at = clock()
    conflicting_gear(service.store, conflict_at, order)
    # Equivalent wire spelling at the same time and an older P cannot repair it.
    ingest(service.store, conflict_at, {'stringValue': 'P'})
    ingest(service.store, conflict_at-1, {'shiftStateValue': 'ShiftStateP'})
    rest_response(fleet, clock, monkeypatch, None)
    intent = prepare(service, vehicle_ref, operation)
    assert admission(service, intent, allowed=False)['status'] == 'conflicting'
    before = list(fleet.calls)
    clock.advance(1)
    ingest(service.store, clock(), {'shiftStateValue': 'ShiftState'+new_gear})
    assert fleet.calls == before  # Ingestion never retries or dispatches a command.
    result = admission(service, intent, allowed=new_gear == 'P')
    assert result['status'] == ('verified' if new_gear == 'P' else 'not_park')
    assert result['observations'][1]['quality'] == 'valid'
    assert result['observations'][1]['value'] == new_gear
    assert sum(name == operation for name, *_ in fleet.calls) == int(new_gear == 'P')
    assert not any(name == 'vehicle_wake_up' for name, *_ in fleet.calls)


@pytest.mark.parametrize('operation', ['window_control', 'remote_start_drive'])
@pytest.mark.parametrize('rest', ['P', None])
def test_normal_invalid_gear_is_not_park_or_a_time_conflict(
        service, fleet, vehicle_ref, clock, monkeypatch, operation, rest):
    ingest(service.store, clock()-1, {'shiftStateValue': 'ShiftStateP'})
    ingest(service.store, clock(), {'invalid': True})
    rest_response(fleet, clock, monkeypatch, rest)
    intent = prepare(service, vehicle_ref, operation)
    allowed = rest == 'P' or operation == 'remote_start_drive'
    result = admission(service, intent, allowed=allowed)
    assert result['status'] == ('verified' if rest == 'P' else 'unknown')
    gear = result['observations'][1]
    assert gear['quality'] == 'invalid' and gear['value'] is None and not gear['usable']
    assert sum(name == operation for name, *_ in fleet.calls) == int(allowed)
    assert not any(name == 'vehicle_wake_up' for name, *_ in fleet.calls)


def rest_time(at, encoding='typed_int'):
    if encoding == 'seconds':
        return at
    if encoding == 'milliseconds':
        return at*1000
    whole = int(at)
    return {'seconds': str(whole) if encoding == 'typed_string' else whole,
            'nanos': round((at-whole)*1_000_000_000)}


@pytest.mark.parametrize('operation', ['window_control', 'remote_start_drive'])
@pytest.mark.parametrize('gear', ['D', 'R', 'N', 'P'])
@pytest.mark.parametrize('encoding', ['seconds', 'milliseconds', 'typed_int', 'typed_string'])
def test_rest_clock_encodings_have_the_same_admission_policy(
        service, fleet, vehicle_ref, clock, monkeypatch, operation, gear, encoding):
    at = clock()-.25
    rest_response(fleet, clock, monkeypatch, gear, timestamp=rest_time(at, encoding))
    intent = prepare(service, vehicle_ref, operation)
    result = admission(service, intent, allowed=gear == 'P')
    assert result['status'] == ('verified' if gear == 'P' else 'not_park')
    observed = result['observations'][0]
    assert observed['source_timestamp'] == at and observed['age_seconds'] == .25
    assert observed['value'] == gear and observed['quality'] == 'valid' and observed['usable']
    assert [name for name, *_ in fleet.calls] == [
        'vehicle_fleet_status', 'vehicle_vehicle_data', *([operation] if gear == 'P' else [])]


@pytest.mark.parametrize('operation', ['window_control', 'remote_start_drive'])
@pytest.mark.parametrize('raw_gear', ['P', None])
@pytest.mark.parametrize('stored_gears', [('D',), ('R',), ('N',), ('P', 'D'), ('D', 'P')])
def test_typed_stored_negative_or_conflicted_clock_survives_older_preflight(
        service, fleet, vehicle_ref, clock, monkeypatch, operation, raw_gear, stored_gears):
    for gear in stored_gears:
        service.store.snapshot(vehicle_ref, 'drive_state',
                               {'shift_state': gear, 'timestamp': rest_time(clock(), 'typed_string')},
                               'tesla_cached', clock())
    rest_response(fleet, clock, monkeypatch, raw_gear,
                  timestamp=rest_time(clock()-1))
    intent = prepare(service, vehicle_ref, operation)
    result = admission(service, intent, allowed=False)
    conflict = len(stored_gears) > 1
    assert result['status'] == ('conflicting' if conflict or raw_gear == 'P' else 'not_park')
    stored = result['observations'][2]
    assert stored['source_timestamp'] == clock() and stored['fresh']
    assert stored['quality'] == ('time_conflict' if conflict else 'valid')
    assert stored['usable'] is not conflict
    assert [name for name, *_ in fleet.calls] == ['vehicle_fleet_status', 'vehicle_vehicle_data']


@pytest.mark.parametrize('operation', ['window_control', 'remote_start_drive'])
def test_typed_cached_park_does_not_substitute_for_unknown_preflight(
        service, fleet, vehicle_ref, clock, monkeypatch, operation):
    service.store.snapshot(vehicle_ref, 'drive_state',
                           {'shift_state': 'P', 'timestamp': rest_time(clock())}, 'tesla_cached', clock())
    rest_response(fleet, clock, monkeypatch, None, timestamp=rest_time(clock()-1))
    intent = prepare(service, vehicle_ref, operation)
    allowed = operation == 'remote_start_drive'
    result = admission(service, intent, allowed=allowed)
    assert result['status'] == 'unknown'
    stored = result['observations'][2]
    assert stored['value'] == 'P' and stored['fresh'] and not stored['usable']
    assert sum(name == operation for name, *_ in fleet.calls) == int(allowed)


@pytest.mark.parametrize('operation', ['window_control', 'remote_start_drive'])
@pytest.mark.parametrize('gear', ['P', 'D'])
@pytest.mark.parametrize('age,clock_state', [(30, 'fresh'), (30.001, 'stale'),
                                          (-.0005, 'fresh'), (-.002, 'future'), (-31, 'future')])
def test_typed_clock_preserves_rest_age_and_future_boundaries(
        service, fleet, vehicle_ref, clock, monkeypatch, operation, gear, age, clock_state):
    at = clock()-age
    rest_response(fleet, clock, monkeypatch, gear, timestamp=rest_time(at))
    intent = prepare(service, vehicle_ref, operation)
    state = ('verified' if gear == 'P' else 'not_park') if clock_state == 'fresh' else (
        'stale' if clock_state == 'stale' else 'unknown')
    allowed = state == 'verified' or operation == 'remote_start_drive' and state in ('unknown', 'stale')
    result = admission(service, intent, allowed=allowed)
    assert result['status'] == state
    observed = result['observations'][0]
    assert observed['source_timestamp'] == at and observed['max_age_seconds'] == 30
    assert observed['fresh'] is (clock_state == 'fresh')
    assert observed['usable'] is (clock_state == 'fresh')
    if -.001 <= age < 0:
        assert observed['age_seconds'] == 0
    assert sum(name == operation for name, *_ in fleet.calls) == int(allowed)


@pytest.mark.parametrize('operation', ['window_control', 'remote_start_drive'])
@pytest.mark.parametrize('raw_time', [None, True, {}, {'seconds': True},
    {'seconds': 1800000000, 'nanos': True}, {'seconds': 1800000000, 'nanos': -1},
    {'seconds': 1800000000, 'nanos': 1_000_000_000}, {'seconds': '1800000000.0'},
    {'seconds': 1800000000, 'extra': 1}, {'seconds': 253402300800}])
def test_malformed_rest_clocks_remain_unknown_without_receipt_time_fallback(
        service, fleet, vehicle_ref, clock, monkeypatch, operation, raw_time):
    rest_response(fleet, clock, monkeypatch, 'P', timestamp=raw_time)
    intent = prepare(service, vehicle_ref, operation)
    allowed = operation == 'remote_start_drive'
    result = admission(service, intent, allowed=allowed)
    assert result['status'] == 'unknown'
    observed = result['observations'][0]
    assert observed['source_timestamp'] is None and observed['age_seconds'] is None
    assert not observed['fresh'] and not observed['usable']
    if allowed:
        assert result['park_verified'] is False
    assert sum(name == operation for name, *_ in fleet.calls) == int(allowed)


@pytest.mark.parametrize('operation', ['window_control', 'remote_start_drive'])
@pytest.mark.parametrize('gear', ['P', 'D'])
def test_equivalent_typed_and_millisecond_rest_clocks_do_not_create_conflict(
        service, fleet, vehicle_ref, clock, monkeypatch, operation, gear):
    at = clock()-.25
    service.store.snapshot(vehicle_ref, 'drive_state',
                           {'shift_state': gear, 'timestamp': rest_time(at, 'typed_string')},
                           'tesla_cached', at)
    rest_response(fleet, clock, monkeypatch, gear, timestamp=rest_time(at, 'milliseconds'))
    intent = prepare(service, vehicle_ref, operation)
    result = admission(service, intent, allowed=gear == 'P')
    assert result['status'] == ('verified' if gear == 'P' else 'not_park')
    assert all(row['quality'] != 'time_conflict' for row in result['observations'])
    assert [result['observations'][index]['source_timestamp'] for index in (0, 2)] == [at, at]
    assert sum(name == operation for name, *_ in fleet.calls) == int(gear == 'P')
