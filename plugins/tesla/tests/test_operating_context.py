"""Synthetic replay of the reported B1 pattern; no live commands or configuration."""
import pytest
from conftest import VIN
from tesla_plugin.config import SCOPES
from tesla_plugin.telemetry import Telemetry
from tesla_plugin.store import utc


def ingest(service, clock, values):
    Telemetry(service.store).ingest('V', {'vin': VIN, 'createdAt': utc(clock()), 'data': [
        {'key': k, 'value': v} for k, v in values.items()]})


@pytest.mark.parametrize('charge,rail,expected', [
    ('DetailedChargeStateDisconnected', False, 'drive_power_inactive_observed'),
    ('DetailedChargeStateCharging', False, 'charging_connection_observed'),
    ('DetailedChargeStateDisconnected', True, 'accessory_display_observed')])
def test_unavailable_gear_explains_context_without_inferring_park_or_sleep(service, fleet, vehicle_ref, clock, charge, rail, expected):
    ingest(service, clock, {'Gear': {'invalid': True}, 'DriveRail': {'booleanValue': rail},
                           'DetailedChargeState': {'detailedChargeStateValue': charge},
                           'CenterDisplay': {'displayStateValue': 'DisplayStateAccessory'}})
    result = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)
    view = result['operating_context']
    assert view['state'] == expected and result['park_evidence']['status'] != 'verified'
    assert view['park_inferred'] is view['vehicle_sleep_inferred'] is view['command_admission_changed'] is False
    assert fleet.calls == []
    clock.advance(31)
    assert service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)['operating_context']['state'] == 'gear_unavailable'


@pytest.mark.parametrize('gear,status', [('P', 'park_observed'), ('D', 'driving_gear_observed'), ('R', 'driving_gear_observed'), ('N', 'driving_gear_observed')])
def test_gear_observation_is_not_replaced_by_charging_or_drive_rail(service, vehicle_ref, clock, gear, status):
    ingest(service, clock, {'Gear': {'stringValue': gear}, 'DriveRail': {'booleanValue': False},
                           'DetailedChargeState': {'detailedChargeStateValue': 'DetailedChargeStateCharging'}})
    result = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)
    assert result['operating_context']['state'] == status
    assert not result['operating_context']['physical_motion_verified']


def test_16_second_cadence_does_not_extend_park_guard(service, vehicle_ref, clock):
    ingest(service, clock, {'Gear': {'stringValue': 'P'}, 'DriveRail': {'booleanValue': True}})
    clock.advance(15.1)
    result = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)
    assert result['park_evidence']['status'] == 'stale'
    assert result['operating_context']['state'] == 'gear_stale'
    clock.advance(.9)
    ingest(service, clock, {'Gear': {'invalid': True}})
    assert service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)['park_evidence']['status'] == 'unknown'


@pytest.mark.parametrize('charge', ['Complete', 'Stopped', 'NoPower', 'Starting'])
def test_charge_outcome_alone_does_not_establish_current_cable_connection(service, vehicle_ref, clock, charge):
    ingest(service, clock, {'Gear': {'invalid': True},
        'DetailedChargeState': {'detailedChargeStateValue': 'DetailedChargeState'+charge}})
    result = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)
    view = result['operating_context']
    assert not view['charging_connection_observed']
    assert view['charging_connection']['status'] == 'unknown'
    assert view['observations']['DetailedChargeState']['value'] == 'DetailedChargeState'+charge
    assert result['park_evidence']['status'] == 'unknown'


def test_newer_disconnected_supersedes_older_cable_without_rewriting_observations(service, vehicle_ref, clock):
    ingest(service, clock, {'Gear': {'invalid': True}, 'ChargingCableType': {'cableTypeValue': 'CableTypeIEC'}})
    assert service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)['operating_context']['charging_connection_observed']
    clock.advance(1)
    ingest(service, clock, {'DetailedChargeState': {'detailedChargeStateValue': 'DetailedChargeStateDisconnected'}})
    view = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)['operating_context']
    assert not view['charging_connection_observed'] and view['charging_connection']['status'] == 'disconnected'
    assert view['observations']['ChargingCableType']['value'] == 'CableTypeIEC'


def test_equal_time_disconnected_and_cable_are_conflicting_not_connected(service, vehicle_ref, clock):
    ingest(service, clock, {'Gear': {'invalid': True}, 'ChargingCableType': {'cableTypeValue': 'CableTypeIEC'},
        'DetailedChargeState': {'detailedChargeStateValue': 'DetailedChargeStateDisconnected'}})
    view = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)['operating_context']
    assert not view['charging_connection_observed']
    assert view['charging_connection']['status'] == 'conflicting'
    assert view['state'] == 'charging_connection_conflicting'


def test_conflicting_gear_remains_primary_even_with_drive_power_or_charge_context(service, vehicle_ref, clock):
    ingest(service, clock, {'Gear': {'stringValue': 'D'}, 'DriveRail': {'booleanValue': False},
        'DetailedChargeState': {'detailedChargeStateValue': 'DetailedChargeStateCharging'}})
    service.store.snapshot(vehicle_ref, 'drive_state', {'shift_state': 'P', 'timestamp': clock()*1000}, 'tesla_live', clock())
    result = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)
    assert result['park_evidence']['status'] == 'conflicting'
    assert result['operating_context']['state'] == 'conflicting_evidence'
    assert not result['operating_context']['command_admission_changed']


def test_invalid_or_future_context_is_not_a_current_observation(service, vehicle_ref, clock):
    ingest(service, clock, {'Gear': {'invalid': True}, 'DriveRail': {'invalid': True},
        'ChargingCableType': {'invalid': True}, 'DetailedChargeState': {'invalid': True}})
    view = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)['operating_context']
    assert view['state'] == 'gear_unavailable' and view['drive_power'] == 'unknown'
    # Permitted transport skew must not become positive diagnostic evidence.
    Telemetry(service.store).ingest('V', {'vin': VIN, 'createdAt': utc(clock()+10), 'data': [
        {'key': 'ChargingCableType', 'value': {'cableTypeValue': 'CableTypeIEC'}}]})
    view = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)['operating_context']
    assert not view['charging_connection_observed']
    assert not view['observations']['ChargingCableType']['recent_for_diagnosis']


def test_route_metadata_has_same_limit_in_parent_and_projection():
    from tesla_plugin.state_evidence import field_notes
    for section in ('drive_state', 'navigation_data'):
        notes = field_notes(section)
        assert not notes['complete_itinerary']
        assert 'next stop' in notes['route_target_semantics']
        assert 'independent freshness' in notes['route_residuals']


def test_synthetic_b1_sequence_does_not_make_seat_or_brake_a_gear_inference(service, vehicle_ref, clock):
    # Synthetic scenario based on the reported order, not a raw protobuf replay.
    ingest(service, clock, {'Gear': {'invalid': True}, 'DriveRail': {'booleanValue': False},
        'CenterDisplay': {'displayStateValue': 'DisplayStateAccessory'},
        'DriverSeatOccupied': {'booleanValue': False}, 'BrakePedal': {'booleanValue': False}})
    clock.advance(16)
    ingest(service, clock, {'Gear': {'invalid': True}, 'DriverSeatOccupied': {'booleanValue': True}})
    view = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)
    assert view['operating_context']['state'] == 'drive_power_inactive_observed'
    assert view['park_evidence']['status'] == 'unknown'
    clock.advance(1)
    ingest(service, clock, {'Gear': {'stringValue': 'P'}, 'DriveRail': {'booleanValue': True},
        'CenterDisplay': {'displayStateValue': 'DisplayStateOn'}})
    view = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)
    at = view['operating_context']['observations']['Gear']['source_at']
    assert view['park_evidence']['status'] == 'verified'
    assert view['operating_context']['observations']['BrakePedal']['value'] is False
    for brake in (True, False):
        clock.advance(1)
        ingest(service, clock, {'BrakePedal': {'booleanValue': brake}})
        view = service.state(vehicle_ref, ['drive_state'], 'cached_only', SCOPES)
        assert view['park_evidence']['status'] == 'verified'
        assert view['operating_context']['state'] == 'park_observed'
        assert view['operating_context']['observations']['Gear']['source_at'] == at
        assert not view['operating_context']['causality_proven']
