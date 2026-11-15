"""Legacy diagnostic values never bypass typed signal or location boundaries."""
import json

import pytest
from starlette.testclient import TestClient

from tesla_plugin.operating_context import SIGNALS, explain
from tesla_plugin.server import create_app
from tesla_plugin.store import canonical
from test_spatial_data_permissions import WITHOUT_LOCATION, call


@pytest.mark.parametrize('field', SIGNALS)
@pytest.mark.parametrize('shape', ['object', 'array'])
@pytest.mark.parametrize('quality', ['valid', 'invalid'])
def test_legacy_structures_are_withheld_by_diagnostics_and_mcp_without_location(
        settings, service, store, clock, vehicle_ref, headers, fleet, field, shape, quality):
    spatial = {'latitude': 10.125, 'longitude': 20.875, 'private': 'synthetic-private-content'}
    raw = spatial if shape == 'object' else [spatial, 'synthetic-private-content']
    stored = (vehicle_ref, field, canonical(raw), clock()-1, clock(), quality, 'payload_created_at')
    with store.db() as db:
        db.execute('INSERT OR REPLACE INTO latest VALUES(?,?,?,?,?,?,?)', stored)

    direct = explain(store, vehicle_ref, {'status': 'unknown'})
    observation = direct['observations'][field]
    assert observation['value'] is None and observation['value_withheld'] is True
    assert observation['value_withheld_reason'] == 'incompatible_stored_value'
    assert observation['quality'] == quality
    assert observation['source_at'] == stored[3] and observation['received_at'] == stored[4]
    assert direct['state'] == 'gear_unavailable'
    assert direct['drive_power'] == direct['charging_connection']['status'] == 'unknown'
    assert direct['park_inferred'] is direct['vehicle_sleep_inferred'] is direct['command_admission_changed'] is False

    with TestClient(create_app(settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        arguments = {'vehicle_ref': vehicle_ref, 'sections': ['drive_state'], 'freshness': 'cached_only'}
        denied = call(client, headers(scopes=WITHOUT_LOCATION), 'tesla_get_state', arguments)
        # drive_state already requires location access. This change keeps that
        # boundary and withholds incompatible diagnostic values even with it.
        assert denied['isError'] is True and denied['structuredContent']['code'] == 'SCOPE_REQUIRED'
        response = call(client, headers(), 'tesla_get_state', arguments)
    assert response.get('isError') is not True
    exposed = canonical([denied, response])
    assert '10.125' not in exposed and '20.875' not in exposed and 'synthetic-private-content' not in exposed
    assert 'incompatible_stored_value' in exposed
    assert fleet.calls == []
    with store.db() as db:
        assert tuple(db.execute('SELECT * FROM latest WHERE vehicle=? AND field=?', (vehicle_ref, field)).fetchone()) == stored


@pytest.mark.parametrize('raw,reason', [
    ('{broken-json', 'invalid_stored_json'),
    (canonical('synthetic-private-enum'), 'incompatible_stored_value'),
    ('1', 'incompatible_stored_value'),
    ('null', 'incompatible_stored_value'),
])
def test_unusable_legacy_cable_value_cannot_crash_or_infer_connection(store, vehicle_ref, clock, raw, reason):
    with store.db() as db:
        db.execute('INSERT OR REPLACE INTO latest VALUES(?,?,?,?,?,?,?)',
                   (vehicle_ref, 'ChargingCableType', raw, clock()-1, clock(), 'valid', 'payload_created_at'))
    result = explain(store, vehicle_ref, {'status': 'unknown'})
    assert result['observations']['ChargingCableType']['value'] is None
    assert result['observations']['ChargingCableType']['value_withheld_reason'] == reason
    assert result['charging_connection']['status'] == 'unknown'
    assert 'synthetic-private' not in json.dumps(result)


@pytest.mark.parametrize('field,value,expected_state', [
    ('ChargingCableType', 'CableTypeIEC', 'charging_connection_observed'),
    ('DetailedChargeState', 'DetailedChargeStateCharging', 'charging_connection_observed'),
    ('CenterDisplay', 'DisplayStateAccessory', 'accessory_display_observed'),
    ('DriveRail', False, 'drive_power_inactive_observed'),
    ('DriveRail', True, 'gear_unavailable'),
    ('BrakePedal', False, 'gear_unavailable'),
    ('DriverSeatOccupied', True, 'gear_unavailable'),
    ('Locked', False, 'gear_unavailable'),
    ('Gear', 'ShiftStateP', 'gear_unavailable'),
])
def test_documented_scalar_values_remain_observations_without_new_gear_inferences(
        store, vehicle_ref, clock, field, value, expected_state):
    with store.db() as db:
        db.execute('INSERT OR REPLACE INTO latest VALUES(?,?,?,?,?,?,?)',
                   (vehicle_ref, field, canonical(value), clock()-1, clock(), 'valid', 'payload_created_at'))
    result = explain(store, vehicle_ref, {'status': 'unknown'})
    assert result['state'] == expected_state
    assert result['observations'][field]['value'] == value
    assert result['observations'][field]['value_withheld'] is False
    assert result['observations'][field]['value_withheld_reason'] is None
    assert result['park_inferred'] is result['vehicle_sleep_inferred'] is result['command_admission_changed'] is False
