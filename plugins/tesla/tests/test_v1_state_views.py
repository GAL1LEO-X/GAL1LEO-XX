import json

import pytest
from starlette.testclient import TestClient

from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.server import create_app, input_schema
from tesla_plugin.telemetry import Telemetry, source_time
from test_mcp_portal import rpc
from test_route_evidence import route_value
from test_telemetry_events import payload


def state(service, ref, scopes=SCOPES, **kwargs):
    return service.state(ref, ['charge_state'], 'cached_only', scopes, **kwargs)


def test_current_invalid_and_last_valid_remain_distinct_in_state_and_history(service, vehicle_ref, clock):
    telemetry = Telemetry(service.store)
    first = payload(clock, {'BatteryLevel': 55})
    telemetry.ingest('V', first)
    first_at = source_time(first['createdAt'])
    clock.advance(2)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': None}))
    evidence = state(service, vehicle_ref, telemetry_fields=['BatteryLevel'])['telemetry']['BatteryLevel']
    assert evidence['current_observation']['value'] is None
    assert evidence['current_observation']['quality'] == 'invalid'
    assert evidence['current_observation']['provenance']['status'] == 'recorded'
    assert evidence['last_valid_observation']['value'] == 55
    assert evidence['last_valid_observation']['source_timestamp'] == first_at
    assert not evidence['historical_observation_used_as_current']
    history = service.history(vehicle_ref, ['BatteryLevel'], first_at-1, clock()+1, SCOPES)
    assert [s['quality'] for s in history['samples']] == ['valid', 'invalid']
    assert all(s['provenance']['decoder_version'] for s in history['samples'])
    no_history = state(service, vehicle_ref, [s for s in SCOPES if s != 'tesla:history'],
                       telemetry_fields=['BatteryLevel'])['telemetry']['BatteryLevel']
    assert no_history['last_valid_observation'] is None
    assert no_history['history_access'] == 'scope_required'


def test_state_geographic_selection_requires_permission_even_without_rest_location_section(service, vehicle_ref):
    scopes = [s for s in SCOPES if s != 'tesla:location']
    for options in ({'include_route_geometry': True}, {'telemetry_fields': ['RouteLine']},
                    {'telemetry_fields': ['Location']}):
        with pytest.raises(TeslaError):
            state(service, vehicle_ref, scopes, **options)
    assert service.fleet.calls == []


def test_state_hidden_spatial_content_in_old_non_geographic_sample_is_protected(service, vehicle_ref, clock):
    with service.store.db() as db:
        db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                   ('legacy-private', vehicle_ref, 'BatteryLevel',
                    json.dumps({'latitude': 1, 'longitude': 2}), clock()-2, clock()-2, 'valid', 'synthetic'))
        db.execute('INSERT INTO latest VALUES(?,?,?,?,?,?,?)',
                   (vehicle_ref, 'BatteryLevel', 'null', clock(), clock(), 'invalid', 'synthetic'))
    with pytest.raises(TeslaError):
        state(service, vehicle_ref, [s for s in SCOPES if s != 'tesla:location'],
              telemetry_fields=['BatteryLevel'])


def test_state_geometry_is_opt_in_same_projection_as_panel_and_mcp(service, vehicle_ref, clock, headers):
    from tesla_plugin.route_evidence import view
    Telemetry(service.store).ingest('V', payload(clock, {'RouteLine': route_value()}))
    assert 'route_geometry' not in state(service, vehicle_ref)
    expected = view(service.store, vehicle_ref, location_allowed=True)
    assert expected['status'] == 'available'
    direct = state(service, vehicle_ref, include_route_geometry=True)
    assert direct['route_geometry'] == expected
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        response = rpc(client, headers(), 'tools/call', {'name': 'tesla_get_state', 'arguments': {
            'vehicle_ref': vehicle_ref, 'sections': ['charge_state'], 'freshness': 'cached_only',
            'include_route_geometry': True, 'telemetry_fields': ['RouteLine']}}).json()['result']
    assert response['isError'] is False
    assert response['structuredContent']['route_geometry'] == expected
    assert service.fleet.calls == []


def test_state_and_panel_agree_when_geometry_expires(service, vehicle_ref, clock):
    from tesla_plugin.route_evidence import view
    Telemetry(service.store).ingest('V', payload(clock, {'RouteLine': route_value()}))
    clock.advance(180)
    panel = view(service.store, vehicle_ref, location_allowed=True)
    chat = state(service, vehicle_ref, include_route_geometry=True)['route_geometry']
    assert panel == chat
    assert chat['status'] == 'unavailable'
    assert chat['observation']['status'] == 'stale'


@pytest.mark.parametrize('fields', [[], ['Gear', 'Gear'], ['NoSuchField'], [123], 'Gear'])
def test_invalid_state_field_selection_is_rejected_before_provider_access(service, vehicle_ref, fields):
    with pytest.raises(TeslaError) as caught:
        state(service, vehicle_ref, telemetry_fields=fields)
    assert caught.value.code == 'INVALID_ARGUMENT'
    assert service.fleet.calls == []


def test_state_schema_keeps_projection_optional():
    schema = input_schema('tesla_get_state')
    assert schema['properties']['include_route_geometry']['default'] is False
    assert 'telemetry_fields' in schema['properties']
    assert 'include_route_geometry' not in schema.get('required', [])
