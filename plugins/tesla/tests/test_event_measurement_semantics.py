"""Event presentation shares history warnings without rewriting recorded evidence."""
import json

from starlette.testclient import TestClient

from tesla_plugin.config import SCOPES
from tesla_plugin.events import Events
from tesla_plugin.server import create_app
from tesla_plugin.store import canonical
from test_mcp_portal import rpc


def batch(store, ref, clock, values, kind='telemetry_changed'):
    observations = {field: {'value': value, 'quality': 'valid', 'source_at': clock(), 'received_at': clock()}
                    for field, value in values.items()}
    data = {'changes': {field: {'before': observation.copy(), 'after': observation.copy()}
                        for field, observation in observations.items()}}
    with store.db() as db:
        event_id = Events.emit(db, ref, kind, clock(), data, clock())
        for field, value in values.items():
            db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                       (field, ref, field, canonical(value), clock(), clock(), 'valid', 'synthetic'))
        original = db.execute('SELECT data FROM events WHERE id=?', (event_id,)).fetchone()[0]
    return event_id, original


def test_event_and_history_warnings_agree_without_mutating_evidence(service, vehicle_ref, clock, headers, fleet):
    values = {'TpmsLastSeenPressureTimeFl': int(clock()+7200), 'ChargeRateMilePerHour': -1}
    event_id, original = batch(service.store, vehicle_ref, clock, values)
    history = service.history(vehicle_ref, list(values), clock()-1, clock()+1, SCOPES)
    history = {sample['field']: sample for sample in history['samples']}
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        response = rpc(client, headers(), 'tools/call', {'name': 'tesla_get_event', 'arguments': {'event_id': event_id}}).json()['result']
    assert not response['isError']
    changes = response['structuredContent']['data']['changes']
    for field, change in changes.items():
        for position in ('before', 'after'):
            observation = change[position]
            assert observation['semantics'] == history[field]['semantics']
            assert observation['value'] == values[field]
            assert observation['quality'] == 'valid' and observation['source_at'] == clock()
    with service.store.db() as db:
        assert db.execute('SELECT data FROM events WHERE id=?', (event_id,)).fetchone()[0] == original
    assert fleet.calls == []


def test_route_warning_remains_permission_gated_and_large_values_stay_bounded(service, vehicle_ref, clock, headers):
    event_id, _ = batch(service.store, vehicle_ref, clock, {'DestinationName': 'Synthetic place '+('x'*3000)}, 'location_changed')
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        args = {'name': 'tesla_get_event', 'arguments': {'event_id': event_id}}
        denied = rpc(client, headers(scopes=['tesla:read']), 'tools/call', args).json()['result']
        assert denied['isError'] and 'Synthetic place' not in json.dumps(denied)
        allowed = rpc(client, headers(), 'tools/call', args).json()['result']
    assert not allowed['isError']
    for observation in allowed['structuredContent']['data']['changes']['DestinationName'].values():
        assert observation['value_omitted'] and 'value' not in observation
        assert observation['retrieve_with'] == 'tesla_get_history'
        assert 'reported_route_target_may_be_next_stop_not_final_destination' in observation['semantics']['warnings']
