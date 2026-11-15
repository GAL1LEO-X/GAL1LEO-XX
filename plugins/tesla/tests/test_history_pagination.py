import pytest
from starlette.testclient import TestClient

from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.server import create_app
from test_mcp_portal import rpc


def insert(store, ref, clock, identifier, value, when=None):
    with store.db() as db:
        db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                   (identifier, ref, 'BatteryLevel', str(value), clock() if when is None else when, clock(), 'valid', 'synthetic'))


def test_cursor_excludes_new_arrivals_and_is_bound_to_query(service, vehicle_ref, clock):
    for n in range(4):
        insert(service.store, vehicle_ref, clock, str(n), n)
    after, before = clock()-10, clock()+10
    first = service.history(vehicle_ref, ['BatteryLevel'], after, before, SCOPES, limit=2)
    insert(service.store, vehicle_ref, clock, 'new', 50)
    second = service.history(vehicle_ref, ['BatteryLevel'], after, before, SCOPES, limit=2, cursor=first['next_cursor'])
    assert [s['value'] for s in second['samples']] == [2, 3]
    assert second['next_cursor'] is None and not second['truncated']
    assert second['snapshot_at'] == first['snapshot_at']
    for args in ({'fields': ['Locked']}, {'after': after-1}, {'cursor': first['next_cursor'][:-5]+'wrong'}):
        query = dict(ref=vehicle_ref, fields=['BatteryLevel'], after=after, before=before, scopes=SCOPES, cursor=first['next_cursor']) | args
        with pytest.raises(TeslaError) as error:
            service.history(**query)
        assert error.value.code == 'INVALID_CURSOR'
    clock.advance(601)
    with pytest.raises(TeslaError):
        service.history(vehicle_ref, ['BatteryLevel'], after, before, SCOPES, cursor=first['next_cursor'])


def test_mcp_history_exposes_and_accepts_cursor(service, vehicle_ref, clock, headers):
    for n in range(3):
        insert(service.store, vehicle_ref, clock, str(n), n)
    args = dict(vehicle_ref=vehicle_ref, fields=['BatteryLevel'], after=clock()-1, before=clock()+1, limit=2)
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        first = rpc(client, headers(), 'tools/call', {'name': 'tesla_get_history', 'arguments': args}).json()['result']
        assert not first.get('isError')
        second = rpc(client, headers(), 'tools/call', {'name': 'tesla_get_history', 'arguments': args | {'cursor': first['structuredContent']['next_cursor']}}).json()['result']
        assert not second.get('isError')
        assert len(second['structuredContent']['samples']) == 1


def test_broad_mcp_selection_queries_every_field_and_paginates_samples(service, vehicle_ref, clock, headers):
    from tesla_plugin.profiles import full_profile
    fields = sorted(full_profile())[:180]
    with service.store.db() as db:
        for i, field in enumerate(fields):
            db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                       ('broad-'+str(i), vehicle_ref, field, 'null', clock(), clock(), 'invalid', 'synthetic'))
    args = dict(vehicle_ref=vehicle_ref, fields=fields, after=clock()-1, before=clock()+1, limit=100)
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        first = rpc(client, headers(), 'tools/call', {'name': 'tesla_get_history', 'arguments': args}).json()['result']
        assert first.get('isError') is False
        first = first['structuredContent']
        assert first['requested_fields'] == first['effective_fields'] == fields
        second = rpc(client, headers(), 'tools/call', {'name': 'tesla_get_history', 'arguments': args | {'cursor': first['next_cursor']}}).json()['result']['structuredContent']
        assert {s['field'] for s in first['samples']} | {s['field'] for s in second['samples']} == set(fields)
        assert not ({s['field'] for s in first['samples']} & {s['field'] for s in second['samples']})
        assert second['snapshot_at'] == first['snapshot_at'] and second['next_cursor'] is None


def test_history_measurement_warnings_do_not_change_raw_value_or_quality(service, vehicle_ref, clock):
    import json
    future = int(clock()+7200)
    with service.store.db() as db:
        for field, value in [('TpmsLastSeenPressureTimeFl', future), ('ChargeRateMilePerHour', -1)]:
            db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)',
                       (field, vehicle_ref, field, json.dumps(value), clock(), clock(), 'valid', 'synthetic'))
    result = service.history(vehicle_ref, ['TpmsLastSeenPressureTimeFl', 'ChargeRateMilePerHour'], clock()-1, clock()+1, SCOPES)
    samples = {s['field']: s for s in result['samples']}
    assert samples['TpmsLastSeenPressureTimeFl']['value'] == future
    assert samples['ChargeRateMilePerHour']['value'] == -1
    assert all(s['quality'] == 'valid' and s['semantics']['warnings'] for s in samples.values())
