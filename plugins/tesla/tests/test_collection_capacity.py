"""Wide, explicitly selected profiles: configuration is not reception evidence."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import httpx
import pytest
from starlette.datastructures import FormData
from starlette.testclient import TestClient

from tesla_plugin.collection import Collection, CREATE
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.fleet import Fleet
from tesla_plugin.profiles import full_profile, profile_fields
from tesla_plugin.server import create_app
from tesla_plugin.telemetry import Telemetry, FIELD_MAP, typed_value
from conftest import VIN
from test_collection import prepared_service, fields_form
from test_mcp_portal import login
from test_shared_settings import call
from test_telemetry_events import payload


def test_partial_readback_preserves_owner_profile_for_resume(prepared_service, fleet, vehicle_ref, clock, monkeypatch):
    manager = Collection(prepared_service)
    item = manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref), SCOPES)
    prepared_service.execute_from_owner(item['id'])
    approved = deepcopy(item['arguments']['config'])
    partial = {**approved, 'fields': {'Locked': {'interval_seconds': 15}}}
    original = fleet.call
    monkeypatch.setattr(fleet, 'call', lambda name, *a, **kw: {'config': partial, 'synced': True}
                        if name.endswith('config_get') else original(name, *a, **kw))
    clock.advance(1)
    manager.refresh(vehicle_ref, SCOPES)
    view = manager.view(vehicle_ref)
    assert view['state'] == 'mismatch'
    assert view['saved'] == approved
    resumed = manager.prepare_change(vehicle_ref, 'resume', view['revision'], 'resume-original-profile-01', SCOPES)
    assert resumed['arguments']['config'] == approved


@pytest.mark.parametrize('response', [
    {'updated_vehicles': True, 'skipped_vehicles': {}},
    {'updated_vehicles': 1.0, 'skipped_vehicles': {}},
    {'updated_vehicles': 1, 'skipped_vehicles': None},
    {'updated_vehicles': 1, 'skipped_vehicles': {'missing_key': 'not-a-list'}},
])
def test_malformed_ack_never_claims_collection_accepted(prepared_service, fleet, vehicle_ref, monkeypatch, response):
    manager = Collection(prepared_service)
    item = manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref), SCOPES)
    original = fleet.call
    sends = []
    def response_for(name, *a, **kw):
        if name == CREATE:
            sends.append(name)
            return response
        return original(name, *a, **kw)
    monkeypatch.setattr(fleet, 'call', response_for)
    result = prepared_service.execute_from_owner(item['id'])
    assert result['status'] == 'unknown'
    assert manager.view(vehicle_ref)['saved'] is None
    prepared_service.execute_from_owner(item['id'])
    assert manager.view(vehicle_ref)['blocked']
    assert sends == [CREATE]


@pytest.mark.parametrize('name,value', [('VehicleName', 'MY Unknown'), ('DestinationName', 'Hotel SNA'),
                                      ('RouteLine', '_p~iF~ps|U_ulLnnqC_mqNvxq`@' * 200)])
def test_documented_text_is_not_truncated_or_interpreted_as_unknown_enum(name, value):
    assert typed_value(name, {'stringValue': value}) == (value, 'valid')


@pytest.mark.parametrize('value,expected', [('true', True), ('false', False)])
def test_documented_legacy_boolean_string_is_received(value, expected):
    assert typed_value('DriveRail', {'stringValue': value}) == (expected, 'valid')


def broad_profile():
    fields = profile_fields('full', vehicle_context={'model': 'ModelY', 'firmware_version': '2026.38.3.2', 'fleet_telemetry_version': '1.3.0'})
    fast = {'Gear', 'DriveRail', 'BrakePedal', 'BrakePedalPos', 'DriverSeatOccupied', 'DoorState',
            'Locked', 'CenterDisplay', 'VehicleSpeed', 'PedalPosition', 'DriverSeatBelt', 'PassengerSeatBelt'}
    for name, options in fields.items():
        static = FIELD_MAP[name]['category'] in ('Vehicle Configuration', 'User Preference')
        interval, resend = (1, 1) if name in fast else (60, 300) if static else (5, 15)
        options.update(interval_seconds=interval, resend_interval_seconds=resend)
    return fields


def test_full_profile_mcp_editor_and_signed_request_preserve_every_selection(prepared_service, fleet, vehicle_ref, headers):
    fields = broad_profile()
    assert len(fields) == 234
    assert {x: sum(opts['interval_seconds'] == x for opts in fields.values()) for x in (1, 5, 60)} == {1: 12, 5: 203, 60: 19}
    assert fields['Location']['minimum_delta'] == 25
    assert fields['SelfDrivingMilesSinceReset']['minimum_delta'] == 1
    form = [('field', name) for name in fields] + [('hours', '8'), ('customer_alerts', 'on')]
    for name, opts in fields.items():
        form.extend((prefix+'_'+name, str(opts[key])) for prefix, key in (
            ('interval', 'interval_seconds'), ('resend', 'resend_interval_seconds'), ('delta', 'minimum_delta')) if key in opts)
        form.append(('include_'+name, ''))
    assert Collection.form_profile(FormData(form)) == (fields, True, 8)
    manager = Collection(prepared_service)
    with TestClient(create_app(prepared_service.settings, service=prepared_service, start_worker=False), base_url='https://bridge.example') as client:
        csrf = login(client)
        from urllib.parse import urlencode
        quote = client.post('/tesla/owner/collection/'+vehicle_ref, content=urlencode(form+[('csrf', csrf), ('collection_action', 'estimate'), ('revision', manager.view(vehicle_ref)['revision'])]),
                            headers={'origin': 'https://bridge.example', 'content-type': 'application/x-www-form-urlencoded'})
        assert quote.status_code == 200 and 'id="selected-count">234</output>' in quote.text
        review = call(client, headers(), 'tesla_prepare_collection', vehicle_ref=vehicle_ref, action='configure', preset='custom',
                      custom_fields=fields, customer_alerts=True, expected_revision=manager.view(vehicle_ref)['revision'],
                      client_request_id='full-capacity-mocked-request-01')
        assert review['fields'] == fields
        assert not any(name == CREATE for name, *_ in fleet.calls)
        acknowledged = call(client, headers(), 'tesla_confirm_collection', vehicle_ref=vehicle_ref,
                            intent_id=review['intent_id'], review_digest=review['review_digest'], decision='confirm')
        assert acknowledged['status'] == 'acknowledged'
    dispatched = [args for name, args, *_ in fleet.calls if name == CREATE]
    assert len(dispatched) == 1 and dispatched[0]['config']['fields'] == fields
    # Verify the actual HTTP adapter, not only the fake service method.
    prepared_service.store.settings = replace(prepared_service.settings, live_enabled=True)
    requests = []
    def transport(request):
        requests.append(request)
        return httpx.Response(200, json={'response': {'updated_vehicles': 1, 'skipped_vehicles': {}}})
    wire = Fleet(prepared_service.store, transport=httpx.MockTransport(transport))
    try:
        response = wire.call(CREATE, dispatched[0], vehicle=prepared_service.store.vehicle(vehicle_ref))
    finally:
        wire.close()
    assert len(requests) == 1 and requests[0].url.host == 'proxy.example'
    body = json.loads(requests[0].content)
    assert body == {**dispatched[0], 'vins': [VIN]}
    assert response.diagnostic['collection_request']['selected_field_count'] == 234
    assert response.diagnostic['collection_request']['automatic_field_removal'] is False


def test_rejected_wide_configuration_keeps_previous_profile_and_preferences(prepared_service, fleet, vehicle_ref, clock, monkeypatch):
    manager, store = Collection(prepared_service), prepared_service.store
    original = manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref), SCOPES)
    prepared_service.execute_from_owner(original['id'])
    saved = deepcopy(manager.view(vehicle_ref)['saved'])
    Telemetry(store).ingest('V', payload(clock, {'Gear': 'P', 'BatteryLevel': 64}))
    with store.db() as db:
        baseline = {t: [tuple(r) for r in db.execute('SELECT * FROM '+t)] for t in ('samples', 'trigger_preferences', 'rules')}
    clock.advance(1)
    item = manager.prepare_change(vehicle_ref, 'configure', manager.view(vehicle_ref)['revision'], 'full-profile-rejected-01', SCOPES,
                                  preset='custom', custom_fields=broad_profile())
    def rejected(name, *a, **kw):
        if name == CREATE:
            raise TeslaError('PROVIDER_ERROR', 'Tesla rejected or could not complete the request', http_status=400)
        return fleet_original(name, *a, **kw)
    fleet_original = fleet.call
    monkeypatch.setattr(fleet, 'call', rejected)
    assert prepared_service.execute_from_owner(item['id'])['status'] == 'rejected'
    view = manager.view(vehicle_ref, include_fields=True)
    assert view['saved'] == view['target']['data'] == saved
    assert len(store.intent(item['id'])['arguments']['config']['fields']) == 234
    assert view['field_evidence']['summary']['last_request_count'] == 234
    assert view['field_evidence']['fields']['BrakePedal']['last_request_included']
    assert view['field_evidence']['fields']['BrakePedal']['reception']['status'] == 'not_observed'
    with store.db() as db:
        assert baseline == {t: [tuple(r) for r in db.execute('SELECT * FROM '+t)] for t in baseline}


def test_explicit_matching_readback_resolves_unknown_without_another_dispatch(prepared_service, fleet, vehicle_ref, clock, monkeypatch):
    manager = Collection(prepared_service)
    item = manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref), SCOPES)
    config = item['arguments']['config']
    sends = []
    original = fleet.call
    def response(name, *a, **kw):
        if name == CREATE:
            sends.append(name)
            raise TeslaError('OUTCOME_UNKNOWN', 'synthetic timeout', uncertain=True)
        if name.endswith('config_get'):
            return {'config': config, 'synced': True}
        return original(name, *a, **kw)
    monkeypatch.setattr(fleet, 'call', response)
    assert prepared_service.execute_from_owner(item['id'])['status'] == 'unknown'
    assert manager.view(vehicle_ref)['saved'] is None
    clock.advance(2)
    manager.refresh(vehicle_ref, SCOPES)
    assert manager.view(vehicle_ref)['saved'] == config
    assert manager.view(vehicle_ref)['state'] == 'active'
    assert sends == [CREATE]


def test_field_evidence_matches_panel_and_never_invents_reception(prepared_service, vehicle_ref, headers, clock):
    store, manager = prepared_service.store, Collection(prepared_service)
    fields = {'BatteryLevel': {'interval_seconds': 60}, 'Gear': {'interval_seconds': 15},
              'DriveRail': {'interval_seconds': 15, 'include_fields': ['BrakePedal']}}
    config = {'fields': fields}
    store.snapshot(vehicle_ref, 'telemetry_saved', config, 'test', clock())
    store.snapshot(vehicle_ref, 'telemetry_target', config, 'test', clock())
    store.snapshot(vehicle_ref, 'telemetry_remote', {'config': config, 'synced': False}, 'test', clock())
    clock.advance(1)
    t = Telemetry(store)
    t.ingest('V', payload(clock, {'BatteryLevel': 60, 'Gear': 'P'}))
    clock.advance(16)
    t.ingest('V', payload(clock, {'Gear': None}))
    with TestClient(create_app(prepared_service.settings, service=prepared_service, start_worker=False), base_url='https://bridge.example') as client:
        result = call(client, headers(), 'tesla_get_collection', vehicle_ref=vehicle_ref, include_catalog=True, catalog_search='Gear')
        item = next(x for x in result['catalog']['items'] if x['field'] == 'Gear')
        assert item['evidence']['configuration']['status'] == 'sync_pending'
        assert item['evidence']['reception']['status'] == 'invalid'
        assert not item['evidence']['vehicle_reception_verified']
        assert result['field_summary']['reception'] == {'valid': 1, 'invalid': 1, 'not_observed': 2}
        assert result['field_summary']['field_count'] == 4
        login(client)
        page = client.get('/tesla/owner/collection/'+vehicle_ref)
        assert 'synchronization unconfirmed' in page.text and 'Last sample: invalid' in page.text
        assert 'no archived sample' in page.text
        assert 'received_at' not in page.text  # metadata is presented in owner vocabulary
    clock.advance(300)
    # No sample for BatteryLevel in subsequent frames: never refresh its timestamp.
    view = manager.view(vehicle_ref, include_fields=True)['field_evidence']['fields']
    assert view['BatteryLevel']['reception']['age_seconds'] == 316
    assert view['BrakePedal']['configuration']['included_by'] == ['DriveRail']
    assert view['BrakePedal']['reception']['status'] == 'not_observed'


def test_scalar_fixes_survive_ingestion_storage_history_and_unknown_gear(prepared_service, vehicle_ref, clock):
    t = Telemetry(prepared_service.store)
    value = '_p~iF~ps|U_ulLnnqC_mqNvxq`@'*200
    data = payload(clock, {'Gear': 'P', 'DestinationName': 'Hotel SNA', 'VehicleName': 'MY Unknown', 'RouteLine': value, 'DriveRail': 'false'})
    t.ingest('V', data)
    clock.advance(1)
    t.ingest('V', payload(clock, {'Gear': None}))
    with prepared_service.store.db() as db:
        values = {r['field']: (json.loads(r['value']), r['quality']) for r in db.execute('SELECT * FROM latest WHERE vehicle=?', (vehicle_ref,))}
    assert values['RouteLine'] == (value, 'valid')
    assert values['DestinationName'] == ('Hotel SNA', 'valid')
    assert values['DriveRail'] == (False, 'valid')
    assert values['Gear'] == (None, 'invalid')
    # No reinterpretation of malformed or absent boolean values as false.
    for envelope in ({'stringValue': 'False'}, {'stringValue': '0'}, {'booleanValue': 'false'}, {'invalid': True}, {}):
        assert typed_value('DriveRail', envelope)[1] == 'invalid'


def test_a_single_full_receiver_frame_reaches_every_selectable_field(store, vehicle_ref, clock):
    # Value oneof branches from the pinned official vehicle_data.proto, including
    # nested structures that the prose table calls "enum". This is transport
    # coverage with synthetic values, not a claim about hardware availability.
    branches = {'ShiftState': 'shiftStateValue', 'LocationValue': 'locationValue', 'Doors': 'doorValue',
                'TireLocation': 'tireLocationValue', 'DetailedChargeStateValue': 'detailedChargeStateValue',
                'ClimateOverheatProtectionTempLimit': 'cabinOverheatProtectionTemperatureLimitValue',
                'CableType': 'cableTypeValue'}
    frame = payload(clock, {})
    for name in sorted(full_profile()):
        spec = FIELD_MAP[name]
        kind, proto = spec['documented_type'], spec['protobuf_value_type']
        if spec.get('value_contract') == 'protobuf_oneof_only':
            branch, value = 'booleanValue', False
        elif spec['enum_values']:
            value = next(v.split('=')[0] for v in spec['enum_values'].split('|')
                         if not v.split('=')[0].endswith(('Unknown', 'Invalid', 'SNA')))
            branch = branches.get(proto, 'stringValue')
        elif kind == 'Location':
            branch, value = 'locationValue', {'latitude': 0.0, 'longitude': 0.0}
        elif kind == 'Doors enum':
            branch, value = 'doorValue', {'DriverFront': False, 'DriverRear': False, 'PassengerFront': False,
                                         'PassengerRear': False, 'TrunkFront': False, 'TrunkRear': False}
        elif kind == 'TireLocation enum':
            branch, value = 'tireLocationValue', {'frontLeft': False, 'frontRight': False, 'rearLeft': False, 'rearRight': False}
        elif kind == 'boolean':
            branch, value = 'booleanValue', False
        elif kind in ('real', 'integer'):
            branch, value = ('doubleValue', 1.5) if kind == 'real' else ('intValue', 1)
        elif kind == 'timestamp':
            branch, value = 'longValue', str(int(clock()))
        else:
            assert kind == 'string', (name, kind)
            branch, value = 'stringValue', 'synthetic text'
        frame['data'].append({'key': name, 'value': {branch: value}})
    Telemetry(store).ingest('V', frame)
    with store.db() as db:
        rows = list(db.execute('SELECT field,quality FROM latest WHERE vehicle=?', (vehicle_ref,)))
    assert {r['field'] for r in rows} == set(full_profile())
    assert not [(r['field'], r['quality']) for r in rows if r['quality'] != ('unqualified' if FIELD_MAP[r['field']].get('value_contract') == 'protobuf_oneof_only' else 'valid')]


@pytest.mark.parametrize('response,reason', [
    ({'updated_vehicles': 0, 'skipped_vehicles': {'unsupported_hardware': [VIN]}}, 'unsupported_hardware'),
    ({'updated_vehicles': 0, 'skipped_vehicles': {'unsupported_firmware': [VIN]}}, 'unsupported_firmware'),
    ({'updated_vehicles': 0, 'skipped_vehicles': {'missing_key': [VIN]}}, 'missing_key'),
    ({'updated_vehicles': 0, 'skipped_vehicles': {'max_configs': [VIN]}}, 'max_configs'),
])
def test_explicit_vehicle_rejections_are_distinct_from_missing_samples(prepared_service, fleet, vehicle_ref, monkeypatch, response, reason):
    manager = Collection(prepared_service)
    item = manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref), SCOPES)
    original = fleet.call
    monkeypatch.setattr(fleet, 'call', lambda name, *a, **kw: response if name == CREATE else original(name, *a, **kw))
    result = prepared_service.execute_from_owner(item['id'])
    assert result['status'] == 'rejected'
    assert result['result']['skipped_reasons'] == [reason]
    assert VIN not in json.dumps(result['result'])
    assert manager.view(vehicle_ref)['saved'] is None


@pytest.mark.parametrize('options', [None, {}, {'interval_seconds': True}, {'interval_seconds': 1, 'include_fields': 'Gear'},
                                    {'interval_seconds': 1, 'include_fields': [{}]}, {'interval_seconds': 1, 'minimum_delta': True}])
def test_malformed_readback_does_not_overwrite_previous_evidence(prepared_service, fleet, vehicle_ref, monkeypatch, clock, options):
    manager = Collection(prepared_service)
    original = {'config': {'fields': {'BatteryLevel': {'interval_seconds': 60}}}, 'synced': True}
    prepared_service.store.snapshot(vehicle_ref, 'telemetry_remote', original, 'test', clock())
    monkeypatch.setattr(fleet, 'call', lambda *a, **kw: {'config': {'fields': {'BatteryLevel': options}}, 'synced': True})
    with pytest.raises(TeslaError) as exc:
        manager.refresh(vehicle_ref, SCOPES)
    assert exc.value.code == 'PROVIDER_RESPONSE_INVALID'
    assert manager.view(vehicle_ref)['remote']['data'] == original


def test_missing_saved_profile_bootstraps_only_from_synced_readback(prepared_service, fleet, vehicle_ref, monkeypatch):
    manager = Collection(prepared_service)
    config = {'fields': {'BatteryLevel': {'interval_seconds': 60}}}
    monkeypatch.setattr(fleet, 'call', lambda *a, **kw: {'config': config, 'synced': False})
    manager.refresh(vehicle_ref, SCOPES)
    assert manager.view(vehicle_ref)['saved'] is None
    monkeypatch.setattr(fleet, 'call', lambda *a, **kw: {'config': config, 'synced': True})
    manager.refresh(vehicle_ref, SCOPES)
    assert manager.view(vehicle_ref)['saved'] == config


def test_all_officially_documented_fields_are_discoverable_and_exclusions_explicit():
    from tesla_plugin.collection_catalog import catalogue_page
    public = json.loads((Path(__file__).parent/'fixtures/telemetry-official-fields-2026-10-29.json').read_text())
    declared = {name: spec['documented_type'] for name, spec in FIELD_MAP.items() if spec['catalog_status'] == 'DOCUMENTED'}
    assert declared == public['fields']
    items = []
    offset = 0
    while offset is not None:
        page = catalogue_page(None, offset, 100, location_authorized=True)
        items.extend(page['items'])
        offset = page['next_offset']
    assert {item['field'] for item in items} == {n for n,spec in FIELD_MAP.items() if spec['catalog_status'] in ('DOCUMENTED', 'PROTO_ONLY_UNDOCUMENTED')}
    assert set(public['fields'])-set(public['known_unavailable']) <= set(full_profile())
    for item in items:
        assert item['known_unavailable'] == (item['field'] in public['known_unavailable'])


def test_field_reception_cannot_disclose_location_timing_without_permission(prepared_service, vehicle_ref, clock):
    Telemetry(prepared_service.store).ingest('V', payload(clock, {'Location': {'latitude': 0, 'longitude': 0}}))
    manager = Collection(prepared_service)
    result = manager.public_view(vehicle_ref, [s for s in SCOPES if s != 'tesla:location'], include_catalog=True, catalog_search='Location')
    item = next(x for x in result['catalog']['items'] if x['field'] == 'Location')
    assert not item['location_permission_satisfied']
    assert item['evidence']['reception']['status'] == 'permission_required'
    assert item['evidence']['reception']['source_at'] is None
    assert not item['evidence']['vehicle_reception_verified']


def test_wide_inclusions_fit_telemetry_budget_without_relaxing_other_commands(prepared_service, vehicle_ref):
    from tesla_plugin.catalogue import validate, COLLECTION_ARGUMENT_BYTES
    fields = broad_profile()
    names = [name for name in fields if name not in ('MilesSinceReset', 'SelfDrivingMilesSinceReset')]
    for name in names[:100]:
        fields[name]['include_fields'] = [f for f in names[:25] if f != name]
    manager = Collection(prepared_service)
    item = manager.prepare_change(vehicle_ref, 'configure', manager.view(vehicle_ref)['revision'], 'wide-inclusions-request-01',
                                  SCOPES, preset='custom', custom_fields=fields)
    assert 32768 < len(json.dumps(item['arguments']).encode()) < COLLECTION_ARGUMENT_BYTES
    assert item['arguments']['config']['fields'] == fields
    with pytest.raises(TeslaError) as exc:
        validate(CREATE, {'config': {'fields': fields, 'ca': 'x'*COLLECTION_ARGUMENT_BYTES}})
    assert exc.value.details['maximum_argument_bytes'] == COLLECTION_ARGUMENT_BYTES
    assert 'no fields were removed' in exc.value.message
    with pytest.raises(TeslaError) as exc:
        validate('navigation_request', {'value': 'x'*40000})
    assert exc.value.details['maximum_argument_bytes'] == 32768


def test_uncatalogued_observed_field_is_counted_without_silent_omission(prepared_service, vehicle_ref, clock):
    config = {'fields': {'BatteryLevel': {'interval_seconds': 60}, 'FuturePublicField': {'interval_seconds': 60}}}
    prepared_service.store.snapshot(vehicle_ref, 'telemetry_remote', {'config': config, 'synced': True}, 'test', clock())
    result = Collection(prepared_service).public_view(vehicle_ref, SCOPES)
    summary = result['field_summary']
    assert summary['field_count'] == summary['observed_count'] == 2
    assert summary['uncatalogued_field_count'] == 1
    assert sum(summary['configuration'].values()) == sum(summary['reception'].values()) == summary['field_count']
    assert result['observed_profile']['fields'] == config['fields']
