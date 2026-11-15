"""Offline regressions for the November 2 public contract audit."""
import pytest
import json
from dataclasses import replace
from contextlib import closing

import httpx
from starlette.testclient import TestClient

from tesla_plugin.catalogue import OPERATIONS, describe, validate
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.profiles import estimate, profile_fields
from tesla_plugin.fleet import Fleet
from tesla_plugin.server import create_app
from tesla_plugin.store import canonical
from test_mcp_portal import rpc
from test_collection import prepared_service


@pytest.mark.parametrize('name,arguments', [
    ('set_preconditioning_max', {'on': True}),
    ('set_scheduled_departure', {'enable': False}),
    ('set_scheduled_departure', {'enable': True, 'departure_time': 420,
                                 'preconditioning_weekdays_only': True}),
])
def test_api03_pinned_proxy_optional_and_weekday_contract(name, arguments):
    assert validate(name, arguments) == arguments


@pytest.mark.parametrize('arguments', [
    {'enable': True}, {'enable': True, 'departure_time': 1440},
    {'enable': False, 'departure_time': -1},
    {'enable': False, 'preconditioning_weekdays_only': 'yes'},
])
def test_api03_schedule_invalid_values_stay_closed(arguments):
    with pytest.raises(TeslaError, match='schema'):
        validate('set_scheduled_departure', arguments)


def test_coll04_explicit_null_resend_rejected_before_estimation():
    with pytest.raises(TeslaError) as error:
        profile_fields('custom', {'BatteryLevel': {'interval_seconds': 60,
                                                  'resend_interval_seconds': None}})
    assert error.value.code == 'INVALID_ARGUMENT'


@pytest.mark.parametrize('options', [{'interval_seconds': 60},
                                    {'interval_seconds': 60, 'resend_interval_seconds': 120}])
def test_coll04_omitted_and_integer_resend_are_estimated(options):
    fields = profile_fields('custom', {'BatteryLevel': options})
    assert fields['BatteryLevel'] == options
    assert estimate(fields)['planned_signals_30_days'] > 0


def test_api01_every_invocable_catalogue_contract_matches_its_tool():
    from tesla_plugin.server import ACTIONS, READS, CollectionPrepare
    for name, operation in OPERATIONS.items():
        contract = describe(name)['call_contract']
        if name in ('vehicle_fleet_telemetry_config_create', 'vehicle_fleet_telemetry_config_delete'):
            assert contract['mode'] == 'collection'
            assert contract['tool'] == 'tesla_prepare_collection'
            assert name not in ACTIONS
            arguments = {'vehicle_ref': 'veh_' + 'a' * 24,
                         'expected_revision': 'b' * 64, 'client_request_id': 'audit-contract-collection',
                         **contract['fixed_arguments']}
            if arguments['action'] == 'configure':
                arguments.update(preset='custom', custom_fields={'BatteryLevel': {'interval_seconds': 60}})
            CollectionPrepare.model_validate(arguments)
        elif operation['availability'] != 'supported_transport':
            assert contract['callable'] is False
            assert 'tool' not in contract
        else:
            assert contract['callable'] is True
            assert name in (READS if contract['tool'] == 'tesla_read' else ACTIONS)


def test_api02_invoice_wrapper_declares_ref_without_changing_fleet_endpoint():
    assert describe('charging_invoice')['call_contract']['vehicle_ref_required'] is True
    assert OPERATIONS['charging_invoice']['vehicle_bound'] is False


def test_api01_collection_contract_completes_review_and_confirmation(prepared_service, vehicle_ref, headers, fleet):
    service = prepared_service
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        def call(name, arguments):
            result = rpc(client, headers(), 'tools/call', {'name': name, 'arguments': arguments}).json()['result']
            assert not result['isError'], result
            return result['structuredContent']
        for operation in ('vehicle_fleet_telemetry_config_create', 'vehicle_fleet_telemetry_config_delete'):
            contract = call('tesla_get_operation_schema', {'operation': operation})['call_contract']
            view = call(contract['workflow'][0], {'vehicle_ref': vehicle_ref})
            args = {'vehicle_ref': vehicle_ref, 'client_request_id': 'audit-mcp-'+operation,
                    'expected_revision': view['revision'], **contract['fixed_arguments']}
            if args['action'] == 'configure':
                args.update(preset='custom', custom_fields={'BatteryLevel': {'interval_seconds': 60}})
            before = sum(name == operation for name, *_ in fleet.calls)
            review = call(contract['tool'], args)
            assert sum(name == operation for name, *_ in fleet.calls) == before
            result = call(contract['workflow'][-1], {'vehicle_ref': vehicle_ref, 'intent_id': review['intent_id'],
                          'review_digest': review['review_digest'], 'decision': 'confirm'})
            assert result['status'] == 'acknowledged'
            assert sum(name == operation for name, *_ in fleet.calls) == 1


def test_api02_invoice_contract_preserves_binding_expiry_and_provider_query(service, vehicle_ref, clock):
    service.settings = replace(service.settings, live_enabled=True)
    service.store.settings = service.settings
    document = 'doc_'+'1'*32
    with service.store.db() as db:
        db.execute('INSERT INTO documents VALUES(?,?,?,?)', (document, vehicle_ref, 'synthetic-invoice-id', clock()+60))
    calls = []
    def response(request):
        calls.append(request)
        return httpx.Response(200, content=b'%PDF-1.4\nsynthetic invoice', headers={'content-type': 'application/pdf'})
    with closing(Fleet(service.store, transport=httpx.MockTransport(response))) as fleet:
        service.fleet = fleet
        with pytest.raises(TeslaError) as missing:
            service.read('charging_invoice', {'id': document}, None, SCOPES)
        assert missing.value.code == 'INVALID_ARGUMENT' and 'vehicle_ref' in missing.value.message
        with pytest.raises(TeslaError) as mismatch:
            service.read('charging_invoice', {'id': document}, 'veh_'+'0'*24, SCOPES)
        assert mismatch.value.code == 'NOT_FOUND'
        assert calls == []
        result = service.read('charging_invoice', {'id': document}, vehicle_ref, SCOPES)
        assert result['content'].startswith(b'%PDF-1.4') and result['document_ref'] == document
        assert calls[0].url.path.endswith('/synthetic-invoice-id')
        assert not calls[0].url.params
        assert 'vin' not in calls[0].url.params
        clock.advance(61)
        with pytest.raises(TeslaError) as expired:
            service.read('charging_invoice', {'id': document}, vehicle_ref, SCOPES)
        assert expired.value.code == 'NOT_FOUND' and len(calls) == 1


def test_api04_capability_reason_tracks_historical_observation(service, vehicle_ref, clock):
    from tesla_plugin.diagnostics import record_operation_observations
    item = service.prepare('set_charge_limit', {'percent': 80}, vehicle_ref, 'audit-capability-observed', SCOPES)
    service.execute_from_owner(item['id'])
    clock.advance(1)
    service.store.snapshot(vehicle_ref, 'charge_state', {'charge_limit_soc': 80}, 'tesla_api', clock())
    record_operation_observations(service.store, vehicle_ref, 'charge_state')
    result = next(row for row in service.capabilities(vehicle_ref)['operations'] if row['operation'] == 'set_charge_limit')
    evidence = result['qualification']
    assert result['vehicle_qualified'] and evidence['status'] == 'effect_observed'
    assert result['reason'] == evidence['reason'] == 'matching_later_observation'
    assert 'pending' not in (result.get('catalogue_limitation') or '').lower()
    assert evidence['causality_proven'] is False and evidence['proves_current_state'] is False
    assert evidence['observation']['source_timestamp'] == clock()


@pytest.mark.parametrize('provider_result,expected', [
    (False, 'rejected'), ({'error': 'synthetic private provider text'}, 'rejected'),
    ({'result': True, 'error': 'contradiction'}, 'unknown'),
    ([], 'unknown'), ({'unexpected': 1}, 'unknown'),
    ({'result': False, 'reason': 'unclassified synthetic'}, 'rejected'),
    ({'result': True}, 'acknowledged'), (True, 'acknowledged'), (None, 'acknowledged'),
])
def test_api05_delete_outcome_preserves_last_target_when_unconfirmed(service, fleet, vehicle_ref,
                                                                   provider_result, expected):
    target = {'fields': {'BatteryLevel': {'interval_seconds': 60}}}
    service.store.snapshot(vehicle_ref, 'telemetry_target', target, 'local_configuration', service.store.clock())
    fleet.result = provider_result
    item = service.prepare('vehicle_fleet_telemetry_config_delete', {}, vehicle_ref,
                           'audit-delete-outcome', SCOPES)
    result = service.execute_from_owner(item['id'])
    assert result['status'] == expected
    with service.store.db() as db:
        actual = json.loads(db.execute("SELECT data FROM snapshots WHERE vehicle=? AND section='telemetry_target'",
                                       (vehicle_ref,)).fetchone()[0])
    assert actual == (None if expected == 'acknowledged' else target)
    assert 'synthetic private provider text' not in json.dumps(result)
    calls = list(fleet.calls)
    service.execute_from_owner(item['id'])
    assert fleet.calls == calls


@pytest.mark.parametrize('body', [
    {'response': None, 'error': 'synthetic private provider text'},
    {'response': {'result': True}, 'error': 'synthetic private provider text'},
    {'response': False}, {'response': {'error': 'synthetic private provider text'}},
    {'response': []}, {'response': {'unexpected': 1}},
])
def test_api05_real_fleet_negative_envelopes_preserve_target(service, vehicle_ref, body):
    service.settings = replace(service.settings, live_enabled=True)
    service.store.settings = service.settings
    target = {'fields': {'BatteryLevel': {'interval_seconds': 60}}}
    service.store.snapshot(vehicle_ref, 'telemetry_target', target, 'local_configuration', service.store.clock())
    item = service.prepare('vehicle_fleet_telemetry_config_delete', {}, vehicle_ref,
                           'audit-delete-real-fleet', SCOPES)
    calls = []
    def response(request):
        calls.append(request)
        return httpx.Response(200, json=body)
    with closing(Fleet(service.store, transport=httpx.MockTransport(response))) as fleet:
        service.fleet = fleet
        result = service.execute_from_owner(item['id'])
        assert result['status'] in ('rejected', 'unknown')
        assert service.intent_view(item['id'])['status'] == result['status']
        service.execute_from_owner(item['id'])
    assert len(calls) == 1
    with service.store.db() as db:
        assert json.loads(db.execute("SELECT data FROM snapshots WHERE vehicle=? AND section='telemetry_target'",
                                     (vehicle_ref,)).fetchone()[0]) == target
    assert 'synthetic private provider text' not in json.dumps(result)


@pytest.mark.parametrize('key', ['error', 'errors', 'error_description'])
@pytest.mark.parametrize('error,expected', [('synthetic private error', 'unknown'),
                                          (['synthetic private error'], 'unknown'),
                                          ([], 'acknowledged'), ({}, 'acknowledged')])
def test_api05_inner_error_indicators_match_outer_envelope(key, error, expected):
    from tesla_plugin.collection_diagnostics import deletion_outcome
    status, evidence = deletion_outcome({'result': True, key: error})
    assert status == expected
    assert 'synthetic private error' not in json.dumps(evidence)


def test_evt02_rule_event_is_bounded_retrievable_and_keeps_source(service, vehicle_ref, clock, headers, fleet):
    from tesla_plugin.telemetry import Telemetry
    from test_telemetry_events import payload
    telemetry = Telemetry(service.store)
    telemetry.configure_rule(vehicle_ref, 'field_changed', {'field': 'RouteLine'})
    values = ['synthetic-route-' + 'a' * 60000, 'synthetic-route-' + 'b' * 60000]
    for value in values:
        telemetry.ingest('V', payload(clock, {'RouteLine': value}))
        clock.advance(1)
    with service.store.db() as db:
        event = db.execute("SELECT * FROM events WHERE name='field_changed'").fetchone()
        original = event['data']
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        args = {'name': 'tesla_get_event', 'arguments': {'event_id': event['id']}}
        denied = rpc(client, headers(scopes=['tesla:read']), 'tools/call', args).json()['result']
        assert denied['isError'] and 'synthetic-route' not in json.dumps(denied)
        result = rpc(client, headers(), 'tools/call', args).json()['result']
        assert not result['isError']
        assert len(canonical(result).encode()) < 16000
        data = result['structuredContent']['data']
        assert 'RouteLine' not in data['observed']
        pointer = data['observed_omitted']['RouteLine']
        assert pointer['value_omitted'] and pointer['retrieve_with'] == 'tesla_get_history'
        history = rpc(client, headers(), 'tools/call', {'name': pointer['retrieve_with'],
                                                       'arguments': pointer['arguments']}).json()['result']
        assert not history['isError']
        assert any(sample['value'] == values[-1] for sample in history['structuredContent']['samples'])
    with service.store.db() as db:
        assert db.execute('SELECT data FROM events WHERE id=?', (event['id'],)).fetchone()[0] == original
    assert json.loads(original)['observed']['RouteLine'] == values[-1]
    assert fleet.calls == []


def test_rule_config_schema_documents_kind_requirements_without_root_union(service, headers):
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        tools = rpc(client, headers(), 'tools/list').json()['result']['tools']
    schema = next(item['inputSchema'] for item in tools if item['name'] == 'tesla_configure_rule')
    assert schema['type'] == 'object' and not {'oneOf', 'anyOf'} & schema.keys()
    config = schema['properties']['config']
    if '$ref' in config:
        config = schema['$defs'][config['$ref'].split('/')[-1]]
    assert config['additionalProperties'] is False
    assert {'field', 'threshold', 'direction', 'latitude', 'longitude', 'radius_m'} <= config['properties'].keys()
    kinds = config['x-config-by-kind']
    assert kinds['threshold']['required'] == ['field', 'threshold', 'direction']
    assert kinds['field_changed']['required'] == ['field']
    assert kinds['geofence']['required'] == ['latitude', 'longitude', 'radius_m']
    assert kinds['battery_low']['defaults']['threshold'] == 20
