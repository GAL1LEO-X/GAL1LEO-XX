import json
import pytest

from conftest import VIN
from test_collection import prepared_service
from tesla_plugin.collection import Collection
from tesla_plugin.collection_catalog import catalogue_page, field_info
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.field_capabilities import context, qualification, meets_version
from tesla_plugin.profiles import full_profile, profile_fields
from tesla_plugin.telemetry import Telemetry, FIELD_MAP
from tesla_plugin.store import utc

MODEL_Y = {'model': 'ModelY', 'hardware': 'HW4', 'firmware_version': '2026.38.3.2', 'fleet_telemetry_version': '1.3.0'}


def test_maximum_proposal_excludes_other_models_with_reasons_and_keeps_unknown_hardware_explicit():
    result = Collection.scenario('full', vehicle_context=MODEL_Y)
    fields = result['fields']
    assert len(fields) == 234
    assert 'LifetimeEnergyUsedDrive' not in fields
    assert not any(n.startswith('Semitruck') or n.startswith('Tonneau') for n in fields)
    assert {'RemoteStartActive', 'GpsAccuracyMeters', 'MilesSinceReset', 'SelfDrivingMilesSinceReset'} <= fields.keys()
    assert {x['field'] for x in result['selection_review']['excluded']} == set(full_profile())-set(fields)
    assert result['tesla_requests'] == result['vehicle_actuations'] == 0
    unknown = Collection.scenario('full')['selection_review']
    assert any('requires_HW4' in item['reasons'] for item in unknown['warnings'])


@pytest.mark.parametrize('actual,expected', [('2026.32.299', False), ('2026.32.300', True),
    ('2026.38.3.2', False), ('2026.38.6', True), ('2026.40.1', True), (None, None), (2026.38, None), ('2026.38broken', None)])
def test_alternative_firmware_branches_do_not_qualify_an_older_build(actual, expected):
    assert meets_version(actual, '2026.32.300 / 2026.38.6') is expected


def test_unimplemented_receiver_keys_are_discoverable_but_not_configurable():
    info = field_info(FIELD_MAP['AccessoryRail'])
    assert not info['configurable']
    assert 'receiver_upgrade_required' in info['qualification']['blockers']
    with pytest.raises(TeslaError):
        profile_fields('custom', {'AccessoryRail': {'interval_seconds': 60}})


def test_catalogue_extension_stays_idempotent_and_does_not_enable_new_receiver_keys():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location('catalogue_extension',
        Path(__file__).resolve().parents[1]/'tools/extend_catalogue.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    once = module.extend_telemetry(list(FIELD_MAP.values()))
    assert once == module.extend_telemetry(once)
    assert len(once) == len({f['field'] for f in once}) == 278
    assert not next(f for f in once if f['field'] == 'AccessoryRail')['configurable']


@pytest.mark.parametrize('model,expected', [('ModelY', 234), ('SemiTruck', 249), ('Cybertruck', 237)])
def test_maximum_profile_is_model_specific_not_a_fixed_number(model, expected):
    result = Collection.scenario('full', vehicle_context={**MODEL_Y, 'model': model})
    assert len(result['fields']) == expected
    if model == 'SemiTruck':
        assert 'LifetimeEnergyUsedDrive' in result['fields']
        assert 'TonneauPosition' not in result['fields']
    if model == 'Cybertruck':
        assert 'TonneauPosition' in result['fields']
        assert 'LifetimeEnergyUsedDrive' not in result['fields']


def test_protocol_key_is_receivable_without_claiming_semantic_qualification(store, clock, vehicle_ref):
    fields = {'RemoteStartActive': {'interval_seconds': 60}}
    assert profile_fields('custom', fields) == fields
    Telemetry(store).ingest('V', {'vin': VIN, 'createdAt': utc(clock()), 'data': [
        {'key': 'RemoteStartActive', 'value': {'booleanValue': False}}]})
    with store.db() as db:
        row = db.execute("SELECT value,quality FROM latest WHERE field='RemoteStartActive'").fetchone()
    assert json.loads(row['value']) is False and row['quality'] == 'unqualified'


def test_custom_wrong_model_is_rejected_not_silently_removed(prepared_service, fleet, vehicle_ref):
    manager = Collection(prepared_service)
    prepared_service.store.snapshot(vehicle_ref, 'vehicle_config', {'car_type': 'modely'}, 'synthetic', prepared_service.store.clock())
    with pytest.raises(TeslaError, match='LifetimeEnergyUsedDrive'):
        manager.prepare_change(vehicle_ref, 'configure', manager.view(vehicle_ref)['revision'], 'wrong-model-profile-01', SCOPES,
                               preset='custom', custom_fields={'LifetimeEnergyUsedDrive': {'interval_seconds': 60}})
    assert fleet.calls == []
    assert manager.view(vehicle_ref)['saved'] is None


@pytest.mark.parametrize('purpose', ['charging', 'comfort', 'park', 'journey', 'security'])
def test_contextual_discovery_is_local_and_never_applies_a_profile(prepared_service, fleet, vehicle_ref, purpose):
    result = Collection(prepared_service).public_view(vehicle_ref, SCOPES, for_context=purpose)
    assert result['context_proposal']['proposal_only'] and not result['context_proposal']['applied']
    assert result['context_proposal']['estimate']['billing_cap'] is False
    assert fleet.calls == [] and result['saved_profile'] is None
    assert set(result['data_channels']) == {'on_demand', 'telemetry', 'history', 'events', 'derived'}


def test_model_not_inferred_from_display_name_and_metadata_limitations_are_visible(store, vehicle_ref):
    assert context(store, vehicle_ref)['model'] is None
    assert FIELD_MAP['OffroadLightbarPresent']['unit_explicit_in_description'] == ''
    assert 'unità: bar' not in field_info(FIELD_MAP['OffroadLightbarPresent'])['description']
    for field in ('PassengerSeatBelt', 'TpmsLastSeenPressureTimeFl'):
        info = field_info(FIELD_MAP[field])
        assert info['notes'] and info['sources'] and info['limitations']


def test_context_uses_newest_observed_firmware_not_always_telemetry(store, vehicle_ref, clock):
    Telemetry(store).ingest('V', {'vin': VIN, 'createdAt': utc(clock()), 'data': [
        {'key': 'Version', 'value': {'stringValue': '2026.26.6'}}]})
    clock.advance(3600)
    store.snapshot(vehicle_ref, 'capabilities', {'firmware_version': '2026.38.3.2', 'fleet_telemetry_version': '1.3.0'}, 'tesla_api', clock())
    view = context(store, vehicle_ref)
    assert view['firmware_version'] == '2026.38.3.2'
    assert view['firmware_evidence'] == {'source': 'capabilities', 'source_at': clock()}
    assert 'GpsAccuracyMeters' in profile_fields('full', vehicle_context=view)
    clock.advance(1)
    Telemetry(store).ingest('V', {'vin': VIN, 'createdAt': utc(clock()), 'data': [
        {'key': 'Version', 'value': {'stringValue': '2026.40.1'}}]})
    assert context(store, vehicle_ref)['firmware_version'] == '2026.40.1'


def test_unknown_firmware_text_does_not_hide_version_evidence(store, vehicle_ref, clock):
    store.snapshot(vehicle_ref, 'capabilities', {'firmware_version': '2026.38.3.2'}, 'tesla_api', clock())
    clock.advance(1)
    Telemetry(store).ingest('V', {'vin': VIN, 'createdAt': utc(clock()), 'data': [
        {'key': 'Version', 'value': {'stringValue': 'unavailable'}}]})
    assert context(store, vehicle_ref)['firmware_version'] == '2026.38.3.2'


@pytest.mark.parametrize('firmware', [2026.38, '2026.38broken', None])
def test_prepare_rejects_malformed_fleet_versions(prepared_service, fleet, vehicle_ref, firmware):
    from tesla_plugin.profiles import build
    original = fleet.call
    def call(name, *args, **kwargs):
        result = original(name, *args, **kwargs)
        if name == 'vehicle_fleet_status':
            result['vehicle_info'][VIN]['firmware_version'] = firmware
        return result
    fleet.call = call
    with pytest.raises(TeslaError, match='requires a paired key'):
        build(prepared_service, vehicle_ref, 'essential', None, SCOPES, 8)
    assert [c[0] for c in fleet.calls] == ['vehicle_fleet_status']
