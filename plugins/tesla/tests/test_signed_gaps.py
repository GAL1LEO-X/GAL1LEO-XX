"""Public wire extensions: isolated intents, permissions and observable effects."""
from dataclasses import replace
import math
import pytest
from tesla_plugin.catalogue import OPERATIONS, validate, describe
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError

CASES = [
    ('navigation_gps_request', {'lat':0, 'lon':0, 'order':3}),
    ('navigation_sc_request', {'id':123456, 'order':2}),
    ('navigation_waypoints_request', {'waypoints':'refId:synthetic-a,refId:synthetic-b', 'destination_arrival_soe':20}),
    ('remote_auto_steering_wheel_heat_climate_request', {'on':True}),
    ('remote_steering_wheel_heat_level_request', {'level':3}),
    ('remote_boombox', {'sound':2000}),
    ('upcoming_calendar_entries', {'calendar_data':'synthetic-encoded-data'}),
]


@pytest.mark.parametrize('name,args', CASES)
def test_extensions_have_a_closed_shared_contract_and_do_not_claim_physical_effect(service, fleet, vehicle_ref, name, args):
    schema = describe(name)
    assert schema['availability'] == 'supported_transport'
    assert schema['implementation_status'] == 'signed_extension_implemented'
    assert schema['transport_requirement'] == 'gal1leo-vehicle-command/2'
    assert schema['limitations'] and not schema['vehicle_qualified']
    prepared = service.prepare(name,args,vehicle_ref,'signed-gap-contract-'+name,SCOPES)
    assert prepared['arguments'] == args and prepared['limitations'] == schema['limitations']
    assert not fleet.calls
    service.settings = replace(service.settings,live_enabled=True)
    result = service.execute_action_from_chat(prepared['id'], prepared['action_digest'], 'execute', SCOPES)
    assert result['status'] == 'acknowledged'
    assert not result['verification']['effect_observed']
    assert fleet.calls[-1][:2] == (name,args)
    calls = list(fleet.calls)
    service.execute_from_owner(prepared['id'])
    assert fleet.calls == calls


@pytest.mark.parametrize('name,args', [
    ('navigation_gps_request', {'lat':91,'lon':0,'order':1}),
    ('navigation_gps_request', {'lat':math.inf,'lon':0,'order':1}),
    ('navigation_gps_request', {'lat':0,'lon':0,'order':4}),
    ('navigation_sc_request', {'id':9007199254740992,'order':1}),
    ('navigation_sc_request', {'id':0,'order':1}),
    ('navigation_sc_request', {'id':True,'order':1}),
    ('navigation_waypoints_request', {'waypoints':'x','append':True}),
    ('navigation_waypoints_request', {'waypoints':'x','destination_arrival_soe':0.5}),
    ('navigation_waypoints_request', {'waypoints':'x','destination_start_soe':None}),
    ('remote_auto_steering_wheel_heat_climate_request', {'on':1}),
    ('remote_steering_wheel_heat_level_request', {'level':2}),
    ('remote_boombox', {'sound':1}),
    ('upcoming_calendar_entries', {'calendar_data':'é'*8193}),
    ('upcoming_calendar_entries', {'calendar_data':'x\x00'}),
    ('upcoming_calendar_entries', {'calendar_data':'\ud800'}),
    ('upcoming_calendar_entries', {'calendar_data':'   '}),
])
def test_invalid_wire_extension_arguments_are_rejected(name,args):
    with pytest.raises(TeslaError): validate(name,args)


def test_navigation_permission_is_rechecked_before_any_tesla_request(service,fleet,vehicle_ref):
    name,args = CASES[0]
    restricted = set(SCOPES)-{'tesla:location'}
    with pytest.raises(TeslaError): service.prepare(name,args,vehicle_ref,'no-location-nav-test',restricted)
    intent = service.prepare(name,args,vehicle_ref,'location-nav-prepare',SCOPES)
    service.settings = replace(service.settings,allowed_scopes=tuple(restricted))
    with pytest.raises(TeslaError): service.execute_from_owner(intent['id'])
    assert not fleet.calls
    assert service.intent_view(intent['id'])['status']=='prepared'


def test_boombox_requires_observed_park_without_assuming_null(service,fleet,vehicle_ref):
    intent = service.prepare('remote_boombox',{'sound':2000},vehicle_ref,'boombox-park-contract',SCOPES)
    fleet.park = None
    with pytest.raises(TeslaError): service.execute_from_owner(intent['id'])
    assert all(name != 'remote_boombox' for name,_,_ in fleet.calls)


@pytest.mark.parametrize('name,args,field,value', [
    ('remote_auto_steering_wheel_heat_climate_request',{'on':False},'auto_steering_wheel_heat',False),
    ('remote_steering_wheel_heat_level_request',{'level':0},'steering_wheel_heat_level',0),
])
def test_wheel_effects_use_requested_later_data_not_null_or_an_added_read(service,fleet,vehicle_ref,clock,name,args,field,value):
    intent = service.prepare(name,args,vehicle_ref,'wheel-effects-'+name,SCOPES)
    service.execute_from_owner(intent['id'])
    calls=list(fleet.calls)
    clock.advance(1)
    service._cache(vehicle_ref,{'climate_state':{field:None,'timestamp':clock()*1000}},'tesla_live',authorization=fleet.authorization())
    assert not service.intent_view(intent['id'])['verification']['effect_observed']
    clock.advance(1)
    service._cache(vehicle_ref,{'climate_state':{field:value,'timestamp':clock()*1000}},'tesla_live',authorization=fleet.authorization())
    assert service.intent_view(intent['id'])['verification']['effect_observed']
    assert fleet.calls==calls


def test_catalogue_extension_is_repeatable_and_keeps_unsupported_operations_closed():
    import importlib.util
    from pathlib import Path
    from tesla_plugin.catalogue import CATALOGUE
    from copy import deepcopy
    path=Path(__file__).resolve().parents[1]/'tools/extend_catalogue.py'
    spec=importlib.util.spec_from_file_location('extend_catalogue',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    assert module.extend(deepcopy(CATALOGUE))==CATALOGUE
    assert sum(op['availability']=='supported_transport' for op in OPERATIONS.values())==105
    assert OPERATIONS['vehicle_signed_command']['availability']=='operator_only'
