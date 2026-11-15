"""Synthetic extension and acquisition contracts; never open a Tesla connection."""
from dataclasses import replace
import json
import math
import pytest
import httpx
from starlette.datastructures import FormData
from tesla_plugin.catalogue import OPERATIONS, validate
from tesla_plugin.collection import Collection
from tesla_plugin.collection_state import matches_config
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.fleet import Fleet
from tesla_plugin.profiles import profile_fields, estimate, build, full_profile, effective_fields
from tesla_plugin.trigger_dependencies import assess_path
from test_profiles_storage_packages import certificate


@pytest.mark.parametrize('name,args', [
 ('set_low_power_mode', {'enable':True}), ('keep_accessory_power_mode', {'enable':False}),
 ('close_trunk', {}), ('batch_remove_charge_schedules', {'home':True,'work':False,'other':False}),
 ('batch_remove_precondition_schedules', {'home':False,'work':True,'other':False}),
 ('set_seat_heaters', {'levels':{'0':1,'5':3}}),
 ('set_climate_keeper_mode', {'climate_keeper_mode':1,'manual_override':False}),
])
def test_new_command_immutable_intents_and_acceptance(service, fleet, vehicle_ref, name, args):
    assert validate(name,args) == args
    intent=service.prepare(name,args,vehicle_ref,'sdk-extension-'+name,SCOPES)
    original=service.intent_view(intent['id'])
    assert original['arguments'] == args
    result=service.execute_from_owner(intent['id'])
    assert result['status']=='acknowledged'
    assert not result['verification']['effect_observed']
    calls=list(fleet.calls)
    service.execute_from_owner(intent['id'])
    assert fleet.calls==calls


@pytest.mark.parametrize('name,args', [
 ('set_low_power_mode', {'enable':1}), ('close_trunk', {'which_trunk':'front'}),
 ('batch_remove_charge_schedules', {'home':False,'work':False,'other':False}),
 ('batch_remove_charge_schedules', {'home':True}), ('set_seat_heaters', {'levels':{'3':2}}),
 ('set_seat_heaters', {'levels':{'0':True}}), ('set_seat_heaters', {'levels':{}}),
])
def test_closed_new_schemas(name,args):
    with pytest.raises(TeslaError): validate(name,args)


@pytest.mark.parametrize('attestation', [{}, {'protocol':'old','operations':['close_trunk']},
 {'protocol':'gal1leo-vehicle-command/1','operations':['close_trunk']},
 {'protocol':'gal1leo-vehicle-command/2','operations':'close_trunk'},
 {'protocol':'gal1leo-vehicle-command/2','operations':[]},
 {'protocol':'gal1leo-vehicle-command/2','operations':['close_trunk']}])
def test_extension_gate_probes_only_local_proxy_and_never_sends_token(store, vehicle_ref, attestation):
    store.settings=replace(store.settings,live_enabled=True)
    requests=[]
    def transport(request):
        requests.append(request)
        if request.url.path=='/gal1leo/capabilities':
            assert 'authorization' not in request.headers
            return httpx.Response(200,json=attestation)
        return httpx.Response(200,json={'response':{'result':True}})
    fleet=Fleet(store,transport=httpx.MockTransport(transport))
    valid=attestation.get('protocol')=='gal1leo-vehicle-command/2' and isinstance(attestation.get('operations'),list) and 'close_trunk' in attestation.get('operations',[])
    if valid:
        assert fleet.call('close_trunk',{},vehicle=store.vehicle(vehicle_ref))=={'result':True}
    else:
        with pytest.raises(TeslaError,match='no Tesla command'): fleet.call('close_trunk',{},vehicle=store.vehicle(vehicle_ref))
    assert len(requests)==(2 if valid else 1)
    assert all(r.url.host=='proxy.example' for r in requests)
    fleet.close()


def test_includes_form_cost_and_configuration_readback_are_consistent():
    fields={'BatteryLevel':{'interval_seconds':60,'resend_interval_seconds':120,'minimum_delta':0.5,'include_fields':['Locked','InsideTemp']}}
    assert profile_fields('custom',fields)==fields
    form=FormData({'field':'BatteryLevel','interval_BatteryLevel':'60','resend_BatteryLevel':'120','delta_BatteryLevel':'0.5','include_BatteryLevel':'Locked, InsideTemp','hours':'8'})
    assert Collection.form_profile(form)[0]==fields
    base={'BatteryLevel':{k:v for k,v in fields['BatteryLevel'].items() if k!='include_fields'}}
    assert estimate(fields)['planned_signals_30_days']==3*estimate(base)['planned_signals_30_days']
    assert effective_fields(fields)=={'BatteryLevel','Locked','InsideTemp'}
    observed={'fields':{'BatteryLevel':{**fields['BatteryLevel'],'include_fields':['InsideTemp','Locked']}}}
    assert matches_config({'fields':fields}, observed)
    assert not matches_config({'fields':base},observed)
    observed['fields']['BatteryLevel']['include_fields']=['Locked']
    assert not matches_config({'fields':fields},observed)


@pytest.mark.parametrize('options', [
 {'minimum_delta':math.nan}, {'minimum_delta':True}, {'minimum_delta':-0.1},
 {'include_fields':['BatteryLevel']}, {'include_fields':['Locked','Locked']},
 {'include_fields':'Locked'}, {'include_fields':[1]}, {'include_fields':['NoSuchField']},
 {'include_fields':['MilesSinceReset']},
])
def test_invalid_extended_fields_rejected(options):
    with pytest.raises(TeslaError): profile_fields('custom',{'BatteryLevel':{'interval_seconds':60,**options}})


def test_include_location_requires_scope_before_fleet_request(service, fleet, vehicle_ref):
    with pytest.raises(TeslaError):
        build(service,vehicle_ref,'custom',{'BatteryLevel':{'interval_seconds':60,'include_fields':['Location']}},set(SCOPES)-{'tesla:location'},8)
    assert fleet.calls==[]


def test_includes_firmware_gate_and_decimal_signed_config(service, fleet, vehicle_ref, tmp_path, monkeypatch):
    service.settings=replace(service.settings,telemetry_host='telemetry.example',telemetry_ca_file=certificate(tmp_path/'ca.crt'))
    fields={'BatteryLevel':{'interval_seconds':60,'minimum_delta':0.5,'include_fields':['Locked']}}
    body,_=build(service,vehicle_ref,'custom',fields,SCOPES,8)
    assert validate('vehicle_fleet_telemetry_config_create',body)==body
    original=fleet.call
    def old(*args,**kwargs):
        result=original(*args,**kwargs)
        for info in result['vehicle_info'].values(): info['firmware_version']='2026.26.5'
        return result
    monkeypatch.setattr(fleet,'call',old)
    with pytest.raises(TeslaError,match='include_fields requires'): build(service,vehicle_ref,'custom',fields,SCOPES,8)
    assert all(name=='vehicle_fleet_status' for name,_,_ in fleet.calls)


def test_included_only_readiness_does_not_claim_independent_refresh():
    req={'fields':['Locked'],'max_age_seconds':120,'suggested_max_interval_seconds':15,'customer_alerts':False,'kind':'field','coherence_seconds':None}
    status=assess_path(req,{'verified':True},{'fields':{'BatteryLevel':{'interval_seconds':60,'include_fields':['Locked']}}},{},1000)
    assert status['coverage']=='covered' and status['observation_status']=='missing'
    assert status['timing_warnings'][0]['reason']=='included_only_no_independent_interval'
    assert 'RouteLastUpdated' not in full_profile()


@pytest.mark.parametrize('name,args,section,data',[
 ('charge_start',{},'charge_state',{'charging_state':'Charging'}),
 ('charge_stop',{},'charge_state',{'charging_state':'Stopped'}),
 ('set_charging_amps',{'charging_amps':12},'charge_state',{'charge_current_request':12}),
 ('charge_port_door_close',{},'charge_state',{'charge_port_door_open':False}),
 ('set_sentry_mode',{'on':True},'vehicle_state',{'sentry_mode':True}),
 ('close_trunk',{},'vehicle_state',{'rt':0}),
 ('remote_seat_heater_request',{'seat_position':5,'level':2},'climate_state',{'seat_heater_rear_right':2}),
 ('set_seat_heaters',{'levels':{'0':1,'5':3}},'climate_state',{'seat_heater_left':1,'seat_heater_rear_right':3}),
 ('remote_steering_wheel_heater_request',{'on':True},'climate_state',{'steering_wheel_heater':True}),
])
def test_effects_require_later_present_matching_values_without_new_requests(service, fleet, vehicle_ref, clock, name,args,section,data):
    intent=service.prepare(name,args,vehicle_ref,'new-effects-'+name,SCOPES)
    service.execute_from_owner(intent['id'])
    calls=list(fleet.calls)
    clock.advance(1)
    service._cache(vehicle_ref,{section:{**dict.fromkeys(data), 'timestamp':clock()*1000}},'tesla_live',authorization=fleet.authorization())
    assert not service.intent_view(intent['id'])['verification']['effect_observed']
    clock.advance(1)
    service._cache(vehicle_ref,{section:{**data,'timestamp':clock()*1000}},'tesla_live',authorization=fleet.authorization())
    evidence=service.intent_view(intent['id'])['verification']
    assert evidence['effect_observed'] and not evidence['causality_proven']
    assert fleet.calls==calls


def test_proxy_extension_lock_and_archive_contain_the_reviewed_sources():
    import importlib.util
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    spec=importlib.util.spec_from_file_location('proxy_extension',root/'tools/proxy_extension.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    lock=json.loads((root/'deploy/components.lock.json').read_text())
    assert module.source_hashes()==lock['vehicle_command']['extension']['sources_sha256']
    spec=importlib.util.spec_from_file_location('tesla_build',root/'build.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    included={p.relative_to(root).as_posix() for p in builder.source_inputs(root)}
    assert {'deploy/proxy-extension/'+name for name in module.FILES} <= included


def test_owner_confirmation_rechecks_included_location_permission(service,fleet,vehicle_ref,tmp_path):
    service.settings=replace(service.settings,telemetry_host='telemetry.example',telemetry_ca_file=certificate(tmp_path/'ca.crt'))
    fields={'BatteryLevel':{'interval_seconds':60,'include_fields':['Location']}}
    intent=service.prepare_profile(vehicle_ref,'custom',fields,'included-location-permission-check',SCOPES)
    service.settings=replace(service.settings,allowed_scopes=tuple(s for s in SCOPES if s!='tesla:location'))
    calls=list(fleet.calls)
    with pytest.raises(TeslaError): service.execute_from_owner(intent['id'])
    assert fleet.calls==calls
    assert service.intent_view(intent['id'])['status']=='prepared'
