"""Compare real local discovery exports with the source contracts and packages."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from conftest import rpc, call
from sally_whatsapp.account_events import (
    APPLICATION_EVENT_TYPES,EVENT_TYPES,STATE_EVENT_TYPES,GENERATED_EVENT_TYPES,PROVIDER_EVENT_TYPES,
)
from sally_whatsapp.discovery_contract import compare_snapshot,expected_contract
from sally_whatsapp.event_policies import Filters,normalize_filters
from sally_whatsapp.operations import OPERATIONS
from sally_whatsapp.provider_events import NORMALIZED_EVENT_TYPES
from sally_whatsapp.server import EventList,Subscribe,Unsubscribe

ROOT=Path(__file__).resolve().parents[3]


def snapshot(client):
    return {'format':'whatsapp-discovery-v1',
            'observed_at':datetime.now(timezone.utc).isoformat(),
            'responses':{method:rpc(client,method) for method in ('server/discover','tools/list','events/list')}}


def account_event(value):
    return next(item for item in value['responses']['events/list']['result']['events']
                if item['name']=='whatsapp.event')


def test_complete_wire_discovery_matches_source_without_subscription_or_provider_calls(app_client,environment):
    app,client=app_client
    before=app.state.service.store.state()
    value=snapshot(client)
    report=compare_snapshot(value)
    assert report['status']=='aligned',report
    assert report['differences']==[] and report['missing_application_events']==[]
    assert report['external_catalog_verified'] is False
    assert report['evidence']=='supplied_snapshot_only'
    assert app.state.service.store.state()==before
    assert environment[1].requests==[] and environment[2].sent==[]
    actual=account_event(value)
    names=set(APPLICATION_EVENT_TYPES)
    assert names==set(EVENT_TYPES)|set(STATE_EVENT_TYPES)|set(NORMALIZED_EVENT_TYPES)|set(GENERATED_EVENT_TYPES)
    assert len(APPLICATION_EVENT_TYPES)==len(names)
    assert set(actual['inputSchema']['properties']['event_types']['items']['enum'])==names
    assert set(actual['payloadSchema']['properties']['event_type']['enum'])==names
    assert set(EventList.model_json_schema()['properties']['event_types']['items']['enum'])==names
    for model in (Subscribe,Unsubscribe):
        assert set(model.model_json_schema()['$defs']['Filters']['properties']['event_types']['items']['enum'])==names
    assert set(Filters.model_json_schema()['properties']['event_types']['items']['enum'])==names
    assert set(PROVIDER_EVENT_TYPES)==set(EVENT_TYPES)|{'engine.event'}
    for kind in names:
        assert normalize_filters('whatsapp.event',{'all_chats':True,'event_types':[kind]})['event_types']==[kind]


@pytest.mark.parametrize('location',['input','payload','reader'])
def test_historical_partial_event_catalog_is_reported_by_names(app_client,location):
    _,client=app_client
    value=snapshot(client)
    # Reconstruct the former subset from its source families, not the number 27.
    legacy=list(EVENT_TYPES+STATE_EVENT_TYPES)
    assert set(legacy)<set(APPLICATION_EVENT_TYPES)
    if location=='input':
        account_event(value)['inputSchema']['properties']['event_types']['items']['enum']=legacy
    elif location=='payload':
        account_event(value)['payloadSchema']['properties']['event_type']['enum']=legacy
    else:
        reader=next(item for item in value['responses']['tools/list']['result']['tools']
                    if item['name']=='list_account_events')
        reader['inputSchema']['properties']['event_types']['items']['enum']=legacy
    report=compare_snapshot(value)
    assert report['status']=='mismatch' and report['differences']
    if location=='payload':
        assert set(report['missing_application_events'])==set(APPLICATION_EVENT_TYPES)-set(legacy)


def test_equal_event_count_with_wrong_names_is_not_alignment(app_client):
    _,client=app_client
    value=snapshot(client)
    enum=account_event(value)['payloadSchema']['properties']['event_type']['enum']
    missing=enum.pop()
    enum.append('synthetic.not.a.supported.event')
    assert len(enum)==len(APPLICATION_EVENT_TYPES)
    report=compare_snapshot(value)
    assert report['status']=='mismatch' and report['missing_application_events']==[missing]


def test_semantically_unordered_schema_and_scope_values_remain_aligned(app_client):
    _,client=app_client
    value=snapshot(client)
    def reverse_unordered(item):
        if isinstance(item,dict):
            for key,child in item.items():
                if key in ('enum','required','type','scopes') and isinstance(child,list):
                    child.reverse()
                reverse_unordered(child)
        elif isinstance(item,list):
            for child in item: reverse_unordered(child)
    reverse_unordered(value)
    assert compare_snapshot(value)['status']=='aligned'


@pytest.mark.parametrize('mutation',['missing_tool','renamed_tool','scope','duplicate','partial','error','version',
                                    'capability','tools_capability','capability_value','tools_capability_value',
                                    'protocol_missing','protocol_wrong','protocol_malformed',
                                    'output_schema','profile_meta','file_meta','description'])
def test_discovery_mismatches_and_incomplete_exports_do_not_pass(app_client,mutation):
    _,client=app_client
    value=snapshot(client)
    tools=value['responses']['tools/list']['result']
    discovery=value['responses']['server/discover']['result']
    if mutation=='missing_tool': tools['tools'].pop()
    elif mutation=='renamed_tool': tools['tools'][0]['name']='untrusted-name-with-secret'
    elif mutation=='scope': tools['tools'][0]['securitySchemes'][0]['scopes']=['unexpected:write']
    elif mutation=='duplicate': tools['tools'].append(copy.deepcopy(tools['tools'][0]))
    elif mutation=='partial': tools['nextCursor']='still-more'
    elif mutation=='error': value['responses']['events/list']={'error':{'message':'private details'}}
    elif mutation=='version':
        from mcp_types import SERVER_INFO_META_KEY
        discovery['_meta'][SERVER_INFO_META_KEY]['version']='old-synthetic'
    elif mutation=='capability': discovery['capabilities'].pop('events')
    elif mutation=='tools_capability': discovery['capabilities'].pop('tools')
    elif mutation=='capability_value': discovery['capabilities']['events']={'unsupported':True}
    elif mutation=='tools_capability_value': discovery['capabilities']['tools']['listChanged']=True
    elif mutation=='protocol_missing': discovery.pop('supportedVersions')
    elif mutation=='protocol_wrong': discovery['supportedVersions']=['1900-01-01']
    elif mutation=='protocol_malformed': discovery['supportedVersions']='2026-07-28'
    elif mutation=='description':
        tool=next(item for item in tools['tools'] if item['name']=='get_transfer_status')
        tool['description']='Previous tool description without inline images'
    else:
        tool=next(item for item in tools['tools'] if item['name']=='write_whatsapp')
        if mutation=='output_schema': tool['outputSchema']={'type':'string'}
        elif mutation=='profile_meta': tool['_meta']['openai/profile']=True
        else: tool['_meta']['openai/fileParams']=['unrelated_file']
    if mutation in ('duplicate','partial','error'):
        with pytest.raises(ValueError): compare_snapshot(value)
    else:
        report=compare_snapshot(value)
        assert report['status']=='mismatch' and report['external_catalog_verified'] is False
        assert 'untrusted-name-with-secret' not in json.dumps(report)


def test_all_operation_schema_responses_and_tool_enums_match_packaged_catalog(app_client):
    _,client=app_client
    expected=expected_contract()
    assert set(expected['tools']['get_operation_schema']['inputSchema']['properties']['operation']['enum'])==set(OPERATIONS)
    for name in ('read_whatsapp','write_whatsapp','send_media'):
        names=set(expected['tools'][name]['inputSchema']['properties']['operation']['enum'])
        assert names and names < set(OPERATIONS)
        assert all(OPERATIONS[item]['readonly'] == (name == 'read_whatsapp') for item in names)
    assert not {'messages_send_poll','messages_send_poll_vote'} & set(OPERATIONS)
    # This endpoint returns declarations; it does not execute provider operations.
    service=app_client[0].state.service
    service.ab_provider_operations=lambda: set()
    for name,operation in OPERATIONS.items():
        response=call(client,'get_operation_schema',{'operation':name})['result']['structuredContent']
        assert response['operation']==name
        assert {key:response[key] for key in operation}==operation


def test_snapshot_cli_is_read_only_and_rejects_ambiguous_json(app_client,tmp_path):
    _,client=app_client
    path=tmp_path/'synthetic-discovery.json'
    path.write_text(json.dumps(snapshot(client)))
    original=path.read_bytes()
    command=[sys.executable,'-m','sally_whatsapp.discovery_contract',str(path)]
    run=subprocess.run(command,capture_output=True,text=True,check=True)
    assert json.loads(run.stdout)['status']=='aligned'
    assert path.read_bytes()==original
    path.write_text('{"format":"secret-material","format":"whatsapp-discovery-v1"}')
    run=subprocess.run(command,capture_output=True,text=True)
    assert run.returncode==2 and 'secret-material' not in run.stdout+run.stderr


def test_web_and_portable_packages_do_not_embed_a_second_discovery_catalog(tmp_path):
    from tools.build_plugin import build
    spec=importlib.util.spec_from_file_location('alignment_export',ROOT/'plugins/whatsapp/scripts/export_plugin.py')
    exporter=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)
    from sally_whatsapp.tenancy import Instance
    instance=Instance('sample','Synthetic','11111111-1111-4111-8111-111111111111',8876)
    archives=[tmp_path/'web.zip',tmp_path/'portable.zip',tmp_path/'legacy-export.zip']
    options={'name':'whatsapp-synthetic','version':'0.0.0-test','connect_url':'https://fixture.example/connect'}
    build(archives[0],mode='web',app_id='asdk_app_'+'1'*32,**options)
    build(archives[1],mode='portable',mcp_url='https://fixture.example/mcp',**options)
    exporter.export(instance,archives[2],ROOT/'plugins/whatsapp')
    for archive in archives:
        with zipfile.ZipFile(archive) as package:
            for member in package.namelist():
                if member.endswith('.json'):
                    document=json.loads(package.read(member))
                    def keys(value):
                        if isinstance(value,dict):
                            return set(value).union(*(keys(child) for child in value.values()))
                        if isinstance(value,list):
                            return set().union(*(keys(child) for child in value))
                        return set()
                    assert not {'event_types','payloadSchema','inputSchema','events/list','tools/list'} & keys(document)
    with zipfile.ZipFile(archives[0]) as package:
        assert '.app.json' in package.namelist() and 'mcp.json' not in package.namelist()
    for archive in archives[1:]:
        with zipfile.ZipFile(archive) as package:
            assert 'mcp.json' in package.namelist() and '.app.json' not in package.namelist()
