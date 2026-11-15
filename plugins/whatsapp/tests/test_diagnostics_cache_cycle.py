"""Concrete diagnostic contracts; synthetic identities and provider responses."""
import json
import time
import httpx
import pytest

from conftest import call
from sally_whatsapp.gateway import GatewayUnavailable, Waha
from sally_whatsapp.server import Service, SendKey


def test_uncertain_listing_is_owner_bound_read_only_and_omits_payloads(app_client):
    app, client = app_client
    store = app.state.service.store
    for key, owner, op in [('historical-own-action-01','test-owner','profile_set_profile_status'),
                           ('historical-own-action-02','test-owner','groups_revoke_invite_code'),
                           ('historical-other-user-01','other-owner','messages_send_text')]:
        store.queue_action(key, owner, op, {'body': {'status': 'private-content-never-list'}})
        store.finish_send(key, 'uncertain', result={'id': 'private-provider-value'})
    before = store.path.read_bytes()
    value = call(client,'get_send_status',{'mode':'uncertain','limit':1})['result']['structuredContent']
    assert value['total']==2 and len(value['actions'])==1 and value['next_offset']==1
    assert value['actions'][0]['state']=='uncertain'
    assert value['actions'][0]['operation']=='profile_set_profile_status'
    assert value['actions'][0]['provider_id_present'] is False
    assert 'private-content-never-list' not in json.dumps(value) and 'private-provider-value' not in json.dumps(value)
    value2=call(client,'get_send_status',{'mode':'uncertain','limit':1,'offset':1})['result']['structuredContent']
    assert value2['next_offset'] is None and value2['actions'][0]['key']!=value['actions'][0]['key']
    assert before == store.path.read_bytes()
    assert store.send_status('historical-own-action-01')['state']=='uncertain'


@pytest.mark.parametrize('args',[{}, {'mode':'uncertain','idempotency_key':'historical-own-action-01'},
                                {'idempotency_key':'historical-own-action-01','offset':1},
                                {'mode':'uncertain','limit':True}, {'mode':'uncertain','offset':-1}])
def test_uncertain_lookup_modes_do_not_silently_ignore_arguments(args):
    with pytest.raises(ValueError): SendKey.model_validate(args)


def test_legacy_send_lookup_remains_the_same(app_client):
    app,client=app_client;store=app.state.service.store
    store.queue_action('historical-own-action-01','test-owner','profile_set_profile_status',{})
    store.finish_send('historical-own-action-01','uncertain')
    result=call(client,'get_send_status',{'idempotency_key':'historical-own-action-01'})['result']['structuredContent']
    assert result['state']=='uncertain' and result['key']=='historical-own-action-01'


def test_status_preview_cannot_expose_another_owner(app_client):
    app,client=app_client;store=app.state.service.store
    for owner,key in [('test-owner','historical-own-action-01'),('other-owner','historical-other-action-01')]:
        store.queue_action(key,owner,'messages_set_star',{})
        store.finish_send(key,'uncertain')
    result=call(client,'connection_status')['result']['structuredContent']['action_diagnostics']
    assert result['uncertain_total']==1
    assert [r['key'] for r in result['uncertain_actions_preview']]==['historical-own-action-01']


@pytest.mark.parametrize('args',[
    {}, {'idempotency_key':None}, {'idempotency_key':'historical-own-action-01'},
    {'idempotency_key':'historical-own-action-01','mode':'single'},
    {'mode':'uncertain'}, {'mode':'uncertain','limit':2,'offset':0},
    {'mode':'uncertain','idempotency_key':None}, {'mode':'single'},
    {'mode':'uncertain','idempotency_key':'historical-own-action-01'},
    {'idempotency_key':'historical-own-action-01','offset':1},
])
def test_send_status_schema_describes_its_two_modes(args):
    from jsonschema import Draft202012Validator
    schema_valid=Draft202012Validator(SendKey.model_json_schema()).is_valid(args)
    try: SendKey.model_validate(args); model_valid=True
    except ValueError: model_valid=False
    assert schema_valid==model_valid


def test_capabilities_reports_the_current_contract_without_claiming_consumer_refresh(app_client):
    _,client=app_client
    result=call(client,'get_capabilities')['result']['structuredContent']['discovery_contract']
    assert result['tool_count']==27 and result['operation_catalog_count']==120
    assert result['operation_enum_counts']=={'read_whatsapp':44,'write_whatsapp':60,'send_media':12}
    assert len(result['contract_sha256'])==64 and result['external_catalog_reload_verified'] is False


def test_status_distinguishes_old_uncertain_actions_from_active_work(environment):
    settings,receiver,gateway,_=environment;service=Service(settings,gateway=gateway,event_transport=receiver)
    service.store.queue_action('historical-own-action-01','test-owner','messages_set_star',{})
    service.store.finish_send('historical-own-action-01','uncertain')
    service.store.queue_action('active-own-action-0001','test-owner','messages_send_text',{})
    status=service.connection_status()
    assert status['uncertain_sends']==1
    assert status['action_diagnostics']['uncertain_by_operation']=={'messages_set_star':1}
    assert status['action_diagnostics']['queued']==1 and status['action_diagnostics']['sending']==0
    assert status['action_diagnostics']['uncertain_are_pending_retries'] is False


def test_session_webhook_logs_transition_and_duplicate_is_not_a_new_incident(environment):
    settings,receiver,gateway,_=environment;service=Service(settings,gateway=gateway,event_transport=receiver)
    now=time.time()
    for idx,state in enumerate(('STARTING','WORKING')):
        envelope={'event':'session.status','id':'synthetic-status-'+state,'timestamp':(now+idx)*1000,'payload':{'status':state,'private':'never-log'}}
        service.ingest(envelope);service.ingest(envelope)
    service.diagnostics.close()
    rows=[json.loads(s) for s in (settings.database.parent/'diagnostics/events.jsonl').read_text().splitlines()]
    observed=[r for r in rows if r['event']=='connection.observed']
    assert [r['state'] for r in observed]==['STARTING','WORKING']
    assert all(r['observation_source']=='webhook' for r in observed)
    assert 'never-log' not in json.dumps(rows)
    assert service.store.state()['recovery_reasons']['connection_interrupted']['status']=='open'


@pytest.mark.parametrize('payload,expected',[
    ({'exception':{'code':2,'details':'info query returned status 404: item-not-found'}},'resource_not_found'),
    ({'exception':{'code':3,'details':'private-api-key-must-not-be-logged'}},'invalid_request'),
    ({'exception':{'code':2,'details':'unclassified private failure'}},'provider_failure'),
])
def test_provider_error_classification_is_bounded_and_never_logs_details(environment,payload,expected):
    settings,_,_,_=environment;gateway=Waha(settings);gateway.client.close()
    from dataclasses import replace
    gateway.settings=replace(settings,live_account_enabled=True)
    gateway.client=httpx.Client(base_url=settings.waha_url,transport=httpx.MockTransport(lambda r:httpx.Response(500,json=payload)))
    from sally_whatsapp.diagnostics import Diagnostics
    gateway.diagnostics=Diagnostics(settings)
    with pytest.raises(GatewayUnavailable) as error:gateway.request('GET','/api/default/groups/synthetic-group')
    assert error.value.provider_error_kind==expected
    gateway.diagnostics.close();rows=(settings.database.parent/'diagnostics/events.jsonl').read_text()
    assert expected in rows and 'private-api-key' not in rows and 'unclassified private' not in rows


def test_non_json_response_retains_observed_http_status_in_diagnostics(environment):
    from dataclasses import replace
    from sally_whatsapp.diagnostics import Diagnostics
    settings,*_=environment;gateway=Waha(replace(settings,live_account_enabled=True));gateway.client.close()
    gateway.client=httpx.Client(base_url=settings.waha_url,transport=httpx.MockTransport(lambda r:httpx.Response(200,text='private-invalid-body')))
    gateway.diagnostics=Diagnostics(settings)
    with pytest.raises(GatewayUnavailable):gateway.request('GET','/api/default/profile')
    gateway.diagnostics.close();rows=[json.loads(s) for s in (settings.database.parent/'diagnostics/events.jsonl').read_text().splitlines()]
    assert rows[-1]['status']==200 and rows[-1]['provider_error_kind']=='invalid_provider_response'
    assert 'private-invalid-body' not in json.dumps(rows)


def test_action_failure_log_correlates_without_persisting_action_payload(environment):
    from dataclasses import replace
    from sally_whatsapp.diagnostics import Diagnostics,reference
    settings,receiver,_,_=environment;settings=replace(settings,live_account_enabled=True,account_actions_enabled=True)
    gateway=Waha(settings);gateway.client.close()
    gateway.client=httpx.Client(base_url=settings.waha_url,transport=httpx.MockTransport(lambda r:httpx.Response(500,json={'exception':{'code':3,'details':'private-about-text'}})))
    service=Service(settings,gateway=gateway,event_transport=receiver)
    key='diagnostic-action-key-001'
    service.store.queue_action(key,'test-owner','profile_set_profile_status',{'path':{},'query':{},'body':{'status':'private-about-text'}})
    assert service.process_action()
    assert service.store.send_status(key)['state']=='uncertain'
    service.diagnostics.close();rows=[json.loads(s) for s in (settings.database.parent/'diagnostics/events.jsonl').read_text().splitlines()]
    failure=next(r for r in rows if r['event']=='gateway.failed')
    assert failure['job_ref']==reference(key) and failure['operation']=='profile_set_profile_status'
    assert failure['provider_error_kind']=='invalid_request'
    assert 'private-about-text' not in json.dumps(rows) and key not in json.dumps(rows)
