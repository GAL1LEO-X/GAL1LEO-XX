from dataclasses import replace
import pytest
from starlette.testclient import TestClient

from tesla_plugin.config import SCOPES
from tesla_plugin.events import Events
from tesla_plugin.server import create_app
from tesla_plugin.telemetry import Telemetry
from tesla_plugin.triggers import Triggers
from tesla_plugin.trigger_ui import render
from test_mcp_portal import rpc
from test_telemetry_events import Delivery, subscription, payload
from test_trigger_dependencies import observed, item


def test_ready_waiting_blocked_and_disabled_preserve_selection(store, vehicle_ref, clock):
    store.settings = replace(store.settings, live_enabled=True)
    manager = Triggers(store)
    observed(store, vehicle_ref, {'BatteryLevel': {'interval_seconds': 30, 'resend_interval_seconds': 60}})
    Telemetry(store).ingest('V', payload(clock, {'BatteryLevel': 55}))
    assert item(store, vehicle_ref)['operational']['reason'] == 'native_subscription_missing'
    events = Events(store, transport=Delivery())
    subscription(events, vehicle_ref, clock)
    assert item(store, vehicle_ref)['operational']['status'] == 'ready'
    with store.db() as db:
        db.execute('UPDATE vehicles SET checked=?', (clock()-301,))
    assert item(store, vehicle_ref)['operational']['status'] == 'blocked'
    manager.update(vehicle_ref, [], SCOPES, expected_revision=0, automatic_access_checks=True)
    view = manager.view(vehicle_ref, SCOPES)
    battery = next(i for i in view['items'] if i['id'] == 'event:battery_low')
    assert battery['operational']['status'] == 'waiting_for_access'
    assert battery['operational']['label'] in render(view, 'synthetic-csrf', '/tesla')
    assert view['delivery_pipeline']['stages']['processed']['state'] == 'not_observable_by_plugin'
    clock.advance(121)
    assert item(store, vehicle_ref)['operational']['status'] == 'waiting_for_data'
    manager.update(vehicle_ref, [{'trigger_id': 'event:battery_low', 'enabled': False}], SCOPES, expected_revision=1)
    assert item(store, vehicle_ref)['operational']['status'] == 'disabled'
    assert manager.view(vehicle_ref, SCOPES)['collection']['verified']


def test_mcp_operational_filter_and_no_automatic_provider_calls(service, vehicle_ref, headers, fleet):
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        response = rpc(client, headers(), 'tools/call', {'name': 'tesla_list_triggers', 'arguments': {
            'vehicle_ref': vehicle_ref, 'status': 'disabled', 'limit': 100}}).json()['result']
    assert not response.get('isError')
    assert response['structuredContent']['items']
    assert all(i['operational']['status'] == 'disabled' for i in response['structuredContent']['items'])
    assert response['structuredContent']['revision'] == 0
    assert fleet.calls == []


@pytest.mark.parametrize('filters', [
    {'status': 'waiting_for_data'},
    {'category': 'Rules'},
    {'category': 'Rules', 'status': 'waiting_for_data'},
    {'search': 'BatteryLevel'},
    {'selected': False},
    {'needs_attention': True},
    {'search': 'no-such-selector'},
])
def test_trigger_summary_counts_matching_selectors_including_rules_before_pagination(
        service, vehicle_ref, headers, fleet, clock, filters):
    store = service.store
    store.settings = replace(store.settings, live_enabled=True)
    manager = Triggers(store)
    manager.apply_preset(vehicle_ref, 'all', SCOPES, expected_revision=0)
    observed(store, vehicle_ref, {'BatteryLevel': {'interval_seconds': 30, 'resend_interval_seconds': 60}})
    subscription(Events(store, transport=Delivery()), vehicle_ref, clock)
    baseline = manager.view(vehicle_ref, SCOPES)
    assert any(i['id'].startswith('rule:') and i['operational']['status'] == 'waiting_for_data'
               for i in baseline['items'])
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        pages = []
        for offset in (0, 1, 1000):
            result = rpc(client, headers(), 'tools/call', {'name': 'tesla_list_triggers', 'arguments': {
                'vehicle_ref': vehicle_ref, **filters, 'limit': 1, 'offset': offset}}).json()['result']
            assert not result.get('isError')
            page = result['structuredContent']
            assert sum(page['operational_summary'].values()) == page['total']
            assert page['operational_summary_scope'] == 'matching_selectors_before_pagination'
            assert page['catalog_total'] == len(baseline['items'])
            assert sum(page['catalog_operational_summary'].values()) == page['catalog_total']
            assert page['catalog_operational_summary'] == baseline['operational_summary']
            if filters.get('status') and page['total']:
                assert page['operational_summary'] == {filters['status']: page['total']}
            assert page['revision'] == baseline['revision']
            pages.append(page)
    assert pages[0]['operational_summary'] == pages[1]['operational_summary'] == pages[2]['operational_summary']
    assert pages[2]['items'] == [] and pages[2]['next_offset'] is None
    if filters == {'category': 'Rules'}:
        assert pages[0]['total'] == 6
        assert pages[0]['operational_summary']['waiting_for_data'] > 0
    if filters == {'search': 'no-such-selector'}:
        assert pages[0]['total'] == 0 and pages[0]['operational_summary'] == {}
    assert fleet.calls == []
    assert manager.view(vehicle_ref, SCOPES)['revision'] == baseline['revision']


@pytest.mark.parametrize('name,arguments,section,data', [
    ('set_charge_limit', {'percent': 80}, 'charge_state', {'charge_limit_soc': 80}),
    ('door_lock', {}, 'vehicle_state', {'locked': True}),
    ('door_unlock', {}, 'vehicle_state', {'locked': False}),
])
def test_further_effect_checks_use_only_requested_observations(service, vehicle_ref, clock, fleet, name, arguments, section, data):
    intent = service.prepare(name, arguments, vehicle_ref, 'effect-check-'+name, SCOPES)
    service.execute_from_owner(intent['id'])
    assert not service.intent_view(intent['id'])['verification']['effect_observed']
    calls = list(fleet.calls)
    clock.advance(2)
    service._cache(vehicle_ref, {section: data | {'timestamp': clock()*1000}}, 'tesla_live', authorization=fleet.authorization())
    evidence = service.intent_view(intent['id'])['verification']
    assert evidence['effect_observed'] and not evidence['causality_proven']
    assert fleet.calls == calls
    clock.advance(121)
    evidence = service.intent_view(intent['id'])['verification']
    assert evidence['effect_observed'] and not evidence['observation']['fresh']
