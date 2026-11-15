"""Consolidated owner evidence and reviewed windows, with synthetic data only."""
from dataclasses import replace
import json
import os
import re

import pytest
from starlette.testclient import TestClient

from tesla_plugin.collection import Collection, CREATE
from tesla_plugin.config import SCOPES
from tesla_plugin.dashboard import render, history
from tesla_plugin.overview_ui import route_panel
from tesla_plugin.portal import command_evidence
from tesla_plugin.route_evidence import view as route_view
from tesla_plugin.server import create_app
from tesla_plugin.service import Service
from tesla_plugin.telemetry import Telemetry
from test_mcp_portal import login
from test_owner_browser import run_browser
from test_profiles_storage_packages import certificate
from test_route_geometry import route, encoded_points
from test_telemetry_events import payload
from test_trigger_dependencies import observed
from test_spatial_data_permissions import change_grant, SYNTHETIC_LOCATION


def dashboard(store, ref):
    return render(store, ref, 'UTC', name='Synthetic', state='online', base='/tesla')


def test_invalid_latest_never_replaces_current_with_last_valid(store, vehicle_ref, clock):
    telemetry = Telemetry(store)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 66}, when=clock()-600))
    telemetry.ingest('V', payload(clock, {'BatteryLevel': None}))
    page = dashboard(store, vehicle_ref)
    assert 'Unavailable' in re.search(r'<p class="charge-value">(.*?)</p>', page).group(1)
    assert 'Invalid value' in page and 'Last valid value · historical</strong>: 66' in page
    assert 'Telemetry' in page and 'invalid' in page


def test_stale_and_future_are_distinct_from_a_recent_value(store, vehicle_ref, clock):
    Telemetry(store).ingest('V', payload(clock, {'BatteryLevel': 66}, when=clock()-601))
    page = dashboard(store, vehicle_ref)
    assert 'Historical · 10 min ago' in page
    assert 'Tesla vehicle list: Online · read 0 s ago' in page
    with store.db() as db:
        db.execute("UPDATE latest SET source_at=? WHERE vehicle=? AND field='BatteryLevel'", (clock()+5, vehicle_ref))
    page = dashboard(store, vehicle_ref)
    assert 'Future timestamp' in page and 'Source not recorded' in page
    assert 'Unavailable' in re.search(r'<p class="charge-value">(.*?)</p>', page).group(1)


def test_battery_chart_does_not_plot_contradictory_same_time_samples(store, vehicle_ref, clock):
    telemetry = Telemetry(store)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 60}))
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 80}))
    page = history(store, vehicle_ref, 'UTC')
    assert '<polyline' not in page and 'No valid data' in page


def test_route_permissions_staleness_and_no_external_map(store, vehicle_ref, clock):
    Telemetry(store).ingest('V', payload(clock, {'RouteLine': route()}))
    assert route_panel(route_view(store, vehicle_ref, location_allowed=False), 'UTC') == ''
    page = route_panel(route_view(store, vehicle_ref, location_allowed=True), 'UTC')
    assert 'class="route-sketch"' in page and 'Partial trace' in page and 'https://' not in page
    clock.advance(301)
    page = route_panel(route_view(store, vehicle_ref, location_allowed=True), 'UTC')
    assert 'class="route-sketch"' not in page and 'not presented as a current route' in page


def test_command_evidence_distinguishes_acceptance_from_observation(clock):
    item = {'status': 'acknowledged', 'verification': {'command_accepted': True, 'effect_observed': False}}
    page = command_evidence(item, 'UTC')
    assert 'Sent' in page and 'Accepted by Tesla' in page and 'Effect unverified' in page
    item['verification'].update(effect_observed=True, observation={'source': 'tesla_live', 'source_timestamp': clock(), 'age_seconds': 0})
    page = command_evidence(item, 'UTC')
    assert 'Effect observed after the command' in page and 'does not prove current state or causality' in page


@pytest.mark.integration
def test_browser_evidence_route_and_temporary_review(settings, fleet, store, clock, vehicle_ref, signing_key, tmp_path):
    settings = replace(settings, public_url='https://tesla.localhost/tesla/mcp',
        tesla_redirect_uri='https://tesla.localhost/tesla/oauth/callback',
        telemetry_host='telemetry.example', telemetry_ca_file=certificate(tmp_path/'ca.crt'))
    service = Service(settings, store=store, fleet=fleet)
    baseline = observed(store, vehicle_ref, {'BatteryLevel': {'interval_seconds': 600, 'resend_interval_seconds': 1200, 'minimum_delta': 2, 'include_fields': ['Locked']}})
    store.snapshot(vehicle_ref, 'telemetry_saved', baseline, 'owner_request', clock())
    store.snapshot(vehicle_ref, 'telemetry_target', baseline, 'owner_request', clock())
    telemetry = Telemetry(store)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 66}, when=clock()-600))
    telemetry.ingest('V', payload(clock, {'InsideTemp': 19}, when=clock()-601))
    telemetry.ingest('V', payload(clock, {'BatteryLevel': None, 'Locked': True,
        'OutsideTemp': 12, 'Version': '2026.synthetic', 'DetailedChargeState': 'DetailedChargeStateDisconnected',
        'RouteLine': route(encoded_points([(0, 0), (1000, 2000), (2500, 1500), (3000, 3000)]))}))
    result = run_browser(settings, service, signing_key, tmp_path, 'v1-browser.js', {
        'vehicle_ref': vehicle_ref, 'results': os.environ.get('PLUGINS_TEST_RESULTS_DIR')})
    assert result == {'external_requests': 0, 'evidence_reviewed': True, 'temporary_reviewed': True}
    assert sum(name == CREATE for name, *_ in fleet.calls) == 1
    temporary = Collection(service).view(vehicle_ref)['temporary_collection']
    assert temporary['status'] == 'active' and temporary['duration_seconds'] == 3600
    assert temporary['baseline']['fields'] == baseline['fields']


def test_owner_route_is_removed_after_location_scope_loss(service, store, clock, vehicle_ref):
    Telemetry(store).ingest('V', payload(clock, {'RouteLine': route()}))
    service.settings = replace(service.settings, allowed_scopes=tuple(s for s in SCOPES if s != 'tesla:location'))
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        login(client)
        page = client.get('/tesla/owner')
    assert page.status_code == 200 and 'route-sketch' not in page.text and 'Received route' not in page.text


@pytest.mark.parametrize('field', ['BatteryLevel', 'Locked', 'InsideTemp', 'OutsideTemp', 'Version', 'DetailedChargeState'])
@pytest.mark.parametrize('position', ['current', 'historical'])
@pytest.mark.parametrize('mode', ['hide_private', 'tesla_scope', 'mcp_scope', 'allowed'])
def test_scalar_cards_never_expose_legacy_structures(service, store, clock, vehicle_ref, fleet, field, position, mode):
    """Exercise the authenticated owner HTML, including closed disclosures."""
    spatial = {'unexpected': [SYNTHETIC_LOCATION]}
    row = ('legacy-scalar', vehicle_ref, field, json.dumps(spatial), clock()-2, clock()-2, 'valid', 'synthetic')
    with store.db() as db:
        db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)', row)
        latest = row[1:] if position == 'current' else (vehicle_ref, field, 'null', clock(), clock(), 'invalid', 'synthetic')
        db.execute('INSERT OR REPLACE INTO latest VALUES(?,?,?,?,?,?,?)', latest)
    change_grant(store, mode)
    if mode == 'mcp_scope':
        service.settings = replace(service.settings, allowed_scopes=tuple(scope for scope in SCOPES if scope != 'tesla:location'))
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        login(client)
        response = client.get('/tesla/owner')
    assert response.status_code == 200
    assert all(marker not in response.text for marker in ('10.125', '20.875', 'latitude', 'longitude', 'unexpected'))
    assert 'Format cannot be displayed in this card' in response.text
    with store.db() as db:
        assert json.loads(db.execute('SELECT value FROM samples WHERE id=?', (row[0],)).fetchone()[0]) == spatial
    assert fleet.calls == []
