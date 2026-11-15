"""Offline regressions for the independently reproduced November UI audit."""
from dataclasses import asdict, replace
import json
import os
import re

import pytest
from starlette.testclient import TestClient

from tesla_plugin.cli import main
from tesla_plugin.collection import Collection
from tesla_plugin.dashboard import history, park_panel, chart_paths, reduce_path
from tesla_plugin.overview_ui import route_panel
from tesla_plugin.route_evidence import view as route_view
from tesla_plugin.server import create_app
from tesla_plugin.service import Service
from tesla_plugin.telemetry import Telemetry
from test_collection import prepared_service, fields_form
from test_mcp_portal import login
from test_owner_browser import run_browser
from test_route_geometry import route
from test_telemetry_events import payload


def test_estimate_preserves_stale_draft_and_rejects_revision_adoption(prepared_service, vehicle_ref, clock, fleet):
    service, manager = prepared_service, Collection(prepared_service)
    old = dict(fields_form(manager, vehicle_ref, 'estimate'))
    clock.advance(1)
    service.store.snapshot(vehicle_ref, 'telemetry_saved', {'fields': {'BatteryLevel': {'interval_seconds': 1800},
        'Locked': {'interval_seconds': 300}}}, 'owner_request', clock())
    current = manager.view(vehicle_ref)['revision']
    assert old['revision'] != current
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        csrf = login(client)
        result = client.post('/tesla/owner/collection/'+vehicle_ref, data=old | {'csrf': csrf},
                             headers={'origin': 'https://bridge.example'})
    assert result.status_code == 409
    editor = result.text.split('id="collection-editor"', 1)[1]
    assert 'name="revision" value="'+old['revision']+'"' in editor
    assert 'name="interval_BatteryLevel"' in editor and 'value="60"' in editor
    assert 'value="configure" disabled' in editor
    assert 'Reload current profile' in result.text
    with service.store.db() as db:
        assert db.execute('SELECT COUNT(*) FROM intents').fetchone()[0] == 0
    assert fleet.calls == []


def test_normal_alias_uses_same_alert_defaults_as_domain(prepared_service, vehicle_ref):
    with TestClient(create_app(prepared_service.settings, service=prepared_service, start_worker=False), base_url='https://bridge.example') as client:
        login(client)
        result = client.get('/tesla/owner/collection/'+vehicle_ref+'?preset=normal')
    assert result.status_code == 200
    assert re.search(r'name="customer_alerts"[^>]* checked', result.text)
    assert Collection(prepared_service).scenario('normal')['customer_alerts'] is True


def test_estimate_without_draft_revision_cannot_create_fresh_token(prepared_service, vehicle_ref):
    form = dict(fields_form(Collection(prepared_service), vehicle_ref, 'estimate'))
    del form['revision']
    with TestClient(create_app(prepared_service.settings, service=prepared_service, start_worker=False), base_url='https://bridge.example') as client:
        csrf = login(client)
        result = client.post('/tesla/owner/collection/'+vehicle_ref, data=form | {'csrf': csrf},
                             headers={'origin': 'https://bridge.example'})
    assert result.status_code == 400 and 'Draft revision missing' in result.text
    assert 'id="collection-editor"' not in result.text


def dense_samples(store, vehicle_ref, now, count=3600):
    with store.db() as db:
        db.executemany('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)', [
            (f'ui-dense-{i}', vehicle_ref, 'BatteryLevel', json.dumps(50 if i < 2000 else 90),
             now-3600+i, now-3600+i, 'valid', 'synthetic') for i in range(count)])


def test_dense_history_covers_full_hour_and_preserves_latest(store, vehicle_ref, clock):
    dense_samples(store, vehicle_ref, clock())
    page = history(store, vehicle_ref, 'UTC')
    assert 'Last hour · 50–90 %' in page
    assert '3600 samples' in page and 'full hour' in page
    lines = re.findall(r'<polyline class="chart-line" points="([^"]+)"', page)
    assert any(float(point.split(',')[1]) == 45 for line in lines for point in line.split())
    assert any(float(point.split(',')[0]) > 761 for line in lines for point in line.split())
    assert sum(len(line.split()) for line in lines) < 3600


@pytest.mark.parametrize('zone', ['Mars/Olympus', '', '../UTC', '/etc/passwd', None, 123])
def test_configuration_rejects_invalid_timezone_before_render(settings, zone):
    with pytest.raises(ValueError, match='timezone'):
        replace(settings, timezone=zone)


def test_check_config_rejects_invalid_timezone(settings, tmp_path, capsys):
    config = tmp_path/'config.json'
    config.write_text(json.dumps(asdict(settings) | {'timezone': 'Mars/Olympus'}, default=str))
    assert main(['check-config', '--config', str(config)]) == 1
    assert 'configuration_valid' not in capsys.readouterr().out


def test_park_and_route_export_expiry_without_changing_guard(store, vehicle_ref, clock):
    Telemetry(store).ingest('V', payload(clock, {'Gear': 'ShiftStateP', 'RouteLine': route()}))
    park = park_panel(store, vehicle_ref, 'UTC')
    geometry = route_panel(route_view(store, vehicle_ref, location_allowed=True), 'UTC')
    assert float(re.search('data-evidence-expires-in="([^"]+)"', park).group(1)) == pytest.approx(15, abs=.001)
    assert float(re.search('data-evidence-expires-in="([^"]+)"', geometry).group(1)) == pytest.approx(120, abs=.001)
    assert 'Assessment at page load' in park


def test_operating_context_expires_with_its_oldest_usable_signal(store, vehicle_ref, clock):
    Telemetry(store).ingest('V', payload(clock, {'Gear': None, 'DriveRail': False}, when=clock()-29))
    page = park_panel(store, vehicle_ref, 'UTC')
    assert float(re.search('data-evidence-expires-in="([^"]+)"', page).group(1)) == pytest.approx(1, abs=.001)


def test_chart_reduction_keeps_spikes_endpoints_and_quality_breaks():
    rows = [{'source_at': i, 'value': json.dumps(2 if i == 4 else 98 if i == 5 else 60),
             'quality': 'invalid' if i == 6 else 'valid'} for i in range(20)]
    paths = chart_paths(rows)
    assert len(paths) == 2
    reduced = [reduce_path(path, 0) for path in paths]
    assert reduced[0] == [(0, 60), (4, 2), (5, 98)]
    assert reduced[1][0] == (7, 60) and reduced[1][-1] == (19, 60)
    assert all(not any(at < 6 for at, _ in path) or not any(at > 6 for at, _ in path) for path in reduced)


@pytest.mark.parametrize('zone', ['UTC', 'Europe/Amsterdam', 'America/New_York'])
def test_supported_timezone_renders_configuration(settings, zone):
    assert replace(settings, timezone=zone).timezone == zone


def test_owner_incomplete_collection_can_cancel_but_not_confirm(prepared_service, vehicle_ref):
    manager = Collection(prepared_service)
    item = manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref), prepared_service.settings.allowed_scopes)
    with prepared_service.store.db() as db:
        db.execute('DELETE FROM snapshots WHERE vehicle=? AND section=?', (vehicle_ref, 'telemetry_preview_'+item['id']))
    with TestClient(create_app(prepared_service.settings, service=prepared_service, start_worker=False), base_url='https://bridge.example') as client:
        csrf = login(client)
        page = client.get('/tesla/owner/intents/'+item['id'])
        assert page.status_code == 200
        assert 'Review unavailable' in page.text
        assert 'Confirm collection' not in page.text and 'Cancel' in page.text
        assert '8 hours/day' not in page.text
        overview = client.get('/tesla/owner')
        assert 'Incomplete review' in overview.text
        assert 'Nothing awaiting confirmation' in overview.text
        response = client.post('/tesla/owner/intents/'+item['id'], data={'csrf': csrf, 'decision': 'cancel'},
                               headers={'origin': 'https://bridge.example'})
        assert response.status_code == 200
    assert prepared_service.store.intent(item['id'])['status'] == 'cancelled'


@pytest.mark.integration
def test_browser_audit_freshness_and_full_history(settings, fleet, store, clock, vehicle_ref, signing_key, tmp_path):
    settings = replace(settings, public_url='https://tesla.localhost/tesla/mcp',
                       tesla_redirect_uri='https://tesla.localhost/tesla/oauth/callback')
    service = Service(settings, store=store, fleet=fleet)
    dense_samples(store, vehicle_ref, clock())
    Telemetry(store).ingest('V', payload(clock, {'BatteryLevel': 90, 'Gear': 'ShiftStateP', 'RouteLine': route()}))
    result = run_browser(settings, service, signing_key, tmp_path, 'audit-regressions-browser.js', {
        'results': os.environ.get('PLUGINS_TEST_RESULTS_DIR')})
    assert result == {'external_requests': 0, 'requests_during_aging': 0, 'park_expired': True, 'route_expired': True}
    assert fleet.calls == []
