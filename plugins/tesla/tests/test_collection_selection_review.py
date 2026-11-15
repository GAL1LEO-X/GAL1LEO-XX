"""Qualification exclusions belong to the immutable confirmation, not only quotes."""
from copy import deepcopy
import json

import pytest
from starlette.testclient import TestClient

from tesla_plugin.collection import Collection, CREATE
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.server import create_app
from test_collection import prepared_service
from test_mcp_portal import login
from test_shared_settings import call


def test_full_mcp_confirmation_retains_exclusions_and_unqualified_warnings(prepared_service, vehicle_ref, headers, fleet):
    service = prepared_service
    service.store.snapshot(vehicle_ref, 'vehicle_config', {'car_type': 'modely'}, 'synthetic', service.store.clock())
    manager = Collection(service)
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        result = call(client, headers(), 'tesla_prepare_collection', vehicle_ref=vehicle_ref,
                      action='configure', preset='full', expected_revision=manager.view(vehicle_ref)['revision'],
                      client_request_id='full-qualified-review-synthetic')
        selection = result['selection_review']
        assert selection['context']['model'] == 'ModelY'
        assert len(selection['excluded']) == 18
        assert any(i['field'] == 'LifetimeEnergyUsedDrive' for i in selection['excluded'])
        assert any('field_semantics_not_documented' in i['reasons'] for i in selection['warnings'])
        assert len(result['fields']) == 234
        login(client)
        page = client.get('/tesla/owner/intents/'+result['intent_id'])
        assert page.status_code == 200
        assert 'selection-review' in page.text and '18 excluded fields with reasons' in page.text
        assert 'LifetimeEnergyUsedDrive' in page.text
    assert not any(name == CREATE for name, *_ in fleet.calls)


@pytest.mark.parametrize('status', ['cancelled', 'rejected', 'acknowledged', 'unknown'])
def test_terminal_intent_keeps_its_original_qualification_and_cost(prepared_service, vehicle_ref, clock, fleet, status):
    service = prepared_service
    service.store.snapshot(vehicle_ref, 'vehicle_config', {'car_type': 'modely'}, 'synthetic', clock())
    key = 'terminal-full-selection-synthetic'
    first = service.prepare_profile(vehicle_ref, 'full', None, key, SCOPES)
    with service.store.db() as db:
        db.execute('UPDATE intents SET status=? WHERE id=?', (status, first['id']))
    clock.advance(1)
    again = service.prepare_profile(vehicle_ref, 'full', None, key, SCOPES, active_hours_per_day=4)
    assert again['id'] == first['id'] and again['status'] == status
    assert again['selection_review'] == first['selection_review']
    assert again['estimate'] == first['estimate']
    assert not any(name == CREATE for name, *_ in fleet.calls)


def test_qualification_review_is_frozen_on_idempotent_prepare_and_bound_to_digest(prepared_service, vehicle_ref, clock, fleet):
    service = prepared_service
    service.store.snapshot(vehicle_ref, 'vehicle_config', {'car_type': 'modely'}, 'synthetic', clock())
    manager = Collection(service)
    key = 'immutable-full-selection-synthetic'
    first = service.prepare_profile(vehicle_ref, 'full', None, key, SCOPES)
    original = manager.review(vehicle_ref, first['id'])
    assert first['selection_review'] == original['selection_review']
    clock.advance(1)
    # The fleet capability observation time can change without changing fields.
    again = service.prepare_profile(vehicle_ref, 'full', None, key, SCOPES)
    assert again['id'] == first['id']
    assert again['selection_review'] == original['selection_review']
    assert manager.review(vehicle_ref, first['id'])['review_digest'] == original['review_digest']
    # A changed cost assumption must still conflict, rather than be ignored.
    with pytest.raises(TeslaError, match='cost scenario'):
        service.prepare_profile(vehicle_ref, 'full', None, key, SCOPES, active_hours_per_day=4)
    with service.store.db() as db:
        row = db.execute('SELECT data FROM snapshots WHERE vehicle=? AND section=?',
                         (vehicle_ref, 'telemetry_preview_'+first['id'])).fetchone()
    preview = json.loads(row[0])
    altered = deepcopy(preview)
    altered['selection_review']['warnings'] = []
    service.store.snapshot(vehicle_ref, 'telemetry_preview_'+first['id'], altered, 'synthetic', clock())
    assert manager.review(vehicle_ref, first['id'])['review_digest'] != original['review_digest']
    with pytest.raises(TeslaError):
        manager.resolve(vehicle_ref, first['id'], original['review_digest'], 'confirm', SCOPES)
    assert not any(name == CREATE for name, *_ in fleet.calls)
