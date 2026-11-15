"""A completed MCP call is not proof that Tesla accepted a collection change."""
from copy import deepcopy

import pytest
from starlette.testclient import TestClient

from tesla_plugin.collection import Collection, CREATE, DELETE
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.server import create_app
from test_collection import prepared_service, fields_form
from test_mcp_portal import rpc
from test_shared_settings import call


@pytest.mark.parametrize('action', ['configure', 'pause', 'resume'])
@pytest.mark.parametrize('uncertain', [False, True])
def test_failed_collection_confirmation_is_mcp_error_without_replay(
        prepared_service, fleet, vehicle_ref, headers, clock, monkeypatch, action, uncertain):
    manager = Collection(prepared_service)
    previous = manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref), SCOPES)
    prepared_service.execute_from_owner(previous['id'])
    baseline = deepcopy(manager.view(vehicle_ref)['saved'])
    clock.advance(1)
    original_call = fleet.call
    dispatches = []

    def failing_dispatch(name, *args, **kwargs):
        if name in (CREATE, DELETE):
            dispatches.append(name)
            raise TeslaError('OUTCOME_UNKNOWN' if uncertain else 'PROVIDER_ERROR',
                             'Synthetic provider outcome', http_status=503 if uncertain else 400,
                             uncertain=uncertain)
        return original_call(name, *args, **kwargs)

    monkeypatch.setattr(fleet, 'call', failing_dispatch)
    options = {'preset': 'essential'} if action == 'configure' else {}
    with TestClient(create_app(prepared_service.settings, service=prepared_service,
                               start_worker=False), base_url='https://bridge.example') as client:
        review = call(client, headers(), 'tesla_prepare_collection', vehicle_ref=vehicle_ref,
                      action=action, expected_revision=manager.view(vehicle_ref)['revision'],
                      client_request_id='synthetic-collection-outcome-request', **options)
        arguments = dict(vehicle_ref=vehicle_ref, intent_id=review['intent_id'],
                         review_digest=review['review_digest'], decision='confirm')
        for _ in range(2):
            result = rpc(client, headers(), 'tools/call', {
                'name': 'tesla_confirm_collection', 'arguments': arguments}).json()['result']
            assert result['structuredContent']['status'] == ('unknown' if uncertain else 'rejected')
            assert result['isError'] is True
        # Reading the retained result succeeds; it is not a new execution.
        observed = call(client, headers(), 'tesla_get_collection', vehicle_ref=vehicle_ref)
        assert observed['last_request']['status'] == ('unknown' if uncertain else 'rejected')
    assert dispatches == [DELETE if action == 'pause' else CREATE]
    assert manager.view(vehicle_ref)['saved'] == baseline
