"""Owner acquisition controls, cost scenarios and real dispatch boundaries."""
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock
import json
import re

import pytest
from starlette.datastructures import FormData
from starlette.testclient import TestClient

from tesla_plugin.collection import Collection, CREATE, DELETE, collection_enabled, full_profile
from tesla_plugin.cli import consume_step
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.server import create_app
from test_mcp_portal import login
from test_profiles_storage_packages import certificate
from test_telemetry_events import payload
from tesla_plugin.telemetry import Telemetry


@pytest.fixture
def prepared_service(service, settings, tmp_path):
    configured = replace(settings, telemetry_host="telemetry.example", telemetry_ca_file=certificate(tmp_path/"ca.crt"))
    service.settings = configured
    return service


def fields_form(manager, ref, action="configure", **overrides):
    return FormData({"revision": manager.view(ref)["revision"], "request_id": "collection-synthetic-request-01",
                     "collection_action": action, "field": "BatteryLevel", "interval_BatteryLevel": "60",
                     "resend_BatteryLevel": "600", "delta_BatteryLevel": "1", "hours": "8", **overrides})


def test_selection_and_estimate_are_local_and_owner_only(prepared_service, fleet, vehicle_ref):
    service = prepared_service
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        path = "/tesla/owner/collection/"+vehicle_ref
        assert 'Sign in' in client.get(path).text
        csrf = login(client)
        assert "/owner/collection/"+vehicle_ref in client.get("/tesla/owner").text
        for preset, count in (("essential", 4), ("notifications", 7), ("journeys", 11), ("full", 234), ("charging", 9), ("comfort", 8), ("drive_diagnostics", 7)):
            response = client.get(path+"?preset="+preset)
            assert response.status_code == 200
            assert re.search('id="selected-count">'+str(count)+'</output>', response.text)
        data = dict(fields_form(Collection(service), vehicle_ref, "estimate")) | {"csrf": csrf}
        assert client.post(path, data=data, headers={"origin": "https://wrong.example"}).status_code == 400
        assert client.post(path, data={**data, "csrf": "bad"}, headers={"origin": "https://bridge.example"}).status_code == 400
        result = client.post(path, data=data, headers={"origin": "https://bridge.example"})
        assert result.status_code == 200 and 'id="monthly-cost">0.11</output>' in result.text
        assert 'id="signal-count">15870</output>' in result.text
        assert "script-src 'self'" in result.headers["content-security-policy"]
        assert "script-src" not in client.get("/tesla/owner/login").headers["content-security-policy"]
        assert client.get("/tesla/assets/collection.js").headers["content-type"].startswith("text/javascript")
    assert fleet.calls == []
    with service.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM intents").fetchone()[0] == 0


def test_owner_apply_pause_resume_preserves_profile_history_and_triggers(prepared_service, fleet, vehicle_ref, clock):
    service, manager = prepared_service, Collection(prepared_service)
    Telemetry(service.store).ingest("V", payload(clock, {"BatteryLevel": 55}))
    with service.store.db() as db:
        preferences = [tuple(r) for r in db.execute("SELECT * FROM trigger_preferences")]
        samples = [tuple(r) for r in db.execute("SELECT * FROM samples")]
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        csrf = login(client)
        path = "/tesla/owner/collection/"+vehicle_ref
        def post_form(form):
            return client.post(path, data=dict(form) | {"csrf": csrf}, headers={"origin": "https://bridge.example"})
        def confirm(identifier):
            return client.post("/tesla/owner/intents/"+identifier, data={"csrf": csrf, "decision": "execute"}, headers={"origin": "https://bridge.example"})
        response = post_form(fields_form(manager, vehicle_ref))
        assert response.status_code == 200 and 'Confirm collection' in response.text
        assert "0.11 USD" in response.text and "BEGIN CERTIFICATE" not in response.text
        assert not any(name == CREATE for name, *_ in fleet.calls)
        identifier = manager.view(vehicle_ref)["last"]["id"]
        assert confirm(identifier).status_code == 200
        assert collection_enabled(service.store)
        config = service.store.intent(identifier)["arguments"]["config"]
        assert manager.view(vehicle_ref)["state"] == "starting"
        clock.advance(1)
        pause = post_form(fields_form(manager, vehicle_ref, "pause", request_id="collection-synthetic-pause-01"))
        assert 'Confirm pause' in pause.text
        assert not any(name == DELETE for name, *_ in fleet.calls)
        pause_id = manager.view(vehicle_ref)["last"]["id"]
        confirm(pause_id)
        confirm(pause_id)  # replay cannot dispatch twice
        assert sum(name == DELETE for name, *_ in fleet.calls) == 1
        assert not collection_enabled(service.store)
        assert manager.view(vehicle_ref)["state"] == "pausing"
        clock.advance(1)
        assert post_form(fields_form(manager, vehicle_ref, "refresh")).status_code == 200
        assert manager.view(vehicle_ref)["state"] == "paused"
        response = post_form(fields_form(manager, vehicle_ref, "resume", request_id="collection-synthetic-resume-01"))
        assert 'Confirm collection' in response.text
        resumed = service.store.intent(manager.view(vehicle_ref)["last"]["id"])
        assert resumed["arguments"]["config"] == config
        assert sum(name == CREATE for name, *_ in fleet.calls) == 1
        clock.advance(1)
        confirm(resumed["id"])
        assert collection_enabled(service.store)
        assert sum(name == CREATE for name, *_ in fleet.calls) == 2
    with service.store.db() as db:
        assert preferences == [tuple(r) for r in db.execute("SELECT * FROM trigger_preferences")]
        assert samples == [tuple(r) for r in db.execute("SELECT * FROM samples")]
    assert not any(name in ("vehicle_wake_up", "vehicle_vehicle_data") for name, *_ in fleet.calls)


def test_stale_tabs_pending_work_and_request_replay(prepared_service, vehicle_ref, clock):
    service, manager = prepared_service, Collection(prepared_service)
    old = fields_form(manager, vehicle_ref)
    first = manager.prepare(vehicle_ref, old, SCOPES)
    assert manager.prepare(vehicle_ref, old, SCOPES)["id"] == first["id"]
    with pytest.raises(TeslaError, match="changed"):
        manager.prepare(vehicle_ref, FormData({**dict(old), "request_id": "another-stale-form-request"}), SCOPES)
    with pytest.raises(TeslaError, match="pending"):
        manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref, "pause", request_id="another-current-pause-request"), SCOPES)
    with pytest.raises(TeslaError, match="pending telemetry"):
        service.prepare(DELETE, {}, vehicle_ref, "different-synthetic-request", SCOPES)
    again = service.prepare_profile(vehicle_ref, "custom", first["arguments"]["config"]["fields"], "collection-synthetic-request-01", SCOPES)
    assert again["id"] == first["id"]
    clock.advance(service.settings.intent_ttl_seconds+1)
    assert not manager.view(vehicle_ref)["blocked"]


@pytest.mark.parametrize("overrides", [
    {"field": "invalid"}, {"hours": "nan"}, {"hours": "25"}, {"hours": "0"},
    {"interval_BatteryLevel": "0"}, {"interval_BatteryLevel": "bad"}, {"interval_BatteryLevel": "2.5"},
    {"resend_BatteryLevel": "20"}, {"delta_BatteryLevel": "-1"},
])
def test_invalid_forms_do_not_touch_provider(prepared_service, fleet, vehicle_ref, overrides):
    manager = Collection(prepared_service)
    with pytest.raises(TeslaError):
        manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref, **overrides), SCOPES)
    assert fleet.calls == []


def test_readback_and_disconnect_cannot_claim_an_unverified_pause(prepared_service, fleet, vehicle_ref, clock, monkeypatch):
    service, manager = prepared_service, Collection(prepared_service)
    item = manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref), SCOPES)
    service.execute_from_owner(item["id"])
    config = item["arguments"]["config"]
    clock.advance(1)
    original = fleet.call
    monkeypatch.setattr(fleet, "call", lambda name, *a, **kw: {"config": config, "synced": False} if name.endswith("config_get") else original(name, *a, **kw))
    manager.refresh(vehicle_ref, SCOPES)
    assert manager.view(vehicle_ref)["state"] == "syncing"
    clock.advance(1)
    monkeypatch.setattr(fleet, "call", lambda name, *a, **kw: {"config": config, "synced": True} if name.endswith("config_get") else original(name, *a, **kw))
    manager.refresh(vehicle_ref, SCOPES)
    assert manager.view(vehicle_ref)["state"] == "active"
    clock.advance(1)
    pause = manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref, "pause", request_id="uncertain-pause-request-01"), SCOPES)
    def failed(name, *a, **kw):
        if name == DELETE or name.endswith("config_get"):
            raise TeslaError("OUTCOME_UNKNOWN", "synthetic timeout", uncertain=True)
        return original(name, *a, **kw)
    monkeypatch.setattr(fleet, "call", failed)
    assert service.execute_from_owner(pause["id"])["status"] == "unknown"
    assert manager.view(vehicle_ref)["state"] == "unknown"
    assert collection_enabled(service.store)  # local idle != provider suspension
    with pytest.raises(TeslaError):
        manager.refresh(vehicle_ref, SCOPES)
    assert manager.view(vehicle_ref)["state"] == "unknown"
    clock.advance(1)
    monkeypatch.setattr(fleet, "call", original)  # fake GET reports synced null config
    manager.refresh(vehicle_ref, SCOPES)
    assert service.store.intent(pause["id"])["result"]["configuration_verified"]
    assert manager.view(vehicle_ref)["state"] == "paused"
    assert not collection_enabled(service.store)


def test_consumer_does_not_poll_tesla_until_configured_and_receiving(store, clock, vehicle_ref, monkeypatch):
    monkeypatch.setattr("tesla_plugin.cli.time.sleep", lambda _: None)
    consumer, telemetry, fleet = Mock(), Mock(), Mock()
    assert consume_step(store, consumer, telemetry, fleet, None) is None
    assert not consumer.mock_calls and not fleet.mock_calls
    store.snapshot(vehicle_ref, "telemetry_target", {"fields": {"BatteryLevel": {"interval_seconds": 60}}}, "local_configuration", clock())
    consumer.poll.return_value = {}
    assert consume_step(store, consumer, telemetry, fleet, None) is None
    assert not fleet.mock_calls
    consumer.poll.return_value = {"partition": []}
    checked = consume_step(store, consumer, telemetry, fleet, None)
    assert fleet.discover.call_count == 1 and fleet.oauth.access_token.call_count == 1
    assert consume_step(store, consumer, telemetry, fleet, checked) == checked
    assert fleet.discover.call_count == 1
    clock.advance(1)
    store.snapshot(vehicle_ref, "telemetry_target", None, "local_configuration", clock())
    consumer.reset_mock(); fleet.reset_mock()
    consume_step(store, consumer, telemetry, fleet, checked)
    assert not consumer.mock_calls and not fleet.mock_calls


def test_full_profile_includes_all_documented_fields_and_required_delta():
    from tesla_plugin.profiles import profile_fields
    assert len(full_profile()) == 252
    assert profile_fields("custom", full_profile())["SelfDrivingMilesSinceReset"]["minimum_delta"] == 1


def test_different_or_invalid_readback_never_resolves_uncertain_configuration(prepared_service, fleet, vehicle_ref, clock, monkeypatch):
    service, manager = prepared_service, Collection(prepared_service)
    item = manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref), SCOPES)
    with service.store.db() as db:
        db.execute("UPDATE intents SET status='unknown' WHERE id=?", (item["id"],))
    config = item["arguments"]["config"]
    different = {**config, "fields": {"BatteryLevel": {"interval_seconds": 10}}}
    monkeypatch.setattr(fleet, "call", lambda *a, **kw: {"synced": True, "config": different})
    manager.refresh(vehicle_ref, SCOPES)
    assert service.store.intent(item["id"])["status"] == "unknown"
    clock.advance(1)
    monkeypatch.setattr(fleet, "call", lambda *a, **kw: {"synced": "true", "config": None})
    with pytest.raises(TeslaError, match="Invalid telemetry"):
        manager.refresh(vehicle_ref, SCOPES)
    assert service.store.intent(item["id"])["status"] == "unknown"
    monkeypatch.setattr(fleet, "call", lambda *a, **kw: {"synced": True, "config": config})
    manager.refresh(vehicle_ref, SCOPES)
    assert service.store.intent(item["id"])["status"] == "reconciled"
    assert service.intent_view(item["id"])["verification"]["command_accepted"] is False
    assert collection_enabled(service.store)


def test_historical_estimate_keeps_its_own_hours(prepared_service, vehicle_ref, clock):
    from tesla_plugin.collection_ui import review
    service, manager = prepared_service, Collection(prepared_service)
    first = manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref, hours="20"), SCOPES)
    with service.store.db() as db:
        db.execute("UPDATE intents SET status='cancelled' WHERE id=?", (first["id"],))
    clock.advance(1)
    manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref, hours="4", request_id="second-cost-scenario-01"), SCOPES)
    assert '20 hours/day' in review(first, service.store, service.settings)


def test_missing_grant_stops_collection_change_before_dispatch(prepared_service, fleet, vehicle_ref):
    manager = Collection(prepared_service)
    with pytest.raises(TeslaError, match="Required plugin permissions"):
        manager.prepare(vehicle_ref, fields_form(manager, vehicle_ref), ["tesla:read"])
    assert fleet.calls == []
