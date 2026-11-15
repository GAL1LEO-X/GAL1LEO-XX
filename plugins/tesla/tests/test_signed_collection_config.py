"""Signed provider readbacks preserve settings without false collection drift."""
from copy import deepcopy
import socket

import pytest

from tesla_plugin.collection import Collection
from tesla_plugin.collection_state import matches_config
from tesla_plugin.config import SCOPES
from tesla_plugin.profiles import estimate
from tesla_plugin.temporary_collection import CHECK_SECONDS, TemporaryCollection, same_config
from test_collection import prepared_service
from test_temporary_collection import temporary_setup, prepare as prepare_temporary, writes


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Signed config tests prohibit network connections")
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


def config():
    return {"hostname": "telemetry.example", "port": 8443, "ca": "synthetic-ca",
            "delivery_policy": "latest", "alert_types": ["customer"],
            "fields": {"BatteryLevel": {"interval_seconds": 60, "minimum_delta": 1,
                                        "resend_interval_seconds": 600,
                                        "include_fields": ["ChargeLimitSoc"]}}}


def signed(value):
    return {**deepcopy(value), "aud": "com.tesla.fleet.TelemetryClient", "iss": "synthetic-public-issuer"}


@pytest.mark.parametrize("compare", [matches_config, same_config])
@pytest.mark.parametrize("claims", [{"aud": "com.tesla.fleet.TelemetryClient"},
                                   {"iss": "synthetic-public-issuer"},
                                   {"aud": "com.tesla.fleet.TelemetryClient", "iss": "synthetic-public-issuer"}])
def test_signing_claims_do_not_change_settings_or_inputs(compare, claims):
    expected = config()
    observed = {**deepcopy(expected), **claims}
    originals = deepcopy((expected, observed))
    assert compare(expected, observed)
    assert compare(observed, expected)
    assert (expected, observed) == originals
    # The signer rewrites claims even when a baseline was itself a readback.
    assert compare(observed, signed(expected))
    assert compare({**expected, "iss": "previous-synthetic-issuer"}, signed(expected))


CHANGES = [
    (("hostname",), "other.example"), (("port",), 9443), (("ca",), "other-synthetic-ca"),
    (("delivery_policy",), "all"), (("alert_types",), []), (("future_option",), True),
    (("fields", "BatteryLevel", "interval_seconds"), 30),
    (("fields", "BatteryLevel", "resend_interval_seconds"), 300),
    (("fields", "BatteryLevel", "minimum_delta"), 2),
    (("fields", "BatteryLevel", "include_fields"), []),
    (("fields", "BatteryLevel", "future_option"), True),
    (("fields", "BatteryLevel", "aud"), "nested-option"),
    (("fields", "BatteryLevel", "iss"), "nested-option"),
    (("fields", "Locked"), {"interval_seconds": 15}),
]


@pytest.mark.parametrize("compare", [matches_config, same_config])
@pytest.mark.parametrize("path,value", CHANGES)
def test_signing_claims_never_hide_real_settings_changes(compare, path, value):
    expected, observed = config(), signed(config())
    parent = observed
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    assert not compare(expected, observed)
    assert not compare(observed, expected)


@pytest.mark.parametrize("compare", [matches_config, same_config])
def test_signing_metadata_does_not_turn_missing_config_into_paused(compare):
    assert compare(None, None)
    assert not compare(config(), None)
    assert not compare(None, signed(config()))
    assert not compare(None, {"aud": "com.tesla.fleet.TelemetryClient"})
    expected, observed = config(), signed(config())
    del observed["fields"]["BatteryLevel"]["minimum_delta"]
    assert not compare(expected, observed)


@pytest.mark.parametrize("status", ["acknowledged", "unknown"])
@pytest.mark.parametrize("drift", [False, True])
def test_signed_readback_public_state_and_uncertain_reconciliation(
        prepared_service, vehicle_ref, fleet, clock, monkeypatch, status, drift):
    service, manager = prepared_service, Collection(prepared_service)
    item = manager.prepare_change(vehicle_ref, "configure", manager.view(vehicle_ref)["revision"],
                                  "synthetic-signed-config-01", SCOPES, preset="custom",
                                  custom_fields={"BatteryLevel": {"interval_seconds": 60}})
    service.execute_from_owner(item["id"])
    if status == "unknown":
        with service.store.db() as db:
            db.execute("UPDATE intents SET status='unknown' WHERE id=?", (item["id"],))
    expected = deepcopy(item["arguments"]["config"])
    observed = signed(expected)
    if drift:
        observed["fields"]["BatteryLevel"]["minimum_delta"] = 2
    original = fleet.call
    def provider(name, *args, **kwargs):
        result = original(name, *args, **kwargs)
        return {"synced": True, "config": deepcopy(observed)} if name.endswith("config_get") else result
    monkeypatch.setattr(fleet, "call", provider)
    clock.advance(1)
    before = len(fleet.calls)
    manager.refresh(vehicle_ref, SCOPES)
    view = manager.public_view(vehicle_ref, SCOPES)
    assert view["evidence"]["provider_synced"] is True
    assert view["evidence"]["configuration_matches_target"] is (not drift)
    assert view["state"] == ("unknown" if status == "unknown" and drift else "mismatch" if drift else "active")
    assert service.store.intent(item["id"])["status"] == ("reconciled" if status == "unknown" and not drift else status)
    assert manager.view(vehicle_ref)["remote"]["data"]["config"] == observed
    assert manager.view(vehicle_ref)["saved"] == expected
    assert service.store.intent(item["id"])["arguments"]["config"] == expected
    assert [name for name, *_ in fleet.calls[before:]] == ["vehicle_fleet_telemetry_config_get"]
    comparison = manager.cost_comparison(vehicle_ref, {"estimate": estimate(expected["fields"], 8)})
    assert comparison["baseline_applied_verified"] is (not drift)


@pytest.mark.parametrize("drift", [False, True])
def test_signed_temporary_baseline_restoration_preserves_drift_guard(
        temporary_setup, vehicle_ref, clock, fleet, monkeypatch, drift):
    service, manager, remote, provider = temporary_setup
    original_baseline = deepcopy(remote["config"])
    def signed_provider(name, *args, **kwargs):
        result = provider(name, *args, **kwargs)
        if name.endswith("config_get") and result["config"] is not None:
            result["config"] = signed(result["config"])
        return result
    monkeypatch.setattr(fleet, "call", signed_provider)
    clock.advance(1)
    manager.refresh(vehicle_ref, SCOPES)
    item = prepare_temporary(temporary_setup, vehicle_ref)
    review = manager.review(vehicle_ref, item["id"])
    assert not writes(fleet)
    service.execute_from_owner(item["id"])
    assert manager.view(vehicle_ref)["saved"] == original_baseline
    if drift:
        remote["config"]["fields"]["BatteryLevel"]["minimum_delta"] = 3
    clock.advance(60)
    outcome = TemporaryCollection(service).tick()
    if drift:
        assert outcome["status"] == "superseded"
        assert outcome["last_error"] == "observed_configuration_changed"
        assert len(writes(fleet)) == 1
    else:
        assert outcome["status"] == "restore_accepted" and not outcome["restore_verified"], outcome["last_error"]
        assert len(writes(fleet)) == 2
        assert writes(fleet)[-1][1]["config"] == original_baseline
        clock.advance(CHECK_SECONDS)
        assert TemporaryCollection(service).tick()["restore_verified"]
        assert manager.view(vehicle_ref)["state"] == "active"
        assert len(writes(fleet)) == 2
    assert manager.review(vehicle_ref, item["id"])["review_digest"] == review["review_digest"]
    assert not any(name == "vehicle_wake_up" for name, *_ in fleet.calls)
