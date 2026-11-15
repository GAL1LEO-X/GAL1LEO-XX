"""Numeric JSON roundtrips and overdue obligations; no vehicle/network traffic."""
from copy import deepcopy
import json
import socket

import pytest

from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.temporary_collection import CHECK_SECONDS, TemporaryCollection, same_config
from test_temporary_collection import temporary_setup, writes


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Temporary roundtrip tests prohibit network")
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


def config(delta=1.0):
    return {"hostname": "telemetry.example", "port": 8443, "ca": "synthetic-ca",
            "delivery_policy": "latest", "alert_types": ["customer"],
            "fields": {"BatteryLevel": {"interval_seconds": 5, "resend_interval_seconds": 15,
                                        "minimum_delta": delta,
                                        "include_fields": ["ChargeLimitSoc", "Locked"]}}}


@pytest.mark.parametrize("left,right", [(1.0, 1), (2, 2.0), (-0.0, 0), (0.5, 0.5),
                                      (2**53, float(2**53))])
def test_numeric_roundtrip_is_equivalent_without_rewriting_originals(left, right):
    requested, observed = config(left), config(right)
    observed.update(aud="com.tesla.fleet.TelemetryClient", iss="synthetic-public-issuer")
    original = (json.dumps(requested), json.dumps(observed))
    assert same_config(requested, observed)
    assert same_config(observed, requested)
    assert (json.dumps(requested), json.dumps(observed)) == original


@pytest.mark.parametrize("left,right", [(True, 1), (False, 0), (True, 1.0), (False, -0.0),
                                      (1, 1.0000000000000002), (2**53+1, float(2**53)),
                                      ("1", 1), (None, 0), (1.0, 2),
                                      (float("inf"), float("inf")), (float("nan"), float("nan"))])
def test_numeric_comparison_does_not_alias_booleans_or_distinct_values(left, right):
    assert not same_config(config(left), config(right))
    assert not same_config(config(right), config(left))


@pytest.mark.parametrize("path,value", [
    (("hostname",), "other.example"), (("port",), 9443), (("ca",), "other-ca"),
    (("delivery_policy",), "all"), (("alert_types",), []),
    (("unknown_option",), 1),
    (("fields", "BatteryLevel", "minimum_delta"), 1.25),
    (("fields", "BatteryLevel", "include_fields"), ["Locked", "ChargeLimitSoc"]),
    (("fields", "BatteryLevel", "include_fields"), []),
    (("fields", "BatteryLevel", "unknown_option"), 1),
    (("fields", "BatteryLevel", "aud"), "nested-audience"),
    (("fields", "BatteryLevel", "iss"), "nested-issuer"),
])
def test_equivalent_number_never_hides_other_configuration_drift(path, value):
    requested, observed = config(1.0), config(1)
    observed.update(aud="com.tesla.fleet.TelemetryClient", iss="synthetic-public-issuer")
    parent = observed
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    assert not same_config(requested, observed)
    assert not same_config(observed, requested)


def test_omission_empty_list_and_null_remain_distinct():
    original = config()
    without = deepcopy(original)
    del without["fields"]["BatteryLevel"]["include_fields"]
    empty = deepcopy(without)
    empty["fields"]["BatteryLevel"]["include_fields"] = []
    null = deepcopy(without)
    null["fields"]["BatteryLevel"]["include_fields"] = None
    assert not same_config(without, empty)
    assert not same_config(without, null)
    assert not same_config(empty, null)
    assert same_config(None, None)
    assert not same_config(None, {"aud": "signing-metadata-only"})


@pytest.mark.parametrize("path", [
    ("future_option",), ("port",), ("fields", "BatteryLevel", "future_option"),
    ("fields", "BatteryLevel", "interval_seconds"),
    ("fields", "BatteryLevel", "resend_interval_seconds"),
    ("fields", "FutureUnknownField", "minimum_delta"),
    ("fields", "Locked", "minimum_delta"),
])
def test_number_normalization_is_limited_to_documented_numeric_delta(path):
    left, right = config(), config()
    for value, scalar in ((left, 1.0), (right, 1)):
        parent = value
        for key in path[:-1]:
            parent = parent.setdefault(key, {})
        parent[path[-1]] = scalar
    assert not same_config(left, right)
    assert not same_config(right, left)


def test_location_delta_has_the_same_documented_number_contract():
    left, right = config(), config()
    left["fields"] = {"Location": {"interval_seconds": 300, "minimum_delta": 25.0}}
    right["fields"] = {"Location": {"interval_seconds": 300, "minimum_delta": 25}}
    assert same_config(left, right)


def prepare_decimal(setup, ref):
    _, manager, _, _ = setup
    return manager.prepare_change(ref, "configure", manager.view(ref)["revision"],
                                  "synthetic-vehicle-numeric-window", SCOPES, preset="custom",
                                  custom_fields={"BatteryLevel": {"interval_seconds": 5,
                                                                  "minimum_delta": 1.0}},
                                  duration_seconds=60)


@pytest.mark.parametrize("drift", [False, True])
def test_expiry_signed_numeric_roundtrip_restores_once_or_preserves_real_drift(
        temporary_setup, vehicle_ref, clock, fleet, monkeypatch, drift):
    service, manager, remote, provider = temporary_setup
    baseline = deepcopy(remote["config"])
    # The readback's JSON representation has integer numbers, as emitted by
    # the independently exercised pinned Go signer. This provider is synthetic.
    def signed_integer_provider(name, *args, **kwargs):
        result = provider(name, *args, **kwargs)
        if name.endswith("config_get") and result["config"] is not None:
            for options in result["config"]["fields"].values():
                value = options.get("minimum_delta")
                if type(value) is float and value.is_integer():
                    options["minimum_delta"] = int(value)
            result["config"].update(aud="com.tesla.fleet.TelemetryClient", iss="synthetic-public-issuer")
        return result
    monkeypatch.setattr(fleet, "call", signed_integer_provider)
    item = prepare_decimal(temporary_setup, vehicle_ref)
    original_review = manager.review(vehicle_ref, item["id"])["review_digest"]
    original_arguments = json.dumps(service.store.intent(item["id"])["arguments"], sort_keys=True)
    service.execute_from_owner(item["id"])
    if drift:
        remote["config"]["fields"]["BatteryLevel"]["minimum_delta"] = 1.5
    clock.advance(60)
    outcome = TemporaryCollection(service).tick()
    if drift:
        assert outcome["status"] == "superseded"
        assert len(writes(fleet)) == 1
    else:
        assert outcome["status"] == "restore_accepted", outcome
        assert len(writes(fleet)) == 2
        restored = writes(fleet)[-1][1]["config"]
        assert restored == baseline
        assert "aud" not in restored and "iss" not in restored
        clock.advance(CHECK_SECONDS)
        assert TemporaryCollection(service).tick()["restore_verified"]
        assert len(writes(fleet)) == 2
    assert manager.review(vehicle_ref, item["id"])["review_digest"] == original_review
    assert json.dumps(service.store.intent(item["id"])["arguments"], sort_keys=True) == original_arguments
    assert not any(name == "vehicle_wake_up" for name, *_ in fleet.calls)


def test_superseded_readback_preserves_due_obligation_without_restore(
        temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service = temporary_setup[0]
    item = prepare_decimal(temporary_setup, vehicle_ref)
    service.execute_from_owner(item["id"])
    def superseded(*args, **kwargs):
        raise TeslaError("COLLECTION_READBACK_SUPERSEDED", "A newer configuration observation is committed")
    monkeypatch.setattr(service, "read", superseded)
    clock.advance(60)
    view = TemporaryCollection(service).tick()
    assert view["status"] == "blocked"
    assert view["last_error"] == "COLLECTION_READBACK_SUPERSEDED"
    assert view["restore_intent_id"] is None and not view["restore_verified"]
    assert len(writes(fleet)) == 1


def test_due_window_reports_clock_overrun_without_claiming_streaming_or_changing_state(
        temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, manager, _, _ = temporary_setup
    item = prepare_decimal(temporary_setup, vehicle_ref)
    assert manager.view(vehicle_ref)["temporary_collection"]["timing"]["restore_overdue"] is False
    service.execute_from_owner(item["id"])
    initial = manager.view(vehicle_ref)["temporary_collection"]
    assert initial["timing"]["elapsed_seconds"] == 0
    clock.advance(181)
    def failed_read(*args, **kwargs):
        raise TeslaError("PROVIDER_UNAVAILABLE", "Synthetic read failure")
    monkeypatch.setattr(service, "read", failed_read)
    view = TemporaryCollection(service).tick()
    assert view["status"] == "blocked" and not view["restore_verified"]
    assert view["timing"]["deadline_elapsed"] is True
    assert view["timing"]["restore_overdue"] is True
    assert view["timing"]["overdue_seconds"] == 121
    assert view["timing"]["streaming_duration_verified"] is False
    cost = view["timing"]["conditional_additional_streaming_cost"]
    assert cost["condition"] == "temporary_configuration_continues_with_continuous_activity"
    assert cost["observed_charge"] is False and cost["billing_cap"] is False
    assert cost["additional_planned_signals"] == 25
    assert cost["estimated_gross_usd"] == round(25/150000, 4)
    assert len(writes(fleet)) == 1
    # A local clock projection cannot mutate durable status or invent evidence.
    with service.store.db() as db:
        before = dict(db.execute("SELECT * FROM temporary_collections WHERE intent_id=?", (item["id"],)).fetchone())
    clock.advance(10)
    refreshed = manager.view(vehicle_ref)["temporary_collection"]
    assert refreshed["timing"]["overdue_seconds"] == 131
    assert refreshed["status"] == "blocked"
    with service.store.db() as db:
        assert dict(db.execute("SELECT * FROM temporary_collections WHERE intent_id=?", (item["id"],)).fetchone()) == before


def test_clock_before_start_and_completed_restore_never_claim_active_overrun(
        temporary_setup, vehicle_ref, clock, fleet):
    service, manager, _, _ = temporary_setup
    item = prepare_decimal(temporary_setup, vehicle_ref)
    service.execute_from_owner(item["id"])
    clock.advance(-1)
    view = manager.view(vehicle_ref)["temporary_collection"]
    assert view["timing"]["clock_before_start"] is True
    assert view["timing"]["elapsed_seconds"] is None
    assert not view["timing"]["restore_overdue"]
    clock.advance(61)
    TemporaryCollection(service).tick()
    clock.advance(CHECK_SECONDS)
    view = TemporaryCollection(service).tick()
    assert view["restore_verified"]
    assert view["timing"]["deadline_elapsed"] is True
    assert view["timing"]["restore_overdue"] is False
    assert view["timing"]["overdue_seconds"] is None
    assert view["timing"]["conditional_additional_streaming_cost"] is None
    assert len(writes(fleet)) == 2
