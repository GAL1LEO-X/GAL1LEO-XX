"""Synthetic expiry/restart/concurrency tests; no provider or vehicle traffic."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from threading import Event

import pytest

from tesla_plugin.collection import Collection
from tesla_plugin.collection_state import CREATE, DELETE
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.profiles import profile_fields
from tesla_plugin.service import Service
from tesla_plugin.store import Store, canonical
from tesla_plugin.temporary_collection import TemporaryCollection, CHECK_SECONDS, LEASE_SECONDS, MAX_CHECKS
from test_profiles_storage_packages import certificate


@pytest.fixture
def temporary_setup(service, fleet, clock, vehicle_ref, tmp_path, monkeypatch):
    service.settings = replace(service.settings, live_enabled=True, telemetry_host="telemetry.example",
                               telemetry_ca_file=certificate(tmp_path/"ca.crt"))
    remote = {"config": None, "synced": True}
    original = fleet.call
    def provider(name, arguments=None, **kwargs):
        result = original(name, arguments, **kwargs)
        if name == CREATE:
            remote["config"] = deepcopy(arguments["config"])
        elif name == DELETE:
            remote["config"] = None
        elif name.endswith("config_get"):
            return deepcopy(remote)
        return result
    monkeypatch.setattr(fleet, "call", provider)
    manager = Collection(service)
    baseline_fields = {"BatteryLevel": {"interval_seconds": 300, "resend_interval_seconds": 900,
                                       "minimum_delta": 2, "include_fields": ["ChargeLimitSoc"]}}
    baseline = service.prepare_profile(vehicle_ref, "custom", baseline_fields, "synthetic-baseline-01", SCOPES, customer_alerts=True)
    service.execute_from_owner(baseline["id"])
    clock.advance(1)
    manager.refresh(vehicle_ref, SCOPES)
    fleet.calls.clear()
    return service, manager, remote, provider


def prepare(setup, ref, *, duration=60, request_id="synthetic-temporary-01"):
    service, manager, _, _ = setup
    return manager.prepare_change(ref, "configure", manager.view(ref)["revision"], request_id, SCOPES,
                                  preset="custom", custom_fields={"BatteryLevel": {"interval_seconds": 5}},
                                  duration_seconds=duration)


def start(setup, ref, **kwargs):
    item = prepare(setup, ref, **kwargs)
    setup[0].execute_from_owner(item["id"])
    return item


def writes(fleet):
    return [x for x in fleet.calls if x[0] in (CREATE, DELETE)]


def test_expiry_restores_exact_baseline_and_acceptance_needs_readback(temporary_setup, vehicle_ref, clock, fleet):
    service, manager, remote, _ = temporary_setup
    baseline = deepcopy(remote["config"])
    item = prepare(temporary_setup, vehicle_ref)
    review = manager.review(vehicle_ref, item["id"])
    plan = review["temporary_collection"]
    assert plan["baseline"]["fields"] == baseline["fields"]
    assert plan["restore_action"] == "configure" and plan["expires_at"] is None
    assert plan["estimated_gross_usd"] >= 0 and not plan["cost"]["billing_cap"]
    assert not writes(fleet)
    clock.advance(5)
    service.execute_from_owner(item["id"])
    started = manager.view(vehicle_ref)["temporary_collection"]
    assert started["started_at"] == clock() and started["expires_at"] == clock()+60
    assert manager.view(vehicle_ref)["saved"] == baseline
    clock.advance(59)
    assert TemporaryCollection(service).tick() is None
    clock.advance(1)
    outcome = TemporaryCollection(service).tick()
    assert outcome["status"] == "restore_accepted" and not outcome["restore_verified"]
    assert writes(fleet)[-1][1]["config"] == baseline and len(writes(fleet)) == 2
    clock.advance(CHECK_SECONDS)
    assert TemporaryCollection(service).tick()["restore_verified"]
    assert manager.view(vehicle_ref)["state"] == "active"
    assert manager.view(vehicle_ref)["saved"] == baseline
    assert manager.review(vehicle_ref, item["id"])["review_digest"] == review["review_digest"]


@pytest.mark.parametrize("value", [0, 59, 86401, -1, True, 60.0, "60", float("nan")])
def test_invalid_duration_fails_before_provider(temporary_setup, vehicle_ref, fleet, value):
    with pytest.raises(TeslaError, match="duration"):
        prepare(temporary_setup, vehicle_ref, duration=value)
    assert not fleet.calls


def test_unverified_baseline_and_non_streaming_duration_rejected(service, vehicle_ref, fleet):
    manager = Collection(service)
    with pytest.raises(TeslaError) as exc:
        manager.prepare_change(vehicle_ref, "configure", manager.view(vehicle_ref)["revision"], "synthetic-unverified-1", SCOPES,
                               preset="essential", duration_seconds=60)
    assert exc.value.code == "BASELINE_UNVERIFIED"
    for action, preset in (("pause", None), ("resume", None), ("configure", "on_demand")):
        with pytest.raises(TeslaError):
            manager.prepare_change(vehicle_ref, action, manager.view(vehicle_ref)["revision"], "synthetic-invalid-mode", SCOPES,
                                   preset=preset, duration_seconds=60)
    assert not fleet.calls


def test_prepared_expired_or_upgraded_profiles_never_start_automatically(temporary_setup, vehicle_ref, clock, fleet):
    service = temporary_setup[0]
    assert TemporaryCollection(service).tick() is None
    prepare(temporary_setup, vehicle_ref)
    fleet.calls.clear()
    clock.advance(86401)
    restarted = Service(service.settings, store=Store(service.settings, clock=clock), fleet=fleet)
    assert TemporaryCollection(restarted).tick() is None
    assert not fleet.calls
    assert Collection(restarted).view(vehicle_ref)["temporary_collection"]["status"] == "cancelled"


def test_restart_recovers_due_window_and_dead_lease(temporary_setup, vehicle_ref, clock, fleet):
    service = temporary_setup[0]
    item = start(temporary_setup, vehicle_ref)
    with service.store.db() as db:
        db.execute("UPDATE temporary_collections SET lease_owner='dead-process',lease_until=? WHERE intent_id=?", (clock()+90, item["id"]))
    clock.advance(60)
    restarted = Service(service.settings, store=Store(service.settings, clock=clock), fleet=fleet)
    assert TemporaryCollection(restarted).tick() is None
    clock.advance(31)
    assert TemporaryCollection(restarted).tick()["status"] == "restore_accepted"
    assert len(writes(fleet)) == 2


def test_crash_after_restore_intent_reservation_can_take_over_without_duplicate(temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service = temporary_setup[0]
    start(temporary_setup, vehicle_ref)
    clock.advance(60)
    monkeypatch.setattr(service, "execute_from_owner", lambda *args, **kwargs: (_ for _ in ()).throw(SystemExit("crash before sending")))
    with pytest.raises(SystemExit):
        TemporaryCollection(service).tick()
    assert len(writes(fleet)) == 1
    clock.advance(LEASE_SECONDS+1)
    restarted = Service(service.settings, store=service.store, fleet=fleet)
    assert TemporaryCollection(restarted).tick()["status"] == "restore_accepted"
    clock.advance(CHECK_SECONDS)
    assert TemporaryCollection(restarted).tick()["restore_verified"]
    assert len(writes(fleet)) == 2


def test_unknown_start_is_reconciled_before_restoring(temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, manager, remote, provider = temporary_setup
    def uncertain_start(name, arguments=None, **kwargs):
        result = provider(name, arguments, **kwargs)
        if name == CREATE:
            raise TeslaError("OUTCOME_UNKNOWN", "synthetic response lost", uncertain=True)
        return result
    monkeypatch.setattr(fleet, "call", uncertain_start)
    item = start(temporary_setup, vehicle_ref)
    assert manager.view(vehicle_ref)["temporary_collection"]["status"] == "start_unknown"
    monkeypatch.setattr(fleet, "call", provider)
    clock.advance(60)
    assert TemporaryCollection(service).tick()["status"] == "restore_accepted"
    assert service.store.intent(item["id"])["result"]["configuration_verified"]
    assert len(writes(fleet)) == 2


def test_unknown_restore_is_never_retried_even_after_restart(temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, _, _, provider = temporary_setup
    start(temporary_setup, vehicle_ref)
    def timeout(name, arguments=None, **kwargs):
        if name == CREATE:
            fleet.calls.append((name, arguments, None))
            raise TeslaError("OUTCOME_UNKNOWN", "synthetic timeout", uncertain=True)
        return provider(name, arguments, **kwargs)
    monkeypatch.setattr(fleet, "call", timeout)
    clock.advance(60)
    assert TemporaryCollection(service).tick()["status"] == "restore_unknown"
    restarted = Service(service.settings, store=Store(service.settings, clock=clock), fleet=fleet)
    for _ in range(3):
        clock.advance(CHECK_SECONDS)
        assert TemporaryCollection(restarted).tick()["status"] == "restore_unknown"
    assert len(writes(fleet)) == 2


def test_unknown_restore_that_applied_is_verified_without_retry(temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, _, _, provider = temporary_setup
    start(temporary_setup, vehicle_ref)
    def timeout_after_apply(name, arguments=None, **kwargs):
        result = provider(name, arguments, **kwargs)
        if name == CREATE:
            raise TeslaError("OUTCOME_UNKNOWN", "synthetic timeout", uncertain=True)
        return result
    monkeypatch.setattr(fleet, "call", timeout_after_apply)
    clock.advance(60)
    assert TemporaryCollection(service).tick()["status"] == "restore_unknown"
    clock.advance(CHECK_SECONDS)
    verified = TemporaryCollection(service).tick()
    assert verified["restore_verified"]
    operation = service.intent_view(verified["restore_intent_id"])
    assert operation["status"] == "reconciled" and not operation["verification"]["command_accepted"]
    assert len(writes(fleet)) == 2


def test_remote_new_options_are_not_clobbered(temporary_setup, vehicle_ref, clock, fleet):
    service, _, remote, _ = temporary_setup
    start(temporary_setup, vehicle_ref)
    remote["config"]["fields"]["BatteryLevel"]["minimum_delta"] = 3
    clock.advance(60)
    result = TemporaryCollection(service).tick()
    assert result["status"] == "superseded" and result["last_error"] == "observed_configuration_changed"
    assert len(writes(fleet)) == 1


def test_later_owner_change_supersedes_restore(temporary_setup, vehicle_ref, clock, fleet):
    service, manager, _, _ = temporary_setup
    start(temporary_setup, vehicle_ref)
    clock.advance(1)
    later = manager.prepare_change(vehicle_ref, "pause", manager.view(vehicle_ref)["revision"], "synthetic-owner-pause-1", SCOPES)
    service.execute_from_owner(later["id"])
    clock.advance(60)
    fleet.calls.clear()
    assert TemporaryCollection(service).tick() is None
    assert manager.view(vehicle_ref)["temporary_collection"]["status"] == "superseded"
    assert not fleet.calls


@pytest.mark.parametrize("change", ["generation", "scopes", "trigger"])
def test_changed_authorization_or_revision_blocks_restore(temporary_setup, vehicle_ref, clock, fleet, change):
    service, manager, _, _ = temporary_setup
    start(temporary_setup, vehicle_ref)
    if change == "scopes":
        service.settings = replace(service.settings, allowed_scopes=tuple(x for x in SCOPES if x != "tesla:manage"))
    else:
        with service.store.db() as db:
            db.execute("UPDATE connection SET generation=generation+1" if change == "generation" else "UPDATE trigger_settings SET revision=revision+1")
    fleet.calls.clear()
    clock.advance(60)
    result = TemporaryCollection(service).tick()
    assert result["status"] == "blocked" and not result["restore_verified"]
    assert not fleet.calls


def test_only_one_worker_reads_and_dispatches(temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, _, _, provider = temporary_setup
    start(temporary_setup, vehicle_ref)
    clock.advance(60)
    entered, release = Event(), Event()
    def delayed(name, arguments=None, **kwargs):
        if name.endswith("config_get"):
            entered.set()
            assert release.wait(5)
        return provider(name, arguments, **kwargs)
    monkeypatch.setattr(fleet, "call", delayed)
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(TemporaryCollection(service).tick)
        assert entered.wait(5)
        assert TemporaryCollection(service).tick() is None
        release.set()
        assert first.result()["status"] == "restore_accepted"
    assert len(writes(fleet)) == 2


def test_baseline_options_changed_after_prepare_reject_confirmation(temporary_setup, vehicle_ref, clock, fleet):
    service, manager, remote, _ = temporary_setup
    item = prepare(temporary_setup, vehicle_ref)
    remote["config"]["fields"]["BatteryLevel"]["minimum_delta"] = 99
    clock.advance(1)
    manager.refresh(vehicle_ref, SCOPES)
    with pytest.raises(TeslaError) as exc:
        service.execute_from_owner(item["id"])
    assert exc.value.code == "REVISION_CONFLICT" and not writes(fleet)


def test_stale_baseline_requires_explicit_refresh_before_preparing(temporary_setup, vehicle_ref, clock, fleet):
    clock.advance(301)
    with pytest.raises(TeslaError) as exc:
        prepare(temporary_setup, vehicle_ref)
    assert exc.value.code == "BASELINE_UNVERIFIED" and not fleet.calls


def test_baseline_age_is_checked_again_at_dispatch(temporary_setup, vehicle_ref, clock, fleet):
    service, _, _, _ = temporary_setup
    clock.advance(295)
    item = prepare(temporary_setup, vehicle_ref)
    clock.advance(6)
    with pytest.raises(TeslaError) as exc:
        service.execute_from_owner(item["id"])
    assert exc.value.code == "REVISION_CONFLICT" and not writes(fleet)


def test_named_profiles_preserve_legacy_aliases():
    assert profile_fields("normal") == profile_fields("recommended")
    assert profile_fields("travel") == profile_fields("journeys")
    assert profile_fields("diagnostic") == profile_fields("drive_diagnostics")
    assert len(profile_fields("normal")) < len(profile_fields("full"))


def test_restore_to_paused_baseline_preserves_saved_profile(temporary_setup, vehicle_ref, clock, fleet):
    service, manager, _, _ = temporary_setup
    baseline_saved = deepcopy(manager.view(vehicle_ref)["saved"])
    item = manager.prepare_change(vehicle_ref, "pause", manager.view(vehicle_ref)["revision"], "synthetic-paused-base-1", SCOPES)
    service.execute_from_owner(item["id"])
    clock.advance(1)
    manager.refresh(vehicle_ref, SCOPES)
    temporary = start(temporary_setup, vehicle_ref)
    assert manager.review(vehicle_ref, temporary["id"])["temporary_collection"]["restore_action"] == "pause"
    clock.advance(60)
    assert TemporaryCollection(service).tick()["status"] == "restore_accepted"
    assert writes(fleet)[-1][0] == DELETE
    clock.advance(CHECK_SECONDS)
    assert TemporaryCollection(service).tick()["restore_verified"]
    assert manager.view(vehicle_ref)["state"] == "paused" and manager.view(vehicle_ref)["saved"] == baseline_saved


def test_restore_rejection_is_visible_without_retry(temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, _, _, provider = temporary_setup
    start(temporary_setup, vehicle_ref)
    def rejected(name, arguments=None, **kwargs):
        if name == CREATE:
            fleet.calls.append((name, arguments, None))
            raise TeslaError("COMMAND_REJECTED", "synthetic rejection")
        return provider(name, arguments, **kwargs)
    monkeypatch.setattr(fleet, "call", rejected)
    clock.advance(60)
    outcome = TemporaryCollection(service).tick()
    assert outcome["status"] == "restore_rejected" and outcome["last_error"] == "COMMAND_REJECTED"
    clock.advance(CHECK_SECONDS)
    assert TemporaryCollection(service).tick()["status"] == "restore_rejected"
    assert len(writes(fleet)) == 2


def test_readback_budget_is_durable_and_explicit_read_can_verify(temporary_setup, vehicle_ref, clock, fleet):
    service, manager, remote, _ = temporary_setup
    baseline = deepcopy(remote["config"])
    start(temporary_setup, vehicle_ref)
    remote["synced"] = False
    clock.advance(60)
    for _ in range(MAX_CHECKS):
        TemporaryCollection(service).tick()
        clock.advance(CHECK_SECONDS)
    restarted = Service(service.settings, store=Store(service.settings, clock=clock), fleet=fleet)
    assert TemporaryCollection(restarted).tick()["last_error"] == "RESTORE_VERIFICATION_LIMIT_REACHED"
    calls = len(fleet.calls)
    clock.advance(86400)
    assert TemporaryCollection(restarted).tick() is None and len(fleet.calls) == calls
    remote.update(config=baseline, synced=True)
    manager.refresh(vehicle_ref, SCOPES)
    assert manager.view(vehicle_ref)["temporary_collection"]["restore_verified"]
    assert len(writes(fleet)) == 1


def test_restore_recovers_baseline_cost_hours(temporary_setup, vehicle_ref, clock):
    service, manager, _, _ = temporary_setup
    service.store.snapshot(vehicle_ref, "telemetry_preview", {"hours": 12}, "owner_request", clock())
    item = manager.prepare_change(vehicle_ref, "configure", manager.view(vehicle_ref)["revision"], "synthetic-hours-window-1", SCOPES,
                                  preset="essential", duration_seconds=60, active_hours_per_day=2)
    service.execute_from_owner(item["id"])
    clock.advance(60)
    TemporaryCollection(service).tick()
    clock.advance(CHECK_SECONDS)
    TemporaryCollection(service).tick()
    assert manager.view(vehicle_ref)["hours"] == 12


def test_restore_rechecks_new_readback_after_provider_preflight(temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, manager, remote, provider = temporary_setup
    start(temporary_setup, vehicle_ref)
    clock.advance(60)
    injected = False
    def changed_during_preflight(name, arguments=None, **kwargs):
        nonlocal injected
        if name == "vehicle_fleet_status" and not injected:
            injected = True
            remote["config"]["fields"]["BatteryLevel"]["minimum_delta"] = 99
            manager.refresh(vehicle_ref, SCOPES)
        return provider(name, arguments, **kwargs)
    monkeypatch.setattr(fleet, "call", changed_during_preflight)
    result = TemporaryCollection(service).tick()
    assert result["status"] == "superseded"
    assert result["last_error"] == "observed_configuration_changed"
    assert service.store.intent(result["restore_intent_id"])["status"] == "cancelled"
    assert not manager.view(vehicle_ref)["blocked"]
    assert remote["config"]["fields"]["BatteryLevel"]["minimum_delta"] == 99
    assert len(writes(fleet)) == 1


@pytest.mark.parametrize("change", ["stale", "unsynced", "local_target"])
def test_restore_dispatch_rechecks_local_target_and_readback_quality(temporary_setup, vehicle_ref, clock, fleet, monkeypatch, change):
    service, _, remote, provider = temporary_setup
    start(temporary_setup, vehicle_ref)
    clock.advance(60)
    def changed_preflight(name, arguments=None, **kwargs):
        if name == "vehicle_fleet_status":
            if change == "stale":
                clock.advance(CHECK_SECONDS+1)
            elif change == "unsynced":
                service.store.snapshot(vehicle_ref, "telemetry_remote", {**remote, "synced": False}, "tesla_api", clock())
            else:
                service.store.snapshot(vehicle_ref, "telemetry_target", {"fields": {"Locked": {"interval_seconds": 99}}}, "local_configuration", clock())
        return provider(name, arguments, **kwargs)
    monkeypatch.setattr(fleet, "call", changed_preflight)
    result = TemporaryCollection(service).tick()
    assert len(writes(fleet)) == 1
    if change == "local_target":
        assert result["status"] == "superseded"
        assert service.store.intent(result["restore_intent_id"])["status"] == "cancelled"
    else:
        assert result["status"] == "blocked" and result["last_error"] == "RESTORE_READBACK_REQUIRED"
        assert service.store.intent(result["restore_intent_id"])["status"] == "prepared"
        monkeypatch.setattr(fleet, "call", provider)
        clock.advance(CHECK_SECONDS)
        assert TemporaryCollection(service).tick()["status"] == "restore_accepted"
        assert len(writes(fleet)) == 2


@pytest.mark.parametrize("stage", ["start", "restore"])
@pytest.mark.parametrize("regrant_before_ack", [False, True])
def test_late_collection_ack_cannot_revive_revoked_membership(temporary_setup, vehicle_ref, clock, fleet, monkeypatch, stage, regrant_before_ack):
    service, _, _, provider = temporary_setup
    vehicle_data = deepcopy(service.store.vehicle(vehicle_ref)["data"])
    if stage == "restore":
        item = start(temporary_setup, vehicle_ref)
        clock.advance(60)
    else:
        item = prepare(temporary_setup, vehicle_ref)
    def revoke_during_write(name, arguments=None, **kwargs):
        result = provider(name, arguments, **kwargs)
        if name == CREATE:
            service.store.save_vehicles([])
            if regrant_before_ack:
                service.store.save_vehicles([vehicle_data])
        return result
    monkeypatch.setattr(fleet, "call", revoke_during_write)
    if stage == "start":
        result = service.execute_from_owner(item["id"])
        assert result["status"] == "acknowledged"
        assert result["result"]["configuration_state_recorded"] is False
    else:
        assert TemporaryCollection(service).tick()["status"] == "blocked"
    with service.store.db() as db:
        obligation = db.execute("SELECT * FROM temporary_collections WHERE intent_id=?", (item["id"],)).fetchone()
        assert obligation["status"] == "blocked" and obligation["error"] == "VEHICLE_ACCESS_REVOKED"
        assert obligation["next_check"] == 1e30 and obligation["lease_owner"] is None
        assert not db.execute("SELECT 1 FROM snapshots WHERE vehicle=?", (vehicle_ref,)).fetchone()
    if not regrant_before_ack:
        service.store.save_vehicles([vehicle_data])
    writes_before = len(writes(fleet))
    clock.advance(120)
    assert TemporaryCollection(service).tick() is None
    assert len(writes(fleet)) == writes_before


@pytest.mark.parametrize("read_mode", ["explicit", "worker"])
def test_late_configuration_read_cannot_recreate_revoked_snapshots(temporary_setup, vehicle_ref, clock, fleet, monkeypatch, read_mode):
    service, manager, _, provider = temporary_setup
    start(temporary_setup, vehicle_ref)
    clock.advance(60)
    def revoke_during_read(name, arguments=None, **kwargs):
        result = provider(name, arguments, **kwargs)
        if name.endswith("config_get"):
            service.store.save_vehicles([])
        return result
    monkeypatch.setattr(fleet, "call", revoke_during_read)
    if read_mode == "explicit":
        with pytest.raises(TeslaError) as exc:
            manager.refresh(vehicle_ref, SCOPES)
        assert exc.value.code == "AUTHORIZATION_CHANGED"
    else:
        result = TemporaryCollection(service).tick()
        assert result["status"] == "blocked" and result["last_error"] == "VEHICLE_ACCESS_REVOKED"
    with service.store.db() as db:
        assert not db.execute("SELECT 1 FROM snapshots WHERE vehicle=?", (vehicle_ref,)).fetchone()
    assert len(writes(fleet)) == 1


@pytest.mark.parametrize("phase", ["accepted", "verified"])
@pytest.mark.parametrize("late_outcome", ["acknowledged", "rejected", "unknown"])
def test_late_start_response_cannot_regress_a_worker_restore(temporary_setup, vehicle_ref, clock, fleet, monkeypatch, phase, late_outcome):
    service, manager, remote, provider = temporary_setup
    baseline = deepcopy(remote["config"])
    item = prepare(temporary_setup, vehicle_ref)
    delayed = False
    def delayed_start_response(name, arguments=None, **kwargs):
        nonlocal delayed
        result = provider(name, arguments, **kwargs)
        if name == CREATE and not delayed:
            delayed = True
            # The start is durably sending while its provider reply is delayed.
            # The deadline worker observes it and completes the authorized restore.
            clock.advance(60)
            assert TemporaryCollection(service).tick()["status"] == "restore_accepted"
            if phase == "verified":
                clock.advance(CHECK_SECONDS)
                assert TemporaryCollection(service).tick()["restore_verified"]
            if late_outcome != "acknowledged":
                raise TeslaError("OUTCOME_UNKNOWN" if late_outcome == "unknown" else "COMMAND_REJECTED",
                                 "synthetic late response", uncertain=late_outcome == "unknown")
        return result
    monkeypatch.setattr(fleet, "call", delayed_start_response)
    result = service.execute_from_owner(item["id"])
    view = manager.view(vehicle_ref)
    assert result["status"] == "reconciled"
    assert view["temporary_collection"]["status"] == ("restore_accepted" if phase == "accepted" else "restored_verified")
    assert remote["config"] == baseline and view["target"]["data"] == baseline
    assert view["saved"] == baseline and len(writes(fleet)) == 2
    if phase == "accepted":
        clock.advance(CHECK_SECONDS)
        assert TemporaryCollection(service).tick()["restore_verified"]
    assert manager.view(vehicle_ref)["state"] == "active"
    assert len(writes(fleet)) == 2


def test_late_restore_response_cannot_age_out_verified_readback(temporary_setup, vehicle_ref, clock, fleet, monkeypatch):
    service, manager, _, provider = temporary_setup
    start(temporary_setup, vehicle_ref)
    clock.advance(60)
    def delayed_restore_response(name, arguments=None, **kwargs):
        result = provider(name, arguments, **kwargs)
        if name == CREATE:
            # A replacement worker observes the applied baseline after the
            # original restore worker's lease expires, before its reply arrives.
            clock.advance(LEASE_SECONDS+1)
            assert TemporaryCollection(service).tick()["restore_verified"]
            clock.advance(1)
        return result
    monkeypatch.setattr(fleet, "call", delayed_restore_response)
    assert TemporaryCollection(service).tick()["restore_verified"]
    view = manager.view(vehicle_ref)
    assert view["target"]["at"] == view["remote"]["at"]
    assert view["state"] == "active" and len(writes(fleet)) == 2
