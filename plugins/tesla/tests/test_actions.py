from concurrent.futures import ThreadPoolExecutor
import json
import pytest
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError


def prepare(service, ref, name="set_charge_limit", args=None, key="stable-request-0001"):
    return service.prepare(name, {"percent": 80} if args is None else args, ref, key, SCOPES)


def test_prepare_has_no_vehicle_effect_and_dispatch_is_once(service, fleet, vehicle_ref):
    intent = prepare(service, vehicle_ref)
    assert fleet.calls == []
    assert intent["status"] == "prepared"
    assert prepare(service, vehicle_ref)["id"] == intent["id"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: service.execute_from_owner(intent["id"]), range(2)))
    assert sum(name == "set_charge_limit" for name, _, _ in fleet.calls) == 1
    assert service.intent_view(intent["id"])["status"] == "acknowledged"
    assert service.intent_view(intent["id"])["result"]["physical_effect_verified"] is False


def test_idempotency_key_cannot_change_action(service, vehicle_ref):
    prepare(service, vehicle_ref)
    with pytest.raises(TeslaError, match="different action"):
        prepare(service, vehicle_ref, args={"percent": 90})


def test_expired_intent_does_not_dispatch(service, fleet, vehicle_ref, clock):
    intent = prepare(service, vehicle_ref)
    clock.advance(301)
    with pytest.raises(TeslaError) as exc:
        service.execute_from_owner(intent["id"])
    assert exc.value.code == "INTENT_EXPIRED"
    assert fleet.calls == []


def test_timeout_is_uncertain_never_retried(service, fleet, vehicle_ref):
    fleet.error = TeslaError("OUTCOME_UNKNOWN", "timeout", uncertain=True)
    intent = prepare(service, vehicle_ref)
    assert service.execute_from_owner(intent["id"])["status"] == "unknown"
    service.execute_from_owner(intent["id"])
    assert sum(n == "set_charge_limit" for n, _, _ in fleet.calls) == 1


def test_restart_does_not_replay_sending(service, fleet, vehicle_ref):
    intent = prepare(service, vehicle_ref)
    with service.store.db() as db:
        db.execute("UPDATE intents SET status='sending' WHERE id=?", (intent["id"],))
    service.store.recover_inflight()
    assert service.execute_from_owner(intent["id"])["status"] == "unknown"
    assert fleet.calls == []


@pytest.mark.parametrize("gear", [None, "D", "R", "unknown"])
def test_opening_requires_explicit_park(service, fleet, vehicle_ref, gear):
    fleet.park = gear
    intent = prepare(service, vehicle_ref, "actuate_trunk", {"which_trunk": "front"})
    with pytest.raises(TeslaError) as exc:
        service.execute_from_owner(intent["id"])
    assert exc.value.code == "PRECONDITION_FAILED"
    assert not any(n == "actuate_trunk" for n, _, _ in fleet.calls)


def test_secure_pin_not_saved_in_intent_or_result(service, fleet, vehicle_ref):
    intent = prepare(service, vehicle_ref, "parental_controls_activate", {})
    service.execute_from_owner(intent["id"], {"pin": "0197"})
    assert fleet.calls[-1][1] == {"pin": "0197"}
    with service.store.db() as db:
        row = dict(db.execute("SELECT * FROM intents WHERE id=?", (intent["id"],)).fetchone())
    # Inspect payloads: an epoch timestamp (or random ID) may coincidentally
    # contain the PIN digits without storing the PIN itself.
    assert "0197" not in row["arguments"] + (row["result"] or "")


def test_new_authorization_invalidates_existing_intent(service, vehicle_ref):
    intent = prepare(service, vehicle_ref)
    service.store.set_tokens({"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 1000}, [], "eu")
    assert service.intent_view(intent["id"])["status"] == "cancelled"


def test_missing_extended_transport_never_dispatches(service, fleet, vehicle_ref, monkeypatch):
    def unavailable(op):
        raise TeslaError("TRANSPORT_UNAVAILABLE", "Adapter unavailable")
    monkeypatch.setattr(fleet, "require_extension", unavailable)
    with pytest.raises(TeslaError):
        prepare(service, vehicle_ref, "remote_boombox", {"sound": 0})
    assert fleet.calls == []


def test_cache_labels_old_data_and_never_wakes(service, fleet, vehicle_ref):
    result = service.state(vehicle_ref, ["charge_state"], "cache_preferred", SCOPES)
    assert result["data"]["charge_state"]["quality"] == "stale"
    assert result["data"]["charge_state"]["data"]["battery_level"] == 55
    assert result["wake_sent"] is False
    assert not any(n == "vehicle_wake_up" for n, _, _ in fleet.calls)


def test_location_scope_is_not_inferred_from_read_scope(service, fleet, vehicle_ref):
    with pytest.raises(TeslaError) as exc:
        service.state(vehicle_ref, ["drive_state"], "live_if_online", ["tesla:read"])
    assert exc.value.code == "SCOPE_REQUIRED"
    assert fleet.calls == []
