import base64
import hashlib
import hmac
import json
import socket
from types import SimpleNamespace
import pytest

from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.events import Events, CallbackError, callback_url, signed_headers, PinnedHTTPS
from tesla_plugin.telemetry import Telemetry, typed_value, consume_record
from tesla_plugin.store import utc, canonical
from conftest import VIN


@pytest.fixture(autouse=True)
def isolate_explicit_rules(store):
    # These unit tests exercise one rule at a time. Default presets and their
    # interaction with the shared panel selection are covered in test_triggers.
    with store.db() as db:
        db.execute("DELETE FROM rules")


def payload(clock, fields, *, when=None):
    def typed(value):
        if isinstance(value, dict):
            return {"locationValue": value}
        if type(value) is bool:
            return {"booleanValue": value}
        if type(value) in (int, float):
            return {"doubleValue": value}
        if value is None:
            return {"invalid": True}
        return {"stringValue": value}
    return {"vin": VIN, "createdAt": utc(clock() if when is None else when),
            "data": [{"key": key, "value": typed(value)} for key, value in fields.items()]}


def kinds(store):
    with store.db() as db:
        return [r[0] for r in db.execute("SELECT name FROM events ORDER BY occurred,id")]


def test_battery_bootstrap_hysteresis_and_replay(store, clock, vehicle_ref):
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, "battery_low", {"threshold": 20, "hysteresis": 2})
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 19}))
    assert kinds(store) == []  # Already low at connection is not a crossing.
    for value in [21, 20, 23, 20]:
        clock.advance(10)
        telemetry.ingest("V", payload(clock, {"BatteryLevel": value}))
    assert kinds(store) == ["battery_low"]
    repeated = payload(clock, {"BatteryLevel": 20})
    assert telemetry.ingest("V", repeated)["status"] == "duplicate"
    assert telemetry.ingest("V", repeated | {"isResend": True})["status"] == "duplicate"
    assert kinds(store) == ["battery_low"]


@pytest.mark.parametrize("middle", [None, "garbage", True])
def test_invalid_sample_resets_threshold_baseline(store, clock, vehicle_ref, middle):
    telemetry = Telemetry(store)
    telemetry.configure_rule(vehicle_ref, "battery_low", {})
    for value in [25, middle, 10]:
        telemetry.ingest("V", payload(clock, {"BatteryLevel": value}))
        clock.advance(10)
    assert kinds(store) == []


def test_old_replay_and_source_gap_cannot_create_crossing(store, clock, vehicle_ref):
    telemetry = Telemetry(store)
    telemetry.configure_rule(vehicle_ref, "battery_low", {"max_gap_seconds": 60})
    start = clock()
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 25}))
    clock.advance(100)
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 10}))
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 25}, when=start+1))
    assert kinds(store) == []
    with store.db() as db:
        row = db.execute("SELECT value,source_at FROM latest WHERE field='BatteryLevel'").fetchone()
    assert json.loads(row[0]) == 10


def test_same_timestamp_conflicting_value_invalidates_current_state(store, clock, vehicle_ref):
    telemetry = Telemetry(store)
    telemetry.configure_rule(vehicle_ref, "battery_low", {})
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 25}))
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 10}))
    with store.db() as db:
        assert db.execute("SELECT quality FROM latest WHERE field='BatteryLevel'").fetchone()[0] == "time_conflict"
    assert kinds(store) == []


def test_unknown_charge_state_does_not_become_a_valid_baseline(store, clock, vehicle_ref):
    telemetry = Telemetry(store)
    telemetry.configure_rule(vehicle_ref, "charging", {})
    for value in ["DetailedChargeStateStopped", "not-a-real-enum", "DetailedChargeStateCharging"]:
        telemetry.ingest("V", payload(clock, {"DetailedChargeState": value}))
        clock.advance(10)
    assert kinds(store) == []


def test_charging_lifecycle_observed_only_once(store, clock, vehicle_ref):
    telemetry = Telemetry(store)
    telemetry.configure_rule(vehicle_ref, "charging", {})
    for value in ["Disconnected", "Charging", "Charging", "Stopped", "Charging", "Complete"]:
        telemetry.ingest("V", payload(clock, {"DetailedChargeState": "DetailedChargeState"+value}))
        clock.advance(10)
    assert kinds(store) == ["charge_started", "charge_stopped", "charge_resumed", "charge_completed"]


def test_unlocked_dwell_requires_park_unoccupied_fresh_observations(store, clock, vehicle_ref):
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, "unlocked_parked", {"dwell_seconds": 20})
    values = {"Locked": False, "Gear": "ShiftStateP", "DriverSeatOccupied": False}
    telemetry.ingest("V", payload(clock, values))
    clock.advance(10)
    telemetry.ingest("V", payload(clock, values))
    assert kinds(store) == []
    clock.advance(10)
    telemetry.ingest("V", payload(clock, values))
    assert kinds(store) == ["unlocked_parked"]
    clock.advance(10)
    telemetry.ingest("V", payload(clock, values))
    assert kinds(store) == ["unlocked_parked"]


def test_restart_does_not_resume_an_old_dwell(store, clock, vehicle_ref):
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, "unlocked_parked", {"dwell_seconds": 20})
    values = {"Locked": False, "Gear": "ShiftStateP", "DriverSeatOccupied": False}
    telemetry.ingest("V", payload(clock, values))
    clock.advance(20)
    restarted = Telemetry(store, monotonic=clock)
    restarted.ingest("V", payload(clock, values))
    assert kinds(store) == []


def test_geofence_requires_gps_and_dwell(store, clock, vehicle_ref):
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, "geofence", {"latitude": 48.2, "longitude": 16.3, "radius_m": 100, "dwell_seconds": 10})
    for gps, lat in [(False, 48.2), (True, 48.3), (True, 48.2), (True, 48.2)]:
        telemetry.ingest("V", payload(clock, {"Location": {"latitude": lat, "longitude": 16.3}, "GpsState": gps}))
        clock.advance(10)
    assert kinds(store) == ["geofence_enter"]


def test_stale_notification_does_not_claim_vehicle_offline(store, clock, vehicle_ref):
    telemetry = Telemetry(store)
    telemetry.configure_rule(vehicle_ref, "stale", {"field": "BatteryLevel", "max_age_seconds": 60})
    telemetry.tick()
    assert kinds(store) == []
    telemetry.ingest("V", payload(clock, {"BatteryLevel": 50}))
    clock.advance(61)
    telemetry.tick()
    telemetry.tick()
    assert kinds(store) == ["data_stale"]
    with store.db() as db:
        assert json.loads(db.execute("SELECT data FROM events").fetchone()[0])["vehicle_offline_proven"] is False


def test_hidden_location_never_enters_history(store, clock, vehicle_ref):
    with store.db() as db:
        db.execute("UPDATE vehicles SET data=?", (canonical({"granular_access": {"hide_private": True}}),))
    Telemetry(store).ingest("V", payload(clock, {"Location": {"latitude": 48.2, "longitude": 16.3}, "BatteryLevel": 50}))
    with store.db() as db:
        assert [r[0] for r in db.execute("SELECT field FROM samples")] == ["BatteryLevel"]


def test_receiver_identity_is_checked_before_committing(store, clock):
    record = SimpleNamespace(value=canonical(payload(clock, {"BatteryLevel": 50})).encode(), key=VIN.encode(),
                             headers=[("vin", b"OTHER000000000001"), ("txtype", b"V")], topic="tesla_V", partition=0, offset=1)
    with pytest.raises(TeslaError):
        consume_record(Telemetry(store), record)
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM samples").fetchone()[0] == 0


def test_alert_lifetime_deduplicates_repeated_frames_and_old_history(store, clock):
    telemetry = Telemetry(store)
    started = utc(clock())
    alert = {"name": "SyntheticCustomerAlert", "audiences": ["Customer"], "startedAt": started, "endedAt": None}
    def frame(item):
        return {"vin": VIN, "createdAt": utc(clock()), "alerts": [item]}
    telemetry.ingest("alerts", frame(alert))
    clock.advance(10)
    telemetry.ingest("alerts", frame(alert))
    assert kinds(store) == ["alert_started"]
    ended = {**alert, "endedAt": utc(clock())}
    telemetry.ingest("alerts", frame(ended))
    clock.advance(10)
    telemetry.ingest("alerts", frame(ended))
    telemetry.ingest("alerts", frame(alert))  # A replay cannot reopen it.
    telemetry.ingest("alerts", frame({**alert, "name": "OldAlert", "startedAt": utc(clock()-10000)}))
    telemetry.ingest("alerts", frame({**alert, "name": "ServiceOnly", "audiences": ["Service"]}))
    assert kinds(store) == ["alert_started", "alert_ended"]


def test_connectivity_change_is_per_connection_and_not_proof_of_offline(store, clock):
    telemetry = Telemetry(store)
    def frame(status, when=None):
        return {"vin": VIN, "createdAt": utc(clock() if when is None else when), "connectionId": "test-connection", "status": status}
    telemetry.ingest("connectivity", frame("CONNECTED"))
    clock.advance(5)
    telemetry.ingest("connectivity", frame("CONNECTED"))
    clock.advance(5)
    telemetry.ingest("connectivity", frame("DISCONNECTED"))
    telemetry.ingest("connectivity", frame("CONNECTED", clock()-8))
    assert kinds(store) == ["connectivity_changed", "connectivity_changed"]
    with store.db() as db:
        assert all(json.loads(r[0])["vehicle_offline_proven"] is False for r in db.execute("SELECT data FROM events"))


def test_unlocked_needs_repeated_observations_of_each_signal(store, clock, vehicle_ref):
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, "unlocked_parked", {"dwell_seconds": 20})
    telemetry.ingest("V", payload(clock, {"Locked": False, "Gear": "ShiftStateP", "DriverSeatOccupied": False}))
    for _ in range(3):
        clock.advance(10)
        telemetry.ingest("V", payload(clock, {"Locked": False}))
    assert kinds(store) == []
    clock.advance(1)
    telemetry.ingest("V", payload(clock, {"Locked": False, "Gear": "ShiftStateP", "DriverSeatOccupied": False}))
    assert kinds(store) == ["unlocked_parked"]


def test_scalar_conversion_rejects_boolean_in_numeric_field():
    assert typed_value("BatteryLevel", {"stringValue": "52.5"}) == (52.5, "valid")
    assert typed_value("BatteryLevel", {"booleanValue": True})[1] == "invalid"
    assert typed_value("BatteryLevel", {"stringValue": "NaN"})[1] == "invalid"
    assert typed_value("BatteryLevel", {"stringValue": "1e999"})[1] == "invalid"


class Delivery:
    def __init__(self):
        self.calls, self.status = [], 200
    def post(self, url, body, headers):
        self.calls.append((url, body, headers))
        content = json.loads(body)
        if content.get("type") == "verification":
            return 200, json.dumps({"challenge": content["challenge"]}).encode()
        return self.status, b"{}"


def subscription(events, ref, clock, *, ttl=3600):
    secret = "whsec_"+base64.b64encode(b"synthetic-signing-key-for-tests!!").decode()
    filters = {"vehicle_ref": ref, "kinds": ["battery_low"]}
    result = events.subscribe("tesla.vehicle_event", filters, {"url": "https://receiver.example/callback", "secret": secret}, SCOPES,
                              expires_at=clock()+ttl)
    return result, filters, secret


def test_callback_signature_covers_exact_id_time_and_body():
    secret = "whsec_"+base64.b64encode(b"a"*32).decode()
    body = b'{"x":1}'
    headers = signed_headers(secret, "event-id", "sub-id", body, 12345)
    expected = base64.b64encode(hmac.digest(b"a"*32, b"event-id.12345."+body, "sha256")).decode()
    assert headers["webhook-signature"] == "v1,"+expected


@pytest.mark.parametrize("url", ["http://receiver.example/x", "https://user@receiver.example/x", "https://receiver.example:444/x",
                                  "https://127.0.0.1/x", "https://receiver.example.evil.test/x", "https://receiver.example/x#fragment"])
def test_callback_url_restrictions(url):
    with pytest.raises(CallbackError):
        callback_url(url, ["receiver.example"])


def test_dns_rebinding_private_address_rejected_before_socket(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(CallbackError, match="non_public_address"):
        PinnedHTTPS("receiver.example").connect()


def test_event_retry_preserves_identity_and_persisted_body(store, clock, vehicle_ref):
    delivery = Delivery()
    events = Events(store, transport=delivery)
    sub, filters, secret = subscription(events, vehicle_ref, clock)
    with store.db() as db:
        event = Events.emit(db, vehicle_ref, "battery_low", clock(), {"level": 20}, clock())
    delivery.status = 503
    assert events.dispatch_one()
    first = delivery.calls[-1]
    clock.advance(3)
    delivery.status = 200
    assert events.dispatch_one()
    second = delivery.calls[-1]
    assert first[1] == second[1]
    assert first[2]["webhook-id"] == second[2]["webhook-id"] == event
    with store.db() as db:
        assert db.execute("SELECT state FROM deliveries").fetchone()[0] == "accepted"
        assert secret.encode() not in bytes(db.execute("SELECT secret FROM subscriptions").fetchone()[0])


def test_expiration_and_unsubscribe_cancel_queued_notifications(store, clock, vehicle_ref):
    delivery = Delivery()
    events = Events(store, transport=delivery)
    sub, filters, _ = subscription(events, vehicle_ref, clock, ttl=10)
    with store.db() as db:
        Events.emit(db, vehicle_ref, "battery_low", clock(), {}, clock())
    clock.advance(11)
    assert events.dispatch_one() is False
    assert len(delivery.calls) == 1  # Verification only.
    events.unsubscribe("tesla.vehicle_event", filters, "https://receiver.example/callback", SCOPES)


@pytest.mark.parametrize("reactivation", ["expired", "unsubscribed"])
def test_subscription_reactivation_preserves_accepted_delivery_history(store, clock, vehicle_ref, reactivation):
    delivery = Delivery()
    events = Events(store, transport=delivery)
    initial, filters, secret = subscription(events, vehicle_ref, clock, ttl=10)
    with store.db() as db:
        accepted = Events.emit(db, vehicle_ref, "battery_low", clock(), {"case": "accepted"}, clock())
    assert events.dispatch_one()
    with store.db() as db:
        queued = Events.emit(db, vehicle_ref, "battery_low", clock(), {"case": "queued"}, clock())
        before = tuple(db.execute("SELECT state,attempts,last_code FROM deliveries WHERE event=?", (accepted,)).fetchone())
    assert before == ("accepted", 1, "200")
    if reactivation == "expired":
        clock.advance(11)
    else:
        events.unsubscribe("tesla.vehicle_event", filters, "https://receiver.example/callback", SCOPES)
    renewed = events.subscribe("tesla.vehicle_event", filters,
                              {"url": "https://receiver.example/callback", "secret": secret}, SCOPES,
                              expires_at=clock()+3600)
    assert renewed["id"] == initial["id"]
    with store.db() as db:
        assert tuple(db.execute("SELECT state,attempts,last_code FROM deliveries WHERE event=?", (accepted,)).fetchone()) == before
        assert db.execute("SELECT state FROM deliveries WHERE event=?", (queued,)).fetchone()[0] == "cancelled"
        new = Events.emit(db, vehicle_ref, "battery_low", clock(), {"case": "after reactivation"}, clock())
    assert events.dispatch_one()
    assert not events.dispatch_one()
    sent_ids = [json.loads(body)["eventId"] for _, body, _ in delivery.calls if "eventId" in json.loads(body)]
    assert sent_ids == [accepted, new]


def test_callback_410_terminates_current_subscription(store, clock, vehicle_ref):
    delivery = Delivery()
    events = Events(store, transport=delivery)
    subscription(events, vehicle_ref, clock)
    with store.db() as db:
        Events.emit(db, vehicle_ref, "battery_low", clock(), {}, clock())
    delivery.status = 410
    events.dispatch_one()
    with store.db() as db:
        assert db.execute("SELECT active FROM subscriptions").fetchone()[0] == 0


def test_challenge_failure_does_not_save_subscription(store, clock, vehicle_ref):
    delivery = Delivery()
    delivery.post = lambda *args: (200, b'{"challenge":"wrong"}')
    events = Events(store, transport=delivery)
    with pytest.raises(CallbackError):
        subscription(events, vehicle_ref, clock)
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM subscriptions").fetchone()[0] == 0


def test_signing_secret_rotation_has_bounded_overlap(store, clock, vehicle_ref):
    delivery = Delivery()
    events = Events(store, transport=delivery)
    initial, filters, old = subscription(events, vehicle_ref, clock)
    new = "whsec_"+base64.b64encode(b"another-synthetic-signing-secret!").decode()
    refreshed = events.subscribe("tesla.vehicle_event", filters, {"url": "https://receiver.example/callback", "secret": new}, SCOPES,
                                 expires_at=clock()+3600)
    assert refreshed["id"] == initial["id"]
    with store.db() as db:
        Events.emit(db, vehicle_ref, "battery_low", clock(), {}, clock())
    events.dispatch_one()
    assert delivery.calls[-1][2]["webhook-signature"].count("v1,") == 2
    clock.advance(301)
    with store.db() as db:
        db.execute("UPDATE vehicles SET checked=?", (clock(),))
        Events.emit(db, vehicle_ref, "battery_low", clock(), {}, clock())
    events.dispatch_one()
    assert delivery.calls[-1][2]["webhook-signature"].count("v1,") == 1


def test_expiry_during_verification_never_activates_subscription(store, clock, vehicle_ref):
    delivery = Delivery()
    original = delivery.post
    def slow(*args):
        result = original(*args)
        clock.advance(11)
        return result
    delivery.post = slow
    with pytest.raises(CallbackError):
        subscription(Events(store, transport=delivery), vehicle_ref, clock, ttl=10)
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM subscriptions").fetchone()[0] == 0
