"""Opt-in, queued-event authorization checks. No vehicle wake or data polling."""
import json
import secrets

from .catalogue import operation
from .errors import TeslaError
from .store import canonical, utc

POLICY = "event_delivery_access"
STATE_KEY = "event_delivery_access_check"
FRESH_SECONDS = 300
WINDOW_SECONDS = 900
MAX_ATTEMPTS = 3
MAX_PAGES = 3
LEASE_SECONDS = 60


def automatic_enabled(db, ref, generation):
    row = db.execute("SELECT data FROM snapshots WHERE vehicle=? AND section=?", (ref, POLICY)).fetchone()
    policy = json.loads(row[0]) if row else {}
    # A new account consent must not inherit background-call permission.
    return policy.get("automatic") is True and policy.get("generation") == generation


def read_state(db, generation):
    row = db.execute("SELECT value FROM meta WHERE key=?", (STATE_KEY,)).fetchone()
    state = json.loads(row[0]) if row else {}
    return state if state.get("generation") == generation else {"generation": generation}


def write_state(db, state):
    db.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (STATE_KEY, canonical(state)))


def diagnostics(store, ref, connection):
    generation = connection["generation"] if connection else None
    with store.db() as db:
        enabled = automatic_enabled(db, ref, generation)
        state = read_state(db, generation)
    blocked = ("automatic_checks_disabled" if not enabled else prerequisite_error(store, connection))
    return {"automatic": enabled, "trigger": "eligible_queued_event_only", "wake_sent": False,
            "blocked_reason": blocked,
            "membership_max_age_seconds": FRESH_SECONDS,
            "max_attempts_per_window": MAX_ATTEMPTS, "window_seconds": WINDOW_SECONDS,
            "max_pages_per_attempt": MAX_PAGES,
            "last_started_at": utc(state["started"]) if state.get("started") else None,
            "last_finished_at": utc(state["finished"]) if state.get("finished") else None,
            "last_result": state.get("result"), "last_error_code": state.get("error"),
            "retry_after": utc(state["next_attempt"]) if state.get("next_attempt", 0) > store.clock() else None,
            "in_progress": state.get("lease_until", 0) > store.clock(),
            "provider_operation": "vehicle_list", "pricing_category": operation("vehicle_list")["pricing_category"],
            "billing_note": "Separate REST authorization check, not telemetry streaming. Uses the catalogue's no-charge endpoint only; provider billing remains authoritative. Token renewal may also be needed."}


def prerequisite_error(store, connection):
    op = operation("vehicle_list")
    if not connection:
        return "authorization_required"
    if not store.settings.live_enabled:
        return "live_disabled"
    if not set(op["scopes"]) <= set(json.loads(connection["scopes"])):
        return "tesla_scope_required"
    if not op["readonly"] or op["pricing_category"] != "explicit_null_no_charge":
        return "pricing_review_required"
    return None


class DeliveryAccess:
    def __init__(self, service):
        self.store, self.fleet = service.store, service.fleet

    def check(self, ref):
        """Called only for an otherwise eligible pending delivery, outside its transaction.

        Return the earliest retry time, or None after a successful check. The
        dispatcher must revalidate the original delivery after this network gap.
        Account-wide leases and attempt history survive worker restarts.
        """
        now = self.store.clock()
        try:
            connection = self.store.connection()
        except TeslaError:
            return now + WINDOW_SECONDS
        generation = connection["generation"]
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            active = db.execute("SELECT * FROM connection WHERE id=1 AND status='active'").fetchone()
            if not active or active["generation"] != generation or not automatic_enabled(db, ref, generation):
                return now + 60
            vehicle = db.execute("SELECT checked FROM vehicles WHERE ref=? AND active=1", (ref,)).fetchone()
            if not vehicle:
                return now + WINDOW_SECONDS
            if 0 <= now-vehicle[0] <= FRESH_SECONDS:
                return None
            state = read_state(db, generation)
            attempts = [t for t in state.get("attempts", []) if t > now-WINDOW_SECONDS]
            retry_at = max(state.get("lease_until", 0), state.get("next_attempt", 0),
                           min(attempts)+WINDOW_SECONDS if len(attempts) >= MAX_ATTEMPTS else 0)
            if retry_at > now:
                return retry_at
            if prerequisite_error(self.store, active):
                # Do not silently turn a changed tariff into new automatic costs.
                return now + WINDOW_SECONDS
            reservation = secrets.token_hex(12)
            state.update(attempts=attempts+[now], started=now, finished=None, result="checking", error=None,
                         reservation=reservation, lease_until=now+LEASE_SECONDS, next_attempt=now+LEASE_SECONDS)
            write_state(db, state)
        error = None
        try:
            self.fleet.discover(max_pages=MAX_PAGES, expected_generation=generation)
        except TeslaError as exc:
            # Codes are controlled by the bridge; never persist provider text.
            error = exc.code
        except Exception:
            error = "ACCESS_CHECK_FAILED"
        now = self.store.clock()
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            state = read_state(db, generation)
            active = db.execute("SELECT * FROM connection WHERE id=1 AND status='active'").fetchone()
            if not active or active["generation"] != generation or state.get("reservation") != reservation:
                return now + WINDOW_SECONDS
            if prerequisite_error(self.store, active) and error is None:
                error = "ACCESS_PERMISSION_CHANGED"
            vehicle = db.execute("SELECT checked FROM vehicles WHERE ref=? AND active=1", (ref,)).fetchone()
            verified = error is None and vehicle and 0 <= now-vehicle[0] <= FRESH_SECONDS
            if not verified and error is None:
                error = "VEHICLE_ACCESS_REQUIRED"
            failures = 0 if verified else state.get("failures", 0)+1
            retry_at = now if verified else now+min(300, 60*2**min(failures-1, 3))
            attempts = [t for t in state["attempts"] if t > now-WINDOW_SECONDS]
            if len(attempts) >= MAX_ATTEMPTS:
                retry_at = max(retry_at, min(attempts)+WINDOW_SECONDS)
            state.update(finished=now, lease_until=0, next_attempt=retry_at, failures=failures,
                         result="verified" if verified else "blocked", error=error)
            write_state(db, state)
        return None if verified else retry_at
