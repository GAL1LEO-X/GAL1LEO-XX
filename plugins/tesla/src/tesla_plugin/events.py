"""Persistent MCP Events; signing and delivery are independent of vehicle commands."""
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import secrets
import socket
import ssl
from urllib.parse import urlsplit

from .errors import TeslaError
from .store import canonical, digest, utc
from .trigger_catalog import EVENT_KINDS, LOCATION_EVENTS, event_selected, location_allowed
from .delivery_access import FRESH_SECONDS
from .authorization import Authorization
from .state_sequences import advance, counter, membership_key, subscription_key
from . import event_support

class CallbackError(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def signing_key(secret):
    try:
        if not isinstance(secret, str) or not secret.startswith("whsec_"):
            raise ValueError()
        key = base64.b64decode(secret[6:], validate=True)
        if not 24 <= len(key) <= 64:
            raise ValueError()
        return key
    except ValueError:
        raise CallbackError("invalid_secret") from None


def signed_headers(secret, event_id, subscription_id, body, now, previous_secret=None):
    when = str(int(now))
    signature = base64.b64encode(hmac.digest(signing_key(secret), event_id.encode()+b"."+when.encode()+b"."+body, "sha256")).decode()
    signatures = "v1,"+signature
    if previous_secret and previous_secret != secret:
        old = base64.b64encode(hmac.digest(signing_key(previous_secret), event_id.encode()+b"."+when.encode()+b"."+body, "sha256")).decode()
        signatures += " v1,"+old
    return {"Content-Type": "application/json", "webhook-id": event_id, "webhook-timestamp": when,
            "webhook-signature": signatures, "X-MCP-Subscription-Id": subscription_id}


def callback_url(url, allowed_hosts):
    try:
        u = urlsplit(url)
        if (len(url)>2048 or any(ord(c)<33 for c in url) or u.scheme!="https" or not u.hostname
                or u.hostname not in allowed_hosts or u.port not in (None, 443) or u.username or u.password or u.fragment):
            raise ValueError()
        return u
    except (TypeError, ValueError):
        raise CallbackError("invalid_url") from None


class PinnedHTTPS(http.client.HTTPSConnection):
    def connect(self):
        addresses = socket.getaddrinfo(self.host, 443, type=socket.SOCK_STREAM)
        if not addresses:
            raise CallbackError("dns_failed")
        for _, _, _, _, address in addresses:
            ip = ipaddress.ip_address(address[0])
            if not ip.is_global or getattr(ip, "ipv4_mapped", None) is not None:
                raise CallbackError("non_public_address")
        # One validated DNS answer set; connect to numeric addresses with the
        # original hostname retained for SNI and certificate verification.
        for family, kind, proto, _, address in addresses:
            sock = socket.socket(family, kind, proto)
            sock.settimeout(self.timeout)
            try:
                sock.connect(address)
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
                return
            except OSError:
                sock.close()
        raise CallbackError("connection_failed")


class HTTPSDelivery:
    def __init__(self, hosts):
        self.hosts = hosts

    def post(self, url, body, headers):
        u = callback_url(url, self.hosts)
        if any(os.environ.get(k) for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")):
            # Do not bypass managed Cloud egress. Qualify a proxy-aware pinned
            # transport before enabling actual callbacks in such an environment.
            raise CallbackError("proxy_transport_not_qualified")
        conn = PinnedHTTPS(u.hostname, timeout=8, context=ssl.create_default_context())
        try:
            conn.request("POST", (u.path or "/")+("?"+u.query if u.query else ""), body, headers)
            response = conn.getresponse()
            data = response.read(65537)
            if len(data)>65536:
                raise CallbackError("response_too_large")
            return response.status, data
        except (OSError, http.client.HTTPException):
            raise CallbackError("connection_failed") from None
        finally:
            conn.close()


class Events:
    def __init__(self, store, *, transport=None, access_check=None):
        self.store, self.settings = store, store.settings
        self.transport = transport or HTTPSDelivery(self.settings.callback_hosts)
        self.access_check = access_check

    @staticmethod
    def _filters(arguments):
        """Canonical identity, without requirements for granting new access."""
        if not isinstance(arguments, dict) or set(arguments) != {"vehicle_ref", "kinds"}:
            raise TeslaError("INVALID_ARGUMENT", "Select a vehicle and event kinds")
        if not isinstance(arguments["vehicle_ref"], str) or not arguments["vehicle_ref"]:
            raise TeslaError("INVALID_ARGUMENT", "Select a vehicle reference")
        kinds = arguments["kinds"]
        if not isinstance(kinds, list) or not kinds or any(not isinstance(k, str) or k not in EVENT_KINDS for k in kinds):
            raise TeslaError("INVALID_ARGUMENT", "Unknown event kind")
        return {"vehicle_ref": arguments["vehicle_ref"], "kinds": sorted(set(kinds))}

    @staticmethod
    def _subscription_access(db, filters, scopes):
        connection = db.execute("SELECT * FROM connection WHERE id=1 AND status='active'").fetchone()
        if not connection:
            raise TeslaError("AUTH_REQUIRED", "Connect your Tesla account before subscribing")
        vehicle = db.execute("SELECT * FROM vehicles WHERE ref=? AND active=1", (filters["vehicle_ref"],)).fetchone()
        if not vehicle:
            raise TeslaError("VEHICLE_ACCESS_REQUIRED", "Choose a currently authorized vehicle")
        if set(filters["kinds"]) & LOCATION_EVENTS:
            # Broad field events may reference location; require that grant for
            # the whole subscription rather than disclose data through a callback.
            if not location_allowed(connection, {"data": json.loads(vehicle["data"])}, scopes):
                raise TeslaError("LOCATION_WITHHELD", "These event kinds require location authorization")
        return connection

    def filters(self, arguments, scopes):
        filters = self._filters(arguments)
        with self.store.db() as db:
            self._subscription_access(db, filters, scopes)
        return filters

    def subscribe(self, name, arguments, delivery, scopes, *, expires_at, ttl_ms=None):
        if name != "tesla.vehicle_event" or "tesla:events" not in scopes:
            raise TeslaError("SCOPE_REQUIRED", "Tesla event authorization is required")
        filters = self._filters(arguments)
        delivery, scopes = dict(delivery), frozenset(scopes)
        callback_url(delivery["url"], self.settings.callback_hosts)
        signing_key(delivery["secret"])
        now = self.store.clock()
        expiry = min(now+86400, expires_at, now+ttl_ms/1000 if ttl_ms is not None else now+86400)
        if expiry <= now:
            raise TeslaError("AUTH_REQUIRED", "Subscription authorization has expired")
        identifier = "sub_"+digest(canonical([self.settings.owner_subject, name, filters, delivery["url"]]))
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            connection = self._subscription_access(db, filters, scopes)
            authorization = Authorization.from_row(self.store, connection)
            membership = counter(db, membership_key(filters["vehicle_ref"]))
            db.execute("INSERT OR IGNORE INTO meta VALUES(?, '0')", (subscription_key(identifier),))
            subscription = counter(db, subscription_key(identifier))
        challenge = secrets.token_urlsafe(32)
        body = canonical({"type": "verification", "challenge": challenge}).encode()
        headers = signed_headers(delivery["secret"], "verify_"+secrets.token_hex(16), identifier, body, now)
        status, response = self.transport.post(delivery["url"], body, headers)
        try:
            echo = json.loads(response).get("challenge")
            verified = isinstance(echo, str) and hmac.compare_digest(echo, challenge)
        except (ValueError, AttributeError):
            verified = False
        if not 200 <= status < 300 or not verified or self.store.clock()-now > 30 or expiry <= self.store.clock():
            raise CallbackError("challenge_failed")
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            self.store.assert_authorization(db, authorization)
            self._subscription_access(db, filters, scopes)
            if (counter(db, membership_key(filters["vehicle_ref"])) != membership
                    or counter(db, subscription_key(identifier)) != subscription):
                raise TeslaError("SUBSCRIPTION_CHANGED", "Subscription or vehicle access changed during verification; start a new subscription")
            if expiry <= self.store.clock():
                raise TeslaError("AUTH_REQUIRED", "Subscription authorization has expired")
            if self.store.clock()-now > 30:
                raise CallbackError("challenge_failed")
            old = db.execute("SELECT * FROM subscriptions WHERE id=?", (identifier,)).fetchone()
            generation = old["generation"] if old else 1
            previous, previous_until = (old["old_secret"], old["old_secret_until"]) if old else (None, 0)
            if old and self.store.unseal(old["secret"]) != delivery["secret"]:
                previous, previous_until = old["secret"], self.store.clock()+300
            if old and (not old["active"] or old["expires"] <= self.store.clock()):
                generation += 1
                db.execute("UPDATE deliveries SET state='cancelled' WHERE subscription=? AND state IN ('pending','sending')", (identifier,))
            db.execute("INSERT OR REPLACE INTO subscriptions VALUES(?,?,?,?,?,?,?,1,?,?)",
                       (identifier, name, canonical(filters), delivery["url"], self.store.seal(delivery["secret"]), expiry, generation, previous, previous_until))
            advance(db, subscription_key(identifier))
        return {"id": identifier, "refreshBefore": utc(expiry), "cursor": None, "truncated": False}

    def unsubscribe(self, name, arguments, url, scopes):
        if name != "tesla.vehicle_event":
            raise TeslaError("INVALID_ARGUMENT", "Unknown event")
        if "tesla:events" not in scopes:
            raise TeslaError("SCOPE_REQUIRED", "Tesla event authorization is required")
        # Revocation needs the owner's exact subscription identity, not current
        # Tesla membership or the location grants required to activate it.
        filters = self._filters(arguments)
        if not isinstance(url, str):
            raise TeslaError("INVALID_ARGUMENT", "Select a subscription callback URL")
        identifier = "sub_"+digest(canonical([self.settings.owner_subject, name, filters, url]))
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            # A pending initial handshake has reserved its identity in metadata.
            # Unknown identities are a no-op, without accumulating tombstones.
            if (db.execute("SELECT 1 FROM meta WHERE key=?", (subscription_key(identifier),)).fetchone()
                    or db.execute("SELECT 1 FROM subscriptions WHERE id=?", (identifier,)).fetchone()):
                advance(db, subscription_key(identifier))
            db.execute("UPDATE subscriptions SET active=0 WHERE id=?", (identifier,))
            db.execute("UPDATE deliveries SET state='cancelled' WHERE subscription=? AND state IN ('pending','sending')", (identifier,))
        return {}

    @staticmethod
    def emit(db, vehicle, kind, occurred, data, now, *, support=None):
        if support is None and 'changes' in data:
            support = event_support.for_event(data)
        if support is not None:
            data = data | {event_support.KEY: support}
        identifier = "evt_"+digest(canonical([vehicle, kind, occurred, data]))
        added = db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?)", (identifier, kind, vehicle, occurred, canonical(data))).rowcount
        if not added:
            return identifier
        if event_support.conflicted(db, vehicle, support):
            return identifier
        if not event_selected(db, vehicle, kind):
            return identifier
        for sub in db.execute("SELECT * FROM subscriptions WHERE active=1 AND expires>?", (now,)).fetchall():
            filters = json.loads(sub["filters"])
            if filters["vehicle_ref"] != vehicle or kind not in filters["kinds"]:
                continue
            summary = {"event_id": identifier, "vehicle_ref": vehicle, "kind": kind, "quality": "observed"}
            body = canonical({"eventId": identifier, "name": "tesla.vehicle_event", "timestamp": utc(occurred), "data": summary, "cursor": None}).encode()
            delivery_id = digest(canonical([sub["id"], sub["generation"], identifier]))
            db.execute("INSERT OR IGNORE INTO deliveries VALUES(?,?,?,?,?,'pending',0,?,0,NULL)",
                       (delivery_id, sub["id"], sub["generation"], identifier, body, now))
        return identifier

    def dispatch_one(self, *, _delivery_id=None, _allow_check=True):
        now = self.store.clock()
        needs_access = None
        try:
            connection = self.store.connection()
        except TeslaError:
            return False
        if "vehicle_device_data" not in json.loads(connection["scopes"]):
            return False
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE deliveries SET state='pending' WHERE state='sending' AND lease<=?", (now,))
            db.execute("UPDATE deliveries SET state='cancelled' WHERE state IN ('pending','sending') AND subscription IN (SELECT id FROM subscriptions WHERE active=0 OR expires<=?)", (now,))
            row = db.execute("SELECT d.*,s.url,s.secret,s.old_secret,s.old_secret_until,s.expires,s.active,s.filters,s.generation AS current_generation FROM deliveries d JOIN subscriptions s ON s.id=d.subscription WHERE d.state='pending' AND d.next_attempt<=? AND (? IS NULL OR d.id=?) ORDER BY d.next_attempt,d.id LIMIT 1", (now, _delivery_id, _delivery_id)).fetchone()
            if not row:
                return False
            source = db.execute("SELECT occurred,name,vehicle,data FROM events WHERE id=?", (row["event"],)).fetchone()
            if source and row['attempts'] == 0:
                data = json.loads(source['data'])
                support = event_support.for_event(data)
                # No invented timestamps for legacy rule events. History and
                # already attempted deliveries remain unchanged.
                missing = (('rule_id' in data and 'observed' in data or 'changes' in data)
                           and not event_support.known(support))
                if missing or event_support.conflicted(db, source['vehicle'], support):
                    db.execute("UPDATE deliveries SET state='cancelled',last_code=? WHERE id=?",
                               ('support_unavailable' if missing else 'support_time_conflict', row['id']))
                    return True
            vehicle = db.execute("SELECT active,checked,data FROM vehicles WHERE ref=?", (json.loads(row["filters"])["vehicle_ref"],)).fetchone()
            if source and (not event_selected(db, source["vehicle"], source["name"]) or (source["name"] in LOCATION_EVENTS and vehicle and
                    not location_allowed(self.store.connection(), {"data": json.loads(vehicle["data"])}, ("tesla:location",)))):
                db.execute("UPDATE deliveries SET state='cancelled' WHERE id=?", (row["id"],))
                return True
            if (not source or not vehicle or not vehicle[0] or not -0.001 <= now-source[0] <= 900
                    or row["generation"] != row["current_generation"] or row["attempts"] >= 8):
                db.execute("UPDATE deliveries SET state='expired' WHERE id=?", (row["id"],))
                return True
            if not 0 <= now-vehicle["checked"] <= FRESH_SECONDS:
                needs_access = source["vehicle"]
            else:
                db.execute("UPDATE deliveries SET state='sending',attempts=attempts+1,lease=? WHERE id=?", (now+30, row["id"]))
        if needs_access:
            if not self.access_check or not _allow_check:
                return False
            retry_at = self.access_check.check(needs_access)
            if retry_at is None:
                # Ownership, selectors, scopes, subscription/generation and age
                # can all change during the network call. Claim the same event
                # only after checking them again; never send the stale row.
                return self.dispatch_one(_delivery_id=row["id"], _allow_check=False)
            with self.store.db() as db:
                # A blocked vehicle must not starve unrelated fresh deliveries.
                # Authorization checks do not consume webhook retry attempts.
                db.execute("UPDATE deliveries SET next_attempt=? WHERE id=? AND state='pending'",
                           (min(retry_at, source["occurred"]+901), row["id"]))
            return False
        try:
            previous = self.store.unseal(row["old_secret"]) if row["old_secret"] and row["old_secret_until"] > now else None
            headers = signed_headers(self.store.unseal(row["secret"]), row["event"], row["subscription"], row["body"], now, previous)
            code, _ = self.transport.post(row["url"], row["body"], headers)
            if 200 <= code < 300:
                state = "accepted"
            elif code == 429 or 500 <= code < 600:
                state = "pending"
            else:
                state = "failed"
            reason = str(code)
        except CallbackError as exc:
            state, reason, code = "pending", exc.reason, None
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT * FROM subscriptions WHERE id=?", (row["subscription"],)).fetchone()
            # The captured persisted ciphertext identifies this renewal even
            # when the plaintext secret is unchanged. Never re-encrypt to compare.
            same_renewal = bool(current and current["generation"] == row["generation"]
                                and current["secret"] == row["secret"] and current["expires"] == row["expires"])
            if code == 410 and current and current["active"] and current["generation"] == row["generation"] and not same_renewal:
                state, reason = "pending", "obsolete_410_after_renewal"
            completed = db.execute("UPDATE deliveries SET state=?,next_attempt=?,lease=0,last_code=? "
                                   "WHERE id=? AND generation=? AND state='sending' AND attempts=?",
                                   (state, self.store.clock()+min(300, 2**(row["attempts"]+1)), reason,
                                    row["id"], row["generation"], row["attempts"]+1)).rowcount
            if completed and code == 410 and same_renewal:
                db.execute("UPDATE subscriptions SET active=0 WHERE id=? AND generation=? AND secret=? AND expires=?",
                           (row["subscription"], row["generation"], row["secret"], row["expires"]))
        return True
