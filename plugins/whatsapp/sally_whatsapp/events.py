"""Persistent MCP Events with Standard Webhooks signing and pinned HTTPS delivery."""
import base64
from datetime import datetime
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import secrets
import socket
import ssl
import time
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from .config import secret
from .event_policies import normalize_filters, quiet_until
from .store import canonical, utc
from .event_recovery import attempt_limit,source_reason
from .callback_audit import cancel as cancel_delivery

log = logging.getLogger(__name__)


class CallbackError(Exception):
    def __init__(self, reason, *, status_code=None):
        self.reason = reason
        self.status_code = status_code
        super().__init__(reason)


def signing_key(value):
    if not isinstance(value, str) or not value.startswith("whsec_"):
        raise ValueError("Expected whsec_ signing secret")
    try:
        key = base64.b64decode(value[6:], validate=True)
    except ValueError:
        raise ValueError("Invalid signing secret") from None
    if not 24 <= len(key) <= 64:
        raise ValueError("Signing key must contain 24..64 bytes")
    return key


def signed_headers(secret_value, event_id, subscription_id, body, timestamp=None, previous_secrets=()):
    timestamp = int(time.time()) if timestamp is None else int(timestamp)
    signed = event_id.encode() + b"." + str(timestamp).encode() + b"." + body
    signatures = ["v1,"+base64.b64encode(hmac.digest(signing_key(key), signed, "sha256")).decode()
                  for key in [secret_value,*previous_secrets]]
    return {"Content-Type": "application/json", "webhook-id": event_id, "webhook-timestamp": str(timestamp),
            "webhook-signature": " ".join(signatures), "X-MCP-Subscription-Id": subscription_id}


def callback_url(url, allowed_hosts):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 for c in url):
        raise CallbackError("invalid_url")
    try:
        u = urlsplit(url)
        if u.scheme != "https" or not u.hostname or u.username or u.password or u.fragment or u.port not in (None,443):
            raise ValueError()
        if u.hostname.lower() not in allowed_hosts:
            # Host only: callback paths, signing keys and payloads stay private.
            log.warning("Event callback host is not configured: %r", u.hostname.lower()[:253])
            raise CallbackError("host_not_allowed")
    except ValueError:
        raise CallbackError("invalid_url") from None
    return u


def public_addresses(host):
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not addresses:
        raise CallbackError("dns_failed")
    for family, kind, proto, canon, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global or getattr(ip, "ipv4_mapped", None) is not None:
            raise CallbackError("non_public_address")
    return addresses


class PinnedHTTPS(http.client.HTTPSConnection):
    def connect(self):
        # Resolve exactly once per connection. Do not resolve again after validation.
        addresses = public_addresses(self.host)
        last = None
        for family, kind, proto, _, address in addresses:
            sock = socket.socket(family, kind, proto)
            sock.settimeout(self.timeout)
            try:
                sock.connect(address)
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
                return
            except OSError as exc:
                last = exc
                sock.close()
        raise last or CallbackError("connect_failed")


class HTTPSDelivery:
    def __init__(self, allowed_hosts):
        self.allowed_hosts = allowed_hosts

    def post(self, url, body, headers):
        u = callback_url(url, self.allowed_hosts)
        conn = PinnedHTTPS(u.hostname, timeout=8, context=ssl.create_default_context())
        status = None
        try:
            conn.request("POST", (u.path or "/") + ("?"+u.query if u.query else ""), body, headers)
            response = conn.getresponse()
            status = response.status
            data = response.read(65537)
            if len(data)>65536:
                raise CallbackError("response_too_large", status_code=status)
            # No redirects, proxies, or URL-derived Authorization headers.
            return response.status, data
        except (OSError, http.client.HTTPException) as exc:
            raise CallbackError("timeout" if isinstance(exc, TimeoutError) else "connection_failed",
                                status_code=status) from None
        finally:
            conn.close()


class Events:
    def __init__(self, store, settings, transport=None):
        self.store, self.settings = store, settings
        self.cipher = Fernet(secret(settings.encryption_key_file).encode())
        self.transport = transport or HTTPSDelivery(settings.callback_hosts)

    @staticmethod
    def identity(owner, name, filters, url):
        return "sub_" + hashlib.sha256(canonical([owner,name,normalize_filters(name,filters),url]).encode()).hexdigest()

    def subscribe(self, owner, name, filters, delivery, *, ttl_ms=None, access_expires_at=None):
        filters = normalize_filters(name, filters)
        if name == 'message.digest' and filters['digest_window_seconds'] >= self.store.event_max_age_seconds:
            raise ValueError('Digest window must be shorter than event maximum age')
        callback_url(delivery["url"], self.settings.callback_hosts)
        signing_key(delivery["secret"])
        sub_id = self.identity(owner,name,filters,delivery["url"])
        verification_id=hashlib.sha256(canonical([owner,delivery["url"],delivery["secret"]]).encode()).hexdigest()
        with self.store.db() as db:
            cached=db.execute("SELECT expires FROM callback_verifications WHERE identity=?",(verification_id,)).fetchone()
        now=time.time()
        challenge = secrets.token_urlsafe(32)
        body = canonical({"type": "verification", "challenge": challenge}).encode()
        event_id = "verify_" + secrets.token_hex(16)
        if not cached or cached["expires"]<=now:
            status, data = self.transport.post(delivery["url"], body, signed_headers(delivery["secret"],event_id,sub_id,body))
            try:
                echoed = json.loads(data).get("challenge", "")
                verified = isinstance(echoed, str) and hmac.compare_digest(echoed,challenge)
            except (ValueError, AttributeError, TypeError):
                verified = False
            if not 200 <= status < 300 or not verified:
                raise CallbackError("challenge_failed")
        ttl=self.settings.subscription_ttl
        if ttl_ms is not None:
            # The validated request may be shorter than the configured minimum.
            # Configuration and token expiry are ceilings, never extensions.
            ttl=min(ttl,ttl_ms/1000)
        expires = time.time() + ttl
        if access_expires_at is not None:
            expires=min(expires,access_expires_at)
        if expires<=time.time():
            raise ValueError("Authorization expired")
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT active,expires,secret FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
            # Refresh an active subscription preserves its pending queue; reactivation does not replay old monitoring.
            if old and (not old["active"] or old["expires"] <= time.time()):
                cancel_delivery(db, "subscription=?", (sub_id,), "subscription_reactivated")
            db.execute("INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET secret=excluded.secret,expires=excluded.expires,active=1",
                       (sub_id,owner,name,canonical(filters),delivery["url"],self.cipher.encrypt(delivery["secret"].encode()),expires))
            if old and old["active"] and old["expires"]>now and self.cipher.decrypt(old["secret"]).decode()!=delivery["secret"]:
                db.execute("INSERT INTO subscription_keys VALUES(?,?,?)",(sub_id,old["secret"],now+60))
            db.execute("DELETE FROM subscription_keys WHERE expires<=?",(now,))
            db.execute("DELETE FROM callback_verifications WHERE expires<=?",(now,))
            db.execute("INSERT INTO callback_verifications VALUES(?,?) ON CONFLICT(identity) DO NOTHING",(verification_id,now+300))
        return {"id": sub_id, "refreshBefore": utc(expires), "cursor": None, "truncated": False}

    def unsubscribe(self, owner, name, filters, url):
        sub_id=self.identity(owner,name,filters,url)
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE subscriptions SET active=0 WHERE id=? AND owner=?", (sub_id,owner))
            cancel_delivery(db, "subscription IN (SELECT id FROM subscriptions WHERE id=? AND owner=? AND active=0)", (sub_id,owner), "subscription_unsubscribed")
        return {}

    def _event_current(self, db, event, now):
        if event.get('name') == 'message.digest':
            dates = [db.execute('SELECT timestamp FROM messages WHERE id=?', (item,)).fetchone()
                     for item in event.get('data', {}).get('message_ids', [])]
            return bool(dates) and all(r and 0 <= now - r[0] < self.store.event_max_age_seconds for r in dates)
        observed = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')).timestamp()
        return 0 <= now - observed < self.store.event_max_age_seconds

    def _unavailable_sources(self, db, event):
        data=event.get('data',{})
        if event.get('name')=='message.digest':
            return [item for item in data.get('message_ids',[]) if self.store.is_unavailable(db,item)]
        if event.get('name')=='message.received':
            identifier=data.get('message_id')
            return [identifier] if self.store.is_unavailable(db,identifier,chat_id=data.get('chat_id')) else []
        if event.get('name')=='whatsapp.event':
            source=db.execute('SELECT * FROM account_events WHERE id=?',(data.get('event_id'),)).fetchone()
            # Every wake-up must retain a readable event reference. An orphaned
            # delivery cannot satisfy the consumer's get_account_event lookup.
            if not source:
                return [data.get('event_id')]
            # State notifications remain meaningful precisely when their
            # target is unavailable. Content derivatives use all typed refs.
            if self.store.event_source_reason(db,source):
                return [source['id']]
        return []

    def dispatch_one(self, now=None):
        now = time.time() if now is None else now
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE deliveries SET state='pending' WHERE state='sending' AND lease_until<?", (now,))
            cancel_delivery(db, "subscription IN (SELECT id FROM subscriptions WHERE active=0 OR expires<=? OR owner<>?)", (now,self.settings.owner_subject), "authorization_unavailable", now=now)
            # Persistent round robin prevents a backlog of account receipts
            # from holding every newly acquired message behind it. Due-time
            # ordering within a class keeps ready retries from starving.
            cursor=db.execute("SELECT value FROM state WHERE key='private:callback_scheduler:v1'").fetchone()
            next_class=int(cursor[0]) if cursor and cursor[0] in ('0','1','2') else 0
            row = db.execute("""SELECT d.*,s.url,s.secret,s.filters,
                CASE s.name WHEN 'message.received' THEN 0 WHEN 'message.digest' THEN 1 ELSE 2 END AS queue_class
                FROM deliveries d JOIN subscriptions s ON s.id=d.subscription
                WHERE d.state IN ('collecting','pending') AND d.next_attempt<=?
                ORDER BY ((CASE s.name WHEN 'message.received' THEN 0 WHEN 'message.digest' THEN 1 ELSE 2 END-?+3)%3),
                    d.next_attempt,d.id LIMIT 1""", (now,next_class)).fetchone()
            if not row:
                return False
            self.store._state(db,'private:callback_scheduler:v1',(row['queue_class']+1)%3)
            recovery_limit=attempt_limit(db,row['id'])
            # Claims consume attempts even if the process dies before HTTP.
            # Check the budget under the same write lock as lease recovery and
            # claim, so pending rows and expired leases cannot exceed it. Only
            # an explicit administrative permit authorizes an extra attempt.
            limit = self.settings.max_callback_attempts if recovery_limit is None else recovery_limit
            if row['attempts'] >= limit:
                db.execute("UPDATE deliveries SET state='failed',last_status=0,lease_until=0 WHERE id=?",(row['id'],))
                return True
            if recovery_limit is not None:
                if source_reason(self.store,self.settings,db,row,now):
                    cancel_delivery(db, "id=?", (row["id"],), "recovery_source_changed", reset_lease=True, now=now)
                    return True
            filters = json.loads(row['filters'])
            due = quiet_until(now, filters.get('quiet_hours'))
            if due > now:
                db.execute('UPDATE deliveries SET next_attempt=? WHERE id=?', (due, row['id']))
                return True
            event = json.loads(row['body'])
            members = (event.get('data', {}).get('message_ids', []) if event.get('name') == 'message.digest'
                       else [event.get('data', {}).get('message_id')] if event.get('name') == 'message.received'
                       else [])
            if event.get('name') == 'message.digest':
                dates = [db.execute('SELECT timestamp FROM messages WHERE id=?', (item,)).fetchone() for item in members]
                valid = [item for item, date in zip(members, dates) if date and 0 <= now - date[0] < self.store.event_max_age_seconds]
                expired = len(valid) != len(members) or not valid
                if expired and valid and row['attempts'] == 0:
                    # The collecting payload has never left the bridge. Trim stale
                    # members without sacrificing fresh members or changing IDs.
                    event['data']['message_ids'] = valid
                    row = dict(row)
                    row['body'] = canonical(event)
                    db.execute('UPDATE deliveries SET body=? WHERE id=?', (row['body'], row['id']))
                    self.store.require_recovery('callback_event_outside_age_window', db=db)
                    members, expired = valid, False
            else:
                expired = not self._event_current(db, event, now)
            if expired:
                cancel_delivery(db, "id=?", (row["id"],), "event_expired", now=now)
                self.store.require_recovery('callback_event_outside_age_window', db=db)
                return True
            revoked = [item for item in members if self.store.is_revoked(db, item)]
            for item in revoked:
                self.store._revoke_derivatives(db, item)
            if revoked:
                return True
            unavailable=self._unavailable_sources(db,event)
            if unavailable:
                # Linked-device exclusions retain the archive. They must not
                # invoke the destructive revoke repair or emit old previews.
                remaining=[item for item in members if item not in unavailable]
                if event.get('name')=='message.digest' and remaining and row['attempts']==0:
                    # This batch has never left the bridge: preserve valid
                    # members without consuming another ID or losing a wake-up.
                    event['data']['message_ids']=remaining
                    row=dict(row)
                    row['body']=canonical(event)
                    db.execute('UPDATE deliveries SET body=? WHERE id=?',(row['body'],row['id']))
                else:
                    if event.get('name')=='message.digest' and remaining and row['attempts']:
                        self.store.require_recovery('digest_cancelled_after_attempt',db=db)
                    cancel_delivery(db, "id=?", (row["id"],), "source_unavailable", reset_lease=True, now=now)
                    return True
            db.execute("UPDATE deliveries SET state='sending',lease_until=?,attempts=attempts+1 WHERE id=?", (now+120,row["id"]))
        body = row["body"].encode()
        status = 0
        transport_duration_ms = 0
        attempt_at = accepted_at = None
        try:
            if len(body)>262144:
                status = 413
            else:
                signing_secret = self.cipher.decrypt(row["secret"]).decode()
                with self.store.db() as db:
                    current=db.execute("""SELECT d.state,d.attempts,s.active,s.expires,s.owner,s.secret FROM deliveries d
                        JOIN subscriptions s ON s.id=d.subscription WHERE d.id=?""",(row['id'],)).fetchone()
                    if current['state']!='sending' or current['attempts']!=row['attempts']+1: return True
                    if not current['active'] or current['expires'] <= max(now,time.time()) or current['owner'] != self.settings.owner_subject:
                        cancel_delivery(db, "id=? AND state='sending' AND attempts=?", (row["id"],row["attempts"]+1), "authorization_unavailable")
                        return True
                    current_now = max(now,time.time())
                    unavailable=self._unavailable_sources(db,event)
                    if unavailable:
                        if event.get('name')=='message.digest' and any(
                                item not in unavailable for item in event['data']['message_ids']):
                            self.store.require_recovery('digest_cancelled_after_attempt',db=db)
                        cancel_delivery(db, "id=? AND state='sending' AND attempts=?", (row["id"],row["attempts"]+1), "source_unavailable", reset_lease=True)
                        return True
                    if not self._event_current(db, event, current_now):
                        cancel_delivery(db, "id=? AND state='sending' AND attempts=?", (row["id"],row["attempts"]+1), "event_expired")
                        self.store.require_recovery('callback_event_outside_age_window', db=db)
                        return True
                    if recovery_limit is not None and source_reason(self.store,self.settings,db,row,current_now):
                        # A source edit or policy change after claim invalidates
                        # the administrative recovery too; keep its attempt consumed.
                        cancel_delivery(db, "id=? AND state='sending' AND attempts=?", (row["id"],row["attempts"]+1), "recovery_source_changed")
                        return True
                    due = quiet_until(current_now, filters.get('quiet_hours'))
                    if due > current_now:
                        db.execute("UPDATE deliveries SET state='pending',next_attempt=?,lease_until=0,attempts=attempts-1 WHERE id=? AND state='sending' AND attempts=?", (due,row['id'],row['attempts']+1))
                        return True
                    # Renewal may rotate the key after this delivery was
                    # claimed. Sign with the current subscription key, then
                    # include still-valid prior keys once each for overlap.
                    if current['secret'] != row['secret']:
                        signing_secret = self.cipher.decrypt(current['secret']).decode()
                    old_keys=list(dict.fromkeys(self.cipher.decrypt(r[0]).decode() for r in db.execute(
                        "SELECT secret FROM subscription_keys WHERE subscription=? AND expires>?",(row["subscription"],current_now))))
                    old_keys=[key for key in old_keys if key != signing_secret]
                    timing_row=db.execute('SELECT value FROM state WHERE key=?',
                        ('private:event_timing:'+row['event_id'],)).fetchone()
                    try:
                        timing=json.loads(timing_row[0]) if timing_row else {}
                    except (ValueError,TypeError):
                        timing={}
                    if not isinstance(timing,dict): timing={}
                    timing={key:value for key,value in timing.items()
                            if (key in ('provider_at','ingested_at','queued_at') and type(value) in (int,float) and value>=0)
                            or (key == 'ingestion_ref' and isinstance(value,str) and len(value)==24
                                and all(c in '0123456789abcdef' for c in value))}
                attempt_at=time.time()
                if getattr(self,'diagnostics',None):
                    from .diagnostics import reference
                    self.diagnostics.emit('callback.started',attempt=row['attempts']+1,
                        job_ref=reference(row['id']),event_ref=reference(row['event_id']),
                        source_event=event.get('data',{}).get('event_type',event.get('name','unknown')),
                        attempt_at=attempt_at,**timing,
                        event_age_ms=max(0,attempt_at-timing['provider_at'])*1000 if 'provider_at' in timing else None,
                        queue_delay_ms=max(0,attempt_at-timing['queued_at'])*1000 if 'queued_at' in timing else None)
                headers=signed_headers(signing_secret,row["event_id"],row["subscription"],body,previous_secrets=old_keys)
                transport_started = time.monotonic()
                try:
                    status,_ = self.transport.post(row["url"],body,headers)
                    if 200 <= status < 300: accepted_at=time.time()
                finally:
                    transport_duration_ms=(time.monotonic()-transport_started)*1000
        except CallbackError as exc:
            # Event delivery acknowledges by HTTP status. A failure consuming
            # its body does not undo a received status (including terminal 410).
            # subscribe() still requires its complete, valid challenge body.
            status = exc.status_code or 0
            if 200 <= status < 300: accepted_at=time.time()
        attempts = row["attempts"]+1
        if 200 <= status < 300:
            state = "accepted"
        elif status in (410,413) or (400<=status<500 and status not in (408,429)) or 300<=status<400 or attempts>=self.settings.max_callback_attempts or (recovery_limit is not None and attempts>=recovery_limit):
            state = "failed"
        else:
            state = "pending"
        delay = min(3600, 2**attempts * 5) + secrets.randbelow(5)
        with self.store.db() as db:
            # A timed-out lease can already belong to a newer HTTP attempt.
            # Its predecessor's late response is not evidence for that claim,
            # and must neither overwrite it nor revoke its subscription.
            updated=db.execute("UPDATE deliveries SET state=?,last_status=?,next_attempt=?,lease_until=0 WHERE id=? AND state='sending' AND attempts=?", (state,status,now+delay,row["id"],attempts)).rowcount
            if not updated:
                latest=db.execute('SELECT state,attempts FROM deliveries WHERE id=?',(row['id'],)).fetchone()
                state='superseded' if latest['attempts']!=attempts else latest['state']
            if status==410 and updated:
                # A response from an earlier authorization generation cannot
                # deactivate a subscription renewed while its HTTP was in flight.
                db.execute("UPDATE subscriptions SET active=0 WHERE id=? AND secret=? AND expires=?",
                    (row["subscription"],current['secret'],current['expires']))
        if getattr(self,'diagnostics',None):
            from .diagnostics import reference
            self.diagnostics.emit('callback.attempt','info' if state in ('accepted','superseded') else 'warning',
                state=state,status=status,attempt=attempts,job_ref=reference(row['id']),
                event_ref=reference(row['event_id']),
                source_event=event.get('data',{}).get('event_type',event.get('name','unknown')),
                duration_ms=transport_duration_ms,attempt_at=attempt_at,accepted_at=accepted_at)
        return True

