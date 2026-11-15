"""Single-owner durable state. No credentials in clear text, no command replay."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time

from cryptography.fernet import Fernet
from .config import secret
from .errors import TeslaError
from .schema_migrations import TEMPORARY_COLLECTION_TERMINAL
from .state_sequences import advance, counter, membership_key


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def utc(value=None):
    return datetime.fromtimestamp(time.time() if value is None else value, timezone.utc).isoformat().replace("+00:00", "Z")


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS connection (id INTEGER PRIMARY KEY CHECK(id=1), tokens BLOB NOT NULL,
 expires REAL NOT NULL, scopes TEXT NOT NULL, region TEXT NOT NULL, generation INTEGER NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_states (id TEXT PRIMARY KEY, session TEXT NOT NULL, expires REAL NOT NULL, verifier BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS login_attempts (at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS vehicles (ref TEXT PRIMARY KEY, vin TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
 data TEXT NOT NULL, checked REAL NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS snapshots (vehicle TEXT NOT NULL, section TEXT NOT NULL, data TEXT NOT NULL,
 source TEXT NOT NULL, source_at REAL, received REAL NOT NULL, PRIMARY KEY(vehicle,section));
CREATE TABLE IF NOT EXISTS intents (id TEXT PRIMARY KEY, client_key TEXT UNIQUE NOT NULL, fingerprint TEXT NOT NULL,
 vehicle TEXT, operation TEXT NOT NULL, arguments TEXT NOT NULL, scopes TEXT NOT NULL, generation INTEGER NOT NULL,
 created REAL NOT NULL, expires REAL NOT NULL, status TEXT NOT NULL, result TEXT);
CREATE TABLE IF NOT EXISTS requests (at REAL NOT NULL, category TEXT NOT NULL, cost_microusd INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS requests_at ON requests(at);
CREATE TABLE IF NOT EXISTS samples (id TEXT PRIMARY KEY, vehicle TEXT NOT NULL, field TEXT NOT NULL,
 value TEXT, source_at REAL NOT NULL, received REAL NOT NULL, quality TEXT NOT NULL, time_basis TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS sample_history ON samples(vehicle,field,source_at);
CREATE INDEX IF NOT EXISTS sample_retention ON samples(received);
CREATE TABLE IF NOT EXISTS latest (vehicle TEXT NOT NULL, field TEXT NOT NULL, value TEXT,
 source_at REAL NOT NULL, received REAL NOT NULL, quality TEXT NOT NULL, time_basis TEXT NOT NULL,
 PRIMARY KEY(vehicle,field));
CREATE TABLE IF NOT EXISTS sample_provenance (sample_id TEXT PRIMARY KEY REFERENCES samples(id) ON DELETE CASCADE,
 source_transport TEXT NOT NULL, quality_reason TEXT NOT NULL, decoder_version TEXT NOT NULL,
 contract_version TEXT NOT NULL, oneof_branch TEXT);
CREATE TABLE IF NOT EXISTS latest_provenance (vehicle TEXT NOT NULL, field TEXT NOT NULL, sample_id TEXT,
 source_at REAL NOT NULL, received REAL NOT NULL, quality TEXT NOT NULL, value_digest TEXT NOT NULL,
 source_transport TEXT NOT NULL, quality_reason TEXT NOT NULL, decoder_version TEXT NOT NULL,
 contract_version TEXT NOT NULL, oneof_branch TEXT, PRIMARY KEY(vehicle,field),
 FOREIGN KEY(vehicle,field) REFERENCES latest(vehicle,field) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS ingest (id TEXT PRIMARY KEY, received REAL NOT NULL);
CREATE INDEX IF NOT EXISTS ingest_retention ON ingest(received);
CREATE TABLE IF NOT EXISTS ingestion_errors (id TEXT PRIMARY KEY, reason TEXT NOT NULL, received REAL NOT NULL);
CREATE TABLE IF NOT EXISTS alert_states (vehicle TEXT NOT NULL, name TEXT NOT NULL, started REAL NOT NULL,
 ended REAL, PRIMARY KEY(vehicle,name,started));
CREATE TABLE IF NOT EXISTS connectivity (vehicle TEXT NOT NULL, connection_id TEXT NOT NULL,
 status TEXT NOT NULL, source_at REAL NOT NULL, PRIMARY KEY(vehicle,connection_id));
CREATE TABLE IF NOT EXISTS rules (id TEXT PRIMARY KEY, vehicle TEXT NOT NULL, kind TEXT NOT NULL,
 config TEXT NOT NULL, state TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS trigger_settings (vehicle TEXT PRIMARY KEY, revision INTEGER NOT NULL, batch_seconds INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS trigger_preferences (vehicle TEXT NOT NULL, id TEXT NOT NULL, enabled INTEGER NOT NULL,
 PRIMARY KEY(vehicle,id));
CREATE TABLE IF NOT EXISTS trigger_buffer (vehicle TEXT NOT NULL, field TEXT NOT NULL, started REAL NOT NULL, data TEXT NOT NULL,
 PRIMARY KEY(vehicle,field));
CREATE TABLE IF NOT EXISTS trigger_audit (vehicle TEXT NOT NULL, revision INTEGER NOT NULL, source TEXT NOT NULL,
 changed TEXT NOT NULL, at REAL NOT NULL, PRIMARY KEY(vehicle,revision));
CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, name TEXT NOT NULL, vehicle TEXT NOT NULL,
 occurred REAL NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS event_vehicle_time ON events(vehicle,occurred);
CREATE INDEX IF NOT EXISTS event_retention ON events(occurred);
CREATE TABLE IF NOT EXISTS subscriptions (id TEXT PRIMARY KEY, name TEXT NOT NULL, filters TEXT NOT NULL,
 url TEXT NOT NULL, secret BLOB NOT NULL, expires REAL NOT NULL, generation INTEGER NOT NULL, active INTEGER NOT NULL,
 old_secret BLOB, old_secret_until REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS deliveries (id TEXT PRIMARY KEY, subscription TEXT NOT NULL, generation INTEGER NOT NULL,
 event TEXT NOT NULL, body BLOB NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL,
 next_attempt REAL NOT NULL, lease REAL NOT NULL DEFAULT 0, last_code TEXT);
CREATE INDEX IF NOT EXISTS delivery_work ON deliveries(state,next_attempt);
CREATE INDEX IF NOT EXISTS delivery_event ON deliveries(event);
CREATE TABLE IF NOT EXISTS documents (ref TEXT PRIMARY KEY, vehicle TEXT NOT NULL, provider_id TEXT NOT NULL,
 expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS temporary_collections (intent_id TEXT PRIMARY KEY, vehicle TEXT NOT NULL,
 plan TEXT NOT NULL, generation INTEGER NOT NULL, status TEXT NOT NULL, started REAL, expires REAL,
 restore_intent TEXT, lease_owner TEXT, lease_until REAL NOT NULL DEFAULT 0,
 next_check REAL NOT NULL DEFAULT 0, updated REAL NOT NULL, error TEXT,
 check_count INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS temporary_collection_work ON temporary_collections(status,next_check,lease_until);
"""


class Store:
    def __init__(self, settings, *, clock=time.time):
        self.settings, self.path, self.clock = settings, Path(settings.database), clock
        self.cipher = Fernet(secret(settings.encryption_key_file).encode())
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise ValueError("Database symlinks are not allowed")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError:
            if self.path.stat().st_mode & 0o077:
                raise ValueError("Database permissions must be private")
        from .schema_migrations import initialize_database
        self.migration_backup = initialize_database(self.path, settings.owner_subject, SCHEMA)
        with self.db() as db:
            from .triggers import initialize
            for row in db.execute("SELECT ref FROM vehicles WHERE active=1").fetchall():
                initialize(db, row[0])

    @contextmanager
    def db(self):
        from .schema_migrations import validate_database
        validate_database(self.path, self.settings.owner_subject)
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        from .value_semantics import json_equal
        db.create_function('telemetry_value_equal', 3, json_equal, deterministic=True)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def seal(self, value):
        return self.cipher.encrypt(canonical(value).encode())

    def unseal(self, value):
        return json.loads(self.cipher.decrypt(value))

    def connection(self):
        with self.db() as db:
            r = db.execute("SELECT * FROM connection WHERE id=1").fetchone()
        if not r or r["status"] != "active":
            raise TeslaError("AUTH_REQUIRED", "Connect your Tesla account in the owner console")
        return dict(r)

    @staticmethod
    def assert_authorization(db, authorization):
        row = db.execute("SELECT * FROM connection WHERE id=1").fetchone()
        if not authorization.matches(row):
            raise TeslaError("AUTHORIZATION_CHANGED", "Authorization changed during the request; the obsolete result was not applied")

    def require_authorization(self, authorization):
        with self.db() as db:
            self.assert_authorization(db, authorization)

    def invalidate_authorization(self, authorization):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM connection WHERE id=1").fetchone()
            if not authorization.matches(row):
                return False
            db.execute("UPDATE connection SET status='reauth_required' WHERE id=1")
            db.execute("UPDATE intents SET status='cancelled' WHERE status='prepared'")
            db.execute("UPDATE subscriptions SET active=0")
            return True

    def set_tokens(self, tokens, scopes, region, *, db=None, generation=None):
        if not isinstance(tokens.get("access_token"), str) or not isinstance(tokens.get("refresh_token"), str):
            raise TeslaError("AUTH_RESPONSE_INVALID", "Tesla did not return renewable authorization")
        lifetime = tokens.get("expires_in")
        if type(lifetime) not in (int, float) or not 0 < lifetime <= 86400:
            raise TeslaError("AUTH_RESPONSE_INVALID", "Unexpected access token lifetime")
        def write(conn):
            nonlocal generation
            if generation is None:
                generation = int(conn.execute("SELECT value FROM meta WHERE key='connection_generation'").fetchone()[0]) + 1
                conn.execute("UPDATE meta SET value=? WHERE key='connection_generation'", (str(generation),))
                conn.execute("UPDATE intents SET status='cancelled' WHERE status='prepared'")
                conn.execute("UPDATE subscriptions SET active=0")
                conn.execute("UPDATE vehicles SET active=0")
                conn.execute("UPDATE rules SET enabled=0,state='{}'")
                conn.execute("DELETE FROM trigger_buffer")
                conn.execute("UPDATE trigger_preferences SET enabled=0")
                conn.execute("UPDATE trigger_settings SET revision=revision+1")
            conn.execute("INSERT OR REPLACE INTO connection VALUES(1,?,?,?,?,?,?)",
                         (self.seal({k: tokens[k] for k in ("access_token", "refresh_token")}),
                          self.clock()+lifetime, canonical(sorted(set(scopes))), region, generation, "active"))
        if db is not None:
            write(db)
        else:
            with self.db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                write(conn)

    def recover_inflight(self):
        with self.db() as db:
            db.execute("UPDATE intents SET status='unknown',result=? WHERE status='sending'",
                       (canonical({"code": "OUTCOME_UNKNOWN", "message": "Service restarted during dispatch; command was not replayed"}),))

    def vehicle(self, ref):
        with self.db() as db:
            r = db.execute("SELECT * FROM vehicles WHERE ref=? AND active=1", (ref,)).fetchone()
        if not r:
            raise TeslaError("VEHICLE_ACCESS_REQUIRED", "Choose a currently authorized vehicle")
        result = dict(r)
        result["data"] = json.loads(result["data"])
        return result

    def begin_discovery(self, authorization):
        """Order a complete inventory attempt before its first provider page."""
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            self.assert_authorization(db, authorization)
            return advance(db, "discovery_sequence")

    def save_vehicles(self, vehicles, *, expected_generation=None, authorization=None, discovery_sequence=None):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if authorization is not None:
                self.assert_authorization(db, authorization)
            if expected_generation is not None:
                active = db.execute("SELECT generation FROM connection WHERE id=1 AND status='active'").fetchone()
                if not active or active[0] != expected_generation:
                    raise TeslaError("AUTH_REQUIRED", "Account authorization changed during vehicle discovery")
            if discovery_sequence is None:
                # Local inventory writes also supersede already pending reads.
                discovery_sequence = advance(db, "discovery_sequence")
            if (type(discovery_sequence) is not int or discovery_sequence <= counter(db, "discovery_applied_sequence")
                    or discovery_sequence > counter(db, "discovery_sequence")):
                raise TeslaError("DISCOVERY_SUPERSEDED", "A newer vehicle inventory was already applied; the obsolete result was not saved")
            db.execute("UPDATE vehicles SET active=0")
            for vehicle in vehicles:
                vin = vehicle.get("vin")
                if not isinstance(vin, str) or len(vin) != 17 or not vin.isalnum():
                    raise TeslaError("PROVIDER_RESPONSE_INVALID", "Invalid vehicle identity")
                old = db.execute("SELECT ref FROM vehicles WHERE vin=?", (vin,)).fetchone()
                ref = old[0] if old else "veh_"+secrets.token_hex(12)
                db.execute("INSERT INTO vehicles VALUES(?,?,?,?,?,1) ON CONFLICT(ref) DO UPDATE SET name=excluded.name,data=excluded.data,checked=excluded.checked,active=1",
                           (ref, vin, str(vehicle.get("display_name", "Model Y"))[:128], canonical(vehicle), self.clock()))
                from .triggers import initialize
                initialize(db, ref)
            revoked = [r[0] for r in db.execute("SELECT ref FROM vehicles WHERE active=0")]
            for ref in revoked:
                self._remove_vehicle_data(db, ref)
            db.execute("INSERT INTO meta VALUES('discovery_applied_sequence',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (str(discovery_sequence),))

    @staticmethod
    def _remove_vehicle_data(db, ref):
        # A later regrant of the same reference must not revive a handshake that
        # crossed this revocation, even under an otherwise unchanged consent.
        advance(db, membership_key(ref))
        for table in ("snapshots", "samples", "latest", "rules", "events", "documents", "alert_states", "connectivity",
                      "trigger_settings", "trigger_preferences", "trigger_buffer", "trigger_audit"):
            db.execute(f"DELETE FROM {table} WHERE vehicle=?", (ref,))
        # Revocation does not prove a temporary provider configuration was
        # restored. Retain unresolved obligations without retaining authority
        # to contact that vehicle; the worker rechecks access and generation.
        db.execute('DELETE FROM temporary_collections WHERE vehicle=? AND status IN (?,?,?,?)',
                   (ref, *sorted(TEMPORARY_COLLECTION_TERMINAL)))
        db.execute("UPDATE temporary_collections SET status='blocked',error='VEHICLE_ACCESS_REVOKED', "
                   'next_check=1e30,lease_owner=NULL,lease_until=0 WHERE vehicle=?', (ref,))
        db.execute("UPDATE intents SET status='cancelled' WHERE vehicle=? AND status='prepared'", (ref,))
        db.execute("UPDATE subscriptions SET active=0 WHERE json_extract(filters,'$.vehicle_ref')=?", (ref,))
        db.execute("UPDATE deliveries SET state='cancelled' WHERE subscription IN (SELECT id FROM subscriptions WHERE active=0)")

    def disconnect(self):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM intents WHERE status='sending'").fetchone():
                raise TeslaError("ACTION_IN_PROGRESS", "Wait for the in-flight command outcome before removing local state")
            # Fence authorization-code exchanges already outside the database.
            # The epoch survives deletion of connection, including when empty.
            advance(db, "connection_generation")
            for table in ("connection", "oauth_states", "snapshots", "samples", "latest", "rules", "events", "documents", "subscriptions", "deliveries", "intents", "vehicles", "ingest", "ingestion_errors", "alert_states", "connectivity", "trigger_settings", "trigger_preferences", "trigger_buffer", "trigger_audit"):
                db.execute(f"DELETE FROM {table}")
            db.execute('DELETE FROM temporary_collections WHERE status IN (?,?,?,?)', tuple(sorted(TEMPORARY_COLLECTION_TERMINAL)))
            db.execute("UPDATE temporary_collections SET status='blocked',error='AUTHORIZATION_REMOVED', "
                       'next_check=1e30,lease_owner=NULL,lease_until=0')
            db.execute("DELETE FROM meta WHERE key GLOB 'request_diagnostic:*'")
            db.execute("DELETE FROM meta WHERE key GLOB 'vehicle_membership_epoch:*' OR key GLOB 'subscription_epoch:*'")

    def snapshot(self, ref, section, data, source, source_at=None, *, authorization=None):
        from .state_evidence import REST_STATE_SECTIONS, REST_TIME_CONFLICT, snapshot_transition
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if authorization is not None:
                self.assert_authorization(db, authorization)
            if section in REST_STATE_SECTIONS:
                previous = db.execute('SELECT * FROM snapshots WHERE vehicle=? AND section=?', (ref, section)).fetchone()
                action, source_at = snapshot_transition(previous, data, source_at, now=self.clock())
                if action == 'keep':
                    return False
                if action == 'conflict':
                    now = self.clock()
                    detail = {'sources': list(dict.fromkeys((previous['source'], source))),
                              'source_timestamp': source_at, 'detected_at': now,
                              'kind': 'same_source_time_conflict', 'proves_current_state': False}
                    db.execute('INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?)',
                               (ref, 'rest_conflict:'+section, canonical(detail), 'local_conflict_detection', source_at, now))
                    db.execute('UPDATE snapshots SET source=?,received=? WHERE vehicle=? AND section=?',
                               (REST_TIME_CONFLICT, now, ref, section))
                    from .diagnostics import invalidate_operation_observations
                    invalidate_operation_observations(db, ref, section, source_at, now)
                    return False
                db.execute('DELETE FROM snapshots WHERE vehicle=? AND section=?', (ref, 'rest_conflict:'+section))
            db.execute("INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?)",
                       (ref, section, canonical(data), source, source_at, self.clock()))
            return True

    def intent(self, identifier):
        with self.db() as db:
            r = db.execute("SELECT * FROM intents WHERE id=?", (identifier,)).fetchone()
        if not r:
            raise TeslaError("NOT_FOUND", "Intent not found")
        out = dict(r)
        for key in ("arguments", "result", "scopes"):
            if out[key] is not None:
                out[key] = json.loads(out[key])
        return out

    def reserve_request(self, category):
        costs = {"data": 2000, "commands": 1000, "wake": 20000, "free": 0}
        limits = {"data": 60, "commands": 30, "wake": 3, "free": 60}
        now = self.clock()
        start = datetime.fromtimestamp(now, timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            used = db.execute("SELECT coalesce(sum(cost_microusd),0) FROM requests WHERE at>=?", (start,)).fetchone()[0]
            if used + costs[category] > self.settings.monthly_limit_usd * 1_000_000:
                raise TeslaError("BUDGET_EXCEEDED", "Local request budget reached")
            count = db.execute("SELECT count(*) FROM requests WHERE category=? AND at>?", (category, now-60)).fetchone()[0]
            if count >= limits[category]:
                raise TeslaError("RATE_LIMITED", "Local request rate limit reached")
            db.execute("INSERT INTO requests VALUES(?,?,?)", (now, category, costs[category]))

    def prune(self):
        from .provider_diagnostics import prune as prune_diagnostics
        cutoff = self.clock() - self.settings.history_days * 86400
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            from .temporary_collection import expire_unstarted, preserve_restore_lineage
            expire_unstarted(db, self.clock())
            preserve_restore_lineage(db, self.clock())
            prune_diagnostics(db, self.clock())
            for table, column in (("samples", "received"), ("events", "occurred"), ("ingest", "received"), ("ingestion_errors", "received"), ("alert_states", "ended")):
                db.execute(f"DELETE FROM {table} WHERE {column}<?", (cutoff,))
            db.execute("DELETE FROM deliveries WHERE event NOT IN (SELECT id FROM events)")
            db.execute("DELETE FROM intents WHERE created<? AND status NOT IN ('prepared','sending') "
                       "AND NOT EXISTS (SELECT 1 FROM temporary_collections t WHERE t.status NOT IN (?,?,?,?) "
                       "AND (t.intent_id=intents.id OR t.restore_intent=intents.id))",
                       (cutoff, *sorted(TEMPORARY_COLLECTION_TERMINAL)))
            db.execute("DELETE FROM requests WHERE at<?", (self.clock()-90*86400,))
            db.execute("DELETE FROM sessions WHERE expires<=?", (self.clock(),))
            db.execute("DELETE FROM oauth_states WHERE expires<=?", (self.clock(),))
            db.execute("DELETE FROM documents WHERE expires<=?", (self.clock(),))
            db.execute("DELETE FROM login_attempts WHERE at<?", (self.clock()-3600,))
            db.execute("DELETE FROM trigger_audit WHERE at<?", (cutoff,))
            db.execute('DELETE FROM temporary_collections WHERE updated<? AND status IN (?,?,?,?)',
                       (cutoff, *sorted(TEMPORARY_COLLECTION_TERMINAL)))
            db.execute("UPDATE intents SET status='expired' WHERE status='prepared' AND expires<=?", (self.clock(),))
