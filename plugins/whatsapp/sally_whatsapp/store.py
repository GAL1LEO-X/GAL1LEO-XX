"""One SQLite transaction commits each message, deduplication key and event outbox."""
from contextlib import contextmanager,nullcontext
from datetime import datetime, timezone, timedelta
import hashlib
import json
import math
import re
import sqlite3
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from .account_events import APPLICATION_EVENT_TYPES as EVENT_TYPES,STATE_EVENT_TYPES,NORMALIZED_EVENT_TYPES,GENERATED_EVENT_TYPES,safe_data,event_chat,message_chat,message_content,source_message,event_references,MULTI_SOURCE_EVENTS,STATE_NOTIFICATIONS
from .delivery import delivery_status, MESSAGE_OPERATIONS
from .event_policies import message_matches, message_mentions, quiet_until
from . import visibility
from . import media_diagnostics
from .callback_audit import cancel as cancel_delivery
from . import ingestion_metrics
from .chat_identity import normalize_chat_id, legacy_chat_id, chat_type as classify_chat, validate_chat_type


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


INVITE_CODE_OPERATIONS = frozenset({'groups_get_invite_code', 'groups_revoke_invite_code'})
PARTICIPANT_RESULT_OPERATIONS = frozenset({
    'groups_add_participants', 'groups_remove_participants', 'groups_promote_to_admin',
    'groups_demote_to_admin', 'groups_approve_group_join_requests', 'groups_reject_group_join_requests',
})


def operation_result_metadata(value, state=None, operation=None):
    """Action acknowledgements retain identifiers, never echoed message content.

    Apply to both new writes and legacy read projections. Read-only gateway
    operations have a separate contract and do not use this projection.
    """
    if state == 'failed_before_send':
        return {'error': 'Action preparation failed; no provider request made'}
    if operation == 'presence_get_presence':
        from .presence import presence_result_metadata
        return presence_result_metadata(value)
    if type(value) is bool:
        return value  # A provider's false administrative outcome is significant.
    if operation in INVITE_CODE_OPERATIONS and isinstance(value, str):
        return value  # These two account actions return an invite code, not a message.
    if operation in PARTICIPANT_RESULT_OPERATIONS and isinstance(value, list):
        return [operation_result_metadata(item, operation=operation) if isinstance(item, dict) else {}
                for item in value]
    metadata = {}
    if isinstance(value, dict):
        for field in ('id', 'requesterId'):
            if isinstance(value.get(field), str) and value[field]:
                metadata[field] = value[field]
        if 'requesterId' in value and value['requesterId'] is None:
            metadata['requesterId'] = None
        for field in ('success','result','accepted'):
            if type(value.get(field)) is bool:
                metadata[field] = value[field]
        from .operation_outcomes import OUTCOMES
        if isinstance(value.get('outcome'),str) and value['outcome'] in OUTCOMES:
            metadata['outcome'] = value['outcome']
        for field in ('error', 'status'):
            if type(value.get(field)) is int:
                metadata[field] = value[field]
    return metadata


def utc(ts=None):
    return datetime.fromtimestamp(ts if ts is not None else time.time(), timezone.utc).isoformat().replace("+00:00", "Z")


SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
 id TEXT PRIMARY KEY, chat_id TEXT NOT NULL, sender TEXT, timestamp INTEGER NOT NULL,
 from_me INTEGER NOT NULL, body TEXT NOT NULL, media TEXT, deleted INTEGER NOT NULL DEFAULT 0,
 source TEXT NOT NULL, observed_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_chat_time ON messages(chat_id,timestamp,id);
CREATE TABLE IF NOT EXISTS message_content (message_id TEXT PRIMARY KEY REFERENCES messages(id),data TEXT NOT NULL);
CREATE VIRTUAL TABLE IF NOT EXISTS message_search USING fts5(id UNINDEXED, body, tokenize='unicode61');
CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, received_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS message_live_receipts (message_id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS chats (id TEXT PRIMARY KEY, name TEXT);
CREATE TABLE IF NOT EXISTS chat_aliases (alias TEXT PRIMARY KEY,chat_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS subscriptions (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, filters TEXT NOT NULL,
 url TEXT NOT NULL, secret BLOB NOT NULL, expires REAL NOT NULL, active INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS subscription_keys (
 subscription TEXT NOT NULL REFERENCES subscriptions(id), secret BLOB NOT NULL, expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS callback_verifications (
 identity TEXT PRIMARY KEY, expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
 id INTEGER PRIMARY KEY, subscription TEXT NOT NULL REFERENCES subscriptions(id), event_id TEXT NOT NULL,
 body TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt REAL NOT NULL DEFAULT 0, lease_until REAL NOT NULL DEFAULT 0, last_status INTEGER,
 UNIQUE(subscription,event_id)
);
CREATE INDEX IF NOT EXISTS delivery_due ON deliveries(state,next_attempt);
CREATE TABLE IF NOT EXISTS sends (
 key TEXT PRIMARY KEY, owner TEXT NOT NULL, payload_hash TEXT NOT NULL, state TEXT NOT NULL,
 provider_id TEXT, created REAL NOT NULL, updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS operation_results (key TEXT PRIMARY KEY REFERENCES sends(key), result TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS action_jobs (
 key TEXT PRIMARY KEY REFERENCES sends(key), operation TEXT NOT NULL, arguments TEXT NOT NULL, transfer_id TEXT
);
CREATE TABLE IF NOT EXISTS media_jobs (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, identity TEXT NOT NULL, state TEXT NOT NULL, source BLOB NOT NULL,
 filename TEXT NOT NULL, mimetype TEXT NOT NULL, size INTEGER, sha256 TEXT, created REAL NOT NULL,
 expires REAL NOT NULL, error TEXT, source_message_id TEXT
);
CREATE INDEX IF NOT EXISTS media_jobs_due ON media_jobs(state,created);
CREATE INDEX IF NOT EXISTS media_jobs_source ON media_jobs(source_message_id);
CREATE TABLE IF NOT EXISTS history_jobs (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, request_key TEXT NOT NULL UNIQUE, request_hash TEXT NOT NULL,
 state TEXT NOT NULL, progress TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS account_events (
 id TEXT PRIMARY KEY, event_type TEXT NOT NULL, chat_id TEXT, timestamp REAL NOT NULL, data TEXT NOT NULL, source_message_id TEXT
);
CREATE INDEX IF NOT EXISTS account_events_time ON account_events(timestamp,id);
CREATE INDEX IF NOT EXISTS account_events_source ON account_events(source_message_id);
CREATE TABLE IF NOT EXISTS message_mutations (
 message_id TEXT PRIMARY KEY, kind TEXT NOT NULL, body TEXT, event_epoch REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS link_login_states (
 state_hash TEXT PRIMARY KEY, proof_hash TEXT NOT NULL, verifier BLOB NOT NULL,
 nonce TEXT NOT NULL, expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS link_sessions (
 id_hash TEXT PRIMARY KEY, owner TEXT NOT NULL, access_token BLOB NOT NULL,
 csrf TEXT NOT NULL, expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS link_rate_limit (singleton INTEGER PRIMARY KEY CHECK(singleton=1),last_request REAL NOT NULL);
-- Schema eight continuity references.
-- Keep byte-for-byte identical to deploy/7-8.sql. No network or source-content recovery.
CREATE TABLE IF NOT EXISTS event_source_refs (
 event_id TEXT NOT NULL REFERENCES account_events(id) ON DELETE CASCADE,
 role TEXT NOT NULL, message_id TEXT, canonical_id TEXT, chat_id TEXT,
 raw_id TEXT, from_me INTEGER, resolution TEXT NOT NULL, decoder_version INTEGER NOT NULL,
 PRIMARY KEY(event_id,role)
);
CREATE INDEX IF NOT EXISTS event_refs_canonical ON event_source_refs(canonical_id,event_id);
CREATE INDEX IF NOT EXISTS event_refs_context ON event_source_refs(chat_id,raw_id,event_id);
CREATE TABLE IF NOT EXISTS action_job_metadata (
 key TEXT PRIMARY KEY REFERENCES action_jobs(key), version INTEGER NOT NULL,
 metadata_state TEXT NOT NULL, caller_id_state TEXT NOT NULL, caller_message_id TEXT,
 destination_state TEXT NOT NULL, destination_chat_id TEXT, payload_state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS action_job_sources (
 key TEXT NOT NULL REFERENCES action_jobs(key), role TEXT NOT NULL,
 message_id TEXT NOT NULL, canonical_id TEXT NOT NULL, chat_id TEXT, PRIMARY KEY(key,role,message_id)
);
CREATE INDEX IF NOT EXISTS action_job_sources_message ON action_job_sources(message_id,key);
CREATE INDEX IF NOT EXISTS action_job_sources_canonical ON action_job_sources(canonical_id,key);
CREATE INDEX IF NOT EXISTS action_job_sources_chat ON action_job_sources(chat_id,key);
PRAGMA user_version=8;
"""

# Keep the historical schema for the existing 0..6 upgrade path. Schema eight
# adds reference/continuity metadata, not foreign keys to acquired messages:
# a source may be revoked before its content is acquired.
SCHEMA_7 = SCHEMA.split('-- Schema eight continuity references.',1)[0] + 'PRAGMA user_version=7;\n'

REVOCATION_REPAIR_KEY = 'private:revocation_derivatives_repair:v1'
OPERATION_RESULT_REPAIR_KEY = 'private:operation_result_metadata:v1'
REVOCATION_REPAIR_BATCH = 100
EVENT_REFS_REPAIR_KEY = 'private:event_source_refs:v2'
JOB_METADATA_REPAIR_KEY = 'private:action_job_metadata:v1'
CHAT_ARCHIVE_PREFIX = 'private:chat_archive:'
CHAT_ARCHIVE_GAP_KEY = 'private:chat_archive_gap'


class Store:
    def __init__(self, path: Path, *, recover_inflight=False, event_max_age_seconds=86400, migrate_schema=True, continuity=None):
        self.path = path
        self.continuity = continuity
        self.event_max_age_seconds=event_max_age_seconds
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2, 3, 4, 5, 6, 7, 8):
                raise RuntimeError("Database from a newer bridge; refuse downgrade")
            if version < 8 and not migrate_schema and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone():
                raise RuntimeError('Database schema upgrade required; run the declared migration before checking or serving in maintenance')
            if version < 7:
                # Preserve the historical Store upgrades (missing tables in v0..5),
                # then apply exactly the declared release migration, also in wheels.
                legacy = SCHEMA_7.replace(', source_message_id TEXT', '')
                legacy = legacy.replace('CREATE INDEX IF NOT EXISTS media_jobs_source ON media_jobs(source_message_id);', '')
                legacy = legacy.replace('CREATE INDEX IF NOT EXISTS account_events_source ON account_events(source_message_id);', '')
                legacy = legacy.replace('PRAGMA user_version=7;', 'PRAGMA user_version=6;')
                migration = (Path(__file__).with_name('migrations')/'6-7.sql').read_text()
                db.executescript('BEGIN IMMEDIATE;\n'+legacy+'\n'+migration+'\nCOMMIT;')
                version = 7
            if version == 7:
                migration = (Path(__file__).with_name('migrations')/'7-8.sql').read_text()
                db.executescript('BEGIN IMMEDIATE;\n'+migration+'\nCOMMIT;')
            db.executescript(SCHEMA)
            # A crash after an outbound request never grants permission to resend.
            if recover_inflight:
                db.execute("UPDATE sends SET state='uncertain',updated=? WHERE state='sending'", (time.time(),))
                db.execute("UPDATE media_jobs SET state='queued' WHERE state='downloading'")
                self._invalidate_chat_archive_states(db, 'event_stream_restart')
        # Existing schema-7 rows also need this semantic correction. Checks and
        # maintenance disable repairs during construction; activation prepares later.
        if migrate_schema:
            self._prepare_serving()

    def _prepare_serving(self):
        """Idempotent semantic preparation before workers and request admission.

        Release maintenance skips constructor repairs. Readiness must run the
        same preparation after activation on the actual database being served.
        """
        self._repair_revocation_derivatives()
        self._repair_clear_coverage()
        self._repair_message_lifetimes()
        self._repair_event_references()
        self._repair_job_metadata()
        self._repair_alias_callbacks()

    def _repair_clear_coverage(self):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            visibility.repair_clear_coverage(db,self._canonical_chat)

    @staticmethod
    def _alias_signature(db):
        return hashlib.sha256(canonical([tuple(row) for row in db.execute(
            'SELECT alias,chat_id FROM chat_aliases ORDER BY alias')]).encode()).hexdigest()

    def _repair_alias_callbacks(self):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            signature=self._callback_identity_checkpoint(db)
            marker='private:message_alias_callbacks:v1'
            previous=db.execute('SELECT value FROM state WHERE key=?',(marker,)).fetchone()
            if previous and json.loads(previous[0])==signature: return
            self._reconcile_alias_callbacks(db)
            self._state(db,marker,signature)

    def _callback_identity_checkpoint(self,db):
        return {'aliases':self._alias_signature(db),
                'through':db.execute('SELECT coalesce(max(id),0) FROM deliveries').fetchone()[0]}

    def _reconcile_alias_callbacks(self,db):
        """Suppress equivalent old wake-ups without replaying attempted bytes.

        Original messages and provider IDs stay intact. A callback that may
        already have left the bridge cannot be undone; overlapping retries are
        cancelled, never rewritten or replaced with a fresh event ID.
        """
        def batches(condition):
            after=0
            while True:
                rows=db.execute("""SELECT d.id,d.subscription,d.body,d.attempts,d.state
                    FROM deliveries d JOIN subscriptions s ON s.id=d.subscription
                    WHERE s.name IN ('message.received','message.digest','whatsapp.event') AND d.id>?
                    AND """+condition+" ORDER BY d.id LIMIT 16",(after,)).fetchall()
                if not rows: return
                yield from rows
                after=rows[-1]['id']

        def decoded(row):
            try:
                payload=json.loads(row['body'])
                data=payload['data']
                members=(data['message_ids'] if payload['name']=='message.digest'
                         else [data['message_id']] if payload['name']=='message.received'
                         or payload['name']=='whatsapp.event' and data.get('event_type')=='message.sent' else [])
                if not isinstance(members,list) or not all(isinstance(item,str) and item for item in members):
                    return None
            except (ValueError,TypeError,KeyError):
                return None
            identities=[visibility.canonical_identifier(db,item,self._canonical_chat) for item in members]
            return payload,members,identities

        # Bound payload memory even for an old outbox with many accepted rows.
        # This temporary index carries only identity/count metadata, never bodies.
        db.execute("""CREATE TEMP TABLE alias_callback_seen(
            subscription TEXT,identity TEXT,attempted INTEGER NOT NULL DEFAULT 0,
            retained INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(subscription,identity))""")
        overlap_found=False
        try:
            for row in batches('d.attempts>0'):
                value=decoded(row)
                if value is None: continue
                for identity in set(value[2]):
                    db.execute("""INSERT INTO alias_callback_seen(subscription,identity,attempted)
                        VALUES(?,?,1) ON CONFLICT(subscription,identity)
                        DO UPDATE SET attempted=attempted+1""",(row['subscription'],identity))
            for row in batches("d.state IN ('collecting','pending','sending')"):
                value=decoded(row)
                if value is None: continue
                payload,members,identities=value
                if row['attempts']:
                    overlap=(len(identities)!=len(set(identities)) or any(
                        db.execute("""SELECT attempted FROM alias_callback_seen
                            WHERE subscription=? AND identity=?""",
                            (row['subscription'],identity)).fetchone()[0]>1 for identity in identities))
                    if overlap:
                        cancel_delivery(db, "id=?", (row["id"],), "alias_duplicate", reset_lease=True)
                        overlap_found=True
                    continue
                remaining=[]
                for member,identity in zip(members,identities):
                    key=(row['subscription'],identity)
                    seen=db.execute("""SELECT attempted,retained FROM alias_callback_seen
                        WHERE subscription=? AND identity=?""",key).fetchone()
                    if seen and (seen['attempted'] or seen['retained']): continue
                    db.execute("""INSERT INTO alias_callback_seen(subscription,identity,retained)
                        VALUES(?,?,1) ON CONFLICT(subscription,identity) DO UPDATE SET retained=1""",key)
                    remaining.append(member)
                if remaining==members: continue
                if not remaining:
                    cancel_delivery(db, "id=?", (row["id"],), "alias_duplicate", reset_lease=True)
                elif payload['name']=='message.digest':
                    payload['data']['message_ids']=remaining
                    db.execute('UPDATE deliveries SET body=? WHERE id=?',(canonical(payload),row['id']))
            if overlap_found:
                self.require_recovery('message_alias_callback_overlap',db=db)
        finally:
            db.execute('DROP TABLE alias_callback_seen')

    def _repair_message_lifetimes(self):
        """Recover retained typed metadata only, in restartable bounded batches.

        Old messages whose engine metadata was discarded cannot be classified
        retrospectively. Never infer their lifetime from age or body text.
        """
        from . import lifetime
        marker='private:message_lifetime_repair:v1'
        while True:
            with self.db() as db:
                db.execute('BEGIN IMMEDIATE')
                saved=db.execute('SELECT value FROM state WHERE key=?',(marker,)).fetchone()
                progress=json.loads(saved[0]) if saved else {'phase':'events','after':0}
                if progress.get('complete'): return
                if progress['phase']=='events':
                    rows=db.execute('SELECT rowid AS sequence,* FROM account_events WHERE rowid>? ORDER BY rowid LIMIT ?',
                                    (progress['after'],REVOCATION_REPAIR_BATCH)).fetchall()
                    for row in rows:
                        data=self._event_data(row)
                        if not isinstance(data,dict): continue
                        source=row['source_message_id'] or source_message(row['event_type'],data)
                        self._observe_payload_lifetimes(db,data,source,row['chat_id'],edited=row['event_type']=='message.edited')
                        projected=lifetime.project_tree(data)
                        if source and self._message_state(db,source,chat_id=row['chat_id'])['state'] in lifetime.BLOCKED:
                            projected={'message_id':source,'unavailable':True}
                        if projected!=data:
                            db.execute('UPDATE account_events SET data=? WHERE id=?',(canonical(projected),row['id']))
                else:
                    rows=db.execute('''SELECT m.rowid AS sequence,m.id,m.chat_id,m.timestamp,m.media,c.data AS content
                        FROM messages m LEFT JOIN message_content c ON c.message_id=m.id
                        WHERE m.rowid>? ORDER BY m.rowid LIMIT ?''',(progress['after'],REVOCATION_REPAIR_BATCH)).fetchall()
                    for row in rows:
                        for field in ('content','media'):
                            try: payload=json.loads(row[field]) if row[field] else None
                            except (ValueError,TypeError): payload=None
                            if not isinstance(payload,dict): continue
                            self._observe_payload_lifetimes(db,{'id':row['id'],'timestamp':row['timestamp'],**payload},row['id'],row['chat_id'])
                            cleaned=lifetime.project_tree(payload)
                            if cleaned!=payload and self._message_state(db,row['id'],chat_id=row['chat_id'])['state'] not in lifetime.BLOCKED:
                                if field=='content':
                                    db.execute('UPDATE message_content SET data=? WHERE message_id=?',(canonical(cleaned),row['id']))
                                else:
                                    db.execute('UPDATE messages SET media=? WHERE id=?',(canonical(cleaned),row['id']))
                if rows: progress['after']=rows[-1]['sequence']
                if len(rows)<REVOCATION_REPAIR_BATCH:
                    if progress['phase']=='events': progress={'phase':'messages','after':0}
                    else: progress['complete']=True
                self._state(db,marker,progress)
            if progress.get('complete'): return

    @contextmanager
    def db(self):
        db = self.continuity.connect(timeout=10) if self.continuity is not None else sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        if self.continuity is not None:
            try: self.continuity.validate(db)
            except BaseException:
                db.close()
                raise
        db.create_function('linked_tuple_match', 3, visibility.tuple_match, deterministic=True)
        db.create_function('linked_chat_id', 1, normalize_chat_id, deterministic=True)
        db.create_function('linked_legacy_chat_id', 1, legacy_chat_id, deterministic=True)
        db.create_function('linked_chat_type', 1, classify_chat, deterministic=True)
        from . import lifetime
        db.create_function('linked_lifetime_match', 2, lambda identifier,value:
            bool(visibility.lifetime_reference_match(db,identifier,json.loads(value),self._canonical_chat)))
        db.create_function('linked_lifetime_state', 1, lambda value:lifetime.state(json.loads(value)))
        db.create_function('linked_identifier_variants', 1, lambda identifier:
            canonical(visibility.identifier_variants(db,identifier,self._canonical_chat)))
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def set_state(self, key, value):
        with self.db() as db:
            self._state(db, key, value)

    def connection_generation(self):
        from .connection_observations import generation
        with self.db() as db:
            return generation(db)

    def message_delivery_evidence(self, identifier, chat_id):
        """Exact existing action/receipt evidence only; never create a send row."""
        with self.db() as db, visibility.read_snapshot(db):
            if (visibility.message_identity(identifier) is None or
                    not self._identity_context_matches(db, identifier, chat_id, True)):
                return {'status':'not_correlated', 'reason':'unverified_message_identity', 'evidence':{}}
            if self.is_unavailable(db, identifier, chat_id=chat_id):
                return {'status': 'unavailable', 'reason': 'source_unavailable', 'evidence': {}}
            variants = visibility.identifier_variants(db, identifier, self._canonical_chat)
            # Reaction/edit results can repeat the original message ID. Only
            # message-producing actions compete, as in delivery_status itself.
            rows = db.execute('''SELECT s.* FROM sends s LEFT JOIN action_jobs j USING(key)
                WHERE s.provider_id IN (SELECT value FROM json_each(?))
                AND (j.operation IS NULL OR j.operation IN (SELECT value FROM json_each(?))) LIMIT 2''',
                (canonical(variants), canonical(sorted(MESSAGE_OPERATIONS)))).fetchall()
            if len(rows) != 1:
                return {'status': 'not_correlated' if not rows else 'ambiguous', 'evidence': {}}
            row = rows[0]
            job = db.execute('SELECT * FROM action_jobs WHERE key=?', (row['key'],)).fetchone()
            return delivery_status(db, row, job, canonical_chat=lambda chat:self._canonical_chat(db, chat),
                revoked=False, identifier_variants=lambda key:visibility.identifier_variants(db, key, self._canonical_chat))

    def record_connection_poll(self, status, *, checked_epoch, checked_at, expected_generation=None):
        """Commit one poll and its recovery incident together, without backfill."""
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute("SELECT value FROM state WHERE key='connection'").fetchone()
            previous=json.loads(row[0]) if row else 'UNKNOWN'
            from .connection_observations import record, SUPERSEDED
            if not record(db, source='poll', observed_at=checked_epoch, expected_generation=expected_generation, write=self._state):
                return SUPERSEDED
            self._state(db,'connection',status)
            self._state(db,'connection_checked_epoch',checked_epoch)
            self._state(db,'last_connection_check_at',checked_at)
            # Returning to WORKING retains, but does not refresh, an interruption.
            if status not in ('WORKING','NOT_LINKED') or (status == 'NOT_LINKED' and previous not in (None,'UNKNOWN','NOT_LINKED')):
                self.require_recovery('connection_interrupted',db=db)
        return previous

    def require_recovery(self, reason, *, db=None):
        with self.db() if db is None else nullcontext(db) as db:
            if not db.in_transaction: db.execute('BEGIN IMMEDIATE')
            reasons=self._recovery_reasons(db)
            now=utc()
            previous=reasons.get(reason,{})
            if previous.get('last_seen'):
                last=datetime.fromisoformat(previous['last_seen'].replace('Z','+00:00'))
                if datetime.fromisoformat(now.replace('Z','+00:00'))<=last:
                    # Preserve the compare-and-set token even if the system clock repeats or moves back.
                    now=(last+timedelta(microseconds=1)).isoformat().replace('+00:00','Z')
            reasons[reason]={'first_seen':previous.get('first_seen',now),'last_seen':now,'status':'open'}
            self._state(db,'recovery_reasons',reasons)
            self._state(db,'recovery_required',True)
            if reason == 'connection_interrupted':
                self._invalidate_chat_archive_states(db, 'event_stream_gap')

    @staticmethod
    def _recovery_reasons(db):
        row=db.execute("SELECT value FROM state WHERE key='recovery_reasons'").fetchone()
        reasons=json.loads(row[0]) if row else {}
        legacy=db.execute("SELECT value FROM state WHERE key='recovery_required'").fetchone()
        if not row and legacy and json.loads(legacy[0]):
            reasons['legacy_unknown']={'first_seen':None,'last_seen':None,'status':'open'}
        return reasons

    def reconcile_recovery(self, reason, last_seen):
        """Explicit administrative acknowledgement, never a claim of message/event recovery."""
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            reasons=self._recovery_reasons(db)
            issue=reasons.get(reason)
            if not issue: raise ValueError('Unknown recovery reason')
            if issue['last_seen']!=last_seen:
                raise ValueError('Recovery reason changed; inspect current status before reconciliation')
            if issue['status']=='open':
                issue.update(status='reconciled',reconciled_at=utc())
                self._state(db,'recovery_reasons',reasons)
                self._state(db,'recovery_required',any(item['status']=='open' for item in reasons.values()))
        return reasons

    def cache_chat_names(self, entries, source, *, observed_at=None, db=None):
        """Only callers with gateway directory/event data may supply display names."""
        if source not in ('live_directory','history_directory','group_event'):
            raise ValueError('Unknown chat name source')
        now=time.time() if observed_at is None else observed_at
        with self.db() if db is None else nullcontext(db) as db:
            if not db.in_transaction: db.execute('BEGIN IMMEDIATE')
            for entry in entries:
                identifier=entry.get('id')
                if isinstance(identifier,dict): identifier=identifier.get('_serialized')
                name=entry.get('name') or entry.get('subject')
                if not isinstance(identifier,str) or not identifier or len(identifier)>200:
                    continue
                if not isinstance(name,str) or not name.strip() or len(name)>512 or any(ord(c)<32 for c in name):
                    continue
                identifier=self._canonical_chat(db,identifier)
                key='chat_name:'+identifier
                old=db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone()
                if old and json.loads(old[0])['updated_epoch']>now: continue
                db.execute('INSERT INTO chats VALUES(?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name',(identifier,name))
                self._state(db,key,{'source':source,'updated_at':utc(now),'updated_epoch':now})

    @staticmethod
    def _canonical_chat(db,chat_id):
        chat_id=normalize_chat_id(chat_id)
        if not isinstance(chat_id,str) or not chat_id.endswith('@lid'): return chat_id
        row=db.execute('SELECT chat_id FROM chat_aliases WHERE alias=?',(chat_id,)).fetchone()
        return row[0] if row else chat_id

    def canonical_chat(self,chat_id):
        chat_id=normalize_chat_id(chat_id)
        if not isinstance(chat_id,str) or not chat_id.endswith('@lid'): return chat_id
        with self.db() as db: return self._canonical_chat(db,chat_id)

    @classmethod
    def _identity_context_matches(cls,db,identifier,chat_id,from_me=None,participant=None):
        identity=visibility.message_identity(identifier)
        if identity is None: return True
        def address(value):
            return cls._canonical_chat(db,value)
        if (chat_id and address(identity[0])!=address(chat_id)
                or type(from_me) is bool and from_me!=identity[1]):
            return False
        if identity[0].endswith('@g.us') and participant and '_' in identity[2]:
            author=identity[2].rsplit('_',1)[1]
            if re.fullmatch(r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)',author):
                return address(author)==address(participant)
        return True

    @classmethod
    def _acquired_context_matches(cls,db,identifier,chat_id,from_me,participant):
        """An acquired key cannot attribute a second conversation or author.

        Complete keys are validated independently against their serialized
        context. Opaque IDs and group keys lacking a participant need the
        acquired identity too: a conflicting webhook must not consume its
        first live receipt or wake a callback with the unrelated stored body.
        """
        variants=canonical(visibility.identifier_variants(db,identifier,cls._canonical_chat))
        row=db.execute('''SELECT chat_id,from_me,sender FROM messages
            WHERE id IN (SELECT value FROM json_each(?)) ORDER BY rowid LIMIT 1''',(variants,)).fetchone()
        if row is None:
            return True
        def address(value):
            return cls._canonical_chat(db,value)
        if address(row['chat_id'])!=address(chat_id) or type(from_me) is bool and bool(row['from_me'])!=from_me:
            return False
        return not (chat_id.endswith('@g.us') and participant and isinstance(row['sender'],str)
                    and re.fullmatch(r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)',row['sender'])
                    and address(row['sender'])!=address(participant))

    def observed_edit(self, identifier, body, *, chat_id=None, timestamp=None, from_me=None, participant=None):
        """Compare an observation with acquired edits; never certify phone state."""
        with self.db() as db, visibility.read_snapshot(db):
            identity=visibility.message_identity(identifier)
            if not self._identity_context_matches(db,identifier,chat_id,from_me,participant):
                return {'content_state':'unverified_reference'}
            state=self._message_state(db,identifier,chat_id=chat_id,timestamp=timestamp)['state']
            if state != 'unknown':
                return {'content_state':state}
            if identity is None:
                row=db.execute('SELECT chat_id FROM messages WHERE id=?',(identifier,)).fetchone()
                saved=db.execute('SELECT value FROM state WHERE key=?',(visibility.CONTEXT+identifier,)).fetchone() if identifier else None
                context=json.loads(saved[0]).get('chat_id') if saved else None
                # A raw edit before its original still has a scoped context.
                # Without that context (or an acquired row) it cannot supply
                # content to a live raw reference in an arbitrary conversation.
                known=row['chat_id'] if row else context
                if (not chat_id or not known or not context
                        or self._canonical_chat(db,known)!=self._canonical_chat(db,chat_id)
                        or context and self._canonical_chat(db,context)!=self._canonical_chat(db,chat_id)):
                    return None
            variants=visibility.identifier_variants(db,identifier,self._canonical_chat)
            row=db.execute("""SELECT body,event_epoch FROM message_mutations
                WHERE kind='edited' AND message_id IN (SELECT value FROM json_each(?))
                ORDER BY event_epoch DESC,message_id LIMIT 1""",(canonical(variants),)).fetchone()
            if not row: return None
            return {'body':row['body'],'observed_at':row['event_epoch'],
                    'matches_provider':row['body']==body,'source':'acquired_edit'}

    @classmethod
    def is_revoked(cls, db, message_id):
        if not message_id: return False
        variants=canonical(visibility.identifier_variants(db,message_id,cls._canonical_chat))
        exact=bool(db.execute("""SELECT 1 FROM message_mutations
            WHERE message_id IN (SELECT value FROM json_each(?)) AND kind='revoked'
            UNION ALL SELECT 1 FROM messages
            WHERE id IN (SELECT value FROM json_each(?)) AND deleted=1 LIMIT 1""",(variants,variants)).fetchone())
        return exact or visibility.state(db,message_id,None,None,cls._canonical_chat)['state']=='revoked'

    @classmethod
    def is_unavailable(cls, db, message_id, *, chat_id=None, timestamp=None):
        return cls._message_state(db,message_id,chat_id=chat_id,timestamp=timestamp)['state'] != 'unknown'

    def message_state(self, message_id, *, chat_id=None, timestamp=None):
        with self.db() as db, visibility.read_snapshot(db):
            return self._message_state(db,message_id,chat_id=chat_id,timestamp=timestamp)

    def observe_message_lifetime(self, message_id, chat_id, evidence, *, db=None, from_me=None, participant=None):
        """Retain attributable lifetime evidence; False rejects a contradictory key."""
        from . import lifetime
        if evidence is None or not isinstance(message_id,str) or not message_id:
            return
        identity=visibility.message_identity(message_id)
        chat_id=chat_id or (identity[0] if identity else None)
        if not isinstance(chat_id,str) or not chat_id:
            return
        with self.db() if db is None else nullcontext(db) as db:
            if not db.in_transaction: db.execute('BEGIN IMMEDIATE')
            if not self._identity_context_matches(db,message_id,chat_id,from_me,participant):
                return False
            chat_id=self._canonical_chat(db,chat_id)
            identifier=visibility.canonical_identifier(db,message_id,self._canonical_chat)
            participant=(self._canonical_chat(db,participant)
                         if isinstance(participant,str) and re.fullmatch(r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)',participant) else None)
            record={'kind':'lifetime','reason':'message_lifetime',
                'chat_id':chat_id,'identifier':identifier,'lifetime':evidence,
                'event_at':time.time(),'from_me':from_me if type(from_me) is bool else None,
                'participant':participant}
            visibility.apply(db,[record],self._canonical_chat)
            if (lifetime.state(evidence) not in lifetime.BLOCKED
                    and self._message_state(db,message_id,chat_id=chat_id)['state'] not in lifetime.BLOCKED):
                return
            # A newly observed restriction also removes earlier retained copies.
            targets=set()
            for candidate in (message_id,identifier):
                acquired=db.execute('SELECT chat_id FROM messages WHERE id=?',(candidate,)).fetchone()
                if (acquired and self._canonical_chat(db,acquired['chat_id'])==chat_id
                        and visibility.lifetime_reference_match(db,candidate,record,self._canonical_chat)=='exact'
                        or acquired is None and visibility.message_identity(candidate) is not None):
                    targets.add(candidate)
            targets.update(row['id'] for row in db.execute('SELECT id FROM messages WHERE chat_id IN (?,?)',(chat_id,legacy_chat_id(chat_id)))
                if visibility.lifetime_reference_match(db,row['id'],record,self._canonical_chat)=='exact')
            for target in targets:
                db.execute("UPDATE messages SET body='',media=NULL WHERE id=?",(target,))
                db.execute('DELETE FROM message_search WHERE id=?',(target,))
                db.execute('DELETE FROM message_content WHERE message_id=?',(target,))
                db.execute("UPDATE message_mutations SET body=NULL WHERE message_id=? AND kind='edited'",(target,))
                self._redact_referenced_events(db,target,chat_id)
                db.execute("UPDATE media_jobs SET state='cancelled',source=X'',filename='',mimetype='',size=NULL,sha256=NULL,error='Source message lifetime unavailable' WHERE source_message_id=?",(target,))
                media_diagnostics.forget_source_failures(db,target)
                event_id='evt_'+hashlib.sha256(target.encode()).hexdigest()
                for row in db.execute('SELECT id,body FROM deliveries WHERE event_id=?',(event_id,)).fetchall():
                    payload=json.loads(row['body'])
                    payload['data']['preview']=''
                    cancel_delivery(db, "id=? AND state IN ('pending','sending')", (row["id"],), "source_lifetime_unavailable")
                    db.execute("UPDATE deliveries SET body=? WHERE id=?",(canonical(payload),row["id"]))

    def _observe_payload_lifetimes(self, db, payload, identifier, chat_id, *, edited=False):
        from . import lifetime
        if not self._identity_context_matches(db,identifier,chat_id,payload.get('fromMe'),payload.get('participant')):
            return
        observed=payload
        if edited:
            original=db.execute('SELECT timestamp FROM messages WHERE id=?',(identifier,)).fetchone()
            observed={**payload,'timestamp':original[0] if original else None}
        self.observe_message_lifetime(identifier,chat_id,lifetime.metadata(observed),db=db,
                                      from_me=payload.get('fromMe'),participant=payload.get('participant'))
        quote=payload.get('replyTo')
        for _ in range(9):
            if not isinstance(quote,dict): break
            quote_chat=message_chat(quote) or chat_id
            if not self._identity_context_matches(db,quote.get('id'),quote_chat,quote.get('fromMe'),quote.get('participant')):
                break
            self.observe_message_lifetime(quote.get('id'),quote_chat,lifetime.metadata(quote),db=db,
                                          from_me=quote.get('fromMe'),participant=quote.get('participant'))
            quote=quote.get('replyTo')

    @classmethod
    def _message_state(cls, db, message_id, *, chat_id=None, timestamp=None):
        identity=visibility.message_identity(message_id)
        exact=db.execute('SELECT chat_id,timestamp FROM messages WHERE id=?',(message_id,)).fetchone()
        peers=[]
        if identity:
            variants=canonical(visibility.identifier_variants(db,message_id,cls._canonical_chat))
            peers=db.execute("""SELECT id,chat_id,timestamp FROM messages
                WHERE id IN (SELECT value FROM json_each(?)) ORDER BY rowid""",(variants,)).fetchall()
            if not exact and peers:
                exact=peers[0]
                chat_id=exact['chat_id']
                timestamp=exact['timestamp']
        # A legacy context-free raw tombstone is not evidence about an equal
        # raw reference in another conversation.
        attributable=(chat_id is None or identity is not None or exact and
                      cls._canonical_chat(db,exact['chat_id'])==cls._canonical_chat(db,chat_id))
        if attributable and cls.is_revoked(db,message_id):
            return {'state':'revoked','source':'provider_revocation'}
        references=visibility.reference_ids(db,message_id,chat_id,cls._canonical_chat)
        if references:
            states=[cls._message_state(db,identifier,chat_id=chat_id) for identifier in references]
            hidden=[state for state in states if state['state']!='unknown']
            if hidden:
                return hidden[0] if len(hidden)==len(states) else {'state':'unverified_reference','source':'ambiguous_provider_reference'}
        result=visibility.state(db,message_id,chat_id,timestamp,cls._canonical_chat)
        if result['state']=='unknown':
            # Historical duplicates can disagree on their timestamps. Verified
            # identity must not let the less restrictive copy revive content.
            for peer in peers:
                if peer['id']==message_id: continue
                peer_state=visibility.state(db,peer['id'],peer['chat_id'],peer['timestamp'],cls._canonical_chat)
                if peer_state['state']!='unknown':
                    result=peer_state
                    break
        context=exact['chat_id'] if exact else chat_id or (identity[0] if identity else None)
        if context is None and message_id:
            saved=db.execute('SELECT value FROM state WHERE key=?',(visibility.CONTEXT+message_id,)).fetchone()
            context=json.loads(saved[0]).get('chat_id') if saved else None
        coverage=visibility.clear_coverage(db,context,cls._canonical_chat) if context else None
        return {**result,**({'clear_chat_coverage':coverage} if coverage else {})}

    def clear_chat_coverage(self,chat_id=None):
        with self.db() as db, visibility.read_snapshot(db):
            return visibility.clear_coverage(db,chat_id,self._canonical_chat)

    def _visible_event_data(self,db,event,data,chat_id,*,retain_unavailable=False):
        if not retain_unavailable and event=='chat.cleared' and isinstance(data,dict) and 'clearCoverage' not in data:
            # Legacy storage discarded the range. Keep its private audit row,
            # but never expose the old assertion of certified member coverage.
            return {**data,'reason':visibility.CLEAR_UNCERTAIN,'coverage':'uncertain',
                    'excludedReferences':0,
                    'clearCoverage':{'version':1,'certainty':'uncertain','selection':'unavailable',
                                     'range':{},'anchors':[],'boundaryUnknown':True,
                                     'legacyRangeUnavailable':True}}
        if event != 'message.edited' or not isinstance(data,dict) or not isinstance(data.get('replyTo'),dict):
            return data
        from .linked_state_reads import _message
        def message_state(identifier,**context):
            state=self._message_state(db,identifier,**context)
            return {'state':'unknown'} if retain_unavailable and state['state'] not in ('revoked','view_once','expired','lifetime_unknown') else state
        view=SimpleNamespace(message_state=message_state)
        return {**data,'replyTo':_message(view,data['replyTo'],chat_id=chat_id)}

    @classmethod
    def remember_message_context(cls, db, message_id, chat_id, timestamp=None):
        visibility.remember_context(db, message_id, chat_id, timestamp, cls._canonical_chat)

    @staticmethod
    def redacted_event(message_id):
        return {'message_id':message_id,'revoked':True}

    @staticmethod
    def _event_data(row):
        try: return json.loads(row['data'])
        except (ValueError,TypeError): return None

    @staticmethod
    def _event_source(row,data):
        if row['event_type'] not in ('message.reaction',*MULTI_SOURCE_EVENTS): return row['source_message_id']
        # A previously redacted row has no original reaction payload to recover.
        if (isinstance(data,dict) and set(data) in ({'message_id','revoked'},{'message_id','unavailable'},{'message_id','unavailable','reason'})
                and (data.get('revoked') is True or data.get('unavailable') is True)
                and isinstance(data['message_id'],str) and data['message_id']):
            return data['message_id']
        return source_message(row['event_type'],data) if isinstance(data,dict) else None

    @staticmethod
    def _projected_event_data(data):
        return (isinstance(data,dict) and set(data) in ({'message_id','revoked'},{'message_id','unavailable'},{'message_id','unavailable','reason'})
                and (data.get('revoked') is True or data.get('unavailable') is True))

    def _event_references(self,db,row,data):
        if self._projected_event_data(data):
            saved=[dict(r) for r in db.execute('SELECT * FROM event_source_refs WHERE event_id=?',(row['id'],))]
            if saved: return saved
            source=data.get('message_id') or row['source_message_id']
            return event_references('message.revoked',{'revokedMessageId':source},row['chat_id'])
        if row['event_type'] not in ('message.reaction',*MULTI_SOURCE_EVENTS) and row['source_message_id']:
            # Existing raw edit/revocation tombstones remain authoritative;
            # replacing them with a newly reconstructed serialization loses
            # defensive redaction of retained schema-seven rows.
            references=event_references('message.revoked',{'revokedMessageId':row['source_message_id']},row['chat_id'])
            references.extend(ref for ref in event_references(row['event_type'],data,row['chat_id'])
                              if ref['role'].startswith('quote:'))
            return references
        references=event_references(row['event_type'],data,row['chat_id'])
        if not references and row['event_type'] not in MULTI_SOURCE_EVENTS and row['source_message_id']:
            references=event_references('message.revoked',{'revokedMessageId':row['source_message_id']},row['chat_id'])
        return references

    def _save_event_references(self,db,row,data):
        references=self._event_references(db,row,data)
        db.execute('DELETE FROM event_source_refs WHERE event_id=?',(row['id'],))
        for ref in references:
            identifier=ref['message_id']
            canonical_id=visibility.canonical_identifier(db,identifier,self._canonical_chat) if identifier else None
            db.execute('INSERT INTO event_source_refs VALUES(?,?,?,?,?,?,?,?,2)',
                       (row['id'],ref['role'],identifier,canonical_id,self._canonical_chat(db,ref['chat_id']),
                        ref['raw_id'],ref['from_me'],ref['resolution']))

    def _event_availability(self,db,row,data):
        """One policy for getters, both dispatcher barriers and recovery preview."""
        references=self._event_references(db,row,data)
        unavailable=[]
        for ref in references:
            # Quote visibility is projected separately, preserving independent
            # edit content. These refs locate retained JSON for targeted repair.
            if ref['role'].startswith('quote:'): continue
            if ref['resolution']!='resolved':
                if row['event_type'] in MULTI_SOURCE_EVENTS:
                    unavailable.append((ref['message_id'],'unverified_reference'))
                continue
            identifier=ref['message_id']
            # Preserve legacy exact source semantics for old message events;
            # typed raw poll/RSVP references always keep their chat scope.
            state='unknown'
            if row['event_type'] not in MULTI_SOURCE_EVENTS and self.is_revoked(db,identifier):
                state='revoked'
            elif self.is_unavailable(db,identifier,chat_id=ref['chat_id']):
                state=self._message_state(db,identifier,chat_id=ref['chat_id'])['state']
                if state=='unknown': state='unavailable'
            if state!='unknown': unavailable.append((identifier,state))
        return next((value for value in unavailable if value[1]=='revoked'),unavailable[0] if unavailable else (None,'unknown'))

    def event_source_reason(self,db,row,data=None):
        if row['event_type'] in STATE_NOTIFICATIONS: return None
        identifier,state=self._event_availability(db,row,self._event_data(row) if data is None else data)
        if state=='revoked': return 'source_revoked'
        if state!='unknown': return 'source_unavailable'
        return None

    def _event_projection(self,db,row,data):
        if row['event_type']=='message.revoked':
            # A state notification never carries `before` or other original
            # content, even when a malformed provider notice has lost its ID.
            source=self._event_source(row,data)
            return self.redacted_event(source) if source else {'unavailable':True,'reason':'revocation_target_unavailable'}
        source,state=self._event_availability(db,row,data)
        if state=='revoked': return self.redacted_event(source)
        # Decoder-generated state notifications contain only safe metadata.
        if state!='unknown' and row['event_type'] not in STATE_NOTIFICATIONS:
            return {'message_id':source,'unavailable':True,
                    **({'reason':'source_reference_unresolved'} if state=='unverified_reference' else {})}
        return self._visible_event_data(db,row['event_type'],data,row['chat_id'])

    def _repair_event_references(self):
        """Bounded, restartable preparation; each checkpoint commits with its batch.

        Called only at normal startup/activation, before admitting workers.
        Neither check nor maintenance construction runs this backfill.
        """
        while True:
            with self.db() as db:
                db.execute('BEGIN IMMEDIATE')
                saved=db.execute('SELECT value FROM state WHERE key=?',(EVENT_REFS_REPAIR_KEY,)).fetchone()
                progress=json.loads(saved[0]) if saved else {'after':0,'through':db.execute('SELECT coalesce(max(rowid),0) FROM account_events').fetchone()[0]}
                if progress.get('complete'): return
                rows=db.execute('SELECT rowid AS sequence,* FROM account_events WHERE rowid>? AND rowid<=? ORDER BY rowid LIMIT ?',
                                (progress['after'],progress['through'],REVOCATION_REPAIR_BATCH)).fetchall()
                for row in rows:
                    data=self._event_data(row)
                    self._save_event_references(db,row,data)
                    source=self._event_source(row,data)
                    target,state=self._event_availability(db,row,data)
                    # Repair only proven revocation content. A read projection
                    # of legacy ClearChat uncertainty must never overwrite the
                    # evidence consumed by its independent gated preparation.
                    projected=(canonical(self._event_projection(db,row,data)) if row['event_type']=='message.revoked'
                               else canonical(self.redacted_event(target)) if state=='revoked'
                               else canonical({'message_id':target,'unavailable':True}) if state in ('view_once','expired','lifetime_unknown')
                               else canonical(self._visible_event_data(db,row['event_type'],data,row['chat_id'],retain_unavailable=True)))
                    db.execute('UPDATE account_events SET source_message_id=?,data=? WHERE id=?',
                               (source,projected,row['id']))
                if rows: progress['after']=rows[-1]['sequence']
                progress['complete']=len(rows)<REVOCATION_REPAIR_BATCH
                self._state(db,EVENT_REFS_REPAIR_KEY,progress)
            if progress['complete']: return

    def _repair_job_metadata(self):
        from . import job_metadata
        while True:
            with self.db() as db:
                db.execute('BEGIN IMMEDIATE')
                saved=db.execute('SELECT value FROM state WHERE key=?',(JOB_METADATA_REPAIR_KEY,)).fetchone()
                progress=json.loads(saved[0]) if saved else {'after':0}
                if progress.get('complete'): return
                after,done=job_metadata.backfill_batch(db,progress['after'],REVOCATION_REPAIR_BATCH,
                    message_state=lambda identifier,**context:self._message_state(db,identifier,**context))
                progress.update(after=after,complete=done)
                self._state(db,JOB_METADATA_REPAIR_KEY,progress)
            if done: return

    def _redact_referenced_events(self,db,message_id,chat_id=None):
        canonical_id=visibility.canonical_identifier(db,message_id,self._canonical_chat)
        identity=visibility.message_identity(canonical_id)
        raw=message_id
        direction=None
        if identity:
            chat_id,direction,raw=identity
            if chat_id.endswith('@g.us') and '_' in raw:
                first,participant=raw.rsplit('_',1)
                if re.fullmatch(r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)',participant): raw=first
        chat_id=self._canonical_chat(db,chat_id)
        identifiers={r[0] for r in db.execute('SELECT event_id FROM event_source_refs WHERE canonical_id=?',(canonical_id,))}
        if chat_id:
            identifiers.update(r[0] for r in db.execute('SELECT event_id FROM event_source_refs WHERE chat_id=? AND raw_id=?',(chat_id,raw)))
        for event_id in identifiers:
            row=db.execute('SELECT * FROM account_events WHERE id=?',(event_id,)).fetchone()
            if not row: continue
            data=self._event_data(row)
            source,state=self._event_availability(db,row,data)
            if state=='revoked':
                db.execute('UPDATE account_events SET data=? WHERE id=?',(canonical(self.redacted_event(source)),event_id))
            elif state in ('view_once','expired','lifetime_unknown'):
                db.execute('UPDATE account_events SET data=? WHERE id=?',
                           (canonical({'message_id':source,'unavailable':True}),event_id))
            else:
                retained=self._visible_event_data(db,row['event_type'],data,row['chat_id'],retain_unavailable=True)
                db.execute('UPDATE account_events SET data=? WHERE id=?',(canonical(retained),event_id))

    @staticmethod
    def redact_media_job(db,identifier,error='Source message revoked'):
        """Caller has checked ownership/provenance; terminal rows also lose metadata."""
        db.execute("UPDATE media_jobs SET state='cancelled',source=X'',filename='',mimetype='',size=NULL,sha256=NULL,error=? WHERE id=?",
                   (error,identifier))
        media_diagnostics.forget_failure(db,identifier)

    def _repair_revocation_derivatives(self):
        """One atomic pass before workers: bounded reads, one durable completion marker.

        The first corrective startup holds the write lock during the scan. If
        interrupted, all corrections and the marker roll back and restart retries.
        """
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT 1 FROM state WHERE key=?',(OPERATION_RESULT_REPAIR_KEY,)).fetchone():
                cursor=db.execute('''SELECT r.key,r.result,s.state,j.operation FROM operation_results r
                    JOIN sends s ON s.key=r.key LEFT JOIN action_jobs j ON j.key=r.key ORDER BY r.rowid''')
                while rows:=cursor.fetchmany(REVOCATION_REPAIR_BATCH):
                    for row in rows:
                        try: value=json.loads(row['result'])
                        except (ValueError,TypeError): value=None
                        db.execute('UPDATE operation_results SET result=? WHERE key=?',
                                   (canonical(operation_result_metadata(value,row['state'],row['operation'])),row['key']))
                self._state(db,OPERATION_RESULT_REPAIR_KEY,True)
            if db.execute('SELECT 1 FROM state WHERE key=?',(REVOCATION_REPAIR_KEY,)).fetchone(): return
            cursor=db.execute("SELECT * FROM account_events WHERE event_type='message.reaction' ORDER BY rowid")
            while rows:=cursor.fetchmany(REVOCATION_REPAIR_BATCH):
                for row in rows:
                    data=self._event_data(row)
                    source=self._event_source(row,data)
                    redacted=canonical(self.redacted_event(source)) if self.is_revoked(db,source) else row['data']
                    if source!=row['source_message_id'] or redacted!=row['data']:
                        db.execute('UPDATE account_events SET source_message_id=?,data=? WHERE id=?',(source,redacted,row['id']))
            cursor=db.execute('SELECT * FROM media_jobs ORDER BY rowid')
            while rows:=cursor.fetchmany(REVOCATION_REPAIR_BATCH):
                for row in rows:
                    revoked=self.is_revoked(db,row['source_message_id'])
                    legacy=(row['state']=='cancelled' and (
                        row['error']=='Source message revoked'
                        or row['source_message_id'] is None and row['error']=='Transfer invalidated by schema upgrade; request the file again'
                        or row['source_message_id']=='' and row['error']=='Source unavailable after upgrade; request the file again'))
                    if revoked or legacy:
                        self.redact_media_job(db,row['id'],'Source message revoked' if revoked else row['error'])
            self._state(db,REVOCATION_REPAIR_KEY,True)

    def _revoke_derivatives(self, db, message_id):
        from . import job_metadata
        job_metadata.redact_revoked(db,message_id,
            message_state=lambda identifier,**context:self._message_state(db,identifier,**context))
        self._redact_referenced_events(db,message_id)
        # Old gateway responses may echo the entire original message, including
        # for non-message actions. Keep only acknowledgement metadata atomically
        # with the tombstone. New writers independently apply the same boundary.
        for row in db.execute('''SELECT r.key,r.result,s.state,j.operation FROM operation_results r
                JOIN sends s ON s.key=r.key LEFT JOIN action_jobs j ON j.key=r.key
                WHERE s.provider_id=?''',(message_id,)).fetchall():
            try: value=json.loads(row['result'])
            except (ValueError,TypeError): value=None
            db.execute('UPDATE operation_results SET result=? WHERE key=?',
                       (canonical(operation_result_metadata(value,row['state'],row['operation'])),row['key']))
        db.execute("UPDATE account_events SET data=? WHERE source_message_id=? AND event_type!='message.reaction'",
                   (canonical(self.redacted_event(message_id)),message_id))
        # Legacy schema-7 reaction rows can still point at the reaction's own ID.
        # Validate their actual target, including when a different ID is revoked.
        rows=db.execute("""SELECT * FROM account_events WHERE event_type='message.reaction' AND
            (source_message_id=? OR CASE WHEN json_valid(data) THEN
             json_type(data,'$.reaction.messageId')='text' AND json_extract(data,'$.reaction.messageId')=? ELSE 0 END)""",
                        (message_id,message_id)).fetchall()
        for row in rows:
            if self._event_source(row,self._event_data(row))==message_id:
                db.execute('UPDATE account_events SET source_message_id=?,data=? WHERE id=?',
                           (message_id,canonical(self.redacted_event(message_id)),row['id']))
        db.execute("UPDATE media_jobs SET state='cancelled',source=X'',filename='',mimetype='',size=NULL,sha256=NULL,error='Source message revoked' WHERE source_message_id=?",(message_id,))
        media_diagnostics.forget_source_failures(db,message_id)
        event_id='evt_'+hashlib.sha256(message_id.encode()).hexdigest()
        for row in db.execute('SELECT id,body FROM deliveries WHERE event_id=?',(event_id,)).fetchall():
            payload=json.loads(row['body'])
            payload['data']['preview']=''
            cancel_delivery(db, "id=? AND state IN ('pending','sending')", (row["id"],), "source_revoked")
            db.execute("UPDATE deliveries SET body=? WHERE id=?",(canonical(payload),row["id"]))

        # IDs are the only digest content. Remove membership even from terminal
        # records, but never requeue an already attempted/ambiguous batch.
        rows = db.execute("""SELECT d.* FROM deliveries d JOIN subscriptions s ON s.id=d.subscription
            WHERE s.name='message.digest' AND EXISTS
            (SELECT 1 FROM json_each(d.body,'$.data.message_ids') WHERE value=?)""", (message_id,)).fetchall()
        for row in rows:
            payload = json.loads(row['body'])
            members = [item for item in payload['data']['message_ids'] if item != message_id]
            payload['data']['message_ids'] = members
            state = row['state']
            if state in ('collecting', 'pending', 'sending'):
                if not members or row['attempts'] or state == 'sending':
                    state = 'cancelled'
                    if members:
                        self.require_recovery('digest_cancelled_after_attempt', db=db)
            if state == 'cancelled':
                cancel_delivery(db, 'id=?', (row['id'],), 'digest_source_revoked')
            db.execute('UPDATE deliveries SET body=?,state=? WHERE id=?', (canonical(payload), state, row['id']))

    def _record_revocation(self,db,identifier,event_epoch,now):
        db.execute("INSERT INTO message_mutations VALUES(?,'revoked',NULL,?) ON CONFLICT(message_id) DO UPDATE SET kind='revoked',body=NULL,event_epoch=max(message_mutations.event_epoch,excluded.event_epoch)",(identifier,event_epoch))
        db.execute("UPDATE messages SET deleted=1,body='',media=NULL,observed_at=? WHERE id=?",(now,identifier))
        db.execute('DELETE FROM message_search WHERE id=?',(identifier,))
        db.execute('DELETE FROM message_content WHERE message_id=?',(identifier,))
        self._revoke_derivatives(db,identifier)

    def _apply_edit(self,db,identifier,body,now):
        if db.execute('UPDATE messages SET body=?,observed_at=? WHERE id=? AND deleted=0',(body,now,identifier)).rowcount:
            db.execute('DELETE FROM message_search WHERE id=?',(identifier,))
            db.execute('INSERT INTO message_search(id,body) VALUES(?,?)',(identifier,body))
            # A stale preview must not be delivered or rewritten after an
            # attempted callback. Its original identity remains cancelled.
            cancel_delivery(db, """event_id=? AND state IN ('pending','sending')
                AND json_extract(body,'$.data.preview')<>?""",
                ('evt_'+hashlib.sha256(identifier.encode()).hexdigest(),body[:250]), 'source_edited', reset_lease=True)

    def bind_chat_alias(self,alias,chat_id):
        if not re.fullmatch(r'[0-9]{5,25}@lid',alias) or not re.fullmatch(r'[0-9]{5,20}@c\.us',chat_id):
            raise ValueError('Invalid chat alias')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT chat_id FROM chat_aliases WHERE alias=?',(alias,)).fetchone()
            if old and old[0]!=chat_id: raise ValueError('Chat alias already belongs to another conversation')
            db.execute('INSERT OR IGNORE INTO chat_aliases VALUES(?,?)',(alias,chat_id))
            visibility.bind_alias(db,alias,chat_id)
            self._bind_chat_archive_alias(db,alias,chat_id)
            for row in db.execute('SELECT * FROM message_mutations').fetchall():
                target=visibility.canonical_identifier(db,row['message_id'],self._canonical_chat)
                if target!=row['message_id']:
                    db.execute("""INSERT INTO message_mutations VALUES(?,?,?,?) ON CONFLICT(message_id) DO UPDATE SET
                        kind=CASE WHEN message_mutations.kind='revoked' OR excluded.kind='revoked' THEN 'revoked' ELSE 'edited' END,
                        body=CASE WHEN message_mutations.kind='revoked' OR excluded.kind='revoked' THEN NULL
                             WHEN excluded.event_epoch>=message_mutations.event_epoch THEN excluded.body ELSE message_mutations.body END,
                        event_epoch=max(message_mutations.event_epoch,excluded.event_epoch)""",
                        (target,row['kind'],row['body'],row['event_epoch']))
            db.execute('INSERT OR IGNORE INTO chats VALUES(?,NULL)',(chat_id,))
            alias_name=db.execute('SELECT name FROM chats WHERE id=?',(alias,)).fetchone()
            known_name=db.execute('SELECT name FROM chats WHERE id=?',(chat_id,)).fetchone()
            if alias_name and alias_name[0] and not known_name[0]:
                db.execute('UPDATE chats SET name=? WHERE id=?',(alias_name[0],chat_id))
                metadata=db.execute('SELECT value FROM state WHERE key=?',('chat_name:'+alias,)).fetchone()
                if metadata: self._state(db,'chat_name:'+chat_id,json.loads(metadata[0]))
            db.execute('UPDATE messages SET chat_id=? WHERE chat_id=?',(chat_id,alias))
            canonical_suffix='_'+chat_id
            for row in db.execute("""SELECT id FROM messages WHERE deleted=0 AND
                (chat_id=? OR substr(id,-?)=? OR EXISTS
                 (SELECT 1 FROM chat_aliases a WHERE a.chat_id=?
                  AND substr(messages.id,-(length(a.alias)+1))='_'||a.alias))""",
                                  (chat_id,len(canonical_suffix),canonical_suffix,chat_id)).fetchall():
                if self.is_revoked(db,row['id']):
                    self._record_revocation(db,row['id'],time.time(),time.time())
                elif self._message_state(db,row['id'])['state'] in ('view_once','expired','lifetime_unknown'):
                    identifier=visibility.canonical_identifier(db,row['id'],self._canonical_chat)
                    for _,item in visibility.records(db):
                        if (item['kind']=='lifetime' and
                                visibility.lifetime_reference_match(db,row['id'],item,self._canonical_chat)=='exact'):
                            self.observe_message_lifetime(row['id'],item['chat_id'],item['lifetime'],db=db)
                else:
                    identifier=visibility.canonical_identifier(db,row['id'],self._canonical_chat)
                    mutation=db.execute("SELECT body FROM message_mutations WHERE message_id IN (?,?) AND kind='edited' ORDER BY event_epoch DESC LIMIT 1",(identifier,row['id'])).fetchone()
                    if mutation:
                        self._apply_edit(db,row['id'],mutation['body'],time.time())
            db.execute('UPDATE account_events SET chat_id=? WHERE chat_id=?',(chat_id,alias))
            # Alias binding is evidence, not a guessed rewrite of provider IDs.
            referenced={r[0] for r in db.execute('''SELECT event_id FROM event_source_refs
                WHERE chat_id=? OR substr(message_id,-?)=?''',(alias,len(alias)+1,'_'+alias))}
            for event_id in referenced:
                row=db.execute('SELECT * FROM account_events WHERE id=?',(event_id,)).fetchone()
                if row:
                    data=self._event_data(row)
                    self._save_event_references(db,row,data)
                    source,state=self._event_availability(db,row,data)
                    if state=='revoked': db.execute('UPDATE account_events SET data=? WHERE id=?',(canonical(self.redacted_event(source)),event_id))
                    elif state in ('view_once','expired','lifetime_unknown'):
                        db.execute('UPDATE account_events SET data=? WHERE id=?',
                                   (canonical({'message_id':source,'unavailable':True}),event_id))
                    else:
                        retained=self._visible_event_data(db,row['event_type'],data,row['chat_id'],retain_unavailable=True)
                        db.execute('UPDATE account_events SET data=? WHERE id=?',(canonical(retained),event_id))
            from . import job_metadata
            job_metadata.rebind_alias(db,alias,chat_id,
                message_state=lambda identifier,**context:self._message_state(db,identifier,**context))
            # Once claimed, the receiver may have accepted these exact bytes
            # even after a timeout/503. Keep the event ID bound to that body.
            for row in db.execute("SELECT id,body FROM deliveries WHERE state='pending' AND attempts=0").fetchall():
                body=json.loads(row['body'])
                if body.get('data',{}).get('chat_id')==alias:
                    body['data']['chat_id']=chat_id
                    db.execute('UPDATE deliveries SET body=? WHERE id=?',(canonical(body),row['id']))
            self._reconcile_alias_callbacks(db)
            self._state(db,'private:message_alias_callbacks:v1',self._callback_identity_checkpoint(db))

    @staticmethod
    def _state(db, key, value):
        db.execute("INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, canonical(value)))

    def state(self, *, owner=None):
        with self.db() as db, visibility.read_snapshot(db):
            result = {r["key"]: json.loads(r["value"]) for r in db.execute("SELECT * FROM state WHERE key NOT LIKE 'chat_name:%' AND key NOT LIKE 'private:%'")}
            result['recovery_reasons']=self._recovery_reasons(db)
            result["archive_messages"] = db.execute("SELECT count(*) FROM messages").fetchone()[0]
            result["deliveries"] = dict(db.execute("SELECT state,count(*) FROM deliveries GROUP BY state").fetchall())
            from .callback_audit import summary as callback_summary
            result['callback_diagnostics'] = callback_summary(db)
            from .connection_observations import summary as connection_summary
            result['connection_observation'] = connection_summary(db)
            result['ingestion_diagnostics'] = ingestion_metrics.summary(db)
            result["uncertain_sends"] = db.execute("SELECT count(*) FROM sends WHERE state='uncertain'").fetchone()[0]
            from .action_diagnostics import summary
            result['action_diagnostics'] = summary(db, owner=owner)
            result['uncertain_active'] = result['action_diagnostics']['uncertain_active']
            result['uncertain_known_history'] = result['action_diagnostics']['uncertain_known_history']
            result['uncertain_sends_is_historical_total'] = True
            result["active_subscriptions"] = db.execute("SELECT count(*) FROM subscriptions WHERE active=1 AND expires>?",(time.time(),)).fetchone()[0]
        result.setdefault("connection", "UNKNOWN")
        result.setdefault('recovery_required',False)
        result["history_complete"] = False
        result['history_complete_reason'] = 'linked_device_and_acquisition_coverage_unverified'
        return result

    @staticmethod
    def _profile_identity(row):
        if row is None:
            raise ValueError("Connection profile is not initialized")
        try:
            profile_id = json.loads(row[0])
        except (ValueError, TypeError):
            raise ValueError("Connection profile identity is invalid") from None
        if not isinstance(profile_id, str) or not profile_id.strip():
            raise ValueError("Connection profile identity is invalid")
        return profile_id

    def prepare_profile(self, owner):
        """Initialize the configured owner's identity before request admission."""
        key="profile_id:"+hashlib.sha256(owner.encode()).hexdigest()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT value FROM state WHERE key=?",(key,)).fetchone()
            if row is None:
                self._state(db,key,"prf_"+uuid.uuid4().hex)
            else:
                self._profile_identity(row)

    def profile(self, owner):
        key="profile_id:"+hashlib.sha256(owner.encode()).hexdigest()
        with self.db() as db:
            row=db.execute("SELECT value FROM state WHERE key=?",(key,)).fetchone()
        return {"id":self._profile_identity(row),"nickname":"WhatsApp"}

    def ingest(self, envelope, *, historical=False, db=None):
        with ingestion_metrics.observing(historical) as observation:
            with self.db() if db is None else nullcontext(db) as transaction:
                result = self._ingest(envelope, historical=historical, db=transaction)
                ingestion_metrics.record(transaction, observation, result)
        # A caller-supplied transaction may still roll back (history pages).
        # Only an owned, successfully committed transaction has this log event.
        diagnostics = getattr(self, 'diagnostics', None)
        if db is None and diagnostics is not None:
            diagnostics.emit('ingestion.committed', ingestion_ref=observation.ingestion_ref,
                             observation_source=observation.origin,
                             disposition=ingestion_metrics.disposition(result), **observation.counts)
        return result

    def _ingest(self, envelope, *, historical=False, db=None):
        if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), dict):
            raise ValueError("Invalid event envelope")
        exclusions = None
        if envelope.get('event') == 'engine.event':
            from .linked_state import decode_engine_event
            decoded = decode_engine_event(envelope)
            if decoded is None:
                return {'ignored': True, 'reason': 'unsupported_engine_event'}
            exclusions = decoded['exclusions']
            envelope = {**envelope, 'event': decoded['event'], 'payload': decoded['payload']}
        event = envelope.get("event")
        if event in GENERATED_EVENT_TYPES or event in (*STATE_EVENT_TYPES,*NORMALIZED_EVENT_TYPES) and exclusions is None:
            raise ValueError('Unsupported event')
        if event not in ("message", "message.any", *EVENT_TYPES):
            raise ValueError("Unsupported event")
        p = envelope["payload"]
        receipt = envelope.get("id") or hashlib.sha256(canonical(envelope).encode()).hexdigest()
        if not isinstance(receipt,str) or len(receipt)>512:
            raise ValueError("Invalid event identifier")
        # Bind sender-relative GOWS private reactions before lifetime checks,
        # event references or callbacks. Receipt identity remains the original
        # provider envelope, and the caller's input is never mutated.
        from .reaction_identity import normalize_envelope
        envelope = normalize_envelope(envelope)
        p = envelope['payload']
        now = time.time()
        event_epoch=self.event_epoch(envelope,now)
        if event in ("message", "message.any"):
            if not isinstance(p.get("id"), str) or not p["id"] or not isinstance(p.get("fromMe"), bool):
                raise ValueError("Message id/fromMe required")
            chat_id = self._canonical_chat(db,message_chat(p)) if db is not None else self.canonical_chat(message_chat(p))
            if not isinstance(chat_id, str) or not chat_id or len(chat_id)>200 or type(p.get("timestamp")) is not int or not 0 <= p["timestamp"] <= 253402300799:
                raise ValueError("Message chat/timestamp required")
            body = p.get("body") or ""
            if not isinstance(body, str) or len(body) > 100000:
                raise ValueError("Message body too large or invalid")
            media = p.get("media")
            if media is not None and not isinstance(media, dict):
                raise ValueError("Invalid media")
            # Never store engine internal blobs, credentials, or event envelope metadata.
            media = {k: media[k] for k in ("url", "mimetype", "filename") if isinstance(media.get(k), str)} if media else None
            if not media and p.get('hasMedia'):
                media={'has_media':True}
            from .live_attachments import archive_media_identity
            media_identity=archive_media_identity(p)
            if media_identity is not None:
                media={**(media or {'has_media':True}),'identity':media_identity}
            content=message_content(p)
        elif event=='session.status':
            if p.get("status") not in ("STOPPED", "STARTING", "SCAN_QR_CODE", "WORKING", "FAILED", "PASSKEY_REQUIRED", "PASSKEY_CONFIRMATION_REQUIRED"):
                raise ValueError("Unknown session status")
        # A history page supplies its transaction so messages and progress commit together.
        with self.db() if db is None else nullcontext(db) as db:
            if not db.in_transaction: db.execute("BEGIN IMMEDIATE")
            if event in ('message','message.any'): chat_id=self._canonical_chat(db,chat_id)
            from . import lifetime
            target=p.get('id') if event in ('message','message.any') else source_message(event,p)
            target_chat=chat_id if event in ('message','message.any') else event_chat(p)
            if (event in ('message','message.any') and not self._acquired_context_matches(
                    db,target,target_chat,p['fromMe'],p.get('participant'))):
                return {'event':event,'recorded':False,'reason':'ambiguous_message_identity'}
            if (event in ('message','message.any','message.edited') and not self._identity_context_matches(
                    db,target,target_chat,p.get('fromMe'),p.get('participant'))):
                reason='ambiguous_edit_identity' if event=='message.edited' else 'ambiguous_message_identity'
                if event=='message.edited':
                    self._account_event(db,{**envelope,'payload':{
                        'editedMessageId':target,'unavailable':True,'reason':reason}},receipt,now,historical=historical)
                return {'event':event,'recorded':False,'reason':reason}
            self._observe_payload_lifetimes(db,p,target,target_chat,edited=event=='message.edited')
            self._state(db, 'last_history_ingested_at' if historical else 'last_webhook_at', utc(now))
            fresh_receipt=db.execute("INSERT OR IGNORE INTO receipts VALUES(?,?)", (receipt, now)).rowcount
            ingestion_metrics.stage('receipts_inserted', fresh_receipt)
            live_first=False
            if event in ('message','message.any'):
                variants=canonical(visibility.identifier_variants(db,p['id'],self._canonical_chat))
                acquired=db.execute("""SELECT id FROM messages
                    WHERE id IN (SELECT value FROM json_each(?)) ORDER BY rowid LIMIT 1""",(variants,)).fetchone()
                # Preserve the first acquired provider key and resolve alternate
                # verified serializations on read. Never replace content on replay.
                archive_id=acquired['id'] if acquired else p['id']
            if event in ('message','message.any') and not historical:
                live_first=not db.execute("""SELECT 1 FROM message_live_receipts
                    WHERE message_id IN (SELECT value FROM json_each(?)) LIMIT 1""",(variants,)).fetchone()
                db.execute('INSERT OR IGNORE INTO message_live_receipts VALUES(?)',(p['id'],))
                ingestion_metrics.stage('first_live_messages', int(live_first))
            if not fresh_receipt and not live_first:
                return {"duplicate": True}
            if target and event in ('message','message.any','message.edited') and self._message_state(db,target,chat_id=target_chat)['state'] in lifetime.BLOCKED:
                if event=='message.edited': self._account_event(db,envelope,receipt,now,historical=historical)
                return {'ignored':True,'id':target,'reason':'message_lifetime_unavailable'}
            if event == 'chat.archived':
                self._observe_chat_archive_event(db, p, now)
                self._account_event(db,envelope,receipt,now,historical=historical)
                return {'event':event,'recorded':True}
            if exclusions is not None:
                visibility.apply(db,exclusions,self._canonical_chat)
                self._account_event(db,envelope,receipt,now,historical=historical)
                return {'event':event,'recorded':True,'excluded_references':0 if event=='chat.cleared' else len(exclusions)}
            if event == "session.status":
                from .connection_observations import record
                record(db, source='webhook', observed_at=now, write=self._state)
                self._state(db, "connection", p["status"])
                self._state(db, "last_status_event_at", utc(now))
                if p["status"] != "WORKING":
                    self.require_recovery('connection_interrupted',db=db)
                self._account_event(db,envelope,receipt,now,historical=historical)
                return {"status": p["status"]}
            if event not in ('message','message.any'):
                if event=='group.v2.update' and isinstance(p.get('group'),dict):
                    self.cache_chat_names([p['group']],'group_event',observed_at=event_epoch,db=db)
                if event=='message.edited':
                    identifier=source_message(event,p)
                    body=p.get('body')
                    if not isinstance(identifier,str) or not isinstance(body,str) or len(body)>100000:
                        raise ValueError('Invalid edited message')
                    chat=self._canonical_chat(db,event_chat(p))
                    identifier=visibility.canonical_identifier(db,identifier,self._canonical_chat)
                    identity=visibility.message_identity(identifier)
                    if identity is not None:
                        chat=chat or identity[0]
                    else:
                        acquired=db.execute('SELECT chat_id FROM messages WHERE id=?',(identifier,)).fetchone()
                        saved=db.execute('SELECT value FROM state WHERE key=?',(visibility.CONTEXT+identifier,)).fetchone()
                        context=json.loads(saved[0]).get('chat_id') if saved else None
                        known=acquired['chat_id'] if acquired else context
                        if (chat and known and self._canonical_chat(db,known)!=chat
                                or context and chat and self._canonical_chat(db,context)!=chat):
                            self._account_event(db,{**envelope,'payload':{
                                'editedMessageId':identifier,'unavailable':True,
                                'reason':'ambiguous_edit_identity'}},receipt,now,historical=historical)
                            return {'event':event,'recorded':False,'reason':'ambiguous_edit_identity'}
                        chat=chat or known
                        if not chat:
                            self._account_event(db,{**envelope,'payload':{
                                'editedMessageId':identifier,'unavailable':True,
                                'reason':'ambiguous_edit_identity'}},receipt,now,historical=historical)
                            return {'event':event,'recorded':False,'reason':'ambiguous_edit_identity'}
                    # GOWS's edited Message timestamp belongs to the notice,
                    # not the original. Retain only the verified chat context.
                    recorded=db.execute("INSERT INTO message_mutations VALUES(?,'edited',?,?) ON CONFLICT(message_id) DO UPDATE SET body=excluded.body,event_epoch=excluded.event_epoch WHERE message_mutations.kind='edited' AND excluded.event_epoch>=message_mutations.event_epoch",
                                        (identifier,body,event_epoch)).rowcount
                    if recorded:
                        self.remember_message_context(db,identifier,chat)
                        targets=[r['id'] for r in db.execute('SELECT id FROM messages WHERE chat_id IN (?,?) OR id=?',(chat,legacy_chat_id(chat),identifier))
                                 if visibility.canonical_identifier(db,r['id'],self._canonical_chat)==identifier]
                        for target in targets:
                            self._apply_edit(db,target,body,now)
                elif event=='message.revoked':
                    identifier=source_message(event,p)
                    if isinstance(identifier,str):
                        scoped=self._canonical_chat(db,event_chat(p))
                        raw=bool(re.fullmatch(r'[A-Za-z0-9.:-]{1,200}',identifier))
                        if raw and isinstance(scoped,str) and '@' in scoped:
                            # GOWS revocations target raw IDs. Their notice's
                            # direction/participant can be an admin, not the
                            # author of the revoked message: scope by chat.
                            visibility.apply(db,[{'kind':'message','chat_id':scoped,'raw_id':identifier,
                                'from_me':None,'reason':'revoked','event_at':event_epoch}],self._canonical_chat)
                            for row in db.execute('SELECT id FROM messages WHERE chat_id IN (?,?) AND linked_tuple_match(id,?,NULL)',(scoped,legacy_chat_id(scoped),identifier)).fetchall():
                                self._record_revocation(db,row['id'],event_epoch,now)
                            self._redact_referenced_events(db,identifier,scoped)
                            from . import job_metadata
                            job_metadata.redact_revoked(db,identifier,chat_id=scoped,
                                message_state=lambda target,**context:self._message_state(db,target,**context))
                        else:
                            identity=visibility.message_identity(identifier)
                            targets={identifier}
                            if identity:
                                chat,direction,suffix=identity
                                chat=self._canonical_chat(db,chat)
                                visibility.apply(db,[{'kind':'message','chat_id':chat,'raw_id':suffix,
                                    'from_me':direction,'reason':'revoked','event_at':event_epoch}],self._canonical_chat)
                                canonical_id=visibility.canonical_identifier(db,identifier,self._canonical_chat)
                                # Persist the verified identity even before a
                                # message exists under either serialization.
                                targets.add(canonical_id)
                                targets.update(row['id'] for row in db.execute('SELECT id FROM messages WHERE chat_id IN (?,?)',(chat,legacy_chat_id(chat)))
                                               if visibility.canonical_identifier(db,row['id'],self._canonical_chat)==canonical_id)
                            for target in targets:
                                self._record_revocation(db,target,event_epoch,now)
                self._account_event(db,envelope,receipt,now,historical=historical)
                return {'event':event,'recorded':True}
            p={**p,'id':archive_id}
            canonical_id=visibility.canonical_identifier(db,p['id'],self._canonical_chat)
            mutation=db.execute("SELECT * FROM message_mutations WHERE message_id IN (?,?) ORDER BY kind='revoked' DESC,event_epoch DESC LIMIT 1",(canonical_id,p['id'])).fetchone()
            if mutation and mutation['kind']=='edited' and visibility.message_identity(mutation['message_id']) is None:
                saved=db.execute('SELECT value FROM state WHERE key=?',(visibility.CONTEXT+mutation['message_id'],)).fetchone()
                context=json.loads(saved[0]).get('chat_id') if saved else None
                if not context or self._canonical_chat(db,context)!=chat_id:
                    mutation=None
            deleted=bool(mutation and mutation['kind']=='revoked') or self.is_revoked(db,p['id'])
            if deleted:
                body,media='',None
                content={}
            elif mutation:
                body=mutation['body']
                content={}
            new = db.execute("INSERT OR IGNORE INTO messages(id,chat_id,sender,timestamp,from_me,body,media,source,observed_at,deleted) VALUES(?,?,?,?,?,?,?,?,?,?)",
                             (p["id"], chat_id, p.get("participant") or (None if p['fromMe'] and p.get('from')==chat_id else p.get("from")), int(p["timestamp"]), int(p["fromMe"]),
                              body, canonical(media) if media else None, "history" if historical else "webhook", now,int(deleted))).rowcount
            ingestion_metrics.stage('messages_inserted', new)
            if content and not deleted and not mutation:
                existing=db.execute('SELECT chat_id,from_me,timestamp,body FROM messages WHERE id=?',(p['id'],)).fetchone()
                if (new or existing and self._canonical_chat(db,existing['chat_id'])==chat_id
                        and bool(existing['from_me'])==p['fromMe']
                        and existing['timestamp']==p['timestamp'] and existing['body']==body):
                    # History may supply structured content omitted by an old
                    # acquisition. Fill an absent row only; neither an edit nor
                    # a contradictory replay may replace retained content.
                    db.execute('INSERT OR IGNORE INTO message_content VALUES(?,?)',(p['id'],canonical(content)))
            if not new and not live_first:
                return {"duplicate": True}
            if not new:
                # Importing content and observing its first live webhook are separate.
                # Use the current archive (including edits/revokes), never a stale copy.
                existing=db.execute('SELECT * FROM messages WHERE id=?',(p['id'],)).fetchone()
                body,chat_id,deleted=existing['body'],existing['chat_id'],bool(existing['deleted'])
                media=json.loads(existing['media']) if existing['media'] else None
                saved_content=db.execute('SELECT data FROM message_content WHERE message_id=?',(p['id'],)).fetchone()
                content=json.loads(saved_content[0]) if saved_content else {}
                incoming=not existing['from_me']
                message_time=existing['timestamp']
            else:
                incoming=not p['fromMe']
                message_time=p['timestamp']
            if new and not deleted: db.execute("INSERT INTO message_search(id,body) VALUES(?,?)", (p["id"], body))
            db.execute("INSERT OR IGNORE INTO chats VALUES(?,NULL)", (chat_id,))
            self._state(db, "last_message_ingested_at", utc(now))
            # Historical imports never wake a consumer. Own messages use the
            # explicit message.sent account event, never message.received.
            age=now-int(message_time)
            if live_first and not 0 <= age < self.event_max_age_seconds:
                self.require_recovery('message_outside_event_age_window',db=db)
                self._state(db,"last_event_suppressed_at",utc(now))
                self._state(db,"last_event_suppressed_reason","message_outside_event_age_window")
            unavailable = self.is_unavailable(db,p['id'])
            if not deleted and not unavailable and live_first and not incoming:
                self._account_event(db,{'event':'message.sent','timestamp':message_time,
                    'payload':{'id':p['id'],'chatId':chat_id,'fromMe':True,
                               'timestamp':message_time}},'message.sent:'+p['id'],now)
            if not deleted and not unavailable and live_first and incoming and 0 <= age < self.event_max_age_seconds:
                event_body = {"eventId": "evt_" + hashlib.sha256(p["id"].encode()).hexdigest(),
                              "name": "message.received", "timestamp": utc(message_time), "cursor": None,
                              "data": {"message_id": p["id"], "chat_id": chat_id,
                                       "preview": body[:250] or ('[Location]' if 'location' in content else '[Contatto]' if 'vCards' in content else '[Allegato]' if media else ''),
                                       "has_media": bool(media)}}
                for sub in db.execute("SELECT * FROM subscriptions WHERE name IN ('message.received','message.digest') AND active=1 AND expires>?", (now,)):
                    f = json.loads(sub["filters"])
                    if message_matches(f, p, chat_id, body, bool(media), lambda c: self._canonical_chat(db,c), message_mentions(p)):
                        self._enqueue_message(db, sub, f, event_body, now)
            return {"duplicate": not bool(new), "id": p["id"]}

    def _enqueue_message(self, db, sub, filters, event, now):
        if sub['name'] == 'message.received':
            inserted=db.execute("INSERT OR IGNORE INTO deliveries(subscription,event_id,body,next_attempt) VALUES(?,?,?,?)",
                       (sub['id'], event['eventId'], canonical(event), quiet_until(now, filters.get('quiet_hours')))).rowcount
            if inserted: self._record_event_timing(db,event['eventId'],event['timestamp'],now)
            return
        window = filters['digest_window_seconds']
        bucket = int(now // window) * window
        prefix = 'digest_' + hashlib.sha256(canonical([sub['id'], bucket]).encode()).hexdigest() + '_'
        # Include terminal rows in the ordinal: a revoked chunk is never reused.
        last = db.execute("SELECT id,event_id,body,state FROM deliveries WHERE subscription=? AND event_id GLOB ? ORDER BY id DESC LIMIT 1",
                          (sub['id'], prefix + '*')).fetchone()
        row = last if last and last['state'] == 'collecting' else None
        if row:
            payload = json.loads(row['body'])
            if len(payload['data']['message_ids']) < 50:
                payload['data']['message_ids'].append(event['data']['message_id'])
                if len(canonical(payload).encode()) <= 262144:
                    db.execute('UPDATE deliveries SET body=? WHERE id=?', (canonical(payload), row['id']))
                    ingestion_metrics.stage('digest_members_added')
                    return
        identifier = prefix + str(int(last['event_id'].rsplit('_', 1)[1]) + 1 if last else 0)
        payload = {'eventId': identifier, 'name': 'message.digest', 'timestamp': utc(bucket), 'cursor': None,
                   'data': {'message_ids': [event['data']['message_id']]}}
        encoded = canonical(payload)
        if len(encoded.encode()) > 262144:
            # Preserve the archive even when a provider supplies a pathological ID.
            self.require_recovery('event_payload_too_large', db=db)
            return
        due = quiet_until(bucket + window, filters.get('quiet_hours'))
        db.execute("INSERT INTO deliveries(subscription,event_id,body,state,next_attempt) VALUES(?,?,?,'collecting',?)",
                   (sub['id'], identifier, encoded, due))
        self._record_event_timing(db,identifier,event['timestamp'],now)

    @staticmethod
    def _record_event_timing(db,identifier,provider_timestamp,now):
        # Private, content-free additive metadata; old rows remain unknown.
        # A digest dates its first member. Retry/renewal never rewrite the
        # acquisition/queue time or the signed callback bytes.
        from datetime import datetime
        provider_at=(datetime.fromisoformat(provider_timestamp.replace('Z','+00:00')).timestamp()
                     if provider_timestamp is not None else None)
        observation = ingestion_metrics.current.get()
        ingestion_metrics.stage('callbacks_queued')
        db.execute('INSERT OR IGNORE INTO state VALUES(?,?)',('private:event_timing:'+identifier,
            canonical({**({'provider_at':provider_at} if provider_at is not None else {}),
                       **({'ingestion_ref':observation.ingestion_ref} if observation is not None else {}),
                       'ingested_at':now,'queued_at':now})))


    @staticmethod
    def event_epoch(envelope,now):
        observed=envelope.get('timestamp')
        observed=observed/1000 if type(observed) in (int,float) and observed>100000000000 else observed
        return observed if type(observed) in (int,float) and 0<=observed<=253402300799 else now

    def _account_event(self,db,envelope,receipt,now,*,historical=False):
        event=envelope['event']
        payload=envelope['payload']
        from . import lifetime
        data={'status':payload['status']} if event=='session.status' else safe_data(lifetime.project_tree(payload))
        source=source_message(event,payload)
        chat=self._canonical_chat(db,event_chat(payload,event))
        # The envelope timestamp is milliseconds. GOWS's edit payload timestamp
        # belongs to the edit notice and cannot date the original target.
        observed=self.event_epoch(envelope,now)
        identifier='change_'+hashlib.sha256(receipt.encode()).hexdigest()
        if source and self._message_state(db,source,chat_id=chat)['state'] in lifetime.BLOCKED:
            data={'message_id':source,'unavailable':True}
        inserted=db.execute('INSERT OR IGNORE INTO account_events VALUES(?,?,?,?,?,?)',(identifier,event,chat,observed,canonical(data),source)).rowcount
        ingestion_metrics.stage('account_events_inserted', inserted)
        row=db.execute('SELECT * FROM account_events WHERE id=?',(identifier,)).fetchone()
        # Acquired content and reversible visibility are separate. Preserve
        # private evidence for unavailable/ambiguous sources, while permanent
        # revocations (including quoted content) remove the retained payload.
        self._save_event_references(db,row,data)
        projected=self._event_projection(db,row,data)
        _,source_state=self._event_availability(db,row,data)
        retained=(projected if event=='message.revoked' or source_state in ('revoked',*lifetime.BLOCKED)
                  else self._visible_event_data(db,event,data,chat,retain_unavailable=True))
        db.execute('UPDATE account_events SET data=? WHERE id=?',(canonical(retained),identifier))
        data=projected
        # A sync snapshot may update acquired state, but is not a new event.
        # Do not enqueue it now or create replay work for a later renewal.
        if historical or payload.get('fromFullSync') is True:
            return
        if not 0<=now-observed<self.event_max_age_seconds:
            self.require_recovery('account_event_outside_event_age_window',db=db)
            return
        event_body={'eventId':identifier,'name':'whatsapp.event','timestamp':utc(observed),'cursor':None,
                    'data':{'event_id':identifier,'event_type':event,'chat_id':chat}}
        message_id=self._account_event_message_id(db,row,data)
        if message_id: event_body['data']['message_id']=message_id
        searchable=canonical(data).casefold()
        for sub in db.execute("SELECT * FROM subscriptions WHERE name='whatsapp.event' AND active=1 AND expires>?",(now,)):
            filters=json.loads(sub['filters'])
            if event not in filters.get('event_types',[]): continue
            if not filters.get('all_chats') and chat not in [self._canonical_chat(db,c) for c in filters.get('chat_ids',[])]: continue
            if filters.get('contains') and filters['contains'].casefold() not in searchable: continue
            inserted=db.execute('INSERT OR IGNORE INTO deliveries(subscription,event_id,body,next_attempt) VALUES(?,?,?,?)',
                                (sub['id'],identifier,canonical(event_body),now)).rowcount
            if inserted:
                supplied=envelope.get('timestamp')
                if type(supplied) in (int,float) and supplied>100000000000: supplied/=1000
                provider_timestamp=event_body['timestamp'] if type(supplied) in (int,float) and 0<=supplied<=253402300799 else None
                self._record_event_timing(db,identifier,provider_timestamp,now)

    def _account_event_message_id(self,db,row,data):
        """Expose a usable source key only when its conversation is attributable.

        A raw provider target is resolved in its chat, never globally. Multiple
        authors/directions sharing a raw key remain unresolved. Verified PN/LID
        serializations collapse without changing the first acquired key.
        """
        source=self._event_source(row,data)
        if not source: return None
        chat=row['chat_id']
        if not self._identity_context_matches(db,source,chat): return None
        variants=visibility.identifier_variants(db,source,self._canonical_chat)
        candidates=db.execute('SELECT id,chat_id FROM messages WHERE id IN (SELECT value FROM json_each(?)) ORDER BY rowid',
                              (canonical(variants),)).fetchall()
        candidates=[candidate for candidate in candidates if not chat or self._canonical_chat(db,candidate['chat_id'])==self._canonical_chat(db,chat)]
        references=visibility.reference_ids(db,source,chat,self._canonical_chat)
        identities={visibility.canonical_identifier(db,key,self._canonical_chat)
                    for key in [*(candidate['id'] for candidate in candidates),*references]}
        if len(identities)>1: return None
        if candidates: return candidates[0]['id']
        if len(identities)==1: return references[0]
        return source if visibility.message_identity(source) is not None else None

    def account_event(self,identifier):
        with self.db() as db, visibility.read_snapshot(db):
            row=db.execute('SELECT * FROM account_events WHERE id=?',(identifier,)).fetchone()
            if not row: return None
            data=self._event_data(row)
            data=self._event_projection(db,row,data)
            message_id=self._account_event_message_id(db,row,data)
        value=dict(row)
        value.pop('source_message_id')
        value['data']=data if data is not None else {}
        if message_id: value['message_id']=message_id
        return value

    def list_account_events(self,*,event_types=None,chat_id=None,after=0,limit=50,offset=0):
        chat_id=self.canonical_chat(chat_id)
        clauses=['timestamp>=?']
        values=[after]
        if event_types:
            clauses.append('event_type IN ('+','.join('?' for _ in event_types)+')')
            values.extend(event_types)
        if chat_id:
            clauses.append('chat_id=?')
            values.append(chat_id)
        with self.db() as db:
            rows=db.execute('SELECT id,event_type,chat_id,timestamp FROM account_events WHERE '+' AND '.join(clauses)+' ORDER BY timestamp DESC,id LIMIT ? OFFSET ?',values+[limit+1,offset]).fetchall()
        return {'events':[dict(r) for r in rows[:limit]],'next_offset':offset+limit if len(rows)>limit else None}

    def _message_reactions(self, db, identifier, chat_id):
        """Bounded acquired reaction history, not a current phone-state claim.

        Match complete keys and verified aliases only. Reuse event visibility so
        revocation, temporary content and ambiguous sources remain withheld.
        Empty text records removal; history is not an aggregate reaction count.
        """
        variants = visibility.identifier_variants(db, identifier, self._canonical_chat)
        rows = db.execute("""SELECT * FROM account_events WHERE event_type='message.reaction'
            AND source_message_id IN (SELECT value FROM json_each(?))
            ORDER BY timestamp DESC,id LIMIT 51""", (canonical(variants),)).fetchall()
        events = []
        target = visibility.canonical_identifier(db, identifier, self._canonical_chat)
        resolved = {}
        for row in rows[:50]:
            if self._canonical_chat(db, row['chat_id']) != self._canonical_chat(db, chat_id):
                continue
            data = self._event_data(row)
            if not isinstance(data, dict):
                continue
            source = self._event_source(row, data)
            if visibility.canonical_identifier(db, source, self._canonical_chat) != target:
                continue
            reaction = data.get('reaction')
            text = reaction.get('text') if isinstance(reaction, dict) else None
            if not isinstance(text, str) or len(text) > 128:
                continue
            # Reaction visibility depends only on its typed target, unlike
            # multi-source events/quoted edits. Reuse that decision for the same
            # full key within this read snapshot; never cache across messages,
            # connections or requests, or bypass the shared privacy projection.
            if source not in resolved:
                projected = self._event_projection(db, row, data)
                usable = self._account_event_message_id(db, row, projected)
                resolved[source] = (isinstance(projected, dict) and 'reaction' in projected
                    and visibility.canonical_identifier(db, usable, self._canonical_chat) == target)
            if not resolved[source]:
                continue
            item = {'event_id': row['id'], 'timestamp': row['timestamp'],
                    'text': text, 'removed': text == ''}
            if type(data.get('fromMe')) is bool:
                item['from_me'] = data['fromMe']
            actor = data.get('participant')
            if not actor and not chat_id.endswith('@g.us') and data.get('fromMe') is False:
                actor = data.get('from')
            if isinstance(actor, str) and len(actor) <= 200:
                item['actor'] = self._canonical_chat(db, actor)
            events.append(item)
        if not events:
            return {}
        return {'reaction_events': events, 'reaction_coverage': {
            'source': 'acquired_events', 'current_state': 'unknown',
            'complete': False, 'truncated': len(rows) > 50}}

    def search(self, query="", chat_id=None, after=0, before=253402300799, limit=50, offset=0, cursor=None, chat_type='all'):
        from .archive_cursor import cursor_key,query_identity,decode_cursor,encode_cursor
        validate_chat_type(chat_type)
        if (type(after) is not int or type(before) is not int
                or not 0<=after<=before<=253402300799):
            raise ValueError('Invalid message time window')
        if cursor is not None and offset: raise ValueError('A cursor cannot be combined with a nonzero offset')
        key=cursor_key(self)
        with self.db() as db, visibility.read_snapshot(db):
            chat_id=self._canonical_chat(db,chat_id)
            identity=query_identity(query,chat_id,after,before,chat_type)
            # Resolving aliases can collapse two old rows into one logical
            # message. Reject an earlier page boundary instead of duplicating
            # or skipping messages across different identity projections.
            if db.execute('SELECT 1 FROM chat_aliases LIMIT 1').fetchone():
                identity=hashlib.sha256(canonical([identity,self._alias_signature(db)]).encode()).hexdigest()
            position=decode_cursor(key,cursor,identity) if cursor is not None else None
            clauses = ["m.deleted=0", visibility.visible_sql(), visibility.representative_sql(),
                       "m.timestamp>=?", "m.timestamp<=?"]
            values = [after, before]
            if chat_id:
                clauses.append("m.chat_id IN (?,?)")
                values.extend([chat_id,legacy_chat_id(chat_id)])
            if chat_type!='all':
                clauses.append('linked_chat_type(m.chat_id)=?')
                values.append(chat_type)
            if query:
                clauses.append("m.id IN (SELECT id FROM message_search WHERE message_search MATCH ?)")
                values.append('"' + query.replace('"', '""') + '"')
            if position:
                timestamp,identifier=position['boundary']
                clauses.append('(m.timestamp<? OR (m.timestamp=? AND m.id>?))')
                values.extend([timestamp,timestamp,identifier])
            cutoff=position['cutoff'] if position else db.execute('SELECT coalesce(max(rowid),0) FROM messages').fetchone()[0]
            clauses.append('m.rowid<=?')
            values.append(cutoff)
            rows = db.execute("SELECT m.*,c.data AS content FROM messages m LEFT JOIN message_content c ON c.message_id=m.id WHERE " + " AND ".join(clauses) + " ORDER BY m.timestamp DESC,m.id LIMIT ? OFFSET ?", values + [limit+1, offset]).fetchall()
            summary=visibility.clear_coverage(db,chat_id,self._canonical_chat)
            public=[]
            for row in rows[:limit]:
                value=dict(row)
                value['chat_id']=self._canonical_chat(db,row['chat_id'])
                metadata=visibility.clear_coverage(db,row['chat_id'],self._canonical_chat)
                if metadata: value['clear_chat_coverage']=metadata
                public.append({**self.public_message(value),
                               **self._message_reactions(db, row['id'], row['chat_id'])})
        expires=position['expires'] if position else int(time.time())+86400
        next_cursor=encode_cursor(key,identity,cutoff,[rows[limit-1]['timestamp'],rows[limit-1]['id']],expires) if len(rows)>limit else None
        return {"messages": public,
                **({"clear_chat_coverage":summary} if summary else {}),
                "next_offset": offset+limit if len(rows)>limit and cursor is None else None,
                'next_cursor':next_cursor,'pagination_consistency':'insertion_cutoff_current_content' if cursor is not None else 'legacy_offset_use_next_cursor_for_stability',
                "coverage": "acquired_archive_only", 'source':'acquired_archive',
                'current_state':visibility.CLEAR_UNCERTAIN if summary and summary['boundary_unknown'] else 'unknown',
                'mirror_complete':False}

    @staticmethod
    def public_message(row):
        value = dict(row)
        raw_content=value.pop('content',None)
        if raw_content: value.update(json.loads(raw_content))
        raw_media = value.pop("media")
        media = json.loads(raw_media) if raw_media else None
        value["attachment"] = {k: v for k,v in (media or {}).items() if k != "url"} if media else None
        value["from_me"] = bool(value["from_me"])
        value['chat_id']=normalize_chat_id(value['chat_id'])
        value['chat_type']=classify_chat(value['chat_id'])
        coverage=value.get('clear_chat_coverage')
        value['current_state'] = visibility.CLEAR_UNCERTAIN if coverage and coverage['boundary_unknown'] else 'unknown'
        value['content_state'] = 'acquired_current_unverified' if coverage else 'acquired'
        return value

    def message(self, message_id):
        with self.db() as db, visibility.read_snapshot(db):
            if self._message_state(db,message_id)['state']!='unknown': return None
            variants=canonical(visibility.identifier_variants(db,message_id,self._canonical_chat))
            r = db.execute("""SELECT m.*,c.data AS content FROM messages m
                LEFT JOIN message_content c ON c.message_id=m.id
                WHERE m.id IN (SELECT value FROM json_each(?)) AND m.deleted=0 AND """
                +visibility.visible_sql()+" ORDER BY m.rowid LIMIT 1", (variants,)).fetchone()
            if not r: return None
            value=dict(r)
            value['chat_id']=self._canonical_chat(db,r['chat_id'])
            value['chat_type']=classify_chat(value['chat_id'])
            coverage=visibility.clear_coverage(db,r['chat_id'],self._canonical_chat)
            if coverage: value['clear_chat_coverage']=coverage
            value.update(self._message_reactions(db, r['id'], r['chat_id']))
            return value

    def chats(self, limit=50, offset=0, *, owner=None, include_deleted=False, chat_type='all'):
        from .history_coverage import chat_summaries
        validate_chat_type(chat_type)
        with self.db() as db, visibility.read_snapshot(db):
            # Project deletion evidence and current visible activity in one read
            # snapshot. Directory metadata is never evidence of reappearance.
            # Legacy explicit anchors can outlive both the acquired row and event.
            rows = db.execute(f"""WITH deletions AS (
                SELECT linked_chat_id(json_extract(value,'$.chat_id')) AS chat_id,
                       max(max(coalesce(json_extract(value,'$.before'),
                                        json_extract(value,'$.event_at')),
                               json_extract(value,'$.event_at'))) AS boundary
                FROM state WHERE key>=? AND key<?
                  AND json_extract(value,'$.reason')='chat_deleted'
                GROUP BY linked_chat_id(json_extract(value,'$.chat_id'))
            ), directory AS (
                SELECT linked_chat_id(id) AS id,
                       coalesce(max(CASE WHEN id=linked_chat_id(id) THEN name END),max(name)) AS name
                FROM chats GROUP BY linked_chat_id(id)
            ), chat_ids AS (
                SELECT id FROM directory UNION SELECT chat_id FROM deletions
            ), acquired AS (
                SELECT i.id,c.name,min(m.timestamp) AS first_message_at,
                       max(m.timestamp) AS last_message_at,count(m.id) AS archived_messages,
                       d.boundary AS deletion_evidence_at,
                       CASE WHEN d.boundary IS NOT NULL AND
                            (max(m.timestamp) IS NULL OR max(m.timestamp)<=d.boundary)
                            THEN 1 ELSE 0 END AS is_deleted
                FROM chat_ids i LEFT JOIN directory c ON c.id=i.id
                LEFT JOIN messages m ON m.chat_id IN (i.id,linked_legacy_chat_id(i.id)) AND m.deleted=0
                    AND {visibility.visible_sql()} AND {visibility.representative_sql()}
                LEFT JOIN deletions d ON d.chat_id=i.id
                WHERE i.id NOT IN (SELECT alias FROM chat_aliases)
                GROUP BY i.id
            ) SELECT * FROM acquired WHERE (? OR is_deleted=0) AND (?='all' OR linked_chat_type(id)=?)
              ORDER BY last_message_at DESC,id LIMIT ? OFFSET ?""",
                (visibility.PREFIX,visibility.PREFIX+'~',include_deleted,chat_type,chat_type,limit+1,offset)).fetchall()
            coverage=chat_summaries(self,db,[row['id'] for row in rows[:limit]],owner=owner)
            values=[]
            for row in rows[:limit]:
                value=dict(row)
                value['chat_type']=classify_chat(row['id'])
                deleted=bool(value.pop('is_deleted'))
                metadata=db.execute('SELECT value FROM state WHERE key=?',('chat_name:'+row['id'],)).fetchone()
                metadata=json.loads(metadata[0]) if metadata else {}
                value.update(name_source=metadata.get('source'),name_updated_at=metadata.get('updated_at'))
                value['history_coverage']=coverage[row['id']]
                value.update(source='acquired_archive',current_state='chat_deleted' if deleted else 'unknown',
                             chat_state='deleted' if deleted else 'has_acquired_messages' if row['archived_messages'] else 'no_acquired_messages',
                             message_count_scope='visible_acquired_only')
                clear=visibility.clear_coverage(db,row['id'],self._canonical_chat)
                if clear:
                    value.update(clear_chat_coverage=clear,message_count_scope='visible_acquired_only')
                    if clear['boundary_unknown'] and not deleted: value['current_state']=visibility.CLEAR_UNCERTAIN
                values.append(value)
        return {"chats": values, "next_offset": offset+limit if len(rows)>limit else None,
                'source':'acquired_archive','current_state':'unknown','mirror_complete':False,
                'pagination_consistency':'offset_current_visible_activity'}

    @staticmethod
    def _chat_archive_key(chat_id):
        return CHAT_ARCHIVE_PREFIX + hashlib.sha256(chat_id.encode()).hexdigest()

    @staticmethod
    def _archive_chat_id(chat_id):
        from .linked_state import _jid
        return _jid(chat_id)

    @staticmethod
    def _merge_chat_archive_state(previous, value):
        if not previous:
            return value
        old_time,new_time=previous.get('event_at'),value.get('event_at')
        # Cache lacks an event timestamp; it cannot displace ordered events.
        if old_time is not None:
            if new_time is None or new_time < old_time:
                return previous
            if new_time == old_time:
                if (previous.get('reason') == 'conflicting_same_timestamp' or
                        previous.get('archived') != value.get('archived') and previous.get('known')):
                    return {**previous,'known':False,'archived':None,
                            'reason':'conflicting_same_timestamp'}
                # An old full-sync/duplicate cannot erase a known stream gap.
                return previous
        elif new_time is None and value['observed_at'] <= previous.get('invalidated_at',-1):
            # A cache request started before a stream gap cannot restore state
            # merely because its response completed after the gap.
            return previous
        elif new_time is None and value['observed_at'] < previous['observed_at']:
            # A cache read requested earlier may finish after a later read.
            return previous
        elif new_time is None and value['observed_at'] == previous['observed_at']:
            if (previous.get('reason') == 'conflicting_cache_observation_time' or
                    previous.get('archived') != value.get('archived')):
                return {**previous,'known':False,'archived':None,
                        'reason':'conflicting_cache_observation_time'}
            return previous
        return value

    def _save_chat_archive_state(self, db, value):
        if value.get('event_at') is None:
            # This barrier exists even when the first cache request was already
            # in flight before a gap and no per-chat projection existed yet.
            # Read it in the same transaction that commits the observation.
            gap=db.execute('SELECT value FROM state WHERE key=?',(CHAT_ARCHIVE_GAP_KEY,)).fetchone()
            gap=json.loads(gap[0]) if gap else None
            if gap and value['observed_at'] <= gap['invalidated_at']:
                value={**value,'known':False,'archived':None,**gap}
        key=self._chat_archive_key(value['chat_id'])
        row=db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone()
        previous=json.loads(row[0]) if row else None
        self._state(db,key,self._merge_chat_archive_state(previous,value))

    def _observe_chat_archive_event(self, db, payload, observed_at):
        chat_id=self._canonical_chat(db,payload['chatId'])
        self._save_chat_archive_state(db,{
            'chat_id':chat_id,'known':True,'archived':payload['archived'],
            'source':'gows_archive_event','event_at':payload['eventAt'],
            'observed_at':observed_at,'from_full_sync':payload['fromFullSync'],
            'phone_fresh':False})

    def observe_chat_archive_cache(self, chat_id, snapshot, *, observed_at=None):
        """Store a typed provider cache snapshot; never infer phone freshness."""
        chat_id=self._archive_chat_id(chat_id)
        if (not isinstance(snapshot,dict) or type(snapshot.get('known')) is not bool or
                type(snapshot.get('archived')) is not bool or
                snapshot.get('source') != 'whatsmeow_chat_settings_cache' or
                snapshot.get('phone_fresh',snapshot.get('phoneFresh')) is not False):
            raise ValueError('Invalid chat archive cache snapshot')
        if 'phoneFresh' in snapshot and snapshot['phoneFresh'] is not False:
            raise ValueError('Invalid chat archive cache snapshot')
        observed_at=time.time() if observed_at is None else observed_at
        if type(observed_at) not in (int,float) or not math.isfinite(observed_at) or not 0 <= observed_at <= 253402300799:
            raise ValueError('Invalid chat archive observation time')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            chat_id=self._canonical_chat(db,chat_id)
            self._save_chat_archive_state(db,{
                'chat_id':chat_id,'known':snapshot['known'],
                'archived':snapshot['archived'] if snapshot['known'] else None,
                'source':'whatsmeow_chat_settings_cache','event_at':None,
                'observed_at':observed_at,'phone_fresh':False})
        return self.chat_archive_state(chat_id)

    def chat_archive_state(self, chat_id):
        """Organizational metadata, independent of acquired content/coverage."""
        chat_id=self._archive_chat_id(chat_id)
        with self.db() as db:
            chat_id=self._canonical_chat(db,chat_id)
            row=db.execute('SELECT value FROM state WHERE key=?',(self._chat_archive_key(chat_id),)).fetchone()
        value = json.loads(row[0]) if row else {
            'chat_id':chat_id,'known':False,'archived':None,'source':None,
            'event_at':None,'observed_at':None,'phone_fresh':False}
        return {**value, 'coverage_scope': 'chat_archived_flag_only', 'proves_missing_messages': False}

    @staticmethod
    def _invalidate_chat_archive_states(db, reason):
        # Persist a global barrier before visiting rows: a chat with no previous
        # cache/event observation can still have an in-flight cache request.
        row=db.execute('SELECT value FROM state WHERE key=?',(CHAT_ARCHIVE_GAP_KEY,)).fetchone()
        previous=json.loads(row[0]) if row else {}
        invalidated_at=max(time.time(),previous.get('invalidated_at',0))
        Store._state(db,CHAT_ARCHIVE_GAP_KEY,{'invalidated_at':invalidated_at,'reason':reason})
        # The metadata stays available for ordering, while the current value
        # becomes unknown across a delivery gap. Never touch message content.
        for row in db.execute('SELECT key,value FROM state WHERE key>=? AND key<?',
                              (CHAT_ARCHIVE_PREFIX,CHAT_ARCHIVE_PREFIX+'~')).fetchall():
            value=json.loads(row['value'])
            value.update(known=False,archived=None,reason=reason,invalidated_at=invalidated_at)
            Store._state(db,row['key'],value)

    def _bind_chat_archive_alias(self, db, alias, chat_id):
        alias_key=self._chat_archive_key(alias)
        row=db.execute('SELECT value FROM state WHERE key=?',(alias_key,)).fetchone()
        if row:
            value=json.loads(row[0])
            value['chat_id']=chat_id
            self._save_chat_archive_state(db,value)
            db.execute('DELETE FROM state WHERE key=?',(alias_key,))

    def reserve_send(self, key, owner, payload):
        digest = hashlib.sha256(canonical(payload).encode()).hexdigest()
        now = time.time()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT * FROM sends WHERE key=?", (key,)).fetchone()
            if old:
                if old["owner"] != owner or old["payload_hash"] != digest:
                    raise ValueError("Idempotency key already used for another payload")
                return False, dict(old)
            db.execute("INSERT INTO sends VALUES(?,?,?,?,?,?,?)", (key,owner,digest,"sending",None,now,now))
            return True, {"key": key, "state": "sending"}

    def record_send_result(self, key, state, provider_id=None, result=None):
        """Commit completion evidence without a fallible public read afterward.

        Callers classify dispatch before this phase. A persistence or later
        projection failure must not be recast as a new provider outcome. If
        this transaction rolls back, the consumed sending key remains for
        conservative restart recovery; it is never automatically dispatched again.
        """
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("UPDATE sends SET state=?,provider_id=?,updated=? WHERE key=?", (state,provider_id,time.time(),key))
            if result is not None:
                job=db.execute('SELECT operation FROM action_jobs WHERE key=?',(key,)).fetchone()
                db.execute('INSERT OR REPLACE INTO operation_results VALUES(?,?)',
                           (key,canonical(operation_result_metadata(result,state,job['operation'] if job else None))))
            from . import job_metadata
            job_metadata.reconcile(db,key,message_state=lambda identifier,**context:self._message_state(db,identifier,**context))

    def finish_send(self, key, state, provider_id=None, result=None):
        self.record_send_result(key,state,provider_id,result)
        return self.send_status(key)

    def queue_action(self,key,owner,operation,arguments,transfer_id=None):
        payload={'operation':operation,'arguments':arguments,'transfer_id':transfer_id}
        digest=hashlib.sha256(canonical(payload).encode()).hexdigest()
        now=time.time()
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT * FROM sends WHERE key=?',(key,)).fetchone()
            if old:
                if old['owner']!=owner or old['payload_hash']!=digest:
                    raise ValueError('Idempotency key already used for another payload')
            else:
                db.execute('INSERT INTO sends VALUES(?,?,?,?,?,?,?)',(key,owner,digest,'queued',None,now,now))
                db.execute('INSERT INTO action_jobs VALUES(?,?,?,?)',(key,operation,canonical(arguments),transfer_id))
                from . import job_metadata
                job_metadata.record(db,key,operation,arguments,transfer_id)
                job_metadata.reconcile(db,key,message_state=lambda identifier,**context:self._message_state(db,identifier,**context))
        return self.send_status(key)

    def existing_action(self,key,owner,operation,arguments,transfer_id=None):
        """Read an idempotent action before checking expirable execution inputs."""
        payload={'operation':operation,'arguments':arguments,'transfer_id':transfer_id}
        digest=hashlib.sha256(canonical(payload).encode()).hexdigest()
        with self.db() as db, visibility.read_snapshot(db):
            old=db.execute('SELECT owner,payload_hash FROM sends WHERE key=?',(key,)).fetchone()
            if not old: return None
            if old['owner']!=owner or old['payload_hash']!=digest:
                raise ValueError('Idempotency key already used for another payload')
        return self.send_status(key,owner=owner)

    def action_ready(self,key):
        from . import job_metadata
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            return job_metadata.reconcile(db,key,message_state=lambda identifier,**context:self._message_state(db,identifier,**context))

    def uncertain_actions(self, owner, *, limit=50, offset=0):
        from .action_diagnostics import list_uncertain
        with self.db() as db:
            db.execute('BEGIN')
            return list_uncertain(db, owner, limit=limit, offset=offset)

    def send_status(self, key, *, owner=None):
        from .operation_outcomes import provider_outcome
        with self.db() as db, visibility.read_snapshot(db):
            # Receipt evidence, revocation and action state share one snapshot;
            # reading status never advances an action or repairs the archive.
            r = db.execute("SELECT key,state,provider_id,created,updated FROM sends WHERE key=?", (key,)).fetchone()
            if not r: return None
            if owner is not None and not db.execute('SELECT 1 FROM sends WHERE key=? AND owner=?',(key,owner)).fetchone():
                return None
            value=dict(r)
            job=db.execute('SELECT operation,arguments FROM action_jobs WHERE key=?',(key,)).fetchone()
            extra=db.execute('SELECT result FROM operation_results WHERE key=?',(key,)).fetchone()
            if extra:
                try: result=json.loads(extra[0])
                except (ValueError,TypeError): result=None
                value['result']=operation_result_metadata(result,r['state'],job['operation'] if job else None)
            value['provider_outcome']=provider_outcome(value.get('result'))
            if r['state'] == 'uncertain':
                from .uncertain_review import status as review_status
                reviewed_owner = owner if owner is not None else db.execute(
                    'SELECT owner FROM sends WHERE key=?', (key,)).fetchone()[0]
                value['diagnostic_review'] = review_status(db, reviewed_owner, key)
            if (job and job['operation'] in ('groups_create_group','groups_join_group')
                    and r['state'] in ('submitted','uncertain')
                    and not (isinstance(r['provider_id'],str) and re.fullmatch(
                        r'[0-9]{1,25}(?:-[0-9]{1,25})?@g\.us',r['provider_id']))):
                value['group_identity']={'state':'unknown',
                    'recovery':'Reconcile the existing action; do not recreate or retry with a new key.'}
            value['delivery']=delivery_status(db,r,job,canonical_chat=lambda chat:self._canonical_chat(db,chat),
                                              revoked=self.is_revoked(db,r['provider_id']),
                                              identifier_variants=lambda identifier:visibility.identifier_variants(db,identifier,self._canonical_chat))
            return value

    def backup(self, target):
        target = Path(target)
        if target.exists():
            raise ValueError("Backup target already exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db, sqlite3.connect(target) as copy:
            db.backup(copy)
            if copy.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("Backup integrity check failed")

