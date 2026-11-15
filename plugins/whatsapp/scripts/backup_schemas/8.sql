
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
