-- Exact schema from 7d3c3c4fd6f31ccc085920d177f6282aec8a344d (0.3.4).

CREATE TABLE IF NOT EXISTS messages (
 id TEXT PRIMARY KEY, chat_id TEXT NOT NULL, sender TEXT, timestamp INTEGER NOT NULL,
 from_me INTEGER NOT NULL, body TEXT NOT NULL, media TEXT, deleted INTEGER NOT NULL DEFAULT 0,
 source TEXT NOT NULL, observed_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_chat_time ON messages(chat_id,timestamp,id);
CREATE TABLE IF NOT EXISTS message_content (message_id TEXT PRIMARY KEY REFERENCES messages(id),data TEXT NOT NULL);
CREATE VIRTUAL TABLE IF NOT EXISTS message_search USING fts5(id UNINDEXED, body, tokenize='unicode61');
CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, received_at REAL NOT NULL);
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
 expires REAL NOT NULL, error TEXT
);
CREATE INDEX IF NOT EXISTS media_jobs_due ON media_jobs(state,created);
CREATE TABLE IF NOT EXISTS history_jobs (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, request_key TEXT NOT NULL UNIQUE, request_hash TEXT NOT NULL,
 state TEXT NOT NULL, progress TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS account_events (
 id TEXT PRIMARY KEY, event_type TEXT NOT NULL, chat_id TEXT, timestamp REAL NOT NULL, data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS account_events_time ON account_events(timestamp,id);
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
PRAGMA user_version=6;
