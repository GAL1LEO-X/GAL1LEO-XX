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
