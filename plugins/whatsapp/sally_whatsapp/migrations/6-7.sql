-- Keep this byte-for-byte identical to sally_whatsapp/migrations/6-7.sql.
ALTER TABLE media_jobs ADD COLUMN source_message_id TEXT;
ALTER TABLE account_events ADD COLUMN source_message_id TEXT;
CREATE INDEX IF NOT EXISTS media_jobs_source ON media_jobs(source_message_id);
CREATE INDEX IF NOT EXISTS account_events_source ON account_events(source_message_id);
CREATE TABLE IF NOT EXISTS message_live_receipts (message_id TEXT PRIMARY KEY);
INSERT OR IGNORE INTO message_live_receipts SELECT id FROM messages WHERE source='webhook';

UPDATE account_events SET source_message_id=CASE
 WHEN NOT json_valid(data) THEN NULL
 WHEN event_type='message.revoked' THEN CASE
  WHEN json_type(data,'$.revokedMessageId')='text' AND json_extract(data,'$.revokedMessageId')<>'' THEN json_extract(data,'$.revokedMessageId')
  WHEN json_type(data,'$.before.id')='text' AND json_extract(data,'$.before.id')<>'' THEN json_extract(data,'$.before.id') END
 WHEN event_type='message.edited' THEN CASE
  WHEN json_type(data,'$.editedMessageId')='text' AND json_extract(data,'$.editedMessageId')<>'' THEN json_extract(data,'$.editedMessageId')
  WHEN json_type(data,'$.id')='text' AND json_extract(data,'$.id')<>'' THEN json_extract(data,'$.id') END
 WHEN event_type='message.reaction' THEN CASE
  WHEN json_type(data,'$.reaction')='object' AND json_type(data,'$.reaction.messageId')='text'
       AND json_extract(data,'$.reaction.messageId')<>'' THEN json_extract(data,'$.reaction.messageId')
  WHEN json_type(data,'$.revoked')='true' AND json_type(data,'$.message_id')='text'
       AND json_extract(data,'$.message_id')<>'' AND (SELECT count(*) FROM json_each(data))=2 THEN json_extract(data,'$.message_id') END
 WHEN event_type LIKE 'message.%' AND json_type(data,'$.id')='text' AND json_extract(data,'$.id')<>'' THEN json_extract(data,'$.id')
 END;
UPDATE messages SET deleted=1,body='',media=NULL
 WHERE deleted=1 OR id IN (SELECT message_id FROM message_mutations WHERE kind='revoked');
UPDATE message_content SET data='{}' WHERE message_id IN (SELECT id FROM messages WHERE deleted=1);
DELETE FROM message_search WHERE id IN (SELECT id FROM messages WHERE deleted=1);
UPDATE account_events SET data=json_object('message_id',source_message_id,'revoked',json('true'))
 WHERE source_message_id IN (SELECT message_id FROM message_mutations WHERE kind='revoked')
    OR source_message_id IN (SELECT id FROM messages WHERE deleted=1);
UPDATE deliveries SET body=json_set(body,'$.data.preview',''),
 state=CASE WHEN state IN ('pending','sending') THEN 'cancelled' ELSE state END
 WHERE json_extract(body,'$.name')='message.received'
 AND (json_extract(body,'$.data.message_id') IN (SELECT message_id FROM message_mutations WHERE kind='revoked')
   OR json_extract(body,'$.data.message_id') IN (SELECT id FROM messages WHERE deleted=1));

-- v6 discarded the source of ready files. Neither gateway provenance nor a
-- revoked source can be recovered safely. Invalidate old grants, preserve IDs;
-- the user can explicitly request another transfer. No automatic download.
UPDATE media_jobs SET state='cancelled',source=X'',filename='',mimetype='',size=NULL,sha256=NULL,
 error='Transfer invalidated by schema upgrade; request the file again'
 WHERE state='ready';
-- Empty string marks legacy encrypted sources pending application backfill.
-- NULL remains a transfer without a WhatsApp source (for example an upload).
UPDATE media_jobs SET source_message_id='' WHERE state IN ('queued','downloading');
PRAGMA user_version=7;
