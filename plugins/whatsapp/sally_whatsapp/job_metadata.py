"""Durable action identity, separate from the disposable execution payload.

These helpers participate in their caller's transaction. They never dispatch an
action, change its idempotency hash, or turn an uncertain attempt into a retry.
"""
import json

from . import visibility
from .delivery import MESSAGE_OPERATIONS


VERSION = 1
PRODUCING_OPERATIONS = MESSAGE_OPERATIONS | {
    'messages_forward_message', 'messages_send_buttons_reply',
    'status_send_text_status', 'status_send_image_status',
    'status_send_voice_status', 'status_send_video_status',
}
REDACTED_ROLES = frozenset({'produced', 'forward', 'media'})


def _canonical_chat(db, chat):
    if not isinstance(chat, str) or not chat.endswith('@lid'):
        return chat
    row = db.execute('SELECT chat_id FROM chat_aliases WHERE alias=?', (chat,)).fetchone()
    return row[0] if row else chat


def _arguments(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return {}, 'malformed'
    if not isinstance(value, dict):
        return {}, 'malformed'
    # An already blank historical payload cannot establish absent metadata.
    if not value:
        return {}, 'unknown'
    if any(part in value and not isinstance(value[part], dict) for part in ('body', 'path')):
        return {}, 'malformed'
    if not any(part in value for part in ('body', 'path')):
        return {}, 'unknown'
    return value, 'known'


def _field(value, known):
    if known != 'known':
        return known, None
    if value is None or value == '':
        return 'absent', None
    if not isinstance(value, str):
        return 'malformed', None
    return 'present', value


def _add_source(db, key, role, identifier, chat=None):
    if not isinstance(identifier, str) or not identifier:
        return
    identity = visibility.message_identity(identifier)
    actual = db.execute('SELECT chat_id FROM messages WHERE id=?', (identifier,)).fetchone()
    # Full provider identity or an acquired row is stronger than destination.
    context = actual[0] if actual else identity[0] if identity else chat
    context = _canonical_chat(db, context)
    canonical = visibility.canonical_identifier(db, identifier, _canonical_chat)
    db.execute('''INSERT INTO action_job_sources(key,role,message_id,canonical_id,chat_id)
                  VALUES(?,?,?,?,?) ON CONFLICT(key,role,message_id) DO UPDATE SET
                  canonical_id=excluded.canonical_id,chat_id=excluded.chat_id''',
               (key, role, identifier, canonical, context))


def record(db, key, operation, arguments, transfer_id=None):
    """Extract reconciliation fields before any payload redaction, exactly once."""
    if db.execute('SELECT 1 FROM action_job_metadata WHERE key=?', (key,)).fetchone():
        return
    args, known = _arguments(arguments)
    body, path = args.get('body', {}), args.get('path', {})
    caller_state, caller = _field(body.get('id'), known)
    # Preserve the original body-or-path precedence, including absent/empty body.
    if any(part.get('chatId') is not None and not isinstance(part.get('chatId'), str)
           for part in (body, path)):
        destination_state, destination = 'malformed', None
    else:
        destination_state, destination = _field(body.get('chatId') or path.get('chatId'), known)
    db.execute('''INSERT INTO action_job_metadata
                  (key,version,metadata_state,caller_id_state,caller_message_id,
                   destination_state,destination_chat_id,payload_state)
                  VALUES(?,?,?,?,?,?,?,'available')''',
               (key, VERSION, known, caller_state, caller, destination_state, destination))
    if known != 'known':
        return
    for field in ('reply_to', 'replyTo'):
        _add_source(db, key, 'reply', body.get(field), destination)
    if operation == 'messages_forward_message':
        # Forward destination is not the source chat. A raw unacquired source
        # stays unscoped instead of being attributed to the recipient.
        _add_source(db, key, 'forward', body.get('messageId'))
    elif operation in {'messages_send_seen', 'messages_set_reaction', 'messages_set_star'}:
        _add_source(db, key, 'target', body.get('messageId'), destination)
        for identifier in body.get('messageIds', []) if isinstance(body.get('messageIds'), list) else []:
            _add_source(db, key, 'target', identifier, destination)
    elif operation == 'messages_send_poll_vote':
        _add_source(db, key, 'target', body.get('pollMessageId'), destination)
    elif operation.startswith('chats_'):
        _add_source(db, key, 'target', path.get('messageId'), destination)
    elif operation == 'status_delete_status':
        _add_source(db, key, 'target', body.get('id'))
    if transfer_id:
        row = db.execute('SELECT source_message_id FROM media_jobs WHERE id=?', (transfer_id,)).fetchone()
        if row:
            _add_source(db, key, 'media', row[0])


def delivery_metadata(db, key):
    """Read only; unknown historical fields must not become negative evidence."""
    row = db.execute('SELECT * FROM action_job_metadata WHERE key=?', (key,)).fetchone()
    if row is None or row['version'] != VERSION:
        return {'metadata_state': 'unknown', 'caller_id_state': 'unknown',
                'destination_state': 'unknown', 'destination_chat_id': None}
    return dict(row)


def reconcile(db, key, *, message_state):
    """Redact proven revoked payload and report whether a worker may proceed.

    A reply/target reference guards the request but does not establish that its
    independently authored text is copied from the target. Local deletion only
    withholds execution; irreversible redaction requires a permanent revocation.
    """
    job = db.execute('''SELECT j.operation,j.arguments,j.transfer_id,s.provider_id
                        FROM action_jobs j JOIN sends s USING(key) WHERE j.key=?''', (key,)).fetchone()
    if job is None:
        return False
    record(db, key, job['operation'], job['arguments'], job['transfer_id'])
    metadata = delivery_metadata(db, key)
    arguments, known = _arguments(job['arguments'])
    metadata_removal = (known == 'known' and
        (job['operation'] == 'chats_unpin_message' or
         job['operation'] == 'messages_set_star' and arguments.get('body', {}).get('star') is False))
    if job['operation'] in PRODUCING_OPERATIONS:
        _add_source(db, key, 'produced', job['provider_id'], metadata.get('destination_chat_id'))
    permitted = metadata.get('version') == VERSION and metadata.get('payload_state') == 'available'
    redact = False
    for source in db.execute('SELECT * FROM action_job_sources WHERE key=?', (key,)).fetchall():
        if (source['role']=='forward' or source['role']=='target' and
                job['operation'] in ('messages_set_star','chats_pin_message') and not metadata_removal):
            from .forwarding import source_state
            state=source_state(message_state,source['message_id'],chat_id=source['chat_id'],defer_unknown_time=True)['state']
        else:
            state = message_state(source['message_id'], chat_id=source['chat_id'])['state']
        # Provider-returned IDs are exact identities, including opaque IDs that
        # do not encode a chat. A legacy unscoped tombstone must still remove
        # their payload. User-supplied raw reply/target references remain scoped.
        if source['role'] in ('produced', 'media') and state != 'revoked':
            if message_state(source['message_id'])['state'] == 'revoked':
                state = 'revoked'
        # Removing a star/pin changes metadata without reading or re-sending
        # the original. Known removal does not prevent that inverse action;
        # full identity/destination checks still run before dispatch.
        if state != 'unknown' and not (metadata_removal and source['role'] == 'target'):
            permitted = False
        if state == 'revoked' and source['role'] in REDACTED_ROLES:
            redact = True
    if redact:
        db.execute("UPDATE action_jobs SET arguments='{}' WHERE key=?", (key,))
        db.execute("UPDATE action_job_metadata SET payload_state='redacted' WHERE key=?", (key,))
    return permitted and not redact


def redact_revoked(db, message_id, *, message_state, chat_id=None):
    """Reconcile only jobs related to this exact or explicitly scoped notice."""
    canonical = visibility.canonical_identifier(db, message_id, _canonical_chat)
    keys = set()
    if chat_id is None or visibility.message_identity(message_id) is not None:
        keys.update(row[0] for row in db.execute('''SELECT key FROM action_job_sources
                    WHERE message_id=? OR canonical_id=?''', (message_id, canonical)))
    if chat_id is not None:
        chat = _canonical_chat(db, chat_id)
        keys.update(row[0] for row in db.execute('''SELECT key FROM action_job_sources
                    WHERE chat_id=? AND linked_tuple_match(message_id,?,NULL)''', (chat, message_id)))
    # Startup backfill completes before admission; fresh queue/finish writers
    # persist these references atomically. No global job scan on each notice.
    for key in sorted(keys):
        reconcile(db, key, message_state=message_state)


def rebind_alias(db, alias, chat_id, *, message_state):
    """Reindex verified references after alias binding, in the same transaction."""
    keys = set()
    # A participant alias can occur inside a group serialization; this scan is
    # limited to alias changes, never repeated for every revocation/read.
    rows = db.execute('''SELECT * FROM action_job_sources
                         WHERE chat_id=? OR instr(message_id,?)>0''', (alias, alias)).fetchall()
    for row in rows:
        _add_source(db, row['key'], row['role'], row['message_id'],
                    chat_id if row['chat_id'] == alias else row['chat_id'])
        keys.add(row['key'])
    for key in sorted(keys):
        reconcile(db, key, message_state=message_state)


def backfill_batch(db, after_rowid, limit, *, message_state):
    """Caller commits refs/redaction and its progress marker in one batch."""
    rows = db.execute('''SELECT rowid,key,operation,arguments,transfer_id FROM action_jobs
                         WHERE rowid>? ORDER BY rowid LIMIT ?''', (after_rowid, limit)).fetchall()
    for row in rows:
        record(db, row['key'], row['operation'], row['arguments'], row['transfer_id'])
        reconcile(db, row['key'], message_state=message_state)
    return (rows[-1]['rowid'] if rows else after_rowid), len(rows) < limit
