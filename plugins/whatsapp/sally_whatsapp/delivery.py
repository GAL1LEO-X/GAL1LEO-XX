"""Read-only receipt evidence; gateway submission is a separate contract.

WAHA 2026.9.2 (90ba445a0e765701c8910f0fac08176250c3e0fd), WAMessageAck.
Do not infer missing levels, shorten message IDs, or count group recipients.
Complete serialized IDs may match only through verified persisted aliases.
"""
import json


# These operations create a message. An edit/reaction/seen result can contain the
# original message's ID: its receipts must never be attributed to that action.
MESSAGE_OPERATIONS = frozenset({
    'messages_send_text', 'messages_send_image', 'messages_send_file',
    'messages_send_voice', 'messages_send_video', 'messages_send_sticker',
    'messages_send_link_custom_preview', 'messages_send_list',
    'messages_send_poll', 'messages_send_location', 'messages_send_contact_vcard',
    'messages_forward_message', 'calendar_send_event',
})
ACK_NAMES = {-1: 'ERROR', 0: 'PENDING', 1: 'SERVER', 2: 'DEVICE', 3: 'READ', 4: 'PLAYED'}
ACK_LEVELS = {-1: 'error', 0: 'pending', 1: 'server', 2: 'delivered', 3: 'read', 4: 'played'}


def cache_ack_provenance(store, message, chat_id):
    """Compare observations without rewriting a provider ACK or acquired data."""
    ack = message.get('ack')
    valid = type(ack) is int and ack in ACK_NAMES
    result = {'source': 'provider_message_projection', 'enum': 'WAHA_WAMessageAck',
              'ack': ack if valid else None, 'ack_name': ACK_NAMES[ack] if valid else None,
              'observed_at_source': 'unknown', 'phone_current_state': 'unknown',
              'comparison': 'not_compared', 'missing_levels_inferred': False}
    reader = getattr(store, 'message_delivery_evidence', None)
    if not callable(reader) or message.get('fromMe') is not True or not isinstance(message.get('id'), str):
        return result
    evidence = reader(message['id'], chat_id)
    result['acquired_receipts'] = evidence
    levels = [item['ack'] for item in evidence.get('evidence', {}).values()]
    if valid and levels:
        highest = max(levels)
        result['comparison'] = ('consistent_observations' if highest == ack else
                                'provider_cache_behind_acquired_receipt' if 0 <= ack < highest else
                                'different_observations')
    return result


def _result(status, *, reason=None, scope='unknown', evidence=None):
    value = {'status': status, 'scope': scope, 'coverage': 'acquired_webhooks_only',
             'evidence': evidence or {}}
    if reason:
        value['reason'] = reason
    return value


def delivery_status(db, send, job, *, canonical_chat, revoked, identifier_variants=None):
    """Project exact, persisted receipt evidence in the caller's read snapshot."""
    if job and job['operation'] not in MESSAGE_OPERATIONS:
        return _result('not_applicable', reason='operation_not_tracked')
    provider_id = send['provider_id']
    if not isinstance(provider_id, str) or not provider_id:
        return _result('unavailable', reason='provider_id_missing')
    if revoked:
        return _result('unavailable', reason='message_revoked')
    if send['state'] not in ('submitted', 'uncertain'):
        return _result('unavailable', reason='action_not_submitted')
    variants = (identifier_variants(provider_id) if identifier_variants else [provider_id])
    identifiers = set(variants)
    encoded = json.dumps(variants)

    # A provider ID reused by two message-producing requests cannot identify
    # which request a receipt acknowledges. Non-message actions do not compete.
    matches = 0
    for row in db.execute('''SELECT j.operation FROM sends s
                            LEFT JOIN action_jobs j ON j.key=s.key
                            WHERE s.provider_id IN (SELECT value FROM json_each(?))''', (encoded,)):
        if row['operation'] is None or row['operation'] in MESSAGE_OPERATIONS:
            matches += 1
            if matches > 1:
                return _result('ambiguous', reason='provider_id_reused')

    destination = None
    if job:
        from .job_metadata import delivery_metadata
        metadata = delivery_metadata(db, send['key'])
        if (metadata['metadata_state'] != 'known'
                or metadata['caller_id_state'] in ('unknown', 'malformed')
                or metadata['destination_state'] in ('unknown', 'malformed')):
            return _result('unavailable', reason='action_metadata_unavailable')
        # Several sending DTOs accept a caller-supplied WA message ID. It may
        # reuse a pre-existing message outside the local sends registry.
        if metadata['caller_id_state'] == 'present':
            return _result('ambiguous', reason='caller_supplied_message_id')
        destination = canonical_chat(metadata['destination_chat_id'])
    evidence, chats, scopes = {}, set(), set()
    rows = db.execute('''SELECT id,event_type,chat_id,timestamp,data FROM account_events
                         WHERE source_message_id IN (SELECT value FROM json_each(?))
                           AND event_type IN ('message.ack','message.ack.group')
                         ORDER BY timestamp,id''', (encoded,))
    for row in rows:
        try:
            payload = json.loads(row['data'])
        except (ValueError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        ack = payload.get('ack')
        # bool is an int subclass; strings and unknown enums are not receipts.
        if (not isinstance(payload.get('id'), str) or payload['id'] not in identifiers
                or type(ack) is not int or ack not in ACK_NAMES
                or payload.get('ackName') != ACK_NAMES[ack]):
            continue
        chat = canonical_chat(row['chat_id'])
        if not isinstance(chat, str):
            continue
        group = chat.endswith('@g.us')
        if not group and not chat.endswith(('@c.us', '@lid', '@s.whatsapp.net')):
            continue
        if row['event_type'] == 'message.ack.group':
            # WEBJS emits fromMe=false for an outgoing group receipt. Permit
            # that verified shape only with a persisted, matching destination.
            if not group or type(payload.get('fromMe')) is not bool:
                continue
            if payload['fromMe'] is False and (not destination or destination != chat):
                continue
        elif payload.get('fromMe') is not True:
            continue
        if destination and chat != destination:
            return _result('ambiguous', reason='receipt_destination_conflict')
        chats.add(chat)
        if len(chats) > 1:
            return _result('ambiguous', reason='receipt_chat_conflict')
        scopes.add('group_partial' if group else 'direct')
        level = ACK_LEVELS[ack]
        # Earliest acquired envelope per level, ordered deterministically. A
        # late, earlier envelope can refine this reference without losing levels.
        # Timestamp is the webhook envelope time, never a promised delivery time.
        evidence.setdefault(level, {'event_id': row['id'], 'event_type': row['event_type'],
                                    'ack': ack, 'ack_name': ACK_NAMES[ack],
                                    'event_timestamp': row['timestamp']})
    if not evidence:
        return _result('not_observed')
    return _result('observed', scope=scopes.pop(), evidence=evidence)
