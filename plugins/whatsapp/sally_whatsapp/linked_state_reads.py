"""Read projections preserve known deletions without inferring a complete mirror.

Only catalog operations whose result contains messages enter this boundary. An
arbitrary provider object with an ``id`` is not evidence that it is a message.
Empty pages and unavailable sources never mutate acquired state.
"""
import math
import time

from .account_events import message_chat
from .visibility import CLEAR_UNCERTAIN
from . import lifetime
from . import visibility
from .chat_identity import chat_type
from .gateway import GatewayUnavailable


MESSAGE_LIST_OPERATIONS = frozenset({
    'chats_get_chat_messages',
})
CHAT_LIST_OPERATIONS = frozenset({'chats_get_chats', 'chats_get_chats_overview', 'chats_post_chats_overview'})
MESSAGE_READ_OPERATIONS = MESSAGE_LIST_OPERATIONS | CHAT_LIST_OPERATIONS | {
    'chats_get_chat_message',
    'channels_preview_channel_messages',
}


def validate_live_scope(store, operation, arguments, value):
    """Reject a contradictory top-level page, never silently shift its offset.

Only the two exact chat-message routes promise this scope. Quoted replies and
channel preview wrappers have their own provenance and are not page members.
Validation runs before public/lifetime projection and makes no observations.
"""
    if operation not in MESSAGE_LIST_OPERATIONS | {'chats_get_chat_message'}:
        return
    path, query = arguments['path'], arguments['query']
    multiple = operation in MESSAGE_LIST_OPERATIONS
    rows = value if multiple else [value]
    def invalid():
        raise GatewayUnavailable('Provider message response does not match the requested scope')
    if not isinstance(rows, list) or multiple and len(rows) > query.get('limit', 100):
        invalid()
    with store.db() as db, visibility.read_snapshot(db):
        chat = store._canonical_chat(db, path['chatId'])
        requested = path.get('messageId')
        variants = visibility.identifier_variants(db, requested, store._canonical_chat) if requested else ()
        for row in rows:
            if not isinstance(row, dict): invalid()
            identifier = row.get('id')
            if (not isinstance(identifier, str) or not 0 < len(identifier) <= 512
                    or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in identifier)):
                invalid()
            identity = visibility.message_identity(identifier)
            if 'fromMe' in row and type(row['fromMe']) is not bool:
                invalid()
            observed_chat = message_chat(row) or (identity[0] if identity else None)
            # A complete serialized key can establish context when optional
            # provider fields are absent; an opaque ID alone cannot.
            if (not observed_chat or store._canonical_chat(db, observed_chat) != chat
                    or not store._identity_context_matches(db, identifier, chat, row.get('fromMe'), row.get('participant'))
                    or requested and identifier not in variants):
                invalid()
            # Do not turn an explicit contradictory from/to context into an
            # apparently valid key-only response (notably outgoing messages).
            if (row.get('fromMe') is True and ('from' in row or 'to' in row)
                    and chat not in (store._canonical_chat(db,row.get('from')),store._canonical_chat(db,row.get('to')))):
                invalid()
            direction=row.get('fromMe',identity[1] if identity else None)
            if not store._acquired_context_matches(db,identifier,chat,direction,row.get('participant')):
                invalid()
            lower, upper = query.get('filter.timestamp.gte'), query.get('filter.timestamp.lte')
            if lower is not None or upper is not None:
                timestamp = row.get('timestamp')
                if (type(timestamp) not in (int, float) or not 0 <= timestamp <= 253402300799
                        or not math.isfinite(timestamp)
                        or lower is not None and timestamp < lower or upper is not None and timestamp > upper):
                    invalid()


def provenance(source, *, current_state=None, observed_at=None):
    return {'source': source,
            'current_state': current_state or ('provider_observation' if source == 'live_gateway' else 'unknown'),
            'mirror_complete': False,
            **({'observed_at': observed_at} if observed_at is not None else {})}


def state_model():
    """Implementation limits, not an attestation of provider configuration."""
    return {
        'model': 'linked_device_working_copy',
        'archive_source': 'acquired_archive',
        'live_source': 'live_gateway',
        'mirror_complete': False,
        'absence_implies_deletion': False,
        'unobserved_current_state': 'unknown',
        'deletion_evidence': 'explicit_provider_events',
        'provider_event_coverage': 'depends_on_engine_and_session_configuration',
        'provider_event_configuration_verified': False,
    }


def _message(store, value, *, chat_id=None, identifier=None, depth=0, include_chat_type=False):
    # Retained event quotes also enter at depth zero. Metadata opt-in is
    # separate from nesting depth so their original projection budget stays 9.
    if not isinstance(value, dict):
        return value
    requested_identifier = identifier
    identifier = value.get('id') if isinstance(value.get('id'), str) else identifier
    chat_id = message_chat(value) or chat_id
    evidence=lifetime.metadata(value)
    observe=getattr(store,'observe_message_lifetime',None)
    if evidence is not None and callable(observe):
        if observe(identifier,chat_id,evidence,from_me=value.get('fromMe'),participant=value.get('participant')) is False:
            return {**({'id':identifier} if identifier else {}),'content_state':'unverified_reference'}
    value=lifetime.project(value)
    if value.get('content_state') in lifetime.BLOCKED:
        return value
    timestamp = value.get('timestamp')
    if (type(timestamp) not in (int, float) or not 0 <= timestamp <= 253402300799
            or not math.isfinite(timestamp)): timestamp = None
    state = store.message_state(identifier, chat_id=chat_id, timestamp=timestamp)
    if state['state'] == 'unknown' and requested_identifier and requested_identifier != identifier:
        state = store.message_state(requested_identifier, chat_id=chat_id, timestamp=timestamp)
    if state['state'] != 'unknown':
        # Whitelist the output: filenames, URLs, quoted text and future provider
        # content fields must not survive a known deletion.
        return {**({'id': identifier} if identifier else {}), 'content_state': state['state']}
    edit_reader = getattr(store, 'observed_edit', None)
    edit = edit_reader(identifier, value.get('body'), chat_id=chat_id, timestamp=timestamp,
                       from_me=value.get('fromMe'), participant=value.get('participant')) if callable(edit_reader) else None
    if edit and 'content_state' in edit:
        return {**({'id': identifier} if identifier else {}), 'content_state': edit['content_state']}
    if edit and not edit['matches_provider']:
        # The provider can retain an original after a real edit. Expose the
        # acquired edit with explicit provenance; never label it current live
        # content or leak old quotes/previews/captions alongside it.
        value = {key: value[key] for key in ('id','from','to','fromMe','participant','timestamp')
                 if key in value}
        return {**value, **({'chat_type':chat_type(chat_id)} if include_chat_type and chat_id else {}),
                'body': edit['body'], 'body_source': 'acquired_edit',
                'content_state': 'edit_conflict', 'current_state': 'edit_conflict',
                'provider_body_matches_observed_edit': False,
                'edit_observed_at': edit['observed_at']}
    if edit:
        value = {**value, 'provider_body_matches_observed_edit': True,
                 'edit_observed_at': edit['observed_at']}
    # WAHA's documented Message.replyTo carries quoted content and an optional
    # original ID. Never infer that target from participant or quoted text.
    # https://waha.devlike.pro/docs/how-to/receive-messages/#replyto
    if isinstance(value.get('replyTo'), dict):
        reply = (_message(store, value['replyTo'], chat_id=chat_id, depth=depth+1)
                 if depth < 8 else {'content_state': 'unknown', 'content_omitted': 'nested_reply_limit'})
        value={**value, 'replyTo': reply}
    coverage=state.get('clear_chat_coverage')
    if coverage:
        value={**value,'clear_chat_coverage':coverage,
               **({'current_state':CLEAR_UNCERTAIN} if coverage['boundary_unknown'] else {})}
    if 'ack' in value:
        from .delivery import cache_ack_provenance
        value={**value, 'ack_provenance':cache_ack_provenance(store,value,chat_id)}
    return {**value, **({'chat_type': chat_type(chat_id)} if include_chat_type and chat_id else {})}


def project_live_read(store, operation, arguments, value, *, observed_at=None):
    """Preserve result shape and offsets while redacting known deleted targets."""
    if operation in ('groups_get_group', 'groups_get_member_add_mode'):
        # GOWS GetGroupInfo reads its group cache, not a fresh WhatsApp query.
        # Retrieval time cannot certify when that cache last changed.
        result = {'result': value, 'source': 'provider_group_cache',
                  'retrieved_at': time.time() if observed_at is None else observed_at,
                  'freshness': {'state': 'unverified', 'may_be_stale_after_mutation': True,
                                'refresh_operation': 'groups_refresh_groups'}}
        if operation == 'groups_get_group' and isinstance(value, dict):
            participants = value.get('Participants')
            reported = value.get('ParticipantCount')
            if isinstance(participants, list) and type(reported) is int:
                result['participant_count_evidence'] = {
                    'reported': reported, 'listed': len(participants),
                    'agreement': 'consistent' if reported == len(participants) else 'mismatch',
                    'list_completeness': 'unverified', 'current_count': 'unknown'}
        return result
    if operation not in MESSAGE_READ_OPERATIONS:
        return {'result': value}
    path = arguments.get('path', {})
    channel_id = path.get('id')
    chat_id = path.get('chatId') or (channel_id if operation == 'channels_preview_channel_messages'
                                   and isinstance(channel_id, str) and channel_id.endswith('@newsletter') else None)
    if operation == 'chats_get_chat_message':
        result = _message(store, value, chat_id=chat_id, identifier=path.get('messageId'), include_chat_type=True)
    elif operation in MESSAGE_LIST_OPERATIONS:
        result = [_message(store, item, chat_id=chat_id, include_chat_type=True) for item in value] if isinstance(value, list) else value
    elif operation == 'channels_preview_channel_messages':
        # The documented preview is [{message: Message, reactions, viewCount}],
        # not a Message[]. Keep pagination while removing the deleted wrapper's
        # metadata as well as its message content.
        # https://waha.devlike.pro/docs/how-to/channels/#get-messages-preview-for-channel
        result = [] if isinstance(value, list) else value
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and isinstance(item.get('message'), dict):
                    projected = _message(store, item['message'], chat_id=chat_id, include_chat_type=True)
                    item = ({'message': projected} if projected.get('content_state') not in (None, 'unknown')
                            else {**item, 'message': projected})
                result.append(item)
    else:
        result = [] if isinstance(value, list) else value
        if isinstance(value, list):
            for chat in value:
                if isinstance(chat, dict) and isinstance(chat.get('lastMessage'), dict):
                    chat = {**chat, 'lastMessage': _message(store, chat['lastMessage'], chat_id=chat.get('id'), include_chat_type=True)}
                result.append(chat)
    coverage_reader=getattr(store,'clear_chat_coverage',None)
    coverage=coverage_reader(chat_id) if callable(coverage_reader) else None
    return {'result': result,
            **provenance('live_gateway',current_state=CLEAR_UNCERTAIN if coverage and coverage['boundary_unknown'] else None,
                         observed_at=time.time() if observed_at is None else observed_at),
            **({'clear_chat_coverage':coverage} if coverage else {})}
