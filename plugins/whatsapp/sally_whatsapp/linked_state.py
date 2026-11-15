"""Bounded projections of the pinned GOWS app-state events.

This decoder establishes neither webhook authenticity nor completeness. Its caller
must authenticate the envelope and apply the returned exclusions transactionally.
ClearChat establishes uncertain coverage only. Range keys can be boundary
anchors and the pinned decoder loses an uninterpreted selection index.
"""
from datetime import datetime
import math
import re

from .event_validation import EventValidationError, checked_field
from .provider_events import PROVIDER_EVENT_TYPES
from .chat_identity import normalize_chat_id


_EVENTS = {
    'events.DeleteChat': ('chat.deleted', 'chat_deleted'),
    'events.ClearChat': ('chat.cleared', 'chat_cleared'),
    'events.DeleteForMe': ('message.deleted_for_me', 'deleted_for_me'),
    'events.Archive': ('chat.archived', 'archive_state'),
}
ENGINE_EVENT_TYPES = tuple(_EVENTS) + PROVIDER_EVENT_TYPES
_JID = re.compile(r'(?:[0-9]+@(?:s\.whatsapp\.net|c\.us|lid)|[0-9]+(?:-[0-9]+)?@g\.us)\Z')
_RFC3339 = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)\Z')
_RAW_ID = re.compile(r'[A-Za-z0-9_.:-]{1,200}\Z')


def _invalid(reason='invalid_value', field=None):
    # Do not reflect arbitrary source data, which may contain private content.
    raise EventValidationError('Invalid GOWS linked-state event', reason=reason, field=field)


@checked_field('JID')
def _jid(value):
    if not isinstance(value, str) or len(value) > 200 or not _JID.fullmatch(value):
        _invalid()
    return normalize_chat_id(value)


@checked_field('MessageID')
def _raw_id(value):
    if not isinstance(value, str) or not _RAW_ID.fullmatch(value):
        _invalid()
    return value


def _boolean(data, name, default=False):
    value = data.get(name, default)
    if type(value) is not bool:
        _invalid('invalid_type', name)
    return value


@checked_field('Timestamp')
def _event_timestamp(value):
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        _invalid('invalid_type' if not isinstance(value, str) else 'invalid_value')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except (ValueError, OverflowError, OSError):
        _invalid()
    if not math.isfinite(result) or result < 0:
        _invalid('out_of_range')
    return result


def _optional_seconds(data, name):
    if name in data:
        value = data[name]
        if type(value) is not int or not 0 <= value <= 253402300799:
            _invalid('invalid_type' if type(value) is not int else 'out_of_range', name)


def _action(data):
    action = data.get('Action')
    if action is None:
        return {}
    if not isinstance(action, dict):
        _invalid('invalid_type', 'Action')
    return action


def _references(action, chat_id, reason, event_at):
    value = action.get('messageRange')
    if value is None:
        return []
    if not isinstance(value, dict):
        _invalid('invalid_type', 'Action.messageRange')
    _optional_seconds(value, 'lastMessageTimestamp')
    _optional_seconds(value, 'lastSystemMessageTimestamp')
    messages = value.get('messages', [])
    if not isinstance(messages, list) or len(messages) > 1000:
        _invalid('invalid_type' if not isinstance(messages, list) else 'out_of_range', 'Action.messageRange.messages')
    result, seen = [], set()
    for message in messages:
        if not isinstance(message, dict) or not isinstance(message.get('key'), dict):
            _invalid('invalid_type', 'Action.messageRange.messages.key')
        _optional_seconds(message, 'timestamp')
        key = message['key']
        if 'remoteJID' in key and _jid(key['remoteJID'], field='remoteJID') != chat_id:
            _invalid('inconsistent', 'remoteJID')
        if 'participant' in key:
            if not isinstance(key['participant'], str):
                _invalid('invalid_type', 'participant')
            if key['participant']:
                _jid(key['participant'], field='participant')
        if 'fromMe' not in key:
            _invalid('missing', 'fromMe')
        raw_id, from_me = _raw_id(key.get('ID'), field='ID'), _boolean(key, 'fromMe')
        identity = (raw_id, from_me)
        if identity not in seen:
            seen.add(identity)
            result.append({'kind': 'message', 'chat_id': chat_id, 'raw_id': raw_id,
                           'from_me': from_me, 'reason': reason, 'event_at': event_at})
    return result


def decode_engine_event(envelope):
    """Return safe metadata/exclusions, ignore unknown engines/events, reject malformed known events."""
    if not isinstance(envelope, dict) or envelope.get('event') != 'engine.event' or envelope.get('engine') != 'GOWS':
        return None
    payload = envelope.get('payload')
    if not isinstance(payload, dict) or not isinstance(payload.get('event'), str):
        return None
    if payload['event'] not in _EVENTS:
        from .provider_events import decode_provider_event
        return decode_provider_event(envelope)
    if 'session' in payload and payload['session'] != envelope.get('session'):
        _invalid('inconsistent', 'session')
    data = payload.get('data')
    if not isinstance(data, dict):
        _invalid('invalid_type', 'data')
    event, reason = _EVENTS[payload['event']]
    is_message = event == 'message.deleted_for_me'
    chat_id = _jid(data.get('ChatJID' if is_message else 'JID'), field='ChatJID' if is_message else 'JID')
    event_at = _event_timestamp(data.get('Timestamp'))
    from_full_sync = _boolean(data, 'FromFullSync')
    action = _action(data)
    metadata = {'chatId': chat_id, 'reason': reason, 'eventAt': event_at,
                'fromFullSync': from_full_sync}
    if event == 'chat.archived':
        # Missing protobuf booleans are unknown, never implicit unarchive. Range
        # keys are not needed to observe this organizational setting and never
        # become acquired messages, exclusions, or historical coverage.
        if 'archived' not in action:
            _invalid('missing', 'archived')
        archived = _boolean(action, 'archived')
        return {'event': event, 'payload': {
            'chatId': chat_id, 'archived': archived, 'eventAt': event_at,
            'fromFullSync': from_full_sync, 'source': 'gows_archive_event',
            'phoneFresh': False}, 'exclusions': []}
    if is_message:
        if 'IsFromMe' not in data:
            _invalid('missing', 'IsFromMe')
        from_me, raw_id = _boolean(data, 'IsFromMe'), _raw_id(data.get('MessageID'))
        if 'SenderJID' in data:
            if not isinstance(data['SenderJID'], str):
                _invalid('invalid_type', 'SenderJID')
            if data['SenderJID']:
                _jid(data['SenderJID'], field='SenderJID')
        _boolean(action, 'deleteMedia')
        _optional_seconds(action, 'messageTimestamp')
        exclusions = [{'kind': 'message', 'chat_id': chat_id, 'raw_id': raw_id,
                       'from_me': from_me, 'reason': reason, 'event_at': event_at}]
        metadata.update(coverage='message', messageId=raw_id, fromMe=from_me)
    else:
        _boolean(data, 'DeleteMedia')
        exclusions = _references(action, chat_id, reason, event_at)
        metadata['coverage'] = 'explicit_messages' if exclusions else 'unresolved'
        if event == 'chat.cleared':
            interval=action.get('messageRange') or {}
            bounds={k:interval[k] for k in ('lastMessageTimestamp','lastSystemMessageTimestamp') if k in interval}
            anchors=[]
            for reference in exclusions:
                raw_id,direction=reference['raw_id'],reference['from_me']
                original=next(item for item in interval.get('messages',[]) if
                              item['key']['ID']==raw_id and item['key']['fromMe']==direction)
                anchors.append({'raw_id':raw_id,'from_me':direction,
                                **({'timestamp':original['timestamp']} if 'timestamp' in original else {})})
            through=bounds.get('lastMessageTimestamp')
            # A conflicting source time is retained as metadata, never replaced
            # with an event-time cutoff. A range is only a candidate scope.
            if through is not None and through>event_at: through=None
            metadata.update(reason='clear_chat_coverage_uncertain',coverage='uncertain',
                            clearCoverage={'version':1,'certainty':'uncertain','selection':'unavailable',
                                           'range':bounds,'boundaryUnknown':through is None,
                                           'anchors':anchors})
            exclusions=[{'kind':'clear','chat_id':chat_id,'reason':'clear_chat_coverage_uncertain',
                         'event_at':event_at,'through':through,
                         'system_through':bounds.get('lastSystemMessageTimestamp'),
                         'anchors':anchors,'range':bounds,'before':0}]
        if event == 'chat.deleted':
            exclusions.insert(0, {'kind': 'chat', 'chat_id': chat_id, 'before': event_at,
                                  'reason': reason, 'event_at': event_at})
            metadata.update(coverage='provider_chat_before', before=event_at)
    metadata['excludedReferences'] = sum(item['kind'] == 'message' for item in exclusions)
    return {'event': event, 'payload': metadata, 'exclusions': exclusions}
