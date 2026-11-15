"""Typed projections of additional events emitted by the pinned GOWS provider.

This is an allowlist, not a recursive sanitizer for arbitrary engine events.
Authentication, raw protocol trees, cryptographic fields and historical blobs
never cross this boundary. Acquisition, authorization and delivery are callers'
responsibility; FromFullSync observations must not trigger fresh notifications.
"""
from datetime import datetime
import math
import re

from .event_validation import EventValidationError, checked_field


_EVENTS = {
    'events.Star': 'message.starred',
    'events.Pin': 'chat.pinned',
    'events.Mute': 'chat.muted',
    'events.MarkChatAsRead': 'chat.read',
    'events.LabelAssociationMessage': 'label.message.added',
    'events.PushNameSetting': 'profile.name.changed',
    'events.UnarchiveChatsSetting': 'chat.archive_setting',
    'events.UserStatusMute': 'status.muted',
    'events.PushName': 'contact.push_name',
    'events.BusinessName': 'contact.business_name',
    'events.Picture': 'contact.picture',
    'events.UserAbout': 'contact.about',
    'events.IdentityChange': 'contact.identity',
    'events.PrivacySettings': 'account.privacy',
    'events.Blocklist': 'account.blocklist',
    'events.NewsletterJoin': 'channel.joined',
    'events.NewsletterLeave': 'channel.left',
    'events.NewsletterMuteChange': 'channel.muted',
    'events.NewsletterLiveUpdate': 'channel.updated',
    'events.UndecryptableMessage': 'message.unavailable',
    'events.NotifyAccountReachoutTimelock': 'account.reachout_timelock',
    'gows.MessageCapping': 'account.message_capping',
    'events.CallTerminate': 'call.terminated',
    'events.Receipt': 'message.receipt.self',
    'events.GroupInfo': 'group.v2.metadata',
}
PROVIDER_EVENT_TYPES = tuple(_EVENTS)
NORMALIZED_EVENT_TYPES = tuple(_EVENTS.values()) + ('label.message.deleted',)
_APPSTATE = frozenset((
    'events.Star', 'events.Pin', 'events.Mute', 'events.MarkChatAsRead',
    'events.LabelAssociationMessage', 'events.PushNameSetting',
    'events.UnarchiveChatsSetting', 'events.UserStatusMute',
))
_USER = re.compile(r'([0-9]{1,25})(?::([0-9]{1,5}))?@(s\.whatsapp\.net|c\.us|lid)\Z')
_CHAT = re.compile(r'[0-9]{1,25}(?:-[0-9]{1,25})?@g\.us\Z')
_CHANNEL = re.compile(r'[0-9]{1,25}@newsletter\Z')
_RAW_ID = re.compile(r'[A-Za-z0-9.:-]{1,200}\Z')
_STAMP = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)\Z')
_PRIVACY_FIELDS = ('GroupAdd', 'LastSeen', 'Status', 'Profile', 'ReadReceipts',
                   'Online', 'CallAdd', 'Messages', 'Defense', 'Stickers')
_PRIVACY_VALUES = ('', 'all', 'contacts', 'contact_allowlist', 'contact_blacklist',
                   'match_last_seen', 'known', 'none', 'on_standard', 'off')


def _invalid(reason='invalid_value', field=None):
    raise EventValidationError('Invalid GOWS provider event', reason=reason, field=field)


@checked_field('data')
def _object(value):
    if not isinstance(value, dict):
        _invalid('invalid_type')
    return value


@checked_field('data')
def _text(value, limit=1000):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 and c not in '\n\t' for c in value):
        _invalid()
    return value


@checked_field('data')
def _enum(value, values):
    if not isinstance(value, str) or value not in values:
        _invalid()
    return value


@checked_field('data')
def _bool(value):
    if type(value) is not bool:
        _invalid('invalid_type')
    return value


@checked_field('data')
def _int(value, minimum=0, maximum=2**53-1):
    if type(value) is not int:
        _invalid('invalid_type')
    if not minimum <= value <= maximum:
        _invalid('out_of_range')
    return value


@checked_field('Timestamp')
def _epoch(value):
    if isinstance(value, str) and re.fullmatch(r'[0-9]{1,12}', value):
        value = int(value)
    return _int(value, maximum=253402300799)


@checked_field('Timestamp')
def _timestamp(value):
    if not isinstance(value, str):
        _invalid('invalid_type')
    if not _STAMP.fullmatch(value):
        _invalid()
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except (ValueError, OverflowError, OSError):
        _invalid()
    if not math.isfinite(result) or not 0 <= result <= 253402300799:
        _invalid('out_of_range')
    return result


@checked_field('JID')
def _jid(value, *, user=False, channel=False):
    if not isinstance(value, str):
        _invalid('invalid_type')
    if channel:
        if not _CHANNEL.fullmatch(value):
            _invalid()
        return value
    match = _USER.fullmatch(value)
    if match:
        if match[2] and int(match[2]) > 65535:
            _invalid()
        return match[1] + '@' + ('c.us' if match[3] == 's.whatsapp.net' else match[3])
    if not user and (_CHAT.fullmatch(value) or _CHANNEL.fullmatch(value) or value == 'status@broadcast'):
        return value
    _invalid()


@checked_field('MessageID')
def _raw_id(value):
    if not isinstance(value, str) or not _RAW_ID.fullmatch(value):
        _invalid()
    return value


@checked_field('Messages')
def _items(value, limit=100):
    if not isinstance(value, list):
        _invalid('invalid_type')
    return value[:limit], len(value)


def _message_reference(chat, raw, direction, participant=None):
    """Only complete, direction-proven keys become get_message identifiers."""
    raw = _raw_id(raw)
    result = {'rawMessageId': raw, 'messageIdentity': 'partial'}
    if direction is None:
        return result
    direction = _bool(direction, field='IsFromMe')
    result['fromMe'] = direction
    suffix = ''
    if chat.endswith('@g.us'):
        if not participant:
            return result
        participant = _jid(participant, user=True, field='participant')
        result['participant'] = participant
        suffix = '_' + participant
    elif not _USER.fullmatch(chat):
        return result
    result.update(id=str(direction).lower()+'_'+chat+'_'+raw+suffix, messageIdentity='complete')
    return result


def _appstate(raw, data, out):
    action = _object(data.get('Action'), field='Action')
    if raw == 'events.Star':
        out['chatId'] = _jid(data.get('ChatJID'), field='ChatJID')
        out['starred'] = _bool(action.get('starred'), field='Action.starred')
        participant = data.get('SenderJID')
        if participant not in (None, ''):
            participant = _jid(participant, user=True, field='SenderJID')
        elif participant is not None and not isinstance(participant, str):
            _invalid('invalid_type', 'SenderJID')
        out.update(_message_reference(out['chatId'], data.get('MessageID'), _bool(data.get('IsFromMe'), field='IsFromMe'), participant))
    elif raw == 'events.LabelAssociationMessage':
        out['chatId'] = _jid(data.get('JID'), field='JID')
        out['labelId'] = _raw_id(data.get('LabelID'), field='LabelID')
        out['labeled'] = _bool(action.get('labeled'), field='Action.labeled')
        out.update(_message_reference(out['chatId'], data.get('MessageID'), None))
    elif raw == 'events.PushNameSetting':
        out['name'] = _text(action.get('name'), field='Action.name')
    elif raw == 'events.UnarchiveChatsSetting':
        out['unarchiveChats'] = _bool(action.get('unarchiveChats'), field='Action.unarchiveChats')
    else:
        out['chatId'] = _jid(data.get('JID'), field='JID')
        key = {'events.Pin': 'pinned', 'events.Mute': 'muted', 'events.MarkChatAsRead': 'read',
               'events.UserStatusMute': 'muted'}[raw]
        out[key] = _bool(action.get(key), field='Action.' + key)
        if raw == 'events.Mute':
            if 'muteEndTimestamp' in action:
                out['muteEndTimestampMs'] = _int(action['muteEndTimestamp'], minimum=-1, maximum=253402300799999, field='Action.muteEndTimestamp')
            if 'autoMuted' in action:
                out['autoMuted'] = _bool(action['autoMuted'], field='Action.autoMuted')


def _privacy(data, out):
    settings = _object(data.get('NewSettings'), field='NewSettings')
    out['settings'] = {key: _enum(settings[key], _PRIVACY_VALUES, field='NewSettings') for key in _PRIVACY_FIELDS if key in settings}
    out['changed'] = [key for key in _PRIVACY_FIELDS if _bool(data.get(key+'Changed', False), field='PrivacyChanged')]


def _blocklist(data, out):
    out['action'] = _enum(data.get('Action'), ('', 'modify'), field='Action')
    changes = data.get('Changes')
    items, count = _items([] if changes is None else changes, field='Changes')
    out['changes'] = [{
        'chatId': _jid(_object(item, field='Changes').get('JID'), user=True, field='JID'),
        'action': _enum(item.get('Action'), ('block', 'unblock'), field='Action'),
    } for item in items]
    out.update(changeCount=count, truncated=count > len(items), requiresRefresh=out['action'] == 'modify')


def _channel(raw, data, out):
    out['chatId'] = _jid(data.get('JID' if raw == 'events.NewsletterLiveUpdate' else 'id'), channel=True)
    if raw == 'events.NewsletterLeave':
        out['role'] = _enum(data.get('role'), ('subscriber', 'guest', 'admin', 'owner', ''), field='role')
    elif raw == 'events.NewsletterMuteChange':
        out['muted'] = _enum(data.get('mute'), ('on', 'off'), field='mute') == 'on'
    elif raw == 'events.NewsletterJoin':
        if 'state' in data:
            out['state'] = _enum(_object(data['state'], field='state').get('type'), ('active', 'suspended', 'geosuspended'), field='state.type')
        thread = data.get('thread_metadata')
        if thread is not None:
            thread = _object(thread, field='thread_metadata')
            for key in ('name', 'description'):
                if key in thread:
                    out[key] = _text(_object(thread[key], field='thread_metadata').get('text'), 4000, field='thread_metadata.text')
    else:
        out['eventAt'] = _timestamp(data.get('Time'), field='Time')
        items, count = _items(data.get('Messages'), field='Messages')
        messages = []
        for item in items:
            item = _object(item, field='Messages')
            message = {'serverId': _int(item.get('MessageServerID'), field='MessageServerID'), 'views': _int(item.get('ViewsCount', 0), field='ViewsCount')}
            if item.get('MessageID'):
                message['rawMessageId'] = _raw_id(item['MessageID'], field='MessageID')
            if item.get('Type'):
                message['type'] = _text(item['Type'], 64, field='Type')
            # Zero Go timestamps mean absent. No content, URLs or opaque nodes.
            if item.get('Timestamp') is not None:
                stamp = item['Timestamp']
                if stamp != '0001-01-01T00:00:00Z':
                    message['eventAt'] = _timestamp(stamp)
            counts = item.get('ReactionCounts')
            if counts is not None:
                counts = _object(counts, field='ReactionCounts')
                if len(counts) > 100:
                    _invalid('out_of_range', 'ReactionCounts')
                message['reactionCounts'] = {_text(key, 64, field='ReactionCounts.key'): _int(value, field='ReactionCounts.value') for key, value in counts.items()}
            messages.append(message)
        out.update(messages=messages, messageCount=count, truncated=count > len(items))


def _self_receipt(data, out):
    """Observe another own device; this neither sends receipts nor asserts ACK."""
    out['chatId'] = _jid(data.get('Chat'), field='Chat')
    out['eventAt'] = _timestamp(data.get('Timestamp'), field='Timestamp')
    out['receiptType'] = _enum(data.get('Type'), ('read-self', 'played-self'), field='Type')
    out['receiptFromMe'] = _bool(data.get('IsFromMe'), field='IsFromMe')
    if data.get('Sender'):
        out['actorId'] = _jid(data['Sender'], user=True, field='Sender')
    participant = data.get('MessageSender')
    if participant not in (None, ''):
        participant = _jid(participant, user=True, field='MessageSender')
    # Same owner-relative inversion as WAHA receiptToMessageAck, with group
    # author mandatory. A batch never receives a misleading singular id/ACK.
    items, count = _items(data.get('MessageIDs'), field='MessageIDs')
    if not count:
        _invalid('missing', 'MessageIDs')
    out.update(messages=[_message_reference(out['chatId'], raw, not out['receiptFromMe'], participant)
                         for raw in items], messageCount=count, truncated=count > len(items))


def _group_metadata(data, out):
    chat = _jid(data.get('JID'), field='JID')
    if not _CHAT.fullmatch(chat):
        _invalid('invalid_value', 'JID')
    out.update(chatId=chat, eventAt=_timestamp(data.get('Timestamp'), field='Timestamp'))
    changes = {}
    if data.get('Locked') is not None:
        changes['locked'] = _bool(_object(data['Locked'], field='Locked').get('IsLocked'), field='Locked.IsLocked')
    if data.get('Ephemeral') is not None:
        value = _object(data['Ephemeral'], field='Ephemeral')
        changes['ephemeral'] = {'enabled': _bool(value.get('IsEphemeral'), field='Ephemeral.IsEphemeral'),
                                'seconds': _int(value.get('DisappearingTimer'), maximum=2**32-1, field='Ephemeral.DisappearingTimer')}
    if data.get('Delete') is not None:
        value = _object(data['Delete'], field='Delete')
        changes['delete'] = {'deleted': _bool(value.get('Deleted'), field='Delete.Deleted'),
                             'reason': _text(value.get('DeleteReason'), 128, field='Delete.DeleteReason')}
    for field in ('Link', 'Unlink'):
        if data.get(field) is None:
            continue
        value = _object(data[field], field=field)
        target = _jid(_object(value.get('Group'), field='Group').get('JID'), field='Group.JID')
        if not _CHAT.fullmatch(target):
            _invalid('invalid_value', 'Group.JID')
        changes[field.lower()] = {'groupId': target,
            'type': _enum(value.get('Type'), ('parent_group', 'sub_group', 'sibling_group'), field='Type'),
            'reason': _enum(value.get('UnlinkReason', ''), ('', 'unlink_group', 'delete_parent'), field='UnlinkReason')}
    suspended = _bool(data.get('Suspended', False), field='Suspended')
    unsuspended = _bool(data.get('Unsuspended', False), field='Unsuspended')
    if suspended and unsuspended:
        _invalid('inconsistent', 'Suspended')
    if suspended or unsuspended:
        changes['suspended'] = suspended
    out['changes'] = changes


def _call_terminated(data, out):
    out['callId'] = _raw_id(data.get('CallID'), field='CallID')
    out['reason'] = _text(data.get('Reason'), 128, field='Reason')
    out['from'] = _jid(data.get('From'), field='From')
    node = data.get('Data')
    attrs = node.get('Attrs') if isinstance(node, dict) else None
    attrs = attrs if isinstance(attrs, dict) else {}
    candidates = [value for value in (data.get('GroupJID'), attrs.get('group-jid')) if value not in (None, '')]
    if out['from'].endswith('@g.us'):
        candidates.append(out['from'])
    is_group = bool(candidates) or attrs.get('type') == 'group'
    out['isGroup'] = is_group
    if not is_group:
        out['chatId'] = out['from']
        return
    # The provider exposes group membership via either BasicCallMeta.GroupJID
    # or the typed call node's group-jid attribute. The caller's phone is not
    # the conversation of a group call. Conflicting/missing group identities
    # stay account-scoped instead of being routed to the caller's DM.
    valid = [value for value in candidates if isinstance(value, str) and _CHAT.fullmatch(value)]
    proven = bool(valid) and len(valid) == len(candidates) and len(set(valid)) == 1
    out['chatId'] = valid[0] if proven else None
    out['groupIdentity'] = 'complete' if proven else 'unknown'


def decode_provider_event(envelope):
    """Ignore unlisted events; reject malformed allowlisted events without echoing data."""
    if not isinstance(envelope, dict) or envelope.get('event') != 'engine.event' or envelope.get('engine') != 'GOWS':
        return None
    payload = envelope.get('payload')
    if not isinstance(payload, dict) or not isinstance(payload.get('event'), str) or payload['event'] not in _EVENTS:
        return None
    if 'session' in payload and payload['session'] != envelope.get('session'):
        _invalid('inconsistent', 'session')
    raw, data = payload['event'], _object(payload.get('data'), field='data')
    # Already-covered public event variants remain ignored in the raw path.
    if raw == 'events.Receipt' and data.get('Type') not in ('read-self', 'played-self'):
        return None
    if raw == 'events.GroupInfo' and not (
        any(data.get(key) is not None for key in ('Locked', 'Ephemeral', 'Delete', 'Link', 'Unlink'))
        or data.get('Suspended') is True or data.get('Unsuspended') is True
    ):
        return None
    out = {'chatId': None, 'source': 'gows_provider_event', 'providerEvent': raw,
           'fromFullSync': _bool(data.get('FromFullSync', False), field='FromFullSync')}
    if raw in _APPSTATE or raw in ('events.Picture', 'events.UserAbout', 'events.IdentityChange', 'events.CallTerminate'):
        out['eventAt'] = _timestamp(data.get('Timestamp'), field='Timestamp')
    if raw in _APPSTATE:
        _appstate(raw, data, out)
    elif raw in ('events.PushName', 'events.BusinessName'):
        out['chatId'] = _jid(data.get('JID'), user=True, field='JID')
        prefix = 'PushName' if raw == 'events.PushName' else 'BusinessName'
        out.update(previousName=_text(data.get('Old'+prefix), field='Old'+prefix), name=_text(data.get('New'+prefix), field='New'+prefix))
    elif raw == 'events.Picture':
        out['chatId'] = _jid(data.get('JID'), field='JID')
        out['removed'] = _bool(data.get('Remove'), field='Remove')
        if data.get('Author'):
            out['authorId'] = _jid(data['Author'], user=True, field='Author')
        if data.get('PictureID'):
            out['pictureId'] = _raw_id(data['PictureID'], field='PictureID')
    elif raw == 'events.UserAbout':
        out.update(chatId=_jid(data.get('JID'), user=True, field='JID'), about=_text(data.get('Status'), 4000, field='Status'))
    elif raw == 'events.IdentityChange':
        out.update(chatId=_jid(data.get('JID'), user=True, field='JID'), implicit=_bool(data.get('Implicit'), field='Implicit'))
    elif raw == 'events.PrivacySettings':
        _privacy(data, out)
    elif raw == 'events.Blocklist':
        _blocklist(data, out)
    elif raw.startswith('events.Newsletter'):
        _channel(raw, data, out)
    elif raw == 'events.UndecryptableMessage':
        info = _object(data.get('Info'), field='Info')
        out['chatId'] = _jid(info.get('Chat'), field='Chat')
        out['eventAt'] = _timestamp(info.get('Timestamp'), field='Timestamp')
        if _bool(info.get('IsGroup'), field='IsGroup') != out['chatId'].endswith('@g.us'):
            _invalid('inconsistent', 'IsGroup')
        out.update(_message_reference(out['chatId'], info.get('ID'), _bool(info.get('IsFromMe'), field='IsFromMe'), info.get('Sender')))
        out.update(unavailable=_bool(data.get('IsUnavailable'), field='IsUnavailable'),
                   unavailableType=_enum(data.get('UnavailableType', ''), ('', 'view_once'), field='UnavailableType'),
                   decryptFailMode=_enum(data.get('DecryptFailMode', ''), ('', 'hide'), field='DecryptFailMode'),
                   contentAvailable=False)
    elif raw == 'events.NotifyAccountReachoutTimelock':
        # False/empty values are omitted by encoding/json, unlike protobuf bool pointers.
        out['active'] = _bool(data.get('is_active', False), field='is_active')
        if 'enforcement_type' in data:
            out['enforcementType'] = _text(data['enforcement_type'], 64, field='enforcement_type')
        if 'time_enforcement_ends' in data:
            out['endsAt'] = _epoch(data['time_enforcement_ends'], field='time_enforcement_ends')
    elif raw == 'gows.MessageCapping':
        out['totalQuota'] = _int(data.get('total_quota'), minimum=-1, field='total_quota')
        out['usedQuota'] = _int(data.get('used_quota'), field='used_quota')
        for name in ('capping_status', 'mv_status', 'ote_status'):
            if name in data:
                out[name] = _text(data[name], 64, field=name)
        for name in ('cycle_start_timestamp', 'cycle_end_timestamp', 'server_sent_timestamp'):
            if name in data:
                out[name] = _epoch(data[name], field=name)
    elif raw == 'events.CallTerminate':
        _call_terminated(data, out)
    elif raw == 'events.Receipt':
        _self_receipt(data, out)
    elif raw == 'events.GroupInfo':
        _group_metadata(data, out)
    event = _EVENTS[raw]
    if raw == 'events.LabelAssociationMessage' and not out['labeled']:
        event = 'label.message.deleted'
    return {'event': event, 'payload': out, 'exclusions': []}
