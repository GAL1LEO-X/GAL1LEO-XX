"""Finite diagnostic codes for rejected events; never retain a rejected value."""
from functools import wraps


VALIDATION_REASONS = frozenset(('invalid_type', 'invalid_value', 'out_of_range',
                               'missing', 'inconsistent'))
# Names describe schema locations, never map keys supplied by an account.
VALIDATION_FIELDS = frozenset('''
data session state Locked Ephemeral Delete Group Link Unlink JID ChatJID Chat From Sender SenderJID Author GroupJID
Timestamp Time eventAt FromFullSync Action Action.pinned Action.muted Action.read
Action.starred Action.labeled Action.name Action.unarchiveChats Action.autoMuted
Action.muteEndTimestamp MessageID MessageIDs ID IsFromMe MessageSender
LabelID OldPushName NewPushName OldBusinessName NewBusinessName Remove PictureID
Status Implicit NewSettings PrivacyChanged Changes role mute state.type
thread_metadata thread_metadata.text Messages MessageServerID ViewsCount Type
ReactionCounts ReactionCounts.value ReactionCounts.key
Locked.IsLocked Ephemeral.IsEphemeral Ephemeral.DisappearingTimer
Delete.Deleted Delete.DeleteReason Group.JID Link.Type UnlinkReason Suspended
Unsuspended CallID Reason Info IsGroup IsUnavailable UnavailableType
DecryptFailMode is_active enforcement_type time_enforcement_ends total_quota
used_quota capping_status mv_status ote_status cycle_start_timestamp
cycle_end_timestamp server_sent_timestamp
Action.messageRange lastMessageTimestamp lastSystemMessageTimestamp
Action.messageRange.messages Action.messageRange.messages.key remoteJID
participant fromMe archived DeleteMedia deleteMedia messageTimestamp timestamp
'''.split())


class EventValidationError(ValueError):
    def __init__(self, message, *, reason='invalid_value', field=None):
        super().__init__(message)
        self.reason = reason if reason in VALIDATION_REASONS else 'invalid_value'
        self.field = field if field in VALIDATION_FIELDS else None


def checked_field(default):
    """Attach a fixed field name without changing a validator's accepted inputs."""
    def decorate(check):
        @wraps(check)
        def checked(*args, field=None, **kwargs):
            try:
                return check(*args, **kwargs)
            except EventValidationError as exc:
                if field is not None or exc.field is None:
                    candidate = field if field is not None else default
                    exc.field = candidate if candidate in VALIDATION_FIELDS else 'data'
                raise
        return checked
    return decorate


# Versioned receiver/sender handshake. Unknown failures deliberately lack it.
REJECTION_CONTRACT = 'gal1leo.webhook-rejection.v1'
PERMANENT_EVENT_CODES = frozenset((
    'EVENT_JSON', 'EVENT_ENVELOPE', 'EVENT_UNSUPPORTED', 'EVENT_ID',
    'MESSAGE_ID_DIRECTION', 'MESSAGE_CHAT_TIME', 'MESSAGE_BODY', 'MESSAGE_MEDIA',
    'SESSION_STATUS', 'MESSAGE_EDIT', 'EVENT_ENGINE_VALIDATION',
))
