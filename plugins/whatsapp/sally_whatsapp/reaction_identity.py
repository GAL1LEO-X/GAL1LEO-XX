"""Normalize the known GOWS private-chat reaction key at acquisition.

Whatsmeow BuildReaction uses the reacting sender's BuildMessageKey. GOWS
serializes that key without changing perspective. For incoming private events,
the target chat must be the authenticated envelope's own PN/LID, while the
event identifies the peer. This proof does not apply to group participants,
other engines, old rows lacking envelope identity, or already normalized keys.
"""
import re

from .visibility import message_identity


def private_address(value):
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r'([0-9]{5,25})(?::[0-9]+)?@(c\.us|s\.whatsapp\.net|lid)', value)
    if match is None:
        return None
    return match[1] + ('@lid' if match[2] == 'lid' else '@c.us')


def private_reaction_target(payload, me):
    """Return a full local key only when the remote perspective is proved.

    ``me`` must come from this event's trusted provider envelope, or from an
    explicitly reviewed offline archive repair. Never discover it by matching
    short stanza IDs, display names, contact lists, or the first archive hit.
    """
    if not isinstance(payload, dict) or not isinstance(me, dict):
        return None
    if payload.get('fromMe') is not False or payload.get('participant') not in (None, ''):
        return None
    own = {address for field in ('id', 'lid') if (address := private_address(me.get(field)))}
    peer = private_address(payload.get('from'))
    notice = message_identity(payload.get('id'))
    reaction = payload.get('reaction')
    target = message_identity(reaction.get('messageId')) if isinstance(reaction, dict) else None
    if (not own or not peer or peer in own or not notice or notice[1]
            or private_address(notice[0]) != peer or not target
            or private_address(target[0]) not in own
            or not re.fullmatch(r'[A-Za-z0-9.:-]{1,200}', target[2])):
        return None
    recipient = payload.get('to')
    if recipient not in (None, '') and private_address(recipient) not in own:
        return None
    return str(not target[1]).lower() + '_' + peer + '_' + target[2]


def normalize_envelope(envelope):
    if envelope.get('event') != 'message.reaction' or envelope.get('engine') != 'GOWS':
        return envelope
    payload = envelope.get('payload')
    target = private_reaction_target(payload, envelope.get('me'))
    if target is None:
        return envelope
    return {**envelope, 'payload': {**payload,
            'reaction': {**payload['reaction'], 'messageId': target}}}
