"""Content-free lifetime evidence from the pinned GOWS message representation.

Missing metadata is legacy/unknown, never proof that an observed lifetime ended.
The original message timestamp starts its timer; the settings timestamp does not.
"""
import math
import re
import time

BLOCKED = frozenset({'view_once', 'expired', 'lifetime_unknown'})
MAX_TIMESTAMP = 253402300799


def _number(value):
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 12:
        value = int(value)
    return value if type(value) is int or type(value) is float and math.isfinite(value) else None


def context_lifetime(context):
    """Return durations, temporary indications and invalidity for one context.

    A zero timer applies only to this context. Its settings may still describe
    an earlier chat configuration; they do not activate a message timer.
    Positive or malformed durations in the same context remain authoritative.
    """
    durations = []
    zero = False
    uncertain = False
    settings = False
    for field, value in context.items():
        field = field.replace('_', '').lower()
        if field == 'expiration' and value is not None:
            duration = _number(value)
            if duration is None or not 0 <= duration <= 4294967295 or duration != int(duration):
                uncertain = True
            elif duration == 0:
                zero = True
            else:
                durations.append(duration)
        elif field == 'ephemeralsettingtimestamp' and _number(value) == 0:
            continue
        elif field in ('ephemeralsettingtimestamp', 'ephemeralsharedsecret', 'disappearingmode'):
            if value is not None and value != 0:
                settings = True
    return durations, bool(durations) or (settings and not zero), uncertain


def metadata(payload):
    if not isinstance(payload, dict):
        return None
    if payload.get('content_state') in BLOCKED:
        return {'kind': 'view_once' if payload['content_state'] == 'view_once' else
                'ephemeral' if payload['content_state'] == 'expired' else 'unknown',
                **({'expires_at': 0} if payload['content_state'] == 'expired' else {})}
    normalized = _number(payload.get('content_expires_at'))
    projected = ({'kind': 'ephemeral', 'expires_at': normalized}
                 if normalized is not None and 0 <= normalized <= MAX_TIMESTAMP else None)
    raw = payload.get('_data')
    if not isinstance(raw, dict):
        return projected
    once = False
    temporary = False
    uncertain = False
    durations = []
    for flag in ('IsViewOnce', 'IsViewOnceV2', 'IsViewOnceV2Extension', 'IsEphemeral'):
        value = raw.get(flag)
        if value is True:
            if flag == 'IsEphemeral': temporary = True
            else: once = True
        elif value is not None and value is not False:
            uncertain = True

    def content(value, depth=0):
        nonlocal once, temporary, uncertain
        if not isinstance(value, dict):
            return
        if depth > 8:
            uncertain = True
            return
        for key, item in value.items():
            name = key.replace('_', '').lower()
            if name in ('viewoncemessage', 'viewoncemessagev2', 'viewoncemessagev2extension') and item is not None:
                once = True
            if name == 'viewonce' and item is not None and item is not False:
                if item is True: once = True
                else: uncertain = True
            if name == 'ephemeralmessage' and item is not None:
                temporary = True
            if name == 'contextinfo':
                if not isinstance(item, dict):
                    if item is not None: uncertain = True
                    continue
                found, indicated, invalid = context_lifetime(item)
                durations.extend(found)
                temporary = temporary or indicated
                uncertain = uncertain or invalid
                # Quotes have their own lifetimes; they do not date this source.
                continue
            if isinstance(item, dict):
                content(item, depth + 1)

    content(raw.get('Message'))
    content(raw.get('RawMessage'))
    if 'Message' not in raw and 'RawMessage' not in raw:
        # WAHA replyTo._data is the quoted protobuf content, not an event.
        content(raw)
    if once:
        return {'kind': 'view_once'}
    if uncertain:
        return {'kind': 'unknown'}
    if not temporary:
        return projected
    timestamp = _number(payload.get('timestamp'))
    if not durations or timestamp is None or not 0 <= timestamp <= MAX_TIMESTAMP:
        return {'kind': 'unknown'}
    expires = timestamp + min(durations)
    if projected is not None:
        expires = min(expires, projected['expires_at'])
    return {'kind': 'ephemeral', 'expires_at': expires} if expires <= MAX_TIMESTAMP else {'kind': 'unknown'}


def state(value, now=None):
    if value is None:
        return 'unknown'
    if value.get('kind') == 'view_once':
        return 'view_once'
    if value.get('kind') != 'ephemeral':
        return 'lifetime_unknown'
    expires = _number(value.get('expires_at'))
    if expires is None:
        return 'lifetime_unknown'
    return 'expired' if expires <= (time.time() if now is None else now) else 'unknown'


def project(payload):
    """Project before stripping private provider metadata; never expose that blob."""
    evidence = metadata(payload)
    status = state(evidence)
    if status in BLOCKED:
        identity={'id':payload['id']} if isinstance(payload.get('id'),str) else {}
        participant=payload.get('participant')
        if isinstance(participant,str) and re.fullmatch(r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)',participant):
            identity['participant']=participant
        if type(payload.get('fromMe')) is bool: identity['fromMe']=payload['fromMe']
        return {**identity,'content_state':status}
    if evidence and evidence.get('kind') == 'ephemeral':
        return {**payload, 'content_expires_at': evidence['expires_at']}
    return payload


def project_tree(value, depth=0):
    if depth > 12:
        return {'content_state':'lifetime_unknown'}
    if isinstance(value, list):
        return [project_tree(item, depth+1) for item in value]
    if isinstance(value, dict):
        value=project(value)
        return {key:project_tree(item, depth+1) for key,item in value.items() if not key.startswith('_')}
    return value
