"""Verify A/B metadata targets without importing or reproducing their content."""
import math
import re
from urllib.parse import quote

from . import lifetime, visibility
from .forwarding import _identity_matches, source_state

_CONTACT = re.compile(r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)')
_GROUP = re.compile(r'[0-9]{5,25}(?:-[0-9]{1,20})?@g\.us')
_STANZA = re.compile(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,199}')
_NAMES = frozenset({'chats_pin_message', 'chats_unpin_message', 'messages_set_star'})
_FLAGS = ('IsViewOnce', 'IsViewOnceV2', 'IsViewOnceV2Extension', 'IsEphemeral')


def metadata_only(name, args):
    """Only removal of pin/star metadata can bypass source-content reads."""
    return (name == 'chats_unpin_message' or name == 'messages_set_star'
            and isinstance(args, dict) and isinstance(args.get('body'), dict)
            and args['body'].get('star') is False)


def _chat(value):
    if not isinstance(value, str) or not (_CONTACT.fullmatch(value) or _GROUP.fullmatch(value)):
        raise ValueError('Message target requires a complete provider identity')
    return value.replace('@s.whatsapp.net', '@c.us')


def _key(identifier):
    identity = visibility.message_identity(identifier)
    if identity is None or len(identifier) > 512:
        raise ValueError('Message target requires a complete provider identity')
    parts = identifier.split('_')
    chat = _chat(identity[0])
    group = chat.endswith('@g.us')
    if len(parts) != (4 if group else 3) or not _STANZA.fullmatch(parts[2]):
        raise ValueError('Message target requires a complete provider identity and participant')
    participant = _chat(parts[3]) if group else None
    if participant is not None and not _CONTACT.fullmatch(participant):
        raise ValueError('Message target participant must identify a contact')
    return (chat, identity[1], identity[2]), participant


def _target(store, db, name, args):
    if name not in _NAMES or not isinstance(args, dict):
        raise ValueError('Unsupported message metadata operation')
    values = args.get('body') if name == 'messages_set_star' else args.get('path')
    if not isinstance(values, dict):
        raise ValueError('Message target requires a complete provider identity')
    identifier = values.get('messageId')
    identity, participant = _key(identifier)
    target_chat = _chat(values.get('chatId'))
    if store._canonical_chat(db, target_chat) != store._canonical_chat(db, identity[0]):
        raise ValueError('Message target chat does not match its provider identity')
    return identifier, identity, participant


def _available(store, db, identifier, identity, timestamp=None, *, defer_time=False):
    state = source_state(lambda target, **context: store._message_state(db, target, **context),
        identifier, chat_id=identity[0], timestamp=timestamp, defer_unknown_time=defer_time)
    if state['state'] != 'unknown' or state.get('clear_chat_coverage', {}).get('boundary_unknown'):
        raise ValueError('Message target is removed or its visibility cannot be established')


def _matches(store, db, identifier, identity, participant, observed):
    if not _identity_matches(store, db, identifier, identity, observed):
        raise ValueError('Message target identity could not be verified')
    _key(observed['id'])  # The legacy identity parser alone accepts partial group keys.
    if participant is not None and observed.get('participant') is not None:
        actual = _chat(observed['participant'])
        if store._canonical_chat(db, actual) != store._canonical_chat(db, participant):
            raise ValueError('Message target participant could not be verified')


def _fields(value):
    return {key.replace('_', '').lower(): item for key, item in value.items()} if isinstance(value, dict) else {}


def _removed(observed):
    if observed.get('revoked') is True or observed.get('deleted') is True or observed.get('unavailable') is True:
        return True
    raw = observed.get('_data')
    web = _fields(_fields(raw).get('sourcewebmsg'))
    revoke_value = web.get('revokemessagetimestamp')
    revoke_time = lifetime._number(revoke_value)
    if (web.get('messagestubtype') in (1, 'REVOKE')
            or revoke_value is not None and (revoke_time is None or revoke_time != 0)):
        return True

    def revoked(value, depth=0):
        if not isinstance(value, dict):
            return False
        if depth > 8:
            return True
        for name, item in _fields(value).items():
            if name == 'contextinfo':
                continue  # A quoted message does not determine this target's state.
            if name == 'protocolmessage' and isinstance(item, dict):
                if _fields(item).get('type', 0) in (0, 'REVOKE'):
                    return True
            if isinstance(item, dict) and revoked(item, depth + 1):
                return True
        return False

    return revoked(_fields(raw).get('message')) or revoked(_fields(raw).get('rawmessage'))


def _evidence(observed):
    evidence = lifetime.metadata(observed)
    # The event normally exposes ContextInfo. Retained WebMessageInfo can also
    # carry explicit expiry metadata; it may strengthen, never extend, a timer.
    web = _fields(_fields(observed.get('_data')).get('sourcewebmsg'))
    if not web.get('ephemeralduration'):
        return evidence
    duration = lifetime._number(web['ephemeralduration'])
    started = lifetime._number(web.get('ephemeralstarttimestamp', observed.get('timestamp')))
    if duration is None or not 0 < duration <= 4294967295 or started is None or not 0 <= started <= lifetime.MAX_TIMESTAMP:
        return {'kind': 'unknown'}
    expires = started + duration
    if expires > lifetime.MAX_TIMESTAMP:
        return {'kind': 'unknown'}
    if evidence and evidence.get('kind') in ('view_once', 'unknown'):
        return evidence
    if evidence and evidence.get('kind') == 'ephemeral':
        expires = min(expires, evidence['expires_at'])
    return {'kind': 'ephemeral', 'expires_at': expires}


def verify_target(store, gateway, settings, name, args):
    """One bounded live read for positive actions, no body reads for cleanup.

    The returned observation contains only identity/time/lifetime metadata for
    the caller's final dispatch check. Private provider content is never
    returned, logged or archived by this function.
    """
    removal = metadata_only(name, args)
    with store.db() as db, visibility.read_snapshot(db):
        identifier, identity, participant = _target(store, db, name, args)
        if not removal:
            _available(store, db, identifier, identity, defer_time=True)
    result = {'id': identifier, 'chat_id': identity[0], 'timestamp': None,
              'from_me': identity[1], 'participant': participant,
              'lifetime': None, 'metadata_only': removal}
    if removal:
        return result
    path = ('/api/' + quote(settings.session, safe='') + '/chats/' + quote(identity[0], safe='')
            + '/messages/' + quote(identifier, safe=''))
    try:
        observed = gateway.request('GET', path, params={'downloadMedia': 'false'}, timeout=15)
    except Exception:
        # Provider exception strings may contain private content. No write has
        # been invoked, so fail preflight without exposing that exception.
        raise ValueError('Message target could not be verified by the provider') from None
    with store.db() as db, visibility.read_snapshot(db):
        _target(store, db, name, args)
        _matches(store, db, identifier, identity, participant, observed)
    evidence = _evidence(observed)
    removed = _removed(observed)
    if removed:
        evidence = {'kind': 'unknown'}  # Retain unavailability, never a late body.
    store.observe_message_lifetime(identifier, identity[0], evidence,
        from_me=identity[1], participant=participant)
    raw = observed.get('_data')
    if (removed or not isinstance(raw, dict) or any(raw.get(flag) is not False for flag in _FLAGS[:-1])
            or type(raw.get('IsEphemeral')) is not bool or not isinstance(raw.get('Message'), dict)
            or not raw['Message'] or lifetime.state(evidence) in lifetime.BLOCKED
            or raw['IsEphemeral'] and not evidence):
        raise ValueError('Message target is removed, temporary or its lifetime cannot be verified')
    timestamp = observed.get('timestamp')
    if type(timestamp) not in (int, float) or not math.isfinite(timestamp) or not 0 <= timestamp <= lifetime.MAX_TIMESTAMP:
        raise ValueError('Message target time could not be verified')
    with store.db() as db, visibility.read_snapshot(db):
        _target(store, db, name, args)
        _matches(store, db, identifier, identity, participant, observed)
        _available(store, db, identifier, identity, timestamp)
    return {**result, 'timestamp': timestamp, 'lifetime': evidence}


def recheck_target(store, name, args, metadata):
    """Recheck the verified identity and ledger immediately before dispatch.

    This consumes only the content-free result of verify_target; it performs
    no provider request and does not read the acquired message body.
    """
    removal = metadata_only(name, args)
    with store.db() as db, visibility.read_snapshot(db):
        identifier, identity, participant = _target(store, db, name, args)
        if (not isinstance(metadata, dict) or metadata.get('id') != identifier
                or metadata.get('chat_id') != identity[0]
                or metadata.get('from_me') is not identity[1]
                or metadata.get('participant') != participant
                or metadata.get('metadata_only') is not removal):
            raise ValueError('Message target verification metadata does not match')
        if removal:
            return metadata
        timestamp = metadata.get('timestamp')
        if (type(timestamp) not in (int, float) or not math.isfinite(timestamp)
                or not 0 <= timestamp <= lifetime.MAX_TIMESTAMP
                or 'lifetime' not in metadata
                or metadata['lifetime'] is not None and not isinstance(metadata['lifetime'], dict)
                or lifetime.state(metadata['lifetime']) in lifetime.BLOCKED):
            raise ValueError('Message target time or lifetime can no longer be verified')
        _available(store, db, identifier, identity, timestamp)
    return metadata
