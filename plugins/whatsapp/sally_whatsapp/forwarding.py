"""Validate a forward source without importing it or trusting an unscoped raw ID."""
import json
import math

from . import lifetime, visibility
from .account_events import message_chat

_UNOBSERVED = object()
_MAX_TIMESTAMP = 253402300799


def _identity_matches(store,db,identifier,identity,observation):
    observed_id=observation.get('id') if isinstance(observation,dict) else None
    return (visibility.message_identity(observed_id) is not None
            and visibility.canonical_identifier(db,observed_id,store._canonical_chat)==
                visibility.canonical_identifier(db,identifier,store._canonical_chat)
            and store._canonical_chat(db,message_chat(observation))==store._canonical_chat(db,identity[0])
            and observation.get('fromMe') is identity[1]
            and store._identity_context_matches(db,observed_id,message_chat(observation),
                observation.get('fromMe'),observation.get('participant')))


def _temporary_content(content, depth=0):
    if not isinstance(content,dict) or depth>8:
        return True
    for key,value in content.items():
        name=key.replace('_','').lower()
        if name in ('ephemeralmessage','viewoncemessage','viewoncemessagev2','viewoncemessagev2extension') and value is not None:
            return True
        if name=='viewonce' and value is not False and value is not None:
            return True
        if name=='contextinfo':
            if value is None: continue
            if not isinstance(value,dict): return True
            _,temporary,uncertain=lifetime.context_lifetime(value)
            if temporary or uncertain: return True
            # GOWS drops this original context, including quoted messages. A
            # quoted temporary message does not make this source temporary.
            continue
        if isinstance(value,dict) and _temporary_content(value,depth+1):
            return True
    return False


def source_state(message_state, identifier, *, chat_id=None, timestamp=None, defer_unknown_time=False):
    state=message_state(identifier,chat_id=chat_id,timestamp=timestamp)
    if (defer_unknown_time and timestamp is None
            and state.get('source') in ('unknown_time_after_chat_deletion','provider_clear_incomplete')
            and not state.get('clear_chat_coverage',{}).get('boundary_unknown')):
        # Classify a timestamp-only exclusion without inventing an observation.
        # Stored timestamps, exact clear anchors and message tombstones still
        # win. Only the mandatory live preflight may establish the real time.
        later=message_state(identifier,chat_id=chat_id,timestamp=_MAX_TIMESTAMP)
        if later['state']=='unknown': return later
    return state


def require_source(store, identifier, observation=_UNOBSERVED):
    """Known removal wins; a live provider identity must match before dispatch.

    GOWS retrieves forward content by raw ID, ignoring its serialized chat. Its
    read endpoint exposes the stored identity, so verify that identity rather
    than requiring an archive import. This is not proof of complete phone state.
    """
    identity = visibility.message_identity(identifier)
    if (identity is None or len(identifier) > 512 or not identity[2]
            or len(identifier.split('_')) not in (3, 4)):
        raise ValueError('Forwarding requires the complete provider message ID, including its source chat')
    if observation is not _UNOBSERVED:
        with store.db() as db, visibility.read_snapshot(db):
            if not _identity_matches(store,db,identifier,identity,observation):
                raise ValueError('Forward source identity could not be verified')
        # Commit content-free restrictions before a validation error can roll
        # back this preflight. Later observations with missing metadata cannot
        # resurrect a lifetime-restricted source already seen by the bridge.
        observed_lifetime=lifetime.metadata(observation)
        store.observe_message_lifetime(identifier,identity[0],observed_lifetime,
            from_me=observation.get('fromMe'),participant=observation.get('participant'))
    with store.db() as db, visibility.read_snapshot(db):
        canonical = visibility.canonical_identifier(db, identifier, store._canonical_chat)
        timestamp = None
        if observation is not _UNOBSERVED:
            if not _identity_matches(store,db,identifier,identity,observation):
                raise ValueError('Forward source identity could not be verified')
            raw=observation.get('_data')
            flags=('IsViewOnce','IsViewOnceV2','IsViewOnceV2Extension','IsEphemeral')
            # GOWS forwards an already-unwrapped stored copy. These original
            # lifetime flags must be explicitly false, never silently stripped
            # by public_result or inferred from absent metadata.
            if (observed_lifetime is not None or not isinstance(raw,dict)
                    or any(raw.get(flag) is not False for flag in flags)):
                raise ValueError('Forward source is temporary or its lifetime cannot be verified')
            content=raw.get('Message')
            original=raw.get('RawMessage')
            if (not content or _temporary_content(content)
                    or original is not None and _temporary_content(original)):
                raise ValueError('Forward source is temporary or its lifetime cannot be verified')
            timestamp = observation.get('timestamp')
            if (type(timestamp) not in (int, float) or not math.isfinite(timestamp)
                    or not 0 <= timestamp <= 253402300799):
                raise ValueError('Forward source time could not be verified')
        state = source_state(lambda identifier,**context:store._message_state(db,identifier,**context),
            identifier,chat_id=identity[0],timestamp=timestamp,defer_unknown_time=observation is _UNOBSERVED)
        if (state['state'] != 'unknown'
                or state.get('clear_chat_coverage', {}).get('boundary_unknown')):
            raise ValueError('Forward source is removed or its visibility cannot be established')
        if observation is not _UNOBSERVED:
            # The pinned GOWS store does not establish replacement of every
            # original on edits. Never forward a known superseded body.
            edits=[]
            for row in db.execute("SELECT message_id,body,event_epoch FROM message_mutations WHERE kind='edited'"):
                if visibility.canonical_identifier(db,row['message_id'],store._canonical_chat)==canonical:
                    edits.append(row)
                elif (visibility.message_identity(row['message_id']) is None
                      and visibility.tuple_match(identifier,row['message_id'],None)):
                    context=db.execute('SELECT value FROM state WHERE key=?',
                        (visibility.CONTEXT+row['message_id'],)).fetchone()
                    if context and store._canonical_chat(db,json.loads(context[0]).get('chat_id'))==store._canonical_chat(db,identity[0]):
                        raise ValueError('Forward source has an ambiguous observed edit')
            if edits and observation.get('body') != max(edits, key=lambda row: row['event_epoch'])['body']:
                raise ValueError('Forward source differs from its latest observed edit')
    return identity[0]
