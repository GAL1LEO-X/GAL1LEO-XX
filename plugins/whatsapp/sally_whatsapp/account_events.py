"""Stable application events; engine internals and authentication material are excluded."""
import math
import re
from .provider_events import NORMALIZED_EVENT_TYPES
from .chat_identity import normalize_chat_id
STATE_EVENT_TYPES = ('chat.deleted', 'chat.cleared', 'message.deleted_for_me', 'chat.archived')
EVENT_TYPES=(
    'session.status','message.reaction','message.ack','message.ack.group','message.edited','message.revoked',
    'group.v2.join','group.v2.leave','group.v2.update','group.v2.participants','group.v2.participants.join-request',
    'presence.update','poll.vote','poll.vote.failed','call.received','call.accepted','call.rejected',
    'label.upsert','label.deleted','label.chat.added','label.chat.deleted','event.response','event.response.failed',
)
GENERATED_EVENT_TYPES = ('message.sent',)
APPLICATION_EVENT_TYPES = EVENT_TYPES + STATE_EVENT_TYPES + NORMALIZED_EVENT_TYPES + GENERATED_EVENT_TYPES
# Internal normalized events are not names accepted by WAHA. The GOWS
# app-state feed must be requested explicitly; WAHA excludes it from '*'.
PROVIDER_EVENT_TYPES = EVENT_TYPES + ('engine.event',)
MULTI_SOURCE_EVENTS = ('poll.vote', 'poll.vote.failed', 'event.response', 'event.response.failed')
STATE_NOTIFICATIONS = ('message.revoked', 'message.unavailable', 'message.starred', *STATE_EVENT_TYPES)


def source_message(event, payload):
    """Identify a message derivative without guessing from arbitrary user text."""
    if event == 'message.revoked':
        before=payload.get('before') if isinstance(payload.get('before'),dict) else {}
        values=(payload.get('revokedMessageId'),before.get('id'))
    elif event == 'message.edited':
        raw=payload.get('editedMessageId')
        notice=payload.get('id')
        # GOWS reports the target ID raw, while id identifies the edit notice.
        # Use the notice's owner-relative chat/direction and group participant;
        # protocolMessage.key.fromMe is relative to the sender, not the owner.
        if isinstance(raw,str) and re.fullmatch(r'[A-Za-z0-9.:-]{1,200}',raw) and isinstance(notice,str):
            parts=notice.split('_',2)
            direction=payload.get('fromMe')
            chat=message_chat(payload)
            if (type(direction) is bool and len(parts)==3 and parts[0]==str(direction).lower()
                    and normalize_chat_id(parts[1])==normalize_chat_id(chat)):
                suffix=''
                if chat.endswith('@g.us'):
                    participant=payload.get('participant')
                    if isinstance(participant,str) and re.fullmatch(r'[0-9]{5,25}@(c\.us|lid)',participant):
                        suffix='_'+participant
                    else:
                        return raw
                return parts[0]+'_'+chat+'_'+raw+suffix
        values=(payload.get('editedMessageId'),payload.get('id'))
    elif event == 'message.reaction':
        # WAHA identifies the reaction itself in payload.id. Only the typed
        # nested messageId identifies its target; never infer it from text or
        # fall back to the reaction's ID when the target is missing/malformed.
        reaction=payload.get('reaction') if isinstance(payload,dict) else None
        values=(reaction.get('messageId'),) if isinstance(reaction,dict) else ()
    elif event in ('poll.vote', 'poll.vote.failed'):
        target=payload.get('poll')
        values=(target.get('id'),) if isinstance(target,dict) else ()
    elif event in ('event.response', 'event.response.failed'):
        target=payload.get('eventCreationKey')
        values=(target.get('id'),) if isinstance(target,dict) else ()
    elif event.startswith('message.'):
        values=(payload.get('id'),)
    else:
        values=()
    return next((value for value in values if isinstance(value,str) and value),None)


def event_references(event, payload, chat_id=None):
    """Typed source roles from the pinned WAHA contract; never scan free text.

    A malformed/missing target is distinct from an event with no dependency.
    Original provider IDs are retained; the store binds verified aliases only.
    Reaction semantics deliberately remain target-only for compatibility.
    """
    payload=payload if isinstance(payload,dict) else {}
    candidates=[]
    if event in ('poll.vote','poll.vote.failed'):
        for role,name in (('target','poll'),('self','vote')):
            part=payload.get(name)
            candidates.append((role,part.get('id') if isinstance(part,dict) else None,part))
    elif event in ('event.response','event.response.failed'):
        part=payload.get('eventCreationKey')
        candidates=[('target',part.get('id') if isinstance(part,dict) else None,part),
                    ('self',payload.get('id'),payload)]
    else:
        source=source_message(event,payload)
        if source: candidates=[('target',source,payload)]
    if event == 'message.edited':
        # Match the bounded Message.replyTo projection. Quote dependencies are
        # independent of the edit target: revoking one removes only that quote.
        quote=payload.get('replyTo')
        context=event_chat(payload) or chat_id
        for depth in range(9):
            if not isinstance(quote,dict): break
            context=message_chat(quote) or context
            candidates.append(('quote:'+str(depth),quote.get('id'),{**quote,'chatId':context}))
            quote=quote.get('replyTo')
    references=[]
    for role,identifier,part in candidates:
        valid=isinstance(identifier,str) and 0<len(identifier)<=512 and not any(ord(c)<33 for c in identifier)
        parsed=identifier.split('_',2) if valid else []
        serialized=len(parsed)==3 and parsed[0] in ('true','false') and '@' in parsed[1]
        context=(normalize_chat_id(parsed[1]) if serialized
                 else (event_chat(part) if isinstance(part,dict) else None) or chat_id)
        direction=parsed[0]=='true' if serialized else part.get('fromMe') if isinstance(part,dict) and type(part.get('fromMe')) is bool else None
        # Raw references require a verified conversation; an equal raw token
        # in an unrelated conversation is not an identity.
        resolved=valid and (serialized or isinstance(context,str) and '@' in context)
        # Legacy unscoped message sources retain their existing exact-ID rule.
        if event not in MULTI_SOURCE_EVENTS and not role.startswith('quote:'): resolved=valid
        raw=parsed[2] if serialized else identifier if valid else None
        if serialized and parsed[1].endswith('@g.us') and '_' in raw:
            first,participant=raw.rsplit('_',1)
            if re.fullmatch(r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)',participant): raw=first
        references.append({'role':role,'message_id':identifier if valid else None,'chat_id':context,
                           'raw_id':raw,'from_me':direction,'resolution':'resolved' if resolved else 'unresolved'})
    return references


def safe_data(value):
    if isinstance(value,list): return [safe_data(v) for v in value]
    if isinstance(value,dict):
        return {k:safe_data(v) for k,v in value.items() if not k.startswith('_') and k.lower() not in
                ('apikey','api_key','password','token','secret','credentials','mediakey','directpath','fileencsha256','mediaurl')
                and not (k=='url' and ('mimetype' in value or 'filename' in value))}
    return value


def message_chat(payload):
    if payload.get('fromMe') is not True: return payload.get('from')
    destination=payload.get('to')
    # GOWS puts the remote chat in from, with to=null for direct messages or
    # to=the sender for groups. Other engines put the remote chat in to.
    # The serialized ID resolves these variants only when a payload field agrees.
    identifier=payload.get('id')
    source=payload.get('from')
    if isinstance(identifier,str) and identifier.startswith('true_'):
        parts=identifier.split('_',2)
        if len(parts)==3 and '@' in parts[1]:
            return parts[1] if normalize_chat_id(parts[1]) in (normalize_chat_id(source),normalize_chat_id(destination)) else None
    return destination


def message_content(payload):
    """Preserve bounded user-visible non-text content, excluding thumbnails/internal blobs."""
    content={}
    location=payload.get('location')
    if isinstance(location,dict):
        try:
            latitude,longitude=float(location['latitude']),float(location['longitude'])
            if not math.isfinite(latitude) or not math.isfinite(longitude) or not -90<=latitude<=90 or not -180<=longitude<=180:
                raise ValueError('Invalid coordinates')
            content['location']={'latitude':latitude,'longitude':longitude,'live':location.get('live') is True}
            for key in ('name','address'):
                if isinstance(location.get(key),str): content['location'][key]=location[key][:2000]
        except (KeyError,TypeError,ValueError):
            content['content_truncated']=True
    cards=payload.get('vCards')
    if isinstance(cards,list) and cards:
        accepted=[];size=0
        for card in cards:
            if not isinstance(card,str) or len(card)>32768 or size+len(card)>131072 or len(accepted)>=50:
                content['content_truncated']=True
                continue
            accepted.append(card);size+=len(card)
        if accepted: content['vCards']=accepted
    return content


def event_chat(payload, event=None):
    if event in NORMALIZED_EVENT_TYPES:
        # The typed decoder has already attributed this conversation. Its
        # explicit null is meaningful: a caller/author is not a fallback chat.
        return payload.get('chatId') if isinstance(payload.get('chatId'),str) else None
    # WAHAChatPresences.id is the conversation, unlike label/call/message IDs.
    # Accept this provider field only for its typed event, never generically.
    if event == 'presence.update':
        identifier=payload.get('id')
        if isinstance(identifier,str) and re.fullmatch(r'[0-9]{1,25}(?:-[0-9]{1,25})?@(c\.us|s\.whatsapp\.net|lid|g\.us)',identifier):
            return normalize_chat_id(identifier)
    if event in ('call.received','call.accepted','call.rejected'):
        raw=payload.get('_data')
        raw=raw if isinstance(raw,dict) else {}
        node=raw.get('Data')
        attrs=node.get('Attrs') if isinstance(node,dict) else None
        attrs=attrs if isinstance(attrs,dict) else {}
        groups=[value for value in (raw.get('GroupJID'),attrs.get('group-jid')) if value]
        if payload.get('isGroup') is True or groups or attrs.get('type')=='group':
            if payload.get('isGroup') is not True: return None
            if isinstance(payload.get('from'),str) and payload['from'].endswith('@g.us'):
                groups.append(payload['from'])
            if not groups or any(not isinstance(value,str) or not re.fullmatch(r'[0-9]{1,25}(?:-[0-9]{1,25})?@g\.us',value) for value in groups):
                return None
            # Public CallData.from is often the caller, not the group. Only
            # the two attested typed provider fields can attribute that chat.
            return groups[0] if len(set(groups))==1 else None
    group=payload.get('group')
    if isinstance(group,dict) and isinstance(group.get('id'),str): return group['id']
    if isinstance(group,str): return group
    if isinstance(payload.get('chatId'),str): return payload['chatId']
    for nested in ('vote','poll','before','after'):
        if isinstance(payload.get(nested),dict):
            value=event_chat(payload[nested])
            if value: return value
    value=message_chat(payload)
    if isinstance(value,str) and '@' in value: return value
    identifier=payload.get('revokedMessageId') or payload.get('editedMessageId') or payload.get('id')
    if isinstance(identifier,str):
        pieces=identifier.split('_')
        if len(pieces)>2 and '@' in pieces[1]: return pieces[1]
    return None
