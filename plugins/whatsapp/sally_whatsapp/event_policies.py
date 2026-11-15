"""Bounded mechanical notification policies. Never evaluate message instructions."""
from datetime import datetime, timezone
import math
import re
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .account_events import APPLICATION_EVENT_TYPES as EVENT_TYPES

PersonId = Annotated[str, Field(pattern=r'^[0-9]{5,25}@(c\.us|lid)$', max_length=32)]
LiteralText = Annotated[str, Field(min_length=1, max_length=200)]


class QuietHours(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    timezone: str = Field(min_length=1, max_length=100)
    start: str = Field(pattern=r'^(?:[01][0-9]|2[0-3]):[0-5][0-9]$')
    end: str = Field(pattern=r'^(?:[01][0-9]|2[0-3]):[0-5][0-9]$')

    @model_validator(mode='after')
    def valid_window(self):
        if self.start == self.end:
            raise ValueError('Quiet hours must leave a delivery window')
        try:
            ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError('Unknown IANA timezone') from None
        return self


class Filters(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    chat_ids: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(default_factory=list, max_length=5000)
    all_chats: bool = False
    contains: str = Field(default='', max_length=200)
    event_types: list[Literal[EVENT_TYPES]] = Field(default_factory=list, max_length=len(EVENT_TYPES))
    sender_ids: list[PersonId] = Field(default_factory=list, max_length=100)
    mention_ids: list[PersonId] = Field(default_factory=list, max_length=100)
    attachments: Literal['any', 'with', 'without'] = 'any'
    text_all: list[LiteralText] = Field(default_factory=list, max_length=20)
    text_any: list[LiteralText] = Field(default_factory=list, max_length=20)
    text_none: list[LiteralText] = Field(default_factory=list, max_length=20)
    digest_window_seconds: int = Field(default=0, ge=0, le=86400)
    quiet_hours: QuietHours | None = None


def normalize_filters(name, filters):
    """Keep exactly the four legacy defaults in the hash; omit new neutral defaults."""
    if name not in ('message.received', 'message.digest', 'whatsapp.event'):
        raise ValueError('Unknown event')
    f = Filters.model_validate(filters).model_dump()
    if bool(f['chat_ids']) == f['all_chats']:
        raise ValueError('Select chat_ids or all_chats')
    if (name == 'whatsapp.event') != bool(f['event_types']):
        raise ValueError('Event types are required only for whatsapp.event')
    if (name == 'message.digest') != (60 <= f['digest_window_seconds'] <= 86400):
        raise ValueError('Digest requires a window of 60..86400 seconds')
    if name != 'message.digest' and f['digest_window_seconds']:
        raise ValueError('Window is only valid for digest')
    neutral = Filters().model_dump()
    for key in tuple(f):
        if isinstance(f[key], list):
            f[key] = sorted(set(f[key]))
        if key not in ('chat_ids', 'all_chats', 'contains', 'event_types'):
            if f[key] == neutral[key]:
                del f[key]
            elif name == 'whatsapp.event':
                raise ValueError('Message policies do not apply to whatsapp.event')
    return f


def quiet_until(now, quiet):
    """First UTC minute outside a daily local interval, including DST folds/gaps.

    Evaluate UTC instants rather than constructing ambiguous/nonexistent local
    times. A fold may repeat a quiet interval; dispatch always checks again.
    """
    if not quiet:
        return now
    zone = ZoneInfo(quiet['timezone'])
    start, end = quiet['start'], quiet['end']

    def inside(epoch):
        wall = datetime.fromtimestamp(epoch, timezone.utc).astimezone(zone).strftime('%H:%M')
        return start <= wall < end if start < end else wall >= start or wall < end

    if not inside(now):
        return now
    minute = (math.floor(now / 60) + 1) * 60
    # Every valid daily interval has an opening within two UTC days, including
    # date-line transitions. This is a bounded calendar calculation, not a timer.
    for offset in range(2880):
        candidate = minute + offset * 60
        if not inside(candidate):
            return candidate
    raise ValueError('Quiet hours have no opening in the next 48 hours')


def person_id(value):
    return value if isinstance(value, str) and re.fullmatch(r'[0-9]{5,25}@(c\.us|lid)', value) else None


def message_mentions(payload):
    """Pinned GOWS 2026.9.2 protocol path; no body/quoted-message heuristics.

    See docs/VALIDATION.md and provider-checkpoint for the WAHA -> GOWS -> Whatsmeow source chain.
    Unknown engine shapes fail closed rather than claiming a mention match.
    """
    raw = payload.get('_data')
    proto = raw.get('Message') if isinstance(raw, dict) else None
    if not isinstance(proto, dict):
        return set()
    found = set()
    for kind in ('extendedTextMessage', 'imageMessage', 'videoMessage', 'documentMessage', 'audioMessage', 'stickerMessage'):
        value = proto.get(kind)
        context = value.get('contextInfo') if isinstance(value, dict) else None
        identifiers = context.get('mentionedJID') if isinstance(context, dict) else None
        if not isinstance(identifiers, list) or len(identifiers) > 1000:
            continue
        for value in identifiers:
            if isinstance(value, str):
                value = value.removesuffix('@s.whatsapp.net') + '@c.us' if value.endswith('@s.whatsapp.net') else value
                if person_id(value):
                    found.add(value)
    return found


def message_matches(filters, payload, chat_id, body, has_media, canonical_chat, mentions=()):
    if not filters.get('all_chats') and chat_id not in {canonical_chat(c) for c in filters['chat_ids']}:
        return False
    # Only protocol sender fields count; a group's chat ID or display text does not.
    sender = person_id(payload.get('participant') if str(payload.get('from', '')).endswith('@g.us') else payload.get('from'))
    if filters.get('sender_ids') and (not sender or canonical_chat(sender) not in {canonical_chat(c) for c in filters['sender_ids']}):
        return False
    if filters.get('mention_ids') and not ({canonical_chat(c) for c in mentions} & {canonical_chat(c) for c in filters['mention_ids']}):
        return False
    if filters.get('attachments', 'any') != 'any':
        if 'hasMedia' in payload and type(payload['hasMedia']) is not bool:
            return False
        if (filters['attachments'] == 'with') != has_media:
            return False
    text = body.casefold()
    return ((not filters.get('contains') or filters['contains'].casefold() in text)
            and all(s.casefold() in text for s in filters.get('text_all', []))
            and (not filters.get('text_any') or any(s.casefold() in text for s in filters['text_any']))
            and not any(s.casefold() in text for s in filters.get('text_none', [])))
