"""Conversation namespaces, independent of names, content and PN/LID evidence.

The phone-number suffixes are two serializations of the same address. A LID
remains distinct until the store binds an explicitly verified relationship.
"""
import re
from typing import Literal


ChatType = Literal['private', 'group', 'status', 'channel', 'broadcast', 'unknown']
ChatTypeFilter = Literal['all', 'private', 'group', 'status', 'channel', 'broadcast', 'unknown']
CHAT_TYPES = frozenset({'private', 'group', 'status', 'channel', 'broadcast', 'unknown'})


def normalize_chat_id(value):
    if isinstance(value, str) and value.endswith('@s.whatsapp.net'):
        return value[:-len('@s.whatsapp.net')] + '@c.us'
    return value


def legacy_chat_id(value):
    """Alternate PN serialization for indexed reads of unmigrated old rows."""
    value = normalize_chat_id(value)
    return value[:-len('@c.us')] + '@s.whatsapp.net' if isinstance(value, str) and value.endswith('@c.us') else value


def chat_type(value):
    value = normalize_chat_id(value)
    if not isinstance(value, str):
        return 'unknown'
    if value == 'status@broadcast':
        return 'status'
    if re.fullmatch(r'[0-9]{5,25}@(c\.us|lid)', value):
        return 'private'
    if re.fullmatch(r'[0-9]{5,25}(?:-[0-9]{1,25})?@g\.us', value):
        return 'group'
    if re.fullmatch(r'[0-9]{5,25}@newsletter', value):
        return 'channel'
    if re.fullmatch(r'[0-9]{5,25}@broadcast', value):
        return 'broadcast'
    return 'unknown'


def validate_chat_type(value):
    if value != 'all' and value not in CHAT_TYPES:
        raise ValueError('Invalid chat type filter')
