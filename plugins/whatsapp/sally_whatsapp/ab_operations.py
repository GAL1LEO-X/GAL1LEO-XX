"""The additive GOWS A/B contract and durable mutation identity.

Capability discovery never authorizes an action. The normal owner, scope,
configuration, destination and source checks remain mandatory.
"""
import hashlib
import math
import re


CONTRACT_VERSION = 'gows-ab-v1'
CAPABILITY = 'gows_ab_v1'
OPERATIONS = frozenset({
    'contacts_get_about', 'contacts_block', 'contacts_unblock',
    'chats_archive_chat', 'chats_unarchive_chat', 'messages_set_star',
    'chats_pin_message', 'chats_unpin_message',
})


def contract_operations(value):
    if not isinstance(value, dict) or value.get('version') != CONTRACT_VERSION:
        raise ValueError('The installed provider does not expose the qualified A/B contract')
    names = value.get('operations')
    if (not isinstance(names, list) or len(names) > 64
            or any(not isinstance(name, str) or len(name) > 128 for name in names)
            or len(set(names)) != len(names)):
        raise ValueError('Invalid provider A/B capability response')
    return frozenset(names) & OPERATIONS


def durable_intent(owner, key, created):
    """Derive immutable transport metadata from the existing committed job."""
    if (not isinstance(owner, str) or not owner or not isinstance(key, str) or not key
            or type(created) not in (int, float) or not math.isfinite(created)
            or not 0 < created <= 253402300799):
        raise ValueError('Durable action identity is unavailable')
    digest = hashlib.sha256((CONTRACT_VERSION + '\0' + owner + '\0' + key).encode()).hexdigest()
    return {'id': 'AB' + digest[:38].upper(), 'timestamp_ms': int(created * 1000)}


def intent_headers(intent):
    if (not isinstance(intent, dict)
            or not isinstance(intent.get('id'), str)
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', intent['id'])
            or type(intent.get('timestamp_ms')) is not int
            or not 0 < intent['timestamp_ms'] <= 253402300799999):
        raise ValueError('A durable A/B mutation intent is required')
    return {'X-WhatsApp-Intent-Id': intent['id'],
            'X-WhatsApp-Intent-Timestamp-Ms': str(intent['timestamp_ms'])}
