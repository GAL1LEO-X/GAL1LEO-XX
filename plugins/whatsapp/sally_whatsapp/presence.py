"""Validate cached presence observations without treating them as current state."""
import math
import re

from .gateway import GatewayUnavailable


def _chat_id(value):
    return (isinstance(value, str)
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}@(c\.us|s\.whatsapp\.net|lid|g\.us)', value))


def validate_presence_list(value, diagnostics=None):
    """WAHA's fixed GOWS adapter can emit cache indices instead of chat IDs.

    Do not reinterpret an index or drop invalid rows and imply an empty list.
    The contract is WAHAChatPresences[] in the pinned presence.dto.ts.
    """
    valid = isinstance(value, list)
    for row in value if valid else []:
        if not isinstance(row, dict) or not _chat_id(row.get('id')) or not isinstance(row.get('presences'), list):
            valid = False
            break
        for observation in row['presences']:
            if (not isinstance(observation, dict) or not _chat_id(observation.get('participant'))
                    or observation.get('lastKnownPresence') not in ('online', 'offline', 'typing', 'recording', 'paused')):
                valid = False
                break
            last_seen = observation.get('lastSeen')
            if (last_seen is not None and (type(last_seen) not in (int, float)
                    or not math.isfinite(last_seen) or not 0 <= last_seen <= 253402300799)):
                valid = False
                break
        if not valid:
            break
    if not valid:
        if diagnostics is not None:
            diagnostics.emit('gateway.failed', 'warning', operation='presence_get_presence_all',
                             error_code='WAHA_PRESENCE_SCHEMA')
        raise GatewayUnavailable('The gateway returned an invalid presence list; no current presence can be inferred. '
                                 'Use the authorized per-chat presence action.')
    return value


def presence_result_metadata(value):
    """Retain only validated cached observations, never infer current presence.

    Missing observations can reflect privacy or a cache miss. A malformed row
    is unavailable rather than silently reporting an empty successful list.
    This projection is used on execution, persistence and status reads.
    """
    unavailable = {'availability': 'unavailable', 'source': 'provider_cache',
                   'current_state': 'unknown'}
    if not isinstance(value, dict) or not _chat_id(value.get('id')):
        return {**unavailable, 'reason': 'invalid_presence_response'}
    result = {**unavailable, 'id': value['id']}
    observations = value.get('presences')
    if observations is None:
        return {**result, 'reason': value.get('reason') if value.get('reason') in
                ('invalid_presence_response', 'no_cached_observation') else 'no_cached_observation'}
    try:
        validate_presence_list([value])
    except GatewayUnavailable:
        return {**result, 'reason': 'invalid_presence_response'}
    result['presences'] = [
        {key: row[key] for key in ('participant', 'lastKnownPresence', 'lastSeen') if key in row}
        for row in observations]
    if observations:
        result['availability'] = 'observed'
    else:
        result['reason'] = 'no_cached_observation'
    return result
