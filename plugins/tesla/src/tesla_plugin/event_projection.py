"""Bounded read projections; retained event and sample evidence is untouched."""
from .store import canonical
from .telemetry_values import semantics

VALUE_BYTES = 2048
PAGE_BYTES = 32768


def history_pointer(vehicle, field, occurred, *, source_at=None):
    # Rule events store a shared payload time, not a source time for every field.
    # The largest supported rule age is one day. A paginated history selection
    # keeps older supporting observations reachable without inventing timestamps.
    after = source_at - .001 if source_at is not None else occurred - 86400
    before = source_at + .001 if source_at is not None else occurred + .001
    return {'value_omitted': True, 'retrieve_with': 'tesla_get_history',
            'arguments': {'vehicle_ref': vehicle, 'fields': [field], 'after': max(0, after),
                          'before': before, 'limit': 1000},
            'note': 'Follow next_cursor if present; retained samples may expire independently of the event.'}


def project_observed(data, vehicle, occurred, offset, limit):
    """Project legacy rule observations as well as modern batched changes."""
    if not isinstance(data.get('observed'), dict):
        return
    observed, omitted, meaning = {}, {}, {}
    keys = sorted(data['observed'])
    count = 0
    for field in keys[offset:offset+limit]:
        value = data['observed'][field]
        # Rule observations are emitted after value-contract validation. They
        # lack a separate per-field measurement clock: never substitute the
        # shared event time when adding interpretation warnings.
        notes = semantics(field, value, None, 'valid')
        target = omitted if len(canonical(value).encode()) > VALUE_BYTES else observed
        item = history_pointer(vehicle, field, occurred) if target is omitted else value
        if count and len(canonical({'observed': observed, 'observed_omitted': omitted,
                                    'observed_semantics': meaning,
                                    'next': {field: item}, 'next_semantics': notes}).encode()) > PAGE_BYTES:
            break
        target[field] = item
        if notes:
            meaning[field] = notes
        count += 1
    data['observed'] = observed
    if omitted:
        data['observed_omitted'] = omitted
    if meaning:
        data['observed_semantics'] = meaning
    data['observed_total'] = len(keys)
    data['next_offset'] = offset+count if offset+count < len(keys) else None
