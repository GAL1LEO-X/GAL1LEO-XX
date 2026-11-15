"""Typed provider acknowledgements, independent of dispatch and delivery state.

Only explicit outcome fields are evidence. Missing fields, an ID or a 2xx
transport alone do not prove the requested effect. A rejection after dispatch
does not prove that every side effect was rolled back and never permits retry.
"""


OUTCOMES = frozenset({'accepted', 'rejected', 'partial', 'uncertain', 'unverified'})


def provider_outcome(value):
    if type(value) is bool:
        return 'accepted' if value else 'rejected'
    if isinstance(value, list):
        outcomes = {provider_outcome(item) for item in value}
        if not outcomes:
            return 'unverified'
        if len(outcomes) == 1:
            return next(iter(outcomes))
        if 'partial' in outcomes or 'rejected' in outcomes and 'accepted' in outcomes:
            return 'partial'
        return 'uncertain'
    if not isinstance(value, dict):
        return 'unverified'
    positive = negative = ambiguous = False
    for field in ('success', 'result', 'accepted'):
        if type(value.get(field)) is bool:
            positive |= value[field]
            negative |= not value[field]
    outcome = value.get('outcome')
    if outcome == 'partial':
        return 'partial'
    positive |= outcome == 'accepted'
    negative |= outcome == 'rejected'
    ambiguous |= outcome == 'uncertain'
    for field in ('status', 'error'):
        code = value.get(field)
        if type(code) is int:
            negative |= 400 <= code <= 599
            positive |= field == 'status' and 200 <= code <= 299
    if ambiguous or positive and negative:
        return 'uncertain'
    if negative:
        return 'rejected'
    if positive:
        return 'accepted'
    return 'unverified'
