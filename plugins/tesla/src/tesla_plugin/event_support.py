"""Compact observation dependencies for notification rules, never vehicle actions.

A point refers to one field/source-time group. A range is used only for dwell
rules whose evaluation used every intervening observation of that field. Values
are not copied here, so support metadata cannot duplicate large/private values.
"""
import json
import math

VERSION = 1
KEY = 'observation_support'


def points(records):
    return {'version': VERSION, 'fields': {
        row['field']: [[row['source_at'], row['source_at']]] for row in records}}


def combine(*supports, span=False):
    fields = {}
    for support in supports:
        if not known(support):
            continue
        for field, ranges in support['fields'].items():
            fields.setdefault(field, []).extend(ranges)
    for field, ranges in fields.items():
        merged = []
        for start, end in sorted(ranges):
            if merged and (span or start <= merged[-1][1]):
                merged[-1][1] = max(end, merged[-1][1])
            else:
                merged.append([start, end])
        fields[field] = merged
    return {'version': VERSION, 'fields': fields}


def known(support):
    if (not isinstance(support, dict) or type(support.get('version')) is not int
            or support['version'] != VERSION or not isinstance(support.get('fields'), dict)):
        return False
    return all(isinstance(field, str) and isinstance(ranges, list) and all(
        isinstance(pair, list) and len(pair) == 2 and all(
            type(t) in (int, float) and math.isfinite(t) for t in pair) and pair[0] <= pair[1]
        for pair in ranges) for field, ranges in support['fields'].items())


def for_event(data):
    """Use recorded support, or exact times already present in legacy batches.

    Legacy rule events have only a shared payload time: do not invent per-field
    support for them. This projection never rewrites persisted event evidence.
    """
    if KEY in data:
        return data[KEY]
    if not isinstance(data.get('changes'), dict):
        return None
    supports = []
    for field, change in data['changes'].items():
        if not isinstance(change, dict):
            return None
        after = change.get('after')
        # An explicit conflict report is evidence of ambiguity, not a claim
        # that its before/after measurements are currently unambiguous.
        if isinstance(after, dict) and after.get('quality') == 'time_conflict':
            continue
        for position in ('before', 'after'):
            observation = change.get(position)
            if observation is None:
                continue
            if not isinstance(observation, dict):
                return None
            if observation.get('quality') == 'valid':
                when = observation.get('source_at')
                if type(when) not in (int, float) or not math.isfinite(when):
                    return None
                supports.append(points([{'field': field, 'source_at': when}]))
    return combine(*supports)


def uses(support, field, when):
    return known(support) and any(start <= when <= end for start, end in support['fields'].get(field, []))


def conflicted(db, vehicle, support):
    """Inspect retained same-time contradictions, not a newer physical state."""
    if not known(support):
        return False
    for field, ranges in support['fields'].items():
        for start, end in ranges:
            if db.execute(
                # One representative per time group avoids a quadratic pairwise
                # join for equivalent retransmissions. sample_history indexes
                # both the bounded grouping and the lookup of its members.
                "SELECT 1 FROM (SELECT source_at,min(rowid) AS representative FROM samples "
                "WHERE vehicle=? AND field=? AND source_at BETWEEN ? AND ? GROUP BY source_at) g "
                "JOIN samples c ON c.rowid=g.representative JOIN samples s ON s.vehicle=c.vehicle "
                "AND s.field=c.field AND s.source_at=c.source_at "
                "WHERE c.quality!=s.quality OR NOT telemetry_value_equal(s.field,c.value,s.value) LIMIT 1",
                    (vehicle, field, start, end)).fetchone():
                return True
            # Retention can remove the history while a latest conflict remains.
            if db.execute("SELECT 1 FROM latest WHERE vehicle=? AND field=? AND quality='time_conflict' "
                          "AND source_at BETWEEN ? AND ?", (vehicle, field, start, end)).fetchone():
                return True
    return False


def invalidate(db, vehicle, field, when):
    """Called in the ingestion transaction, including for out-of-order samples.

Only deliveries that have never been claimed are cancellable here. A claimed or
attempted request may already exist at the receiver; its persisted body, receipt
and retry identity remain immutable. Event evidence itself is never rewritten.
"""
    for event in db.execute(
            "SELECT e.id,e.data FROM events e WHERE e.vehicle=? AND EXISTS "
            "(SELECT 1 FROM deliveries d WHERE d.event=e.id AND d.state='pending' AND d.attempts=0)",
            (vehicle,)).fetchall():
        if uses(for_event(json.loads(event['data'])), field, when):
            db.execute("UPDATE deliveries SET state='cancelled',last_code='support_time_conflict' "
                       "WHERE event=? AND state='pending' AND attempts=0", (event['id'],))
    for rule in db.execute("SELECT id,state FROM rules WHERE vehicle=?", (vehicle,)).fetchall():
        if uses(json.loads(rule['state']).get(KEY), field, when):
            db.execute("UPDATE rules SET state='{}' WHERE id=?", (rule['id'],))
