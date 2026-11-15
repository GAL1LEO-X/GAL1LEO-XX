"""Reversible visibility from provider deletion and incomplete clear evidence.

Only normalized, authenticated app-state events create these records. Empty
directories and failed reads never create records. No message content is kept
here; the acquired rows remain separate from this projection.
"""
import hashlib
import json
import math
import re
from contextlib import contextmanager
from contextvars import ContextVar
from . import lifetime
from .chat_identity import normalize_chat_id, legacy_chat_id

PREFIX = 'private:linked_visibility:v1:'
CONTEXT = 'private:linked_context:v1:'
CLEAR_UNCERTAIN = 'clear_chat_coverage_uncertain'
CLEAR_REPAIR = 'private:clear_coverage_repair:v1'

# Only a read_snapshot block owns these values. Connections cannot carry Python
# attributes, and a process-wide connection cache would outlive a read page.
_read_scopes = ContextVar('linked_visibility_read_scopes', default=())


class _ReadSnapshot:
    def __init__(self, db):
        self.db = db
        self.active = True
        self.invalidate()

    def invalidate(self):
        self.changes = self.db.total_changes
        self.records = None
        self.by_chat = {}
        self.coverage = {}


@contextmanager
def read_snapshot(db):
    """Reuse visibility projections inside one explicit transaction/read page.

    The enclosing connection owner commits or rolls back the transaction. Do
    not end it or roll back a savepoint inside this scope; a new transaction or
    page requires a new scope. Local writes invalidate projections, and other
    connections' commits remain outside SQLite's existing read snapshot.
    """
    if not db.in_transaction:
        db.execute('BEGIN')
    snapshot = _ReadSnapshot(db)
    token = _read_scopes.set((*_read_scopes.get(), snapshot))
    try:
        yield db
    finally:
        snapshot.active = False
        snapshot.invalidate()
        _read_scopes.reset(token)


def _snapshot(db):
    for snapshot in reversed(_read_scopes.get()):
        if snapshot.db is db and snapshot.active:
            if not db.in_transaction:
                snapshot.invalidate()
                return None
            if snapshot.changes != db.total_changes:
                snapshot.invalidate()
            return snapshot
    return None


def _invalidate(db):
    for snapshot in _read_scopes.get():
        if snapshot.db is db and snapshot.active:
            snapshot.invalidate()


def message_identity(identifier):
    if not isinstance(identifier, str):
        return None
    parts = identifier.split('_', 2)
    if len(parts) != 3 or parts[0] not in ('true', 'false') or '@' not in parts[1]:
        return None
    chat = normalize_chat_id(parts[1])
    return chat, parts[0] == 'true', parts[2]


def tuple_match(identifier, raw_id, from_me):
    identity = message_identity(identifier)
    if identity is None:
        return identifier == raw_id
    _, direction, suffix = identity
    # A group ID may append a participant. Do not invent the missing self JID
    # for outgoing DeleteForMe: chat/rawID/direction identifies the target.
    participant = suffix[len(raw_id) + 1:] if suffix.startswith(raw_id + '_') else ''
    return (from_me is None or direction == bool(from_me)) and (suffix == raw_id or bool(re.fullmatch(
        r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)', participant)))


def canonical_identifier(db, identifier, canonical_chat):
    identity=message_identity(identifier)
    if identity is None:
        return identifier
    chat,direction,suffix=identity
    if chat.endswith('@g.us') and '_' in suffix:
        raw,participant=suffix.rsplit('_',1)
        if re.fullmatch(r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)',participant):
            participant=normalize_chat_id(participant)
            suffix=raw+'_'+canonical_chat(db,participant)
    return str(direction).lower()+'_'+canonical_chat(db,chat)+'_'+suffix


def identifier_variants(db, identifier, canonical_chat):
    """Enumerate complete provider keys using only persisted, verified aliases.

    Never add/remove a group participant, infer a direction or match a raw
    stanza globally. Opaque identifiers retain their exact-ID contract.
    """
    identity = message_identity(identifier)
    if identity is None:
        return [identifier] if isinstance(identifier, str) and identifier else []

    def addresses(address):
        address = normalize_chat_id(address)
        canonical = canonical_chat(db, address)
        values = {address, canonical}
        if isinstance(canonical, str) and canonical.endswith('@c.us'):
            values.update(row[0] for row in db.execute(
                'SELECT alias FROM chat_aliases WHERE chat_id=?', (canonical,)))
            values.add(legacy_chat_id(canonical))
        return values

    chat, direction, suffix = identity
    suffixes = {suffix}
    if chat.endswith('@g.us') and '_' in suffix:
        raw, participant = suffix.rsplit('_', 1)
        if re.fullmatch(r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)', participant):
            suffixes = {raw + '_' + value for value in addresses(participant)}
    return sorted({identifier, *(str(direction).lower() + '_' + target + '_' + ending
                                for target in addresses(chat) for ending in suffixes)})


def representative_sql(alias='m'):
    """Select one acquired row per verified identity before filtering/paging.

    Retain every historical row and original ID. Indexed exact-ID probes avoid
    scanning the archive for every candidate or inventing equivalence from text.
    """
    return f'''NOT EXISTS (SELECT 1 FROM messages identity_peer
        WHERE identity_peer.id IN (
            SELECT value FROM json_each(linked_identifier_variants({alias}.id)))
        AND (identity_peer.rowid<{alias}.rowid OR identity_peer.deleted=1
             OR NOT ({visible_sql('identity_peer')})))'''


def lifetime_reference_match(db, identifier, item, canonical_chat):
    """Scope a quoted raw stanza ID; never manufacture its missing sender."""
    target=item['identifier']
    if canonical_identifier(db,identifier,canonical_chat)==canonical_identifier(db,target,canonical_chat):
        if message_identity(target) is None:
            row=db.execute('SELECT from_me,sender FROM messages WHERE id=?',(identifier,)).fetchone()
            if row and item.get('from_me') is not None and bool(row['from_me'])!=item['from_me']:
                return None
            participant=item.get('participant')
            if row and item['chat_id'].endswith('@g.us') and participant:
                actual=row['sender']
                if isinstance(actual,str) and re.fullmatch(r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)',actual):
                    if canonical_chat(db,actual)!=canonical_chat(db,participant):
                        return None
        return 'exact'
    identity=message_identity(identifier)
    if (identity is None or message_identity(target) is not None
            or not re.fullmatch(r'[A-Za-z0-9.:-]{1,200}',target)
            or canonical_chat(db,identity[0])!=canonical_chat(db,item['chat_id'])
            or not tuple_match(identifier,target,item.get('from_me'))):
        return None
    participant=item.get('participant')
    if identity[0].endswith('@g.us') and participant:
        suffix=identity[2]
        actual=suffix[len(target)+1:] if suffix.startswith(target+'_') else None
        if actual and canonical_chat(db,actual)!=canonical_chat(db,participant):
            return None
        if actual and item.get('from_me') is not None:
            return 'exact'
    elif not identity[0].endswith('@g.us') and item.get('from_me') is not None:
        return 'exact'
    # A raw reference with missing direction/participant cannot establish that
    # a candidate is ordinary. Withhold it without destructively revoking it.
    return 'ambiguous'


def records(db):
    snapshot = _snapshot(db)
    if snapshot is not None and snapshot.records is not None:
        return snapshot.records
    values=[(row['key'], json.loads(row['value'])) for row in db.execute(
        'SELECT key,value FROM state WHERE key>=? AND key<?', (PREFIX, PREFIX + '~'))]
    # A reversible boundary must never mask irreversible revocation evidence.
    def priority(pair):
        item=pair[1]
        rank=(0 if item['reason']=='revoked' else 1 if item['kind']=='lifetime'
              else 3 if item['reason'] in (CLEAR_UNCERTAIN,'chat_cleared') else 2)
        return rank,item['kind']!='message',pair[0]
    result = sorted(values,key=priority)
    if snapshot is not None:
        snapshot.records = result
    return result


def _records_for_chat(db, chat, canonical_chat):
    snapshot = _snapshot(db)
    if snapshot is None:
        return [item for _,item in records(db) if canonical_chat(db,item['chat_id']) == chat]
    if canonical_chat not in snapshot.by_chat:
        grouped = {}
        for _, item in records(db):
            grouped.setdefault(canonical_chat(db,item['chat_id']), []).append(item)
        snapshot.by_chat[canonical_chat] = grouped
    return snapshot.by_chat[canonical_chat].get(chat, ())


def remember_context(db, identifier, chat, timestamp, canonical_chat):
    if not isinstance(identifier, str) or not identifier or not isinstance(chat, str) or not chat:
        return
    key = CONTEXT + identifier
    old = db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
    value = json.loads(old[0]) if old else {}
    normalized = canonical_chat(db, chat)
    # Conflicting identities are not proof of a new association.
    if value and canonical_chat(db, value['chat_id']) != normalized:
        return
    value['chat_id'] = normalized
    if 'timestamp' not in value and type(timestamp) in (int, float) and math.isfinite(timestamp) and 0 <= timestamp <= 253402300799:
        value['timestamp'] = timestamp
    db.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
               (key, json.dumps(value, sort_keys=True)))


def apply(db, exclusions, canonical_chat):
    _invalidate(db)
    for item in exclusions:
        value = {**item, 'chat_id': canonical_chat(db, item['chat_id'])}
        identity = [value['kind'], value['chat_id'], value.get('raw_id'),
                    value.get('from_me'), value['reason']]
        if value['kind']=='lifetime':
            identity.append(value['identifier'])
            identity.append(value.get('participant'))
        if value['kind']=='clear':
            # Keep independent observations: an out-of-order event must not
            # replace a larger previous candidate scope with a smaller one.
            identity.extend([value['event_at'],value.get('range'),value.get('through'),value.get('anchors')])
        key = PREFIX + hashlib.sha256(json.dumps(identity).encode()).hexdigest()
        old = db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
        if old:
            previous = json.loads(old[0])
            value['event_at'] = max(previous['event_at'], value['event_at'])
            if value['kind'] == 'chat':
                value['before'] = max(previous['before'], value['before'])
            if value['kind'] == 'lifetime':
                earlier=previous['lifetime']
                newer=value['lifetime']
                if earlier['kind']=='view_once' or earlier['kind']=='unknown' and newer['kind']!='view_once':
                    value['lifetime']=earlier
                elif newer['kind']=='ephemeral':
                    value['lifetime']={**newer,'expires_at':min(earlier['expires_at'],newer['expires_at'])}
        db.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                   (key, json.dumps(value, sort_keys=True)))


def clear_coverage(db,chat,canonical_chat):
    chat = canonical_chat(db,chat) if chat is not None else None
    snapshot = _snapshot(db)
    key = (canonical_chat,chat)
    if snapshot is not None and key in snapshot.coverage:
        cached = snapshot.coverage[key]
        return dict(cached) if cached is not None else None
    candidates = [item for _,item in records(db)] if chat is None else _records_for_chat(db,chat,canonical_chat)
    items=[item for item in candidates if item['reason'] in (CLEAR_UNCERTAIN,'chat_cleared')]
    result = {'certainty':'uncertain','selection':'unavailable','timestamp_class':'unavailable',
            'boundary_unknown':any(item['kind']!='clear' or item.get('through') is None for item in items),
            'system_range_unresolved':any(item.get('system_through') is not None for item in items),
            'potential_scope':'ordinary_timestamp_candidates_and_anchors',
            'content_may_be_withheld':any(item['kind']=='message' or item.get('through') is not None or
                                       item.get('anchors') for item in items),
            'archive_is_current':False} if items else None
    if snapshot is not None:
        snapshot.coverage[key] = result
    return dict(result) if result is not None else None


def repair_clear_coverage(db,canonical_chat):
    """Retained legacy events lost their ranges: persist only that uncertainty.

    No event time, local message or old anchor is used to reconstruct a range.
    Existing private bodies, FTS rows, receipts and visibility records survive.
    """
    _invalidate(db)
    if db.execute('SELECT 1 FROM state WHERE key=?',(CLEAR_REPAIR,)).fetchone(): return
    for row in db.execute("SELECT chat_id,data FROM account_events WHERE event_type='chat.cleared'").fetchall():
        try: data=json.loads(row['data'])
        except (ValueError,TypeError): continue
        if not isinstance(data,dict) or 'clearCoverage' in data: continue
        chat=row['chat_id'] or data.get('chatId')
        epoch=data.get('eventAt')
        if not isinstance(chat,str) or type(epoch) not in (int,float) or not math.isfinite(epoch): continue
        apply(db,[{'kind':'clear','chat_id':chat,'reason':CLEAR_UNCERTAIN,'event_at':epoch,
                   'through':None,'system_through':None,'anchors':[],'range':{},
                   'legacy_range_unavailable':True,'before':0}],canonical_chat)
    db.execute('INSERT INTO state VALUES(?,?)',(CLEAR_REPAIR,'true'))


def reference_ids(db, identifier, chat, canonical_chat):
    """Resolve raw quoted IDs only in an explicitly known conversation.

    A serialized reference can additionally match its verified PN/LID alias.
    Never resolve a raw ID globally across conversations.
    """
    if not isinstance(identifier,str) or not identifier:
        return []
    identity=message_identity(identifier)
    chat=canonical_chat(db,chat or (identity[0] if identity else None))
    if not chat:
        return []
    if identity:
        # Complete identities already bound direction, chat and participant.
        # Probe only their verified serializations; scanning every message in
        # the conversation for every reaction turns a bounded page quadratic.
        variants=json.dumps(identifier_variants(db,identifier,canonical_chat))
        candidates=db.execute("""SELECT message_id AS id,NULL AS acquired_chat FROM message_mutations
            WHERE kind='revoked' AND message_id IN (SELECT value FROM json_each(?))
            UNION ALL SELECT id,chat_id AS acquired_chat FROM messages WHERE deleted=1
            AND id IN (SELECT value FROM json_each(?))""",(variants,variants)).fetchall()
        # Filter context after the exact primary-key probes. Combining chat_id
        # with the IN predicate can make SQLite choose its conversation index
        # and scan the whole chat instead, defeating the bounded lookup.
        return sorted({row['id'] for row in candidates if row['id']!=identifier
                and canonical_chat(db,row['acquired_chat']) in (None,chat)
                and (parsed:=message_identity(row['id'])) is not None
                and canonical_chat(db,parsed[0])==chat and parsed[1:]==identity[1:]})
    result=[]
    candidates={row['id'] for row in db.execute('SELECT id FROM messages WHERE chat_id IN (?,?)',(chat,legacy_chat_id(chat)))}
    candidates.update(row['message_id'] for row in db.execute("SELECT message_id FROM message_mutations WHERE kind='revoked'"))
    for candidate in candidates:
        if candidate==identifier:
            continue
        parsed=message_identity(candidate)
        if parsed is None or canonical_chat(db,parsed[0])!=chat:
            continue
        matches=tuple_match(candidate,identifier,parsed[1])
        if matches:
            result.append(candidate)
    return sorted(result)


def state(db, identifier, chat, timestamp, canonical_chat):
    if not identifier and (not chat or timestamp is None):
        return {'state': 'unknown', 'source': 'no_current_state_evidence'}
    row = db.execute('SELECT chat_id,timestamp,from_me FROM messages WHERE id=?', (identifier,)).fetchone()
    identity = message_identity(identifier)
    context = db.execute('SELECT value FROM state WHERE key=?', (CONTEXT + identifier,)).fetchone() if identifier else None
    context = json.loads(context[0]) if context else {}
    # Stored acquired identity is stronger than optional caller context.
    chat = row['chat_id'] if row else chat or context.get('chat_id') or (identity[0] if identity else None)
    timestamp = row['timestamp'] if row else context.get('timestamp', timestamp)
    direction = bool(row['from_me']) if row else identity[1] if identity else None
    chat = canonical_chat(db, chat)
    for item in _records_for_chat(db, chat, canonical_chat):
        if item['kind']=='lifetime':
            match=lifetime_reference_match(db,identifier,item,canonical_chat)
            if match:
                status=lifetime.state(item['lifetime'])
                if status!='unknown':
                    return {'state':status if match=='exact' else 'lifetime_unknown',
                            'source':'provider_message_lifetime','evidence_at':item['event_at']}
            continue
        if item['kind']=='clear':
            anchored=any((direction is None or direction==a['from_me']) and
                         tuple_match(identifier,a['raw_id'],a['from_me']) for a in item['anchors'])
            bound=item.get('through')
            if anchored or bound is not None and (timestamp is None or
                    type(timestamp) in (int,float) and math.isfinite(timestamp) and timestamp<=bound):
                return {'state':CLEAR_UNCERTAIN,'source':'provider_clear_incomplete',
                        'evidence_at':item['event_at'],'certainty':'uncertain'}
            continue
        if item['kind'] == 'message':
            if item['from_me'] is None and identifier==item['raw_id']:
                return {'state':item['reason'],'source':'provider_revocation','evidence_at':item['event_at']}
            if direction is None and identifier==item['raw_id']:
                return {'state':'unverified_reference','source':'ambiguous_provider_reference',
                        'evidence_at':item['event_at']}
            matches = ((item['from_me'] is None or direction is not None and direction == item['from_me'])
                       and tuple_match(identifier, item['raw_id'], item['from_me']))
        else:
            if timestamp is None:
                return {'state':'unverified_reference','source':'unknown_time_after_chat_deletion',
                        'evidence_at':item['event_at']}
            matches = (type(timestamp) in (int, float) and math.isfinite(timestamp)
                       and timestamp < item['before'])
        if matches:
            reason=CLEAR_UNCERTAIN if item['reason']=='chat_cleared' else item['reason']
            return {'state': reason, 'source': 'provider_app_state',
                    'evidence_at': item['event_at']}
    return {'state': 'unknown', 'source': 'no_current_state_evidence'}


def visible_sql(alias='m'):
    """Use current evidence, indexed by chat for this statement's read snapshot.

    Materialize only visibility records once, rather than decode the entire
    state range for every candidate message. The TEXT affinity is essential:
    it lets SQLite build an automatic covering chat index against messages'
    TEXT chat_id. No durable schema or tombstone is changed by a read.
    """
    return f'''NOT EXISTS (WITH exclusions AS MATERIALIZED (
        SELECT value,CAST(linked_chat_id(json_extract(value,'$.chat_id')) AS TEXT) AS chat_id
        FROM state WHERE key>='{PREFIX}' AND key<'{PREFIX}~'
        ) SELECT 1 FROM exclusions v WHERE v.chat_id=linked_chat_id({alias}.chat_id)
        AND ((json_extract(v.value,'$.kind')='clear' AND
              ({alias}.timestamp<=json_extract(v.value,'$.through') OR EXISTS
                (SELECT 1 FROM json_each(v.value,'$.anchors') a WHERE
                 {alias}.from_me=json_extract(a.value,'$.from_me') AND linked_tuple_match({alias}.id,json_extract(a.value,'$.raw_id'),json_extract(a.value,'$.from_me')))))
             OR (json_extract(v.value,'$.kind')='chat'
              AND {alias}.timestamp<json_extract(v.value,'$.before'))
             OR (json_extract(v.value,'$.kind')='message'
                 AND (json_type(v.value,'$.from_me')='null' OR {alias}.from_me=json_extract(v.value,'$.from_me'))
                 AND linked_tuple_match({alias}.id,json_extract(v.value,'$.raw_id'),
                                        json_extract(v.value,'$.from_me')))
             OR (json_extract(v.value,'$.kind')='lifetime'
                 AND linked_lifetime_match({alias}.id,v.value)
                 AND linked_lifetime_state(json_extract(v.value,'$.lifetime'))!='unknown')))'''


def bind_alias(db, alias, chat):
    _invalidate(db)
    for key, item in records(db):
        if item['chat_id'] == alias:
            item = {**item, 'chat_id': chat}
            db.execute('UPDATE state SET value=? WHERE key=?', (json.dumps(item, sort_keys=True), key))
