"""Explicit, additive review of known history; never change action outcomes.

Read projections fail open for attention. Only an exact reviewed plan can mark
specific unchanged uncertain rows; date/operation patterns never suppress rows.
"""
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import time

FORMAT = 'whatsapp-uncertain-review-v1'
PREFIX = 'private:uncertain_review:v1:'
AUDIT = 'private:uncertain_review_audit:v1:'
MAX_CASES = 100
MAX_EVIDENCE = 256
FINGERPRINT_VERSION = 2
MODES = {'acknowledge_known_history', 'reopen'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def database_binding(db):
    filename = next(row[2] for row in db.execute('PRAGMA database_list') if row[1] == 'main')
    path = Path(filename).resolve(strict=True)
    info = path.stat()
    return digest([str(path), info.st_dev, info.st_ino])


def _key(owner, key):
    return PREFIX + digest([owner, key])


def _current(db, owner, key):
    row = db.execute('SELECT value FROM state WHERE key=?', (_key(owner, key),)).fetchone()
    return row[0] if row else None


def _bounded(db, query, parameters=()):
    rows = [dict(row) for row in db.execute(query + ' LIMIT ?', (*parameters, MAX_EVIDENCE + 1))]
    if len(rows) > MAX_EVIDENCE:
        raise ValueError('Related evidence exceeds review bound')
    return rows


def _source_evidence(db, row, parts):
    """Fingerprint acquired evidence without resolving a raw ID globally.

    Complete keys retain chat, direction and group participant. Opaque keys
    keep their exact-ID contract; known source context additionally constrains
    the match. PN/LID variants come only from the persisted alias relation.
    Nothing here changes action state, visibility or the original source.
    """
    from . import visibility
    from .store import Store

    def chat(value):
        return Store._canonical_chat(db, value.replace('@s.whatsapp.net', '@c.us')) if isinstance(value, str) else None

    refs = {}

    def add(identifier, context=None):
        if not identifier:
            return
        identity = visibility.message_identity(identifier)
        context = chat(context)
        if identity:
            actual = chat(identity[0])
            if context is not None and context != actual:
                raise ValueError('Source identity context is contradictory')
            context = actual
        for variant in visibility.identifier_variants(db, identifier, Store._canonical_chat):
            old = refs.get(variant)
            if old is not None and context is not None and old != context:
                raise ValueError('Source identity context is contradictory')
            refs[variant] = context if context is not None else old
            if len(refs) > MAX_EVIDENCE:
                raise ValueError('Related evidence exceeds review bound')

    for source in parts['action_job_sources']:
        for field in ('message_id', 'canonical_id'):
            add(source[field], source['chat_id'])
    # Produced opaque IDs can use the separately retained destination. A
    # complete provider key always has to agree with that context.
    destination = next((item['destination_chat_id'] for item in parts['action_job_metadata']
                        if item['destination_state'] == 'present'), None)
    add(row['provider_id'], destination)
    identifiers = encoded(sorted(refs))
    parts['references'] = [[identifier, refs[identifier]] for identifier in sorted(refs)]
    acquired = _bounded(db, '''SELECT id,chat_id,sender,timestamp,from_me,source,observed_at,deleted
        FROM messages WHERE id IN (SELECT value FROM json_each(?)) ORDER BY rowid''', (identifiers,))
    contexts = {item['key'][len(visibility.CONTEXT):]: json.loads(item['value']) for item in _bounded(
        db, 'SELECT key,value FROM state WHERE key IN (SELECT ? || value FROM json_each(?)) ORDER BY key',
        (visibility.CONTEXT, identifiers))}
    def attributable(identifier, context):
        identity = visibility.message_identity(identifier)
        context = context or (identity[0] if identity else None)
        return identifier in refs and (refs[identifier] is None or chat(context) == refs[identifier])

    parts['messages'] = [item for item in acquired if attributable(item['id'], item['chat_id'])]
    messages = {item['id']: item for item in parts['messages']}
    peers = {}
    for item in parts['messages']:
        canonical = visibility.canonical_identifier(db, item['id'], Store._canonical_chat)
        previous = peers.get(canonical)
        if previous is None or item['timestamp'] < previous['timestamp']:
            # Verified duplicate serializations can have different timestamps.
            # Reuse the strongest boundary evidence, as visibility does; an
            # alias without its own row must not manufacture an unknown time.
            peers[canonical] = item
    contexts = {identifier: item for identifier, item in contexts.items()
                if attributable(identifier, item.get('chat_id'))}
    parts['account_events'] = [item for item in _bounded(db, '''SELECT * FROM account_events
        WHERE source_message_id IN (SELECT value FROM json_each(?)) ORDER BY rowid''', (identifiers,))
        if attributable(item['source_message_id'], item['chat_id'])]
    mutations = []
    for item in _bounded(db, '''SELECT * FROM message_mutations
            WHERE message_id IN (SELECT value FROM json_each(?)) ORDER BY rowid''', (identifiers,)):
        identifier = item['message_id']
        identity = visibility.message_identity(identifier)
        context = (identity[0] if identity else messages.get(identifier, {}).get('chat_id')
                   or contexts.get(identifier, {}).get('chat_id'))
        if attributable(identifier, context):
            mutations.append(item)
    parts['message_mutations'] = mutations

    chats, raw_ids = set(), set()
    for identifier, context in refs.items():
        identity = visibility.message_identity(identifier)
        if context is None:
            context = chat(messages.get(identifier, {}).get('chat_id') or contexts.get(identifier, {}).get('chat_id'))
            refs[identifier] = context
        if context is not None:
            chats.add(context)
            if context.endswith('@c.us'):
                chats.add(context.removesuffix('@c.us') + '@s.whatsapp.net')
                chats.update(item['alias'] for item in _bounded(
                    db, 'SELECT alias FROM chat_aliases WHERE chat_id=? ORDER BY alias', (context,)))
        raw_ids.add(identity[2] if identity else identifier)
        if identity and identity[0].endswith('@g.us') and '_' in identity[2]:
            raw, participant = identity[2].rsplit('_', 1)
            if re.fullmatch(r'[0-9]{5,25}@(c\.us|s\.whatsapp\.net|lid)', participant):
                raw_ids.add(raw)
    if len(chats) > MAX_EVIDENCE or len(raw_ids) > MAX_EVIDENCE:
        raise ValueError('Related evidence exceeds review bound')
    candidates = _bounded(db, '''SELECT key,value FROM state WHERE key>=? AND key<?
        AND json_extract(value,'$.chat_id') IN (SELECT value FROM json_each(?))
        AND (json_extract(value,'$.kind') IN ('chat','clear')
            OR json_extract(value,'$.kind')='message'
               AND json_extract(value,'$.raw_id') IN (SELECT value FROM json_each(?))
            OR json_extract(value,'$.kind')='lifetime'
               AND json_extract(value,'$.identifier') IN (SELECT value FROM json_each(?)))
        ORDER BY key''', (visibility.PREFIX, visibility.PREFIX + '~', encoded(sorted(chats)),
                         encoded(sorted(raw_ids)), encoded(sorted(set(refs) | raw_ids))))

    def relevant(item):
        for identifier, context in refs.items():
            if context is None or context != chat(item['chat_id']):
                continue
            identity = visibility.message_identity(identifier)
            acquired = peers.get(visibility.canonical_identifier(db, identifier, Store._canonical_chat), {})
            direction = identity[1] if identity else bool(acquired['from_me']) if acquired else None
            timestamp = acquired.get('timestamp', contexts.get(identifier, {}).get('timestamp'))
            if item['kind'] == 'message':
                if (item['from_me'] is None or direction is None or direction == item['from_me']) and visibility.tuple_match(
                        identifier, item['raw_id'], item['from_me']):
                    return True
            elif item['kind'] == 'lifetime':
                if visibility.lifetime_reference_match(db, identifier, item, Store._canonical_chat):
                    return True
            elif item['kind'] == 'clear':
                # Even an unknown clear boundary changes what can be inferred
                # about this source; it does not establish actual deletion.
                if (item.get('through') is None or timestamp is None or timestamp <= item['through']
                        or any((direction is None or direction == anchor['from_me']) and
                               visibility.tuple_match(identifier, anchor['raw_id'], anchor['from_me'])
                               for anchor in item.get('anchors', []))):
                    return True
            elif item['kind'] == 'chat' and (timestamp is None or timestamp < item['before']):
                return True
        return False

    parts['visibility'] = [item for item in candidates if relevant(json.loads(item['value']))]


def fingerprint(db, owner, key):
    row = db.execute("SELECT * FROM sends WHERE owner=? AND key=? AND state='uncertain'", (owner, key)).fetchone()
    if row is None:
        raise ValueError('Exact uncertain action for this owner is required')
    parts = {'send': dict(row), 'fingerprint_version': FINGERPRINT_VERSION}
    for table in ('action_jobs', 'operation_results', 'action_job_metadata', 'action_job_sources'):
        parts[table] = _bounded(db, 'SELECT * FROM '+table+' WHERE key=? ORDER BY rowid', (key,))
    _source_evidence(db, row, parts)
    return digest(parts)


def status(db, owner, key):
    result = {'classification':'unreviewed', 'requires_attention':True,
              'repeat_alert_eligible':True, 'outcome':'uncertain', 'outcome_verified':False}
    raw = _current(db, owner, key)
    if raw is None:
        return result
    try:
        value = json.loads(raw)
        audit_id = value['audit_id']
        audit_row = db.execute('SELECT value FROM state WHERE key=?', (AUDIT+audit_id,)).fetchone()
        audit = json.loads(audit_row[0]) if audit_row else {}
        if (value['version'] != 1 or value.get('fingerprint_version') != FINGERPRINT_VERSION
                or audit.get('fingerprint_version') != FINGERPRINT_VERSION
                or not isinstance(audit_id,str) or not re.fullmatch('[a-f0-9]{64}',audit_id)
                or type(value['reviewed_at']) not in (int,float) or not math.isfinite(value['reviewed_at'])
                or value['database'] != database_binding(db)
                or value['binding'] != digest([owner,key])
                or audit.get('plan_sha256') != audit_id
                or audit.get('mode') != value['mode'] or audit.get('database') != value['database']
                or audit.get('reviewed_at') != value['reviewed_at']
                or value['entry'] not in audit.get('entries', [])):
            raise ValueError('Review binding unavailable')
        entry = value['entry']
        if entry['binding'] != value['binding'] or entry['fingerprint'] != value['fingerprint']:
            raise ValueError('Review evidence unavailable')
        result.update(reviewed_at=value['reviewed_at'], audit_id=audit_id)
        if value['mode'] == 'reopen':
            result['classification'] = 'reopened_explicitly'
        elif value['mode'] != 'acknowledge_known_history':
            raise ValueError('Unknown review mode')
        elif fingerprint(db, owner, key) != value['fingerprint']:
            result['classification'] = 'reopened_evidence_changed'
        else:
            result.update(classification='known_historical_unverifiable',
                          requires_attention=False, repeat_alert_eligible=False)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, sqlite3.Error):
        result.update(classification='review_unverifiable', requires_attention=True, repeat_alert_eligible=True)
    return result


def prepare(db, owner, keys, *, mode='acknowledge_known_history', evidence_ref=None):
    if (not isinstance(owner,str) or not owner or mode not in MODES
            or not isinstance(keys,list) or not 1 <= len(keys) <= MAX_CASES
            or any(not isinstance(k,str) or not 1 <= len(k) <= 512 for k in keys)
            or len(keys) != len(set(keys))
            or evidence_ref is not None and (not isinstance(evidence_ref,str) or not re.fullmatch('[a-f0-9]{64}', evidence_ref))):
        raise ValueError('Explicit owner, unique exact keys and review mode required')
    if not db.in_transaction:
        db.execute('BEGIN')
    if db.execute('PRAGMA user_version').fetchone()[0] != 8:
        raise ValueError('Schema 8 is required; no automatic migration')
    cases = []
    for key in keys:
        raw = _current(db, owner, key)
        if mode == 'reopen' and raw is None:
            raise ValueError('No prior review to reopen')
        cases.append({'key':key, 'fingerprint':fingerprint(db,owner,key), 'prior_review':digest(raw)})
    return {'format':FORMAT, 'database':database_binding(db), 'owner':owner,
            'mode':mode, 'prepared_at':time.time(), 'evidence_ref':evidence_ref, 'cases':cases}


def apply(db, plan, expected_sha256):
    """Caller commits/rolls back; all predicates verified before metadata writes."""
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    if (not isinstance(plan,dict) or set(plan) != {'format','database','owner','mode','prepared_at','evidence_ref','cases'}
            or plan.get('format') != FORMAT or digest(plan) != expected_sha256
            or not isinstance(expected_sha256,str) or not re.fullmatch('[a-f0-9]{64}',expected_sha256)
            or plan.get('database') != database_binding(db)
            or plan.get('mode') not in MODES or not isinstance(plan.get('owner'),str) or not plan['owner']
            or type(plan.get('prepared_at')) not in (int,float) or not math.isfinite(plan['prepared_at'])
            or not isinstance(plan.get('cases'),list) or not 1 <= len(plan['cases']) <= MAX_CASES
            or plan['evidence_ref'] is not None and (not isinstance(plan['evidence_ref'],str)
                or not re.fullmatch('[a-f0-9]{64}',plan['evidence_ref']))):
        raise ValueError('Exact reviewed plan for this database is required')
    existing = db.execute('SELECT value FROM state WHERE key=?', (AUDIT+expected_sha256,)).fetchone()
    if existing:
        # Do not overwrite new evidence/reopening by reapplying an old plan.
        return {'state':'already_applied', 'plan_sha256':expected_sha256}
    if db.execute('PRAGMA user_version').fetchone()[0] != 8:
        raise ValueError('Schema 8 is required; no automatic migration')
    seen, entries = set(), []
    for case in plan['cases']:
        if (not isinstance(case,dict) or set(case) != {'key','fingerprint','prior_review'}
                or not isinstance(case['key'],str) or not 1 <= len(case['key']) <= 512 or case['key'] in seen):
            raise ValueError('Unique exact case identities required')
        key = case['key']; seen.add(key)
        if (case['fingerprint'] != fingerprint(db,plan['owner'],key)
                or case['prior_review'] != digest(_current(db,plan['owner'],key))):
            raise ValueError('Action evidence or prior review changed; prepare a new plan')
        if plan['mode'] == 'reopen' and _current(db,plan['owner'],key) is None:
            raise ValueError('No prior review to reopen')
        entries.append({'binding':digest([plan['owner'],key]), 'fingerprint':case['fingerprint']})
    now = time.time()
    audit = {'version':1, 'fingerprint_version':FINGERPRINT_VERSION,
             'plan_sha256':expected_sha256, 'mode':plan['mode'],
             'database':plan['database'], 'reviewed_at':now,
             'evidence_ref':plan['evidence_ref'], 'entries':entries,
             'original_outcomes_changed':False}
    db.execute('INSERT INTO state VALUES(?,?)', (AUDIT+expected_sha256, encoded(audit)))
    for case, entry in zip(plan['cases'], entries):
        value = {'version':1,'fingerprint_version':FINGERPRINT_VERSION,
                 'database':plan['database'],'binding':entry['binding'],
                 'fingerprint':case['fingerprint'],'mode':plan['mode'],'reviewed_at':now,
                 'audit_id':expected_sha256,'entry':entry}
        db.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                   (_key(plan['owner'],case['key']), encoded(value)))
    return {'state':'applied','plan_sha256':expected_sha256,'count':len(entries),'original_outcomes_changed':False}
