"""A local, durable coordinator for native-tool and browser QA steps.

This module cannot contact WhatsApp. A caller obtains a single instruction,
executes it through its authorized native tool/browser, then records evidence.
An interrupted mutation is never returned as a fresh send. All run files belong
under the ignored work directory; public reports contain no private IDs/content.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time

from .schema_cases import canonical


READ_TOOLS = {'get_profile', 'connection_status', 'get_capabilities', 'get_operation_schema',
              'list_chats', 'list_contacts', 'search_messages', 'read_conversation',
              'get_message', 'get_send_status', 'get_history_sync', 'list_account_events',
              'get_account_event', 'read_whatsapp'}
MUTATION_TOOLS = {'send_text', 'write_whatsapp', 'send_media', 'prepare_file', 'get_attachment',
                  'get_transfer_status', 'start_history_sync', 'control_history_sync',
                  'sync_chat', 'list_live_chats', 'check_event_authorization'}
SEND_TOOLS = {'send_text', 'write_whatsapp', 'send_media', 'start_history_sync'}
DM_ACTIONS = {'chats_edit_message', 'messages_set_reaction'}
MEDIA_ACTIONS = {'messages_send_image', 'messages_send_video', 'messages_send_voice',
                 'messages_send_file', 'messages_send_sticker'}
GROUP_ACTIONS = {'groups_set_subject', 'groups_set_description', 'groups_add_participants'}
POLL_TOOLS = READ_TOOLS | {'get_transfer_status'}
PRIVATE_KEYS = {'token', 'secret', 'password', 'authorization', 'cookie', 'api_key', 'apikey',
                'download_url', 'url', 'directpath', 'mediakey', 'credentials'}
FINAL = {'PASS', 'FAIL', 'BLOCKED', 'NOT_SUPPORTED', 'NOT_APPLICABLE'}


class NotReady(ValueError):
    pass


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def extends_binding(previous, current):
    """Permit newly discovered fields without replacing any recorded identity."""
    if isinstance(previous, dict) and isinstance(current, dict):
        return all(key in current and extends_binding(value, current[key])
                   for key, value in previous.items())
    return type(previous) is type(current) and previous == current


def lookup(value, path):
    if path in ('', '/'):
        return value
    current = value
    for part in path.strip('/').split('/'):
        part = part.replace('~1', '/').replace('~0', '~')
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current


def resolve(value, context):
    if isinstance(value, dict):
        if set(value) == {'$ref'}:
            try:
                return copy.deepcopy(lookup(context, value['$ref']))
            except (KeyError, IndexError, ValueError, TypeError):
                raise NotReady('Missing binding: ' + value['$ref']) from None
        if set(value) == {'$text'}:
            return ''.join(str(resolve(part, context)) for part in value['$text'])
        return {key: resolve(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve(item, context) for item in value]
    return value


def scrub(value):
    """Retain useful private run evidence, excluding authentication and links."""
    if isinstance(value, dict):
        return {key: scrub(item) for key, item in value.items() if key.lower() not in PRIVATE_KEYS}
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, str) and (value.startswith(('https://', 'http://'))):
        return '[URL omitted]'
    return value


def structured(result):
    if not isinstance(result, dict):
        raise ValueError('Expected a tool/browser result object')
    if result.get('isError'):
        raise ValueError('Native tool returned isError')
    if 'structuredContent' in result:
        value = result['structuredContent']
    elif 'content' in result:
        blocks = [block['text'] for block in result['content'] if block.get('type') == 'text']
        if len(blocks) != 1:
            raise ValueError('No unambiguous structured result')
        value = json.loads(blocks[0])
    else:
        value = result
    if not isinstance(value, dict):
        raise ValueError('Expected structured object evidence')
    return value


def assertions(observed, checks):
    errors = []
    for check in checks:
        try:
            actual = lookup(observed, check['path'])
        except (KeyError, IndexError, TypeError, ValueError):
            if check['op'] != 'absent':
                errors.append(check['path'] + ': missing')
            continue
        op, expected = check['op'], check.get('value')
        if op == 'equals':
            valid = type(actual) is type(expected) and actual == expected
        elif op == 'contains':
            valid = isinstance(actual, (str, list)) and expected in actual
        elif op == 'nonempty':
            valid = bool(actual)
        elif op == 'one_of':
            valid = any(type(actual) is type(item) and actual == item for item in expected)
        elif op == 'absent':
            valid = False  # Absence is handled explicitly below.
        else:
            raise ValueError('Unknown assertion: ' + op)
        if not valid:
            errors.append(check['path'] + ': ' + op + ' failed')
    return errors


def validate_manifest(manifest):
    if manifest.get('version') != 1 or not isinstance(manifest.get('steps'), list):
        raise ValueError('Unsupported campaign manifest')
    seen = set()
    for step in manifest['steps']:
        identifier = step.get('id', '')
        if not re.fullmatch('[a-z0-9][a-z0-9_-]{0,79}', identifier) or identifier in seen:
            raise ValueError('Invalid or duplicate step ID')
        if not set(step.get('depends_on', ())) <= seen:
            raise ValueError('Dependencies must reference earlier steps')
        seen.add(identifier)
        if step['executor'] not in {'native', 'browser', 'human'}:
            raise ValueError('Unknown executor')
        if step['executor'] == 'native' and step['tool'] not in READ_TOOLS | MUTATION_TOOLS:
            raise ValueError('Unknown native tool')
        if step['executor'] == 'human' and not step.get('instruction'):
            raise ValueError('Human step needs a concrete instruction')
        if not step.get('assertions'):
            raise ValueError('Every step requires explicit evidence assertions')
        if step.get('effect') not in {'read', 'write', 'human'}:
            raise ValueError('Every step must declare its effect')
        if step['executor'] == 'native' and step['tool'] in MUTATION_TOOLS and step['effect'] != 'write':
            raise ValueError('Mutating tool cannot be relabeled as read-only')
        if step['executor'] == 'browser' and step.get('action') not in {'inspect', 'verify_identity'} and step['effect'] != 'write':
            raise ValueError('Opening/reading a chat can send receipts; it requires live scope')
    return manifest


class Journal:
    def __init__(self, path):
        self.path = Path(path)
        if not self.path.is_file():
            raise ValueError('Campaign journal does not exist')
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA busy_timeout=10000')

    @classmethod
    def create(cls, path, manifest, bindings=None, *, run_id=None):
        validate_manifest(manifest)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation avoids accidentally resetting another campaign.
        with path.open('xb'):
            pass
        run_id = run_id or 'qa-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + digest(str(path))[:6]
        if not re.fullmatch('[A-Za-z0-9_-]{8,64}', run_id):
            path.unlink()
            raise ValueError('Invalid run ID')
        journal = cls(path)
        journal.db.executescript('''
            CREATE TABLE run (id TEXT PRIMARY KEY, manifest TEXT NOT NULL, manifest_hash TEXT NOT NULL,
                bindings TEXT NOT NULL, live INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL);
            CREATE TABLE step (id TEXT PRIMARY KEY, position INTEGER UNIQUE, specification TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'PENDING', instruction TEXT, instruction_hash TEXT,
                evidence TEXT, errors TEXT, issued REAL, updated REAL, polls INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE audit (sequence INTEGER PRIMARY KEY, at REAL, step_id TEXT, action TEXT, detail TEXT);
        ''')
        journal.db.execute('INSERT INTO run VALUES (?,?,?,?,0,?)',
                           (run_id, canonical(manifest), digest(manifest), canonical(bindings or {}), time.time()))
        for position, step in enumerate(manifest['steps']):
            journal.db.execute('INSERT INTO step(id,position,specification) VALUES (?,?,?)',
                               (step['id'], position, canonical(step)))
        return journal

    def close(self):
        self.db.close()

    def audit(self, step, action, detail):
        self.db.execute('INSERT INTO audit(at,step_id,action,detail) VALUES (?,?,?,?)',
                        (time.time(), step, action, canonical(scrub(detail))))

    def bind(self, name, value):
        if not re.fullmatch('[a-z][a-z0-9_]{0,63}', name):
            raise ValueError('Invalid binding name')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row = self.db.execute('SELECT bindings FROM run').fetchone()
            bindings = json.loads(row['bindings'])
            if name in bindings and not extends_binding(bindings[name], value):
                raise ValueError('Existing binding is immutable; start a new run for a different identity')
            bindings[name] = value
            self.db.execute('UPDATE run SET bindings=?', (canonical(bindings),))
            self.audit(None, 'bind', {'name': name, 'value_hash': digest(value)})
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def enable_live(self, authorization):
        if not isinstance(authorization, str) or not authorization.strip():
            raise ValueError('Record the current user mandate before enabling live steps')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.audit(None, 'live_scope_enabled', {'user_mandate': authorization})
            self.db.execute('UPDATE run SET live=1')
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def context(self):
        run = self.db.execute('SELECT * FROM run').fetchone()
        captured = {}
        for row in self.db.execute("SELECT id,specification,evidence FROM step WHERE state='PASS'"):
            result = json.loads(row['evidence'])
            specification = json.loads(row['specification'])
            captured[row['id']] = {name: lookup(result, path) for name, path in specification.get('capture', {}).items()}
        return {'run_id': run['id'], 'bindings': json.loads(run['bindings']), 'steps': captured}

    def _instruction(self, specification, context):
        instruction = resolve(specification, context)
        tool = instruction.get('tool')
        if tool in SEND_TOOLS:
            arguments = instruction.setdefault('arguments', {})
            key = 'qa_' + digest([context['run_id'], specification['id']])[:48]
            if 'idempotency_key' in arguments and arguments['idempotency_key'] != key:
                raise ValueError('Idempotency key is assigned by the journal')
            arguments['idempotency_key'] = key
        if tool in {'read_whatsapp', 'write_whatsapp', 'send_media'}:
            from sally_whatsapp.operations import OPERATIONS
            operation = OPERATIONS[instruction['arguments']['operation']]
            if tool == 'read_whatsapp' and not operation['readonly']:
                raise ValueError('A mutation cannot use the read tool')
        if instruction.get('effect') == 'write' and instruction.get('executor') == 'native':
            if tool not in {'send_text', 'write_whatsapp', 'prepare_file', 'get_transfer_status', 'send_media'}:
                raise NotReady('This mutation needs a dedicated fixture and reconciliation adapter')
            arguments = instruction['arguments']
            if tool == 'prepare_file' and arguments.get('file') not in context['bindings'].get('fixture_files', []):
                raise ValueError('Only explicitly registered generated fixture files may be staged')
            if tool in {'send_media', 'get_transfer_status'}:
                transfers = {values['transfer_id'] for values in context['steps'].values() if 'transfer_id' in values}
                if arguments.get('transfer_id') not in transfers:
                    raise ValueError('Transfer must have been captured by this campaign')
            if tool == 'send_media' and arguments.get('operation') not in MEDIA_ACTIONS:
                raise ValueError('Only test-chat media sends are enabled')
            if tool == 'write_whatsapp':
                operation_name = arguments['operation']
                if operation_name not in DM_ACTIONS | GROUP_ACTIONS | {'groups_create_group'}:
                    raise NotReady('Only the prepared direct-message actions are enabled in this recipe')
                if operation_name == 'groups_create_group':
                    body = arguments.get('arguments', {}).get('body', {})
                    if not body.get('name', '').startswith('QA ' + context['run_id']):
                        raise ValueError('A new test group requires the campaign marker')
                    members = [p.get('id') for p in body.get('participants', [])]
                    if not members or not set(members) <= set(instruction.get('destinations', [])):
                        raise ValueError('Group members must be explicitly allowed test destinations')
                if operation_name in GROUP_ACTIONS:
                    created = {v['created_group_id'] for v in context['steps'].values() if 'created_group_id' in v}
                    if arguments.get('arguments', {}).get('path', {}).get('id') not in created:
                        raise ValueError('Group edits must target a group created by this campaign')
                if operation_name == 'groups_add_participants':
                    members = [p.get('id') for p in arguments.get('arguments', {}).get('body', {}).get('participants', [])]
                    allowed_members = set(context['bindings'].get('allowed_chat_ids', []))
                    if not members or not set(members) <= allowed_members or not set(members) <= set(instruction.get('destinations', [])):
                        raise ValueError('New members must be explicitly allowed test destinations')
                known_messages = {values['message_id'] for values in context['steps'].values()
                                  if 'message_id' in values}
                operation_arguments = arguments['arguments']
                for container in (operation_arguments.get('path', {}), operation_arguments.get('body', {})):
                    if 'messageId' in container and container['messageId'] not in known_messages:
                        raise ValueError('Mutation must reference a message captured by this campaign')
        allowed = set(context['bindings'].get('allowed_chat_ids', []))
        allowed.update(v['created_group_id'] for v in context['steps'].values()
                       if isinstance(v.get('created_group_id'), str) and v['created_group_id'].endswith('@g.us'))
        if instruction.get('effect') == 'write':
            scopes = instruction.get('destinations', [])
            if not scopes or not set(scopes) <= allowed:
                raise NotReady('The live step requires exact, registered test destinations')
            arguments = instruction.get('arguments', {})
            direct = []
            for container in (arguments, arguments.get('arguments', {}).get('body', {}),
                              arguments.get('arguments', {}).get('path', {})):
                for key in ('chat_id', 'chatId', 'contactId'):
                    if key in container:
                        direct.append(container[key])
            if 'chat_ids' in arguments:
                direct.extend(arguments['chat_ids'] or [])
                if not arguments['chat_ids']:
                    raise ValueError('Whole-account history imports are not QA fixtures')
            if any(destination not in allowed or destination not in scopes for destination in direct):
                raise ValueError('Instruction payload targets a destination outside the declared scope')
        return instruction

    def next(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            run = self.db.execute('SELECT * FROM run').fetchone()
            rows = self.db.execute('SELECT * FROM step ORDER BY position').fetchall()
            states = {row['id']: row['state'] for row in rows}
            for row in rows:
                if row['state'] in {'IN_FLIGHT', 'WAITING', 'UNCERTAIN'}:
                    original = json.loads(row['instruction'])
                    if row['state'] == 'WAITING' and time.time() < row['updated'] + original.get('poll_seconds', 2):
                        self.db.execute('COMMIT')
                        return {'status': 'wait', 'step_id': row['id'], 'seconds': original.get('poll_seconds', 2)}
                    if original.get('tool') in POLL_TOOLS:
                        if row['polls'] >= original.get('max_polls', 20) or time.time() - row['issued'] > 600:
                            self.db.execute("UPDATE step SET state='FAIL',errors=? WHERE id=?",
                                            (canonical(['Read condition timed out; no mutation retried']), row['id']))
                            self.db.execute('COMMIT')
                            return {'status': 'read_timeout', 'step_id': row['id']}
                        self.db.execute('UPDATE step SET polls=polls+1 WHERE id=?', (row['id'],))
                        self.db.execute('COMMIT')
                        return {**original, 'status': 'observe', 'step_id': row['id'], 'resend': False}
                    if original.get('tool') in {'send_text', 'write_whatsapp', 'send_media'}:
                        if row['polls'] >= 20 or time.time() - row['issued'] > 600:
                            self.db.execute('COMMIT')
                            return {'status': 'needs_reconciliation', 'step_id': row['id'], 'resend': False}
                        self.db.execute('UPDATE step SET polls=polls+1 WHERE id=?', (row['id'],))
                        self.db.execute('COMMIT')
                        return {'status': 'observe', 'step_id': row['id'], 'executor': 'native',
                                'tool': 'get_send_status', 'arguments': {'idempotency_key': original['arguments']['idempotency_key']},
                                'resend': False}
                    self.db.execute('COMMIT')
                    return {'status': 'needs_reconciliation', 'step_id': row['id'], 'resend': False}
                if row['state'] != 'PENDING':
                    continue
                spec = json.loads(row['specification'])
                if any(states[dependency] != 'PASS' for dependency in spec.get('depends_on', [])):
                    continue
                if spec['effect'] != 'read' and not run['live']:
                    self.db.execute('COMMIT')
                    return {'status': 'prepared', 'step_id': row['id'], 'reason': 'live_scope_not_enabled'}
                try:
                    instruction = self._instruction(spec, self.context())
                except NotReady as error:
                    self.db.execute('COMMIT')
                    return {'status': 'needs_binding', 'step_id': row['id'], 'reason': str(error)}
                self.db.execute("UPDATE step SET state='IN_FLIGHT',instruction=?,instruction_hash=?,issued=?,updated=? WHERE id=?",
                                (canonical(instruction), digest(instruction), time.time(), time.time(), row['id']))
                self.audit(row['id'], 'issued_once', {'instruction_hash': digest(instruction)})
                self.db.execute('COMMIT')
                return {'status': 'execute_once', 'step_id': row['id'], **instruction}
            self.db.execute('COMMIT')
            return {'status': 'complete' if all(state in FINAL for state in states.values()) else 'waiting_dependencies',
                    'states': states}
        except BaseException:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            raise

    def record(self, step_id, raw_result):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row = self.db.execute('SELECT * FROM step WHERE id=?', (step_id,)).fetchone()
            if row is None or row['state'] not in {'IN_FLIGHT', 'WAITING', 'UNCERTAIN'}:
                raise ValueError('No issued instruction awaits this evidence')
            instruction = json.loads(row['instruction'])
            try:
                result = structured(raw_result)
                errors = []
            except (ValueError, TypeError, json.JSONDecodeError):
                result, errors = {'tool_error': True}, ['Tool returned an error or unusable result']
            state = 'FAIL' if errors else 'PASS'
            if instruction.get('tool') in {'send_text', 'write_whatsapp', 'send_media'} and not errors:
                outcome = result.get('state')
                if outcome in {'queued', 'sending'}:
                    state = 'WAITING'
                elif outcome in {'uncertain', 'not_found'}:
                    state = 'UNCERTAIN'
                elif outcome != 'submitted':
                    state, errors = 'FAIL', ['Action was not submitted']
            if state == 'PASS':
                errors = assertions(result, instruction['assertions'])
                for name, path in instruction.get('capture', {}).items():
                    try:
                        lookup(result, path)
                    except (KeyError, TypeError, IndexError):
                        errors.append('Missing capture: ' + name)
                if errors:
                    state = 'WAITING' if instruction.get('tool') in POLL_TOOLS and instruction.get('retry_read') else 'FAIL'
            if state == 'PASS' and result.get('delivery', {}).get('scope') == 'group_partial':
                # Nothing in a campaign can promote observed partial evidence.
                if any(check.get('value') == 'all_recipients' for check in instruction['assertions']):
                    state, errors = 'FAIL', ['Group delivery remains partial']
            self.db.execute('UPDATE step SET state=?,evidence=?,errors=?,updated=? WHERE id=?',
                            (state, canonical(scrub(result)), canonical(errors), time.time(), step_id))
            self.audit(step_id, 'evidence', {'state': state, 'evidence_hash': digest(scrub(result))})
            self.db.execute('COMMIT')
            return {'step_id': step_id, 'state': state, 'errors': errors}
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def report(self):
        run = self.db.execute('SELECT * FROM run').fetchone()
        steps = []
        for row in self.db.execute('SELECT * FROM step ORDER BY position'):
            spec = json.loads(row['specification'])
            steps.append({'id': row['id'], 'state': row['state'], 'executor': spec['executor'],
                          'coverage': spec.get('coverage', []), 'errors': json.loads(row['errors'] or '[]')})
        return {'run_id': run['id'], 'manifest_hash': run['manifest_hash'], 'live_enabled': bool(run['live']),
                'steps': steps, 'all_passed': bool(steps) and all(step['state'] == 'PASS' for step in steps)}
