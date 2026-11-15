"""Opt-in local, finite WhatsApp administration broker.

No service or permission is installed by this module. A separate administrator
must admit its source closure, policy, socket directory and private journal.
The web process supplies an approval ID, never a command, path or credential.
"""
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timezone
import argparse
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import signal
import socket
import socketserver
import sqlite3
import stat
import struct
import subprocess
import sys
import time

FORMAT = 'whatsapp-web-administration-v1'
MAX_FRAME = 65536
MAX_FILE = 4 * 1024 * 1024
ACTIONS = frozenset(('instance.allocate', 'instance.prepare', 'instance.activate',
                     'instance.cancel', 'release.preview', 'release.activate',
                     'backup.create', 'backup.restore'))
TRUST_ROOT = Path('/')
TRUST_UID = 0


class Rejected(ValueError):
    def __init__(self, code='BROKER_INPUT_REJECTED'):
        self.code = code
        super().__init__(code)


def require(ok, code='BROKER_INPUT_REJECTED'):
    if not ok:
        raise Rejected(code)


def hexid(value, size=32):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{%d}' % size, value) is not None


def slug(value):
    return isinstance(value, str) and re.fullmatch('[a-z][a-z0-9-]{0,47}', value) is not None


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def decode(value):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            require(key not in result)
            result[key] = item
        return result
    def bad_constant(value):
        raise Rejected()
    return json.loads(value, object_pairs_hook=unique, parse_constant=bad_constant)


def now():
    return datetime.now(timezone.utc).isoformat()


def protected(path, *, directory=False, private=False):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve(strict=True), 'BROKER_UNTRUSTED_PATH')
    try:
        relative = path.relative_to(TRUST_ROOT)
    except ValueError:
        raise Rejected('BROKER_UNTRUSTED_PATH') from None
    current = TRUST_ROOT
    for index, part in enumerate(('', *relative.parts)):
        if part:
            current /= part
        info = current.lstat()
        kind = stat.S_ISDIR if directory or index < len(relative.parts) else stat.S_ISREG
        require(kind(info.st_mode) and info.st_uid == TRUST_UID and not info.st_mode & 0o022,
                'BROKER_UNTRUSTED_PATH')
        if index == len(relative.parts) and private:
            require(not info.st_mode & 0o077, 'BROKER_UNTRUSTED_PATH')
    return path


def read(path, *, private=False):
    path = protected(path, private=private)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_FILE)
        value = stream.read(MAX_FILE + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(len(value) <= MAX_FILE and identity(before) == identity(after) == identity(path.lstat()))
    return value


def artifact(value):
    require(isinstance(value, dict) and set(value) == {'path', 'sha256'} and hexid(value['sha256'], 64))
    content = read(value['path'], private=True)
    require(digest(content) == value['sha256'], 'BROKER_ARTIFACT_CHANGED')
    return content


def validate_owner(owner):
    require(isinstance(owner, dict) and set(owner) == {'protocol', 'epoch', 'state', 'generation', 'manifest_sha256'})
    require(type(owner['protocol']) is int and owner['protocol'] == 1 and hexid(owner['epoch'])
            and owner['state'] == 'dedicated' and hexid(owner['manifest_sha256'], 64)
            and isinstance(owner['generation'], str) and Path(owner['generation']).is_absolute())


def restore_marker_present(configuration, *, allow_missing_parent=False):
    parent = Path(configuration)
    try:
        require(parent.is_absolute() and parent.resolve(strict=False) == parent,
                'BROKER_RESTORE_RECONCILIATION_REQUIRED')
        try:
            info = parent.lstat()
        except FileNotFoundError:
            require(allow_missing_parent, 'BROKER_RESTORE_RECONCILIATION_REQUIRED')
            return False
        require(stat.S_ISDIR(info.st_mode), 'BROKER_RESTORE_RECONCILIATION_REQUIRED')
        try:
            (parent / 'restore-maintenance.json').lstat()
        except FileNotFoundError:
            return False
    except OSError:
        raise Rejected('BROKER_RESTORE_RECONCILIATION_REQUIRED') from None
    return True


def source_files(project):
    result = {}
    for folder in ('scripts', 'sally_whatsapp', 'deploy'):
        root = protected(project / folder, directory=True)
        for path in root.rglob('*'):
            require(not path.is_symlink(), 'BROKER_SOURCE_CHANGED')
            if path.suffix in ('.pyc', '.pyo') or path.name == '__pycache__':
                raise Rejected('BROKER_SOURCE_BYTECODE')
            if path.is_file():
                result[path.relative_to(project).as_posix()] = digest(read(path))
    return result


def runtime_interpreter(project):
    """Admit Python startup imports before running the privileged worker."""
    project = protected(project, directory=True)
    venv = protected((project / '.venv').resolve(strict=True), directory=True)
    require(not project.is_relative_to(venv), 'BROKER_RUNTIME_UNTRUSTED')
    configuration = {}
    for line in read(venv / 'pyvenv.cfg').decode().splitlines():
        key, delimiter, value = line.partition('=')
        require(delimiter and key.strip() not in configuration, 'BROKER_RUNTIME_UNTRUSTED')
        configuration[key.strip()] = value.strip()
    require(configuration.get('include-system-site-packages') == 'false', 'BROKER_RUNTIME_UNTRUSTED')
    interpreter = venv / 'bin/python'
    protected(interpreter.parent, directory=True)
    protected(interpreter.resolve(strict=True))
    # Dispatch admits the project root on sys.path too. Every directory can
    # be a namespace package, including work/private; no writable subtree is
    # silently excluded from the import closure. Operational data belong in
    # the separate instance layout. Inspect metadata, not those data contents.
    roots = [project] if venv.is_relative_to(project) else [project, venv]
    count = 0
    for root in roots:
        for item in root.rglob('*'):
            count += 1
            require(count <= 100000, 'BROKER_RUNTIME_UNTRUSTED')
            selected = item.resolve(strict=True)
            protected(selected, directory=selected.is_dir())
            # rglob does not follow directory links. Admit only targets in a
            # fully scanned root, including a release's separate venv root.
            if selected.is_dir():
                require(any(selected.is_relative_to(root) for root in roots), 'BROKER_RUNTIME_UNTRUSTED')
            if item.suffix == '.pth':
                for line in read(selected).decode().splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    require(not line.startswith(('import ', 'import\t')), 'BROKER_RUNTIME_UNTRUSTED')
                    location = (item.parent / line).resolve(strict=True)
                    require(location.is_relative_to(venv), 'BROKER_RUNTIME_UNTRUSTED')
                    protected(location, directory=True)
    return interpreter


def validate_policy(value):
    fields = {'format', 'enabled', 'project', 'installation_sha256', 'owner', 'sources',
              'state_directory', 'socket', 'socket_gid', 'principals', 'approvals'}
    require(isinstance(value, dict) and set(value) == fields and value['format'] == FORMAT)
    require(type(value['enabled']) is bool and value['enabled'], 'BROKER_DISABLED')
    require(hexid(value['installation_sha256'], 64))
    validate_owner(value['owner'])
    for key in ('project', 'state_directory', 'socket'):
        require(isinstance(value[key], str) and Path(value[key]).is_absolute()
                and '..' not in Path(value[key]).parts)
    project = Path(value['project'])
    # The ledger must not be reverted by an instance backup or source update.
    require(not Path(value['state_directory']).is_relative_to(project)
            and not project.is_relative_to(Path(value['state_directory'])))
    require(str(value['socket']).startswith('/run/') and type(value['socket_gid']) is int
            and value['socket_gid'] >= 0)
    require(isinstance(value['sources'], dict) and value['sources']
            and all(hexid(v, 64) for v in value['sources'].values()))
    require(isinstance(value['principals'], list) and 0 < len(value['principals']) <= 64)
    identities = set()
    for principal in value['principals']:
        require(isinstance(principal, dict) and set(principal) == {
            'uid', 'owner', 'instance', 'targets', 'operations', 'global_admin'})
        require(type(principal['uid']) is int and principal['uid'] > 0
                and isinstance(principal['owner'], str) and 0 < len(principal['owner']) <= 512
                and slug(principal['instance']) and type(principal['global_admin']) is bool)
        # One UID is one web principal. A UID cannot assert a different tenant.
        require(principal['uid'] not in identities)
        identities.add(principal['uid'])
        require(isinstance(principal['targets'], list) and 0 < len(principal['targets']) <= 128
                and all(slug(item) for item in principal['targets'])
                and len(set(principal['targets'])) == len(principal['targets']))
        require(isinstance(principal['operations'], list) and principal['operations']
                and set(principal['operations']) <= ACTIONS
                and len(set(principal['operations'])) == len(principal['operations']))
    require(isinstance(value['approvals'], dict) and len(value['approvals']) <= 512)
    for identifier, approval in value['approvals'].items():
        require(hexid(identifier) and isinstance(approval, dict) and set(approval) - {'recovers'} == {
            'uid', 'operation', 'target', 'scope', 'affected_instances', 'description', 'expires', 'parameters'}
            and ('recovers' not in approval or hexid(approval['recovers'])))
        require(approval['uid'] in identities and approval['operation'] in ACTIONS
                and isinstance(approval['description'], str) and 0 < len(approval['description']) <= 256
                and bool(approval['description'].strip())
                and type(approval['expires']) in (int, float) and 0 < approval['expires'] < 253402300799)
        affected = approval['affected_instances']
        require(isinstance(affected, list) and 0 < len(affected) <= 128 and all(slug(item) for item in affected)
                and affected == sorted(set(affected)))
        if approval['operation'].startswith('release.'):
            require(approval['scope'] == 'installation' and approval['target'] == 'installation')
        else:
            require(approval['scope'] == 'instance' and slug(approval['target'])
                    and affected == [approval['target']])
        validate_parameters(approval)
    return value


def validate_parameters(approval):
    p = approval['parameters']
    op = approval['operation']
    require(isinstance(p, dict))
    if op == 'instance.allocate':
        require(set(p) == {'plan', 'source_checkout'} and isinstance(p['source_checkout'], str)
                and Path(p['source_checkout']).is_absolute())
    elif op == 'backup.restore':
        require(set(p) == {'plan'})
    elif op == 'instance.prepare':
        require(set(p) == {'entry', 'attempt_id', 'host_plan', 'setup'}
                and p['entry'] in ('provision', 'add') and hexid(p['attempt_id'])
                and isinstance(p['setup'], dict))
        required = {'name', 'hostname', 'issuer', 'jwks_url', 'subject', 'oauth_client_id',
                    'link_client_id', 'chatgpt_callback', 'auth_mode'}
        require(set(p['setup']) == required and p['setup']['auth_mode'] == 'external-oidc'
                and all(isinstance(v, str) and 0 < len(v) <= 2048 for v in p['setup'].values()))
    elif op == 'instance.activate':
        require(set(p) == {'host_plan', 'capabilities'} and p['capabilities'] in ('full', 'read-only'))
    elif op == 'instance.cancel':
        require(set(p) == {'host_plan', 'attempt_id'} and hexid(p['attempt_id']))
    elif op.startswith('release.'):
        require(set(p) == {'request'})
    else:
        require(op == 'backup.create' and not p)
    for key in ('plan', 'host_plan', 'request'):
        if key in p:
            item = p[key]
            require(isinstance(item, dict) and set(item) == {'path', 'sha256'}
                    and isinstance(item['path'], str) and Path(item['path']).is_absolute()
                    and hexid(item['sha256'], 64))


def validate_recovery(current, previous, *, origin_prepare=None):
    require(current['target'] == previous['target'] and current['uid'] == previous['uid']
            and current['affected_instances'] == previous['affected_instances'], 'BROKER_RECOVERY_MISMATCH')
    if previous['operation'] == 'backup.restore':
        require(current['operation'] == 'backup.restore' and current['parameters'] == previous['parameters'],
                'BROKER_RECOVERY_MISMATCH')
    elif previous['operation'] == 'instance.cancel':
        if current['operation'] == 'instance.prepare':
            require(origin_prepare is not None and current['parameters'] == origin_prepare['parameters']
                    and {key: current['parameters'][key] for key in ('attempt_id', 'host_plan')} == previous['parameters'],
                    'BROKER_RECOVERY_MISMATCH')
        else:
            require(current['operation'] == 'instance.cancel' and current['parameters'] == previous['parameters'],
                    'BROKER_RECOVERY_MISMATCH')
    else:
        require(previous['operation'] == 'instance.prepare' and current['operation'] in ('instance.prepare', 'instance.cancel'),
                'BROKER_RECOVERY_MISMATCH')
        if current['operation'] == 'instance.prepare':
            require(current['parameters'] == previous['parameters'], 'BROKER_RECOVERY_MISMATCH')
        else:
            require(current['parameters'] == {key: previous['parameters'][key] for key in ('attempt_id', 'host_plan')},
                    'BROKER_RECOVERY_MISMATCH')


def owner_record(generation):
    return {'protocol': 1, 'epoch': generation.epoch, 'state': generation.state,
            'generation': str(generation.path), 'manifest_sha256': generation.manifest_sha256}


def authorize(policy, uid, envelope):
    require(isinstance(envelope, dict) and set(envelope) == {'version', 'method', 'owner', 'instance', 'request'}
            and type(envelope['version']) is int and envelope['version'] == 1
            and envelope['method'] in ('capabilities', 'status', 'execute')
            and isinstance(envelope['request'], dict))
    principal = next((item for item in policy['principals'] if item['uid'] == uid), None)
    require(principal is not None and envelope['owner'] == principal['owner']
            and envelope['instance'] == principal['instance'], 'BROKER_NOT_AUTHORIZED')
    return principal


def permitted(principal, approval):
    return (approval['uid'] == principal['uid'] and approval['operation'] in principal['operations']
            and set(approval['affected_instances']) <= set(principal['targets'])
            and (approval['scope'] != 'installation' or principal['global_admin']))


class Broker:
    def __init__(self, policy_path, *, executor=None, preflight=None):
        self.policy_path = Path(policy_path)
        self.executor = executor or self.execute_child
        self.preflight = preflight or self.check_installation
        self._policy_digest = None

    def policy(self):
        value = validate_policy(decode(read(self.policy_path, private=True)))
        identity = digest(encoded(value))
        require(self._policy_digest in (None, identity), 'BROKER_POLICY_RESTART_REQUIRED')
        self._policy_digest = identity
        return value

    @contextmanager
    def database(self, policy):
        state = protected(policy['state_directory'], directory=True, private=True)
        path = state / 'journal.sqlite'
        if path.exists() or path.is_symlink():
            protected(path, private=True)
            require(path.stat().st_nlink == 1)
        else:
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                # Another first reader may have created the journal since our
                # existence check. Apply the same checks as for an existing file.
                protected(path, private=True)
                require(path.stat().st_nlink == 1)
            else:
                os.close(fd)
            parent_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        connection = sqlite3.connect(path, timeout=5)
        try:
            path.chmod(0o600)
            connection.execute('PRAGMA journal_mode=DELETE')
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, uid INTEGER NOT NULL, owner TEXT NOT NULL, instance TEXT NOT NULL, approval TEXT UNIQUE NOT NULL, fingerprint TEXT NOT NULL, record TEXT NOT NULL, approval_json TEXT NOT NULL)')
            connection.commit()
            yield connection
        finally:
            connection.close()

    @contextmanager
    def execution_lock(self, policy):
        state = protected(policy['state_directory'], directory=True, private=True)
        path = state / 'execution.lock'
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == TRUST_UID
                    and not info.st_mode & 0o077)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Rejected('BROKER_BUSY') from None
            require((info.st_dev, info.st_ino) == (path.stat().st_dev, path.stat().st_ino))
            yield fd
        finally:
            os.close(fd)

    @staticmethod
    def visible(record):
        record = dict(record)
        if record['state'] == 'running':
            record['state'] = 'uncertain'
            record['error_code'] = 'BROKER_OUTCOME_UNVERIFIED'
        return record

    def handle(self, uid, envelope):
        try:
            policy = self.policy()
            principal = authorize(policy, uid, envelope)
            method, request = envelope['method'], envelope['request']
            if method == 'capabilities':
                require(not request)
                with self.database(policy) as db:
                    used = dict(db.execute('SELECT approval,id FROM requests'))
                    receipts = [self.visible(decode(row[0])) for row in db.execute(
                        'SELECT record FROM requests WHERE uid=? AND owner=? AND instance=? ORDER BY rowid DESC LIMIT 100',
                        (uid, principal['owner'], principal['instance']))]
                actions = []
                for identifier, approval in policy['approvals'].items():
                    if permitted(principal, approval) and approval['expires'] > time.time():
                        actions.append({key: approval[key] for key in
                                        ('operation', 'target', 'scope', 'affected_instances', 'description')} |
                                       {'approval': identifier, 'available': identifier not in used,
                                        **({'request_id': used[identifier]} if identifier in used else {})})
                result = {'actions': actions[:128], 'scope': 'delegated_only', 'receipts': receipts,
                          'actions_truncated': len(actions) > 128, 'receipts_truncated': len(receipts) == 100}
                while len(encoded(result)) > MAX_FRAME - 1024 and result['receipts']:
                    result['receipts'].pop()
                    result['receipts_truncated'] = True
                while len(encoded(result)) > MAX_FRAME - 1024 and result['actions']:
                    result['actions'].pop()
                    result['actions_truncated'] = True
            elif method == 'status':
                require(set(request) == {'id'} and hexid(request['id']))
                with self.database(policy) as db:
                    row = db.execute('SELECT record FROM requests WHERE id=? AND uid=? AND owner=? AND instance=?',
                                     (request['id'], uid, principal['owner'], principal['instance'])).fetchone()
                require(row is not None, 'BROKER_NOT_FOUND')
                result = self.visible(decode(row[0]))
            else:
                result = self.execute(policy, principal, request)
            return {'ok': True, 'result': result}
        except Rejected as exc:
            return {'ok': False, 'error_code': exc.code, 'message': 'Administration request not permitted.'}
        except Exception:
            return {'ok': False, 'error_code': 'BROKER_UNAVAILABLE', 'message': 'Administration status cannot be verified.'}

    def execute(self, policy, principal, request):
        require(set(request) == {'id', 'operation', 'target', 'arguments', 'confirmation'}
                and hexid(request['id']) and isinstance(request['arguments'], dict)
                and set(request['arguments']) == {'approval'} and hexid(request['arguments']['approval']))
        require(isinstance(request['operation'], str) and isinstance(request['target'], str)
                and request['confirmation'] == request['operation'] + ':' + request['target'])
        identifier = request['arguments']['approval']
        approval = policy['approvals'].get(identifier)
        require(approval is not None and permitted(principal, approval)
                and request['operation'] == approval['operation'] and request['target'] == approval['target'],
                'BROKER_NOT_AUTHORIZED')
        fingerprint = digest(encoded(request))
        with self.database(policy) as db:
            row = db.execute('SELECT uid,owner,instance,fingerprint,record FROM requests WHERE id=?', (request['id'],)).fetchone()
            if row:
                require(tuple(row[:4]) == (principal['uid'], principal['owner'], principal['instance'], fingerprint),
                        'BROKER_IDEMPOTENCY_CONFLICT')
                return self.visible(decode(row[4]))
        with self.execution_lock(policy) as lease:
            # Reload admission after acquiring the execution lease. A policy
            # replacement, revocation or changed closure cannot race dispatch.
            current = self.policy()
            require(current == policy, 'BROKER_POLICY_CHANGED')
            with self.database(policy) as db:
                db.execute('BEGIN IMMEDIATE')
                # The earlier read can race a preceding worker. Never turn an
                # existing request or consumed approval into a new rejection
                # receipt: its previous effects remain authoritative.
                row = db.execute('SELECT uid,owner,instance,fingerprint,record FROM requests WHERE id=?',
                                 (request['id'],)).fetchone()
                if row:
                    require(tuple(row[:4]) == (principal['uid'], principal['owner'], principal['instance'], fingerprint),
                            'BROKER_IDEMPOTENCY_CONFLICT')
                    return self.visible(decode(row[4]))
                used = db.execute('SELECT id FROM requests WHERE approval=?', (identifier,)).fetchone()
                require(used is None, 'BROKER_APPROVAL_CONSUMED')
                try:
                    # Only these read-only checks precede any durable execution
                    # intent. Database/commit failures and all later effects are
                    # deliberately outside this narrowly scoped rejection path.
                    require(approval['expires'] > time.time(), 'BROKER_APPROVAL_EXPIRED')
                    self.preflight(policy, approval)
                    outstanding = [(decode(row[0]), row[1], decode(row[2])) for row in db.execute(
                        'SELECT record,approval,approval_json FROM requests')
                        if decode(row[0])['state'] in ('running', 'uncertain') and not decode(row[0]).get('reconciled_by')]
                    if outstanding:
                        require(approval.get('recovers') in {row[1] for row in outstanding},
                                'BROKER_RECONCILIATION_REQUIRED')
                        origins = [item[2] for item in outstanding if item[2]['operation'] == 'instance.prepare']
                        origin = origins[0] if origins else None
                        for previous, previous_id, previous_approval in outstanding:
                            validate_recovery(approval, previous_approval, origin_prepare=origin)
                    else:
                        require('recovers' not in approval, 'BROKER_RECOVERY_NOT_REQUIRED')
                except Rejected as exc:
                    # This negative receipt is not persisted at the host. A
                    # lost reply remains uncertain; absence on status is never
                    # proof that a different or interrupted request did nothing.
                    return {'id': request['id'], 'operation': request['operation'], 'target': request['target'],
                            'approval': identifier, 'state': 'failed_before_execution',
                            'execution_phase': 'before_intent', 'error_code': exc.code,
                            'scope': approval['scope'], 'affected_instances': approval['affected_instances'],
                            'created_at': now(), 'updated_at': now()}
                record = {'id': request['id'], 'operation': request['operation'], 'target': request['target'],
                          'state': 'running', 'approval': identifier, 'created_at': now(), 'updated_at': now(),
                          'scope': approval['scope'], 'affected_instances': approval['affected_instances']}
                db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?,?,?)',
                           (request['id'], principal['uid'], principal['owner'], principal['instance'],
                            identifier, fingerprint, encoded(record).decode(), encoded(approval).decode()))
                db.commit()  # FULL durable intent before any child can mutate.
            try:
                result = self.executor(policy, identifier, lease)
                require(isinstance(result, dict) and result.get('completed') is True
                        and result.get('operation') == request['operation'] and result.get('target') == request['target'],
                        'BROKER_OUTCOME_UNVERIFIED')
                public = {'exit_code': 0, 'receipt_sha256': digest(encoded(result))}
                if request['operation'] == 'instance.cancel':
                    require(result.get('allocation_released') is False and result.get('instance_reusable') is False
                            and result.get('administrative_records_retained') is True, 'BROKER_OUTCOME_UNVERIFIED')
                    public.update(allocation_released=False, instance_reusable=False, administrative_records_retained=True)
                record.update(state='completed', result=public)
            except Exception:
                record.update(state='uncertain', error_code='BROKER_OUTCOME_UNVERIFIED')
            record['updated_at'] = now()
            with self.database(policy) as db:
                db.execute('BEGIN IMMEDIATE')
                db.execute('UPDATE requests SET record=? WHERE id=?', (encoded(record).decode(), request['id']))
                if record['state'] == 'completed' and outstanding:
                    for previous, previous_id, previous_approval in outstanding:
                        previous.update(reconciled_by=request['id'], updated_at=now())
                        db.execute('UPDATE requests SET record=? WHERE id=?', (encoded(previous).decode(), previous['id']))
                db.commit()
            return self.visible(record)

    def check_installation(self, policy, approval):
        project = protected(policy['project'], directory=True)
        require(source_files(project) == policy['sources'], 'BROKER_SOURCE_CHANGED')
        require('scripts/web_admin_broker.py' in policy['sources'])
        for value in approval['parameters'].values():
            if isinstance(value, dict) and set(value) == {'path', 'sha256'}:
                artifact(value)
        sys.path.insert(0, str(project / 'scripts'))
        try:
            import installation_layout
            import host_integration
            profile = installation_layout.active()
            require(profile.sha256 == policy['installation_sha256'] and Path(profile.path('project')) == project,
                    'BROKER_INSTALLATION_CHANGED')
            require(policy['state_directory'] == profile.mapped('/var/lib/develative-deploy/whatsapp/web-admin'),
                    'BROKER_LEDGER_LOCATION')
            for instance in approval['affected_instances']:
                marker = restore_marker_present(profile.instance_paths(instance)['configuration'],
                    allow_missing_parent=approval['operation'] in ('instance.allocate', 'instance.prepare', 'instance.cancel'))
                if marker:
                    require(approval['operation'] == 'backup.restore', 'BROKER_RESTORE_RECONCILIATION_REQUIRED')
            administration = host_integration.load_administration()
            require(owner_record(administration.load_generation(states=('dedicated',))) == policy['owner'],
                    'BROKER_OWNER_CHANGED')
        finally:
            sys.path.pop(0)

    def execute_child(self, policy, identifier, lease):
        project = Path(policy['project'])
        interpreter = runtime_interpreter(project)
        command = [str(interpreter), '-I', '-B', str(project / 'scripts/web_admin_broker.py'),
                   'worker', '--policy', str(self.policy_path), '--policy-sha256', digest(encoded(policy)),
                   '--approval', identifier]
        process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, cwd='/', env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                 'LANG': 'C.UTF-8', 'HOME': '/root'}, pass_fds=(lease,), umask=0o077, check=False)
        require(process.returncode == 0 and len(process.stdout) <= MAX_FRAME, 'BROKER_OUTCOME_UNVERIFIED')
        return decode(process.stdout)


def _call(script, arguments):
    old = sys.argv
    output = io.StringIO()
    try:
        sys.argv = [str(script), *arguments]
        with redirect_stdout(output):
            try:
                runpy.run_path(str(script), run_name='__main__')
            except SystemExit as exc:
                require(exc.code in (None, 0), 'BROKER_OUTCOME_UNVERIFIED')
    finally:
        sys.argv = old
    require(len(output.getvalue()) <= MAX_FILE, 'BROKER_OUTCOME_UNVERIFIED')
    rows = []
    for line in output.getvalue().splitlines():
        if line.strip():
            rows.append(decode(line))
    return rows


def dispatch(policy, identifier):
    """Run only reviewed entrypoints; their own admission/leases remain active."""
    approval = policy['approvals'][identifier]
    op, target, p = approval['operation'], approval['target'], approval['parameters']
    project = Path(policy['project'])
    scripts = project / 'scripts'
    sys.path[:0] = [str(project), str(scripts)]
    import host_integration
    import installation_layout
    require(installation_layout.active().sha256 == policy['installation_sha256'])
    result_fields = {}
    with host_integration.constrained_admission(policy['owner']):
        if op == 'instance.allocate':
            plan = decode(artifact(p['plan']))
            require(set(plan.get('additions', {})) == {target} and plan.get('owner') == policy['owner'])
            checkout = protected(p['source_checkout'], directory=True)
            closure = {'plugins/whatsapp/scripts/instance_expansion.py',
                       'plugins/whatsapp/scripts/installation_layout.py', 'plugins/whatsapp/scripts/host_integration.py',
                       'plugins/whatsapp/sally_whatsapp/installation.py', 'plugins/whatsapp/sally_whatsapp/__init__.py',
                       'host/__init__.py', 'host/lifecycle/__init__.py', 'host/lifecycle/filesystem.py'}
            require(set(plan.get('sources', {})) == closure)
            for name, expected in plan['sources'].items():
                require(digest(read(checkout / name)) == expected, 'BROKER_SOURCE_CHANGED')
                if name.startswith('plugins/whatsapp/') and name != 'plugins/whatsapp/scripts/instance_expansion.py':
                    require(policy['sources'].get(name.removeprefix('plugins/whatsapp/')) == expected,
                            'BROKER_SOURCE_CHANGED')
            rows = _call(checkout / 'plugins/whatsapp/scripts/instance_expansion.py',
                         ['apply', '--operation', p['plan']['path'], '--sha256', p['plan']['sha256']])
            require(rows and rows[-1].get('status') == 'allocated' and rows[-1].get('instances') == [target])
        elif op in ('instance.prepare', 'instance.activate', 'instance.cancel'):
            plan = decode(artifact(p['host_plan']))
            require(plan.get('instance', {}).get('slug') == target)
            args = ['--user', target, '--host-plan', p['host_plan']['path'], '--host-plan-sha256', p['host_plan']['sha256']]
            if op == 'instance.cancel':
                rows = _call(scripts / 'provisioning_attempt.py', ['cancel', *args, '--attempt-id', p['attempt_id']])
                require(rows and rows[-1].get('state') == 'cancelled' and rows[-1].get('target') == target
                        and rows[-1].get('attempt_id') == p['attempt_id']
                        and rows[-1].get('allocation_released') is False
                        and rows[-1].get('instance_reusable') is False
                        and rows[-1].get('administrative_records_retained') is True)
                result_fields.update(allocation_released=False, instance_reusable=False, administrative_records_retained=True)
            elif op == 'instance.prepare':
                args += ['--attempt-id', p['attempt_id']]
                for key, value in p['setup'].items():
                    args += ['--' + key.replace('_', '-'), value]
                script = 'provision_host.py' if p['entry'] == 'provision' else 'tenant_admin.py'
                rows = _call(scripts / script, args if p['entry'] == 'provision' else ['add', '--apply', *args])
                registry = decode(read(project / 'private/tenants.json', private=True))
                require(registry.get('instances', {}).get(target, {}).get('phase') in ('prepared', 'ready', 'existing'))
                attempt = _call(scripts / 'provisioning_attempt.py', ['status', *args[:6], '--attempt-id', p['attempt_id']])
                require(attempt and attempt[-1].get('state') == 'prepared' and attempt[-1].get('target') == target
                        and attempt[-1].get('attempt_id') == p['attempt_id'])
            else:
                rows = _call(scripts / 'tenant_admin.py', ['enable-linking', '--apply', *args, '--capabilities', p['capabilities']])
                registry = decode(read(project / 'private/tenants.json', private=True))
                require(registry.get('instances', {}).get(target, {}).get('phase') == 'ready')
        elif op == 'backup.restore':
            plan = decode(artifact(p['plan']))
            require(plan.get('instance') == target and plan.get('owner') == policy['owner'])
            rows = _call(scripts / 'restore_runtime.py', ['apply', '--plan', p['plan']['path'], '--sha256', p['plan']['sha256']])
            require(rows and rows[-1].get('state') == 'completed' and rows[-1].get('instance') == target)
        elif op == 'backup.create':
            pin = {'epoch': policy['owner']['epoch'], 'path': policy['owner']['generation'],
                   'manifest': policy['owner']['manifest_sha256']}
            rows = _call(scripts / 'backup_runtime.py', ['--user', target, '--managed-child', '--admin-pin', json.dumps(pin)])
            require(rows and rows[-1].get('user') == target and rows[-1].get('complete') is True)
        else:
            require(op in ('release.preview', 'release.activate'))
            rows = release_dispatch(policy, approval)
    return {'completed': True, 'operation': op, 'target': target, 'evidence_sha256': digest(encoded(rows)), **result_fields}


def release_dispatch(policy, approval):
    """Use the existing installed receiver, including its CI/Release gates."""
    import host_integration
    administration = host_integration.load_administration()
    generation = administration.load_generation(states=('dedicated',))
    require(owner_record(generation) == policy['owner'], 'BROKER_OWNER_CHANGED')
    administration.pin_generation(generation)
    request = decode(artifact(approval['parameters']['request']))
    require(request.get('dry_run', False) is (approval['operation'] == 'release.preview'))
    require(hexid(request.get('expected_commit'), 40))
    # Load only the admitted generation with its pinned bootstrap authority.
    sys.modules['release_admin'] = administration
    sys.path.insert(0, str(generation.path))
    import github_release as release
    import github_release_common as common
    administration.require_current(release.__file__, expected=generation)
    administration.require_current(common.__file__, expected=generation)
    def preflight():
        # common.main repeats this inside publication_lock before download;
        # tenant operations acquire that lease first too.
        registered = release.instances(release.ROOT)
        require(sorted(item['slug'] for item in registered) == approval['affected_instances'],
                'BROKER_IMPACT_CHANGED')
        for instance in registered:
            require(not restore_marker_present(Path(instance['config']).parent),
                    'BROKER_RESTORE_RECONCILIATION_REQUIRED')
    def publish(checkout, target, config):
        preflight()
        return release.publish(checkout, target, config)
    old_stdin = sys.stdin
    stream = io.TextIOWrapper(io.BytesIO(encoded(request)))
    output = io.StringIO()
    try:
        sys.stdin = stream
        with redirect_stdout(output):
            try:
                common.main('whatsapp', publish, preflight=preflight)
            except SystemExit as exc:
                require(exc.code in (None, 0), 'BROKER_OUTCOME_UNVERIFIED')
    finally:
        sys.stdin = old_stdin
    rows = [decode(line) for line in output.getvalue().splitlines() if line.strip()]
    require(rows and rows[-1].get('status') in ('verified', 'published', 'already-active')
            and rows[-1].get('commit') == request['expected_commit'])
    return rows


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            pid, uid, gid = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            data = bytearray()
            while b'\n' not in data:
                part = self.request.recv(min(4096, MAX_FRAME + 1 - len(data)))
                require(bool(part) and len(data) + len(part) <= MAX_FRAME)
                data.extend(part)
            require(data.endswith(b'\n') and data.count(b'\n') == 1)
            result = self.server.broker.handle(uid, decode(data))
        except Exception:
            result = {'ok': False, 'error_code': 'BROKER_INPUT_REJECTED', 'message': 'Administration request not permitted.'}
        try:
            self.request.sendall(encoded(result))
        except OSError:
            pass  # The durable ledger, not the transport response, owns outcome.


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self, address, handler):
        self.stop_requested = False
        self._bound_identity = None
        self._endpoint_name = Path(address).name
        self._endpoint_parent = os.open(Path(address).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            super().__init__(address, handler)
        except BaseException:
            self.server_close()
            raise

    def server_bind(self):
        super().server_bind()
        info = os.stat(self._endpoint_name, dir_fd=self._endpoint_parent, follow_symlinks=False)
        require(stat.S_ISSOCK(info.st_mode), 'BROKER_SOCKET_CHANGED')
        self._bound_identity = (info.st_dev, info.st_ino)

    def server_close(self):
        try:
            # Close the listener, then drain non-daemon handlers and their
            # workers before releasing our pathname. Their leases stay held.
            super().server_close()
        finally:
            if self._endpoint_parent is not None:
                try:
                    info = os.stat(self._endpoint_name, dir_fd=self._endpoint_parent, follow_symlinks=False)
                    if stat.S_ISSOCK(info.st_mode) and self._bound_identity == (info.st_dev, info.st_ino):
                        os.unlink(self._endpoint_name, dir_fd=self._endpoint_parent)
                except FileNotFoundError:
                    pass
                finally:
                    os.close(self._endpoint_parent)
                    self._endpoint_parent = None

    def verify_request(self, request, client_address):
        return not self.stop_requested

    def serve_until_stopped(self, poll_interval=0.25):
        self.timeout = poll_interval
        while not self.stop_requested:
            self.handle_request()


@contextmanager
def termination_signals(server):
    def stop(signum, frame):
        # Do not raise asynchronously or release leases from a signal handler.
        server.stop_requested = True
    previous = {}
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, stop)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('serve', 'worker', 'inspect'))
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-sha256')
    parser.add_argument('--approval')
    args = parser.parse_args(argv)
    require(os.geteuid() == 0, 'BROKER_NOT_AUTHORIZED')
    sys.dont_write_bytecode = True
    broker = Broker(args.policy)
    policy = broker.policy()
    if args.command == 'inspect':
        print(json.dumps({'format': FORMAT, 'enabled': policy['enabled'],
                          'principals': len(policy['principals']), 'approvals': len(policy['approvals']),
                          'host_changed': False}))
        return
    if args.command == 'worker':
        os.umask(0o077)
        require(hexid(args.approval) and digest(encoded(policy)) == args.policy_sha256
                and args.approval in policy['approvals'])
        approval = policy['approvals'][args.approval]
        require(approval['expires'] > time.time())
        broker.check_installation(policy, approval)
        # Child utilities may write directly to fd 1, bypassing Python's
        # redirected stream. They never become RPC output or leak credentials.
        saved_stdout = os.dup(1)
        quiet = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(quiet, 1)
            result = dispatch(policy, args.approval)
        finally:
            os.dup2(saved_stdout, 1)
            os.close(saved_stdout)
            os.close(quiet)
        print(json.dumps(result))
        return
    require(args.approval is None and args.policy_sha256 is None)
    endpoint = Path(policy['socket'])
    protected(endpoint.parent, directory=True)
    require(not endpoint.exists() and not endpoint.is_symlink(), 'BROKER_SOCKET_EXISTS')
    protected(policy['state_directory'], directory=True, private=True)
    # The restrictive socket mask applies only to bind, never to workers or
    # private directories. Existing sockets remain an administrative decision.
    old_umask = os.umask(0o117)
    try:
        server = Server(str(endpoint), Handler)
    finally:
        os.umask(old_umask)
    try:
        with termination_signals(server):
            with server:
                os.chown(endpoint, 0, policy['socket_gid'])
                os.chmod(endpoint, 0o660)
                server.broker = broker
                server.serve_until_stopped()
    finally:
        server.server_close()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('WhatsApp web administration stopped; inspect protected policy and private journal') from None
