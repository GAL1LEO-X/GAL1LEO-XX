"""Owner-scoped administration using existing runtime services.

The bridge never acquires host privileges. Host lifecycle operations require the
dedicated administrative channel; an HTTP request cannot enable that channel.
"""
import base64
import hashlib
from html import escape
import json
import math
import os
import stat
import re
import time

from starlette.responses import HTMLResponse, JSONResponse, FileResponse
from starlette.routing import Route

from . import __version__
from .admin_broker import AdminBrokerClient, BrokerError, HOST_ACTIONS
from .capabilities import capabilities
from .diagnostics import reference
from .gateway import GatewayUnavailable
from .installation import Installation, ROSTER_FORMAT
from .linking import ASSETS, HEADERS, LinkError
from .store import canonical, utc


LOCAL_ACTIONS = ('subscription.disable', 'history.pause', 'history.resume', 'history.cancel', 'instance.preview')
PREFIX = 'private:admin:job:'
RECORD_TTL = 30 * 86400
MAX_RECORDS = 500
PAGE_SIZE = 100


def page_cursor(kind, value):
    """Public seek position only; every query remains bound to the session owner."""
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError('Invalid list cursor')
    if kind == 'subscriptions':
        if re.fullmatch('sub_[a-f0-9]{64}', value) is None:
            raise ValueError('Invalid subscription cursor')
        return value
    position = json.loads(base64.b64decode(value, altchars=b'-_', validate=True))
    if (not isinstance(position, list) or len(position) != 2
            or type(position[0]) not in (int, float) or not math.isfinite(position[0]) or position[0] < 0
            or not isinstance(position[1], str) or re.fullmatch('history_[a-f0-9]{32}', position[1]) is None):
        raise ValueError('Invalid history cursor')
    return position


class AdminError(ValueError):
    def __init__(self, code, message, status=400):
        self.code, self.status = code, status
        super().__init__(message)


class RuntimeAdminOperations:
    """Bounded, persistent operations; no shell, URLs or caller-selected paths.

The private state namespace is included in existing SQLite backups. After a
crash a running record is uncertain and is never executed a second time.
"""
    def __init__(self, service):
        self.service = service
        self.store = service.store
        self.owner = service.settings.owner_subject
        path = service.settings.admin_broker_socket
        self.broker = (AdminBrokerClient(path, self.owner, service.settings.admin_broker_instance)
                       if path is not None else None)

    def records(self):
        with self.store.db() as db:
            values = [json.loads(row[0]) for row in db.execute(
                'SELECT value FROM state WHERE key LIKE ?', (PREFIX + '%',))]
        return sorted(values, key=lambda row: row['created_at'], reverse=True)

    @staticmethod
    def visible(row):
        value = {key: item for key, item in row.items() if key not in ('request_hash',)}
        if value['state'] == 'running':
            value.update(state='uncertain', message='Operation started; outcome not verified yet. Do not repeat with a new identifier.')
        return value

    def preview(self, target, args):
        if set(args) != {'installation', 'roster', 'account', 'bridge', 'gateway'}:
            raise ValueError('Declare the installation, current roster and new account/ports')
        profile = Installation.from_dict(args['installation'])
        if args['roster'] is not None:
            profile = profile.with_roster(args['roster'])
        old = profile.roster or {'revision': 0, 'instances': {}}
        if target in profile.accounts():
            raise ValueError('Instance already allocated')
        roster = {'format': ROSTER_FORMAT, 'installation_sha256': profile.sha256,
                  'revision': old['revision'] + 1, 'previous': profile.roster_sha256,
                  'instances': {**old['instances'], target: {name: args[name] for name in ('account', 'bridge', 'gateway')}}}
        proposed = profile.with_roster(roster)
        return {'installation_sha256': profile.sha256, 'roster': proposed.roster,
                'state': 'preview_only', 'resources_reserved': False, 'provisioned': False,
                'host_collisions_checked': False, 'domains_checked': False,
                'next_step': 'Compile and admit the expansion through the dedicated administrative channel; this public preview is not an allocation.'}

    def execute(self, request):
        if not isinstance(request, dict) or set(request) != {'id', 'operation', 'target', 'arguments', 'confirmation'}:
            raise ValueError('Exact administrative operation fields required')
        identifier, operation, target, args = (request[name] for name in ('id', 'operation', 'target', 'arguments'))
        if not isinstance(identifier, str) or not re.fullmatch('[a-f0-9]{32}', identifier):
            raise ValueError('A 32-character hexadecimal request ID is required')
        if not isinstance(operation, str) or operation not in (*LOCAL_ACTIONS, *HOST_ACTIONS):
            raise ValueError('Unknown administrative operation')
        if operation in LOCAL_ACTIONS and getattr(self.service, 'restore_maintenance', False):
            raise AdminError('ADMIN_RESTORE_MAINTENANCE',
                             'Restoration in maintenance: check the receipt and complete administrative recovery.', 409)
        if not isinstance(target, str) or not re.fullmatch('[A-Za-z0-9_.:-]{1,128}', target):
            raise ValueError('Invalid operation target')
        if not isinstance(args, dict):
            raise ValueError('Invalid operation arguments')
        if request['confirmation'] != operation + ':' + target:
            raise AdminError('CONFIRMATION_REQUIRED', 'Explicitly confirm the operation and target.', 409)
        if operation in HOST_ACTIONS:
            if self.broker is None:
                raise AdminError('EXTERNAL_EXECUTION_REQUIRED',
                    'Requires the dedicated administration channel and its policy. No host operation was executed.', 409)
            if (set(args) != {'approval'} or not isinstance(args['approval'], str)
                    or re.fullmatch('[a-f0-9]{32}', args['approval']) is None):
                raise ValueError('An exact approved operation reference is required')
        if operation not in (*HOST_ACTIONS, 'instance.preview') and args:
            raise ValueError('This operation has no arguments')
        if operation.startswith('history.') and not re.fullmatch('history_[a-f0-9]{32}', target):
            raise ValueError('Invalid history job ID')
        if operation == 'subscription.disable' and not re.fullmatch('sub_[a-f0-9]{64}', target):
            raise ValueError('Invalid subscription ID')
        fingerprint = hashlib.sha256(canonical(request).encode()).hexdigest()
        now = time.time()
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT value FROM state WHERE key=?', (PREFIX + identifier,)).fetchone()
            if existing:
                old = json.loads(existing[0])
                if old['request_hash'] != fingerprint:
                    raise AdminError('IDEMPOTENCY_CONFLICT', 'Identifier already used for another operation.', 409)
                return self.visible(old)
            for row in db.execute('SELECT key,value FROM state WHERE key LIKE ?', (PREFIX + '%',)).fetchall():
                old = json.loads(row['value'])
                if old['state'] in ('completed', 'failed_before_execution') and old['updated_epoch'] < now - RECORD_TTL:
                    db.execute('DELETE FROM state WHERE key=?', (row['key'],))
            if db.execute('SELECT count(*) FROM state WHERE key LIKE ?', (PREFIX + '%',)).fetchone()[0] >= MAX_RECORDS:
                raise AdminError('ADMIN_JOURNAL_FULL', 'Administration journal is full: reconcile operations before continuing.', 409)
            row = {'id': identifier, 'operation': operation, 'target': target,
                   'request_hash': fingerprint, 'state': 'running', 'created_at': utc(now),
                   'updated_at': utc(now), 'updated_epoch': now}
            if operation in HOST_ACTIONS:
                row['approval'] = args['approval']
            self.store._state(db, PREFIX + identifier, row)
        self.service.diagnostics.emit('admin.started', operation=operation, job_ref=reference(identifier))
        try:
            if operation in HOST_ACTIONS:
                row.update(self.broker.execute(request))
                value = None
            elif operation == 'instance.preview':
                value = self.preview(target, args)
            elif operation.startswith('history.'):
                result = self.service.history.control(target, self.owner, operation.split('.')[1])
                value = {key: result[key] for key in ('id', 'state', 'updated_at')}
            else:
                with self.store.db() as db:
                    sub = db.execute('SELECT name,filters,url FROM subscriptions WHERE id=? AND owner=?',
                                     (target, self.owner)).fetchone()
                if sub is None:
                    raise ValueError('Subscription not found for this instance owner')
                self.service.events.unsubscribe(self.owner, sub['name'], json.loads(sub['filters']), sub['url'])
                value = {'id': target, 'active': False, 'inflight_delivery_may_complete': True}
            if operation not in HOST_ACTIONS:
                row.update(state='completed', result=value)
        except BrokerError as exc:
            row.update(state='uncertain' if exc.uncertain else 'failed_before_execution',
                       error_code=exc.code,
                       message=('Host outcome unverified. Read the receipt before starting another operation.'
                                if exc.uncertain else 'Request not sent to the administration broker.'))
        except ValueError:
            row.update(state='failed_before_execution' if operation == 'instance.preview' else 'uncertain',
                       error_code='ADMIN_INPUT_REJECTED' if operation == 'instance.preview' else 'ADMIN_OUTCOME_UNVERIFIED',
                       message='Invalid preview.' if operation == 'instance.preview' else 'Status cannot be verified; check the target before another request.')
        except Exception:
            row.update(state='uncertain', error_code='ADMIN_OUTCOME_UNVERIFIED',
                       message='Outcome cannot be verified: check the target before another request.')
        row.update(updated_at=utc(), updated_epoch=time.time())
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            found = db.execute('SELECT value FROM state WHERE key=?', (PREFIX + identifier,)).fetchone()
            current = json.loads(found[0]) if found is not None else row
            # A concurrent receipt read can establish success before the caller
            # sees a timeout. Never downgrade that authoritative observation.
            same_request = (current.get('request_hash') == row['request_hash'] or
                            (operation in HOST_ACTIONS and all(current.get(key) == row.get(key)
                             for key in ('id', 'operation', 'target', 'approval'))))
            if same_request:
                if current['state'] in ('completed', 'failed_before_execution'):
                    row = current
                self.store._state(db, PREFIX + identifier, row)
        self.service.diagnostics.emit('admin.finished', operation=operation, state=row['state'], job_ref=reference(identifier))
        return self.visible(row)

    def reconcile(self, identifier):
        if not isinstance(identifier, str) or re.fullmatch('[a-f0-9]{32}', identifier) is None:
            raise ValueError('Invalid operation ID')
        with self.store.db() as db:
            found = db.execute('SELECT value FROM state WHERE key=?', (PREFIX + identifier,)).fetchone()
        if found is None and self.broker is None:
            raise AdminError('ADMIN_OPERATION_NOT_FOUND', "Operation not found in this instance's journal.", 404)
        row = json.loads(found[0]) if found is not None else None
        if row is not None and (row['operation'] not in HOST_ACTIONS or row['state'] in ('completed', 'failed_before_execution')):
            return self.visible(row)
        if self.broker is None:
            raise AdminError('EXTERNAL_EXECUTION_REQUIRED', 'Administration broker is not configured.', 409)
        try:
            observation = self.broker.status(row if row is not None else identifier)
        except BrokerError:
            if row is None:
                raise AdminError('ADMIN_RECEIPT_UNAVAILABLE', 'Receipt unavailable for this access.', 404) from None
            value = self.visible(row)
            value['observation_error_code'] = 'ADMIN_BROKER_UNAVAILABLE'
            return value
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            found = db.execute('SELECT value FROM state WHERE key=?', (PREFIX + identifier,)).fetchone()
            if found is None:
                # A restore may legitimately replace the tenant database with
                # one predating this operation. Host receipts remain scoped and
                # authoritative. An imported row can never authorize a replay.
                current = {**observation, 'request_hash': None, 'delegated': True,
                           'created_at': observation.get('created_at', utc()),
                           'updated_at': observation.get('updated_at', utc()), 'updated_epoch': time.time()}
                count = db.execute('SELECT count(*) FROM state WHERE key LIKE ?', (PREFIX + '%',)).fetchone()[0]
                if count < MAX_RECORDS:
                    self.store._state(db, PREFIX + identifier, current)
                return self.visible(current)
            current = json.loads(found[0])
            if any(current.get(key) != observation.get(key) for key in ('id', 'operation', 'target', 'approval')):
                value = self.visible(current)
                value['observation_error_code'] = 'ADMIN_RECEIPT_CONFLICT'
                return value
            if current['state'] in ('running', 'uncertain'):
                current.update(observation, updated_at=utc(), updated_epoch=time.time())
                current.pop('message', None)
                if current['state'] == 'completed':
                    current.pop('error_code', None)
                self.store._state(db, PREFIX + identifier, current)
        return self.visible(current)

    def host_state(self):
        if self.broker is None:
            return {'actions': [{'operation': op, 'available': False, 'reason': 'external_execution_required'} for op in HOST_ACTIONS], 'receipts': []}
        try:
            return self.broker.capabilities()
        except BrokerError:
            return {'actions': [{'operation': op, 'available': False, 'reason': 'broker_unavailable'} for op in HOST_ACTIONS], 'receipts': []}

    def host_actions(self):
        return self.host_state()['actions']

    def snapshot(self, *, history_cursor=None, subscriptions_cursor=None):
        history_position = page_cursor('history', history_cursor)
        subscriptions_position = page_cursor('subscriptions', subscriptions_cursor)
        now = time.time()
        settings = self.service.settings
        host = self.host_state()
        operations = {row['id']: self.visible(row) for row in self.records()}
        for receipt in host['receipts']:
            old = operations.get(receipt['id'], {})
            if old and any(old.get(key) != receipt.get(key) for key in ('operation', 'target', 'approval')):
                continue
            if old.get('state') not in ('completed', 'failed_before_execution'):
                operations[receipt['id']] = {**old, **receipt, 'delegated': True}
        with self.store.db() as db:
            db.execute('BEGIN')
            subscriptions = [dict(row) for row in db.execute(
                'SELECT id,name,active,expires FROM subscriptions WHERE owner=? AND id>? ORDER BY id LIMIT ?',
                (self.owner, subscriptions_position or '', PAGE_SIZE + 1))]
            for row in subscriptions[:PAGE_SIZE]:
                row['configured'] = bool(row.pop('active'))
                row['active'] = row['configured'] and row['expires'] > now
                row['deliveries'] = dict(db.execute('SELECT state,count(*) FROM deliveries WHERE subscription=? GROUP BY state', (row['id'],)).fetchall())
                row['callback_acceptance_observed'] = row['deliveries'].get('accepted', 0) > 0
                row['acceptance_scope'] = 'retained_HTTP_2xx_evidence_only_not_downstream_delivery_or_current_connection'
                row['acceptance_timestamp'] = None
                row['acceptance_timestamp_available'] = False
            history_where, history_args = '', []
            if history_position is not None:
                created, identifier = history_position
                history_where = ' AND (created<? OR (created=? AND id>?))'
                history_args = [created, created, identifier]
            history = [dict(row) for row in db.execute(
                'SELECT id,state,created,updated FROM history_jobs WHERE owner=?' + history_where +
                ' ORDER BY created DESC,id LIMIT ?', (self.owner, *history_args, PAGE_SIZE + 1))]
        subscriptions_next = subscriptions[PAGE_SIZE - 1]['id'] if len(subscriptions) > PAGE_SIZE else None
        history_next = (base64.urlsafe_b64encode(canonical([history[PAGE_SIZE - 1]['created'],
                        history[PAGE_SIZE - 1]['id']]).encode()).decode() if len(history) > PAGE_SIZE else None)
        provider_operations = ()
        provider_observation = 'account_access_disabled'
        if settings.live_account_enabled:
            try:
                provider_operations = self.service.ab_provider_operations()
                provider_observation = ('provider_contract_confirmed' if provider_operations else
                                        'provider_contract_not_confirmed_missing_unsupported_or_unavailable')
            except Exception:
                provider_observation = 'provider_unavailable_support_unverified'
        return {'observed_at': utc(now), 'scope': 'current_instance_with_explicit_host_delegations' if self.broker else 'current_instance_only', 'version': __version__, 'schema': 8,
                'instance': settings.profile_name, 'connection': self.service.connection_status(),
                'subscriptions': subscriptions[:PAGE_SIZE], 'subscriptions_truncated': subscriptions_next is not None,
                'subscriptions_page': {'limit': PAGE_SIZE, 'next_cursor': subscriptions_next},
                'history': history[:PAGE_SIZE], 'history_truncated': history_next is not None,
                'history_page': {'limit': PAGE_SIZE, 'next_cursor': history_next},
                'operations': list(operations.values()),
                'local_actions': [] if getattr(self.service, 'restore_maintenance', False) else list(LOCAL_ACTIONS),
                'restore_maintenance': bool(getattr(self.service, 'restore_maintenance', False)),
                'host_actions': host['actions'],
                'host_actions_truncated': host.get('actions_truncated', False),
                'host_receipts_truncated': host.get('receipts_truncated', False),
                'capabilities': capabilities(settings, [], provider_operations=provider_operations),
                'capability_observation': provider_observation,
                'token_grants': 'owner_portal_session_is_not_an_MCP_grant',
                'retention': {'completed_admin_records_days': 30, 'max_admin_records': MAX_RECORDS,
                              'uncertain_admin_records': 'retained_until_reconciled', 'backup_copies': 'not_erased_by_local_actions'}}


class AdminPortal:
    def __init__(self, service, portal):
        if portal is None:
            raise ValueError('Owner portal required')
        self.service, self.portal = service, portal
        self.operations = RuntimeAdminOperations(service)

    def routes(self):
        return [Route('/admin', self.page), Route('/admin/', self.page),
                Route('/admin/api/status', self.status), Route('/admin/api/logs', self.logs),
                Route('/admin/api/connection', self.connection),
                Route('/admin/api/operations', self.action, methods=['POST']),
                Route('/admin/api/operations/{identifier}', self.operation_status),
                Route('/admin/static/admin.js', self.script), Route('/admin/static/admin.css', self.style)]

    def session(self, request):
        if not self.service.settings.admin_enabled:
            raise LinkError('Administration disabled.', 403)
        return self.portal.session(request)

    async def page(self, request):
        try:
            session = await self.service.run_sync(self.session, request)
        except LinkError as exc:
            return HTMLResponse('<!doctype html><html lang="en"><title>WhatsApp administration</title><main><h1>Sign-in required</h1><p>Sign in to the authorized profile, then reopen this page.</p><a href="/connect/login">Sign in</a></main></html>', status_code=exc.status, headers=HEADERS)
        return HTMLResponse(PAGE.replace('CSRF_TOKEN', escape(session['csrf'], quote=True)), headers=HEADERS)

    async def status(self, request):
        try:
            await self.service.run_sync(self.session, request)
        except LinkError as exc:
            return JSONResponse({'error_code': 'ADMIN_AUTH_REQUIRED', 'message': str(exc)}, status_code=exc.status, headers=HEADERS)
        try:
            query = request.query_params
            if (set(query) - {'history_cursor', 'subscriptions_cursor'}
                    or any(len(query.getlist(key)) != 1 for key in query)):
                raise ValueError('Invalid list query')
            for kind in ('history', 'subscriptions'):
                page_cursor(kind, query.get(kind + '_cursor'))
        except (ValueError, TypeError, OverflowError):
            return JSONResponse({'error_code': 'ADMIN_INVALID_INPUT', 'message': 'Invalid list position.'}, status_code=400, headers=HEADERS)
        value = await self.service.run_sync(self.operations.snapshot, **dict(query))
        return JSONResponse(value, headers=HEADERS)

    def connection_flow(self):
        """Current-instance prerequisites and phone state; never pairing secrets."""
        settings = self.service.settings
        enabled = settings.live_account_enabled and settings.link_enabled
        error_code = None
        try:
            observation = self.portal.connection()
        except (GatewayUnavailable, ValueError, TypeError, AttributeError):
            observation = {'state':'UNKNOWN','connected':False}
            error_code = 'PHONE_CONNECTION_UNVERIFIED'
        connected = observation['connected'] is True
        state = observation['state']
        can_activate = any(action['operation'] == 'instance.activate' and action.get('available')
                           and action.get('target') == settings.admin_broker_instance
                           for action in self.operations.host_actions()) if (
                               self.operations.broker and not getattr(self.service, 'restore_maintenance', False)) else False
        stage = ('activation_required' if not enabled else 'connected' if connected else
                 'reconnection_required' if state == 'FAILED' else
                 'phone_confirmation_required' if state in ('PASSKEY_REQUIRED','PASSKEY_CONFIRMATION_REQUIRED') else
                 'pairing_ready' if state in ('STOPPED','SCAN_QR_CODE') else 'provider_wait')
        return {'scope':'current_instance_only','instance':settings.profile_name,
                'observed_at':utc(),'stage':stage,'error_code':error_code,
                'configuration':{'live_account_enabled':settings.live_account_enabled,'link_enabled':settings.link_enabled},
                'phone':{'state':state,'connected':connected,
                         'source':'provider_observation' if enabled and error_code is None else 'local_configuration_only' if not enabled else 'unverified'},
                'pairing_url':'/connect' if enabled else None,
                'activation':{'required':not enabled,
                              'execution':'delegated_host_broker' if can_activate else 'dedicated_administrative_channel',
                              'host_preparation_verified':False,'can_activate_from_panel':bool(can_activate)},
                'chatgpt':{'consent_state':'not_verified_here','separate_authorization_required':True,
                           'phone_pairing_grants_mcp':False,'configured_scopes':list(settings.oauth_allowed_scopes)},
                'secrets_included':False}

    async def connection(self, request):
        try:
            await self.service.run_sync(self.session, request)
            return JSONResponse(await self.service.run_sync(self.connection_flow), headers=HEADERS)
        except LinkError as exc:
            return JSONResponse({'error_code':'ADMIN_AUTH_REQUIRED','message':str(exc)}, status_code=exc.status, headers=HEADERS)

    async def action(self, request):
        try:
            session = await self.service.run_sync(self.session, request)
            self.portal.csrf(request, session)
            if request.headers.get('content-type', '').split(';')[0] != 'application/json':
                raise ValueError('JSON required')
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 65536:
                    raise AdminError('ADMIN_INPUT_TOO_LARGE', 'Request too large.', 413)
            value = json.loads(body)
            result = await self.service.run_sync(self.operations.execute, value)
            return JSONResponse(result, headers=HEADERS)
        except LinkError as exc:
            return JSONResponse({'error_code': 'ADMIN_ACCESS_DENIED', 'message': str(exc)}, status_code=exc.status, headers=HEADERS)
        except AdminError as exc:
            return JSONResponse({'error_code': exc.code, 'message': str(exc)}, status_code=exc.status, headers=HEADERS)
        except (ValueError, TypeError):
            return JSONResponse({'error_code': 'ADMIN_INVALID_INPUT', 'message': 'Invalid administration request.'}, status_code=400, headers=HEADERS)

    async def operation_status(self, request):
        try:
            await self.service.run_sync(self.session, request)
            result = await self.service.run_sync(self.operations.reconcile, request.path_params['identifier'])
            return JSONResponse(result, headers=HEADERS)
        except LinkError as exc:
            return JSONResponse({'error_code': 'ADMIN_AUTH_REQUIRED'}, status_code=exc.status, headers=HEADERS)
        except AdminError as exc:
            return JSONResponse({'error_code': exc.code, 'message': str(exc)}, status_code=exc.status, headers=HEADERS)
        except ValueError:
            return JSONResponse({'error_code': 'ADMIN_INVALID_INPUT'}, status_code=400, headers=HEADERS)

    def read_logs(self):
        # Only the fixed, structured diagnostic log; no user-supplied file paths.
        try:
            parent = os.open(self.service.settings.database.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                if os.fstat(parent).st_uid != os.getuid() or os.fstat(parent).st_mode & 0o022:
                    raise ValueError('Unprotected instance directory')
                directory = os.open('diagnostics', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            finally:
                os.close(parent)
            try:
                if os.fstat(directory).st_uid != os.getuid() or os.fstat(directory).st_mode & 0o022:
                    raise ValueError('Unprotected diagnostic directory')
                descriptor = os.open('events.jsonl', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            finally:
                os.close(directory)
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                    raise ValueError('Diagnostic path is not an owned regular file')
                stream.seek(0, 2)
                size = stream.tell()
                stream.seek(max(0, size - 65536))
                lines = stream.read(65536).splitlines()
            if size > 65536:
                lines = lines[1:]
        except FileNotFoundError:
            lines = []
        allowed = ('at', 'version', 'level', 'event', 'operation', 'state', 'error_code', 'job_ref', 'request_id')
        result = []
        for line in lines[-100:]:
            try:
                row = json.loads(line)
                result.append({key: row[key] for key in allowed if key in row and isinstance(row[key], str) and len(row[key]) <= 100})
            except (ValueError, TypeError):
                continue
        return {'entries': result, 'coverage': 'last_100_in_bounded_tail_only', 'observed_at': utc()}

    async def logs(self, request):
        try:
            await self.service.run_sync(self.session, request)
            return JSONResponse(await self.service.run_sync(self.read_logs), headers=HEADERS)
        except LinkError as exc:
            return JSONResponse({'error_code': 'ADMIN_AUTH_REQUIRED'}, status_code=exc.status, headers=HEADERS)
        except (OSError, ValueError):
            return JSONResponse({'error_code': 'ADMIN_LOG_UNAVAILABLE'}, status_code=503, headers=HEADERS)

    async def script(self, request):
        return FileResponse(ASSETS / 'admin.js', media_type='application/javascript', headers=HEADERS)

    async def style(self, request):
        return FileResponse(ASSETS / 'admin.css', media_type='text/css', headers=HEADERS)


PAGE = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WhatsApp administration</title><link rel="stylesheet" href="/admin/static/admin.css"><script src="/admin/static/admin.js" defer></script></head>\n<body data-csrf="CSRF_TOKEN"><header><p>WHATSAPP · ADMINISTRATION</p><h1 id="instance">Your management space</h1><p>Controls restricted to the current instance owner.</p></header><main>\n<nav aria-label="Sections"><a href="#status">Status</a><a href="#instances">Instances</a><a href="#connection">Connection</a><a href="#events">Capabilities and events</a><a href="#maintenance">Maintenance</a></nav>\n<p id="error" role="alert" hidden></p><p id="maintenance-notice" role="status" hidden>Instance in maintenance after restoration. Local work and the phone remain suspended: check the server receipt and complete administrative recovery.</p><p id="notice" role="status" aria-live="polite">Loading…</p><button id="refresh" type="button">Refresh observation</button>\n<section id="status"><h2>Status</h2><p id="summary"></p><div class="grid" id="status-cards"></div><details><summary>Observation diagnostics</summary><pre id="diagnostics"></pre></details></section>\n<section id="instances"><h2>Instances</h2><p>Preview an addition to the public installation profile. This does not reserve resources or check DNS or server collisions.</p>\n<form id="preview"><label>Public installation profile (JSON)<textarea id="profile" rows="5" required></textarea></label><label>Current roster (JSON, optional)<textarea id="roster" rows="2"></textarea></label><div class="grid"><label>Instance name<input id="slug" pattern="[a-z][a-z0-9-]{1,19}" required></label><label>Service account<input id="account" required></label><label>Backend port<input id="bridge" type="number" min="1024" max="65535" required></label><label>Gateway port<input id="gateway" type="number" min="1024" max="65535" required></label></div><button type="submit">Check preview</button></form><pre id="preview-result"></pre></section>\n<section id="connection"><h2>Phone connection</h2><p>Each instance uses its own domain, owner and WhatsApp session. Previewing a new instance does not change the profile open on this page.</p>\n<ol class="connection-steps"><li><strong>1. Add and prepare the instance</strong><p>Check the preview, then complete allocation and provisioning through the dedicated administration channel. The server must confirm resources, the HTTPS domain and OAuth identity.</p></li>\n<li><strong>2. Activate the connection</strong><p id="activation-state">Checking prerequisites…</p><p>Configuration read here does not by itself verify server provisioning; this panel enables no administrative policy.</p></li>\n<li><strong>3. Connect or reconnect the phone</strong><p id="phone-state">State not observed.</p><a id="phone-link" href="/connect" hidden>Open phone connection</a><p>QR and codes remain on the connection page, are temporary and do not enter the administration journal.</p></li>\n<li><strong>4. Authorize ChatGPT separately</strong><p id="chatgpt-state">Phone pairing does not grant ChatGPT permissions. Open the plugin in ChatGPT and complete OAuth consent for the desired features. This panel cannot verify that consent.</p></li></ol></section>\n<section id="events"><h2>Capabilities and events</h2><p id="capability-note"></p><details><summary>Catalogue and configured permissions</summary><pre id="capabilities"></pre></details><h3>Subscriptions</h3><div id="subscriptions"></div><div role="group" aria-label="Pages · Subscriptions"><p id="subscriptions-page" role="status" tabindex="-1"></p><button id="subscriptions-previous" type="button" disabled aria-controls="subscriptions">Previous page</button><button id="subscriptions-next" type="button" disabled aria-controls="subscriptions">Next page</button></div></section>\n<section id="maintenance"><h2>Maintenance</h2><p>Server operations are available only after an administrator configures the broker and approves the specific operation. Check affected instances before confirmation. An uncertain outcome requires reading the receipt.</p><h3>Authorized server operations</h3><p id="host-list-limit" hidden>Partial approval list: ask the administrator to select the relevant operations.</p><ul id="host-actions"></ul><h3>History imports</h3><div id="history"></div><div role="group" aria-label="Pages · History imports"><p id="history-page" role="status" tabindex="-1"></p><button id="history-previous" type="button" disabled aria-controls="history">Previous page</button><button id="history-next" type="button" disabled aria-controls="history">Next page</button></div><h3>Operations and progress</h3><p id="host-receipt-limit" hidden>Only the latest host receipts are shown. Retrieve other receipts by identifier.</p><form id="receipt-lookup"><label>Host operation identifier<input id="receipt-id" pattern="[a-f0-9]{32}" maxlength="32" required></label><button type="submit">Read receipt by identifier</button></form><div id="operations"></div><h3>Diagnostic logs</h3><button type="button" id="logs-button">Read latest logs</button><pre id="logs"></pre><p>Logs do not contain messages or secrets. Local deletion does not remove backup copies.</p></section>\n<dialog id="confirmation"><form method="dialog"><h2>Confirm operation</h2><p id="confirmation-label"></p><p id="confirmation-details"></p><label>Enter the exact operation and target<input id="confirmation-input" autocomplete="off"></label><button value="cancel">Cancel</button><button id="confirm-button" value="confirm">Confirm</button></form></dialog></main><footer><a href="/connect">Access management</a> · <button id="logout" type="button">Sign out</button></footer></body></html>'
