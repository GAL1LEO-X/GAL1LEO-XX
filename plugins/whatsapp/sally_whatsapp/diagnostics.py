"""Bounded per-instance diagnostics. Inputs, content, credentials and URLs are never logged."""
from contextvars import ContextVar
from contextlib import contextmanager
from datetime import datetime, UTC
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re
import secrets
import time

from . import __version__
from .mcp_diagnostics import MCPObservation, ENUM_FIELDS, RPC_ERROR_CODES

request_id = ContextVar('whatsapp_request_id', default='')
action_context = ContextVar('whatsapp_action_diagnostic_context', default={})
auth_admission = ContextVar('whatsapp_auth_admission', default=None)
TEXT_FIELDS = {'tool', 'operation', 'state', 'previous_state', 'worker', 'route',
               'method', 'error_code', 'exception', 'job_ref', 'event_ref', 'source_event',
               'observation_source', 'provider_error_kind', 'source_subtype', 'delivery_ref',
               'validation_field', 'validation_reason', 'credential_state', 'auth_stage', 'auth_reason',
               'failure_reason', 'limit_basis'}
NUMBER_FIELDS = {'status', 'duration_ms', 'bytes', 'attempt', 'count', 'schema',
                 'provider_at', 'ingested_at', 'queued_at', 'attempt_at', 'accepted_at',
                 'event_age_ms', 'queue_delay_ms', 'quota_observed_at', 'cache_capacity_bytes',
                 'cache_used_bytes', 'cache_remaining_bytes', 'file_limit_bytes', 'effective_limit_bytes',
                 'observed_bytes'}
NUMBER_FIELDS |= {'receipts_inserted', 'messages_inserted', 'first_live_messages', 'account_events_inserted',
                  'callbacks_queued', 'digest_members_added', 'callbacks_cancelled'}
INGEST_ENUMS = {'disposition': {'acquired', 'duplicate', 'ignored'},
               'ingestion_stage': {'body_rejected', 'signature_rejected', 'validation_rejected'},
               'http_failure_layer': {'authentication', 'authorization', 'mcp_protocol', 'http_routing',
                                      'webhook_admission', 'application_or_transport', 'undetermined'}}


def reference(value):
    return hashlib.sha256(str(value).encode()).hexdigest()[:16]


def credential_state(scope):
    """Match the SDK's admission shape, retaining neither scheme nor credential."""
    values = [value for key, value in scope.get('headers', ()) if key.lower() == b'authorization']
    if not values:
        return 'absent'
    if len(values) != 1:
        return 'multiple'
    if not values[0]:
        return 'absent'
    value = values[0].lower()
    if value == b'bearer' or (value.startswith(b'bearer ') and not value[7:].strip()):
        return 'empty_bearer'
    return 'bearer' if value.startswith(b'bearer ') else 'unsupported_scheme'


class AuthAdmission:
    """One request-local record, also shared with the verifier's to_thread copy."""
    def __init__(self, scope):
        self.credential_state = credential_state(scope)
        self.rejection = None
        self.verified = False
        self.challenge = None

    def rejected_fields(self, status):
        admission = {'absent': ('AUTH_MISSING', 'missing_credentials'),
                     'unsupported_scheme': ('AUTH_SCHEME', 'unsupported_scheme'),
                     'empty_bearer': ('AUTH_EMPTY', 'empty_bearer')}
        if status == 401 and self.challenge == 'invalid_token' and self.credential_state in admission:
            code, reason = admission[self.credential_state]
            return dict(error_code=code, auth_reason=reason, auth_stage='admission')
        if self.rejection is not None:
            return dict(self.rejection, auth_reason='verification_rejected', auth_stage='verification')
        if status == 403 and self.challenge == 'insufficient_scope':
            return dict(error_code='AUTH_SCOPE', auth_reason='insufficient_permissions', auth_stage='authorization')
        if status == 401 and self.challenge == 'invalid_token':
            return dict(error_code='AUTH_ADMISSION', auth_stage='admission',
                        auth_reason='post_verification_rejected' if self.verified else 'verification_not_observed')
        return None


def auth_rejected(diagnostics, code, exception=None):
    fields = {'error_code': code}
    if exception: fields['exception'] = exception
    observation = auth_admission.get()
    if observation is not None:
        # Mutate only this request's bounded record; ContextVar.set in a worker
        # would not propagate back to its caller. Never use global dedup state.
        observation.rejection = fields
    elif diagnostics:
        diagnostics.emit('auth.rejected', 'warning', **fields)


def auth_verified():
    observation = auth_admission.get()
    if observation is not None:
        observation.verified = True


@contextmanager
def action_diagnostic_context(operation, key):
    token = action_context.set({'operation': operation, 'job_ref': reference(key)})
    try: yield
    finally: action_context.reset(token)


class PrivateRotatingHandler(RotatingFileHandler):
    def handleError(self, record):
        # logging's default handler prints the original record and traceback.
        print('{"event":"diagnostics.write_failed","level":"error"}', flush=True)


class Diagnostics:
    def __init__(self, settings):
        self.enabled = settings.diagnostics_enabled
        self.directory = settings.database.parent / 'diagnostics'
        self.handler = None
        if self.enabled:
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.handler = PrivateRotatingHandler(self.directory / 'events.jsonl',
                maxBytes=settings.diagnostics_max_bytes, backupCount=settings.diagnostics_backups,
                encoding='utf-8', delay=True)
            self.handler.setFormatter(logging.Formatter('%(message)s'))

    def emit(self, event, level='info', **fields):
        if not self.handler: return
        if not re.fullmatch(r'[a-z][a-z0-9_.]{0,79}', event): return
        item = {'at': datetime.now(UTC).isoformat(), 'version': __version__,
                'level': level if level in ('info','warning','error') else 'error', 'event': event}
        correlation = request_id.get()
        if correlation: item['request_id'] = correlation
        for key, value in {**action_context.get(), **fields}.items():
            if key == 'ingestion_ref' and isinstance(value, str) and re.fullmatch(r'[0-9a-f]{24}', value):
                item[key] = value
            elif key in INGEST_ENUMS and isinstance(value, str) and value in INGEST_ENUMS[key]:
                item[key] = value
            elif key in ENUM_FIELDS and isinstance(value, str) and value in ENUM_FIELDS[key]:
                item[key] = value
            elif key == 'rpc_error_code' and type(value) is int and value in RPC_ERROR_CODES:
                item[key] = value
            elif key in TEXT_FIELDS and isinstance(value, str) and re.fullmatch(r'[a-zA-Z0-9_.:-]{1,100}', value):
                item[key] = value
            elif key in NUMBER_FIELDS and type(value) in (int,float) and 0 <= value < 10**15:
                item[key] = round(value, 2) if isinstance(value, float) else value
        message = json.dumps(item, separators=(',',':'), ensure_ascii=True)
        try:
            self.handler.handle(logging.LogRecord('whatsapp.diagnostics', logging.INFO, '', 0, message, (), None))
        except (OSError, ValueError):
            # Logging availability must not change a committed ingestion or an
            # HTTP result. Never print the original record/exception on failure.
            print('{"event":"diagnostics.write_failed","level":"error"}', flush=True)

    def close(self):
        if self.handler: self.handler.close()


class RequestDiagnostics:
    """No request-body reads; finite headers and bounded error codes only for MCP."""
    def __init__(self, app, diagnostics):
        self.app, self.diagnostics = app, diagnostics

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        identifier = secrets.token_hex(12)
        context = request_id.set(identifier)
        started, status = time.monotonic(), 500
        path = scope.get('path','')
        routes = {'/mcp':'mcp','/webhooks/waha':'webhook','/healthz':'health',
                  '/connect':'link.page','/connect/':'link.page','/connect/login':'link.login',
                  '/connect/callback':'link.callback','/connect/api/status':'link.status',
                  '/connect/api/pair':'link.pair','/connect/api/logout':'link.logout','/connect/qr':'link.qr'}
        route = routes.get(path, 'files' if path.startswith('/files/') else 'other')
        authentication = AuthAdmission(scope) if route == 'mcp' else None
        mcp = MCPObservation(scope) if route == 'mcp' else None
        auth_context = auth_admission.set(authentication)
        response_started = response_ended = False
        async def response(message):
            nonlocal status, response_started, response_ended
            if message['type'] == 'http.response.start':
                response_started = True
                # Legacy MCP supplies HTTPStatus (an IntEnum); the log's strict
                # numeric allowlist otherwise drops it. Do not alter the response.
                status = int(message['status'])
                if mcp is not None:
                    mcp.start(message)
                if authentication is not None:
                    for key, value in message.get('headers', ()):
                        if key.lower() == b'www-authenticate' and value.lower().startswith(b'bearer '):
                            for code in ('invalid_token', 'insufficient_scope'):
                                if ('error="' + code + '"').encode() in value:
                                    authentication.challenge = code
                message = {**message, 'headers': [*message.get('headers',[]), (b'x-request-id',identifier.encode())]}
            elif message['type'] == 'http.response.body':
                if mcp is not None:
                    mcp.chunk(message)
                if not message.get('more_body',False):
                    response_ended = True
            await send(message)
        try:
            await self.app(scope, receive, response)
        except Exception as exc:
            self.diagnostics.emit('request.failed','error',route=route,exception=type(exc).__name__,error_code='INTERNAL_ERROR')
            if not response_started:
                from starlette.responses import JSONResponse
                await JSONResponse({'error':'internal_error','request_id':identifier}, status_code=500)(scope, receive, response)
            elif not response_ended:
                await send({'type':'http.response.body','body':b'','more_body':False})
            # A partial stream must terminate; do not propagate a potentially sensitive exception.
        finally:
            if mcp is not None:
                mcp.body = None
            rejected = None
            if authentication is not None:
                fields = authentication.rejected_fields(status)
                if fields:
                    rejected = fields
                    self.diagnostics.emit('auth.rejected', 'warning', route=route, status=status,
                                          credential_state=authentication.credential_state, **fields)
            if route not in ('health','link.status','other') or status >= 400:
                layer = None
                if status >= 400:
                    layer = ('authorization' if rejected and status == 403 else
                             'authentication' if rejected else
                             'mcp_protocol' if mcp is not None and 'rpc_error_code' in mcp.fields else
                             'http_routing' if route in ('other','link.page') and status in (404,405) else
                             'webhook_admission' if route == 'webhook' and status in (400,401,413) else
                             'application_or_transport' if status >= 500 else 'undetermined')
                self.diagnostics.emit('request.completed', 'error' if status>=500 else 'warning' if status>=400 else 'info',
                    route=route,method=scope.get('method',''),status=status,duration_ms=(time.monotonic()-started)*1000,
                    http_failure_layer=layer,
                    **(mcp.fields if mcp is not None else {}))
            auth_admission.reset(auth_context)
            request_id.reset(context)
