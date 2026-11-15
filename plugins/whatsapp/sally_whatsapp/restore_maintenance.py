"""Keep restored historical data offline until its reconciliation is approved.

The root restore worker creates this marker outside the restored database. Its
presence (including a damaged or unreadable marker) closes data/provider access.
It is latched for the process lifetime; deleting a file cannot activate workers.
"""
from dataclasses import replace
import json
import os
import re
import stat

from starlette.responses import JSONResponse


def required(settings):
    path = settings.encryption_key_file.parent / 'restore-maintenance.json'
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise RuntimeError('RESTORE_RECONCILIATION_REQUIRED') from None
    # A service restart during a swap must not even initialize SQLite. Only
    # the durable post-swap phase permits the owner maintenance portal.
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate restore marker field')
            value[key] = item
        return value
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('Restore marker must be regular')
            raw = stream.read(8193)
        if len(raw) > 8192:
            raise ValueError('Restore marker exceeds bound')
        marker = json.loads(raw, object_pairs_hook=unique)
        if (not isinstance(marker, dict) or set(marker) != {
                'format', 'id', 'plan_sha256', 'instance', 'phase'}
                or marker['format'] != 'whatsapp-restore-maintenance-v1'
                or marker['phase'] != 'maintenance'
                or not isinstance(marker['id'], str) or not re.fullmatch('[a-f0-9]{32}', marker['id'])
                or not isinstance(marker['plan_sha256'], str) or not re.fullmatch('[a-f0-9]{64}', marker['plan_sha256'])
                or not isinstance(marker['instance'], str) or not re.fullmatch('[a-z][a-z0-9-]{0,47}', marker['instance'])):
            raise ValueError('Restore not admitted for maintenance startup')
    except (OSError, ValueError, TypeError):
        raise RuntimeError('RESTORE_RECONCILIATION_REQUIRED') from None
    return True


def offline_settings(settings):
    return replace(settings, live_account_enabled=False, link_enabled=False,
                   send_enabled=False, account_actions_enabled=False,
                   allow_all_destinations=False, transcription_socket=None, transcription_server_uid=None)


class RestoreMaintenanceAdmission:
    """Permit owner administration/authentication, never historical data APIs."""
    AUTH_ROUTES = frozenset({
        '/connect', '/connect/', '/connect/login', '/connect/callback',
        '/connect/api/logout', '/connect/api/status',
        '/connect/static/style.css', '/connect/static/app.js',
        '/healthz', '/.well-known/oauth-protected-resource',
    })

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'websocket':
            await send({'type': 'websocket.close', 'code': 1013})
            return
        if scope['type'] == 'http':
            path = scope['path']
            if not (path in self.AUTH_ROUTES or path == '/admin' or path.startswith('/admin/')):
                await JSONResponse({
                    'error_code': 'RESTORE_RECONCILIATION_REQUIRED',
                    'message': 'Restoration in maintenance: WhatsApp data and operations require administrative reconciliation.',
                }, status_code=503, headers={'Cache-Control': 'no-store'})(scope, receive, send)
                return
        await self.app(scope, receive, send)
