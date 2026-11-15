"""Loopback-only synthetic responses serving the actual production pages/assets.

The login routes below simulate page transitions, not OAuth validation. Real
owner/PKCE/nonce/CSRF checks are exercised separately by test_linking.py.
"""
import asyncio
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from sally_whatsapp.linking import LinkPortal, LinkError, HEADERS

SOURCE = Path(__file__).resolve().parents[2] / 'plugins/whatsapp/sally_whatsapp'
portal = object.__new__(LinkPortal)
portal.settings = SimpleNamespace(profile_name='Profilo dimostrativo · utenza di prova')
state = {}


def session(request):
    if not state['authenticated']:
        raise LinkError('The page session expired. Sign in again.', 401)
    return {'csrf': 'synthetic-browser-fixture'}


portal.session = session


def reset():
    state.update(state='FAILED', revision=0, qr_reads=0, pairs=0,
                 authenticated=True, wrong_owner=False, reject_pair=False)


reset()


def result():
    value = {'state': state['state'], 'connected': state['state'] == 'WORKING'}
    if state['state'] == 'SCAN_QR_CODE':
        value['qr_revision'] = str(state['revision'])
    return value


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, body, mime='application/json', status=200, location=None):
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        for key, value in HEADERS.items():
            self.send_header(key, value)
        if location:
            self.send_header('Location', location)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/connect':
            return self.respond(asyncio.run(portal.page(None)).body, 'text/html; charset=utf-8')
        if path == '/connect/login':
            state['authenticated'] = False
            return self.respond('', status=302, location='/connect/callback')
        if path == '/connect/callback':
            if state['wrong_owner']:
                response = portal.login_error('This account is not authorized for the profile.', 403)
                return self.respond(response.body, 'text/html; charset=utf-8', response.status_code)
            state['authenticated'] = True
            return self.respond('', status=303, location='/connect')
        assets = {'/connect/static/app.js': ('assets/connect.js', 'application/javascript'),
                  '/connect/static/style.css': ('assets/connect.css', 'text/css'),
                  '/assets/whatsapp-gpt.png': ('assets/whatsapp-gpt.png', 'image/png')}
        if path in assets:
            file, mime = assets[path]
            return self.respond((SOURCE / file).read_bytes(), mime)
        if path in ('/connect/api/status', '/connect/qr') and not state['authenticated']:
            return self.respond({'error': 'The page session expired. Sign in again.'}, status=401)
        if path == '/connect/api/status':
            return self.respond(result())
        if path == '/test/receipt':
            return self.respond(state)
        if path == '/connect/qr':
            state['qr_reads'] += 1
            return self.respond('<svg xmlns="http://www.w3.org/2000/svg" width="260" height="260"><rect width="260" height="260" fill="#eef6f0"/><text x="24" y="130">QR SIMULATO ' + str(state['revision']) + '</text></svg>', 'image/svg+xml')
        return self.respond({}, status=404)

    def do_POST(self):
        path = urlsplit(self.path).path
        length = int(self.headers.get('Content-Length', '0'))
        if length > 4096:
            return self.respond({}, status=413)
        raw = self.rfile.read(length)
        if path.startswith('/connect/api/'):
            if not state['authenticated']:
                return self.respond({'error': 'The page session expired. Sign in again.'}, status=401)
            if self.headers.get('X-CSRF-Token') != 'synthetic-browser-fixture':
                return self.respond({'error': 'The request expired. Reload the page.'}, status=403)
        if path == '/connect/api/pair':
            state['pairs'] += 1
            if state['reject_pair']:
                return self.respond({'error': 'Wait 30 seconds before requesting another code or QR.'}, status=429)
            body = json.loads(raw)
            state.update(state='SCAN_QR_CODE', revision=state['revision'] + 1)
            value = result()
            value.update({'qr_url': '/connect/qr'} if body['mode'] == 'qr' else {'code': 'TEST-ONLY'})
            return self.respond(value)
        if path == '/connect/api/logout':
            state['authenticated'] = False
            return self.respond({'signed_out': True})
        if path == '/test/reset':
            reset()
        elif path == '/test/rotate':
            state['revision'] += 1
        elif path == '/test/fail':
            state['state'] = 'FAILED'
        elif path == '/test/working':
            state['state'] = 'WORKING'
        elif path == '/test/expire':
            state['authenticated'] = False
        elif path == '/test/wrong-owner':
            state.update(authenticated=False, wrong_owner=True)
        elif path == '/test/correct-owner':
            state['wrong_owner'] = False
        elif path == '/test/reject-pair':
            state['reject_pair'] = True
        else:
            return self.respond({}, status=404)
        return self.respond({})


if __name__ == '__main__':
    print('Synthetic portal fixture on loopback:8875', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8875), Handler).serve_forever()
