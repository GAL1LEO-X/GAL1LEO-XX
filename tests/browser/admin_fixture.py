"""Real HTTPS ASGI admin API; only identity issuance/provider are synthetic.

All keys, session records and SQLite state live in a TemporaryDirectory. Test
routes are defined here only, never in the runtime package. No external I/O.
"""
from datetime import datetime, timedelta, timezone
from dataclasses import replace
import base64
import ipaddress
from pathlib import Path
import secrets
import tempfile
import time

import jwt
import uvicorn
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route

from sally_whatsapp.config import Settings
from sally_whatsapp.event_policies import normalize_filters
from sally_whatsapp.linking import COOKIE, digest
from sally_whatsapp.server import create_app
from sally_whatsapp.store import canonical
from admin_broker_fixture import SyntheticAdminHost


class SyntheticGateway:
    def __init__(self):
        self.state = 'STOPPED'
        self.session = 'default'
        self.requests = []
        self.qr_reads = 0

    def ab_operations(self):
        return frozenset()

    def request(self, method, path, **kwargs):
        self.requests.append({'method':method,'path':path})
        if method == 'GET' and path == '/api/sessions/default':
            return {'status':self.state,'me':{'id':'synthetic-provider-identity-never-exposed'}}
        if method == 'POST' and path in ('/api/sessions/default/start','/api/sessions/default/restart'):
            self.state = 'SCAN_QR_CODE'
            return {}
        if method == 'POST' and path == '/api/default/auth/request-code':
            return {'code':'TEST-ONLY'}
        raise AssertionError('Unexpected synthetic provider request')

    def pairing_qr(self):
        self.qr_reads += 1
        return base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=')

    def close(self):
        pass


def main():
    with tempfile.TemporaryDirectory(prefix='whatsapp-admin-browser-') as directory:
        root = Path(directory)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        (root/'key.pem').write_bytes(private)
        (root/'public.pem').write_bytes(public)
        (root/'webhook.key').write_text(secrets.token_hex(32))
        (root/'encryption.key').write_bytes(Fernet.generate_key())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
                .not_valid_after(now+timedelta(days=1)).add_extension(
                    x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                .sign(key, hashes.SHA256()))
        (root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        settings = Settings(database=root/'state.sqlite', public_url='https://127.0.0.1:8876',
            issuer='https://issuer.invalid', owner_subject='synthetic-owner',
            webhook_secret_file=root/'webhook.key', encryption_key_file=root/'encryption.key',
            public_key_file=root/'public.pem', waha_key_file=root/'webhook.key',
            live_account_enabled=True, link_enabled=True, admin_enabled=True,
            link_client_id='synthetic-portal', link_authorize_url='https://issuer.invalid/authorize',
            link_token_url='https://issuer.invalid/token', oauth_client_ids=['synthetic-mcp'],
            allowed_hosts=['127.0.0.1:8876'], profile_name='Istanza sintetica · browser API reale')
        gateway = SyntheticGateway()
        app = create_app(settings, gateway=gateway, start_worker=False)
        service = app.state.service
        synthetic_host = None

        async def login(request):
            sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            token = jwt.encode({'iss':settings.issuer, 'aud':settings.public_url, 'sub':settings.owner_subject,
                'azp':settings.link_client_id, 'scope':'whatsapp:link', 'iat':int(time.time()),
                'exp':int(time.time())+600}, private, algorithm='RS256')
            with service.store.db() as db:
                db.execute('INSERT INTO link_sessions VALUES(?,?,?,?,?)',
                    (digest(sid),settings.owner_subject,app.state.link_portal.cipher.encrypt(token.encode()),csrf,time.time()+600))
            response = RedirectResponse('/admin', status_code=303)
            response.set_cookie(COOKIE, sid, secure=True, httponly=True, samesite='strict', path='/')
            return response

        async def seed(request):
            job = service.history.start(settings.owner_subject, secrets.token_hex(16), ['synthetic@c.us'])
            return JSONResponse({'id':job['id']})

        async def history(request):
            return JSONResponse(service.history.status(request.path_params['job'], settings.owner_subject))

        async def reset_records(request):
            with service.store.db() as db:
                for table in ('deliveries', 'subscription_keys', 'subscriptions', 'history_jobs'):
                    db.execute('DELETE FROM ' + table)
                db.execute("DELETE FROM state WHERE key LIKE 'private:admin:job:%'")
            return JSONResponse({'reset': True})

        async def seed_records(request):
            # Deterministic bounded-list fixture; no callbacks or workers.
            await reset_records(request)
            first = service.history.start(settings.owner_subject, secrets.token_hex(16), ['synthetic@c.us'])
            for _ in range(100):
                job = service.history.start(settings.owner_subject, secrets.token_hex(16), ['synthetic@c.us'])
                service.history.control(job['id'], settings.owner_subject, 'cancel')
            filters = normalize_filters('message.received', {'all_chats': True})
            rows = sorted((service.events.identity(settings.owner_subject, 'message.received', filters, url), url)
                          for url in ('https://callback.invalid/synthetic/' + str(i) for i in range(101)))
            secret = service.events.cipher.encrypt(b'whsec_' + base64.b64encode(b'synthetic-key-for-browser-fixture'))
            with service.store.db() as db:
                for i, (identifier, url) in enumerate(rows):
                    db.execute('INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?)',
                        (identifier, settings.owner_subject, 'message.received', canonical(filters), url,
                         secret, time.time()+3600, int(i == 100)))
            return JSONResponse({'history': first['id'], 'subscription': rows[-1][0]})

        async def configure(request):
            # Synthetic config reload models a separately admitted host transition.
            # It is never an admin API and never appears in the packaged backend.
            prepared = request.path_params['phase'] == 'prepared'
            current = replace(settings, live_account_enabled=not prepared, link_enabled=not prepared)
            service.settings = current
            app.state.link_portal.settings = current
            gateway.state = 'STOPPED'
            gateway.requests.clear()
            gateway.qr_reads = 0
            with service.store.db() as db:
                db.execute('DELETE FROM link_rate_limit')
            return JSONResponse({'phase':'prepared' if prepared else 'activated','synthetic_configuration_only':True})

        async def phone(request):
            state = request.path_params['state']
            if state not in ('FAILED','WORKING','SCAN_QR_CODE','STOPPED'):
                return JSONResponse({},status_code=400)
            gateway.state = state
            with service.store.db() as db:
                db.execute('DELETE FROM link_rate_limit')
            return JSONResponse({'state':state})

        async def expire(request):
            with service.store.db() as db:
                db.execute('UPDATE link_sessions SET expires=?',(time.time()-1,))
            return JSONResponse({'expired':True})

        async def receipt(request):
            with service.store.db() as db:
                journal = [row[0] for row in db.execute("SELECT value FROM state WHERE key LIKE 'private:admin:%'")]
            return JSONResponse({'requests':gateway.requests,'qr_reads':gateway.qr_reads,'journal':journal})

        async def host_start(request):
            nonlocal synthetic_host
            if synthetic_host:
                synthetic_host.close()
            body = await request.json()
            synthetic_host = SyntheticAdminHost(root / secrets.token_hex(8), settings.owner_subject,
                                                hold=body.get('hold') is True)
            app.state.admin_portal.operations.broker = synthetic_host.client
            return JSONResponse(synthetic_host.observation())

        async def host_state(request):
            return JSONResponse(synthetic_host.observation() if synthetic_host else {'effects': 0, 'ids': []})

        async def host_release(request):
            synthetic_host.release.set()
            return JSONResponse({'released': True})

        async def host_stop(request):
            nonlocal synthetic_host
            app.state.admin_portal.operations.broker = None
            if synthetic_host:
                synthetic_host.close()
                synthetic_host = None
            return JSONResponse({'stopped': True})

        app.router.routes.insert(0, Route('/test/login', login))
        app.router.routes.insert(0, Route('/test/history', seed, methods=['POST']))
        app.router.routes.insert(0, Route('/test/history/{job}', history))
        app.router.routes.insert(0, Route('/test/admin-records', seed_records, methods=['POST']))
        app.router.routes.insert(0, Route('/test/admin-records/reset', reset_records, methods=['POST']))
        app.router.routes.insert(0, Route('/test/configure/{phase}', configure, methods=['POST']))
        app.router.routes.insert(0, Route('/test/phone/{state}', phone, methods=['POST']))
        app.router.routes.insert(0, Route('/test/expire', expire, methods=['POST']))
        app.router.routes.insert(0, Route('/test/receipt', receipt))
        app.router.routes.insert(0, Route('/test/broker/start', host_start, methods=['POST']))
        app.router.routes.insert(0, Route('/test/broker/state', host_state))
        app.router.routes.insert(0, Route('/test/broker/release', host_release, methods=['POST']))
        app.router.routes.insert(0, Route('/test/broker/stop', host_stop, methods=['POST']))
        try:
            # Browser polling waits five seconds. Keep the synthetic control
            # client's idle connection beyond that boundary; no request retry.
            uvicorn.run(app, host='127.0.0.1', port=8876, ssl_keyfile=str(root/'key.pem'),
                        ssl_certfile=str(root/'cert.pem'), log_level='warning', access_log=False,
                        timeout_keep_alive=30)
        finally:
            if synthetic_host:
                synthetic_host.close()


if __name__ == '__main__':
    main()
