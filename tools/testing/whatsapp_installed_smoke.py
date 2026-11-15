"""Qualify an installed WhatsApp wheel with synthetic state and no IP network.

Run with the new virtualenv's ``python -I`` from outside the checkout. See
plugins/whatsapp/docs/INSTALLATION.md for build/install/restart commands.
This is a development probe, never an installer or a production health check.
"""
import argparse
import asyncio
from dataclasses import replace
import hashlib
import importlib.metadata
import importlib.resources
import json
import os
from pathlib import Path
import socket
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True, help='Isolated qualification directory')
parser.add_argument('--version', required=True, help='Expected wheel version')
parser.add_argument('--phase', choices=('first', 'repeat'), required=True)
args = parser.parse_args()
root = args.output.resolve(strict=True)
run = args.phase
assert sys.flags.isolated == 1
runtime = root / 'runtime'
assert runtime.exists() == (run == 'repeat'), 'First requires new state; repeat requires existing state'
runtime.mkdir(exist_ok=True, mode=0o700)
network_attempts = []
original_connect = socket.socket.connect
def guarded_connect(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        network_attempts.append(str(address))
        raise AssertionError('This smoke permits no IPv4/IPv6 connection')
    return original_connect(sock, address)
socket.socket.connect = guarded_connect

import sally_whatsapp
from sally_whatsapp import installation
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

installed_root = Path(sally_whatsapp.__file__).resolve().parent
assert installed_root.is_relative_to(Path(sys.prefix).resolve()), installed_root
assert 'site-packages' in installed_root.parts
identity_root = runtime / 'synthetic-host'
identity_root.mkdir(exist_ok=True, mode=0o700)
marker = identity_root / installation.IDENTITY.relative_to('/')
marker.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
if not marker.exists():
    marker.write_bytes(installation.identity_bytes(installation.Installation.legacy()))
    marker.chmod(0o600)
installation.activate_installation(root=identity_root, trusted_uid=os.getuid())

webhook = runtime / 'webhook.key'
encryption = runtime / 'encryption.key'
public = runtime / 'public.pem'
if not webhook.exists():
    webhook.write_text('synthetic-offline-smoke-webhook-key-only-20261021')
    encryption.write_bytes(Fernet.generate_key())
    public.write_bytes(rsa.generate_private_key(public_exponent=65537, key_size=2048)
                      .public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo))
    for path in (webhook, encryption, public):
        path.chmod(0o600)

from sally_whatsapp.config import Settings
from sally_whatsapp.gateway import DisconnectedGateway
from sally_whatsapp.server import create_app
from starlette.testclient import TestClient

settings = Settings(database=runtime / 'state.sqlite', public_url='https://bridge.example',
                    issuer='https://issuer.example', owner_subject='synthetic-owner',
                    webhook_secret_file=webhook, encryption_key_file=encryption,
                    public_key_file=public, oauth_client_ids=['synthetic-client'],
                    allowed_hosts=['testserver'])
assert not any((settings.live_account_enabled, settings.send_enabled,
                settings.account_actions_enabled, settings.link_enabled, settings.admin_enabled))
class ObservedDisconnectedGateway(DisconnectedGateway):
    closed = False
    def __init__(self):
        self.provider_requests = []
    def request(self, *args, **kwargs):
        self.provider_requests.append(args)
        raise AssertionError('Prepared instance must not contact provider')
    send = messages = chats = contacts = attachment = pairing_qr = ab_operations = request
    def close(self):
        self.closed = True
        super().close()

gateway = ObservedDisconnectedGateway()
app = create_app(settings, gateway=gateway, start_worker=True,
                 maintenance_gate=runtime / 'no-maintenance')
service = app.state.service
assert service.gateway.status() == 'NOT_LINKED'
service._prepare_serving()
service._prepare_serving()
with service.store.db() as db:
    schema = db.execute('PRAGMA user_version').fetchone()[0]
assert schema == 8
sentinel = 'private:clean-qualification'
with service.store.db() as db:
    row = db.execute('SELECT value FROM state WHERE key=?', (sentinel,)).fetchone()
before = json.loads(row[0]) if row else None
if run == 'first':
    assert before is None
    service.store.set_state(sentinel, {'synthetic': True, 'persisted': True})
else:
    assert before == {'synthetic': True, 'persisted': True}, before

async def wait_ready(readiness):
    async with asyncio.timeout(10):
        while not readiness.ready:
            assert readiness.state != 'failed', readiness.snapshot()
            await asyncio.sleep(0.01)

with TestClient(app, base_url='https://testserver') as client:
    client.portal.call(wait_ready, app.state.readiness)
    health = client.get('/healthz')
    assert health.status_code == 200
    health_value = health.json()
    assert health_value['version'] == args.version
    assert health_value['readiness']['ready'] is True
    assert all(health_value['readiness']['workers'].values())
    assert health.headers['cache-control'] == 'no-store'
    metadata = client.get('/.well-known/oauth-protected-resource')
    assert metadata.status_code == 200
    assert metadata.json()['resource'] == settings.public_url
    icon = client.get('/assets/whatsapp-gpt.png')
    assert icon.status_code == 200
    assert icon.content.startswith(b'\x89PNG\r\n\x1a\n')
    assert icon.headers['x-content-type-options'] == 'nosniff'
    unauthorized = client.post('/mcp', json={
        'jsonrpc':'2.0', 'id':1, 'method':'tools/list', 'params':{}})
    assert unauthorized.status_code == 401, unauthorized.text
    assert client.get('/admin').status_code == 404

assert gateway.closed
assert not app.state.readiness.ready
assert not any(app.state.readiness.workers.values())
assert not app.state.readiness.shutdown_timed_out.is_set()
assert not gateway.provider_requests

# A prepared owner portal must work before activation of a phone account.
prepared = replace(settings, admin_enabled=True, link_enabled=False, live_account_enabled=False,
                   link_client_id='synthetic-owner-portal',
                   link_authorize_url='https://issuer.example/authorize',
                   link_token_url='https://issuer.example/token')
prepared_gateway = ObservedDisconnectedGateway()
prepared_app = create_app(prepared, gateway=prepared_gateway, start_worker=True,
                          maintenance_gate=runtime / 'no-maintenance')
with TestClient(prepared_app, base_url='https://testserver') as client:
    client.portal.call(wait_ready, prepared_app.state.readiness)
    prepared_health = client.get('/healthz').json()
    assert prepared_health['readiness']['ready'] is True
    assert set(prepared_health['readiness']['workers']) == {'events','transfers','history','actions','portal'}
    assert all(prepared_health['readiness']['workers'].values())
    assert client.get('/connect').status_code == 200
    assert client.get('/admin').status_code == 401
    assert client.get('/admin/api/connection').status_code == 401
    assert client.get('/admin/api/status').status_code == 401
assert prepared_gateway.closed
assert not prepared_gateway.provider_requests
assert not prepared_app.state.readiness.ready
assert not any(prepared_app.state.readiness.workers.values())
assert not prepared_app.state.readiness.shutdown_timed_out.is_set()
assert prepared_app.state.link_portal.client.is_closed
assert not network_attempts, network_attempts
assets = {}
for relative in ('operations.json', 'assets/admin.js', 'assets/admin.css',
                 'assets/whatsapp-gpt.png', 'migrations/6-7.sql', 'migrations/7-8.sql'):
    data = importlib.resources.files('sally_whatsapp').joinpath(relative).read_bytes()
    assert data, relative
    assets[relative] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
dependencies = {dist.metadata['Name']: dist.version for dist in importlib.metadata.distributions()}
assert dependencies['certifi'] == '2026.10.19'
assert importlib.metadata.version('whatsapp-personal-bridge') == args.version
result = {'run': run, 'python': sys.version, 'executable': sys.executable,
          'isolated': sys.flags.isolated, 'cwd': str(Path.cwd()),
          'installed_module': str(installed_root), 'schema': schema,
          'health': health_value, 'provider': service.gateway.status(),
          'repeated_prepare': 'passed', 'sentinel_restored': run != 'first',
          'gateway_closed': gateway.closed, 'network_connection_attempts': network_attempts,
          'prepared_admin': {'health': prepared_health, 'gateway_closed': prepared_gateway.closed,
                             'provider_requests': prepared_gateway.provider_requests,
                             'oauth_client_closed': prepared_app.state.link_portal.client.is_closed,
                             'http_checks': {'connect': 200, 'admin': 401, 'connection': 401, 'status': 401}},
          'assets': assets, 'dependencies': dependencies,
          'http_checks': {'health': 200, 'metadata': 200, 'icon': 200,
                          'unauthenticated_mcp': 401, 'disabled_admin': 404}}
(root / ('smoke-' + run + '.json')).write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
