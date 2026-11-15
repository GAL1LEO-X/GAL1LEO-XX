"""Offline candidate check, using synthetic credentials and private database copies."""
import asyncio
import json
from pathlib import Path
import secrets
import sys
import tempfile
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient
from sally_whatsapp.config import Settings
from sally_whatsapp.server import create_app
from sally_whatsapp.store import Store
from release_runtime import Maintenance


def check_readiness(payload, state):
    readiness=payload['readiness']
    assert isinstance(readiness,dict), 'Invalid readiness contract'
    expected=state=='ready'
    assert readiness.get('state')==state
    assert readiness.get('ready') is expected
    workers=readiness.get('workers')
    assert isinstance(workers,dict)
    assert set(workers)=={'events','transfers','history','actions'}
    assert all(value is expected for value in workers.values())


def main():
    for filename in sys.argv[1:]:
        Store(Path(filename),recover_inflight=False)
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        public=root/'public.pem'
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        webhook=root/'webhook.key';webhook.write_text(secrets.token_hex(32))
        encryption=root/'encryption.key';encryption.write_bytes(Fernet.generate_key())
        gate=root/'maintenance';gate.touch()
        settings=Settings(database=root/'archive.sqlite',public_url='https://release.invalid',
            issuer='https://issuer.invalid',owner_subject='synthetic',public_key_file=public,
            webhook_secret_file=webhook,encryption_key_file=encryption,allowed_hosts=['testserver'],
            oauth_client_ids=['release-probe'],diagnostics_enabled=False)
        # This is a new disposable fixture, not a missing registered tenant.
        # The maintenance/check path must keep refusing absent databases.
        Store(settings.database,recover_inflight=False)
        event=asyncio.Event()
        app=create_app(settings,recover_inflight=False,activation_event=event)
        calls=[]
        async def worker():
            calls.append('started')
            await asyncio.Event().wait()
        service=app.state.service
        for name in ('worker','transfer_worker','history_worker','action_worker'):
            setattr(service,name,worker)
        with TestClient(Maintenance(app,event,gate)) as client:
            health=client.get('/healthz')
            assert health.status_code==200
            payload=health.json()
            readiness_contract='readiness' in payload
            if readiness_contract:
                check_readiness(payload,'waiting')
            assert client.post('/mcp').status_code==503
            assert client.post('/webhooks/waha').status_code==503
            assert not calls, 'Workers started before activation'
            gate.unlink()
            for _ in range(100):
                if len(calls)==4:break
                time.sleep(.02)
            assert len(calls)==4, 'Workers did not start after activation'
            health=client.get('/healthz')
            assert health.status_code==200
            payload=health.json()
            assert ('readiness' in payload) is readiness_contract, 'Readiness contract changed during activation'
            if readiness_contract:
                check_readiness(payload,'ready')
            assert client.get('/mcp').status_code==401
        print(json.dumps({'passed':True,'offlineDatabases':len(sys.argv)-1,'maintenanceGate':True,
                          'workersGated':True,'readinessContract':readiness_contract}))


if __name__=='__main__':main()
