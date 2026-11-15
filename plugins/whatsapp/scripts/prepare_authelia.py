"""Prepare a dedicated user and OIDC candidate. Does not activate configuration.

Run on Develative as root with this project's virtual environment. Secrets remain
in root-only server storage and are never printed. Existing users are preserved.
"""
from pathlib import Path
import datetime
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from sally_whatsapp.tenancy import CHATGPT_CALLBACK, CHATGPT_OIDC_SCOPES
from sally_whatsapp.installation import active as installation_profile

if not installation_profile().compatibility:
    raise SystemExit('This historical managed-Authelia adapter requires the explicit legacy layout; use the configured external OIDC provider')

ROOT = Path('/srv/openai-codex/projects/whatsapp-personal')
PRIVATE = ROOT / 'private'
AUTH = Path('/var/lib/sally-browser/stack/config')
AS_USER = '/srv/openai-codex/projects/sally-browser/bin/as-user'
USERNAME = 'whatsapp-personale'
os.umask(0o077)
PRIVATE.mkdir(mode=0o700, exist_ok=True)
cfg = json.loads((AUTH / 'authelia.yml').read_text())
users = json.loads((AUTH / 'users.yml').read_text())
if cfg.get('identity_providers', {}).get('oidc'):
    raise SystemExit('OIDC is already configured; inspect before merging')
if USERNAME in users['users']:
    raise SystemExit('Dedicated identity already exists; do not replace credentials')

credentials_path = PRIVATE / 'identity.json'
if not credentials_path.exists():
    result = subprocess.run([AS_USER, 'podman', 'exec', 'sally-auth', 'authelia',
        'crypto', 'hash', 'generate', 'argon2', '--random', '--random.length', '40'],
        check=True, capture_output=True, text=True)
    password = re.search(r'^Random Password: (.+)$', result.stdout, re.M)
    digest = re.search(r'^Digest: (.+)$', result.stdout, re.M)
    if not password or not digest:
        raise SystemExit('Password generator output could not be parsed; output withheld')
    credentials_path.write_text(json.dumps({'username': USERNAME,
        'display_name': 'WhatsApp personale', 'password': password.group(1),
        'password_hash': digest.group(1), 'subject': str(uuid.uuid4())}, indent=2))
identity = json.loads(credentials_path.read_text())
users['users'][USERNAME] = {'disabled': False, 'displayname': 'WhatsApp personale',
    'password': identity['password_hash'], 'groups': ['whatsapp-personal']}

keypath = PRIVATE / 'oidc-signing.pem'
if not keypath.exists():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
secretpath = PRIVATE / 'oidc-hmac.key'
if not secretpath.exists():
    secretpath.write_text(secrets.token_hex(48))

scopes = ['whatsapp:read', 'whatsapp:events', 'whatsapp:send']
cfg.setdefault('identity_providers', {})['oidc'] = {
    'hmac_secret': secretpath.read_text(),
    'jwks': [{'key_id': 'whatsapp-personal-20261011', 'algorithm': 'RS256',
              'use': 'sig', 'key': keypath.read_text()}],
    'enforce_pkce': 'always',
    'enable_pkce_plain_challenge': False,
    'authorization_policies': {'whatsapp_personal_only': {
        'default_policy': 'deny',
        'rules': [{'policy': 'two_factor', 'subject': [['user:' + USERNAME]]}]}},
    'scopes': {scope: {'claims': []} for scope in scopes},
    'lifespans': {'access_token': '1h', 'refresh_token': '30d',
                  'id_token': '1h', 'authorize_code': '1m'},
    'clients': [{'client_id': 'whatsapp-personal-chatgpt',
        'client_name': 'WhatsApp personale - ChatGPT', 'public': True,
        'authorization_policy': 'whatsapp_personal_only',
        'consent_mode': 'explicit',
        # Verify this registered callback against the target ChatGPT connection.
        'redirect_uris': [CHATGPT_CALLBACK],
        'audience': ['https://whatsapp.example.invalid'],
        'scopes': [*CHATGPT_OIDC_SCOPES, *scopes],
        'grant_types': ['authorization_code', 'refresh_token'],
        'response_types': ['code'], 'response_modes': ['query'],
        'require_pkce': True, 'pkce_challenge_method': 'S256',
        'access_token_signed_response_alg': 'RS256',
        'token_endpoint_auth_method': 'none'}]
}
(PRIVATE / 'authelia.candidate.json').write_text(json.dumps(cfg, indent=2))
(PRIVATE / 'users.candidate.json').write_text(json.dumps(users, indent=2))

backup = Path('/var/backups/whatsapp-personal') / ('before-oidc-' +
    datetime.datetime.now(datetime.UTC).strftime('%Y%m%dT%H%M%SZ'))
backup.mkdir(mode=0o700)
for name in ['authelia.yml', 'users.yml']:
    shutil.copy2(AUTH / name, backup / name)
source = sqlite3.connect('file:/var/lib/sally-browser/stack/authelia/db.sqlite3?mode=ro', uri=True)
target = sqlite3.connect(backup / 'authelia.sqlite3')
source.backup(target)
if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
    raise SystemExit('Auth database backup failed integrity check')
target.close()
source.close()
(PRIVATE / 'pre-oidc-backup.txt').write_text(str(backup))
print(json.dumps({'prepared': True, 'activated': False, 'username': USERNAME,
    'existing_users_preserved': sorted(set(users['users']) - {USERNAME}),
    'backup': str(backup)}))
