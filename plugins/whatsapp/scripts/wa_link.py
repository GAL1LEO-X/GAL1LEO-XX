"""Local administrator helper for pairing. Never prints credentials or account data."""
import sys as _installation_sys
from pathlib import Path as _InstallationPath
import types as _installation_types
if 'installation_layout' not in _installation_sys.modules:
    _installation_source=_InstallationPath(__file__).with_name('installation_layout.py')
    _installation_module=_installation_types.ModuleType('installation_layout')
    _installation_module.__file__=str(_installation_source)
    _installation_sys.modules['installation_layout']=_installation_module
    try:
        exec(compile(_installation_source.read_bytes(),str(_installation_source),'exec'),_installation_module.__dict__)
    except BaseException:
        _installation_sys.modules.pop('installation_layout',None)
        raise
if getattr(_installation_sys.modules['installation_layout'], 'FORMAT', None) != 'whatsapp-installation-v1':
    raise ImportError('The whatsapp entry point cannot reuse another product installation layout')
from installation_layout import active as installation_profile, mapped as installation_path
import argparse
import base64
import json
import os
from pathlib import Path
import time
import httpx
from sally_whatsapp.account_events import PROVIDER_EVENT_TYPES

parser = argparse.ArgumentParser()
parser.add_argument('action', choices=['prepare', 'start', 'status', 'qr'])
parser.add_argument('--user',default='personal')
args = parser.parse_args()
os.umask(0o077)
root = Path(installation_path('/srv/openai-codex/projects/whatsapp-personal'))
profile=installation_profile()
conf=Path(profile.instance_paths(args.user)['configuration'])
if profile.compatibility:
    if args.user=='personal':ports={'bridge':8820,'gateway':8821}
    else:
        from sally_whatsapp.tenancy import Instance
        row=json.loads((root/'private/tenants.json').read_text())['instances'][args.user]
        selected=Instance(**row['spec']);conf=selected.config_dir
        ports={'bridge':selected.bridge_port,'gateway':selected.gateway_port}
else:ports=profile.instance_ports(args.user)
client = httpx.Client(base_url='http://127.0.0.1:'+str(ports['gateway']),
    headers={'X-Api-Key': (conf/'waha.key').read_text().strip()},
    timeout=30, follow_redirects=False, trust_env=False)

def request(method, path, **kwargs):
    try:
        response = client.request(method, path, **kwargs)
    except httpx.HTTPError:
        raise SystemExit('WAHA is not ready or reachable; retry after startup') from None
    if response.is_error:
        raise SystemExit(f'WAHA returned HTTP {response.status_code}; body withheld')
    return response

if args.action == 'prepare':
    sessions = request('GET', '/api/sessions', params={'all':'true'}).json()
    existing = next((s for s in sessions if s['name']=='default'), None)
    if existing:
        print(json.dumps({'created':False,'status':existing['status']}))
    else:
        body = {'name':'default','start':False,'config':{
            'debug':False,
            'gows':{'storage':{'messages':True,'groups':True,'chats':True,'contacts':True}},
            'webhooks':[{'url':f'http://10.0.2.2:{ports["bridge"]}/webhooks/waha',
                'events':['message.any',*PROVIDER_EVENT_TYPES],
                'hmac':{'key':(conf/'webhook.key').read_text().strip()},
                'retries':{'delaySeconds':2,'attempts':15,'policy':'linear'}}]}}
        response = request('POST','/api/sessions',json=body).json()
        print(json.dumps({'created':True,'status':response.get('status')}))
elif args.action == 'start':
    response = request('POST','/api/sessions/default/start').json()
    print(json.dumps({'status':response.get('status')}))
elif args.action == 'status':
    response = request('GET','/api/sessions/default').json()
    print(json.dumps({'name':response['name'],'status':response['status'],
                      'account_present':bool(response.get('me'))}))
else:
    for attempt in range(10):
        response = client.get('/api/default/auth/qr',params={'format':'image'},headers={'Accept':'image/png'})
        if response.is_success: break
        time.sleep(1)
    if response.is_error:
        raise SystemExit(f'QR unavailable: HTTP {response.status_code}; body withheld')
    if 'image/png' in response.headers.get('content-type',''):
        data=response.content
    else:
        payload=response.json()
        data=base64.b64decode(payload['data'],validate=True)
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        raise SystemExit('Unexpected QR image format')
    destination=(root/'private' if args.user=='personal' else root/'private/tenants'/args.user)/'pairing-qr.png'
    destination.write_bytes(data)
    os.chmod(destination,0o600)
    print(json.dumps({'qr_ready':True,'file':str(destination)}))
client.close()
