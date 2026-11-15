"""Collect a sanitized, read-only technical report for one managed user."""
import argparse
from collections import Counter, deque
from datetime import datetime, UTC
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time

import httpx
from sally_whatsapp import __version__
from sally_whatsapp.config import Settings
from sally_whatsapp.store import Store
from sally_whatsapp.media_diagnostics import quota_snapshot
from sally_whatsapp.tenancy import Instance, ROOT


def inspect(instance, hours, tail):
    settings=Settings.load(str(instance.config_dir/'config.toml'))
    report={'format':'whatsapp-diagnostics-v1','generated_utc':datetime.now(UTC).isoformat(),
            'user':instance.slug,'version':__version__,'window_hours':hours,'credentials_included':False}
    report['services']={}
    for label,command in [('bridge',['systemctl','is-active',instance.base+'.service']),
                          ('gateway',[str(instance.wrapper),'systemctl','--user','is-active','whatsapp-waha.service'])]:
        result=subprocess.run(command,capture_output=True,text=True)
        value=result.stdout.strip()
        report['services'][label]=value if value in ('active','inactive','failed','activating','deactivating') else 'unknown'
    with httpx.Client(timeout=5,trust_env=False,follow_redirects=False) as client:
        try:
            response=client.get(f'http://127.0.0.1:{instance.bridge_port}/healthz')
            value=response.json()
            report['health']={'status':response.status_code,'version':value.get('version'),'process':value.get('process')}
        except (httpx.HTTPError,ValueError): report['health']={'error':'bridge_unreachable'}
        try:
            response=client.get(f'http://127.0.0.1:{instance.gateway_port}/api/sessions/default',
                                headers={'X-Api-Key':settings.waha_key_file.read_text().strip()})
            value=response.json().get('status') if response.is_success else None
            report['whatsapp_state']=value if value in ('WORKING','STOPPED','STARTING','SCAN_QR_CODE','FAILED','PASSKEY_REQUIRED','PASSKEY_CONFIRMATION_REQUIRED') else 'UNKNOWN'
        except (httpx.HTTPError,ValueError): report['whatsapp_state']='UNREACHABLE'
    with sqlite3.connect('file:'+str(settings.database)+'?mode=ro',uri=True) as db:
        db.execute('BEGIN')
        report['sqlite_schema']=db.execute('PRAGMA user_version').fetchone()[0]
        report['queues']={table:dict(db.execute('SELECT state,count(*) FROM '+table+' GROUP BY state'))
                          for table in ('sends','deliveries','media_jobs','history_jobs')}
        report['media_cache']=quota_snapshot(db,settings)
        report['active_subscriptions']=db.execute('SELECT count(*) FROM subscriptions WHERE active=1 AND expires>?',(time.time(),)).fetchone()[0]
        allowed=['last_connection_check_at','last_message_ingested_at','last_webhook_at','last_history_ingested_at',
                 'last_worker_error_at','recovery_required','recovery_reasons']
        report['runtime']={key:json.loads(value) for key,value in db.execute('SELECT key,value FROM state') if key in allowed}
        # Match connection_status, including legacy flags without a stored cause.
        # Calling Store's constructor would run schema/repair code; use only its reader.
        report['runtime']['recovery_reasons']=Store._recovery_reasons(db)
    files=sorted((settings.database.parent/'diagnostics').glob('events.jsonl*'),key=lambda p:p.stat().st_mtime)
    cutoff=time.time()-hours*3600
    recent=deque(maxlen=tail)
    codes=Counter();levels=Counter();events=Counter()
    bad=0
    for path in files:
        with path.open(encoding='utf-8') as stream:
            for line in stream:
                try:
                    row=json.loads(line)
                    if datetime.fromisoformat(row['at']).timestamp()<cutoff: continue
                    recent.append(row)
                    levels[row['level']]+=1;events[row['event']]+=1
                    if row.get('error_code'): codes[row['error_code']]+=1
                except (ValueError,KeyError,TypeError): bad+=1
    report['logs']={'bytes':sum(p.stat().st_size for p in files),'files':len(files),'malformed_rows':bad,
                    'levels':dict(levels),'events':dict(events),'error_codes':dict(codes),'recent':list(recent),
                    'retention':'size_rotation_only','limit_bytes':settings.diagnostics_max_bytes*(1+settings.diagnostics_backups)}
    report['disk_free_bytes']=shutil.disk_usage(settings.database.parent).free
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user',default='personal')
    parser.add_argument('--hours',type=int,default=24)
    parser.add_argument('--tail',type=int,default=200)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if os.geteuid()!=0: raise SystemExit('Run as the authorized server administrator')
    if not 1<=args.hours<=720 or not 1<=args.tail<=5000: raise SystemExit('Hours 1..720; tail 1..5000')
    os.umask(0o077)
    data=json.loads((ROOT/'private/tenants.json').read_text())
    if args.user not in data['instances']: raise SystemExit('Unknown managed user')
    report=inspect(Instance(**data['instances'][args.user]['spec']),args.hours,args.tail)
    content=json.dumps(report,indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with args.output.open('x',encoding='utf-8') as stream: stream.write(content+'\n')
        print(json.dumps({'report':str(args.output),'credentials_included':False}))
    else: print(content)


if __name__=='__main__': main()
