"""Offline reviewed schema8 probe. Never run on a live database or production host.

Input must be a standalone, validated private backup copy. Only fresh clones
inside a new private work directory are mutated. The real app lifespan runs
with synthetic settings, forbidden transports and inert replacement workers.
Registered copies require their original identity context and external marker.
Legacy copies without identity receive one only on disposable working clones;
this is fixture preparation, never authorization to bootstrap a live tenant.
The configured owner's profile is also prepared once on the disposable common
clone before comparison baselines; existing IDs are preserved without rewriting.
"""
import argparse
from contextlib import closing, contextmanager
import hashlib
import json
import math
from pathlib import Path
import platform
import sqlite3
import sys
import time
import tracemalloc


@contextmanager
def connect(path, *, immutable=False):
    db=sqlite3.connect(path.resolve().as_uri()+('?mode=ro&immutable=1' if immutable else '?mode=rw'),uri=True,timeout=10)
    db.row_factory=sqlite3.Row
    try: yield db
    finally: db.close()


def file_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def fingerprint(db):
    """Stream stable logical rows; never return or log row values."""
    result={}
    for name,sql in db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall():
        quoted='"'+name.replace('"','""')+'"'
        keys=[r['name'] for r in sorted(db.execute('PRAGMA table_info('+quoted+')'),key=lambda r:r['pk']) if r['pk']]
        order=','.join('"'+key.replace('"','""')+'"' for key in keys) if keys else 'rowid'
        query='SELECT '+('*' if keys else 'rowid,*')+' FROM '+quoted+' ORDER BY '+order
        digest=hashlib.sha256()
        count=0
        for row in db.execute(query):
            values=[['blob',v.hex()] if isinstance(v,bytes) else [type(v).__name__,v] for v in row]
            encoded=json.dumps(values,ensure_ascii=True,separators=(',',':')).encode()
            digest.update(len(encoded).to_bytes(8,'big'))
            digest.update(encoded)
            count+=1
        result[name]={'count':count,'sha256':digest.hexdigest()}
    result['__schema__']={'sha256':hashlib.sha256(json.dumps([tuple(r) for r in db.execute(
        'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name')],ensure_ascii=True).encode()).hexdigest()}
    result['__user_version__']=db.execute('PRAGMA user_version').fetchone()[0]
    return result


def check(db):
    if [r[0] for r in db.execute('PRAGMA integrity_check')]!=['ok']:
        raise RuntimeError('integrity_check failed')
    if db.execute('PRAGMA foreign_key_check').fetchone():
        raise RuntimeError('foreign_key_check failed')


def state(db):
    return dict(db.execute('SELECT key,value FROM state'))


def delta(before,after,old,new,prefix,marker):
    changed=[name for name in before if before[name]!=after.get(name)]
    if set(before)!=set(after) or any(name!='state' for name in changed):
        raise RuntimeError('Unexpected logical table/schema change')
    if any(new.get(key)!=value for key,value in old.items()):
        raise RuntimeError('Existing state changed or lost')
    additions=set(new)-set(old)
    if marker not in additions or json.loads(new[marker]) is not True:
        raise RuntimeError('Missing completion marker')
    for key in additions-{marker}:
        item=json.loads(new[key])
        if not key.startswith(prefix) or not (item.get('kind')=='clear' and
                item.get('reason')=='clear_chat_coverage_uncertain' and
                item.get('through') is None and item.get('system_through') is None and
                item.get('range')=={} and item.get('anchors')==[] and
                item.get('legacy_range_unavailable') is True and item.get('before')==0):
            raise RuntimeError('Unexpected new state record')
    return {'changed_tables':changed,'new_observations':len(additions)-1,
            'old_rows_unchanged':True,'old_state_unchanged':True}



def probe_settings(path,config,context,marker):
    from sally_whatsapp import __version__
    from sally_whatsapp.config import Settings
    # Older reviewed Settings classes predate this field and have no panel.
    administration={'admin_enabled':False} if __version__ in ('0.8.0','0.8.1','0.8.2','0.8.3','0.8.4','0.8.5','0.8.6','0.8.7','0.8.8','0.8.9','0.8.10','0.8.11','0.8.12','0.8.13') else {}
    return Settings(database=path,issuer='https://issuer.invalid',
        **context,webhook_secret_file=config/'synthetic-webhook.key',
        encryption_key_file=config/'synthetic-encryption.key',
        public_key_file=config/'synthetic-public.pem',state_identity_file=marker,
        allowed_hosts=['testserver'],oauth_client_ids=['synthetic-copy-probe'],
        live_account_enabled=False,send_enabled=False,account_actions_enabled=False,
        link_enabled=False,diagnostics_enabled=False,**administration)


def gated_activation(path,work,expected,context):
    """Real gated lifecycle, synthetic settings and inert worker substitutes."""
    import asyncio
    import secrets
    import socket
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from starlette.testclient import TestClient
    from sally_whatsapp.server import create_app
    from sally_whatsapp import visibility
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
    import installation_layout
    # The explicit offline-only probe supplies every database, configuration
    # and maintenance path below. Select its synthetic host layout before
    # importing the real wrapper; never consult or enroll this machine's
    # installation. This does not replace the copied DB's technical identity.
    installation_layout.select(installation_layout.Installation.legacy())
    from release_runtime import Maintenance

    socketpair_code=getattr(socket.socketpair,'__code__',None)
    def no_network(event,args):
        if event in ('socket.connect','socket.getaddrinfo','socket.gethostbyname','socket.bind'):
            # Windows asyncio can implement socketpair using a transient local
            # TCP pair. Permit only calls inside that stdlib implementation,
            # which accepts no remote address; application networking stays off.
            frame=sys._getframe()
            while frame is not None:
                if socketpair_code is not None and frame.f_code is socketpair_code and event in ('socket.connect','socket.bind'):
                    return
                frame=frame.f_back
            raise RuntimeError('Network is forbidden in this offline probe')
    sys.addaudithook(no_network)
    config=work/'synthetic-settings'
    # Disposable test material only. Never read production keys or config.
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    public=config/'synthetic-public.pem'
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo))
    encryption=config/'synthetic-encryption.key'
    encryption.write_bytes(Fernet.generate_key())
    webhook=config/'synthetic-webhook.key'
    webhook.write_text(secrets.token_hex(32))
    settings=probe_settings(path,config,context,config/'technical-state.json')
    class ForbiddenGateway:
        def close(self): pass
        def __getattr__(self,name):
            raise RuntimeError('Gateway access forbidden')
    class ForbiddenDelivery:
        def post(self,*args,**kwargs): raise RuntimeError('Callback forbidden')
    results=[]
    for cycle in ('first','repeat'):
        gate=config/('maintenance-'+cycle)
        gate.touch(mode=0o600)
        event=asyncio.Event()
        with connect(path) as db: before=fingerprint(db)
        app=create_app(settings,gateway=ForbiddenGateway(),event_transport=ForbiddenDelivery(),
                       recover_inflight=False,activation_event=event)
        with connect(path) as db:
            if fingerprint(db)!=before: raise RuntimeError('Constructor changed the gated copy')
        entered=[]
        for method in ('worker','transfer_worker','history_worker','action_worker'):
            async def inert_worker(name=method):
                with connect(path) as db:
                    marker=db.execute('SELECT value FROM state WHERE key=?',(visibility.CLEAR_REPAIR,)).fetchone()
                    if not marker or json.loads(marker[0]) is not True:
                        raise RuntimeError('Worker entered before clear repair')
                entered.append(name)
                await asyncio.Event().wait()
            setattr(app.state.service,method,inert_worker)
        started=time.perf_counter()
        with TestClient(Maintenance(app,event,gate)) as client:
            if client.get('/healthz').json()['readiness']['state']!='waiting':
                raise RuntimeError('Expected gated waiting state')
            if client.post('/mcp').status_code!=503 or client.post('/webhooks/waha').status_code!=503:
                raise RuntimeError('Maintenance admitted a request')
            with connect(path) as db:
                if fingerprint(db)!=before or entered: raise RuntimeError('Mutation or worker before gate')
            released=time.perf_counter()
            gate.unlink()
            deadline=time.monotonic()+120
            while True:
                status=client.get('/healthz').json()['readiness']
                if status['state']=='failed': raise RuntimeError('Gated preparation failed')
                if status['ready'] and len(entered)==4: break
                if time.monotonic()>deadline: raise RuntimeError('Gated preparation timed out')
                time.sleep(.01)
            ready=time.perf_counter()
            if client.post('/mcp').status_code!=401: raise RuntimeError('Expected authenticated admission after ready')
        with connect(path) as db:
            check(db)
            if fingerprint(db)!=expected: raise RuntimeError('Gated lifecycle differs from isolated repair')
        results.append({'cycle':cycle,'gate_to_ready_seconds':ready-released,
                        'lifespan_to_ready_seconds':ready-started,'workers':len(entered),
                        'marker_before_workers':True,'no_mutation_before_gate':True,
                        'mcp_503_before_and_401_after':True})
    return {'runs':results,'idempotent':True,'network_forbidden':True,'all_real_workers_replaced':True,
            'host_installation':'explicit-offline-fixture'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--copy',type=Path,required=True)
    p.add_argument('--work-dir',type=Path,required=True)
    p.add_argument('--offline-copy-only',action='store_true',required=True)
    p.add_argument('--identity-context',type=Path,
                   help='Private JSON with original owner_subject, public_url and session; no credentials')
    p.add_argument('--identity-marker',type=Path,
                   help='Original external identity marker for a registered copy, outside its DB directory')
    args=p.parse_args()
    source=args.copy.resolve(strict=True)
    if not source.is_file() or any(Path(str(source)+suffix).exists() for suffix in ('-wal','-shm','-journal')):
        raise RuntimeError('Require a standalone consistent backup copy without sidecars')
    # Imports only the candidate package beside this documented probe.
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
    from sally_whatsapp import __version__, visibility
    from sally_whatsapp.store import (Store, REVOCATION_REPAIR_KEY, OPERATION_RESULT_REPAIR_KEY,
                                      EVENT_REFS_REPAIR_KEY, JOB_METADATA_REPAIR_KEY)
    from sally_whatsapp.state_continuity import STATE_KEY, StateContinuity, register_external_identity
    # 0.8.0 retains the exact schema8 and clear-coverage repair. Its new admin
    # surface is explicitly disabled above; the real gated lifecycle and full
    # row/schema fingerprints below still qualify the disposable copies.
    # Do not replace this review boundary with a semver range or schema alone.
    # 0.8.1 retains schema8 and the same repair; its QA120 changes do not
    # broaden admission to any other version or enable the admin interface.
    # 0.8.2 preserves the same gated preparation and schema. Reaction repair is
    # an explicit offline operation, never called by construction/activation.
    # 0.8.3 adds read-only diagnostics without changing the gated preparation,
    # continuity registration or semantic repairs qualified below.
    # 0.8.4 changes event/auth diagnostics and discovery only; startup, schema8
    # and copy-repair invariants are covered by the same synthetic copy tests.
    # 0.8.5 changes only the backend version and provider receipt diagnostics;
    # Store, continuity, schema8, gated startup and the wrapper are unchanged.
    # 0.8.6 adds private media-failure diagnostics and their revocation cleanup;
    # schema8, clear-coverage repair and gated startup retain the copy contract.
    # The synthetic probe still verifies input preservation and activation.
    # 0.8.7 adds optional lazy transcription; the offline fixture does not
    # configure its socket and restoration explicitly disables it. No schema change.
    # 0.8.8 changes provider error projection and passive MCP diagnostics only;
    # schema8, Store, continuity and gated startup retain this copy contract.
    # 0.8.9 pairs the provider diagnostic build; backend schema, Store and startup
    # are unchanged. No migration or restoration semantics are added.
    # 0.8.10 adds private diagnostic state but no schema migration or automatic
    # historical marking. The gated startup and copy repair retain the same
    # invariants; full-row fingerprints below must still match after activation.
    # 0.8.11 changes resources, async dispatch, download deadlines, JWKS refresh
    # and evidence fingerprints. Schema8, clear repair and the pre-SQLite restore
    # fence are unchanged; the complete gated lifecycle is qualified below.
    # 0.8.12 adds bounded image tool content without changing persisted data.
    # 0.8.13 fixes send evidence, callbacks, media deadlines and domain contracts.
    # Schema8, clear repair and the pre-SQLite restore fence are preserved;
    # the synthetic probe verifies full-row preservation and gated activation.
    # Keep this exact candidate boundary and the disabled admin fixture above.
    if __version__ not in ('0.5.0','0.6.0','0.7.0','0.8.0','0.8.1','0.8.2','0.8.3','0.8.4','0.8.5','0.8.6','0.8.7','0.8.8','0.8.9','0.8.10','0.8.11','0.8.12','0.8.13'):
        raise RuntimeError('Expected a reviewed candidate: 0.5.0, 0.6.0, 0.7.0, 0.8.0, 0.8.1, 0.8.2, 0.8.3, 0.8.4, 0.8.5, 0.8.6, 0.8.7, 0.8.8, 0.8.9, 0.8.10, 0.8.11, 0.8.12 or 0.8.13 with schema8')
    source_hash=file_hash(source)
    context={'owner_subject':'synthetic-copy-probe','public_url':'https://offline.invalid','session':'default'}
    marker_bytes=None
    context_hash=None
    with connect(source,immutable=True) as origin:
        check(origin)
        if origin.execute('PRAGMA user_version').fetchone()[0]!=8: raise RuntimeError('Require schema8')
        old_state=state(origin)
        has_identity=STATE_KEY in old_state
        if has_identity:
            if args.identity_context is None or args.identity_marker is None:
                raise RuntimeError('Registered copies require their original identity context and external marker')
            context=json.loads(args.identity_context.read_text())
            if (not isinstance(context,dict) or set(context)!={'owner_subject','public_url','session'}
                    or any(not isinstance(value,str) or not value for value in context.values())):
                raise RuntimeError('Invalid identity context')
            # Verify the existing identity with the real guard, before creating
            # any working copy. A hash in the DB cannot supply a tenant context.
            StateContinuity(probe_settings(source,args.work_dir/'synthetic-settings',context,
                            args.identity_marker.resolve()),allow_bootstrap=False)
            marker_bytes=args.identity_marker.read_bytes()
            context_hash=file_hash(args.identity_context)
        elif args.identity_context is not None or args.identity_marker is not None:
            raise RuntimeError('Identity inputs supplied for an unregistered legacy copy')
        legacy=[]
        clear_count=0
        for row in origin.execute("SELECT chat_id,data FROM account_events WHERE event_type='chat.cleared'"):
            clear_count+=1
            try: data=json.loads(row['data'])
            except (ValueError,TypeError): continue
            if not isinstance(data,dict) or 'clearCoverage' in data: continue
            chat=row['chat_id'] or data.get('chatId')
            epoch=data.get('eventAt')
            if isinstance(chat,str) and type(epoch) in (int,float) and math.isfinite(epoch):
                legacy.append((Store._canonical_chat(origin,chat),epoch))
        chats={item[0] for item in legacy}
        affected=sum(1 for row in origin.execute('SELECT chat_id FROM messages')
                     if Store._canonical_chat(origin,row[0]) in chats)
        impact={'retained_clear_events':clear_count,'eligible_legacy_events':len(legacy),
                'unique_legacy_chat_event_pairs':len(set(legacy)),'legacy_chats':len(chats),
                'acquired_rows_in_legacy_chats':affected}
        if any(json.loads(old_state.get(key,'false')) is not True for key in (REVOCATION_REPAIR_KEY,OPERATION_RESULT_REPAIR_KEY)):
            raise RuntimeError('Prior semantic repair markers are not true; stop for separate review')
        for key in (EVENT_REFS_REPAIR_KEY,JOB_METADATA_REPAIR_KEY):
            progress=json.loads(old_state.get(key,'null'))
            if not isinstance(progress,dict) or progress.get('complete') is not True:
                raise RuntimeError('Schema8 preparation incomplete; stop for separate review')
        if visibility.CLEAR_REPAIR in old_state: raise RuntimeError('First-run marker already present; do not delete it')
        original_fingerprint=fingerprint(origin)
        args.work_dir.mkdir(mode=0o700,parents=False,exist_ok=False)
        config=args.work_dir/'synthetic-settings'
        config.mkdir(mode=0o700)
        data=args.work_dir/'data'
        data.mkdir(mode=0o700)
        paths={name:args.work_dir/(name+'.sqlite') for name in ('repair','timing','startup','abort','maintenance')}
        paths['maintenance']=data/'maintenance.sqlite'
        paths['maintenance'].touch(mode=0o600,exist_ok=False)
        with closing(sqlite3.connect(paths['maintenance'])) as dest: origin.backup(dest)
        marker=config/'technical-state.json'
        if has_identity:
            marker.touch(mode=0o600,exist_ok=False)
            marker.write_bytes(marker_bytes)
        else:
            # Explicit enrollment of this disposable offline clone only. Every
            # compared clone gets the same identity before its baseline is taken.
            register_external_identity(probe_settings(paths['maintenance'],config,context,marker))
        # Service activation now prepares the owner's MCP profile as well as
        # semantic repairs. Give every compared clone the same valid profile
        # before measuring clear coverage, retaining full fingerprints below.
        # Never initialize or rewrite this record in the source backup.
        profile_key='profile_id:'+hashlib.sha256(context['owner_subject'].encode()).hexdigest()
        has_profile=profile_key in old_state
        clone_settings=probe_settings(paths['maintenance'],config,context,marker)
        clone_guard=StateContinuity(clone_settings,allow_bootstrap=False)
        clone_store=Store(paths['maintenance'],recover_inflight=False,migrate_schema=False,
                          continuity=clone_guard)
        clone_store.prepare_profile(context['owner_subject'])
        with connect(paths['maintenance']) as prepared:
            prepared_state=state(prepared)
            prepared_fingerprint=fingerprint(prepared)
            if any(prepared_fingerprint.get(key)!=value for key,value in original_fingerprint.items()
                   if key!='state') or set(prepared_fingerprint)!=set(original_fingerprint):
                raise RuntimeError('Identity preparation changed data or schema')
            if any(prepared_state.get(key)!=value for key,value in old_state.items()):
                raise RuntimeError('Identity preparation changed existing state')
            expected_additions=({STATE_KEY} if not has_identity else set()) | ({profile_key} if not has_profile else set())
            if set(prepared_state)-set(old_state)!=expected_additions:
                raise RuntimeError('Identity preparation changed unexpected state')
            # Validate without normalization; existing JSON bytes were checked
            # above and the same prepared bytes are copied to every fixture.
            clone_store.profile(context['owner_subject'])
        for name,target in paths.items():
            if name=='maintenance': continue
            target.touch(mode=0o600,exist_ok=False)
            with connect(paths['maintenance']) as prepared, closing(sqlite3.connect(target)) as dest:
                prepared.backup(dest)
    report={'version':__version__,'python':platform.python_version(),'sqlite':sqlite3.sqlite_version,
            'platform':platform.system()+' '+platform.machine(),'input_bytes':source.stat().st_size,
            'input_sha256':source_hash,'impact':impact,'runtime_sha256':{name:file_hash(Path(visibility.__file__).with_name(name))
                                                     for name in ('visibility.py','store.py','server.py','readiness.py')},
            'maintenance_reproduction':'real create_app lifespan and Maintenance ASGI wrapper; all workers replaced',
            'continuity':{'identity_preserved':has_identity,'original_context_verified':has_identity,
                          'synthetic_identity_on_legacy_clones_only':not has_identity},
            'profile_preparation':{'existing_identity_preserved':has_profile,
                'initialized_on_disposable_clones_only':not has_profile,
                'same_identity_in_all_comparison_clones':True,
                'included_in_full_fingerprints':True},
            'release_source_sha256':{name:file_hash(Path(__file__).resolve().parents[2]/'scripts'/name)
                for name in ('release_runtime.py','release_database.py','github_release.py','release_transaction.py','release_probe.py')}}
    with connect(paths['repair']) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        before=fingerprint(db)
        old=state(db)
        started=time.perf_counter()
        db.execute('BEGIN IMMEDIATE')
        acquired=time.perf_counter()
        def busy_probe():
            with connect(paths['repair']) as rival:
                rival.execute('PRAGMA busy_timeout=0')
                try: rival.execute('BEGIN IMMEDIATE')
                except sqlite3.OperationalError as error:
                    if error.sqlite_errorcode not in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED): raise
                else:
                    rival.rollback()
                    raise RuntimeError('Expected competing writer to be blocked')
        busy_probe()
        with connect(paths['repair']) as reader:
            reader.execute('PRAGMA query_only=ON')
            read_start=time.perf_counter()
            reader.execute('SELECT count(*) FROM messages').fetchone()
            read_seconds=time.perf_counter()-read_start
        tracemalloc.start()
        repair_start=time.perf_counter()
        visibility.repair_clear_coverage(db,Store._canonical_chat)
        repair_seconds=time.perf_counter()-repair_start
        _,peak=tracemalloc.get_traced_memory()
        tracemalloc.stop()
        busy_probe()
        commit_start=time.perf_counter()
        db.commit()
        committed=time.perf_counter()
        with connect(paths['repair']) as rival:
            rival.execute('PRAGMA busy_timeout=0')
            rival.execute('BEGIN IMMEDIATE')
            rival.rollback()
        after=fingerprint(db)
        new=state(db)
        report['repair']=delta(before,after,old,new,visibility.PREFIX,visibility.CLEAR_REPAIR)
        report['repair'].update(begin_wait_seconds=acquired-started,helper_seconds=repair_seconds,
            commit_seconds=committed-commit_start,lock_held_seconds=committed-acquired,
            peak_python_bytes=peak,reader_count_seconds=read_seconds,
            competing_writer_blocked_before_and_after_helper=True,writer_acquired_after_commit=True)
        warm=time.perf_counter()
        db.execute('BEGIN IMMEDIATE')
        visibility.repair_clear_coverage(db,Store._canonical_chat)
        db.commit()
        report['warm_start_seconds']=time.perf_counter()-warm
        if fingerprint(db)!=after: raise RuntimeError('Repeated repair is not idempotent')
        check(db)
    # A separate first-run clone measures latency without tracemalloc or lock
    # probes. The instrumented lock interval above includes their overhead.
    with connect(paths['timing']) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        begun=time.perf_counter()
        db.execute('BEGIN IMMEDIATE')
        locked=time.perf_counter()
        visibility.repair_clear_coverage(db,Store._canonical_chat)
        done=time.perf_counter()
        db.commit()
        finished=time.perf_counter()
        report['uninstrumented']={'begin_wait_seconds':locked-begun,
            'helper_seconds':done-locked,'commit_seconds':finished-done,
            'lock_held_seconds':finished-locked}
        if fingerprint(db)!=after: raise RuntimeError('Uninstrumented result differs')
    with connect(paths['startup']) as db: baseline=fingerprint(db)
    started=time.perf_counter()
    Store(paths['startup'],recover_inflight=False,migrate_schema=True)
    report['store_startup_seconds']=time.perf_counter()-started
    with connect(paths['startup']) as db:
        check(db)
        delta(baseline,fingerprint(db),old,state(db),visibility.PREFIX,visibility.CLEAR_REPAIR)
        if fingerprint(db)!=after: raise RuntimeError('Full startup differs from isolated repair')
    # Exercise the real app lifespan and installed-style Maintenance wrapper.
    with connect(paths['maintenance']) as db: baseline=fingerprint(db)
    gated=gated_activation(paths['maintenance'],args.work_dir,after,context)
    with connect(paths['maintenance']) as db:
        delta(baseline,fingerprint(db),old,state(db),visibility.PREFIX,visibility.CLEAR_REPAIR)
    report['gated_activation']=gated
    report['maintenance_path_clear_marker_present']=True
    report['release_path_blocker']=False
    with connect(paths['abort']) as db:
        baseline=fingerprint(db)
        db.execute('BEGIN IMMEDIATE')
        visibility.repair_clear_coverage(db,Store._canonical_chat)
        db.rollback()
        if fingerprint(db)!=baseline: raise RuntimeError('Rollback lost or changed data')
        check(db)
    if file_hash(source)!=source_hash: raise RuntimeError('Source copy changed')
    if has_identity and (args.identity_marker.read_bytes()!=marker_bytes or
                         file_hash(args.identity_context)!=context_hash):
        raise RuntimeError('Original identity inputs changed')
    report['continuity']['source_identity_inputs_unchanged']=True
    (args.work_dir/'fingerprints-private.json').write_text(json.dumps({'before':before,'after':after},indent=2)+'\n')
    report.update(input_unchanged=True,rollback_unchanged=True,idempotent=True,integrity_ok=True,
                  full_startup_matches_isolated_repair=True)
    (args.work_dir/'evidence-private.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS offline copy probe; release-path blocker='+str(report['release_path_blocker'])+'. No installation is authorized.')


if __name__=='__main__':
    try: main()
    except Exception as error:
        print('STOP offline copy probe: '+type(error).__name__+'. Keep private copies for local review; do not publish raw errors.',file=sys.stderr)
        raise SystemExit(1)
