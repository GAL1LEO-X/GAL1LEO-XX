"""Offline handoff probe: synthetic private copy, no account configuration."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

import pytest

from conftest import message
from sally_whatsapp.store import Store
from sally_whatsapp import visibility
from sally_whatsapp.config import Settings
from sally_whatsapp.state_continuity import STATE_KEY, register_external_identity

PROBE=Path(__file__).resolve().parents[1]/'docs/probes/clear_coverage_copy.py'
CHAT='15550001111@c.us'


def source_copy(tmp_path,*,first_run=True):
    path=tmp_path/'synthetic-private.sqlite'
    store=Store(path)
    for raw,epoch in [('B',1100),('C',1200),('F',1600)]:
        store.ingest(message(f'false_{CHAT}_{raw}',CHAT,timestamp=epoch,text='Synthetic '+raw))
    with store.db() as db:
        if first_run: db.execute('DELETE FROM state WHERE key=?',(visibility.CLEAR_REPAIR,))
        visibility.apply(db,[{'kind':'message','chat_id':CHAT,'raw_id':'C','from_me':False,
                             'reason':'chat_cleared','event_at':1500}],store._canonical_chat)
        db.execute('INSERT INTO account_events VALUES(?,?,?,?,?,?)',
                   ('legacy','chat.cleared',CHAT,1500,json.dumps({'chatId':CHAT,'eventAt':1500,
                    'coverage':'explicit_messages','reason':'chat_cleared','excludedReferences':1}),''))
    return path


def run_probe(source,work):
    return subprocess.run([sys.executable,str(PROBE),'--copy',str(source),'--work-dir',str(work),
                           '--offline-copy-only'],capture_output=True,text=True,timeout=30)


def registered_source(tmp_path, *, profile=None):
    source=source_copy(tmp_path/'source-data')
    config=tmp_path/'source-configuration'
    config.mkdir()
    marker=config/'technical-state.json'
    context={'owner_subject':'synthetic-registered-owner','public_url':'https://registered.invalid',
             'session':'registered-session'}
    context_file=config/'identity-context.json'
    context_file.write_text(json.dumps(context))
    # Only the continuity guard uses these settings. No secret file or account
    # transport exists in this fixture; the probe generates its own test keys.
    settings=Settings(database=source,**context,issuer='https://issuer.invalid',
        public_key_file=config/'unused-public.pem',webhook_secret_file=config/'unused-webhook.key',
        encryption_key_file=config/'unused-encryption.key',oauth_client_ids=['synthetic-probe'],
        state_identity_file=marker)
    register_external_identity(settings)
    if profile is not None:
        with Store(source,migrate_schema=False).db() as db:
            key='profile_id:'+hashlib.sha256(context['owner_subject'].encode()).hexdigest()
            db.execute('INSERT INTO state(key,value) VALUES(?,?)',(key,profile))
    return source,context_file,marker


def run_registered_probe(source,work,context_file,marker):
    return subprocess.run([sys.executable,str(PROBE),'--copy',str(source),'--work-dir',str(work),
                           '--offline-copy-only','--identity-context',str(context_file),
                           '--identity-marker',str(marker)],capture_output=True,text=True,timeout=30)


@pytest.mark.parametrize('profile',[None,'  "synthetic-existing-profile-id"  '],ids=['new-profile','preserved-profile'])
def test_registered_copy_preserves_original_identity_and_uses_verified_context(tmp_path,profile):
    source,context_file,marker=registered_source(tmp_path,profile=profile)
    originals={path:path.read_bytes() for path in (source,context_file,marker)}
    work=tmp_path/'registered-work'
    result=run_registered_probe(source,work,context_file,marker)
    assert result.returncode==0,result.stdout+result.stderr
    assert all(path.read_bytes()==content for path,content in originals.items())
    report=json.loads((work/'evidence-private.json').read_text())
    assert report['continuity']=={'identity_preserved':True,'original_context_verified':True,
        'synthetic_identity_on_legacy_clones_only':False,'source_identity_inputs_unchanged':True}
    assert (work/'synthetic-settings'/'technical-state.json').read_bytes()==originals[marker]
    profile_values=[]
    for copy in (work/'startup.sqlite',work/'repair.sqlite',work/'timing.sqlite',work/'abort.sqlite',work/'data'/'maintenance.sqlite'):
        store=Store(copy,migrate_schema=False,recover_inflight=False)
        with store.db() as db:
            identity=json.loads(db.execute('SELECT value FROM state WHERE key=?',(STATE_KEY,)).fetchone()[0])
            key='profile_id:'+hashlib.sha256(b'synthetic-registered-owner').hexdigest()
            profile_values.append(db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone()[0])
        assert identity==json.loads(originals[marker])
    assert len(set(profile_values))==1
    if profile is not None:
        assert profile_values==[profile]*5  # Preserve original JSON bytes, too.
    else:
        assert json.loads(profile_values[0]).startswith('prf_')
    assert report['profile_preparation']=={'existing_identity_preserved':profile is not None,
        'initialized_on_disposable_clones_only':profile is None,
        'same_identity_in_all_comparison_clones':True,'included_in_full_fingerprints':True}
    evidence=(work/'evidence-private.json').read_text()+result.stdout+result.stderr
    assert all(value not in evidence for value in json.loads(originals[context_file]).values())
    assert all(json.loads(value) not in evidence for value in profile_values)


@pytest.mark.parametrize('profile',['not-json','"   "'])
def test_registered_copy_rejects_invalid_profile_without_replacing_source(tmp_path,profile):
    source,context_file,marker=registered_source(tmp_path,profile=profile)
    originals={path:path.read_bytes() for path in (source,context_file,marker)}
    work=tmp_path/'invalid-profile-work'
    result=run_registered_probe(source,work,context_file,marker)
    assert result.returncode==1
    assert all(path.read_bytes()==content for path,content in originals.items())
    assert not (work/'evidence-private.json').exists()
    key='profile_id:'+hashlib.sha256(b'synthetic-registered-owner').hexdigest()
    with Store(work/'data'/'maintenance.sqlite',migrate_schema=False).db() as db:
        assert db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone()[0]==profile


@pytest.mark.parametrize('invalid',['missing_inputs','different_context','different_identity','missing_marker'])
def test_registered_copy_never_replaces_identity_to_fit_synthetic_context(tmp_path,invalid):
    source,context_file,marker=registered_source(tmp_path)
    original=source.read_bytes()
    if invalid=='different_context':
        context=json.loads(context_file.read_text())
        context['owner_subject']='another-synthetic-owner'
        context_file.write_text(json.dumps(context))
    elif invalid=='different_identity':
        identity=json.loads(marker.read_text())
        identity['id']='0'*32
        marker.write_text(json.dumps(identity))
    elif invalid=='missing_marker':
        marker.unlink()
    saved_marker=marker.read_bytes() if marker.exists() else None
    work=tmp_path/'refused-identity-work'
    result=(run_probe(source,work) if invalid=='missing_inputs'
            else run_registered_probe(source,work,context_file,marker))
    assert result.returncode==1
    assert source.read_bytes()==original
    assert (marker.read_bytes() if marker.exists() else None)==saved_marker
    assert not work.exists()


def test_offline_probe_preserves_source_and_repairs_through_real_gated_lifespan(tmp_path):
    source=source_copy(tmp_path)
    original=source.read_bytes()
    work=tmp_path/'new-private-work'
    completed=run_probe(source,work)
    assert completed.returncode==0,completed.stdout+completed.stderr
    report=json.loads((work/'evidence-private.json').read_text())
    from sally_whatsapp import __version__
    assert report['version']==__version__
    assert report['input_unchanged'] and source.read_bytes()==original
    assert report['integrity_ok'] and report['idempotent'] and report['rollback_unchanged']
    assert report['full_startup_matches_isolated_repair']
    assert report['repair']['changed_tables']==['state']
    assert report['repair']['new_observations']==1
    assert report['repair']['competing_writer_blocked_before_and_after_helper']
    assert report['repair']['writer_acquired_after_commit']
    assert not report['release_path_blocker'] and report['maintenance_path_clear_marker_present']
    assert report['gated_activation']['idempotent']
    assert report['continuity']=={'identity_preserved':False,'original_context_verified':False,
        'synthetic_identity_on_legacy_clones_only':True,'source_identity_inputs_unchanged':True}
    assert report['profile_preparation']=={'existing_identity_preserved':False,
        'initialized_on_disposable_clones_only':True,
        'same_identity_in_all_comparison_clones':True,'included_in_full_fingerprints':True}
    assert all(r['marker_before_workers'] and r['workers']==4 for r in report['gated_activation']['runs'])
    store=Store(work/'startup.sqlite',migrate_schema=False,recover_inflight=False)
    assert store.message_state(f'false_{CHAT}_C')['state']==visibility.CLEAR_UNCERTAIN
    assert store.message(f'false_{CHAT}_C') is None
    before=store.public_message(store.message(f'false_{CHAT}_B'))
    assert before['body']=='Synthetic B' and before['current_state']==visibility.CLEAR_UNCERTAIN
    assert store.message(f'false_{CHAT}_F') is not None
    fingerprints=json.loads((work/'fingerprints-private.json').read_text())
    assert fingerprints['before']['messages']==fingerprints['after']['messages']
    assert fingerprints['before']['message_search']==fingerprints['after']['message_search']
    # Contents and identifiers are never included in evidence or stdout.
    assert 'Synthetic B' not in (work/'evidence-private.json').read_text()+completed.stdout
    assert CHAT not in (work/'evidence-private.json').read_text()+completed.stdout


def test_offline_profile_fixture_preparation_rejects_unrelated_state_additions(tmp_path):
    source=source_copy(tmp_path)
    original=source.read_bytes()
    work=tmp_path/'unexpected-profile-state-work'
    bootstrap='''import sys,runpy
sys.path.insert(0,sys.argv[1])
from sally_whatsapp.store import Store
original=Store.prepare_profile
def unexpected(self,owner):
    original(self,owner)
    self.set_state('synthetic-unexpected-profile-side-effect',True)
Store.prepare_profile=unexpected
sys.argv=sys.argv[2:]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    result=subprocess.run([sys.executable,'-c',bootstrap,str(PROBE.parents[2]),str(PROBE),
                           '--copy',str(source),'--work-dir',str(work),'--offline-copy-only'],
                          capture_output=True,text=True,timeout=30)
    assert result.returncode==1
    assert source.read_bytes()==original
    assert not (work/'evidence-private.json').exists()
    with Store(work/'data'/'maintenance.sqlite',migrate_schema=False).db() as db:
        assert db.execute('SELECT value FROM state WHERE key=?',
                          ('synthetic-unexpected-profile-side-effect',)).fetchone()[0]=='true'


@pytest.mark.parametrize('reason',['already_repaired','sidecar','existing_work'])
def test_offline_probe_refuses_unsafe_or_nonfirst_run_inputs(tmp_path,reason):
    source=source_copy(tmp_path,first_run=reason!='already_repaired')
    original=source.read_bytes()
    work=tmp_path/'private-work'
    if reason=='sidecar': Path(str(source)+'-wal').touch()
    if reason=='existing_work': work.mkdir()
    result=run_probe(source,work)
    assert result.returncode==1
    assert source.read_bytes()==original
    assert not (work/'evidence-private.json').exists()


def test_offline_probe_allows_only_stdlib_loopback_socketpair_plumbing(tmp_path):
    source=source_copy(tmp_path)
    work=tmp_path/'fallback-private-work'
    # Exercise CPython's fallback used for Windows event-loop self-pipes.
    # The stdlib function chooses its own local endpoints; no address is
    # provided by this probe or by a private database row.
    bootstrap='import socket,runpy,sys; socket.socketpair=socket._fallback_socketpair; sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name="__main__")'
    completed=subprocess.run([sys.executable,'-c',bootstrap,str(PROBE),'--copy',str(source),
                              '--work-dir',str(work),'--offline-copy-only'],
                             capture_output=True,text=True,timeout=30)
    assert completed.returncode==0,completed.stdout+completed.stderr
    report=json.loads((work/'evidence-private.json').read_text())
    assert report['gated_activation']['network_forbidden']
    assert report['gated_activation']['idempotent']


def test_offline_probe_detects_constructor_repair_before_gate(tmp_path):
    source=source_copy(tmp_path)
    work=tmp_path/'premature-constructor-work'
    # Emulate the exact regression the offline handoff must detect: a server
    # constructor repairs the DB despite migrate_schema=False. Its final rows
    # would otherwise look correct after activation.
    bootstrap='''import sys,runpy
sys.path.insert(0,sys.argv[1])
from sally_whatsapp.store import Store
original=Store.__init__
def premature(self,*args,**kwargs):
    original(self,*args,**kwargs)
    if kwargs.get('migrate_schema') is False:
        self._repair_clear_coverage()
Store.__init__=premature
sys.argv=sys.argv[2:]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    result=subprocess.run([sys.executable,'-c',bootstrap,str(PROBE.parents[2]),str(PROBE),
                           '--copy',str(source),'--work-dir',str(work),'--offline-copy-only'],
                          capture_output=True,text=True,timeout=30)
    assert result.returncode==1
    assert not (work/'evidence-private.json').exists()


@pytest.mark.parametrize('version', ['0.4.7', '0.4.8', '0.4.9', '0.4.10', '0.5.1', '0.6.1',
    '0.7.1', '0.8.14', '0.9.0', '1.0.0', '0.6.0-dev', '0.8.0-dev', '0.8.0rc1',
    '0.8.5-dev', '0.8.5rc1', '0.8.6-dev', '0.8.6rc1', '0.8.7-dev', '0.8.7rc1',
    '0.8.8-dev', '0.8.8rc1', '0.8.9-dev', '0.8.9rc1', '0.8.10-dev', '0.8.10rc1', '0.8.11-dev', '0.8.11rc1', '0.8.12-dev', '0.8.12rc1', '0.8.13-dev', '0.8.13rc1'])
def test_offline_probe_rejects_other_versions_before_copying(tmp_path, version):
    source = source_copy(tmp_path)
    original = source.read_bytes()
    work = tmp_path/'wrong-candidate-work'
    bootstrap = '''import sys,runpy
sys.path.insert(0,sys.argv[1])
import sally_whatsapp
sally_whatsapp.__version__=sys.argv[2]
sys.argv=sys.argv[3:]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    result = subprocess.run([sys.executable, '-c', bootstrap, str(PROBE.parents[2]), version,
                             str(PROBE), '--copy', str(source), '--work-dir', str(work),
                             '--offline-copy-only'], capture_output=True, text=True, timeout=30)
    assert result.returncode == 1
    assert source.read_bytes() == original
    assert not work.exists()


@pytest.mark.parametrize('version', ['0.5.0', '0.6.0', '0.7.0', '0.8.0', '0.8.1', '0.8.2', '0.8.3', '0.8.4', '0.8.5', '0.8.6', '0.8.7', '0.8.8', '0.8.9', '0.8.10', '0.8.11', '0.8.12', '0.8.13'])
def test_offline_probe_accepts_only_reviewed_schema8_candidates(tmp_path, version):
    source = source_copy(tmp_path)
    original = source.read_bytes()
    work = tmp_path/'reviewed-candidate-work'
    bootstrap = '''import sys,runpy
sys.path.insert(0,sys.argv[1])
import sally_whatsapp
sally_whatsapp.__version__=sys.argv[2]
sys.argv=sys.argv[3:]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    result = subprocess.run([sys.executable, '-c', bootstrap, str(PROBE.parents[2]), version,
                             str(PROBE), '--copy', str(source), '--work-dir', str(work),
                             '--offline-copy-only'], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert source.read_bytes() == original
    report = json.loads((work/'evidence-private.json').read_text())
    assert report['version'] == version and report['input_unchanged']
    assert report['gated_activation']['network_forbidden'] and report['gated_activation']['idempotent']


@pytest.mark.parametrize('schema', [6, 7, 9, 99])
def test_offline_probe_rejects_unreviewed_schema_before_copying(tmp_path, schema):
    source = source_copy(tmp_path)
    import sqlite3
    with sqlite3.connect(source) as db:
        db.execute('PRAGMA user_version=' + str(schema))
    original = source.read_bytes()
    work = tmp_path/'wrong-schema-work'
    result = run_probe(source, work)
    assert result.returncode == 1 and result.stderr.startswith('STOP offline copy probe: RuntimeError.')
    assert source.read_bytes() == original and not work.exists()
