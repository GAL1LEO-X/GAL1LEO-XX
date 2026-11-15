from contextlib import closing
import importlib.util
import os
from pathlib import Path
import sqlite3
import subprocess
from types import SimpleNamespace

import httpx
import pytest


def prepare_installation(backup, host, monkeypatch, profile=None):
    """A real protected marker under a temporary root, never a host /etc write."""
    import installation_layout as layout
    profile = layout.Installation.legacy() if profile is None else profile
    marker = host/layout.IDENTITY.relative_to('/')
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_bytes(layout.identity_bytes(profile)); marker.chmod(0o600)
    if not profile.compatibility:
        locator = host/layout.PROFILE.relative_to('/')
        locator.write_bytes(profile._encoded); locator.chmod(0o600)
    monkeypatch.setattr(backup, '_INSTALLATION_ROOT', host)
    monkeypatch.setattr(backup, '_INSTALLATION_UID', os.getuid())
    monkeypatch.setattr(backup, 'installation_profile', lambda: profile)
    return marker


@pytest.fixture
def backup_module():
    spec=importlib.util.spec_from_file_location('backup_runtime',Path(__file__).parents[1]/'scripts/backup_runtime.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('gateway_active,bridge_active',[(True,True),(True,False),(False,True),(False,False)])
def test_recovery_attempts_only_previously_active_components(backup_module,tmp_path,monkeypatch,gateway_active,bridge_active):
    instance=SimpleNamespace(wrapper=tmp_path/'wrapper',base='fixture',config_dir=tmp_path,gateway_port=8823,bridge_port=8822)
    (tmp_path/'waha.key').write_text('synthetic-only')
    starts=[];reads=[]
    def run(args,**kwargs):
        starts.append(args[-1])
        raise subprocess.CalledProcessError(1,args)
    class Client:
        def __init__(self,**kwargs): pass
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def get(self,url,**kwargs):
            reads.append(url)
            if url.endswith('/api/version'): raise httpx.ConnectError('synthetic unavailable')
            return SimpleNamespace(is_success=True)
    monkeypatch.setattr(backup_module,'subprocess',SimpleNamespace(run=run))
    monkeypatch.setattr(backup_module.httpx,'Client',Client)
    monkeypatch.setattr(backup_module.time,'sleep',lambda *_:None)
    failures=backup_module.restore_components(instance,gateway_active,bridge_active)
    assert starts==(['whatsapp-waha.service'] if gateway_active else [])+(['fixture.service'] if bridge_active else [])
    assert [stage for stage,_ in failures]==(['gateway.start'] if gateway_active else [])+(['bridge.start'] if bridge_active else [])+(['gateway.readiness'] if gateway_active else [])
    assert any(url.endswith('/healthz') for url in reads)==bridge_active
    assert any(url.endswith('/api/version') for url in reads)==gateway_active


@pytest.mark.parametrize('snapshot_fails',[False,True])
def test_backup_preserves_snapshot_and_independent_recovery_errors(backup_module,tmp_path,monkeypatch,snapshot_fails):
    instance=SimpleNamespace(slug='fixture',base='fixture',wrapper=tmp_path/'wrapper',state_dir=tmp_path/'state',
        config_dir=tmp_path/'config',gateway_home=tmp_path/'gateway',private_dir=tmp_path/'private')
    monkeypatch.setattr(backup_module,'ROOT',tmp_path/'project')
    monkeypatch.setattr(backup_module,'Path',lambda value:tmp_path/'host'/str(value).lstrip('/'))
    prepare_installation(backup_module, tmp_path/'host', monkeypatch)
    def snapshot(source,target):
        if snapshot_fails: raise OSError('sensitive diagnostic detail')
        target.write_bytes(b'synthetic snapshot')
    def run(args,**kwargs):
        if str(args[-1]).endswith('source.tar.gz'): Path(args[-1]).write_bytes(b'synthetic source')
        return SimpleNamespace(returncode=0)
    recovered=[]
    def recover(*args):
        recovered.append(args[1:])
        return [('gateway.start',RuntimeError('private gateway detail')),('bridge.start',RuntimeError('private bridge detail'))]
    monkeypatch.setattr(backup_module,'snapshot_database',snapshot)
    monkeypatch.setattr(backup_module,'snapshot_tenant_database',lambda instance,target,**kw:snapshot(instance.state_dir/'archive.sqlite',target))
    monkeypatch.setattr(backup_module,'validate_snapshot',lambda *args,**kwargs:None)
    monkeypatch.setattr(backup_module,'subprocess',SimpleNamespace(run=run))
    monkeypatch.setattr(backup_module,'restore_components',recover)
    with pytest.raises(backup_module.BackupError) as caught: backup_module.backup(instance)
    assert recovered==[(True,True)]
    assert caught.value.complete==(not snapshot_fails)
    assert [stage for stage,_ in caught.value.failures]==(['snapshot'] if snapshot_fails else [])+['gateway.start','bridge.start']
    assert 'private' not in str(caught.value) and 'sensitive' not in str(caught.value)


def test_live_wal_backup_is_standalone_and_keeps_source_mode(tmp_path):
    spec=importlib.util.spec_from_file_location('backup_runtime',Path(__file__).parents[1]/'scripts/backup_runtime.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source=tmp_path/'live.sqlite'
    target=tmp_path/'snapshot.sqlite'
    with closing(sqlite3.connect(source)) as live:
        live.execute('PRAGMA journal_mode=WAL')
        live.execute('CREATE TABLE evidence(value TEXT)')
        live.execute('INSERT INTO evidence VALUES (?)',('committed-in-wal',))
        live.commit()
        module.snapshot_database(source,target)
        assert live.execute('PRAGMA journal_mode').fetchone()[0]=='wal'
        assert not Path(str(target)+'-wal').exists()
        assert not Path(str(target)+'-shm').exists()
        with closing(sqlite3.connect('file:'+str(target)+'?mode=ro',uri=True)) as snapshot:
            assert snapshot.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
            assert snapshot.execute('PRAGMA journal_mode').fetchone()[0]=='delete'
            assert snapshot.execute('SELECT value FROM evidence').fetchone()[0]=='committed-in-wal'
        assert not Path(str(target)+'-wal').exists()
        assert not Path(str(target)+'-shm').exists()
