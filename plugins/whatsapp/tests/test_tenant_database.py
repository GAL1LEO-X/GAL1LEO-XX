"""Synthetic privilege and identity boundaries; never consult host accounts/services."""
from contextlib import closing
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
import tenant_database as secure
from sally_whatsapp.store import SCHEMA


def context_for(path):
    """Business-lifecycle fixtures already own their synthetic DB identity."""
    with closing(sqlite3.connect(path)) as db:
        expected = json.loads(db.execute('SELECT value FROM state WHERE key=?', (secure.KEY,)).fetchone()[0])
    info = path.stat()
    return {'database': str(path), 'expected': expected, 'uid': os.getuid(), 'gid': os.getgid(),
            'inode': [info.st_dev, info.st_ino], 'groups': os.getgroups()}


def suspend_fixture(instance):
    secure.perform(context_for(instance.state_dir/'archive.sqlite'), 'suspend', io.BytesIO())


@pytest.fixture
def tenants(tmp_path, monkeypatch):
    monkeypatch.setattr(secure, '_TRUST_ROOT', tmp_path)
    monkeypatch.setattr(secure, '_TRUST_UID', os.getuid())
    monkeypatch.setattr(secure.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
    instances = []
    for slug in ('alpha', 'bravo'):
        root = tmp_path/slug; root.mkdir()
        configuration = root/'config'; configuration.mkdir()
        state = root/'state'; state.mkdir()
        instance = SimpleNamespace(config_dir=configuration, state_dir=state, service_user='synthetic-'+slug,
                                   subject='owner-'+slug, public_url='https://'+slug+'.example.test')
        config = {'database': str(state/'archive.sqlite'), 'owner_subject': instance.subject,
                  'public_url': instance.public_url, 'session': 'default'}
        (configuration/'config.toml').write_text('[bridge]\n'+'\n'.join(key+' = '+json.dumps(value) for key,value in config.items()))
        tenant = hashlib.sha256(json.dumps([instance.subject,instance.public_url,'default'], separators=(',', ':')).encode()).hexdigest()
        expected = {'protocol':1, 'id':('a' if slug == 'alpha' else 'b')*32, 'tenant':tenant}
        (configuration/'technical-state.json').write_text(json.dumps(expected))
        with closing(sqlite3.connect(state/'archive.sqlite')) as db:
            db.executescript(SCHEMA)
            db.execute('INSERT INTO state VALUES (?,?)', (secure.KEY,json.dumps(expected)))
            db.execute('INSERT INTO link_login_states VALUES (?,?,?,?,?)', ('synthetic', 'verifier', 'nonce', 99999999999, 0))
            db.commit()
        instances.append(instance)
    return instances


def test_snapshot_and_suspend_use_actual_unprivileged_worker(tenants, tmp_path):
    first, second = tenants
    before = (second.state_dir/'archive.sqlite').read_bytes()
    destination = tmp_path/'snapshot.sqlite'
    secure.verify_tenant_database(first)
    secure.snapshot_tenant_database(first, destination)
    with closing(sqlite3.connect(destination)) as db:
        assert db.execute('PRAGMA journal_mode').fetchone() == ('delete',)
        assert db.execute('SELECT COUNT(*) FROM link_login_states').fetchone() == (1,)
    assert destination.stat().st_mode & 0o777 == 0o600
    secure.suspend_tenant_database(first)
    with closing(sqlite3.connect(first.state_dir/'archive.sqlite')) as db:
        assert db.execute('SELECT COUNT(*) FROM link_login_states').fetchone() == (0,)
    assert (second.state_dir/'archive.sqlite').read_bytes() == before


@pytest.mark.parametrize('damage', ['symlink', 'parent-symlink', 'hardlink', 'foreign-identity', 'missing', 'fifo',
                                   'marker-symlink', 'marker-writable', 'config-writable'])
@pytest.mark.parametrize('action', ['suspend', 'snapshot'])
def test_foreign_or_untrusted_state_never_changes_other_tenant(tenants,tmp_path,damage,action):
    first, second = tenants
    source = first.state_dir/'archive.sqlite'; other = second.state_dir/'archive.sqlite'
    before = other.read_bytes()
    if damage in ('symlink', 'hardlink', 'foreign-identity', 'missing', 'fifo'):
        source.unlink()
        if damage == 'symlink': source.symlink_to(other)
        elif damage == 'hardlink': os.link(other,source)
        elif damage == 'foreign-identity': source.write_bytes(before)
        elif damage == 'fifo': os.mkfifo(source)
    elif damage == 'parent-symlink':
        preserved = first.state_dir.with_name('preserved'); first.state_dir.rename(preserved)
        first.state_dir.symlink_to(second.state_dir, target_is_directory=True)
    elif damage == 'marker-symlink':
        marker = first.config_dir/'technical-state.json'; marker.unlink()
        marker.symlink_to(second.config_dir/'technical-state.json')
    else:
        name = 'technical-state.json' if damage == 'marker-writable' else 'config.toml'
        (first.config_dir/name).chmod(0o666)
    destination = tmp_path/'rejected.sqlite'
    with pytest.raises((OSError,RuntimeError,subprocess.CalledProcessError)):
        secure.run_database(first,action,**({'target':destination} if action=='snapshot' else {}))
    assert other.read_bytes() == before
    assert not destination.exists()
    if damage == 'missing': assert not source.exists()


@pytest.mark.parametrize('action', ['suspend','snapshot'])
def test_replacement_at_sqlite_open_is_rejected_before_work(tenants,tmp_path,monkeypatch,action):
    first, second = tenants
    request = secure.tenant_context(first)
    source = first.state_dir/'archive.sqlite'; other = second.state_dir/'archive.sqlite'
    before = other.read_bytes(); connect = secure.sqlite3.connect
    def swapped(*args, **kwargs):
        source.rename(source.with_suffix('.previous'))
        source.symlink_to(other)
        return connect(*args,**kwargs)
    monkeypatch.setattr(secure.sqlite3,'connect',swapped)
    output = io.BytesIO()
    with pytest.raises((OSError, RuntimeError)):
        secure.perform(request,action,output)
    assert other.read_bytes() == before
    assert output.getvalue() == b''


def test_privileged_parent_drops_all_supplementary_groups_before_exec(tenants,monkeypatch):
    first, _ = tenants
    observed = []
    monkeypatch.setattr(secure.os,'geteuid',lambda:0)
    monkeypatch.setattr(secure.subprocess,'run',lambda command,**options:observed.append((command,options)))
    secure.suspend_tenant_database(first)
    command, options = observed[0]
    assert command[1:3] == ['-I','-B']
    assert command[3] == '-' and options['input'] == Path(secure.__file__).read_bytes()
    assert options['user'] == os.getuid() and options['group'] == os.getgid()
    assert options['extra_groups'] == [] and options['env'] == {} and options['close_fds']
    assert json.loads(command[-1])['groups'] == []
    assert options['cwd'] == '/' and 'preexec_fn' not in options


@pytest.mark.skipif(os.geteuid() == 0, reason='Directory listing denial requires an unprivileged fixture')
@pytest.mark.parametrize('selected', [0, 1])
@pytest.mark.parametrize('action', ['verify', 'idle', 'snapshot', 'suspend'])
def test_search_only_ancestor_allows_worker_without_directory_listing(tenants,tmp_path,selected,action):
    instance, other = tenants[selected], tenants[1-selected]
    source = instance.state_dir/'archive.sqlite'
    ancestor = instance.state_dir.parent
    before, other_before = source.read_bytes(), (other.state_dir/'archive.sqlite').read_bytes()
    previous_mode = ancestor.stat().st_mode & 0o777
    ancestor.chmod(0o111)
    destination = tmp_path/'search-only-snapshot.sqlite'
    try:
        # The actual Unix identity may traverse this ancestor but cannot list it.
        with pytest.raises(PermissionError):
            with secure.physical_directory(ancestor):
                pass
        secure.run_database(instance,action,**({'target':destination} if action == 'snapshot' else {}))
        assert ancestor.stat().st_mode & 0o777 == 0o111
        if action == 'suspend':
            with closing(sqlite3.connect(source)) as db:
                assert db.execute('SELECT COUNT(*) FROM link_login_states').fetchone() == (0,)
        else:
            assert source.read_bytes() == before
        if action == 'snapshot':
            with closing(sqlite3.connect(destination)) as db:
                assert db.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
                assert db.execute('PRAGMA journal_mode').fetchone() == ('delete',)
                assert db.execute('SELECT COUNT(*) FROM link_login_states').fetchone() == (1,)
            assert destination.stat().st_mode & 0o777 == 0o600
        assert (other.state_dir/'archive.sqlite').read_bytes() == other_before
    finally:
        ancestor.chmod(previous_mode)


@pytest.mark.skipif(os.geteuid() == 0, reason='Directory search denial requires an unprivileged fixture')
@pytest.mark.parametrize('action', ['verify', 'idle', 'snapshot', 'suspend'])
def test_unsearchable_ancestor_is_rejected_before_sqlite(tenants,monkeypatch,action):
    instance, other = tenants
    request = secure.tenant_context(instance)
    ancestor = instance.state_dir.parent
    previous_mode = ancestor.stat().st_mode & 0o777
    other_before = (other.state_dir/'archive.sqlite').read_bytes()
    monkeypatch.setattr(secure.sqlite3,'connect',lambda *args,**kwargs:pytest.fail('SQLite reached without search permission'))
    output = io.BytesIO()
    ancestor.chmod(0)
    try:
        with pytest.raises(PermissionError):
            secure.perform(request,action,output)
        assert ancestor.stat().st_mode & 0o777 == 0
        assert output.getvalue() == b''
        assert (other.state_dir/'archive.sqlite').read_bytes() == other_before
    finally:
        ancestor.chmod(previous_mode)


@pytest.mark.skipif(os.geteuid() == 0, reason='Directory listing denial requires an unprivileged fixture')
def test_search_only_ancestor_does_not_bypass_busy_queue_gate(tenants):
    instance, other = tenants
    source = instance.state_dir/'archive.sqlite'
    with closing(sqlite3.connect(source)) as db:
        db.execute('INSERT INTO sends VALUES (?,?,?,?,?,?,?)', ('synthetic-active','owner','hash','sending',None,0,0))
        db.commit()
    before, other_before = source.read_bytes(), (other.state_dir/'archive.sqlite').read_bytes()
    ancestor = instance.state_dir.parent
    previous_mode = ancestor.stat().st_mode & 0o777
    ancestor.chmod(0o111)
    try:
        with pytest.raises(subprocess.CalledProcessError):
            secure.run_database(instance,'idle')
        assert source.read_bytes() == before
        assert (other.state_dir/'archive.sqlite').read_bytes() == other_before
        assert ancestor.stat().st_mode & 0o777 == 0o111
    finally:
        ancestor.chmod(previous_mode)
