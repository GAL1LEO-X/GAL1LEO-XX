"""Independent offline review of administrative enrollment and restart edges."""
from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3

import pytest

from sally_whatsapp import cli, state_continuity
from sally_whatsapp.config import Settings
from sally_whatsapp.state_continuity import StateContinuity, StateContinuityError, STATE_KEY, register_external_identity
from sally_whatsapp.store import SCHEMA_7, Store


def external_settings(environment, tmp_path):
    return replace(environment[0], database=tmp_path/'data'/'archive.sqlite',
                   state_identity_file=tmp_path/'config'/'technical-state.json')


def database_identity(path):
    with sqlite3.connect(path) as db:
        return json.loads(db.execute('SELECT value FROM state WHERE key=?', (STATE_KEY,)).fetchone()[0])


def file_config(settings, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    names=('database','public_url','issuer','owner_subject','webhook_secret_file',
           'encryption_key_file','public_key_file','oauth_client_ids','session')
    path.write_text('[bridge]\n'+'\n'.join(name+' = '+json.dumps(
        str(value) if isinstance(value,Path) else value)
        for name in names for value in [getattr(settings,name)])+'\n')
    return Settings.load(str(path))


def test_offline_registration_preserves_schema7_records_and_normal_upgrade_identity(environment,tmp_path):
    settings=external_settings(environment,tmp_path)
    settings.database.parent.mkdir()
    with sqlite3.connect(settings.database) as db:
        db.executescript(SCHEMA_7)
        db.execute("INSERT INTO message_mutations VALUES('revoked-before-upgrade','revoked',NULL,100)")
        db.execute("INSERT INTO state VALUES('retained-setting','true')")
    register_external_identity(settings)
    identity=database_identity(settings.database)
    marker=settings.state_identity_file.read_bytes()
    with sqlite3.connect(settings.database) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==7
        assert db.execute('SELECT * FROM message_mutations').fetchall()==[('revoked-before-upgrade','revoked',None,100.0)]
        assert db.execute("SELECT value FROM state WHERE key='retained-setting'").fetchone()[0]=='true'
    guard=StateContinuity(settings,allow_bootstrap=True)
    store=Store(settings.database,continuity=guard)
    guard.enroll(store)
    with store.db() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==8
    assert database_identity(settings.database)==identity
    assert settings.state_identity_file.read_bytes()==marker
    assert store.message_state('revoked-before-upgrade')['state']=='revoked'


def test_external_enrollment_crash_requires_explicit_idempotent_repair(environment,tmp_path,monkeypatch):
    settings=external_settings(environment,tmp_path)
    Store(settings.database)
    original=state_continuity._write_marker
    def interrupted(*args):
        raise OSError('synthetic failure after database commit')
    monkeypatch.setattr(state_continuity,'_write_marker',interrupted)
    with pytest.raises(StateContinuityError):
        register_external_identity(settings)
    committed=database_identity(settings.database)
    assert not settings.state_identity_file.exists()
    with pytest.raises(StateContinuityError):
        StateContinuity(settings,allow_bootstrap=True)
    monkeypatch.setattr(state_continuity,'_write_marker',original)
    register_external_identity(settings)
    register_external_identity(settings)
    assert json.loads(settings.state_identity_file.read_text())==committed
    assert settings.state_identity_file.stat().st_mode & 0o777 == 0o600
    assert not list(settings.state_identity_file.parent.glob('.state-identity-*'))


def test_read_only_external_marker_is_not_rewritten_by_open_enroll_or_check(environment,tmp_path,monkeypatch,capsys):
    settings=external_settings(environment,tmp_path)
    loaded=file_config(settings,tmp_path/'config'/'bridge.toml')
    Store(loaded.database)
    register_external_identity(loaded)
    marker=loaded.state_identity_file
    marker.chmod(0o440)
    before=marker.read_bytes(),marker.stat().st_mtime_ns,marker.stat().st_ino
    guard=StateContinuity(loaded,allow_bootstrap=False)
    store=Store(loaded.database,migrate_schema=False,continuity=guard)
    guard.enroll(store)
    monkeypatch.setattr('sys.argv',['sally-whatsapp','--config',str(tmp_path/'config'/'bridge.toml'),'check'])
    cli.main()
    assert 'no network/account action performed' in capsys.readouterr().out
    assert (marker.read_bytes(),marker.stat().st_mtime_ns,marker.stat().st_ino)==before
    assert marker.stat().st_mode & 0o777 == 0o440
    assert environment[2].sent==[]


def test_legitimate_snapshot_replacement_requires_new_process_guard(environment,tmp_path):
    settings=external_settings(environment,tmp_path)
    Store(settings.database)
    register_external_identity(settings)
    guard=StateContinuity(settings,allow_bootstrap=False)
    store=Store(settings.database,migrate_schema=False,continuity=guard)
    store.reserve_send('retained-key','test-owner',{'text':'synthetic'})
    replacement=tmp_path/'snapshot.sqlite'
    store.backup(replacement)
    os.replace(replacement,settings.database)
    with pytest.raises(StateContinuityError):
        store.send_status('retained-key')
    restarted_guard=StateContinuity(settings,allow_bootstrap=False)
    restarted=Store(settings.database,migrate_schema=False,continuity=restarted_guard)
    assert restarted.send_status('retained-key')['state']=='sending'
    assert restarted_guard.file_identity!=guard.file_identity


@pytest.mark.parametrize('change',[{'owner_subject':'other-owner'}, {'public_url':'https://other.example'}, {'session':'other-session'}])
def test_external_identity_is_bound_to_every_tenant_context_component(environment,tmp_path,change):
    settings=external_settings(environment,tmp_path)
    Store(settings.database)
    register_external_identity(settings)
    altered=replace(settings,**change)
    with pytest.raises(StateContinuityError):
        StateContinuity(altered,allow_bootstrap=True)
    with pytest.raises(StateContinuityError):
        register_external_identity(altered)


def test_default_config_marker_requires_separate_tenant_directories(environment,tmp_path):
    first=external_settings(environment,tmp_path)
    second=replace(first,database=tmp_path/'data-other'/'archive.sqlite',owner_subject='other-owner')
    loaded_first=file_config(first,tmp_path/'config'/'first.toml')
    loaded_second=file_config(second,tmp_path/'config'/'second.toml')
    assert loaded_first.state_identity_file==loaded_second.state_identity_file
    Store(first.database);Store(second.database)
    register_external_identity(loaded_first)
    with pytest.raises(StateContinuityError):
        register_external_identity(loaded_second)
    distinct=file_config(second,tmp_path/'config-other'/'second.toml')
    register_external_identity(distinct)
    assert json.loads(distinct.state_identity_file.read_text())['tenant']!=json.loads(loaded_first.state_identity_file.read_text())['tenant']


def test_malformed_stored_identity_fails_closed_without_replacing_marker(environment,tmp_path):
    settings=external_settings(environment,tmp_path)
    Store(settings.database)
    register_external_identity(settings)
    marker=settings.state_identity_file.read_bytes()
    with sqlite3.connect(settings.database) as db:
        db.execute('UPDATE state SET value=? WHERE key=?',('[1,2]',STATE_KEY))
    with pytest.raises(StateContinuityError):
        StateContinuity(settings,allow_bootstrap=True)
    with pytest.raises(StateContinuityError):
        register_external_identity(settings)
    assert settings.state_identity_file.read_bytes()==marker
