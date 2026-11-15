"""Registered deployment marker preflight checks only a synthetic DB copy."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import github_release as release
from github_release_common import ReleaseError


@pytest.fixture
def identity(tmp_path,monkeypatch):
    config_dir=tmp_path/'config';config_dir.mkdir()
    data=tmp_path/'data';data.mkdir()
    config={'database':str(data/'archive.sqlite'),'owner_subject':'synthetic-owner',
            'public_url':'https://synthetic.invalid','session':'default'}
    path=config_dir/'config.toml'
    path.write_text('[bridge]\n'+'\n'.join(key+'='+json.dumps(value) for key,value in config.items()))
    marker=config_dir/'technical-state.json'
    value={'protocol':1,'id':'a'*32,'tenant':hashlib.sha256(json.dumps(
        [config['owner_subject'],config['public_url'],config['session']],separators=(',',':')).encode()).hexdigest()}
    marker.write_text(json.dumps(value));marker.chmod(0o640)
    copy=tmp_path/'preview.sqlite'
    with closing(sqlite3.connect(copy)) as db:
        db.execute('CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT)')
        db.execute('INSERT INTO state VALUES(?,?)',('private:technical_state_identity:v1',json.dumps(value)))
        db.commit()
    original_stat=Path.stat
    def stat(file,*args,**kwargs):
        info=original_stat(file,*args,**kwargs)
        if file==marker:
            fields=list(info);fields[4]=0
            return os.stat_result(fields)
        return info
    monkeypatch.setattr(Path,'stat',stat)
    return {'config':path},copy,marker,value,data


def test_conventional_marker_works_without_changing_legacy_configuration(identity):
    instance,copy,marker,value,data=identity
    before={path:path.read_bytes() for path in (instance['config'],copy,marker)}
    assert release.verify_state_identity(instance,copy)==marker
    assert before=={path:path.read_bytes() for path in before}
    assert not (data/'archive.sqlite').exists()
    assert not copy.with_name(copy.name+'-wal').exists()


@pytest.mark.parametrize('damage',['missing','tenant','id','permission','copy','inside-data','symlink',
                                   'protocol-bool','copy-protocol-bool','id-uppercase','tenant-uppercase','extra'])
def test_marker_preflight_rejects_inconsistent_or_unprotected_state(identity,damage):
    instance,copy,marker,value,data=identity
    if damage=='missing':marker.unlink()
    elif damage in ('tenant','id'):
        value[damage]='b'*(64 if damage=='tenant' else 32);marker.write_text(json.dumps(value))
    elif damage=='permission':marker.chmod(0o666)
    elif damage=='copy':
        with closing(sqlite3.connect(copy)) as db:db.execute('DELETE FROM state');db.commit()
    elif damage=='inside-data':
        destination=data/'identity.json';destination.write_text(marker.read_text())
        with instance['config'].open('a') as stream:stream.write('\nstate_identity_file='+json.dumps(str(destination)))
    elif damage=='symlink':
        target=marker.with_suffix('.target');marker.rename(target);marker.symlink_to(target)
    else:
        if damage in ('protocol-bool','copy-protocol-bool'):value['protocol']=True
        elif damage=='extra':value['extra']='untrusted'
        else:
            key=damage.split('-')[0];value[key]=value[key].upper()
        if damage!='copy-protocol-bool':marker.write_text(json.dumps(value))
        # A matching corrupt DB must not make an invalid marker acceptable;
        # boolean True compares equal to integer 1 in ordinary dict equality.
        with closing(sqlite3.connect(copy)) as db:
            db.execute('UPDATE state SET value=?',(json.dumps(value),));db.commit()
    with pytest.raises((ReleaseError,FileNotFoundError)):release.verify_state_identity(instance,copy)


def test_service_access_probe_includes_the_actual_marker(identity,monkeypatch):
    instance,copy,marker,value,data=identity
    instance={**instance,'slug':'synthetic','unit':'synthetic.service'}
    monkeypatch.setattr(release,'prepare_gate_directory',lambda:None)
    commands=[]
    def run(args,**kwargs):
        commands.append(list(map(str,args)))
        return 'synthetic-user' if args[0]=='systemctl' else ''
    monkeypatch.setattr(release,'run',run)
    release.verify_service_access(copy.parent,[instance],state_markers={'synthetic':marker})
    assert commands[-1][0:3]==['runuser','-u','synthetic-user']
    assert commands[-1][-1]==str(marker)
