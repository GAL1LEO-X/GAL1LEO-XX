"""Archive content guards shared by release validation and synthetic restore."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import tarfile
import tracemalloc
from types import SimpleNamespace

import pytest


PLUGIN = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PLUGIN/'scripts'), str(PLUGIN/'tests'), str(PLUGIN)]
import backup_validation as candidate
from sally_whatsapp.store import SCHEMA
import github_release as release
import test_backup_restore as restore

SOURCE_FILES = ['pyproject.toml','requirements.lock','sally_whatsapp/__init__.py','sally_whatsapp/store.py']
RUNTIME_FILES = ['etc/whatsapp-fixture/'+v for v in ['config.toml','encryption.key','webhook.key','waha.key']]
RUNTIME_FILES += ['var/lib/sally-browser/stack/config/'+v for v in ['authelia.yml','users.yml']]


def raw_tar(names, *, empty=None, extra=()):
    target=io.BytesIO()
    with tarfile.open(fileobj=target,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,data in [(name,b'' if name==empty else b'synthetic-only') for name in names]+list(extra):
            info=tarfile.TarInfo(name);info.size=len(data)
            archive.addfile(info,io.BytesIO(data))
    return target.getvalue()


def sign(snapshot):
    manifest={'format':candidate.FORMAT,'user':'fixture','created_utc':'20261012T000000000000Z',
              'sqlite_integrity':'ok','includes_credentials':True,'files':{}}
    for name in candidate.SNAPSHOT_FILES:
        data=(snapshot/name).read_bytes()
        manifest['files'][name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    (snapshot/'manifest.json').write_text(json.dumps(manifest))


@pytest.fixture
def snapshot(tmp_path,monkeypatch):
    root=tmp_path/'snapshot';root.mkdir()
    for name in ['archive.sqlite','shared-authelia.sqlite3']:
        connection=sqlite3.connect(root/name)
        connection.executescript(SCHEMA if name == 'archive.sqlite' else
            'CREATE TABLE user_opaque_identifier(service TEXT,sector_id TEXT,username TEXT,identifier TEXT UNIQUE);')
        connection.commit();connection.close()
    (root/'source.tar.gz').write_bytes(gzip.compress(raw_tar(SOURCE_FILES),mtime=0))
    (root/'private-runtime.tar.gz').write_bytes(gzip.compress(raw_tar(RUNTIME_FILES),mtime=0))
    sign(root)
    monkeypatch.setattr(release,'BACKUPS',tmp_path)
    return root


def both_gates(snapshot,expected):
    before={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in snapshot.iterdir()}
    receipt=json.dumps({'user':'fixture','backup':str(snapshot),'complete':True})
    if expected:
        assert candidate.validate_snapshot(snapshot,'fixture')['user']=='fixture'
        assert release.verify_backups(receipt,['fixture'])==[str(snapshot)]
    else:
        with pytest.raises(ValueError):candidate.validate_snapshot(snapshot,'fixture')
        with pytest.raises(release.ReleaseError,match='backup validation failed'):
            release.verify_backups(receipt,['fixture'])
    assert before=={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in snapshot.iterdir()}


CASES=['standard','extra_zero_tar','raw_zero_gzip','buffered_nonzero','tail_nonzero',
       'same_gzip_second_tar','concatenated_garbage','concatenated_second_tar',
       'concatenated_empty','concatenated_zero','crc_first','footer_first','raw_garbage','crc_second','footer_second']
ACCEPTED={'standard','extra_zero_tar','raw_zero_gzip','concatenated_empty','concatenated_zero'}


@pytest.mark.parametrize('case',CASES)
def test_tail_matrix_checks_real_snapshot_and_release_gate(snapshot,case):
    raw=raw_tar(SOURCE_FILES);gz=gzip.compress(raw,mtime=0);marker=b'SYNTHETIC-TRAILING-NONZERO'
    other=raw_tar(['synthetic-tail.txt'],extra=[('pyproject.toml',b'second-version')]);gzother=gzip.compress(other,mtime=0)
    blobs={'standard':gz,'extra_zero_tar':gzip.compress(raw+bytes(20480),mtime=0),'raw_zero_gzip':gz+bytes(32),
        'buffered_nonzero':gzip.compress(raw[:5400]+marker+raw[5400+len(marker):],mtime=0),
        'tail_nonzero':gzip.compress(raw+marker,mtime=0),'same_gzip_second_tar':gzip.compress(raw+other,mtime=0),
        'concatenated_garbage':gz+gzip.compress(marker,mtime=0),'concatenated_second_tar':gz+gzother,
        'concatenated_empty':gz+gzip.compress(b'',mtime=0),'concatenated_zero':gz+gzip.compress(bytes(1024),mtime=0),
        'crc_first':gz[:-8]+bytes([gz[-8]^1])+gz[-7:],'footer_first':gz[:-4],'raw_garbage':gz+marker,
        'crc_second':gz+gzother[:-8]+bytes([gzother[-8]^1])+gzother[-7:],'footer_second':gz+gzother[:-4]}
    (snapshot/'source.tar.gz').write_bytes(blobs[case]);sign(snapshot)
    both_gates(snapshot,case in ACCEPTED)


@pytest.mark.parametrize('archive,names,empty',
    [('source.tar.gz',SOURCE_FILES,v) for v in SOURCE_FILES]+[('private-runtime.tar.gz',RUNTIME_FILES,v) for v in RUNTIME_FILES])
def test_each_mandatory_zero_length_member_is_rejected(snapshot,archive,names,empty):
    (snapshot/archive).write_bytes(gzip.compress(raw_tar(names,empty=empty),mtime=0));sign(snapshot)
    with pytest.raises(ValueError,match='Required backup archive member is empty'):
        candidate.validate_snapshot(snapshot,'fixture')
    both_gates(snapshot,False)


def test_optional_empty_members_stay_compatible(snapshot):
    (snapshot/'source.tar.gz').write_bytes(gzip.compress(raw_tar(SOURCE_FILES,
        extra=[('optional/.keep',b''),('optional/empty.txt',b'')]),mtime=0));sign(snapshot)
    both_gates(snapshot,True)


def test_empty_regular_file_still_conflicts_with_child_path(snapshot):
    (snapshot/'source.tar.gz').write_bytes(gzip.compress(raw_tar(SOURCE_FILES,
        extra=[('optional',b''),('optional/child',b'x')]),mtime=0));sign(snapshot)
    both_gates(snapshot,False)


def test_required_iterator_is_not_consumed_before_completeness_check(tmp_path):
    path=tmp_path/'missing.tar.gz';path.write_bytes(gzip.compress(raw_tar(['present']),mtime=0))
    with pytest.raises(ValueError,match='missing required files'):
        candidate.validate_archive(path,(name for name in ['present','missing']))


@pytest.mark.parametrize('damage',['empty','tail'])
def test_restore_rehearsal_blocks_before_creating_destination(snapshot,tmp_path,damage):
    raw=raw_tar(SOURCE_FILES,empty='pyproject.toml' if damage=='empty' else None)
    if damage=='tail':raw+=b'synthetic-nonpadding'
    (snapshot/'source.tar.gz').write_bytes(gzip.compress(raw,mtime=0));sign(snapshot)
    target=tmp_path/'restore-must-not-exist'
    with pytest.raises(ValueError):
        restore.restore_fixture({'fixture':snapshot},target,Path('/'),
                                {'fixture':SimpleNamespace(state_dir=Path('/var/lib/whatsapp-fixture'))})
    assert not target.exists()


class RepeatingReader:
    def __init__(self,size):self.remaining=size
    def read(self,size=-1):
        size=self.remaining if size<0 else min(size,self.remaining)
        self.remaining-=size
        return b'x'*size


@pytest.mark.parametrize('tail',[False,True])
def test_large_pax_long_names_remain_bounded_and_tail_checked(tmp_path,tail,record_property):
    path=tmp_path/'large-pax.tar.gz'
    long_name='nested/'+('very-long-component-'*12)+'/synthetic-large.bin'
    size=32*1024*1024
    with tarfile.open(path,mode='w:gz',format=tarfile.PAX_FORMAT) as archive:
        directory=tarfile.TarInfo('nested');directory.type=tarfile.DIRTYPE;archive.addfile(directory)
        for name in SOURCE_FILES:
            info=tarfile.TarInfo(name);info.size=1;archive.addfile(info,io.BytesIO(b'x'))
        info=tarfile.TarInfo(long_name);info.size=size;info.mtime=1.25
        archive.addfile(info,RepeatingReader(size))
    if tail:
        with path.open('ab') as stream:stream.write(gzip.compress(b'nonzero-after-large-pax',mtime=0))
    tracemalloc.start()
    try:
        if tail:
            with pytest.raises(ValueError,match='Non-padding data'):
                candidate.validate_archive(path,SOURCE_FILES)
        else:candidate.validate_archive(path,SOURCE_FILES)
        _,peak=tracemalloc.get_traced_memory()
    finally:tracemalloc.stop()
    record_property('uncompressed_file_bytes',size)
    record_property('peak_python_traced_bytes',peak)
    assert peak < 16*1024*1024, 'Validation must not retain the whole 32 MiB member'
