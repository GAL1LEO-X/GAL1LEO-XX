"""Synthetic immutable-generation and admission tests; no host service calls."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPTS = Path(__file__).parents[1]/'scripts'
sys.path.insert(0, str(SCRIPTS))
import release_admin as admin
import release_entry as entry


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def declare(root, owner, *, epoch='a'*32, state='dedicated'):
    files={path.relative_to(root).as_posix():hashlib.sha256(path.read_bytes()).hexdigest()
           for path in root.rglob('*') if path.is_file() and path.name!='manifest.json'}
    manifest=encoded({'protocol':1,'files':files})
    (root/'manifest.json').write_bytes(manifest)
    value={'protocol':1,'epoch':epoch,'state':state,'generation':str(root),
           'manifest_sha256':hashlib.sha256(manifest).hexdigest()}
    owner.write_bytes(encoded(value))
    return value


@pytest.fixture
def installation(tmp_path,monkeypatch):
    bootstrap=tmp_path/'bootstrap';bootstrap.mkdir()
    roots=tmp_path/'generations';roots.mkdir()
    generation=roots/'generation-a';generation.mkdir()
    state=tmp_path/'wa-state';state.mkdir()
    owner_directory=tmp_path/'owners';owner_directory.mkdir()
    owner=owner_directory/'whatsapp.json'
    from installation_layout import IDENTITY, Installation, identity_bytes
    marker=tmp_path/IDENTITY.relative_to('/')
    marker.parent.mkdir(parents=True)
    marker.write_bytes(identity_bytes(Installation.legacy()));marker.chmod(0o600)
    # The synthetic bootstrap has an explicit trust root. Its copied loader
    # still reads the protected identity marker before the administrative core.
    layout_source=(SCRIPTS/'installation_layout.py').read_text()
    layout_source+='\nactivate_installation(root=Path('+repr(str(tmp_path))+'),trusted_uid='+str(os.getuid())+')\n'
    (bootstrap/'installation_layout.py').write_text(layout_source)
    for filename in ('github_release.py','release_recover.py','state_enrollment.py'):
        (generation/filename).write_text(
            "import json, sys, release_admin\n"
            "states=('dedicated','retiring') if __file__.endswith('release_recover.py') else ('dedicated',)\n"
            "current=release_admin.require_current(__file__,states=states)\n"
            "print(json.dumps({'epoch':current.epoch,'generation':str(current.path),'arguments':sys.argv[1:]}))\n")
    for name,value in {'_TRUST_ROOT':tmp_path,'BOOTSTRAP':bootstrap,'ENTRYPOINT':bootstrap/'release_entry.py',
                       'GENERATIONS':roots,'OWNER':owner,'STATE':state,'PUBLICATION_LOCK':state/'publication.lock',
                       '_PINNED':None}.items():
        monkeypatch.setattr(admin,name,value)
    # The temporary fixture is the synthetic trust root. Only UID attestation
    # differs on non-root test runners; modes, links, hashes and paths are real.
    monkeypatch.setattr(admin,'_trusted_uid',lambda uid:uid==os.getuid())
    declare(generation,owner)
    return generation,owner


def test_attested_generation_and_lock_are_read_only_for_owner_and_manifest(installation):
    root,owner=installation
    before=owner.read_bytes(),(root/'manifest.json').read_bytes()
    generation=admin.load_generation()
    assert generation.path==root and generation.epoch=='a'*32
    assert admin.require_current(root/'release_recover.py',expected=generation)==generation
    with admin.publication_lock(root/'release_recover.py',expected=generation) as admitted:
        assert admitted==generation
    assert (owner.read_bytes(),(root/'manifest.json').read_bytes())==before
    assert admin.PUBLICATION_LOCK.parent==admin.STATE
    assert not list(root.rglob('*.pyc'))
    with pytest.raises(TypeError):
        generation.files['unexpected']='value'


@pytest.mark.parametrize('state',['transitioning','retiring','retired','unknown',None])
def test_non_dedicated_owner_cannot_admit_new_work_or_create_lock(installation,state):
    root,owner=installation
    value=json.loads(owner.read_bytes());value['state']=state;owner.write_bytes(encoded(value))
    before=owner.read_bytes()
    with pytest.raises(admin.AdminError):
        with admin.publication_lock():
            pytest.fail('a closed owner admitted work')
    assert owner.read_bytes()==before and not admin.PUBLICATION_LOCK.exists()


def test_retiring_requires_explicit_reader_policy_and_never_changes_owner(installation):
    root,owner=installation
    declare(root,owner,state='retiring')
    assert admin.load_generation(states=('retiring',)).state=='retiring'
    with admin.publication_lock(states=('retiring',)) as generation:
        assert generation.state=='retiring'
    with pytest.raises(admin.AdminError):
        with admin.publication_lock(states=('transitioning',)):
            pass
    for state in ('transitioning','retired'):
        with pytest.raises(admin.AdminError):admin.load_generation(states=(state,))
    assert json.loads(owner.read_bytes())['state']=='retiring'


@pytest.mark.parametrize('mutation',[lambda v:v.update(protocol=True),lambda v:v.update(epoch='not-an-epoch'),
                                   lambda v:v.update(extra=True),lambda v:v.pop('manifest_sha256')])
def test_invalid_owner_fields_fail_closed(installation,mutation):
    _,owner=installation
    value=json.loads(owner.read_bytes());mutation(value);owner.write_bytes(encoded(value))
    with pytest.raises(admin.AdminError):admin.load_generation()


def test_missing_owner_is_never_recreated(installation):
    _,owner=installation;owner.unlink()
    with pytest.raises(admin.AdminError):admin.load_generation()
    assert not owner.exists() and not admin.PUBLICATION_LOCK.exists()


@pytest.mark.parametrize('target',['owner','generation','helper','ancestor'])
def test_writable_administrative_path_is_rejected(installation,target):
    root,owner=installation
    path={'owner':owner,'generation':root,'helper':root/'release_recover.py','ancestor':root.parent}[target]
    path.chmod(path.stat().st_mode | 0o020)
    with pytest.raises(admin.AdminError):admin.load_generation()


def test_untrusted_owner_uid_is_rejected(installation,monkeypatch):
    monkeypatch.setattr(admin,'_trusted_uid',lambda uid:False)
    with pytest.raises(admin.AdminError):admin.load_generation()


@pytest.mark.parametrize('kind',['helper-link','generation-link','extra-file','pyc','cache'])
def test_manifest_requires_physical_complete_source_only_tree(installation,kind):
    root,owner=installation
    if kind=='helper-link':
        original=root/'release_recover.py';target=root/'saved.py'
        original.rename(target);original.symlink_to(target)
    elif kind=='generation-link':
        link=root.parent/'alias';link.symlink_to(root,target_is_directory=True)
        value=json.loads(owner.read_bytes());value['generation']=str(link);owner.write_bytes(encoded(value))
    elif kind=='extra-file':(root/'undeclared.txt').write_text('synthetic')
    elif kind=='pyc':(root/'stale.pyc').write_bytes(b'synthetic stale bytecode')
    else:(root/'__pycache__').mkdir()
    with pytest.raises(admin.AdminError):admin.load_generation()


def test_manifest_and_source_hash_tampering_fail_closed(installation):
    root,owner=installation
    (root/'release_recover.py').write_text('raise RuntimeError("synthetic unapproved")\n')
    with pytest.raises(admin.AdminError):admin.load_generation()
    declare(root,owner)
    manifest=root/'manifest.json';manifest.write_bytes(manifest.read_bytes()+b' ')
    with pytest.raises(admin.AdminError):admin.load_generation()


def test_old_path_and_old_epoch_are_not_silently_reselected(installation):
    root,owner=installation
    original=admin.load_generation()
    other=root.parent/'generation-b';other.mkdir()
    (other/'release_recover.py').write_text('pass\n')
    with pytest.raises(admin.AdminError):admin.require_current(other/'release_recover.py')
    declare(root,owner,epoch='b'*32)
    with pytest.raises(admin.AdminError):
        with admin.publication_lock(expected=original):pass
    admin.pin_generation(original)
    with pytest.raises(admin.AdminError):admin.load_generation()


def test_owner_changed_while_acquiring_lock_cannot_enter_body(installation,monkeypatch):
    root,owner=installation
    lock=fcntl.flock
    def changed(fd,operation):
        lock(fd,operation)
        declare(root,owner,epoch='b'*32)
    monkeypatch.setattr(admin.fcntl,'flock',changed)
    with pytest.raises(admin.AdminError):
        with admin.publication_lock(root/'release_recover.py'):
            pytest.fail('changed owner admitted the old operation')


def test_other_namespace_lock_does_not_block_wa_and_wa_contention_defers(installation,tmp_path):
    unrelated=tmp_path/'publication.lock'
    with unrelated.open('a') as held:
        fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with admin.publication_lock():
            with pytest.raises(admin.AdminBusy):
                with admin.publication_lock():pass
    with admin.publication_lock():pass


def test_operation_errors_are_not_disguised_as_lock_failures(installation):
    with pytest.raises(OSError,match='synthetic operation'):
        with admin.publication_lock():raise OSError('synthetic operation')
    with admin.publication_lock():pass


def test_entry_allowlist_and_pinned_dispatch(installation,monkeypatch,capsys):
    root,owner=installation
    monkeypatch.setattr(entry,'_admin_module',lambda:admin)
    monkeypatch.setattr(sys,'path',list(sys.path))
    monkeypatch.setattr(sys,'argv',list(sys.argv))
    monkeypatch.setattr(sys,'dont_write_bytecode',False)
    with pytest.raises(SystemExit):entry.main(['arbitrary-module'])
    entry.main(['recovery','--check'])
    assert json.loads(capsys.readouterr().out)=={'epoch':'a'*32,'generation':str(root),'arguments':['--check']}
    declare(root,owner,epoch='b'*32)
    with pytest.raises(admin.AdminError):entry.main(['recovery'])


def test_retirement_admits_only_recovery_of_existing_work(installation,monkeypatch,capsys):
    root,owner=installation
    declare(root,owner,state='retiring')
    monkeypatch.setattr(entry,'_admin_module',lambda:admin)
    monkeypatch.setattr(sys,'path',list(sys.path))
    monkeypatch.setattr(sys,'argv',list(sys.argv))
    entry.main(['recovery'])
    assert json.loads(capsys.readouterr().out)['epoch']=='a'*32
    for action in ('receiver','enrollment'):
        with pytest.raises(admin.AdminError):entry.main([action])


def test_cold_boot_uses_protected_source_and_persistent_owner(installation,tmp_path):
    root,owner=installation
    # Exercise actual entry execution in new interpreters. Trust-root and UID
    # overrides exist only in these temporary synthetic bootstrap sources.
    source=(SCRIPTS/'release_admin.py').read_text()
    overrides={name:getattr(admin,name) for name in
               ('_TRUST_ROOT','STATE','PUBLICATION_LOCK','OWNER','BOOTSTRAP','ENTRYPOINT','GENERATIONS')}
    source+='\n'+'\n'.join(name+'=Path('+repr(str(value))+')' for name,value in overrides.items())
    source+='\n_trusted_uid=lambda uid:uid=='+str(os.getuid())+'\n'
    (admin.BOOTSTRAP/'release_admin.py').write_text(source)
    entry_source=(SCRIPTS/'release_entry.py').read_text().replace("_TRUST_ROOT = Path('/')",'_TRUST_ROOT = Path('+repr(str(tmp_path))+')')
    entry_source=entry_source.replace('return uid == 0','return uid == '+str(os.getuid()))
    admin.ENTRYPOINT.write_text(entry_source)
    # A bootstrap cache is never executed: bootstrap compiles protected source.
    cache=admin.BOOTSTRAP/'__pycache__';cache.mkdir()
    (cache/'release_admin.cpython-test.pyc').write_bytes(b'untrusted stale cache')
    before=owner.read_bytes()
    command=[sys.executable,'-I','-B',str(admin.ENTRYPOINT),'recovery','--check']
    for _ in range(2):
        result=subprocess.run(command,capture_output=True,text=True,check=True,timeout=10)
        assert json.loads(result.stdout)['epoch']=='a'*32
    assert owner.read_bytes()==before
    declare(root,owner,state='transitioning')
    stopped=subprocess.run(command,capture_output=True,text=True,timeout=10)
    assert stopped.returncode!=0 and not stopped.stdout
    assert 'administration blocked' in stopped.stderr
    assert not admin.PUBLICATION_LOCK.exists()


def test_loaded_bootstrap_still_requires_the_fixed_entrypoint(installation,monkeypatch):
    # A previously loaded core must not bypass the stable entry path contract.
    core=admin.BOOTSTRAP/'release_admin.py';core.write_text('synthetic core placeholder\n')
    renamed=admin.BOOTSTRAP/'renamed_entry.py';renamed.write_text('synthetic entry placeholder\n')
    monkeypatch.setattr(admin,'__file__',str(core))
    monkeypatch.setattr(entry,'__file__',str(renamed))
    monkeypatch.setattr(entry,'_TRUST_ROOT',admin._TRUST_ROOT)
    monkeypatch.setattr(entry,'_trusted_uid',lambda uid:uid==os.getuid())
    monkeypatch.setitem(sys.modules,'installation_layout',sys.modules['installation_layout'])
    with pytest.raises(RuntimeError,match='path differs'):
        entry._admin_module()
