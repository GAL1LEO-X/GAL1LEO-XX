"""Cold backup subprocesses against a synthetic protected administration tree."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from test_release_admin import SCRIPTS, admin, declare, installation


PARENT = r'''
import hashlib, json, os, subprocess, sys, types
from pathlib import Path
case, bootstrap, generation, owner, project = map(Path, sys.argv[1:])
assert sys.flags.dont_write_bytecode == 1
assert 'PYTHONDONTWRITEBYTECODE' not in os.environ
def source_module(name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module
source_module('installation_layout', bootstrap/'installation_layout.py')
administration = source_module('release_admin', bootstrap/'release_admin.py')
current = administration.load_generation()
administration.pin_generation(current)
sys.path.insert(0, str(generation))
import github_release as release
assert Path(release.__file__) == generation/'github_release.py'
def inventory():
    result = {}
    for item in (generation, *sorted(generation.rglob('*')), owner):
        info = item.lstat()
        name = 'owner' if item == owner else item.relative_to(generation).as_posix()
        result[name] = [info.st_mode, info.st_uid, info.st_gid, info.st_mtime_ns,
                        hashlib.sha256(item.read_bytes()).hexdigest() if item.is_file() else None]
    return result
before = inventory()
preflight = []
def verify_prerequisites(root):
    # Exercise the actual read-only worker branch with the preflight's -B.
    checked = subprocess.run([root/'.venv/bin/python', '-B', root/'scripts/backup_runtime.py',
                              '--check-recovery'], capture_output=True, text=True, timeout=15)
    assert checked.returncode == 0, checked.stderr
    value = json.loads(checked.stdout)
    assert value['helper'] == str(generation/'release_backup.py')
    assert value['beforeStop'] is True
    assert inventory() == before
    preflight.append('passed-without-generation-mutation')
release.backup_recovery.verify_prerequisites = verify_prerequisites
release.backup_components = lambda rows: []
plan = {'id': 'f'*32, 'servicesRestored': True, 'copies': {'synthetic': {'complete': True}}}
release.backup_recovery.begin = lambda *args: plan
release.backup_recovery.recover = lambda *args: plan
def verify_backups(output, selected, *, auth_modes):
    assert json.loads(output) == {'registry_boundary': True}
    assert selected == ['synthetic'] and auth_modes == {'synthetic': 'managed-authelia'}
    return ['synthetic-backup']
release.verify_backups = verify_backups
error = None
paths = None
with (project/'private/tenant-admin.lock').open('a') as lock:
    try:
        # Both the command constructor and run_backup_process/Popen are real.
        paths = release.runtime_backups(project, [{'slug': 'synthetic'}], lock.fileno(), '0.5.0')
    except Exception as failure:
        error = {'type': type(failure).__name__, 'message': str(failure)}
after = inventory()
outcome = (json.loads((case/'worker-outcome.json').read_text())
           if (case/'worker-outcome.json').exists() else {'status': 'worker-not-reached'})
result = {'preflight': preflight, 'parent_bytecode_flag': sys.flags.dont_write_bytecode,
                  'environment_bytecode_override': 'PYTHONDONTWRITEBYTECODE' in os.environ,
                  'paths': paths, 'error': error, 'worker': outcome,
                  'generation_and_owner_unchanged': after == before,
                  'created_generation_paths': sorted(set(after)-set(before))}
(case/'cold-backup-result.json').write_text(json.dumps(result, sort_keys=True))
print(json.dumps(result))
'''


def synthetic_worker(source, *, case, bootstrap, project):
    """Adapt only local UID/trust-root and the boundary before registry/service IO.

    recovery_helpers, main, the imports, inherited-FD checks and every generation
    hash/tree admission remain production code. Root ownership is represented by
    the test runner's UID inside its explicit temporary trust root, as in the
    existing cold administrative bootstrap fixtures.
    """
    source = source.replace(
        'for item in (path, layout_path, *path.parents):',
        'for item in (path, layout_path, *[p for p in path.parents if p.is_relative_to(_fixture_root)]):')
    source = source.replace('metadata.st_uid != 0', 'metadata.st_uid != _fixture_uid')
    boundary = f'''
_fixture_root = Path({str(case)!r})
_fixture_uid = {os.getuid()}
BOOTSTRAP_ADMIN = Path({str(bootstrap/'release_admin.py')!r})
ROOT = Path({str(project)!r})
os.geteuid = lambda: 0
def _fixture_outcome(value):
    value['bytecode_flag'] = sys.flags.dont_write_bytecode
    Path({str(case/'worker-outcome.json')!r}).write_text(json.dumps(value))
def _fixture_failure(kind, error, trace):
    _fixture_outcome({{'status': 'rejected', 'type': kind.__name__, 'message': str(error)}})
    sys.__excepthook__(kind, error, trace)
sys.excepthook = _fixture_failure
def _fixture_registry_boundary(*args):
    _fixture_outcome({{'status': 'registry-boundary'}})
    print(json.dumps({{'registry_boundary': True}}))
    raise SystemExit(0)
registered_instances = _fixture_registry_boundary
if __name__=='__main__': main()
'''
    assert source.count("if __name__=='__main__': main()") == 1
    setup = ('from pathlib import Path\n'
             'from sally_whatsapp.installation import activate_installation\n'
             'activate_installation(root=Path('+repr(str(case))+'),trusted_uid='+str(os.getuid())+')\n')
    return setup + source.replace("if __name__=='__main__': main()", boundary)


def backup_tree(installation, tmp_path):
    generation, owner = installation
    import build_admin_bundle as builder
    # Actual complete source closure, not mocks of the offending imports.
    for name in builder.GENERATION_FILES:
        target = generation/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SCRIPTS/name, target)
    declare(generation, owner)
    bootstrap = admin.BOOTSTRAP
    source = (SCRIPTS/'release_admin.py').read_text()
    for name in ('_TRUST_ROOT', 'STATE', 'PUBLICATION_LOCK', 'OWNER', 'BOOTSTRAP',
                 'ENTRYPOINT', 'GENERATIONS'):
        source += '\n'+name+'=Path('+repr(str(getattr(admin, name)))+')'
    source += '\n_trusted_uid=lambda uid:uid=='+str(os.getuid())+'\n'
    (bootstrap/'release_admin.py').write_text(source)
    project = tmp_path/'project'
    (project/'scripts').mkdir(parents=True)
    (project/'private').mkdir()
    (project/'.venv/bin').mkdir(parents=True)
    # A real interpreter; neither a command recorder nor a fabricated child.
    (project/'.venv/bin/python').symlink_to(sys.executable)
    shutil.copyfile(Path(sys.prefix)/'pyvenv.cfg', project/'.venv/pyvenv.cfg')
    packages = Path('lib')/('python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor))/'site-packages'
    (project/'.venv'/packages).parent.mkdir(parents=True)
    (project/'.venv'/packages).symlink_to(Path(sys.prefix)/packages, target_is_directory=True)
    shutil.copyfile(bootstrap/'installation_layout.py', project/'scripts/installation_layout.py')
    worker = synthetic_worker((SCRIPTS/'backup_runtime.py').read_text(),
                              case=tmp_path, bootstrap=bootstrap, project=project)
    (project/'scripts/backup_runtime.py').write_text(worker)
    return generation, owner, bootstrap, project


def test_runtime_backup_child_preserves_generation_after_real_preflight(
        installation, tmp_path):
    generation, owner, bootstrap, project = backup_tree(installation, tmp_path)
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith('PYTHON'):
            environment.pop(name)
    process = subprocess.run([sys.executable, '-I', '-B', '-c', PARENT, str(tmp_path),
                              str(bootstrap), str(generation), str(owner), str(project)],
                             env=environment, cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stderr
    result = json.loads(process.stdout)
    assert result['preflight'] == ['passed-without-generation-mutation'], result
    assert result['parent_bytecode_flag'] == 1 and result['environment_bytecode_override'] is False
    assert result['error'] is None, result
    assert result['paths'] == ['synthetic-backup']
    assert result['worker'] == {'status': 'registry-boundary', 'bytecode_flag': 1}
    assert result['generation_and_owner_unchanged'], result
    assert result['created_generation_paths'] == []
