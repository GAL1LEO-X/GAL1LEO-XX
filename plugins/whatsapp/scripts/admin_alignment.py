"""Align only the public administrative project with its admitted deploy-v1 runtime.

This maintenance library is executed from a reviewed repository checkout, never
from an uploaded restore snapshot. It does not activate the legacy recovery
engine or touch units, credentials, tenant data or deployment configuration.
The caller holds host_integration.runtime_admission for planning and applying.
An exact plan digest and retained filesystem journal make interruption explicit.
"""
import copy
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

REPOSITORY = Path(__file__).resolve().parents[3]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))
from host.lifecycle import filesystem
import admin_deployment
from build_admin_bundle import PROJECT_FILES
from package_source import PUBLIC_DATA, ROOT_FILES

FORMAT = 'whatsapp-administrative-alignment-v1'
MAX_SOURCE_FILES = 512
MAX_SOURCE_BYTES = 32 * 1024 * 1024


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return filesystem.encoded(value)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(root, path, value):
    root._write(str(path), encoded(value), {'uid': root.uid, 'gid': root.gid, 'mode': 0o600},
                temporary=str(path) + '.pending')


def source_files(source):
    """Finite public closure: backend, metadata, skill templates and admin helpers."""
    source = Path(source)
    require(source.is_dir() and source.resolve(strict=True) == source, 'Physical reviewed source required')
    names = {name for name in ROOT_FILES if (source / name).exists()} | {'scripts/' + name for name in PROJECT_FILES}
    names |= {name for name in PUBLIC_DATA if name.startswith('plugin/')}
    for path in (source / 'sally_whatsapp').rglob('*'):
        name = path.relative_to(source).as_posix()
        if path.suffix == '.py' or name in PUBLIC_DATA:
            names.add(name)
        require(len(names) <= MAX_SOURCE_FILES, 'Administrative source file bound exceeded')
    result, size = {}, 0
    for name in sorted(names):
        path = source / name
        require(path.resolve(strict=True) == path, 'Public source cannot contain links')
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Regular public source required')
        raw = path.read_bytes()
        size += len(raw)
        require(size <= MAX_SOURCE_BYTES and len(raw) <= filesystem.MAX_FILE_BYTES,
                'Administrative source byte bound exceeded')
        result[name] = raw
    return result


def closure(project, payloads):
    files = {str(project / name): raw for name, raw in payloads.items()}
    directories = {str(project)}
    for path in files:
        directories.update(str(parent) for parent in Path(path).parents if parent == project or parent.is_relative_to(project))
    return files, directories


def prepare(root, source, profile, runtime, *, commit, operation_id, owner):
    """Read preimages only; caller reviews/pins this result before apply."""
    require(re.fullmatch('[a-f0-9]{40}', commit) and re.fullmatch('[a-f0-9]{32}', operation_id),
            'Exact source commit and fresh operation identity required')
    runtime.check_current()
    project = Path(profile.path('project'))
    files, directories = closure(project, source_files(source))
    before = {'format': 1, 'owner': 'whatsapp', 'files': {}, 'directories': {}, 'links': {}}
    after = copy.deepcopy(before)
    for path in sorted(directories):
        previous = root.directory(path)
        if previous is not None:
            require(previous['uid'] == root.uid and not previous['mode'] & 0o022,
                    'Administrative directory is not protected')
            before['directories'][path] = {**previous, 'retention': 'retain'}
        after['directories'][path] = {**(previous or {'uid': root.uid, 'gid': root.gid, 'mode': 0o755}),
                                      'retention': 'retain'}
    for path, raw in files.items():
        previous = root.snapshot(path)
        if previous is not None:
            require(previous['uid'] == root.uid and not previous['mode'] & 0o022,
                    'Administrative file is not protected; permissions are never repaired')
            before['files'][path] = {**previous, 'retention': 'managed'}
        metadata = {key: previous[key] for key in ('uid', 'gid', 'mode')} if previous else {
            'uid': root.uid, 'gid': root.gid, 'mode': 0o644}
        after['files'][path] = {**metadata, 'sha256': sha(raw), 'retention': 'managed'}
    link = root.link(str(project / '.venv'))
    require(link is not None and link['uid'] == root.uid and Path(link['target']).is_absolute(),
            'Existing administrative interpreter must be an owned absolute link')
    return {'format': FORMAT, 'id': operation_id, 'source_commit': commit,
            'installation_sha256': profile.sha256, 'deployment': runtime.binding,
            'owner': owner, 'venv_before': link, 'before': before, 'after': after}


def validate(plan, source, profile, runtime, owner):
    require(isinstance(plan, dict) and set(plan) == {'format', 'id', 'source_commit', 'installation_sha256',
                'deployment', 'owner', 'venv_before', 'before', 'after'}
            and plan['format'] == FORMAT and re.fullmatch('[a-f0-9]{32}', plan['id'])
            and re.fullmatch('[a-f0-9]{40}', plan['source_commit'])
            and plan['installation_sha256'] == profile.sha256 and plan['deployment'] == runtime.binding
            and plan['owner'] == owner, 'Alignment authority or source identity differs')
    project = Path(profile.path('project'))
    files, directories = closure(project, source_files(source))
    before, after = (filesystem.validate_manifest(plan[key]) for key in ('before', 'after'))
    require(before['owner'] == after['owner'] == 'whatsapp' and not before['links'] and not after['links']
            and set(after['files']) == set(files) and set(after['directories']) == directories
            and set(before['files']) <= set(files) and set(before['directories']) <= directories,
            'Alignment is outside its independent public source closure')
    for path, raw in files.items():
        require(after['files'][path]['sha256'] == sha(raw), 'Alignment source digest differs')
        if path in before['files']:
            require(all(before['files'][path][k] == after['files'][path][k] for k in ('uid', 'gid', 'mode')),
                    'Alignment cannot change existing file permissions')
    for path in before['directories']:
        require(before['directories'][path] == after['directories'][path],
                'Alignment cannot change existing directory permissions')
    link = plan['venv_before']
    require(isinstance(link, dict) and set(link) == {'target', 'uid', 'gid'}
            and isinstance(link['target'], str) and Path(link['target']).is_absolute(), 'Exact interpreter preimage required')
    return files


def apply(root, source, profile, runtime, plan, *, expected_sha256, owner, fault=None):
    """Durable file preimages, then one pinned interpreter link; no service actions.

    On failure preserve the plan, journal and source bundle. Reconcile the same
    ID after inspecting them; never regenerate a plan from a partially updated
    tree. Old file bytes stay in the neutral engine's quarantine, and the old
    interpreter remains intact at the exact target recorded in this plan.
    """
    require(sha(encoded(plan)) == expected_sha256, 'Alignment plan differs from its approved digest')
    runtime.check_current()
    files = validate(plan, source, profile, runtime, owner)
    for kind in ('files', 'directories'):
        for path, spec in plan['after'][kind].items():
            if path not in plan['before'][kind]:
                require(spec['uid'] == root.uid and spec['gid'] == root.gid
                        and spec['mode'] == (0o644 if kind == 'files' else 0o755),
                        'New administrative files must use the fixed existing protection contract')
    project = Path(profile.path('project'))
    link_path = str(project / '.venv')
    desired = {'target': str(runtime.venv), 'uid': root.uid, 'gid': root.gid}
    require(plan['venv_before']['uid'] == root.uid and plan['venv_before']['gid'] == root.gid,
            'Interpreter link ownership must remain unchanged')
    allowed = sorted(set(files) | set(plan['after']['directories']))
    # Persist the full plan (including the original interpreter link) in the
    # existing administrative state, not beneath the live import tree.
    operation = Path(profile.path('administration_state')) / 'whatsapp/alignments' / plan['id']
    logical_plan = str(operation / 'plan.json')
    private = {'uid': root.uid, 'gid': root.gid, 'mode': 0o700}
    if root.directory(str(operation.parent)) is None:
        root._mkdir(str(operation.parent), private)
    require(root.directory(str(operation.parent)) == private, 'Alignment state protection differs')
    if root.directory(str(operation)) is None:
        require(root.link(link_path) == plan['venv_before'], 'Interpreter changed before alignment')
        root._mkdir(str(operation), private)
    require(root.directory(str(operation)) == private, 'Alignment operation protection differs')
    present = root.snapshot(logical_plan)
    if present is None:
        require(root.link(link_path) == plan['venv_before'], 'Interpreter changed before durable alignment intent')
        save(root, logical_plan, plan)
    else:
        require(present['sha256'] == expected_sha256, 'Alignment operation ID is already bound to another plan')
    require(root.link(link_path) in (plan['venv_before'], desired), 'Administrative interpreter is neither reviewed state')
    receipt = filesystem.reconcile(root, operation_id=plan['id'], before=plan['before'], after=plan['after'],
                                   payloads=files, allowed_paths=allowed, fault=fault)
    runtime.check_current()
    if fault:
        fault('alignment-files-committed', {'operation_id': plan['id']})
    if root.link(link_path) != desired:
        # Root._parent anchors the namespace. The only admitted directory target
        # is the fully sealed runtime already checked under deploy-v1 leases.
        temporary = '.admin-alignment-' + plan['id']
        with root._parent(link_path) as (parent, name):
            try:
                os.symlink(desired['target'], temporary, dir_fd=parent)
            except FileExistsError:
                info = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISLNK(info.st_mode) and info.st_uid == root.uid
                        and os.readlink(temporary, dir_fd=parent) == desired['target'],
                        'Pending interpreter publication differs')
            os.fsync(parent)
            require(root.link(link_path) == plan['venv_before'], 'Interpreter changed before publication')
            runtime.check_current()
            os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
    require(root.link(link_path) == desired, 'Administrative interpreter publication is not verified')
    result = {'format': FORMAT, 'id': plan['id'], 'source_commit': plan['source_commit'],
              'plan_sha256': expected_sha256, 'deployment': runtime.binding, 'phase': 'completed',
              'file_receipt': receipt, 'interpreter': desired, 'original_interpreter': plan['venv_before'],
              'services_changed': False, 'tenant_data_changed': False, 'configuration_changed': False}
    save(root, operation / 'receipt.json', result)
    return result
