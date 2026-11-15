#!/usr/bin/env python3
"""Compile, inspect and apply additive instance allocations.

Run operational commands from a complete protected source checkout. Allocation
does not provision accounts, initialize data, call an identity provider or start
services. The original installation and existing tenant records never change.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

REPOSITORY = Path(__file__).resolve().parents[3]
FORMAT = 'whatsapp-instance-expansion-v1'
MAX_BYTES = 1024 * 1024
SOURCES = (
    'plugins/whatsapp/scripts/instance_expansion.py',
    'plugins/whatsapp/scripts/installation_layout.py',
    'plugins/whatsapp/scripts/host_integration.py',
    'plugins/whatsapp/sally_whatsapp/installation.py',
    'plugins/whatsapp/sally_whatsapp/__init__.py',
    'host/__init__.py', 'host/lifecycle/__init__.py', 'host/lifecycle/filesystem.py',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(content):
    return hashlib.sha256(content).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'Duplicate expansion JSON field')
        value[key] = item
    return value


def decode(content):
    require(type(content) is bytes and len(content) <= MAX_BYTES, 'Bounded expansion input required')
    return json.loads(content, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite expansion input')))


def hexid(value, length=64):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{' + str(length) + '}', value) is not None


def layout_module():
    # Pure module, deliberately not active(): recovery must read its exact
    # operation before selecting an installed allocation snapshot.
    name = '_whatsapp_expansion_layout'
    if name not in sys.modules:
        path = Path(__file__).with_name('installation_layout.py')
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
        sys.modules[name] = module
        exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return sys.modules[name]


def filesystem_module():
    if str(REPOSITORY) not in sys.path:
        sys.path.insert(0, str(REPOSITORY))
    from host.lifecycle import filesystem
    return filesystem


def source_hashes(root=REPOSITORY):
    return {name: digest((Path(root) / name).read_bytes()) for name in SOURCES}


def profiles(operation):
    layout = layout_module()
    original = layout.Installation.from_dict(operation['installation'])
    before = original
    if operation['before_roster'] is not None:
        before = before.with_roster(operation['before_roster'])
    additions = operation['additions']
    require(isinstance(additions, dict) and additions
            and not set(additions).intersection(before.accounts()),
            'Expansion must add new instance names only')
    roster = before.roster or {'revision': 0, 'instances': {}}
    after = original.with_roster({
        'format': layout.ROSTER_FORMAT, 'installation_sha256': original.sha256,
        'revision': roster['revision'] + 1, 'previous': before.roster_sha256,
        'instances': {**roster['instances'], **additions},
    })
    return before, after


def validate(operation):
    require(isinstance(operation, dict) and set(operation) == {
        'format', 'id', 'source_revision', 'sources', 'installation', 'before_roster',
        'additions', 'registry_sha256', 'owner',
    } and operation['format'] == FORMAT and hexid(operation['id'], 32)
        and hexid(operation['source_revision'], 40) and hexid(operation['registry_sha256']),
        'Exact expansion operation contract required')
    require(isinstance(operation['sources'], dict) and set(operation['sources']) == set(SOURCES)
            and all(hexid(value) for value in operation['sources'].values()),
            'Complete expansion source closure required')
    before, after = profiles(operation)
    owner = operation['owner']
    require(isinstance(owner, dict) and set(owner) ==
            {'protocol', 'epoch', 'state', 'generation', 'manifest_sha256'}
            and type(owner['protocol']) is int and owner['protocol'] == 1
            and owner['state'] == 'dedicated' and hexid(owner['epoch'], 32)
            and hexid(owner['manifest_sha256'])
            and owner['generation'] == before.mapped(
                '/usr/local/lib/develative-deploy/whatsapp-generations/') + owner['manifest_sha256'],
            'Exact dedicated administrative owner required')
    return before, after


def validate_registry(content, profile):
    value = decode(content)
    require(isinstance(value, dict) and set(value) == {'format', 'instances'}
            and type(value['format']) is int and value['format'] == 1
            and isinstance(value['instances'], dict) and value['instances'],
            'An existing, complete tenant registry is required')
    for slug, row in value['instances'].items():
        require(isinstance(row, dict) and set(row) == {'spec', 'phase', 'enabled'}
                and type(row['enabled']) is bool
                and row['phase'] in ('existing', 'ready', 'prepared', 'preparing')
                and isinstance(row['spec'], dict) and row['spec'].get('slug') == slug
                and row['spec'].get('installation') == profile.as_dict()
                and row['spec'].get('bridge_port') == profile.instance_ports(slug)['bridge']
                and row['spec'].get('auth_mode') == 'external-oidc',
                'Existing tenant identity differs from the pinned installation')
    return value


def compile_operation(profile, additions, *, registry_bytes, owner, operation_id,
                      source_revision, source_root=REPOSITORY):
    """Pure compilation using explicit public profile and private registry bytes."""
    validate_registry(registry_bytes, profile)
    operation = {'format': FORMAT, 'id': operation_id, 'source_revision': source_revision,
                 'sources': source_hashes(source_root), 'installation': profile.as_dict(),
                 'before_roster': profile.roster, 'additions': additions,
                 'registry_sha256': digest(registry_bytes), 'owner': owner}
    validate(operation)
    content = encoded(operation)
    require(len(content) <= MAX_BYTES, 'Expansion operation exceeds its bound')
    return content


def step_id(operation, name):
    return digest((operation['id'] + ':' + name).encode())[:32]


def _file(content, root, mode=0o644):
    return {'sha256': digest(content), 'mode': mode, 'uid': root.uid, 'gid': root.gid, 'retention': 'managed'}


def _manifest(files=None, directories=None):
    return {'format': 1, 'owner': 'whatsapp', 'files': files or {}, 'directories': directories or {}}


def _journal_path(operation, step):
    return '/var/lib/develative-host-lifecycle/whatsapp/operations/' + step_id(operation, step) + '/journal.json'


def _exists(root, path):
    try:
        with root._parent(path) as (parent, name):
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _unused(root, profile, additions):
    for slug in additions:
        paths = list(profile.instance_paths(slug).values())
        unit = profile.service(slug) + '.service'
        paths += [profile.path('project') + '/private/tenants/' + slug,
                  '/etc/systemd/system/' + unit,
                  '/etc/systemd/system/' + unit + '.d',
                  '/etc/systemd/system/multi-user.target.wants/' + unit]
        require(not any(_exists(root, path) for path in paths),
                'New instance artifacts already exist; reconcile instead of reallocating')


def _owner(root, operation, profile):
    path = profile.mapped('/etc/develative-deploy/recovery-owners/whatsapp.json')
    require(decode(root.read_bytes(path)) == operation['owner'],
            'Administrative owner changed; compile a current operation')
    # The ordinary runtime admission verifies the entire installed generation.
    # In addition, allocation requires the new reader at every administrative
    # bootstrap, generation and runtime import location, not merely a new CLI.
    layout_sha = operation['sources']['plugins/whatsapp/scripts/installation_layout.py']
    for path in (
        operation['owner']['generation'] + '/installation_layout.py',
        profile.mapped('/usr/local/lib/develative-deploy/whatsapp-bootstrap/installation_layout.py'),
        profile.path('project') + '/scripts/installation_layout.py',
        profile.path('project') + '/sally_whatsapp/installation.py',
    ):
        metadata = root.snapshot(path)
        require(metadata is not None and metadata['uid'] == root.uid and not metadata['mode'] & 0o022
                and metadata['sha256'] == layout_sha,
                'Upgrade all allocation readers through the ordinary reviewed administration first')


def _stage_inputs(operation, after):
    configuration = after.path('configuration') + '/administration'
    state = after.path('administration_state') + '/whatsapp/instance-expansions'
    operation_path = state + '/' + operation['id'] + '.json'
    snapshot_path = after.roster_snapshot(after.roster_sha256)
    contents = {operation_path: encoded(operation), snapshot_path: after._roster}
    directories = {
        configuration: 0o755, configuration + '/instance-rosters': 0o755,
        after.path('administration_state') + '/whatsapp': 0o700, state: 0o700,
    }
    return operation_path, contents, directories


def _stage(root, operation, after, fault):
    fs = filesystem_module()
    operation_path, contents, directories = _stage_inputs(operation, after)
    files = {path: _file(raw, root, 0o600 if path == operation_path else 0o644)
             for path, raw in contents.items()}
    allowed = set(files) | set(directories)
    if _exists(root, _journal_path(operation, 'stage')):
        journal = fs.inspect_operation(root, owner='whatsapp', operation_id=step_id(operation, 'stage'),
                                       allowed_paths=allowed)
        require(journal['after']['files'] == files and not journal['after']['links']
                and set(journal['after']['directories']) == set(directories)
                and not journal['before']['links']
                and set(journal['before']['files']) <= set(files)
                and all(item == files[path] for path, item in journal['before']['files'].items()),
                'Staged expansion differs from the exact operation')
        for path, item in journal['after']['directories'].items():
            require(item['uid'] == root.uid and item['gid'] == root.gid and not item['mode'] & 0o022
                    and item['retention'] == 'retain'
                    and (path in journal['before']['directories'] or item['mode'] == directories[path]),
                    'Staged expansion directory policy differs')
        return fs.resume(root, owner='whatsapp', operation_id=step_id(operation, 'stage'),
                         allowed_paths=allowed, payloads=contents, fault=fault)
    before_files, before_dirs, after_dirs = {}, {}, {}
    for path, item in files.items():
        actual = root.snapshot(path)
        require(actual is None or actual == {key: value for key, value in item.items() if key != 'retention'},
                'Immutable expansion artifact already differs')
        if actual is not None:
            before_files[path] = item
    for path, mode in directories.items():
        actual = root.directory(path)
        require(actual is None or actual['uid'] == root.uid and actual['gid'] == root.gid
                and not actual['mode'] & 0o022, 'Expansion directory is not protected')
        after_dirs[path] = {**(actual or {'mode': mode, 'uid': root.uid, 'gid': root.gid}), 'retention': 'retain'}
        if actual is not None:
            before_dirs[path] = after_dirs[path]
    return fs.reconcile(root, operation_id=step_id(operation, 'stage'),
                        before=_manifest(before_files, before_dirs), after=_manifest(files, after_dirs),
                        payloads=contents, allowed_paths=allowed, fault=fault)


def _publish(root, operation, before, after, *, reverse=False, fault=None):
    fs, layout = filesystem_module(), layout_module()
    path = before.roster_pointer()
    old = None if before.roster is None else layout.encoded(layout.roster_pointer_record(before))
    new = layout.encoded(layout.roster_pointer_record(after))
    first, last = (new, old) if reverse else (old, new)
    before_manifest = _manifest({path: _file(first, root)} if first is not None else {})
    after_manifest = _manifest({path: _file(last, root)} if last is not None else {})
    return fs.reconcile(root, operation_id=step_id(operation, 'rollback' if reverse else 'publish'),
                        before=before_manifest, after=after_manifest,
                        payloads={path: last} if last is not None else {}, allowed_paths={path},
                        inline_payloads={path} if last is not None else (), fault=fault)


def _cancel_unpublished(root, operation, before, *, fault=None):
    """Persist terminal cancellation without briefly making new allocations live."""
    fs = filesystem_module()
    path = before.roster_pointer()
    content = None if before.roster is None else layout_module().encoded(
        layout_module().roster_pointer_record(before))
    state = before.path('administration_state') + '/whatsapp'
    operation_path = state + '/instance-expansions/' + operation['id'] + '.json'
    raw = encoded(operation)
    files = {path: _file(content, root)} if content is not None else {}
    files[operation_path] = _file(raw, root, 0o600)
    directories = {state: {'mode': 0o700, 'uid': root.uid, 'gid': root.gid, 'retention': 'retain'},
                   state + '/instance-expansions': {
                       'mode': 0o700, 'uid': root.uid, 'gid': root.gid, 'retention': 'retain'}}
    allowed = {path, operation_path, *directories}
    if _exists(root, _journal_path(operation, 'cancel')):
        journal = fs.inspect_operation(root, owner='whatsapp', operation_id=step_id(operation, 'cancel'),
                                       allowed_paths=allowed)
        require(journal['after']['files'] == files and journal['after']['directories'] == directories,
                'Cancellation differs from the exact operation')
        return fs.resume(root, owner='whatsapp', operation_id=step_id(operation, 'cancel'),
                         allowed_paths=allowed, payloads={operation_path: raw}, fault=fault)
    before_files = {path: _file(content, root)} if content is not None else {}
    actual = root.snapshot(operation_path)
    require(actual is None or actual == {key: value for key, value in files[operation_path].items()
                                        if key != 'retention'}, 'Saved operation differs')
    if actual is not None:
        before_files[operation_path] = files[operation_path]
    before_dirs = {}
    for directory, expected in directories.items():
        actual = root.directory(directory)
        require(actual is None or actual == {key: value for key, value in expected.items() if key != 'retention'},
                'Cancellation state directory differs')
        if actual is not None:
            before_dirs[directory] = expected
    return fs.reconcile(root, operation_id=step_id(operation, 'cancel'),
        before=_manifest(before_files, before_dirs), after=_manifest(files, directories),
        payloads={operation_path: raw}, allowed_paths=allowed,
        inline_payloads={operation_path}, fault=fault)


def operation_status(root, operation):
    """Read persistent allocation progress; never resume or infer live readiness.

    The caller must provide its admitted protected Root. This is a point-in-time
    administrative observation, not authorization to execute an operation.
    """
    before, after = validate(operation)
    layout, fs = layout_module(), filesystem_module()
    layout.preflight_roots(before, root=root.base, trusted_uid=root.uid)
    current = layout.read_installation(root=root.base, trusted_uid=root.uid)
    require(current.sha256 == before.sha256, 'Operation belongs to another installation')
    operation_path, contents, directories = _stage_inputs(operation, after)
    if _exists(root, operation_path):
        metadata = root.snapshot(operation_path)
        require(metadata is not None and metadata['uid'] == root.uid and not metadata['mode'] & 0o077,
                'Saved operation is not administratively protected')
        require(root.read_bytes(operation_path) == encoded(operation), 'Saved operation differs')
    steps = {}
    for step in ('stage', 'publish', 'rollback', 'cancel'):
        if _exists(root, _journal_path(operation, step)):
            allowed = set(contents) | set(directories) if step == 'stage' else {before.roster_pointer()}
            if step == 'cancel':
                state = before.path('administration_state') + '/whatsapp'
                allowed |= {operation_path, state, state + '/instance-expansions'}
            journal = fs.inspect_operation(root, owner='whatsapp', operation_id=step_id(operation, step),
                                           allowed_paths=allowed)
            steps[step] = journal['phase']
    if current.selection not in (before.selection, after.selection):
        status = 'superseded'
    elif 'cancel' in steps or 'rollback' in steps:
        final = steps.get('cancel', steps.get('rollback')) == 'committed'
        status = 'rolled_back' if final and current.selection == before.selection else 'rolling_back'
    elif current.selection == after.selection:
        require('publish' in steps, 'This allocation was published by another operation')
        status = 'allocated' if steps['publish'] == 'committed' else 'allocating'
    else:
        status = 'preparing' if steps else 'not_started'
    registry_path = before.path('project') + '/private/tenants.json'
    metadata = root.snapshot(registry_path)
    require(metadata is not None and metadata['uid'] == root.uid and not metadata['mode'] & 0o022,
            'Tenant registry must remain administratively protected')
    registry = validate_registry(root.read_bytes(registry_path), current)
    instances = {slug: {'registered': slug in registry['instances'],
                        'phase': registry['instances'].get(slug, {}).get('phase')}
                 for slug in sorted(operation['additions'])}
    require(layout.read_installation(root=root.base, trusted_uid=root.uid).selection == current.selection,
            'Allocation changed during observation; read status again')
    return {'format': FORMAT, 'operation_id': operation['id'], 'status': status, 'steps': steps,
            'installation_sha256': before.sha256, 'roster_sha256': current.roster_sha256,
            'instances': instances, 'runtime_verified': False,
            'observed_at': datetime.now(timezone.utc).isoformat(), 'source': 'local_administrative_journals'}


def advance(root, operation, *, admission, resource_check, rollback=False, fault=None):
    """Apply on a protected Root; test seams are never exposed as CLI switches."""
    fs, layout = filesystem_module(), layout_module()
    before, after = validate(operation)
    require(callable(admission) and callable(resource_check), 'Explicit owner admission and resource checks required')
    with admission(operation):
        layout.preflight_roots(before, root=root.base, trusted_uid=root.uid)
        _owner(root, operation, before)
        current = layout.read_installation(root=root.base, trusted_uid=root.uid)
        require(current.selection in (before.selection, after.selection),
                'Allocation pointer changed; preserve the pending operation')
        if current.selection == after.selection:
            require(_exists(root, _journal_path(operation, 'publish')),
                    'This allocation was published by another operation')
        inverse = _exists(root, _journal_path(operation, 'rollback'))
        cancelled = _exists(root, _journal_path(operation, 'cancel'))
        unpublished_cancellation = rollback and not _exists(root, _journal_path(operation, 'publish'))
        if (inverse or cancelled) and not rollback:
            raise ValueError('This expansion was rolled back or has a pending rollback')
        registry_path = before.path('project') + '/private/tenants.json'
        if rollback or current.selection == before.selection and not inverse:
            metadata = root.snapshot(registry_path)
            require(metadata is not None and metadata['uid'] == root.uid and not metadata['mode'] & 0o022,
                    'Tenant registry must remain administratively protected')
            registry = root.read_bytes(registry_path)
            require(digest(registry) == operation['registry_sha256'],
                    'Tenant registry changed; rollback/reallocation is no longer safe')
            validate_registry(registry, before)
            # An unpublished cancellation removes no runtime resources and
            # cannot claim ports/accounts acquired later by someone else.
            # Published reversal keeps the original ownership/use guards.
            if not unpublished_cancellation:
                _unused(root, after, operation['additions'])
                resource_check(operation, after)
        if cancelled or unpublished_cancellation:
            require(current.selection == before.selection, 'Cannot cancel a published allocation')
            result = _cancel_unpublished(root, operation, before, fault=fault)
        elif inverse:
            result = _publish(root, operation, before, after, reverse=True, fault=fault)
        else:
            _stage(root, operation, after, fault)
            _publish(root, operation, before, after, fault=fault)
            result = (_publish(root, operation, before, after, reverse=True, fault=fault)
                      if rollback else {'phase': 'committed'})
        expected = before if rollback else after
        require(layout.read_installation(root=root.base, trusted_uid=root.uid).selection == expected.selection,
                'Published allocation was not verified')
        return {'format': FORMAT, 'operation_id': operation['id'], 'phase': result['phase'],
                'status': 'rolled_back' if rollback else 'allocated',
                'installation_sha256': before.sha256, 'roster_sha256': expected.roster_sha256,
                'instances': sorted(operation['additions']), 'provisioned': False, 'live_enabled': False}


def protect_sources(operation):
    for name, expected in operation['sources'].items():
        path = REPOSITORY / name
        require(path == path.resolve(strict=True), 'Expansion source path must be physical')
        for item in (path, *path.parents):
            info = item.lstat()
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'Expansion source closure must be root protected')
        require(digest(path.read_bytes()) == expected, 'Expansion source differs from its approved closure')


@contextmanager
def installed_admission(operation):
    scripts = REPOSITORY / 'plugins/whatsapp/scripts'
    package = REPOSITORY / 'plugins/whatsapp'
    for path in (package, scripts):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    import host_integration
    administration = host_integration.load_administration()
    with host_integration.runtime_admission(operation['installation']['paths']['project'],
                                            administration=administration):
        generation = administration.load_generation(states=('dedicated',))
        require({'protocol': 1, 'epoch': generation.epoch, 'state': generation.state,
                 'generation': str(generation.path), 'manifest_sha256': generation.manifest_sha256} == operation['owner'],
                'Owner changed after acquiring the publication and tenant leases')
        yield


def installed_resources(operation, profile):
    import pwd
    import grp
    import socket
    for slug, item in operation['additions'].items():
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup(item['account'])
            except KeyError:
                pass
            else:
                raise ValueError('New service account or group already exists')
        for port in (item['bridge'], item['gateway']):
            with socket.socket() as probe:
                try:
                    probe.bind(('127.0.0.1', port))
                except OSError:
                    raise ValueError('New loopback port is already in use') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    compiler = commands.add_parser('compile')
    compiler.add_argument('--inputs', type=Path, required=True)
    compiler.add_argument('--inputs-sha256', required=True)
    compiler.add_argument('--output', type=Path, required=True)
    for name in ('inspect', 'status', 'apply', 'rollback'):
        command = commands.add_parser(name)
        command.add_argument('--operation', type=Path, required=True)
        command.add_argument('--sha256', required=True)
    args = parser.parse_args(argv)
    if args.command == 'compile':
        raw = args.inputs.read_bytes()
        require(hexid(args.inputs_sha256) and digest(raw) == args.inputs_sha256, 'Compiler input digest differs')
        value = decode(raw)
        require(isinstance(value, dict) and set(value) == {
            'installation', 'before_roster', 'additions', 'registry_base64', 'owner', 'id', 'source_revision',
        }, 'Exact offline compiler inputs required')
        profile = layout_module().Installation.from_dict(value['installation'])
        if value['before_roster'] is not None:
            profile = profile.with_roster(value['before_roster'])
        registry = base64.b64decode(value['registry_base64'], validate=True)
        content = compile_operation(profile, value['additions'], registry_bytes=registry, owner=value['owner'],
                                    operation_id=value['id'], source_revision=value['source_revision'])
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({'operation': str(args.output), 'sha256': digest(content), 'host_changed': False}))
        return
    raw = args.operation.read_bytes() if args.command == 'inspect' else layout_module()._read_protected(args.operation)
    require(hexid(args.sha256) and digest(raw) == args.sha256, 'Operation digest differs')
    operation = decode(raw)
    before, after = validate(operation)
    if args.command == 'inspect':
        print(json.dumps({'installation_sha256': before.sha256, 'before_roster_sha256': before.roster_sha256,
                          'after_roster_sha256': after.roster_sha256, 'instances': sorted(operation['additions']),
                          'host_changed': False, 'provisioned': False}))
        return
    require(os.geteuid() == 0, 'Run as the authorized host administrator')
    protect_sources(operation)
    with filesystem_module().Root('/') as root:
        if args.command == 'status':
            result = operation_status(root, operation)
        else:
            result = advance(root, operation, admission=installed_admission,
                             resource_check=installed_resources, rollback=args.command == 'rollback')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError):
        raise SystemExit('Instance expansion stopped; preserve the operation and inspect its private journal') from None
