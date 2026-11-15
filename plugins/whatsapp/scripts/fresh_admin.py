#!/usr/bin/env python3
"""Compile one explicitly attested, new WhatsApp administration installation.

This is a local compiler, never a discovery or installation command. It accepts
no existing artifacts, other product's invokers, upgrades, or removals. The
operator supplies a protected, digest-pinned attestation; an empty directory
does not establish that no invoker exists. The normal installer re-observes
the named scope and metadata, and its filesystem engine rejects unexpected
targets before publishing payloads. Control intents can already exist then:
preserve them for inspection, never silently adopt or roll back a collision.
"""
import sys as _installation_sys
from pathlib import Path as _InstallationPath
import types as _installation_types
if 'installation_layout' not in _installation_sys.modules:
    _installation_source=_InstallationPath(__file__).with_name('installation_layout.py')
    _installation_module=_installation_types.ModuleType('installation_layout')
    _installation_module.__file__=str(_installation_source)
    _installation_sys.modules['installation_layout']=_installation_module
    try:
        exec(compile(_installation_source.read_bytes(),str(_installation_source),'exec'),_installation_module.__dict__)
    except BaseException:
        _installation_sys.modules.pop('installation_layout',None)
        raise
if getattr(_installation_sys.modules['installation_layout'], 'FORMAT', None) != 'whatsapp-installation-v1':
    raise ImportError('The whatsapp entry point cannot reuse another product installation layout')
from installation_layout import active as installation_profile, mapped as installation_path
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import admin_manifest
import admin_install

REPOSITORY = SCRIPTS.parents[2]
from host.lifecycle import evidence

FORMAT = 'whatsapp-fresh-administration-inputs-v1'
STATE = installation_path('/var/lib/develative-deploy/whatsapp')
ATTESTATIONS = installation_path('/etc/develative-deploy/fresh-whatsapp')
PRIVATE = installation_path('/srv/openai-codex/projects/whatsapp-personal/private')
RECOVERY_CGROUP = installation_path('/system.slice/develative-whatsapp-recovery.service')
MAX_INPUT = 128 * 1024


class FreshError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise FreshError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def digest(content):
    return hashlib.sha256(content).hexdigest()


def hex_value(value, length):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate fresh input field')
        result[key] = value
    return result


def prerequisite_paths(compiled):
    """Exact existing parents; app-specific artifact directories stay new."""
    declared = set(compiled['manifest']['directories'])
    targets = set(compiled['manifest']['files']) | declared | {PRIVATE, ATTESTATIONS}
    result = {PRIVATE, ATTESTATIONS, '/etc/systemd/system', installation_path('/var/lib/develative-deploy')}
    for target in targets:
        for parent in PurePosixPath(target).parents:
            path = str(parent)
            if path != '/' and path not in declared:
                result.add(path)
    # The root of the new generation is managed by the bundle, not adopted.
    return sorted(result)


def input_template(compiled):
    """Incomplete operator input: no assertion of absence or completeness."""
    return {'format': FORMAT, 'mode': 'fresh', 'operation_id': None, 'epoch': None,
        'cgroups': None, 'directory_modes': {path: None for path in prerequisite_paths(compiled)},
        'attestation': {'format': 2, 'complete': False, 'invokers': [],
            'manual_policy': {'operation_id': None, 'unregistered_root_commands': None}}}


def compile_fresh(bundle, *, source_revision, metadata_sha256, input_bytes,
                  inputs_sha256, uid=0, gid=0, source_root=REPOSITORY):
    """Return operation + attestation bytes without consulting a target host.

    uid/gid are fixture seams; the CLI always compiles administrative root:root.
    Existing infrastructure directory modes are operator observations, not
    chmod instructions. Every artifact path must be absent on first install.
    """
    require(type(input_bytes) is bytes and len(input_bytes) <= MAX_INPUT
            and hex_value(inputs_sha256, 64) and digest(input_bytes) == inputs_sha256,
            'Fresh inputs differ from their bounded reviewed digest')
    require(hex_value(metadata_sha256, 64), 'An explicit bundle metadata digest is required')
    try:
        inputs = json.loads(input_bytes, object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise FreshError('Invalid fresh input JSON') from error
    require(isinstance(inputs, dict) and set(inputs) == {
        'format', 'mode', 'operation_id', 'epoch', 'cgroups', 'directory_modes', 'attestation'}
        and inputs['format'] == FORMAT and inputs['mode'] == 'fresh',
        'Only the exact fresh administration input contract is supported')
    operation_id, epoch = inputs['operation_id'], inputs['epoch']
    require(hex_value(operation_id, 32) and hex_value(epoch, 32) and operation_id != epoch,
            'Distinct explicit operation and owner epoch identities are required')
    require(inputs['cgroups'] == [RECOVERY_CGROUP],
            'Fresh profile requires the explicitly selected standard WhatsApp recovery cgroup')
    attestation = inputs['attestation']
    require(isinstance(attestation, dict) and set(attestation) == {
        'format', 'complete', 'invokers', 'manual_policy'}
        and type(attestation['format']) is int and attestation['format'] == 2
        and attestation['complete'] is True and attestation['invokers'] == []
        and attestation['manual_policy'] == {'operation_id': operation_id,
            'unregistered_root_commands': 'frozen-for-operation'},
        'Explicit complete, operation-bound absence of existing invokers is required')
    compiled = admin_manifest.load_bundle(bundle, source_revision, uid=uid, gid=gid,
        expected_metadata_sha256=metadata_sha256)
    modes = inputs['directory_modes']
    require(isinstance(modes, dict) and set(modes) == set(prerequisite_paths(compiled)),
            'Exact existing infrastructure directory observations are required')
    require(all(isinstance(value, str) and re.fullmatch('0[0-7]{3}', value)
                and not int(value, 8) & 0o022 and int(value, 8) & 0o700 == 0o700
                for value in modes.values()), 'Directory modes must be protected and traversable by the administrator')
    require(modes['/etc/systemd/system'] == '0755',
            'The supported systemd directory must already match bundle metadata')
    directories = {path: {'mode': int(mode, 8), 'uid': uid, 'gid': gid, 'retention': 'retain'}
                   for path, mode in modes.items()}
    previous = admin_manifest.empty_manifest()
    previous['directories']['/etc/systemd/system'] = directories['/etc/systemd/system']
    prepared = admin_manifest.prepare_action(compiled, previous,
        adopted_sha256=admin_manifest.manifest_digest(previous))
    attestation_bytes = encoded(attestation)
    attestation_path = ATTESTATIONS + '/' + operation_id + '.json'
    inventory_manifest = admin_manifest.empty_manifest()
    inventory_manifest['directories'] = directories
    inventory_manifest['files'][attestation_path] = {'sha256': digest(attestation_bytes),
        'mode': 0o600, 'uid': uid, 'gid': gid, 'retention': 'retain'}
    inventory = {'scope': {'cgroups': inputs['cgroups'], 'script_roots': [], 'script_paths': []},
                 'manifest': inventory_manifest, 'units': {}}
    generation = compiled['generation']
    profile = {'format': 'whatsapp-host-inventory-v1', 'attestation': {
        'path': attestation_path, 'sha256': digest(attestation_bytes)}, 'retirement_attestation': None,
        'stages': {'inventory': inventory, 'installed': inventory},
        'final_manifest': prepared['active_manifest'], 'retained_manifest': prepared['retained_manifest'],
        'invokers': [], 'generation_id': generation['manifest_sha256']}
    control = {installation_path('/etc/develative-deploy/recovery-owners'): 0o755,
               STATE: 0o700, STATE + '/handoff': 0o700}
    plan = {'format': 'whatsapp-admin-handoff-v1', 'id': operation_id, 'mode': 'fresh',
        'inventory_digest': evidence.digest(profile),
        'evidence_digests': {name: evidence.digest_inventory(item['scope'], item['manifest'], item['units'])
                             for name, item in profile['stages'].items()},
        'owner': {'protocol': 1, 'epoch': epoch, 'state': 'dedicated',
                  'generation': generation['destination'], 'manifest_sha256': generation['manifest_sha256']},
        'previous_owner': None, 'owner_metadata': {'mode': 0o600, 'uid': uid, 'gid': gid},
        'journal': {'path': STATE + '/handoff/' + operation_id + '.json', 'mode': 0o600, 'uid': uid, 'gid': gid},
        'control_directories': {path: {'mode': mode, 'uid': uid, 'gid': gid, 'retention': 'retain'}
                                for path, mode in control.items()},
        'actions': {'install': prepared['action']}}
    operation, operation_sha = admin_install.encode_operation(plan, profile,
        {'install': prepared['payloads']}, source_revision=source_revision, source_root=source_root)
    receipt = {'format': 'whatsapp-fresh-administration-compilation-v1',
        'source_revision_assertion': source_revision, 'inputs_sha256': inputs_sha256,
        'bundle_metadata_sha256': metadata_sha256, 'operation_sha256': operation_sha,
        'attestation': profile['attestation'], 'required_existing_directories': directories,
        'required_absent_artifacts': sorted(compiled['manifest']['files']),
        'host_observed': False, 'installed': False, 'owner_written': False}
    return {'operation.json': operation, 'attestation.json': attestation_bytes,
            'compilation.json': encoded(receipt)}


def read_protected(path, *, max_bytes=MAX_INPUT):
    require(type(max_bytes) is int and 0 < max_bytes <= admin_install.MAX_OPERATION,
            'An explicit bounded compiler input size is required')
    path = Path(path).absolute()
    require(path == path.resolve(strict=True), 'Input must have a physical path')
    # This is local preparation, possibly as a nonroot reviewer. The installer
    # separately requires root ownership of the captured operation and sources.
    for parent in (path, *path.parents):
        info = parent.lstat()
        require(not info.st_mode & 0o022 and (parent != path or info.st_uid == os.geteuid()),
                'Compiler input and ancestors must be administratively protected')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= max_bytes, 'Input must be a bounded regular file')
        content = stream.read(max_bytes + 1)
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    require(len(content) <= max_bytes and identity(before) == identity(after) == identity(path.lstat()),
            'Compiler input changed while reading')
    return content


def write_output(path, files):
    path = Path(path).absolute()
    require(path.parent == path.parent.resolve(strict=True), 'Output parent must be physical')
    require(not path.exists() and not path.is_symlink(), 'Output must be a new directory')
    path.mkdir(mode=0o700)
    for name, content in files.items():
        fd = os.open(path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--bundle-sha256', required=True, help='SHA256 of bundle.json, not a ZIP')
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--input-template', action='store_true', help='Print incomplete input; no host observation')
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--inputs-sha256')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        require(hex_value(args.bundle_sha256, 64), 'An explicit bundle metadata digest is required')
        if args.input_template:
            require(args.inputs is None and args.inputs_sha256 is None and args.output is None,
                    'Template output cannot be combined with operation inputs')
            compiled = admin_manifest.load_bundle(args.bundle, args.source_revision,
                expected_metadata_sha256=args.bundle_sha256)
            print(encoded(input_template(compiled)).decode(), end='')
            return 0
        require(args.inputs is not None and args.inputs_sha256 is not None and args.output is not None,
                'Operation preparation requires inputs, their digest, and a new output directory')
        files = compile_fresh(args.bundle, source_revision=args.source_revision,
            metadata_sha256=args.bundle_sha256, input_bytes=read_protected(args.inputs),
            inputs_sha256=args.inputs_sha256)
        write_output(args.output, files)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, 'Fresh preparation requires inspection: ' + str(error) + '\n')
    print(json.dumps(json.loads(files['compilation.json']), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
