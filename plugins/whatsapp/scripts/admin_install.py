#!/usr/bin/env python3
"""Inspect or advance one reviewed WhatsApp administration operation.

This one-shot tool runs from the complete reviewed source checkout. It does
not discover credentials, acquire artifacts from the network, stop BOX or
perform application provisioning. Advance is deliberately one durable phase;
pending work returns immediately and must be observed again on the next call.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

REPOSITORY = Path(__file__).resolve().parents[3]
MAX_OPERATION = 16 * 1024 * 1024
INSTALLER_SOURCES = (
    'plugins/whatsapp/scripts/installation_layout.py', 'plugins/whatsapp/scripts/admin_install.py', 'plugins/whatsapp/scripts/admin_handoff.py',
    'plugins/whatsapp/scripts/admin_host.py', 'host/lifecycle/filesystem.py',
    'host/lifecycle/evidence.py', 'host/installation.py', 'host/lifecycle/services.py',
    'host/lifecycle/service_client.py',
    'host/__init__.py', 'host/lifecycle/__init__.py',
)

filesystem = admin_handoff = admin_host = None


class InstallerError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InstallerError(message)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'Duplicate operation JSON field')
        value[key] = item
    return value


def bootstrap_header(content, expected_sha256):
    require(type(content) is bytes and len(content) <= MAX_OPERATION
            and isinstance(expected_sha256, str) and re.fullmatch('[0-9a-f]{64}', expected_sha256),
            'A bounded operation and exact SHA256 are required')
    require(hashlib.sha256(content).hexdigest() == expected_sha256,
            'Operation differs from its reviewed digest')
    try:
        value = json.loads(content, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as error:
        raise InstallerError('Invalid operation JSON') from error
    require(isinstance(value, dict) and isinstance(value.get('installer_sources'), dict)
            and set(value['installer_sources']) == set(INSTALLER_SOURCES)
            and all(isinstance(item, str) and re.fullmatch('[0-9a-f]{64}', item)
                    for item in value['installer_sources'].values()),
            'Exact installer source closure is required')
    return value


def bootstrap_read(root, logical):
    """Anchored read before importing any operational module."""
    root = Path(root).absolute()
    require(root == root.resolve(strict=True), 'Root must be physical')
    target = Path(logical)
    require(target.is_absolute() and str(target) == logical and '..' not in target.parts
            and logical != '/', 'Operation path must be exact and absolute')
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    authority = os.fstat(descriptor).st_uid
    require(not os.fstat(descriptor).st_mode & 0o022, 'Root is not protected')
    try:
        for part in target.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
            info = os.fstat(descriptor)
            require(info.st_uid == authority and not info.st_mode & 0o022, 'Operation ancestor is not protected')
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(fd, 'rb') as stream:
            initial = os.fstat(stream.fileno())
            require(stat.S_ISREG(initial.st_mode) and initial.st_uid == authority
                    and not initial.st_mode & 0o022 and initial.st_size <= MAX_OPERATION,
                    'Operation must be a protected bounded regular file')
            content = stream.read(MAX_OPERATION + 1)
            final = os.fstat(stream.fileno())
        actual = os.stat(target.name, dir_fd=descriptor, follow_symlinks=False)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(identity(initial) == identity(final) == identity(actual)
                and len(content) <= MAX_OPERATION, 'Operation changed while reading')
        return content
    finally:
        os.close(descriptor)


def load_modules(expected=None, *, root=Path('/'), authority=0):
    global filesystem, admin_handoff, admin_host
    if expected is not None:
        closure = (
            ('host', 'host/__init__.py', True),
            ('host.lifecycle', 'host/lifecycle/__init__.py', True),
            ('host.lifecycle.filesystem', 'host/lifecycle/filesystem.py', False),
            ('host.lifecycle.evidence', 'host/lifecycle/evidence.py', False),
            ('installation_layout','plugins/whatsapp/scripts/installation_layout.py',False),
        ('host.installation','host/installation.py',False),
        ('host.lifecycle.services','host/lifecycle/services.py',False),
            ('admin_handoff', 'plugins/whatsapp/scripts/admin_handoff.py', False),
            ('admin_host', 'plugins/whatsapp/scripts/admin_host.py', False),
        )
        for name, relative, package in closure:
            path = REPOSITORY / relative
            content = path.read_bytes()
            require(hashlib.sha256(content).hexdigest() == expected[relative],
                    'Installer source changed before execution')
            module = types.ModuleType(name)
            module.__file__ = str(path)
            module.__package__ = name if package else name.rpartition('.')[0]
            if package:
                module.__path__ = [str(path.parent)]
            sys.modules[name] = module
            if '.' in name:
                parent, _, child = name.rpartition('.')
                setattr(sys.modules[parent], child, module)
            # Execute exactly the reviewed bytes, ignoring any adjacent pyc.
            exec(compile(content, str(path), 'exec'), module.__dict__)
            if name in ('installation_layout', 'host.installation'):
                module.activate_installation(root=root, trusted_uid=authority)
        filesystem = sys.modules['host.lifecycle.filesystem']
        admin_handoff, admin_host = sys.modules['admin_handoff'], sys.modules['admin_host']
        return
    if filesystem is not None:
        return
    for directory in (REPOSITORY, REPOSITORY / 'plugins/whatsapp/scripts'):
        if str(directory) not in sys.path:
            sys.path.insert(0, str(directory))
    from host.lifecycle import filesystem as fs
    import admin_handoff as handoff
    import admin_host as host
    filesystem, admin_handoff, admin_host = fs, handoff, host


def decode_operation(content, expected_sha256):
    value = bootstrap_header(content, expected_sha256)
    load_modules()
    require(isinstance(value, dict) and set(value) ==
            {'format', 'source_revision', 'installer_sources', 'plan', 'profile', 'payloads'}
            and value['format'] == 'whatsapp-admin-operation-v1'
            and isinstance(value['source_revision'], str)
            and re.fullmatch('[0-9a-f]{40}', value['source_revision']), 'Invalid operation envelope')
    require(isinstance(value['installer_sources'], dict)
            and set(value['installer_sources']) == set(INSTALLER_SOURCES)
            and all(isinstance(item, str) and re.fullmatch('[0-9a-f]{64}', item)
                    for item in value['installer_sources'].values()), 'Exact installer source closure is required')
    require(isinstance(value['payloads'], dict), 'Payloads must be explicit')
    payloads, total = {}, 0
    for action, files in value['payloads'].items():
        require(isinstance(files, dict) and len(files) <= filesystem.MAX_FILES,
                'Invalid bounded payload map')
        payloads[action] = {}
        for path, encoded in files.items():
            require(isinstance(encoded, str), 'Payload is not base64 text')
            try:
                data = base64.b64decode(encoded, validate=True)
            except ValueError as error:
                raise filesystem.LifecycleError('Invalid base64 payload') from error
            total += len(data)
            require(len(data) <= filesystem.MAX_FILE_BYTES and total <= filesystem.MAX_PAYLOAD_BYTES,
                    'Operation payload exceeds its bound')
            payloads[action][path] = data
    plan_digest = admin_handoff.validate_plan(value['plan'], payloads, filesystem)
    require(admin_host.validate_profile(value['profile']) == value['plan']['inventory_digest'],
            'Operation profile differs from the approved plan')
    admin_host.validate_admission(value['profile'], value['plan'])
    return value, payloads, plan_digest


def encode_operation(plan, profile, payloads, *, source_revision, source_root=REPOSITORY):
    """Prepare reviewable bytes locally, without installing or opening a host."""
    root = Path(source_root).absolute()
    sources = {}
    for relative in INSTALLER_SOURCES:
        target = root / relative
        require(target == target.resolve(strict=True), 'Installer source contains a symlink')
        sources[relative] = hashlib.sha256(target.read_bytes()).hexdigest()
    value = {'format': 'whatsapp-admin-operation-v1', 'source_revision': source_revision,
             'installer_sources': sources, 'plan': plan, 'profile': profile,
             'payloads': {action: {path: base64.b64encode(content).decode('ascii')
                                   for path, content in files.items()}
                          for action, files in payloads.items()}}
    content = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    sha256 = hashlib.sha256(content).hexdigest()
    decode_operation(content, sha256)
    return content, sha256


def protect_sources(expected, *, require_root=True):
    """Check this fixed source closure before any host mutation.

    Git revision in the envelope is provenance supplied by the release
    coordinator; the administrator must separately verify it against the
    checked-out source. This function enforces filesystem trust, not Git trust.
    """
    for relative in INSTALLER_SOURCES:
        target = REPOSITORY / relative
        require(target.absolute() == target.resolve(strict=True), 'Installer sources must be physical')
        for path in (target, *target.parents) if require_root else ():
            info = path.lstat()
            require(info.st_uid == 0 and not info.st_mode & 0o022,
                    'Installer source closure must be protected by root')
        require(hashlib.sha256(target.read_bytes()).hexdigest() == expected[relative],
                'Installer source differs from the reviewed operation')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'advance'))
    parser.add_argument('--root', default='/', type=Path,
                        help='Physical filesystem root; advance is only available on the host root')
    parser.add_argument('--operation', required=True,
                        help='Exact absolute path to a root-protected operation JSON, relative to --root')
    parser.add_argument('--sha256', required=True, help='Independently reviewed operation digest')
    args = parser.parse_args(argv)
    try:
        data = bootstrap_read(args.root, args.operation)
        header = bootstrap_header(data, args.sha256)
        if args.action == 'advance':
            require(args.root.absolute() == Path('/') and os.geteuid() == 0,
                    'Host advance requires root; isolated tests use the injectable library')
        protect_sources(header['installer_sources'], require_root=args.action == 'advance')
        load_modules(header['installer_sources'], root=args.root,
                     authority=args.root.stat().st_uid)
        with filesystem.Root(args.root) as root:
            operation, payloads, plan_digest = decode_operation(data, args.sha256)
            if args.action == 'inspect':
                result = {'action': 'inspect', 'operation_sha256': args.sha256,
                          'source_revision_assertion': operation['source_revision'],
                          'plan_digest': plan_digest, 'mode': operation['plan']['mode'],
                          'action_paths': {name: sorted(action['allowed_paths'])
                                           for name, action in operation['plan']['actions'].items()},
                          'mutations': False}
            else:
                provider = admin_host.AdminHost(root, operation['profile'])
                result = admin_handoff.handoff(root, operation['plan'], payloads, provider)
                result.update(action='advance', operation_sha256=args.sha256,
                              plan_digest=plan_digest)
    except (OSError, ValueError, RuntimeError) as error:
        # Never emit source payloads, raw command output or private journals.
        parser.exit(1, 'Administration requires inspection: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))
    return 3 if result.get('pending') else 0


if __name__ == '__main__':
    raise SystemExit(main())
