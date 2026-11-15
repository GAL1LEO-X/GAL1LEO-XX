#!/usr/bin/env python3
"""Receipt-bound recovery for the fresh installation blocked on systemd 257.

The original operation, source closure and handoff engine remain immutable.
Only the dedicated recovery reader is adapted. No network or source discovery.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

ORIGINAL_REVISION = '777201995a586f008d933db7d57e84838877dec4'
FORMAT = 'whatsapp-recovery-compat-v1'
REPOSITORY = Path(__file__).resolve().parents[3]
COMPAT_SOURCES = ('plugins/whatsapp/scripts/admin_recovery_compat.py', 'host/lifecycle/services.py')
# SHA256 of the complete installer closure at ORIGINAL_REVISION. This adapter
# does not accept a different closure merely because an envelope asserts that revision.
ORIGINAL_DIGESTS = {
    'plugins/whatsapp/scripts/installation_layout.py': '3caf30a82271742a8ebd1943f77371a0ac45c204986a0494235c1368a93c42d1',
    'plugins/whatsapp/scripts/admin_install.py': '72dab51c0f3cea301cc4553c896f0e951295b203a90b679c6d95834052fca0ff',
    'plugins/whatsapp/scripts/admin_handoff.py': '48bbd43d5e73825b56ec54973983c22bbb69192da8e1cf9ae292744752b87c87',
    'plugins/whatsapp/scripts/admin_host.py': '5812440c46b614eda374f6a886d3a4d5c984446c0c80686cad138e7c2c1826f6',
    'host/lifecycle/filesystem.py': '1200d60d254abbb2a395a713ad9a61f23f4b45c1b422ef4c123f0e02b4014ed9',
    'host/lifecycle/evidence.py': '67fe733c10fa2e9b2a709a8a61f8304dd2d088c2cf39bf761e931b81069ddc95',
    'host/installation.py': '3caf30a82271742a8ebd1943f77371a0ac45c204986a0494235c1368a93c42d1',
    'host/lifecycle/services.py': '6bbf2dcbd373d0f538af39d04a257579afa8ee02a45b59a7e54e4b7529ac2f5c',
    'host/lifecycle/service_client.py': '8128560b3b59e9fb85e23fda99bf38854292ca418b0555be35267711ab050e2d',
    'host/__init__.py': '0a8cff692058ff4db443c98d59d453d05473dd9a51956419cd1f4adff31ff457',
    'host/lifecycle/__init__.py': '21688b59660c8db9c5263a89b3897e8c8a14b469080659943d700cf56f33a439',
}
ORIGINAL_SOURCES = tuple(ORIGINAL_DIGESTS)
MAX_BYTES = 16 * 1024 * 1024
TAIL = {'installed': 'recovery_armed', 'recovery_armed': 'owner_dedicated',
        'owner_dedicated': 'verified', 'verified': None}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'Duplicate compatibility field')
        value[key] = item
    return value


def decode(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, 'Invalid bounded compatibility input')
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))


def protected_read(anchor, logical):
    """Read below a physical trusted anchor before importing operational code."""
    anchor = Path(anchor).absolute()
    require(anchor == anchor.resolve(strict=True), 'Source or host root must be physical')
    path = Path(logical)
    require(path.is_absolute() and str(path) == logical and '..' not in path.parts and logical != '/',
            'An exact absolute path is required')
    authority = anchor.stat().st_uid
    require(not anchor.stat().st_mode & 0o022, 'Anchor is not protected')
    fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            require(info.st_uid == authority and not info.st_mode & 0o022, 'Unprotected ancestor')
        child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(child, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == authority
                    and not before.st_mode & 0o022 and before.st_size <= MAX_BYTES,
                    'Unprotected or oversized input')
            raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
        current = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(identity(before) == identity(after) == identity(current) and len(raw) <= MAX_BYTES,
                'Input changed while reading')
        return raw
    finally:
        os.close(fd)


def source_bytes(directory, relative, *, live=False):
    directory = Path(directory).absolute()
    if live:
        # Live entrypoints cannot trust a root-owned checkout below a writable parent.
        for path in (directory, *directory.parents):
            info = path.lstat()
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'Live source ancestor is not protected')
    return protected_read(directory, '/' + relative)


def load_context(root_path, operation_raw, operation_sha, original_root, receipt=None, *, live=False):
    require(re.fullmatch('[0-9a-f]{64}', operation_sha or '') and digest(operation_raw) == operation_sha,
            'Original operation digest differs')
    header = decode(operation_raw)
    require(isinstance(header, dict) and header.get('source_revision') == ORIGINAL_REVISION
            and isinstance(header.get('installer_sources'), dict)
            and header['installer_sources'] == ORIGINAL_DIGESTS,
            'Only the original reviewed installation source closure is supported')
    original = {name: source_bytes(original_root, name, live=live) for name in ORIGINAL_SOURCES}
    require(all(digest(raw) == header['installer_sources'][name] for name, raw in original.items()),
            'Original installer source differs from the operation')
    correction = {name: source_bytes(REPOSITORY, name, live=live) for name in COMPAT_SOURCES}
    correction_hashes = {name: digest(raw) for name, raw in correction.items()}
    if receipt is not None:
        require(isinstance(receipt, dict) and receipt.get('operation_sha256') == operation_sha
                and receipt.get('installer_sources') == header['installer_sources']
                and receipt.get('compat_sources') == correction_hashes,
                'Compatibility receipt does not bind these artifacts')
    # Execute the original loader only after the complete original closure and
    # the separately approved correction closure have been checked.
    installer = types.ModuleType('compat_original_installer')
    installer.__file__ = str(Path(original_root).absolute() / 'plugins/whatsapp/scripts/admin_install.py')
    exec(compile(original['plugins/whatsapp/scripts/admin_install.py'], installer.__file__, 'exec'), installer.__dict__)
    installer.load_modules(header['installer_sources'], root=Path(root_path), authority=Path(root_path).stat().st_uid)
    operation, payloads, plan_sha = installer.decode_operation(operation_raw, operation_sha)
    require(operation['plan']['mode'] == 'fresh', 'Compatibility is limited to this fresh installation')
    services = installer.admin_host.services
    corrected = types.ModuleType('host.lifecycle.compat_recovery_reader')
    corrected.__file__ = str(REPOSITORY / 'host/lifecycle/services.py')
    corrected.__package__ = 'host.lifecycle'
    exec(compile(correction['host/lifecycle/services.py'], corrected.__file__, 'exec'), corrected.__dict__)
    require(services.WA_RECOVERY == corrected.WA_RECOVERY
            and all(services.recovery_show_argv(unit) == corrected.recovery_show_argv(unit)
                    for unit in services.WA_RECOVERY), 'Recovery profiles differ')
    return types.SimpleNamespace(installer=installer, fs=installer.filesystem,
        handoff=installer.admin_handoff, services=services, corrected=corrected,
        operation=operation, payloads=payloads, operation_sha=operation_sha, plan_sha=plan_sha,
        correction_hashes=correction_hashes,
        installation_sha=installer.admin_host.installation_profile().sha256)


def compatible_reader(context, raw_reader=None):
    read = raw_reader or context.corrected.recovery_read_runner
    def normalized(argv, **bounds):
        unit = argv[-1]
        require(unit in context.services.WA_RECOVERY
                and argv == context.services.recovery_show_argv(unit)
                and bounds == {'timeout': 5.0, 'max_bytes': context.services.MAX_OUTPUT},
                'Compatibility read is outside the dedicated recovery profile')
        values = context.corrected._recovery_properties(unit, read)
        return ('\n'.join(key + '=' + value for key, value in values.items()) + '\n').encode()
    return normalized


def journal(context, root):
    return context.handoff._load(root, context.operation['plan'], context.plan_sha)


def receipt_value(context, initial_raw):
    initial = decode(initial_raw)
    require(isinstance(initial, dict) and initial.get('phase') == 'installed' and initial.get('intent') == 'recovery_armed'
            and initial.get('sequence') == 6 and initial.get('processes') == [],
            'Only the observed installed/recovery_armed checkpoint is supported')
    return {'format': FORMAT, 'operation_sha256': context.operation_sha,
        'original_revision': ORIGINAL_REVISION, 'plan_sha256': context.plan_sha,
        'installer_sources': context.operation['installer_sources'],
        'compat_sources': context.correction_hashes, 'installation_sha256': context.installation_sha,
        'units': list(context.services.WA_RECOVERY), 'initial_journal_sha256': digest(initial_raw),
        'initial_sequence': 6}


def validate_receipt(context, receipt):
    require(isinstance(receipt, dict) and set(receipt) == {'format', 'operation_sha256',
        'original_revision', 'plan_sha256', 'installer_sources', 'compat_sources',
        'installation_sha256', 'units', 'initial_journal_sha256', 'initial_sequence'},
        'Invalid compatibility receipt fields')
    require(receipt['format'] == FORMAT and receipt['operation_sha256'] == context.operation_sha
        and receipt['original_revision'] == ORIGINAL_REVISION and receipt['plan_sha256'] == context.plan_sha
        and receipt['installer_sources'] == context.operation['installer_sources']
        and receipt['compat_sources'] == context.correction_hashes
        and receipt['installation_sha256'] == context.installation_sha
        and receipt['units'] == list(context.services.WA_RECOVERY)
        and type(receipt['initial_sequence']) is int and receipt['initial_sequence'] == 6
        and isinstance(receipt['initial_journal_sha256'], str)
        and re.fullmatch('[0-9a-f]{64}', receipt['initial_journal_sha256']),
        'Compatibility receipt identity differs')


def paths(context):
    record = context.operation['plan']['journal']['path'] + '.recovery-compat.json'
    transaction = digest(('recovery-compat:' + context.operation_sha).encode())[:32]
    return record, transaction


def registration(context, root, receipt_raw):
    record, transaction = paths(context)
    before = {'format': 1, 'owner': 'whatsapp', 'files': {}, 'directories': {}}
    after = {**before, 'files': {record: {'sha256': digest(receipt_raw), 'mode': 0o600,
                                         'uid': root.uid, 'gid': root.gid, 'retention': 'managed'}}}
    before, after = context.fs.validate_manifest(before), context.fs.validate_manifest(after)
    engine_path = context.fs.STATE + '/whatsapp/operations/' + transaction + '/journal.json'
    if root.snapshot(engine_path) is None:
        require(root.directory(str(Path(engine_path).parent)) is None,
                'Compatibility reservation has no durable journal; preserve it for explicit engine inspection')
        require(root.snapshot(record) is None, 'Compatibility record exists without its transaction')
        return record, transaction, before, after, None
    state = context.fs.inspect_operation(root, owner='whatsapp', operation_id=transaction, allowed_paths=[record])
    require(state['before'] == before and state['after'] == after
            and state.get('inline_payloads') == {record: base64.b64encode(receipt_raw).decode()},
            'Compatibility registration transaction differs')
    if state['phase'] == 'committed':
        require(root.snapshot(record) == {key: value for key, value in after['files'][record].items() if key != 'retention'}
                and root.read_bytes(record) == receipt_raw, 'Registered compatibility receipt changed')
    return record, transaction, before, after, state


def guard(context, root, receipt, *, registered):
    value = journal(context, root)
    require(value is not None and value['phase'] in TAIL and (registered or value['processes'] == [])
            and value['sequence'] >= receipt['initial_sequence'], 'Handoff is outside the approved recovery tail')
    require(value['intent'] in (None, TAIL[value['phase']])
            and (value['phase'] != 'installed' or value['intent'] == 'recovery_armed'),
            'Handoff intent is outside the approved recovery tail')
    plan = context.operation['plan']
    owner = context.handoff._owner_value(root, plan)
    admitted = [context.handoff._expected_owner(plan, value['phase'])]
    if value['intent'] == 'owner_dedicated':
        admitted.append(context.handoff._desired_owner(plan, 'owner_dedicated'))
    require(owner in admitted, 'Original handoff owner differs')
    if not registered:
        require(digest(root.read_bytes(plan['journal']['path'])) == receipt['initial_journal_sha256']
                and value['sequence'] == 6 and value['phase'] == 'installed',
                'Initial checkpoint differs before compatibility registration')
    return value


def initial_preflight(context, provider):
    result = provider.services.verify(context.operation['profile']['final_manifest'], enabled=False)
    require(result['main_pid'] == result['control_pid'] == 0
            and result['service_state'] in ('inactive', 'failed'), 'Recovery process has not drained')


def inspect(context, root, receipt_raw, receipt_sha, provider):
    require(digest(receipt_raw) == receipt_sha, 'Compatibility receipt digest differs')
    receipt = decode(receipt_raw); validate_receipt(context, receipt)
    *_, state = registration(context, root, receipt_raw)
    registered = state is not None and state['phase'] == 'committed'
    value = guard(context, root, receipt, registered=registered)
    if not registered:
        initial_preflight(context, provider)
    return {'phase': value['phase'], 'intent': value['intent'], 'registered': registered,
            'operation_sha256': context.operation_sha, 'receipt_sha256': receipt_sha, 'mutations': False}


def advance(context, root, receipt_raw, receipt_sha, provider, *, fault=None, filesystem_fault=None):
    require(digest(receipt_raw) == receipt_sha, 'Compatibility receipt digest differs')
    receipt = decode(receipt_raw); validate_receipt(context, receipt)
    record, _ = paths(context)
    with context.services._named_locks(root, (record + '.lock',)):
        with provider.critical_section(context.operation['plan']):
            record, transaction, before, after, state = registration(context, root, receipt_raw)
            registered = state is not None and state['phase'] == 'committed'
            guard(context, root, receipt, registered=registered)
            if not registered:
                initial_preflight(context, provider)
                if state is None:
                    context.fs.reconcile(root, operation_id=transaction, before=before, after=after,
                        payloads={record: receipt_raw}, allowed_paths=[record], inline_payloads=[record],
                        fault=filesystem_fault)
                else:
                    context.fs.resume(root, owner='whatsapp', operation_id=transaction,
                        allowed_paths=[record], fault=filesystem_fault)
            registration(context, root, receipt_raw)  # Recheck the durable receipt before any host effect.
        if fault is not None:
            fault('compatibility-registered', journal(context, root))
        result = context.handoff.handoff(root, context.operation['plan'], context.payloads, provider, fault=fault)
        guard(context, root, receipt, registered=True)
        result.update(operation_sha256=context.operation_sha, receipt_sha256=receipt_sha)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'inspect', 'advance'))
    parser.add_argument('--root', type=Path, default=Path('/'))
    parser.add_argument('--original-checkout', type=Path, required=True)
    parser.add_argument('--operation', required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--initial-journal-sha256')
    parser.add_argument('--receipt')
    parser.add_argument('--receipt-sha256')
    args = parser.parse_args(argv)
    try:
        if args.action == 'advance':
            require(args.root.absolute() == Path('/') and os.geteuid() == 0,
                    'Host advance requires root; isolated tests use the injectable library')
        operation_raw = protected_read(args.root, args.operation)
        if args.action == 'prepare':
            require(args.receipt is None and args.receipt_sha256 is None
                    and re.fullmatch('[0-9a-f]{64}', args.initial_journal_sha256 or ''),
                    'Prepare requires the independently reviewed initial journal digest')
            receipt_raw = receipt = None
        else:
            require(args.initial_journal_sha256 is None and args.receipt and args.receipt_sha256,
                    'Inspect/advance require the reviewed receipt and digest')
            receipt_raw = protected_read(args.root, args.receipt)
            require(digest(receipt_raw) == args.receipt_sha256, 'Compatibility receipt digest differs')
            receipt = decode(receipt_raw)
        context = load_context(args.root, operation_raw, args.sha256, args.original_checkout, receipt,
                               live=args.root.absolute() == Path('/'))
        with context.fs.Root(args.root) as root:
            provider = context.installer.admin_host.AdminHost(root, context.operation['profile'])
            provider.services.reader = compatible_reader(context)
            if args.action == 'prepare':
                raw = root.read_bytes(context.operation['plan']['journal']['path'])
                require(digest(raw) == args.initial_journal_sha256, 'Initial journal digest differs')
                result = receipt_value(context, raw)
                validate_receipt(context, result)
                guard(context, root, result, registered=False)
                initial_preflight(context, provider)
            elif args.action == 'inspect':
                result = inspect(context, root, receipt_raw, args.receipt_sha256, provider)
            else:
                result = advance(context, root, receipt_raw, args.receipt_sha256, provider)
    except (OSError, ValueError, RuntimeError, RecursionError) as error:
        parser.exit(1, 'Compatibility recovery requires inspection: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))
    return 3 if result.get('pending') else 0


if __name__ == '__main__':
    raise SystemExit(main())
