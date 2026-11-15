"""Compile explicit upgrade/removal inventories; never discover an installed host.

Select the public installation with installation_command.py. Completeness and
previous ownership are operator inputs, never inferred from an empty directory.
"""
import argparse
import copy
import json
from pathlib import Path

import fresh_admin as common
from host import installation as host_installation
# Offline compilation binds the neutral service names to the same explicit
# public profile; it must never consult this review machine's /etc identity.
_profile = common.installation_profile()
_selected = (host_installation.Installation.legacy() if _profile.compatibility
    else host_installation.Installation.from_dict(_profile.as_dict()))
if _profile.roster is not None:
    _selected = _selected.with_roster(_profile.roster)
host_installation.select(_selected)
import admin_host
import admin_handoff
from host.lifecycle import evidence, filesystem

FORMAT = 'whatsapp-administration-inputs-v1'
MAX_INPUT = 8 * 1024 * 1024


def template(mode, compiled=None):
    common.require(mode in ('upgrade', 'remove'), 'Explicit administration mode required')
    manifest = {'format': 1, 'owner': 'whatsapp', 'files': None, 'directories': None, 'links': None}
    inventory = {'scope': {'cgroups': None, 'script_roots': None, 'script_paths': None},
                 'manifest': manifest, 'units': None}
    stages = ('inventory', 'previous', 'installed') if mode == 'upgrade' else ('inventory', 'removal')
    value = {'format': FORMAT, 'mode': mode, 'operation_id': None, 'epoch': None,
        'before': copy.deepcopy(manifest),
        'previous_owner': {'protocol': 1, 'epoch': None, 'state': None,
                           'generation': None, 'manifest_sha256': None},
        'profile': {'format': 'whatsapp-host-inventory-v1', 'generation_id': None,
            'invokers': None, 'stages': {name: copy.deepcopy(inventory) for name in stages},
            'final_manifest': copy.deepcopy(manifest), 'retained_manifest': copy.deepcopy(manifest)},
        'attestations': {'inventory': {'path': None, 'record': {
            'format': 2, 'complete': False, 'invokers': None,
            'manual_policy': {'operation_id': None, 'unregistered_root_commands': None}}},
            'retirement': None if mode == 'upgrade' else {'path': None, 'record': {
                'format': 3, 'complete': False, 'invokers': None, 'operation_id': None,
                'epoch': None, 'references': None}}}}
    if mode == 'remove':
        value['runtime_retirement'] = {'operation_id': None}
    else:
        # A null value never authorizes a runtime replacement. The operator
        # supplies the separately reviewed before/after and backend byte pins.
        value['runtime_update'] = None
    if compiled is not None:
        # These are desired bundle facts, never observations of installed state.
        value['profile']['generation_id'] = compiled['generation']['manifest_sha256']
        if mode == 'upgrade':
            value['profile']['final_manifest'] = copy.deepcopy(compiled['manifest'])
    return value


def _combined(left, right):
    left, right = (filesystem.validate_manifest(value) for value in (left, right))
    common.require(left['owner'] == right['owner'] == 'whatsapp', 'Only WhatsApp artifacts are supported')
    result = copy.deepcopy(left)
    for kind in ('files', 'directories', 'links'):
        for path, spec in right[kind].items():
            common.require(path not in result[kind] or result[kind][path] == spec,
                           'Active and retained manifests disagree')
            result[kind][path] = copy.deepcopy(spec)
    return filesystem.validate_manifest(result)


def _action(before, after):
    paths = {path for side in (before, after) for kind in ('files', 'directories', 'links')
             for path in side.get(kind, {})}
    return {'before': before, 'after': after, 'allowed_paths': sorted(paths)}


def compile_operation(bundle, *, source_revision, metadata_sha256, input_bytes,
                      inputs_sha256, mode, uid=0, gid=0, source_root=common.REPOSITORY):
    common.require(mode in ('upgrade', 'remove') and type(input_bytes) is bytes
        and len(input_bytes) <= MAX_INPUT and common.hex_value(inputs_sha256, 64)
        and common.digest(input_bytes) == inputs_sha256, 'Exact bounded reviewed administration inputs required')
    inputs = json.loads(input_bytes, object_pairs_hook=common.unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite input')))
    expected = {'format', 'mode', 'operation_id', 'epoch', 'before', 'previous_owner', 'profile', 'attestations'}
    if mode == 'remove':
        expected.add('runtime_retirement')
    elif isinstance(inputs, dict) and 'runtime_update' in inputs:
        expected.add('runtime_update')
    common.require(isinstance(inputs, dict) and set(inputs) == expected
        and inputs['format'] == FORMAT and inputs['mode'] == mode, 'Exact administration input contract required')
    common.require(common.hex_value(source_revision, 40) and common.hex_value(metadata_sha256, 64),
                   'Explicit bundle digest and source revision required')
    operation_id, epoch = inputs['operation_id'], inputs['epoch']
    common.require(common.hex_value(operation_id, 32) and common.hex_value(epoch, 32)
        and operation_id != epoch, 'Distinct explicit operation and owner epoch required')
    common.require(type(uid) is int and type(gid) is int and uid >= 0 and gid >= 0,
                   'Explicit administrative ownership required')
    compiled = common.admin_manifest.load_bundle(bundle, source_revision, uid=uid, gid=gid,
        expected_metadata_sha256=metadata_sha256)
    before = common.admin_manifest._adoption(inputs['before'])
    previous = inputs['previous_owner']
    admin_handoff._owner(previous)
    common.require(previous['state'] == 'dedicated', 'Existing dedicated owner must be explicitly observed')
    profile = copy.deepcopy(inputs['profile'])
    common.require(isinstance(profile, dict) and 'attestation' not in profile
        and 'retirement_attestation' not in profile, 'Attestation references come from separate documents')
    documents = inputs['attestations']
    common.require(isinstance(documents, dict) and set(documents) == {'inventory', 'retirement'}
        and (documents['retirement'] is None) == (mode == 'upgrade'), 'Exact stage attestations required')
    files, destinations = {}, {}
    for name, field in (('inventory', 'attestation'), ('retirement', 'retirement_attestation')):
        item = documents[name]
        if item is None:
            profile[field] = None
            continue
        common.require(isinstance(item, dict) and set(item) == {'path', 'record'},
                       'Explicit attestation path and record required')
        evidence.path_name(item['path'])
        raw = common.encoded(item['record'])
        filename = name + '-attestation.json'
        files[filename], destinations[filename] = raw, item['path']
        profile[field] = {'path': item['path'], 'sha256': common.digest(raw)}
    inventory_digest = admin_host.validate_profile(profile)
    if mode == 'upgrade':
        common.require(epoch != previous['epoch'], 'Upgrade requires a new owner epoch')
        prepared = common.admin_manifest.prepare_action(compiled, before,
            adopted_sha256=common.admin_manifest.manifest_digest(before), runtime_update=inputs.get('runtime_update'))
        common.require(filesystem.validate_manifest(profile['final_manifest']) ==
            filesystem.validate_manifest(prepared['active_manifest'])
            and filesystem.validate_manifest(profile['retained_manifest']) ==
            filesystem.validate_manifest(prepared['retained_manifest']),
            'Declared final/retained manifests differ from the compiled generation')
        generation = compiled['generation']
        owner = {'protocol': 1, 'epoch': epoch, 'state': 'dedicated',
                 'generation': generation['destination'], 'manifest_sha256': generation['manifest_sha256']}
        actions, payloads = {'install': prepared['action']}, {'install': prepared['payloads']}
    else:
        common.require(epoch == previous['epoch'], 'Removal must preserve the existing owner epoch')
        generation = compiled['generation']
        common.require(previous['generation'] == generation['destination']
            and previous['manifest_sha256'] == generation['manifest_sha256'],
            'Removal bundle must identify the existing owner generation')
        for kind in ('files', 'directories'):
            common.require(all(path in before[kind] and before[kind][path] == spec
                for path, spec in compiled['manifest'][kind].items()),
                'Removal inventory must include the complete installed administration bundle')
        owner = previous
        after = _combined(profile['final_manifest'], profile['retained_manifest'])
        common.require(before['directories'] == after['directories'] and not before['links'] and not after['links']
            and set(after['files']) <= set(before['files'])
            and all(spec == before['files'][path] for path, spec in after['files'].items()),
            'Removal may only retain or quarantine exact files, never alter data or directories')
        actions = {'close_invokers': _action(before, copy.deepcopy(before)), 'remove': _action(before, after)}
        payloads = {'close_invokers': {}, 'remove': {}}
    common.require(profile['generation_id'] == owner['manifest_sha256'], 'Inventory generation differs from the owner')
    plan = {'format': admin_handoff.FORMAT, 'id': operation_id, 'mode': mode,
        'inventory_digest': inventory_digest,
        'evidence_digests': {name: evidence.digest_inventory(item['scope'], item['manifest'], item['units'])
                             for name, item in profile['stages'].items()},
        'owner': owner, 'previous_owner': previous,
        'owner_metadata': {'mode': 0o600, 'uid': uid, 'gid': gid},
        'journal': {'path': common.STATE + '/handoff/' + operation_id + '.json',
                    'mode': 0o600, 'uid': uid, 'gid': gid},
        'control_directories': {}, 'actions': actions}
    if common.installation_profile().roster_sha256 is not None:
        plan['allocation_sha256'] = common.installation_profile().roster_sha256
    if mode == 'remove':
        plan['runtime_retirement'] = inputs['runtime_retirement']
    elif inputs.get('runtime_update') is not None:
        plan['runtime_update'] = copy.deepcopy(inputs['runtime_update'])
    admin_handoff.validate_plan(plan, payloads, filesystem)
    admin_host.validate_admission(profile, plan)
    admin_host.validate_inventory_attestation(documents['inventory']['record'], profile, plan)
    if mode == 'remove':
        admin_host.validate_retirement_attestation(documents['retirement']['record'], profile, plan, authority_uid=uid)
    operation, operation_sha = common.admin_install.encode_operation(plan, profile, payloads,
        source_revision=source_revision, source_root=source_root)
    files['operation.json'] = operation
    files['compilation.json'] = common.encoded({'format': 'whatsapp-administration-compilation-v1',
        'mode': mode, 'installation_sha256': common.installation_profile().sha256,
        'source_revision_assertion': source_revision, 'inputs_sha256': inputs_sha256,
        'bundle_metadata_sha256': metadata_sha256, 'operation_sha256': operation_sha,
        'attestation_destinations': destinations, 'host_observed': False, 'installed': False,
        'owner_written': False, 'live_admission_certified': False})
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('upgrade', 'remove'), required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--bundle-sha256', required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--input-template', action='store_true')
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--inputs-sha256')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.input_template:
            common.require(args.inputs is None and args.inputs_sha256 is None and args.output is None,
                           'Template cannot publish an operation')
            compiled = common.admin_manifest.load_bundle(args.bundle, args.source_revision,
                expected_metadata_sha256=args.bundle_sha256)
            print(common.encoded(template(args.mode, compiled)).decode(), end='')
            return 0
        common.require(args.inputs is not None and args.inputs_sha256 is not None and args.output is not None,
                       'Reviewed inputs, digest and new output directory required')
        files = compile_operation(args.bundle, source_revision=args.source_revision,
            metadata_sha256=args.bundle_sha256, input_bytes=common.read_protected(args.inputs, max_bytes=MAX_INPUT),
            inputs_sha256=args.inputs_sha256, mode=args.mode)
        common.write_output(args.output, files)
    except (OSError, ValueError, RuntimeError, TypeError, KeyError) as error:
        parser.exit(1, 'Administration preparation requires inspection: ' + str(error) + '\n')
    print(files['compilation.json'].decode(), end='')
    return 0
