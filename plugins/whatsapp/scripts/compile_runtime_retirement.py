#!/usr/bin/env python3
"""Compile bounded, explicitly inventoried WhatsApp retirement inputs offline.

No command observes a host, grants authority, or advances the runtime. The
observation receipt and the complete-inventory assertion remain distinct.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

SCRIPTS = Path(__file__).resolve().parent
REPOSITORY = SCRIPTS.parents[2]
FORMAT = 'whatsapp-runtime-retirement-inputs-v1'
MAX_BYTES = 16 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(content):
    return hashlib.sha256(content).hexdigest()


def hex_value(value, length=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def decode(content):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate compiler input field')
            value[key] = item
        return value
    return json.loads(content, object_pairs_hook=unique,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Non-finite compiler input')))


def read_pinned(path, digest):
    path = Path(path)
    require(hex_value(digest) and path.is_absolute() and path == path.resolve(strict=True),
            'Input needs a physical absolute path and reviewed digest')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_BYTES, 'Input is not a bounded regular file')
        content = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    require(len(content) <= MAX_BYTES and identity(before) == identity(after) == identity(path.lstat())
            and sha(content) == digest, 'Compiler input changed or differs from its digest')
    return content


def reference(root, item):
    from host.lifecycle.evidence import path_name
    require(isinstance(item, dict) and set(item) == {'path', 'sha256'}, 'Exact inventory reference required')
    path_name(item['path'])
    root = Path(root).absolute()
    require(root == root.resolve(strict=True), 'Inventory snapshot root must be physical')
    target = root / item['path'].lstrip('/')
    require(target == target.resolve(strict=True) and target.is_relative_to(root), 'Inventory reference escaped the snapshot')
    return read_pinned(target, item['sha256'])


def modules(profile_bytes, roster_bytes=None):
    # Local source is the compiler's reviewed checkout. Operational entry points
    # will independently authenticate their installed identity and source pins.
    sys.path[:0] = [str(SCRIPTS), str(REPOSITORY)]
    import installation_layout as installation
    require(getattr(installation, 'FORMAT', None) == 'whatsapp-installation-v1', 'Wrong product layout')
    selected = installation.Installation.from_dict(decode(profile_bytes))
    if roster_bytes is not None:
        selected = selected.with_roster(decode(roster_bytes))
        require(roster_bytes == selected._roster, 'Canonical allocation snapshot required')
    installation.select(selected)
    from host import installation as host_installation
    require(host_installation.FORMAT == installation.FORMAT, 'Wrong host installation layout')
    copied = host_installation.Installation.from_dict(selected.as_dict())
    if selected.roster is not None:
        copied = copied.with_roster(selected.roster)
    host_installation.select(copied)
    import runtime_lifecycle as runtime
    return selected, runtime


def metadata_template(digest=None):
    return {'sha256': digest, 'mode': None, 'uid': None, 'gid': None}


def template(selected, runtime, slugs):
    require(bool(slugs) and len(slugs) == len(set(slugs)) and len(slugs) <= 64,
            'Name every registered tenant explicitly')
    tenants = []
    for slug in sorted(slugs):
        item = runtime.layout(slug)
        tenants.append({'slug': slug, 'uid': None, 'gid': None,
            'bridge_cgroup': '/system.slice/' + item['bridge_unit'], 'gateway_cgroup': None,
            'wrapper': metadata_template(), 'sources': {
                item['bridge_source']: metadata_template(), item['quadlet']: metadata_template()}})
    directory = runtime.STATE + '/runtime-retirement-inputs'
    return {'format': FORMAT, 'complete': False, 'operation_id': None,
        'collector_path': str(SCRIPTS / 'runtime_lifecycle.py'),
        'observation_tenants': tenants,
        'observation_request': {'path': directory + '/request.json', 'sha256': None},
        'observation_provenance_path': directory + '/provenance.json',
        'observation_receipt': {'path': directory + '/observation.json', 'sha256': None},
        'admin_operation': {'path': directory + '/admin-remove.json', 'sha256': None},
        'tenant_registry': {'path': runtime.PROJECT + '/private/tenants.json', 'sha256': None},
        'registry_metadata': metadata_template(),
        'frontend': {key: {'path': '/etc/develative-host-frontend/' + key + '.json', 'sha256': None}
                     for key in ('profile', 'registry')},
        'qos_policy': {'path': '/etc/develative-host-qos/policy.json', 'sha256': None},
        'attestation_path': directory + '/attestation.json',
        'manual_policy': None, 'external_references': None,
        'helper_metadata': {
            runtime.HELPER: metadata_template(sha((SCRIPTS / 'runtime_lifecycle.py').read_bytes())),
            runtime.HELPER_LAYOUT: metadata_template(sha((SCRIPTS / 'installation_layout.py').read_bytes()))},
        'application_files': None, 'directories': None}


def observation(inputs, runtime, *, authority_uid=0):
    from host.lifecycle.evidence import path_name
    require(type(authority_uid) is int and authority_uid >= 0, 'Explicit observation authority required')
    require(inputs.get('format') == FORMAT and hex_value(inputs.get('operation_id'), 32),
            'Explicit runtime operation identity required')
    destinations = (inputs['observation_request']['path'], inputs['observation_provenance_path'],
                    inputs['observation_receipt']['path'], inputs['attestation_path'])
    for path in destinations:
        path_name(path)
        require(path.startswith(runtime.STATE + '/runtime-retirement-inputs/') and path.endswith('.json'),
                'Retirement documents belong inside the selected private administration input directory')
    require(len(set(destinations)) == len(destinations), 'Retirement document destinations must be distinct')
    # These documents will be materialized separately on the inventoried host.
    # A collision would require contradictory bytes (or presence/absence) at a
    # single pathname, even though compilation itself only writes local output.
    immutable = {inputs['admin_operation']['path'], inputs['tenant_registry']['path'],
                 *(item['path'] for item in inputs['frontend'].values())}
    if inputs['qos_policy'] is not None:
        immutable.add(inputs['qos_policy']['path'])
    for field in ('external_references', 'helper_metadata', 'application_files', 'directories'):
        if isinstance(inputs[field], dict):
            immutable.update(inputs[field])
    immutable.update((inputs['collector_path'],
                      str(Path(inputs['collector_path']).with_name('installation_layout.py'))))
    for item in inputs['observation_tenants']:
        immutable.update(item['sources'])
        immutable.add(runtime.layout(item['slug'])['wrapper'])
    require(not set(destinations).intersection(immutable),
            'Retirement document destinations cannot overlap immutable inventory references')
    source = inputs['collector_path']; path_name(source)
    require(Path(source).name == 'runtime_lifecycle.py', 'Select the exact reviewed collector pathname')
    tenants = inputs['observation_tenants']
    require(isinstance(tenants, list) and 1 <= len(tenants) <= 64, 'Bounded tenant observation required')
    seen, uids = set(), set()
    for item in tenants:
        runtime.fields(item, ('slug', 'uid', 'gid', 'bridge_cgroup', 'gateway_cgroup', 'wrapper', 'sources'))
        wanted = runtime.layout(item['slug'])
        require(item['slug'] not in seen and type(item['uid']) is int and item['uid'] > 0
                and type(item['gid']) is int and item['gid'] > 0 and item['uid'] not in uids,
                'Explicit distinct positive tenant UID/GID required')
        seen.add(item['slug']); uids.add(item['uid'])
        uid = str(item['uid'])
        require(item['bridge_cgroup'] == '/system.slice/' + wanted['bridge_unit']
                and item['gateway_cgroup'] in (
                    '/system.slice/user@' + uid + '.service/app.slice/whatsapp-waha.service',
                    '/user.slice/user-' + uid + '.slice/user@' + uid + '.service/app.slice/whatsapp-waha.service'),
                'Use the observed finite tenant cgroups')
        runtime._metadata(item['wrapper'])
        require(item['wrapper']['uid'] == authority_uid and item['wrapper']['mode'] & 0o100
                and not item['wrapper']['mode'] & 0o022, 'Protected executable wrapper metadata required')
        allowed = {wanted['bridge_source'], wanted['quadlet'],
            wanted['bridge_source'] + '.d/60-whatsapp-priority.conf',
            wanted['bridge_source'] + '.d/70-release-runtime.conf',
            wanted['home'] + '/.config/systemd/user/whatsapp-waha.service.d/60-whatsapp-priority.conf'}
        require(isinstance(item['sources'], dict)
                and {wanted['bridge_source'], wanted['quadlet']} <= set(item['sources']) <= allowed,
                'Enumerate the finite bridge, Quadlet and observed drop-ins')
        for path, spec in item['sources'].items():
            runtime._metadata(spec)
            require(spec['uid'] == (item['uid'] if path == wanted['quadlet'] else authority_uid)
                    and not spec['mode'] & 0o022, 'Observed source authority differs')
    source_sha = sha((SCRIPTS / 'runtime_lifecycle.py').read_bytes())
    layout_sha = sha((SCRIPTS / 'installation_layout.py').read_bytes())
    provenance = encoded({'format': 2, 'operation_id': inputs['operation_id'],
        'source_sha256': source_sha, 'layout_sha256': layout_sha,
        'tenant_scope_sha256': sha(encoded(tenants))})
    path_name(inputs['observation_provenance_path'])
    request = encoded({'format': 'whatsapp-runtime-observation-v2', 'operation_id': inputs['operation_id'],
        'source': {'path': source, 'sha256': source_sha},
        'layout_source': {'path': str(Path(source).with_name('installation_layout.py')), 'sha256': layout_sha},
        'provenance': {'path': inputs['observation_provenance_path'], 'sha256': sha(provenance)}, 'tenants': tenants})
    return request, provenance


def compile_operation(inputs, runtime, *, inventory_root, source_revision, authority_uid=0):
    """Validate local inputs; alternate authority is an explicit filesystem-test seam.

    The CLI always uses administrative UID 0 and exposes no authority override.
    """
    import admin_install
    from host.lifecycle import evidence
    from host.frontend import adapter, provider
    require(inputs.get('complete') is True
            and inputs.get('manual_policy') == 'unregistered-runtime-starts-frozen',
            'Explicit complete inventoried scope and operation freeze assertion required')
    request_bytes, provenance = observation(inputs, runtime, authority_uid=authority_uid)
    require(reference(inventory_root, inputs['observation_request']) == request_bytes,
            'Observation request differs from this exact reviewed scope/source')
    request = decode(request_bytes)
    require(reference(inventory_root, request['provenance']) == provenance, 'Observation provenance differs')
    receipt = decode(reference(inventory_root, inputs['observation_receipt']))
    runtime.fields(receipt, ('format', 'operation_id', 'request_sha256', 'source_sha256', 'layout_sha256',
        'provenance_sha256', 'mutations', 'invoker_completeness_proven', 'lifecycle_contract', 'units'))
    require(receipt['format'] == 'whatsapp-runtime-observation-receipt-v2'
            and receipt['operation_id'] == inputs['operation_id'] and receipt['request_sha256'] == sha(request_bytes)
            and receipt['source_sha256'] == request['source']['sha256']
            and receipt['layout_sha256'] == request['layout_source']['sha256']
            and receipt['provenance_sha256'] == sha(provenance) and receipt['mutations'] is False
            and receipt['invoker_completeness_proven'] is False
            and receipt['lifecycle_contract'] == 'whatsapp-rootless-quadlet-cleanup-v1',
            'Receipt is not bound to the exact finite observation; it cannot prove completeness')
    admin_raw = reference(inventory_root, inputs['admin_operation'])
    admin, _, admin_digest = admin_install.decode_operation(admin_raw, inputs['admin_operation']['sha256'])
    require(admin['plan']['mode'] == 'remove'
            and admin['plan'].get('runtime_retirement') == {'operation_id': inputs['operation_id']},
            'A validated administrative removal must name this runtime operation')
    require(hex_value(source_revision, 40) and admin['source_revision'] == source_revision,
            'Administrative and runtime source revision assertions differ')
    registry_raw = reference(inventory_root, inputs['tenant_registry'])
    registry = decode(registry_raw)
    runtime.fields(registry, ('format', 'instances'))
    require(inputs['tenant_registry']['path'] == runtime.PROJECT + '/private/tenants.json'
            and type(registry['format']) is int and registry['format'] == 1
            and isinstance(registry['instances'], dict), 'Exact registered tenant inventory required')
    slugs = sorted(item['slug'] for item in request['tenants'])
    require(set(registry['instances']) == set(slugs), 'Include every registered tenant, including prepared or disabled ones')
    for slug, row in registry['instances'].items():
        require(isinstance(row, dict) and isinstance(row.get('spec'), dict)
                and row['spec'].get('slug') == slug and type(row.get('enabled')) is bool
                and row.get('phase') in ('preparing', 'prepared', 'existing', 'ready')
                and row['spec'].get('installation') == runtime.installation_profile().as_dict(),
                'Registered tenant belongs to another installation or lifecycle state')
    runtime._metadata(inputs['registry_metadata'])
    require(inputs['registry_metadata']['sha256'] == sha(registry_raw)
            and inputs['registry_metadata']['uid'] == authority_uid and not inputs['registry_metadata']['mode'] & 0o022,
            'Registry metadata must bind the protected observed bytes')
    refs = inputs['external_references']
    require(isinstance(refs, dict) and inputs['tenant_registry']['path'] not in refs,
            'Explicit external reference inventory required; registry is bound separately')
    for path, spec in refs.items():
        evidence.path_name(path)
        if spec is not None: runtime._metadata(spec)
    attestation = encoded({'format': 1, 'operation_id': inputs['operation_id'], 'tenant_slugs': slugs,
        'manual_policy': inputs['manual_policy'],
        'references': {**refs, inputs['tenant_registry']['path']: inputs['registry_metadata']}})
    evidence.path_name(inputs['attestation_path'])
    require(set(inputs['helper_metadata']) == {runtime.HELPER, runtime.HELPER_LAYOUT}, 'Both retained helpers are required')
    files = {}
    for path, spec in inputs['helper_metadata'].items():
        runtime._metadata(spec)
        expected = request['source' if path == runtime.HELPER else 'layout_source']['sha256']
        require(spec['uid'] == authority_uid and not spec['mode'] & 0o022 and spec['sha256'] == expected,
                'Installed helper must match the reviewed captured source')
        files[path] = {**spec, 'retention': 'managed'}
    retained = set(files)
    tenants = []
    require(isinstance(receipt['units'], dict) and set(receipt['units']) ==
            {slug + ':' + component for slug in slugs for component in ('bridge', 'gateway')},
            'Receipt must cover exactly both units of every tenant')
    for item in request['tenants']:
        wanted = runtime.layout(item['slug'])
        files[wanted['wrapper']] = {**item['wrapper'], 'retention': 'managed'}
        retained.add(wanted['wrapper'])
        tenant = {key: item[key] for key in ('slug', 'uid', 'gid', 'bridge_cgroup', 'gateway_cgroup')}
        tenant.update(wanted, quadlet_metadata=item['sources'][wanted['quadlet']])
        for component in ('bridge', 'gateway'):
            observed = receipt['units'][item['slug'] + ':' + component]
            runtime.fields(observed, ('definition', 'state'))
            tenant[component + '_definition'] = observed['definition']
            tenant[component + '_dropins'] = {path: spec for path, spec in item['sources'].items()
                if path.endswith('.conf') and (path.startswith(wanted['bridge_source'] + '.d/')
                    if component == 'bridge' else path.startswith(wanted['home'] + '/'))}
        for path in (wanted['bridge_source'], *tenant['bridge_dropins']):
            files[path] = {**item['sources'][path], 'retention': 'managed'}
        tenants.append(tenant)
    require(isinstance(inputs['application_files'], dict) and isinstance(inputs['directories'], dict),
            'Explicit optional application file/directory inventory required, including deliberate empty maps')
    require(not set(inputs['application_files']).intersection(files), 'Application inventory overlaps finite runtime sources')
    files.update(inputs['application_files'])
    retained.update(path for path, spec in inputs['application_files'].items() if spec.get('retention') == 'retain')
    before = {'format': 1, 'owner': 'whatsapp', 'files': files, 'directories': inputs['directories'], 'links': {}}
    after = {**before, 'files': {path: files[path] for path in retained}}
    require(not set(refs).intersection(files), 'External references cannot overlap managed runtime files')
    frontend = inputs['frontend']
    runtime.fields(frontend, ('profile', 'registry'))
    require(frontend['profile']['path'] == adapter.PROFILE and frontend['registry']['path'] == adapter.REGISTRY,
            'Only the neutral frontend profile and registry are admitted')
    front_registry = decode(reference(inventory_root, frontend['registry']))
    front_profile = decode(reference(inventory_root, frontend['profile']))
    provider.validate_registry(front_registry); adapter.validate_profile(front_profile, front_registry)
    if inputs['qos_policy'] is not None:
        from host.qos.applicator import validate_policy
        validate_policy(decode(reference(inventory_root, inputs['qos_policy'])))
    plan = {'format': runtime.FORMAT, 'operation_id': inputs['operation_id'],
        'source_sha256': request['source']['sha256'], 'admin_plan_sha256': admin_digest,
        'admin_profile_sha256': evidence.digest(admin['profile']),
        'attestation': {'path': inputs['attestation_path'], 'sha256': sha(attestation)},
        'tenants': tenants, 'scope': {'cgroups': [item[key] for item in tenants
            for key in ('bridge_cgroup', 'gateway_cgroup')], 'script_roots': [], 'script_paths': []},
        'generation_id': '0' * 64, 'before': before, 'after': after, 'qos_policy': inputs['qos_policy']}
    if runtime.installation_profile().roster_sha256 is not None:
        plan['allocation_sha256'] = runtime.installation_profile().roster_sha256
    sources = {name: sha((REPOSITORY / name).read_bytes()) for name in runtime.source_paths(plan)}
    require(all(sources.get(name) == digest for name, digest in admin['installer_sources'].items()),
            'Administrative and runtime operations use different source bytes')
    plan['generation_id'] = sha(encoded(sources))
    runtime.validate_plan(plan, authority_uid=authority_uid)
    content = runtime.encode_operation(plan, admin_operation=inputs['admin_operation'], frontend=frontend,
        source_revision=source_revision, source_root=REPOSITORY)
    require(decode(content)['sources'] == sources, 'Source tree changed during compilation')
    report = {'format': 'whatsapp-runtime-compilation-v1', 'operation_sha256': sha(content),
        'attestation': plan['attestation'], 'source_revision_assertion': source_revision,
        'tenant_slugs': slugs, 'required_admin_phase': 'retired', 'host_observed': False,
        'completeness_asserted_by_operator': True, 'completeness_proven_by_compiler': False,
        'mutations': False, 'retired': False}
    return {'operation.json': content, 'attestation.json': attestation, 'compilation.json': encoded(report)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('template', 'prepare-observation', 'compile'))
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    parser.add_argument('--roster', type=Path)
    parser.add_argument('--roster-sha256')
    parser.add_argument('--tenant', action='append', default=[])
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--inputs-sha256')
    parser.add_argument('--inventory-root', type=Path)
    parser.add_argument('--source-revision')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    require(bool(args.roster) == bool(args.roster_sha256), 'Allocation path and digest must be supplied together')
    selected, runtime = modules(read_pinned(args.profile, args.profile_sha256),
        read_pinned(args.roster, args.roster_sha256) if args.roster else None)
    require(not args.output.exists() and not args.output.is_symlink(), 'Compilation output must be new')
    if args.action == 'template':
        result = {'inputs.json': encoded(template(selected, runtime, args.tenant))}
    else:
        require(args.inputs is not None, 'Digest-pinned inputs are required')
        inputs = decode(read_pinned(args.inputs, args.inputs_sha256))
        expected = set(template(selected, runtime, [row['slug'] for row in inputs['observation_tenants']]))
        require(set(inputs) == expected, 'Retirement compiler input fields differ')
        if args.action == 'prepare-observation':
            request, provenance = observation(inputs, runtime)
            from host.lifecycle.evidence import path_name
            path_name(inputs['observation_request']['path'])
            inputs['observation_request']['sha256'] = sha(request)
            inputs['complete'] = False
            result = {'request.json': request, 'provenance.json': provenance, 'inputs.next.json': encoded(inputs)}
        else:
            require(args.inventory_root is not None, 'An explicit local inventory snapshot root is required')
            result = compile_operation(inputs, runtime, inventory_root=args.inventory_root,
                                       source_revision=args.source_revision)
    args.output.mkdir(mode=0o700)
    for name, content in result.items():
        with (args.output / name).open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600); stream.write(content)
    print(json.dumps({'output': str(args.output), 'files': {name: sha(content) for name, content in result.items()},
        'host_observed': False, 'host_changed': False, 'installed': False}))


if __name__ == '__main__':
    main()
