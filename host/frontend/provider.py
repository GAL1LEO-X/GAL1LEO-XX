"""Host-owned Apache consumers and certificate deployment.

The host lifecycle engine owns filesystem effects. A trusted finite adapter
owns Apache validation/reload and existing certificate-hook integration. No
certificate issuance, scheduler creation, listener selection or shell commands
are inferred from a consumer manifest.
"""
import copy
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import posixpath
import stat

PROVIDER = 'develative-host-frontend'
VERSION = '0.1.0'
REGISTRY = '/etc/develative-host-frontend/registry.json'
STATE = '/var/lib/develative-host-frontend'
LEGACY_HOOKS = {'deploy': '/usr/local/lib/develative-host-frontend/legacy-deploy',
                'post': '/usr/local/lib/develative-host-frontend/legacy-post'}
MAX_FILES = 1024


class FrontendError(ValueError):
    pass


def require(value, message):
    if not value:
        raise FrontendError(message)


def fields(value, expected, message):
    require(isinstance(value, dict) and set(value) == set(expected), message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(content):
    return hashlib.sha256(content).hexdigest()


def hexadecimal(value, length=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def path(value):
    require(isinstance(value, str) and re.fullmatch(r'/[A-Za-z0-9_.@/-]+', value)
            and value != '/' and str(PurePosixPath(value)) == value
            and '..' not in PurePosixPath(value).parts, 'An exact canonical administrative path is required')
    return value


def domain(value):
    return (isinstance(value, str) and len(value) <= 253 and '.' in value
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                    for label in value.split('.')))


def link_target(name, item):
    literal = item['target']
    require(isinstance(literal, str) and literal, 'Invalid link literal')
    if literal.startswith('/'): return path(literal)
    parts, resolved = literal.split('/'), list(PurePosixPath(name).parent.parts[1:])
    require(all(part not in ('', '.') for part in parts), 'Noncanonical relative link')
    ordinary = False
    for part in parts:
        if part == '..':
            require(resolved and not ordinary, 'Relative link escapes or is noncanonical')
            resolved.pop()
        else:
            ordinary = True; resolved.append(part)
    target = path('/' + '/'.join(resolved))
    require(item.get('resolved_target') == target, 'Relative link resolution differs')
    return target


def domains(value):
    require(isinstance(value, list) and 0 < len(value) <= 128
            and all(domain(item) for item in value) and len(set(value)) == len(value),
            'Exact lowercase DNS domains are required')
    return set(value)


def validate_registry(value):
    fields(value, {'format', 'provider', 'version', 'owner', 'apache', 'scheduler',
                   'artifacts', 'directories', 'links', 'host_files', 'consumers',
                   'lineages', 'legacy_hooks'}, 'Invalid frontend registry')
    require(type(value['format']) is int and value['format'] == 1 and value['provider'] == PROVIDER
            and value['version'] == VERSION and value['owner'] == 'host', 'Unsupported frontend provider')
    fields(value['apache'], {'unit', 'config_path'}, 'Invalid Apache identity')
    require(value['apache']['unit'] in ('apache2.service', 'httpd.service'), 'Use the attested host Apache unit')
    path(value['apache']['config_path'])
    require(value['scheduler'] == {'owner': 'host', 'unit': 'certbot.timer'},
            'Preserve the single host certificate scheduler')
    for kind in ('artifacts', 'directories', 'links', 'consumers', 'lineages', 'legacy_hooks'):
        require(isinstance(value[kind], dict) and len(value[kind]) <= MAX_FILES, 'Invalid bounded registry collection')
    require(isinstance(value['host_files'], list) and len(set(value['host_files'])) == len(value['host_files']),
            'Invalid host resource references')
    objects = set(value['artifacts']) | set(value['links'])
    require(len(objects) == len(value['artifacts']) + len(value['links'])
            and not objects.intersection(value['directories'])
            and set(value['host_files']) <= objects and value['apache']['config_path'] in value['host_files'],
            'Host configuration must be retained independently of application consumers')
    for kind in ('artifacts', 'directories', 'links'):
        for name, item in value[kind].items():
            path(name)
            require(name != REGISTRY and not name.startswith(STATE + '/'), 'Provider control state is not a consumer artifact')
            expected = {'uid', 'gid', 'retention'} | ({'target'} if kind == 'links' else {'mode'})
            if kind == 'links' and isinstance(item.get('target'), str) and not item['target'].startswith('/'):
                expected.add('resolved_target')
            if kind == 'artifacts': expected.add('sha256')
            fields(item, expected, 'Invalid artifact metadata')
            require(all(type(item[key]) is int and 0 <= item[key] < 2**31 for key in ('uid', 'gid')),
                    'Invalid artifact ownership')
            require(item['retention'] in (('retain',) if kind == 'directories' else ('managed', 'retain')),
                    'Invalid artifact retention')
            if kind != 'links':
                require(type(item['mode']) is int and 0 <= item['mode'] <= 0o777 and not item['mode'] & 0o022,
                        'Frontend files must be administratively protected')
            if kind == 'artifacts': require(hexadecimal(item['sha256']), 'Invalid artifact hash')
            if kind == 'links':
                require(link_target(name, item) in value['artifacts'], 'A configuration link target must belong to the pinned closure')
    claimed, used, vhost_owners = {}, set(value['host_files']), {}
    for name, item in value['consumers'].items():
        fields(item, {'owner', 'status', 'domains', 'vhosts', 'lineages'}, 'Invalid consumer')
        require(isinstance(name, str) and re.fullmatch(r'(host|box|whatsapp)\.[a-z][a-z0-9.-]*', name)
                and item['owner'] == name.split('.')[0] and item['status'] in ('active', 'retired', 'pending_tls'),
                'Consumer namespace and ownership differ')
        for host in domains(item['domains']):
            require(host not in claimed, 'A hostname belongs to multiple consumers')
            claimed[host] = name
        require(isinstance(item['vhosts'], list) and item['vhosts']
                and len(set(item['vhosts'])) == len(item['vhosts']) and set(item['vhosts']) <= objects,
                'Consumer vhost references are incomplete')
        used.update(item['vhosts'])
        for vhost in item['vhosts']:
            require(item['owner'] == 'host' or vhost not in value['host_files'],
                    'Application routes cannot be retained as an unremovable host reference')
            require(vhost not in vhost_owners or vhost_owners[vhost] == item['owner'],
                    'A mixed-owner vhost file needs an explicit reviewed split before retirement')
            vhost_owners[vhost] = item['owner']
        require(isinstance(item['lineages'], list)
                and (not item['lineages'] if item['status'] == 'pending_tls'
                     else bool(item['lineages']) or item['status'] == 'retired')
                and len(set(item['lineages'])) == len(item['lineages']), 'Consumer lineage references are incomplete')
        for lineage in item['lineages']:
            path(lineage)
            require(lineage in value['lineages'], 'Consumer lineage is not registered')
    require(used == objects, 'Every configuration artifact needs an explicit lifecycle reference')
    material_paths = {}
    for lineage, item in value['lineages'].items():
        path(lineage)
        fields(item, {'domains', 'consumers', 'source', 'destinations'}, 'Invalid certificate lineage')
        hosts = domains(item['domains'])
        require(isinstance(item['consumers'], list) and item['consumers']
                and len(set(item['consumers'])) == len(item['consumers'])
                and set(item['consumers']) <= set(value['consumers']), 'Unknown or duplicate lineage consumer')
        require(hosts == {host for name in item['consumers'] for host in value['consumers'][name]['domains']}
                and all(lineage in value['consumers'][name]['lineages'] for name in item['consumers']),
                'Lineage SAN set and consumer registry differ')
        fields(item['source'], {'certificate', 'key'}, 'Invalid lineage material references')
        require(path(item['source']['certificate']) != path(item['source']['key']), 'Certificate and key paths overlap')
        require(isinstance(item['destinations'], list) and item['destinations'], 'Certificate destinations are required')
        covered = set()
        for target in item['destinations']:
            fields(target, {'consumer', 'mode', 'certificate', 'key', 'uid', 'gid',
                            'certificate_mode', 'key_mode'}, 'Invalid certificate destination')
            require(target['consumer'] in item['consumers'] and target['mode'] in ('direct', 'copy'),
                    'Unknown material consumer or deployment mode')
            covered.add(target['consumer'])
            require(path(target['certificate']) != path(target['key'])
                    and all(type(target[key]) is int and 0 <= target[key] < 2**31 for key in ('uid', 'gid')),
                    'Invalid material destination ownership')
            require(type(target['certificate_mode']) is int and target['certificate_mode'] in (0o600, 0o640, 0o644)
                    and type(target['key_mode']) is int and target['key_mode'] in (0o600, 0o640),
                    'Certificate and key permissions must be explicit and bounded')
            identity = (lineage, target['certificate'], target['key'], target['uid'], target['gid'],
                        target['certificate_mode'], target['key_mode'], target['mode'])
            for target_path in (target['certificate'], target['key']):
                require(target_path not in objects and target_path != REGISTRY
                        and not target_path.startswith(STATE + '/'), 'TLS destination overlaps configuration or control state')
                require(target_path not in material_paths or material_paths[target_path] == identity,
                        'TLS destinations overlap unrelated material or ownership')
                material_paths[target_path] = identity
            if target['mode'] == 'direct':
                require(all(target[key] == item['source'][key] for key in ('certificate', 'key')),
                        'Direct material must reference the registered lineage')
        require(covered == set(item['consumers']), 'Missing material destinations')
    fields(value['legacy_hooks'], {'deploy', 'post'}, 'Both existing hook references must be explicit')
    for event, item in value['legacy_hooks'].items():
        fields(item, {'path', 'sha256'}, 'Invalid legacy hook reference')
        path(item['path'])
        require(item['path'] == LEGACY_HOOKS[event], 'Preserved hooks must use the source-owned neutral namespace')
        require(hexadecimal(item['sha256']), 'Legacy hook source must be pinned')
        require(item['path'] in value['host_files'] and item['path'] in value['artifacts']
                and value['artifacts'][item['path']]['sha256'] == item['sha256'],
                'Legacy hook must be a retained part of the pinned host closure')
    return value


def render(registry, pinned_artifacts):
    """Assemble attested existing profiles without rewriting BOX/Sally routing."""
    validate_registry(registry)
    manifest = managed_manifest(registry)
    selected = set(manifest['files']) - {REGISTRY}
    require(isinstance(pinned_artifacts, dict)
            and set(pinned_artifacts) in (set(registry['artifacts']), selected),
            'Provide the complete selected pinned configuration closure')
    for name, content in pinned_artifacts.items():
        require(type(content) is bytes and len(content) <= 16 * 1024 * 1024
                and digest(content) == registry['artifacts'][name]['sha256'], 'Pinned configuration differs')
    payloads = {name: pinned_artifacts[name] for name in manifest['files'] if name != REGISTRY}
    payloads[REGISTRY] = encoded(registry)
    return {'manifest': manifest, 'payloads': payloads, 'configuration_sha256': digest(encoded(manifest))}


def managed_manifest(registry):
    """Describe desired files without requiring already-retired source bytes."""
    validate_registry(registry)
    selected = set(registry['host_files'])
    for item in registry['consumers'].values():
        if item['status'] in ('active', 'pending_tls'): selected.update(item['vhosts'])
    # A still referenced link keeps its exact target; no broad tree ownership.
    selected.update(link_target(name, registry['links'][name]) for name in list(selected) if name in registry['links'])
    files = {name: copy.deepcopy(item) for name, item in registry['artifacts'].items() if name in selected}
    links = {name: copy.deepcopy(item) for name, item in registry['links'].items() if name in selected}
    body = encoded(registry)
    files[REGISTRY] = {'sha256': digest(body), 'mode': 0o600, 'uid': 0, 'gid': 0, 'retention': 'managed'}
    return {'format': 1, 'owner': 'host', 'files': files,
            'directories': copy.deepcopy(registry['directories']), 'links': links}


def retire_consumers(registry, owner):
    validate_registry(registry)
    require(owner in ('box', 'whatsapp'), 'Application retirement cannot retire host infrastructure')
    result = copy.deepcopy(registry)
    for item in result['consumers'].values():
        if item['owner'] == owner: item['status'] = 'retired'
    return result


def retirement_identity(registry, owner):
    """Bind a completed retirement to the same application's retained records."""
    selected = {name: copy.deepcopy(item) for name, item in registry['consumers'].items() if item['owner'] == owner}
    references = {name for item in selected.values() for name in item['vhosts']}
    links = {name: copy.deepcopy(item) for name, item in registry['links'].items() if name in references}
    references.update(link_target(name, item) for name, item in links.items())
    artifacts = {name: copy.deepcopy(item) for name, item in registry['artifacts'].items() if name in references}
    lineages = {name: copy.deepcopy(registry['lineages'][name]) for item in selected.values() for name in item['lineages']}
    return digest(encoded({'consumers': selected, 'artifacts': artifacts, 'links': links, 'lineages': lineages}))


def _receipt(root, engine, operation_id, value):
    target = STATE + '/operations/' + operation_id + '.json'
    current = root.snapshot(target)
    body = encoded(value)
    if current is not None and current['sha256'] == digest(body): return
    folders = (STATE, STATE + '/operations')
    before_dirs, after_dirs = {}, {}
    for folder in folders:
        existing = root.directory(folder)
        spec = {'mode': 0o700, 'uid': root.uid, 'gid': root.gid} if existing is None else existing
        require(spec == {'mode': 0o700, 'uid': root.uid, 'gid': root.gid}, 'Receipt directory protection differs')
        after_dirs[folder] = {**spec, 'retention': 'retain'}
        if existing is not None: before_dirs[folder] = after_dirs[folder]
    before = {'format': 1, 'owner': 'host', 'files': {} if current is None else
              {target: {**current, 'retention': 'managed'}}, 'directories': before_dirs}
    after = {'format': 1, 'owner': 'host', 'files': {target: {'sha256': digest(body), 'mode': 0o600,
             'uid': root.uid, 'gid': root.gid, 'retention': 'managed'}}, 'directories': after_dirs}
    derived = digest(encoded({'operation': operation_id, 'before': before, 'after': after}))[:32]
    engine.reconcile(root, operation_id=derived, before=before, after=after, payloads={target: body},
                     allowed_paths={target, *folders})


def _load_receipt(root, operation_id):
    require(hexadecimal(operation_id, 32), 'An exact operation identity is required')
    target = STATE + '/operations/' + operation_id + '.json'
    metadata = root.snapshot(target)
    if metadata is None: return None
    require(metadata['uid'] == root.uid and metadata['gid'] == root.gid and metadata['mode'] == 0o600,
            'Frontend receipt is not administratively protected')
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate frontend receipt field'); result[key] = value
        return result
    def number(value): raise FrontendError('Floating or non-finite receipt metadata is unsupported')
    content = root.read_bytes(target, max_bytes=8 * 1024 * 1024)
    require(root.snapshot(target) == metadata, 'Frontend receipt changed during admission')
    return json.loads(content, object_pairs_hook=unique, parse_float=number, parse_constant=number)


def _receipt_artifact(root, engine, name):
    """Recognize only an engine object proven to belong to a receipt write."""
    match = re.fullmatch(r'\.lifecycle-([0-9a-f]{32})-0\.(new|quarantine|quarantine\.tmp)', name)
    require(match is not None, 'Unknown object in frontend receipt census')
    engine_id, kind = match.groups()
    journal_path = '/var/lib/develative-host-lifecycle/host/operations/' + engine_id + '/journal.json'
    metadata = root.snapshot(journal_path)
    require(metadata is not None and metadata['mode'] == 0o600
            and metadata['uid'] == root.uid and metadata['gid'] == root.gid,
            'Receipt artifact lacks a protected engine journal')
    content = root.read_bytes(journal_path, max_bytes=8 * 1024 * 1024)
    require(root.snapshot(journal_path) == metadata, 'Receipt artifact journal changed')
    preliminary = json.loads(content)
    require(isinstance(preliminary, dict) and isinstance(preliminary.get('after'), dict),
            'Receipt artifact journal is malformed')
    files = preliminary['after'].get('files', {})
    require(isinstance(files, dict) and len(files) == 1, 'Receipt artifact journal has an unrelated write set')
    target = next(iter(files))
    require(re.fullmatch(re.escape(STATE + '/operations/') + r'[0-9a-f]{32}\.json', target),
            'Receipt artifact journal targets an unrelated file')
    allowed = {STATE, STATE + '/operations', target}
    journal = engine.inspect_operation(root, owner='host', operation_id=engine_id, allowed_paths=allowed)
    before, after = journal['before'], journal['after']
    require(set(before['files']) <= {target} and set(after['files']) == {target}
            and not before.get('links') and not after.get('links')
            and set(before['directories']) <= {STATE, STATE + '/operations'}
            and set(after['directories']) == {STATE, STATE + '/operations'},
            'Receipt artifact journal contains foreign objects')
    expected = (after if kind == 'new' else before)['files'].get(target)
    require(expected is not None and expected['mode'] == 0o600
            and expected['uid'] == root.uid and expected['gid'] == root.gid
            and root.snapshot(STATE + '/operations/' + name) ==
                {key: value for key, value in expected.items() if key != 'retention'},
            'Receipt artifact differs from its recorded bytes or ownership')
    return journal, target.rsplit('/', 1)[1][:-5], allowed


def guard_pending(root, operation_id=None, *, engine):
    """Admit one durable frontend operation, called while holding its lease.

    Prepared receipts are durable before effects. A different operation cannot
    supersede them after process death; only the original plan may roll forward.
    This census covers our own named metadata, never application history.
    """
    require(operation_id is None or hexadecimal(operation_id, 32), 'Invalid frontend admission identity')
    folder = STATE + '/operations'
    current = root.directory(folder)
    if current is None: return
    require(current == {'mode': 0o700, 'uid': root.uid, 'gid': root.gid}, 'Frontend receipt directory is unprotected')
    count, total, receipts, pending = 0, 0, [], {}
    with root._parent(folder + '/census') as (descriptor, _), os.scandir(descriptor) as entries:
        for entry in entries:
            count += 1
            info = entry.stat(follow_symlinks=False)
            total += info.st_size
            require(count <= 16384 and total <= 64 * 1024 * 1024,
                    'Frontend receipt census exceeds its bound; inspect administrative metadata without deleting it')
            require(stat.S_ISREG(info.st_mode), 'Unknown object in frontend receipt census')
            if not re.fullmatch(r'[0-9a-f]{32}\.json', entry.name):
                journal, selected, allowed = _receipt_artifact(root, engine, entry.name)
                receipts.append(selected)
                if journal['phase'] != 'committed':
                    require(selected == operation_id,
                            'Another durable frontend operation is pending; resume its original operation ID and plan')
                    pending[journal['operation_id']] = allowed
                continue
            receipts.append(entry.name[:-5])
    # Only finish a proven write of this operation's own receipt. The original
    # engine payload is immutable and was staged before these artifacts existed.
    for engine_id, allowed in pending.items():
        engine.resume(root, owner='host', operation_id=engine_id, allowed_paths=allowed)
    for selected in sorted(set(receipts)):
        record = _load_receipt(root, selected)
        require(isinstance(record, dict) and record.get('operation_id') == selected,
                'Malformed frontend receipt identity')
        if record.get('kind') == 'retire-renewals':
            require(set(record) == {'kind', 'operation_id', 'before', 'after', 'selected', 'owner', 'phase'}
                    | ({'quarantine'} if record.get('phase') == 'complete' else set())
                    and record.get('owner') in (None, 'box', 'whatsapp')
                    and record.get('phase') in ('prepared', 'complete') and isinstance(record.get('selected'), dict),
                    'Malformed renewal retirement receipt')
        else:
            require(set(record) == {'format', 'operation_id', 'plan_sha256', 'phase', 'before', 'after', 'allowed_paths', 'context'}
                    and type(record.get('format')) is int and record['format'] == 1
                    and hexadecimal(record.get('plan_sha256'))
                    and record.get('phase') in ('prepared', 'files_committed', 'validated', 'reloading', 'complete')
                    and isinstance(record.get('allowed_paths'), list) and isinstance(record.get('context'), dict),
                    'Malformed frontend operation receipt')
        require(isinstance(record.get('before'), dict) and isinstance(record.get('after'), dict),
                'Frontend receipt lacks its original manifests')
        require(record['phase'] == 'complete' or selected == operation_id,
                'Another durable frontend operation is pending; resume its original operation ID and plan')


def reconcile_edge(root, *, engine, operation_id, before, after, payloads, allowed_paths, adapter, context=None):
    """Execute filesystem + Apache phases, preserving an explicit reload receipt.

    The integration adapter must serialize these host-frontend effects with its
    dedicated operation lock. It must implement staged/active configuration
    validation and a bounded, idempotent reload of the pinned host unit.
    """
    context = {'kind': 'configuration'} if context is None else context
    guard_pending(root, operation_id, engine=engine)
    require(context == {'kind': 'configuration'} or
            (isinstance(context, dict) and set(context) == {'kind', 'owner', 'retired_owner_sha256'}
             and context['kind'] == 'retire-application' and context['owner'] in ('box', 'whatsapp')
             and hexadecimal(context['retired_owner_sha256'])) or
            (isinstance(context, dict) and set(context) == {'kind', 'source_revision'}
             and context['kind'] == 'tls' and hexadecimal(context['source_revision'])),
            'Invalid frontend operation context')
    wanted = digest(encoded({'before': before, 'after': after, 'allowed_paths': sorted(allowed_paths), 'context': context}))
    record = _load_receipt(root, operation_id)
    if record is None:
        record = {'format': 1, 'operation_id': operation_id, 'plan_sha256': wanted, 'phase': 'prepared',
                  'before': before, 'after': after, 'allowed_paths': sorted(allowed_paths), 'context': context}
        _receipt(root, engine, operation_id, record)
    require(record.get('plan_sha256') == wanted and record.get('operation_id') == operation_id,
            'Frontend operation is already bound to a different plan')
    require(record.get('phase') in ('prepared', 'files_committed', 'validated', 'reloading', 'complete'),
            'Unknown frontend operation phase; inspect without resetting it')
    configuration_sha = digest(encoded(after))
    if record['phase'] == 'complete':
        require(adapter.validate_active(after) == {'ok': True, 'configuration_sha256': configuration_sha},
                'Completed frontend operation no longer matches the active configuration')
        return record
    if record['phase'] == 'prepared':
        evidence = adapter.validate_staged(after, payloads)
        require(evidence == {'ok': True, 'configuration_sha256': configuration_sha},
                'Staged Apache configuration is not validated')
        engine.reconcile(root, operation_id=digest(('frontend-files:' + operation_id).encode())[:32],
                         before=before, after=after, payloads=payloads, allowed_paths=allowed_paths)
        record['phase'] = 'files_committed'; _receipt(root, engine, operation_id, record)
    evidence = adapter.validate_active(after)
    require(evidence == {'ok': True, 'configuration_sha256': configuration_sha},
            'Active Apache configuration differs; no reload was requested')
    if record['phase'] != 'reloading':
        record['phase'] = 'validated'; _receipt(root, engine, operation_id, record)
        record['phase'] = 'reloading'; _receipt(root, engine, operation_id, record)
    # A retry after loss of the response repeats only this documented idempotent
    # reload; it never claims physical exactly-once or replays certificate issuance.
    require(adapter.reload_apache(configuration_sha) is True, 'Apache reload did not complete')
    record['phase'] = 'complete'; _receipt(root, engine, operation_id, record)
    return record


def handle_deploy_hook(registry, *, lineage, renewed_domains, adapter):
    """Dispatch a successful existing renewal, never issue or renew a certificate.

    The finite adapter pins legacy hook bytes, validates source certificates
    and key correspondence, durably deploys each copy as a pair, and performs
    the same staged validation/reload protocol as configuration reconciliation.
    """
    validate_registry(registry)
    path(lineage)
    require(isinstance(renewed_domains, str), 'Missing renewed domains')
    names = renewed_domains.split()
    received = domains(names)
    if lineage not in registry['lineages']:
        pending = [item for item in registry['consumers'].values() if item['status'] == 'pending_tls'
                   and received == set(item['domains'])]
        if pending:
            # This event does not attest a lineage or install anything. The
            # finite provisioning adapter must validate issuance and register
            # the exact lineage before the consumer becomes TLS-active.
            return {'status': 'pending_tls', 'deployed': False, 'reason': 'await-explicit-lineage-binding'}
        require(not received.intersection({host for item in registry['consumers'].values() for host in item['domains']}),
                'Known consumer domains were presented under a different lineage')
        # Preserve other services by invoking the exact attested legacy branch,
        # rather than inventing its allowlist or treating unknown events as WA.
        return adapter.legacy_deploy(registry['legacy_hooks']['deploy'], lineage, names)
    selected = registry['lineages'][lineage]
    require(received == set(selected['domains']), 'Renewed lineage and exact SAN set differ')
    active = [item for item in selected['destinations']
              if registry['consumers'][item['consumer']]['status'] == 'active']
    if not active: return {'status': 'retained', 'deployed': False, 'reason': 'no-active-consumers'}
    proof = adapter.validate_lineage(lineage, selected['source'], sorted(received))
    fields(proof, {'domains', 'certificate_sha256', 'key_matches', 'source_revision'}, 'Incomplete certificate evidence')
    require(domains(proof['domains']) == received and proof['key_matches'] is True
            and hexadecimal(proof['certificate_sha256']) and hexadecimal(proof['source_revision']),
            'Renewed certificate and private key have not been validated together')
    outcome = adapter.deploy_materials(lineage, selected['source'], active, proof, registry['apache'])
    require(isinstance(outcome, dict) and outcome.get('status') == 'complete'
            and outcome.get('source_revision') == proof['source_revision'],
            'Material deployment/reload is incomplete; preserve the operation for recovery')
    return outcome


def handle_post_hook(registry, *, adapter):
    """Keep the post-hook event separate from per-lineage deploy events.

    Never call this from handle_deploy_hook: Certbot owns the original event
    ordering and other services' post actions must not be multiplied per cert.
    The integration adapter verifies the exact pinned source before delegation.
    """
    validate_registry(registry)
    return adapter.legacy_post(registry['legacy_hooks']['post'])


def invoke_pinned_legacy(root, hook, *, event, lineage=None, renewed_domains=None, runner):
    """Verify protected source bytes before the integration runner executes it.

    The runner receives one exact executable and named Certbot inputs, never a
    shell command string. Other environment preservation is its host contract.
    """
    fields(hook, {'path', 'sha256'}, 'Invalid legacy hook reference')
    selected = path(hook['path'])
    require(hexadecimal(hook['sha256']) and event in ('deploy', 'post'), 'Invalid hook invocation')
    metadata = root.snapshot(selected)
    require(metadata is not None and metadata['sha256'] == hook['sha256']
            and metadata['uid'] == root.uid and not metadata['mode'] & 0o022
            and metadata['mode'] & 0o100, 'Legacy hook no longer matches its protected source')
    environment = {}
    if event == 'deploy':
        path(lineage); domains(renewed_domains)
        environment = {'RENEWED_LINEAGE': lineage, 'RENEWED_DOMAINS': ' '.join(renewed_domains)}
    else:
        require(lineage is None and renewed_domains is None, 'Post hooks are not per-lineage deploy events')
    return runner.execute_legacy(selected, environment)


def deploy_materials(root, *, engine, operation_id, targets, proof, certificate, key,
                     allowed_paths, adapter):
    """Publish actual certificate/key copies through the engine before reload.

    Source resolution belongs to the trusted adapter because Certbot live files
    are links. Bytes passed here must still match its pinned source revision;
    a source change requires a new verification, never a stale copy plus reload.
    Only tests with synthetic key material call this code in the Cloud.
    """
    require(isinstance(targets, list) and targets, 'Explicit certificate targets are required')
    fields(proof, {'domains', 'certificate_sha256', 'key_matches', 'source_revision'}, 'Incomplete certificate proof')
    domains(proof['domains'])
    require(type(certificate) is bytes and type(key) is bytes
            and 0 < len(certificate) <= 1024 * 1024 and 0 < len(key) <= 1024 * 1024,
            'Invalid bounded certificate material')
    revision = digest(encoded({'certificate_sha256': digest(certificate), 'key_sha256': digest(key)}))
    require(proof.get('certificate_sha256') == digest(certificate)
            and proof.get('source_revision') == revision and proof.get('key_matches') is True,
            'Certificate source changed after verification')
    require(adapter.validate_certificate_pair(certificate, key, proof['domains']) is True,
            'Certificate/key pair validation failed')
    before = {'format': 1, 'owner': 'host', 'files': {}, 'directories': {}}
    after = copy.deepcopy(before)
    payloads = {}
    for target in targets:
        fields(target, {'consumer', 'mode', 'certificate', 'key', 'uid', 'gid',
                        'certificate_mode', 'key_mode'}, 'Invalid material target')
        require(target['mode'] in ('direct', 'copy'), 'Invalid material deployment mode')
        require(path(target['certificate']) != path(target['key'])
                and all(type(target[field]) is int and 0 <= target[field] < 2**31 for field in ('uid', 'gid'))
                and type(target['certificate_mode']) is int and target['certificate_mode'] in (0o600, 0o640, 0o644)
                and type(target['key_mode']) is int and target['key_mode'] in (0o600, 0o640),
                'Material destinations or permissions are unsafe')
        if target['mode'] == 'direct': continue
        for kind, content in (('certificate', certificate), ('key', key)):
            name = path(target[kind])
            require(name in allowed_paths, 'Material destination is outside the independent path policy')
            parent = str(PurePosixPath(name).parent)
            require(root.directory(parent) is not None, 'Certificate parent must already be provisioned and protected')
            current = root.snapshot(name)
            if current is not None: before['files'][name] = {**current, 'retention': 'managed'}
            spec = {'sha256': digest(content), 'mode': target[kind + '_mode'],
                    'uid': target['uid'], 'gid': target['gid'], 'retention': 'managed'}
            require(name not in after['files'] or after['files'][name] == spec, 'Conflicting material copies')
            after['files'][name] = spec
            payloads[name] = content
    previous = _load_receipt(root, operation_id)
    if previous is not None:
        require(previous.get('after') == after and previous.get('context') ==
                {'kind': 'tls', 'source_revision': revision}, 'Material operation belongs to another source revision')
        before = previous['before']
    outcome = reconcile_edge(root, engine=engine, operation_id=operation_id, before=before,
                             after=after, payloads=payloads, allowed_paths=allowed_paths, adapter=adapter,
                             context={'kind': 'tls', 'source_revision': revision})
    return {'status': outcome['phase'], 'source_revision': revision,
            'copied_paths': sorted(payloads), 'certificate_sha256': digest(certificate)}
