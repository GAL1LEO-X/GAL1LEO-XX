"""Concrete host adapter for the WhatsApp administration handoff.

The profile is a root-approved, digest-bound inventory, not a discovery guess.
It contains no credentials and never authorizes an arbitrary command. Reads
and writes may be rooted in an isolated directory; real commands require '/'.
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
import hashlib
import json
from pathlib import Path
import re
import time

from host.lifecycle import evidence, filesystem, services

STATE = installation_path('/var/lib/develative-deploy/whatsapp')
JOURNALS = {'transaction': STATE + '/transaction.json',
            'backup': STATE + '/backup.json', 'pending': STATE + '/pending.json'}
GATE = installation_path('/var/lib/develative-release-gates/whatsapp')
# Source-finite phases from release_transaction.py; do not import generation
# helpers while the administrative admission barrier is closed.
TRANSACTION_PHASES = frozenset({'prepared', 'stopped', 'frozen', 'switched',
    'committed', 'published', 'rollback-committed', 'rolled-back', 'rollback-failed'})
BACKUP_PHASES = frozenset({'prepared', 'copying', 'recovering', 'recovery-failed', 'restored'})
LEGACY_RECEIVER = installation_path('/usr/local/lib/develative-deploy/whatsapp/github_release.py')
GLOBAL_RECOVERY = installation_path('/usr/local/lib/develative-deploy/release_recover.py')
OWNER_RECORD = installation_path('/etc/develative-deploy/recovery-owners/whatsapp.json')
BOOTSTRAP_ENTRY = installation_path('/usr/local/lib/develative-deploy/whatsapp-bootstrap/release_entry.py')
BOOTSTRAP_ADMIN = installation_path('/usr/local/lib/develative-deploy/whatsapp-bootstrap/release_admin.py')
BACKUP_ENTRY = installation_path('/srv/openai-codex/projects/whatsapp-personal/scripts/backup_runtime.py')
LEGACY_BACKUP_SHA256 = '8c298c576b131ca8beb82fa8733c7a78693e549f7e28e6061030eb340699bd04'
LEGACY_BACKUP_GUARD = b"raise SystemExit('WhatsApp legacy backup admission closed for administrative handoff')\n"
TENANT_ENTRY = installation_path('/srv/openai-codex/projects/whatsapp-personal/scripts/tenant_admin.py')
PROVISION_ENTRY = installation_path('/srv/openai-codex/projects/whatsapp-personal/scripts/provision_host.py')
LEGACY_DESTINATIONS = {
    BACKUP_ENTRY: (LEGACY_BACKUP_SHA256, LEGACY_BACKUP_GUARD),
    TENANT_ENTRY: ('7cd2e214aa74175dc926c542e8a65bcc1bde68d6554431eb39987484e059ecfa',
        b"raise SystemExit('WhatsApp legacy tenant admission closed for administrative handoff')\n"),
    PROVISION_ENTRY: ('d1212c5352141d9b781f8c67f23ee842a09cb47746ec5fb6d600eac6df4d23aa',
        b"raise SystemExit('WhatsApp legacy provisioning admission closed for administrative handoff')\n"),
}
BACKUP_TIMER = installation_path('whatsapp-personal-backup.timer')
BACKUP_SERVICE = installation_path('whatsapp-personal-backup.service')


def backup_execution_contract():
    """Finite public command identity, using the PRO8 typed projection format."""
    empty = {'count': 0, 'identity_sha256': hashlib.sha256(evidence.canonical([]) + b'\n').hexdigest()}
    command = [{'path': '/usr/bin/flock', 'argv': ['/usr/bin/flock', '-n',
        installation_path('/run/lock/whatsapp-personal-backup.lock'),
        installation_path('/srv/openai-codex/projects/whatsapp-personal/.venv/bin/python'), BACKUP_ENTRY],
        'ignore_errors': False}]
    return {key: ({'count': 1, 'identity_sha256': hashlib.sha256(evidence.canonical(command) + b'\n').hexdigest()}
                  if key == 'ExecStart' else dict(empty)) for key in evidence.EXECUTION_PROPERTIES}
# These are reviewed gate implementations, not hashes supplied by an invoker.
# A source change intentionally requires reviewing and updating this contract.
OWNER_GATE_SOURCES = {
    LEGACY_RECEIVER: ('release_receiver_entry.py', 'd3cb0690df8140b1d38e37da5641d82bd0adadb6dc264525d4ca82bf7d134d4b'),
    BOOTSTRAP_ENTRY: ('release_entry.py', '4576761c151b4af07ae297e723a39adc4c17d3dac24cf9381aa04c9e2f890626'),
    BOOTSTRAP_ADMIN: ('release_admin.py', '169e7c1f5c0c1326199c678686a7fd8845e2ed94656b96f120333a47858fa4f3'),
    BACKUP_ENTRY: ('backup_runtime.py', '04eb16f49393d1e80225c7637ddacc11a490b1245323b4e62cd67546c922de6b'),
}
PREVIOUS_OWNER_GATE_SHA256 = {'release_receiver_entry.py': '9ebd34094e71368d972e6fac5012cdfea93b2c78fcebfc0df1554d6f9f723e29', 'release_entry.py': 'f540cef73e5da2c570520df671183a18d4a2ed8ca32dd2a21bb60884cccf4f68', 'release_admin.py': '6ea770e8f41d2d8ef7e4d95d1d82e7ef34f10aadc162ee69eff37dda5b2a7679', 'backup_runtime.py': '53acae1b1df5930da73b99a39f8f45e9cc52532e051ab09d4ee3ff6bd17c03db'}
# Reviewed configured sources retain their owner/generation admission. Unlike
# the older fixed-layout source above, each requires the protected layout below.
# The 0.6.0 entrypoint predates the early no-bytecode guard, so an upgrade must
# still recognize its exact bytes while draining the previous generation.
PREVIOUS_CONFIGURED_OWNER_GATE_SHA256 = {
    'backup_runtime.py': frozenset({
        # 0.7.0 through 26b7857: same protected admission, before preserving
        # bridge and gateway service drop-ins in the private snapshot.
        'df04588602f4a9d7a8663a75b6548e5b72003d1be74537ed73580dfe4e37a99f',
        'abd4d9ad81e159a41213166a3edd2a2f9dae9db341b43adef85f3d0d1787f457',
        '00eb65ab1e025abd0a6ee6fffd39aa715d3539c52466b429a10fc3a95c854702',
        'd6d9810816d82d8bf5932be63f3da57375b19b095bd59c504ecd4fead8a3b57a',
    }),
}
# These current gates execute the adjacent layout before checking their owner.
# Its implementation is therefore part of the reviewed admission contract,
# rather than merely an arbitrary hash declared by the installation inventory.
OWNER_GATE_LAYOUT_SHA256 = 'cf6a0ee39430ac2cff3121cdf616d53b267229904b8ff2b4b9ae099b2e4c9531'
# Reviewed pre-roster layouts retain their owner admission behavior. The
# current source additionally verifies the protected append-only allocation.
PREVIOUS_OWNER_GATE_LAYOUT_SHA256 = frozenset({
    # 0.7.0 through 26b7857: protected roster/identity checks unchanged;
    # the new source additionally rejects two reserved initial slugs.
    '049be515b1244c421b731cab52d18c09c3eedf5c2a8513aece171f6c47a3c3ef',
    '3caf30a82271742a8ebd1943f77371a0ac45c204986a0494235c1368a93c42d1',
    '5d4c0a0534769d33f4693f5ae192104b3631d648be21d6f8bd50099b54d9f98e',
})
OWNER_GATE_LAYOUT_DEPENDENCIES = {
    BOOTSTRAP_ENTRY: str(Path(BOOTSTRAP_ENTRY).with_name('installation_layout.py')),
    BOOTSTRAP_ADMIN: str(Path(BOOTSTRAP_ADMIN).with_name('installation_layout.py')),
    BACKUP_ENTRY: str(Path(BACKUP_ENTRY).with_name('installation_layout.py')),
}
INVOKER_CONTRACTS = {
    'legacy-receiver': (LEGACY_RECEIVER, 'legacy-main-guard', ('ssh-forced-command', 'systemd')),
    'global-recovery': (GLOBAL_RECOVERY, 'dispatcher-cut', ('systemd',)),
    'owner-receiver': (LEGACY_RECEIVER, 'owner-admission', ('ssh-forced-command', 'systemd')),
    'owner-backup': (BACKUP_ENTRY, 'owner-pin', ('systemd',)),
    'dedicated-recovery': (BOOTSTRAP_ENTRY, 'recovery-retirement', ('systemd',)),
}


def require(condition, message):
    if not condition:
        raise filesystem.LifecycleError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field in host inventory')
        result[key] = value
    return result


def decode_json(content):
    try:
        return json.loads(content, object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise filesystem.LifecycleError('Invalid protected JSON input') from error


def load_json(root, path):
    return decode_json(root.read_bytes(path, max_bytes=8 * 1024 * 1024))


def attested_json(root, item):
    before = root.snapshot(item['path'])
    require(before is not None and before['uid'] == root.uid and not before['mode'] & 0o022,
            'Inventory attestation must be administratively protected')
    content = root.read_bytes(item['path'], max_bytes=8 * 1024 * 1024)
    require(hashlib.sha256(content).hexdigest() == item['sha256'], 'Protected inventory attestation changed')
    require(root.snapshot(item['path']) == before, 'Inventory attestation metadata or contents changed')
    return decode_json(content)


def runtime_retirement_receipt(root, plan, plan_digest):
    """Read the independent runtime proof before removing its administrator.

    No runtime helper is imported: its installed source may already be in the
    exact forward-removal transaction. The host-owned journal remains retained.
    """
    requested = plan.get('runtime_retirement')
    require(plan.get('mode') == 'remove' and isinstance(requested, dict)
            and set(requested) == {'operation_id'}
            and isinstance(requested['operation_id'], str)
            and re.fullmatch('[0-9a-f]{32}', requested['operation_id']),
            'Administrative removal requires an exact runtime retirement operation')
    path = STATE + '/runtime-retirement-' + requested['operation_id'] + '.json'
    metadata = root.snapshot(path)
    require(metadata is not None and metadata['uid'] == root.uid and metadata['gid'] == root.gid
            and metadata['mode'] == 0o600, 'Verified protected runtime retirement journal is required')
    value = attested_json(root, {'path': path, 'sha256': metadata['sha256']})
    require(isinstance(value, dict) and set(value) == {'format', 'plan_sha256', 'admin_plan_sha256',
                'operation_id', 'phase', 'intent', 'processes', 'receipts'}
            and value['format'] == 'whatsapp-runtime-retirement-v1'
            and value['admin_plan_sha256'] == plan_digest
            and value['operation_id'] == requested['operation_id']
            and evidence.hex_digest(value['plan_sha256'])
            and isinstance(value['processes'], list) and isinstance(value['receipts'], dict)
            and value['receipts'], 'Runtime retirement identity or journal shape differs')
    require(value['phase'] == 'verified' and value['intent'] is None,
            'Runtime retirement has not completed; preserve the administrative helpers and owner')
    return {'operation_id': requested['operation_id'], 'sha256': metadata['sha256'], 'phase': 'verified'}


def validate_transaction_journal(value):
    """Recognize persisted 0.4.9 through 0.6.0 records without importing code.

    A terminal phase alone is insufficient evidence that recovery is closed.
    This validates structure and internal identities, never reads old backups
    or treats a historical record as authority to restore data.
    """
    fields = {'root', 'candidate', 'record', 'version', 'sourceCommit', 'previousVersion',
              'selected', 'registered', 'before', 'activeUnits', 'allUnits', 'databases',
              'dropins', 'frozen', 'phase'}
    require(isinstance(value, dict) and isinstance(value.get('phase'), str)
            and value['phase'] in TRANSACTION_PHASES,
            'Unknown activation journal phase')
    require(set(value) in (fields, fields | {'activationError'}),
            'Invalid activation journal fields')
    for name in ('root', 'candidate', 'record'):
        evidence.path_name(value[name])
    require(value['root'] == installation_path('/srv/openai-codex/projects/whatsapp-personal')
            and isinstance(value['sourceCommit'], str) and re.fullmatch('[0-9a-f]{40}', value['sourceCommit'])
            and all(isinstance(value[key], str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value[key])
                    for key in ('version', 'previousVersion'))
            and type(value['frozen']) is bool, 'Invalid activation journal identity')
    require('activationError' not in value or (value['activationError'] == 'activation_not_verified'
            and value['phase'] == 'committed'), 'Invalid activation error state')
    require(isinstance(value['registered'], list) and 0 < len(value['registered']) <= 256
            and isinstance(value['selected'], list) and value['selected'], 'Invalid activation tenant list')
    first_registered = value['registered'][0]
    require(isinstance(first_registered, dict), 'Invalid activation tenant identity')
    tenant_fields = {'slug', 'unit', 'base', 'port', 'config', 'wrapper'}
    if 'auth_mode' in first_registered:
        tenant_fields.add('auth_mode')
    instances = {}
    for item in value['registered']:
        require(isinstance(item, dict) and set(item) == tenant_fields
                and isinstance(item['slug'], str) and re.fullmatch('[a-z][a-z0-9-]{1,19}', item['slug'])
                and item['slug'] not in instances, 'Invalid activation tenant identity')
        require('auth_mode' not in item or (isinstance(item['auth_mode'], str)
                and item['auth_mode'] in ('managed-authelia', 'external-oidc')),
                'Invalid activation authentication mode')
        base = installation_profile().service(item['slug'])
        wrapper = value['root'] + ('/scripts/as-user' if item['slug'] == 'personal'
                                   else '/private/tenants/' + item['slug'] + '/as-user')
        require(item['base'] == base and item['unit'] == base + '.service'
                and item['config'] == installation_profile().instance_paths(item['slug'])['configuration'] + '/config.toml' and item['wrapper'] == wrapper
                and valid_port(item['slug'],item['port']),
                'Activation tenant paths or port differ')
        instances[item['slug']] = item
    selected = value['selected']
    require(all(isinstance(item, dict) and item.get('slug') in instances
                and item == instances[item['slug']] for item in selected)
            and len({item['slug'] for item in selected}) == len(selected)
            and len({item['port'] for item in instances.values()}) == len(instances)
            and value['activeUnits'] == [item['unit'] for item in selected]
            and value['allUnits'] == [item['unit'] for item in value['registered']]
            and isinstance(value['before'], dict)
            and set(value['before']) == {item['slug'] for item in selected}
            and all(isinstance(state, str) and state in
                    ('WORKING', 'STOPPED', 'STARTING', 'SCAN_QR_CODE', 'FAILED')
                    for state in value['before'].values()),
            'Activation selection or prior state is inconsistent')
    require(isinstance(value['dropins'], list) and len(value['dropins']) == len(instances),
            'Activation drop-in inventory is incomplete')
    for entry, item in zip(value['dropins'], value['registered']):
        require(isinstance(entry, dict) and set(entry) == {'path', 'before'}
                and entry['path'] == '/etc/systemd/system/' + item['unit'] + '.d/70-release-runtime.conf'
                and (entry['before'] is None or isinstance(entry['before'], str)),
                'Activation drop-in identity differs')
    require(isinstance(value['databases'], list) and len(value['databases']) <= len(instances),
            'Invalid activation database inventory')
    for entry, item in zip(value['databases'], value['registered']):
        require(isinstance(entry, dict) and set(entry) == {'path', 'backup', 'sha256', 'migrated', 'migration'}
                and entry['path'] == installation_profile().instance_paths(item['slug'])['state'] + '/archive.sqlite'
                and entry['backup'] == item['slug'] + '-before.sqlite'
                and entry['migrated'] == item['slug'] + '-candidate.sqlite'
                and evidence.hex_digest(entry['sha256']) and isinstance(entry['migration'], dict),
                'Activation database identity differs')
        migration = entry['migration']
        require(set(migration) == {'fromSchema', 'toSchema', 'integrity', 'recordIdentitiesPreserved'}
                and type(migration['fromSchema']) is int and type(migration['toSchema']) is int
                and 6 <= migration['fromSchema'] <= migration['toSchema']
                and migration['integrity'] == 'ok' and migration['recordIdentitiesPreserved'] is True,
                'Activation migration evidence is incomplete or inconsistent')
    require(not value['frozen'] or len(value['databases']) == len(instances),
            'Frozen activation is missing a database')
    require(value['phase'] not in ('frozen', 'switched', 'committed', 'published') or value['frozen'],
            'Activation phase lacks a completed freeze')


def valid_port(slug,port):
    profile=installation_profile()
    return (type(port) is int and (8820 <= port <= 8998 and port % 2 == 0
            if profile.compatibility else port==profile.instance_ports(slug)['bridge']))


def validate_backup_journal(value):
    fields = {'format', 'id', 'root', 'version', 'context', 'selected', 'components',
              'phase', 'copies', 'servicesRestored', 'failures', 'worker'}
    require(isinstance(value, dict) and set(value) == fields
            and value['format'] == 'whatsapp-backup-recovery-v1'
            and isinstance(value['id'], str) and re.fullmatch('[0-9a-f]{32}', value['id'])
            and value['root'] == installation_path('/srv/openai-codex/projects/whatsapp-personal')
            and isinstance(value['version'], str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value['version'])
            and isinstance(value['phase'], str) and value['phase'] in BACKUP_PHASES
            and type(value['servicesRestored']) is bool
            and (value['phase'] == 'restored') == value['servicesRestored'],
            'Invalid backup recovery journal')
    require(isinstance(value['selected'], list) and 0 < len(value['selected']) <= 256
            and all(isinstance(slug, str) and re.fullmatch('[a-z][a-z0-9-]{1,19}', slug)
                    for slug in value['selected'])
            and len(set(value['selected'])) == len(value['selected'])
            and isinstance(value['copies'], dict) and set(value['copies']) == set(value['selected'])
            and isinstance(value['context'], dict) and value['context']
            and isinstance(value['failures'], list)
            and all(isinstance(item, str) for item in value['failures'])
            and (not value['servicesRestored'] or not value['failures']),
            'Invalid backup recovery selection or outcome')
    expected_context = {value['root'] + '/private/tenants.json', value['root'] + '/sally_whatsapp/__init__.py'}
    for slug in value['selected']:
        base = installation_profile().service(slug)
        expected_context.update((installation_profile().instance_paths(slug)['configuration'] + '/config.toml', value['root'] +
            ('/scripts/as-user' if slug == 'personal' else '/private/tenants/' + slug + '/as-user')))
    require(set(value['context']) == expected_context, 'Backup context does not cover the exact selected instances')
    for name, sha256 in value['context'].items():
        evidence.path_name(name)
        require(evidence.hex_digest(sha256), 'Invalid backup context hash')
    for item in value['copies'].values():
        require(isinstance(item, dict) and set(item) == {'path', 'complete'}
                and type(item['complete']) is bool and (item['path'] is not None or not item['complete']),
                'Invalid backup copy status')
        if item['path'] is not None:
            evidence.path_name(item['path'])
    components = value['components']
    require(isinstance(components, list) and len(components) == 2 * len(value['selected'])
            and all(isinstance(item, dict) and set(item) == {'name', 'kind', 'command', 'unit', 'port', 'config', 'active'}
                    and isinstance(item['name'], str) and type(item['active']) is bool
                    and item['kind'] in ('gateway', 'bridge')
                    and isinstance(item['command'], list) and all(isinstance(arg, str) for arg in item['command'])
                    and isinstance(item['unit'], str) and type(item['port']) is int
                    and isinstance(item['config'], str) for item in components)
            and {item['name'] for item in components} == {slug + '.' + kind
                for slug in value['selected'] for kind in ('gateway', 'bridge')},
            'Invalid backup recovery components')
    ports = set()
    for index, slug in enumerate(value['selected']):
        gateway, bridge = components[2 * index:2 * index + 2]
        base = installation_profile().service(slug)
        wrapper = value['root'] + ('/scripts/as-user' if slug == 'personal'
                                   else '/private/tenants/' + slug + '/as-user')
        port = bridge['port']
        require(valid_port(slug,port) and port not in ports,
                'Backup bridge port is invalid or duplicated')
        ports.add(port)
        for item, kind, command, unit, selected_port in (
                (gateway, 'gateway', [wrapper, 'systemctl', '--user'], 'whatsapp-waha.service', port + 1 if installation_profile().compatibility else installation_profile().instance_ports(slug)['gateway']),
                (bridge, 'bridge', ['systemctl'], base + '.service', port)):
            require({key: entry for key, entry in item.items() if key != 'active'} == {
                'name': slug + '.' + kind, 'kind': kind, 'command': command, 'unit': unit,
                'port': selected_port, 'config': installation_profile().instance_paths(slug)['configuration'] + '/config.toml'},
                'Backup component does not match its selected instance and role')
    worker = value['worker']
    require(worker is None or (isinstance(worker, dict) and set(worker) == {'pid', 'session', 'start', 'boot'}
            and type(worker['pid']) is int and worker['pid'] > 0
            and type(worker['session']) is int and worker['session'] == worker['pid']
            and isinstance(worker['start'], str) and re.fullmatch('[0-9]+', worker['start'])
            and isinstance(worker['boot'], str)
            and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', worker['boot'])),
            'Invalid backup worker identity')


def validate_profile(profile):
    fields = {'format', 'attestation', 'retirement_attestation', 'stages', 'final_manifest',
              'invokers', 'retained_manifest', 'generation_id'}
    require(isinstance(profile, dict) and set(profile) == fields
            and profile['format'] == 'whatsapp-host-inventory-v1',
            'Invalid WhatsApp host inventory')
    require(evidence.hex_digest(profile['generation_id']), 'Invalid inventoried generation')
    attestation = profile['attestation']
    require(isinstance(attestation, dict) and set(attestation) == {'path', 'sha256'},
            'Root inventory attestation is required')
    evidence.path_name(attestation['path'])
    require(evidence.hex_digest(attestation['sha256']), 'Invalid inventory attestation digest')
    retirement = profile['retirement_attestation']
    if retirement is not None:
        require(isinstance(retirement, dict) and set(retirement) == {'path', 'sha256'},
                'Invalid final reference attestation')
        evidence.path_name(retirement['path'])
        require(evidence.hex_digest(retirement['sha256']) and retirement['path'] != attestation['path'],
                'Final reference attestation must be separately pinned')
    bindings = profile['invokers']
    require(isinstance(bindings, list) and len(bindings) <= 256, 'Invalid invoker inventory')
    seen = set()
    for binding in bindings:
        require(isinstance(binding, dict) and set(binding) ==
                {'id', 'kind', 'executable', 'argv_sha256', 'reference', 'role',
                 'entrypoint', 'launch_mode', 'gate'}, 'Invalid invoker binding')
        require(isinstance(binding['id'], str) and binding['id'] and binding['id'] not in seen
                and len(binding['id']) <= 128,
                'Invoker identity must be unique and explicit')
        seen.add(binding['id'])
        evidence.path_name(binding['executable']); evidence.path_name(binding['reference'])
        require(evidence.hex_digest(binding['argv_sha256']), 'Invalid invocation digest')
        require(isinstance(binding['role'], str) and binding['role'] in INVOKER_CONTRACTS,
                'Unsupported initiator: no implemented admission contract exists for this role')
        entrypoint, mechanism, kinds = INVOKER_CONTRACTS[binding['role']]
        executables = ('/usr/bin/python3', entrypoint)
        if binding['role'] == 'owner-backup':
            executables += (installation_path('/srv/openai-codex/projects/whatsapp-personal/.venv/bin/python'),)
        require(binding['kind'] in kinds and binding['entrypoint'] == entrypoint
                and binding['launch_mode'] == ('python-main-recovery' if binding['role'] == 'dedicated-recovery' else 'python-main')
                and binding['executable'] in executables,
                'Invoker launch does not match a supported exact entrypoint')
        gate_path = OWNER_RECORD if binding['role'] in ('owner-receiver', 'owner-backup', 'dedicated-recovery') else entrypoint
        require(binding['gate'] == {'mechanism': mechanism, 'path': gate_path},
                'Invoker has no supported exact admission gate')
    require(isinstance(profile['stages'], dict) and profile['stages'], 'Stage inventories are required')
    for stage, inventory in profile['stages'].items():
        require(stage in ('inventory', 'legacy_work', 'legacy_all', 'previous', 'installed', 'removal')
                and isinstance(inventory, dict) and set(inventory) == {'scope', 'manifest', 'units'},
                'Unknown evidence stage')
        evidence.digest_inventory(inventory['scope'], inventory['manifest'], inventory['units'])
    filesystem.validate_manifest(profile['final_manifest'])
    filesystem.validate_manifest(profile['retained_manifest'])
    return evidence.digest(profile)


def validate_admission(profile, plan):
    """Link attested launch routes to source-finite actions and observations.

    This verifies the declared mapping. Its completeness, including an SSH
    forced command's actual route, remains root's explicit attestation; argv
    hashes and roles alone are not observational proof of that mapping.
    """
    bindings = profile['invokers']
    require(plan['mode'] in ('fresh', 'legacy', 'upgrade', 'remove'), 'Unknown administration mode')
    if plan['mode'] == 'fresh':
        require(not bindings,
                'Fresh installation cannot have existing administrative initiators')
        return
    if plan['mode'] == 'remove':
        return validate_removal_admission(profile, plan)
    if plan['mode'] == 'upgrade':
        return validate_upgrade_admission(profile, plan)
    require({item['role'] for item in bindings} == {'legacy-receiver', 'global-recovery'},
            'Legacy handoff must explicitly inventory receiver and global recovery routes')
    validate_guarded_destinations(profile, plan)
    validate_guarded_backup(profile)
    stages = profile['stages']
    require({'inventory', 'legacy_work', 'legacy_all'} <= set(stages),
            'Legacy admission requires all three source and process inventories')
    actions = plan.get('actions', {})
    require({'guard_ingress', 'cut_dispatcher'} <= set(actions),
            'Legacy admission requires receiver guard and dispatcher cut actions')
    guard, cut = actions['guard_ingress'], actions['cut_dispatcher']
    for action, path in ((guard, LEGACY_RECEIVER), (cut, GLOBAL_RECOVERY)):
        paths = {LEGACY_RECEIVER, *LEGACY_DESTINATIONS} if path == LEGACY_RECEIVER else {GLOBAL_RECOVERY}
        require(isinstance(action, dict) and all(isinstance(action.get(side), dict)
                and set(action[side].get('files', {})) == paths
                for side in ('before', 'after')), 'Admission action does not cover its exact entrypoint')
        require(action['before']['files'][path]['sha256'] != action['after']['files'][path]['sha256'],
                'Admission action does not change its entrypoint')

    def covered(stage, path, expected, *, census=True):
        item = stages[stage]
        require(path in item['manifest']['files'], 'Admission source is absent from a stage inventory')
        source = item['manifest']['files'][path]
        require(all(source[key] == expected[key] for key in ('sha256', 'mode', 'uid', 'gid')),
                'Admission source digest or metadata differs from its stage action')
        if census:
            require(path in item['scope']['script_paths'],
                    'Admission entrypoint is missing from the exact process census')

    for stage in ('inventory', 'legacy_work', 'legacy_all'):
        covered(stage, LEGACY_RECEIVER, guard['before' if stage == 'inventory' else 'after']['files'][LEGACY_RECEIVER])
        # The global recovery remains executable through legacy_work so it can
        # reconcile existing journals. Only after the cut must its old parents
        # and children drain; its BOX service is never disabled by this adapter.
        covered(stage, GLOBAL_RECOVERY, cut['after' if stage == 'legacy_all' else 'before']['files'][GLOBAL_RECOVERY],
                census=stage != 'legacy_work')
    for binding in bindings:
        if binding['kind'] == 'systemd':
            require(any(unit['fragment_path'] == binding['reference']
                        for unit in stages['inventory']['units'].values()),
                    'Automatic initiator is absent from the initial unit inventory')


def validate_guarded_destinations(profile, plan):
    """Recompute the three exact preimages, closed stages and pinned successors."""
    actions = plan.get('actions', {})
    require({'guard_ingress', 'install'} <= set(actions), 'Legacy destinations need guard and installation actions')
    guard, install = actions['guard_ingress'], actions['install']
    for destination, (preimage, tombstone) in LEGACY_DESTINATIONS.items():
        before = guard.get('before', {}).get('files', {}).get(destination)
        closed = guard.get('after', {}).get('files', {}).get(destination)
        candidate = install.get('after', {}).get('files', {}).get(destination)
        closed_hash = hashlib.sha256(tombstone).hexdigest()
        require(before is not None and before['sha256'] == preimage
                and closed is not None and closed['sha256'] == closed_hash
                and candidate is not None and candidate['sha256'] not in (preimage, closed_hash)
                and install.get('before', {}).get('files', {}).get(destination) == closed,
                'Destination must transition from the exact legacy source through its unconditional guard to the pinned candidate')
        for stage in ('inventory', 'legacy_work', 'legacy_all', 'installed'):
            require(stage in profile['stages'], 'Destination closure requires every old-generation observation stage')
            item = profile['stages'][stage]
            expected = before if stage == 'inventory' else candidate if stage == 'installed' else closed
            current = item['manifest']['files'].get(destination)
            require(current == expected and not current['mode'] & 0o022
                    and destination in item['scope']['script_paths'],
                    'Destination source or old-process census differs from its exact handoff stage')


def validate_guarded_backup(profile):
    """The disabled policy and callbacks remain mandatory alongside closure.

    The inverse stays in the ordinary exact inventory, but is never evidence
    that no cron, manual caller or unloaded timer exists.
    """
    for stage in ('inventory', 'legacy_work', 'legacy_all', 'installed'):
        item = profile['stages'][stage]
        timer, service = (item['units'].get(name) for name in (BACKUP_TIMER, BACKUP_SERVICE))
        require(timer is not None and service is not None
                and timer['fragment_path'] == '/etc/systemd/system/' + BACKUP_TIMER
                and service['fragment_path'] == '/etc/systemd/system/' + BACKUP_SERVICE
                and not timer['drop_in_paths'] and not service['drop_in_paths']
                and timer.get('state') == {'UnitFileState': 'disabled', 'ActiveState': 'inactive', 'SubState': 'dead'}
                and service.get('state') == {'ActiveState': 'inactive', 'SubState': 'dead'}
                and timer['references']['Triggers'] == [BACKUP_SERVICE]
                and all(not unit['references'][key] for unit in (timer, service)
                        for key in ('OnFailure', 'OnSuccess', 'PropagatesStopTo', 'PartOf', 'BindsTo'))
                and service.get('execution') == backup_execution_contract(),
                'Backup closure requires disabled inactive units and their complete finite callback contract')


def validate_removal_admission(profile, plan):
    bindings = profile['invokers']
    if not bindings:
        return  # Exact, operation-bound administrative absence is still required.
    roles = {item['role'] for item in bindings}
    require(roles <= {'owner-receiver', 'owner-backup', 'dedicated-recovery'},
            'Removal requires implemented dedicated owner gates, not legacy routes')
    require(plan.get('previous_owner') == plan['owner'] and plan['owner'].get('state') == 'dedicated',
            'Removal must name the current dedicated owner generation')
    generation = plan['owner']['generation']
    require(generation == installation_path('/usr/local/lib/develative-deploy/whatsapp-generations/') + plan['owner']['manifest_sha256'],
            'Removal generation is outside the owner namespace')
    require({'inventory', 'removal'} <= set(profile['stages']), 'Removal needs both process censuses')
    source_paths = {BOOTSTRAP_ENTRY, BOOTSTRAP_ADMIN}
    source_paths.update(binding['entrypoint'] for binding in bindings)
    closure = plan.get('actions', {}).get('close_invokers', {})
    admitted_paths = set(source_paths)
    for stage in ('inventory', 'removal'):
        item = profile['stages'][stage]
        require(generation in item['scope']['script_roots']
                and {binding['entrypoint'] for binding in bindings} | {BOOTSTRAP_ENTRY}
                    <= set(item['scope']['script_paths']), 'Removal census omits an entrypoint or its loaded generation')
        for path in source_paths:
            source = item['manifest']['files'].get(path)
            name, current_sha = OWNER_GATE_SOURCES[path]
            previous_sha = PREVIOUS_OWNER_GATE_SHA256[name]
            configured_sources = {current_sha} | PREVIOUS_CONFIGURED_OWNER_GATE_SHA256.get(name, frozenset())
            require(source is not None and (source['sha256'] in configured_sources
                    or installation_profile().compatibility and source['sha256'] == previous_sha)
                    and source['uid'] == plan['owner_metadata']['uid']
                    and not source['mode'] & 0o022, 'Removal gate source differs from its reviewed implementation')
            expected = closure.get('before' if stage == 'inventory' else 'after', {}).get('files', {}).get(path)
            require(source == expected, 'Removal gate source differs from its closed admission action')
            if source['sha256'] in configured_sources and path in OWNER_GATE_LAYOUT_DEPENDENCIES:
                dependency = OWNER_GATE_LAYOUT_DEPENDENCIES[path]
                layout = item['manifest']['files'].get(dependency)
                require(layout is not None and layout['sha256'] in
                        ({OWNER_GATE_LAYOUT_SHA256} | PREVIOUS_OWNER_GATE_LAYOUT_SHA256)
                        and layout['uid'] == plan['owner_metadata']['uid'] and not layout['mode'] & 0o022,
                        'Removal gate installation dependency differs from its reviewed protected source')
                require(layout == closure.get('before' if stage == 'inventory' else 'after', {}).get('files', {}).get(dependency),
                        'Removal gate installation dependency differs from its closed admission action')
                admitted_paths.add(dependency)
        require(item['manifest']['files'].get(generation + '/manifest.json', {}).get('sha256') == plan['owner']['manifest_sha256'],
                'Removal census does not bind the owner generation manifest')
    for path in admitted_paths:
        require(closure.get('before', {}).get('files', {}).get(path)
                == closure.get('after', {}).get('files', {}).get(path),
                'Owner gate sources must remain unchanged while existing work drains')
    initial_units = profile['stages']['inventory']['units']
    for binding in bindings:
        if binding['kind'] == 'systemd':
            require(any(unit['fragment_path'] == binding['reference'] for unit in initial_units.values()),
                    'Automatic removal initiator is absent from the unit inventory')
        if binding['role'] == 'dedicated-recovery':
            require(binding['reference'] == installation_path('/etc/systemd/system/develative-whatsapp-recovery.service')
                    and set(services.WA_RECOVERY) <= set(initial_units),
                    'Dedicated recovery must use the exact timer and service closed by this adapter')


def validate_upgrade_admission(profile, plan):
    """Reuse the reviewed old-owner gates before replacing any of their code.

    The installed census must still follow the old loaded generation, even
    when all external launch routes are explicitly attested absent. Invoker
    completeness remains an operation-bound administrator assertion.
    """
    previous = plan.get('previous_owner')
    require(isinstance(previous, dict) and previous.get('state') == 'dedicated'
            and previous.get('epoch') != plan['owner'].get('epoch'),
            'Upgrade needs the existing dedicated owner and a new epoch')
    require(set(profile['stages']) == {'inventory', 'previous', 'installed'},
            'Upgrade requires exact before, drained and installed censuses')
    before = plan['actions']['install']['before']
    after = plan['actions']['install']['after']
    generation = previous['generation']
    require(before['files'].get(generation + '/manifest.json', {}).get('sha256') == previous['manifest_sha256'],
            'Upgrade must retain the exact previous generation manifest')
    for path, spec in before['files'].items():
        if path.startswith(generation + '/'):
            unchanged = {key: value for key, value in spec.items() if key != 'retention'}
            require({key: value for key, value in after['files'].get(path, {}).items() if key != 'retention'} == unchanged,
                    'Upgrade must preserve every previous generation artifact')
    for name, item in profile['stages'].items():
        require(generation in item['scope']['script_roots']
                and BOOTSTRAP_ENTRY in item['scope']['script_paths'],
                'Upgrade census must follow the previous loaded generation and bootstrap')
        require(item['manifest']['files'].get(generation + '/manifest.json', {}).get('sha256') == previous['manifest_sha256'],
                'Upgrade census omitted or changed the previous generation manifest')
    if 'runtime_update' in plan:
        from admin_handoff import validate_runtime_update
        update = plan['runtime_update']
        validate_runtime_update(update, before, after, plan['owner']['generation'], filesystem)
        for name, item in profile['stages'].items():
            expected = {**update['after' if name == 'installed' else 'before'], **update['backend']}
            require(all(item['manifest']['files'].get(path) == spec for path, spec in expected.items()),
                    'Runtime update census must bind exact runtime, layout and unchanged backend sources')
    # Existing dedicated gates use the same retiring-owner barrier for upgrade
    # and removal. Compare the old before-state on both sides of that barrier;
    # installation happens only after the independent previous-stage drain.
    projected_profile = {**profile, 'stages': {'inventory': profile['stages']['inventory'],
                                               'removal': profile['stages']['previous']}}
    projected_plan = {**plan, 'owner': previous, 'previous_owner': previous,
        'actions': {'close_invokers': {'before': before, 'after': before}}}
    validate_removal_admission(projected_profile, projected_plan)


def validate_inventory_attestation(record, profile, plan):
    require(isinstance(record, dict) and set(record) == {'format', 'complete', 'invokers', 'manual_policy'}
            and record['format'] == 2 and record['complete'] is True
            and record['invokers'] == profile['invokers']
            and record['manual_policy'] == {'operation_id': plan['id'],
                'unregistered_root_commands': 'frozen-for-operation'},
            'Root has not attested this complete invoker inventory')


def validate_retirement_attestation(record, profile, plan, *, authority_uid):
    """Validate declared transitions offline; callers still observe the host."""
    require(isinstance(record, dict) and set(record) == {'format', 'complete', 'invokers',
                'operation_id', 'epoch', 'references'}
            and record['format'] == 3 and record['complete'] is True and record['invokers'] == []
            and record['operation_id'] == plan['id'] and record['epoch'] == plan['owner']['epoch'],
            'Incoming references are not attested absent for this retirement')
    references = record['references']
    require(isinstance(references, dict) and set(references) == {
                binding['reference'] for binding in profile['invokers']},
            'Retirement must account for every original invoker reference')
    action = plan.get('actions', {}).get('remove', {})
    for path, phases in references.items():
        require(isinstance(phases, dict) and set(phases) == {'before', 'after'},
                'Retirement references need explicit before and after snapshots')
        for expected in phases.values():
            if expected is not None:
                require(isinstance(expected, dict) and set(expected) == {'sha256', 'mode', 'uid', 'gid'}
                        and evidence.hex_digest(expected['sha256'])
                        and all(type(expected[key]) is int and expected[key] >= 0 for key in ('mode', 'uid', 'gid'))
                        and expected['uid'] == authority_uid and expected['mode'] <= 0o777
                        and not expected['mode'] & 0o022, 'Invalid protected retirement reference snapshot')
        before_files, after_files = (action.get(side, {}).get('files', {}) for side in ('before', 'after'))
        require(not any(path in action.get(side, {}).get('links', {}) for side in ('before', 'after')),
                'Retirement reference links require a separate supported snapshot contract')
        strip = lambda value: {key: item for key, item in value.items() if key != 'retention'}
        if path in before_files:
            require(phases['before'] == strip(before_files[path]),
                    'Retirement reference does not match the removal precondition')
        expected_after = strip(after_files[path]) if path in after_files else (
            None if path in before_files else phases['before'])
        require(phases['after'] == expected_after,
                'Retirement reference after-state differs from the exact removal action')
    return references


class AdminHost:
    """Root inventory plus actual bounded file/process/unit observations.

    Root's attestation certifies completeness of invoker mapping. This adapter
    does not inspect SSH credentials or claim that /proc proves loaded code.
    All collected output is limited to hashes, identities and service state.
    """
    def __init__(self, root, profile, *, proc_root='/proc',
                 readonly_runner=evidence.readonly_runner,
                 service_runner=services.service_runner, clock_ns=time.monotonic_ns):
        require(isinstance(root, filesystem.Root), 'An anchored filesystem root is required')
        self.root = root
        self.profile = json.loads(evidence.canonical(profile))
        self.profile_digest = validate_profile(self.profile)
        self.proc_root = Path(proc_root)
        require(root.base == Path('/') or readonly_runner is not evidence.readonly_runner,
                'Fixture roots cannot query host service state')
        self.runner = readonly_runner
        reader = services.recovery_read_runner if readonly_runner is evidence.readonly_runner else readonly_runner
        self.services = services.RecoveryServices(root, runner=service_runner, reader=reader)
        self.clock = clock_ns
        self.plan_digest = None

    def now_ns(self):
        return self.clock()

    def _bind(self, plan):
        require(plan['inventory_digest'] == self.profile_digest,
                'Plan is not bound to this exact root inventory')
        require(set(plan['evidence_digests']) == set(self.profile['stages']),
                'Plan stages differ from the inventory')
        validate_admission(self.profile, plan)
        for stage, item in self.profile['stages'].items():
            require(plan['evidence_digests'][stage] == evidence.digest_inventory(
                    item['scope'], item['manifest'], item['units']),
                    'Plan evidence scope differs from the root inventory')
        # Use the same representation as the handoff state machine, including
        # its final newline. Never infer plan identity from the current journal.
        content = json.dumps(plan, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n'
        self.plan_digest = hashlib.sha256(content.encode()).hexdigest()
        attestation = self.profile['attestation']
        record = attested_json(self.root, attestation)
        validate_inventory_attestation(record, self.profile, plan)

    def inventory(self, plan, plan_digest):
        self._bind(plan)
        require(self.plan_digest == plan_digest, 'Plan identity differs')
        return self.observe(plan, [], phase='inventory')

    def observe(self, plan, prior_processes, *, phase):
        self._bind(plan)
        item = self.profile['stages'][phase]
        context = {'format': 1, 'authority': 'root-inventory',
                   'plan_digest': self.plan_digest, 'invocation_id': plan['id'],
                   'generation_id': self.profile['generation_id'],
                   'inventory_digest': evidence.digest_inventory(item['scope'], item['manifest'],
                       item['units'], prior_processes=prior_processes),
                   'boot_id': evidence._boot(self.proc_root)}
        receipt = evidence.observe(item['scope'], item['manifest'], context=context,
            units=item['units'], fs_root=self.root, proc_root=self.proc_root,
            runner=self.runner, clock_ns=self.clock, prior_processes=prior_processes)
        return {'receipt': receipt, 'context': context, 'now_ns': self.clock()}

    def critical_section(self, plan):
        self._bind(plan)
        self._prepare_state(plan)
        # services.operation_locks holds the client lease first, then raw
        # publication -> tenant locks. It is nonblocking and preserves inodes.
        return services.operation_locks(self.root, owner='whatsapp')

    def _prepare_state(self, plan):
        """Create only the fresh app lock namespace, with a resumable intent.

        Shared parents and the installed application's private directory are
        prerequisites, never created or repaired by the administration handoff.
        An existing application state directory keeps its protected metadata.
        """
        for path in (installation_path('/var/lib/develative-deploy'),
                     installation_path('/srv/openai-codex/projects/whatsapp-personal/private')):
            info = self.root.directory(path)
            require(info is not None and info['uid'] == self.root.uid and not info['mode'] & 0o022,
                    'Protected host/application prerequisite directory is missing')
        operation_id = hashlib.sha256(('wa-state-prelude:' + plan['id']).encode()).hexdigest()[:32]
        journal = filesystem.STATE + '/whatsapp/operations/' + operation_id + '/journal.json'
        try:
            self.root.read_bytes(journal)
        except FileNotFoundError:
            current = self.root.directory(STATE)
            if current is not None:
                require(current['uid'] == self.root.uid and not current['mode'] & 0o022,
                        'Existing WhatsApp state is not protected')
                return
            require(plan['mode'] == 'fresh', 'An existing application lost its administration state')
            before = {'format': 1, 'owner': 'whatsapp', 'files': {}, 'directories': {}}
            after = {**before, 'directories': {STATE: {'mode': 0o700, 'uid': self.root.uid,
                     'gid': self.root.gid, 'retention': 'retain'}}}
            filesystem.reconcile(self.root, operation_id=operation_id, before=before,
                                 after=after, payloads={}, allowed_paths=[STATE])
        else:
            filesystem.resume(self.root, owner='whatsapp', operation_id=operation_id,
                              allowed_paths=[STATE], payloads={})

    def journals_terminal(self, plan):
        self._bind(plan)
        # Lazy import avoids loading the runtime generation or a cycle when
        # the controller constructs its adapter.
        from admin_handoff import Pending
        # Do not import runtime helpers: their admission is deliberately closed
        # while the installer owns the transitioning barrier.
        pending_reasons = []
        if self.root.snapshot(JOURNALS['pending']) is not None:
            value = load_json(self.root, JOURNALS['pending'])
            require(isinstance(value, dict) and value.get('status') == 'activation-pending'
                    and isinstance(value.get('commit'), str) and len(value['commit']) == 40
                    and all(char in '0123456789abcdef' for char in value['commit'])
                    and isinstance(value.get('filesSha256'), dict)
                    and isinstance(value.get('previousHashes'), dict)
                    and isinstance(value.get('previousCode'), str)
                    and value['previousCode'].startswith('/'), 'Invalid pending publication journal')
            pending_reasons.append('Pending WhatsApp publication requires reconciliation')
        if self.root.snapshot(GATE) is not None:
            pending_reasons.append('An application release gate is still present')
        for name in ('transaction', 'backup'):
            try:
                value = load_json(self.root, JOURNALS[name])
            except FileNotFoundError:
                continue
            require(isinstance(value, dict), 'Invalid administrative journal')
            if name == 'transaction':
                validate_transaction_journal(value)
                if value['phase'] not in ('published', 'rolled-back'):
                    pending_reasons.append('WhatsApp activation is not terminal')
            else:
                validate_backup_journal(value)
                if value['phase'] != 'restored':
                    pending_reasons.append('WhatsApp backup services require recovery')
        if pending_reasons:
            raise Pending('; '.join(pending_reasons))

    def _match(self, manifest):
        observed = evidence.collect_files(manifest, fs_root=self.root)
        for kind in ('files', 'directories', 'links'):
            for path, spec in manifest.get(kind, {}).items():
                wanted = {'state': 'present', **{key: value for key, value in spec.items()
                                                if key != 'retention'}}
                require(observed[kind][path] == wanted, 'Installed or retained artifact differs')

    def verify_installation(self, plan):
        self._bind(plan)
        self._match(self.profile['final_manifest'])
        self._match(self.profile['retained_manifest'])
        self.journals_terminal(plan)
        if plan['mode'] == 'remove':
            self.verify_runtime_retirement(plan)
            self.verify_invokers_absent(plan, after_removal=True)
            action = plan['actions']['remove']
            for kind in ('files', 'links'):
                for path in set(action['before'].get(kind, {})) - set(action['after'].get(kind, {})):
                    reader = self.root.snapshot if kind == 'files' else self.root.link
                    require(reader(path) is None, 'A retired artifact is still installed')
        else:
            self.services.verify(self.profile['final_manifest'])
        return {'manifest_digest': evidence.digest(self.profile['final_manifest']),
                'retained_digest': evidence.digest(self.profile['retained_manifest'])}

    def verify_runtime_retirement(self, plan):
        self._bind(plan)
        return runtime_retirement_receipt(self.root, plan, self.plan_digest)

    def verify_invokers_absent(self, plan, *, after_removal=False, resuming_removal=False):
        """Check attested absence against the exact reference publication phase.

        resuming_removal is reserved for a controller which has already checked
        a durable removal intent and will resume the exact filesystem journal.
        Only its changed managed references are delegated to that journal;
        invariant references still require their current exact snapshot here.
        The caller must then check after_removal before recording completion.
        """
        self._bind(plan)
        item = self.profile['retirement_attestation']
        require(item is not None, 'Final removal requires a separate reference attestation')
        record = attested_json(self.root, item)
        references = validate_retirement_attestation(record, self.profile, plan, authority_uid=self.root.uid)
        require(type(after_removal) is bool and type(resuming_removal) is bool
                and not (after_removal and resuming_removal), 'Retirement reference phase must be explicit')
        for path, phases in references.items():
            if resuming_removal and phases['before'] != phases['after']:
                continue  # Exact managed mutation is checked by filesystem.resume.
            require(self.root.snapshot(path) == phases['after' if after_removal else 'before'],
                    'Retired invoker reference changed after the absence attestation')

    def activate_recovery(self, plan):
        self._bind(plan)
        self.services.activate(self.profile['final_manifest'])

    def close_recovery(self, plan):
        self._bind(plan)
        self.services.close(self.profile['stages']['removal']['manifest'])
