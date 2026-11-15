"""Finite transition from the acquired legacy priority helpers to the host.

Only the two priority services are disabled/stopped. BOX/WhatsApp workloads and
recovery timers are never stopped. The destructive legacy ExecStop is cleared
and its effective loaded value verified before any stop command is admitted.
"""
import copy
import os
from pathlib import Path
import re
import time

LEGACY = ('box-network-priority.service', 'whatsapp-resource-priority.service')
HOST_UNIT = 'develative-host-qos.service'
ENTRYPOINTS = {'/usr/local/sbin/box-network-priority': 'network',
    '/srv/openai-codex/projects/whatsapp-personal/scripts/resource_priority.py': 'resources'}
UNIT_HASHES = {'box-network-priority.service': 'b4bfbd5faaee41056c4d4e919b8e626a587df3dc417559b0b64d025c1335687c', 'whatsapp-resource-priority.service': '19f668d3ebb91587f56ee756dc7647483466afb70600663d2131d42d1cdbb981'}
PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'InvocationID', 'Job',
    'ExecStart', 'ExecReload', 'ExecStop', 'Requires', 'After', 'NeedDaemonReload', 'UnitFileState',
    'FragmentPath', 'DropInPaths', 'CPUWeight', 'IOWeight', 'Delegate', 'Slice', 'ExecMainStatus', 'User')
GUARD = b'#!/usr/bin/python3\nraise SystemExit("Resource priority is owned by the neutral host provider")\n'
OVERRIDE = (b'# Host-owned retirement guard; retain until all legacy references are gone.\n'
    b'[Unit]\nRequires=\nAfter=network-online.target\n[Service]\n'
    b'ExecStart=\nExecStart=/usr/bin/true\nExecReload=\nExecReload=/usr/bin/true\nExecStop=\n')


class Systemd:
    def __init__(self, qos, root, policy, descriptor):
        qos.require(root.base == Path('/') and os.geteuid() == 0, 'Fixture cannot invoke real systemd')
        self.qos, self.root, self.policy, self.descriptor = qos, root, policy, descriptor
        qos.protected('/usr/bin/systemctl')
        self.units = {*LEGACY, HOST_UNIT, *(f"user@{item['uid']}.service" for item in policy['initial_consumers'].values()
                                           if item['owner'] == 'whatsapp')}

    def show(self, unit):
        self.qos.require(unit in self.units, 'Unit is outside the source-owned QoS scope')
        raw = self.qos.supervised(['/usr/bin/systemctl', 'show', '--property=' + ','.join(PROPERTIES), '--', unit], None, self.descriptor)
        result = {}
        for line in raw.decode('utf-8').splitlines():
            key, separator, value = line.partition('=')
            self.qos.require(separator and key in PROPERTIES and key not in result, 'Invalid systemd property observation')
            result[key] = value
        self.qos.require(set(result) == set(PROPERTIES) and result['Id'] == unit, 'Incomplete effective unit observation')
        return result

    def command(self, operation, unit=None):
        if operation == 'reload':
            self.qos.require(unit is None, 'Reload has no unit argument'); argv = ['daemon-reload']
        elif operation in ('stop', 'disable'):
            self.qos.require(unit in LEGACY, 'Only retired priority services may be stopped')
            argv = [operation, '--', unit]
        else:
            self.qos.require(operation in ('enable', 'start') and unit == HOST_UNIT, 'Only the neutral QoS service may be activated')
            argv = (['--no-block', 'start', '--', unit] if operation == 'start' else ['enable', '--', unit])
        self.qos.supervised(['/usr/bin/systemctl', *argv], None, self.descriptor)

    def ready(self):
        item = self.show(HOST_UNIT)
        self.qos.require(item['LoadState'] == 'loaded' and item['ActiveState'] == 'active'
            and item['SubState'] == 'exited' and item['UnitFileState'] == 'enabled'
            and item['NeedDaemonReload'] == 'no' and item['Job'] in ('', '0')
            and item['ExecMainStatus'] == '0' and item['ExecStop'] == '', 'Neutral QoS service is not fully active')
        return item

    def wait_ready(self):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            item = self.show(HOST_UNIT)
            if item['ActiveState'] == 'active' and item['Job'] in ('', '0'):
                return self.ready()
            self.qos.require(item['ActiveState'] in ('activating', 'active'), 'Neutral service activation failed')
            time.sleep(0.1)
        raise self.qos.QoSError('Neutral service activation timed out')

    def registration_state(self, record):
        unit = f"user@{record['uid']}.service"
        self.units.update((unit, record['unit']))
        item = self.show(unit)
        self.qos.require(item['LoadState'] == 'loaded' and item['ActiveState'] in ('active', 'inactive')
                         and item['Job'] in ('', '0'), 'User manager has an in-flight transition')
        return _manager_identity(item)

    def registration_ready(self, record, previous=None, *, reload=False):
        unit = f"user@{record['uid']}.service"
        self.units.update((unit, record['unit']))
        if reload: self.command('reload')
        item, bridge = self.show(unit), self.show(record['unit'])
        self.qos.require(previous is None or _manager_identity(item) == previous,
                         'Enrollment changed the existing user manager identity')
        self.qos.require(item['LoadState'] == bridge['LoadState'] == 'loaded'
            and item['NeedDaemonReload'] == bridge['NeedDaemonReload'] == 'no'
            and item['Job'] in ('', '0') and bridge['Job'] in ('', '0')
            and item['CPUWeight'] == item['IOWeight'] == bridge['CPUWeight'] == bridge['IOWeight'] == '800'
            and HOST_UNIT in item['Requires'].split() and HOST_UNIT in item['After'].split()
            and not set(LEGACY).intersection(item['Requires'].split())
            and not set(LEGACY).intersection(item['After'].split())
            and bridge['User'] == record['account']
            and bridge['FragmentPath'] == '/etc/systemd/system/' + record['unit'],
            'Effective consumer dependencies, identity or weights differ after reload')


def manifest(files=None, directories=None):
    return {'format': 1, 'owner': 'host', 'files': files or {}, 'directories': directories or {}, 'links': {}}


def _action(qos, root, payloads, *, expected_old, allow_missing):
    before, after, directories = {}, {}, {}
    for name, content in payloads.items():
        current = root.snapshot(name)
        desired = {'sha256': qos.sha(content), 'mode': 0o755 if name in ENTRYPOINTS else 0o644,
                   'uid': root.uid, 'gid': root.gid, 'retention': 'managed'}
        if current:
            qos.require(current['uid'] == root.uid and current['gid'] == root.gid and not current['mode'] & 0o022,
                        'Unprotected legacy/adoption artifact')
            qos.require(current['sha256'] == desired['sha256'] or current['sha256'] == expected_old.get(name),
                        'Legacy/adoption artifact differs from explicit source evidence')
            before[name] = {**current, 'retention': 'managed'}
        else:
            qos.require(name in allow_missing, 'Required legacy artifact is missing')
        after[name] = desired
        parent = str(Path(name).parent)
        if root.directory(parent) is None:
            # Only a single named .service.d directory under the system root.
            qos.require(parent.startswith('/etc/systemd/system/') and parent.endswith('.service.d')
                        and str(Path(parent).parent) == '/etc/systemd/system', 'Unprepared administrative parent')
            directories[parent] = {'uid': root.uid, 'gid': root.gid, 'mode': 0o755, 'retention': 'retain'}
    return {'before': manifest(before), 'after': manifest(after, directories),
            'allowed_paths': sorted(set(payloads) | set(directories)), 'payloads': payloads}


def compile_adoption(qos, root, policy, policy_sha256, entrypoint, sources_manifest, sources_sha256):
    payloads = {name: GUARD for name in ENTRYPOINTS}
    expected = {name: qos.SOURCE_HASHES[kind] for name, kind in ENTRYPOINTS.items()}
    hostunit = qos.render_units(policy_sha256, entrypoint, sources_manifest, sources_sha256)
    payloads.update(hostunit)
    allow_missing = set(hostunit)
    for unit in LEGACY:
        original = '/etc/systemd/system/' + unit
        info = root.snapshot(original)
        qos.require(info is not None and info['sha256'] == UNIT_HASHES[unit]
                    and info['uid'] == root.uid and info['mode'] == 0o644, 'Legacy priority unit source differs')
        path = original + '.d/99-host-qos-retired.conf'
        payloads[path] = OVERRIDE; allow_missing.add(path)
    old_manager = (b'# Managed by WhatsApp resource priority.\n[Unit]\nRequires=whatsapp-resource-priority.service\n'
        b'After=whatsapp-resource-priority.service\n[Service]\nSlice=system.slice\nCPUWeight=800\nIOWeight=800\nDelegate=cpu io memory pids\n')
    old_weights = b'# Managed by WhatsApp resource priority.\n[Service]\nCPUWeight=800\nIOWeight=800\n'
    for record in policy['initial_consumers'].values():
        if record['owner'] != 'whatsapp': continue
        for path, content in qos.consumer_dropins(record)['administrative'].items():
            payloads[path] = content
            expected[path] = qos.sha(old_manager if '/user@' in path else old_weights)
    return _action(qos, root, payloads, expected_old=expected, allow_missing=allow_missing)


def _manager_identity(item):
    return {key: item[key] for key in ('MainPID', 'InvocationID', 'ActiveState', 'SubState')}


def verify_transition(qos, services, initial, *, retired=False):
    for unit in LEGACY:
        item = services.show(unit)
        qos.require(item['LoadState'] == 'loaded' and item['NeedDaemonReload'] == 'no'
            and item['Job'] in ('', '0') and item['ExecStop'] == ''
            and item['ExecStart'].count('path=/usr/bin/true') == 1
            and item['ExecReload'].count('path=/usr/bin/true') == 1,
            'Legacy destructive actions are still effective')
        if retired:
            qos.require(item['ActiveState'] == 'inactive' and item['UnitFileState'] == 'disabled'
                        and item['MainPID'] == '0', 'Legacy priority initiator is still active')
    for unit, original in initial['managers'].items():
        item = services.show(unit)
        qos.require(_manager_identity(item) == _manager_identity(original)
                    and item['NeedDaemonReload'] == 'no' and item['Job'] in ('', '0')
                    and item['CPUWeight'] == item['IOWeight'] == '800'
                    and set(item['Requires'].split()) == (set(original['Requires'].split()) - set(LEGACY)) | {HOST_UNIT}
                    and set(item['After'].split()) == (set(original['After'].split()) - set(LEGACY)) | {HOST_UNIT},
                    'User manager identity, dependencies or effective weights changed unexpectedly')


def _check_operation_installation(qos, root, policy, policy_sha256, journal):
    consumers = policy['initial_consumers']
    if journal is not None and journal.get('phase') == 'committed':
        registry = qos.validate_registry(qos.read_control(root, qos.REGISTRY), policy)
        qos.require(registry['policy_sha256'] == policy_sha256, 'Completed operation registry belongs to another policy')
        consumers = registry['consumers']
    qos.check_installation_bindings(consumers)


def adopt(qos, root, *, policy_path, expected_sha256, operation_id, entrypoint, sources_manifest,
          sources_sha256, kernel_factory, service_factory=Systemd, lookup, census, admission_path,
          admission_sha256, proc_root=Path('/proc'), fault=None):
    qos.require(re.fullmatch('[0-9a-f]{32}', operation_id), 'Stable adoption identity required')
    emit = fault or (lambda event, detail: None)
    admission = manual_gate(qos, root, admission_path, admission_sha256, operation_id)
    qos.require(admission['ssh_admission'] == 'externally-fenced',
                'SSH admission is unknown; adoption is read-only blocked before publication')
    policy = qos.read_policy(root, policy_path, expected_sha256)
    journal_path = qos.STATE + '/operations/adopt-' + operation_id + '.json'
    request = {'policy_sha256': expected_sha256, 'operation_id': operation_id, 'entrypoint': entrypoint,
               'sources_manifest': sources_manifest, 'sources_sha256': sources_sha256,
               'admission_path': admission_path}
    with qos.lease(root, qos.STATE + '/adoption.lock') as adoption_fd:
        services = service_factory(qos, root, policy, adoption_fd)
        with qos.lease(root) as descriptor:
            backend = kernel_factory(root, policy, descriptor)
            journal = qos.read_control(root, journal_path)
            _check_operation_installation(qos, root, policy, expected_sha256, journal)
            if journal is None:
                qos.check_accounts(policy, policy['initial_consumers'], lookup, census)
                before = backend.observe()
                qos.require(before == {'tc': policy['parameters']['tc'], 'io': policy['parameters']['io_qos'],
                    'nft': qos.nft_policy(policy, policy['initial_consumers'], legacy=True)[1]},
                    'Legacy adoption requires the complete acquired kernel policy')
                action = compile_adoption(qos, root, policy, expected_sha256, entrypoint, sources_manifest, sources_sha256)
                initial = {'legacy': {unit: services.show(unit) for unit in LEGACY}, 'managers': {}}
                for unit, item in initial['legacy'].items():
                    qos.require(item['LoadState'] == 'loaded' and item['NeedDaemonReload'] == 'no'
                        and item['Job'] in ('', '0') and item['MainPID'] == '0'
                        and item['ActiveState'] == 'active' and item['SubState'] == 'exited'
                        and item['UnitFileState'] == 'enabled' and not item['DropInPaths']
                        and item['FragmentPath'] == '/etc/systemd/system/' + unit,
                        'Legacy priority unit is not the acquired idle oneshot')
                for record in policy['initial_consumers'].values():
                    if record['owner'] != 'whatsapp': continue
                    unit = f"user@{record['uid']}.service"; item = services.show(unit)
                    qos.require(item['ActiveState'] == 'active' and item['Job'] in ('', '0')
                                and item['NeedDaemonReload'] == 'no' and int(item['MainPID']) > 0
                                and item['InvocationID'] and item['CPUWeight'] == item['IOWeight'] == '800'
                                and LEGACY[1] in item['Requires'].split(), 'User manager evidence differs')
                    initial['managers'][unit] = item
                journal = {'format': 1, 'request': request, 'phase': 'prepared', 'initial': initial,
                    'kernel_before': before, 'process_prior': [], 'admission_sha256s': [admission_sha256], 'action': {key: value for key, value in action.items() if key != 'payloads'},
                    'payloads': {name: qos.base64.b64encode(content).decode() for name, content in action['payloads'].items()}}
                qos._persist(root, journal_path, journal); emit('adoption-prepared', None)
            else:
                qos.fields(journal, {'format', 'request', 'phase', 'initial', 'kernel_before', 'process_prior', 'admission_sha256s', 'action', 'payloads'})
                qos.require(journal['format'] == 1 and journal['request'] == request, 'Adoption identity conflicts')
                if admission_sha256 not in journal['admission_sha256s']:
                    qos.require(len(journal['admission_sha256s']) < 64, 'Too many renewed admission statements')
                    journal['admission_sha256s'].append(admission_sha256)
                    qos._persist(root, journal_path, journal)
            phases = ('prepared', 'published', 'reloaded', 'legacy-retired', 'kernel-adopted', 'activated', 'committed')
            qos.require(journal['phase'] in phases, 'Unknown adoption phase')
            def checkpoint(phase):
                journal['phase'] = phase; qos._persist(root, journal_path, journal); emit('adoption-' + phase, None)
            scope = {'script_paths': sorted([*ENTRYPOINTS, '/usr/sbin/tc', '/usr/sbin/nft']),
                     'cgroups': ['/system.slice/' + unit for unit in LEGACY]}
            def barrier():
                manual_gate(qos, root, admission_path, admission_sha256, operation_id)
                prior = journal['process_prior']
                observed = qos.processes.collect(scope, prior_records=prior, proc_root=proc_root)
                if observed['records']:
                    combined = {(item['boot_id'], item['pid'], item['start_ticks']): item for item in [*prior, *observed['records']]}
                    journal['process_prior'] = list(combined.values())
                    qos._persist(root, journal_path, journal)
                qos.processes.require_quiet(observed, scope=scope, prior_records=prior)
            if journal['phase'] == 'prepared':
                barrier()
                qos.require(backend.observe() == journal['kernel_before'], 'Legacy policy changed before guarded publication')
                action = journal['action']
                # The engine binds this exact durable intent, including all source hashes and scope.
                payloads = {name: qos.base64.b64decode(data, validate=True) for name, data in journal['payloads'].items()}
                qos.engine.reconcile(root, operation_id=qos.sha(qos.canonical(request))[:32],
                    before=action['before'], after=action['after'], allowed_paths=set(action['allowed_paths']),
                    payloads=payloads, inline_payloads=set(payloads))
                checkpoint('published')
            if journal['phase'] == 'published':
                barrier()
                admission = manual_gate(qos, root, admission_path, admission_sha256, operation_id)
                qos.require(admission['ssh_admission'] == 'externally-fenced',
                    'SSH admission is unknown: guards remain staged, activation requires separate fence evidence')
                services.command('reload')
                verify_transition(qos, services, journal['initial'])
                qos.require(backend.observe() == journal['kernel_before'], 'Reload altered the shared kernel policy')
                checkpoint('reloaded')
            if journal['phase'] == 'reloaded':
                verify_transition(qos, services, journal['initial'])
                for unit in LEGACY:
                    services.command('disable', unit)
                    # Re-read the loaded ExecStop immediately before the exact named stop.
                    qos.require(services.show(unit)['ExecStop'] == '', 'Destructive legacy stop reappeared')
                    services.command('stop', unit)
                verify_transition(qos, services, journal['initial'], retired=True)
                qos.require(backend.observe() == journal['kernel_before'], 'Legacy retirement altered shared kernel state')
                checkpoint('legacy-retired')
            if journal['phase'] == 'legacy-retired':
                barrier()
                manual_gate(qos, root, admission_path, admission_sha256, operation_id)
                verify_transition(qos, services, journal['initial'], retired=True)
                qos.operate(root, policy_path=policy_path, expected_sha256=expected_sha256, action='apply',
                    operation_id=qos.sha(qos.canonical({'adoption': request}))[:32], kernel_factory=kernel_factory,
                    lookup=lookup, census=census, _lease_fd=descriptor)
                checkpoint('kernel-adopted')
        # The child boot/apply needs the QoS lease itself. Adoption's independent
        # lease still serializes this handoff and survives its command supervisor.
        if journal['phase'] == 'kernel-adopted':
            services.command('enable', HOST_UNIT); services.command('start', HOST_UNIT)
            services.wait_ready(); checkpoint('activated')
        if journal['phase'] in ('activated', 'committed'):
            services.ready(); verify_transition(qos, services, journal['initial'], retired=True)
            qos.operate(root, policy_path=policy_path, expected_sha256=expected_sha256, action='check',
                        kernel_factory=kernel_factory, lookup=lookup, census=census)
            checkpoint('committed')
        return {'provider': qos.PROVIDER, 'status': 'complete', 'operation_id': operation_id,
                'legacy_priority_services': 'disabled-inactive', 'user_managers': 'same-pid-and-invocation',
                'kernel_policy': 'neutral-three-class', 'host_unit': HOST_UNIT}


def registration_plan(qos, root, record, *, allow_legacy_user=False):
    """Preflight every admin/account drop-in before publishing any one of them."""
    bridge = '/etc/systemd/system/' + record['unit']
    info = root.snapshot(bridge)
    qos.require(info is not None and info['uid'] == root.uid and not info['mode'] & 0o022,
                'A protected bridge unit must exist before consumer enrollment')
    content = root.read_bytes(bridge, max_bytes=65536).decode()
    qos.require(re.findall(r'^User\s*=\s*(\S+)\s*$', content, re.M) == [record['account']],
                'Bridge unit has a different or ambiguous service account')
    templates = qos.consumer_dropins(record)
    plans = []
    for scope, payloads in templates.items():
        scoped = root if scope == 'administrative' else qos.engine.Root(root.base / record['home'].lstrip('/'))
        try:
            if scope == 'account':
                qos.require((scoped.uid, scoped.gid) == (record['uid'], record['gid']), 'Account home ownership differs')
                payloads = {name[len(record['home']):]: value for name, value in payloads.items()}
            before, after, before_dirs, after_dirs = {}, {}, {}, {}
            for name, value in payloads.items():
                expected = {'sha256': qos.sha(value), 'mode': 0o644, 'uid': scoped.uid, 'gid': scoped.gid}
                current = scoped.snapshot(name)
                legacy = {**expected, 'sha256': qos.sha(value.replace(b'# Managed by host resource priority.\n',
                    b'# Managed by WhatsApp resource priority.\n', 1))}
                # These two exact preimages come from the pinned unit_files
                # source. No dependency-bearing administrative legacy file is
                # admitted by this account-only migration.
                adopted = scope == 'account' and allow_legacy_user and current == legacy
                qos.require(current is None or current == expected or adopted,
                            'Existing drop-in needs explicit legacy adoption; enrollment cannot overwrite it')
                if current: before[name] = {**current, 'retention': 'managed'}
                after[name] = {**expected, 'retention': 'managed'}
                parent = Path(name).parent
                while str(parent) != '/':
                    directory = scoped.directory(str(parent))
                    if directory is not None:
                        qos.require(directory['uid'] == scoped.uid and not directory['mode'] & 0o022,
                                    'Drop-in parent is not protected for its scoped owner')
                        before_dirs[str(parent)] = after_dirs[str(parent)] = {**directory, 'retention': 'retain'}
                        break
                    after_dirs[str(parent)] = {'mode': 0o755 if scope == 'administrative' else 0o700,
                        'uid': scoped.uid, 'gid': scoped.gid, 'retention': 'retain'}
                    parent = parent.parent
            if scope == 'administrative':
                before[bridge] = after[bridge] = {**info, 'retention': 'retain'}
            identity = None
            if scope == 'account':
                info = os.fstat(scoped.fd)
                identity = {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid}
            plans.append({'scope': scope, 'root': '/' if scope == 'administrative' else record['home'], 'root_identity': identity,
                'before': manifest(before, before_dirs), 'after': manifest(after, after_dirs),
                'allowed_paths': sorted(set(before) | set(after) | set(before_dirs) | set(after_dirs)),
                'payloads': {name: qos.base64.b64encode(value).decode() for name, value in payloads.items()}})
        finally:
            if scoped is not root: scoped.close()
    return plans


def _account_engine(qos, target, control, account_root):
    """Private adapter for the two user drop-ins, with host-owned journals.

    Only the parent's anchored target dirfd can serve target paths; lifecycle
    control files stay beneath the separately protected host Root. The durable
    operation namespace binds the account root and its physical identity.
    """
    info = os.fstat(target.fd)
    identity = qos.sha(qos.canonical({'home': account_root, 'uid': target.uid, 'gid': target.gid,
                                      'device': info.st_dev, 'inode': info.st_ino}))
    class AccountTargets(qos.engine.Root):
        def __init__(self):
            self.base, self.uid, self.gid = target.base, control.uid, control.gid
            self.partial_directory = None
        def _directory_uid(self, path):
            qos.engine._path(path)
            if path == qos.engine.STATE or path.startswith(qos.engine.STATE + '/'):
                return control.uid
            qos.require(path in ('/.config', '/.config/systemd', '/.config/systemd/user')
                        or path.startswith('/.config/systemd/user/'), 'Unknown account directory authority')
            return target.uid
        @qos.contextmanager
        def _account_parent(self, path):
            parts = Path(qos.engine._path(path)).parts[1:]
            descriptor = os.dup(target.fd); traversed = ''
            try:
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                    os.close(descriptor); descriptor = child; traversed += '/' + part
                    actual = os.fstat(descriptor)
                    qos.require(not actual.st_mode & 0o022 and (actual.st_uid == target.uid or
                        traversed == self.partial_directory and actual.st_uid == control.uid),
                        'Account ancestor differs from the scoped owner or exact pending directory')
                yield descriptor, parts[-1]
            finally:
                os.close(descriptor)
        def _parent(self, path):
            qos.engine._path(path)
            state = qos.engine.STATE
            if path == state or path.startswith(state + '/'):
                parts = path[len(state) + 1:].split('/')
                if len(parts) >= 3 and parts[1] == 'operations' and re.fullmatch('[0-9a-f]{32}', parts[2]):
                    parts[2] = qos.sha((identity + ':' + parts[2]).encode())[:32]
                    path = state + '/' + '/'.join(parts)
                return control._parent(path)
            qos.require(path in ('/.config', '/.config/systemd', '/.config/systemd/user')
                        or path.startswith('/.config/systemd/user/'), 'Account target escaped the finite drop-in subtree')
            return self._account_parent(path)
        def _finish_directory(self, path, spec):
            if not (path == qos.engine.STATE or path.startswith(qos.engine.STATE + '/')):
                # The durable creation intent can have survived the fchown.
                # Already-final account directories are accepted exactly;
                # only still-root-owned staging directories may be finished.
                if target.directory(path) == {key: value for key, value in spec.items() if key != 'retention'}:
                    return
            return super()._finish_directory(path, spec)
        def close(self):
            pass  # Borrowed anchored Roots remain owned by the caller.
    return AccountTargets()


def publish_registration(qos, root, plans, request):
    def identity(action):
        if action['scope'] == 'account':
            path = root.base / action['root'].lstrip('/')
            info = path.lstat()
            qos.require(path == path.resolve(strict=True) and path.is_dir() and
                {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid} == action['root_identity'],
                'Physical account root changed since durable registration planning')
    for action in plans: identity(action)
    # Recheck both independent roots before either transaction publishes files.
    # Existing per-root journals authorize only their exact interrupted states.
    for action in plans:
        scoped = root if action['scope'] == 'administrative' else qos.engine.Root(root.base / action['root'].lstrip('/'))
        try:
            if action['scope'] == 'account':
                info = os.fstat(scoped.fd)
                qos.require({'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid}
                            == action['root_identity'], 'Opened account root differs from durable registration identity')
            view = scoped if action['scope'] == 'administrative' else _account_engine(qos, scoped, root, action['root'])
            opid = qos.sha(qos.canonical({'request': request, 'scope': action['scope'], 'root': action['root']}))[:32]
            journal_path = qos.engine.STATE + '/host/operations/' + opid + '/journal.json'
            journal = (qos.engine.inspect_operation(view, owner='host', operation_id=opid, allowed_paths=set(action['allowed_paths']))
                       if view.snapshot(journal_path) is not None else None)
            if action['scope'] == 'account' and journal is not None:
                view.partial_directory = journal['directory_intent']
            qos.engine._preflight(view, qos.engine.validate_manifest(action['before']),
                                 qos.engine.validate_manifest(action['after']), opid, journal=journal)
        finally:
            if scoped is not root: scoped.close()
    for action in plans:
        identity(action)
        scoped = root if action['scope'] == 'administrative' else qos.engine.Root(root.base / action['root'].lstrip('/'))
        try:
            if action['scope'] == 'account':
                info = os.fstat(scoped.fd)
                qos.require({'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid}
                            == action['root_identity'], 'Opened account root differs from durable registration identity')
            payloads = {name: qos.base64.b64decode(value, validate=True) for name, value in action['payloads'].items()}
            view = scoped if action['scope'] == 'administrative' else _account_engine(qos, scoped, root, action['root'])
            opid = qos.sha(qos.canonical({'request': request, 'scope': action['scope'], 'root': action['root']}))[:32]
            if action['scope'] == 'account' and view.snapshot(qos.engine.STATE + '/host/operations/' + opid + '/journal.json') is not None:
                view.partial_directory = qos.engine.inspect_operation(view, owner='host', operation_id=opid,
                    allowed_paths=set(action['allowed_paths']))['directory_intent']
            qos.engine.reconcile(view, operation_id=opid,
                before=action['before'], after=action['after'], payloads=payloads,
                allowed_paths=set(action['allowed_paths']), inline_payloads=set(payloads))
            identity(action)
        finally:
            if scoped is not root: scoped.close()


def manual_gate(qos, root, path, expected_sha256, operation_id, *, now_ns=None):
    qos.require(path == '/etc/develative-host-qos/adoption-' + operation_id + '.json'
                and re.fullmatch('[0-9a-f]{64}', expected_sha256), 'Exact adoption admission evidence required')
    info = root.snapshot(path)
    qos.require(info is not None and info['uid'] == root.uid and not info['mode'] & 0o022,
                'Adoption evidence is not administratively protected')
    raw = root.read_bytes(path, max_bytes=65536)
    qos.require(qos.sha(raw) == expected_sha256 == info['sha256'], 'Adoption admission evidence changed')
    value = qos.decode(raw)
    qos.fields(value, {'format', 'operation_id', 'script_paths', 'manual_freeze', 'ssh_admission',
                       'ssh_fence_evidence', 'issued_ns', 'expires_ns'})
    now_ns = time.time_ns() if now_ns is None else now_ns
    qos.require(value['format'] == 1 and value['operation_id'] == operation_id
        and value['script_paths'] == sorted(ENTRYPOINTS) and value['manual_freeze'] == 'until-adoption-complete'
        and type(value['issued_ns']) is int and type(value['expires_ns']) is int
        and value['issued_ns'] <= now_ns < value['expires_ns'] <= value['issued_ns'] + 3600 * 10**9,
        'Manual freeze evidence is incomplete or expired')
    qos.require(value['ssh_admission'] in ('unknown', 'externally-fenced'), 'Unknown SSH admission statement')
    if value['ssh_admission'] == 'unknown':
        qos.require(value['ssh_fence_evidence'] is None, 'Unknown SSH admission cannot claim fence evidence')
    else:
        reference = value['ssh_fence_evidence']; qos.fields(reference, {'path', 'sha256'})
        qos.require(reference['path'] == '/etc/develative-host-qos/admission-evidence/' + operation_id + '.json'
                    and re.fullmatch('[0-9a-f]{64}', reference['sha256']), 'Exact operation-scoped fence reference required')
        evidence_info = root.snapshot(reference['path'])
        qos.require(evidence_info is not None and evidence_info['uid'] == root.uid and not evidence_info['mode'] & 0o022,
                    'External fence evidence is not protected')
        evidence_raw = root.read_bytes(reference['path'], max_bytes=65536)
        qos.require(qos.sha(evidence_raw) == reference['sha256'] == evidence_info['sha256'], 'External fence evidence changed')
        evidence = qos.decode(evidence_raw)
        qos.fields(evidence, {'format', 'kind', 'authority', 'operation_id', 'method', 'scope', 'observed_ns'})
        qos.require(evidence['format'] == 1 and evidence['kind'] == 'administrative-attestation'
                    and evidence['authority'] == 'host-administrator' and evidence['operation_id'] == operation_id
                    and evidence['method'] == 'externally-verified-priority-admission-suspension'
                    and evidence['scope'] == {'script_paths': sorted(ENTRYPOINTS), 'unmapped_ssh_priority_launches': 'suspended'}
                    and type(evidence['observed_ns']) is int and value['issued_ns'] <= evidence['observed_ns'] <= now_ns,
                    'External fence attestation must state its narrow method, scope and observation')
        # This authenticates a protected administrator statement. It does not
        # inspect authorized_keys or turn an unknown SSH inventory into a
        # technically verified complete inventory.
    return value



def verify_registration(qos, root, plans):
    for action in plans:
        scoped = root if action['scope'] == 'administrative' else qos.engine.Root(root.base / action['root'].lstrip('/'))
        try:
            if action['scope'] == 'account':
                info = os.fstat(scoped.fd)
                qos.require({'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid}
                            == action['root_identity'], 'Completed registration account root changed')
            for kind, method in (('files', scoped.snapshot), ('directories', scoped.directory)):
                for path, spec in action['after'][kind].items():
                    qos.require(method(path) == {key: value for key, value in spec.items() if key != 'retention'},
                                'Completed consumer drop-in configuration changed')
        finally:
            if scoped is not root: scoped.close()


def activate_fresh(qos, root, *, policy_path, expected_sha256, operation_id, entrypoint,
                   sources_manifest, sources_sha256, kernel_factory, lookup, census,
                   service_factory=Systemd, proc_root=Path('/proc'), fault=None):
    """Install/activate the host unit only when the legacy provider is absent."""
    qos.require(re.fullmatch('[0-9a-f]{32}', operation_id), 'Stable fresh activation identity required')
    policy = qos.read_policy(root, policy_path, expected_sha256)
    request = {'operation_id': operation_id, 'policy_sha256': expected_sha256, 'entrypoint': entrypoint,
               'sources_manifest': sources_manifest, 'sources_sha256': sources_sha256}
    emit = fault or (lambda event, detail: None)
    path = qos.STATE + '/operations/activate-' + operation_id + '.json'
    with qos.lease(root, qos.STATE + '/adoption.lock') as descriptor:
        services = service_factory(qos, root, policy, descriptor)
        def absent():
            for name in (*ENTRYPOINTS, *('/etc/systemd/system/' + unit for unit in LEGACY)):
                qos.require(root.snapshot(name) is None, 'Existing legacy provider requires explicit adoption')
            for unit in LEGACY:
                item = services.show(unit)
                qos.require(item['LoadState'] == 'not-found' and item['ActiveState'] == 'inactive'
                    and item['MainPID'] == '0' and item['Job'] in ('', '0'), 'Legacy priority unit still exists or is running')
            scope = {'script_paths': sorted([*ENTRYPOINTS, '/usr/sbin/tc', '/usr/sbin/nft']),
                     'cgroups': ['/system.slice/' + unit for unit in LEGACY]}
            qos.processes.require_quiet(qos.processes.collect(scope, proc_root=proc_root), scope=scope)
        absent()
        journal = qos.read_control(root, path)
        _check_operation_installation(qos, root, policy, expected_sha256, journal)
        if journal is None:
            payloads = qos.render_units(expected_sha256, entrypoint, sources_manifest, sources_sha256)
            qos.require(all(root.snapshot(name) is None for name in payloads), 'Existing host unit needs its original activation intent')
            action = _action(qos, root, payloads, expected_old={}, allow_missing=set(payloads))
            backend = kernel_factory(root, policy, descriptor)
            before = backend.observe()
            qos.require(not before['nft'], 'Fresh activation cannot adopt any existing marking table')
            qos.kernel_steps(policy, before, policy['initial_consumers'], allow_legacy=True)
            qos.check_accounts(policy, policy['initial_consumers'], lookup, census)
            journal = {'format': 1, 'request': request, 'phase': 'prepared',
                'action': {key: value for key, value in action.items() if key != 'payloads'},
                'payloads': {name: qos.base64.b64encode(content).decode() for name, content in payloads.items()}}
            qos._persist(root, path, journal); emit('fresh-prepared', None)
        else:
            qos.fields(journal, {'format', 'request', 'phase', 'action', 'payloads'})
            qos.require(journal['format'] == 1 and journal['request'] == request, 'Fresh activation identity conflicts')
        qos.require(journal['phase'] in ('prepared', 'kernel-ready', 'published', 'activated', 'committed'), 'Unknown fresh phase')
        def checkpoint(phase):
            journal['phase'] = phase; qos._persist(root, path, journal); emit('fresh-' + phase, None)
        if journal['phase'] == 'prepared':
            qos.operate(root, policy_path=policy_path, expected_sha256=expected_sha256, action='apply',
                operation_id=qos.sha(qos.canonical(request))[:32], kernel_factory=kernel_factory, lookup=lookup, census=census)
            checkpoint('kernel-ready')
        if journal['phase'] == 'kernel-ready':
            absent(); action = journal['action']
            qos.engine.reconcile(root, operation_id=qos.sha(qos.canonical({'fresh-unit': request}))[:32],
                before=action['before'], after=action['after'], allowed_paths=set(action['allowed_paths']),
                payloads={name: qos.base64.b64decode(value, validate=True) for name, value in journal['payloads'].items()},
                inline_payloads=set(journal['payloads']))
            checkpoint('published')
        if journal['phase'] == 'published':
            absent(); services.command('reload'); services.command('enable', HOST_UNIT); services.command('start', HOST_UNIT)
            services.wait_ready(); checkpoint('activated')
        services.ready()
        qos.operate(root, policy_path=policy_path, expected_sha256=expected_sha256, action='check',
                    kernel_factory=kernel_factory, lookup=lookup, census=census)
        checkpoint('committed')
        return {'provider': qos.PROVIDER, 'status': 'complete', 'operation_id': operation_id,
                'host_unit': HOST_UNIT, 'legacy_provider': 'absent', 'kernel_policy': 'neutral-three-class'}
