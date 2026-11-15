"""Forward-only runtime retirement, after the administration owner is retired.

No account, phone, session, key, database or shared-service operation exists here.
The caller supplies a reviewed, digest-bound plan and concrete host providers.
Imports have no host effects. The protected CLI exposes inspection, finite unit
observation, forward retirement and the scoped UID Quadlet helper.
"""
import sys as _installation_sys
from pathlib import Path as _InstallationPath
import types as _installation_types
if __name__ != '__main__':
    _installation_module=globals().get('_PINNED_INSTALLATION_LAYOUT')
    if _installation_module is None:
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
        _installation_module=_installation_sys.modules['installation_layout']
    if getattr(_installation_module, 'FORMAT', None) != 'whatsapp-installation-v1':
        raise ImportError('The whatsapp entry point cannot reuse another product installation layout')
import ctypes
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import types

def _configure_installation(module, *, root=None):
    global PROJECT, OWNER, STATE, HELPER, HELPER_LAYOUT, installation_profile, installation_path
    require(getattr(module, 'FORMAT', None) == 'whatsapp-installation-v1', 'Invalid captured installation owner')
    if root is not None:
        module.activate_installation(root=root, trusted_uid=0 if root == Path('/') else os.getuid())
    installation_profile, installation_path = module.active, module.mapped
    PROJECT = installation_path('/srv/openai-codex/projects/whatsapp-personal')
    OWNER = installation_path('/etc/develative-deploy/recovery-owners/whatsapp.json')
    STATE = installation_path('/var/lib/develative-deploy/whatsapp')
    HELPER = PROJECT + '/scripts/runtime_lifecycle.py'
    HELPER_LAYOUT = PROJECT + '/scripts/installation_layout.py'


FORMAT = 'whatsapp-runtime-retirement-v1'
PHASES = ('prepared', 'services_closed', 'quadlets_retired', 'consumers_retired', 'files_removed', 'verified')
PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlPID', 'Job',
    'ControlGroup', 'FragmentPath', 'SourcePath', 'DropInPaths', 'NeedDaemonReload', 'UnitFileState',
    'User', 'ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecCondition',
    'Restart', 'KillMode', 'OnFailure', 'OnSuccess', 'PropagatesStopTo', 'BoundBy',
    'ConsistsOf', 'RequiredBy', 'RequisiteOf', 'Triggers')
PROPAGATION_PROPERTIES = ('OnFailure', 'OnSuccess', 'PropagatesStopTo', 'BoundBy',
    'ConsistsOf', 'RequiredBy', 'RequisiteOf', 'Triggers')
EXEC_PROPERTIES = tuple(key for key in PROPERTIES if key.startswith('Exec'))
DEFINITION = tuple(key for key in PROPERTIES if key not in
    ('ActiveState', 'SubState', 'MainPID', 'ControlPID', 'Job', 'ControlGroup', 'UnitFileState'))
SOURCE_ROOT = Path(__file__).resolve().parents[3]
SOURCES = ('plugins/whatsapp/scripts/installation_layout.py', 'plugins/whatsapp/scripts/runtime_lifecycle.py', 'plugins/whatsapp/scripts/admin_install.py',
    'plugins/whatsapp/scripts/admin_handoff.py', 'plugins/whatsapp/scripts/admin_host.py',
    'host/__init__.py', 'host/lifecycle/__init__.py', 'host/lifecycle/filesystem.py',
    'host/lifecycle/evidence.py', 'host/installation.py', 'host/lifecycle/services.py', 'host/lifecycle/service_client.py',
    'host/qos/contract.py', 'host/qos/adoption.py', 'host/qos/processes.py', 'host/qos/applicator.py',
    'host/frontend/provider.py', 'host/frontend/adapter.py')
STANDALONE_SOURCES = tuple(name for name in SOURCES if not name.startswith('host/qos/'))


class RuntimeError(ValueError):
    pass


class Pending(RuntimeError):
    """Bounded observation found work or a manager job still running."""


def require(value, message):
    if not value:
        raise RuntimeError(message)


if __name__ != '__main__':
    _configure_installation(_installation_module)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def hex_value(value, size=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None


def fields(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), 'Runtime input fields differ')


def source_paths(plan):
    require(isinstance(plan, dict) and 'qos_policy' in plan,
            'Runtime plan must explicitly select QoS or null')
    return STANDALONE_SOURCES if plan['qos_policy'] is None else SOURCES


def decode(content):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate runtime JSON field')
            result[key] = value
        return result
    try:
        return json.loads(content, object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError('Invalid runtime JSON input') from error


def layout(slug):
    require(isinstance(slug, str) and re.fullmatch('[a-z][a-z0-9-]{1,19}', slug)
            and '--' not in slug, 'Invalid runtime tenant slug')
    profile=installation_profile()
    base=profile.service(slug)
    home=profile.instance_paths(slug)['gateway']
    return {'account': profile.account(slug),
        'home': home, 'bridge_unit': base + '.service', 'gateway_unit': 'whatsapp-waha.service',
        'wrapper': PROJECT + '/scripts/as-user' if slug == 'personal' else PROJECT + '/private/tenants/' + slug + '/as-user',
        'quadlet': home + '/.config/containers/systemd/whatsapp-waha.container',
        'bridge_source': '/etc/systemd/system/' + base + '.service'}


def unit_definition(values):
    """Hash only typed command identity, excluding execution timestamps/PIDs."""
    return {key: ('sha256:' + digest(encoded(values[key])) if key in EXEC_PROPERTIES else values[key])
            for key in DEFINITION}


def exec_commands(raw):
    """Decode one busctl typed property without reading Environment or logging argv."""
    require(isinstance(raw, bytes) and len(raw) <= 256 * 1024, 'Unbounded effective command property')
    value = decode(raw)
    fields(value, ('type', 'data'))
    require(value['type'] == 'a(sasbttttuii)' and isinstance(value['data'], list)
            and len(value['data']) <= 1, 'Unexpected typed effective command property')
    output = []
    for record in value['data']:
        require(isinstance(record, list) and len(record) == 10 and isinstance(record[0], str)
                and isinstance(record[1], list) and 0 < len(record[1]) <= 512
                and all(isinstance(arg, str) and '\0' not in arg for arg in record[1])
                and type(record[2]) is bool and all(type(item) is int for item in record[3:]),
                'Incomplete typed effective command identity')
        output.append({'path': record[0], 'argv': record[1], 'ignore_errors': record[2]})
    return output


def validate_unit_effects(tenant, component, value, *, deployment=None):
    """Finite stop semantics; start identity is linked to the reviewed source.

    No start operation is exposed. Remaining gateway run arguments are hashed
    for drift detection, not asserted to be a general-purpose Podman validator.
    """
    require(all(not value[key] for key in PROPAGATION_PROPERTIES), 'Runtime lifecycle can propagate to another unit')
    require(all(not value[key] for key in ('ExecStartPre', 'ExecStartPost', 'ExecCondition')),
            'Auxiliary runtime execution is not supported')
    require(len(value['ExecStart']) == 1, 'One source-linked runtime entry point is required')
    start = value['ExecStart'][0]
    require(not start['ignore_errors'], 'Runtime entry point cannot ignore errors')
    if component == 'bridge':
        executable = PROJECT + '/.venv/bin/python'
        config = installation_profile().instance_paths(tenant['slug'])['configuration'] + '/config.toml'
        permitted = ([executable, '-m', 'sally_whatsapp.cli', '--config', config, 'serve'],
            [executable, installation_path('/usr/local/lib/develative-deploy/whatsapp/release_runtime.py'), '--config', config])
        if deployment is not None:
            from admin_deployment import Runtime
            require(isinstance(deployment, Runtime) and deployment.instance['slug'] == tenant['slug']
                    and deployment.instance['user'] == tenant['account']
                    and deployment.instance['uid'] == tenant['uid'] and deployment.instance['gid'] == tenant['gid']
                    and deployment.instance['unit'] == tenant['bridge_unit']
                    and deployment.instance['config'] == config, 'Deployment service identity differs')
            deployment.check_current()
            permitted = (deployment.command(),)
            executable = permitted[0][0]
        require(start['path'] == executable and start['argv'] in permitted
                and not value['ExecStop'] and not value['ExecStopPost']
                and value['FragmentPath'] == tenant['bridge_source'] and not value['SourcePath']
                and value['User'] == tenant['account'] and value['KillMode'] == 'control-group',
                'Bridge lifecycle differs from its finite source contract')
    else:
        cid = '/run/user/' + str(tenant['uid']) + '/whatsapp-waha.cid'
        prefix = ['/usr/bin/podman', 'run', '--name', 'whatsapp-waha', '--cidfile=' + cid]
        require(start['path'] == '/usr/bin/podman' and start['argv'][:5] == prefix
                and value['SourcePath'] == tenant['quadlet']
                and value['FragmentPath'] == '/run/user/' + str(tenant['uid']) + '/systemd/generator/whatsapp-waha.service'
                and not value['User'] and value['KillMode'] in ('mixed', 'control-group'),
                'Gateway entry point is not linked to the named rootless Quadlet')
        argv = ['/usr/bin/podman', 'rm', '-v', '-f', '-i', '--cidfile=' + cid]
        for key, ignore in (('ExecStop', False), ('ExecStopPost', True)):
            require(value[key] == [{'path': '/usr/bin/podman', 'argv': argv, 'ignore_errors': ignore}],
                    'Gateway cleanup differs from the finite named-container contract')
    return 'whatsapp-rootless-quadlet-cleanup-v1'


def _metadata(spec):
    fields(spec, ('sha256', 'mode', 'uid', 'gid'))
    require(hex_value(spec['sha256']) and all(type(spec[k]) is int and spec[k] >= 0 for k in ('mode', 'uid', 'gid'))
            and spec['mode'] <= 0o7777, 'Invalid runtime file metadata')


def _read_protected(root, item):
    fields(item, ('path', 'sha256'))
    from host.lifecycle.evidence import path_name
    path_name(item['path']); require(hex_value(item['sha256']), 'Invalid protected input digest')
    before = root.snapshot(item['path'])
    require(before is not None and before['uid'] == root.uid and not before['mode'] & 0o022,
            'Runtime input is not administratively protected')
    content = root.read_bytes(item['path'], max_bytes=8 * 1024 * 1024)
    require(digest(content) == item['sha256'] and root.snapshot(item['path']) == before,
            'Runtime input changed')
    return decode(content)


def require_no_active_qos(root):
    """Read host membership without importing QoS, resolving accounts or mutating it.

    A null policy is an explicit nonparticipation assertion. Protected host
    records must agree; an unfinished transaction cannot attest retirement.
    These repeated observations do not lock out a concurrent host adoption.
    """
    registry_path = '/etc/develative-host-qos/registry.json'
    policy_path = '/etc/develative-host-qos/policy.json'
    pointer_path = '/var/lib/develative-host-qos/active-operation.json'
    observed = {}

    def read(path, *, json_value=True):
        before = root.snapshot(path); observed[path] = before
        if before is None:
            return None
        require(before['uid'] == root.uid and not before['mode'] & 0o022,
                'QoS nonparticipation record is not protected')
        raw = root.read_bytes(path, max_bytes=8 * 1024 * 1024)
        require(root.snapshot(path) == before and digest(raw) == before['sha256'],
                'QoS nonparticipation record changed')
        if not json_value:
            return raw
        value = decode(raw)
        encoded(value)  # Reject nonfinite JSON values, including nested ones.
        return value

    def membership(value):
        fields(value, ('format', 'policy_sha256', 'consumers'))
        require(type(value['format']) is int and value['format'] == 1
                and hex_value(value['policy_sha256'])
                and isinstance(value['consumers'], dict) and len(value['consumers']) <= 256,
                'QoS registry identity is ambiguous')
        uids = set()
        for name, consumer in value['consumers'].items():
            fields(consumer, ('owner', 'account', 'uid', 'gid', 'home', 'unit', 'status'))
            require(consumer['owner'] in ('whatsapp', 'box') and isinstance(name, str)
                    and re.fullmatch(consumer['owner'] + r'\.[a-z][a-z0-9-]{0,31}', name)
                    and consumer['status'] in ('active', 'retired')
                    and type(consumer['uid']) is int and 0 < consumer['uid'] < 2**31 and consumer['uid'] not in uids
                    and type(consumer['gid']) is int and 0 <= consumer['gid'] < 2**31
                    and all(isinstance(consumer[key], str) and 0 < len(consumer[key]) <= 544
                            and not any(c in consumer[key] for c in '\x00\n\r') for key in ('account', 'home', 'unit')),
                    'QoS consumer membership is ambiguous')
            uids.add(consumer['uid'])
        return value['consumers']

    registry = read(registry_path)
    policy = read(policy_path, json_value=False)
    pointer = read(pointer_path)
    if registry is None:
        require(policy is None and pointer is None,
                'Missing QoS registry cannot prove absence while policy or operation state remains')
    else:
        consumers = membership(registry)
        require(policy is not None and digest(policy) == registry['policy_sha256'],
                'QoS policy identity is ambiguous')
        require(not any(item['owner'] == 'whatsapp' and item['status'] == 'active' for item in consumers.values()),
                'Null QoS policy cannot omit an active WhatsApp consumer')
        if pointer is not None:
            fields(pointer, ('format', 'request'))
            require(type(pointer['format']) is int and pointer['format'] == 1
                    and isinstance(pointer['request'], dict), 'QoS operation pointer is ambiguous')
            request = pointer['request']
            ordinary = {'policy_sha256', 'action', 'operation_id', 'consumer_id', 'account', 'unit'}
            frontend = {'policy_sha256', 'action', 'operation_id', 'consumer_id',
                        'frontend_operation_id', 'frontend_receipt_sha256'}
            require(hex_value(request.get('operation_id'), 32)
                    and request.get('policy_sha256') == registry['policy_sha256']
                    and (set(request) == ordinary and request.get('action') in ('apply', 'register-consumer', 'retire-consumer')
                         or set(request) == frontend and request.get('action') == 'register-frontend'),
                    'QoS operation identity is ambiguous')
            journal = read('/var/lib/develative-host-qos/operations/' + request['operation_id'] + '.json')
            require(isinstance(journal, dict) and type(journal.get('format')) is int and journal['format'] == 1
                    and journal.get('request') == request and journal.get('phase') == 'committed',
                    'Pending or incoherent QoS operation must finish before null-policy retirement')
            if request['action'] == 'register-frontend':
                fields(journal, ('format', 'request', 'before', 'after', 'phase'))
            else:
                fields(journal, ('format', 'request', 'registration', 'registration_state', 'frontend_retirement',
                                 'before_registry', 'after_registry', 'steps', 'done', 'phase', 'initial_state'))
                require(isinstance(journal['steps'], list) and type(journal['done']) is int
                        and journal['done'] == len(journal['steps']) and journal['after_registry'] == registry,
                        'Committed QoS operation is incomplete or differs from current membership')
                membership(journal['before_registry'])
                require(journal['before_registry']['policy_sha256'] == registry['policy_sha256'],
                        'Historical QoS operation belongs to a different policy')
    require(all(root.snapshot(path) == before for path, before in observed.items()),
            'QoS membership changed during nonparticipation observation')


def load_plan(root, path, expected_sha256):
    """Read an externally reviewed plan, without assuming its digest authorizes it."""
    value = _read_protected(root, {'path': path, 'sha256': expected_sha256})
    validate_plan(value, authority_uid=root.uid)
    return value


def validate_plan(plan, *, authority_uid=0):
    from host.lifecycle import evidence, filesystem
    required = {'format', 'operation_id', 'source_sha256', 'admin_plan_sha256', 'admin_profile_sha256',
        'attestation', 'tenants', 'scope', 'generation_id', 'before', 'after', 'qos_policy'}
    allocation = installation_profile().roster_sha256
    if allocation is not None:
        required.add('allocation_sha256')
    fields(plan, required)
    require(plan.get('allocation_sha256') == allocation,
            'Runtime allocation changed; recompile the retirement plan')
    require(plan['format'] == FORMAT and hex_value(plan['operation_id'], 32)
            and all(hex_value(plan[key]) for key in ('source_sha256', 'admin_plan_sha256',
                                                    'admin_profile_sha256', 'generation_id')),
            'Invalid runtime retirement identity')
    require(isinstance(plan['tenants'], list) and 1 <= len(plan['tenants']) <= 64,
            'Complete bounded tenant inventory is required')
    filesystem.validate_manifest(plan['before']); filesystem.validate_manifest(plan['after'])
    before, after = plan['before'], plan['after']
    require(before['owner'] == after['owner'] == 'whatsapp'
            and before['directories'] == after['directories']
            and not before.get('links') and not after.get('links'), 'Runtime removal cannot alter directories or arbitrary links')
    require(set(after['files']) <= set(before['files']) and
            all(before['files'][path] == spec for path, spec in after['files'].items()),
            'Runtime removal only retains or quarantines named files')
    seen, identities, groups = set(), set(), set()
    retained = {HELPER, HELPER_LAYOUT}
    bridges = set()
    for tenant in plan['tenants']:
        fields(tenant, ('slug', 'account', 'uid', 'gid', 'home', 'bridge_unit', 'gateway_unit', 'wrapper',
            'quadlet', 'bridge_source', 'quadlet_metadata', 'bridge_definition', 'gateway_definition',
            'bridge_cgroup', 'gateway_cgroup', 'bridge_dropins', 'gateway_dropins'))
        wanted = layout(tenant['slug'])
        require(all(tenant[key] == value for key, value in wanted.items()), 'Tenant runtime destination differs from its source model')
        require(tenant['slug'] not in seen and tenant['uid'] not in identities
                and all(type(tenant[key]) is int and tenant[key] > 0 for key in ('uid', 'gid')),
                'Tenant UID/GID must be explicit, positive and isolated')
        seen.add(tenant['slug']); identities.add(tenant['uid'])
        _metadata(tenant['quadlet_metadata'])
        require(tenant['quadlet_metadata']['uid'] == tenant['uid']
                and tenant['quadlet_metadata']['gid'] == tenant['gid']
                and not tenant['quadlet_metadata']['mode'] & 0o022, 'Quadlet authority differs from its gateway account')
        for component in ('bridge', 'gateway'):
            definition = tenant[component + '_definition']
            fields(definition, DEFINITION)
            require(all(isinstance(value, str) for value in definition.values())
                    and definition['Id'] == tenant[component + '_unit']
                    and definition['NeedDaemonReload'] == 'no' and definition['LoadState'] == 'loaded',
                    'Exact effective runtime definitions are required')
            require(all(definition[key].startswith('sha256:') and hex_value(definition[key][7:])
                        for key in EXEC_PROPERTIES), 'Effective commands must be represented by local observation digests')
            dropins = tenant[component + '_dropins']
            require(isinstance(dropins, dict) and sorted(definition['DropInPaths'].split()) == sorted(dropins),
                    'Effective runtime drop-ins differ from the exact inventory')
            allowed_dropins = ({tenant['bridge_source'] + '.d/' + name for name in
                ('60-whatsapp-priority.conf', '70-release-runtime.conf')} if component == 'bridge' else
                {tenant['home'] + '/.config/systemd/user/whatsapp-waha.service.d/60-whatsapp-priority.conf'})
            require(set(dropins) <= allowed_dropins, 'Runtime drop-in is outside the finite source policy')
            for path, spec in dropins.items():
                _metadata(spec)
                require(spec['uid'] == authority_uid
                        and not spec['mode'] & 0o022, 'Runtime drop-in authority differs')
                if component == 'bridge':
                    require(before['files'].get(path) == {**spec, 'retention': 'managed'} and path not in after['files'],
                            'Bridge drop-in must be a named filesystem retirement')
                    bridges.add(path)
            group = tenant[component + '_cgroup']; evidence.path_name(group)
            require(group not in groups, 'Runtime cgroups overlap')
            groups.add(group)
        require(tenant['bridge_definition']['FragmentPath'] == tenant['bridge_source']
                and tenant['bridge_definition']['User'] == tenant['account']
                and tenant['gateway_definition']['SourcePath'] == tenant['quadlet'],
                'Runtime unit source or service identity differs')
        retained.add(tenant['wrapper']); bridges.add(tenant['bridge_source'])
    require(retained <= set(after['files']) and bridges <= set(before['files']) - set(after['files']),
            'Runtime helper/wrappers must remain for final observation; bridge units must be retired')
    require(before['files'][HELPER]['sha256'] == plan['source_sha256'], 'UID helper must be the reviewed runtime source')
    for path, spec in before['files'].items():
        allowed = path in retained | bridges or (path.startswith(PROJECT + '/sally_whatsapp/')
            and re.fullmatch(r'[A-Za-z0-9_/-]+\.py', path[len(PROJECT + '/sally_whatsapp/'):]))
        require(allowed and '..' not in Path(path).parts and spec['uid'] == authority_uid and not spec['mode'] & 0o022,
                'Runtime file is outside the protected application code/unit policy')
    evidence.validate_scope(plan['scope'])
    require(set(plan['scope']['cgroups']) == groups and not plan['scope']['script_roots']
            and not plan['scope']['script_paths'], 'Runtime census must bind every exact bridge and gateway cgroup')
    if plan['qos_policy'] is not None:
        fields(plan['qos_policy'], ('path', 'sha256')); evidence.path_name(plan['qos_policy']['path'])
        require(hex_value(plan['qos_policy']['sha256']), 'A reviewed host QoS policy is required')
    fields(plan['attestation'], ('path', 'sha256')); evidence.path_name(plan['attestation']['path'])
    require(hex_value(plan['attestation']['sha256']), 'A complete root runtime inventory attestation is required')
    return digest(encoded(plan))


def command(tenant, component, operation):
    """No arbitrary unit, wrapper, account, daemon or workload command is accepted."""
    wanted = layout(tenant['slug'])
    require(all(tenant[key] == value for key, value in wanted.items()), 'Runtime command identity differs')
    require(component in ('bridge', 'gateway'), 'Unknown runtime component')
    prefix = ['/usr/bin/systemctl'] if component == 'bridge' else [tenant['wrapper'], '/usr/bin/systemctl', '--user']
    unit = tenant[component + '_unit']
    if operation == 'show':
        return prefix + ['show', '--no-pager', '--all', '--property=' + ','.join(key for key in PROPERTIES if key not in EXEC_PROPERTIES), '--', unit]
    if operation in EXEC_PROPERTIES:
        escaped = ''.join(char if char.isascii() and char.isalnum() else '_' + format(ord(char), '02x') for char in unit)
        bus = ['/usr/bin/busctl', '--system'] if component == 'bridge' else [tenant['wrapper'], '/usr/bin/busctl', '--user']
        return bus + ['--json=short', 'get-property', 'org.freedesktop.systemd1',
            '/org/freedesktop/systemd1/unit/' + escaped, 'org.freedesktop.systemd1.Service', operation]
    if operation == 'stop': return prefix + ['--no-block', 'stop', '--', unit]
    if operation == 'disable' and component == 'bridge': return prefix + ['disable', '--', unit]
    if operation == 'mask' and component == 'gateway': return prefix + ['mask', '--', unit]
    if operation == 'reload': return prefix + ['daemon-reload']
    raise RuntimeError('Operation is outside the finite runtime contract')


def read_unit(tenant, component, reader):
    raw = reader(command(tenant, component, 'show'))
    require(isinstance(raw, bytes) and len(raw) <= 256 * 1024, 'Invalid bounded runtime observation')
    values = {}
    for line in raw.decode('utf-8').splitlines():
        key, separator, value = line.partition('=')
        require(separator and key in PROPERTIES and key not in EXEC_PROPERTIES and key not in values,
                'Unexpected runtime unit property')
        values[key] = value
    require(set(values) == set(PROPERTIES) - set(EXEC_PROPERTIES) and values['Id'] == tenant[component + '_unit']
            and all(re.fullmatch(r'0|[1-9][0-9]*', values[key]) for key in ('MainPID', 'ControlPID')),
            'Incomplete runtime unit or process identity')
    require(values['ControlGroup'] == tenant[component + '_cgroup'] or
            not values['ControlGroup'] and values['MainPID'] == values['ControlPID'] == '0',
            'Runtime process scope changed')
    for key in EXEC_PROPERTIES:
        values[key] = [] if values['LoadState'] in ('masked', 'not-found') else exec_commands(reader(command(tenant, component, key)))
    return values


def _capture_unit_property(argv):
    """Read one source-finite command with incremental time/output bounds."""
    import selectors
    import subprocess
    import time
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0'})
    selector = selectors.DefaultSelector(); output = bytearray(); total = 0; deadline = time.monotonic() + 5
    try:
        for stream in (child.stdout, child.stderr):
            os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'Unit observation exceeded its time bound')
            for event, _ in selector.select(remaining):
                data = os.read(event.fd, 8192)
                if not data: selector.unregister(event.fileobj); continue
                total += len(data); require(total <= 256 * 1024, 'Unit observation exceeded its byte bound')
                if event.fileobj is child.stdout: output.extend(data)
        child.wait(timeout=max(0.001, deadline-time.monotonic()))
        require(child.returncode == 0, 'Unit property observation failed')
        return bytes(output)
    finally:
        selector.close()
        if child.poll() is None: child.kill()
        child.wait(); child.stdout.close(); child.stderr.close()


def _observer_file(root_path, tenant, path, expected):
    """Read only a validated nominal source; no generalized write authority."""
    root_path = Path(root_path).absolute()
    require(root_path == root_path.resolve(strict=True), 'Observation root must be physical')
    descriptor = os.open(root_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    authority = os.fstat(descriptor).st_uid
    try:
        require(not os.fstat(descriptor).st_mode & 0o022, 'Observation root is not protected')
        current = ''
        for part in Path(path).parts[1:-1]:
            current += '/' + part
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
            info = os.fstat(descriptor)
            owners = (authority, tenant['uid']) if current == tenant['home'] or current.startswith(tenant['home'] + '/') else (authority,)
            require(info.st_uid in owners and not info.st_mode & 0o022, 'Nominal source ancestor is not protected')
        name = Path(path).name
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(child, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 65536,
                    'Nominal source is not a bounded physical single-link file')
            content = stream.read(65537); after = os.fstat(stream.fileno())
        current_info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(len(content) <= 65536 and identity(info) == identity(after) == identity(current_info),
                'Nominal source changed during observation')
        actual = {'sha256': digest(content), 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
        require(actual == expected, 'Nominal source differs from its reviewed metadata')
        return content
    finally: os.close(descriptor)


def collect_units(root_path, request_bytes, expected_sha256, *, reader=None, lookup=pwd.getpwnam):
    """Initial read-only observation; no retirement plan or installed helper.

    Trust comes from independently pinned, protected request/source/provenance.
    An input digest by itself is neither authorization nor invoker completeness.
    Fixture callers inject their own reader/account model and physical root.
    """
    require(isinstance(request_bytes, bytes) and len(request_bytes) <= 1024 * 1024
            and hex_value(expected_sha256) and digest(request_bytes) == expected_sha256, 'Observation request differs from its pin')
    request = decode(request_bytes)
    fields(request, ('format', 'operation_id', 'source', 'layout_source', 'provenance', 'tenants'))
    require(request['format'] == 'whatsapp-runtime-observation-v2' and hex_value(request['operation_id'], 32)
            and isinstance(request['tenants'], list) and 1 <= len(request['tenants']) <= 64, 'Invalid bounded observation request')
    for key in ('source', 'layout_source', 'provenance'):
        fields(request[key], ('path', 'sha256'))
        require(hex_value(request[key]['sha256']), 'Observation input requires an independent digest')
    require(request['source']['path'] == str(Path(__file__).absolute()), 'Collector source path is not this exact entrypoint')
    source_relative = '/' + str(Path(__file__).absolute().relative_to(SOURCE_ROOT))
    source = _bootstrap_read(SOURCE_ROOT, source_relative)
    require(digest(source) == request['source']['sha256'], 'Collector source differs from its reviewed pin')
    layout_path = Path(__file__).absolute().with_name('installation_layout.py')
    require(request['layout_source']['path'] == str(layout_path), 'Collector layout must be its exact sibling')
    layout_source = _bootstrap_read(SOURCE_ROOT, '/' + str(layout_path.relative_to(SOURCE_ROOT)))
    require(digest(layout_source) == request['layout_source']['sha256'], 'Collector layout differs from its reviewed pin')
    root_path = Path(root_path).absolute(); authority = root_path.stat().st_uid
    if root_path == Path('/'):
        require(os.geteuid() == 0 and all(path.stat().st_uid == 0 and not path.stat().st_mode & 0o022
            for path in (SOURCE_ROOT, *SOURCE_ROOT.parents)), 'Host collector requires protected root source ancestry')
    else:
        require(reader is not None and lookup is not pwd.getpwnam, 'Fixture observations require explicit isolated adapters')
    provenance_raw = _bootstrap_read(root_path, request['provenance']['path'], maximum=1024 * 1024)
    require(digest(provenance_raw) == request['provenance']['sha256'], 'Observation provenance changed')
    provenance = decode(provenance_raw)
    require(provenance == {'format': 2, 'operation_id': request['operation_id'],
        'source_sha256': request['source']['sha256'], 'layout_sha256': request['layout_source']['sha256'],
        'tenant_scope_sha256': digest(encoded(request['tenants']))},
        'Observation provenance is not bound to both exact sources and tenant scope')
    installation = _captured_installation(layout_source, layout_path, root_path)
    pinned = types.ModuleType('_wa_runtime_observer_captured')
    pinned.__file__ = str(Path(__file__).absolute())
    pinned._PINNED_INSTALLATION_LAYOUT = installation
    exec(compile(source, pinned.__file__, 'exec'), pinned.__dict__)
    try:
        return pinned._observe_units(root_path, request, expected_sha256, provenance_raw, source, layout_source,
            reader=reader, lookup=lookup)
    except pinned.RuntimeError as error:
        raise RuntimeError(str(error)) from error


def _observe_units(root_path, request, expected_sha256, provenance_raw, source, layout_source, *, reader, lookup):
    """Run only inside the independently captured collector and installation."""
    import time
    authority = root_path.stat().st_uid
    source_relative = '/' + str(Path(__file__).absolute().relative_to(SOURCE_ROOT))
    layout_relative = str(Path(source_relative).with_name('installation_layout.py'))
    tenants = []; seen = set(); uids = set()
    for item in request['tenants']:
        fields(item, ('slug', 'uid', 'gid', 'bridge_cgroup', 'gateway_cgroup', 'wrapper', 'sources'))
        tenant = {**item, **layout(item['slug'])}
        require(item['slug'] not in seen and type(item['uid']) is int and item['uid'] > 0
                and type(item['gid']) is int and item['gid'] > 0 and item['uid'] not in uids,
                'Observation tenant identity is not isolated')
        seen.add(item['slug']); uids.add(item['uid'])
        uid = str(item['uid'])
        require(item['bridge_cgroup'] == '/system.slice/' + tenant['bridge_unit'] and item['gateway_cgroup'] in
            ('/system.slice/user@' + uid + '.service/app.slice/whatsapp-waha.service',
             '/user.slice/user-' + uid + '.slice/user@' + uid + '.service/app.slice/whatsapp-waha.service'),
            'Observation cgroup is outside the named tenant layout')
        _metadata(item['wrapper'])
        require(item['wrapper']['uid'] == authority and item['wrapper']['mode'] & 0o100
                and not item['wrapper']['mode'] & 0o022, 'Observation wrapper must be administratively protected')
        allowed = {tenant['bridge_source'], tenant['quadlet'], tenant['bridge_source'] + '.d/60-whatsapp-priority.conf',
            tenant['bridge_source'] + '.d/70-release-runtime.conf',
            tenant['home'] + '/.config/systemd/user/whatsapp-waha.service.d/60-whatsapp-priority.conf'}
        require(isinstance(item['sources'], dict) and {tenant['bridge_source'], tenant['quadlet']} <= set(item['sources'])
                <= allowed, 'Observation sources differ from the finite tenant lineage')
        for path, spec in item['sources'].items():
            _metadata(spec)
            require(spec['uid'] == (tenant['uid'] if path == tenant['quadlet'] else authority)
                    and not spec['mode'] & 0o022, 'Observation source ownership differs')
        tenants.append((tenant, item))
    def attest_sources():
        installation_profile()
        total = 0
        for tenant, item in tenants:
            account = lookup(tenant['account'])
            require((account.pw_uid, account.pw_gid, account.pw_dir) == (tenant['uid'], tenant['gid'], tenant['home']),
                    'Observation account identity differs')
            wrapper = _observer_file(root_path, tenant, tenant['wrapper'], item['wrapper'])
            expected_wrapper = ('#!/bin/sh\nset -eu\ncd ' + tenant['home'] + '\nexec runuser -u ' + tenant['account'] +
                ' -- env HOME=' + tenant['home'] + ' XDG_RUNTIME_DIR=/run/user/' + str(tenant['uid']) +
                ' DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(tenant['uid']) + '/bus "$@"\n')
            require(wrapper == expected_wrapper.encode(), 'Observation wrapper differs from its finite source template')
            for path, spec in item['sources'].items():
                total += len(_observer_file(root_path, tenant, path, spec))
                require(total <= 16 * 1024 * 1024, 'Observation source collection exceeded its bound')
        require(_bootstrap_read(root_path, request['provenance']['path'], maximum=1024 * 1024) == provenance_raw
                and _bootstrap_read(SOURCE_ROOT, source_relative) == source
                and _bootstrap_read(SOURCE_ROOT, layout_relative) == layout_source, 'Observation trust inputs changed')
    attest_sources(); observed = []; deadline = time.monotonic() + 60
    effective_reader = _capture_unit_property if reader is None else reader
    def bounded_reader(argv):
        require(time.monotonic() < deadline, 'Observation exceeded its aggregate time bound')
        return effective_reader(argv)
    for _ in range(2):
        snapshot = {}
        for tenant, item in tenants:
            for component in ('bridge', 'gateway'):
                value = read_unit(tenant, component, bounded_reader)
                require(value['LoadState'] == 'loaded' and value['NeedDaemonReload'] == 'no'
                        and value['Job'] in ('', '0'), 'Observation requires a stable loaded unit without pending work')
                validate_unit_effects(tenant, component, value)
                expected_dropins = sorted(path for path in item['sources'] if path.endswith('.conf') and
                    (path.startswith(tenant['bridge_source'] + '.d/') if component == 'bridge' else path.startswith(tenant['home'] + '/')))
                require(sorted(value['DropInPaths'].split()) == expected_dropins, 'Observed drop-ins differ from the pinned source lineage')
                snapshot[tenant['slug'] + ':' + component] = value
        observed.append(snapshot)
    require(observed[0] == observed[1], 'Unit observation changed between snapshots')
    attest_sources()
    return {'format': 'whatsapp-runtime-observation-receipt-v2', 'operation_id': request['operation_id'],
        'request_sha256': expected_sha256, 'source_sha256': request['source']['sha256'],
        'layout_sha256': request['layout_source']['sha256'],
        'provenance_sha256': request['provenance']['sha256'], 'mutations': False,
        'invoker_completeness_proven': False, 'lifecycle_contract': 'whatsapp-rootless-quadlet-cleanup-v1',
        'units': {name: {'definition': unit_definition(value), 'state': {key: value[key] for key in
            ('ActiveState', 'SubState', 'MainPID', 'ControlPID', 'Job', 'ControlGroup', 'UnitFileState')}}
            for name, value in observed[0].items()}}


def collector_main(argv):
    parser = argparse.ArgumentParser(description='Finite initial runtime observation; no retirement or host-provider plan required')
    parser.add_argument('--request', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args(argv)
    require(os.geteuid() == 0, 'Initial host observation requires administrative authority')
    raw = _bootstrap_read(Path('/'), args.request, maximum=1024 * 1024)
    print(json.dumps(collect_units(Path('/'), raw, args.sha256), sort_keys=True))
    return 0


def _quarantine_name(operation_id):
    require(hex_value(operation_id, 32), 'Invalid Quadlet operation identity')
    return 'whatsapp-waha.container.retired-' + operation_id + '.quarantine'


def supervise_runtime_client(argv, lease, *, timeout=30):
    """Keep the app lease through runuser's own late/orphaned helper descendants.

    This is called only in our dedicated fork child. systemd-managed workloads
    are not its descendants. A blocked helper keeps the lease rather than
    allowing another controller to race its unfinished filesystem operation.
    """
    from host.lifecycle.service_client import supervise
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(36, 1, 0, 0, 0) == 0, 'A private client subreaper is required')
    try:
        return supervise(argv, lease, timeout=timeout)
    finally:
        while True:
            try: os.waitpid(-1, 0)
            except InterruptedError: continue
            except ChildProcessError: break


def quadlet_retire(home, operation_id, expected, *, authority_uid=None, check_only=False, retired=False, artifact='quadlet'):
    """UID-scoped helper; one file, same-parent rename, no directory/data deletion.

    The production CLI derives home from slug and requires its exact UID. Tests
    may pass an isolated physical home and their own current UID explicitly.
    """
    _metadata(expected)
    uid = os.geteuid() if authority_uid is None else authority_uid
    require(uid == os.geteuid(), 'Quadlet helper must run as its exact gateway UID')
    require(artifact == 'gateway-priority' or expected['uid'] == uid, 'Quadlet source is not owned by its gateway UID')
    if artifact == 'gateway-priority':
        require(check_only and not retired and expected['uid'] in (0, uid),
                'Gateway priority is a retained, read-only administrative artifact')
    home = Path(home)
    require(home.is_absolute() and str(home) == str(home.resolve(strict=True)), 'Gateway home must be physical')
    selections = {'quadlet': (('.config', 'containers', 'systemd'), 'whatsapp-waha.container'),
        'gateway-priority': (('.config', 'systemd', 'user', 'whatsapp-waha.service.d'), '60-whatsapp-priority.conf')}
    require(artifact in selections, 'UID helper artifact is outside the finite source policy')
    parents, source = selections[artifact]
    descriptor = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in (None, *parents):
            if part is not None:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor); descriptor = child
            info = os.fstat(descriptor)
            require(info.st_uid in ((uid, 0) if artifact == 'gateway-priority' else (uid,))
                    and not info.st_mode & 0o022, 'Quadlet parent is not protected by its account')
        target = source + '.retired-' + operation_id + '.quarantine'
        require(hex_value(operation_id, 32), 'Invalid UID artifact operation identity')
        def snapshot(name):
            try: child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            except FileNotFoundError: return None
            with os.fdopen(child, 'rb') as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 1024 * 1024,
                        'Quadlet is not a bounded physical single-link file')
                data = stream.read(1024 * 1024 + 1); after = os.fstat(stream.fileno())
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            require(len(data) <= 1024 * 1024 and identity(info) == identity(after) == identity(current),
                    'Quadlet changed during inspection')
            if artifact == 'gateway-priority':
                require([line.strip() for line in data.decode('utf-8').splitlines()
                    if line.strip() and not line.lstrip().startswith('#')] ==
                    ['[Service]', 'CPUWeight=800', 'IOWeight=800'], 'Retained priority artifact has unsupported effects')
            return {'sha256': digest(data), 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
        original, quarantined = snapshot(source), snapshot(target)
        if artifact == 'gateway-priority':
            require(original == expected and quarantined is None, 'Retained gateway priority artifact changed')
            return {'status': 'retained', 'sha256': expected['sha256']}
        require((original == expected and quarantined is None) or (original is None and quarantined == expected),
                'Quadlet source/quarantine state differs; retain both for inspection')
        if check_only:
            require((original is None and quarantined == expected) if retired else
                    (original == expected and quarantined is None), 'Quadlet phase differs')
            return {'status': 'retired' if retired else 'present', 'sha256': expected['sha256']}
        if original is not None:
            rename = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
            require(rename is not None, 'Atomic no-replace rename is required')
            rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
            rename.restype = ctypes.c_int
            if rename(descriptor, source.encode(), descriptor, target.encode(), 1):
                raise OSError(ctypes.get_errno(), 'Quadlet quarantine could not be created without replacement')
            os.fsync(descriptor)
        require(snapshot(source) is None and snapshot(target) == expected, 'Quadlet retirement did not verify')
        return {'status': 'retired', 'sha256': expected['sha256'], 'quarantine': target}
    finally:
        os.close(descriptor)


class RuntimeHost:
    """Concrete retirement coordinator; dependencies are explicit, never fake defaults."""
    def __init__(self, root, plan, *, admin_plan, admin_provider, frontend_adapter,
                 qos_module=None, qos_options=None, reader=None, runner=None, lookup=pwd.getpwnam, proc_root='/proc', fault=None):
        from host.lifecycle import evidence, filesystem, services
        self.evidence, self.fs, self.services = evidence, filesystem, services
        self.root = root; self.plan = decode(encoded(plan)); self.plan_digest = validate_plan(self.plan, authority_uid=root.uid)
        if self.plan['qos_policy'] is not None and qos_module is None:
            from host.qos import applicator as qos_module
        self.admin_plan, self.admin = admin_plan, admin_provider
        self.frontend, self.qos = frontend_adapter, qos_module
        self.qos_options = {} if qos_options is None else dict(qos_options)
        require(set(self.qos_options) <= {'kernel_factory', 'lookup', 'census', 'proc_root'}, 'Invalid isolated QoS injection')
        self.reader, self.runner, self.lookup = reader, runner, lookup
        self.proc_root, self.fault = proc_root, fault
        self.journal_path = STATE + '/runtime-retirement-' + plan['operation_id'] + '.json'
        require(digest(encoded(admin_plan)) == plan['admin_plan_sha256']
                and admin_provider.profile_digest == plan['admin_profile_sha256']
                and admin_plan['mode'] == 'remove'
                and admin_plan.get('runtime_retirement') == {'operation_id': plan['operation_id']}, 'Runtime retirement is not bound to the reviewed administrative removal')
        if root.base != Path('/'):
            require(reader is not None and runner is not None and
                    (self.plan['qos_policy'] is None or qos_module.__name__ != 'host.qos.applicator'
                     or set(self.qos_options) == {'kernel_factory', 'lookup', 'census', 'proc_root'}),
                    'Fixture roots require isolated service and QoS adapters')

    def _event(self, name, value):
        if self.fault is not None: self.fault(name, decode(encoded(value)))

    def _save(self, journal):
        current = self.root.snapshot(self.journal_path)
        spec = {'mode': 0o600, 'uid': self.root.uid, 'gid': self.root.gid}
        require(current is None or all(current[key] == value for key, value in spec.items()),
                'Runtime journal protection changed')
        self.root._write(self.journal_path, encoded(journal), spec, temporary=self.journal_path + '.next')
        self._event('journal-saved', journal)

    def _journal(self):
        if self.root.snapshot(self.journal_path) is None: return None
        spec = self.root.snapshot(self.journal_path)
        require(spec['uid'] == self.root.uid and spec['mode'] == 0o600, 'Runtime journal is not protected')
        value = decode(self.root.read_bytes(self.journal_path, max_bytes=8 * 1024 * 1024))
        fields(value, ('format', 'operation_id', 'admin_plan_sha256', 'plan_sha256', 'phase', 'intent', 'processes', 'receipts'))
        require(value['format'] == FORMAT and value['operation_id'] == self.plan['operation_id']
                and value['admin_plan_sha256'] == self.plan['admin_plan_sha256']
                and value['plan_sha256'] == self.plan_digest
                and value['phase'] in PHASES and isinstance(value['receipts'], dict), 'Runtime journal identity or phase differs')
        index = PHASES.index(value['phase'])
        require(value['intent'] is None or index + 1 < len(PHASES) and value['intent'] == PHASES[index + 1],
                'Runtime journal cannot roll back or skip a phase')
        self.evidence._validate_prior(value['processes'])
        return value

    def _admission(self):
        if self.plan['qos_policy'] is None:
            require_no_active_qos(self.root)
        import admin_handoff
        journal = admin_handoff._load(self.root, self.admin_plan, self.plan['admin_plan_sha256'])
        require(journal is not None and journal['phase'] == 'retired' and journal['intent'] is None,
                'Runtime retirement requires completed administrative retirement before helper removal')
        require(decode(self.root.read_bytes(OWNER, max_bytes=8192)) == {**self.admin_plan['owner'], 'state': 'retired'},
                'Administrative admission is not retired')
        owner_metadata = self.root.snapshot(OWNER)
        require(owner_metadata is not None and owner_metadata['uid'] == self.root.uid and not owner_metadata['mode'] & 0o022,
                'Administrative owner record is not protected')
        self.admin.journals_terminal(self.admin_plan)
        envelope = self.admin.observe(self.admin_plan, journal['processes'], phase='removal')
        require(envelope['context']['plan_digest'] == self.plan['admin_plan_sha256'], 'Administrative evidence belongs to another plan')
        self.evidence.require_quiescent(envelope['receipt'], context=envelope['context'], now_ns=self.admin.now_ns())
        record = _read_protected(self.root, self.plan['attestation'])
        fields(record, ('format', 'operation_id', 'tenant_slugs', 'manual_policy', 'references'))
        require(record['format'] == 1 and record['operation_id'] == self.plan['operation_id']
                and record['tenant_slugs'] == sorted(item['slug'] for item in self.plan['tenants'])
                and record['manual_policy'] == 'unregistered-runtime-starts-frozen'
                and isinstance(record['references'], dict), 'Complete runtime initiator attestation differs')
        require(bool(record['references']), 'Named external runtime references are required')
        registry_path = PROJECT + '/private/tenants.json'
        registry_spec = record['references'].get(registry_path)
        require(registry_spec is not None, 'Runtime retirement requires the protected tenant registry reference')
        for path, spec in record['references'].items():
            self.evidence.path_name(path)
            require(path not in self.plan['before']['files'], 'External references must be distinct from managed runtime artifacts')
            if spec is not None: _metadata(spec)
            require(self.root.snapshot(path) == spec, 'Runtime external reference changed')
        registry = _read_protected(self.root, {'path': registry_path, 'sha256': registry_spec['sha256']})
        fields(registry, ('format', 'instances'))
        require(type(registry['format']) is int and registry['format'] == 1
                and isinstance(registry['instances'], dict) and 1 <= len(registry['instances']) <= 64,
                'Invalid authoritative runtime tenant registry')
        for slug, row in registry['instances'].items():
            layout(slug)
            require(isinstance(row, dict) and isinstance(row.get('spec'), dict)
                    and row['spec'].get('slug') == slug and type(row.get('enabled')) is bool
                    and row.get('phase') in ('preparing', 'prepared', 'existing', 'ready'),
                    'Invalid registered runtime tenant identity')
        # The public profile may reserve tenants which have never been created.
        # Every registered tenant, including disabled or partially prepared ones,
        # must nevertheless be covered before retiring the whole owner frontend.
        require(set(registry['instances']) == {item['slug'] for item in self.plan['tenants']},
                'Runtime retirement must cover every registered tenant')
        return envelope['receipt']['receipt_digest']

    def _sources(self, *, removed=False, verify_absence=True):
        wanted = self.plan['after'] if removed else self.plan['before']
        for path, spec in wanted['files'].items():
            require(self.root.snapshot(path) == {key: value for key, value in spec.items() if key != 'retention'},
                    'Named runtime source changed')
        if removed and verify_absence:
            for path in set(self.plan['before']['files']) - set(wanted['files']):
                require(self.root.snapshot(path) is None, 'Retired runtime artifact reappeared')
        for tenant in self.plan['tenants']:
            account = self.lookup(tenant['account'])
            require((account.pw_uid, account.pw_gid, account.pw_dir) == (tenant['uid'], tenant['gid'], tenant['home']),
                    'Gateway account identity changed')
            expected_wrapper = ('#!/bin/sh\nset -eu\ncd ' + tenant['home'] + '\nexec runuser -u ' +
                tenant['account'] + ' -- env HOME=' + tenant['home'] + ' XDG_RUNTIME_DIR=/run/user/' +
                str(tenant['uid']) + ' DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(tenant['uid']) + '/bus "$@"\n')
            require(self.root.read_bytes(tenant['wrapper'], max_bytes=4096) == expected_wrapper.encode(),
                    'Gateway wrapper differs from the finite source template')
            require(self.root.snapshot(tenant['wrapper'])['mode'] & 0o100, 'Gateway wrapper must be executable by root')

    def _read(self, tenant, component):
        reader = self.reader or (lambda argv: self.services._bounded(argv, timeout=5).encode())
        return read_unit(tenant, component, reader)

    def observe_units(self):
        """Read twice locally; report exact definitions with command hashes only.

        This supplies missing effective properties for a subsequent reviewed
        plan. It does not grant admission or establish invoker completeness.
        """
        self._sources()
        readings = [{tenant['slug'] + ':' + component: self._read(tenant, component)
            for tenant in self.plan['tenants'] for component in ('bridge', 'gateway')} for _ in range(2)]
        require(readings[0] == readings[1], 'Effective runtime definitions changed during observation')
        for tenant in self.plan['tenants']:
            for component in ('bridge', 'gateway'):
                validate_unit_effects(tenant, component, readings[0][tenant['slug'] + ':' + component])
        return {'mutations': False, 'invoker_completeness_proven': False,
            'lifecycle_contract': 'whatsapp-rootless-quadlet-cleanup-v1',
            'units': {name: {'definition': unit_definition(value),
                'state': {key: value[key] for key in ('ActiveState', 'SubState', 'MainPID', 'ControlPID',
                    'Job', 'ControlGroup', 'UnitFileState')}} for name, value in readings[0].items()}}

    def _units(self, *, closed=False, removed=False, allow_masked=False):
        result = {}
        for tenant in self.plan['tenants']:
            for component in ('bridge', 'gateway'):
                value = self._read(tenant, component)
                if value['Job'] not in ('', '0'): raise Pending('Runtime manager job is still pending')
                require(all(not value[key] for key in PROPAGATION_PROPERTIES), 'Runtime lifecycle can propagate to another unit')
                if value['LoadState'] == 'masked':
                    require(value['ActiveState'] in ('inactive', 'failed') and value['MainPID'] == value['ControlPID'] == '0',
                            'A masked runtime unexpectedly remains active')
                if closed:
                    require(value['ActiveState'] in ('inactive', 'failed') and value['MainPID'] == value['ControlPID'] == '0',
                            'Runtime service has not drained')
                if closed or (allow_masked and component == 'gateway' and value['LoadState'] == 'masked'):
                    if component == 'gateway':
                        require(value['LoadState'] == 'masked' and value['UnitFileState'] == 'masked'
                                and value['FragmentPath'] == '/dev/null' and not value['DropInPaths'],
                                'Gateway must retain its named inactive mask')
                    elif removed:
                        require(value['LoadState'] == 'not-found' and value['UnitFileState'] in ('', 'disabled'),
                                'Retired bridge definition is still loaded')
                        require(not value['DropInPaths'] and not value['FragmentPath'], 'A retired bridge still has a loaded source')
                    else:
                        require(value['UnitFileState'] == 'disabled', 'Bridge must be disabled')
                if not (component == 'gateway' and value['LoadState'] == 'masked') and not (removed and component == 'bridge'):
                    validate_unit_effects(tenant, component, value)
                    require(unit_definition(value) == tenant[component + '_definition'],
                            'Effective runtime definition differs from the reviewed inventory')
                result[tenant['slug'] + ':' + component] = value
        return result

    def _census(self, prior, *, quiescent=False):
        snapshots = [self.evidence.collect_processes(self.plan['scope'], proc_root=self.proc_root,
            generation_id=self.plan['generation_id'], prior_processes=prior) for _ in range(2)]
        require(snapshots[0] == snapshots[1], 'Runtime census changed; observe again')
        if quiescent and any(item['state'] not in ('Z', 'X', 'x') for item in snapshots[0]['processes']):
            raise Pending('Runtime process or late descendant still exists')
        return snapshots[0]['processes']

    def _run(self, argv, lease):
        self.services._require_service_lease(self.root, lease)
        if self.runner is not None: return self.runner(argv, lease=lease)
        # A local supervisor, independent of systemctl/runuser FD handling,
        # keeps only the application lease until its bounded own child is reaped.
        child = os.fork()
        if child == 0:
            try:
                keep = lease[0]
                os.closerange(3, keep); os.closerange(keep + 1, 65536)
                supervise_runtime_client(argv, lease)
                os._exit(0)
            except BaseException: os._exit(71)
        _, status = os.waitpid(child, 0)
        require(os.waitstatus_to_exitcode(status) == 0, 'Runtime service client did not complete; reobserve before resuming')

    def _quadlets(self, lease, *, check_only=False, retired=False):
        for tenant in self.plan['tenants']:
            action = ('_check-retired-quadlet' if retired else '_check-quadlet') if check_only else '_retire-quadlet'
            selections = {'quadlet': tenant['quadlet_metadata']}
            if tenant['gateway_dropins']:
                selections['gateway-priority'] = next(iter(tenant['gateway_dropins'].values()))
            for artifact, spec in selections.items():
                selected_action = '_check-quadlet' if artifact == 'gateway-priority' else action
                argv = [tenant['wrapper'], '/usr/bin/python3', '-I', '-B', HELPER, selected_action,
                    tenant['slug'], self.plan['operation_id'], spec['sha256'], str(spec['mode']), str(spec['uid']), str(spec['gid']), artifact,
                    self.plan['before']['files'][HELPER_LAYOUT]['sha256']]
                self._run(argv, lease)
            if not check_only: self._run(command(tenant, 'gateway', 'reload'), lease)

    def _consumers(self):
        output = {}
        policy = self.plan['qos_policy']
        if policy is None:
            require_no_active_qos(self.root)
        for tenant in self.plan['tenants'] if policy is not None else ():
            name = 'whatsapp.' + tenant['slug']
            receipt = self.qos.operate(self.root, policy_path=policy['path'], expected_sha256=policy['sha256'],
                action='retire-consumer', operation_id=digest((self.plan['operation_id'] + ':qos:' + name).encode())[:32],
                consumer_id=name, **self.qos_options)
            require(receipt.get('status') == 'complete' and receipt.get('consumer_status') == 'retired'
                    and receipt.get('consumer_id') == name and receipt.get('uid') == tenant['uid'],
                    'Host QoS retirement did not attest this exact gateway consumer')
            output[name] = receipt
        with self.frontend.lease():
            output['frontend'] = self.frontend.retire_application(owner='whatsapp',
                operation_id=digest((self.plan['operation_id'] + ':frontend').encode())[:32])
            require(output['frontend'].get('phase') == 'complete', 'Host frontend retirement is incomplete')
            output['renewals'] = self.frontend.retire_renewals(owner='whatsapp',
                operation_id=digest((self.plan['operation_id'] + ':renewals').encode())[:32])
        return output

    def advance(self):
        """Advance one durable phase; exceptions preserve intent for forward replay."""
        with self.services.operation_locks(self.root, owner='whatsapp') as locks:
            lease = locks[:1]
            journal = self._journal()
            self._admission()
            if journal is None:
                self._sources(); self._units(); self._quadlets(lease, check_only=True)
                journal = {'format': FORMAT, 'operation_id': self.plan['operation_id'],
                    'admin_plan_sha256': self.plan['admin_plan_sha256'],
                    'plan_sha256': self.plan_digest, 'phase': 'prepared',
                    'intent': None, 'processes': self._census([]), 'receipts': {}}
                self._save(journal)
                return {'phase': 'prepared', 'complete': False, 'journal': self.journal_path}
            phase = journal['phase']
            if phase == 'verified':
                self._verify(journal)
                self._quadlets(lease, check_only=True, retired=True)
                return {'phase': phase, 'complete': True, 'journal': self.journal_path}
            target = PHASES[PHASES.index(phase) + 1]
            resuming_files = target == 'files_removed' and journal['intent'] == target
            if not resuming_files:
                self._sources(removed=phase == 'files_removed')
            else:
                # The exact durable engine journal, never an accept-either test,
                # owns the mixed before/after state during filesystem replay.
                operation_path = self.fs.STATE + '/whatsapp/operations/' + self._files_id()
                if self.root.directory(operation_path) is None:
                    self._sources()
                    operation = None
                else:
                    operation = self.fs.inspect_operation(self.root, owner='whatsapp', operation_id=self._files_id(),
                        allowed_paths=self._file_paths())
                if operation is not None:
                    self._sources(removed=True, verify_absence=False)
                    require(operation['before'] == self.plan['before'] and operation['after'] == self.plan['after'],
                            'Runtime filesystem intent differs from its approved plan')
            journal['intent'] = target; self._save(journal); self._event('before-' + target, journal)
            if target == 'services_closed':
                self._units(allow_masked=True)
                self._quadlets(lease, check_only=True)
                for tenant in self.plan['tenants']:
                    for component, operation in (('bridge', 'disable'), ('bridge', 'stop'), ('gateway', 'stop'), ('gateway', 'mask')):
                        self._run(command(tenant, component, operation), lease)
                self._closed(journal)
            elif target == 'quadlets_retired':
                self._closed(journal); self._quadlets(lease); self._closed(journal)
            elif target == 'consumers_retired':
                self._closed(journal); journal['receipts'] = self._consumers(); self._closed(journal)
            elif target == 'files_removed':
                if not resuming_files: self._closed(journal)
                else: self._drain_before_files(journal)
                self.fs.reconcile(self.root, operation_id=self._files_id(), before=self.plan['before'],
                    after=self.plan['after'], payloads={}, allowed_paths=self._file_paths())
                self._run(command(self.plan['tenants'][0], 'bridge', 'reload'), lease)
                self._closed(journal, removed=True); self._sources(removed=True)
            else:
                self._verify(journal)
                self._quadlets(lease, check_only=True, retired=True)
            self._event('after-' + target, journal)
            journal['phase'], journal['intent'] = target, None; self._save(journal)
            return {'phase': target, 'complete': target == 'verified', 'journal': self.journal_path}

    def _files_id(self):
        return digest((self.plan['operation_id'] + ':runtime-files').encode())[:32]

    def _file_paths(self):
        return sorted(set(self.plan['before']['files']) | set(self.plan['before']['directories']))

    def _drain_before_files(self, journal):
        # During an engine replay source files can be partially quarantined.
        # Their exact state belongs to that journal; loaded service/job state
        # must still be quiescent before any further file mutation.
        def observe():
            result = {}
            for tenant in self.plan['tenants']:
                for component in ('bridge', 'gateway'):
                    value = self._read(tenant, component)
                    if value['Job'] not in ('', '0'): raise Pending('Runtime manager job is still pending')
                    require(value['MainPID'] == value['ControlPID'] == '0'
                            and value['ActiveState'] in ('inactive', 'failed')
                            and all(not value[key] for key in PROPAGATION_PROPERTIES), 'Runtime is not drained before filesystem replay')
                    require((value['LoadState'] == value['UnitFileState'] == 'masked' and value['FragmentPath'] == '/dev/null')
                            if component == 'gateway' else value['UnitFileState'] in ('disabled', '')
                            and value['LoadState'] in ('loaded', 'not-found'), 'Runtime admission changed before filesystem replay')
                    result[tenant['slug'] + ':' + component] = value
            return result
        first = observe(); self._census(journal['processes'], quiescent=True)
        require(first == observe(), 'Runtime changed during filesystem replay observation')

    def _closed(self, journal, *, removed=False):
        first = self._units(closed=True, removed=removed)
        self._census(journal['processes'], quiescent=True)
        require(first == self._units(closed=True, removed=removed), 'Runtime changed between final observations')

    def _verify(self, journal):
        if self.plan['qos_policy'] is None:
            require_no_active_qos(self.root)
        self._sources(removed=True); self._closed(journal, removed=True)
        with self.frontend.lease():
            status = self.frontend.retirement_status('whatsapp')
        require(status.get('status') == 'retired', 'Host frontend references reappeared')
        policy = self.plan['qos_policy']
        for tenant in self.plan['tenants'] if policy is not None else ():
            observed = self.qos.operate(self.root, policy_path=policy['path'], expected_sha256=policy['sha256'],
                action='check', consumer_id='whatsapp.' + tenant['slug'], **self.qos_options)
            require(observed.get('status') == 'complete' and observed.get('consumer_status') == 'retired'
                    and observed.get('uid') == tenant['uid'], 'Host QoS consumer is active, changed or incoherent')
        require(journal['receipts'], 'Runtime consumer retirement receipts are missing')


def uid_helper(argv, *, installation_root=Path('/'), helper_path=None):
    args = argv
    require(len(args) == 9 and args[0] in ('_retire-quadlet', '_check-quadlet', '_check-retired-quadlet'),
            'Only the finite UID Quadlet helper is exposed')
    action, slug, operation_id, sha, mode, uid, gid, artifact, layout_sha = args
    require(hex_value(layout_sha), 'UID helper requires the reviewed installation source digest')
    layout_path = Path(helper_path or Path(__file__).absolute()).with_name('installation_layout.py')
    layout_source = _bootstrap_read(installation_root, str(layout_path))
    require(digest(layout_source) == layout_sha, 'UID helper installation source differs from its reviewed pin')
    installation = _captured_installation(layout_source, layout_path, installation_root)
    _configure_installation(installation)
    require(all(re.fullmatch('[0-9]+', value) for value in (mode, uid, gid)), 'Invalid UID helper metadata')
    expected = {'sha256': sha, 'mode': int(mode), 'uid': int(uid), 'gid': int(gid)}
    account = pwd.getpwnam(layout(slug)['account'])
    require(account.pw_uid == os.geteuid() and account.pw_dir == layout(slug)['home'], 'Gateway account identity differs')
    require((artifact == 'gateway-priority' and expected['uid'] == 0) or
            (artifact == 'quadlet' and (account.pw_uid, account.pw_gid) == (expected['uid'], expected['gid'])),
            'UID helper artifact authority differs')
    quadlet_retire(layout(slug)['home'], operation_id, expected,
        check_only=action != '_retire-quadlet', retired=action == '_check-retired-quadlet', artifact=artifact)


def _bootstrap_read(root, logical, *, maximum=16 * 1024 * 1024):
    """Anchored, bounded stdlib read before importing any operational dependency."""
    root = Path(root).absolute(); path = Path(logical)
    require(root == root.resolve(strict=True) and path.is_absolute() and str(path) == logical
            and '..' not in path.parts and logical != '/', 'Bootstrap paths must be exact and physical')
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    authority = os.fstat(descriptor).st_uid
    try:
        require(not os.fstat(descriptor).st_mode & 0o022, 'Bootstrap root is not protected')
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
            info = os.fstat(descriptor)
            require(info.st_uid == authority and not info.st_mode & 0o022, 'Bootstrap ancestor is not protected')
        child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(child, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == authority and not info.st_mode & 0o022
                    and info.st_size <= maximum, 'Bootstrap input is not a protected bounded file')
            value = stream.read(maximum + 1); after = os.fstat(stream.fileno())
        current = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(len(value) <= maximum and identity(info) == identity(after) == identity(current), 'Bootstrap input changed')
        return value
    finally:
        os.close(descriptor)


def _captured_installation(content, source_path, installation_root):
    """Load verified bytes privately, without trusting a cached sibling module."""
    module = types.ModuleType('_wa_runtime_installation_captured')
    module.__file__ = str(source_path)
    exec(compile(content, module.__file__, 'exec'), module.__dict__)
    require(getattr(module, 'FORMAT', None) == 'whatsapp-installation-v1', 'Invalid captured installation owner')
    root = Path(installation_root).absolute()
    module.activate_installation(root=root, trusted_uid=0 if root == Path('/') else os.getuid())
    return module


def bootstrap(operation_bytes, expected_sha256, *, root_path, source_root=SOURCE_ROOT):
    """Authenticate all declared input/source bytes before the first compile."""
    require(hex_value(expected_sha256) and digest(operation_bytes) == expected_sha256,
            'Runtime operation differs from its reviewed digest')
    operation = decode(operation_bytes)
    fields(operation, ('format', 'source_revision', 'sources', 'plan', 'admin_operation', 'frontend'))
    require(operation['format'] == 'whatsapp-runtime-operation-v1' and hex_value(operation['source_revision'], 40)
            and isinstance(operation['sources'], dict) and set(operation['sources']) == set(source_paths(operation['plan']))
            and all(hex_value(value) for value in operation['sources'].values()), 'Incomplete runtime source closure')
    fields(operation['frontend'], ('profile', 'registry'))
    inputs = {}
    for name, item in (('admin', operation['admin_operation']), ('profile', operation['frontend']['profile']),
                       ('registry', operation['frontend']['registry'])):
        fields(item, ('path', 'sha256'))
        require(hex_value(item['sha256']), 'Every operational input requires a reviewed digest')
        raw = _bootstrap_read(root_path, item['path'])
        # Registry changes are allowed only after the durable runtime intent;
        # that link is checked below using its exact provider receipt.
        if name != 'registry': require(digest(raw) == item['sha256'], 'Operational input changed before bootstrap')
        inputs[name] = raw
    source_root = Path(source_root).absolute()
    sources = {}
    for relative in source_paths(operation['plan']):
        raw = _bootstrap_read(source_root, '/' + relative)
        require(digest(raw) == operation['sources'][relative], 'Runtime source closure differs from its reviewed bytes')
        sources[relative] = raw
    require(operation['plan'].get('source_sha256') == operation['sources']['plugins/whatsapp/scripts/runtime_lifecycle.py'],
            'Installed UID helper and controller source must match')
    admin_header = decode(inputs['admin'])
    require(isinstance(admin_header, dict) and isinstance(admin_header.get('installer_sources'), dict)
            and all(operation['sources'].get(name) == sha for name, sha in admin_header['installer_sources'].items()),
            'Administrative and runtime operations use different source generations')
    return operation, inputs, sources


def _compile_sources(sources, source_root, *, installation_root=None, plan=None):
    """Execute captured bytes directly; no adjacent pyc or dynamic source reread."""
    require(set(sources) in (set(SOURCES), set(STANDALONE_SOURCES)), 'Incomplete captured runtime closure')
    # Installed CLI admission starts from captured layout bytes, never an
    # ambient module's selected profile. Offline callers select explicitly.
    installation = installation_profile() if installation_root is None else None
    modules = {}
    closure = [('installation_layout','plugins/whatsapp/scripts/installation_layout.py',False),
        ('host', 'host/__init__.py', True), ('host.lifecycle', 'host/lifecycle/__init__.py', True),
        ('host.lifecycle.filesystem', 'host/lifecycle/filesystem.py', False),
        ('host.lifecycle.evidence', 'host/lifecycle/evidence.py', False),
        ('host.installation','host/installation.py',False),
        ('host.lifecycle.services','host/lifecycle/services.py',False),
        ('host.lifecycle.service_client', 'host/lifecycle/service_client.py', False),
        ('admin_handoff', 'plugins/whatsapp/scripts/admin_handoff.py', False),
        ('admin_host', 'plugins/whatsapp/scripts/admin_host.py', False),
        ('admin_install', 'plugins/whatsapp/scripts/admin_install.py', False),
        ('host.qos', None, True), ('host.qos.contract', 'host/qos/contract.py', False),
        ('host.qos.adoption', 'host/qos/adoption.py', False), ('host.qos.processes', 'host/qos/processes.py', False), ('host.qos.applicator', 'host/qos/applicator.py', False),
        ('host.frontend', None, True), ('host.frontend.provider', 'host/frontend/provider.py', False),
        ('host.frontend.adapter', 'host/frontend/adapter.py', False),
        ('wa_runtime_pinned', 'plugins/whatsapp/scripts/runtime_lifecycle.py', False)]
    for name, relative, package in closure:
        if name.startswith('host.qos') and 'host/qos/applicator.py' not in sources:
            continue
        module = types.ModuleType(name); modules[name] = module; sys.modules[name] = module
        module.__file__ = str(Path(source_root)/(relative or name.replace('.', '/') + '/__init__.py'))
        module.__package__ = name if package else name.rpartition('.')[0]
        if package: module.__path__ = [str(Path(module.__file__).parent)]
        if '.' in name:
            parent, _, child = name.rpartition('.'); setattr(sys.modules[parent], child, module)
        if name == 'host.frontend.adapter': module._PINNED_PROVIDER = modules['host.frontend.provider']
        if name == 'host.qos.applicator': module._PINNED_MODULES = (modules['host.lifecycle.filesystem'],
            modules['host.qos.contract'], modules['host.qos.adoption'], modules['host.qos.processes'])
        if relative: exec(compile(sources[relative], module.__file__, 'exec'), module.__dict__)
        if name in ('installation_layout', 'host.installation'):
            require(getattr(module, 'FORMAT', None) == 'whatsapp-installation-v1', 'Invalid captured installation owner')
            if installation_root is not None:
                selected = module.activate_installation(root=installation_root,
                    trusted_uid=0 if installation_root == Path('/') else os.getuid())
                if installation is None:
                    installation = selected
                    layout_path = installation.path('project') + '/scripts/installation_layout.py'
                    require(isinstance(plan, dict) and isinstance(plan.get('before'), dict)
                            and isinstance(plan['before'].get('files'), dict)
                            and isinstance(plan['before']['files'].get(layout_path), dict)
                            and plan['before']['files'][layout_path].get('sha256') ==
                                digest(sources['plugins/whatsapp/scripts/installation_layout.py']),
                            'Installed UID layout and captured controller layout must match')
                else:
                    require(selected.selection == installation.selection, 'Installation changed during captured-source bootstrap')
            else:
                copied = (module.Installation.legacy() if installation.compatibility
                          else module.Installation.from_dict(installation.as_dict()))
                if installation.roster is not None:
                    copied = copied.with_roster(installation.roster)
                module.select(copied)
    install = modules['admin_install']
    install.filesystem, install.admin_handoff, install.admin_host = (
        modules['host.lifecycle.filesystem'], modules['admin_handoff'], modules['admin_host'])
    if 'host.qos.applicator' in modules:
        qos = modules['host.qos.applicator']
        qos.engine, qos.contract, qos.adoption, qos.processes = (modules['host.lifecycle.filesystem'],
            modules['host.qos.contract'], modules['host.qos.adoption'], modules['host.qos.processes'])
    return modules


def encode_operation(plan, *, admin_operation, frontend, source_revision, source_root=SOURCE_ROOT):
    """Build reviewable bytes locally; this does not approve or execute them."""
    return encoded({'format': 'whatsapp-runtime-operation-v1', 'source_revision': source_revision,
        'sources': {name: digest((Path(source_root)/name).read_bytes()) for name in source_paths(plan)},
        'plan': plan, 'admin_operation': admin_operation, 'frontend': frontend})


def controller_main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'observe-units', 'advance'))
    parser.add_argument('--operation', required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--root', default='/', type=Path)
    args = parser.parse_args(argv)
    require(args.action == 'inspect' or args.root.absolute() == Path('/') and os.geteuid() == 0,
            'Runtime advance requires root on the actual host; fixtures use explicit adapters')
    raw = _bootstrap_read(args.root, args.operation)
    operation, inputs, sources = bootstrap(raw, args.sha256, root_path=args.root)
    if args.action != 'inspect':
        require(all(path.stat().st_uid == 0 and not path.stat().st_mode & 0o022
                    for path in (SOURCE_ROOT, *SOURCE_ROOT.parents)), 'Host controller source ancestry must be protected by root')
    modules = _compile_sources(sources, SOURCE_ROOT, installation_root=args.root.absolute(), plan=operation['plan'])
    _configure_installation(modules['installation_layout'])
    fs = modules['host.lifecycle.filesystem']; pinned = modules['wa_runtime_pinned']
    with fs.Root(args.root) as root:
        admin_operation, _, admin_digest = modules['admin_install'].decode_operation(
            inputs['admin'], operation['admin_operation']['sha256'])
        plan_digest = pinned.validate_plan(operation['plan'], authority_uid=root.uid)
        require(operation['plan']['admin_plan_sha256'] == admin_digest and admin_operation['plan']['mode'] == 'remove'
                and admin_operation['plan'].get('runtime_retirement') == {'operation_id': operation['plan']['operation_id']},
                'Wrong administrative operation binding')
        if args.action == 'inspect':
            result = {'action': 'inspect', 'plan_sha256': plan_digest, 'mutations': False,
                'source_revision_assertion': operation['source_revision'],
                'required_admin_phase': 'retired', 'ssh_inventory_proven': False,
                'tenant_slugs': [item['slug'] for item in operation['plan']['tenants']],
                'retained_runtime_helpers': sorted(operation['plan']['after']['files']),
                'retained_gateway_dropins': sorted(path for item in operation['plan']['tenants'] for path in item['gateway_dropins'])}
        else:
            front = modules['host.frontend.adapter']
            require(operation['frontend']['profile']['path'] == front.PROFILE
                    and operation['frontend']['registry']['path'] == front.REGISTRY,
                    'Only the registered neutral frontend inputs are admitted')
            registry = decode(inputs['registry']); profile = decode(inputs['profile'])
            if digest(inputs['registry']) != operation['frontend']['registry']['sha256']:
                # A resumed consumer retirement must bind the original registry
                # through the provider's own persisted original before-manifest.
                runtime_journal = decode(root.read_bytes(STATE+'/runtime-retirement-'+operation['plan']['operation_id']+'.json'))
                require(runtime_journal.get('plan_sha256') == plan_digest and
                    (runtime_journal.get('intent') == 'consumers_retired' or runtime_journal.get('phase') in PHASES[3:]),
                    'Frontend registry changed before the durable runtime retirement intent')
                provider = modules['host.frontend.provider']
                receipt = provider._load_receipt(root, digest((operation['plan']['operation_id']+':frontend').encode())[:32])
                require(receipt is not None and receipt['context'].get('kind') == 'retire-application' and receipt['context'].get('owner') == 'whatsapp'
                        and hex_value(receipt['context'].get('retired_owner_sha256'))
                        and receipt['before']['files'][front.REGISTRY]['sha256'] == operation['frontend']['registry']['sha256'],
                        'Frontend registry is not linked to this original retirement plan')
            adapter = front.HostAdapter(root, fs, registry, profile)
            admin = modules['admin_host'].AdminHost(root, admin_operation['profile'])
            host = pinned.RuntimeHost(root, operation['plan'], admin_plan=admin_operation['plan'], admin_provider=admin,
                frontend_adapter=adapter, qos_module=modules.get('host.qos.applicator'))
            result = host.observe_units() if args.action == 'observe-units' else host.advance()
        print(json.dumps(result, sort_keys=True))
    return 0


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] == 'collect-units': return collector_main(args[1:])
    if args and args[0].startswith('_'):
        return uid_helper(args)
    return controller_main(args)


if __name__ == '__main__':
    try: main()
    except Exception:
        # Neither command output nor sensitive file contents are emitted.
        raise SystemExit(71) from None
