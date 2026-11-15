"""Bounded read-only lifecycle evidence. No workload signals or service mutations.

The caller authenticates the root inventory and fences its invokers. A matching
script path/cgroup does not prove which Python generation is loaded in memory;
that association is supplied explicitly by the digest-bound inventory context.
"""
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import stat
import subprocess
import time

from .filesystem import LifecycleError, Root, resolve_link_target

MAX_FILE = 16 * 1024 * 1024
MAX_COMMAND = 256 * 1024
MAX_PROCESSES = 32768
REFERENCE_PROPERTIES = ('Requires', 'Wants', 'After', 'Before', 'PartOf', 'BindsTo',
                        'OnFailure', 'OnSuccess', 'PropagatesStopTo', 'Triggers', 'TriggeredBy')
UNIT_COMMON_PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Job',
                          'FragmentPath', 'DropInPaths', 'NeedDaemonReload',
                          'InvocationID', 'UnitFileState', *REFERENCE_PROPERTIES)
UNIT_TYPE_PROPERTIES = {'service': ('MainPID', 'ControlPID', 'ControlGroup'), 'timer': ()}
EXECUTION_PROPERTIES = ('ExecStartPre', 'ExecStart', 'ExecStartPost', 'ExecStop',
                        'ExecStopPost', 'ExecReload', 'ExecCondition')


class EvidenceError(ValueError):
    """Evidence is incomplete, stale or inconsistent; no destructive action is safe."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def keys(value, expected, message):
    require(isinstance(value, dict) and set(value) == set(expected), message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def hex_digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def path_name(value, *, root=False):
    require(isinstance(value, str) and re.fullmatch(r'/[A-Za-z0-9_./@:+-]*', value)
            and '..' not in PurePosixPath(value).parts and str(PurePosixPath(value)) == value
            and (root or value != '/'), 'Expected a normalized explicit absolute path')
    return value


def unit_name(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,150}\.(service|timer|socket|target|path|slice|scope)', value) is not None


def dependency_name(value):
    return (isinstance(value, str) and len(value) <= 255 and
            re.fullmatch(r'(?:[A-Za-z0-9_.:@-]|\\x[0-9a-fA-F]{2})+\.(service|timer|socket|target|path|slice|scope|device|mount|automount|swap)', value) is not None)


def validate_execution(value):
    keys(value, EXECUTION_PROPERTIES, 'Every typed execution property is required')
    for item in value.values():
        keys(item, {'count', 'identity_sha256'}, 'Invalid typed execution identity')
        require(type(item['count']) is int and 0 <= item['count'] <= 32
                and hex_digest(item['identity_sha256']), 'Invalid bounded execution identity')


def unit_properties(name):
    """Finite properties of the observed object; dependency names may use other types.

    systemd v257's Timer interface has neither service PIDs nor ControlGroup.
    Missing applicable properties fail closed rather than becoming synthetic zeroes.
    """
    require(unit_name(name), 'Invalid collector unit')
    kind = name.rsplit('.', 1)[1]
    require(kind in UNIT_TYPE_PROPERTIES, 'Unsupported observed unit type')
    return UNIT_COMMON_PROPERTIES + UNIT_TYPE_PROPERTIES[kind]


def _validate_unit_record(name, actual):
    properties = set(unit_properties(name))
    require(isinstance(actual, dict) and set(actual) in (properties, properties | {'Execution'})
            and all(isinstance(actual[key], str) for key in properties), 'Incomplete typed unit properties')
    if 'Execution' in actual:
        require(name.endswith('.service'), 'Only services have typed execution properties')
        validate_execution(actual['Execution'])
    require(actual['Id'] == name, 'Incomplete unit identity')
    if name.endswith('.service'):
        require(all(re.fullmatch(r'0|[1-9][0-9]*', actual[key])
                    for key in ('MainPID', 'ControlPID')), 'Invalid observed service PID')


def unit_quiescent(name, actual):
    """Derive quiescence from a typed record already bound by verify's receipt.

    This helper alone does not authenticate provenance or prove a complete census.
    """
    _validate_unit_record(name, actual)
    return (actual['ActiveState'] in ('inactive', 'failed') and actual['Job'] in ('', '0')
            and (not name.endswith('.service') or actual['MainPID'] == actual['ControlPID'] == '0'))


def boot_name(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None


def validate_manifest(value):
    require(isinstance(value, dict) and set(value) in ({'format', 'owner', 'files', 'directories'},
            {'format', 'owner', 'files', 'directories', 'links'}), 'Invalid filesystem manifest')
    require(type(value['format']) is int and value['format'] == 1 and value['owner'] in ('whatsapp', 'box', 'host'),
            'Unsupported filesystem manifest')
    maps = [value['files'], value['directories'], value.get('links', {})]
    require(all(isinstance(item, dict) for item in maps) and sum(len(item) for item in maps) <= 4096
            and len(set().union(*maps)) == sum(len(item) for item in maps), 'Invalid bounded filesystem inventory')
    for kind in ('files', 'directories'):
        for path, item in value[kind].items():
            path_name(path)
            keys(item, {'mode', 'uid', 'gid', 'retention'} | ({'sha256'} if kind == 'files' else set()),
                 'Invalid expected file metadata')
            require(all(type(item[key]) is int and item[key] >= 0 for key in ('uid', 'gid', 'mode'))
                    and item['mode'] <= 0o7777, 'Invalid expected ownership or mode')
            require(item['retention'] in (('managed', 'retain') if kind == 'files' else ('retain',)),
                    'Invalid expected retention')
            if kind == 'files':
                require(hex_digest(item['sha256']), 'Invalid expected file digest')
    for path, item in value.get('links', {}).items():
        path_name(path)
        require(isinstance(item, dict) and isinstance(item.get('target'), str), 'Invalid expected link metadata')
        relative = not item['target'].startswith('/')
        keys(item, {'target', 'uid', 'gid', 'retention'} | ({'resolved_target'} if relative else set()),
             'Invalid expected link metadata')
        try:
            resolved = resolve_link_target(path, item['target'])
        except LifecycleError:
            raise EvidenceError('Invalid lexical link target') from None
        path_name(resolved)
        require(not relative or item['resolved_target'] == resolved, 'Relative link resolved target differs')
        require(all(type(item[key]) is int and item[key] >= 0 for key in ('uid', 'gid'))
                and item['retention'] in ('managed', 'retain'), 'Invalid expected link ownership or retention')


def validate_scope(scope):
    keys(scope, {'cgroups', 'script_roots', 'script_paths'}, 'Invalid process scope')
    for field in scope:
        require(isinstance(scope[field], list) and len(scope[field]) <= 256
                and all(isinstance(value, str) for value in scope[field])
                and len(set(scope[field])) == len(scope[field]), 'Invalid bounded process scope')
        for value in scope[field]:
            path_name(value)
    require(any(scope.values()), 'Process scope must be explicit and nonempty')


def validate_units(units, manifest):
    require(isinstance(units, dict) and len(units) <= 256, 'Invalid bounded unit inventory')
    for name, item in units.items():
        properties = unit_properties(name)
        required = {'fragment_path', 'drop_in_paths', 'references', 'scope_cgroup'}
        require(isinstance(item, dict) and required <= set(item)
                and set(item) <= required | {'state', 'execution'},
                'Invalid expected unit')
        if 'execution' in item:
            require(name.endswith('.service'), 'Only service inventories may require execution properties')
            validate_execution(item['execution'])
        if 'state' in item:
            require(isinstance(item['state'], dict) and bool(item['state'])
                    and set(item['state']) <= {'UnitFileState', 'ActiveState', 'SubState'}
                    and all(isinstance(value, str) and re.fullmatch('[a-z-]{1,32}', value)
                            for value in item['state'].values()), 'Invalid expected unit state')
        path_name(item['fragment_path'])
        require(isinstance(item['drop_in_paths'], list) and len(set(item['drop_in_paths'])) == len(item['drop_in_paths']),
                'Invalid unit drop-in list')
        for path in [item['fragment_path'], *item['drop_in_paths']]:
            path_name(path)
            require(_declared_source(path, manifest['files'], manifest.get('links', {})),
                    'Every unit fragment and drop-in must have an inventoried digest')
        keys(item['references'], REFERENCE_PROPERTIES, 'All unit reference properties must be inventoried')
        for references in item['references'].values():
            require(isinstance(references, list) and all(dependency_name(value) for value in references)
                    and len(set(references)) == len(references), 'Invalid exact unit references')
        if item['scope_cgroup'] is not None:
            require('ControlGroup' in properties, 'Observed unit type has no process cgroup')
            path_name(item['scope_cgroup'])


def digest_inventory(scope, expected_manifest, units, *, prior_processes=()):
    validate_manifest(expected_manifest); validate_scope(scope); validate_units(units, expected_manifest)
    _validate_prior(prior_processes)
    require(all(_declared_source(path, expected_manifest['files'], expected_manifest.get('links', {}))
                for path in scope['script_paths']), 'Every exact script path must have an inventoried digest')
    require(all(any(path.startswith(root + '/') for path in expected_manifest['files']) for root in scope['script_roots']),
            'Every script root must contain inventoried source files')
    return digest({'scope': scope, 'manifest': expected_manifest, 'units': units,
                   'prior_processes': list(prior_processes)})


def validate_context(context, inventory_digest=None):
    keys(context, {'format', 'authority', 'plan_digest', 'invocation_id', 'generation_id', 'inventory_digest', 'boot_id'},
         'Invalid root inventory context')
    require(type(context['format']) is int and context['format'] == 1 and context['authority'] == 'root-inventory'
            and all(hex_digest(context[key]) for key in ('plan_digest', 'generation_id', 'inventory_digest'))
            and isinstance(context['invocation_id'], str)
            and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}', context['invocation_id'])
            and boot_name(context['boot_id']), 'Incomplete inventory provenance or operation identity')
    if inventory_digest is not None:
        require(context['inventory_digest'] == inventory_digest, 'Root inventory does not bind this exact scope, manifest and units')


def _bounded_read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Evidence input is not a regular file')
        value = stream.read(maximum + 1)
        require(len(value) <= maximum, 'Evidence input exceeds its size limit')
        return value


def collect_files(expected_manifest, *, fs_root):
    """Observe named objects through protected, anchored directory descriptors."""
    validate_manifest(expected_manifest)
    result = {'files': {}, 'directories': {}}
    if 'links' in expected_manifest:
        result['links'] = {}
    manager = nullcontext(fs_root) if isinstance(fs_root, Root) else Root(fs_root)
    try:
        with manager as root:
            for kind in result:
                observer = {'files': root.snapshot, 'directories': root.directory, 'links': root.link}[kind]
                for logical in sorted(expected_manifest[kind]):
                    record = observer(logical)
                    if record is not None and kind == 'links':
                        path_name(record.get('resolved_target', record['target']))
                    result[kind][logical] = {'state': 'missing'} if record is None else {'state': 'present', **record}
    except LifecycleError:
        raise EvidenceError('Inventoried filesystem object is unsafe, unavailable or changed') from None
    return result


def show_argv(unit):
    return ['/usr/bin/systemctl', 'show', '--no-pager', '--all', '--property=' + ','.join(unit_properties(unit)), '--', unit]


def execution_argv(unit, property_name):
    require(unit_name(unit) and unit.endswith('.service') and property_name in EXECUTION_PROPERTIES,
            'Execution query is outside the finite service property set')
    object_name = ''.join(c if c.isascii() and c.isalnum() else '_' + format(ord(c), '02x') for c in unit)
    return ['/usr/bin/busctl', '--system', '--json=short', 'get-property',
            'org.freedesktop.systemd1', '/org/freedesktop/systemd1/unit/' + object_name,
            'org.freedesktop.systemd1.Service', property_name]


def _readonly_argv(argv):
    if not isinstance(argv, list) or not argv or not all(isinstance(part, str) for part in argv):
        return False
    if argv[0] == '/usr/bin/systemctl':
        return unit_name(argv[-1]) and argv == show_argv(argv[-1])
    if len(argv) != 8 or argv[0] != '/usr/bin/busctl':
        return False
    prefix = '/org/freedesktop/systemd1/unit/'
    if not argv[5].startswith(prefix):
        return False
    unit = re.sub(r'_([0-9a-f]{2})', lambda match: chr(int(match[1], 16)), argv[5][len(prefix):])
    return (unit_name(unit) and unit.endswith('.service') and argv[-1] in EXECUTION_PROPERTIES
            and argv == execution_argv(unit, argv[-1]))


def execution_identity(raw):
    """Hash the same typed command projection as the approved PRO8 reader.

    Raw argv is never returned or included in errors or lifecycle receipts.
    Empty commands require an actual typed empty array, never a missing field.
    """
    require(type(raw) is bytes and len(raw) <= MAX_COMMAND, 'Invalid bounded execution response')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate typed response field')
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        keys(value, {'type', 'data'}, 'Incomplete typed execution response')
        require(value['type'] == 'a(sasbttttuii)' and type(value['data']) is list
                and len(value['data']) <= 32, 'Unexpected typed execution signature')
        commands = []
        for row in value['data']:
            require(type(row) is list and len(row) == 10 and isinstance(row[0], str)
                    and type(row[1]) is list and 0 < len(row[1]) <= 512
                    and all(isinstance(arg, str) and '\0' not in arg for arg in row[1])
                    and type(row[2]) is bool and all(type(number) is int for number in row[3:]),
                    'Invalid typed execution row')
            commands.append({'path': row[0], 'argv': row[1], 'ignore_errors': row[2]})
        return {'count': len(commands), 'identity_sha256': hashlib.sha256(canonical(commands) + b'\n').hexdigest()}
    except (ValueError, UnicodeError, TypeError):
        raise EvidenceError('Invalid typed execution response; raw output withheld') from None


def readonly_runner(argv, *, timeout=5.0, max_bytes=MAX_COMMAND):
    """Execute one finite show or typed execution-property query. No workload signals.

    A timed-out/oversized collector subprocess is terminated, never its units.
    """
    require(_readonly_argv(argv), 'Collector command is outside the read-only allowlist')
    require(type(timeout) in (int, float) and 0 < timeout <= 10 and type(max_bytes) is int
            and 0 < max_bytes <= MAX_COMMAND, 'Invalid collector resource limit')
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                               env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0'},
                               close_fds=True)
    streams = selectors.DefaultSelector()
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False); streams.register(stream, selectors.EVENT_READ)
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    try:
        while streams.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'Read-only collector timed out')
            for key, _ in streams.select(remaining):
                data = os.read(key.fd, 8192)
                if not data:
                    streams.unregister(key.fileobj); continue
                (output if key.fileobj is process.stdout else errors).extend(data)
                require(len(output) + len(errors) <= max_bytes, 'Read-only collector output is oversized')
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Read-only collector timed out')
        process.wait(timeout=remaining)
        require(process.returncode == 0 and not errors, 'Read-only collector failed')
        return bytes(output)
    finally:
        streams.close()
        if process.poll() is None:
            process.kill()  # Only this bounded read-only command, never a workload PID.
            process.wait()
        process.stdout.close(); process.stderr.close()


def collect_units(units, *, runner):
    result = {}
    for name in sorted(units):
        expected_properties = unit_properties(name)
        raw = runner(show_argv(name), timeout=5.0, max_bytes=MAX_COMMAND)
        require(isinstance(raw, bytes) and len(raw) <= MAX_COMMAND, 'Invalid bounded collector response')
        try:
            lines = raw.decode('utf-8').splitlines()
        except UnicodeError:
            raise EvidenceError('Invalid unit property encoding') from None
        properties = {}
        for line in lines:
            key, separator, value = line.partition('=')
            require(separator and key in expected_properties and key not in properties, 'Unexpected or duplicate unit property')
            properties[key] = value
        _validate_unit_record(name, properties)
        if 'execution' in units[name]:
            properties['Execution'] = {key: execution_identity(runner(execution_argv(name, key),
                timeout=5.0, max_bytes=MAX_COMMAND)) for key in EXECUTION_PROPERTIES}
        result[name] = properties
    return result


def parse_stat(data, pid):
    try:
        text = data.decode('utf-8')
        prefix, _, tail = text.rpartition(')')
        require(prefix.partition(' (')[0] == str(pid) and ' (' in prefix, 'Process stat identity differs')
        fields = tail.split()
        require(len(fields) >= 20 and len(fields[0]) == 1 and fields[0] in 'RSDZTWXxKPIt', 'Incomplete process stat')
        values = [int(fields[index]) for index in (1, 2, 3, 19)]
        require(all(value >= 0 for value in values) and values[3] > 0, 'Invalid process identity')
        return {'pid': pid, 'state': fields[0], 'ppid': values[0], 'pgrp': values[1],
                'session': values[2], 'start_ticks': values[3]}
    except (UnicodeError, IndexError, ValueError):
        raise EvidenceError('Cannot read an exact process identity') from None


def _beneath(path, root):
    return path == root or path.startswith(root + '/')


def _declared_source(path, files, links):
    """Resolve only declared link text, never follow filesystem symlinks."""
    seen = set()
    while path not in seen and len(seen) <= 16:
        seen.add(path)
        if path in files:
            return True
        matches = [name for name in links if _beneath(path, name)]
        if not matches:
            return False
        name = max(matches, key=len)
        path = links[name].get('resolved_target', links[name]['target']) + path[len(name):]
    return False


def _boot(proc_root):
    value = _bounded_read(Path(proc_root)/'sys/kernel/random/boot_id', 64).decode('ascii').strip()
    require(boot_name(value), 'Invalid observed boot identity')
    return value


def _validate_prior(records):
    require(isinstance(records, (list, tuple)) and len(records) <= MAX_PROCESSES, 'Invalid prior process records')
    for record in records:
        keys(record, {'pid', 'state', 'ppid', 'pgrp', 'session', 'start_ticks', 'cgroup', 'boot_id', 'generation_id', 'scope_ids'},
             'Invalid prior process identity')
        require(all(type(record[key]) is int and record[key] >= 0 for key in ('pid', 'ppid', 'pgrp', 'session', 'start_ticks'))
                and record['pid'] > 0 and record['start_ticks'] > 0 and boot_name(record['boot_id'])
                and hex_digest(record['generation_id']) and isinstance(record['scope_ids'], list)
                and bool(record['scope_ids']) and all(isinstance(value, str) for value in record['scope_ids'])
                and isinstance(record['state'], str) and len(record['state']) == 1
                and record['state'] in 'RSDZTWXxKPIt',
                'Invalid prior process provenance')
        path_name(record['cgroup'], root=True)


def collect_processes(scope, *, proc_root, generation_id, prior_processes=(), source_files=None, source_links=None):
    """Full bounded /proc census; errors never mean zero processes. No argv leaves here."""
    validate_scope(scope); _validate_prior(prior_processes)
    require(hex_digest(generation_id), 'A supplied generation identity is required')
    root = Path(proc_root)
    boot = _boot(root)
    pids = sorted(int(path.name) for path in root.iterdir() if path.name.isdecimal())
    require(len(pids) <= MAX_PROCESSES, 'Process census exceeds its limit')
    processes, matched = {}, {}
    for pid in pids:
        directory = root/str(pid)
        before = parse_stat(_bounded_read(directory/'stat', 8192), pid)
        raw_group = _bounded_read(directory/'cgroup', 16384).decode('utf-8')
        groups = [line[3:] for line in raw_group.splitlines() if line.startswith('0::')]
        require(len(groups) == 1, 'Complete cgroup-v2 process identity is required')
        group = path_name(groups[0], root=True)
        selected = ['cgroup:' + item for item in scope['cgroups'] if _beneath(group, item)]
        if scope['script_roots'] or scope['script_paths']:
            raw = _bounded_read(directory/'cmdline', 65536)
            # Exact NUL-separated argument tokens only. Contents are never returned.
            tokens = raw.split(b'\0')
            for path in scope['script_paths']:
                if path.encode() in tokens:
                    selected.append('script:' + path)
            for base in scope['script_roots']:
                for token in tokens:
                    if not token.startswith((base + '/').encode()):
                        continue
                    require(b'/../' not in token and b'/./' not in token and b'//' not in token,
                            'Ambiguous script path inside the observed scope')
                    if source_files is not None:
                        try:
                            declared = _declared_source(token.decode('utf-8'), source_files, source_links or {})
                        except UnicodeError:
                            declared = False
                        require(declared,
                                'Scoped source path has no inventoried digest')
                    selected.append('root:' + base)
        after = parse_stat(_bounded_read(directory/'stat', 8192), pid)
        require(all(before[key] == after[key] for key in ('pid', 'ppid', 'pgrp', 'session', 'start_ticks')),
                'Process changed identity during observation')
        record = {**after, 'cgroup': group, 'boot_id': boot, 'generation_id': generation_id,
                  'scope_ids': sorted(set(selected))}
        processes[pid] = record
        if selected:
            matched[pid] = record
    require(_boot(root) == boot, 'Boot changed during process observation')
    for prior in prior_processes:
        if prior['boot_id'] != boot:
            continue  # Old-boot processes are gone; current scopes are still fully re-enumerated.
        current = processes.get(prior['pid'])
        if current is not None:
            require(current['start_ticks'] == prior['start_ticks'], 'Prior process PID was reused')
            current['scope_ids'] = sorted(set(current['scope_ids']) | {'prior:' + str(prior['pid'])})
            matched[current['pid']] = current
    # Follow exact observed parent links. A surviving session is included only
    # when its leader identity was observed/recorded, avoiding arbitrary SID reuse.
    sessions = {record['session'] for record in matched.values() if record['pid'] == record['session']}
    sessions.update(prior['session'] for prior in prior_processes if prior['boot_id'] == boot
                    and prior['pid'] == prior['session'] and (prior['pid'] not in processes
                         or processes[prior['pid']]['start_ticks'] == prior['start_ticks']))
    changed = True
    while changed:
        changed = False
        for pid, record in processes.items():
            if pid not in matched and (record['ppid'] in matched or record['session'] in sessions):
                record['scope_ids'] = ['descendant-or-session']
                matched[pid] = record; changed = True
    return {'boot_id': boot, 'census_count': len(pids), 'processes': [matched[pid] for pid in sorted(matched)]}


def observe(scope, expected_manifest, *, context, units, fs_root, proc_root, runner,
            clock_ns=time.monotonic_ns, prior_processes=()):
    inventory = digest_inventory(scope, expected_manifest, units, prior_processes=prior_processes)
    validate_context(context, inventory)
    _validate_prior(prior_processes)
    started = clock_ns()
    snapshots = []
    for _ in range(2):
        snapshots.append({'files': collect_files(expected_manifest, fs_root=fs_root),
                          'units': collect_units(units, runner=runner),
                          'processes': collect_processes(scope, proc_root=proc_root,
                              generation_id=context['generation_id'], prior_processes=prior_processes,
                              source_files=expected_manifest['files'], source_links=expected_manifest.get('links', {}))})
    receipt = {'format': 1, 'context': dict(context), 'inventory_digest': inventory,
               'expected': {'scope': scope, 'manifest': expected_manifest, 'units': units,
                            'prior_processes': list(prior_processes)},
               'started_at_ns': started, 'observed_at_ns': clock_ns(), 'snapshots': snapshots}
    receipt = json.loads(canonical(receipt))  # Detach from mutable caller input.
    receipt['receipt_digest'] = digest(receipt)
    return receipt


def snapshots_equal(first, second):
    """Compare a derived view; never rewrite the raw observations or receipt digest.

    Only the exact unit After/Before strings describe unordered member sets.
    Every other value, including Triggers/TriggeredBy and typed Exec, stays strict.
    """
    def same(left, right, path):
        if type(left) is not type(right):
            return False
        if len(path) == 3 and path[0] == 'units' and path[2] in ('After', 'Before'):
            require(type(left) is str, 'Ordering dependency must be a string')
            a, b = left.split(), right.split()
            require(all(dependency_name(item) for item in a + b)
                    and len(a) == len(set(a)) and len(b) == len(set(b)),
                    'Invalid or duplicate ordering dependency')
            return set(a) == set(b)
        if type(left) is dict:
            return set(left) == set(right) and all(same(left[key], right[key], path + (key,)) for key in left)
        if type(left) is list:
            return len(left) == len(right) and all(same(a, b, path + (str(index),))
                for index, (a, b) in enumerate(zip(left, right)))
        return left == right
    return same(first, second, ())


def verify(receipt, *, context, now_ns, max_age_ns=5_000_000_000):
    """Recompute all gates; receipts are evidence, not signatures or caller authority."""
    keys(receipt, {'format', 'context', 'inventory_digest', 'expected', 'started_at_ns', 'observed_at_ns', 'snapshots', 'receipt_digest'},
         'Invalid evidence receipt')
    validate_context(context)
    require(receipt['context'] == context, 'Evidence belongs to a different operation or root inventory')
    require(receipt['receipt_digest'] == digest({key: value for key, value in receipt.items() if key != 'receipt_digest'}),
            'Evidence receipt changed')
    require(type(receipt['format']) is int and receipt['format'] == 1
            and all(type(value) is int and value >= 0 for value in (receipt['started_at_ns'], receipt['observed_at_ns'], now_ns, max_age_ns))
            and max_age_ns > 0 and receipt['started_at_ns'] <= receipt['observed_at_ns'] <= now_ns
            and now_ns - receipt['started_at_ns'] <= max_age_ns, 'Evidence is stale or has an invalid clock')
    keys(receipt['expected'], {'scope', 'manifest', 'units', 'prior_processes'}, 'Invalid evidence inventory')
    expected = receipt['expected']
    require(digest_inventory(expected['scope'], expected['manifest'], expected['units'],
                             prior_processes=expected['prior_processes']) == context['inventory_digest'] == receipt['inventory_digest'],
            'Evidence inventory changed')
    snapshots = receipt['snapshots']
    require(isinstance(snapshots, list) and len(snapshots) == 2, 'Two complete observations are required')
    blockers = []
    for snapshot in snapshots:
        keys(snapshot, {'files', 'units', 'processes'}, 'Incomplete observation')
        file_kinds = {'files', 'directories'} | ({'links'} if 'links' in expected['manifest'] else set())
        keys(snapshot['files'], file_kinds, 'Incomplete filesystem observation')
        for kind in file_kinds:
            require(set(snapshot['files'][kind]) == set(expected['manifest'][kind]), 'Observed path set differs')
            for path, item in expected['manifest'][kind].items():
                wanted = {'state': 'present', **{key: value for key, value in item.items() if key != 'retention'}}
                if snapshot['files'][kind][path] != wanted:
                    blockers.append('Inventoried file metadata or content differs')
        require(set(snapshot['units']) == set(expected['units']), 'Observed unit set differs')
        for name, wanted in expected['units'].items():
            actual = snapshot['units'][name]
            _validate_unit_record(name, actual)
            require(('Execution' in actual) == ('execution' in wanted),
                    'Execution observation differs from the exact declared requirement')
            if 'execution' in wanted and actual['Execution'] != wanted['execution']:
                blockers.append('Typed unit execution differs')
            if actual['Id'] != name or actual['LoadState'] != 'loaded' or actual['NeedDaemonReload'] != 'no':
                blockers.append('Unit is not loaded from a coherent generation')
            if actual['FragmentPath'] != wanted['fragment_path'] or sorted(actual['DropInPaths'].split()) != sorted(wanted['drop_in_paths']):
                blockers.append('Unit file references differ')
            if any(sorted(actual[key].split()) != sorted(value) for key, value in wanted['references'].items()):
                blockers.append('Unit dependency references differ')
            if actual.get('ControlGroup') and actual['ControlGroup'] != wanted['scope_cgroup']:
                blockers.append('Unit process scope differs')
            if any(actual[key] != value for key, value in wanted.get('state', {}).items()):
                blockers.append('Unit activation or enablement state differs')
            if wanted.get('state', {}).get('ActiveState') == 'inactive' and not unit_quiescent(name, actual):
                blockers.append('Expected inactive unit still has processes or jobs')
        census = snapshot['processes']
        keys(census, {'boot_id', 'census_count', 'processes'}, 'Incomplete process census')
        require(census['boot_id'] == context['boot_id'], 'Boot changed; reobserve using a new root inventory context')
        require(type(census['census_count']) is int and 0 <= census['census_count'] <= MAX_PROCESSES, 'Invalid census size')
        _validate_prior(census['processes'])
        require(len({record['pid'] for record in census['processes']}) == len(census['processes'])
                and len(census['processes']) <= census['census_count'], 'Duplicate or incomplete observed process identities')
        require(all(record['boot_id'] == context['boot_id'] and record['generation_id'] == context['generation_id']
                    for record in census['processes']), 'Process provenance differs from the inventory context')
    if not snapshots_equal(snapshots[0], snapshots[1]):
        blockers.append('Observation changed between snapshots')
    require(not blockers, '; '.join(sorted(set(blockers))))
    return {'inventory_digest': receipt['inventory_digest'], 'receipt_digest': receipt['receipt_digest'],
            'boot_id': context['boot_id'], 'processes': snapshots[1]['processes']['processes'],
            'units': snapshots[1]['units']}


def require_quiescent(receipt, *, context, now_ns, max_age_ns=5_000_000_000):
    checked = verify(receipt, context=context, now_ns=now_ns, max_age_ns=max_age_ns)
    require(not [record for record in checked['processes'] if record['state'] not in ('Z', 'X', 'x')],
            'Scoped process or late descendant is still alive')
    for name, actual in checked['units'].items():
        require(unit_quiescent(name, actual), 'Scoped unit or queued unit job is not quiescent')
    return {'quiescent': True, 'receipt_digest': checked['receipt_digest'],
            'inventory_digest': checked['inventory_digest'], 'boot_id': checked['boot_id']}
