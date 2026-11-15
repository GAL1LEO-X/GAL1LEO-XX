"""Bounded, read-only census of named QoS processes or all users of a UID.

This proves quiescence only of the supplied source paths/cgroups, prior identities
and their observed descendants. It is not a complete SSH/root-writer inventory.
The caller must separately attest a freeze of unregistered manual QoS commands.
No argv, environment, comm or other process content is returned in a receipt.
The UID retirement gate scans all process groups and all four UID credentials.
"""
import errno
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import time

MAX_PROCESSES = 32768
MAX_MATCHED = 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_CMDLINE_BYTES = 512 * 1024
MAX_CGROUP_BYTES = 65536
MAX_STAT_BYTES = 4096
MAX_STATUS_BYTES = 65536
RECORD_FIELDS = {'boot_id', 'pid', 'start_ticks', 'ppid', 'pgrp', 'session',
                 'cgroups', 'scope_ids', 'scope_sha256'}


class ProcessesError(ValueError):
    pass


class ProcessesBusy(ProcessesError):
    pass


def _require(value, message):
    if not value:
        raise ProcessesError(message)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _path(value):
    _require(isinstance(value, str) and value.startswith('/') and not value.startswith('//') and value != '/'
             and len(value) <= 4096 and '\x00' not in value and '\n' not in value
             and posixpath.normpath(value) == value, 'Invalid named process scope path')
    return value


def validate_scope(scope):
    _require(isinstance(scope, dict) and set(scope) == {'script_paths', 'cgroups'},
             'Process scope must name paths and cgroups explicitly')
    normalized = {}
    for key in ('script_paths', 'cgroups'):
        values = scope[key]
        _require(isinstance(values, (list, tuple)) and len(values) <= 32, 'Process scope exceeds its bound')
        normalized[key] = sorted(_path(value) for value in values)
        _require(len(set(normalized[key])) == len(values), 'Duplicate process scope path')
    _require(any(normalized.values()), 'An empty process scope cannot prove quiescence')
    return normalized


def _boot(value):
    _require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value),
             'Invalid boot identity')
    return value


def _record(value, scope_sha):
    _require(isinstance(value, dict) and set(value) == RECORD_FIELDS, 'Incomplete prior process identity')
    _boot(value['boot_id'])
    _require(value['scope_sha256'] == scope_sha, 'Prior process belongs to another scope')
    for key in ('pid', 'start_ticks', 'ppid', 'pgrp', 'session'):
        _require(type(value[key]) is int and 0 <= value[key] < 2**64, 'Invalid process identity counter')
    _require(0 < value['pid'] < 2**31
             and all(value[key] < 2**31 for key in ('ppid', 'pgrp', 'session')),
             'Invalid process PID or start identity')
    _require(isinstance(value['cgroups'], list) and len(value['cgroups']) <= 128
             and all(isinstance(group, str) and group.startswith('/') and len(group) <= 4096
                     and '\x00' not in group and '\n' not in group for group in value['cgroups']),
             'Invalid process cgroup identity')
    _require(isinstance(value['scope_ids'], list) and 0 < len(value['scope_ids']) <= 128
             and all(isinstance(item, str) and 0 < len(item) <= 8192 and '\x00' not in item
                     for item in value['scope_ids']), 'Invalid process provenance')
    return dict(value)


def _prior(records, scope_sha):
    _require(isinstance(records, (list, tuple)) and len(records) <= MAX_MATCHED, 'Prior census exceeds its bound')
    result = [_record(record, scope_sha) for record in records]
    identities = [(item['boot_id'], item['pid'], item['start_ticks']) for item in result]
    _require(len(set(identities)) == len(result), 'Duplicate prior process identity')
    return sorted(result, key=lambda item: (item['boot_id'], item['pid'], item['start_ticks']))


def _read_at(parent, name, maximum, budget):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        _require(stat.S_ISREG(os.fstat(fd).st_mode), 'Process evidence is not a regular proc file')
        chunks, count = [], 0
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - count))
            if not chunk:
                break
            count += len(chunk); budget[0] += len(chunk)
            _require(count <= maximum and budget[0] <= MAX_TOTAL_BYTES, 'Process census byte bound exceeded')
            chunks.append(chunk)
        return b''.join(chunks)
    finally:
        os.close(fd)


def _boot_at(root, budget):
    descriptor = os.dup(root)
    try:
        for name in ('sys', 'kernel', 'random'):
            next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor); descriptor = next_fd
        return _boot(_read_at(descriptor, 'boot_id', 64, budget).decode('ascii').strip())
    finally:
        os.close(descriptor)


def _stat(raw, expected_pid):
    # comm may contain spaces and parentheses. Numeric fields follow its LAST ')'.
    marker = raw.rfind(b') ')
    _require(marker > 0 and raw[:raw.find(b' (')] == str(expected_pid).encode(), 'Malformed process stat identity')
    values = raw[marker + 2:].split()
    _require(len(values) >= 20 and values[0] in (b'R', b'S', b'D', b'Z', b'T', b't', b'X', b'x', b'K', b'W', b'P', b'I'),
             'Incomplete process state')
    try:
        result = {'pid': expected_pid, 'ppid': int(values[1]), 'pgrp': int(values[2]),
                  'session': int(values[3]), 'start_ticks': int(values[19])}
    except ValueError:
        raise ProcessesError('Malformed process identity counters') from None
    _require(0 <= result['start_ticks'] < 2**64 and all(0 <= result[key] < 2**31 for key in ('ppid', 'pgrp', 'session')),
             'Invalid process counters')
    result['_dead'] = values[0] in (b'Z', b'X', b'x')
    return result


def _groups(raw):
    result = []
    for line in raw.decode('utf-8').splitlines():
        parts = line.split(':', 2)
        _require(len(parts) == 3 and parts[0].isdigit() and parts[2].startswith('/')
                 and len(parts[2]) <= 4096 and '\x00' not in parts[2], 'Malformed process cgroup evidence')
        result.append(parts[2])
    _require(len(result) <= 128, 'Process cgroup evidence exceeds its bound')
    return sorted(set(result))


def _path_matches(args, paths, process_fd):
    matches = []
    cwd = None
    for path in paths:
        encoded = os.fsencode(path)
        if encoded in args:
            matches.append('path:' + path)
            continue
        # Legacy tools can be invoked through PATH. This intentionally errs on
        # the side of busy for an argv[0] collision; it never authorizes a write.
        if args and args[0] == os.fsencode(posixpath.basename(path)):
            matches.append('path:' + path)
            continue
        for argument in args:
            if argument.startswith(b'/') or os.path.basename(argument) != os.fsencode(posixpath.basename(path)):
                continue
            if cwd is None:
                cwd = os.readlink('cwd', dir_fd=process_fd)
            if posixpath.normpath(posixpath.join(cwd, os.fsdecode(argument))) == path:
                matches.append('path:' + path)
                break
    return matches


def _snapshot(root, scope, scope_sha, priors):
    budget = [0]
    boot = _boot_at(root, budget)
    all_processes = {}
    # scandir is consumed incrementally; an enormous proc fixture cannot allocate
    # an unbounded directory listing before the cardinality check.
    with os.scandir(root) as entries:
        count = 0
        for entry in entries:
            if not re.fullmatch(r'[1-9][0-9]*', entry.name):
                continue
            count += 1
            _require(count <= MAX_PROCESSES, 'Process census cardinality exceeds its bound')
            pid = int(entry.name)
            _require(pid < 2**31, 'Invalid proc PID')
            descriptor = None
            try:
                descriptor = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
                before = _stat(_read_at(descriptor, 'stat', MAX_STAT_BYTES, budget), pid)
                args = _read_at(descriptor, 'cmdline', MAX_CMDLINE_BYTES, budget)
                _require(not args or args.endswith(b'\x00'), 'Truncated process command line')
                groups = _groups(_read_at(descriptor, 'cgroup', MAX_CGROUP_BYTES, budget))
                selected = _path_matches(args.rstrip(b'\x00').split(b'\x00') if args else [], scope['script_paths'], descriptor)
                selected += ['cgroup:' + wanted for wanted in scope['cgroups']
                             if any(group == wanted or group.startswith(wanted + '/') for group in groups)]
                after = _stat(_read_at(descriptor, 'stat', MAX_STAT_BYTES, budget), pid)
                _require(before['start_ticks'] == after['start_ticks'], 'PID identity changed during observation')
                all_processes[pid] = {**after, 'boot_id': boot, 'cgroups': groups, 'scope_ids': selected,
                                      'scope_sha256': scope_sha}
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ESRCH):
                    raise ProcessesError('A process could not be observed safely') from None
                # ENOENT for missing cmdline/cgroup/cwd in an extant PID is an
                # incomplete observation, not evidence that the process exited.
                try:
                    probe = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
                except OSError as absent:
                    if absent.errno not in (errno.ENOENT, errno.ESRCH):
                        raise ProcessesError('Process disappearance is ambiguous') from None
                else:
                    os.close(probe)
                    raise ProcessesError('A live process has incomplete evidence') from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
    prior_current = [record for record in priors if record['boot_id'] == boot]
    for record in prior_current:
        actual = all_processes.get(record['pid'])
        identity = f"{record['pid']}:{record['start_ticks']}"
        if actual is not None and actual['start_ticks'] == record['start_ticks']:
            actual['scope_ids'].append('prior:' + identity)
        # A session/group owned by the known process can retain orphan children.
        # Shared interactive sessions are not promoted to ownership of all root
        # processes; finite tool paths and persisted exact children cover those.
        if actual is not None and actual['start_ticks'] != record['start_ticks']:
            continue  # The old numeric leader ID has been reused.
        for candidate in all_processes.values():
            if record['session'] == record['pid'] and candidate['session'] == record['session']:
                candidate['scope_ids'].append('session:' + identity)
            elif record['pgrp'] == record['pid'] and candidate['pgrp'] == record['pgrp']:
                candidate['scope_ids'].append('pgrp:' + identity)
    # Traverse each parent edge once, including a reverse-ordered proc listing.
    # A dead parent can connect a live child; only live records block quiescence.
    children = {}
    for pid, record in all_processes.items():
        children.setdefault(record['ppid'], []).append(pid)
    selected_pids = {pid for pid, record in all_processes.items() if record['scope_ids']}
    pending = deque(selected_pids)
    while pending:
        parent = all_processes[pending.popleft()]
        for pid in children.get(parent['pid'], ()):
            if pid not in selected_pids:
                all_processes[pid]['scope_ids'].append(f"descendant:{parent['pid']}:{parent['start_ticks']}")
                selected_pids.add(pid); pending.append(pid)
    records = []
    for pid in sorted(selected_pids):
        record = all_processes[pid]
        if record.pop('_dead'):
            continue
        record['scope_ids'] = sorted(set(record['scope_ids']))
        records.append(_record(record, scope_sha))
    _require(len(records) <= MAX_MATCHED, 'Matched process census exceeds its bound')
    _require(_boot_at(root, budget) == boot, 'Boot changed during process census')
    return boot, {'records': records, 'process_count': count}


def collect(scope, prior_records=(), *, proc_root=Path('/proc'), clock_ns=time.monotonic_ns):
    scope = validate_scope(scope); scope_sha = _digest(scope)
    priors = _prior(prior_records, scope_sha)
    base = Path(proc_root).absolute()
    _require(base == base.resolve(strict=True), 'Proc root must be physical')
    root = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    started = clock_ns()
    try:
        boot, first = _snapshot(root, scope, scope_sha, priors)
        seeded = {(item['boot_id'], item['pid'], item['start_ticks']): item for item in [*priors, *first['records']]}
        boot_after, second = _snapshot(root, scope, scope_sha, list(seeded.values()))
        _require(boot_after == boot, 'Boot changed between process observations')
    except (OSError, UnicodeError) as error:
        raise ProcessesError('Process census is incomplete') from error
    finally:
        os.close(root)
    finished = clock_ns()
    _require(type(started) is int and type(finished) is int and 0 <= started <= finished, 'Invalid observation clock')
    selected = {(item['boot_id'], item['pid'], item['start_ticks']): item for item in [*first['records'], *second['records']]}
    return {'format': 1, 'scope_sha256': scope_sha, 'prior_sha256': _digest(priors), 'boot_id': boot,
            'started_ns': started, 'finished_ns': finished, 'snapshots': [first, second],
            'records': sorted(selected.values(), key=lambda item: (item['boot_id'], item['pid'], item['start_ticks']))}


def require_quiet(receipt, *, scope, prior_records=(), now_ns=None, max_age_ns=5_000_000_000):
    normalized = validate_scope(scope); scope_sha = _digest(normalized)
    priors = _prior(prior_records, scope_sha)
    fields = {'format', 'scope_sha256', 'prior_sha256', 'boot_id', 'started_ns', 'finished_ns', 'snapshots', 'records'}
    _require(isinstance(receipt, dict) and set(receipt) == fields and type(receipt['format']) is int
             and receipt['format'] == 1 and receipt['scope_sha256'] == scope_sha
             and receipt['prior_sha256'] == _digest(priors), 'Census receipt is not bound to this scope and prior identities')
    boot = _boot(receipt['boot_id'])
    now = time.monotonic_ns() if now_ns is None else now_ns
    _require(all(type(value) is int for value in (now, max_age_ns, receipt['started_ns'], receipt['finished_ns']))
             and 0 < max_age_ns <= 5_000_000_000 and 0 <= receipt['started_ns'] <= receipt['finished_ns'] <= now
             and now - receipt['started_ns'] <= max_age_ns, 'Process census is stale or has an invalid clock')
    _require(isinstance(receipt['snapshots'], list) and len(receipt['snapshots']) == 2, 'Two process observations are required')
    union = {}
    for snapshot in receipt['snapshots']:
        _require(isinstance(snapshot, dict) and set(snapshot) == {'records', 'process_count'}
                 and type(snapshot['process_count']) is int and 0 <= snapshot['process_count'] <= MAX_PROCESSES,
                 'Invalid process observation shape')
        records = _prior(snapshot['records'], scope_sha)
        _require(len(records) <= snapshot['process_count'], 'Process observation count is incomplete')
        _require(all(record['boot_id'] == boot for record in records), 'Census includes another boot')
        for record in records:
            union[(record['boot_id'], record['pid'], record['start_ticks'])] = record
    expected = sorted(union.values(), key=lambda item: (item['boot_id'], item['pid'], item['start_ticks']))
    _require(_prior(receipt['records'], scope_sha) == expected, 'Process receipt records differ from the two observations')
    if expected:
        raise ProcessesBusy('Named QoS processes or their observed descendants are still active')
    return receipt


def _uids(raw):
    # All four credentials matter: a saved or filesystem UID can still be used
    # after the effective UID changes. Never infer credentials from an owner or
    # a service/cgroup name. The rest of status is deliberately not retained.
    lines = [line for line in raw.splitlines() if line.startswith(b'Uid:')]
    _require(len(lines) == 1, 'Process status has no unique UID evidence')
    values = lines[0][4:].split()
    _require(len(values) == 4 and all(re.fullmatch(rb'[0-9]{1,10}', value) for value in values),
             'Process UID evidence is incomplete')
    result = [int(value) for value in values]
    _require(all(value < 2**32 - 1 for value in result), 'Process UID is outside the kernel UID range')
    return result


def _uid_snapshot(root, uid):
    budget = [0]
    boot = _boot_at(root, budget)
    records, count = [], 0
    with os.scandir(root) as entries:
        for entry in entries:
            if not re.fullmatch(r'[1-9][0-9]*', entry.name):
                continue
            count += 1
            _require(count <= MAX_PROCESSES, 'UID census cardinality exceeds its bound')
            pid = int(entry.name)
            _require(pid < 2**31, 'Invalid proc PID')
            descriptor = None
            try:
                descriptor = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=root)
                before = _stat(_read_at(descriptor, 'stat', MAX_STAT_BYTES, budget), pid)
                uids = _uids(_read_at(descriptor, 'status', MAX_STATUS_BYTES, budget))
                after = _stat(_read_at(descriptor, 'stat', MAX_STAT_BYTES, budget), pid)
                _require(before['start_ticks'] == after['start_ticks'], 'PID identity changed during UID observation')
                if uid in uids:
                    # Even zombies count here. This is an account-wide absence
                    # gate, stronger than the named active-writer census above.
                    records.append({'boot_id': boot, 'pid': pid, 'start_ticks': after['start_ticks'], 'uids': uids})
                    _require(len(records) <= MAX_MATCHED, 'Matched UID census exceeds its bound')
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ESRCH):
                    raise ProcessesError('A process UID could not be observed safely') from None
                try:
                    probe = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
                except OSError as absent:
                    if absent.errno not in (errno.ENOENT, errno.ESRCH):
                        raise ProcessesError('UID process disappearance is ambiguous') from None
                else:
                    os.close(probe)
                    raise ProcessesError('An extant process has incomplete UID evidence') from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
    _require(_boot_at(root, budget) == boot, 'Boot changed during UID census')
    return boot, {'records': sorted(records, key=lambda record: record['pid']), 'process_count': count}


def require_uid_quiet(uid, *, proc_root=Path('/proc'), clock_ns=time.monotonic_ns):
    """Require two complete observations with no process using this UID.

    This intentionally spans all cgroups and checks real/effective/saved/fs UIDs.
    It is a read-only admission observation, not a freeze against future process
    creation: the caller must retain its owner gate through the mutation.
    """
    _require(type(uid) is int and 0 <= uid < 2**32 - 1, 'Invalid UID for process census')
    root = None
    try:
        base = Path(proc_root).absolute()
        _require(base == base.resolve(strict=True), 'Proc root must be physical')
        root = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        started = clock_ns()
        boot, first = _uid_snapshot(root, uid)
        boot_after, second = _uid_snapshot(root, uid)
        _require(boot_after == boot, 'Boot changed between UID observations')
        finished = clock_ns()
        _require(type(started) is int and type(finished) is int and 0 <= started <= finished
                 and finished - started <= 5_000_000_000, 'UID census is stale or has an invalid clock')
    except (OSError, UnicodeError) as error:
        raise ProcessesError('UID census is incomplete') from error
    finally:
        if root is not None:
            os.close(root)
    selected = {(record['boot_id'], record['pid'], record['start_ticks']): record
                for record in [*first['records'], *second['records']]}
    receipt = {'format': 1, 'uid': uid, 'boot_id': boot, 'started_ns': started, 'finished_ns': finished,
               'snapshots': [first, second],
               'records': sorted(selected.values(), key=lambda record: (record['pid'], record['start_ticks']))}
    if selected:
        error = ProcessesBusy('Processes still use the UID whose QoS rule would be retired')
        error.receipt = receipt
        raise error
    return receipt
