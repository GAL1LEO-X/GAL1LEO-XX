"""Finite host operations used by reviewed lifecycle profiles.

Importing this module has no host effects. Commands are explicit argv, bounded,
and never taken from a manifest. Filesystem mutations belong to filesystem.py.
Fixture roots cannot invoke the real service runner.
"""
from contextlib import contextmanager, nullcontext
import fcntl
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
import sys as _installation_sys
from pathlib import Path as _InstallationPath
_installation_sys.path.insert(0,str(_InstallationPath(__file__).resolve().parents[2]))
from host.installation import active as installation_profile, mapped as installation_path

from .filesystem import LifecycleBusy, LifecycleError, Root, require


WA_RECOVERY = (installation_path('develative-whatsapp-recovery.service'),
               installation_path('develative-whatsapp-recovery.timer'))
WA_LOCKS = (installation_path('/var/lib/develative-deploy/whatsapp/publication.lock'),
            installation_path('/srv/openai-codex/projects/whatsapp-personal/private/tenant-admin.lock'))
BOX_LOCKS = ('/var/lib/develative-deploy/publication.lock',)
SERVICE_LEASE = installation_path('/var/lib/develative-deploy/whatsapp/service-operation.lock')
MAX_OUTPUT = 256 * 1024
RECOVERY_COMMON = ('Id', 'LoadState', 'NeedDaemonReload', 'FragmentPath', 'DropInPaths',
                   'Job', 'ActiveState', 'SubState')
RECOVERY_PROPERTIES = {
    WA_RECOVERY[0]: (*RECOVERY_COMMON, 'Type', 'User', 'ExecStart', 'ExecStartPre', 'ExecStartPost',
                    'ExecStop', 'ExecStopPost', 'ExecCondition', 'KillMode', 'RemainAfterExit',
                    'Restart', 'RestartForceExitStatus', 'TimeoutStartUSec', 'MainPID', 'ControlPID'),
    WA_RECOVERY[1]: (*RECOVERY_COMMON, 'UnitFileState', 'Unit', 'TimersMonotonic', 'TimersCalendar'),
}
RECOVERY_ENTRYPOINT = installation_path('/usr/local/lib/develative-deploy/whatsapp-bootstrap/release_entry.py')
# systemctl's custom printers can omit empty structured values even with
# --all. Missing identity/state properties must still fail closed. Only these
# fields can be recovered, by proving their typed value is actually empty.
RECOVERY_EMPTY_PROPERTIES = {
    'ExecStartPre': ('Service', 'a(sasbttttuii)', []),
    'ExecStartPost': ('Service', 'a(sasbttttuii)', []),
    'ExecStop': ('Service', 'a(sasbttttuii)', []),
    'ExecStopPost': ('Service', 'a(sasbttttuii)', []),
    'ExecCondition': ('Service', 'a(sasbttttuii)', []),
    'TimersCalendar': ('Timer', 'a(sst)', []),
}


def _bounded(argv, *, timeout=10, max_bytes=MAX_OUTPUT, pass_fds=(), preserve_child=False):
    """Private bounded process runner; callers expose finite operations only."""
    require(type(timeout) in (float, int) and 0 < timeout <= 30,
            'Invalid command timeout')
    require(type(max_bytes) is int and 0 < max_bytes <= MAX_OUTPUT
            and isinstance(pass_fds, tuple) and all(type(fd) is int and fd >= 0 for fd in pass_fds),
            'Invalid command resource or lease descriptors')
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, close_fds=True, pass_fds=pass_fds,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
             'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0'})
    selector = selectors.DefaultSelector()
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'Host command timed out; observe before resuming')
            for item, _ in selector.select(remaining):
                chunk = os.read(item.fd, 8192)
                if not chunk:
                    selector.unregister(item.fileobj)
                    continue
                (output if item.fileobj is process.stdout else errors).extend(chunk)
                require(len(output) + len(errors) <= max_bytes,
                        'Host command output exceeded its bound; observe before resuming')
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
        require(process.returncode == 0, 'Host command failed; inspect scoped service state')
        return output.decode('utf-8', errors='strict')
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        raise LifecycleError('Host command did not complete; observe before resuming') from error
    finally:
        selector.close()
        if process.poll() is None and not preserve_child:
            # This is the short-lived systemctl client, never a workload PID.
            process.kill()
        if not preserve_child or process.poll() is not None:
            process.wait()
        process.stdout.close()
        process.stderr.close()


def service_argv(operation):
    """No BOX, shared recovery, application or network unit is writable here."""
    commands = {
        'reload-definitions': ['/usr/bin/systemctl', 'daemon-reload'],
        'enable-wa-recovery': ['/usr/bin/systemctl', 'enable', '--', WA_RECOVERY[1]],
        'start-wa-recovery': ['/usr/bin/systemctl', '--no-block', 'start', '--', WA_RECOVERY[1]],
        'disable-wa-recovery': ['/usr/bin/systemctl', 'disable', '--', WA_RECOVERY[1]],
        'stop-wa-recovery': ['/usr/bin/systemctl', '--no-block', 'stop', '--', WA_RECOVERY[1]],
    }
    require(operation in commands, 'Service operation is outside this profile')
    return commands[operation]


def service_runner(operation, *, pass_fds):
    require(os.geteuid() == 0, 'Root is required for host service operations')
    require(isinstance(pass_fds, tuple) and len(pass_fds) == 1, 'A service operation lease is required')
    service_argv(operation)  # Validate the same finite contract before spawn.
    helper = Path(__file__).with_name('service_client.py')
    require(helper.is_absolute() and helper == helper.resolve(strict=True),
            'Supervisor source must be physical')
    interpreter = Path(sys.executable).resolve(strict=True)
    for path in (helper, interpreter):
        require(path.is_absolute(), 'Supervisor source must be absolute')
        for item in (path, *path.parents):
            info = item.lstat()
            require((stat.S_ISREG(info.st_mode) if item == path else stat.S_ISDIR(info.st_mode))
                    and info.st_uid == 0 and not info.st_mode & 0o022,
                    'Supervisor source or interpreter is not protected')
    return _bounded([str(interpreter), '-I', '-B', str(helper), 'whatsapp', operation, str(pass_fds[0])],
                    pass_fds=pass_fds, timeout=30, preserve_child=True)


def recovery_show_argv(unit):
    require(unit in RECOVERY_PROPERTIES, 'Unit is outside the dedicated recovery read profile')
    return ['/usr/bin/systemctl', 'show', '--no-pager', '--all',
            '--property=' + ','.join(RECOVERY_PROPERTIES[unit]), '--', unit]


def recovery_empty_argv(unit, field):
    require(unit in RECOVERY_PROPERTIES and field in RECOVERY_PROPERTIES[unit]
            and field in RECOVERY_EMPTY_PROPERTIES,
            'Property is outside the dedicated recovery empty-value profile')
    interface = RECOVERY_EMPTY_PROPERTIES[field][0]
    object_name = ''.join(char if char.isascii() and char.isalnum()
                          else '_' + format(ord(char), '02x') for char in unit)
    return ['/usr/bin/busctl', '--system', '--json=short', 'get-property',
            'org.freedesktop.systemd1', '/org/freedesktop/systemd1/unit/' + object_name,
            'org.freedesktop.systemd1.' + interface, field]


def recovery_read_runner(argv, *, timeout=5.0, max_bytes=MAX_OUTPUT):
    allowed = [recovery_show_argv(unit) for unit in WA_RECOVERY]
    allowed.extend(recovery_empty_argv(unit, field) for unit in WA_RECOVERY
                   for field in RECOVERY_PROPERTIES[unit] if field in RECOVERY_EMPTY_PROPERTIES)
    require(isinstance(argv, list) and argv in allowed,
            'Read operation is outside the dedicated recovery profile')
    return _bounded(argv, timeout=timeout, max_bytes=max_bytes).encode('utf-8')


def _verify_recovery_empty(unit, field, reader):
    raw = reader(recovery_empty_argv(unit, field), timeout=5.0, max_bytes=MAX_OUTPUT)
    require(type(raw) is bytes and len(raw) <= MAX_OUTPUT, 'Invalid typed recovery response')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate typed recovery response field')
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise LifecycleError('Invalid typed recovery response; raw output withheld') from None
    _, signature, empty = RECOVERY_EMPTY_PROPERTIES[field]
    require(isinstance(value, dict) and set(value) == {'type', 'data'}
            and value['type'] == signature and value['data'] == empty,
            'Omitted recovery property is not proven empty: ' + field)


def _recovery_properties(unit, reader):
    data = reader(recovery_show_argv(unit), timeout=5.0, max_bytes=MAX_OUTPUT)
    require(isinstance(data, bytes) and len(data) <= MAX_OUTPUT, 'Invalid recovery unit observation')
    try:
        lines = data.decode('utf-8').splitlines()
    except UnicodeError:
        raise LifecycleError('Invalid recovery unit observation encoding') from None
    properties = {}
    for line in lines:
        key, separator, value = line.partition('=')
        require(separator and key in RECOVERY_PROPERTIES[unit]
                and (key not in properties or key == 'TimersMonotonic'), 'Unknown or repeated recovery property')
        properties[key] = properties[key] + ' ' + value if key in properties else value
    missing = set(RECOVERY_PROPERTIES[unit]) - set(properties)
    require(missing <= set(RECOVERY_EMPTY_PROPERTIES) and properties.get('Id') == unit,
            'Incomplete dedicated recovery identity')
    for field in RECOVERY_PROPERTIES[unit]:
        if field in missing:
            _verify_recovery_empty(unit, field, reader)
            properties[field] = ''
    return properties


def _verify_recovery_properties(properties, *, enabled=True):
    for unit in WA_RECOVERY:
        item = properties[unit]
        require(item['LoadState'] == 'loaded' and item['NeedDaemonReload'] == 'no'
                and item['FragmentPath'] == '/etc/systemd/system/' + unit and not item['DropInPaths'],
                'Dedicated recovery is not loaded from its reviewed unit without drop-ins')
        if item['Job'] not in ('', '0'):
            raise LifecycleBusy('Dedicated recovery has a pending manager job; observe again after natural completion')
    timer = properties[WA_RECOVERY[1]]
    require(timer['Unit'] == WA_RECOVERY[0] and not timer['TimersCalendar'],
            'Dedicated recovery timer must target only its own service')
    if enabled:
        require(timer['ActiveState'] == 'active' and timer['UnitFileState'] == 'enabled',
                'Dedicated recovery timer must be active, enabled and target only its own service')
    else:
        require(timer['ActiveState'] == 'inactive' and timer['SubState'] == 'dead'
                and timer['UnitFileState'] == 'disabled',
                'Dedicated recovery timer has not completed disable and stop')
    bases = re.findall(r'\{\s*(On[A-Za-z]+USec)=([^;]+);[^}]*\}', timer['TimersMonotonic'])
    require(len(bases) == 2 and {key: value.strip() for key, value in bases} in
            ({'OnBootUSec': '45s', 'OnUnitInactiveUSec': '1min'},
             {'OnBootUSec': '45s', 'OnUnitInactiveUSec': '60s'}),
            'Dedicated recovery cadence differs from the reviewed template')
    service = properties[WA_RECOVERY[0]]
    require(all(re.fullmatch('[0-9]+', service[key]) for key in ('MainPID', 'ControlPID'))
            and service['ActiveState'] in ('inactive', 'failed', 'activating', 'active', 'deactivating'),
            'Dedicated recovery process state is not observable')
    if service['ActiveState'] in ('inactive', 'failed'):
        require(service['MainPID'] == service['ControlPID'] == '0',
                'Inactive recovery still reports a process')
    require(service['Type'] == 'oneshot' and service['User'] == 'root' and service['KillMode'] == 'control-group'
            and service['RemainAfterExit'] == 'no' and service['Restart'] == 'no'
            and not service['RestartForceExitStatus'] and service['TimeoutStartUSec'] in ('10min', '600s'),
            'Dedicated recovery identity, supervision or execution bound differs')
    require(all(not service[field] for field in ('ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecCondition')),
            'Unexpected auxiliary command in dedicated recovery')
    executable = re.findall(r'\bpath=([^;]+);', service['ExecStart'])
    arguments = re.findall(r'\bargv\[\]=([^;]+);', service['ExecStart'])
    require([value.strip() for value in executable] == ['/usr/bin/python3']
            and [value.strip() for value in arguments] == ['/usr/bin/python3 -I -B ' + RECOVERY_ENTRYPOINT + ' recovery'],
            'Dedicated recovery does not use the reviewed stable entrypoint')


class RecoveryServices:
    """Idempotent timer operations; completion is proved by a fresh observation.

    The recovery service itself is never killed: close stops future timer
    triggers and the lifecycle drains a recovery already in flight naturally.
    A journal intent must be durable before invoking these methods.
    """
    def __init__(self, root, *, runner=service_runner, reader=recovery_read_runner):
        self.root = root if isinstance(root, Root) else Root(root)
        require(runner is not service_runner or self.root.base == Path('/'),
                'A fixture cannot run host service commands')
        self.runner = runner
        self.reader = reader

    def _run(self, operations, lease_fds, manifest, *, enabled):
        manager = service_lease(self.root) if lease_fds is None else nullcontext(lease_fds)
        with manager as descriptors:
            _require_service_lease(self.root, descriptors)
            require(self.reader is not recovery_read_runner or self.root.base == Path('/'),
                    'A fixture cannot query host recovery units')
            expected = self._unit_files(manifest)
            require(all(self.root.snapshot(path) == item for path, item in expected.items()),
                    'Dedicated recovery unit file changed before service operation')
            for unit in WA_RECOVERY:
                item = _recovery_properties(unit, self.reader)
                if item['Job'] not in ('', '0'):
                    raise LifecycleBusy('Dedicated recovery already has a manager job; observe before another operation')
            for operation in operations:
                self.runner(operation, pass_fds=descriptors)
            # The client lease does not own a job already sent over D-Bus.
            # Claim completion only after bounded, effective observations.
            return self.verify(manifest, enabled=enabled)

    def activate(self, manifest, *, lease_fds=None):
        return self._run(('reload-definitions', 'enable-wa-recovery', 'start-wa-recovery'), lease_fds,
                         manifest, enabled=True)

    def close(self, manifest, *, lease_fds=None):
        return self._run(('disable-wa-recovery', 'stop-wa-recovery'), lease_fds, manifest, enabled=False)

    def verify(self, manifest, *, enabled=True):
        """Read effective loaded properties and exact unit files before admission."""
        require(self.reader is not recovery_read_runner or self.root.base == Path('/'),
                'A fixture cannot query host recovery units')
        expected = self._unit_files(manifest)
        for _ in range(2):
            require(all(self.root.snapshot(path) == item for path, item in expected.items()),
                    'Dedicated recovery unit file changed')
            properties = {unit: _recovery_properties(unit, self.reader) for unit in WA_RECOVERY}
            _verify_recovery_properties(properties, enabled=enabled)
        require(all(self.root.snapshot(path) == item for path, item in expected.items()),
                'Dedicated recovery unit file changed during effective verification')
        service = properties[WA_RECOVERY[0]]
        return {'dedicated_recovery_verified': True, 'timer': WA_RECOVERY[1], 'enabled': enabled,
                'unit_files': sorted(expected), 'service_state': service['ActiveState'],
                'main_pid': int(service['MainPID']), 'control_pid': int(service['ControlPID'])}

    def _unit_files(self, manifest):
        expected = {}
        for unit in WA_RECOVERY:
            path = '/etc/systemd/system/' + unit
            require(path in manifest['files'], 'Both dedicated recovery unit files must be inventoried')
            expected[path] = {key: value for key, value in manifest['files'][path].items() if key != 'retention'}
        return expected


@contextmanager
def _named_locks(root, paths):
    descriptors = []
    try:
        for path in paths:
            with root._parent(path) as (parent, name):
                try:
                    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent)
                    descriptors.append(fd)
                    os.fsync(fd)
                    os.fsync(parent)
                except FileExistsError:
                    fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    descriptors.append(fd)
                initial = os.fstat(fd)
                require(stat.S_ISREG(initial.st_mode) and initial.st_uid == root.uid
                        and not initial.st_mode & 0o022 and initial.st_nlink == 1,
                        'Lock is not an exclusive protected regular file')
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise LifecycleBusy('This application has an operation in flight') from error
                actual = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require((initial.st_dev, initial.st_ino, initial.st_uid, initial.st_mode) ==
                        (actual.st_dev, actual.st_ino, actual.st_uid, actual.st_mode),
                        'Lock pathname changed during acquisition')
        yield tuple(descriptors)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


@contextmanager
def raw_locks(root, *, owner, include_tenant=True):
    """Nonblocking stable locks; callers acquire service_lease before WA locks."""
    require(isinstance(root, Root) and owner in ('whatsapp', 'box'), 'Invalid lock authority')
    paths = (WA_LOCKS if include_tenant else WA_LOCKS[:1]) if owner == 'whatsapp' else BOX_LOCKS
    with _named_locks(root, paths) as descriptors:
        yield descriptors


@contextmanager
def service_lease(root):
    """Stable per-WA lease inherited by every mutating service client.

    A dead controller cannot release the lease while its client still owns it.
    The next controller takes this lease before publication/tenant locks and
    obtains fresh unit/process evidence before issuing another mutation.
    """
    require(isinstance(root, Root), 'Invalid service lease authority')
    with _named_locks(root, (SERVICE_LEASE,)) as descriptors:
        yield descriptors


@contextmanager
def operation_locks(root, *, owner, include_tenant=True):
    """Application lifecycle ordering: WA service lease, publication, tenant."""
    require(owner in ('whatsapp', 'box'), 'Invalid operation lock owner')
    lease = service_lease(root) if owner == 'whatsapp' else nullcontext(())
    with lease as lease_fds, raw_locks(root, owner=owner, include_tenant=include_tenant) as locks:
        yield (*lease_fds, *locks)


def _require_service_lease(root, descriptors):
    require(isinstance(descriptors, tuple) and len(descriptors) == 1, 'An exact service lease descriptor is required')
    info = os.fstat(descriptors[0])
    with root._parent(SERVICE_LEASE) as (parent, name):
        actual = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == root.uid and not info.st_mode & 0o022
            and info.st_nlink == 1 and (info.st_dev, info.st_ino, info.st_uid, info.st_mode) ==
            (actual.st_dev, actual.st_ino, actual.st_uid, actual.st_mode), 'Service lease identity changed')
    try:
        fcntl.flock(descriptors[0], fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        raise LifecycleBusy('A service operation client is still active') from error
