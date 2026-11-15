"""Finite privileged service-client supervisor; no manifest commands or shell.

The supervisor retains the inherited application lease independently of any
descriptor handling inside systemctl. It never writes child output to its
controller and does not signal a workload, only its own bounded CLI child.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import re
import stat
import subprocess
import sys
import time


LEASES = {'whatsapp': '/var/lib/develative-deploy/whatsapp/service-operation.lock',
          'box': '/var/lib/develative-deploy/box/service-operation.lock'}
TIMERS = {'whatsapp': 'develative-whatsapp-recovery.timer',
          'box': 'develative-release-recovery.timer'}
LEGACY_LEASES = dict(LEASES)
LEGACY_TIMERS = dict(TIMERS)
MAX_OUTPUT = 256 * 1024


def _public_record(selected, *, root, authority):
    """Read a bounded, protected public record without executing product code."""
    if selected!=selected.resolve(strict=True):raise RuntimeError('Installation record must be physical')
    current=root
    for part in ('',*selected.relative_to(root).parts):
        if part:current/=part
        info=current.lstat();kind=stat.S_ISREG if current==selected else stat.S_ISDIR
        if not kind(info.st_mode) or info.st_uid!=authority or info.st_mode&0o022:
            raise RuntimeError('Installation record is not protected')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise RuntimeError('Duplicate installation field')
            result[key]=value
        return result
    with os.fdopen(os.open(selected,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):raise RuntimeError('Installation record must be regular')
        raw=stream.read(131073);after=os.fstat(stream.fileno())
    identity=lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
    if len(raw)>131072 or identity(before)!=identity(after) or identity(after)!=identity(selected.lstat()):
        raise RuntimeError('Installation record changed or exceeded its bound')
    return json.loads(raw,object_pairs_hook=unique)


def _owner_configuration(owner, *, root=Path('/'), authority=0):
    """Read only the requested product's protected identity and locator.

    The supervisor independently admits a finite recovery identity and lease,
    never an argv or a unit supplied by the operation manifest.
    """
    root=Path(root).absolute()
    if root!=root.resolve(strict=True):raise RuntimeError('Installation root must be physical')
    selected=root/('etc/'+owner+'-installation.json')
    marker=root/('etc/'+owner+'-installation-identity.json')
    identity=_public_record(marker,root=root,authority=authority)
    if (not isinstance(identity,dict) or set(identity)!={'format','mode','installation_sha256'}
            or identity['format']!=owner+'-installation-identity-v1'
            or identity['mode'] not in ('legacy','configured')):
        raise RuntimeError('Invalid installation identity')
    value=({'format':owner+'-installation-legacy-v1'} if identity['mode']=='legacy'
           else _public_record(selected,root=root,authority=authority))
    encoded=(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    if identity['installation_sha256']!=hashlib.sha256(encoded).hexdigest():
        raise RuntimeError('Installation locator differs from its independent identity')
    if identity['mode']=='legacy':
        if os.path.lexists(selected):raise RuntimeError('Legacy identity cannot select a configured locator')
        LEASES[owner],TIMERS[owner]=LEGACY_LEASES[owner],LEGACY_TIMERS[owner]
        return
    box=owner=='box'
    roots=({'code','configuration','state','logs','administration_code','administration_state','backup'} if box
           else {'project','configuration','state','gateway','backup','administration_code','administration_state'})
    fields=({'format','paths','service_prefix','accounts','network_namespace','network_group'} if box else
            {'format','paths','services','accounts','ports','authentication','frontend'})
    if (not isinstance(value,dict) or set(value)!=fields
            or value['format']!=('box-installation-v1' if box else 'whatsapp-installation-v1')
            or not isinstance(value['paths'],dict) or set(value['paths'])!=roots):
        raise RuntimeError('Invalid finite installation binding')
    timer=(value['service_prefix']+'-recovery' if box and isinstance(value['service_prefix'],str)
           else value.get('services',{}).get('recovery'))
    if not isinstance(timer,str) or not re.fullmatch('[a-z][a-z0-9-]{0,47}',timer):
        raise RuntimeError('Invalid finite recovery identity')
    paths=list(value['paths'].values())
    for path in paths:
        if (not isinstance(path,str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+',path)
                or any(part in ('','.','..') for part in path[1:].split('/'))
                or path in ('/etc','/srv','/opt','/usr','/usr/local','/usr/local/lib','/var','/var/lib','/var/log','/var/backups','/run','/tmp','/root','/home')):
            raise RuntimeError('Invalid finite installation root')
    if any(left==right or left.startswith(right+'/') or right.startswith(left+'/')
           for index,left in enumerate(paths) for right in paths[index+1:]):
        raise RuntimeError('Overlapping installation roots')
    LEASES[owner]=value['paths']['administration_state']+'/'+owner+'/service-operation.lock'
    TIMERS[owner]=timer+'.timer'



class SupervisionError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise SupervisionError(message)


def command(owner, operation, *, root=Path('/'), authority=0):
    require(owner in TIMERS, 'Unknown service-operation owner')
    _owner_configuration(owner,root=root,authority=authority)
    token = 'wa' if owner == 'whatsapp' else 'box'
    timer = TIMERS[owner]
    commands = {
        'reload-definitions': ['/usr/bin/systemctl', 'daemon-reload'],
        'enable-' + token + '-recovery': ['/usr/bin/systemctl', 'enable', '--', timer],
        'start-' + token + '-recovery': ['/usr/bin/systemctl', '--no-block', 'start', '--', timer],
        'disable-' + token + '-recovery': ['/usr/bin/systemctl', 'disable', '--', timer],
        'stop-' + token + '-recovery': ['/usr/bin/systemctl', '--no-block', 'stop', '--', timer],
    }
    require(operation in commands, 'Service operation is outside the finite owner profile')
    return commands[operation]


def protected(path):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve(strict=True), 'Supervisor needs physical protected paths')
    for item in (path, *path.parents):
        info = item.lstat()
        require((stat.S_ISREG(info.st_mode) if item == path else stat.S_ISDIR(info.st_mode))
                and info.st_uid == 0 and not info.st_mode & 0o022, 'Supervisor source or interpreter is not protected')


def require_lease(owner, descriptor):
    require(type(descriptor) is int and descriptor >= 3, 'Invalid inherited service lease')
    path = Path(LEASES[owner])
    protected(path)
    current, inherited = path.stat(), os.fstat(descriptor)
    require(stat.S_ISREG(inherited.st_mode) and inherited.st_nlink == 1
            and (current.st_dev, current.st_ino, current.st_uid, current.st_mode) ==
                (inherited.st_dev, inherited.st_ino, inherited.st_uid, inherited.st_mode),
            'Inherited service lease differs from its stable path')
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def supervise(argv, lease_fds, *, timeout=10, max_bytes=MAX_OUTPUT):
    """Wait for one own child while retaining leases even if the parent exits.

    This callable permits synthetic argv for isolated tests. The executable CLI
    below accepts only command(owner, operation), never an arbitrary argv.
    The caller must keep these descriptors open through this call. A timeout
    kills/reaps only this client before returning; a stuck kernel wait keeps
    the lease held and must not be bypassed by another controller.
    """
    require(isinstance(argv, list) and argv and all(isinstance(item, str) and '\0' not in item for item in argv),
            'Invalid client argv')
    require(isinstance(lease_fds, tuple) and bool(lease_fds)
            and all(type(fd) is int and fd >= 3 for fd in lease_fds), 'A supervisor lease is required')
    require(type(timeout) in (int, float) and 0 < timeout <= 30
            and type(max_bytes) is int and 0 < max_bytes <= MAX_OUTPUT, 'Invalid supervision bound')
    for descriptor in lease_fds:
        os.fstat(descriptor)
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        close_fds=True, pass_fds=(), env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                                      'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0'})
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    total = 0
    try:
        for stream in (child.stdout, child.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'Service client timed out')
            for selected, _ in selector.select(remaining):
                data = os.read(selected.fd, 8192)
                if not data:
                    selector.unregister(selected.fileobj)
                    continue
                total += len(data)
                require(total <= max_bytes, 'Service client output exceeded its bound')
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Service client timed out')
        child.wait(timeout=remaining)
        require(child.returncode == 0, 'Service client did not complete successfully')
        return child.returncode
    except subprocess.TimeoutExpired:
        raise SupervisionError('Service client timed out') from None
    finally:
        selector.close()
        if child.poll() is None:
            child.kill()  # Own systemctl CLI only; never the managed service.
        child.wait()  # Retain the lease until this process has actually exited.
        child.stdout.close()
        child.stderr.close()


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    require(os.geteuid() == 0 and len(arguments) == 3, 'An explicit privileged service operation is required')
    owner, operation, descriptor = arguments
    argv = command(owner, operation)
    protected(Path(__file__))
    protected(Path(sys.executable).resolve(strict=True))
    require_lease(owner, int(descriptor))
    supervise(argv, (int(descriptor),))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Deliberately exclude argv, child output and service diagnostics.
        raise SystemExit('Scoped service operation incomplete; retain intent and observe before retrying') from None
