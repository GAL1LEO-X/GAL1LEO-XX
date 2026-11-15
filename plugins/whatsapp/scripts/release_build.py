"""Build release dependencies as an unprivileged, resource-limited systemd job."""
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
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import uuid

from github_release_common import ReleaseError, STATE, require, run, save, sha

BUILD_USER = installation_path('develative-release-build')
RELEASES = Path(installation_path('/opt/develative-releases'))


def sandbox(directory, command, *, network=False, timeout=240):
    """No application accounts, host /etc, /var, /run, home, or production network."""
    directory = Path(directory).resolve()
    require(directory.is_relative_to(RELEASES/'whatsapp') and directory != RELEASES/'whatsapp',
            'Build directory is outside WhatsApp release storage')
    properties = {
        'User': BUILD_USER, 'Group': BUILD_USER, 'WorkingDirectory': str(directory),
        'NoNewPrivileges': 'yes', 'PrivateTmp': 'yes', 'PrivateDevices': 'yes',
        'ProtectSystem': 'strict', 'ProtectHome': 'yes', 'ProtectKernelTunables': 'yes',
        'ProtectKernelModules': 'yes', 'ProtectControlGroups': 'yes', 'RestrictSUIDSGID': 'yes',
        'ProtectProc': 'invisible',
        'CapabilityBoundingSet': '', 'UMask': '0077', 'MemoryMax': '2G',
        'CPUQuota': '150%', 'TasksMax': '512', 'Nice': '10', 'IOWeight': '50',
        'RuntimeMaxSec': str(timeout), 'TimeoutStopSec': '10', 'KillMode': 'control-group',
        'TemporaryFileSystem': '/etc:ro /var:ro /run:ro /srv:ro /opt:ro',
        'BindReadOnlyPaths': '/etc/resolv.conf /etc/hosts /etc/nsswitch.conf /etc/passwd /etc/group /etc/ssl/certs /etc/alternatives /etc/ld.so.cache',
        'BindPaths': str(directory),
        'Environment': 'HOME='+str(directory)+' TMPDIR=/tmp PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1',
    }
    if network:
        properties['IPAddressDeny'] = '127.0.0.0/8 ::1/128 169.254.0.0/16 fe80::/10 224.0.0.0/4 ff00::/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7'
    else:
        properties['PrivateNetwork'] = 'yes'
    name='develative-whatsapp-build-'+uuid.uuid4().hex[:12]
    args = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit='+name]
    for key, value in properties.items():
        args.extend(['--property', key+'='+value])
    # systemd service has its own clean environment, not the receiver's token.
    try:
        process=subprocess.run([str(x) for x in [*args,*command]],capture_output=True,text=True,timeout=timeout+30)
        save(STATE/'whatsapp/build-logs'/(name+'.json'),{'exitCode':process.returncode,
             'stdout':process.stdout[-1000000:],'stderr':process.stderr[-1000000:]})
        require(process.returncode==0,'Isolated build/probe failed; inspect private log '+name)
        return process.stdout.strip()
    except BaseException:
        subprocess.run(['systemctl','stop',name],capture_output=True,timeout=20)
        raise


def tree_hashes(directory):
    root = Path(directory)
    result = {}
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = path.resolve()
            require(target.is_relative_to(root.resolve()) or
                    (relative.startswith('.venv/bin/python') and str(target).startswith('/usr/bin/python3')),
                    'A build created an external symlink')
            result[relative] = 'symlink:'+os.readlink(path)
        elif path.is_file():
            require(path.stat().st_nlink == 1, 'A build created an unexpected hard link')
            result[relative] = sha(path)
        elif not path.is_dir():
            require(False, 'A build created an unexpected file type')
    return result


def create_build(project, source, names):
    require(project == 'whatsapp', 'This builder accepts only WhatsApp')
    import pwd
    import release_admin as administration
    # This parent and the build identity belong to the host. An application
    # update may consume them but cannot repair, replace or retire them.
    administration.trusted_path(RELEASES, directory=True)
    require(stat.S_IMODE(RELEASES.stat().st_mode) == 0o755,
            'Host release storage permissions require administrative inspection')
    account = pwd.getpwnam(BUILD_USER)
    # Each unfinished build and its files remain private to the build account.
    parent = RELEASES/project
    parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    parent.chmod(0o755)
    directory = parent/uuid.uuid4().hex
    directory.mkdir(mode=0o700)
    for name in names:
        path = Path(source)/name
        if path.is_dir():
            shutil.copytree(path, directory/name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        else:
            shutil.copyfile(path, directory/name)
    for path in [directory, *directory.rglob('*')]:
        require(not path.is_symlink(), 'Build sources must not contain symlinks')
        os.chown(path, account.pw_uid, account.pw_gid)
        path.chmod(0o700 if path.is_dir() else 0o600)
    return directory


def seal(directory):
    """Called only after the sandbox exits and systemd kills its entire cgroup."""
    result = tree_hashes(directory)
    for path in [*Path(directory).rglob('*'), Path(directory)]:
        os.chown(path, 0, 0, follow_symlinks=False)
        if not path.is_symlink():
            executable = path.is_file() and bool(path.stat().st_mode & stat.S_IXUSR)
            path.chmod(0o755 if path.is_dir() or executable else 0o644)
    return result
