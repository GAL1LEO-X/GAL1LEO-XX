"""Supervised, explicit 0.4.9 identity enrollment using dedicated WA recovery.

No backup is produced, no schema migration is performed and recovery only
restores prior service activity. A partial identity requires inspection, never
automatic enrollment retry. Execute only under the coordinated host mandate.

The dedicated owner and immutable helper generation must be attested before
any operation. Installing and handing over that external administration stack
requires the separately coordinated host mandate.
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
from installation_layout import active as installation_profile, mapped as installation_path, gateway_port
import argparse
from contextlib import closing
from dataclasses import replace
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import tomllib

KEY = 'private:technical_state_identity:v1'
BOOTSTRAP = Path(installation_path('/usr/local/lib/develative-deploy/whatsapp-bootstrap'))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def identity(value, tenant):
    import re
    require(isinstance(value, dict) and set(value) == {'protocol', 'id', 'tenant'}
            and type(value['protocol']) is int and value['protocol'] == 1
            and isinstance(value['id'], str) and re.fullmatch('[0-9a-f]{32}', value['id'])
            and value['tenant'] == tenant, 'Invalid or unrelated technical identity')
    return value


def private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 1024, 'Invalid identity file')
        content = stream.read(1025)
        require(len(content) <= 1024, 'Identity file grew while being read')
        return json.loads(content), info


def administrative(path):
    """Check both the lexical chain and resolved target; allow trusted venv links."""
    path = Path(path).absolute()
    for item in (path, *path.parents, path.resolve(), *path.resolve().parents):
        info = item.stat()
        require(info.st_uid == 0 and not info.st_mode & 0o022,
                'Administrative path is not root-owned and protected')


def trusted_directory(directory):
    directory = Path(directory).absolute()
    administrative(__file__)
    administrative(directory)
    # A protected directory does not make a pre-existing writable module safe.
    # Validate the import closure before Python executes any helper top level.
    for path in directory.rglob('*'):
        administrative(path)
    return directory


def load_administration():
    # Admission code lives in the stable WA bootstrap, not a generation or a
    # caller-selected directory. Compile its trusted source without bytecode.
    path = BOOTSTRAP / 'release_admin.py'
    administrative(__file__)
    administrative(path)
    require(path == path.resolve(), 'WhatsApp bootstrap must be a physical path')
    loaded = sys.modules.get('release_admin')
    if loaded is not None:
        require(Path(loaded.__file__).absolute() == path,
                'Administration module does not belong to the stable WhatsApp bootstrap')
        return loaded
    spec = importlib.util.spec_from_file_location('release_admin', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules['release_admin'] = module
    try:
        exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    except BaseException:
        sys.modules.pop('release_admin', None)
        raise
    return module


def selected_helpers(generation, supplied=None):
    directory = Path(generation.path)
    require(directory.is_absolute() and not directory.is_symlink(),
            'Attested helper generation must be a physical directory')
    if supplied is not None:
        require(Path(supplied).absolute() == directory and not Path(supplied).is_symlink(),
                'Explicit helpers must match the attested physical WhatsApp generation')
    return directory


def load_helpers(directory):
    directory = trusted_directory(directory)
    sys.path.insert(0, str(directory))
    import github_release as release
    import release_backup as recovery
    for module in (release, recovery):
        require(Path(module.__file__).absolute() == directory / Path(module.__file__).name,
                'Helper import does not belong to the attested physical generation')
    return recovery, release


def command(args, lock_fd, *, input=None, timeout=60):
    result = subprocess.run(list(map(str, args)), input=input, text=True, capture_output=True,
                            timeout=timeout, pass_fds=(lock_fd,))
    require(result.returncode == 0, 'Enrollment command failed; inspect the private operation')
    return result.stdout.strip()


def validate_candidate(candidate, manifest):
    from release_build import tree_hashes
    candidate = Path(candidate).absolute()
    administrative(candidate)
    administrative(manifest)
    administrative(__file__)
    for path in candidate.rglob('*'):
        administrative(path)
    expected = json.loads(Path(manifest).read_text())
    require(isinstance(expected, dict) and expected == tree_hashes(candidate),
            'Candidate stage differs from its verified immutable manifest')
    python = candidate / '.venv/bin/python'
    administrative(python)
    require(python.is_file(), 'Candidate interpreter is missing')
    return python


def tenant_info(row, candidate, lock_fd):
    config_path = Path(row['config'])
    administrative(config_path)
    config = tomllib.loads(config_path.read_text())['bridge']
    require('state_identity_file' not in config,
            'Keep the legacy 0.4.9 TOML unchanged; use the conventional marker path')
    database = Path(config['database'])
    marker = Path(config.get('state_identity_file') or config_path.parent / 'technical-state.json')
    require(database.is_absolute() and database.is_file()
            and not any(path.is_symlink() for path in (database, *database.parents)),
            'An existing regular database is required')
    require(marker.is_absolute() and not marker.is_symlink() and marker.parent.is_dir()
            and not marker.resolve().is_relative_to(database.parent.resolve())
            and not Path(candidate).resolve().is_relative_to(database.parent.resolve()),
            'Candidate and administrative marker must be outside the data directory')
    administrative(marker.parent)
    account_name = command(['systemctl', 'show', row['unit'], '--property=User', '--value'], lock_fd, timeout=15)
    require(account_name and account_name not in ('root', '0'), 'An unprivileged bridge user is required')
    account = pwd.getpwnam(account_name)
    require(account.pw_uid != 0, 'The bridge cannot use root')
    group_name = command(['systemctl', 'show', row['unit'], '--property=Group', '--value'], lock_fd, timeout=15)
    group_id = (int(group_name) if group_name.isdigit() else grp.getgrnam(group_name).gr_gid) if group_name else account.pw_gid
    require(group_id == account.pw_gid, 'Bridge group differs from runuser identity; inspect without changing groups')
    info = database.stat()
    require(info.st_uid == account.pw_uid, 'Database must already belong to the bridge')
    for suffix in ('-wal', '-shm', '-journal'):
        sidecar = database.with_name(database.name + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            require(not sidecar.is_symlink() and sidecar.is_file()
                    and sidecar.stat().st_uid == account.pw_uid, 'Unexpected database sidecar ownership')
    tenant = hashlib.sha256(json.dumps([config['owner_subject'], config['public_url'],
                                      config.get('session', 'default')], separators=(',', ':')).encode()).hexdigest()
    expected = None
    if marker.exists():
        expected, marker_stat = private_json(marker)
        identity(expected, tenant)
        require(marker_stat.st_uid == 0 and marker_stat.st_gid == account.pw_gid
                and stat.S_IMODE(marker_stat.st_mode) == 0o640,
                'Existing marker ownership or permissions require inspection')
    return {'slug': row['slug'], 'config': str(config_path), 'database': str(database),
            'marker': str(marker), 'tenant': tenant, 'expected': expected,
            'uid': account.pw_uid, 'gid': account.pw_gid, 'user': account.pw_name,
            'inode': [info.st_dev, info.st_ino]}


def database_child(request):
    """Only invoked as the existing bridge user; root never opens live SQLite."""
    from sally_whatsapp.config import Settings
    from sally_whatsapp.state_continuity import StateContinuity, register_external_identity
    require(os.geteuid() == request['uid'] and os.geteuid() != 0,
            'Database operation requires the existing bridge user')
    settings = Settings.load(request['config'])
    path = Path(settings.database)
    require(str(path) == request['database'] and str(settings.state_identity_file) == request['marker'],
            'Effective configuration changed')
    tenant = hashlib.sha256(json.dumps([settings.owner_subject, settings.public_url, settings.session],
                                     separators=(',', ':')).encode()).hexdigest()
    require(tenant == request['tenant'], 'Effective tenant changed')
    require(not path.is_symlink() and [path.stat().st_dev, path.stat().st_ino] == request['inode'],
            'Database was replaced during enrollment')
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=rw', uri=True, timeout=5)) as db:
        require(db.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'Database integrity failed')
        schema = db.execute('PRAGMA user_version').fetchone()[0]
        require(schema == 7, 'Enrollment requires the existing 0.4.9 schema without migration')
        stored = db.execute('SELECT value FROM state WHERE key=?', (KEY,)).fetchone()
        stored = identity(json.loads(stored[0]), request['tenant']) if stored else None
        require(stored == request['expected'],
                'Partial or inconsistent identity: preserve it and inspect; no automatic retry')
        for sql, values in [
            ("SELECT COUNT(*) FROM sends WHERE state='sending'", ()),
            ("SELECT COUNT(*) FROM media_jobs WHERE state='downloading'", ()),
            ("SELECT COUNT(*) FROM history_jobs WHERE state='running'", ()),
            ('SELECT COUNT(*) FROM deliveries WHERE lease_until > ?', (time.time(),)),
        ]:
            require(db.execute(sql, values).fetchone()[0] == 0, 'Work is in flight; retry only after it drains')
    if request['action'] == 'enroll':
        register_external_identity(replace(settings, state_identity_file=Path(request['temporary_marker'])))
        value, _ = private_json(request['temporary_marker'])
        identity(value, request['tenant'])
    elif request['action'] == 'verify':
        StateContinuity(settings, allow_bootstrap=False)
        value = stored
    elif request['action'] == 'validate-staged':
        StateContinuity(replace(settings, state_identity_file=Path(request['temporary_marker'])), allow_bootstrap=False)
        value = stored
    else:
        require(request['action'] == 'inspect', 'Invalid database action')
        value = stored
    require(not path.is_symlink() and [path.stat().st_dev, path.stat().st_ino] == request['inode'],
            'Database identity changed during enrollment')
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        require(db.execute('PRAGMA user_version').fetchone()[0] == schema, 'Enrollment changed schema')
    for suffix in ('', '-wal', '-shm', '-journal'):
        item = path.with_name(path.name + suffix)
        if item.exists() or item.is_symlink():
            require(not item.is_symlink() and item.is_file() and item.stat().st_uid == request['uid'],
                    'Unexpected SQLite file ownership')
    return {'identity': value, 'schema': schema, 'inode': request['inode']}


def as_bridge(info, python, lock_fd, action, **extra):
    payload = {**info, 'action': action, **extra}
    output = command(['runuser', '-u', info['user'], '--', python, '-I', '-B',
                      Path(__file__).resolve(), '--database-child'], lock_fd,
                     input=json.dumps(payload), timeout=30)
    result = json.loads(output)
    require(result['schema'] == 7 and result['inode'] == info['inode'], 'Database child identity differs')
    return result


def cgroup_empty(group):
    require(group.startswith('/') and '..' not in Path(group).parts, 'Invalid service cgroup')
    directory = Path('/sys/fs/cgroup') / group.lstrip('/')
    if not directory.exists():
        return True
    events = dict(line.split() for line in (directory / 'cgroup.events').read_text().splitlines())
    return events.get('populated') == '0'


def quiet(component, lock_fd):
    data = command([*component['command'], 'show', component['unit'], '--all',
                    '--property=ActiveState,SubState,MainPID,ControlPID,Job,ControlGroup'], lock_fd, timeout=15)
    values = dict(line.split('=', 1) for line in data.splitlines() if '=' in line)
    require(set(values) == {'ActiveState', 'SubState', 'MainPID', 'ControlPID', 'Job', 'ControlGroup'},
            'Incomplete service stop observation')
    return (values['ActiveState'] in ('inactive', 'failed')
            and values['SubState'] in ('dead', 'failed')
            and values['MainPID'] == values['ControlPID'] == '0'
            and values['Job'] in ('', '0', '0 /')
            and (not values['ControlGroup'] or cgroup_empty(values['ControlGroup'])))


def component_activity(selected, lock_fd):
    components = []
    for row in selected:
        for kind, argv, unit, port in [
            ('gateway', [str(row['wrapper']), 'systemctl', '--user'], 'whatsapp-waha.service', gateway_port(row['slug'],row['port'])),
            ('bridge', ['systemctl'], row['unit'], row['port']),
        ]:
            data = command([*argv, 'show', unit, '--all',
                            '--property=LoadState,ActiveState,SubState,Job'], lock_fd, timeout=15)
            observed = dict(line.split('=', 1) for line in data.splitlines() if '=' in line)
            require(set(observed) == {'LoadState', 'ActiveState', 'SubState', 'Job'}
                    and observed['LoadState'] in ('loaded', 'masked')
                    and observed['Job'] in ('', '0', '0 /')
                    and (observed['ActiveState'], observed['SubState']) in
                    {('active', 'running'), ('active', 'exited'), ('inactive', 'dead'), ('failed', 'failed')},
                    'Service activity is transitional or cannot be established safely')
            components.append({'name': row['slug'] + '.' + kind, 'kind': kind, 'command': argv,
                               'unit': unit, 'port': port, 'config': row['config'],
                               'active': observed['ActiveState'] == 'active'})
    return components


def stop_components(components, lock_fd):
    # Stop ingestion/bridge before gateway; never start an initially inactive one.
    for kind in ('bridge', 'gateway'):
        for item in components:
            if item['kind'] == kind and item['active']:
                command([*item['command'], 'stop', item['unit']], lock_fd, timeout=60)
    for item in components:
        for attempt in range(10):
            if quiet(item, lock_fd):
                break
            require(attempt < 9, 'Service jobs or processes have not drained')
            time.sleep(.2)


def publish_marker(marker, value, uid, gid, validate):
    """Set final protection before no-replace publication; never follow links."""
    marker = Path(marker)
    administrative(marker.parent)
    fd, temporary = tempfile.mkstemp(prefix='.state-enrollment-', dir=marker.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), 0o640)
            os.fsync(stream.fileno())
        validate(Path(temporary))
        try:
            os.link(temporary, marker, follow_symlinks=False)
        except FileExistsError:
            old, info = private_json(marker)
            require(old == value and info.st_uid == uid and info.st_gid == gid
                    and stat.S_IMODE(info.st_mode) == 0o640, 'Existing marker requires inspection')
        directory = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


def enroll_one(info, python, lock_fd):
    if info['expected'] is not None:
        as_bridge(info, python, lock_fd, 'verify')
        return
    # Only this temporary directory is delegated; never grant access to config.
    with tempfile.TemporaryDirectory(prefix='whatsapp-state-enrollment-', dir='/run') as temporary:
        os.chown(temporary, info['uid'], info['gid'])
        os.chmod(temporary, 0o700)
        path = Path(temporary) / 'identity.json'
        result = as_bridge(info, python, lock_fd, 'enroll', temporary_marker=str(path))
        value, metadata = private_json(path)
        identity(value, info['tenant'])
        require(metadata.st_uid == info['uid'] and value == result['identity'], 'Unexpected staged marker')
        current = Path(info['database']).lstat()
        require(stat.S_ISREG(current.st_mode) and [current.st_dev, current.st_ino] == info['inode'],
                'Database changed before marker publication')
        publish_marker(info['marker'], value, 0, info['gid'],
                       lambda staged: as_bridge({**info, 'expected': value}, python, lock_fd,
                                                'validate-staged', temporary_marker=str(staged)))
        as_bridge({**info, 'expected': value}, python, lock_fd, 'verify')


def supervise(root, registered, selected, python, lock_fd, recovery, release):
    require(release.literal(root / 'sally_whatsapp/__init__.py', '__version__') == '0.4.9',
            'Supervised enrollment is only for the pre-upgrade 0.4.9 runtime')
    recovery.verify_prerequisites(root)
    information = [tenant_info(row, Path(python).parent.parent.parent, lock_fd) for row in selected]
    require(len({item['database'] for item in information}) == len(information)
            and len({item['marker'] for item in information}) == len(information)
            and len({tuple(item['inode']) for item in information}) == len(information), 'Tenant paths overlap')
    for info in information:
        as_bridge(info, python, lock_fd, 'inspect')
    components = component_activity(selected, lock_fd)
    plan = recovery.begin(root, selected, components, '0.4.9')
    recovery.attach_worker(plan['id'])
    try:
        stop_components(components, lock_fd)
        recovery.validate_context(recovery.require_id(plan['id']), root, registered)
        for info in information:
            enroll_one(info, python, lock_fd)
    finally:
        # No enrollment replay, DB rollback or fabricated completed copy.
        recovery.recover(root, registered,
                         lambda parts, version: release.restore_backup_components(parts, version, lock_fd=lock_fd))
    return {'operation': plan['id'], 'enrolled': [item['slug'] for item in information],
            'backupProduced': False, 'servicesRestored': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--helpers', type=Path, help='Optional assertion of the attested physical WhatsApp helper generation')
    users = parser.add_mutually_exclusive_group()
    users.add_argument('--user')
    users.add_argument('--all', action='store_true')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--owner-epoch', help=argparse.SUPPRESS)
    parser.add_argument('--helper-generation', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--helper-manifest-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--database-child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.database_child:
        print(json.dumps(database_child(json.loads(sys.stdin.read(16385)))))
        return
    require(os.geteuid() == 0, 'Run only as the authorized administrator')
    require(args.candidate and args.manifest and (args.user or args.all),
            'Select candidate, manifest and tenants')
    supplied_pin = (args.owner_epoch, args.helper_generation, args.helper_manifest_sha256)
    require(all(supplied_pin) if args.worker else not any(supplied_pin),
            'The private worker requires its complete original admission pin')
    administration = load_administration()
    initial = administration.require_current(__file__)
    selected_helpers(initial, args.helpers)
    if args.worker:
        require(supplied_pin == (initial.epoch, initial.path, initial.manifest_sha256),
                'Worker owner epoch or helper generation is no longer current')
    administration.pin_generation(initial)
    os.umask(0o077)
    if not args.worker:
        result = subprocess.run([sys.executable, '-I', '-B', Path(__file__).resolve(),
                                 *sys.argv[1:], '--worker', '--owner-epoch', initial.epoch,
                                 '--helper-generation', str(initial.path),
                                 '--helper-manifest-sha256', initial.manifest_sha256],
                                start_new_session=True, timeout=900)
        raise SystemExit(result.returncode)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(RuntimeError('Enrollment interrupted')))
    with administration.publication_lock(__file__, expected=initial) as generation:
        require(administration.require_current(__file__, expected=generation) == generation,
                'WhatsApp helper generation changed while acquiring administration')
        recovery, release = load_helpers(selected_helpers(generation, args.helpers))
        with (release.ROOT / 'private/tenant-admin.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(administration.require_current(__file__, expected=generation) == generation,
                    'WhatsApp owner or generation changed before enrollment')
            python = validate_candidate(args.candidate, args.manifest)
            registered = release.instances(release.ROOT)
            selected = registered if args.all else [item for item in registered if item['slug'] == args.user]
            require(selected, 'Unknown registered tenant')
            print(json.dumps(supervise(release.ROOT, registered, selected, python, lock.fileno(), recovery, release)))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('State enrollment stopped; inspect the private journal and identity before any retry') from None
