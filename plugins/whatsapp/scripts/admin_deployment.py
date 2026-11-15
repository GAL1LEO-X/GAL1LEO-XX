"""Read-only deploy-v1 identity and existing leases for WhatsApp administration.

No configuration, permission, service, release or database writes. A missing
profile preserves the legacy contract; a present invalid profile fails closed.
The runtime is selected by the installed engine, never by a restore request.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import chain
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ENGINE_CONFIG = Path('/etc/gal1leo-deploy/whatsapp.json')
ENTRYPOINT_SHA256 = '6269f3a607e9950a75ed20860e031275b27628a3ec29bef19626eefe57952bd2'
MAX_JSON = 8 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 200000
MAX_FILES = 20000
MAX_RUNTIME_BYTES = 1024 * 1024 * 1024
_TRUST_ROOT = Path('/')  # Offline fixture seams, never CLI/environment inputs.
_TRUST_UID = 0
START_CONTEXT = ('WorkingDirectory', 'Environment', 'EnvironmentFiles', 'PassEnvironment',
                 'RootDirectory', 'RootImage', 'BindPaths', 'BindReadOnlyPaths', 'TemporaryFileSystem',
                 'User', 'Group', 'DynamicUser', 'SupplementaryGroups', 'NoNewPrivileges')
EMPTY_STRUCTURED = {'EnvironmentFiles': 'a(sb)', 'BindPaths': 'a(ssbt)',
                    'BindReadOnlyPaths': 'a(ssbt)', 'TemporaryFileSystem': 'a(ss)'}
BINDING_KEYS = {'format', 'profile_sha256', 'engine_sha256', 'release_id', 'commit',
                'current_sha256', 'qualification_sha256', 'entrypoint_sha256',
                'release_sha256', 'manifest_sha256', 'application_sha256'}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def decode(raw):
    require(len(raw) <= MAX_JSON, 'Deployment metadata exceeds its bound')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate deployment metadata field')
            value[key] = item
        return value
    try:
        result = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        pending, count = [(result, 0)], 0
        while pending:
            value, depth = pending.pop()
            count += 1
            require(depth <= MAX_JSON_DEPTH and count <= MAX_JSON_NODES,
                    'Deployment metadata structure exceeds its bound')
            children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
            require(count + len(pending) + len(children) <= MAX_JSON_NODES,
                    'Deployment metadata structure exceeds its bound')
            pending.extend((item, depth + 1) for item in children)
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid deployment metadata') from None


def protected(path, *, directory=False):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve(strict=True), 'Physical deployment path required')
    current = _TRUST_ROOT
    for part in ('', *path.relative_to(_TRUST_ROOT).parts):
        if part:
            current /= part
        info = current.lstat()
        kind = stat.S_ISDIR if current != path or directory else stat.S_ISREG
        require(kind(info.st_mode) and info.st_uid == _TRUST_UID and not info.st_mode & 0o022,
                'Deployment authority is not protected')
    return path


def read(path):
    path = protected(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_JSON,
                'Deployment metadata must be a bounded single-link file')
        raw = stream.read(MAX_JSON + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) == identity(path.lstat()) and len(raw) <= MAX_JSON,
            'Deployment metadata changed during observation')
    return raw


def configuration(profile):
    if profile.compatibility:
        return None
    path = Path(profile.path('configuration')) / 'deploy-hooks.json'
    if not os.path.lexists(path):
        return None
    raw, engine_raw = read(path), read(ENGINE_CONFIG)
    config, engine = decode(raw), decode(engine_raw)
    require(isinstance(config, dict) and config.get('format') == 'whatsapp-deploy-profile-v1'
            and config.get('cutover_verified') is True and config.get('app') == 'whatsapp'
            and type(config.get('schema')) is int and config['schema'] == 8,
            'Reviewed WhatsApp deploy-v1 profile required')
    require(isinstance(engine, dict) and engine.get('format') == 'gal1leo-deploy-config-v1'
            and engine.get('app') == 'whatsapp' and engine.get('repository') == 'GAL1LEO-X/GAL1LEO-XX'
            and engine.get('target_id') == config.get('target_id')
            and engine.get('bootstrap') is None and engine.get('root') == config.get('engine_root'),
            'WhatsApp deployment authorities disagree')
    for item in (config.get('engine_root'), config.get('current'), config.get('runtime_entrypoint'),
                 config.get('gate'), engine.get('host_lock')):
        require(isinstance(item, str) and re.fullmatch('/[A-Za-z0-9_./-]+', item)
                and '..' not in Path(item).parts and str(Path(item)) == item,
                'Exact deployment paths required')
    root = protected(config['engine_root'], directory=True)
    require(Path(config['current']) == root / 'current', 'Deployment pointer differs from its root')
    require(config.get('python') == '/usr/bin/python3.13', 'Reviewed deployment interpreter required')
    require(sha(read(config['runtime_entrypoint'])) == ENTRYPOINT_SHA256,
            'Deployment entry point differs from reviewed code')
    instances = config.get('instances')
    require(isinstance(instances, list) and 1 <= len(instances) <= 64
            and all(isinstance(row, dict) for row in instances), 'Bounded deployment instances required')
    require({row.get('slug') for row in instances} == set(profile.accounts())
            and len(instances) == len(profile.accounts()), 'Deployment instance roster differs')
    for row in instances:
        slug = row['slug']
        paths = profile.instance_paths(slug)
        ports = profile.instance_ports(slug)
        require(row.get('user') == profile.account(slug)
                and row.get('unit') == profile.service(slug) + '.service'
                and row.get('config') == paths['configuration'] + '/config.toml'
                and row.get('database') == paths['state'] + '/archive.sqlite'
                and row.get('provider_state') == paths['gateway']
                and row.get('port') == ports['bridge'] and row.get('gateway_port') == ports['gateway']
                and all(type(row.get(key)) is int and row[key] > 0 for key in ('uid', 'gid')),
                'Deployment instance binding differs from installation')
    for key in ('uid', 'gid', 'unit', 'config', 'database', 'provider_state'):
        require(len({row[key] for row in instances}) == len(instances), 'Deployment instances overlap')
    return {'path': path, 'profile': config, 'engine': engine,
            'profile_sha256': sha(raw), 'engine_sha256': sha(engine_raw)}


@contextmanager
def leases(profile):
    """Existing engine order: host shared, WhatsApp exclusive; never create locks."""
    initial = configuration(profile)
    if initial is None:
        yield ()
        return
    descriptors = []
    try:
        for path, shared in ((Path(initial['engine']['host_lock']), True),
                             (Path(initial['engine']['root']) / 'deploy.lock', False)):
            protected(path)
            fd = os.open(path, (os.O_RDONLY if shared else os.O_RDWR) | os.O_NOFOLLOW | os.O_NONBLOCK)
            descriptors.append(fd)
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == _TRUST_UID
                    and not info.st_mode & (0o022 if shared else 0o077), 'Deployment lease is not protected')
            try:
                fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('WhatsApp deployment or host maintenance is in progress') from None
            actual = path.lstat()
            require((info.st_dev, info.st_ino) == (actual.st_dev, actual.st_ino), 'Deployment lease identity changed')
        require(configuration(profile) == initial, 'Deployment authority changed under lease')
        require(not os.path.lexists(Path(initial['engine']['root']) / 'pending.json'),
                'An unfinished deployment requires reconciliation')
        yield tuple(descriptors)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def runtime_inventory(root):
    """Same source-only seal as deploy_hooks; bounded reads, no imports or builds."""
    root = protected(root, directory=True)
    result, total = [], 0
    for path in chain((root,), root.rglob('*')):
        relative = path.relative_to(root).as_posix()
        if relative == 'qualified.json':
            continue
        require(len(result) < MAX_FILES, 'Deployment runtime file bound exceeded')
        info = path.lstat()
        require(info.st_uid == _TRUST_UID and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022),
                'Deployment runtime is not sealed')
        if stat.S_ISLNK(info.st_mode):
            require(relative == 'venv/lib64' and os.readlink(path) == 'lib', 'Unexpected runtime alias')
            result.append({'path': relative, 'link': 'lib'})
        elif stat.S_ISDIR(info.st_mode):
            result.append({'path': relative, 'directory': True, 'mode': stat.S_IMODE(info.st_mode)})
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Unexpected runtime object')
            total += info.st_size
            require(total <= MAX_RUNTIME_BYTES, 'Deployment runtime byte bound exceeded')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                        'Deployment runtime file changed type')
                digest, consumed = hashlib.sha256(), 0
                while chunk := stream.read(min(1024 * 1024, info.st_size - consumed + 1)):
                    consumed += len(chunk)
                    require(consumed <= info.st_size, 'Deployment runtime file grew during observation')
                    digest.update(chunk)
                after = os.fstat(stream.fileno())
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            require(identity(info) == identity(before) == identity(after) == identity(path.lstat()),
                    'Deployment runtime changed during observation')
            result.append({'path': relative, 'size': info.st_size, 'mode': stat.S_IMODE(info.st_mode), 'sha256': digest.hexdigest()})
    # deploy_hooks seals in pathlib component order, not lexical string order:
    # package/child precedes package.py. Preserve that exact existing contract.
    return sorted(result, key=lambda row: Path(row['path']))


@dataclass(frozen=True)
class Runtime:
    authority: dict
    instance: dict
    release: Path
    binding: dict
    version: str

    @property
    def current(self):
        return Path(self.authority['profile']['current'])

    @property
    def venv(self):
        return self.release / 'runtime/venv'

    def command(self):
        p = self.authority['profile']
        return [str(self.current / 'runtime/venv/bin/python'), '-I', '-B', p['runtime_entrypoint'],
                '--config', self.instance['config'], '--gate', p['gate'],
                '--metadata', str(self.current / 'payload/application.json')]

    def check_current(self):
        root = Path(self.authority['engine']['root'])
        require(self.current.is_symlink() and self.current.lstat().st_uid == _TRUST_UID
                and self.current.resolve(strict=True) == self.release
                and not os.path.lexists(root / 'pending.json')
                and sha(read(root / 'current.json')) == self.binding['current_sha256']
                and sha(read(self.authority['path'])) == self.binding['profile_sha256']
                and sha(read(ENGINE_CONFIG)) == self.binding['engine_sha256']
                and sha(read(self.authority['profile']['runtime_entrypoint'])) == self.binding['entrypoint_sha256']
                and sha(read(self.release / 'release.json')) == self.binding['release_sha256']
                and sha(read(self.release / 'manifest.json')) == self.binding['manifest_sha256']
                and sha(read(self.release / 'payload/application.json')) == self.binding['application_sha256']
                and sha(read(self.release / 'runtime/qualified.json')) == self.binding['qualification_sha256'],
                'Pinned deployment changed or has unfinished work')


def validate_binding(value):
    require(isinstance(value, dict) and set(value) == BINDING_KEYS
            and value['format'] == 'whatsapp-admin-deploy-v1'
            and all(isinstance(value[key], str) and re.fullmatch('[a-f0-9]{40}' if key == 'commit' else '[a-f0-9]{64}', value[key])
                    for key in BINDING_KEYS - {'format'}), 'Exact deployment binding required')


def load(profile, slug):
    authority = configuration(profile)
    if authority is None:
        return None
    config, engine = authority['profile'], authority['engine']
    require(slug in profile.accounts(), 'Unknown deployment instance')
    instance = next(row for row in config['instances'] if row['slug'] == slug)
    current, root = Path(config['current']), Path(engine['root'])
    require(current.is_symlink() and current.lstat().st_uid == _TRUST_UID, 'Protected runtime pointer required')
    release = protected(current.resolve(strict=True), directory=True)
    require(release.parent == root / 'releases' and re.fullmatch('[a-f0-9]{64}', release.name),
            'Runtime pointer escaped its immutable release')
    current_raw = read(root / 'current.json')
    release_raw, manifest_raw = read(release / 'release.json'), read(release / 'manifest.json')
    application_raw = read(release / 'payload/application.json')
    current_record, record = decode(current_raw), decode(release_raw)
    manifest, application = decode(manifest_raw), decode(application_raw)
    require(isinstance(current_record, dict) and current_record.get('release_id') == release.name
            and current_record.get('schema') == 8 and isinstance(record, dict)
            and record.get('id') == record.get('package_sha256') == release.name
            and record.get('path') == str(release) and record.get('manifest') == manifest,
            'Deployment release records disagree')
    require(isinstance(manifest, dict) and manifest.get('format') == 'gal1leo-deploy-v1'
            and manifest.get('app') == 'whatsapp' and manifest.get('data') == {'schema': 8, 'readable_schemas': [8]}
            and isinstance(application, dict) and application.get('schema') == 8
            and record.get('commit') == manifest.get('commit') == application.get('commit')
            and isinstance(record.get('commit'), str) and re.fullmatch('[a-f0-9]{40}', record['commit'])
            and manifest.get('version') == application.get('version')
            and isinstance(application.get('version'), str) and re.fullmatch(r'\d+\.\d+\.\d+', application['version']),
            'Deployment application identity differs')
    qualified_raw = read(release / 'runtime/qualified.json')
    qualified = decode(qualified_raw)
    require(isinstance(qualified, dict) and set(qualified) == {'commit', 'package_sha256', 'files'}
            and qualified['commit'] == record['commit'] and qualified['package_sha256'] == release.name
            and qualified['files'] == runtime_inventory(release / 'runtime'), 'Qualified deployment runtime changed')
    binding = {'format': 'whatsapp-admin-deploy-v1', 'profile_sha256': authority['profile_sha256'],
               'engine_sha256': authority['engine_sha256'], 'release_id': release.name, 'commit': record['commit'],
               'current_sha256': sha(current_raw), 'qualification_sha256': sha(qualified_raw),
               'entrypoint_sha256': ENTRYPOINT_SHA256, 'release_sha256': sha(release_raw),
               'manifest_sha256': sha(manifest_raw), 'application_sha256': sha(application_raw)}
    validate_binding(binding)
    runtime = Runtime(authority, instance, release, binding, application['version'])
    runtime.check_current()
    return runtime


def read_start_context(unit, reader):
    """Restore omitted structured empties only after typed D-Bus evidence."""
    require(isinstance(unit, str) and re.fullmatch(r'[a-z][a-z0-9-]{1,63}\.service', unit), 'Literal bridge unit required')
    raw = reader(['/usr/bin/systemctl', 'show', '--all', '--property=' + ','.join(START_CONTEXT), '--', unit])
    require(isinstance(raw, bytes) and len(raw) <= 65536, 'Unbounded maintenance start context')
    pairs = [line.split('=', 1) for line in raw.decode().splitlines()]
    require(all(len(pair) == 2 for pair in pairs) and len({p[0] for p in pairs}) == len(pairs), 'Invalid maintenance start context')
    value = dict(pairs)
    require(set(value) <= set(START_CONTEXT), 'Unexpected maintenance start field')
    for name in set(START_CONTEXT) - set(value):
        require(name in EMPTY_STRUCTURED, 'Incomplete maintenance start context')
        escaped = ''.join(c if c.isascii() and c.isalnum() else '_' + format(ord(c), '02x') for c in unit)
        raw = reader(['/usr/bin/busctl', '--system', '--json=short', 'get-property', 'org.freedesktop.systemd1',
                      '/org/freedesktop/systemd1/unit/' + escaped, 'org.freedesktop.systemd1.Service', name])
        require(decode(raw) == {'type': EMPTY_STRUCTURED[name], 'data': []},
                'Omitted maintenance property is not verified empty')
        value[name] = ''
    return value
