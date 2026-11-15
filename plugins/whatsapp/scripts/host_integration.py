"""Finite WhatsApp consumer wiring to independently installed host providers.

An administrator supplies an exact protected plan and digest. Provider source
comes only from the pinned host generation, never a legacy application helper.
DNS/ACME actions are limited to this tenant; Apache writes always use the host
frontend registry, engine and validation. Isolated certificates are issued/renewed by the separately admitted host service.
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
import copy
from contextlib import contextmanager
from contextvars import ContextVar
import fcntl
import fnmatch
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
import types

GENERATION_ROOT = '/usr/local/lib/develative-host-components'
STATE = installation_path('/var/lib/develative-deploy/whatsapp/host-integration')
QOS_POLICY = '/etc/develative-host-qos/policy.json'
REGISTRY = '/etc/develative-host-frontend/registry.json'
PROFILE = '/etc/develative-host-frontend/profile.json'
REQUIRED_SOURCES = {'host/installation.py', 'host/lifecycle/filesystem.py', 'host/frontend/provider.py',
                    'host/frontend/adapter.py', 'host/qos/contract.py', 'host/qos/applicator.py',
                    'host/qos/adoption.py', 'host/qos/processes.py'}
FRONTEND_SOURCES = {name for name in REQUIRED_SOURCES if not name.startswith('host/qos/')}
TOOLS = {'dig': '/usr/bin/dig', 'virtualmin': '/usr/sbin/virtualmin',
         'certbot': '/usr/bin/certbot', 'python': '/usr/bin/python3'}
MAX_BYTES = 16 * 1024 * 1024
BOOTSTRAP = installation_path('/usr/local/lib/develative-deploy/whatsapp-bootstrap')
BOOTSTRAP_METADATA = {'frontend-sources.json', 'qos-sources.json', 'frontend-profile-sources.json'}
OPTIONAL_METADATA = {'frontend-fresh-sources.json', 'certificates-sources.json'}
_LOCK_FDS = ContextVar('whatsapp_runtime_lock_fds', default=())
_EXPECTED_OWNER = ContextVar('whatsapp_expected_administrative_owner', default=None)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def hexid(value, length=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def dns_name(value):
    if not isinstance(value, str) or len(value) > 253 or '.' not in value:
        return False
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
               for label in value.split('.')):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def decode(content):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate host integration field')
            result[key] = value
        return result
    def constant(value):
        raise ValueError('Non-finite host integration JSON')
    return json.loads(content, object_pairs_hook=unique, parse_constant=constant)


def protected_read(root, logical):
    """Read physical protected inputs before executing any host provider source."""
    root, logical = Path(root).absolute(), PurePosixPath(logical)
    require(logical.is_absolute() and '..' not in logical.parts and str(logical) != '/',
            'Host integration input needs an exact absolute path')
    selected = root / str(logical).lstrip('/')
    require(root == root.resolve(strict=True), 'Host root must be physical')
    authority = root.stat().st_uid
    for item in (root, *list(selected.parents)[:len(logical.parts) - 2][::-1], selected):
        info = item.lstat()
        require(info.st_uid == authority and not info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode),
                'Host integration input or ancestor is not protected')
    descriptor = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        initial = os.fstat(stream.fileno())
        require(stat.S_ISREG(initial.st_mode) and initial.st_size <= MAX_BYTES,
                'Host integration input must be a bounded regular file')
        content = stream.read(MAX_BYTES + 1)
        final = os.fstat(stream.fileno())
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    require(len(content) <= MAX_BYTES and identity(initial) == identity(final) == identity(selected.lstat()),
            'Host integration input changed while reading')
    return content


def load(instance, plan_path, expected_sha256, *, root_path='/', runner=None):
    require(plan_path and hexid(expected_sha256),
            'Apply requires --host-plan and --host-plan-sha256 for the installed neutral providers')
    content = protected_read(root_path, str(plan_path))
    require(sha(content) == expected_sha256, 'Host plan differs from its reviewed digest')
    return Integration(instance, decode(content), expected_sha256, root_path=root_path, runner=runner)


def load_administration(*, root_path='/'):
    """Compile only the physical protected stable bootstrap, without bytecode.

    The root_path seam is for isolated filesystem fixtures; no CLI exposes it.
    The installed administrative owner remains the only admission authority.
    """
    content = protected_read(root_path, BOOTSTRAP + '/release_admin.py')
    protected_read(root_path, BOOTSTRAP + '/release_entry.py')
    path = Path(root_path) / (BOOTSTRAP + '/release_admin.py').lstrip('/')
    name = '_whatsapp_runtime_administration_' + sha(str(path).encode())[:16]
    module = types.ModuleType(name)
    module.__file__ = str(path)
    # dataclasses resolves its defining module while compiling the bootstrap.
    sys.modules[name] = module
    try:
        exec(compile(content, str(path), 'exec'), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def require_active():
    administration = load_administration()
    return administration, administration.load_generation(states=('dedicated',))


@contextmanager
def constrained_admission(owner):
    """Narrow admission to an approved owner; never grant extra authority.

    Used by the protected local broker worker. The same constraint is checked
    after publication and tenant leases, not just before launching a helper.
    """
    require(isinstance(owner, dict) and set(owner) == {
        'protocol', 'epoch', 'state', 'generation', 'manifest_sha256'}, 'Exact approved owner required')
    token = _EXPECTED_OWNER.set(dict(owner))
    try:
        yield
    finally:
        _EXPECTED_OWNER.reset(token)


def _check_constrained_owner(administration):
    expected = _EXPECTED_OWNER.get()
    if expected is not None:
        generation = administration.load_generation(states=('dedicated',))
        require({'protocol': 1, 'epoch': generation.epoch, 'state': generation.state,
                 'generation': str(generation.path), 'manifest_sha256': generation.manifest_sha256} == expected,
                'Administrative owner differs from the approved delegation')


@contextmanager
def runtime_admission(project, *, administration=None):
    """Admit under deploy-v1 leases, WA publication, then the tenant lease.

    Neither lock waits. The current generation is re-read under publication;
    inherited tenant descriptors also exclude recovery while a child acts.
    """
    administration = load_administration() if administration is None else administration
    initial = administration.load_generation(states=('dedicated',))
    from admin_deployment import leases
    with leases(installation_profile()) as deployment_fds, administration.publication_lock(expected=initial, states=('dedicated',)):
        parent = administration.trusted_path(Path(project) / 'private', directory=True)
        path = parent / 'tenant-admin.lock'
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and administration._trusted_uid(info.st_uid) and not info.st_mode & 0o077,
                    'Tenant administration lease is not protected')
            try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise RuntimeError('Tenant administration is already in progress') from None
            actual = path.lstat()
            require((info.st_dev, info.st_ino) == (actual.st_dev, actual.st_ino), 'Tenant lease identity changed')
            _check_constrained_owner(administration)
            token = _LOCK_FDS.set((*deployment_fds, descriptor))
            try: yield descriptor
            finally: _LOCK_FDS.reset(token)
        finally:
            os.close(descriptor)


def command_options(options=None):
    options = dict(options or {})
    descriptors = tuple(dict.fromkeys((*options.get('pass_fds', ()), *_LOCK_FDS.get())))
    if descriptors: options['pass_fds'] = descriptors
    return options


def require_runtime_version():
    from sally_whatsapp import __version__
    parsed = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', __version__)
    require(parsed is not None and tuple(map(int, parsed.groups())) >= (0, 5, 0),
            'Runtime administration requires the verified WhatsApp 0.5.0 or later interpreter; '
            'copying scripts does not upgrade the active 0.4.9 virtual environment')


class LockedRunner:
    def __init__(self, runner): self.runner = runner
    def run(self, argv, **kwargs):
        return self.runner.run(argv, **command_options(kwargs))


class Integration:
    def __init__(self, instance, plan, plan_digest, *, root_path='/', runner=None):
        allocation = instance._installation_identity.roster_sha256
        keys = {'format', 'operation_id', 'instance', 'generation', 'qos', 'frontend', 'tools'}
        if allocation is not None:
            keys.add('allocation_sha256')
        require(isinstance(plan, dict) and set(plan) == keys and plan['format'] == 1 and type(plan['format']) is int
                and hexid(plan['operation_id'], 32), 'Invalid exact host integration plan')
        require(plan.get('allocation_sha256') == allocation,
                'Host plan allocation changed; recompile against the current roster')
        if allocation is not None:
            require(installation_profile().selection == instance._installation_identity.selection,
                    'Host plan instance uses a stale allocation')
        expected = {'slug': instance.slug, 'account': instance.service_user, 'hostname': instance.hostname,
                    'bridge_port': instance.bridge_port, 'gateway_port': instance.gateway_port}
        require(plan['instance'] == expected, 'Host plan belongs to another tenant or port')
        require(set(plan['generation']) == {'path', 'sha256'} and hexid(plan['generation']['sha256'])
                and plan['generation']['path'] == GENERATION_ROOT + '/' + plan['generation']['sha256'],
                'Use an immutable independently installed host generation')
        require(plan['qos'] is None or isinstance(plan['qos'], dict)
                and plan['qos'].keys() == {'policy', 'sha256'} and plan['qos']['policy'] == QOS_POLICY
                and hexid(plan['qos']['sha256']), 'QoS must be explicitly null or an exact installed host policy')
        front = plan['frontend']
        front_keys = {'registry', 'profile', 'address', 'zone', 'local_resolver', 'public_resolver',
                      'webroot', 'lineage', 'archive', 'renewal'}
        require(isinstance(front, dict) and front_keys <= set(front) and set(front) <= front_keys | {'dns_mode', 'certificates'},
                'The complete explicit frontend baseline and DNS/TLS identities are required')
        certificates = front.get('certificates', 'shared')
        require(certificates in ('shared', 'isolated'), 'Unknown certificate store')
        certificate_root = '/etc/develative-certificates' if certificates == 'isolated' else '/etc/letsencrypt'
        dns_mode = front.get('dns_mode', 'managed-virtualmin')
        require(dns_mode in ('managed-virtualmin', 'preconfigured'), 'Unknown explicit DNS mode')
        tool_names = set(TOOLS) if dns_mode == 'managed-virtualmin' else set(TOOLS) - {'virtualmin'}
        require(isinstance(plan['tools'], dict) and set(plan['tools']) == tool_names, 'Exact finite tools are required')
        for name, item in plan['tools'].items():
            require(isinstance(item, dict) and set(item) == {'path', 'sha256'}
                    and (item['path'] == TOOLS[name] or name == 'python'
                         and re.fullmatch(r'/usr/bin/python3\.1[0-9]', item['path']))
                    and hexid(item['sha256']), 'Unexpected administrative tool')
        require(str(ipaddress.IPv4Address(front['address'])) == front['address']
                and not ipaddress.ip_address(front['address']).is_multicast,
                'An exact IPv4 DNS target is required')
        for key in ('local_resolver', 'public_resolver'):
            require(str(ipaddress.ip_address(front[key])) == front[key], 'DNS resolver must be an explicit address')
        require(dns_name(front['zone']) and dns_name(instance.hostname)
                and (instance.hostname == front['zone'] or instance.hostname.endswith('.' + front['zone']))
                and front['webroot'] == '/var/www/' + instance.base + '-acme'
                and front['lineage'] == certificate_root + '/live/' + instance.hostname
                and front['archive'] == certificate_root + '/archive/' + instance.hostname
                and front['renewal'] == certificate_root + '/renewal/' + instance.hostname + '.conf',
                'DNS/TLS scope differs from the named tenant')
        self.instance, self.plan, self.plan_digest = instance, copy.deepcopy(plan), plan_digest
        self.root_path = Path(root_path).absolute()
        generation = plan['generation']['path']
        manifest_bytes = protected_read(self.root_path, generation + '/manifest.json')
        require(sha(manifest_bytes) == plan['generation']['sha256'], 'Host generation manifest differs')
        manifest = decode(manifest_bytes)
        required_sources = (FRONTEND_SOURCES | {'frontend-sources.json'} if plan['qos'] is None
                            else REQUIRED_SOURCES | BOOTSTRAP_METADATA)
        require(isinstance(manifest, dict) and set(manifest) == {'format', 'owner', 'files'}
                and manifest['format'] == 1 and manifest['owner'] == 'host'
                and isinstance(manifest['files'], dict) and required_sources <= set(manifest['files']),
                'Host generation has no complete neutral source closure')
        source = {}
        for name, digest in manifest['files'].items():
            require((name.startswith('host/') or name in BOOTSTRAP_METADATA | OPTIONAL_METADATA) and str(PurePosixPath(name)) == name
                    and '..' not in PurePosixPath(name).parts and hexid(digest), 'Invalid host source path')
            source[name] = protected_read(self.root_path, generation + '/' + name)
            require(sha(source[name]) == digest, 'Installed host source differs from its manifest')
        if (not instance._installation_identity.compatibility
                and instance.slug not in instance._installation_identity.as_dict()['accounts']):
            require(source['host/installation.py'] ==
                    Path(__file__).with_name('installation_layout.py').read_bytes(),
                    'A later instance requires an upgraded, pinned host allocation reader')
        modules = {}
        for name, relative in [('provider', 'host/frontend/provider.py'),
                               ('engine', 'host/lifecycle/filesystem.py'),
                               ('frontend', 'host/frontend/adapter.py')]:
            path = self.root_path / (generation + '/' + relative).lstrip('/')
            module = types.ModuleType('whatsapp_installed_host_' + name)
            module.__file__ = str(path)
            if name == 'frontend': module._PINNED_PROVIDER = modules['provider']
            exec(compile(source[relative], str(path), 'exec'), module.__dict__)
            modules[name] = module
        self.engine, self.frontend = modules['engine'], modules['frontend']
        self.provider = self.frontend.provider
        self.root = self.engine.Root(self.root_path)
        self.runner = LockedRunner(self.frontend.Runner() if runner is None else runner)
        self.source_hashes = manifest['files']
        if plan['qos'] is not None:
            qos_sources = decode(source['qos-sources.json'])
            require(isinstance(qos_sources, dict) and set(qos_sources) == {'format', 'sources'}
                    and qos_sources['format'] == 1 and type(qos_sources['format']) is int
                    and qos_sources['sources'] == {name: self.source_hashes[name] for name in
                        ('host/installation.py', 'host/qos/applicator.py', 'host/qos/contract.py', 'host/qos/adoption.py', 'host/qos/processes.py',
                         'host/lifecycle/filesystem.py')},
                    'QoS bootstrap source closure differs')
        self.provider.validate_registry(front['registry'])
        self.frontend.validate_profile(front['profile'], front['registry'])
        self.consumer = 'whatsapp.' + instance.slug
        self.record = STATE + '/' + plan['operation_id'] + '.json'
        self.checked = False

    def close(self):
        self.root.close()

    def _operation(self, stage):
        return sha((self.plan['operation_id'] + ':' + stage).encode())[:32]

    def _tool(self, name):
        item = self.plan['tools'][name]
        require(sha(protected_read(self.root_path, item['path'])) == item['sha256'], 'Administrative tool changed')
        actual = self.root.snapshot(item['path'])
        require(actual['mode'] & 0o100, 'Administrative tool is not executable')
        return str(self.root_path / item['path'].lstrip('/'))

    def _run(self, name, args, *, timeout=30):
        return self.runner.run([self._tool(name), *map(str, args)],
            environment={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}, timeout=timeout)

    def _qos(self, action, *args):
        script = self.root_path / (self.plan['generation']['path'] + '/host/qos/applicator.py').lstrip('/')
        sources = self.root_path / (self.plan['generation']['path'] + '/qos-sources.json').lstrip('/')
        result = self._run('python', ['-I', '-B', script, '--sources-manifest', sources,
            '--expected-sources-sha256', self.source_hashes['qos-sources.json'], action, '--policy', self.plan['qos']['policy'],
            '--expected-sha256', self.plan['qos']['sha256'], *args], timeout=120)
        value = decode(result)
        require(isinstance(value, dict), 'QoS provider did not return a structured receipt')
        return value

    def _read_record(self):
        try: result = decode(self.root.read_bytes(self.record))
        except FileNotFoundError: return None
        metadata = self.root.snapshot(self.record)
        require(metadata is not None and metadata['uid'] == self.root.uid and metadata['mode'] == 0o600,
                'Interrupted host operation record is not protected')
        require(isinstance(result, dict) and set(result) == {'plan_sha256', 'phase'}
                and result.get('plan_sha256') == self.plan_digest and result.get('phase') in
                ('prepared', 'http-ready', 'issuing', 'tls-ready'), 'Interrupted host operation belongs to another plan')
        return result

    def _save(self, phase):
        current = self.root.snapshot(self.record)
        label = self._operation('state-' + phase)
        directories = {}
        before_dirs = {}
        for path in (installation_path('/var/lib/develative-deploy/whatsapp'), STATE):
            actual = self.root.directory(path)
            spec = {'mode': 0o700, 'uid': self.root.uid, 'gid': self.root.gid, 'retention': 'retain'}
            require(actual is None or actual == {key: value for key, value in spec.items() if key != 'retention'},
                    'WhatsApp administrative state protection differs')
            directories[path] = spec
            if actual is not None: before_dirs[path] = spec
        body = encoded({'plan_sha256': self.plan_digest, 'phase': phase})
        before = {'format': 1, 'owner': 'whatsapp', 'files': {} if current is None else
                  {self.record: {**current, 'retention': 'managed'}}, 'directories': before_dirs}
        after = {'format': 1, 'owner': 'whatsapp', 'files': {self.record: {'sha256': sha(body), 'mode': 0o600,
                 'uid': self.root.uid, 'gid': self.root.gid, 'retention': 'managed'}}, 'directories': directories}
        allowed = {self.record, *directories}
        journal = '/var/lib/develative-host-lifecycle/whatsapp/operations/' + label + '/journal.json'
        if self.root.snapshot(journal) is not None:
            operation = self.engine.inspect_operation(self.root, owner='whatsapp', operation_id=label, allowed_paths=allowed)
            require(operation['after'] == self.engine.validate_manifest(after), 'Interrupted consumer checkpoint differs')
            self.engine.resume(self.root, owner='whatsapp', operation_id=label, allowed_paths=allowed)
        else:
            self.engine.reconcile(self.root, operation_id=label, before=before, after=after, payloads={self.record: body},
                allowed_paths=allowed, inline_payloads={self.record})

    def preflight(self):
        """No managed write; reject missing provider facts before account/IdP effects."""
        for name in self.plan['tools']: self._tool(name)
        front = self.plan['frontend']
        if self._read_record() is None:
            require(decode(self.root.read_bytes(REGISTRY)) == front['registry']
                    and decode(self.root.read_bytes(PROFILE)) == front['profile'],
                    'Frontend baseline differs; prepare a current host plan')
        current = front['registry']['consumers'].get(self.consumer)
        require(current is None or current['owner'] == 'whatsapp' and current['domains'] == [self.instance.hostname]
                and current['status'] == 'active', 'Existing frontend consumer is not an active matching tenant')
        if current is not None and self.plan['qos'] is None:
            for name in current['vhosts']:
                if name in front['registry']['artifacts']:
                    require(not re.search(rb'^[ \t]*BoxPriorityDSCP\b', self.root.read_bytes(name), re.M | re.I),
                            'An existing QoS vhost needs explicit retirement; null is not a migration')
        webroot = self.root.directory(front['webroot'])
        parent = self.root.directory(str(PurePosixPath(front['webroot']).parent))
        require(parent is not None and parent['uid'] == self.root.uid and not parent['mode'] & 0o022
                and (webroot is None or webroot['uid'] == self.root.uid and not webroot['mode'] & 0o022),
                'The named host ACME webroot and parent must be administratively protected')
        if front.get('dns_mode', 'managed-virtualmin') == 'preconfigured':
            self._preconfigured_dns()
        if self.plan['qos'] is not None:
            qos = self._qos('check')
            require(qos.get('provider') == 'develative-host-qos' and qos.get('status') == 'complete',
                    'Installed neutral QoS provider is not ready')
        self.checked = True
        return self

    def _preconfigured_dns(self):
        front = self.plan['frontend']
        for resolver in ('local_resolver', 'public_resolver'):
            actual = self._run('dig', ['@' + front[resolver], self.instance.hostname, 'A', '+short']).decode().split()
            require(actual == [front['address']], 'Preconfigured DNS must resolve exactly to the named target')

    def enroll_runtime(self, account):
        require(self.checked, 'Run the host preflight before provisioning')
        require(account.pw_name == self.instance.service_user and account.pw_dir == str(self.instance.gateway_home)
                and account.pw_shell == '/usr/sbin/nologin' and type(account.pw_uid) is int and account.pw_uid > 0,
                'Service account differs from the host plan')
        if self.plan['qos'] is None:
            return {'status': 'not-configured', 'consumer_id': self.consumer,
                    'account': self.instance.service_user, 'uid': account.pw_uid,
                    'unit': self.instance.base + '.service'}
        result = self._qos('register-consumer', '--operation-id', self._operation('qos'),
            '--consumer-id', self.consumer, '--account', self.instance.service_user,
            '--unit', self.instance.base + '.service')
        require(result.get('status') == 'complete' and result.get('consumer_id') == self.consumer
                and result.get('account') == self.instance.service_user and result.get('uid') == account.pw_uid
                and result.get('unit') == self.instance.base + '.service', 'QoS enrollment was not verified for this runtime')
        return result

    def begin_runtime(self):
        require(self.checked, 'Run the host preflight before runtime changes')
        if self._read_record() is None:
            self._save('prepared')
        name = self.plan['frontend']['webroot']
        operation = self._operation('acme-webroot')
        journal = '/var/lib/develative-host-lifecycle/whatsapp/operations/' + operation + '/journal.json'
        after = {'format': 1, 'owner': 'whatsapp', 'files': {}, 'directories': {
            name: {'mode': 0o755, 'uid': self.root.uid, 'gid': self.root.gid, 'retention': 'retain'}}}
        if self.root.snapshot(journal) is not None:
            prior = self.engine.inspect_operation(self.root,owner='whatsapp',operation_id=operation,allowed_paths={name})
            require(prior['after'] == self.engine.validate_manifest(after), 'Interrupted ACME directory intent differs')
            self.engine.resume(self.root,owner='whatsapp',operation_id=operation,allowed_paths={name})
        elif self.root.directory(name) is None:
            self.engine.reconcile(self.root,operation_id=operation,
                before={'format':1,'owner':'whatsapp','files':{},'directories':{}},
                after=after,payloads={},allowed_paths={name})
        current = self.root.directory(name)
        require(current is not None and current['uid'] == self.root.uid and not current['mode'] & 0o022,
                'ACME directory changed after preflight')

    def resumes_runtime(self):
        return self.checked and self._read_record() is not None

    def _http(self):
        host, webroot = self.instance.hostname, self.plan['frontend']['webroot']
        return (f'<VirtualHost *:80>\n    ServerName {host}\n    DocumentRoot {webroot}\n'
            f'    <Directory {webroot}>\n        Options -Indexes\n        Require all granted\n    </Directory>\n'
            '    RewriteEngine On\n    RewriteCond %{REQUEST_URI} !^/\\.well-known/acme-challenge/\n'
            f'    RewriteRule ^ https://{host}%{{REQUEST_URI}} [R=301,L]\n</VirtualHost>\n').encode()

    def _candidate(self, apache, *, tls):
        front = self.plan['frontend']
        registry, profile = copy.deepcopy(front['registry']), copy.deepcopy(front['profile'])
        old = registry['consumers'].get(self.consumer)
        require(old is None or old['lineages'] == [front['lineage']],
                'Existing tenant lineage differs; do not replace or reissue it')
        http = '/etc/apache2/sites-available/' + self.instance.base + '-http.conf'
        https = '/etc/apache2/sites-available/' + self.instance.base + '-https.conf'
        named = {http, https, http.replace('sites-available', 'sites-enabled'), https.replace('sites-available', 'sites-enabled')}
        require(old is None or set(old['vhosts']) <= named, 'Tenant has additional vhosts needing explicit review')
        generated = {http: self._http()}
        if old is not None and http in registry['artifacts']:
            generated[http] = self.root.read_bytes(http)
            require(sha(generated[http]) == registry['artifacts'][http]['sha256'], 'Existing HTTP route changed')
        if tls:
            body = apache.encode() if isinstance(apache, str) else apache
            if front.get('certificates') == 'isolated':
                body = body.replace(('/etc/letsencrypt/live/' + self.instance.hostname + '/').encode(),
                                    (front['lineage'] + '/').encode())
            if self.plan['qos'] is None:
                if old is not None and https in registry['artifacts']:
                    require(not re.search(rb'^[ \t]*BoxPriorityDSCP\b', self.root.read_bytes(https), re.M | re.I),
                            'An existing QoS vhost needs explicit retirement; null is not a migration')
                directives = [line for line in body.splitlines(keepends=True)
                              if re.match(rb'^[ \t]*BoxPriorityDSCP\b', line, re.I)]
                require(not directives or directives == [b'    BoxPriorityDSCP 34\n'],
                        'Unexpected QoS directive in standalone frontend')
                body = body.replace(b'    BoxPriorityDSCP 34\n', b'')
            else:
                # A portable template has no dependency on the optional host
                # priority module. Only this explicitly pinned QoS plan may
                # request its reviewed AF41 directive.
                directives = [line for line in body.splitlines(keepends=True)
                              if re.match(rb'^[ \t]*BoxPriorityDSCP\b', line, re.I)]
                require(not directives or directives == [b'    BoxPriorityDSCP 34\n'],
                        'Unexpected QoS directive in opted-in frontend')
                if not directives:
                    body, openings = re.subn(rb'(?m)^(<VirtualHost \*:443>)(\r?\n)',
                                             rb'\1\2    BoxPriorityDSCP 34\n', body)
                    require(openings == 1, 'QoS frontend requires one explicit HTTPS vhost')
            generated[https] = body
        selected = []
        for name, body in generated.items():
            registry['artifacts'][name] = {'sha256': sha(body), 'uid': self.root.uid, 'gid': self.root.gid,
                                           'mode': 0o644, 'retention': 'managed'}
            link = name.replace('sites-available', 'sites-enabled')
            existing_link = registry['links'].get(link)
            require(existing_link is None or self.provider.link_target(link, existing_link) == name,
                    'Existing enabled vhost points to another target')
            if existing_link is None:
                registry['links'][link] = {'target': name, 'uid': self.root.uid, 'gid': self.root.gid, 'retention': 'managed'}
            selected.extend((name, link))
            if name not in profile['config_files']: profile['config_files'].append(name)
            matched = 0
            for item in profile['includes']:
                argument = shlex.split(item['text'], comments=True)[1]
                for key, value in profile['environment'].items(): argument = argument.replace('${' + key + '}', value)
                if not argument.startswith('/'): argument = profile['apache']['server_root'] + '/' + argument
                if fnmatch.fnmatchcase(link, argument):
                    item['targets'] = sorted(set(item['targets']) | {link}); matched += 1
            require(matched == 1, 'Tenant vhost needs exactly one attested Include route')
            profile['tls'] = [entry for entry in profile['tls'] if entry['file'] != name]
            for index, line in enumerate(body.decode().splitlines(), 1):
                if re.match(r'^\s*SSLCertificate(?:Key)?File\s+', line, re.I):
                    profile['tls'].append({'file': name, 'line': index, 'text': line, 'path': shlex.split(line)[1]})
        registry['consumers'][self.consumer] = {'owner': 'whatsapp', 'status': 'active' if tls else 'pending_tls',
            'domains': [self.instance.hostname], 'vhosts': selected, 'lineages': [front['lineage']] if tls else []}
        if tls and front['lineage'] not in registry['lineages']:
            source = {'certificate': front['lineage'] + '/fullchain.pem', 'key': front['lineage'] + '/privkey.pem'}
            registry['lineages'][front['lineage']] = {'domains': [self.instance.hostname], 'consumers': [self.consumer],
                'source': source, 'destinations': [{'consumer': self.consumer, 'mode': 'direct', **source,
                    'uid': self.root.uid, 'gid': self.root.gid, 'certificate_mode': 0o644, 'key_mode': 0o600}]}
            renewal = self.root.snapshot(front['renewal'])
            require(renewal is not None and renewal['uid'] == self.root.uid and not renewal['mode'] & 0o022,
                    'Issued certificate has no protected exact renewal configuration')
            profile['lineages'][front['lineage']] = {'archive_directory': front['archive'],
                'renewal': {'path': front['renewal'], 'sha256': renewal['sha256']}}
        raw = {}
        for name, spec in self.provider.managed_manifest(registry)['files'].items():
            if name == REGISTRY: continue
            raw[name] = generated.get(name) if name in generated else self.root.read_bytes(name)
            require(sha(raw[name]) == spec['sha256'], 'Unrelated registered frontend artifact changed')
        self.provider.validate_registry(registry)
        self.frontend.validate_profile(profile, registry)
        return registry, profile, raw

    def _publish(self, apache, *, tls):
        registry, profile, raw = self._candidate(apache, tls=tls)
        adapter = self.frontend.HostAdapter(self.root, self.engine, registry, profile, runner=self.runner)
        operation = self._operation('frontend-tls' if tls else 'frontend-http')
        with adapter.lease():
            previous = self.provider._load_receipt(self.root, operation)
            current = self.frontend.load_protected_json(self.root, REGISTRY)
            current_profile = self.frontend.load_protected_json(self.root, PROFILE)
            allowed = [(self.plan['frontend']['registry'], self.plan['frontend']['profile']), (registry, profile)]
            if tls and self.consumer not in self.plan['frontend']['registry']['consumers']:
                pending_registry, pending_profile, _ = self._candidate(apache, tls=False)
                allowed.append((pending_registry, pending_profile))
            require((current, current_profile) in allowed or previous is not None
                    and current in [item[0] for item in allowed] and current_profile in [item[1] for item in allowed],
                    'Frontend changed outside this exact tenant operation; preserve the other consumers')
            if previous is not None:
                before = previous['before']
            else:
                before = self.provider.managed_manifest(current)
                before['files'][REGISTRY].update(uid=self.root.uid, gid=self.root.gid)
                before['files'][PROFILE] = {**self.root.snapshot(PROFILE), 'retention': 'managed'}
            if tls:
                lineage = self.plan['frontend']['lineage']
                adapter.validate_lineage(lineage, registry['lineages'][lineage]['source'], [self.instance.hostname])
            return self.frontend.apply_configuration(adapter, operation_id=operation, before=before, pinned_artifacts=raw)

    def ensure_https(self, apache):
        require(self.checked, 'Run the host preflight before frontend changes')
        state = self._read_record()
        if state is None:
            self.begin_runtime(); state = self._read_record()
        front = self.plan['frontend']
        existing = self.consumer in front['registry']['consumers']
        if not existing and state['phase'] == 'prepared':
            self._publish(apache, tls=False)
            self._save('http-ready'); state = self._read_record()
        if not existing and state['phase'] in ('http-ready', 'issuing'):
            if front.get('dns_mode', 'managed-virtualmin') == 'preconfigured':
                self._preconfigured_dns()
            else:
                target = front['address']
                local = self._run('dig', ['@' + front['local_resolver'], self.instance.hostname, 'A', '+short']).decode().split()
                require(not local or local == [target], 'Assigned hostname has a different DNS target')
                if not local:
                    self._run('virtualmin', ['modify-dns', '--domain', front['zone'], '--add-record',
                        self.instance.hostname + '. A ' + target], timeout=60)
                public = self._run('dig', ['@' + front['public_resolver'], self.instance.hostname, 'A', '+short']).decode().split()
                require(public == [target], 'Public DNS is not ready; repeat the same operation after propagation')
            certificate = self.root.link(front['lineage'] + '/fullchain.pem')
            if certificate is None:
                require(front.get('certificates') != 'isolated',
                        'Issue this exact lineage with the isolated host certificate service, then resume; no shared Certbot fallback')
                require(state['phase'] != 'issuing',
                        'Certificate issuance was interrupted without a lineage; inspect the exact operation before retry')
                self._save('issuing')
                self._run('certbot', ['certonly', '--non-interactive', '--webroot', '-w', front['webroot'],
                    '--cert-name', self.instance.hostname, '-d', self.instance.hostname], timeout=180)
        frontend = self._publish(apache, tls=True)
        operation = self._operation('frontend-tls')
        require(frontend.get('operation_id') == operation and frontend.get('phase') == 'complete',
                'Frontend configuration publication is incomplete')
        receipt_path = self.provider.STATE + '/operations/' + operation + '.json'
        receipt = protected_read(self.root_path, receipt_path)
        require(decode(receipt) == frontend, 'Published frontend receipt changed before QoS registration')
        if self.plan['qos'] is not None:
            binding = self._qos('register-frontend', '--operation-id', self._operation('qos-frontend'),
                '--consumer-id', self.consumer, '--frontend-operation-id', operation,
                '--frontend-receipt-sha256', sha(receipt))
            require(binding.get('status') == 'configuration-bound' and binding.get('consumer_id') == self.consumer
                    and binding.get('frontend_operation_id') == operation and binding.get('runtime_verified') is False
                    and binding.get('policy_sha256') == self.plan['qos']['sha256']
                    and binding.get('receipt_sha256') == sha(receipt),
                    'QoS frontend configuration binding was not verified for this consumer')
        self._save('tls-ready')
        return {'phase': 'https_ready', 'hostname': self.instance.hostname, 'provider': self.provider.PROVIDER,
                'qos_frontend': 'not-configured' if self.plan['qos'] is None else 'configuration-bound',
                'frontend_traffic_verified': False}
