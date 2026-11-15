"""Prepare a finite Debian Apache2 frontend in a new environment; never apply it.

Only named public package files are inspected. No certificate, private key,
account, DNS record or service is read or changed by this compiler.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import types

SOURCES = ('host/installation.py', 'host/frontend/fresh_profile.py', 'host/frontend/provider.py',
           'host/frontend/adapter.py', 'host/lifecycle/filesystem.py')
MAIN = '/etc/apache2/apache2.conf'
LOCK_SOURCE = '/usr/lib/python3/dist-packages/certbot/_internal/lock.py'
MODULES = ('mpm_event', 'authz_core', 'authz_host', 'alias', 'headers', 'mime',
           'proxy', 'proxy_http', 'rewrite', 'setenvif', 'ssl', 'socache_shmcb')
MODULE_PATHS = {'/usr/lib/apache2/modules/mod_' + name + '.so': name + '_module' for name in MODULES}
TOOLS = {'apache': '/usr/sbin/apache2', 'systemctl': '/usr/bin/systemctl', 'openssl': '/usr/bin/openssl'}
INTEGRATION_TOOLS = {'dig': '/usr/bin/dig', 'certbot': '/usr/bin/certbot'}
HOOK_ROOT = '/usr/local/lib/develative-host-frontend'
HOOK_LINKS = {'deploy': '/etc/letsencrypt/renewal-hooks/deploy/50-develative-services',
              'post': '/etc/letsencrypt/renewal-hooks/post/90-develative-services'}
DIRECTORIES = ('/etc/apache2', '/etc/apache2/sites-available', '/etc/apache2/sites-enabled',
    '/etc/develative-host-frontend', HOOK_ROOT, '/etc/letsencrypt/renewal-hooks',
    '/etc/letsencrypt/renewal-hooks/deploy', '/etc/letsencrypt/renewal-hooks/post')
PREREQUISITES = ('/etc', '/usr/local/lib', '/var/lib', '/var/www', '/var/log/apache2',
                 '/run/apache2', '/etc/letsencrypt')


def require(value, message):
    if not value: raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(content):
    return hashlib.sha256(content).hexdigest()


def decode(content):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate compiler input field')
            result[key] = value
        return result
    def constant(value): raise ValueError('Non-finite compiler input')
    return json.loads(content, object_pairs_hook=unique, parse_constant=constant)


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names), 'Incomplete or unknown fresh input fields')


def dns(value):
    require(isinstance(value, str) and len(value) <= 253 and '.' in value
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                    for part in value.split('.')), 'A lowercase ASCII DNS name is required')
    try: ipaddress.ip_address(value)
    except ValueError: return value
    raise ValueError('A hostname cannot be an IP address')


def metadata(value, uid):
    fields(value, ('sha256', 'mode', 'uid', 'gid'))
    require(isinstance(value['sha256'], str) and re.fullmatch('[a-f0-9]{64}', value['sha256'])
            and all(type(value[k]) is int and value[k] >= 0 for k in ('mode', 'uid', 'gid'))
            and value['uid'] == uid and 0 <= value['mode'] <= 0o777
            and not value['mode'] & 0o022, 'Protected public package metadata is required')


def empty_directory(root, selected):
    """Names only; never collect contents from an existing route or hook."""
    if root.directory(selected) is None: return
    with root._parent(selected) as (parent, leaf):
        descriptor = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            require(info.st_uid == root.uid and not info.st_mode & 0o022,
                    'Fresh route/hook directory is not protected')
            require(not os.listdir(descriptor), 'Fresh route/hook directory must be empty: ' + selected)
        finally: os.close(descriptor)


def build(root, config, *, provider, adapter, engine, generation, installation=None):
    """Return baseline and complete WA host plan, with no managed writes.

    The Root UID is the administrative identity: root in deployment, fixture
    owner in tests. A package-main preimage is the sole permitted replacement.
    """
    if installation is None:
        # Library callers select their reviewed module normally. The installed
        # CLI passes the module compiled from bootstrap's captured bytes.
        from host import installation
    installation_profile = installation.active
    require(installation_profile().compatibility or installation_profile().as_dict()['frontend']=='new',
            'This installation selected an existing frontend; use its complete explicit inventory')
    fields(config, ('format', 'operation_id', 'apache', 'package_main', 'dependencies',
                    'instance', 'dns', 'integration_tools'))
    require(type(config['format']) is int and config['format'] == 1
            and isinstance(config['operation_id'], str) and re.fullmatch('[0-9a-f]{32}', config['operation_id']),
            'Invalid fresh compiler format or operation identity')
    fields(config['apache'], ('user', 'group'))
    require(all(isinstance(x, str) and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', x)
                for x in config['apache'].values()), 'Explicit Apache package user/group required')
    fields(config['instance'], ('slug', 'account', 'hostname', 'bridge_port', 'gateway_port'))
    instance = config['instance']
    require(isinstance(instance['slug'], str) and re.fullmatch('[a-z][a-z0-9-]{1,19}', instance['slug'])
            and '--' not in instance['slug']
            and instance['account'] == installation_profile().account(instance['slug']),
            'Instance account and slug differ')
    dns(instance['hostname'])
    require(all(type(instance[k]) is int for k in ('bridge_port', 'gateway_port'))
            and (8820 <= instance['bridge_port'] <= 8998 and instance['bridge_port'] % 2 == 0
                 and instance['gateway_port'] == instance['bridge_port'] + 1
                 and (instance['slug'] == 'personal') == (instance['bridge_port'] == 8820)
                 if installation_profile().compatibility else
                 {'bridge':instance['bridge_port'],'gateway':instance['gateway_port']}==installation_profile().instance_ports(instance['slug'])),
            'Instance ports differ from the standalone tenant contract')
    fields(config['dns'], ('address', 'zone', 'local_resolver', 'public_resolver'))
    network = config['dns']; dns(network['zone'])
    require(instance['hostname'] == network['zone'] or instance['hostname'].endswith('.' + network['zone']),
            'Hostname lies outside the explicitly configured DNS zone')
    require(isinstance(network['address'], str), 'An explicit IPv4 string is required')
    require(str(ipaddress.IPv4Address(network['address'])) == network['address']
            and not ipaddress.ip_address(network['address']).is_multicast, 'An exact IPv4 target is required')
    for key in ('local_resolver', 'public_resolver'):
        require(isinstance(network[key], str), 'Explicit DNS resolver string required')
        require(str(ipaddress.ip_address(network[key])) == network[key], 'Explicit DNS resolver address required')
    dependencies = config['dependencies']
    require(isinstance(dependencies, dict) and set(dependencies) ==
            set(MODULE_PATHS) | set(TOOLS.values()) | {LOCK_SOURCE, '/etc/mime.types'},
            'The exact finite Apache/Certbot package dependency closure is required')
    fields(config['integration_tools'], ('dig', 'certbot', 'python'))
    integration_tools = {}
    for name, item in config['integration_tools'].items():
        fields(item, ('path', 'metadata'))
        require(item['path'] == INTEGRATION_TOOLS.get(name) if name != 'python' else
                isinstance(item['path'], str) and re.fullmatch('/usr/bin/python3(?:\\.1[0-9])?', item['path']),
                'Unexpected standalone integration tool')
        metadata(item['metadata'], root.uid)
        require(item['metadata']['mode'] & 0o100 and root.snapshot(item['path']) == item['metadata'],
                'Integration tool differs from its supplied public package identity')
        integration_tools[name] = {'path': item['path'], 'sha256': item['metadata']['sha256']}
    for name, item in dependencies.items():
        metadata(item, root.uid)
        require(root.snapshot(name) == item, 'Public package dependency changed: ' + name)
        if name in TOOLS.values(): require(item['mode'] & 0o100, 'Tool is not executable')
    for name in PREREQUISITES:
        actual = root.directory(name)
        require(actual is not None and actual['uid'] == root.uid and not actual['mode'] & 0o022,
                'Protected package/runtime prerequisite is absent: ' + name)
    for name in ('/etc/apache2/sites-enabled', '/etc/letsencrypt/renewal-hooks/deploy',
                 '/etc/letsencrypt/renewal-hooks/post'):
        empty_directory(root, name)
    # A source-generation hash is distinct from any application release.
    fields(generation, ('path', 'sha256'))
    require(isinstance(generation['sha256'], str) and re.fullmatch('[a-f0-9]{64}', generation['sha256'])
            and generation['path'] == '/usr/local/lib/develative-host-components/' + generation['sha256'],
            'An immutable installed neutral source generation is required')
    manifest_bytes = root.read_bytes(generation['path'] + '/manifest.json')
    require(sha(manifest_bytes) == generation['sha256'], 'Source generation manifest changed')
    manifest = decode(manifest_bytes)
    fields(manifest, ('format', 'owner', 'files'))
    require(manifest['format'] == 1 and manifest['owner'] == 'host' and isinstance(manifest['files'], dict),
            'Invalid host source manifest')
    runtime_sources = ('host/frontend/adapter.py', 'host/frontend/provider.py', 'host/lifecycle/filesystem.py')
    for name in (*runtime_sources, 'frontend-sources.json'):
        body = root.read_bytes(generation['path'] + '/' + name)
        require(manifest['files'].get(name) == sha(body), 'Installed runtime source differs')
    source_bytes = root.read_bytes(generation['path'] + '/frontend-sources.json')
    require(decode(source_bytes) == {'format': 1, 'sources': {name: manifest['files'][name] for name in runtime_sources}},
            'Frontend runtime bootstrap closure differs')
    runtime_sha = sha(source_bytes)
    lines = ['# Fresh standalone Apache2 baseline; no application routes yet.',
        'ServerRoot /etc/apache2', 'ServerName ' + instance['hostname'],
        'DefaultRuntimeDir /run/apache2', 'PidFile /run/apache2/apache2.pid',
        'Listen 80', 'Listen 443']
    modules = []
    for name, identifier in MODULE_PATHS.items():
        text = 'LoadModule ' + identifier + ' ' + name
        lines.append(text); modules.append({'file': MAIN, 'line': len(lines), 'text': text,
                                           'path': name, 'identifier': identifier})
    lines += ['User ' + config['apache']['user'], 'Group ' + config['apache']['group'],
        'TypesConfig /etc/mime.types', 'ErrorLog /var/log/apache2/error.log', 'LogLevel warn',
        'LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\"" combined',
        '<Directory />', '    AllowOverride None', '    Require all denied', '</Directory>',
        'IncludeOptional /etc/apache2/sites-enabled/*.conf']
    raw = {MAIN: ('\n'.join(lines) + '\n').encode()}
    artifacts, links, legacy = {}, {}, {}
    for event in ('deploy', 'post'):
        old = HOOK_ROOT + '/legacy-' + event
        raw[old] = b'#!/bin/sh\n# Fresh installation: no prior host hook exists.\nexit 0\n'
        legacy[event] = {'path': old, 'sha256': sha(raw[old])}
        wrapper = HOOK_ROOT + '/' + event + '-hook'
        raw[wrapper] = ('#!/bin/sh\n# Fresh host-owned Certbot event.\nexec ' + integration_tools['python']['path']
            + ' -I -B ' + generation['path'] + '/host/frontend/adapter.py ' + event + '-hook'
            + ' --source-manifest ' + generation['path'] + '/frontend-sources.json --source-sha256 '
            + runtime_sha + '\n').encode()
        links[HOOK_LINKS[event]] = {'target': wrapper, 'uid': root.uid, 'gid': root.gid, 'retention': 'managed'}
    before = {'format': 1, 'owner': 'host', 'files': {}, 'directories': {}, 'links': {}}
    current = root.snapshot(MAIN)
    if config['package_main'] is not None: metadata(config['package_main'], root.uid)
    require(current == config['package_main'], 'Named Apache package-main preimage differs')
    if current is not None: before['files'][MAIN] = {**current, 'retention': 'managed'}
    for name, body in raw.items():
        if name != MAIN: require(root.snapshot(name) is None, 'Fresh hook collision: ' + name)
        artifacts[name] = {'sha256': sha(body), 'mode': 0o644 if name == MAIN else 0o700,
                           'uid': root.uid, 'gid': root.gid, 'retention': 'managed'}
    for name in (provider.REGISTRY, adapter.PROFILE):
        require(root.snapshot(name) is None, 'Fresh frontend already has administrative state')
    directories = {}
    for name in DIRECTORIES:
        existing = root.directory(name)
        require(existing is None or existing['uid'] == root.uid and not existing['mode'] & 0o022,
                'Existing directory needs explicit repair, not fresh adoption')
        item = {**(existing or {'mode': 0o755, 'uid': root.uid, 'gid': root.gid}), 'retention': 'retain'}
        directories[name] = item
        if existing is not None: before['directories'][name] = item
    registry = {'format': 1, 'provider': provider.PROVIDER, 'version': provider.VERSION, 'owner': 'host',
        'apache': {'unit': 'apache2.service', 'config_path': MAIN},
        'scheduler': {'owner': 'host', 'unit': 'certbot.timer'}, 'artifacts': artifacts, 'directories': directories,
        'links': links, 'host_files': sorted(set(artifacts) | set(links)),
        'consumers': {}, 'lineages': {}, 'legacy_hooks': legacy}
    profile = {'format': 1, 'apache': {**registry['apache'], 'server_root': '/etc/apache2'},
        'tools': {name: {'path': selected, 'sha256': dependencies[selected]['sha256']} for name, selected in TOOLS.items()},
        'environment': {'APACHE_LOG_DIR': '/var/log/apache2'}, 'config_files': [MAIN],
        'includes': [{'file': MAIN, 'line': len(lines), 'text': lines[-1], 'targets': []}],
        'modules': modules, 'tls': [], 'dependencies': dependencies, 'lineages': {},
        'certbot_lock': {'directory': '/etc/letsencrypt', 'protocol': 'posix-lockf-unlink-before-close-v1',
                        'source': {'path': LOCK_SOURCE, 'sha256': dependencies[LOCK_SOURCE]['sha256']}}}
    provider.validate_registry(registry); adapter.validate_profile(profile, registry)
    rendered = provider.render(registry, raw); engine.validate_manifest(rendered['manifest']); engine.validate_manifest(before)
    frontend = {**network, 'dns_mode': 'preconfigured', 'registry': registry, 'profile': profile,
        'webroot': '/var/www/' + installation_profile().service(instance['slug']) + '-acme', 'lineage': '/etc/letsencrypt/live/' + instance['hostname'],
        'archive': '/etc/letsencrypt/archive/' + instance['hostname'],
        'renewal': '/etc/letsencrypt/renewal/' + instance['hostname'] + '.conf'}
    plan = {'format': 1, 'operation_id': config['operation_id'], 'instance': instance,
            'generation': generation, 'qos': None, 'frontend': frontend, 'tools': integration_tools}
    if installation_profile().roster_sha256 is not None:
        plan['allocation_sha256'] = installation_profile().roster_sha256
    return {'registry': registry, 'profile': profile, 'before': before, 'pinned_artifacts': raw,
            'host_plan': plan, 'frontend_operation_id': sha(encoded({'kind': 'fresh-frontend', 'plan': plan}))[:32]}


def protected_bytes(selected):
    selected = Path(selected).absolute()
    require(selected == selected.resolve(strict=True), 'Compiler source must be physical')
    for item in (selected, *selected.parents):
        info = item.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022, 'Compiler source must be root-protected')
    descriptor = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        initial = os.fstat(stream.fileno())
        require(stat.S_ISREG(initial.st_mode) and initial.st_size <= 16 * 1024 * 1024, 'Unbounded compiler source')
        body = stream.read(16 * 1024 * 1024 + 1); final = os.fstat(stream.fileno())
    identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    require(identity(initial) == identity(final) == identity(selected.lstat()), 'Compiler source changed')
    return body


def bootstrap(manifest_path, expected_sha256):
    raw = protected_bytes(manifest_path)
    require(sha(raw) == expected_sha256, 'Fresh compiler manifest digest differs')
    manifest = decode(raw); fields(manifest, ('format', 'sources'))
    require(type(manifest['format']) is int and manifest['format'] == 1
            and isinstance(manifest['sources'], dict) and set(manifest['sources']) == set(SOURCES),
            'Exact fresh compiler source closure required')
    base = Path(__file__).absolute().parents[2]
    source = {name: protected_bytes(base / name) for name in SOURCES}
    require(all(sha(body) == manifest['sources'][name] for name, body in source.items()), 'Fresh compiler source drift')
    modules = {}
    for label, relative in (('installation', 'host/installation.py'),
            ('provider', 'host/frontend/provider.py'), ('engine', 'host/lifecycle/filesystem.py'),
            ('adapter', 'host/frontend/adapter.py')):
        module = types.ModuleType('fresh_frontend_' + label)
        module.__file__ = str(base / relative)
        if label == 'adapter': module._PINNED_PROVIDER = modules['provider']
        # dataclasses resolves a captured module by name; no import from a
        # sibling file or ambient host package is needed.
        previous = sys.modules.get(module.__name__)
        sys.modules[module.__name__] = module
        try:
            exec(compile(source[relative], module.__file__, 'exec'), module.__dict__)
        finally:
            if previous is None: sys.modules.pop(module.__name__, None)
            else: sys.modules[module.__name__] = previous
        modules[label] = module
    content = protected_bytes(base / 'manifest.json')
    return modules, {'path': str(base), 'sha256': sha(content)}


def write_package(root, output, built):
    require(isinstance(output, str) and re.fullmatch('/[A-Za-z0-9_./-]+', output)
            and str(PurePosixPath(output)) == output and '..' not in PurePosixPath(output).parts,
            'New package path must be canonical')
    # Anchored exclusive directory creation prevents overwriting an earlier package.
    with root._parent(output) as (parent, leaf): os.mkdir(leaf, 0o700, dir_fd=parent)
    base = root.base / output.lstrip('/')
    payloads = {name + '.json': encoded(built[name]) for name in ('registry', 'profile', 'before', 'host_plan')}
    payloads.update({'artifacts' + name: body for name, body in built['pinned_artifacts'].items()})
    for name, body in payloads.items():
        selected = base / name; selected.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with selected.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600); stream.write(body); stream.flush(); os.fsync(stream.fileno())
    receipt = {'format': 1, 'activated': False, 'private_material_read': False,
        'frontend_operation_id': built['frontend_operation_id'],
        'host_plan_sha256': sha(payloads['host_plan.json']),
        'files': {name: sha(body) for name, body in sorted(payloads.items())}}
    with (base / 'package.json').open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(encoded(receipt)); stream.flush(); os.fsync(stream.fileno())
    for selected in [*(item for item in base.rglob('*') if item.is_dir()), base]:
        descriptor = os.open(selected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    with root._parent(output) as (parent, _): os.fsync(parent)
    return receipt


def input_template():
    """Incomplete input skeleton, never an operational plan or guessed pin."""
    empty_metadata = lambda: {'sha256': None, 'mode': None, 'uid': None, 'gid': None}
    return {'format': 1, 'operation_id': None, 'apache': {'user': None, 'group': None},
        'package_main': None,
        'dependencies': {name: empty_metadata() for name in sorted(
            set(MODULE_PATHS) | set(TOOLS.values()) | {LOCK_SOURCE, '/etc/mime.types'})},
        'instance': {'slug': None, 'account': None, 'hostname': None, 'bridge_port': None, 'gateway_port': None},
        'dns': {'address': None, 'zone': None, 'local_resolver': None, 'public_resolver': None},
        'integration_tools': {name: {'path': path, 'metadata': empty_metadata()} for name, path in
                              {**INTEGRATION_TOOLS, 'python': '/usr/bin/python3.13'}.items()}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-template', action='store_true', help='Print incomplete JSON inputs; no reads or activation')
    parser.add_argument('--source-manifest')
    parser.add_argument('--source-sha256')
    parser.add_argument('--config')
    parser.add_argument('--output')
    args = parser.parse_args(argv)
    if args.input_template:
        require(not any((args.source_manifest, args.source_sha256, args.config, args.output)),
                'Input template cannot be combined with preparation')
        print(json.dumps(input_template(), indent=2, sort_keys=True)); return
    require(all((args.source_manifest, args.source_sha256, args.config, args.output)),
            'Preparation requires config, output and the reviewed compiler source manifest/digest')
    require(os.geteuid() == 0, 'Protected preparation requires the existing administrative context')
    modules, generation = bootstrap(args.source_manifest, args.source_sha256)
    with modules['engine'].Root('/') as root:
        config = modules['adapter'].load_protected_json(root, args.config)
        built = build(root, config, generation=generation, **modules)
        receipt = write_package(root, args.output, built)
    print(json.dumps({'output': args.output, 'activated': False,
                      'host_plan_sha256': receipt['host_plan_sha256']}, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError) as error: raise SystemExit('Fresh frontend preparation stopped: ' + str(error)) from None
