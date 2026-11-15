"""Finite host Apache/Certbot adapter; never issue certificates or start listeners.

The profile is administrative input, pinned alongside the consumer registry.
It enumerates the complete Include graph and exact TLS directive locations.
Only those locations are rewritten in a private configtest staging directory.
"""
from contextlib import contextmanager, ExitStack
import argparse
import copy
import fcntl
import fnmatch
import glob
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import selectors
import shlex
import ssl
import stat
import subprocess
import tempfile
import time


def _sibling(name):
    location = Path(__file__).with_name(name + '.py')
    if __name__ == '__main__':
        for selected in (Path(__file__).absolute(), location.absolute()):
            if selected != selected.resolve(strict=True):
                raise RuntimeError('Neutral source must be physical before import')
            for item in (selected, *selected.parents):
                info = item.lstat()
                if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
                    raise RuntimeError('Neutral source must be protected before import')
    namespace = {'__file__': str(location), '__name__': 'host_frontend_' + name}
    exec(compile(location.read_bytes(), str(location), 'exec'), namespace)
    return type('Module', (), namespace)


# A source-pinned outer loader can inject the provider compiled from the same
# already verified byte snapshot; it must not trigger a second filesystem read.
provider = globals().get('_PINNED_PROVIDER')
if provider is None:
    provider = None if __name__ == '__main__' else _sibling('provider')


def require(value, message):
    if not value:
        raise (ValueError if provider is None else provider.FrontendError)(message)


def fields(value, expected, message):
    return provider.fields(value, expected, message)


def path(value):
    return provider.path(value)


LOCK = '/var/lib/develative-host-frontend/operation.lock'
PROFILE = '/etc/develative-host-frontend/profile.json'
REGISTRY = '/etc/develative-host-frontend/registry.json'
SOURCES = ('host/frontend/adapter.py', 'host/frontend/provider.py', 'host/lifecycle/filesystem.py')
TOOLS = {'apache': {'/usr/sbin/apache2', '/usr/sbin/apache2ctl', '/usr/sbin/httpd'},
         'systemctl': {'/usr/bin/systemctl'}, 'openssl': {'/usr/bin/openssl'}}
APACHE_ENVIRONMENT = {'APACHE_RUN_USER', 'APACHE_RUN_GROUP', 'APACHE_PID_FILE',
                      'APACHE_RUN_DIR', 'APACHE_LOCK_DIR', 'APACHE_LOG_DIR'}
DIRECTIVE = re.compile(r'^\s*(IncludeOptional|Include|SSLCertificateFile|SSLCertificateKeyFile|LoadModule)\s+', re.I)


def validate_profile(value, registry):
    fields(value, {'format', 'apache', 'tools', 'environment', 'config_files', 'includes',
                   'tls', 'dependencies', 'lineages', 'certbot_lock'} | ({'modules'} if 'modules' in value else set()),
           'Invalid finite frontend profile')
    require(value['format'] == 1 and type(value['format']) is int, 'Unsupported frontend profile')
    fields(value['apache'], {'server_root', 'config_path', 'unit'}, 'Invalid Apache profile')
    require(value['apache']['config_path'] == registry['apache']['config_path']
            and value['apache']['unit'] == registry['apache']['unit'], 'Apache profile and registry differ')
    path(value['apache']['server_root'])
    fields(value['tools'], {'apache', 'systemctl', 'openssl'}, 'Finite tool identities are required')
    for name, tool in value['tools'].items():
        fields(tool, {'path', 'sha256'}, 'Invalid tool identity')
        require(tool['path'] in TOOLS[name], 'Tool program identity is outside the source-owned finite allowlist')
        require(provider.hexadecimal(tool['sha256']), 'Tool source hash is required')
    require((value['apache']['unit'], value['tools']['apache']['path']) in
            (('apache2.service', '/usr/sbin/apache2'), ('apache2.service', '/usr/sbin/apache2ctl'),
             ('httpd.service', '/usr/sbin/httpd')),
            'Apache unit and parser executable identities differ')
    require(isinstance(value['environment'], dict) and all(
        key in APACHE_ENVIRONMENT and isinstance(item, str)
        and '\x00' not in item and '\n' not in item and len(item) < 4096
        for key, item in value['environment'].items()), 'Only explicit Apache environment is admitted')
    require(isinstance(value['config_files'], list) and value['config_files']
            and len(set(value['config_files'])) == len(value['config_files'])
            and set(value['config_files']) <= set(registry['artifacts'])
            and value['apache']['config_path'] in value['config_files'], 'Incomplete pinned Apache graph')
    require(isinstance(value['dependencies'], dict) and len(value['dependencies']) <= 1024,
            'Invalid external dependency closure')
    for name, expected in value['dependencies'].items():
        path(name)
        fields(expected, {'sha256', 'mode', 'uid', 'gid'}, 'Invalid dependency evidence')
        require(provider.hexadecimal(expected['sha256']), 'Dependency hash is required')
    locations = set()
    pending_files = {provider.link_target(name, registry['links'][name]) if name in registry['links'] else name
                     for consumer in registry['consumers'].values() if consumer['status'] == 'pending_tls'
                     for name in consumer['vhosts']}
    for kind in ('includes', 'tls', 'modules'):
        require(isinstance(value.get(kind, []), list) and len(value.get(kind, [])) <= 4096, 'Invalid graph locations')
        for entry in value.get(kind, []):
            fields(entry, {'file', 'line', 'text', 'targets' if kind == 'includes' else 'path'}
                   | ({'identifier'} if kind == 'modules' else set()),
                   'Invalid exact directive reference')
            location = (entry['file'], entry['line'])
            require(entry['file'] in value['config_files'] and type(entry['line']) is int
                    and entry['line'] > 0 and location not in locations
                    and isinstance(entry['text'], str) and '\n' not in entry['text']
                    and '\r' not in entry['text'], 'Duplicate or invalid graph source location')
            locations.add(location)
            if kind == 'includes':
                require(isinstance(entry['targets'], list) and len(set(entry['targets'])) == len(entry['targets'])
                        and set(entry['targets']) <= set(registry['artifacts']) | set(registry['links']),
                        'Unpinned Include target')
            elif kind == 'tls':
                require(entry['file'] not in pending_files, 'Pending TLS consumer cannot publish certificate directives')
                path(entry['path'])
                require(entry['file'] in registry['host_files'] or entry['path'] in
                        {target[kind] for lineage in registry['lineages'].values()
                         for target in lineage['destinations'] for kind in ('certificate', 'key')},
                        'TLS directive has no registered material consumer or retained host source')
            else:
                path(entry['path'])
                require(re.fullmatch(r'[a-zA-Z0-9_]+_module', entry['identifier'])
                        and entry['path'] in set(registry['artifacts']) | set(value['dependencies']),
                        'Module directive requires a pinned binary and exact identifier')
    require(isinstance(value['lineages'], dict) and set(value['lineages']) == set(registry['lineages']),
            'Every lineage requires explicit archive and renewal identities')
    for lineage, entry in value['lineages'].items():
        fields(entry, {'archive_directory', 'renewal'}, 'Invalid lineage administration profile')
        path(entry['archive_directory'])
        fields(entry['renewal'], {'path', 'sha256'}, 'An exact renewal file must be nominated')
        path(entry['renewal']['path'])
        renewal = entry['renewal']['path']
        isolated = '/etc/develative-certificates'
        if lineage.startswith(isolated + '/live/'):
            name = lineage[len(isolated + '/live/'):]
            require(provider.domain(name) and '/' not in name
                    and entry['archive_directory'] == isolated + '/archive/' + name
                    and renewal == isolated + '/renewal/' + name + '.conf'
                    and registry['lineages'][lineage]['domains'] == [name]
                    and all(registry['consumers'][consumer]['owner'] in ('host', 'whatsapp')
                            for consumer in registry['lineages'][lineage]['consumers']),
                    'Isolated TLS requires an exact single-domain host/WhatsApp lineage')
        else:
            require(renewal.startswith('/etc/letsencrypt/renewal/') and renewal.endswith('.conf'),
                    'Invalid renewal file identity')
        require(provider.hexadecimal(entry['renewal']['sha256']), 'Invalid renewal file identity')
    require(len({entry['renewal']['path'] for entry in value['lineages'].values()}) == len(value['lineages']),
            'A renewal file cannot belong to unrelated lineages')
    fields(value['certbot_lock'], {'directory', 'protocol', 'source'}, 'Certbot locking evidence is required')
    require(value['certbot_lock']['directory'] == '/etc/letsencrypt'
            and value['certbot_lock']['protocol'] == 'posix-lockf-unlink-before-close-v1',
            'Unsupported Certbot config-dir locking protocol')
    fields(value['certbot_lock']['source'], {'path', 'sha256'}, 'Installed Certbot lock source must be pinned')
    path(value['certbot_lock']['source']['path'])
    require(provider.hexadecimal(value['certbot_lock']['source']['sha256']), 'Missing installed lock source hash')
    return value


class Runner:
    """No shell, fixed bounded operations; command output never includes key bytes."""
    def run(self, argv, *, environment, input_bytes=None, timeout=30, pass_fds=()):
        if pass_fds:
            return self._supervised(argv, environment=environment, input_bytes=input_bytes,
                                    timeout=timeout, pass_fds=pass_fds)
        return self._direct(argv, environment=environment, input_bytes=input_bytes, timeout=timeout)

    def _supervised(self, argv, *, environment, input_bytes, timeout, pass_fds):
        """A Python holder owns the lease until its external client is reaped.

        The external program receives no lease FD and may close arbitrary FDs.
        A killed caller cannot unlock a still-running hook or systemctl client.
        A caller timeout never kills this holder or releases its lease early.
        """
        for descriptor in pass_fds: os.fstat(descriptor)
        reader, writer = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(reader)
            try:
                result = b'1' + self._direct(argv, environment=environment, input_bytes=input_bytes, timeout=timeout)
            except BaseException as error:
                result = b'0' + str(error).encode('utf-8', 'replace')[:4096]
            try:
                remaining = memoryview(result)
                while remaining: remaining = remaining[os.write(writer, remaining):]
            except BrokenPipeError:
                pass
            finally:
                os.close(writer)
                for descriptor in set(pass_fds): os.close(descriptor)
                os._exit(0)
        os.close(writer)
        deadline, result, completed = time.monotonic() + timeout + 5, bytearray(), False
        selector = selectors.DefaultSelector()
        selector.register(reader, selectors.EVENT_READ)
        try:
            while True:
                require(time.monotonic() < deadline,
                        'Administrative supervisor is pending; its lease remains held until client reap')
                if not selector.select(min(0.1, max(0, deadline - time.monotonic()))): continue
                chunk = os.read(reader, 65536)
                if not chunk:
                    completed = True; break
                result.extend(chunk)
                require(len(result) <= 1024 * 1024 + 4097, 'Supervisor response exceeds its bound')
            require(result[:1] == b'1', 'Administrative supervised command failed: ' + bytes(result[1:]).decode('utf-8', 'replace'))
            return bytes(result[1:])
        finally:
            selector.close(); os.close(reader)
            # A pending holder remains alive independently. No SIGKILL or
            # blocking wait here may turn a response timeout into lost fencing.
            if completed: os.waitpid(pid, 0)
            else: os.waitpid(pid, os.WNOHANG)

    def _direct(self, argv, *, environment, input_bytes=None, timeout=30):
        require(input_bytes is None or type(input_bytes) is bytes and len(input_bytes) <= 1024 * 1024,
                'Administrative input exceeds its bound')
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL if input_bytes is None else subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, close_fds=True)
        deadline, output, pending = time.monotonic() + timeout, {'out': bytearray(), 'err': bytearray()}, input_bytes
        selector = selectors.DefaultSelector()
        try:
            for stream, label in ((process.stdout, 'out'), (process.stderr, 'err')):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            if process.stdin is not None:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, 'in')
            while selector.get_map():
                require(time.monotonic() < deadline, 'Administrative command timed out')
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    if key.data == 'in':
                        if pending:
                            written = os.write(key.fd, pending[:65536]); pending = pending[written:]
                        if not pending:
                            selector.unregister(key.fileobj); key.fileobj.close()
                    else:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj); key.fileobj.close(); continue
                        require(len(output[key.data]) + len(chunk) <= 1024 * 1024,
                                'Administrative output exceeds its bound')
                        output[key.data].extend(chunk)
            require(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                    'Administrative command failed; retain the operation receipt')
            return bytes(output['out'])
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
            process.wait()  # The independent holder cannot exit before its client is reaped.
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None: stream.close()


class HostAdapter:
    def __init__(self, root, engine, registry, profile, *, runner=None):
        self.root, self.engine, self.provider = root, engine, provider
        self.registry = copy.deepcopy(provider.validate_registry(registry))
        self.profile = copy.deepcopy(validate_profile(profile, registry))
        self.runner = Runner() if runner is None else runner
        self.environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                            **profile['environment']}
        self.locked, self.material, self.lock_fd = False, None, None

    def physical(self, name):
        return str(self.root.base / path(name).lstrip('/'))

    def _tool(self, name):
        item = self.profile['tools'][name]
        actual = self.root.snapshot(item['path'])
        require(actual is not None and actual['sha256'] == item['sha256']
                and actual['uid'] == self.root.uid and not actual['mode'] & 0o022
                and actual['mode'] & 0o100, 'Tool differs from its protected pinned executable')
        return self.physical(item['path'])

    @contextmanager
    def lease(self, *, create=True):
        """A frontend-only lock, never held across application drain or build."""
        require(not self.locked, 'Nested frontend leases are forbidden')
        require(self.root.directory(provider.STATE) == {'mode': 0o700, 'uid': self.root.uid, 'gid': self.root.gid},
                'Provision the protected host frontend state directory before admission')
        with self.root._parent(LOCK) as (parent, name):
            descriptor = os.open(name, os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT if create else 0), 0o600, dir_fd=parent)
            try:
                info = os.fstat(descriptor)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == self.root.uid
                        and stat.S_IMODE(info.st_mode) == 0o600, 'Frontend lease is not protected')
                try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise provider.FrontendError('Host frontend is busy; retry without waiting under an application lock') from error
                actual = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require((actual.st_dev, actual.st_ino) == (info.st_dev, info.st_ino),
                        'Frontend lease identity changed')
                self.locked = True
                self.lock_fd = descriptor
                yield self
            finally:
                self.locked = False
                self.lock_fd = None
                os.close(descriptor)

    def _admitted(self):
        require(self.locked, 'Hold the frontend lease for the entire operation')
        for name, expected in self.profile['dependencies'].items():
            require(self.root.snapshot(name) == expected, 'External Apache dependency changed')

    @contextmanager
    def certbot_quiescence(self):
        # One lock per store; never substitute a private store for the host lock.
        directories = {self.profile['certbot_lock']['directory']}
        if any(name.startswith('/etc/develative-certificates/live/') for name in self.profile['lineages']):
            directories.add('/etc/develative-certificates')
        with ExitStack() as stack:
            for directory in sorted(directories):
                stack.enter_context(self._certbot_directory(directory))
            yield

    @contextmanager
    def _certbot_directory(self, directory):
        """Nonblocking protocol compatible with the explicitly attested Certbot.

        Never used inside a deploy/post hook, whose Certbot parent owns its lock.
        Busy means STOP/retry, avoiding inversion with a hook awaiting our lease.
        """
        self._admitted()
        source = self.profile['certbot_lock']['source']
        actual = self.root.snapshot(source['path'])
        require(actual is not None and actual['sha256'] == source['sha256']
                and actual['uid'] == self.root.uid and not actual['mode'] & 0o022,
                'Installed Certbot lock protocol differs from its reviewed source')
        selected = directory + '/.certbot.lock'
        with self.root._parent(selected) as (parent, name):
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            acquired = False
            try:
                info = os.fstat(descriptor)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == self.root.uid
                        and stat.S_IMODE(info.st_mode) == 0o600, 'Certbot lock is not protected')
                try: fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise provider.FrontendError('Certbot is busy; retry after its current operation finishes') from error
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino),
                        'Certbot lock changed during admission; retry')
                acquired = True
                yield
            finally:
                try:
                    if acquired:
                        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                        require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino),
                                'Certbot lock identity changed; inspect before retry')
                        os.unlink(name, dir_fd=parent)
                finally:
                    os.close(descriptor)

    def _contents(self, manifest, payloads):
        result = {}
        for name in self.profile['config_files']:
            if name not in manifest['files']: continue
            body = payloads.get(name)
            if body is None: body = self.root.read_bytes(name)
            require(provider.digest(body) == manifest['files'][name]['sha256'], 'Configuration source differs')
            try: result[name] = body.decode('utf-8').splitlines()
            except UnicodeError as error: raise provider.FrontendError('Configuration must be UTF-8') from error
        return result

    def _argument(self, line, directive):
        require(not line.rstrip().endswith('\\'), 'Continued administrative directives require explicit normalization')
        try: tokens = shlex.split(line, comments=True)
        except ValueError as error: raise provider.FrontendError('Invalid Apache directive quoting') from error
        require(len(tokens) == (3 if directive == 'loadmodule' else 2)
                and tokens[0].lower() == directive, 'Ambiguous Apache source directive')
        argument = tokens[-1]
        for key, value in self.environment.items(): argument = argument.replace('${' + key + '}', value)
        require('$' not in argument and '\\' not in argument, 'Unresolved Apache variable or escape')
        if not argument.startswith('/'): argument = self.profile['apache']['server_root'] + '/' + argument
        require('..' not in PurePosixPath(argument).parts and '**' not in argument
                and re.fullmatch(r'/[A-Za-z0-9_.@/*?\[\]-]+', argument), 'Unbounded Apache include/material path')
        return argument

    def _graph(self, manifest, payloads, *, active=False):
        configs = self._contents(manifest, payloads)
        includes = {(entry['file'], entry['line']): entry for entry in self.profile['includes']}
        tls = {(entry['file'], entry['line']): entry for entry in self.profile['tls']}
        modules = {(entry['file'], entry['line']): entry for entry in self.profile.get('modules', [])}
        edges, replacements = {}, {}
        for name, lines in configs.items():
            edges[name] = []
            for index, line in enumerate(lines, 1):
                matched = DIRECTIVE.match(line)
                if not matched: continue
                location, directive = (name, index), matched.group(1).lower()
                entry = (includes if directive.startswith('include') else modules if directive == 'loadmodule' else tls).get(location)
                require(entry is not None and entry['text'] == line, 'Unmodelled or changed Apache directive')
                argument = self._argument(line, directive)
                if directive.startswith('include'):
                    require(entry['targets'] == sorted(entry['targets'])
                            and all(fnmatch.fnmatchcase(target, argument) for target in entry['targets']),
                            'Include targets do not match their exact source pattern and order')
                    selected = [target for target in entry['targets']
                                if target in manifest['files'] or target in manifest.get('links', {})]
                    require(selected or directive == 'includeoptional', 'Required Include has no candidate target')
                    resolved = [provider.link_target(target, manifest['links'][target])
                                if target in manifest.get('links', {}) else target for target in selected]
                    require(all(target in configs for target in resolved), 'Include leaves the pinned configuration closure')
                    observed = sorted('/' + str(Path(item).relative_to(self.root.base))
                                      for item in glob.glob(str(self.root.base / argument.lstrip('/'))))
                    require(set(observed) <= set(entry['targets']),
                            'Uninventoried Include target exists before publication')
                    if active:
                        require(observed == sorted(selected), 'Active Include expansion differs from the pinned graph')
                    edges[name].extend(resolved); replacements[location] = ('include', resolved)
                elif directive == 'loadmodule':
                    require(argument == entry['path'] and shlex.split(line, comments=True)[1] == entry['identifier'],
                            'Module directive differs from its registered identity')
                    replacements[location] = ('module', (entry['identifier'], entry['path']))
                else:
                    require(argument == entry['path'], 'TLS directive path differs from its registered identity')
                    replacements[location] = ('tls', entry['path'])
        for location in set(includes) | set(tls) | set(modules):
            require(location[0] not in configs or location in replacements, 'A pinned directive disappeared')
        visited, visiting = set(), set()
        def visit(name):
            require(name not in visiting, 'Apache Include graph contains a cycle')
            if name in visited: return
            visiting.add(name)
            for child in edges[name]: visit(child)
            visiting.remove(name); visited.add(name)
        main = self.profile['apache']['config_path']
        require(main in configs, 'Apache main configuration is absent')
        visit(main)
        require(visited == set(configs), 'Pinned Apache configuration contains unreachable sources')
        return configs, replacements

    def _full_manifest(self, delta):
        # TLS deltas do not own the Apache configuration itself.
        if self.profile['apache']['config_path'] in delta['files']: return delta
        full = provider.managed_manifest(self.registry)
        full['files'][provider.REGISTRY].update(uid=self.root.uid, gid=self.root.gid)
        for kind in ('files', 'links'):
            full[kind].update(delta.get(kind, {}))
        return full

    def _check(self, configuration):
        self.runner.run([self._tool('apache'), '-t', '-d', self.physical(self.profile['apache']['server_root']),
                         '-f', str(configuration)], environment=self.environment, timeout=30, pass_fds=(self.lock_fd,))

    def validate_staged(self, manifest, payloads):
        self._admitted()
        full = self._full_manifest(manifest)
        configs, replacements = self._graph(full, payloads)
        with tempfile.TemporaryDirectory(prefix='configtest-', dir=self.physical(provider.STATE)) as temporary:
            stage = Path(temporary)
            # No active Include is retained: all edges resolve to physical staged files.
            for name, lines in configs.items():
                rendered = []
                for index, line in enumerate(lines, 1):
                    replacement = replacements.get((name, index))
                    if replacement is None: rendered.append(line); continue
                    kind, targets = replacement
                    if kind == 'include':
                        rendered.extend('Include "' + str(stage / target.lstrip('/')) + '"' for target in targets)
                    elif kind == 'module':
                        identifier, target = targets
                        if target in payloads:
                            require(provider.digest(payloads[target]) == full['files'][target]['sha256'],
                                    'Staged module bytes differ from the candidate')
                            destination = stage / target.lstrip('/')
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            destination.write_bytes(payloads[target]); destination.chmod(0o600)
                            rendered.append('LoadModule ' + identifier + ' "' + str(destination) + '"')
                        else: rendered.append(line)
                    elif targets in payloads:
                        destination = stage / targets.lstrip('/')
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(payloads[targets]); destination.chmod(0o600)
                        rendered.append(line.split()[0] + ' "' + str(destination) + '"')
                    else: rendered.append(line)
                destination = stage / name.lstrip('/')
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text('\n'.join(rendered) + '\n'); destination.chmod(0o600)
            self._check(stage / self.profile['apache']['config_path'].lstrip('/'))
        return {'ok': True, 'configuration_sha256': provider.digest(provider.encoded(manifest))}

    def validate_active(self, manifest):
        self._admitted()
        full = self._full_manifest(manifest)
        for name, expected in full['files'].items():
            require(self.root.snapshot(name) == {key: value for key, value in expected.items() if key != 'retention'},
                    'Active configuration or material metadata differs')
        for name, expected in full.get('links', {}).items():
            require(self.root.link(name) == {key: value for key, value in expected.items() if key != 'retention'},
                    'Active configuration link differs')
        self._graph(full, {}, active=True)
        self._check(self.physical(self.profile['apache']['config_path']))
        return {'ok': True, 'configuration_sha256': provider.digest(provider.encoded(manifest))}

    def reload_apache(self, fingerprint):
        self._admitted(); require(provider.hexadecimal(fingerprint), 'Invalid validated configuration identity')
        if self.material is not None:
            lineage, source, proof = self.material
            try: current = self.validate_lineage(lineage, source, proof['domains'])
            finally: self.material = (lineage, source, proof)
            require(current == proof,
                    'Certificate lineage changed before reload')
        self.runner.run([self._tool('systemctl'), 'reload', self.profile['apache']['unit']],
                        environment=self.environment, timeout=60, pass_fds=(self.lock_fd,))
        return True

    def _source(self, lineage, source):
        require(lineage in self.profile['lineages'] and source == self.registry['lineages'][lineage]['source'],
                'Unregistered TLS source')
        archive = self.profile['lineages'][lineage]['archive_directory']
        result, revisions = {}, []
        for kind in ('certificate', 'key'):
            name = source[kind]
            require(str(PurePosixPath(name).parent) == lineage, 'Material is outside its exact lineage')
            link = self.root.link(name)
            require(link is not None and link['uid'] == self.root.uid, 'Certbot live material must be a protected link')
            target = posixpath.normpath(posixpath.join(lineage, link['target']))
            prefix = 'fullchain' if kind == 'certificate' else 'privkey'
            match = re.fullmatch(re.escape(archive) + '/' + prefix + r'([1-9][0-9]*)\.pem', target)
            require(match is not None, 'Certbot link leaves the exact registered archive')
            metadata = self.root.snapshot(target)
            require(metadata is not None and metadata['uid'] == self.root.uid and not metadata['mode'] & 0o022
                    and (kind != 'key' or metadata['mode'] in (0o600, 0o640)), 'Unsafe lineage material ownership')
            result[kind] = self.root.read_bytes(target, max_bytes=1024 * 1024)
            require(self.root.link(name) == link and self.root.snapshot(target) == metadata,
                    'Lineage changed while reading material')
            revisions.append(match.group(1))
        require(len(set(revisions)) == 1, 'Certificate/key links refer to different Certbot generations')
        return result

    def validate_certificate_pair(self, certificate, key, domains, *, allow_expired=False):
        provider.domains(domains)
        with tempfile.TemporaryDirectory(prefix='tls-check-', dir=self.physical(provider.STATE)) as temporary:
            cert_path, key_path = Path(temporary) / 'certificate.pem', Path(temporary) / 'key.pem'
            for name, body in ((cert_path, certificate), (key_path, key)):
                name.write_bytes(body); name.chmod(0o600)
            binary = self._tool('openssl')
            def run(args, content=None):
                return self.runner.run([binary, *args], environment=self.environment, input_bytes=content, timeout=15,
                                       pass_fds=() if self.lock_fd is None else (self.lock_fd,))
            cert_public = run(['x509', '-in', str(cert_path), '-pubkey', '-noout'])
            cert_der = run(['pkey', '-pubin', '-outform', 'DER'], cert_public)
            key_der = run(['pkey', '-in', str(key_path), '-passin', 'pass:', '-pubout', '-outform', 'DER'])
            require(cert_der and cert_der == key_der, 'Certificate and private key do not match')
            decoded = ssl._ssl._test_decode_cert(str(cert_path))
            names = decoded.get('subjectAltName', ())
            require(names and all(kind == 'DNS' for kind, _ in names)
                    and len(names) == len(set(names)) and {name for _, name in names} == set(domains),
                    'Certificate SAN set differs from the exact consumer registry')
            require(ssl.cert_time_to_seconds(decoded['notBefore']) <= time.time()
                    and (allow_expired or time.time() < ssl.cert_time_to_seconds(decoded['notAfter'])),
                    'Certificate validity interval excludes now')
        return True

    def validate_lineage(self, lineage, source, domains):
        self._admitted()
        material = self._source(lineage, source)
        self.validate_certificate_pair(material['certificate'], material['key'], domains)
        proof = {'domains': domains, 'certificate_sha256': provider.digest(material['certificate']), 'key_matches': True,
                 'source_revision': provider.digest(provider.encoded({
                     'certificate_sha256': provider.digest(material['certificate']),
                     'key_sha256': provider.digest(material['key'])}))}
        self.material = (lineage, source, proof)
        return proof

    def deploy_materials(self, lineage, source, targets, proof, apache):
        self._admitted(); require(apache == self.registry['apache'], 'Unexpected Apache material consumer')
        material = self._source(lineage, source)
        operation = provider.digest(provider.encoded({'lineage': lineage, 'revision': proof['source_revision'],
                                     'targets': targets, 'registry': self.registry}))[:32]
        return provider.deploy_materials(self.root, engine=self.engine, operation_id=operation,
            targets=targets, proof=proof, certificate=material['certificate'], key=material['key'],
            allowed_paths={item[kind] for item in targets for kind in ('certificate', 'key') if item['mode'] == 'copy'},
            adapter=self)

    def execute_legacy(self, selected, environment):
        self._admitted()
        self.runner.run([self.physical(selected)], environment={**self.environment, **environment},
                        timeout=120, pass_fds=(self.lock_fd,))
        return {'status': 'delegated'}

    def legacy_deploy(self, hook, lineage, hosts):
        provider.guard_pending(self.root, engine=self.engine)
        return provider.invoke_pinned_legacy(self.root, hook, event='deploy', lineage=lineage,
                                            renewed_domains=hosts, runner=self)

    def legacy_post(self, hook):
        provider.guard_pending(self.root, engine=self.engine)
        return provider.invoke_pinned_legacy(self.root, hook, event='post', runner=self)

    def assert_registry_current(self):
        """Read under the frontend lease, never reuse a pre-admission inventory."""
        self._admitted()
        require(self.root.read_bytes(provider.REGISTRY) == provider.encoded(self.registry),
                'Consumer registry changed before operation admission')

    def retirement_status(self, owner):
        """Read-only filesystem evidence; a running-service claim needs its receipt."""
        require(owner in ('box', 'whatsapp'), 'Only application consumers may be retired')
        self.assert_registry_current()
        selected = {name: item for name, item in self.registry['consumers'].items() if item['owner'] == owner}
        require(selected and all(item['status'] == 'retired' for item in selected.values()),
                'Application frontend consumers are still active or unregistered')
        after = provider.managed_manifest(self.registry)
        after['files'][provider.REGISTRY].update(uid=self.root.uid, gid=self.root.gid)
        for name in {item for consumer in selected.values() for item in consumer['vhosts']}:
            if name in after['files'] or name in after['links']: continue
            observed = self.root.link(name) if name in self.registry['links'] else self.root.snapshot(name)
            require(observed is None, 'Retired application still has an active frontend reference')
        for name, expected in after['files'].items():
            require(self.root.snapshot(name) == {key: value for key, value in expected.items() if key != 'retention'},
                    'A retained frontend consumer or host resource differs')
        for name, expected in after['links'].items():
            require(self.root.link(name) == {key: value for key, value in expected.items() if key != 'retention'},
                    'A retained frontend link differs')
        self._graph(after, {}, active=True)
        require(self.root.read_bytes(PROFILE) == provider.encoded(self.profile), 'Retained frontend profile differs')
        return {'status': 'retired', 'owner': owner, 'consumers': sorted(selected),
                'registry_sha256': provider.digest(provider.encoded(self.registry)),
                'retained_consumers': sorted(name for name, item in self.registry['consumers'].items()
                                             if item['status'] in ('active', 'pending_tls')),
                'running_service_verified': False}

    def retire_application(self, *, owner, operation_id):
        """Retire only the application's vhosts, with an original durable plan.

        Call after closing and stopping that application. This finite frontend
        transaction never stops application units, removes keys or renews TLS.
        A retry uses the same operation ID and the registry now on disk.
        """
        require(owner in ('box', 'whatsapp') and provider.hexadecimal(operation_id, 32),
                'An exact application owner and operation identity are required')
        provider.guard_pending(self.root, operation_id, engine=self.engine)
        self.assert_registry_current()
        require(any(item['owner'] == owner for item in self.registry['consumers'].values()),
                'Application frontend is not registered')
        require(self.root.read_bytes(PROFILE) == provider.encoded(self.profile), 'Frontend profile changed before retirement')
        with self.certbot_quiescence():
            retired = provider.retire_consumers(self.registry, owner)
            after = provider.managed_manifest(retired)
            after['files'][provider.REGISTRY].update(uid=self.root.uid, gid=self.root.gid)
            profile_metadata = self.root.snapshot(PROFILE)
            require(profile_metadata is not None and profile_metadata['uid'] == self.root.uid
                    and not profile_metadata['mode'] & 0o022, 'Frontend profile protection differs')
            after['files'][PROFILE] = {**profile_metadata, 'retention': 'managed'}
            previous = provider._load_receipt(self.root, operation_id)
            context = {'kind': 'retire-application', 'owner': owner,
                       'retired_owner_sha256': provider.retirement_identity(retired, owner)}
            if previous is not None and previous.get('phase') == 'complete':
                require(previous.get('context') == context, 'Completed retirement belongs to different application records')
                status = self.retirement_status(owner)
                observed = self.validate_active(after)
                require(observed == {'ok': True, 'configuration_sha256': provider.digest(provider.encoded(after))},
                        'Current frontend configuration did not verify')
                return {**previous, 'retirement': status, 'current_configuration_sha256': observed['configuration_sha256']}
            if previous is not None:
                require(previous.get('context') == context and previous.get('after') == after,
                        'Retirement operation is bound to a different application or generation')
                before = previous['before']
            else:
                before = provider.managed_manifest(self.registry)
                before['files'][provider.REGISTRY].update(uid=self.root.uid, gid=self.root.gid)
                before['files'][PROFILE] = {**profile_metadata, 'retention': 'managed'}
            payloads = {name: (provider.encoded(retired) if name == provider.REGISTRY else self.root.read_bytes(name))
                        for name in after['files']}
            allowed = {name for manifest in (before, after) for kind in ('files', 'directories', 'links')
                       for name in manifest.get(kind, {})}
            result = provider.reconcile_edge(self.root, engine=self.engine, operation_id=operation_id,
                before=before, after=after, payloads=payloads, allowed_paths=allowed, adapter=self, context=context)
            self.registry = retired
            return {**result, 'retirement': self.retirement_status(owner),
                    'current_configuration_sha256': provider.digest(provider.encoded(after))}

    def retire_renewals(self, *, operation_id, owner=None):
        """Quarantine only named renewal files with zero active registry consumers.

        Certbot's scheduler, live links, archives and destination keys remain.
        The engine retains the original renewal file in a named quarantine.
        A stale externally modified renewal file requires new administrative
        evidence; no filename is inferred from a hostname or cert display name.
        """
        self._admitted()
        require(provider.hexadecimal(operation_id, 32) and owner in (None, 'box', 'whatsapp'),
                'Invalid renewal retirement identity or owner')
        selected = provider.digest(provider.encoded({'operation': operation_id, 'kind': 'retire-renewals', 'owner': owner}))[:32]
        provider.guard_pending(self.root, selected, engine=self.engine)
        with self.certbot_quiescence():
            return self._retire_renewals(operation_id=operation_id, owner=owner)

    def _retire_renewals(self, *, operation_id, owner=None):
        self.assert_registry_current()
        require(owner is None or owner in ('box', 'whatsapp'), 'Invalid application renewal owner')
        require(provider.hexadecimal(operation_id, 32), 'An exact operation identity is required')
        operation = provider.digest(provider.encoded({'operation': operation_id, 'kind': 'retire-renewals',
                                    'owner': owner}))[:32]
        record = provider._load_receipt(self.root, operation)
        selected = {entry['renewal']['path']: entry['renewal']['sha256']
                    for lineage, entry in self.profile['lineages'].items()
                    if (owner is None or any(self.registry['consumers'][name]['owner'] == owner
                                             for name in self.registry['lineages'][lineage]['consumers']))
                    and not any(self.registry['consumers'][name]['status'] == 'active'
                               for name in self.registry['lineages'][lineage]['consumers'])}
        if record is None:
            before = {'format': 1, 'owner': 'host', 'files': {}, 'directories': {}}
            for name, expected_hash in selected.items():
                actual = self.root.snapshot(name)
                require(actual is not None and actual['sha256'] == expected_hash
                        and actual['uid'] == self.root.uid and not actual['mode'] & 0o022,
                        'Final-consumer renewal source is missing or differs from its attested identity')
                before['files'][name] = {**actual, 'retention': 'managed'}
            record = {'kind': 'retire-renewals', 'operation_id': operation, 'before': before,
                      'after': {'format': 1, 'owner': 'host', 'files': {}, 'directories': {}},
                      'selected': selected, 'owner': owner, 'phase': 'prepared'}
            provider._receipt(self.root, self.engine, operation, record)
        require(record.get('kind') == 'retire-renewals' and record.get('owner') == owner,
                'Renewal retirement receipt belongs to another consumer state')
        # A later unrelated consumer edit cannot change this operation's
        # identity or broaden the original selected renewal set.
        selected = record['selected']
        for name, expected_hash in selected.items():
            identities = [(lineage, entry) for lineage, entry in self.profile['lineages'].items()
                          if entry['renewal']['path'] == name and entry['renewal']['sha256'] == expected_hash]
            require(len(identities) == 1, 'Original renewal source is no longer exactly registered')
            lineage = identities[0][0]
            referenced = self.registry['lineages'][lineage]
            require(not any(self.registry['consumers'][consumer]['status'] in ('active', 'pending_tls')
                            for consumer in referenced['consumers'])
                    and not any(item['status'] == 'pending_tls' and set(item['domains']) & set(referenced['domains'])
                                for item in self.registry['consumers'].values()),
                    'An original renewal has an active or pending TLS consumer again')
        outcome = self.engine.reconcile(self.root, operation_id=provider.digest(('renewal-files:' + operation).encode())[:32],
            before=record['before'], after=record['after'], payloads={}, allowed_paths=set(selected))
        record.update(phase='complete', quarantine=outcome['quarantine'])
        provider._receipt(self.root, self.engine, operation, record)
        return record


def load_protected_json(root, selected):
    actual = root.snapshot(path(selected))
    require(actual is not None and actual['uid'] == root.uid and not actual['mode'] & 0o022,
            'Administrative input is not a protected physical file')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate administrative JSON key')
            result[key] = value
        return result
    def constant(value): raise provider.FrontendError('Non-finite administrative JSON')
    return json.loads(root.read_bytes(selected, max_bytes=16 * 1024 * 1024),
                      object_pairs_hook=unique, parse_constant=constant)


def apply_configuration(adapter, *, operation_id, before, pinned_artifacts):
    """Real finite filesystem/configtest/reload integration, called under lease.

    The source-owned installer supplies the exact previously managed manifest;
    adoption must explicitly inventory it, never treat existing paths as fresh.
    All selected paths are derived from the two closed frontend registries.
    """
    adapter._admitted()
    provider.guard_pending(adapter.root, operation_id, engine=adapter.engine)
    with adapter.certbot_quiescence():
        return _apply_configuration(adapter, operation_id=operation_id, before=before, pinned_artifacts=pinned_artifacts)


def _apply_configuration(adapter, *, operation_id, before, pinned_artifacts):
    adapter._admitted()
    rendered = provider.render(adapter.registry, pinned_artifacts)
    after = rendered['manifest']
    after['files'][provider.REGISTRY].update(uid=adapter.root.uid, gid=adapter.root.gid)
    profile_bytes = provider.encoded(adapter.profile)
    after['files'][PROFILE] = {'sha256': provider.digest(profile_bytes), 'mode': 0o600,
                              'uid': adapter.root.uid, 'gid': adapter.root.gid, 'retention': 'managed'}
    rendered['payloads'][PROFILE] = profile_bytes
    current = adapter.root.snapshot(provider.REGISTRY)
    previous = provider._load_receipt(adapter.root, operation_id)
    if previous is not None:
        # Publication may have stopped between registry and profile. The
        # durable original plan is authoritative even in that partial state.
        require(before == previous.get('before'), 'Retry before manifest differs from its durable plan')
    elif current is not None:
        existing = load_protected_json(adapter.root, provider.REGISTRY)
        expected = provider.managed_manifest(existing)
        expected['files'][provider.REGISTRY].update(uid=adapter.root.uid, gid=adapter.root.gid)
        previous_profile = adapter.root.snapshot(PROFILE)
        require(previous_profile is not None, 'Existing frontend registry lacks its profile; inspect the interrupted adoption')
        expected['files'][PROFILE] = {**previous_profile, 'retention': 'managed'}
        # A retry after publication uses the original durable plan, never an
        # invented fresh before-manifest of the now-published generation.
        require(before == expected,
                'Before manifest differs from the registered host generation')
    else:
        require(all(set(before.get(kind, {})) <= set(after.get(kind, {}))
                    for kind in ('files', 'directories', 'links')), 'Fresh adoption cannot retire unrelated paths')
    allowed = set()
    for manifest in (before, after):
        for kind in ('files', 'directories', 'links'): allowed.update(manifest.get(kind, {}))
    return provider.reconcile_edge(adapter.root, engine=adapter.engine, operation_id=operation_id,
        before=before, after=after, payloads=rendered['payloads'], allowed_paths=allowed, adapter=adapter)


def _protected_bytes(selected):
    """Small stdlib-only trust boundary, before loading any operational source."""
    selected = Path(selected).absolute()
    require(selected == selected.resolve(strict=True), 'Neutral administrative source must be physical')
    for item in (selected, *selected.parents):
        info = item.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode),
                'Execute only the reviewed root-owned neutral source closure')
    descriptor = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        initial = os.fstat(stream.fileno())
        require(stat.S_ISREG(initial.st_mode) and initial.st_size <= 16 * 1024 * 1024,
                'Administrative source must be a bounded regular file')
        content = stream.read(16 * 1024 * 1024 + 1)
        final = os.fstat(stream.fileno())
    actual = selected.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    require(identity(initial) == identity(final) == identity(actual)
            and len(content) <= 16 * 1024 * 1024, 'Administrative source changed while reading')
    return content


def _bootstrap_sources(manifest_path, expected_hash):
    """Hash-pin the fixed neutral closure, ignoring pyc and arbitrary imports."""
    global provider
    content = _protected_bytes(manifest_path)
    require(isinstance(expected_hash, str) and re.fullmatch('[0-9a-f]{64}', expected_hash)
            and hashlib.sha256(content).hexdigest() == expected_hash, 'Source manifest differs from its reviewed digest')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate source manifest field'); result[key] = value
        return result
    value = json.loads(content, object_pairs_hook=unique)
    require(isinstance(value, dict) and set(value) == {'format', 'sources'}
            and type(value['format']) is int and value['format'] == 1
            and isinstance(value['sources'], dict) and set(value['sources']) == set(SOURCES),
            'The complete fixed neutral source manifest is required')
    repository = Path(__file__).absolute().parents[2]
    source_bytes = {}
    for relative in SOURCES:
        body = _protected_bytes(repository / relative)
        require(hashlib.sha256(body).hexdigest() == value['sources'][relative], 'Neutral source differs from reviewed bytes')
        source_bytes[relative] = body
    modules = {}
    for name, relative in (('provider', 'host/frontend/provider.py'), ('lifecycle', 'host/lifecycle/filesystem.py')):
        namespace = {'__file__': str(repository / relative), '__name__': 'host_frontend_' + name}
        exec(compile(source_bytes[relative], str(repository / relative), 'exec'), namespace)
        modules[name] = type('Module', (), namespace)
    provider = modules['provider']
    return modules['lifecycle']


def _prepare_state(root, engine):
    selected = provider.STATE
    current = root.directory(selected)
    desired = {'mode': 0o700, 'uid': root.uid, 'gid': root.gid, 'retention': 'retain'}
    require(current is None or current == {key: value for key, value in desired.items() if key != 'retention'},
            'Frontend state directory protection differs; no ownership repair is automatic')
    before = {'format': 1, 'owner': 'host', 'files': {}, 'directories': {} if current is None else {selected: desired}}
    after = {**before, 'directories': {selected: desired}}
    operation = provider.digest(provider.encoded({'purpose': 'host-frontend-state', 'before': before, 'after': after}))[:32]
    engine.reconcile(root, operation_id=operation, before=before, after=after, payloads={}, allowed_paths={selected})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('inspect', 'apply', 'deploy-hook', 'post-hook', 'retire-renewals',
                                            'retire-application', 'inspect-retirement'))
    parser.add_argument('--profile', default=PROFILE)
    parser.add_argument('--registry', default=REGISTRY)
    parser.add_argument('--operation-id')
    parser.add_argument('--artifacts-directory')
    parser.add_argument('--before-manifest')
    parser.add_argument('--owner', choices=('box', 'whatsapp'))
    parser.add_argument('--source-manifest', required=True)
    parser.add_argument('--source-sha256', required=True)
    arguments = parser.parse_args(argv)
    require(os.geteuid() == 0, 'The neutral frontend adapter requires the existing root administrative context')
    engine = _bootstrap_sources(arguments.source_manifest, arguments.source_sha256)
    with engine.Root('/') as root:
        registry = load_protected_json(root, arguments.registry)
        profile = load_protected_json(root, arguments.profile)
        adapter = HostAdapter(root, engine, registry, profile)
        if arguments.command == 'inspect':
            # No lock creation, service action, config mutation or TLS read.
            result = {'provider': provider.PROVIDER, 'version': provider.VERSION,
                      'registry_sha256': provider.digest(provider.encoded(registry)),
                      'profile_sha256': provider.digest(provider.encoded(profile)),
                      'consumers': {name: item['status'] for name, item in registry['consumers'].items()},
                      'apache_syntax_checked': False, 'renewal_executed': False}
        else:
            if arguments.command != 'inspect-retirement': _prepare_state(root, engine)
            with adapter.lease(create=arguments.command != 'inspect-retirement'):
                require(load_protected_json(root, arguments.registry) == registry
                        and load_protected_json(root, arguments.profile) == profile,
                        'Administrative inputs changed before lease admission')
                if arguments.command == 'apply':
                    require(arguments.operation_id and arguments.artifacts_directory,
                            'Apply needs an operation ID and a protected pinned artifact directory')
                    base = path(arguments.artifacts_directory)
                    actual = root.directory(base)
                    require(actual is not None and actual['uid'] == 0 and not actual['mode'] & 0o022,
                            'Artifact source directory must be administratively protected')
                    raw = {name: root.read_bytes(base + name) for name in provider.managed_manifest(registry)['files']
                           if name != provider.REGISTRY}
                    previous = provider._load_receipt(root, arguments.operation_id)
                    if previous is not None: before = previous['before']
                    elif arguments.before_manifest:
                        before = load_protected_json(root, arguments.before_manifest)
                    elif root.snapshot(provider.REGISTRY) is not None:
                        before = provider.managed_manifest(load_protected_json(root, provider.REGISTRY))
                        metadata = root.snapshot(PROFILE)
                        require(metadata is not None, 'Registered frontend has no protected profile')
                        before['files'][PROFILE] = {**metadata, 'retention': 'managed'}
                    else:
                        before = {'format': 1, 'owner': 'host', 'files': {}, 'directories': {}, 'links': {}}
                    result = apply_configuration(adapter, operation_id=arguments.operation_id,
                                                  before=before, pinned_artifacts=raw)
                else:
                    adapter.assert_registry_current()
                    if arguments.command == 'deploy-hook':
                        result = provider.handle_deploy_hook(registry, lineage=os.environ.get('RENEWED_LINEAGE'),
                            renewed_domains=os.environ.get('RENEWED_DOMAINS'), adapter=adapter)
                    elif arguments.command == 'post-hook':
                        result = provider.handle_post_hook(registry, adapter=adapter)
                    elif arguments.command == 'retire-application':
                        result = adapter.retire_application(owner=arguments.owner, operation_id=arguments.operation_id)
                    elif arguments.command == 'inspect-retirement':
                        result = adapter.retirement_status(arguments.owner)
                    else: result = adapter.retire_renewals(operation_id=arguments.operation_id, owner=arguments.owner)
        # Receipts may contain path metadata, never private material bytes.
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise SystemExit('Host frontend stopped: ' + type(error).__name__) from None
