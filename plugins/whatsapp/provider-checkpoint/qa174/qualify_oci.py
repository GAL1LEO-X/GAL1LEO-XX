#!/usr/bin/env python3
"""Prepare a sealed plan, then separately execute reviewed offline OCI checks.

prepare never invokes Docker. execute requires the exact prepared plan digest;
that flag is a technical opt-in, not a permission grant. The caller must obtain
execution approval first. No pull, missing-input load, publication or pruning.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import selectors
import shutil
import subprocess
import sys
import tarfile
import time

from oci_archive import canonical, convert, require

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[3]
DOCKER = ['docker', '--host=unix:///var/run/docker.sock']
PROXIES = ('HTTP_PROXY', 'HTTPS_PROXY', 'FTP_PROXY', 'ALL_PROXY', 'NO_PROXY',
           'http_proxy', 'https_proxy', 'ftp_proxy', 'all_proxy', 'no_proxy')
CONFIG_KEYS = ('User', 'Env', 'Entrypoint', 'Cmd', 'WorkingDir', 'Volumes',
               'ExposedPorts', 'Healthcheck', 'Labels', 'StopSignal', 'Shell', 'OnBuild')
GIB = 1024 ** 3


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def inventory(root):
    result = {}
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            path = Path(parent) / name
            require(not path.is_symlink(), 'Unexpected inventory symlink: ' + str(path))
            if path.is_file():
                result[path.relative_to(root).as_posix()] = digest(path)
    return dict(sorted(result.items()))


def source_members(archive, kind, destination=None):
    records, total = {}, 0
    with tarfile.open(archive, 'r:*') as source:
        for item in source:
            parts = PurePosixPath(item.name).parts
            require(parts and parts[0] == kind + '-source-qa174' and '..' not in parts
                    and '\\' not in item.name, 'Unexpected corresponding-source path')
            if len(parts) == 1:
                require(item.isdir(), 'Source root must be a directory')
                continue
            name = PurePosixPath(*parts[1:]).as_posix()
            require(name not in records and len(records) < 10000, 'Duplicate/excessive source members')
            require(item.isfile() or (item.issym() and name == 'CLAUDE.md' and item.linkname == 'AGENTS.md'),
                    'Unexpected corresponding-source member')
            total += item.size
            require(total <= 256 * 1024 * 1024, 'Source archive too large')
            if item.issym():
                records[name] = 'symlink:AGENTS.md'
            else:
                records[name] = hashlib.file_digest(source.extractfile(item), 'sha256').hexdigest()
            if destination is not None:
                item.name = name
                source.extract(item, destination, filter='data')
    require(records, 'Empty source archive')
    return dict(sorted(records.items()))


def recipe_files():
    files = [HERE / name for name in ('qualify_oci.py', 'oci_archive.py', 'oci-inputs.json',
             'Dockerfile.runtime', 'probe-candidate.cjs', 'manifest.json')]
    files.extend(REPOSITORY / 'tools/whatsapp_release_runtime' / name
                 for name in ('probe-runtime.cjs', 'lifecycle-guard.cjs'))
    files.append(REPOSITORY / 'plugins/whatsapp/sally_whatsapp/ab_operations.py')
    return {str(path): digest(path) for path in files}


def prepare(waha, gows, output):
    require(not output.exists(), 'Output directory already exists')
    require(output.is_absolute() and not output.is_symlink(), 'An absolute new output directory is required')
    require(not output.resolve().is_relative_to(REPOSITORY), 'Scratch must be outside the source checkout')
    inputs = json.loads((HERE / 'oci-inputs.json').read_text())
    manifest = json.loads((HERE / 'manifest.json').read_text())
    sources = {}
    for kind, supplied in (('waha', waha), ('gows', gows)):
        require(supplied.is_file() and not supplied.is_symlink(), 'Source archive must be a regular file')
        path = supplied.resolve(strict=True)
        spec = manifest['sources'][kind]
        require(digest(path) == spec['local_archive_sha256'] and path.stat().st_size == spec['local_archive_bytes'],
                kind + ': source archive identity differs from the checkpoint')
        members = source_members(path, kind)
        require(len(members) == spec['local_archive_files'], 'Source file count differs')
        sources[kind] = {'path': str(path), 'sha256': digest(path), 'bytes': path.stat().st_size, 'members': members}
    output.mkdir(parents=True, exist_ok=False)
    plan = {'schema_version': 1, 'prepared_only': True, 'approval_granted': False,
            'inputs': inputs, 'sources': sources, 'recipe_files': recipe_files(),
            'output': str(output.resolve()), 'daemon': DOCKER[1],
            'effects': ['inspect exact cached images and daemon storage',
                        'create four bounded offline build containers',
                        'create one local COPY-only candidate image',
                        'save candidate and convert/verify its OCI archive',
                        'load only the newly verified candidate archive and recheck its config ID',
                        'create one empty offline runtime container',
                        'remove only containers owned by this invocation'],
            'network': 'none', 'automatic_pull_or_load': False,
            'scratch_minimum_free_bytes': inputs['scratch_minimum_free_bytes'],
            'daemon_minimum_free_bytes': inputs['daemon_minimum_free_bytes'],
            'storage_estimate': {'two_go_caches_bytes': 1800000000, 'sources_outputs_context_bytes': 300000000,
                'two_compressed_image_archives_bytes': 1800000000,
                'daemon_new_layers_and_temporary_build_bytes': 400000000,
                'notes': 'Existing base/compiler required. No automatic cleanup or missing-input image loading. '
                         'Daemon admission also requires one full base image Size plus the 1 GiB floor '
                         'for archive import staging. Thresholds are admission limits, not reserved space.'}}
    path = output / 'plan.json'
    write_json(path, plan)
    return {'prepared_only': True, 'docker_invoked': False, 'plan': str(path), 'plan_sha256': digest(path)}


def validate_plan(path, reviewed_digest):
    require(re.fullmatch(r'[a-f0-9]{64}', reviewed_digest or ''), 'An exact reviewed plan digest is required')
    require(path.is_file() and not path.is_symlink() and digest(path) == reviewed_digest, 'Prepared plan changed')
    plan = json.loads(path.read_text())
    require(plan['schema_version'] == 1 and plan['prepared_only'] is True and plan['approval_granted'] is False,
            'Not a preparation plan')
    require(plan['daemon'] == DOCKER[1] and plan['network'] == 'none'
            and plan['automatic_pull_or_load'] is False, 'Plan execution boundary changed')
    require(plan['inputs'] == json.loads((HERE / 'oci-inputs.json').read_text()), 'Pinned inputs changed')
    require(plan['recipe_files'] == recipe_files(), 'Recipe or qualification guard changed since preparation')
    require(Path(plan['output']).resolve() == path.resolve().parent, 'Output location changed')
    require(plan['scratch_minimum_free_bytes'] == plan['inputs']['scratch_minimum_free_bytes']
            and plan['daemon_minimum_free_bytes'] == plan['inputs']['daemon_minimum_free_bytes'], 'Budget changed')
    manifest = json.loads((HERE / 'manifest.json').read_text())
    for kind in ('waha', 'gows'):
        source = plan['sources'][kind]
        archive = Path(source['path'])
        require(archive.is_file() and not archive.is_symlink()
                and digest(archive) == source['sha256'] == manifest['sources'][kind]['local_archive_sha256'],
                'Source archive changed')
        require(source_members(archive, kind) == source['members'], 'Source inventory changed')
    return plan


def check_budget(scratch_free, daemon_free, inputs, same_filesystem=False):
    require(scratch_free >= inputs['scratch_minimum_free_bytes'], 'Insufficient scratch space; no cleanup performed')
    require(daemon_free >= inputs['daemon_minimum_free_bytes'], 'Insufficient daemon filesystem space; no cleanup performed')
    if same_filesystem:
        require(scratch_free >= inputs['scratch_minimum_free_bytes'] + inputs['daemon_minimum_free_bytes'],
                'Insufficient shared filesystem space; no cleanup performed')


def image_contract(image, expected):
    require(image['Id'] == expected and image['Os'] == 'linux' and image['Architecture'] == 'amd64',
            'Cached image identity/platform mismatch')
    require(not image['Config'].get('Volumes'), 'Unexpected implicit image volumes')


def overlay_contract(base, candidate):
    image_contract(candidate, candidate['Id'])
    require(candidate['RootFS']['Layers'][:-2] == base['RootFS']['Layers'], 'Expected exactly two additive COPY layers')
    require(all(candidate['Config'].get(key) == base['Config'].get(key) for key in CONFIG_KEYS),
            'Runtime configuration changed by overlay')


def copy_pipe(source, target, timeout, space_check):
    """A silent/stalled Docker client must not bypass the absolute deadline."""
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(source, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'Image save exceeded deadline')
            ready = selector.select(min(remaining, 1))
            space_check()
            if not ready:
                continue
            block = os.read(source.fileno(), 1024 * 1024)
            if not block:
                return
            target.write(block)


class Execution:
    def __init__(self, plan, inspect_only=False):
        self.plan, self.root = plan, Path(plan['output'])
        self.inspect_only = inspect_only
        self.output = self.root / ('inspection' if inspect_only else 'execution')
        self.output.mkdir(exist_ok=False)
        self.nonce = secrets.token_hex(12)
        self.owned, self.records = [], []
        self.result = {'passed': False, 'oci_qualified': False, 'inspect_only': inspect_only,
                       'live_whatsapp': False, 'network': 'none', 'checks': {},
                       'input_plan_sha256': digest(self.root / 'plan.json')}
        self.environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC',
                            'DOCKER_CONFIG': str(self.output / 'empty-docker-config'), 'DOCKER_BUILDKIT': '0'}
        Path(self.environment['DOCKER_CONFIG']).mkdir()

    def run(self, arguments, name, timeout=60, check=True, log=True):
        start = time.monotonic()
        result = subprocess.run(arguments, env=self.environment, text=True, capture_output=True, timeout=timeout)
        record = {'name': name, 'returncode': result.returncode, 'seconds': round(time.monotonic() - start, 3)}
        # Arguments can contain the synthetic API key; do not record them.
        if log or result.returncode:
            path = self.output / (name + '.log')
            content = result.stdout + result.stderr if log else result.stderr
            content = content.replace(getattr(self, 'synthetic_key', '\x00'), '<synthetic-key-redacted>')
            path.write_text(content)
            record['log_sha256'] = digest(path)
        self.records.append(record)
        write_json(self.output / 'commands.json', self.records)
        print(json.dumps(record), flush=True)
        require(not check or result.returncode == 0, name + ' failed; inspect the bounded receipt')
        return result

    def docker(self, arguments, name, **kwargs):
        return self.run(DOCKER + arguments, name, **kwargs)

    def inspect_image(self, identifier, name):
        response = self.docker(['image', 'inspect', identifier], name, log=False)
        image = json.loads(response.stdout)[0]
        image_contract(image, identifier)
        return image

    def container(self, name, image, uid, mounts, environment, command=None, workdir=None, build=False):
        actual_name = 'qa174-' + self.nonce + '-' + name
        memory = 3 * GIB if build else GIB
        scratch = '/tmp' if build else '/run/qualification'
        tmpfs = 'rw,nosuid,nodev,size=' + str(GIB // 2) + ',mode=1777'
        if build:  # Go tests execute temporary binaries.
            tmpfs = 'rw,exec,nosuid,nodev,size=' + str(GIB) + ',mode=1777'
        args = ['create', '--name', actual_name, '--label', 'org.plugins.whatsapp.qa174=' + self.nonce,
                '--pull=never', '--network=none', '--read-only', '--user', f'{uid}:{uid}',
                '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=' + str(memory),
                '--pids-limit=256', '--cpus=2', '--tmpfs=' + scratch + ':' + tmpfs]
        for source, target, readonly in mounts:
            args += ['--mount', f'type=bind,source={source},target={target}' + (',readonly' if readonly else '')]
        env = {**{key: '' for key in PROXIES}, 'NODE_EXTRA_CA_CERTS': '', 'GIT_SSL_CAINFO': '', **environment}
        for key, value in sorted(env.items()):
            args += ['--env', key + '=' + value]
        if workdir:
            args += ['--workdir', workdir]
        if command:
            args += ['--entrypoint', '/bin/sh']
        args.append(image)
        if command:
            args += ['-eu', '-c', command]
        self.owned.append((actual_name, image))  # Reconcile only this name if create times out.
        identity = self.docker(args, name + '-create', timeout=120, log=False).stdout.strip()
        require(re.fullmatch(r'[a-f0-9]{64}', identity), 'Unexpected container identity')
        actual = json.loads(self.docker(['inspect', identity], name + '-isolation', log=False).stdout)[0]
        host, config = actual['HostConfig'], actual['Config']
        require(actual['Id'] == identity and actual['Image'] == image
                and config['Labels'].get('org.plugins.whatsapp.qa174') == self.nonce, 'Container ownership mismatch')
        require(config['User'] == f'{uid}:{uid}' and host['NetworkMode'] == 'none'
                and host['ReadonlyRootfs'] is True and not host.get('Privileged') and not host.get('PortBindings')
                and host.get('CapDrop') == ['ALL'] and 'no-new-privileges' in host.get('SecurityOpt', []),
                'Container isolation mismatch')
        require(host.get('Memory') == memory and host.get('PidsLimit') == 256
                and host.get('NanoCpus') == 2000000000 and host.get('Tmpfs') == {scratch: tmpfs}, 'Container limits mismatch')
        binds = [item for item in actual['Mounts'] if item['Type'] != 'tmpfs']
        observed = {(item['Source'], item['Destination'], not item['RW']) for item in binds}
        require(len(binds) == len(mounts) and observed == {(str(s), t, r) for s, t, r in mounts}, 'Unexpected host mount')
        observed_env = dict(value.split('=', 1) for value in config['Env'])
        require(all(observed_env.get(key) == value for key, value in env.items()), 'Container environment mismatch')
        if build:
            self.docker(['start', '--attach', identity], name + '-build', timeout=600)
            require(self.docker(['wait', identity], name + '-exit').stdout.strip() == '0', name + ': container failed')
        else:
            self.docker(['start', identity], name + '-start')
        return identity

    def cleanup(self):
        failed, stops = [], []
        for name, image in reversed(self.owned):
            try:
                response = self.docker(['inspect', name], name + '-cleanup-inspect', check=False, log=False)
                require(response.returncode == 0, 'Ownership could not be inspected')
                item = json.loads(response.stdout)[0]
                require(item['Image'] == image and item['Config']['Labels'].get('org.plugins.whatsapp.qa174') == self.nonce,
                        'Cleanup ownership mismatch')
                force = False
                if item.get('State', {}).get('Running'):
                    stopped = self.docker(['stop', '--time=20', item['Id']], name + '-stop', timeout=40, check=False)
                    after = json.loads(self.docker(['inspect', item['Id']], name + '-stopped', log=False).stdout)[0]
                    state = after['State']
                    graceful = stopped.returncode == 0 and not state['Running'] and not state.get('OOMKilled') \
                               and state['ExitCode'] in (0, 143)
                    stops.append({'name': name, 'passed': graceful, 'exit_code': state.get('ExitCode')})
                    if not graceful:
                        failed.append(name + ': graceful stop failed')
                        force = True
                else:
                    state = item.get('State', {})
                    if name.endswith('-runtime') or state.get('OOMKilled') or state.get('ExitCode') != 0:
                        failed.append(name + ': stopped before expected cleanup or exited abnormally')
                        stops.append({'name': name, 'passed': False, 'exit_code': state.get('ExitCode'),
                                      'oom_killed': state.get('OOMKilled'), 'premature_exit': True})
                self.docker(['rm', *(['--force'] if force else []), item['Id']], name + '-remove', timeout=120)
            except Exception as error:
                failed.append(name + ': ' + str(error))
        self.result['container_cleanup'] = {'passed': not failed, 'graceful_stops': stops, 'failures': failed}
        if failed:
            self.result['passed'] = False

    def perform(self):
        pins = self.plan['inputs']
        require(shutil.disk_usage(self.root).free >= pins['scratch_minimum_free_bytes'], 'Insufficient scratch space before Docker')
        self.docker(['--version'], 'client-version')
        info = json.loads(self.docker(['info', '--format', '{{json .DockerRootDir}}'], 'daemon-storage', log=False).stdout)
        require(isinstance(info, str) and info.startswith('/'), 'Cannot identify local daemon storage')
        budget = {'scratch_free_bytes': shutil.disk_usage(self.root).free,
                  'daemon_root': info, 'daemon_free_bytes': shutil.disk_usage(info).free}
        self.result['storage'] = budget
        base = self.inspect_image(pins['base']['config_digest'], 'base-image')
        compiler = self.inspect_image(pins['compiler']['config_digest'], 'compiler-image')
        require(type(base.get('Size')) is int and base['Size'] > 0, 'Base image size unavailable')
        effective_pins = dict(pins, daemon_minimum_free_bytes=base['Size'] + pins['daemon_minimum_free_bytes'])
        budget['daemon_required_free_bytes'] = effective_pins['daemon_minimum_free_bytes']
        self.result['checks']['cached_inputs'] = {'passed': True, 'base': base['Id'], 'compiler': compiler['Id'],
             'base_original_manifest_from_lock': pins['base']['original_manifest_digest'],
             'base_original_transport_manifest_verified': False}
        if self.inspect_only:
            try:
                check_budget(budget['scratch_free_bytes'], budget['daemon_free_bytes'], effective_pins,
                             self.root.stat().st_dev == Path(info).stat().st_dev)
                budget['build_admitted'] = True
            except ValueError as error:
                budget.update(build_admitted=False, reason=str(error))
            self.result['passed'] = True
            return
        check_budget(budget['scratch_free_bytes'], budget['daemon_free_bytes'], effective_pins,
                     self.root.stat().st_dev == Path(info).stat().st_dev)
        self.result['execution_checkout_commit'] = self.run(
            ['git', '-C', str(REPOSITORY), 'rev-parse', 'HEAD'], 'checkout-commit').stdout.strip()
        require(os.getuid() != 0 and os.getgid() == os.getuid(), 'Build needs the invoking nonroot UID/GID pair')
        inherited = dict(value.split('=', 1) for value in base['Config'].get('Env', []))
        require(inherited.get('WAHA_WORKER_RESTART_SESSIONS') == 'true', 'Base restart default differs')
        require(not any(inherited.get(key) for key in PROXIES + ('NODE_EXTRA_CA_CERTS', 'GIT_SSL_CAINFO')),
                'Build-only environment is present in the base')
        sources, dists, binaries = {}, {}, {}
        go_env = {'GOTOOLCHAIN': 'local', 'GOWORK': 'off', 'GOENV': 'off', 'GOPROXY': 'off', 'GOSUMDB': 'off',
                  'GOMAXPROCS': '2', 'CGO_ENABLED': '1', 'GOOS': 'linux', 'GOARCH': 'amd64', 'GOAMD64': 'v1',
                  'CC': 'gcc', 'CXX': 'g++', 'TZ': 'UTC', 'LC_ALL': 'C', 'SOURCE_DATE_EPOCH': '0',
                  'GOCACHE': '/work/gocache', 'GOPATH': '/work/gopath', 'GOMODCACHE': '/work/gomodcache', 'GOTMPDIR': '/tmp'}
        for repeat in ('a', 'b'):
            for kind in ('waha', 'gows'):
                root = self.output / (kind + '-' + repeat)
                root.mkdir()
                source = self.plan['sources'][kind]
                require(source_members(Path(source['path']), kind, root) == source['members'], 'Extracted source mismatch')
                sources[kind, repeat] = root
            waha = sources['waha', repeat]
            body = """test "$(node --version)" = v24.19.0
for name in package.json yarn.lock .yarnrc.yml; do cmp "/work/$name" "/app/$name"; done
test -f /app/node_modules/@nestjs/cli/bin/nest.js
ln -s /app/node_modules /work/node_modules
node checkpoints/offline-ab/qa174.test.cjs
node node_modules/@nestjs/cli/bin/nest.js build
node checkpoints/offline-ab/qa174-compiled.test.cjs
"""
            self.container('waha-' + repeat, base['Id'], os.getuid(), [(waha, '/work', False)],
                           {'TZ': 'UTC', 'LC_ALL': 'C'}, body, '/work', True)
            dists[repeat] = inventory(waha / 'dist')
            cache = self.output / ('go-work-' + repeat)
            cache.mkdir()
            for name in ('gocache', 'gopath', 'gomodcache', 'out'):
                (cache / name).mkdir()
            body = """test "$(go version)" = 'go version go1.26.4 linux/amd64'
go version
gcc --version
pkg-config --modversion vips
go test -p=2 -mod=vendor -count=1 -timeout=90s ./gows ./storage/sqlstorage -run '^Test(GroupLeave|OwnGroupIdentity|VerifiedOwnPNAndLID|ReceiptVerified)'
go test -p=2 -mod=vendor -count=1 -timeout=60s ./storage/helpers
go build -p=2 -mod=vendor -trimpath -buildvcs=false -pgo=off -ldflags='-buildid= -linkmode=external -extldflags=-Wl,--build-id=none' -o /work/out/gows .
"""
            self.container('gows-' + repeat, compiler['Id'], os.getuid(),
                           [(sources['gows', repeat], '/source', True), (cache, '/work', False)],
                           go_env, body, '/source/src', True)
            binaries[repeat] = cache / 'out/gows'
        require(dists['a'] == dists['b'], 'Independent WAHA builds differ')
        inv_digest = hashlib.sha256(canonical(dists['a'])).hexdigest()
        require(len(dists['a']) == pins['waha']['native_dist_files']
                and inv_digest == pins['waha']['native_dist_inventory_sha256'], 'Container WAHA differs from reviewed native dist')
        gows_digest = digest(binaries['a'])
        require(gows_digest == digest(binaries['b']), 'Independent compiler-image Go builds differ')
        for (kind, _), root in sources.items():
            for name, value in self.plan['sources'][kind]['members'].items():
                actual = 'symlink:' + os.readlink(root / name) if (root / name).is_symlink() else digest(root / name)
                require(actual == value, 'Compiler modified source: ' + name)
        self.result['checks']['dual_builds'] = {'passed': True, 'gows_sha256': gows_digest,
            'waha_dist_inventory_sha256': inv_digest, 'waha_dist_files': len(dists['a']),
            'compiler_image': compiler['Id'], 'host_native_gows_equivalence_assumed': False}
        context = self.output / 'context'
        context.mkdir()
        runtime_dist = {name: value for name, value in dists['a'].items()
                        if name.split('/')[0] not in ('dashboard', 'plus')}
        for name in runtime_dist:
            target = context / 'dist' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sources['waha', 'a'] / 'dist' / name, target)
            target.chmod(0o644)
        for parent, _, _ in os.walk(context / 'dist'):
            Path(parent).chmod(0o755)
        shutil.copyfile(binaries['a'], context / 'gows')
        (context / 'gows').chmod(0o755)
        shutil.copyfile(HERE / 'Dockerfile.runtime', context / 'Dockerfile')
        require(shutil.disk_usage(info).free >= effective_pins['daemon_minimum_free_bytes'], 'Insufficient daemon space before overlay')
        require(shutil.disk_usage(self.root).free >= 2 * GIB, 'Insufficient scratch for saved and OCI archives')
        iid = self.output / 'image-id.txt'
        self.docker(['build', '--pull=false', '--network=none', '--no-cache', '--rm', '--force-rm',
                     '--iidfile', str(iid), '--file', str(context / 'Dockerfile'), str(context)], 'candidate-build', timeout=300)
        candidate_id = iid.read_text().strip()
        require(re.fullmatch(r'sha256:[a-f0-9]{64}', candidate_id), 'Unexpected candidate identity')
        candidate = self.inspect_image(candidate_id, 'candidate-image')
        overlay_contract(base, candidate)
        self.result['checks']['overlay'] = {'passed': True, 'config_digest': candidate_id,
                                           'base_layers_preserved': len(base['RootFS']['Layers']), 'added_layers': 2}
        saved = self.output / 'candidate.docker.tar.gz'
        with saved.open('xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as zipped, \
                (self.output / 'image-save.stderr').open('wb') as errors:
            process = subprocess.Popen(DOCKER + ['image', 'save', candidate_id], stdout=subprocess.PIPE,
                                       stderr=errors, env=self.environment)
            try:
                def space_check():
                    require(shutil.disk_usage(self.root).free > 512 * 1024 * 1024, 'Image save exhausted scratch budget')
                copy_pipe(process.stdout, zipped, 600, space_check)
                require(process.wait(timeout=30) == 0, 'Image save failed')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
        oci = self.output / 'candidate.oci.tar.gz'
        require(shutil.disk_usage(self.root).free >= saved.stat().st_size + 256 * 1024 * 1024,
                'Insufficient scratch for OCI conversion; no cleanup performed')
        receipt = convert(saved, oci, candidate_id, candidate['RootFS']['Layers'])
        receipt.update(archive_sha256=digest(oci), archive_bytes=oci.stat().st_size,
                       docker_save_sha256=digest(saved), gows_sha256=gows_digest)
        write_json(self.output / 'oci-metadata.json', receipt)
        self.result['checks']['oci_archive'] = {'passed': True, **receipt}
        require(shutil.disk_usage(info).free >= candidate['Size'] + 512 * 1024 * 1024,
                'Insufficient daemon space for candidate archive import; no cleanup performed')
        self.docker(['load', '--input', str(oci)], 'candidate-archive-load', timeout=600)
        loaded = self.inspect_image(candidate_id, 'loaded-candidate-image')
        require(loaded['RootFS']['Layers'] == candidate['RootFS']['Layers'], 'Loaded candidate layers differ')
        overlay_contract(base, loaded)
        require(digest(oci) == receipt['archive_sha256'], 'Candidate archive changed during import')
        self.result['checks']['oci_import'] = {'passed': True, 'config_digest': candidate_id}
        fixtures = self.output / 'fixtures'
        fixtures.mkdir(mode=0o755)
        for path in (HERE / 'probe-candidate.cjs', REPOSITORY / 'tools/whatsapp_release_runtime/probe-runtime.cjs',
                     REPOSITORY / 'tools/whatsapp_release_runtime/lifecycle-guard.cjs'):
            shutil.copyfile(path, fixtures / path.name)
            (fixtures / path.name).chmod(0o644)
        expected = {'node_version': pins['waha']['node_version'], 'dist': runtime_dist,
                    'dependency_files': {name: digest(sources['waha', 'a'] / name)
                                         for name in ('package.json', 'yarn.lock', '.yarnrc.yml')}}
        write_json(fixtures / 'expected.json', expected)
        (fixtures / 'expected.json').chmod(0o644)
        key = self.synthetic_key = secrets.token_urlsafe(32)
        env = {'NODE_OPTIONS': '--require=/opt/offline/lifecycle-guard.cjs', 'WAHA_API_KEY': key,
            'WHATSAPP_API_KEY': '', 'OFFLINE_EXPECTED_GOWS_SHA256': gows_digest, 'OFFLINE_EXPECTED_UID': '1000',
            'OFFLINE_MARKER_ROOT': '/run/qualification/markers', 'TMPDIR': '/run/qualification',
            'WAHA_GOWS_SOCKET': '/run/qualification/gows.sock', 'WAHA_LOCAL_STORE_BASE_DIR': '/run/qualification/sessions',
            'WHATSAPP_FILES_FOLDER': '/run/qualification/media', 'WHATSAPP_START_SESSION': '',
            'WHATSAPP_RESTART_ALL_SESSIONS': 'false', 'WAHA_WORKER_RESTART_SESSIONS': 'false',
            'WAHA_DASHBOARD_ENABLED': 'false', 'WHATSAPP_SWAGGER_ENABLED': 'false', 'WAHA_APPS_ENABLED': 'false',
            'WAHA_PRINT_QR': 'false', 'WAHA_RUN_XVFB': 'false', 'OTEL_SDK_DISABLED': 'true',
            'OTEL_TRACES_EXPORTER': 'none', 'OTEL_METRICS_EXPORTER': 'none', 'OTEL_LOGS_EXPORTER': 'none'}
        runtime = self.container('runtime', candidate_id, 1000, [(fixtures, '/opt/offline', True)], env)
        for attempt in range(45):
            ping = self.docker(['exec', runtime, 'node', '-e',
                "fetch('http://127.0.0.1:3000/api/sessions',{signal:AbortSignal.timeout(1000)})"
                ".then(r=>process.exit(r.status===401?0:1)).catch(()=>process.exit(1))"],
                'readiness-' + str(attempt), timeout=5, check=False, log=False)
            if ping.returncode == 0:
                break
            time.sleep(1)
        else:
            raise ValueError('Runtime not ready in bounded window')
        observed = self.docker(['exec', runtime, 'node', '/opt/offline/probe-candidate.cjs'], 'runtime-probe', timeout=120)
        probe = json.loads(observed.stdout.strip().splitlines()[-1])
        require(probe['sessions'] == [] and probe['liveWhatsApp'] is False
                and probe['lifecycleGuard']['attempts'] == 0 and probe['candidate']['distInventoryVerified'] is True,
                'Incomplete runtime receipt')
        self.result['checks']['runtime'] = {'passed': True, 'probe': probe}
        sys.path.insert(0, str(REPOSITORY / 'plugins/whatsapp'))
        from sally_whatsapp import ab_operations
        require(ab_operations.contract_operations(probe['abContract']) == ab_operations.OPERATIONS,
                'Backend/runtime contract mismatch')
        self.result['checks']['backend_contract'] = {'passed': True, 'operations': sorted(ab_operations.OPERATIONS)}
        require(recipe_files() == self.plan['recipe_files'], 'Recipe inputs changed during execution')
        self.result['passed'] = True
        self.result['oci_qualified'] = True

    def execute(self):
        try:
            self.perform()
        except Exception as error:
            self.result['error'] = str(error).replace(getattr(self, 'synthetic_key', '\x00'), '<synthetic-key-redacted>')
        finally:
            self.cleanup()
            self.result['oci_qualified'] = self.result['passed'] and not self.inspect_only
            write_json(self.output / 'result.json', self.result)
        return self.result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prep = commands.add_parser('prepare', help='Verify inputs and write a plan; no Docker process')
    prep.add_argument('--waha-archive', type=Path, required=True)
    prep.add_argument('--gows-archive', type=Path, required=True)
    prep.add_argument('--output', type=Path, required=True)
    for name, description in (('inspect', 'After approval: read only client, exact images and storage'),
                              ('execute', 'After approval: execute the sealed local qualification plan')):
        run = commands.add_parser(name, help=description)
        run.add_argument('--plan', type=Path, required=True)
        run.add_argument('--reviewed-plan-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'prepare':
            result = prepare(args.waha_archive, args.gows_archive, args.output)
        else:
            plan = validate_plan(args.plan, args.reviewed_plan_sha256)
            result = Execution(plan, inspect_only=args.command == 'inspect').execute()
        print(json.dumps(result, indent=2))
        return 0 if result.get('prepared_only') or result.get('passed') else 1
    except (ValueError, OSError, KeyError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

