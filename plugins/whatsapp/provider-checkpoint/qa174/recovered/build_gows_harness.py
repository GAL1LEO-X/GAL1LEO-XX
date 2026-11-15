#!/usr/bin/env python3
"""QA174 local GOWS qualification using the attested QA163 harness + compiler /usr.

prepare does not invoke Docker. execute requires the explicit authorized flag.
No image pulls/loads, networked builds, production mounts, source edits, or retries.
"""
from pathlib import Path, PurePosixPath
import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import time

EVIDENCE = Path('/workspace/work/qa174-fixes/recovered-qa163')
SCRATCH = Path('/tmp/qa174-native-harness-81f98a4')
ARCHIVE = Path('/workspace/work/qa174-fixes/provider/final-a/gows-source-qa174-local.tar.gz')
ARCHIVE_SHA = '7723a8cf9378a647bf5447c8aff96d0a5bae7c0a4865b9ae91e156279190271b'
COMPILER_USR = Path('/workspace/work/qa162-complete-fixes/compiler/rootfs/usr')
COMPILER_IMAGE = 'sha256:1a7ac3af3af212f23b6a5c90d68268bfb80824694c16a44dab57c1ca12a73bde'
HARNESS = 'sha256:5d2f6e80aabae8bfd64a01f489706f9860f837b3ce3d95d157b91713e0cd9c78'
CHECKOUT = '81f98a44a41ccb805bcbb74ca31e60111beb0126'
DOCKER = ['docker', '--host=unix:///var/run/docker.sock']
LABEL = 'org.plugins.whatsapp.qa174.recovered'
NONCE = '81f98a4-20261102-gows'
PROXIES = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'FTP_PROXY',
           'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'ftp_proxy')
GIB = 1024 ** 3


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(name, value):
    with (EVIDENCE / name).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def inventory(root):
    return {str(p.relative_to(root)): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def storage(min_tmp):
    result = {str(p): shutil.disk_usage(p).free for p in (Path('/tmp'), Path('/workspace'))}
    require(result['/tmp'] >= min_tmp, 'Insufficient /tmp free space')
    require(result['/workspace'] >= 128 * 1024 ** 2, 'Insufficient /workspace free space')
    return result


def prepare():
    require(not SCRATCH.exists(), 'Fresh scratch is required; historical files must remain untouched')
    space = storage(3 * GIB)
    require(sha(ARCHIVE) == ARCHIVE_SHA, 'Source archive digest mismatch')
    require((COMPILER_USR / 'local/go/VERSION').read_text().splitlines()[0] == 'go1.26.4', 'Compiler Go version mismatch')
    SCRATCH.mkdir(mode=0o700)
    for key in ('a', 'b'):
        source = SCRATCH / ('gows-' + key)
        source.mkdir()
        with tarfile.open(ARCHIVE, 'r:gz') as archive:
            for member in archive:
                name = PurePosixPath(member.name)
                require(not name.is_absolute() and '..' not in name.parts and name.parts[0] == 'gows-source-qa174', 'Unsafe source archive path')
                require(member.isfile(), 'Unexpected nonregular source archive entry')
                target = source.joinpath(*name.parts[1:])
                require(not target.exists(), 'Duplicate source archive path')
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as src, target.open('xb') as dst:
                    shutil.copyfileobj(src, dst)
                target.chmod(member.mode & 0o777)
        for name in ('cache', 'gopath', 'modcache', 'out'):
            (SCRATCH / (name + '-' + key)).mkdir()
    first, second = inventory(SCRATCH / 'gows-a'), inventory(SCRATCH / 'gows-b')
    require(first == second and len(first) == 2344, 'Extracted source inventory mismatch')
    write('source-inventory.json', first)
    inputs = {'execution_checkout_commit': CHECKOUT, 'source_archive': str(ARCHIVE),
              'source_archive_sha256': ARCHIVE_SHA, 'source_files': len(first),
              'source_inventory_sha256': sha(EVIDENCE / 'source-inventory.json'),
              'compiler_image_provenance': COMPILER_IMAGE, 'compiler_archive_sha256': '6211754e04aed2bed586c15dca978cd5f4fb94b369c69e9acb6b6c61d01224bb',
              'executed_image': HARNESS, 'compiler_usr_readonly': str(COMPILER_USR),
              'compiler_usr_verification': 'Parent verified all 35406 files and 1919 symlinks against 11 archive layers; zero mismatches or extras.',
              'independent_empty_build_caches': True, 'fresh_independent_source_paths': True,
              'source_date_epoch': '0', 'network': 'none', 'live_accounts': False,
              'prepared_at': now(), 'free_bytes_before_preparation': space,
              'qualification_scope': 'GOWS compile/tests only; final provider runtime is qualified separately.'}
    write('inputs.json', inputs)
    print(json.dumps(inputs), flush=True)


class Execution:
    def __init__(self):
        self.environment = os.environ.copy()
        for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
            self.environment.pop(key, None)
        self.owned = []
        self.sequence = 0
        self.receipt = {'started_at': now(), 'passed': False, 'steps': [], 'cleanup': [],
                        'runner_sha256': sha(__file__), 'inputs_sha256': sha(EVIDENCE / 'inputs.json')}

    def command(self, arguments, key, timeout=60, capture=True):
        self.sequence += 1
        prefix = f'{self.sequence:02d}-{key}'
        intent = {'command': arguments, 'started_at': now(), 'timeout_seconds': timeout}
        write(prefix + '-intent.json', intent)
        result = None
        with (EVIDENCE / (prefix + '.stdout')).open('xb') as out, (EVIDENCE / (prefix + '.stderr')).open('xb') as err:
            try:
                result = subprocess.run(arguments, env=self.environment, stdout=out, stderr=err, timeout=timeout)
            except subprocess.TimeoutExpired:
                write(prefix + '-result.json', {**intent, 'finished_at': now(), 'timed_out': True})
                raise
        write(prefix + '-result.json', {**intent, 'finished_at': now(), 'returncode': result.returncode})
        require(result.returncode == 0, key + ': command failed; see preserved stdout/stderr')
        return (EVIDENCE / (prefix + '.stdout')).read_text() if capture else str(EVIDENCE / (prefix + '.stdout'))

    def docker(self, arguments, key, **kwargs):
        return self.command(DOCKER + arguments, key, **kwargs)

    def inspect(self, target, key):
        # Only freshly created containers are inspected here; their environment is explicitly offline.
        return json.loads(self.docker(['inspect', target], key))[0]

    def owned_container(self, data, name):
        require(data['Name'] == '/' + name and data['Image'] == HARNESS
                and data['Config']['Labels'].get(LABEL) == NONCE, 'Container ownership mismatch; no removal permitted')

    def container(self, key, source_key, flags, entrypoint='/usr/local/go/bin/go', timeout=600, empty_cache=False):
        storage(GIB)
        source = SCRATCH / ('gows-' + source_key)
        expected_inventory = json.loads((EVIDENCE / 'source-inventory.json').read_text())
        require(inventory(source) == expected_inventory, 'Source changed before execution')
        if empty_cache:
            for kind in ('cache', 'gopath', 'modcache', 'out'):
                require(not any((SCRATCH / (kind + '-' + source_key)).iterdir()), 'Build cache/output is not empty')
        name = 'qa174-recovered-' + key
        mounts = [(COMPILER_USR, '/usr', True), (source, '/source', True)]
        mounts += [(SCRATCH / (kind + '-' + source_key), '/' + kind, False) for kind in ('cache', 'gopath', 'modcache', 'out')]
        env = {'GOTOOLCHAIN': 'local', 'GOWORK': 'off', 'GOENV': 'off', 'GOPROXY': 'off', 'GOSUMDB': 'off',
               'GOCACHE': '/cache', 'GOPATH': '/gopath', 'GOMODCACHE': '/modcache', 'CGO_ENABLED': '1',
               'GOOS': 'linux', 'GOARCH': 'amd64', 'GOAMD64': 'v1', 'CC': 'gcc', 'CXX': 'g++',
               'TZ': 'UTC', 'LC_ALL': 'C', 'GOMAXPROCS': '2', 'HOME': '/tmp',
               'PATH': '/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin', 'SOURCE_DATE_EPOCH': '0'}
        env.update({key: '' for key in PROXIES})
        args = ['create', '--name', name, '--label', LABEL + '=' + NONCE, '--pull=never',
                '--network=none', '--read-only', '--user', '1000:1000', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--memory=3221225472', '--pids-limit=256', '--cpus=2',
                '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=1610612736,mode=1777', '-w', '/source/src']
        for path, target, ro in mounts:
            args += ['--mount', f'type=bind,src={path},dst={target}' + (',readonly' if ro else '')]
        for k, v in env.items():
            args += ['--env', k + '=' + v]
        args += ['--entrypoint', entrypoint, HARNESS, *flags]
        self.owned.append(name)
        identifier = self.docker(args, key + '-create', timeout=60).strip()
        require(len(identifier) == 64 and all(c in '0123456789abcdef' for c in identifier), 'Unexpected container ID')
        data = self.inspect(identifier, key + '-inspect-before')
        self.owned_container(data, name)
        host, config = data['HostConfig'], data['Config']
        require(data['Id'] == identifier and not data['State']['Running'], 'Unexpected initial lifecycle state')
        require(config['User'] == '1000:1000' and host['NetworkMode'] == 'none' and host['ReadonlyRootfs']
                and not host['Privileged'] and not host.get('PortBindings') and host['CapDrop'] == ['ALL']
                and 'no-new-privileges' in host['SecurityOpt'], 'Isolation mismatch')
        require(host['Memory'] == 3221225472 and host['PidsLimit'] == 256 and host['NanoCpus'] == 2000000000
                and host['Tmpfs'] == {'/tmp': 'rw,exec,nosuid,nodev,size=1610612736,mode=1777'}, 'Resource limits mismatch')
        actual_mounts = {(m['Source'], m['Destination'], not m['RW']) for m in data['Mounts'] if m['Type'] != 'tmpfs'}
        require(actual_mounts == {(str(p), t, r) for p, t, r in mounts}, 'Unexpected mount')
        observed_env = dict(value.split('=', 1) for value in config['Env'])
        require(all(observed_env.get(k) == v for k, v in env.items()), 'Environment mismatch')
        require(set(observed_env) - set(env) <= {'LANG', 'LANGUAGE'}, 'Unexpected inherited environment keys')
        stdout_path = self.docker(['start', '--attach', identifier], key + '-execute', timeout=timeout, capture=False)
        state = self.inspect(identifier, key + '-inspect-after')['State']
        require(not state['Running'] and state['ExitCode'] == 0 and not state['OOMKilled'] and not state.get('Error'), 'Container failed or OOM-killed')
        step = {'key': key, 'container': identifier, 'source_key': source_key, 'passed': True,
                'exit_code': state['ExitCode'], 'oom_killed': state['OOMKilled'], 'stdout': stdout_path}
        if 'test' in flags:
            events = []
            for line in Path(stdout_path).read_text().splitlines():
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
            step['test_pass'] = sum(e.get('Action') == 'pass' and 'Test' in e for e in events)
            step['test_skip'] = sum(e.get('Action') == 'skip' and 'Test' in e for e in events)
            step['package_pass'] = sum(e.get('Action') == 'pass' and 'Test' not in e for e in events)
            step['failed_events'] = sum(e.get('Action') == 'fail' for e in events)
            require(not step['failed_events'] and step['test_pass'] > 0, 'No passing tests or unexpected failure event')
        self.receipt['steps'].append(step)
        self.cleanup_one(name)
        print(json.dumps(step), flush=True)

    def cleanup_one(self, name):
        data = self.inspect(name, name + '-cleanup-inspect')
        self.owned_container(data, name)
        if data['State']['Running']:
            self.docker(['stop', '--time', '10', data['Id']], name + '-cleanup-stop', timeout=30)
            data = self.inspect(data['Id'], name + '-cleanup-stopped')
            require(not data['State']['Running'], 'Owned container did not stop')
        self.docker(['rm', data['Id']], name + '-cleanup-remove', timeout=30)
        self.owned.remove(name)
        self.receipt['cleanup'].append({'name': name, 'id': data['Id'], 'removed': True})

    def execute(self):
        require(sha(ARCHIVE) == ARCHIVE_SHA, 'Source archive changed')
        require(os.getuid() == 1000 and os.getgid() == 1000, 'Unexpected workspace owner')
        info = json.loads(self.docker(['info', '--format', '{{json .}}'], 'daemon-info'))
        self.receipt['daemon'] = {k: info.get(k) for k in ('ID', 'Driver', 'DockerRootDir', 'ServerVersion', 'OSType', 'Architecture')}
        image = json.loads(self.docker(['image', 'inspect', HARNESS], 'harness-image'))[0]
        require(image['Id'] == HARNESS and image['Os'] == 'linux' and image['Architecture'] == 'amd64', 'Harness identity mismatch')
        self.container('toolchain', 'a', ['-eu', '-c', 'go version; gcc --version; pkg-config --modversion vips; uname -m'], entrypoint='/bin/sh')
        flags = ['build', '-p=2', '-mod=vendor', '-trimpath', '-buildvcs=false', '-pgo=off',
                 '-ldflags=-buildid= -linkmode=external -extldflags=-Wl,--build-id=none', '-o', '/out/gows-linux-amd64', '.']
        self.container('build-a', 'a', flags, empty_cache=True)
        self.container('build-b', 'b', flags, empty_cache=True)
        first, second = SCRATCH / 'out-a/gows-linux-amd64', SCRATCH / 'out-b/gows-linux-amd64'
        require(sha(first) == sha(second), 'Independent build binaries differ')
        self.receipt['binary'] = {'sha256': sha(first), 'bytes': first.stat().st_size,
                                  'first': str(first), 'second': str(second), 'independent_builds_identical': True}
        write('gows-reproducibility.json', self.receipt['binary'])
        print(json.dumps({'binary': self.receipt['binary']}), flush=True)
        common = ['test', '-p=2', '-mod=vendor', '-count=1', '-json', '-timeout=120s']
        self.container('regressions', 'a', common + ['./gows', './storage/sqlstorage', '-run', '^Test(GroupLeave|OwnGroupIdentity|VerifiedOwnPNAndLID|ReceiptVerified)'])
        self.container('provider-tests', 'a', common + ['./gows', './storage/...'])
        self.container('provider-race', 'a', common + ['-race', './gows', './storage/...'])
        self.container('provider-vet', 'a', ['vet', '-mod=vendor', '-composites=false', './gows', './storage/...'])
        for key in ('a', 'b'):
            require(inventory(SCRATCH / ('gows-' + key)) == json.loads((EVIDENCE / 'source-inventory.json').read_text()), 'Source changed during qualification')
        self.receipt['passed'] = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('prepare', 'execute'))
    parser.add_argument('--authorized-recovered-qa163-execution', action='store_true')
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare()
        return
    require(args.authorized_recovered_qa163_execution, 'Explicit execution authorization flag is required')
    require(not (EVIDENCE / 'execution-result.json').exists(), 'Execution already has a result; no automatic retry')
    execution = Execution()
    try:
        execution.execute()
    except BaseException as error:
        execution.receipt['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        for name in list(execution.owned):
            try:
                execution.cleanup_one(name)
            except Exception as error:
                execution.receipt['cleanup'].append({'name': name, 'removed': False, 'error': str(error)})
                execution.receipt['passed'] = False
        execution.receipt['finished_at'] = now()
        execution.receipt['free_bytes_after'] = {str(p): shutil.disk_usage(p).free for p in (Path('/tmp'), Path('/workspace'))}
        write('execution-result.json', execution.receipt)
        print(json.dumps(execution.receipt), flush=True)


if __name__ == '__main__':
    main()
