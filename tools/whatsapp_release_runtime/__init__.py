"""Qualify a locked runtime and exact source snapshot on an isolated CI runner.

Importing this module does not start processes. ``qualify_runtime`` performs
actual checks; callers must never replace its receipts with historical results.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET

try:
    from ..whatsapp_release_common import ReleaseError
except ImportError:
    from whatsapp_release_common import ReleaseError

PROXY_ENVIRONMENT = (
    'HTTP_PROXY', 'HTTPS_PROXY', 'FTP_PROXY', 'ALL_PROXY', 'NO_PROXY',
    'http_proxy', 'https_proxy', 'ftp_proxy', 'all_proxy', 'no_proxy',
)
BUILD_ENVIRONMENT = PROXY_ENVIRONMENT + ('NODE_EXTRA_CA_CERTS', 'GIT_SSL_CAINFO',)
SCRIPTS = ('__init__.py', 'probe-runtime.cjs', 'lifecycle-guard.cjs')
MAX_SOURCE_FILES = 20000
MAX_SOURCE_BYTES = 512 * 1024 * 1024
DOCKER = ('docker', '--host=unix:///var/run/docker.sock')


def _require(condition, message):
    if not condition:
        raise ReleaseError(message)


def _sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _sources(root):
    records, size = {}, 0
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            path = Path(parent) / name
            _require(not path.is_symlink() and name != '.git', 'Snapshot contains a link or Git metadata')
        for name in sorted(files):
            path = Path(parent) / name
            size += path.stat().st_size
            _require(path.is_file() and len(records) < MAX_SOURCE_FILES and size <= MAX_SOURCE_BYTES,
                     'Snapshot exceeds source inventory limits or contains special files')
            records[path.relative_to(root).as_posix()] = _sha(path)
    _require(records, 'Source snapshot is empty')
    return dict(sorted(records.items()))


def _verify_archive(path, metadata):
    """Check pinned bytes and both OCI and Docker-save identity without extraction."""
    _require(path.is_file() and not path.is_symlink(), 'Image archive must be a regular file')
    _require(path.stat().st_size == metadata['archive_bytes'] and _sha(path) == metadata['archive_sha256'],
             'Runtime archive differs from the locked asset')
    with tarfile.open(path, 'r:*') as archive:
        members = {}
        for member in archive:
            name = member.name
            _require(len(members) < 2048 and name not in members and
                     not PurePosixPath(name).is_absolute() and '\\' not in name and
                     '..' not in PurePosixPath(name).parts and (member.isfile() or member.isdir()),
                     'Unsafe or excessive runtime archive members')
            members[name] = member

        def data(name):
            item = members.get(name)
            _require(item and item.isfile() and item.size <= 4 * 1024 * 1024,
                     'Missing or oversized runtime JSON')
            return archive.extractfile(item).read()

        _require(json.loads(data('oci-layout')) == {'imageLayoutVersion': '1.0.0'}, 'Invalid OCI layout')
        index = json.loads(data('index.json'))
        _require(index.get('schemaVersion') == 2 and len(index.get('manifests', [])) == 1,
                 'Exactly one OCI image is required')
        descriptor = index['manifests'][0]
        _require(descriptor['digest'] == metadata['manifest_digest'], 'OCI manifest identity mismatch')
        manifest_bytes = data('blobs/sha256/' + metadata['manifest_digest'][7:])
        _require('sha256:' + hashlib.sha256(manifest_bytes).hexdigest() == metadata['manifest_digest'] and
                 len(manifest_bytes) == descriptor['size'], 'OCI manifest bytes mismatch')
        manifest = json.loads(manifest_bytes)
        _require(manifest.get('schemaVersion') == 2 and manifest['config']['digest'] == metadata['config_digest'],
                 'OCI config identity mismatch')
        config_name = 'blobs/sha256/' + metadata['config_digest'][7:]
        config_bytes = data(config_name)
        _require('sha256:' + hashlib.sha256(config_bytes).hexdigest() == metadata['config_digest'] and
                 len(config_bytes) == manifest['config']['size'], 'OCI config bytes mismatch')
        config = json.loads(config_bytes)
        _require(config.get('os') == 'linux' and config.get('architecture') == 'amd64',
                 'Runtime must target linux/amd64')
        layers = manifest.get('layers', [])
        _require(layers and len(layers) == len(config.get('rootfs', {}).get('diff_ids', [])),
                 'Runtime layer count mismatch')
        layer_names = []
        for layer in layers:
            _require(re.fullmatch(r'sha256:[a-f0-9]{64}', layer['digest']), 'Invalid layer identity')
            name = 'blobs/sha256/' + layer['digest'][7:]
            _require(name in members and members[name].isfile() and members[name].size == layer['size'],
                     'Runtime layer missing or truncated')
            layer_names.append(name)
        saved = json.loads(data('manifest.json'))
        _require(isinstance(saved, list) and len(saved) == 1 and saved[0]['Config'] == config_name and
                 saved[0]['Layers'] == layer_names, 'Docker-save and OCI image identities differ')
    return config


def _environment(output, snapshot=None):
    # No inheritance: in particular no GitHub/Actions credentials, user Python
    # configuration, Docker endpoint override, or host proxy configuration.
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
           'HOME': str(output / 'home'), 'TMPDIR': str(output / 'temporary'),
           'DOCKER_CONFIG': str(output / 'home'), 'PYTHONDONTWRITEBYTECODE': '1',
           'PYTHONNOUSERSITE': '1', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
    if snapshot is not None:
        env['PYTHONPATH'] = os.pathsep.join((str(snapshot / 'plugins/whatsapp'), str(snapshot)))
    return env


def _image_environment(config):
    env = dict(item.split('=', 1) for item in config.get('Env', []))
    _require(not any(env.get(key) for key in BUILD_ENVIRONMENT), 'Build environment leaked into image')
    _require(not any(value and key.startswith(('GH_', 'GITHUB_', 'ACTIONS_', 'RUNNER_'))
                     for key, value in env.items()), 'CI environment leaked into image')
    _require(env.get('WAHA_WORKER_RESTART_SESSIONS') == 'true', 'Runtime restart default changed')


def _isolation(runtime, image, uid, scratch, nonce, scripts):
    host, config = runtime['HostConfig'], runtime['Config']
    _require(runtime['Image'] == image and config['Image'] == image, 'Container uses unexpected image')
    _require(config.get('Labels', {}).get('org.plugins.whatsapp.qualification') == nonce,
             'Container ownership label mismatch')
    _require(config.get('User') == f'{uid}:{uid}', 'Container user is not the expected nonroot identity')
    _require(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True and
             not host.get('PortBindings') and not host.get('Privileged') and
             host.get('CapDrop') == ['ALL'] and 'no-new-privileges' in host.get('SecurityOpt', []),
             'Container isolation differs from qualification policy')
    _require(host.get('Tmpfs', {}).get(scratch) == 'rw,nosuid,nodev,size=536870912,mode=1777' and
             host.get('Memory') == 1073741824 and host.get('PidsLimit') == 256,
             'Container temporary storage or process limits differ from qualification policy')
    mounts = runtime.get('Mounts', [])
    binds = [item for item in mounts if item.get('Type') != 'tmpfs']
    _require(len(binds) == 1 and binds[0].get('Type') == 'bind' and
             binds[0].get('Source') == str(scripts) and binds[0].get('Destination') == '/opt/offline' and
             binds[0].get('RW') is False, 'Unexpected runtime host mount')
    environment = dict(item.split('=', 1) for item in config.get('Env', []))
    _require(all(environment.get(key) == '' for key in PROXY_ENVIRONMENT), 'Runtime proxy environment is not empty')
    _require(environment.get('WHATSAPP_START_SESSION') == '' and
             environment.get('WHATSAPP_RESTART_ALL_SESSIONS') == 'false' and
             environment.get('WAHA_WORKER_RESTART_SESSIONS') == 'false', 'Runtime session startup is enabled')


def qualify_runtime(image_archive, runtime_metadata, source_snapshot, output, python_executable=sys.executable):
    """Run real regressions and account-free smoke checks; write a failure receipt too.

    ``output`` must be absent. Metadata contains archive_sha256/archive_bytes,
    manifest_digest/config_digest/gows_sha256, target_commit and workflow_commit.
    Optional container_temporary_directory is an absolute container-only path.
    No image is pulled and cleanup addresses only the container created here.
    """
    metadata = dict(runtime_metadata)
    for key in ('archive_sha256', 'gows_sha256'):
        _require(re.fullmatch(r'[a-f0-9]{64}', str(metadata.get(key, ''))), 'Invalid ' + key)
    for key in ('config_digest', 'manifest_digest'):
        _require(re.fullmatch(r'sha256:[a-f0-9]{64}', str(metadata.get(key, ''))), 'Invalid ' + key)
    for key in ('target_commit', 'workflow_commit'):
        _require(re.fullmatch(r'(?:[a-f0-9]{40}|[a-f0-9]{64})', str(metadata.get(key, ''))), 'Invalid ' + key)
    _require(type(metadata.get('archive_bytes')) is int and metadata['archive_bytes'] > 0, 'Invalid archive size')
    snapshot, image_archive = Path(source_snapshot).resolve(strict=True), Path(image_archive).absolute()
    output = Path(output).absolute()
    _require(output.parent.resolve(strict=True) == output.parent and not os.path.lexists(output) and
             output != snapshot and snapshot not in output.parents, 'Qualification output must be a new directory outside the snapshot')
    scratch = metadata.get('container_temporary_directory', '/run/qualification')
    _require(isinstance(scratch, str) and re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+', scratch) and
             scratch not in {'/app', '/opt', '/run', '/etc', '/usr', '/var'}, 'Invalid container temporary directory')
    uid = 1000
    output.mkdir(mode=0o700)
    for name in ('home', 'temporary'):
        (output / name).mkdir(mode=0o700)
    token, nonce = secrets.token_urlsafe(32), secrets.token_hex(16)
    scripts = Path(__file__).resolve().parent
    container = None
    creation_attempted = False
    container_name = 'whatsapp-qualification-' + nonce
    result = {'passed': False, 'target_commit': metadata['target_commit'], 'workflow_commit': metadata['workflow_commit'],
              'runtime_config_digest': metadata['config_digest'], 'runtime_manifest_digest': metadata['manifest_digest'],
              'archive_sha256': metadata['archive_sha256'], 'live_whatsapp': False,
              'checks': {'backend_regressions': {'executed': False, 'passed': False},
                         'runtime_smoke': {'executed': False, 'passed': False}},
              'limits': ['No WhatsApp account, session, pairing, send, delivery or phone playback is tested.',
                         'Backend synthetic regressions and runtime smoke are separate checks; no full backend/provider vertical is claimed.']}

    def run(arguments, label=None, timeout=60, check=True, backend=False):
        completed = subprocess.run(list(arguments), cwd=snapshot if backend else output,
                                   env=_environment(output, snapshot if backend else None),
                                   text=True, capture_output=True, timeout=timeout, check=False)
        if label:
            (output / (label + '.stdout')).write_text(completed.stdout.replace(token, '[synthetic-key]'))
            (output / (label + '.stderr')).write_text(completed.stderr.replace(token, '[synthetic-key]'))
        if check:
            _require(completed.returncode == 0, (label or 'Qualification command') + ' failed')
        return completed

    def docker(*arguments, **kwargs):
        return run((*DOCKER, *arguments), **kwargs)

    failure = None
    try:
        inventory = _sources(snapshot)
        result['source_files_sha256'] = inventory
        result['qualification_sources_sha256'] = {name: _sha(scripts / name) for name in SCRIPTS}
        config = _verify_archive(image_archive, metadata)
        _image_environment(config['config'])
        backend = result['checks']['backend_regressions']
        backend['executed'] = True
        run([str(python_executable), '-B', '-m', 'pytest', 'plugins/whatsapp/tests', '-q', '--tb=short',
             '-p', 'no:cacheprovider', '--basetemp=' + str(output / 'pytest-data'),
             '--junitxml=' + str(output / 'backend.xml')], label='backend', timeout=1800, backend=True)
        suites = list(ET.parse(output / 'backend.xml').getroot().iter('testsuite'))
        _require(suites and sum(int(suite.get('tests', 0)) for suite in suites) > 0 and
                 all(int(suite.get('failures', 0)) == 0 and int(suite.get('errors', 0)) == 0 for suite in suites),
                 'Backend test receipt is empty or failed')
        backend.update(passed=True, tests=sum(int(suite.get('tests', 0)) for suite in suites))
        docker('load', '--input', str(image_archive), label='image-load', timeout=600)
        image = json.loads(docker('image', 'inspect', metadata['config_digest']).stdout)[0]
        _require(image['Id'] == metadata['config_digest'] and image['Os'] == 'linux' and image['Architecture'] == 'amd64',
                 'Loaded Docker image identity differs from the locked runtime')
        _image_environment(image['Config'])
        environment = {'NODE_OPTIONS': '--require=/opt/offline/lifecycle-guard.cjs', 'WAHA_API_KEY': token,
                       'OFFLINE_EXPECTED_GOWS_SHA256': metadata['gows_sha256'], 'OFFLINE_EXPECTED_UID': str(uid),
                       'OFFLINE_MARKER_ROOT': scratch + '/markers', 'TMPDIR': scratch,
                       'WAHA_GOWS_SOCKET': scratch + '/gows.sock',
                       'WAHA_LOCAL_STORE_BASE_DIR': scratch + '/sessions', 'WHATSAPP_FILES_FOLDER': scratch + '/media',
                       'WHATSAPP_START_SESSION': '', 'WHATSAPP_RESTART_ALL_SESSIONS': 'false',
                       'WAHA_WORKER_RESTART_SESSIONS': 'false', 'WAHA_DASHBOARD_ENABLED': 'false',
                       'WHATSAPP_SWAGGER_ENABLED': 'false', 'WAHA_APPS_ENABLED': 'false', 'WAHA_PRINT_QR': 'false',
                       'WAHA_RUN_XVFB': 'false', 'OTEL_SDK_DISABLED': 'true', 'OTEL_TRACES_EXPORTER': 'none',
                       'OTEL_METRICS_EXPORTER': 'none', 'OTEL_LOGS_EXPORTER': 'none'}
        environment.update({key: '' for key in PROXY_ENVIRONMENT})
        command = ['create', '--name', container_name, '--label',
                   'org.plugins.whatsapp.qualification=' + nonce, '--pull=never', '--network=none', '--read-only',
                   '--user', f'{uid}:{uid}', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                   '--memory=1073741824', '--pids-limit=256', '--cpus=2',
                   '--tmpfs=' + scratch + ':rw,nosuid,nodev,size=536870912,mode=1777',
                   '--mount', f'type=bind,source={scripts},target=/opt/offline,readonly']
        for name, value in environment.items():
            command += ['--env', name + '=' + value]
        command.append(metadata['config_digest'])
        creation_attempted = True
        identity = docker(*command, timeout=300).stdout.strip()
        _require(re.fullmatch(r'[a-f0-9]{64}', identity), 'Unexpected created container identity')
        observed = json.loads(docker('inspect', identity).stdout)[0]
        _require(observed.get('Id') == identity and
                 observed['Config'].get('Labels', {}).get('org.plugins.whatsapp.qualification') == nonce,
                 'Created container ownership could not be verified')
        container = identity
        _isolation(observed, metadata['config_digest'], uid, scratch, nonce, scripts)
        docker('start', container)
        smoke = result['checks']['runtime_smoke']
        smoke.update(executed=True, image_id=image['Id'], uid=uid, network='none', read_only_root=True,
                     dropped_capabilities=['ALL'], no_new_privileges=True)
        for _ in range(60):
            ping = docker('exec', container, 'node', '-e',
                          "fetch('http://127.0.0.1:3000/api/sessions',{signal:AbortSignal.timeout(1000)})"
                          ".then(r=>process.exit(r.status===401?0:1)).catch(()=>process.exit(1))", timeout=5, check=False)
            if ping.returncode == 0:
                break
            _require(json.loads(docker('inspect', container).stdout)[0]['State']['Running'], 'Runtime stopped before readiness')
            time.sleep(1)
        else:
            raise ReleaseError('Runtime did not become ready within the bounded readiness window')
        probe = docker('exec', container, 'node', '/opt/offline/probe-runtime.cjs', label='probe', timeout=120)
        evidence = json.loads(probe.stdout.strip().splitlines()[-1])
        _require(evidence.get('scope') == 'isolated-no-account-runtime' and evidence.get('liveWhatsApp') is False and
                 evidence.get('authenticatedStatus') == 200 and evidence.get('unauthenticatedStatus') == 401 and
                 evidence.get('sessions') == [] and evidence.get('uid') == uid and
                 evidence.get('gows', {}).get('sha256') == metadata['gows_sha256'] and
                 evidence.get('lifecycleGuard', {}).get('attempts') == 0 and
                 evidence.get('audio', {}).get('decoded') is True, 'Runtime probe receipt is incomplete')
        (output / 'runtime-contract.json').write_text(json.dumps(evidence['abContract']) + '\n')
        compatibility = result['checks']['runtime_backend_contract'] = {'executed': True, 'passed': False}
        response = run([str(python_executable), '-B', '-c',
                        "import json,sys; from pathlib import Path; import sally_whatsapp.ab_operations as ab; "
                        "assert Path(ab.__file__).resolve() == Path(sys.argv[2]).resolve() / 'plugins/whatsapp/sally_whatsapp/ab_operations.py'; "
                        "value=json.loads(Path(sys.argv[1]).read_text()); "
                        "assert ab.contract_operations(value) == ab.OPERATIONS; "
                        "assert frozenset(value['operations']) == ab.OPERATIONS; "
                        "print(json.dumps({'passed':True,'version':ab.CONTRACT_VERSION,'operations':sorted(ab.OPERATIONS)}))",
                        str(output / 'runtime-contract.json'), str(snapshot)],
                       label='backend-contract', backend=True)
        receipt = json.loads(response.stdout)
        _require(receipt.get('passed') is True and receipt.get('version') == evidence['abContract']['version'] and
                 receipt.get('operations') == sorted(evidence['abContract']['operations']),
                 'Backend and actual runtime contract receipts differ')
        compatibility.update(passed=True, **{'contract': receipt})
        smoke.update(passed=True, probe=evidence)
        _require(_sources(snapshot) == inventory and
                 result['qualification_sources_sha256'] == {name: _sha(scripts / name) for name in SCRIPTS},
                 'Qualification inputs changed during execution')
        _require(_sha(image_archive) == metadata['archive_sha256'], 'Image archive changed during qualification')
        result['passed'] = True
    except Exception as error:
        failure = error
        result['error'] = str(error).replace(token, '[synthetic-key]')
    finally:
        if creation_attempted and container is None:
            # A create timeout can leave a container behind. Reconcile only our
            # unpredictable name and ownership label, then remove by exact ID.
            try:
                lookup = docker('inspect', container_name, check=False)
                if lookup.returncode == 0:
                    owned = json.loads(lookup.stdout)[0]
                    identity = owned.get('Id', '')
                    if (re.fullmatch(r'[a-f0-9]{64}', identity) and
                            owned['Config'].get('Labels', {}).get('org.plugins.whatsapp.qualification') == nonce):
                        container = identity
                    else:
                        result['container_reconciliation'] = 'ownership-unverified'
                else:
                    result['container_reconciliation'] = 'not-found'
            except Exception:
                result['container_reconciliation'] = 'uncertain'
        if container is not None:
            try:
                docker('logs', container, label='startup', check=False)
            except Exception:
                result['logs_collected'] = False
            try:
                result['container_removed'] = docker('rm', '--force', container, timeout=120, check=False).returncode == 0
            except Exception:
                result['container_removed'] = False
            if not result['container_removed']:
                result['passed'] = False
                result['error'] = 'Could not remove the qualification container ' + container
                failure = ReleaseError(result['error'])
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    if failure is not None:
        raise ReleaseError(result['error']) from None
    return result
