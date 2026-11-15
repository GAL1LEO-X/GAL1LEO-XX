"""Install one reviewed immutable host source generation; no service effects.

The metadata digest is supplied independently by the administrator. All paths
and the source closure are derived here, never authorized by bundle metadata.
No application files, active selectors, registries or certificates are changed.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat

DESTINATION = '/usr/local/lib/develative-host-components'
DESTINATION = '/usr/local/lib/develative-host-components'
MAX_FILE = 16 * 1024 * 1024
SOURCES = ('host/__init__.py', 'host/installation.py', 'host/lifecycle/__init__.py', 'host/lifecycle/filesystem.py', 'host/lifecycle/evidence.py', 'host/lifecycle/services.py', 'host/lifecycle/service_client.py', 'host/install_bundle.py', 'host/frontend/provider.py', 'host/frontend/adapter.py', 'host/frontend/component.json', 'host/qos/contract.py', 'host/qos/applicator.py', 'host/qos/adoption.py', 'host/qos/processes.py', 'host/qos/component.json', 'host/frontend/fresh_profile.py', 'host/frontend/existing_profile.py', 'host/frontend/certificates.py')
GENERAL_SOURCES = SOURCES
BOOTSTRAP_SOURCES = {'frontend': ('host/frontend/adapter.py', 'host/frontend/provider.py', 'host/lifecycle/filesystem.py'), 'qos': ('host/installation.py', 'host/qos/applicator.py', 'host/qos/contract.py', 'host/qos/adoption.py', 'host/qos/processes.py', 'host/lifecycle/filesystem.py'), 'frontend_profile': ('host/frontend/existing_profile.py', 'host/frontend/provider.py', 'host/frontend/adapter.py', 'host/lifecycle/filesystem.py'), 'frontend_fresh': ('host/installation.py', 'host/frontend/fresh_profile.py', 'host/frontend/provider.py', 'host/frontend/adapter.py', 'host/lifecycle/filesystem.py'), 'certificates': ('host/frontend/certificates.py', 'host/frontend/adapter.py', 'host/frontend/provider.py', 'host/lifecycle/filesystem.py')}
GENERAL_BOOTSTRAP_SOURCES = BOOTSTRAP_SOURCES


class BundleError(ValueError):
    pass


def require(value, message):
    if not value:
        raise BundleError(message)


def sha(content):
    return hashlib.sha256(content).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decode(content):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Repeated bundle field')
            result[key] = value
        return result
    return json.loads(content, object_pairs_hook=unique)


def read(path, *, protected=False):
    path = Path(path).absolute()
    require(path == path.resolve(strict=True), 'Bundle inputs must be physical')
    if protected:
        for item in (path, *path.parents):
            info = item.lstat()
            require(info.st_uid == 0 and not info.st_mode & 0o022,
                    'Host installation requires root-protected source and artifact paths')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        initial = os.fstat(stream.fileno())
        require(stat.S_ISREG(initial.st_mode) and initial.st_size <= MAX_FILE, 'Invalid bounded bundle file')
        content = stream.read(MAX_FILE + 1)
        final = os.fstat(stream.fileno())
    current = path.lstat()
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    require(identity(initial) == identity(final) == identity(current) and len(content) <= MAX_FILE,
            'Bundle input changed while reading')
    return content


def load_bundle(directory, expected_sha256, *, protected=False):
    base = Path(directory).absolute()
    require(base == base.resolve(strict=True) and base.is_dir(), 'Bundle root must be a physical directory')
    require(isinstance(expected_sha256, str) and re.fullmatch('[0-9a-f]{64}', expected_sha256),
            'An independently reviewed metadata digest is required')
    metadata_bytes = read(base / 'bundle.json', protected=protected)
    require(sha(metadata_bytes) == expected_sha256, 'Bundle metadata differs from its reviewed digest')
    metadata = decode(metadata_bytes)
    general=metadata.get('profile')=='general'
    require(general, 'Only the generic public host profile is supported')
    selected_sources=GENERAL_SOURCES if general else SOURCES
    bootstrap_sources=GENERAL_BOOTSTRAP_SOURCES if general else BOOTSTRAP_SOURCES
    required = {'format', 'owner', 'source_revision', 'revision_verification', 'source_hashes', 'generation',
                'destination', 'filesystem_manifest', 'host_prerequisites', 'application_removal',
                'not_included', 'entrypoints', 'bootstrap'} | ({'profile'} if general else set())
    require(isinstance(metadata, dict) and set(metadata) == required
            and metadata['format'] == 'develative-host-components-bundle-v1' and metadata['owner'] == 'host'
            and metadata['revision_verification'] == 'caller-asserted'
            and isinstance(metadata['source_revision'], str) and re.fullmatch('[0-9a-f]{40}', metadata['source_revision'])
            and metadata['application_removal'] == 'retain', 'Unknown host bundle format or ownership')
    expected_files = set(selected_sources) | {'manifest.json', 'bundle.json'} | {
        entry.replace('_', '-') + '-sources.json' for entry in bootstrap_sources}
    actual, actual_dirs = set(), set()
    for item in base.rglob('*'):
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'Bundle links are forbidden')
        if stat.S_ISREG(info.st_mode): actual.add(item.relative_to(base).as_posix())
        else:
            require(stat.S_ISDIR(info.st_mode), 'Unexpected bundle object')
            actual_dirs.add(item.relative_to(base).as_posix())
    require(actual == expected_files, 'Bundle source closure differs from the reviewed installer')
    expected_dirs = {str(parent) for name in expected_files for parent in Path(name).parents if str(parent) != '.'}
    require(actual_dirs == expected_dirs, 'Bundle contains an undeclared directory')
    payloads, total = {}, 0
    for name in sorted(expected_files - {'bundle.json'}):
        payloads[name] = read(base / name, protected=protected)
        total += len(payloads[name])
        require(total <= 128 * 1024 * 1024, 'Host bundle exceeds the aggregate payload bound')
    source_hashes = {name: sha(payloads[name]) for name in selected_sources}
    require(metadata['source_hashes'] == source_hashes, 'Bundle source hashes differ')
    for entry, names in bootstrap_sources.items():
        require(payloads[entry.replace('_', '-')+'-sources.json'] == encoded({'format': 1, 'sources': {
            name: source_hashes[name] for name in names}}), 'Source bootstrap manifest differs')
    manifest = {'format': 1, 'owner': 'host', 'files': {
        name: sha(body) for name, body in payloads.items() if name != 'manifest.json'}}
    require(payloads['manifest.json'] == encoded(manifest), 'Content manifest differs')
    generation = sha(payloads['manifest.json'])
    destination = DESTINATION + '/' + generation
    require(metadata['generation'] == generation and metadata['destination'] == destination,
            'Host generation destination differs')
    directories = {destination}
    for name in payloads:
        parent = Path(destination + '/' + name).parent
        while str(parent).startswith(destination + '/'):
            directories.add(str(parent)); parent = parent.parent
    desired = {'format': 1, 'owner': 'host', 'files': {
        destination + '/' + name: {'sha256': sha(body), 'mode': 0o644, 'uid': 0, 'gid': 0, 'retention': 'retain'}
        for name, body in payloads.items()}, 'directories': {
            name: {'mode': 0o755, 'uid': 0, 'gid': 0, 'retention': 'retain'} for name in directories}, 'links': {}}
    require(metadata['filesystem_manifest'] == desired
            and metadata['host_prerequisites'] == ['/usr/local/lib', '/var/lib'],
            'Bundle cannot authorize additional host paths or permissions')
    require(metadata['entrypoints'] == {'frontend': destination+'/host/frontend/adapter.py',
            'qos': destination+'/host/qos/applicator.py', 'frontend_profile': destination+'/host/frontend/existing_profile.py',
            'frontend_fresh': destination+'/host/frontend/fresh_profile.py',
                                       'certificates': destination+'/host/frontend/certificates.py'}
            and metadata['bootstrap'] == {
                entry: {'path': destination+'/'+entry.replace('_', '-')+'-sources.json',
                        'sha256': sha(payloads[entry.replace('_', '-')+'-sources.json'])}
                for entry in bootstrap_sources}, 'Entrypoints or bootstrap identity differ')
    return {'metadata': metadata, 'metadata_sha256': expected_sha256, 'manifest': desired,
            'payloads': {destination+'/'+name: body for name, body in payloads.items()}}


def install(root, bundle, engine, *, fault=None):
    """Library entry for the same installer with an explicitly isolated root."""
    for prerequisite in ('/usr/local/lib', '/var/lib'):
        actual = root.directory(prerequisite)
        require(actual is not None and actual['uid'] == root.uid and not actual['mode'] & 0o022,
                'Host OS parent is missing or unprotected; no automatic repair')
    after = copy.deepcopy(bundle['manifest'])
    for kind in ('files', 'directories'):
        for item in after[kind].values(): item.update(uid=root.uid, gid=root.gid)
    parent = root.directory(DESTINATION)
    require(parent is None or (parent['uid'] == root.uid and not parent['mode'] & 0o022),
            'Existing host component parent is not protected')
    after['directories'][DESTINATION] = {**(parent or {'uid': root.uid, 'gid': root.gid, 'mode': 0o755}),
                                         'retention': 'retain'}
    allowed = set(after['files']) | set(after['directories'])
    operation = sha(('host-component-install:' + bundle['metadata_sha256']).encode())[:32]
    operation_path = engine.STATE + '/host/operations/' + operation
    old = (None if root.directory(operation_path) is None else
           engine.inspect_operation(root, owner='host', operation_id=operation, allowed_paths=allowed))
    if old is not None:
        require(old['after'] == after and set(old['allowed_paths']) == allowed,
                'Existing host installation intent differs')
        result = engine.resume(root, owner='host', operation_id=operation,
                               allowed_paths=allowed, payloads=bundle['payloads'], fault=fault)
    else:
        before = {'format': 1, 'owner': 'host', 'files': {}, 'directories': {}, 'links': {}}
        for kind, reader in (('files', root.snapshot), ('directories', root.directory)):
            for name, desired in after[kind].items():
                current = reader(name)
                if current is not None:
                    require(current == {key: value for key, value in desired.items() if key != 'retention'},
                            'Immutable host generation collision; preserve existing bytes')
                    before[kind][name] = desired
        result = engine.reconcile(root, operation_id=operation, before=before, after=after,
            allowed_paths=allowed, payloads=bundle['payloads'], fault=fault)
    return {'generation': bundle['metadata']['generation'], 'operation_id': operation,
            'filesystem': result, 'services_changed': False, 'application_removal': 'retain'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'install'))
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args(argv)
    try:
        applying = args.action == 'install'
        require(not applying or os.geteuid() == 0, 'Host installation requires root')
        bundle = load_bundle(args.bundle, args.sha256, protected=applying)
        if applying:
            source = read(Path(__file__), protected=True)
            require(sha(source) == bundle['metadata']['source_hashes']['host/install_bundle.py'],
                    'Installer differs from the reviewed generation')
            filename = bundle['metadata']['destination'] + '/host/lifecycle/filesystem.py'
            namespace = {'__file__': filename, '__name__': 'reviewed_host_filesystem'}
            exec(compile(bundle['payloads'][filename], filename, 'exec'), namespace)
            engine = type('Filesystem', (), namespace)
            with engine.Root('/') as root:
                result = install(root, bundle, engine)
        else:
            result = {'generation': bundle['metadata']['generation'], 'destination': bundle['metadata']['destination'],
                      'metadata_sha256': bundle['metadata_sha256'], 'mutations': False}
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError) as error:
        parser.exit(1, 'Host bundle requires inspection: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
