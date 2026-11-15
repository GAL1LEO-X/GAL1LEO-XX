"""Build an immutable, host-owned source closure locally; never install it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

DESTINATION = '/usr/local/lib/develative-host-components'
MAX_FILE = 16 * 1024 * 1024
SOURCES = ('host/__init__.py', 'host/installation.py', 'host/lifecycle/__init__.py', 'host/lifecycle/filesystem.py', 'host/lifecycle/evidence.py', 'host/lifecycle/services.py', 'host/lifecycle/service_client.py', 'host/install_bundle.py', 'host/frontend/provider.py', 'host/frontend/adapter.py', 'host/frontend/component.json', 'host/qos/contract.py', 'host/qos/applicator.py', 'host/qos/adoption.py', 'host/qos/processes.py', 'host/qos/component.json', 'host/frontend/fresh_profile.py', 'host/frontend/existing_profile.py', 'host/frontend/certificates.py')
GENERAL_SOURCES = SOURCES
BOOTSTRAP_SOURCES = {'frontend': ('host/frontend/adapter.py', 'host/frontend/provider.py', 'host/lifecycle/filesystem.py'), 'qos': ('host/installation.py', 'host/qos/applicator.py', 'host/qos/contract.py', 'host/qos/adoption.py', 'host/qos/processes.py', 'host/lifecycle/filesystem.py'), 'frontend_profile': ('host/frontend/existing_profile.py', 'host/frontend/provider.py', 'host/frontend/adapter.py', 'host/lifecycle/filesystem.py'), 'frontend_fresh': ('host/installation.py', 'host/frontend/fresh_profile.py', 'host/frontend/provider.py', 'host/frontend/adapter.py', 'host/lifecycle/filesystem.py'), 'certificates': ('host/frontend/certificates.py', 'host/frontend/adapter.py', 'host/frontend/provider.py', 'host/lifecycle/filesystem.py')}
GENERAL_BOOTSTRAP_SOURCES = BOOTSTRAP_SOURCES


class BundleError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise BundleError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def read(path):
    path = Path(path).absolute()
    require(path == path.resolve(strict=True), 'Bundle sources must be physical')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        initial = os.fstat(stream.fileno())
        require(stat.S_ISREG(initial.st_mode) and initial.st_size <= 16 * 1024 * 1024,
                'Source must be a bounded regular file')
        content = stream.read(16 * 1024 * 1024 + 1)
        final = os.fstat(stream.fileno())
    actual = path.lstat()
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    require(identity(initial) == identity(final) == identity(actual), 'Source changed while reading')
    return content


def build(source, output, *, source_revision, profile="general"):
    require(profile == "general", "Unknown finite host bundle profile")
    selected_sources=GENERAL_SOURCES if profile=="general" else SOURCES
    bootstrap_sources=GENERAL_BOOTSTRAP_SOURCES if profile=="general" else BOOTSTRAP_SOURCES
    require(isinstance(source_revision, str) and re.fullmatch('[0-9a-f]{40}', source_revision),
            'An explicit source revision is required')
    source, output = Path(source).absolute(), Path(output).absolute()
    require(source == source.resolve(strict=True) and source.is_dir(), 'Source root must be physical')
    require(output.parent == output.parent.resolve(strict=True) and not output.exists()
            and not output.is_symlink(), 'Output must be a new physical directory')
    payloads = {name: read(source / name) for name in selected_sources}
    source_hashes = {name: sha(content) for name, content in sorted(payloads.items())}
    bootstrap_files = {}
    for entry, names in bootstrap_sources.items():
        name = entry.replace('_', '-') + '-sources.json'
        payloads[name] = encoded({'format': 1, 'sources': {relative: source_hashes[relative] for relative in names}})
        bootstrap_files[entry] = {'relative': name, 'sha256': sha(payloads[name])}
    content_manifest = {'format': 1, 'owner': 'host', 'files': {
        name: sha(content) for name, content in sorted(payloads.items())}}
    manifest_content = encoded(content_manifest)
    generation = sha(manifest_content)
    destination = DESTINATION + '/' + generation
    payloads['manifest.json'] = manifest_content
    directories = {destination, *(str(Path(destination + '/' + name).parent) for name in payloads)}
    # All nested parents are explicit. The finite host installer can create
    # the shared prefix beneath the existing protected OS directories.
    for path in list(directories):
        for parent in Path(path).parents:
            if str(parent) == DESTINATION:
                break
            if str(parent).startswith(destination + '/'):
                directories.add(str(parent))
    filesystem_manifest = {'format': 1, 'owner': 'host', 'files': {
        destination + '/' + name: {'sha256': sha(content), 'uid': 0, 'gid': 0,
                                    'mode': 0o644, 'retention': 'retain'}
        for name, content in sorted(payloads.items())}, 'directories': {
            name: {'uid': 0, 'gid': 0, 'mode': 0o755, 'retention': 'retain'}
            for name in sorted(directories)}, 'links': {}}
    metadata = {'format': 'develative-host-components-bundle-v1', 'owner': 'host',
        'source_revision': source_revision, 'revision_verification': 'caller-asserted',
        'source_hashes': source_hashes, 'generation': generation,
        'destination': destination, 'filesystem_manifest': filesystem_manifest,
        'host_prerequisites': ['/usr/local/lib', '/var/lib'], 'application_removal': 'retain',
        'not_included': ['configuration', 'credentials', 'certificates', 'foreign-module-binaries',
                         'registry', 'journals', 'application-data', 'installation'],
        'entrypoints': {'frontend': destination + '/host/frontend/adapter.py',
                       'qos': destination + '/host/qos/applicator.py',
                       'frontend_profile': destination + '/host/frontend/existing_profile.py',
                       'frontend_fresh': destination + '/host/frontend/fresh_profile.py',
                       'certificates': destination + '/host/frontend/certificates.py'},
        'bootstrap': {entry: {'path': destination + '/' + item['relative'], 'sha256': item['sha256']}
                      for entry, item in bootstrap_files.items()}}
    if profile=='general':metadata['profile']='general'
    output.mkdir(mode=0o755)
    for name, content in payloads.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(content)
        target.chmod(0o644)
    for directory in [output, *(item for item in output.rglob('*') if item.is_dir())]:
        directory.chmod(0o755)
    (output / 'bundle.json').write_bytes(encoded(metadata))
    (output / 'bundle.json').chmod(0o644)
    return metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--profile',choices=('general',),default='general')
    args = parser.parse_args(argv)
    try:
        result = build(args.source, args.output, source_revision=args.source_revision,profile=args.profile)
    except (OSError, ValueError) as error:
        parser.exit(1, 'Host bundle rejected: ' + str(error) + '\n')
    print(json.dumps({'generation': result['generation'], 'destination': result['destination'],
                      'metadata_sha256': sha(encoded(result)), 'installed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
