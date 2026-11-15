"""Prepare a deterministic local administration bundle; never install or activate.

The source revision is an explicit caller assertion. File hashes attest the
bytes read, not their Git provenance. Application tags do not install this
bundle. An external reviewed handoff must verify provenance, ownership and
host prerequisites before selecting a generation or updating stable files.
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
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat


BOOTSTRAP = installation_path('/usr/local/lib/develative-deploy/whatsapp-bootstrap')
GENERATIONS = installation_path('/usr/local/lib/develative-deploy/whatsapp-generations')
LEGACY_RUNTIME = installation_path('/usr/local/lib/develative-deploy/whatsapp/release_runtime.py')
RECEIVER_ENTRY = installation_path('/usr/local/lib/develative-deploy/whatsapp/github_release.py')
PROJECT = installation_path('/srv/openai-codex/projects/whatsapp-personal')
BOOTSTRAP_FILES = ('release_admin.py', 'release_entry.py', 'installation_layout.py')
GENERATION_FILES = (
    'installation_layout.py', 'backup_validation.py', 'github_release.py', 'github_release_common.py',
    'release_backup.py', 'release_build.py', 'release_database.py',
    'release_probe.py', 'release_recover.py', 'release_runtime.py',
    'release_transaction.py', 'state_enrollment.py', 'tenant_database.py',
    'backup_schemas/6.sql', 'backup_schemas/7.sql', 'backup_schemas/8.sql',
)
PROJECT_FILES = ('installation_layout.py', 'backup_runtime.py', 'package_source.py', 'runtime_lifecycle.py',
                 'provision_host.py', 'tenant_admin.py', 'host_integration.py', 'tenant_database.py',
                 'wa_link.py', 'build_operations.py', 'export_plugin.py', 'plugin_skills.py', 'prepare_authelia.py',
                 'web_admin_broker.py', 'provisioning_attempt.py', 'restore_runtime.py',
                 'admin_deployment.py', 'backup_validation.py', 'release_database.py',
                 'backup_schemas/6.sql', 'backup_schemas/7.sql', 'backup_schemas/8.sql')
UNIT_FILES = ('develative-whatsapp-recovery.service', 'develative-whatsapp-recovery.timer')
BUILDER_SOURCE = 'scripts/build_admin_bundle.py'


class BundleError(ValueError):
    """An input cannot be represented by this source-only bundle contract."""


def require(condition, message):
    if not condition:
        raise BundleError(message)


def digest(content):
    return hashlib.sha256(content).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def physical(path, *, directory=False):
    path = Path(path).absolute()
    try:
        require(path == path.resolve(strict=True), 'Paths must be physical, without symlinks')
        info = path.lstat()
        require((stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode),
                'Expected a regular source file or directory')
    except OSError as error:
        raise BundleError('Required source or output parent is unavailable') from error
    return path


def read_source(root, relative):
    path = physical(root / relative)
    # Do not follow a final symlink introduced after the path inspection.
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode), 'Expected a regular source file')
            content = stream.read()
            after = os.fstat(stream.fileno())
        current = path.lstat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_ctime_ns) and
                (after.st_dev, after.st_ino) == (current.st_dev, current.st_ino),
                'A source file changed while preparing the bundle')
        return content
    except OSError as error:
        raise BundleError('A source file could not be read safely') from error


def check_imports(root, source_files):
    """Check sibling Python imports without executing administrative sources."""
    available = {Path(name).stem for name in (*GENERATION_FILES, *BOOTSTRAP_FILES)
                 if name.endswith('.py')}
    for name in GENERATION_FILES:
        if not name.endswith('.py'):
            continue
        try:
            tree = ast.parse(source_files['scripts/' + name], filename=name)
        except (SyntaxError, ValueError) as error:
            raise BundleError('An administrative Python source is invalid') from error
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports = [item.name.split('.')[0] for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports = [node.module.split('.')[0]]
            else:
                continue
            for module in imports:
                sibling = root / 'scripts' / (module + '.py')
                require(not (sibling.exists() or sibling.is_symlink()) or module in available,
                        'An administrative sibling import is outside the exact bundle: ' + module)


def specification(destination, *, directory=False):
    # These are installation requirements, never ownership operations here.
    return {'destination': destination, 'owner': 'root', 'group': 'root',
            'mode': '0755' if directory else '0644'}


def build_bundle(source, output, *, source_sha):
    """Write a new local tree and return its metadata; reject all prior output.

    No host inspection, subprocess, application import, network, chown or owner
    record creation occurs. Invalid inputs fail before creating output. An I/O
    interruption can leave an incomplete new tree; it is never resumed or
    overwritten, and bundle.json is written only after every payload file.
    """
    require(isinstance(source_sha, str) and re.fullmatch('[0-9a-f]{40}', source_sha),
            'source-sha must be an explicit lowercase 40-character commit SHA')
    source = physical(source, directory=True)
    output = Path(output).absolute()
    physical(output.parent, directory=True)
    require(not output.exists() and not output.is_symlink(), 'Output must not already exist')
    require(output.name not in ('', '.', '..'), 'Output must be a new directory')

    builder_source = read_source(source, BUILDER_SOURCE)
    running_builder = Path(__file__).absolute()
    require(builder_source == read_source(running_builder.parent, running_builder.name),
            'The source builder must match the executing builder')
    sources = {BUILDER_SOURCE: builder_source}
    layout = {}
    for group, names, parent in (
        ('bootstrap', BOOTSTRAP_FILES, 'scripts'),
        ('generation', GENERATION_FILES, 'scripts'),
        ('legacy-runtime', ('release_runtime.py', 'installation_layout.py'), 'scripts'),
        ('project-scripts', PROJECT_FILES, 'scripts'),
        ('systemd', UNIT_FILES, 'deploy'),
    ):
        for name in names:
            relative = parent + '/' + name
            if relative not in sources:
                sources[relative] = read_source(source, relative)
            content=sources[relative]
            if group=='systemd': content=installation_path(content.decode()).encode()
            layout[group + '/' + name] = (relative, content)
    receiver_source = 'scripts/release_receiver_entry.py'
    sources[receiver_source] = read_source(source, receiver_source)
    layout['receiver-entry/github_release.py'] = (receiver_source, sources[receiver_source])
    check_imports(source, sources)

    profile=installation_profile()
    manifest_value={'protocol': 1, 'files': {
        name: digest(sources['scripts/' + name]) for name in GENERATION_FILES}}
    if not profile.compatibility:
        manifest_value['installation_sha256']=profile.sha256
    manifest = encoded(manifest_value)
    manifest_sha = digest(manifest)
    generation_destination = GENERATIONS + '/' + manifest_sha
    layout['generation/manifest.json'] = (None, manifest)
    destinations = {'bootstrap': BOOTSTRAP, 'generation': generation_destination,
                    'legacy-runtime': str(Path(LEGACY_RUNTIME).parent),
                    'receiver-entry': str(Path(RECEIVER_ENTRY).parent),
                    'project-scripts': PROJECT + '/scripts', 'systemd': '/etc/systemd/system'}
    directories = {}
    for name, destination in sorted({**destinations,
            'generation/backup_schemas': generation_destination + '/backup_schemas',
            'project-scripts/backup_schemas': PROJECT + '/scripts/backup_schemas'}.items()):
        directories[name] = {**specification(destination, directory=True),
                             'lifecycle_owner': 'whatsapp-administration',
                             'policy': 'retain-directory-manage-only-declared-artifact-files'}
    directories['systemd'].update(lifecycle_owner='host-infrastructure', policy='shared-directory-retain')
    directories['legacy-runtime']['policy'] = 'retain-existing-directory-and-unlisted-legacy-helpers'
    directories['project-scripts'].update(lifecycle_owner='whatsapp-application',
                                         policy='retain-application-directory-and-unlisted-files')
    artifacts = {}
    for name, (relative, content) in sorted(layout.items()):
        group, remainder = name.split('/', 1)
        target_name=installation_path(remainder) if group=='systemd' else remainder
        artifacts[name] = {**specification(destinations[group] + '/' + target_name),
                           'sha256': digest(content), 'source': relative,
                           'component': group}
    metadata = {
        'format': 'whatsapp-admin-bundle-v1',
        'source': {'revision': source_sha, 'revision_verification': 'caller-asserted',
                   'files': {name: digest(content) for name, content in sorted(sources.items())}},
        'builder': {'source': BUILDER_SOURCE, 'sha256': digest(builder_source),
                    'included_as_artifact': False},
        'generation': {'directory': 'generation', 'destination': generation_destination,
                       'manifest': 'generation/manifest.json', 'manifest_sha256': manifest_sha,
                       'protocol': 1},
        'bootstrap': {'directory': 'bootstrap', 'destination': BOOTSTRAP,
                      'entrypoint': BOOTSTRAP + '/release_entry.py'},
        'artifacts': artifacts,
        'directories': directories,
        'cleanup_policy': {
            'recursive_directory_removal': False,
            'targets': 'declared-artifact-files-only',
            'requires': ['external-reviewed-cleanup', 'previous-manifest-match',
                         'physical-path-owner-mode-hash-match', 'no-active-references',
                         'post-release-verification-and-process-drain'],
            'unrecognized_or_changed_objects': 'stop-and-retain',
        },
        'handoff': {
            'installation': 'external-reviewed-operation',
            'application_tags_update_administration': False,
            'owner_record_created': False,
            'legacy_runtime': 'separate-reviewed-update-at-preserved-path',
            'receiver_entry': 'permanent-protected-launcher-at-existing-invoker-path',
            'application_release': 'separate-source-and-dependency-artifact',
            'project_scripts': 'require-installed-application-and-environment',
            'fresh_and_upgrade': 'same-managed-artifacts-and-destinations',
        },
        'host_references': {
            'build_parent': {**specification(installation_path('/opt/develative-releases'), directory=True),
                             'lifecycle_owner': 'host-infrastructure',
                             'policy': 'preexisting-host-owned-no-create-or-repair',
                             'removal': 'retain'},
            'build_account': {'name': installation_path('develative-release-build'), 'owner': 'host-infrastructure',
                              'policy': 'preserve-existing-uid-gid'},
        },
        'not_included': ['owner-record-and-epoch', 'host-configuration-and-secrets',
                         'application-source-and-environments', 'databases-and-sessions',
                         'live-journals-and-locks', 'installation-or-removal-procedure'],
    }
    if not profile.compatibility:
        metadata['format']='whatsapp-admin-bundle-v2'
        metadata['installation_sha256']=profile.sha256
        metadata['unit_templates']={name:sources['deploy/'+name].decode() for name in UNIT_FILES}

    # Exclusive creation is also the final guard against a concurrent creator.
    output.mkdir(mode=0o755)
    for name, (_, content) in sorted(layout.items()):
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        with target.open('xb') as stream:
            stream.write(content)
        target.chmod(0o644)
    for directory in (output, *(item for item in output.rglob('*') if item.is_dir())):
        directory.chmod(0o755)
    with (output / 'bundle.json').open('xb') as stream:
        stream.write(encoded(metadata))
    (output / 'bundle.json').chmod(0o644)
    return metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1],
                        help='WhatsApp plugin source directory')
    parser.add_argument('--source-sha', required=True, help='Explicit source commit assertion')
    parser.add_argument('--output', type=Path, required=True, help='New local output directory')
    args = parser.parse_args(argv)
    try:
        metadata = build_bundle(args.source, args.output, source_sha=args.source_sha)
    except (BundleError, OSError) as error:
        parser.exit(1, 'Bundle preparation failed: ' + str(error) + '\n')
    print(json.dumps({'output': str(args.output.absolute()),
                      'metadata_sha256': digest(encoded(metadata)),
                      'generation_manifest_sha256': metadata['generation']['manifest_sha256']}, sort_keys=True))


if __name__ == '__main__':
    main()
