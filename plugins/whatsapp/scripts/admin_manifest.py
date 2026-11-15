"""Compile a local WhatsApp administration bundle into an exact filesystem plan.

This module reads bytes only. It never installs, executes bundled Python, opens
services, creates an owner, or authorizes host paths from artifact metadata.
The source revision remains a caller assertion; a reviewed metadata digest pins
all bundle declarations. Inactive historical artifacts are explicitly retained,
so equality concerns the active manifest, not the host's historical contents.
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
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

REPOSITORY = Path(__file__).resolve().parents[3]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))
from host.lifecycle import filesystem

# Independent source policy: do not import these destinations from the bundle
# or its builder. Changing this closure requires a coordinated source review.
BOOTSTRAP = installation_path('/usr/local/lib/develative-deploy/whatsapp-bootstrap')
GENERATIONS = installation_path('/usr/local/lib/develative-deploy/whatsapp-generations')
LEGACY = installation_path('/usr/local/lib/develative-deploy/whatsapp')
RUNTIME = LEGACY + '/release_runtime.py'
RECEIVER = LEGACY + '/github_release.py'
PROJECT_SCRIPTS = installation_path('/srv/openai-codex/projects/whatsapp-personal/scripts')
SYSTEMD = '/etc/systemd/system'
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
BUILDER = 'scripts/build_admin_bundle.py'
MAX_METADATA = 1024 * 1024


class ManifestError(ValueError):
    """The declared bundle or adoption is outside the reviewed source contract."""


def require(condition, message):
    if not condition:
        raise ManifestError(message)


def sha(content):
    return hashlib.sha256(content).hexdigest()


def _hex(value, count=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(count) + '}', value) is not None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field')
        result[key] = value
    return result


def _json(content):
    try:
        return json.loads(content, object_pairs_hook=_unique)
    except (ValueError, UnicodeError) as error:
        raise ManifestError('Invalid bundle JSON') from error


def empty_manifest():
    return {'format': 1, 'owner': 'whatsapp', 'files': {}, 'directories': {}, 'links': {}}


def manifest_digest(manifest):
    """Canonical digest to approve an explicit previous manifest, including empty."""
    return sha(filesystem.encoded(filesystem.validate_manifest(manifest)))


def _layout(generation):
    result = {}
    for component, names, parent, source in (
        ('bootstrap', BOOTSTRAP_FILES, BOOTSTRAP, 'scripts'),
        ('generation', GENERATION_FILES, generation, 'scripts'),
        ('legacy-runtime', ('release_runtime.py', 'installation_layout.py'), LEGACY, 'scripts'),
        ('project-scripts', PROJECT_FILES, PROJECT_SCRIPTS, 'scripts'),
        ('systemd', UNIT_FILES, SYSTEMD, 'deploy'),
    ):
        for name in names:
            target_name=installation_path(name) if component=='systemd' else name
            result[component + '/' + name] = (parent + '/' + target_name, source + '/' + name, component)
    result['generation/manifest.json'] = (generation + '/manifest.json', None, 'generation')
    result['receiver-entry/github_release.py'] = (RECEIVER, 'scripts/release_receiver_entry.py', 'receiver-entry')
    return result


def _directory_metadata(generation):
    result = {}
    for name, target in {
        'bootstrap': BOOTSTRAP, 'generation': generation,
        'generation/backup_schemas': generation + '/backup_schemas',
        'legacy-runtime': LEGACY, 'receiver-entry': LEGACY,
        'project-scripts': PROJECT_SCRIPTS,
        'project-scripts/backup_schemas': PROJECT_SCRIPTS + '/backup_schemas', 'systemd': SYSTEMD,
    }.items():
        result[name] = {'destination': target, 'owner': 'root', 'group': 'root', 'mode': '0755',
                        'lifecycle_owner': 'whatsapp-administration',
                        'policy': 'retain-directory-manage-only-declared-artifact-files'}
    result['systemd'].update(lifecycle_owner='host-infrastructure', policy='shared-directory-retain')
    result['legacy-runtime']['policy'] = 'retain-existing-directory-and-unlisted-legacy-helpers'
    result['project-scripts'].update(lifecycle_owner='whatsapp-application',
                                    policy='retain-application-directory-and-unlisted-files')
    return result


def _tree(root, expected_files):
    """Refuse even unused symlinks, bytecode, extra files and empty directories."""
    expected_dirs = {str(parent) for name in expected_files for parent in PurePosixPath(name).parents
                     if str(parent) != '.'}
    files, directories = set(), set()
    for directory, dirs, names in os.walk(root.base, followlinks=False):
        for name in (*dirs, *names):
            path = Path(directory) / name
            info = path.lstat()
            relative = path.relative_to(root.base).as_posix()
            require(info.st_uid == root.uid and not info.st_mode & 0o022,
                    'Bundle tree must be protected by its preparing authority')
            if stat.S_ISDIR(info.st_mode):
                directories.add(relative)
            else:
                require(stat.S_ISREG(info.st_mode), 'Only physical regular bundle files are allowed')
                files.add(relative)
            require(len(files) <= len(expected_files) and len(directories) <= len(expected_dirs),
                    'Unexpected bundle objects')
    require(files == expected_files and directories == expected_dirs, 'Bundle tree differs from the exact source closure')


def _policies(metadata):
    require(metadata['cleanup_policy'] == {
        'recursive_directory_removal': False, 'targets': 'declared-artifact-files-only',
        'requires': ['external-reviewed-cleanup', 'previous-manifest-match',
                     'physical-path-owner-mode-hash-match', 'no-active-references',
                     'post-release-verification-and-process-drain'],
        'unrecognized_or_changed_objects': 'stop-and-retain'}, 'Bundle cleanup policy differs')
    require(metadata['handoff'] == {
        'installation': 'external-reviewed-operation', 'application_tags_update_administration': False,
        'owner_record_created': False, 'legacy_runtime': 'separate-reviewed-update-at-preserved-path',
        'receiver_entry': 'permanent-protected-launcher-at-existing-invoker-path',
        'application_release': 'separate-source-and-dependency-artifact',
        'project_scripts': 'require-installed-application-and-environment',
        'fresh_and_upgrade': 'same-managed-artifacts-and-destinations'}, 'Bundle handoff contract differs')
    require(metadata['host_references'] == {
        'build_parent': {'destination': installation_path('/opt/develative-releases'), 'owner': 'root', 'group': 'root',
                         'mode': '0755', 'lifecycle_owner': 'host-infrastructure',
                         'policy': 'preexisting-host-owned-no-create-or-repair', 'removal': 'retain'},
        'build_account': {'name': installation_path('develative-release-build'), 'owner': 'host-infrastructure',
                          'policy': 'preserve-existing-uid-gid'}}, 'Host reference policy differs')
    require(metadata['not_included'] == ['owner-record-and-epoch', 'host-configuration-and-secrets',
        'application-source-and-environments', 'databases-and-sessions', 'live-journals-and-locks',
        'installation-or-removal-procedure'], 'Bundle scope differs')


def load_bundle(bundle_path, source_revision, *, uid=0, gid=0, expected_metadata_sha256=None):
    """Read a complete local bundle and derive paths exclusively from this source.

    uid/gid describe required destination metadata (0/0 on the host); tests may
    explicitly use their fixture identity. There is no chown, write or Git query.
    """
    require(_hex(source_revision, 40), 'An explicit source revision assertion is required')
    require(all(type(value) is int and 0 <= value <= 2**31 - 1 for value in (uid, gid)), 'Invalid destination ownership')
    require(expected_metadata_sha256 is None or _hex(expected_metadata_sha256), 'Invalid reviewed metadata digest')
    with filesystem.Root(bundle_path) as root:
        metadata_bytes = root.read_bytes('/bundle.json', max_bytes=MAX_METADATA)
        metadata_sha = sha(metadata_bytes)
        require(expected_metadata_sha256 is None or expected_metadata_sha256 == metadata_sha,
                'Bundle metadata differs from the reviewed digest')
        metadata = _json(metadata_bytes)
        profile=installation_profile()
        metadata_fields={'format', 'source', 'builder', 'generation', 'bootstrap', 'artifacts',
                         'directories', 'cleanup_policy', 'handoff', 'host_references', 'not_included'}
        if not profile.compatibility: metadata_fields|={'installation_sha256','unit_templates'}
        expected_format='whatsapp-admin-bundle-v1' if profile.compatibility else 'whatsapp-admin-bundle-v2'
        require(isinstance(metadata, dict) and set(metadata)==metadata_fields
                and metadata['format']==expected_format, 'Invalid closed bundle metadata')
        if not profile.compatibility:
            require(metadata['installation_sha256']==profile.sha256
                    and isinstance(metadata['unit_templates'],dict)
                    and set(metadata['unit_templates'])==set(UNIT_FILES)
                    and all(isinstance(value,str) for value in metadata['unit_templates'].values()),
                    'Bundle installation or unit template closure differs')
        generation_bytes = root.read_bytes('/generation/manifest.json', max_bytes=MAX_METADATA)
        generation_sha = sha(generation_bytes)
        generation = GENERATIONS + '/' + generation_sha
        require(isinstance(metadata['generation'], dict) and type(metadata['generation'].get('protocol')) is int
                and metadata['generation'] == {'directory': 'generation', 'destination': generation,
                'manifest': 'generation/manifest.json', 'manifest_sha256': generation_sha, 'protocol': 1},
                'Generation identity or destination differs')
        require(metadata['bootstrap'] == {'directory': 'bootstrap', 'destination': BOOTSTRAP,
                'entrypoint': BOOTSTRAP + '/release_entry.py'}, 'Bootstrap destination differs')
        generation_manifest = _json(generation_bytes)
        profile=installation_profile()
        generation_fields={'protocol','files'} if profile.compatibility else {'protocol','files','installation_sha256'}
        require(isinstance(generation_manifest, dict) and set(generation_manifest) == generation_fields
                and type(generation_manifest['protocol']) is int and generation_manifest['protocol'] == 1
                and isinstance(generation_manifest['files'], dict)
                and set(generation_manifest['files']) == set(GENERATION_FILES)
                and all(_hex(value) for value in generation_manifest['files'].values()), 'Generation closure differs')
        require(profile.compatibility or generation_manifest['installation_sha256']==profile.sha256,
                'Bundle belongs to another installation profile')
        layout = _layout(generation)
        require(isinstance(metadata['artifacts'], dict) and set(metadata['artifacts']) == set(layout),
                'Artifact closure differs')
        _tree(root, set(layout) | {'bundle.json'})
        require(metadata['directories'] == _directory_metadata(generation), 'Directory destination or retention policy differs')
        _policies(metadata)
        source = metadata['source']
        expected_sources = {BUILDER} | {spec[1] for spec in layout.values() if spec[1] is not None}
        require(isinstance(source, dict) and set(source) == {'revision', 'revision_verification', 'files'}
                and source['revision'] == source_revision and source['revision_verification'] == 'caller-asserted'
                and isinstance(source['files'], dict) and set(source['files']) == expected_sources
                and all(_hex(value) for value in source['files'].values()), 'Source assertion or source hash closure differs')
        require(metadata['builder'] == {'source': BUILDER, 'sha256': source['files'][BUILDER],
                'included_as_artifact': False}, 'Builder source assertion differs')
        manifest, payloads, total = empty_manifest(), {}, 0
        for name, (target, relative, component) in sorted(layout.items()):
            data = root.read_bytes('/' + name)
            total += len(data)
            require(total <= filesystem.MAX_PAYLOAD_BYTES, 'Bundle payload exceeds its bound')
            content_sha = sha(data)
            require(metadata['artifacts'][name] == {'destination': target, 'owner': 'root', 'group': 'root',
                    'mode': '0644', 'sha256': content_sha, 'source': relative, 'component': component},
                    'Artifact metadata or payload differs: ' + name)
            if component=='systemd' and not profile.compatibility:
                template=metadata['unit_templates'][name.split('/',1)[1]].encode()
                require(source['files'][relative]==sha(template)
                        and data==installation_path(template.decode()).encode(),
                        'Rendered unit differs from its pinned source template and installation')
            else:
                require(relative is None or source['files'][relative] == content_sha, 'Source hash differs from payload')
            if component == 'generation' and name != 'generation/manifest.json':
                require(generation_manifest['files'][name[len('generation/'):]] == content_sha,
                        'Generation manifest differs from payload')
            payloads[target] = data
            manifest['files'][target] = {'sha256': content_sha, 'mode': 0o644, 'uid': uid, 'gid': gid,
                                        'retention': 'managed'}
        directories = {item['destination'] for item in _directory_metadata(generation).values()} | {GENERATIONS}
        manifest['directories'] = {path: {'mode': 0o755, 'uid': uid, 'gid': gid, 'retention': 'retain'}
                                   for path in sorted(directories)}
        manifest = filesystem.validate_manifest(manifest)
        # Pin the original bytes again after all reads; no mutable on-disk input
        # is needed by prepare_action or by the later filesystem transaction.
        require(root.read_bytes('/bundle.json', max_bytes=MAX_METADATA) == metadata_bytes
                and root.read_bytes('/generation/manifest.json', max_bytes=MAX_METADATA) == generation_bytes,
                'Bundle declarations changed while reading')
    return {'manifest': manifest, 'payloads': payloads,
            'allowed_paths': sorted(set(manifest['files']) | set(manifest['directories'])),
            'generation': dict(metadata['generation']), 'metadata_sha256': metadata_sha,
            'source_revision': source_revision}


def _file_allowed(path):
    fixed = {value[0] for value in _layout(GENERATIONS + '/' + '0' * 64).values()
             if value[2] != 'generation'}
    if path in fixed:
        return True
    if path.startswith(LEGACY + '/'):
        return path[len(LEGACY) + 1:] in GENERATION_FILES
    if path.startswith(GENERATIONS + '/'):
        parts = path[len(GENERATIONS) + 1:].split('/', 1)
        return len(parts) == 2 and _hex(parts[0]) and parts[1] in (*GENERATION_FILES, 'manifest.json')
    return False


def _directory_allowed(path):
    if path in (BOOTSTRAP, GENERATIONS, LEGACY, LEGACY + '/backup_schemas', PROJECT_SCRIPTS,
                PROJECT_SCRIPTS + '/backup_schemas', SYSTEMD):
        return True
    if path.startswith(GENERATIONS + '/'):
        parts = path[len(GENERATIONS) + 1:].split('/', 1)
        return _hex(parts[0]) and (len(parts) == 1 or parts[1] == 'backup_schemas')
    return False


def _adoption(value):
    value = filesystem.validate_manifest(value)
    require(value['owner'] == 'whatsapp' and not value['links'], 'Adoption is restricted to WhatsApp administration files')
    require(all(_file_allowed(path) for path in value['files'])
            and all(_directory_allowed(path) for path in value['directories']),
            'Previous manifest is outside the independent administration closure')
    return value


def prepare_action(bundle, previous_manifest, *, adopted_sha256, runtime_update=None):
    """Adopt only explicitly reviewed before-state; preserve inactive extras.

    The returned active_manifest is identical for fresh install and upgrade.
    retained_manifest identifies only historical extras. Their union is the
    action's after state; no historical cleanup is implied by installation.
    Filesystem preflight still compares every adopted hash/mode/uid/gid to disk.
    """
    previous = _adoption(previous_manifest)
    require(_hex(adopted_sha256) and manifest_digest(previous) == adopted_sha256,
            'Previous manifest differs from its explicit adoption digest')
    require(isinstance(bundle, dict) and {'manifest', 'payloads', 'allowed_paths', 'generation',
            'metadata_sha256', 'source_revision'} == set(bundle), 'Invalid compiled bundle')
    active = _adoption(bundle['manifest'])
    generation = bundle['generation']
    require(isinstance(generation, dict) and type(generation.get('protocol')) is int and _hex(generation.get('manifest_sha256'))
            and generation == {'directory': 'generation', 'destination': GENERATIONS + '/' + generation['manifest_sha256'],
                'manifest': 'generation/manifest.json', 'manifest_sha256': generation['manifest_sha256'], 'protocol': 1},
            'Invalid compiled generation')
    layout = _layout(generation['destination'])
    require(set(active['files']) == {item[0] for item in layout.values()}, 'Compiled active closure differs')
    expected_dirs = {item['destination'] for item in _directory_metadata(generation['destination']).values()} | {GENERATIONS}
    require(set(active['directories']) == expected_dirs, 'Compiled directory closure differs')
    require(bundle['allowed_paths'] == sorted(set(active['files']) | expected_dirs), 'Compiled path policy differs')
    require(isinstance(bundle['payloads'], dict) and set(bundle['payloads']) == set(active['files']), 'Compiled payload closure differs')
    require(_hex(bundle['metadata_sha256']) and _hex(bundle['source_revision'], 40), 'Invalid compiled provenance assertions')
    identity = {(spec['uid'], spec['gid']) for kind in ('files', 'directories') for spec in active[kind].values()}
    require(len(identity) == 1 and all(spec['mode'] == 0o644 and spec['retention'] == 'managed'
            for spec in active['files'].values()) and all(spec['mode'] == 0o755 for spec in active['directories'].values()),
            'Compiled destination ownership or permission policy differs')
    require(all(type(content) is bytes and len(content) <= filesystem.MAX_FILE_BYTES
                and sha(content) == active['files'][path]['sha256'] for path, content in bundle['payloads'].items())
            and sum(len(content) for content in bundle['payloads'].values()) <= filesystem.MAX_PAYLOAD_BYTES,
            'Compiled payload differs or exceeds its bound')
    generation_bytes = bundle['payloads'][generation['destination'] + '/manifest.json']
    expected_generation = {'protocol': 1, 'files': {
        name: active['files'][generation['destination'] + '/' + name]['sha256'] for name in GENERATION_FILES}}
    profile = installation_profile()
    if not profile.compatibility:
        expected_generation['installation_sha256'] = profile.sha256
    require(sha(generation_bytes) == generation['manifest_sha256'] and _json(generation_bytes) ==
            expected_generation, 'Compiled generation differs from its exact payloads')
    if runtime_update is not None:
        from admin_handoff import validate_runtime_update
        validate_runtime_update(runtime_update, previous, active, generation['destination'], filesystem)
    elif RUNTIME in previous['files']:
        require({key: value for key, value in previous['files'][RUNTIME].items() if key != 'retention'} ==
                {key: value for key, value in active['files'][RUNTIME].items() if key != 'retention'},
                'Legacy runtime differs; it requires a separate reviewed update')
    retained = empty_manifest()
    after = json.loads(filesystem.encoded(active))
    for kind in ('files', 'directories'):
        for path, spec in previous[kind].items():
            if path not in active[kind]:
                retained[kind][path] = {**spec, 'retention': 'retain'}
                after[kind][path] = retained[kind][path]
            elif kind == 'directories':
                require(spec == active[kind][path], 'Existing directory metadata requires inspection, not repair')
            elif spec['retention'] == 'retain':
                require(spec == active[kind][path], 'Retained artifact cannot be changed or implicitly reactivated')
    allowed = sorted(set(previous['files']) | set(previous['directories']) | set(after['files']) | set(after['directories']))
    return {'action': {'before': previous, 'after': after, 'allowed_paths': allowed},
            'payloads': dict(bundle['payloads']), 'active_manifest': active, 'retained_manifest': retained}
