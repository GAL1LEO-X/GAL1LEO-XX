"""Build a web or portable WhatsApp plugin from explicit, non-secret inputs."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
from urllib.parse import urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'plugins/whatsapp/plugin'
MCP_SCHEMA = 'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json'
PLUGIN_SCHEMA = 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json'
_skills_spec = importlib.util.spec_from_file_location(
    'whatsapp_plugin_skills', ROOT / 'plugins/whatsapp/scripts/plugin_skills.py')
_skills = importlib.util.module_from_spec(_skills_spec)
_skills_spec.loader.exec_module(_skills)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def write_archive(output, files):
    output = Path(output)
    if output.suffix.lower() != '.zip':
        raise ValueError('Output must be a ZIP file')
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', zipfile.ZIP_DEFLATED) as archive:
        for path, data in sorted(files.items()):
            info = zipfile.ZipInfo(path, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return {'file': str(output), 'bytes': output.stat().st_size,
            'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}

def manifest_json(content):
    """Reject ambiguous manifests before comparing identities and references."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate package manifest key')
            result[key] = value
        return result

    try:
        return json.loads(content, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError('Invalid package manifest JSON') from exc


def validate_portable_mcp(content, name):
    """Accept this builder's single HTTP server format, not arbitrary MCP configs."""
    mcp = manifest_json(content)
    if not isinstance(mcp, dict) or set(mcp) not in ({'mcpServers'}, {'$schema', 'mcpServers'}):
        raise ValueError('Portable MCP manifest must declare only the supported server configuration')
    if '$schema' in mcp and mcp['$schema'] != MCP_SCHEMA:
        raise ValueError('Unsupported portable MCP schema')
    servers = mcp['mcpServers']
    if not isinstance(name, str) or not name or not isinstance(servers, dict) or set(servers) != {name}:
        raise ValueError('Portable MCP manifest must declare exactly the named plugin server')
    server = servers[name]
    if (not isinstance(server, dict) or set(server) != {'type', 'url'}
            or server['type'] != 'streamable-http' or not isinstance(server['url'], str)):
        raise ValueError('Portable MCP server must contain only streamable-http type and URL')
    https_url(server['url'])

def validate_files(files, *, mode, app_id=None, expected_name=None, expected_skill_files=()):
    """Validate a complete standalone package; never infer cloud update semantics."""
    def reference(value, *, directory=False):
        if not isinstance(value, str) or not value.startswith('./') or '\\' in value:
            raise ValueError('Package references must use relative POSIX paths')
        path = value[2:]
        parts = path.rstrip('/').split('/')
        if not path or any(part in ('', '.', '..') for part in parts):
            raise ValueError('Unsafe package reference')
        if directory:
            prefix = path.rstrip('/') + '/'
            if not any(name.startswith(prefix) and data for name, data in files.items()):
                raise ValueError('Referenced package directory is absent or empty')
        elif not files.get(path):
            raise ValueError('Referenced package file is absent or empty')
        return path

    for path in files:
        if PurePosixPath(path).is_absolute() or '\\' in path or any(part in ('', '.', '..') for part in path.split('/')):
            raise ValueError('Unsafe package member')
    try:
        manifest = manifest_json(files['plugin.json'])
        overlay = manifest_json(files['.codex-plugin/plugin.json'])
        ext = manifest['extensions']['com.openai']
        for key in ('name', 'version', 'description', 'author'):
            if manifest[key] != overlay[key]:
                raise ValueError('Package manifests disagree')
        if expected_name is not None and manifest['name'] != expected_name:
            raise ValueError('Update must preserve the verified internal plugin name')
        if ext['interface'] != overlay['interface'] or ext['onboardingSkill'] != overlay['extensions']['com.openai']['onboardingSkill']:
            raise ValueError('Package manifests disagree')
        reference(overlay['skills'], directory=True)
        for name in expected_skill_files:
            reference('./' + name)
        onboarding = reference(ext['onboardingSkill'])
        if not onboarding.startswith(overlay['skills'][2:].rstrip('/') + '/'):
            raise ValueError('Onboarding skill is outside the declared skills directory')
        for key in ('logo', 'composerIcon'):
            if key in ext['interface']: reference(ext['interface'][key])
        if mode == 'web':
            if ext.get('apps') != './.app.json' or overlay.get('apps') != './.app.json':
                raise ValueError('Web manifests must reference the same app manifest')
            reference('./.app.json')
            app_key = 'dev-' + app_id.removeprefix('asdk_app_')
            expected = {app_key: {'id': app_id, 'required': True}}
            app = manifest_json(files['.app.json'])
            if app != {'apps': expected} or app['apps'][app_key]['required'] is not True:
                raise ValueError('Package must require exactly the verified app ID')
            if any(key in item for item in (manifest, ext, overlay) for key in ('mcpServers', 'mcp')) or any(name in files for name in ('mcp.json', '.mcp.json')):
                raise ValueError('Web package must not bundle another MCP connection')
        elif mode == 'portable':
            if '.app.json' in files or any('apps' in item for item in (ext, overlay)):
                raise ValueError('Portable package must not reuse an app registration')
            reference('./mcp.json')
            if '.mcp.json' in files or any(key in item for item in (manifest, ext, overlay) for key in ('mcpServers', 'mcp')):
                raise ValueError('Portable package must use only its mcp.json connection')
            validate_portable_mcp(files['mcp.json'], manifest['name'])
        else:
            raise ValueError('Choose web or portable')
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise ValueError('Incomplete or invalid standalone package') from exc
    return {'standalone_complete': True, 'mode': mode, 'name': manifest['name'],
            'version': manifest['version'], 'registration_ownership_verified_by_builder': False}

def archive_files(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate ZIP members')
        if any(info.file_size > 10 * 1024 * 1024 for info in archive.infolist()) or sum(info.file_size for info in archive.infolist()) > 20 * 1024 * 1024:
            raise ValueError('Package exceeds validation size limits')
        if any((info.external_attr >> 16) & 0o170000 == 0o120000 for info in archive.infolist()):
            raise ValueError('Package symlinks are forbidden')
        if archive.testzip() is not None:
            raise ValueError('Invalid ZIP integrity')
        files = {name: archive.read(name) for name in names}
    return files


def validate_archive(path, *, mode, app_id=None, expected_name=None, expected_skill_files=()):
    if mode == 'web' and (not app_id or not re.fullmatch(r'asdk_app_[0-9a-f]{32}', app_id)):
        raise ValueError('Supply the independently verified app ID')
    return validate_files(archive_files(path), mode=mode, app_id=app_id, expected_name=expected_name,
                          expected_skill_files=expected_skill_files)

def https_url(value):
    # urlsplit silently strips some controls; validate the literal input first.
    if (not isinstance(value, str) or not value.startswith('https://')
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
            or '\\' in value):
        raise ValueError('Use a literal HTTPS URL without whitespace or backslashes')
    parsed = urlsplit(value)
    if (not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or parsed.geturl() != value):
        raise ValueError('Use an HTTPS URL without credentials, query or fragment')
    # Accessing port also rejects non-numeric and out-of-range values. Apply the
    # same contract to the personal link and the portable MCP endpoint.
    port = parsed.port
    if parsed.netloc.endswith(':') or port == 0:
        raise ValueError('Use a valid explicit HTTPS port, or omit it')
    return value.rstrip('/')

def build(output, *, mode, name, version, connect_url, app_id=None, mcp_url=None, template=TEMPLATE):
    if mode not in {'web', 'portable'}:
        raise ValueError('Choose web or portable')
    if not re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', name) or len(name) > 64:
        raise ValueError('Invalid plugin name')
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?', version):
        raise ValueError('Use an explicit semantic version')
    connect_url = https_url(connect_url)
    if mode == 'web':
        if not app_id or not re.fullmatch(r'asdk_app_[0-9a-f]{32}', app_id) or mcp_url:
            raise ValueError('Web packages require the actual registered app ID and no bundled MCP URL')
    elif not mcp_url or app_id:
        raise ValueError('Portable packages require an MCP URL and no registered app ID')
    else:
        mcp_url = https_url(mcp_url)
    manifest = manifest_json((template / 'plugin.json').read_bytes())
    manifest.update(name=name, version=version)
    ext = manifest['extensions']['com.openai']
    ext.pop('apps', None)
    ext.pop('mcpServers', None)
    overlay = {key: manifest[key] for key in ('name', 'version', 'description', 'author')}
    overlay.update(interface=ext['interface'], skills='./skills/', extensions={'com.openai': {'onboardingSkill': ext['onboardingSkill']}})
    files = _skills.collect(template, connect_url)
    files['assets/whatsapp-gpt.png'] = (template / 'assets/whatsapp-gpt.png').read_bytes()
    if mode == 'web':
        ext['apps'] = overlay['apps'] = './.app.json'
        files['.app.json'] = encoded({'apps': {'dev-' + app_id.removeprefix('asdk_app_'): {'id': app_id, 'required': True}}})
        guide = ('Web package bound to the MCP connection specified by the operator. The builder checks the ID format, not connection ownership: verify the target account before uploading. For updates, verify the existing plugin ID, preserve its internal name and use Upload new version on that definition. Uploading as a new plugin may create a second entry: two manifests do not prove duplication. Reuse the registered app and its OAuth; do not recreate it for updates. Uninstall removes the installation but does not guarantee deletion from Created by you. Removing the app may leave this package with an orphaned dependency. Check Apps, Connected status and profile/status tools. Contains no embedded MCP server.')
    else:
        files['mcp.json'] = encoded({'$schema': MCP_SCHEMA,
                                    'mcpServers': {name: {'type': 'streamable-http', 'url': mcp_url}}})
        guide = ('Portable MCP package: ChatGPT may make it available only on desktop. For web use, register and authorize the MCP connection in the target account first, then build the web variant with its app ID.')
    files['plugin.json'] = encoded(manifest)
    files['.codex-plugin/plugin.json'] = encoded(overlay)
    files['CONFIGURATION.md'] = (f'# {name} {version}\n\n{guide}\n\nConnection page: {connect_url}\n\n'
                                 'This package contains no passwords or tokens. Approve codes and QR pairing '
                                 'on the owner phone. Configuration does not authorize test messages.\n').encode()
    validate_files(files, mode=mode, app_id=app_id, expected_skill_files=_skills.SKILL_FILES)
    result = write_archive(output, files)
    validate_archive(output, mode=mode, app_id=app_id, expected_skill_files=_skills.SKILL_FILES)
    return {**result, 'mode': mode, 'name': name, 'version': version,
            'registration_ownership_verified_by_builder': False}


def skill_update_files(snapshot, *, expected_plugin_id, expected_release_id, version,
                       connect_url, template=TEMPLATE):
    """Bootstrap skills on the inspected two-file personal App package only.

    A different source layout needs a new inspection/migration, not a best-effort
    merge with the new-plugin template. This function neither reads nor updates
    a cloud account. The release guard must also be supplied at publication time.
    """
    try:
        plugin = snapshot['plugin']
        if (not expected_plugin_id or not expected_release_id
                or plugin['plugin_id'] != expected_plugin_id
                or plugin['current_release_id'] != expected_release_id):
            raise ValueError('Plugin identity or expected release differs from the source snapshot')
        if plugin['scope'] != 'USER' or plugin['discoverability'] != 'PRIVATE':
            raise ValueError('This migration supports only the inspected private personal package')
        paths = {'.app.json', '.codex-plugin/plugin.json'}
        inventory = snapshot['files']
        contents = snapshot['contents']
        if (snapshot.get('next_offset') is not None or snapshot.get('missing_paths')
                or snapshot.get('size_limited_paths') or len(inventory) != 2
                or {item['path'] for item in inventory} != paths or set(contents) != paths):
            raise ValueError('Requires the complete two-file legacy App source; inspect other layouts separately')
        baseline = {path: value.encode('utf-8') for path, value in contents.items()}
        if any(item['size_bytes'] != len(baseline[item['path']]) for item in inventory):
            raise ValueError('Source inventory and captured bytes disagree')
        legacy = manifest_json(baseline['.codex-plugin/plugin.json'])
        if set(legacy) != {'apps', 'author', 'description', 'interface', 'name', 'version'}:
            raise ValueError('Unmapped legacy fields; preserve source and inspect before migration')
        if legacy['name'] != plugin['name'] or legacy['version'] != plugin['version']:
            raise ValueError('Source metadata and manifest disagree')
        if (not isinstance(legacy['name'], str) or len(legacy['name']) > 64
                or not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', legacy['name'])):
            raise ValueError('Legacy name is not portable')
        def stable_version(value):
            if not isinstance(value, str) or not re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', value):
                raise ValueError('This migration requires stable semantic versions')
            return tuple(map(int, value.split('.')))
        if stable_version(version) <= stable_version(legacy['version']):
            raise ValueError('The candidate version must increase')
        author = legacy['author']
        if (not isinstance(author, dict) or not author or set(author) - {'name', 'email', 'url'}
                or any(not isinstance(value, str) for value in author.values())
                or not isinstance(legacy['description'], str)):
            raise ValueError('Legacy metadata cannot be represented losslessly')
        interface = legacy['interface']
        fields = {'capabilities', 'category', 'defaultPrompt', 'developerName',
                  'displayName', 'longDescription', 'shortDescription'}
        if not isinstance(interface, dict) or set(interface) != fields:
            raise ValueError('Unmapped interface fields; inspect before migration')
        if any(not isinstance(interface[key], str) or not interface[key].strip()
               for key in fields - {'capabilities', 'defaultPrompt'}):
            raise ValueError('Invalid interface text')
        capabilities, prompt = interface['capabilities'], interface['defaultPrompt']
        if (not isinstance(capabilities, list)
                or any(not isinstance(item, str) or not item.strip() for item in capabilities)):
            raise ValueError('Invalid interface capabilities')
        if not (prompt is None or isinstance(prompt, str) or
                (isinstance(prompt, list) and len(prompt) <= 3 and all(isinstance(item, str) for item in prompt))):
            raise ValueError('Invalid interface prompts')
        apps = manifest_json(baseline['.app.json'])
        if (legacy['apps'] != './.app.json' or not isinstance(apps, dict)
                or set(apps) != {'apps'} or not isinstance(apps['apps'], dict)
                or len(apps['apps']) != 1):
            raise ValueError('Expected one existing App reference')
        app = next(iter(apps['apps'].values()))
        if (not isinstance(app, dict) or set(app) - {'id', 'required'}
                or not isinstance(app.get('id'), str)
                or not re.fullmatch(r'asdk_app_[0-9a-f]{32}', app['id'])
                or ('required' in app and type(app['required']) is not bool)):
            raise ValueError('Unsupported existing App reference')
        connect_url = https_url(connect_url)
        files = _skills.collect(template, connect_url)
        onboarding = './skills/whatsapp-setup/SKILL.md'
        # Preserve all App-owned values, including defaultPrompt=null and [].
        manifest = {key: legacy[key] for key in ('name', 'version', 'description', 'author')}
        manifest.update({'$schema': PLUGIN_SCHEMA, 'version': version,
                         'extensions': {'com.openai': {'apps': legacy['apps'],
                                        'interface': interface, 'onboardingSkill': onboarding}}})
        overlay = {**legacy, 'version': version, 'skills': './skills/',
                   'extensions': {'com.openai': {'onboardingSkill': onboarding}}}
        files.update({'plugin.json': encoded(manifest), '.codex-plugin/plugin.json': encoded(overlay),
                      '.app.json': baseline['.app.json']})
        return files
    except (KeyError, TypeError, AttributeError, UnicodeError) as exc:
        raise ValueError('Incomplete or invalid App source snapshot') from exc


def build_skill_update(output, *, snapshot, **options):
    files = skill_update_files(snapshot, **options)
    result = write_archive(output, files)
    if archive_files(output) != files:
        raise ValueError('Candidate archive differs from verified files')
    return {**result, 'mode': 'app-skills-update', 'name': snapshot['plugin']['name'],
            'version': options['version'], 'plugin_id': options['expected_plugin_id'],
            'expected_release_id': options['expected_release_id'], 'delete_paths': [],
            'skills': sorted(name.split('/')[1] for name in files if name.endswith('/SKILL.md')),
            'app_bytes_preserved': True, 'presentation_preserved': True,
            'published': False, 'live_release_guard_verified_by_builder': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['web', 'portable', 'app-skills-update'], required=True)
    parser.add_argument('--name')
    parser.add_argument('--version')
    parser.add_argument('--connect-url')
    parser.add_argument('--app-id')
    parser.add_argument('--mcp-url')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--validate-zip', type=Path, help='Read-only inspection of a complete standalone package')
    parser.add_argument('--expected-name', help='Verified internal name when inspecting an update')
    parser.add_argument('--source-snapshot', type=Path, help='Complete normalized get_plugin_files JSON; never credentials')
    parser.add_argument('--expected-plugin-id')
    parser.add_argument('--expected-release-id')
    args = vars(parser.parse_args())
    validate_zip = args.pop('validate_zip')
    expected_name = args.pop('expected_name')
    output = args.pop('output')
    source_snapshot = args.pop('source_snapshot')
    expected_plugin_id = args.pop('expected_plugin_id')
    expected_release_id = args.pop('expected_release_id')
    try:
        if args['mode'] == 'app-skills-update':
            if (not source_snapshot or not expected_plugin_id or not expected_release_id
                    or not output or not args['version'] or not args['connect_url']
                    or validate_zip or expected_name or any(args[key] for key in ('name', 'app_id', 'mcp_url'))):
                raise ValueError('Skill update requires source snapshot, identity/release guard, version, connect URL and output only')
            result = build_skill_update(output, snapshot=manifest_json(source_snapshot.read_bytes()),
                                        expected_plugin_id=expected_plugin_id, expected_release_id=expected_release_id,
                                        version=args['version'], connect_url=args['connect_url'])
        elif source_snapshot or expected_plugin_id or expected_release_id:
            raise ValueError('Source snapshot and release guard belong only to app-skills-update')
        elif validate_zip:
            if output or any(args[key] for key in ('name','version','connect_url','mcp_url')):
                raise ValueError('Inspection does not build or update a package')
            result = validate_archive(validate_zip, mode=args['mode'], app_id=args['app_id'], expected_name=expected_name)
        else:
            if expected_name or not output or any(not args[key] for key in ('name','version','connect_url')):
                raise ValueError('Build requires output, name, version and connect URL')
            result = build(output, **args)
        print(json.dumps(result, indent=2))
    except (ValueError, FileExistsError, FileNotFoundError, zipfile.BadZipFile) as exc: parser.error(str(exc))

if __name__ == '__main__':
    main()

