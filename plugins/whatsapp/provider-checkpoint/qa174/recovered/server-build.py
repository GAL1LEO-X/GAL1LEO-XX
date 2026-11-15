"""QA163 COPY-only assembly adapted to QA174. Rootless stores; never deploys."""
from pathlib import Path
import argparse, fcntl, gzip, hashlib, io, json, os, pwd, re, shutil, stat, subprocess, tarfile

ROOT = Path('/var/tmp/qa174-provider-81f98a4')
BASE = 'sha256:f0a3c175db2a5d04b48a5dd1989899bb2a535950371f96b74e145683b770f26c'
PROFILE = '4ada47f11ccc007ff82768c7bff773ae68ed6ea0120f95442a3c628af0c5ba8e'
SOURCE = '81f98a44a41ccb805bcbb74ca31e60111beb0126'
TAG = 'localhost/qa174-whatsapp-runtime:81f98a4'
ARCHIVE_NAME = 'whatsapp-runtime-qa174-linux-amd64.oci.tar'

def require(ok, message):
    if not ok: raise RuntimeError(message)

def sha(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()

def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def save(path, data):
    with Path(path).open('x') as stream:
        json.dump(data, stream, indent=2, sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())

def inventory(root):
    result = {}
    require(root.is_dir() and not root.is_symlink(), 'Missing or linked input directory')
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(parent) / name
            require(not path.is_symlink(), 'Input symlink: ' + str(path))
            require(path.is_dir() or path.is_file(), 'Special input file: ' + str(path))
            if path.is_file(): result[path.relative_to(root).as_posix()] = sha(path)
    return dict(sorted(result.items()))

def validate_inputs(root, reviewed):
    require(re.fullmatch('[a-f0-9]{64}', reviewed or ''), 'Reviewed manifest SHA256 required')
    path = root / 'input-manifest.json'
    require(not path.is_symlink() and sha(path) == reviewed, 'Input manifest changed')
    manifest = json.loads(path.read_text())
    require(manifest['schema_version'] == 1 and manifest['status'] == 'inputs_qualified_not_runtime_qualified', 'Inputs not qualified')
    require(manifest['source_commit'] == SOURCE and manifest['staging'] == str(ROOT), 'Source/staging mismatch')
    require(manifest['base']['config_digest'] == BASE and manifest['profile_sha256'] == PROFILE, 'Base/profile mismatch')
    for name, pin in manifest['files'].items():
        require(not name.startswith('/') and '..' not in Path(name).parts, 'Unsafe input path')
        item = root / name
        require(item.is_file() and not item.is_symlink() and item.stat().st_size == pin['bytes'] and sha(item) == pin['sha256'], 'Input changed: ' + name)
    full = json.loads((root / 'dist-inventory.json').read_text())
    require(len(full) == 2067 and hashlib.sha256(canonical(full)).hexdigest() == manifest['waha']['full_inventory_sha256'], 'Full dist inventory changed')
    runtime = {name: value for name, value in full.items() if name.split('/')[0] not in ('dashboard', 'plus')}
    require(inventory(root / 'context/dist') == runtime, 'Runtime dist differs from compiled inventory')
    expected = json.loads((root / 'offline/expected.json').read_text())
    require(expected['dist'] == runtime, 'Probe inventory mismatch')
    require(set(inventory(root / 'context')) == {'Dockerfile', 'gows'} | {'dist/' + n for n in runtime}, 'Unexpected build-context input')
    require(set(inventory(root / 'offline')) == {n[8:] for n in manifest['files'] if n.startswith('offline/')}, 'Unexpected offline fixture')
    native = json.loads((root / 'native-qualification.json').read_text())
    require(native['passed'] is True and native['binary']['independent_builds_identical'] is True, 'Native qualification failed')
    require(native['binary']['sha256'] == manifest['files']['context/gows']['sha256'] and native['binary']['bytes'] == manifest['files']['context/gows']['bytes'], 'Native binary mismatch')
    require(all(s['passed'] and s['exit_code'] == 0 and not s['oom_killed'] for s in native['steps']) and all(x['removed'] for x in native['cleanup']), 'Native execution incomplete')
    complete = json.loads((root / 'native-complete-handoff.json').read_text())
    require(complete['passed'] is True and complete['all_nine_owned_containers_removed'] is True and complete['gows_sha256'] == native['binary']['sha256'], 'Complete native qualification failed')
    require(complete['initial_result_sha256'] == sha(root / 'native-qualification.json') and complete['additional_result_sha256'] == sha(root / 'native-additional-qualification.json'), 'Native receipt chain changed')
    waha = json.loads((root / 'waha-qualification.json').read_text())
    require(waha['waha_dual_build_identical'] is True and all(c['returncode'] == 0 for c in waha['checks']) and waha['waha_dist_inventory'] == full, 'WAHA compilation/qualification failed')
    sources = json.loads((root / 'provider-source-manifest.json').read_text())['sources']
    require(complete['source_archive_sha256'] == sources['gows']['local_archive_sha256'] and waha['source_archives']['waha']['archive_sha256'] == sources['waha']['local_archive_sha256'], 'Source provenance differs from checkpoint')
    return manifest, runtime

def host_profile():
    require(os.geteuid() == 0 and sha('/etc/whatsapp/deploy-hooks.json') == PROFILE, 'Root/current pinned profile required')
    profile = json.loads(Path('/etc/whatsapp/deploy-hooks.json').read_text())
    require([r['slug'] for r in profile['instances']] == ['personal', 'secondary'], 'Instance list changed')
    for row, ids in zip(profile['instances'], ((978, 972), (977, 971))):
        identity = pwd.getpwnam(row['user'])
        require((row['uid'], identity.pw_uid, identity.pw_gid) == (ids[0], *ids), 'Instance identity changed')
    require(not Path(profile['gate']).exists(), 'Maintenance gate present')
    return profile

def acquire_locks():
    held = []
    for path in ('/var/lib/gal1leo-deploy/host.lock', '/srv/whatsapp/deploy-v1/deploy.lock'):
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW); held.append(fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return held

def podman(row, *args, timeout=90, check=True):
    command = ['runuser', '-u', row['user'], '--', 'env', 'XDG_RUNTIME_DIR=/run/user/' + str(row['uid']),
               'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(row['uid']) + '/bus', 'podman', *args]
    try: result = subprocess.run(command, cwd='/', capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired: raise RuntimeError('Podman ' + args[0] + ' timed out; reconcile receipt/state before retry') from None
    require(len(result.stdout) + len(result.stderr) <= 4 * 1024 * 1024, 'Podman output limit exceeded')
    require(not check or result.returncode == 0, 'Podman ' + args[0] + ' failed, exit=' + str(result.returncode) + ': ' + result.stderr[-4096:])
    return result

def image_snapshot(row, identifier):
    fmt = '{"id":{{json .ID}},"os":{{json .Os}},"arch":{{json .Architecture}},"layers":{{json .RootFS.Layers}}}'
    value = json.loads(podman(row, 'image', 'inspect', '--format', fmt, identifier).stdout)
    require(value['id'].removeprefix('sha256:') == identifier.removeprefix('sha256:') and value['os'] == 'linux' and value['arch'] == 'amd64', 'Image identity/platform mismatch')
    return value

def production_snapshot(profile):
    result = {}
    fmt = '{"id":{{json .ID}},"image":{{json .Image}},"running":{{json .State.Running}},"started_at":{{json .State.StartedAt}}}'
    for row in profile['instances']:
        container = json.loads(podman(row, 'inspect', '--format', fmt, 'whatsapp-waha').stdout)
        require(container['running'] is True and container['image'].removeprefix('sha256:') == BASE[7:], 'Production state differs from preflight')
        image = image_snapshot(row, BASE)
        require(len(image['layers']) == 12, 'Base layer count changed')
        result[row['slug']] = {'container': container, 'image': image}
    return result

def oci_metadata(archive):
    members = archive.getmembers()
    require(len({m.name for m in members}) == len(members), 'Duplicate archive members')
    for member in members:
        require((member.isfile() or member.isdir()) and not member.name.startswith('/') and '..' not in Path(member.name).parts, 'Unsafe OCI member')
    def read(name, digest=None):
        member = archive.getmember(name)
        require(member.isfile() and member.size < 8 * 1024 * 1024, 'OCI metadata too large')
        raw = archive.extractfile(member).read()
        require(digest is None or 'sha256:' + hashlib.sha256(raw).hexdigest() == digest, 'OCI metadata digest mismatch')
        return json.loads(raw)
    index = read('index.json'); require(len(index['manifests']) == 1, 'Single OCI manifest required')
    md = index['manifests'][0]['digest']; require(re.fullmatch('sha256:[a-f0-9]{64}', md), 'Invalid manifest digest')
    manifest = read('blobs/sha256/' + md[7:], md)
    cid = manifest['config']['digest']; require(re.fullmatch('sha256:[a-f0-9]{64}', cid), 'Invalid config digest')
    return md, manifest, read('blobs/sha256/' + cid[7:], cid)

def verify_overlay(archive, manifest, config, base_manifest, base_config, runtime, gows):
    require(config['config'] == base_config['config'], 'Runtime configuration changed')
    require(config['os'] == 'linux' and config['architecture'] == 'amd64', 'Candidate platform changed')
    layers = manifest['layers']; base_count = len(base_manifest['layers'])
    require(base_count == 12 and 1 <= len(layers) - base_count <= 2, 'Unexpected number of new layers')
    require(config['rootfs']['diff_ids'][:base_count] == base_config['rootfs']['diff_ids'] and len(config['rootfs']['diff_ids']) == len(layers), 'Base layer chain changed')
    expected = {'app/dist/' + n: h for n, h in runtime.items()}; expected['app/gows'] = gows
    directories = {str(parent) for n in expected for parent in Path(n).parents if str(parent) != '.'}
    observed = {}
    for index, layer in enumerate(layers):
        name = 'blobs/sha256/' + layer['digest'][7:]; member = archive.getmember(name)
        require(member.size == layer['size'] and 'sha256:' + hashlib.file_digest(archive.extractfile(member), 'sha256').hexdigest() == layer['digest'], 'Layer bytes/digest mismatch')
        with archive.extractfile(member) as raw:
            compressed = raw.read(2) == b'\x1f\x8b'; raw.seek(0)
            stream = gzip.GzipFile(fileobj=raw) if compressed else raw
            require('sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest() == config['rootfs']['diff_ids'][index], 'Layer diff ID mismatch')
        if index < base_count: continue
        with archive.extractfile(member) as stream, tarfile.open(fileobj=stream, mode='r|*') as layer_tar:
            for entry in layer_tar:
                path = entry.name.removeprefix('./').rstrip('/')
                require(entry.uid == entry.gid == 0, 'New layer ownership changed')
                if entry.isdir(): require(path in directories and stat.S_IMODE(entry.mode) == 0o755, 'Unexpected layer directory/mode')
                else:
                    require(entry.isfile() and path in expected and path not in observed, 'Unexpected/duplicate layer file: ' + path)
                    require(stat.S_IMODE(entry.mode) == (0o755 if path == 'app/gows' else 0o644), 'New layer file mode changed')
                    observed[path] = hashlib.file_digest(layer_tar.extractfile(entry), 'sha256').hexdigest()
    require(observed.get('app/gows') == gows and all(expected[n] == h for n, h in observed.items()), 'Overlay delta differs from exact input inventory')
    require(any(n.startswith('app/dist/') for n in observed), 'No updated WAHA file in overlay')
    # Buildah may omit byte-identical copies. The unchanged probe checks the full
    # merged /app/dist inventory, including rejection of stale base files.
    return len(layers) - base_count, len(observed)

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--manifest-sha256', required=True); args = parser.parse_args()
    os.umask(0o077)
    require(Path(__file__).resolve().parent == ROOT and ROOT.is_dir() and not ROOT.is_symlink(), 'Wrong staging path')
    manifest, runtime = validate_inputs(ROOT, args.manifest_sha256)
    held = acquire_locks(); profile = host_profile()
    for parent in (ROOT / 'context', ROOT / 'offline'):
        for path in [parent, *parent.rglob('*')]:
            mode = 0o755 if path.is_dir() or path.name == 'gows' else 0o644
            require(path.stat().st_uid == 0 and path.stat().st_gid == 0 and stat.S_IMODE(path.stat().st_mode) == mode, 'Staged ownership/mode differs: ' + str(path))
    before = production_snapshot(profile); row = profile['instances'][0]
    base_archive = Path(manifest['base']['archive_path'])
    require(base_archive.stat().st_size == manifest['base']['archive_bytes'] and sha(base_archive) == manifest['base']['archive_sha256'], 'QA163 base archive changed')
    with tarfile.open(base_archive) as source:
        base_md, base_manifest, base_config = oci_metadata(source)
    require(base_md == manifest['base']['manifest_digest'] and base_manifest['config']['digest'] == BASE, 'Base OCI identity changed')
    require(base_config['rootfs']['diff_ids'] == before[row['slug']]['image']['layers'], 'Store base differs from archive')
    require(shutil.disk_usage(ROOT).free >= 2 * base_archive.stat().st_size + 512 * 1024 * 1024, 'Insufficient staging space; no cleanup performed')
    require(not (ROOT / ARCHIVE_NAME).exists() and not (ROOT / 'runtime-podman.oci.tar').exists(), 'Prior output exists; inspect before retry')
    save(ROOT / 'build-intent.json', {'source_commit': SOURCE, 'manifest_sha256': args.manifest_sha256, 'base': BASE, 'production_before': before, 'network': 'none', 'services_changed': False})
    result = {'passed': False, 'source_commit': SOURCE, 'manifest_sha256': args.manifest_sha256}
    try:
        log = podman(row, 'build', '--pull=never', '--network=none', '--layers=false', '--identity-label=false', '--format=oci', '--tag', TAG, '--file', str(ROOT / 'context/Dockerfile'), str(ROOT / 'context'), timeout=600)
        (ROOT / 'build.log').write_text((log.stdout + log.stderr)[-65536:])
        fmt = '{{json .ID}}'; cid = 'sha256:' + json.loads(podman(row, 'image', 'inspect', '--format', fmt, TAG).stdout).removeprefix('sha256:')
        candidate = image_snapshot(row, cid)
        require(candidate['layers'][:12] == before[row['slug']]['image']['layers'], 'Candidate base chain changed')
        export = ROOT / 'export'; export.mkdir(mode=0o700); identity = pwd.getpwnam(row['user']); os.chown(export, identity.pw_uid, identity.pw_gid)
        raw = ROOT / 'runtime-podman.oci.tar'
        podman(row, 'save', '--format=oci-archive', '--output', str(export / raw.name), cid, timeout=600)
        os.rename(export / raw.name, raw); os.chown(raw, 0, 0); raw.chmod(0o600)
        archive_path = ROOT / ARCHIVE_NAME
        with tarfile.open(raw) as incoming:
            md, image_manifest, config = oci_metadata(incoming)
            require(image_manifest['config']['digest'] == cid and config['rootfs']['diff_ids'] == candidate['layers'], 'Saved candidate identity changed')
            added, overlay_files = verify_overlay(incoming, image_manifest, config, base_manifest, base_config, runtime, manifest['files']['context/gows']['sha256'])
            with tarfile.open(archive_path, 'x') as output:
                for member in incoming.getmembers():
                    require(member.name != 'manifest.json', 'Unexpected existing compatibility manifest')
                    output.addfile(member, incoming.extractfile(member) if member.isfile() else None)
                body = canonical([{'Config': 'blobs/sha256/' + cid[7:], 'RepoTags': [TAG], 'Layers': ['blobs/sha256/' + x['digest'][7:] for x in image_manifest['layers']]}])
                member = tarfile.TarInfo('manifest.json'); member.mode = 0o644; member.size = len(body); output.addfile(member, io.BytesIO(body))
        archive_path.chmod(0o644)
        metadata = {'archive_sha256': sha(archive_path), 'archive_bytes': archive_path.stat().st_size, 'manifest_digest': md, 'config_digest': cid, 'gows_sha256': manifest['files']['context/gows']['sha256'], 'input_manifest_sha256': args.manifest_sha256, 'source_commit': SOURCE}
        result.update(passed=True, config_digest=cid, base_layers_preserved=12, added_layers=added, overlay_files=overlay_files, runtime_config_unchanged=True, merged_inventory_requires_runtime_probe=True)
    except Exception as error:
        result['error'] = str(error)[:2048]
    finally:
        try:
            require(host_profile() == profile and production_snapshot(profile) == before, 'Production/profile changed during assembly')
            result['production_containers_and_images_unchanged'] = True
        except Exception as error: result.update(passed=False, preservation_error=str(error)[:2048])
        save(ROOT / 'build-result.json', result)
    require(result['passed'], 'Assembly failed; inspect build-result.json before retry')
    save(ROOT / 'runtime-metadata.json', metadata)
    print(json.dumps(result), flush=True)

if __name__ == '__main__': main()
