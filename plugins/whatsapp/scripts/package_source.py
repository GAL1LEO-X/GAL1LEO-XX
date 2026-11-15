"""Snapshot public source files without requiring Git on the installed host.

This is the source portion of a runtime backup, not its private configuration.
Generated prepared/dist/build trees and arbitrary configuration files are not
source inputs. New public data formats must be added explicitly below.
"""
import argparse
import io
import os
from pathlib import Path
import re
import stat
import tarfile
import zipfile


ROOT_FILES = {'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'pyproject.toml', 'project.json', 'requirements.lock', 'requirements-test.lock',
              'requirements-transcription.in', 'requirements-transcription.lock', 'transcription-model.json',
              '.gitignore', 'README.md', 'AGENTS.md'}
PUBLIC_DATA = {'provider-checkpoint/reconstruct.py', 'provider-checkpoint/public-sources.lock.json', 'provider-checkpoint/licenses/waha-APACHE-2.0.txt', 'provider-checkpoint/licenses/gows-APACHE-2.0.txt',
    'sally_whatsapp/operations.json',
    'sally_whatsapp/assets/connect.css', 'sally_whatsapp/assets/connect.js',
    'sally_whatsapp/assets/admin.css', 'sally_whatsapp/assets/admin.js',
    'sally_whatsapp/assets/whatsapp-gpt.png',
    'sally_whatsapp/migrations/6-7.sql', 'sally_whatsapp/migrations/7-8.sql',
    'scripts/validate_linux.sh',
    'scripts/backup_schemas/6.sql', 'scripts/backup_schemas/7.sql', 'scripts/backup_schemas/8.sql',
    'deploy/6-7.sql', 'deploy/7-8.sql', 'deploy/migrations.json', 'deploy/images.lock.json',
    'deploy/apache-whatsapp.conf.in', 'deploy/bridge.example.toml',
    'deploy/chatgpt-connection.example.json', 'deploy/instance.example.json',
    'deploy/installation.example.json', 'deploy/secondary-next/bridge.example.toml',
    'deploy/secondary-next/chatgpt-connection.example.json',
    'deploy/whatsapp-personal.service', 'deploy/whatsapp-resource-priority.service',
    'deploy/whatsapp-personal-backup.service', 'deploy/whatsapp-personal-backup.timer',
    'deploy/develative-whatsapp-recovery.service', 'deploy/develative-whatsapp-recovery.timer',
    'deploy/whatsapp-waha.container',
    'plugin/plugin.json', 'plugin/mcp.json.in', 'plugin/assets/whatsapp-gpt.png',
    'plugin/skills/whatsapp-setup/SKILL.md',
    'plugin/skills/whatsapp-use/SKILL.md',
    'plugin/skills/whatsapp-use/references/reading.md',
    'plugin/skills/whatsapp-use/references/actions-and-events.md',
    'plugin/skills/whatsapp-transcription/SKILL.md',
    'qa/browser_peer.mjs', 'tests/browser_peer.test.mjs',
    'tests/fixtures/media-integrity/README.md',
    'tests/fixtures/media-integrity/manifest.json',
    'tests/fixtures/media-integrity/sample.docx',
    'tests/fixtures/media-integrity/sample.jpg',
    'tests/fixtures/media-integrity/sample.mp4',
    'tests/fixtures/media-integrity/sample.ogg',
    'tests/fixtures/media-integrity/sample.pdf',
    'tests/fixtures/media-integrity/sample.png',
    'tests/fixtures/media-integrity/sample.txt',
    'tests/fixtures/media-integrity/sample.wav',
    'tests/fixtures/media-integrity/sample.webp',
    'tests/fixtures/schema6.sql', 'tests/fixtures/waha_2026_9_2_preview_openapi.json',
    'tests/fixtures/LEGACY-SOURCES.md', 'tests/fixtures/backup_runtime_049.py.txt',
    'tests/fixtures/tenant_admin_legacy_20261017.py.txt',
    'tests/fixtures/provision_host_legacy_20261017.py.txt',
    'tests/fixtures/recovery_services_777.py.txt',
    'tests/fixtures/admin_host_777.py.txt', 'tests/fixtures/admin_handoff_777.py.txt',
    'tests/fixtures/installation_layout_777.py.txt',
    'tests/fixtures/RECOVERY-COMPAT-SOURCES.md',
    'docs/probes/clear_coverage_copy.py',
    'docs/event-coverage.json', 'docs/validation-history.json',
    'provider-checkpoint/README.md',
    'provider-checkpoint/fixture-requests.json',
    'provider-checkpoint/run_vertical.py',
    'provider-checkpoint/test_plugin_routes.py',
    'provider-checkpoint/docs/capability-matrix.md',
    'provider-checkpoint/docs/architecture-and-installation.md',
    'provider-checkpoint/docs/problem-cause-fix-proof.md',
    'provider-checkpoint/patches/gows.patch',
    'provider-checkpoint/patches/waha.patch',
    'provider-checkpoint/patches/manifest.json',
    'provider-checkpoint/patches/README.md',
    'provider-checkpoint/patches/APACHE-2.0.txt',
    'provider-checkpoint/qa120/README.md',
    'provider-checkpoint/qa120/manifest.json',
    'provider-checkpoint/qa120/waha.patch',
    'provider-checkpoint/qa125/README.md', 'provider-checkpoint/qa125/manifest.json',
    'provider-checkpoint/qa125/gows.patch', 'provider-checkpoint/qa125/waha.patch',
    'provider-checkpoint/qa129/README.md', 'provider-checkpoint/qa129/manifest.json',
    'provider-checkpoint/qa129/waha.patch',
    'provider-checkpoint/qa129/Dockerfile.runtime', 'provider-checkpoint/qa129/runtime.dockerignore',
    'provider-checkpoint/qa131/README.md', 'provider-checkpoint/qa131/manifest.json',
    'provider-checkpoint/qa131/waha.patch',
    'provider-checkpoint/qa136/README.md', 'provider-checkpoint/qa136/manifest.json',
    'provider-checkpoint/qa136/gows.patch',
    'provider-checkpoint/qa137/README.md', 'provider-checkpoint/qa137/manifest.json',
    'provider-checkpoint/qa137/Dockerfile.runtime', 'provider-checkpoint/qa137/runtime.dockerignore',
    'provider-checkpoint/qa158/README.md', 'provider-checkpoint/qa158/manifest.json',
    'provider-checkpoint/qa158/gows.patch',
    'provider-checkpoint/qa158/Dockerfile.runtime', 'provider-checkpoint/qa158/runtime.dockerignore',
    'provider-checkpoint/qa162/README.md', 'provider-checkpoint/qa162/manifest.json',
    'provider-checkpoint/qa162/gows.patch',
    'provider-checkpoint/qa162/Dockerfile.runtime', 'provider-checkpoint/qa162/runtime.dockerignore',
    'provider-checkpoint/qa174/README.md', 'provider-checkpoint/qa174/manifest.json',
    'provider-checkpoint/qa174/waha.patch', 'provider-checkpoint/qa174/gows.patch',
    'provider-checkpoint/qa174/prepare_sources.py', 'provider-checkpoint/qa174/qualify_native.py',
    'provider-checkpoint/qa174/export_candidate_openapi.cjs',
    'provider-checkpoint/qa174/Dockerfile.runtime', 'provider-checkpoint/qa174/oci-inputs.json',
    'provider-checkpoint/qa174/oci_archive.py', 'provider-checkpoint/qa174/probe-candidate.cjs',
    'provider-checkpoint/qa174/qualify_oci.py',
    'provider-checkpoint/qa174/OCI-QUALIFICATION.md',
    'provider-checkpoint/qa174/qualified-runtime.json',
    'provider-checkpoint/qa174/recovered/build_gows_harness.py',
    'provider-checkpoint/qa174/recovered/complete_remaining_packages.py',
    'provider-checkpoint/qa174/recovered/server-build.py',
    'provider-checkpoint/qa174/recovered/server-qualify.py',
    'provider-checkpoint/qa174/recovered/server-qualify-v2.py',
    'provider-checkpoint/qa174/recovered/run-compiled-tests.cjs',
    'provider-checkpoint/build/Dockerfile',
    'provider-checkpoint/build/.dockerignore',
    'provider-checkpoint/build/Dockerfile.gows-builder',
    'provider-checkpoint/build/README.md',
}
# Only code/documentation at the declared level is extensible. Data, assets and
# templates above are named exactly; e.g. an operator's deploy/config.toml,
# prepared/operator.env or scripts/as-user belongs to no public-source class.
SOURCE_PATTERNS = (
    r'(?:sally_whatsapp|scripts|qa)/[A-Za-z_][A-Za-z0-9_]*\.py',
    r'tests/(?:conftest|test_[A-Za-z0-9_]+)\.py',
    r'docs/[A-Za-z0-9][A-Za-z0-9_.-]*\.md',
)
DIRECTORIES = {'sally_whatsapp', 'scripts', 'tests', 'docs', 'qa'} | {
    parent.as_posix() for name in PUBLIC_DATA for parent in Path(name).parents
    if parent != Path('.')
}


def public_source(name):
    return name in ROOT_FILES or name in PUBLIC_DATA or any(re.fullmatch(pattern, name) for pattern in SOURCE_PATTERNS)


def read_regular(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError(f'Source must be a regular file without links: {path.name}')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            raise ValueError(f'Source changed before capture: {path.name}')
        content = stream.read()
        after = os.fstat(stream.fileno())
    if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
        raise ValueError(f'Source changed during capture: {path.name}')
    return content, opened


def capture(root):
    files = []
    # Parents are checked before children; symlink directories are never walked.
    for relative in ['', *sorted(DIRECTORIES, key=lambda name: (name.count('/'), name))]:
        directory = root / relative
        try:
            info = directory.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or directory.is_junction():
            raise ValueError(f'Source directory must not be a link: {relative or "."}')
        for path in sorted(directory.iterdir()):
            name = path.relative_to(root).as_posix()
            if public_source(name):
                content, metadata = read_regular(path)
                files.append((name, content, metadata))
    return sorted(files)


def package(root, output):
    files = capture(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Archive captured bytes, never ask an archive writer to follow filesystem
    # paths. Existing snapshots remain untouched if a source input is refused.
    if output.suffix == '.zip':
        with zipfile.ZipFile(output, 'x', zipfile.ZIP_DEFLATED) as archive:
            for name, content, metadata in files:
                info = zipfile.ZipInfo('whatsapp-personal/' + name)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | (metadata.st_mode & 0o777)) << 16
                archive.writestr(info, content)
    else:
        with tarfile.open(output, 'x:gz') as archive:
            for name, content, metadata in files:
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = metadata.st_mode & 0o777
                info.mtime = int(metadata.st_mtime)
                archive.addfile(info, io.BytesIO(content))
    return len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        count = package(Path(__file__).resolve().parents[1], args.output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f'Packaged {count} public source and configuration files')


if __name__ == '__main__':
    main()

