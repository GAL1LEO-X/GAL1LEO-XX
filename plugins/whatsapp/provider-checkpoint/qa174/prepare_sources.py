#!/usr/bin/env python3
"""Reapply QA174 to verified retained archives and produce deterministic local sources.

No download, package installation, image build or release operation is performed.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare(kind, archive, output, manifest):
    checkpoint = Path(__file__).resolve().parent
    spec = manifest['sources'][kind]
    if digest(archive) != spec['base_archive_sha256']:
        raise ValueError(f'{kind}: incorrect base archive')
    patch = checkpoint / (kind + '.patch')
    if digest(patch) != spec['patch_sha256']:
        raise ValueError(f'{kind}: incorrect patch')
    root = output / kind
    root.mkdir()
    members = set()
    with tarfile.open(archive) as source:
        for item in source:
            parts = PurePosixPath(item.name).parts
            if not parts or parts[0] != spec['archive_root'] or '..' in parts:
                raise ValueError('Unexpected corresponding-source path')
            if len(parts) == 1:
                continue
            item.name = str(PurePosixPath(*parts[1:]))
            if not (item.isfile() or item.isdir() or
                    (item.issym() and item.name == 'CLAUDE.md' and item.linkname == 'AGENTS.md')):
                raise ValueError('Unexpected corresponding-source member')
            source.extract(item, root, filter='data')
            if not item.isdir():
                members.add(item.name)
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    subprocess.run(['git', '-C', str(root), 'apply', '--check', str(patch)], check=True)
    subprocess.run(['git', '-C', str(root), 'apply', str(patch)], check=True)
    members.update(spec['changed_paths'])
    inventory = {name: digest(root / name) if not (root / name).is_symlink()
                 else 'symlink:' + (root / name).readlink().as_posix()
                 for name in sorted(members) if (root / name).exists()}
    provenance = {
        'status': 'local_source_candidate_not_published_or_installed',
        'base_archive_sha256': spec['base_archive_sha256'],
        'patch_sha256': spec['patch_sha256'],
        'source_inventory_sha256': hashlib.sha256(
            json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'base_metadata': 'Any inherited BUILD-PROVENANCE.json describes only the base release.',
        'runtime_qualification': 'See separate native-build receipt; OCI execution is not attested.',
    }
    (root / 'QA174-SOURCE-PROVENANCE.json').write_text(json.dumps(provenance, indent=2) + '\n')
    members.add('QA174-SOURCE-PROVENANCE.json')
    target = output / (kind + '-source-qa174-local.tar.gz')
    with target.open('xb') as stream, gzip.GzipFile(filename='', fileobj=stream, mode='wb', mtime=0) as zipped, tarfile.open(fileobj=zipped, mode='w|') as packaged:
        for name in sorted(members):
            path = root / name
            info = tarfile.TarInfo(kind + '-source-qa174/' + name)
            info.uid = info.gid = info.mtime = 0
            if path.is_symlink():
                info.type = tarfile.SYMTYPE
                info.linkname = path.readlink().as_posix()
                info.mode = 0o777
                packaged.addfile(info)
            else:
                content = path.read_bytes()
                info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                info.size = len(content)
                packaged.addfile(info, io.BytesIO(content))
    return {**provenance, 'archive': target.name, 'archive_sha256': digest(target),
            'archive_bytes': target.stat().st_size, 'files': len(members)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--waha-archive', required=True, type=Path)
    parser.add_argument('--gows-archive', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='New directory; existing output is refused')
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads(Path(__file__).with_name('manifest.json').read_text())
    result = {kind: prepare(kind, getattr(args, kind + '_archive'), args.output, manifest)
              for kind in ('waha', 'gows')}
    (args.output / 'source-receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
