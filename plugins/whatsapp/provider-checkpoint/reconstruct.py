"""Reconstruct companion provider sources from public upstreams and verified patches.

No accounts, runtime services, private release assets or installed containers are
accessed. Output must be a new directory. Compilation is a separate operation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
STEPS = ('qa120', 'qa125', 'qa129', 'qa131', 'qa136', 'qa158', 'qa162', 'qa174')


def command(folder, *args):
    return subprocess.check_output(['git', '-C', str(folder), *args], text=True).strip()


def patches(root=ROOT):
    baseline = json.loads((root / 'patches/manifest.json').read_text())
    records = []
    for provider in baseline['providers']:
        records.append((provider['name'], root / 'patches' / provider['patch'],
                        provider['patch_sha256'], provider['base_tree'], provider['patched_tree']))
    for step in STEPS:
        manifest = json.loads((root / step / 'manifest.json').read_text())
        for name in ('gows', 'waha'):
            file = root / step / (name + '.patch')
            if not file.is_file():
                continue
            record = manifest.get('sources', {}).get(name, manifest.get(name, manifest))
            records.append((name, file, record['patch_sha256'],
                            record.get('base_tree', record.get('base_patched_tree', record.get('base_gows_tree'))),
                            record.get('candidate_tree')))
    for name, file, digest, before, after in records:
        if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            raise ValueError('Patch hash mismatch: ' + str(file.relative_to(root)))
    return baseline, records


def reconstruct(output, *, root=ROOT):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink() or output.parent != output.parent.resolve(strict=True):
        raise ValueError('Output must be a new directory under a physical parent')
    baseline, records = patches(root)
    output.mkdir()
    for provider in baseline['providers']:
        folder = output / provider['name']
        subprocess.run(['git', 'init', '-q', str(folder)], check=True)
        command(folder, 'config', 'core.autocrlf', 'false')
        command(folder, 'remote', 'add', 'origin', provider['upstream_url'])
        command(folder, 'fetch', '--depth=1', 'origin', provider['base_commit'])
        command(folder, 'checkout', '--detach', provider['base_commit'])
        if command(folder, 'write-tree') != provider['base_tree']:
            raise ValueError('Upstream tree differs from its pin')
    for name, file, digest, before, after in records:
        folder = output / name
        if before and command(folder, 'write-tree') != before:
            raise ValueError('Patch base tree mismatch: ' + str(file.relative_to(root)))
        command(folder, 'apply', '--check', '--index', '--whitespace=error-all', str(file))
        command(folder, 'apply', '--index', '--whitespace=error-all', str(file))
        if after and command(folder, 'write-tree') != after:
            raise ValueError('Patch result differs from its recorded tree')
    result = {
        'format': 'gal1leo-public-provider-sources-v1',
        'provider_version': '0.8.7',
        'trees': {name: command(output / name, 'write-tree') for name in ('gows', 'waha')},
        'patches': {file.relative_to(root).as_posix(): digest for _, file, digest, _, _ in records},
        'compiled': False,
        'live_account_tested': False,
    }
    expected = root / 'public-sources.lock.json'
    if expected.exists() and json.loads(expected.read_text())['trees'] != result['trees']:
        raise ValueError('Reconstructed sources differ from the public tree lock')
    (output / 'reconstruction.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(reconstruct(args.output), indent=2))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, 'Provider reconstruction failed: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
