#!/usr/bin/env python3
"""Offline native qualification; inputs/dependencies must already be present.

This does not qualify an OCI runtime or publish/change the provider lock.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--waha', required=True, type=Path)
    parser.add_argument('--gows', required=True, type=Path)
    parser.add_argument('--go', required=True, type=Path)
    parser.add_argument('--library-root', type=Path, help='Optional retained compiler rootfs with native libraries')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOENV='off', GOPROXY='off',
               GOSUMDB='off', GOMAXPROCS='2', CGO_ENABLED='1', GOOS='linux', GOARCH='amd64',
               GOAMD64='v1', TZ='UTC', LC_ALL='C')
    for key in ('GOCACHE', 'GOPATH', 'GOMODCACHE'):
        location = out / key.lower()
        location.mkdir()
        env[key] = str(location)
    execution = []
    if args.library_root:
        root = args.library_root.resolve()
        lib = root / 'usr/lib/x86_64-linux-gnu'
        env['PKG_CONFIG_SYSROOT_DIR'] = str(root)
        env['PKG_CONFIG_LIBDIR'] = str(lib / 'pkgconfig') + ':' + str(root / 'usr/share/pkgconfig')
        env['CGO_LDFLAGS'] = '-Wl,-rpath-link,' + str(lib)
        execution = ['-exec=' + str(lib / 'ld-linux-x86-64.so.2') + ' --library-path ' + str(lib)]
    records = []
    def run(name, command, cwd, run_env=env, timeout=240):
        started = time.monotonic()
        with (out / (name + '.log')).open('w') as stream:
            result = subprocess.run(command, cwd=cwd, env=run_env, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=timeout)
        record = {'name': name, 'command': command, 'returncode': result.returncode,
                  'seconds': round(time.monotonic() - started, 3), 'log_sha256': digest(out / (name + '.log'))}
        records.append(record)
        (out / 'checks.json').write_text(json.dumps(records, indent=2) + '\n')
        print(json.dumps(record), flush=True)
        if result.returncode:
            raise SystemExit(result.returncode)
    node = shutil.which('node')
    run('node-version', [node, '--version'], args.waha)
    run('go-version', [str(args.go), 'version'], args.gows)
    run('gcc-version', ['gcc', '--version'], args.gows)
    run('waha-source', [node, 'checkpoints/offline-ab/qa174.test.cjs'], args.waha)
    run('waha-build', [node, 'node_modules/@nestjs/cli/bin/nest.js', 'build'], args.waha)
    run('waha-compiled', [node, 'checkpoints/offline-ab/qa174-compiled.test.cjs'], args.waha)
    go = str(args.go)
    run('gows-regressions', [go, 'test', '-p=2', '-mod=vendor', '-count=1', '-timeout=90s', *execution,
                           './gows', './storage/sqlstorage', '-run', '^Test(GroupLeave|OwnGroupIdentity|VerifiedOwnPNAndLID|ReceiptVerified)'], args.gows / 'src')
    run('group-helpers', [go, 'test', '-p=2', '-mod=vendor', '-count=1', '-timeout=60s', *execution,
                          './storage/helpers'], args.gows / 'src')
    flags = ['build', '-p=2', '-mod=vendor', '-trimpath', '-buildvcs=false', '-pgo=off',
             '-ldflags=-buildid= -linkmode=external -extldflags=-Wl,--build-id=none']
    first = out / 'gows-linux-amd64-a'
    run('gows-build-a', [go, *flags, '-o', str(first), '.'], args.gows / 'src')
    second_source = out / 'independent-source'
    shutil.copytree(args.gows, second_source, ignore=shutil.ignore_patterns('.git'))
    second_cache = out / 'independent-cache'
    second_cache.mkdir()
    second = out / 'gows-linux-amd64-b'
    run('gows-build-b', [go, *flags, '-o', str(second), '.'], second_source / 'src',
        dict(env, GOCACHE=str(second_cache)), timeout=300)
    receipt = {'status': 'local_native_candidate_not_OCI_qualified',
               'compiler': 'Go input above plus host GCC; not asserted equivalent to the retained compiler image',
               'gows_sha256': digest(first), 'second_gows_sha256': digest(second),
               'identical': digest(first) == digest(second), 'gows_bytes': first.stat().st_size,
               'waha_dist_inventory': {str(path.relative_to(args.waha / 'dist')): digest(path)
                                       for path in sorted((args.waha / 'dist').rglob('*')) if path.is_file()}}
    (out / 'native-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if not receipt['identical']:
        raise SystemExit('Independent native builds differ')


if __name__ == '__main__':
    main()
