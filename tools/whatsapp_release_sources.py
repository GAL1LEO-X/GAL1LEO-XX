"""Build the two public source archives from an exact, reviewed Git commit.

Only the supplied output directory is written. Git export attributes and working
tree contents are deliberately ignored: snapshots come from verified blob
objects. Packaging is not a CI, provider, publication or deployment attestation.
Python 3.13+ is required by the committed WhatsApp source capture helper.
"""
from __future__ import annotations

import ast
import gzip
import hashlib
import io
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import runpy
import stat
import subprocess
import tarfile
import tempfile
import tomllib

if __package__:
    from .whatsapp_release_common import ReleaseError, validate_version
else:
    from whatsapp_release_common import ReleaseError, validate_version


def _require(condition, message):
    if not condition:
        raise ReleaseError(message)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _safe_name(name):
    return (isinstance(name, str) and bool(name) and name != '.' and '\\' not in name
            and '\0' not in name and not PureWindowsPath(name).drive
            and not PurePosixPath(name).is_absolute()
            and '..' not in PurePosixPath(name).parts
            and PurePosixPath(name).as_posix() == name
            and all(part.lower() != '.git' for part in PurePosixPath(name).parts))


def _git(repo, *args, data=None):
    try:
        return subprocess.run(['git', '--no-replace-objects', '-C', str(repo), *args],
                              input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        raise ReleaseError('Git could not read the requested committed source') from None


def _commit(repo, commit):
    _require(isinstance(commit, str) and re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', commit),
             'An exact Git commit ID is required')
    resolved = _git(repo, 'rev-parse', '--verify', '--end-of-options', commit + '^{commit}').decode().strip()
    _require(resolved == commit, 'The supplied object is not the exact commit')


def _physical_directory(path):
    path = Path(path).absolute()
    _require(path.resolve(strict=True) == path and path.is_dir(),
             'Expected an existing physical output directory')
    return path


def snapshot_commit(repo: Path, commit: str, destination: Path) -> dict:
    """Materialize verified Git blobs in a new directory; return their inventory.

    Links, submodules, unsafe paths and unexpected modes are refused before any
    snapshot file is written. The caller owns this new destination on failure.
    """
    try:
        repo = Path(repo).resolve(strict=True)
        _commit(repo, commit)
        destination = Path(destination).absolute()
        _physical_directory(destination.parent)
        _require(not os.path.lexists(destination), 'Snapshot destination must be absent')
        tree = {}
        for record in _git(repo, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
            if not record:
                continue
            header, raw_name = record.split(b'\t', 1)
            mode, kind, oid = header.decode('ascii').split()
            name = raw_name.decode('utf-8')
            _require(_safe_name(name) and name not in tree, 'Unsafe or duplicate Git source path')
            _require(kind == 'blob' and mode in {'100644', '100755'},
                     'Source tree contains a link, submodule or unsupported object')
            tree[name] = (int(mode[-3:], 8), oid)
        _require(tree, 'Committed source tree is empty')
        object_format = _git(repo, 'rev-parse', '--show-object-format').decode().strip()
        _require(object_format in {'sha1', 'sha256'}, 'Unsupported Git object format')
        # Batch blob reads use only object IDs obtained from the fixed commit.
        ordered = sorted(tree)
        blob_output = io.BytesIO(_git(repo, 'cat-file', '--batch',
                                    data=''.join(tree[name][1] + '\n' for name in ordered).encode('ascii')))
        files = []
        inventory = {}
        for name in ordered:
            mode, expected_oid = tree[name]
            oid, kind, raw_size = blob_output.readline().decode('ascii').split()
            size = int(raw_size)
            _require(oid == expected_oid and kind == 'blob' and size >= 0,
                     'Unexpected Git blob response')
            data = blob_output.read(size)
            _require(len(data) == size and blob_output.read(1) == b'\n', 'Truncated Git blob response')
            actual_oid = hashlib.new(object_format, b'blob ' + str(size).encode() + b'\0' + data).hexdigest()
            _require(actual_oid == expected_oid, 'Source content differs from its Git blob')
            files.append((name, data, mode))
            inventory[name] = {'bytes': size, 'sha256': _sha(data),
                               'mode': f'{mode:04o}', 'git_blob': oid}
        _require(not blob_output.read(1), 'Unexpected trailing Git blob data')
        destination.mkdir(mode=0o700)
        for name, data, mode in files:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(data)
            target.chmod(mode)
        return inventory
    except ReleaseError:
        raise
    except (OSError, ValueError, UnicodeError) as exc:
        raise ReleaseError('Could not snapshot committed source (' + type(exc).__name__ + ')') from None


def _archive_inputs(files, prefix, epoch):
    _require(_safe_name(prefix), 'Unsafe archive prefix')
    _require(type(epoch) is int and epoch >= 0, 'Archive epoch must be a nonnegative integer')
    result = list(files)
    names = set()
    for name, data, mode in result:
        _require(_safe_name(name) and name not in names, 'Unsafe or duplicate archive member')
        _require(isinstance(data, bytes) and type(mode) is int and mode in {0o644, 0o755},
                 'Archive members must contain regular source bytes and modes')
        names.add(name)
    _require(result, 'Source archive must not be empty')
    for name in names:
        _require(not any(parent.as_posix() in names for parent in PurePosixPath(name).parents),
                 'Archive member has a non-directory ancestor')
    return sorted(result)


def canonical_tar(path: Path, files: list[tuple[str, bytes, int]], prefix: str, epoch: int) -> None:
    """Write a new canonical tar/gzip; never overwrite an existing path."""
    created = None
    try:
        files = _archive_inputs(files, prefix, epoch)
        path = Path(path).absolute()
        _physical_directory(path.parent)
        with path.open('xb') as raw:
            metadata = os.fstat(raw.fileno())
            created = (metadata.st_dev, metadata.st_ino)
            with gzip.GzipFile(filename='', fileobj=raw, mode='wb', compresslevel=9, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                    for name, data, mode in files:
                        item = tarfile.TarInfo(prefix + '/' + name)
                        item.uid = item.gid = 0
                        item.uname = item.gname = ''
                        item.mode, item.mtime, item.size = mode, epoch, len(data)
                        archive.addfile(item, io.BytesIO(data))
    except Exception as exc:
        if created is not None:
            _remove_owned(path, created)
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError('Could not write canonical source archive (' + type(exc).__name__ + ')') from None


def _verify_tar(path, files, prefix, epoch):
    expected = {prefix + '/' + name: (data, mode) for name, data, mode in files}
    seen = set()
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            _require(member.isfile() and member.name in expected and member.name not in seen,
                     'Source archive contains an unexpected member')
            data, mode = expected[member.name]
            _require((member.uid, member.gid, member.uname, member.gname, member.mode,
                      member.mtime, member.size) == (0, 0, '', '', mode, epoch, len(data)),
                     'Source archive metadata differs from committed inputs')
            actual = archive.extractfile(member).read()
            _require(len(actual) == len(data) and _sha(actual) == _sha(data),
                     'Source archive member differs from committed inputs')
            seen.add(member.name)
    _require(seen == set(expected), 'Source archive omitted an expected member')


def _remove_owned(path, identity):
    try:
        current = path.lstat()
        if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
            path.unlink()
    except FileNotFoundError:
        pass


def verified_tar(path: Path, files: list[tuple[str, bytes, int]], prefix: str, epoch: int) -> dict:
    """Compare two canonical builds, then reread the exclusively created output."""
    created = None
    try:
        files = _archive_inputs(files, prefix, epoch)
        path = Path(path).absolute()
        parent = _physical_directory(path.parent)
        _require(not os.path.lexists(path), 'Source archive output already exists')
        with tempfile.TemporaryDirectory(prefix='.source-tar-', dir=parent) as temporary:
            first, second = Path(temporary) / 'one.tar.gz', Path(temporary) / 'two.tar.gz'
            canonical_tar(first, files, prefix, epoch)
            canonical_tar(second, files, prefix, epoch)
            data = first.read_bytes()
            _require(data == second.read_bytes(), 'Source archive repeat comparison failed')
            _verify_tar(first, files, prefix, epoch)
            _verify_tar(second, files, prefix, epoch)
            with path.open('xb') as stream:
                metadata = os.fstat(stream.fileno())
                created = (metadata.st_dev, metadata.st_ino)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            _verify_tar(path, files, prefix, epoch)
            reread = path.read_bytes()
            _require(reread == data, 'Source archive changed after publication')
            return {'name': path.name, 'bytes': len(reread), 'sha256': _sha(reread)}
    except Exception as exc:
        if created is not None:
            _remove_owned(path, created)
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError('Could not build source archive (' + type(exc).__name__ + ')') from None


def prepare_sources(repo: Path, commit: str, version: str, output: Path) -> list[dict]:
    """Produce repository_source and backend_source records in an existing output."""
    try:
        validate_version(version)
        repo = Path(repo).resolve(strict=True)
        _commit(repo, commit)
        output = _physical_directory(output)
        names = [f'PLUGINS-{version}-{commit}.tar.gz', f'whatsapp-source-{version}-{commit}.tar.gz']
        _require(not any(os.path.lexists(output / name) for name in names),
                 'Source archive output already exists')
        epoch = int(_git(repo, 'show', '-s', '--format=%ct', commit).decode().strip())
        with tempfile.TemporaryDirectory(prefix='.source-snapshot-', dir=output) as temporary:
            snapshot = Path(temporary) / 'source'
            inventory = snapshot_commit(repo, commit, snapshot)
            plugin = snapshot / 'plugins/whatsapp'
            project = tomllib.loads((plugin / 'pyproject.toml').read_text(encoding='utf-8'))
            _require(project['project']['version'] == version, 'pyproject backend version mismatch')
            assignments = ast.parse((plugin / 'sally_whatsapp/__init__.py').read_bytes())
            versions = [ast.literal_eval(node.value) for node in assignments.body
                        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                        and target.id == '__version__' for target in node.targets)]
            _require(versions == [version], 'Backend __version__ mismatch')
            repository_files = [(name, (snapshot / name).read_bytes(), int(value['mode'], 8))
                                for name, value in sorted(inventory.items())]
            capture = runpy.run_path(str(plugin / 'scripts/package_source.py'),
                                     run_name='release_source_capture')['capture']
            backend_files = [(name, data, stat.S_IMODE(metadata.st_mode))
                             for name, data, metadata in capture(plugin)]
            _require(backend_files, 'Backend source capture is empty')
            for name, data, mode in backend_files:
                expected = inventory.get('plugins/whatsapp/' + name)
                _require(expected and expected['sha256'] == _sha(data)
                         and expected['bytes'] == len(data) and expected['mode'] == f'{mode:04o}',
                         'Captured backend source differs from its Git blob')
            records = []
            for name, files, prefix, role in (
                    (names[0], repository_files, 'PLUGINS-' + commit, 'repository_source'),
                    (names[1], backend_files, 'whatsapp-personal', 'backend_source')):
                artifact = verified_tar(output / name, files, prefix, epoch)
                records.append({'role': role, **artifact, 'origin': {'kind': 'built', 'commit': commit}})
            return records
    except ReleaseError:
        raise
    except Exception as exc:
        raise ReleaseError('Could not prepare committed sources (' + type(exc).__name__ + ')') from None
