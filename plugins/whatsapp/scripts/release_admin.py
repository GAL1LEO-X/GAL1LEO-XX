"""Read-only admission for one immutable WhatsApp administration generation.

The installer owns the external handoff. This module never activates an owner,
retires a legacy process, moves a journal, or acquires another project's lock.
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
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType


STATE = Path(installation_path('/var/lib/develative-deploy/whatsapp'))
PUBLICATION_LOCK = STATE/'publication.lock'
OWNER = Path(installation_path('/etc/develative-deploy/recovery-owners/whatsapp.json'))
BOOTSTRAP = Path(installation_path('/usr/local/lib/develative-deploy/whatsapp-bootstrap'))
ENTRYPOINT = BOOTSTRAP/'release_entry.py'
GENERATIONS = Path(installation_path('/usr/local/lib/develative-deploy/whatsapp-generations'))
PROTOCOL = 1
OWNER_STATES = frozenset({'transitioning', 'dedicated', 'retiring', 'retired'})
_TRUST_ROOT = Path('/')
_PINNED = None


class AdminError(RuntimeError):
    def __init__(self, reason='administration state is not verified'):
        super().__init__('WhatsApp administration blocked: '+reason)


class AdminBusy(AdminError):
    """Benign deferral while another WhatsApp administrative operation runs."""


@dataclass(frozen=True)
class Generation:
    path: Path
    epoch: str
    state: str
    manifest_sha256: str
    files: object


def _trusted_uid(uid):
    return uid == 0


def trusted_path(path, *, directory=False):
    """Require a physical path and a protected root-owned ancestor chain."""
    path = Path(path)
    try:
        if not path.is_absolute() or path != path.resolve(strict=True):
            raise AdminError('a physical administrative path is required')
        relative = path.relative_to(_TRUST_ROOT)
        current = _TRUST_ROOT
        for index, part in enumerate(('', *relative.parts)):
            if part:
                current = current/part
            info = current.lstat()
            last = index == len(relative.parts)
            expected = stat.S_ISDIR if not last or directory else stat.S_ISREG
            if not expected(info.st_mode) or not _trusted_uid(info.st_uid) or info.st_mode & 0o022:
                raise AdminError('administrative path protection differs')
        return path
    except (OSError, ValueError):
        raise AdminError('administrative path is unavailable') from None


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise AdminError('duplicate administrative metadata field')
        value[key] = item
    return value


def _read_json(path, maximum):
    trusted_path(path)
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(maximum+1)
        if len(raw) > maximum:
            raise AdminError('administrative metadata exceeds its bound')
        return json.loads(raw, object_pairs_hook=_object), raw
    except (OSError, ValueError, TypeError):
        raise AdminError('administrative metadata is invalid') from None


def _digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _same(expected, actual):
    return (isinstance(expected, Generation) and
            (expected.path, expected.epoch, expected.manifest_sha256) ==
            (actual.path, actual.epoch, actual.manifest_sha256))


def _check_expected(generation, expected=None):
    for previous in (expected, _PINNED):
        if previous is not None and not _same(previous, generation):
            raise AdminError('the loaded helper generation is no longer current')


def load_generation(*, states=('dedicated',)):
    """Attest the complete physical generation without changing host state."""
    if not states or not set(states) <= {'dedicated', 'retiring'}:
        raise AdminError('unsupported owner admission state')
    owner, _ = _read_json(OWNER, 8192)
    fields = {'protocol', 'epoch', 'state', 'generation', 'manifest_sha256'}
    if (not isinstance(owner, dict) or set(owner) != fields
            or type(owner['protocol']) is not int or owner['protocol'] != PROTOCOL
            or not isinstance(owner['epoch'], str) or not re.fullmatch('[0-9a-f]{32}', owner['epoch'])
            or not isinstance(owner['state'], str) or owner['state'] not in states or owner['state'] not in OWNER_STATES
            or not isinstance(owner['generation'], str) or not _digest(owner['manifest_sha256'])):
        raise AdminError('owner does not admit this operation')
    root = trusted_path(GENERATIONS, directory=True)
    generation = Path(owner['generation'])
    if str(generation) != owner['generation'] or generation.parent != root:
        raise AdminError('generation is outside the dedicated generation directory')
    trusted_path(generation, directory=True)
    manifest, encoded = _read_json(generation/'manifest.json', 1048576)
    if hashlib.sha256(encoded).hexdigest() != owner['manifest_sha256']:
        raise AdminError('generation manifest differs from the owner record')
    profile=installation_profile()
    fields={'protocol','files'} if profile.compatibility else {'protocol','files','installation_sha256'}
    if (not isinstance(manifest, dict) or set(manifest) != fields
            or type(manifest['protocol']) is not int or manifest['protocol'] != PROTOCOL
            or not isinstance(manifest['files'], dict) or not 1 <= len(manifest['files']) <= 4096):
        raise AdminError('generation manifest is invalid')
    if not profile.compatibility and manifest['installation_sha256']!=profile.sha256:
        raise AdminError('installation profile differs from the admitted generation')
    files = manifest['files']
    for name, digest in files.items():
        relative = PurePosixPath(name)
        if (not isinstance(name, str) or relative.is_absolute() or str(relative) != name
                or any(not re.fullmatch('[A-Za-z0-9_.-]+', part) or part in ('.', '..', '__pycache__')
                       for part in relative.parts)
                or name == 'manifest.json' or relative.suffix in ('.pyc', '.pyo') or not _digest(digest)):
            raise AdminError('generation file declaration is invalid')
        target = trusted_path(generation/name)
        try:
            with target.open('rb') as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        except OSError:
            raise AdminError('generation file is unavailable') from None
        if actual != digest:
            raise AdminError('generation file hash differs')
    found = set()
    try:
        for path in generation.rglob('*'):
            if path.is_symlink() or '__pycache__' in path.relative_to(generation).parts or path.suffix in ('.pyc', '.pyo'):
                raise AdminError('generation contains links or bytecode')
            trusted_path(path, directory=path.is_dir())
            if path.is_file():
                found.add(path.relative_to(generation).as_posix())
            if len(found) > 4097:
                raise AdminError('generation contains undeclared files')
    except OSError:
        raise AdminError('generation tree is unavailable') from None
    if found != set(files) | {'manifest.json'}:
        raise AdminError('generation contains undeclared files')
    value = Generation(generation, owner['epoch'], owner['state'], owner['manifest_sha256'], MappingProxyType(files))
    _check_expected(value)
    return value


def pin_generation(generation):
    """The bootstrap pins once; later checks cannot silently select a new bundle."""
    global _PINNED
    if not isinstance(generation, Generation):
        raise AdminError('invalid pinned generation')
    _check_expected(generation)
    _PINNED = generation


def require_current(path, *, expected=None, states=('dedicated',)):
    generation = load_generation(states=states)
    _check_expected(generation, expected)
    path = trusted_path(path)
    try:
        relative = path.relative_to(generation.path).as_posix()
    except ValueError:
        raise AdminError('helper is outside the current generation') from None
    if relative not in generation.files:
        raise AdminError('helper is not declared by the current generation')
    return generation


@contextmanager
def publication_lock(path=None, *, expected=None, states=('dedicated',)):
    """Acquire only the WA lock, then revalidate the loaded helper identity.

    `path` identifies a current helper, never an arbitrary lock pathname.
    This does not write or advance the owner record. The tenant FD, acquired
    by callers afterwards, remains the descriptor inherited by backup workers.
    """
    if not states or not set(states) <= {'dedicated', 'retiring'}:
        raise AdminError('owner state cannot admit administrative writes')
    before = require_current(path, expected=expected, states=states) if path is not None else load_generation(states=states)
    _check_expected(before, expected)
    trusted_path(STATE, directory=True)
    if PUBLICATION_LOCK.parent != STATE:
        raise AdminError('publication lock is outside the WA namespace')
    descriptor = None
    try:
        try:
            descriptor = os.open(PUBLICATION_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or not _trusted_uid(info.st_uid) or info.st_mode & 0o022:
                raise AdminError('publication lock protection differs')
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            trusted_path(PUBLICATION_LOCK)
            current = PUBLICATION_LOCK.stat()
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise AdminError('publication lock identity changed')
            generation = require_current(path, expected=before, states=states) if path is not None else load_generation(states=states)
            _check_expected(generation, before)
        except BlockingIOError:
            raise AdminBusy('another WhatsApp administrative operation is in progress') from None
        except OSError:
            raise AdminError('publication lock is unavailable') from None
        yield generation
    finally:
        if descriptor is not None:
            os.close(descriptor)
