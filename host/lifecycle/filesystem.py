"""Bounded, forward-only filesystem transactions for BOX, WhatsApp and the host.

No services, commands or source code are executed. Callers supply an independent
exact path policy and complete before/after manifests after their own admission
and drain gates. All persistent engine state belongs to the neutral host.
"""
from contextlib import contextmanager
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


STATE = '/var/lib/develative-host-lifecycle'
OWNERS = frozenset({'whatsapp', 'box', 'host'})
MAX_FILES = 2048
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_PAYLOAD_BYTES = 128 * 1024 * 1024
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
MAX_INLINE_ENCODED_BYTES = 1024 * 1024


class LifecycleError(ValueError):
    """An explicit precondition changed; preserve state for inspection."""


class LifecycleBusy(LifecycleError):
    """Only this owner's filesystem transaction is already in progress."""


def require(condition, message):
    if not condition:
        raise LifecycleError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(content):
    return hashlib.sha256(content).hexdigest()


def _path(value):
    require(isinstance(value, str) and value.startswith('/') and not value.startswith('//')
            and value != '/', 'An exact absolute file path is required')
    path = PurePosixPath(value)
    require(str(path) == value and '\x00' not in value and '\\' not in value
            and all(part not in ('.', '..') for part in path.parts), 'Noncanonical path')
    return value


def _metadata(info):
    return {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}


def resolve_link_target(path, literal):
    """Resolve a literal lexically beneath the host root, never dereference it."""
    _path(path)
    require(isinstance(literal, str) and literal and '\x00' not in literal and '\\' not in literal,
            'Invalid named link literal')
    if literal.startswith('/'):
        return _path(literal)
    parts = literal.split('/')
    require(all(part not in ('', '.') for part in parts), 'Relative link literal is not canonical')
    # '..' is admitted only as a leading sequence, as in the actual Apache
    # sites-enabled and mods-enabled links. Redundant a/../b aliases are closed.
    named_at = next((i for i, part in enumerate(parts) if part != '..'), len(parts))
    require('..' not in parts[named_at:], 'Relative link literal is not canonical')
    resolved = list(PurePosixPath(path).parent.parts[1:])
    for part in parts:
        if part == '..':
            require(bool(resolved), 'Relative link escapes the mapped root')
            resolved.pop()
        else:
            resolved.append(part)
    return _path('/' + '/'.join(resolved))


class Root:
    """Map absolute host paths beneath a physical root using anchored dirfds.

    The mapped root's UID is the administrative authority (0 on the host,
    the test user's UID in an isolated fixture). Traversed directories must
    belong to that UID and must not be writable by group or others.
    """
    def __init__(self, path):
        self.base = Path(path).absolute()
        require(self.base == self.base.resolve(strict=True), 'Root must be physical')
        self.fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(self.fd)
        self.uid, self.gid = info.st_uid, info.st_gid
        if info.st_mode & 0o022:
            self.close()
            raise LifecycleError('Root is not administratively protected')

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _directory_uid(self, path):
        """Authority for target directories; ordinary host Roots stay uniform."""
        return self.uid

    @contextmanager
    def _parent(self, path):
        parts = PurePosixPath(_path(path)).parts[1:]
        descriptor = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                info = os.fstat(descriptor)
                require(info.st_uid == self.uid and not info.st_mode & 0o022,
                        'An ancestor is not administratively protected')
            yield descriptor, parts[-1]
        except OSError as error:
            if isinstance(error, FileNotFoundError):
                raise
            raise LifecycleError('A physical path is unavailable or contains a link') from error
        finally:
            os.close(descriptor)

    def read_bytes(self, path, *, max_bytes=MAX_FILE_BYTES):
        with self._parent(path) as (parent, name):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode), 'Only regular files are admitted')
                require(info.st_size <= max_bytes, 'File exceeds its bound')
                content = stream.read(max_bytes + 1)
                after = os.fstat(stream.fileno())
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(len(content) <= max_bytes and
                    (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                    (after.st_dev, after.st_ino) == (current.st_dev, current.st_ino),
                    'File changed during inspection')
            return content

    def snapshot(self, path):
        try:
            with self._parent(path) as (parent, name):
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISREG(info.st_mode), 'A file target is not a regular file')
            content = self.read_bytes(path)
            with self._parent(path) as (parent, name):
                after = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require((info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
                    'File changed during inspection')
            return {'sha256': digest(content), **_metadata(after)}
        except FileNotFoundError:
            return None

    def directory(self, path):
        try:
            with self._parent(path) as (parent, name):
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISDIR(info.st_mode), 'A directory target is not a physical directory')
                return _metadata(info)
        except FileNotFoundError:
            return None

    def link(self, path):
        try:
            with self._parent(path) as (parent, name):
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISLNK(info.st_mode), 'A link target is not a symbolic link')
                target = os.readlink(name, dir_fd=parent)
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require((info.st_dev, info.st_ino, info.st_ctime_ns) ==
                        (current.st_dev, current.st_ino, current.st_ctime_ns), 'Link changed during inspection')
                resolved = resolve_link_target(path, target)
                return {'target': target, 'uid': info.st_uid, 'gid': info.st_gid,
                        **({'resolved_target': resolved} if not target.startswith('/') else {})}
        except FileNotFoundError:
            return None

    def _mkdir(self, path, spec):
        with self._parent(path) as (parent, name):
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
        self._finish_directory(path, spec)

    def _finish_directory(self, path, spec):
        # Used only for a newly created directory with a durable creation
        # intent. Existing administrative directories are never repaired.
        with self._parent(path) as (parent, name):
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                info = os.fstat(descriptor)
                require(info.st_uid == self.uid and not info.st_mode & 0o022,
                        'Incomplete directory is not protected')
                os.fchown(descriptor, spec['uid'], spec['gid'])
                os.fchmod(descriptor, spec['mode'])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(parent)

    def _unlink(self, path, *, link=False):
        with self._parent(path) as (parent, name):
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require((stat.S_ISLNK if link else stat.S_ISREG)(info.st_mode), 'Refusing to unlink an unexpected object')
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)

    def _replace(self, source, target, *, link=False):
        with self._parent(source) as (source_parent, source_name), self._parent(target) as (target_parent, target_name):
            info = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
            require((stat.S_ISLNK if link else stat.S_ISREG)(info.st_mode), 'Only a declared object type may be published')
            os.replace(source_name, target_name, src_dir_fd=source_parent, dst_dir_fd=target_parent)
            os.fsync(target_parent)
            os.fsync(source_parent)

    def _write(self, path, content, spec, *, temporary):
        # The exact temporary name was reserved by the durable operation intent.
        # A partial temporary file can be rebuilt; links and foreign ownership
        # are always refused. The durable source and quarantine are never reset.
        existing = self.snapshot(temporary)
        if existing is not None:
            require(existing['uid'] in (self.uid, spec['uid']), 'Foreign temporary file')
            self._unlink(temporary)
        with self._parent(temporary) as (parent, name):
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(content)
                stream.flush()
                os.fchown(stream.fileno(), spec['uid'], spec['gid'])
                os.fchmod(stream.fileno(), spec['mode'])
                os.fsync(stream.fileno())
            os.fsync(parent)
        self._replace(temporary, path)

    def _symlink(self, path, spec, *, temporary):
        existing = self.link(temporary)
        if existing is not None:
            require(existing['uid'] in (self.uid, spec['uid']), 'Foreign temporary link')
            self._unlink(temporary, link=True)
        with self._parent(temporary) as (parent, name):
            os.symlink(spec['target'], name, dir_fd=parent)
            os.chown(name, spec['uid'], spec['gid'], dir_fd=parent, follow_symlinks=False)
            os.fsync(parent)
        self._replace(temporary, path, link=True)


def validate_manifest(value):
    require(isinstance(value, dict) and set(value) in ({'format', 'owner', 'files', 'directories'},
            {'format', 'owner', 'files', 'directories', 'links'}), 'Invalid manifest fields')
    value = {**value, 'links': value.get('links', {})}
    require(type(value['format']) is int and value['format'] == 1 and isinstance(value['owner'], str)
            and value['owner'] in OWNERS, 'Invalid manifest version or owner')
    require(all(isinstance(value[kind], dict) for kind in ('files', 'directories', 'links'))
            and sum(len(value[kind]) for kind in ('files', 'directories', 'links')) <= MAX_FILES, 'Manifest exceeds its bound')
    for kind in ('files', 'directories', 'links'):
        fields = {'uid', 'gid', 'retention'} | ({'target'} if kind == 'links' else {'mode'}) | ({'sha256'} if kind == 'files' else set())
        for path, spec in value[kind].items():
            _path(path)
            require(not (path == STATE or path.startswith(STATE + '/')), 'Engine state cannot be an application target')
            require(not any(part.startswith('.lifecycle-') for part in PurePosixPath(path).parts), 'Reserved transaction filename')
            relative_link = kind == 'links' and isinstance(spec, dict) and isinstance(spec.get('target'), str) and not spec['target'].startswith('/')
            require(isinstance(spec, dict) and set(spec) == fields | ({'resolved_target'} if relative_link else set()),
                    'Invalid object specification')
            require(all(type(spec[key]) is int and 0 <= spec[key] <= 2**31 - 1 for key in ('uid', 'gid')), 'Invalid numeric ownership')
            if kind != 'links':
                require(type(spec['mode']) is int and 0 <= spec['mode'] <= 0o777, 'Invalid permission mode')
            require(isinstance(spec['retention'], str) and spec['retention'] in
                    ({'retain'} if kind == 'directories' else {'managed', 'retain'}), 'Invalid retention policy')
            if kind == 'files':
                require(isinstance(spec['sha256'], str) and re.fullmatch('[0-9a-f]{64}', spec['sha256']), 'Invalid file digest')
            elif kind == 'directories':
                require(not spec['mode'] & 0o022 and spec['mode'] & 0o700 == 0o700, 'Directory must be administratively protected')
            else:
                target = resolve_link_target(path, spec['target'])
                require(not relative_link or spec['resolved_target'] == target, 'Relative link resolved target differs')
                require(not (target == STATE or target.startswith(STATE + '/')), 'A link cannot target lifecycle control state')
    objects = set(value['files']) | set(value['links'])
    require(len(objects) == len(value['files']) + len(value['links']) and not objects & set(value['directories']), 'A path has conflicting object types')
    for path in (*objects, *value['directories']):
        require(not any(str(parent) in objects for parent in PurePosixPath(path).parents), 'A file or link cannot be an ancestor')
    return json.loads(encoded(value))


def equivalent_managed(left, right):
    return validate_manifest(left) == validate_manifest(right)


def _spec(value):
    return None if value is None else {key: item for key, item in value.items() if key != 'retention'}


def _policy(before, after, allowed_paths):
    require(before['owner'] == after['owner'], 'Cross-owner transaction')
    allowed = sorted({_path(path) for path in allowed_paths})
    require(len(allowed) <= MAX_FILES * 4, 'Exact path policy exceeds its bound')
    selected = set(before['files']) | set(after['files']) | set(before['directories']) | set(after['directories']) | set(before['links']) | set(after['links'])
    require(selected <= set(allowed), 'Manifest is outside the independent exact path policy')
    for kind in ('files', 'links'):
        for path, spec in before[kind].items():
            if spec['retention'] == 'retain':
                require(after[kind].get(path) == spec, 'Retained objects cannot be removed or changed')
    require(not set(before['files']) & set(after['links']) and not set(before['links']) & set(after['files']), 'Object type replacement requires a separate explicit operation')
    for spec in after['links'].values():
        target = spec.get('resolved_target', spec['target'])
        require(target in after['files'] or target in allowed, 'Link target is outside the independent policy')
        require(target not in before['files'] or target in after['files'], 'A retained link cannot target a removed file')
    for path, spec in before['directories'].items():
        require(after['directories'].get(path) == spec, 'Directories are retained without ownership repair')
    return allowed


def _payloads(after, payloads):
    require(isinstance(payloads, dict) and set(payloads) <= set(after['files']), 'Unexpected payload paths')
    total = 0
    for path, content in payloads.items():
        require(type(content) is bytes and len(content) <= MAX_FILE_BYTES, 'Invalid or oversized payload')
        total += len(content)
        require(digest(content) == after['files'][path]['sha256'], 'Payload digest differs from the manifest')
    require(total <= MAX_PAYLOAD_BYTES, 'Payload collection exceeds its bound')


def _decode_inline(after, values):
    require(isinstance(values, dict) and set(values) <= set(after['files']), 'Invalid inline control payload paths')
    require(all(isinstance(value, str) for value in values.values())
            and sum(len(value) for value in values.values()) <= MAX_INLINE_ENCODED_BYTES,
            'Inline control payload collection exceeds its encoded bound')
    try:
        result = {path: base64.b64decode(value, validate=True) for path, value in values.items()}
    except (ValueError, UnicodeError) as error:
        raise LifecycleError('Invalid inline control payload encoding') from error
    _payloads(after, result)
    return result


def _paths(owner, operation_id):
    require(owner in OWNERS and isinstance(operation_id, str) and re.fullmatch('[0-9a-f]{32}', operation_id), 'Invalid owner or operation ID')
    owner_path = STATE + '/' + owner
    operation = owner_path + '/operations/' + operation_id
    return owner_path, operation


def _names(path, operation_id, index):
    parent = str(PurePosixPath(path).parent)
    stem = '.lifecycle-' + operation_id + '-' + str(index)
    return parent + '/' + stem + '.new', parent + '/' + stem + '.quarantine'


def _changes(before, after):
    removed_links = sorted(set(before['links']) - set(after['links']))
    files = [path for path in sorted(set(before['files']) | set(after['files']))
             if _spec(before['files'].get(path)) != _spec(after['files'].get(path))]
    links = [path for path in sorted(after['links'])
             if _spec(before['links'].get(path)) != _spec(after['links'].get(path))]
    return removed_links + files + links


def _kind(before, after, path):
    return 'links' if path in before['links'] or path in after['links'] else 'files'


def _snapshot(root, kind, path):
    return root.link(path) if kind == 'links' else root.snapshot(path)


def _directory_link_tree(root, target, before, after, *, complete):
    """Only a named, closed, immutable physical tree may become a link target.

    Internal links are deliberately unsupported. Callers must hold
    the application's admission/publication lock across activation and recovery;
    the engine owner lock only serializes filesystem transactions.
    """
    require(target in after['directories'], 'Directory link target is undeclared')
    prefix = target + '/'
    files = {path: _spec(spec) for path, spec in after['files'].items() if path.startswith(prefix)}
    directories = {path: _spec(spec) for path, spec in after['directories'].items()
                   if path == target or path.startswith(prefix)}
    require(files and not any(path.startswith(prefix) for path in after['links']),
            'Directory link tree must contain files and no internal links')
    require(all(spec['uid'] == root.uid and not spec['mode'] & 0o022 for spec in files.values()),
            'Directory link payload must be administratively immutable')
    previous_files = {path: _spec(spec) for path, spec in before['files'].items() if path.startswith(prefix)}
    previous_directories = {path: _spec(spec) for path, spec in before['directories'].items()
                            if path == target or path.startswith(prefix)}
    if previous_files or target in before['directories']:
        require(previous_files == files and previous_directories == directories,
                'A published directory tree cannot be modified in place')
    if not complete:
        return
    seen_files, seen_directories = {}, {}
    def visit(path, parent, name):
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            initial = os.fstat(descriptor)
            require(initial.st_uid == root.uid and not initial.st_mode & 0o022,
                    'Directory link tree is not protected')
            seen_directories[path] = _metadata(initial)
            names = []
            with os.scandir(descriptor) as scan:
                for item in scan:
                    names.append(item.name)
                    require(len(names) <= MAX_FILES, 'Runtime tree exceeds its entry bound')
            names.sort()
            for child in names:
                absolute = path + '/' + child
                info = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    require(absolute in directories, 'Undeclared directory in runtime tree')
                    visit(absolute, descriptor, child)
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                            and absolute in files, 'Undeclared or nonregular runtime tree object')
                    seen_files[absolute] = root.snapshot(absolute)
            final = os.fstat(descriptor)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            identity = lambda value: (value.st_dev, value.st_ino, value.st_mtime_ns, value.st_ctime_ns)
            require(identity(initial) == identity(final) == identity(current),
                    'Directory link tree changed while inspected')
        finally:
            os.close(descriptor)
    with root._parent(target) as (parent, name):
        visit(target, parent, name)
    require(seen_files == files and seen_directories == directories,
            'Directory link tree differs from its complete manifest')


def _preserve_before_directory_links(before, after):
    # During A->B publication A may still serve until the current-link swap.
    # A link removed by this operation is processed before any file retirement.
    for path, spec in before['links'].items():
        target = spec.get('resolved_target', spec['target'])
        if path not in after['links'] or target not in before['directories']:
            continue
        prefix = target + '/'
        for kind in ('files', 'directories', 'links'):
            select = lambda manifest: {name: _spec(value) for name, value in manifest[kind].items()
                                       if name == target or name.startswith(prefix)}
            require(select(before) == select(after),
                    'The previous directory link tree must remain immutable during publication')


def _preflight(root, before, after, operation_id, *, journal=None):
    _preserve_before_directory_links(before, after)
    changed = _changes(before, after)
    for path in sorted(set(before['directories']) | set(after['directories']), key=lambda item: (item.count('/'), item)):
        desired = _spec(after['directories'][path])
        require(desired['uid'] == root._directory_uid(path), 'Managed directories must belong to the administrative authority')
        current = root.directory(path)
        partial = (journal is not None and journal['directory_intent'] == path
                   and path in journal['new_directories'] and current is not None
                   and current['uid'] == root.uid and not current['mode'] & 0o022)
        require(current is None and path not in before['directories'] or current == desired or partial,
                'A directory differs; automatic ownership repair is forbidden')
        if journal is not None and path in journal['new_directories'] and current is not None:
            require(path in journal['directories_done'] or journal['directory_intent'] == path,
                    'A pending directory appeared before its recorded intent')
    for path in sorted(set(before['files']) | set(after['files']) | set(before['links']) | set(after['links'])):
        kind = _kind(before, after, path)
        previous, desired = _spec(before[kind].get(path)), _spec(after[kind].get(path))
        current = _snapshot(root, kind, path)
        if journal is None or path not in changed:
            require(current == previous, 'Unmanaged or changed file: ' + path)
        else:
            require(current in (previous, desired), 'Interrupted target differs from both declared states: ' + path)
            if path in journal['done']:
                require(current == desired, 'A completed file changed after publication')
            elif current != previous:
                require(journal['intent'] == path, 'A pending target changed before its recorded intent')
        if path in changed:
            temporary, quarantine = _names(path, operation_id, changed.index(path))
            for candidate in (temporary, quarantine, quarantine + '.tmp'):
                current_reserved = _snapshot(root, kind, candidate)
                if journal is None:
                    require(current_reserved is None, 'An operation-reserved filename already exists')
                elif candidate == quarantine and current_reserved is not None:
                    require(previous is not None and current_reserved == previous, 'Quarantine differs from the recorded original')
                if journal is not None and path in journal['done'] and candidate == quarantine and previous is not None:
                    require(current_reserved == previous, 'A completed operation lost its retained quarantine')
    # Missing parents must be declared directories, so no late validation failure
    # can follow publication of an earlier file.
    for spec in after['links'].values():
        target = spec.get('resolved_target', spec['target'])
        if target in after['directories']:
            _directory_link_tree(root, target, before, after,
                                 complete=journal is not None and journal['phase'] == 'committed')
        elif target not in after['files']:
            require(root.snapshot(target) is not None, 'External link target must be a physical regular file')
    for path in (*after['files'], *after['directories'], *after['links']):
        for parent in PurePosixPath(path).parents:
            if str(parent) == '/':
                break
            if root.directory(str(parent)) is None:
                require(str(parent) in after['directories'], 'A missing parent was not declared')


@contextmanager
def _lock(root, owner):
    spec = {'mode': 0o700, 'uid': root.uid, 'gid': root.gid}
    for path in (STATE, STATE + '/' + owner, STATE + '/' + owner + '/operations'):
        current = root.directory(path)
        if current is None:
            try:
                root._mkdir(path, spec)
            except FileExistsError:
                pass
            current = root.directory(path)
        require(current == spec, 'Lifecycle control directory protection differs')
    path = STATE + '/' + owner + '/lock'
    with root._parent(path) as (parent, name):
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and _metadata(info) == {'mode': 0o600, 'uid': root.uid, 'gid': root.gid}, 'Lifecycle lock protection differs')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LifecycleBusy('This owner already has an active filesystem transaction') from None
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), 'Lifecycle lock identity changed')
            yield
        finally:
            os.close(descriptor)


def _event(fault, event, detail):
    if fault is not None:
        fault(event, detail)


def _save(root, operation, journal, fault, event):
    content = encoded(journal)
    require(len(content) <= MAX_JOURNAL_BYTES, 'Journal exceeds its bound')
    root._write(operation + '/journal.json', content,
                {'mode': 0o600, 'uid': root.uid, 'gid': root.gid},
                temporary=operation + '/journal.tmp')
    _event(fault, event, {'operation_id': journal['operation_id'], 'intent': journal['intent']})


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate journal field')
        result[key] = value
    return result


def _read_journal(root, owner, operation_id, allowed_paths):
    _, operation = _paths(owner, operation_id)
    try:
        journal = json.loads(root.read_bytes(operation + '/journal.json', max_bytes=MAX_JOURNAL_BYTES), object_pairs_hook=_unique)
    except (FileNotFoundError, ValueError) as error:
        raise LifecycleError('Operation is incomplete or its journal is invalid; inspect without resetting') from error
    require(isinstance(journal, dict) and set(journal) == {'format', 'owner', 'operation_id', 'before', 'after', 'allowed_paths', 'plan_sha256', 'phase', 'done', 'intent',
            'new_directories', 'directories_done', 'directory_intent', 'inline_payloads'}, 'Invalid journal fields')
    require(type(journal['format']) is int and journal['format'] == 1 and journal['owner'] == owner and journal['operation_id'] == operation_id, 'Journal identity differs')
    before, after = validate_manifest(journal['before']), validate_manifest(journal['after'])
    require(before['owner'] == owner and after['owner'] == owner, 'Journal manifest owner differs')
    _decode_inline(after, journal['inline_payloads'])
    allowed = _policy(before, after, allowed_paths)
    require(allowed == journal['allowed_paths'] and journal['plan_sha256'] == digest(encoded({'before': before, 'after': after, 'allowed_paths': allowed})), 'Operation policy or manifest changed')
    changes = _changes(before, after)
    created = journal['new_directories']
    require(isinstance(created, list) and all(isinstance(path, str) for path in created)
            and created == sorted(set(created), key=lambda path: (path.count('/'), path))
            and set(created) <= set(after['directories']) - set(before['directories'])
            and isinstance(journal['directories_done'], list)
            and journal['directories_done'] == created[:len(journal['directories_done'])]
            and (journal['directory_intent'] is None or journal['directory_intent'] in
                 created[len(journal['directories_done']):len(journal['directories_done']) + 1]), 'Invalid directory creation progress')
    require(journal['phase'] in ('staging', 'prepared', 'applying', 'committed')
            and isinstance(journal['done'], list) and journal['done'] == changes[:len(journal['done'])]
            and (journal['intent'] is None or journal['intent'] in changes[len(journal['done']):len(journal['done']) + 1]), 'Invalid journal progress')
    require(journal['phase'] != 'committed' or journal['done'] == changes and journal['intent'] is None
            and journal['directories_done'] == created and journal['directory_intent'] is None, 'Incomplete committed journal')
    return journal


def _continue(root, journal, payloads, fault):
    before, after = journal['before'], journal['after']
    operation_id = journal['operation_id']
    _, operation = _paths(journal['owner'], operation_id)
    changes = _changes(before, after)
    _payloads(after, payloads)
    payloads = {**_decode_inline(after, journal['inline_payloads']), **payloads}
    _payloads(after, payloads)
    _preflight(root, before, after, operation_id, journal=journal)
    if journal['phase'] == 'staging':
        for index, path in enumerate(changes):
            if path not in after['files']:
                continue
            staged = operation + '/payload-' + str(index)
            expected = {'sha256': after['files'][path]['sha256'], 'mode': 0o400, 'uid': root.uid, 'gid': root.gid}
            current = root.snapshot(staged)
            if current is None:
                require(path in payloads, 'Staging is incomplete; supply the same verified payloads')
                root._write(staged, payloads[path], expected, temporary=staged + '.tmp')
                _event(fault, 'staged-file', {'path': path})
            else:
                require(current == expected, 'Immutable staged payload changed')
        journal['phase'] = 'prepared'
        _save(root, operation, journal, fault, 'journal-prepared')
    if journal['phase'] == 'prepared':
        journal['phase'] = 'applying'
        _save(root, operation, journal, fault, 'journal-applying')
    if journal['phase'] == 'applying':
        # Every payload and target is checked before the first managed write.
        for index, path in enumerate(changes):
            if path in after['files']:
                expected = {'sha256': after['files'][path]['sha256'], 'mode': 0o400, 'uid': root.uid, 'gid': root.gid}
                require(root.snapshot(operation + '/payload-' + str(index)) == expected, 'Immutable staged payload changed')
        _preflight(root, before, after, operation_id, journal=journal)
        for path in journal['new_directories']:
            if path in journal['directories_done']:
                continue
            spec = after['directories'][path]
            journal['directory_intent'] = path
            _save(root, operation, journal, fault, 'intent-directory')
            if root.directory(path) is None:
                root._mkdir(path, spec)
                _event(fault, 'created-directory', {'path': path})
            else:
                root._finish_directory(path, spec)
            journal['directories_done'].append(path)
            journal['directory_intent'] = None
            _save(root, operation, journal, fault, 'completed-directory')
        for index, path in enumerate(changes):
            if path in journal['done']:
                continue
            kind = _kind(before, after, path)
            previous, desired = _spec(before[kind].get(path)), _spec(after[kind].get(path))
            temporary, quarantine = _names(path, operation_id, index)
            journal['intent'] = path
            _save(root, operation, journal, fault, 'intent-file')
            current = _snapshot(root, kind, path)
            if previous is not None and _snapshot(root, kind, quarantine) is None:
                require(current == previous, 'Original is unavailable before quarantine')
                if desired is None:
                    root._replace(path, quarantine, link=kind == 'links')
                elif kind == 'links':
                    root._symlink(quarantine, previous, temporary=quarantine + '.tmp')
                else:
                    content = root.read_bytes(path)
                    require(digest(content) == previous['sha256'] and root.snapshot(path) == previous, 'Original changed before quarantine')
                    root._write(quarantine, content, previous, temporary=quarantine + '.tmp')
                _event(fault, 'quarantined-file', {'path': path, 'quarantine': quarantine})
            if previous is not None:
                require(_snapshot(root, kind, quarantine) == previous, 'Quarantine no longer contains the original')
            current = _snapshot(root, kind, path)
            if current != desired:
                require(current == previous, 'Target changed after file intent')
                if desired is None:
                    root._unlink(path, link=kind == 'links')
                    _event(fault, 'removed-file', {'path': path})
                elif kind == 'links':
                    target = desired.get('resolved_target', desired['target'])
                    if target in after['directories']:
                        _directory_link_tree(root, target, before, after, complete=True)
                    else:
                        require(root.snapshot(target) is not None, 'Link target is not a physical regular file')
                    root._symlink(path, desired, temporary=temporary)
                    _event(fault, 'replaced-file', {'path': path})
                else:
                    content = root.read_bytes(operation + '/payload-' + str(index))
                    require(digest(content) == desired['sha256'], 'Staged payload changed before publication')
                    root._write(path, content, desired, temporary=temporary)
                    _event(fault, 'replaced-file', {'path': path})
            elif desired is None:
                _event(fault, 'removed-file', {'path': path})
            if kind == 'links' and desired is not None:
                target = desired.get('resolved_target', desired['target'])
                if target in after['directories']:
                    _directory_link_tree(root, target, before, after, complete=True)
            require(_snapshot(root, kind, path) == desired, 'Published object differs')
            journal['done'].append(path)
            journal['intent'] = None
            _save(root, operation, journal, fault, 'completed-file')
        journal['phase'] = 'committed'
        _save(root, operation, journal, fault, 'journal-committed')
    _preflight(root, before, after, operation_id, journal=journal)
    quarantine = {path: _names(path, operation_id, index)[1]
                  for index, path in enumerate(changes) if path in before['files'] or path in before['links']}
    return {'format': 1, 'owner': journal['owner'], 'operation_id': operation_id,
            'phase': 'committed', 'manifest': after, 'manifest_sha256': digest(encoded(after)),
            'quarantine': quarantine, 'journal': operation + '/journal.json', 'changed': changes}


def reconcile(root, *, operation_id, before, after, payloads, allowed_paths, inline_payloads=(), fault=None):
    before, after = validate_manifest(before), validate_manifest(after)
    allowed = _policy(before, after, allowed_paths)
    _payloads(after, payloads)
    selected_inline = set(inline_payloads)
    require(selected_inline <= set(payloads), 'Inline control payloads must be an explicit subset of supplied bytes')
    inline = {path: base64.b64encode(payloads[path]).decode('ascii') for path in sorted(selected_inline)}
    _decode_inline(after, inline)
    owner, operation = after['owner'], _paths(after['owner'], operation_id)[1]
    plan_sha = digest(encoded({'before': before, 'after': after, 'allowed_paths': allowed}))
    require(len(encoded({'before': before, 'after': after, 'allowed_paths': allowed,
                         'done': _changes(before, after), 'new_directories': list(after['directories']),
                         'directories_done': list(after['directories']), 'inline_payloads': inline})) + 4096 <= MAX_JOURNAL_BYTES,
            'Plan cannot fit the bounded durable journal')
    if root.directory(operation) is None:
        _preflight(root, before, after, operation_id)
        require(all(path in payloads for path in _changes(before, after) if path in after['files']), 'A required payload is missing')
    with _lock(root, owner):
        if root.directory(operation) is not None:
            journal = _read_journal(root, owner, operation_id, allowed)
            require(journal['plan_sha256'] == plan_sha, 'Operation ID was already bound to another plan')
        else:
            _preflight(root, before, after, operation_id)
            root._mkdir(operation, {'mode': 0o700, 'uid': root.uid, 'gid': root.gid})
            journal = {'format': 1, 'owner': owner, 'operation_id': operation_id,
                       'before': before, 'after': after, 'allowed_paths': allowed,
                       'plan_sha256': plan_sha, 'phase': 'staging', 'done': [], 'intent': None,
                       'new_directories': [path for path in sorted(after['directories'], key=lambda item: (item.count('/'), item))
                                           if root.directory(path) is None],
                       'directories_done': [], 'directory_intent': None}
            journal['inline_payloads'] = inline
            _save(root, operation, journal, fault, 'journal-staging')
        return _continue(root, journal, payloads, fault)


def resume(root, *, owner, operation_id, allowed_paths, payloads=None, fault=None):
    _paths(owner, operation_id)
    # A partial directory never becomes a fresh installation on retry.
    _read_journal(root, owner, operation_id, allowed_paths)
    with _lock(root, owner):
        journal = _read_journal(root, owner, operation_id, allowed_paths)
        return _continue(root, journal, {} if payloads is None else payloads, fault)


def inspect_operation(root, *, owner, operation_id, allowed_paths):
    """Validate a durable intent without creating state, locking or resuming it.

    Adapters may inspect the exact before/after write set before their own
    reference checks. Actual target bytes are still checked by resume under its
    owner lock; this read is not permission to publish or proof of completion.
    """
    return json.loads(encoded(_read_journal(root, owner, operation_id, allowed_paths)))
