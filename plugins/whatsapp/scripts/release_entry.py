"""Protected stable WhatsApp bootstrap; activation is an external handoff."""
import os
from pathlib import Path
import stat
import sys
import types


_TRUST_ROOT = Path('/')


def _trusted_uid(uid):
    return uid == 0


def _admin_module():
    # Compile trusted source explicitly: neither bootstrap nor generation may
    # select a stale .pyc. Do not import from cwd, user site, or an old bundle.
    entry = Path(__file__)
    source = entry.parent/'release_admin.py'
    layout_source = entry.parent/'installation_layout.py'
    for path in (entry, source, layout_source):
        if not path.is_absolute() or path != path.resolve(strict=True):
            raise RuntimeError('WhatsApp bootstrap requires physical paths')
        relative = path.relative_to(_TRUST_ROOT)
        current = _TRUST_ROOT
        for index, part in enumerate(('', *relative.parts)):
            if part:
                current = current/part
            info = current.lstat()
            expected = stat.S_ISREG if index == len(relative.parts) else stat.S_ISDIR
            if not expected(info.st_mode) or not _trusted_uid(info.st_uid) or info.st_mode & 0o022:
                raise RuntimeError('WhatsApp bootstrap protection differs')
    # Always compile the protected source; never accept an inherited module or
    # bytecode from the project, cwd, a previous generation or user site.
    layout = types.ModuleType('installation_layout')
    layout.__file__ = str(layout_source)
    sys.modules['installation_layout'] = layout
    try:
        exec(compile(layout_source.read_bytes(), str(layout_source), 'exec'), layout.__dict__)
    except BaseException:
        sys.modules.pop('installation_layout', None)
        raise
    if 'release_admin' in sys.modules:
        module = sys.modules['release_admin']
        if Path(getattr(module, '__file__', '')) != source:
            raise RuntimeError('WhatsApp bootstrap core was loaded from another path')
    else:
        module = types.ModuleType('release_admin')
        module.__file__ = str(source)
        sys.modules['release_admin'] = module
        try:
            exec(compile(source.read_bytes(), str(source), 'exec'), module.__dict__)
        except BaseException:
            sys.modules.pop('release_admin', None)
            raise
    if entry != module.ENTRYPOINT or entry.parent != module.BOOTSTRAP:
        raise RuntimeError('WhatsApp bootstrap path differs from the installed contract')
    return module


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    choices = {'receiver':'github_release.py', 'recovery':'release_recover.py', 'enrollment':'state_enrollment.py'}
    if not arguments or arguments[0] not in choices:
        raise SystemExit('Select receiver, recovery or enrollment')
    sys.dont_write_bytecode = True
    admin = _admin_module()
    states = ('dedicated', 'retiring') if arguments[0] == 'recovery' else ('dedicated',)
    generation = admin.load_generation(states=states)
    admin.pin_generation(generation)
    target = generation.path/choices[arguments[0]]
    admin.require_current(target, expected=generation, states=states)
    # The generation is physical and pinned. No later import follows a moving
    # symlink; the protected bootstrap core remains the already-loaded module.
    sys.path.insert(0, str(generation.path))
    sys.argv = [str(target), *arguments[1:]]
    namespace = {'__name__':'__main__', '__file__':str(target), '__package__':None,
                 '__builtins__':__builtins__}
    source = target.read_bytes()
    if admin.hashlib.sha256(source).hexdigest() != generation.files[target.name]:
        raise admin.AdminError('entry helper changed after admission')
    exec(compile(source, str(target), 'exec'), namespace)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('WhatsApp administration blocked; inspect owner, generation and journal before retrying') from None
