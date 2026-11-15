#!/usr/bin/python3
"""Permanent WhatsApp receiver at the historical forced-command entry path."""
import os
from pathlib import Path
import stat
import sys

# The root-protected launcher is installed only at the independently admitted
# receiver destination. Its sibling bootstrap validates the configured path
# and the installation digest before selecting any generation.
ENTRY = Path(__file__)
BOOTSTRAP = ENTRY.parent.parent/'whatsapp-bootstrap/release_entry.py'
PYTHON = Path('/usr/bin/python3')
_TRUST_ROOT = Path('/')


def _trusted_uid(uid):
    return uid == 0


def protected(path):
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise RuntimeError('Receiver requires physical protected paths')
    relative = path.relative_to(_TRUST_ROOT)
    current = _TRUST_ROOT
    for index, part in enumerate(('', *relative.parts)):
        if part:
            current = current / part
        info = current.lstat()
        kind = stat.S_ISREG if index == len(relative.parts) else stat.S_ISDIR
        if not kind(info.st_mode) or not _trusted_uid(info.st_uid) or info.st_mode & 0o022:
            raise RuntimeError('Receiver path protection differs')


def main(argv=None):
    if Path(__file__) != ENTRY:
        raise RuntimeError('Receiver is not at its inventoried external path')
    for path in (ENTRY, BOOTSTRAP, BOOTSTRAP.parent / 'release_admin.py', PYTHON.resolve(strict=True)):
        protected(path)
    arguments = list(sys.argv[1:] if argv is None else argv)
    os.execv(str(PYTHON), [str(PYTHON), '-I', '-B', str(BOOTSTRAP), 'receiver', *arguments])


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('WhatsApp receiver unavailable; inspect the protected administrative installation') from None
