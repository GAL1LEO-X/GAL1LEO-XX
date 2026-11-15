"""Bounded public skill inventory shared by standalone and administrative exports."""
from pathlib import Path
import stat


SKILL_FILES = (
    'skills/whatsapp-setup/SKILL.md',
    'skills/whatsapp-use/SKILL.md',
    'skills/whatsapp-use/references/reading.md',
    'skills/whatsapp-use/references/actions-and-events.md',
    'skills/whatsapp-transcription/SKILL.md',
)
DEFAULT_CONNECT = 'https://whatsapp.example.invalid/connect'


def collect(template, connect_url, *, allow_legacy=False):
    """Copy only reviewed inputs; never recurse into operator files or links."""
    template = Path(template)
    files = {}
    paths = SKILL_FILES
    # An administration-only upgrade delivers scripts, not a new application
    # template. Preserve exports from its existing single-skill template. A
    # partially installed new template must still fail rather than lose skills.
    if allow_legacy and all(not (template / 'skills' / name).exists()
                            and not (template / 'skills' / name).is_symlink()
                            for name in ('whatsapp-use', 'whatsapp-transcription')):
        paths = ('skills/whatsapp-setup/SKILL.md',)
    for name in paths:
        path = template / name
        for parent in (template, *[template / part for part in Path(name).parents if part != Path('.')]):
            if parent.is_symlink() or not parent.is_dir():
                raise ValueError('Skill directory must be a regular directory')
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError('Skill input must be a regular file without links')
        if not 0 < metadata.st_size <= 1024 * 1024:
            raise ValueError('Skill input exceeds size limits or is empty')
        content = path.read_text(encoding='utf-8')
        files[name] = content.replace(DEFAULT_CONNECT, connect_url).encode('utf-8')
    return files
