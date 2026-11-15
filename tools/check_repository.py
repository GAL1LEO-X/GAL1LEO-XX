"""Validate repository hygiene without printing matched secrets or file contents."""
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DENIED_PARTS = {'private', 'secrets', 'state', 'node_modules', '.venv', '.venvs', '__pycache__'}
DENIED_NAMES = {'identity.json', 'tenants.json', 'config.toml', '.env'}
PATTERNS = [
    re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]{80,}'),
    re.compile(rb'\bgh[pousr]_[A-Za-z0-9]{30,}\b'),
    re.compile(rb'\bgithub_pat_[A-Za-z0-9_]{50,}\b'),
    re.compile(rb'\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b'),
    re.compile(rb'\beyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{20,}\b'),
]

def main():
    names = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT).decode().split('\0')
    errors = []
    count = 0
    for name in sorted(set(filter(None, names))):
        path = ROOT / name
        if not path.is_file():
            continue
        count += 1
        if path.is_symlink() or set(Path(name).parts) & DENIED_PARTS or path.name in DENIED_NAMES or path.suffix in {'.key', '.pem', '.sqlite', '.db', '.zip'}:
            errors.append(f'{name}: forbidden source artifact')
            continue
        data = path.read_bytes()
        if any(pattern.search(data) for pattern in PATTERNS):
            errors.append(f'{name}: possible embedded credential (content hidden)')
        if path.suffix == '.json':
            try: json.loads(data)
            except (ValueError, UnicodeError): errors.append(f'{name}: invalid JSON')
    operations = json.loads((ROOT / 'plugins/whatsapp/sally_whatsapp/operations.json').read_text())
    if not operations:
        errors.append('WhatsApp operation catalog is empty')
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print(f'PASS repository hygiene and JSON ({count} source files). This is a basic credential-pattern check, not a complete secret audit.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
