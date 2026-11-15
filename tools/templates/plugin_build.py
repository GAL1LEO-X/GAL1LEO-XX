"""Build this project's source archive. It is not a ChatGPT installer."""
import argparse
import hashlib
from pathlib import Path
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    # Explicit allowlist: never sweep a checkout or local runtime into a package.
    files = [root / 'VERSION', root / 'README.md', *sorted((root / 'src').glob('*.py'))]
    if args.output.exists() or args.output.is_symlink():
        parser.error('Output must be new; existing artifacts are preserved')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            if path.is_symlink() or not path.is_file():
                raise ValueError('Only regular source inputs are allowed')
            archive.write(path, path.relative_to(root))
    print('source_archive_sha256=' + hashlib.sha256(args.output.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
