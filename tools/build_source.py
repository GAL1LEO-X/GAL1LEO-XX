"""Build a deterministic public project source archive with its shared source closure."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

import check_public

ROOT=Path(__file__).resolve().parents[1]
ROOT_FILES={'LICENSE','NOTICE','README.md','AGENTS.md','CONTRIBUTING.md','SECURITY.md',
            '.gitignore','.gitattributes','conftest.py','package.json','package-lock.json','playwright.config.js'}
TESLA_TOOLS={'tools/project.py','tools/build_source.py','tools/check_public.py'}


def build(project,output,*,root=ROOT):
    if project not in ('tesla','whatsapp'):raise ValueError('Choose tesla or whatsapp')
    names,errors=check_public.validate(root)
    if errors:raise ValueError('Public source validation failed: '+'; '.join(errors))
    output=Path(output)
    if output.exists() or output.is_symlink():raise ValueError('Output must be new')
    entries={}
    for name in names:
        selected=(name in ROOT_FILES or name.startswith(('docs/','plugins/'+project+'/'))
                  or (project=='whatsapp' and name.startswith(('host/','tools/','tests/browser/')))
                  or (project=='tesla' and (name in TESLA_TOOLS or name.startswith('tools/cloud/'))))
        if selected:entries[name]=(root/name).read_bytes()
    entries['README.md']=(f'# GAL1LEO {project.capitalize()} source\n\n'
        f'Developer: GAL1LEO — info@gal1leo.com. Original code: Apache-2.0.\n\n'
        f'Start at [the project guide](plugins/{project}/README.md). This bundle includes required shared source.\n'
        'Run the selected project tests from the repository root. The full monorepo is on '
        'https://github.com/GAL1LEO-X/GAL1LEO-XX.\n').encode()
    entries['docs/README.md']=(f'# Documentation\n\n'
        f'- [Project guide](../plugins/{project}/README.md)\n'
        '- [Development](DEVELOPMENT.md)\n').encode()
    entries['docs/DEVELOPMENT.md']=(f'# {project.capitalize()} source development\n\n'
        'Use Linux/WSL, Python 3.13 or 3.14 and Node.js 24. From the archive root:\n\n'
        '```sh\npython3.14 -m venv .venvs/development\n'
        f'.venvs/development/bin/python -m pip install -r plugins/{project}/requirements-test.lock\n'
        f'.venvs/development/bin/python -m pip install --no-deps -e plugins/{project}\n'
        'npm ci --ignore-scripts\nnpx playwright install chromium\n'
        f'.venvs/development/bin/python -m pytest plugins/{project}/tests -q\n```\n\n'
        'Install Chromium system libraries where necessary. Tests use synthetic state. '
        'Shared tooling tests spanning multiple projects run in the full public repository.\n').encode()
    manifest={name:hashlib.sha256(data).hexdigest() for name,data in sorted(entries.items())}
    entries['SHA256SUMS.json']=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode()
    output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for name,data in sorted(entries.items()):
            info=zipfile.ZipInfo(name,date_time=(2026,1,1,0,0,0))
            info.external_attr=0o100644<<16
            info.compress_type=zipfile.ZIP_DEFLATED
            archive.writestr(info,data,compresslevel=9)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:raise ValueError('Archive integrity check failed')
    return {'project':project,'files':len(entries),'sha256':hashlib.sha256(output.read_bytes()).hexdigest()}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project',choices=('tesla','whatsapp'))
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(build(args.project,args.output),indent=2))


if __name__=='__main__':main()
