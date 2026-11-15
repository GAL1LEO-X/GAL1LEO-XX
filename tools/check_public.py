"""Check public source/package inputs without exposing possible secret matches."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT=Path(__file__).resolve().parents[1]
IGNORED={'.git','.venv','.venvs','node_modules','work','outputs','__pycache__',
         '.pytest_cache','dist','playwright-report','test-results'}
SECRET_PATTERNS=[
    rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]{80,}',
    rb'\bgh[pousr]_[A-Za-z0-9]{30,}\b',
    rb'\bgithub_pat_[A-Za-z0-9_]{50,}\b',
    rb'\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b',
    rb'\beyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{20,}\b',
]


def files(root=ROOT):
    for parent,dirs,names in os.walk(root,followlinks=False):
        retained=[]
        for name in dirs:
            if name in IGNORED or name.endswith('.egg-info'):continue
            relative=(Path(parent)/name).relative_to(root).as_posix()
            if relative in ('plugins/tesla/build','plugins/whatsapp/build'):continue
            selected=Path(parent)/name
            if selected.is_symlink():yield selected
            else:retained.append(name)
        dirs[:]=retained
        for name in names:
            path=Path(parent)/name
            if path.suffix in {'.pyc','.pyo'}:continue
            yield path


def validate(root=ROOT):
    root=Path(root)
    errors=[]
    names=[]
    for path in files(root):
        name=path.relative_to(root).as_posix();names.append(name)
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
            errors.append(name+': source links or special files are forbidden');continue
        if (set(path.relative_to(root).parts)&{'private','secrets','state'}
                or path.name in {'.env','identity.json','tenants.json','config.toml','whatsapp-release-provider.lock.json'}
                or path.suffix in {'.key','.pem','.sqlite','.sqlite3','.db','.zip'}):
            errors.append(name+': private/generated artifact');continue
        data=path.read_bytes()
        if any(re.search(pattern,data) for pattern in SECRET_PATTERNS):
            errors.append(name+': possible credential (content hidden)')
        if path.suffix=='.json':
            try:json.loads(data)
            except (ValueError,UnicodeError):errors.append(name+': invalid JSON')
        if path.suffix=='.md':
            text=data.decode('utf-8')
            for target in re.findall(r'\[[^\]]*\]\(([^\s)]+)(?:\s+[^)]*)?\)',text):
                if re.match(r'[a-z][a-z0-9+.-]*:',target,re.I) or target.startswith(('#','/')):continue
                target=target.split('#',1)[0]
                if target and not (path.parent/target).exists():
                    errors.append(name+': missing relative link '+target)
    for folder in sorted((root/'plugins').iterdir()):
        if not folder.is_dir() or folder.name.startswith('.'):continue
        for name in ('LICENSE','NOTICE','THIRD_PARTY_NOTICES.md','README.md','AGENTS.md','project.json'):
            if not (folder/name).is_file():errors.append(str(folder.relative_to(root))+': missing '+name)
        manifest=folder/'plugin/plugin.json'
        if manifest.exists():
            value=json.loads(manifest.read_text())
            if value.get('author')!={'name':'GAL1LEO','email':'info@gal1leo.com'}:
                errors.append(str(manifest.relative_to(root))+': wrong developer attribution')
            if value.get('license')!='Apache-2.0':errors.append(str(manifest.relative_to(root))+': missing license')
            interface=value['extensions']['com.openai']['interface']
            if interface['developerName']!='GAL1LEO' or len(interface['shortDescription'])>30:
                errors.append(str(manifest.relative_to(root))+': invalid listing metadata')
        for skill in (folder/'plugin/skills').glob('*/SKILL.md'):
            text=skill.read_text()
            if not text.startswith('---\n') or 'name: '+skill.parent.name+'\n' not in text or '\ndescription:' not in text:
                errors.append(str(skill.relative_to(root))+': invalid skill frontmatter')
    return names,errors


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    args=parser.parse_args()
    names,errors=validate(args.root)
    if errors:
        print('\n'.join(errors));return 1
    print(f'PASS public-source checks: {len(names)} files, licenses, attribution, JSON and relative links')
    print('Credential patterns are a basic check; manual content and archive review remain required.')
    return 0


if __name__=='__main__':raise SystemExit(main())
