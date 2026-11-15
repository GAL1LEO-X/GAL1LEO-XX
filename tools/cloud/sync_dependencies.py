"""Check or prune Python distributions against the pinned requirements of a venv."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tomllib

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT=Path(__file__).resolve().parents[2]


def locked_requirements(path,environment):
    result={}
    for raw in path.read_text().splitlines():
        line=raw.strip()
        if not line or line.startswith('#'): continue
        if line.startswith('-r '):
            result.update(locked_requirements(path.parent/line[3:].strip(),environment))
            continue
        requirement=Requirement(line)
        if requirement.marker and not requirement.marker.evaluate(environment): continue
        pins=list(requirement.specifier)
        if requirement.url or len(pins)!=1 or pins[0].operator!='==' or '*' in pins[0].version:
            raise ValueError('Requirements must contain exact version pins')
        result[canonicalize_name(requirement.name)]=pins[0].version
    return result


def inventory(python):
    source=('import importlib.metadata as m,json,sys; '
            'print(json.dumps({"isolated":sys.prefix!=sys.base_prefix,"python":sys.version.split()[0],'
            '"packages":{d.metadata["Name"]:d.version for d in m.distributions()}}))')
    value=json.loads(subprocess.check_output([str(python),'-c',source],text=True))
    value['packages']={canonicalize_name(name):version for name,version in value['packages'].items()}
    return value


def synchronize(python,requirements,*,project=None,prune=False):
    current=inventory(python)
    if not current['isolated']: raise ValueError('Dependency synchronization requires an isolated virtualenv')
    environment=default_environment()
    environment.update(python_full_version=current['python'],python_version='.'.join(current['python'].split('.')[:2]))
    wanted=locked_requirements(Path(requirements),environment)
    if project:
        metadata=tomllib.loads(Path(project).read_text())['project']
        wanted[canonicalize_name(metadata['name'])]=metadata['version']
    missing=sorted(set(wanted)-set(current['packages']))
    mismatched=sorted(name for name,version in wanted.items() if name in current['packages'] and current['packages'][name]!=version)
    if missing or mismatched:
        raise ValueError(f'Locked dependencies differ: missing={missing}; version_mismatch={mismatched}')
    # pip is the environment's installer, not an application dependency.
    extra=sorted(set(current['packages'])-set(wanted)-{'pip'})
    if extra and prune:
        subprocess.run([str(python),'-m','pip','--disable-pip-version-check','uninstall','-y',*extra],check=True)
        current=inventory(python)
        extra=sorted(set(current['packages'])-set(wanted)-{'pip'})
        if any(current['packages'].get(name)!=version for name,version in wanted.items()):
            raise ValueError('Dependency inventory changed during synchronization')
    if extra: raise ValueError('Unpinned distributions remain: '+', '.join(extra))
    print(f'PASS exact dependency inventory ({len(wanted)} pinned distributions plus pip).')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prune',action='store_true')
    parser.add_argument('--requirements',type=Path,help='Explicit project lock; omitting it preserves the WhatsApp contract')
    parser.add_argument('--project',type=Path,help='Optional pyproject metadata for an installed project')
    args=parser.parse_args()
    requirements=args.requirements or ROOT/'plugins/whatsapp/requirements-test.lock'
    project=args.project if args.requirements else ROOT/'plugins/whatsapp/pyproject.toml'
    synchronize(sys.executable,requirements,project=project,prune=args.prune)


if __name__=='__main__': main()
