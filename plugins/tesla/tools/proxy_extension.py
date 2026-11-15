"""Apply the reviewed local HTTP adapter to one exact upstream source snapshot."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    'gal1leo_extensions.go':'pkg/proxy/gal1leo_extensions.go',
    'gal1leo_extensions_test.go':'pkg/proxy/gal1leo_extensions_test.go',
    'gal1leo_vehicle.go':'pkg/vehicle/gal1leo_vehicle.go',
    'gal1leo_vehicle_test.go':'pkg/vehicle/gal1leo_vehicle_test.go',
    'gal1leo_commands.proto':'pkg/protocol/protobuf/gal1leo_commands.proto',
    'gal1leo_commands.pb.go':'pkg/protocol/protobuf/gal1leo/gal1leo_commands.pb.go',
    'LICENSE.txt':'GAL1LEO-LICENSE.txt', 'NOTICE.txt':'GAL1LEO-NOTICE.txt',
    'TESLEMETRY-NOTICE.txt':'TESLEMETRY-NOTICE.txt',
    'provenance.json':'GAL1LEO-provenance.json',
}
FILES = ('proxy.patch', *TARGETS)


def source_hashes():
    return {name: hashlib.sha256((ROOT/'deploy/proxy-extension'/name).read_bytes()).hexdigest() for name in FILES}


def apply(context, lock):
    spec = lock['vehicle_command']['extension']
    if spec['protocol'] != 'gal1leo-vehicle-command/2' or source_hashes() != spec['sources_sha256']:
        raise ValueError('Proxy extension inputs differ from the reviewed lock')
    # Do not let git discover the containing PLUGINS worktree.
    env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(context.parent))
    patch = ROOT/'deploy/proxy-extension/proxy.patch'
    subprocess.run(['git', 'apply', '--check', '--whitespace=error-all', str(patch)], cwd=context, env=env, check=True)
    subprocess.run(['git', 'apply', str(patch)], cwd=context, env=env, check=True)
    for name, relative in TARGETS.items():
        target = context/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT/'deploy/proxy-extension'/name, target)
    return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()
