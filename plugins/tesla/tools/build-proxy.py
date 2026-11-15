"""Build the native proxy from a pinned public checkout; no service/vehicle access.

Uses the locked compiler container and the existing module cache read-only.
Tests and compilation have no network. The caller supplies an upstream checkout
and a previously populated Go module cache; no download adapter is introduced.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
from proxy_extension import apply

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream-checkout',type=Path,required=True)
    parser.add_argument('--module-cache',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--build-cache',type=Path,help='Optional reusable Go compilation cache; source work directory remains new')
    args=parser.parse_args()
    work=args.work.resolve(); work.mkdir(parents=True,exist_ok=False)
    lock=json.loads((ROOT/'deploy/components.lock.json').read_text())
    pin=lock['vehicle_command']['commit']
    archive=subprocess.check_output(['git','-C',str(args.upstream_checkout.resolve()),'archive',pin])
    source=work/'source';source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as data: data.extractall(source,filter='data')
    extension=apply(source,lock)
    env={k:v for k,v in os.environ.items() if k not in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH')}
    command=['docker','--host=unix:///var/run/docker.sock','run','--rm','--network','none',
             '--platform',lock['platform'],'-v',str(source)+':/source','-v',str(args.module_cache.resolve())+':/go/pkg/mod:ro',
             '-v',str(args.build_cache.resolve() if args.build_cache else work/'go-cache')+':/root/.cache/go-build','-w','/source','-e','GOFLAGS=-buildvcs=false','-e','GOPROXY=off',
             lock['go_build_image']]
    with (work/'tests.log').open('x') as log:
        subprocess.run(command+['go','test','-race','./pkg/proxy','./pkg/vehicle'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    with (work/'build.log').open('x') as log:
        subprocess.run(command[:-1]+['-e','CGO_ENABLED=0',command[-1],'go','build','-trimpath','-o','tesla-http-proxy','./cmd/tesla-http-proxy'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    binary=source/'tesla-http-proxy'
    receipt={'upstream_commit':pin,'extension_hash':extension,'extension':lock['vehicle_command']['extension'],
             'compiler_image':lock['go_build_image'],'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
             'offline_tests':'go test -race ./pkg/proxy ./pkg/vehicle','vehicle_tested':False}
    (work/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'binary':str(binary),'receipt':str(work/'receipt.json'),'sha256':receipt['binary_sha256']}))

if __name__=='__main__': main()
