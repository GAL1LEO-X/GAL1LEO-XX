"""Build pinned Tesla components in local Docker, without starting any service.

Use an ignored work directory. Managed proxy variables and CA trust are retained;
Docker always targets the local socket. No host tools or daemon settings change.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from proxy_extension import apply as apply_extension

ROOT = Path(__file__).resolve().parents[1]


def run(argv, **kw):
    return subprocess.run(argv, check=True, **kw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--component", choices=("vehicle_command", "fleet_telemetry", "all"), default="all")
    parser.add_argument("--ca-bundle", type=Path, default=Path(os.environ.get("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")))
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(work).free < 6*1024**3:
        raise SystemExit("Component builds require at least 6 GiB free; 12 GiB is recommended for both. No cleanup or environment change was performed.")
    lock = json.loads((ROOT/"deploy/components.lock.json").read_text())
    env = {k: v for k, v in os.environ.items() if k not in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")}
    docker = ["docker", "--host=unix:///var/run/docker.sock"]
    run(docker+["info", "--format", "{{.ServerVersion}}"], env=env)
    for name in ("vehicle_command", "fleet_telemetry"):
        if args.component not in ("all", name):
            continue
        spec = lock[name]
        checkout = work/name
        if not checkout.exists():
            run(["git", "clone", "--no-checkout", spec["repository"], str(checkout)])
            run(["git", "-C", str(checkout), "checkout", "--detach", spec["commit"]])
        head = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
        if head != spec["commit"]:
            raise ValueError("Existing build checkout is at a different commit; use a new work directory")
        # Export only the selected commit, never untracked files or credentials.
        context = work/(name+"-context")
        context.mkdir(exist_ok=False)
        import tarfile
        import io
        data = subprocess.check_output(["git", "-C", str(checkout), "archive", spec["commit"]])
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            archive.extractall(context, filter="data")
        extension_hash = apply_extension(context, lock) if name == "vehicle_command" else None
        shutil.copyfile(args.ca_bundle, context/"build-ca.crt")
        original = (context/"Dockerfile").read_text()
        first, remainder = original.split("\n", 1) if original.startswith("FROM ") else (None, None)
        if first is None:  # Official telemetry Dockerfile starts with a comment.
            index = original.index("FROM ")
            first, remainder = original[index:].split("\n", 1)
        build_image = lock.get(name+"_build_image", lock["go_build_image"])
        buildfile = f'FROM {build_image} AS build\nCOPY build-ca.crt /etc/ssl/certs/ca-certificates.crt\nENV GOFLAGS="-buildvcs=false"\n'+remainder
        if name == "vehicle_command":
            buildfile = buildfile.replace("RUN mkdir build", "RUN --network=none go test -race ./pkg/proxy ./pkg/vehicle\nRUN mkdir build")
        runtime = "gcr.io/distroless/static-debian12:nonroot" if name == "vehicle_command" else "gcr.io/distroless/cc-debian12:nonroot"
        buildfile = buildfile.replace("FROM "+runtime, "FROM "+lock[name+"_runtime"])
        buildfile = buildfile.replace("RUN wget ", "RUN wget -q --timeout=30 --tries=2 ")
        (context/"Dockerfile").write_text(buildfile)
        tag = "gal1leo-tesla-"+name.replace("_", "-")+":"+spec["commit"][:12]+("-"+extension_hash[:12] if extension_hash else "")
        log = work/(name+"-build.log")
        fd = os.open(log, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as output:
            print("Building "+name+"; detailed local log: "+str(log), flush=True)
            run(docker+["build", "--platform", lock["platform"], "--build-arg", "HTTP_PROXY", "--build-arg", "HTTPS_PROXY", "--build-arg", "NO_PROXY",
                        "--label", "org.opencontainers.image.revision="+spec["commit"], "-t", tag, str(context)], env=env, stdout=output, stderr=subprocess.STDOUT)
        identity = subprocess.check_output(docker+["image", "inspect", tag, "--format", "{{.Id}}"], env=env, text=True).strip()
        (work/(name+"-receipt.json")).write_text(json.dumps({"component": name, "commit": spec["commit"], "image": tag,
            "image_id": identity, "extension_hash": extension_hash, "extension": spec.get("extension"), "go_build_image": build_image, "vehicle_tested": False}, indent=2)+"\n")


if __name__ == "__main__":
    main()
