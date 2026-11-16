#!/usr/bin/env python3
"""Build a backend-only deploy package on Debian 13/Python 3.13, without credentials.

Run this trusted controller against a separate clean checkout at the requested
commit. Provider assets are referenced, never downloaded or rebuilt here.

Upstream wheels are authorized by the controller's committed wheel policy,
seeded from official PyPI release metadata before downloading. That reviewed
snapshot fixes bytes; it is not independent upstream author authentication.
Only the application wheel built from the selected source gets a new hash.
"""
from __future__ import annotations

import argparse
import ast
from email.parser import BytesParser
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from urllib.parse import urlsplit
import zipfile

from whatsapp_release_prepare import provider_fingerprint

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "GAL1LEO-X/GAL1LEO-XX"
TARGET = {"os": "linux", "arch": "x86_64", "distro": "debian", "distro_major": 13, "python": "3.13"}
BUILD_REQUIREMENTS = {"setuptools": "84.0.0"}
WHEEL_POLICY = "tools/whatsapp-deploy-wheels.lock.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(args, *, cwd=None, env=None):
    return subprocess.run([str(item) for item in args], cwd=cwd, env=env,
                          check=True, capture_output=True, text=True)


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def require_target():
    require(sys.platform == "linux" and platform.machine() == "x86_64"
            and sys.version_info[:2] == (3, 13), "Build requires Linux x86_64 Python 3.13")
    release = platform.freedesktop_os_release()
    require(release.get("ID") == "debian" and release.get("VERSION_ID") == "13",
            "Build requires Debian 13; no cross-platform wheel inference")


def clean_source(source, commit):
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "Full lowercase source SHA required")
    require(run(["git", "rev-parse", "HEAD"], cwd=source).stdout.strip() == commit,
            "Source checkout does not match requested SHA")
    require(not run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=source).stdout,
            "Source checkout must be clean, including untracked files")
    entries = run(["git", "ls-files", "-s", "--", "plugins/whatsapp"], cwd=source).stdout.splitlines()
    require(entries and all(line.startswith(("100644 ", "100755 ")) for line in entries),
            "Application inputs must be regular Git files")


def runtime_requirements(path):
    """The current lock has exact pins and only one reviewed platform marker."""
    result = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == 'pywin32==312 ; sys_platform == "win32"':
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9.+-]*)", line)
        require(match, "Runtime lock needs reviewed exact pins; URLs, options and unknown markers refused")
        name, version = normalized(match[1]), match[2]
        require(name not in result, "Duplicate runtime distribution")
        result[name] = version
    require(result, "Empty runtime lock")
    return result


def materialize_application(source, commit, destination):
    """Read only committed Git blobs; ignored worktree data is never a build input."""
    prefix = 'plugins/whatsapp/'
    listing = subprocess.check_output(['git', '-C', str(source), 'ls-tree', '-r', '-z', '--full-tree', commit,
                                      '--', 'plugins/whatsapp'], stderr=subprocess.PIPE)
    destination.mkdir()
    seen = set()
    for record in listing.split(b'\0'):
        if not record: continue
        header, raw_name = record.split(b'\t', 1)
        mode, kind, oid = header.decode('ascii').split()
        name = raw_name.decode('utf-8')
        require(kind == 'blob' and mode in ('100644', '100755') and name.startswith(prefix),
                'Application build requires regular committed blobs')
        relative = name[len(prefix):]
        require(relative and '\\' not in relative and '..' not in relative.split('/')
                and not relative.startswith('/') and relative.casefold() not in seen,
                'Unsafe application source path')
        seen.add(relative.casefold())
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(subprocess.check_output(['git', '-C', str(source), 'cat-file', 'blob', oid], stderr=subprocess.PIPE))
        target.chmod(0o755 if mode == '100755' else 0o644)
    require(seen, 'Application source is empty')


def declaration(path, name):
    for node in ast.parse(Path(path).read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(isinstance(item, ast.Name) and item.id == name for item in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError("Missing literal application declaration: " + name)


def provider_reference(source, commit, control=ROOT):
    # Policy belongs to the trusted controller, never the selected application.
    path = control / "tools/whatsapp-release-provider.lock.json"
    require(path.is_file(), "Configure your independently qualified provider release policy first; see tools/templates/provider-release.example.json")
    lock = json.loads(path.read_bytes())
    require(lock.get("repository") == REPOSITORY and lock.get("schema_version") == 1,
            "Provider policy identity differs")
    expected = lock["fingerprint"]["entries"]
    canonical = json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    # The existing provider policy uses canonical JSON with a trailing newline.
    require(hashlib.sha256(canonical + b"\n").hexdigest() == lock["fingerprint"]["sha256"],
            "Provider policy fingerprint differs")
    require(provider_fingerprint(source, commit) == expected,
            "Provider inputs changed: separate provider build/qualification required")
    return {"format": "whatsapp-provider-reference-v1", "policy_sha256": digest(path),
            "source_commit": lock["source_commit"], "source_tag": lock["source_tag"],
            "source_release_id": lock["source_release_id"], "repository": REPOSITORY,
            "runtime": lock["runtime"], "assets": lock["assets"],
            "inputs_sha256": lock["fingerprint"]["sha256"]}


def wheel_identity(path):
    require(path.suffix == ".whl" and path.is_file() and not path.is_symlink(), "Only regular wheels are admitted")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        # Vendored libraries (notably setuptools) can carry nested dist-info.
        # Only the wheel's top-level dist-info identifies its distribution.
        metadata = [name for name in names if name.count("/") == 1 and name.endswith(".dist-info/METADATA")]
        require(len(metadata) == 1, "Wheel must contain one distribution metadata record")
        for name in names:
            require(not name.startswith(("/", "\\")) and "\\" not in name
                    and ".." not in name.split("/"), "Unsafe wheel member")
        value = BytesParser().parsebytes(archive.read(metadata[0]))
        require(value["Name"] and value["Version"], "Wheel metadata is incomplete")
        return normalized(value["Name"]), value["Version"]


def dependency_policy(expected, control=ROOT):
    """Policy is an input from trusted control, never generated by the build."""
    policy = json.loads((control / WHEEL_POLICY).read_bytes())
    require(set(policy) == {"format", "repository", "target", "provenance", "runtime", "build"}
            and policy["format"] == "whatsapp-deploy-wheels-v1"
            and policy["repository"] == REPOSITORY and policy["target"] == TARGET,
            "Wheel policy identity or target differs")
    for group, pins in (("runtime", expected), ("build", BUILD_REQUIREMENTS)):
        entries = policy[group]
        require(type(entries) is dict and set(entries) == set(pins), "Wheel policy pin set differs")
        for name, item in entries.items():
            require(type(item) is dict and set(item) == {"version", "filename", "sha256", "url", "metadata_url"},
                    "Wheel policy entry is incomplete")
            require(item["version"] == pins[name]
                    and type(item["filename"]) is str
                    and re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", item["filename"])
                    and type(item["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]),
                    "Wheel policy version, filename or hash differs")
            require(type(item["url"]) is str
                    and re.fullmatch(r"https://files\.pythonhosted\.org/packages/[A-Za-z0-9/_.+-]+", item["url"]),
                    "Wheel policy URL is invalid")
            url = urlsplit(item["url"])
            require(url.scheme == "https" and url.netloc == "files.pythonhosted.org"
                    and url.path.startswith("/packages/") and url.path.rsplit("/", 1)[-1] == item["filename"]
                    and not url.query and not url.fragment,
                    "Wheel policy requires an exact official PyPI file URL")
            require(item["metadata_url"] == f"https://pypi.org/pypi/{name}/{pins[name]}/json",
                    "Wheel policy metadata source differs")
    return policy


def locked_requirements(entries, *, remote=False):
    return "".join(f"{name} @ {item['url']} --hash=sha256:{item['sha256']}\n" if remote else
                   f"{name}=={item['version']} --hash=sha256:{item['sha256']}\n"
                   for name, item in sorted(entries.items()))


def verify_locked_wheel(path, name, item):
    # Check the pre-existing digest before parsing downloaded ZIP contents.
    require(path.is_file() and not path.is_symlink() and path.name == item["filename"]
            and digest(path) == item["sha256"], "Downloaded wheel differs from trusted policy")
    require(wheel_identity(path) == (name, item["version"]), "Wheel metadata differs from trusted policy")


def download_locked_wheels(entries, destination, requirements, env):
    destination.mkdir()
    requirements.write_text(locked_requirements(entries, remote=True), encoding="utf-8")
    # Public wheel downloads use the configured network transport and CA trust.
    # Keep application build/install processes on the original isolated env;
    # never inherit unrelated credentials, pip indexes or Python settings.
    network_keys = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
                    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
                    "CURL_CA_BUNDLE", "PIP_CERT")
    download_env = {**env, **{name: os.environ[name] for name in network_keys if name in os.environ}}
    # Direct URLs plus local hashes admit no new compatible wheel for a pinned
    # version, and --no-index avoids consulting mutable index selections.
    run([sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--no-deps",
         "--no-index", "--no-cache-dir", "--require-hashes", "--dest", destination,
         "--requirement", requirements], env=download_env)
    require({path.name for path in destination.iterdir()} == {item["filename"] for item in entries.values()},
            "Downloaded wheelhouse differs from trusted policy")
    for name, item in entries.items():
        verify_locked_wheel(destination / item["filename"], name, item)


def hash_lock(wheels, runtime, application):
    """Recheck upstream policy; record a new digest only for our built wheel."""
    app_name, app_version = application
    require(app_name not in runtime, "Application distribution collides with runtime dependency")
    expected = {name: item["version"] for name, item in runtime.items()}
    expected[app_name] = app_version
    upstream = {item["filename"]: name for name, item in runtime.items()}
    actual = {}
    for path in sorted(wheels.iterdir()):
        if path.name in upstream:
            name = upstream[path.name]
            verify_locked_wheel(path, name, runtime[name])
        name, version = wheel_identity(path)
        require(name not in actual and expected.get(name) == version,
                "Unexpected, duplicate or incorrectly versioned wheel")
        if name in runtime:
            verify_locked_wheel(path, name, runtime[name])
            sha = runtime[name]["sha256"]
        else:
            sha = digest(path)
        actual[name] = (version, sha)
    require(set(actual) == set(expected), "Wheelhouse is incomplete")
    return "".join(f"{name}=={version} --hash=sha256:{sha}\n"
                   for name, (version, sha) in sorted(actual.items()))


def write_archive(payload, output, *, commit, version, schema, build):
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "Invalid commit")
    require(type(schema) is int and schema >= 0, "Invalid data schema")
    require(build["repository"] == REPOSITORY and type(build["run_id"]) is int and build["run_id"] > 0
            and type(build["run_attempt"]) is int and build["run_attempt"] > 0
            and re.fullmatch(re.escape(REPOSITORY) + r"/\.github/workflows/[a-zA-Z0-9_.-]+\.yml@[0-9a-f]{40}", build["workflow_ref"]),
            "Build provenance must name the trusted workflow SHA and positive run identifiers")
    files, contents = [], {}
    for path in sorted(payload.rglob("*")):
        require(not path.is_symlink(), "Payload symlinks are forbidden")
        if path.is_dir():
            continue
        require(path.is_file(), "Payload must contain regular files")
        name = "payload/" + path.relative_to(payload).as_posix()
        require(name.casefold() not in {item.casefold() for item in contents}, "Case-folded payload collision")
        data = path.read_bytes()
        contents[name] = data
        files.append({"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": 420})
    manifest = {"format": "gal1leo-deploy-v1", "min_engine": 1, "app": "whatsapp",
                "commit": commit, "version": version, "target": TARGET, "build": build,
                "data": {"schema": schema, "readable_schemas": [schema]}, "files": files}
    contents = {"manifest.json": encoded(manifest), **contents}
    require(len(contents["manifest.json"]) <= 65536, "Manifest exceeds server limit")
    require(not output.exists(), "Output already exists; refusing overwrite")
    output.parent.mkdir(parents=True, exist_ok=True)
    # A failed archive never becomes the advertised output.
    with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".deploy-", delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with temporary_path.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, data in contents.items():
                    info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o644
                    info.uid = info.gid = info.mtime = 0
                    archive.addfile(info, io.BytesIO(data))
        # No other builder is allowed to claim this output concurrently.
        os.link(temporary_path, output)
        return digest(output)
    finally:
        temporary_path.unlink(missing_ok=True)


def build_package(args):
    require_target()
    source, output = Path(args.source).resolve(), Path(args.output).resolve()
    clean_source(source, args.commit)
    require(not output.is_relative_to(source), "Output must be outside the clean source checkout")
    app = source / "plugins/whatsapp"
    project = tomllib.loads((app / "pyproject.toml").read_text(encoding="utf-8"))
    require(project["build-system"] == {"requires": ["setuptools==84.0.0"], "build-backend": "setuptools.build_meta"},
            "Build backend changed; update the trusted builder policy")
    version = project["project"]["version"]
    schema_sql = declaration(app / "sally_whatsapp/store.py", "SCHEMA")
    versions = re.findall(r"(?i)\bPRAGMA\s+user_version\s*=\s*(\d+)\s*;", schema_sql)
    require(len(versions) == 1, "Store schema must declare one literal user_version")
    schema = int(versions[0])
    require(declaration(app / "sally_whatsapp/__init__.py", "__version__") == version,
            "Package and runtime version differ")
    require(json.loads((app / "deploy/migrations.json").read_bytes())["schemaVersion"] == schema,
            "Application and migration schema differ")
    requirements = runtime_requirements(app / "requirements.lock")
    policy = dependency_policy(requirements)
    provider = provider_reference(source, args.commit)
    with tempfile.TemporaryDirectory(prefix="whatsapp-deploy-") as scratch:
        scratch = Path(scratch); payload = scratch / "payload"; wheels = payload / "wheelhouse"
        payload.mkdir()
        home = scratch / "home"; home.mkdir()
        env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": str(home),
               "LANG": "C.UTF-8", "PIP_CONFIG_FILE": os.devnull, "PIP_DISABLE_PIP_VERSION_CHECK": "1",
               "PYTHONNOUSERSITE": "1"}
        download_locked_wheels(policy["runtime"], wheels, scratch / "runtime-download.lock", env)
        backend_wheels = scratch / "build-wheels"
        download_locked_wheels(policy["build"], backend_wheels, scratch / "build-download.lock", env)
        backend_lock = scratch / "build-install.lock"
        backend_lock.write_text(locked_requirements(policy["build"]), encoding="utf-8")
        # A separate venv supplies the hash-checked build backend. Disabling pip
        # build isolation prevents it from fetching unchecked build dependencies.
        backend = scratch / "build-venv"
        run([sys.executable, "-m", "venv", backend], env=env)
        backend_python = backend / "bin/python"
        run([backend_python, "-m", "pip", "install", "--no-index", "--only-binary=:all:",
             "--require-hashes", "--find-links", backend_wheels, "--requirement", backend_lock], env=env)
        run([backend_python, "-m", "pip", "check"], env=env)
        # Build input is copied away from the committed checkout; setuptools may write metadata.
        build_source = scratch / "source"
        materialize_application(source, args.commit, build_source)
        run([backend_python, "-m", "pip", "wheel", "--no-deps", "--no-index", "--no-cache-dir",
             "--no-build-isolation", "--wheel-dir", wheels, build_source], env=env)
        application = (normalized(project["project"]["name"]), version)
        (payload / "requirements.lock").write_text(hash_lock(wheels, policy["runtime"], application), encoding="utf-8")
        (payload / "provider-reference.json").write_bytes(encoded(provider))
        (payload / "application.json").write_bytes(encoded({"name": project["project"]["name"], "version": version,
                                                           "schema": schema, "commit": args.commit}))
        # Test the same offline installation the server will perform, in a fresh final-path venv.
        probe = scratch / "offline-venv"
        run([sys.executable, "-m", "venv", probe], env=env)
        python = probe / "bin/python"
        run([python, "-m", "pip", "install", "--no-index", "--only-binary=:all:", "--require-hashes",
             "--find-links", wheels, "--requirement", payload / "requirements.lock"], env=env)
        run([python, "-m", "pip", "check"], env=env)
        run([python, "-I", "-c", "import sally_whatsapp, sally_whatsapp.server, sally_whatsapp.store; "
             "assert sally_whatsapp.__version__ == " + repr(version)], env=env)
        clean_source(source, args.commit)
        return write_archive(payload, output, commit=args.commit, version=version, schema=schema,
                             build={"repository": args.repository, "run_id": args.run_id,
                                    "run_attempt": args.run_attempt, "workflow_ref": args.workflow_ref})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("source", "output", "commit", "repository", "workflow-ref"):
        parser.add_argument("--" + option, required=True)
    for option in ("run-id", "run-attempt"):
        parser.add_argument("--" + option, required=True, type=int)
    args = parser.parse_args()
    try:
        value = build_package(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        # Child output may contain tool environment details; do not print it.
        print("Package build failed: " + (str(exc) if not isinstance(exc, subprocess.CalledProcessError)
                                        else "isolated dependency/build/offline validation command failed"), file=sys.stderr)
        return 1
    print(json.dumps({"package": str(Path(args.output).resolve()), "sha256": value}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
