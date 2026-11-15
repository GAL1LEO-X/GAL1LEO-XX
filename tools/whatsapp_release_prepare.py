"""Prepare a new backend release with an exactly unchanged, pinned provider.

No GitHub writes. All source bytes are obtained from explicit Git objects. The
runtime download is pinned by ID, bytes and SHA256; a real qualification runner
must succeed before candidate.json is created. Failed preparation keeps its own
scratch directory for diagnosis and never changes an existing destination.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib

try:
    from .whatsapp_release_common import ReleaseError, canonical_json, sha256_file, verify_candidate, validate_manifest, validate_provider_tag, safe_basename, WORKFLOW_PATH, MAX_ASSET_BYTES
    from .whatsapp_release_sources import prepare_sources, snapshot_commit, verified_tar
    from .whatsapp_release_runtime import qualify_runtime
except ImportError:
    from whatsapp_release_common import ReleaseError, canonical_json, sha256_file, verify_candidate, validate_manifest, validate_provider_tag, safe_basename, WORKFLOW_PATH, MAX_ASSET_BYTES
    from whatsapp_release_sources import prepare_sources, snapshot_commit, verified_tar
    from whatsapp_release_runtime import qualify_runtime

REPOSITORY = "GAL1LEO-X/GAL1LEO-XX"
LOCK_PATH = "tools/whatsapp-release-provider.lock.json"
LOCK_SCOPES = (
    "plugins/whatsapp/provider-checkpoint/",
    "plugins/whatsapp/deploy/images.lock.json",
    "plugins/whatsapp/deploy/whatsapp-waha.container",
)
REUSED_ROLES = frozenset({"gows_source", "waha_source", "toolchain_source", "debian_source_1",
    "debian_source_2", "debian_source_3", "debian_source_4", "npm_sources", "source_notices", "runtime_oci"})
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
QUALIFICATION_FILES = frozenset({"result.json", "backend.xml", "runtime-contract.json",
    *(label + suffix for label in ("backend", "image-load", "probe", "startup", "backend-contract")
      for suffix in (".stdout", ".stderr"))})
REVIEW = re.compile(r"https://github\.com/GAL1LEO-X/GAL1LEO-XX/pull/[1-9][0-9]*(?:#[A-Za-z0-9_-]+)?\Z")


def require(value, message):
    if not value:
        raise ReleaseError(message)


def git(repo, *args):
    try:
        return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as exc:
        raise ReleaseError("Cannot read required committed release inputs") from exc


def _json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "Duplicate JSON key in provider lock")
            value[key] = item
        return value
    def invalid(_value):
        raise ReleaseError("Invalid JSON number in provider lock")
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, UnicodeError) as exc:
        raise ReleaseError("Invalid provider lock JSON") from exc


def provider_fingerprint(repo: Path, commit: str) -> list[dict]:
    """Include path and Git mode, and detect additions/deletions in every scope."""
    require(isinstance(commit, str) and HEX40.fullmatch(commit), "Full commit SHA required")
    result = []
    for record in git(repo, "ls-tree", "-r", "-z", "--full-tree", commit, "--", *LOCK_SCOPES).split(b"\0"):
        if not record:
            continue
        header, raw_name = record.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split()
        name = raw_name.decode("utf-8")
        require(kind == "blob" and mode in {"100644", "100755"}, "Provider inputs must be regular Git blobs")
        data = git(repo, "cat-file", "blob", oid)
        result.append({"path": name, "mode": mode, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    require(result, "No provider/runtime inputs at target commit")
    return sorted(result, key=lambda row: row["path"])


def load_provider_lock(repo: Path, workflow_commit: str, target_commit: str) -> tuple[dict, str]:
    """Read reviewed policy from W, compare actual target T, never the worktree."""
    data = git(repo, "show", f"{workflow_commit}:{LOCK_PATH}")
    lock = _json(data)
    require(isinstance(lock, dict) and type(lock.get("schema_version")) is int and lock["schema_version"] == 1,
            "Unsupported provider lock schema")
    require(lock.get("repository") == REPOSITORY, "Provider lock repository mismatch")
    require(type(lock.get("source_release_id")) is int and lock["source_release_id"] > 0, "Invalid source release ID")
    fingerprint = lock.get("fingerprint", {})
    require(isinstance(fingerprint, dict), "Invalid provider fingerprint")
    require(fingerprint.get("scopes") == list(LOCK_SCOPES), "Provider fingerprint scope mismatch")
    expected = fingerprint.get("entries")
    require(isinstance(expected, list) and expected, "Provider input fingerprint missing")
    require(hashlib.sha256(canonical_json(expected)).hexdigest() == fingerprint.get("sha256"),
            "Provider fingerprint digest mismatch")
    require(canonical_json(provider_fingerprint(repo, target_commit)) == canonical_json(expected),
            "Provider/runtime inputs changed: full provider rebuild and new qualification required; reuse refused")
    assets = lock.get("assets")
    require(isinstance(assets, list) and len(assets) == 10, "Provider lock must contain ten assets")
    names, roles, ids = set(), set(), set()
    for asset in assets:
        require(isinstance(asset, dict) and set(asset) == {"name", "bytes", "sha256", "role", "origin"}, "Invalid locked asset")
        name, role, origin = asset["name"], asset["role"], asset["origin"]
        safe_basename(name)
        require(name.casefold() not in names, "Unsafe or duplicate locked asset name")
        require(isinstance(role, str) and role in REUSED_ROLES and role not in roles, "Unknown or duplicate provider asset role")
        require(type(asset["bytes"]) is int and 0 < asset["bytes"] <= MAX_ASSET_BYTES, "Invalid locked asset size")
        require(isinstance(asset["sha256"], str) and HEX64.fullmatch(asset["sha256"]), "Invalid locked asset digest")
        require(isinstance(origin, dict) and set(origin) == {"kind", "release_id", "asset_id", "tag"}
                and origin["kind"] == "reused", "Invalid reused asset origin")
        require(type(origin["release_id"]) is int and origin["release_id"] > 0
                and type(origin["asset_id"]) is int and origin["asset_id"] > 0, "Invalid release or asset ID")
        require(origin["release_id"] == lock.get("source_release_id") and origin["tag"] == lock.get("source_tag"),
                "Reused asset release identity mismatch")
        validate_provider_tag(origin["tag"])
        require(origin["asset_id"] not in ids, "Duplicate asset ID in provider lock")
        names.add(name.casefold()); roles.add(role); ids.add(origin["asset_id"])
    require(roles == REUSED_ROLES, "Incomplete provider asset roles")
    require(sum(a["bytes"] for a in assets) < 4 * 1024**3, "Locked assets exceed candidate budget")
    runtime = lock.get("runtime")
    require(isinstance(runtime, dict) and set(runtime) == {"config_digest", "manifest_digest", "gows_sha256"}, "Invalid runtime identity")
    require(all(isinstance(runtime[k], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", runtime[k])
                for k in ("config_digest", "manifest_digest")) and isinstance(runtime["gows_sha256"], str)
                and HEX64.fullmatch(runtime["gows_sha256"]), "Invalid runtime digest")
    return lock, hashlib.sha256(data).hexdigest()


def _validate_context(repo, target_commit, workflow_commit, version, ci, review, run):
    require(isinstance(target_commit, str) and HEX40.fullmatch(target_commit)
            and isinstance(workflow_commit, str) and HEX40.fullmatch(workflow_commit), "Explicit full target/workflow commits required")
    for value in (target_commit, workflow_commit):
        require(git(repo, "rev-parse", "--verify", value + "^{commit}").decode().strip() == value, "Commit identity mismatch")
    require(isinstance(version, str) and VERSION.fullmatch(version), "Stable backend semantic version required")
    project = tomllib.loads(git(repo, "show", f"{target_commit}:plugins/whatsapp/pyproject.toml").decode())
    require(project.get("project", {}).get("version") == version, "Target backend version mismatch")
    nodes = ast.parse(git(repo, "show", f"{target_commit}:plugins/whatsapp/sally_whatsapp/__init__.py"))
    versions = [ast.literal_eval(node.value) for node in nodes.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)]
    require(versions == [version], "Target package __version__ mismatch")
    require(isinstance(ci, dict) and ci.get("head_sha") == target_commit and ci.get("status") == "completed"
            and ci.get("conclusion") == "success" and type(ci.get("id")) is int and ci["id"] > 0
            and type(ci.get("run_attempt")) is int and ci["run_attempt"] > 0, "Exact successful target CI evidence required")
    require(isinstance(review, str) and len(review) <= 512 and REVIEW.fullmatch(review), "Explicit repository PR review evidence URL required")
    require(isinstance(run, dict) and set(run) == {"id", "attempt", "workflow_path"}
            and type(run.get("id")) is int and run["id"] > 0 and type(run.get("attempt")) is int and run["attempt"] > 0,
            "Exact preparation run identity required")
    require(run["workflow_path"] == WORKFLOW_PATH,
            "Invalid preparation workflow path")


def _qualification_report(report, target, workflow, runtime):
    require(isinstance(report, dict) and report.get("passed") is True, "Current candidate qualification failed")
    require(report.get("target_commit") == target and report.get("workflow_commit") == workflow
            and report.get("runtime_config_digest") == runtime, "Qualification identity does not match current candidate")
    checks = report.get("checks", {})
    for check in ("backend_regressions", "runtime_smoke", "runtime_backend_contract"):
        value = checks.get(check, {})
        require(value.get("executed") is True and value.get("passed") is True, f"Current {check} execution is required")


def prepare_candidate(repo: Path, target_commit: str, workflow_commit: str, version: str,
                      output: Path, github, ci_evidence: dict, review_evidence: str,
                      prepared_run: dict, qualification_runner=None, *, python_executable=None) -> dict:
    """Build a complete candidate; injected runners are for synthetic unit tests.

    The caller is responsible for authenticated main/CI/review gates. This API
    checks their bound identities again. Default qualification executes current
    tests plus an isolated runtime; it never accepts a historical PASS receipt.
    """
    repo = Path(repo).resolve(strict=True)
    _validate_context(repo, target_commit, workflow_commit, version, ci_evidence, review_evidence, prepared_run)
    lock, lock_sha = load_provider_lock(repo, workflow_commit, target_commit)
    output = Path(output).absolute()
    require(output.parent.resolve(strict=True) == output.parent, "Output parent must be a physical directory")
    require(not output.exists() and not output.is_symlink(), "Candidate destination must not exist")
    output.mkdir(mode=0o700)
    assets_dir = output / "assets"
    assets_dir.mkdir(mode=0o700)
    scratch = Path(tempfile.mkdtemp(prefix="whatsapp-release-prepare-", dir=output.parent))
    succeeded = False
    try:
        assets = []
        for item in lock["assets"]:
            path = assets_dir / item["name"]
            github.download_release_asset(item["origin"]["asset_id"], path, item["bytes"], item["sha256"])
            require(sha256_file(path) == (item["bytes"], item["sha256"]), "Downloaded provider asset differs from locked bytes")
            assets.append(item)
        assets.extend(prepare_sources(repo, target_commit, version, assets_dir))
        snapshot = scratch / "target"
        snapshot_commit(repo, target_commit, snapshot)
        runtime_asset = next(a for a in assets if a["role"] == "runtime_oci")
        runtime_metadata = dict(lock["runtime"], archive_sha256=runtime_asset["sha256"], archive_bytes=runtime_asset["bytes"],
                                target_commit=target_commit, workflow_commit=workflow_commit)
        qualification_dir = scratch / "qualification"
        runner = qualification_runner or qualify_runtime
        runner_arguments = {"image_archive": assets_dir / runtime_asset["name"], "runtime_metadata": runtime_metadata,
                            "source_snapshot": snapshot, "output": qualification_dir}
        if python_executable is not None:
            runner_arguments["python_executable"] = python_executable
        report = runner(**runner_arguments)
        _qualification_report(report, target_commit, workflow_commit, lock["runtime"]["config_digest"])
        require(qualification_dir.is_dir() and not qualification_dir.is_symlink(), "Qualification must produce current evidence")
        evidence = [("qualification.json", canonical_json(report), 0o644),
                    ("ci-reference.json", canonical_json({key: ci_evidence[key] for key in ("id", "run_attempt", "head_sha", "status", "conclusion")}), 0o644),
                    ("review-reference.json", canonical_json({"review_evidence": review_evidence, "kind": "operator-attestation-reference"}), 0o644)]
        # Never package HOME, pytest temporary data, keys or fixture databases.
        # Only the explicitly named technical receipts/logs belong in a release.
        require((qualification_dir / "result.json").is_file(), "Qualification evidence files missing")
        for file in sorted(qualification_dir.iterdir()):
            require(not file.is_symlink(), "Qualification evidence contains a symlink")
            if file.is_dir():
                require(file.name in {"home", "temporary", "pytest-data"}, "Unexpected qualification data directory")
                continue
            require(file.name in QUALIFICATION_FILES, "Unexpected qualification evidence file")
            size, _sha = sha256_file(file)
            require(size <= 32 * 1024**2, "Qualification evidence file exceeds bound")
            data = file.read_bytes()
            if file.name == "result.json":
                require(canonical_json(_json(data)) == canonical_json(report), "Stored qualification receipt differs from returned evidence")
            evidence.append(("executed/" + file.name, data, 0o644))
        evidence.append(("LIMITS.md", ("Current offline backend regressions and isolated no-account runtime qualification.\n"
            "Provider/source assets reused with original version and names. No server, live WhatsApp, phone,\n"
            "Podman or full provider rebuild is certified. Prior release receipts are not current PASS.\n").encode(), 0o644))
        epoch = int(git(repo, "show", "-s", "--format=%ct", target_commit))
        validation = verified_tar(assets_dir / f"whatsapp-validation-{version}.tar.gz", evidence, "whatsapp-validation", epoch)
        assets.append(dict(validation, role="validation", origin={"kind": "built", "commit": target_commit}))
        notes = (f"WhatsApp {version}\n\nBackend commit: {target_commit}\nWorkflow commit: {workflow_commit}\n"
                 f"Provider/runtime components retained from {lock['source_tag']} (release {lock['source_release_id']}).\n"
                 "The ten reused asset names and original component version are intentionally unchanged.\n"
                 "The two source archives contain the current committed backend/repository; validation contains\n"
                 "fresh offline backend and isolated runtime receipts for this candidate.\n"
                 "No deployment, account connectivity, phone behavior or full native reproducibility is claimed.\n"
                 "The provider rebuild path is not supported by this preparer; changed inputs fail closed.\n").encode()
        notes_path = output / "RELEASE-NOTES.md"
        with notes_path.open("xb") as handle:
            handle.write(notes)
        manifest = {"schema_version": 1, "repository": REPOSITORY, "target_commit": target_commit,
                    "target_tree": git(repo, "rev-parse", target_commit + "^{tree}").decode().strip(),
                    "workflow_commit": workflow_commit, "version": version, "tag": f"whatsapp/v{version}",
                    "provider_lock_sha256": lock_sha,
                    "runtime": {key: lock["runtime"][key] for key in ("config_digest", "manifest_digest")},
                    "prepared_run": prepared_run,
                    "qualification": {"kind": "offline", "target_commit": target_commit, "workflow_commit": workflow_commit,
                        "runtime_config_digest": lock["runtime"]["config_digest"], "ci_run_id": ci_evidence["id"],
                        "ci_run_attempt": ci_evidence["run_attempt"], "review_evidence": review_evidence},
                    "notes": {"name": notes_path.name, "bytes": len(notes), "sha256": hashlib.sha256(notes).hexdigest()},
                    "assets": sorted(assets, key=lambda asset: asset["role"])}
        validate_manifest(manifest)
        manifest_path = output / "candidate.json"
        with manifest_path.open("xb") as handle:
            handle.write(canonical_json(manifest))
        try:
            result = verify_candidate(output)
        except Exception:
            manifest_path.unlink()  # Our just-created incomplete handoff only.
            raise
        succeeded = True
        return result
    finally:
        if succeeded:
            shutil.rmtree(scratch)  # Only this call's private scratch, never the destination.
