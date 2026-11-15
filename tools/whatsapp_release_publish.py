#!/usr/bin/env python3
"""Publish an approved candidate without replacing tags, assets or releases.

The caller must first check the trusted workflow, preparation run and current CI.
This module adds the local-manifest and remote-release gates immediately around
publication. It has no command-line entry point and never discovers credentials.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
from urllib.parse import quote

from whatsapp_release_common import ReleaseError, sha256_file, validate_sha, verify_candidate
from whatsapp_release_github import APIError


class PublicationError(ReleaseError):
    """A stopped publication, with a credential-free receipt for the caller."""

    def __init__(self, message: str, receipt: dict):
        super().__init__(message)
        self.receipt = receipt


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def _positive_integer(value) -> bool:
    return type(value) is int and value > 0


def _object(value, message="Invalid GitHub object") -> dict:
    _require(type(value) is dict, message)
    return value


def _list(github, path: str, *, maximum: int) -> list:
    """Read the complete bounded collection; never silently accept truncation."""
    result = []
    for page in range(1, maximum // 100 + 2):
        batch = github.get(f"{path}?per_page=100&page={page}")
        _require(type(batch) is list and len(batch) <= 100, "Invalid GitHub collection")
        result.extend(batch)
        _require(len(result) <= maximum, "GitHub collection exceeds the review limit")
        if len(batch) < 100:
            return result
    raise ReleaseError("GitHub collection did not terminate")


def _tag_commit(github, tag: str) -> str | None:
    try:
        ref = _object(github.get("/git/ref/tags/" + quote(tag, safe="/")))
    except APIError as exc:
        if exc.status == 404:
            return None
        raise
    _require(ref.get("ref") == "refs/tags/" + tag, "GitHub returned another tag")
    target = _object(ref.get("object"), "Invalid tag target")
    seen = set()
    for _ in range(8):
        sha = validate_sha(target.get("sha"), length=40)
        if target.get("type") == "commit":
            return sha
        _require(target.get("type") == "tag" and sha not in seen, "Invalid annotated tag chain")
        seen.add(sha)
        annotated = _object(github.get("/git/tags/" + sha))
        _require(annotated.get("sha") == sha, "Annotated tag identity changed")
        target = _object(annotated.get("object"), "Invalid annotated tag target")
    raise ReleaseError("Annotated tag chain exceeds the review limit")


def _find_release(github, tag: str) -> dict | None:
    # Drafts may not be returned by /releases/tags/{tag}. Listing also lets us
    # reject multiple drafts for the same tag instead of choosing one silently.
    releases = _list(github, "/releases", maximum=10_000)
    matches = []
    for release in releases:
        release = _object(release)
        if release.get("tag_name") == tag:
            _require(_positive_integer(release.get("id")), "Invalid release identity")
            matches.append(release)
    _require(len(matches) <= 1, "Multiple releases claim the approved tag")
    if not matches:
        return None
    result = _object(github.get(f"/releases/{matches[0]['id']}"))
    _require(result.get("id") == matches[0]["id"], "Release identity changed")
    return result


def _validate_release(release: dict, manifest: dict, notes: str, *, expected_id=None) -> None:
    release = _object(release)
    _require(_positive_integer(release.get("id")), "Invalid release identity")
    if expected_id is not None:
        _require(release["id"] == expected_id, "Release identity changed")
    _require(type(release.get("draft")) is bool, "Invalid release state")
    _require(release.get("prerelease") is False, "Release is not ordinary")
    _require(release.get("tag_name") == manifest["tag"], "Release tag conflicts with candidate")
    _require(release.get("name") == "WhatsApp " + manifest["version"], "Release title conflicts with candidate")
    _require(release.get("body") == notes, "Release notes conflict with candidate")
    if release["draft"]:
        _require(release.get("published_at") is None, "Draft has inconsistent publication state")
        _require(release.get("target_commitish") == manifest["target_commit"], "Draft target is not the approved immutable commit")
    else:
        _require(type(release.get("published_at")) is str and bool(release["published_at"]), "Published release lacks publication evidence")


def _check_tag(github, manifest: dict, *, required: bool) -> str | None:
    target = _tag_commit(github, manifest["tag"])
    _require(target is None or target == manifest["target_commit"], "Tag points to another commit")
    _require(not required or target is not None, "Published release tag is missing")
    return target


def _check_asset(github, remote: dict, expected: dict) -> str:
    remote = _object(remote)
    _require(_positive_integer(remote.get("id")), "Invalid remote asset identity")
    _require(remote.get("name") == expected["name"], "Remote asset name changed")
    _require(remote.get("state") == "uploaded", "Remote asset is not completely uploaded")
    _require(type(remote.get("size")) is int and remote["size"] == expected["bytes"], "Remote asset size conflicts with approved bytes")
    digest = remote.get("digest")
    if digest is not None and digest != "":
        _require(digest == "sha256:" + expected["sha256"], "Remote asset digest conflicts with approved bytes")
        return "api-digest"
    # Older API responses may omit a digest. Only that missing-evidence case
    # permits a download; an explicit divergent digest is never overridden.
    with tempfile.TemporaryDirectory(prefix="whatsapp-release-readback-") as scratch:
        path = Path(scratch) / "asset"
        github.download_release_asset(remote["id"], path, expected["bytes"], expected["sha256"])
        _require(sha256_file(path) == (expected["bytes"], expected["sha256"]), "Downloaded remote asset differs from approved bytes")
    return "downloaded-bytes"


def _inventory(github, release_id: int, manifest: dict, *, complete: bool) -> dict:
    expected = {a["name"]: a for a in manifest["assets"]}
    remote = _list(github, f"/releases/{release_id}/assets", maximum=len(expected))
    names, ids = {}, set()
    for asset in remote:
        asset = _object(asset)
        name = asset.get("name")
        _require(type(name) is str and name in expected, "Release contains an unexpected asset")
        _require(name not in names, "Release contains duplicate asset names")
        verification = _check_asset(github, asset, expected[name])
        _require(asset["id"] not in ids, "Release contains duplicate asset identities")
        names[name] = {**asset, "_verified_sha256": expected[name]["sha256"], "_verification": verification}
        ids.add(asset["id"])
    _require(not complete or set(names) == set(expected), "Release is missing approved assets")
    return names


def _local_identity(directory: Path, manifest: dict, expected_digest: str) -> None:
    _require(sha256_file(directory / "candidate.json")[1] == expected_digest, "Candidate manifest changed during publication")
    notes = manifest["notes"]
    _require(sha256_file(directory / "RELEASE-NOTES.md") == (notes["bytes"], notes["sha256"]), "Candidate notes changed during publication")


def _read_notes(directory: Path, manifest: dict) -> str:
    # Hash the actual bytes used in the request, not merely the pathname before
    # and after reading. Bound the read and refuse a swapped symlink/FIFO.
    descriptor = os.open(directory / "RELEASE-NOTES.md", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        _require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "Release notes are not a regular file")
        raw = source.read(manifest["notes"]["bytes"] + 1)
    expected = manifest["notes"]
    _require((len(raw), hashlib.sha256(raw).hexdigest()) == (expected["bytes"], expected["sha256"]),
             "Release notes bytes differ from approval")
    # Do not translate CRLF: the exact reviewed body is the remote identity.
    return raw.decode("utf-8")


def _snapshot(github, release_id, manifest, notes, *, complete=False) -> tuple[dict, dict]:
    release = _object(github.get(f"/releases/{release_id}"))
    _validate_release(release, manifest, notes, expected_id=release_id)
    _check_tag(github, manifest, required=not release["draft"])
    inventory = _inventory(github, release_id, manifest, complete=complete or not release["draft"])
    if not release["draft"]:
        visible = _object(github.get("/releases/tags/" + quote(manifest["tag"], safe="")))
        _validate_release(visible, manifest, notes, expected_id=release_id)
        _require(visible["draft"] is False, "Published release is not visible by its tag")
    return release, inventory


def _record_remote(receipt: dict, release: dict, inventory: dict) -> None:
    receipt["release_id"] = release["id"]
    receipt["remote"] = {
        "draft": release["draft"], "prerelease": release["prerelease"],
        "published_at": release.get("published_at"),
        "assets": [{"id": asset["id"], "name": name, "bytes": asset["size"],
                    "digest": asset.get("digest"), "verified_sha256": asset["_verified_sha256"],
                    "verification": asset["_verification"]} for name, asset in sorted(inventory.items())],
    }


def _mutate(receipt: dict, action: str, operation, *, asset: str | None = None):
    record = {"action": action, "state": "pending"}
    if asset is not None:
        record["asset"] = asset
    receipt["mutation_attempts"].append(record)
    try:
        result = operation()
    except APIError as exc:
        record["state"] = "uncertain" if exc.uncertain else "rejected"
        raise
    except Exception:
        # A transport contract violation or a local failure after dispatch is
        # not evidence that the remote operation never happened.
        record["state"] = "uncertain"
        raise
    record["state"] = "acknowledged"
    return result


def _observe_after_uncertainty(github, receipt: dict, manifest: dict) -> None:
    """One read-only reconciliation; never resume writes inside this attempt."""
    try:
        release = _find_release(github, manifest["tag"])
        if release is None:
            receipt["reconciliation"] = {"release_found": False}
            return
        assets = _list(github, f"/releases/{release['id']}/assets", maximum=100)
        receipt["reconciliation"] = {
            "release_found": True, "release_id": release["id"],
            "draft": release.get("draft") if type(release.get("draft")) is bool else None,
            "asset_count": len(assets),
            "meaning": "Observation only; this attempt performs no further writes.",
        }
    except Exception:
        receipt["reconciliation"] = {"status": "unavailable"}


def publish_candidate(directory, github, *, expected_manifest_sha256, confirmation_tag) -> dict:
    """Publish an exact candidate, or validate an identical published release.

    Published releases are never changed. Drafts must have matching immutable
    target, title and notes; existing assets must match before any new upload.
    This requires a single authorized publisher (the workflow concurrency group);
    GitHub does not provide an atomic compare-draft-and-upload transaction.

    On failure ``PublicationError.receipt`` records acknowledged/rejected/uncertain
    writes. No mutating request is retried automatically, including after 5xx.
    """
    receipt = {"schema_version": 1, "status": "blocked", "phase": "validate-candidate",
               "repository": "GAL1LEO-X/GAL1LEO-XX", "mutation_attempts": []}
    manifest = None
    try:
        digest = validate_sha(expected_manifest_sha256)
        directory = Path(directory)
        manifest = verify_candidate(directory, expected_manifest_sha256=digest)
        _require(confirmation_tag == manifest["tag"], "Explicit confirmation must equal the approved tag")
        receipt.update(tag=manifest["tag"], commit=manifest["target_commit"], manifest_sha256=digest)
        notes = _read_notes(directory, manifest)
        _local_identity(directory, manifest, digest)
        receipt["phase"] = "reconcile"
        _check_tag(github, manifest, required=False)
        release = _find_release(github, manifest["tag"])
        if release is None:
            receipt["phase"] = "create-draft"
            verify_candidate(directory, expected_manifest_sha256=digest)
            _local_identity(directory, manifest, digest)
            # A second tag read guards against a ref changed while listing.
            _check_tag(github, manifest, required=False)
            release = _mutate(receipt, "create-draft", lambda: github.post("/releases", {
                "tag_name": manifest["tag"], "target_commitish": manifest["target_commit"],
                "name": "WhatsApp " + manifest["version"], "body": notes,
                "draft": True, "prerelease": False, "generate_release_notes": False,
            }))
        _validate_release(release, manifest, notes)
        release_id = release["id"]
        receipt["release_id"] = release_id
        release, inventory = _snapshot(github, release_id, manifest, notes)
        if not release["draft"]:
            _record_remote(receipt, release, inventory)
            receipt.update(status="already-published", phase="verified")
            return receipt
        for asset in manifest["assets"]:
            receipt["phase"] = "upload"
            # Check the current draft and all existing asset identities before
            # each write. A concurrent publication stops this writer.
            release, inventory = _snapshot(github, release_id, manifest, notes)
            if not release["draft"]:
                _record_remote(receipt, release, inventory)
                receipt.update(status="already-published", phase="verified")
                return receipt
            if asset["name"] in inventory:
                continue
            _local_identity(directory, manifest, digest)
            path = directory / "assets" / asset["name"]
            _require(sha256_file(path) == (asset["bytes"], asset["sha256"]), "Local asset changed before upload")
            uploaded = _mutate(receipt, "upload", lambda: github.upload(
                release_id, asset["name"], path, asset["bytes"], asset["sha256"]), asset=asset["name"])
            _check_asset(github, uploaded, asset)
        receipt["phase"] = "verify-draft"
        verify_candidate(directory, expected_manifest_sha256=digest)
        release, inventory = _snapshot(github, release_id, manifest, notes, complete=True)
        _record_remote(receipt, release, inventory)
        if not release["draft"]:
            receipt.update(status="already-published", phase="verified")
            return receipt
        receipt["phase"] = "publish"
        _local_identity(directory, manifest, digest)
        _mutate(receipt, "publish", lambda: github.patch(f"/releases/{release_id}", {
            "draft": False, "prerelease": False, "make_latest": "true",
        }))
        receipt["phase"] = "verify-published"
        release, inventory = _snapshot(github, release_id, manifest, notes, complete=True)
        _require(not release["draft"], "Publication is not confirmed by the remote state")
        _record_remote(receipt, release, inventory)
        receipt.update(status="published", phase="verified")
        return receipt
    except Exception as exc:
        uncertain = any(x["state"] == "uncertain" for x in receipt["mutation_attempts"])
        # Acknowledged publication without its successful final readback also
        # leaves the final delivery unverified, regardless of the read error.
        uncertain |= receipt["phase"] == "verify-published"
        receipt["status"] = "uncertain" if uncertain else "blocked"
        receipt["error"] = {"kind": "github" if isinstance(exc, APIError) else "validation"}
        if isinstance(exc, APIError):
            receipt["error"].update(http_status=exc.status, method=exc.method)
        elif isinstance(exc, ReleaseError):
            # Shared ReleaseError's contract is a static, sanitized local
            # diagnostic. Never copy arbitrary transport exception strings.
            receipt["error"]["reason"] = str(exc)
        if uncertain and manifest is not None:
            _observe_after_uncertainty(github, receipt, manifest)
        message = "Publication outcome requires reconciliation" if uncertain else "Publication stopped before further writes"
        raise PublicationError(message, receipt) from None
