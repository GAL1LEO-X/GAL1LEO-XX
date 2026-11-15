"""Offline publication contracts: synthetic candidates and a stateful fake API."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import socket
import sys
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from whatsapp_release_common import ASSET_ROLES, canonical_json
from whatsapp_release_github import APIError, GitHubClient
from whatsapp_release_publish import PublicationError, publish_candidate


COMMIT = "a" * 40
WORKFLOW = "b" * 40
VERSION = "0.7.1"
TAG = "whatsapp/v" + VERSION


def digest(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("A synthetic publisher test attempted a real connection")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


@pytest.fixture
def candidate(tmp_path):
    directory = tmp_path / "candidate"
    directory.mkdir()
    (directory / "assets").mkdir()
    notes = b"Synthetic release notes.\nNo live validation is claimed.\n"
    (directory / "RELEASE-NOTES.md").write_bytes(notes)
    assets = []
    for index, role in enumerate(ASSET_ROLES):
        name = role.replace("_", "-") + ".tar.gz"
        body = ("Synthetic bytes for " + role + "\n").encode()
        (directory / "assets" / name).write_bytes(body)
        origin = ({"kind": "built", "commit": COMMIT} if index >= 10 else
                  {"kind": "reused", "release_id": 100, "asset_id": 200 + index,
                   "tag": "whatsapp/v0.7.0"})
        assets.append({"name": name, "bytes": len(body), "sha256": digest(body),
                       "role": role, "origin": origin})
    runtime = "sha256:" + "c" * 64
    manifest = {
        "schema_version": 1, "repository": "GAL1LEO-X/GAL1LEO-XX",
        "target_commit": COMMIT, "target_tree": "d" * 40,
        "workflow_commit": WORKFLOW, "version": VERSION, "tag": TAG,
        "provider_lock_sha256": "e" * 64,
        "runtime": {"config_digest": runtime, "manifest_digest": "sha256:" + "f" * 64},
        "prepared_run": {"id": 101, "attempt": 1,
                         "workflow_path": ".github/workflows/whatsapp-release.yml"},
        "qualification": {"kind": "offline", "target_commit": COMMIT,
            "workflow_commit": WORKFLOW, "runtime_config_digest": runtime,
            "ci_run_id": 102, "ci_run_attempt": 1,
            "review_evidence": "https://github.com/GAL1LEO-X/GAL1LEO-XX/pull/1#issuecomment-2"},
        "notes": {"name": "RELEASE-NOTES.md", "bytes": len(notes), "sha256": digest(notes)},
        "assets": assets,
    }
    raw = canonical_json(manifest)
    (directory / "candidate.json").write_bytes(raw)
    return directory, manifest, digest(raw)


class FakeGitHub:
    """The fake persists accepted writes even when their response is lost."""
    def __init__(self, candidate):
        self.directory, self.manifest, _ = candidate
        self.releases = {}
        self.assets = {}
        self.bytes = {}
        self.refs = {}
        self.annotated = {}
        self.calls = []
        self.mutations = []
        self.downloads = []
        self.failures = {}
        self.on_get = None
        self.next_id = 500
        self.next_asset_id = 1000

    def seed_release(self, *, draft=True, count=0):
        release_id = self.next_id
        self.next_id += 1
        release = {
            "id": release_id, "draft": draft, "prerelease": False,
            "tag_name": self.manifest["tag"], "target_commitish": self.manifest["target_commit"],
            "name": "WhatsApp " + self.manifest["version"],
            "body": (self.directory / "RELEASE-NOTES.md").read_bytes().decode(),
            "published_at": None if draft else "2026-10-21T00:00:00Z",
        }
        self.releases[release_id] = release
        self.assets[release_id] = []
        for item in self.manifest["assets"][:count]:
            self.seed_asset(release_id, item)
        if not draft:
            self.refs[self.manifest["tag"]] = {"type": "commit", "sha": self.manifest["target_commit"]}
        return release

    def seed_asset(self, release_id, item):
        body = (self.directory / "assets" / item["name"]).read_bytes()
        asset = {"id": self.next_asset_id, "name": item["name"], "size": len(body),
                 "state": "uploaded", "digest": "sha256:" + digest(body)}
        self.next_asset_id += 1
        self.assets[release_id].append(asset)
        self.bytes[asset["id"]] = body
        return asset

    def get(self, path):
        self.calls.append(("GET", path))
        if self.on_get is not None:
            self.on_get(path, self)
        parts = urlsplit(path)
        clean = unquote(parts.path)
        if clean.startswith("/git/ref/tags/"):
            tag = clean[len("/git/ref/tags/"):]
            if tag not in self.refs:
                raise APIError(404, "GET", path)
            return {"ref": "refs/tags/" + tag, "object": deepcopy(self.refs[tag])}
        if clean.startswith("/git/tags/"):
            sha = clean[len("/git/tags/"):]
            if sha not in self.annotated:
                raise APIError(404, "GET", path)
            return deepcopy(self.annotated[sha])
        if clean.startswith("/releases/tags/"):
            tag = clean[len("/releases/tags/"):]
            matches = [r for r in self.releases.values() if r["tag_name"] == tag and not r["draft"]]
            if not matches:
                raise APIError(404, "GET", path)
            return deepcopy(matches[0])
        if clean == "/releases":
            values = list(self.releases.values())
        elif clean.startswith("/releases/") and clean.endswith("/assets"):
            values = self.assets[int(clean.split("/")[2])]
        elif clean.startswith("/releases/"):
            release_id = int(clean.split("/")[2])
            if release_id not in self.releases:
                raise APIError(404, "GET", path)
            return deepcopy(self.releases[release_id])
        else:
            raise AssertionError("Unexpected fake GET path: " + path)
        query = parse_qs(parts.query)
        assert query["per_page"] == ["100"]
        page = int(query["page"][0])
        return deepcopy(values[(page - 1) * 100:page * 100])

    def _write(self, action, method, path, operation, name=None):
        self.calls.append((method, path))
        self.mutations.append((action, name))
        failure = self.failures.pop(action, None)
        if failure and not failure[2]:
            raise APIError(failure[0], method, path, uncertain=failure[1])
        result = operation()
        if failure:
            raise APIError(failure[0], method, path, uncertain=failure[1])
        return result

    def post(self, path, data):
        assert path == "/releases"
        assert data["draft"] is True and data["prerelease"] is False
        assert data["generate_release_notes"] is False
        assert data["target_commitish"] == self.manifest["target_commit"]
        def operation():
            assert not any(r["tag_name"] == data["tag_name"] for r in self.releases.values())
            release = self.seed_release()
            release.update(deepcopy(data))
            return deepcopy(release)
        return self._write("create", "POST", path, operation)

    def upload(self, release_id, name, path, expected_bytes, expected_sha256):
        def operation():
            assert self.releases[release_id]["draft"] is True
            assert all(a["name"] != name for a in self.assets[release_id])
            body = Path(path).read_bytes()
            assert len(body) == expected_bytes and digest(body) == expected_sha256
            item = next(a for a in self.manifest["assets"] if a["name"] == name)
            return deepcopy(self.seed_asset(release_id, item))
        return self._write("upload", "POST", f"/releases/{release_id}/assets", operation, name)

    def patch(self, path, data):
        release_id = int(path.split("/")[-1])
        assert data == {"draft": False, "prerelease": False, "make_latest": "true"}
        def operation():
            release = self.releases[release_id]
            assert release["draft"] is True
            assert len(self.assets[release_id]) == 13
            release.update(draft=False, published_at="2026-10-21T00:00:00Z")
            self.refs[release["tag_name"]] = {"type": "commit", "sha": release["target_commitish"]}
            return deepcopy(release)
        return self._write("publish", "PATCH", path, operation)

    def download_release_asset(self, asset_id, target, expected_bytes, expected_sha256):
        self.downloads.append(asset_id)
        Path(target).write_bytes(self.bytes[asset_id])
        return Path(target)


def run(candidate, github, **kwargs):
    directory, manifest, pin = candidate
    return publish_candidate(directory, github, expected_manifest_sha256=pin,
                             confirmation_tag=kwargs.pop("confirmation_tag", manifest["tag"]), **kwargs)


def blocked(candidate, github, *, uncertain=False, **kwargs):
    with pytest.raises(PublicationError) as caught:
        run(candidate, github, **kwargs)
    receipt = caught.value.receipt
    assert receipt["status"] == ("uncertain" if uncertain else "blocked")
    return receipt


def test_new_candidate_publishes_all_thirteen_and_records_final_remote_state(candidate):
    github = FakeGitHub(candidate)
    receipt = run(candidate, github)
    assert receipt["status"] == "published" and receipt["phase"] == "verified"
    assert receipt["commit"] == COMMIT and receipt["manifest_sha256"] == candidate[2]
    assert receipt["remote"]["draft"] is False and receipt["remote"]["prerelease"] is False
    assert len(receipt["remote"]["assets"]) == 13
    assert [a for a, _ in github.mutations] == ["create"] + ["upload"] * 13 + ["publish"]
    assert all(a["state"] == "acknowledged" for a in receipt["mutation_attempts"])
    assert github.refs[TAG]["sha"] == COMMIT
    assert not github.downloads  # Digest metadata suffices; do not redownload 13 archives.


@pytest.mark.parametrize("existing_count", [0, 1, 9, 13])
def test_coherent_draft_resumes_only_missing_assets(candidate, existing_count):
    github = FakeGitHub(candidate)
    existing = github.seed_release(count=existing_count)
    existing_ids = [a["id"] for a in github.assets[existing["id"]]]
    assert run(candidate, github)["status"] == "published"
    assert [a for a, _ in github.mutations] == ["upload"] * (13 - existing_count) + ["publish"]
    assert [a["id"] for a in github.assets[existing["id"]]][:existing_count] == existing_ids


def test_identical_published_release_is_read_only_even_with_branch_commitish(candidate):
    github = FakeGitHub(candidate)
    release = github.seed_release(draft=False, count=13)
    release["target_commitish"] = "main"
    before = deepcopy(github.releases), deepcopy(github.assets)
    receipt = run(candidate, github)
    assert receipt["status"] == "already-published"
    assert github.mutations == [] and receipt["mutation_attempts"] == []
    assert before == (github.releases, github.assets)


@pytest.mark.parametrize("field,value", [("name", "Different approved release title"),
    ("body", "Conflicting notes"), ("prerelease", True), ("draft", "false"),
    ("published_at", None)])
def test_existing_published_release_conflicts_are_never_rewritten(candidate, field, value):
    github = FakeGitHub(candidate)
    github.seed_release(draft=False, count=13)[field] = value
    before = deepcopy(github.releases), deepcopy(github.assets)
    blocked(candidate, github)
    assert github.mutations == [] and before == (github.releases, github.assets)


@pytest.mark.parametrize("field,value", [("body", "Different draft notes"),
    ("target_commitish", "main"), ("target_commitish", "f" * 40),
    ("published_at", "2026-10-21T00:00:00Z"), ("prerelease", True)])
def test_incoherent_drafts_are_not_repaired_or_overwritten(candidate, field, value):
    github = FakeGitHub(candidate)
    github.seed_release(count=3)[field] = value
    blocked(candidate, github)
    assert not github.mutations


@pytest.mark.parametrize("draft", [True, False])
def test_wrong_tag_target_blocks_every_mutation(candidate, draft):
    github = FakeGitHub(candidate)
    github.seed_release(draft=draft, count=13 if not draft else 0)
    github.refs[TAG] = {"type": "commit", "sha": "f" * 40}
    blocked(candidate, github)
    assert not github.mutations


def test_preexisting_exact_lightweight_tag_can_create_release(candidate):
    github = FakeGitHub(candidate)
    github.refs[TAG] = {"type": "commit", "sha": COMMIT}
    assert run(candidate, github)["status"] == "published"


def test_annotated_tag_resolves_to_exact_approved_commit(candidate):
    github = FakeGitHub(candidate)
    github.seed_release(draft=False, count=13)
    sha = "1" * 40
    github.refs[TAG] = {"type": "tag", "sha": sha}
    github.annotated[sha] = {"sha": sha, "object": {"type": "commit", "sha": COMMIT}}
    assert run(candidate, github)["status"] == "already-published"
    assert not github.mutations


@pytest.mark.parametrize("mode", ["cycle", "too-deep", "tree", "wrong-commit", "wrong-identity"])
def test_invalid_annotated_tag_chains_block(candidate, mode):
    github = FakeGitHub(candidate)
    sha = "1" * 40
    github.refs[TAG] = {"type": "tag", "sha": sha}
    obj = {"type": "commit", "sha": COMMIT}
    if mode == "cycle":
        obj = {"type": "tag", "sha": sha}
    elif mode == "tree":
        obj["type"] = "tree"
    elif mode == "wrong-commit":
        obj["sha"] = "2" * 40
    github.annotated[sha] = {"sha": "2" * 40 if mode == "wrong-identity" else sha, "object": obj}
    if mode == "too-deep":
        for index in range(1, 10):
            current = f"{index:040x}"
            next_sha = f"{index + 1:040x}"
            github.annotated[current] = {"sha": current, "object": {"type": "tag", "sha": next_sha}}
        github.refs[TAG]["sha"] = f"{1:040x}"
    blocked(candidate, github)
    assert not github.mutations


def test_published_release_requires_actual_tag(candidate):
    github = FakeGitHub(candidate)
    github.seed_release(draft=False, count=13)
    github.refs.clear()
    blocked(candidate, github)
    assert not github.mutations


def test_multiple_drafts_for_same_tag_block_instead_of_selecting_one(candidate):
    github = FakeGitHub(candidate)
    github.seed_release(count=0)
    github.seed_release(count=4)
    blocked(candidate, github)
    assert not github.mutations


def test_release_listing_paginates_and_finds_draft_not_in_first_page(candidate):
    github = FakeGitHub(candidate)
    for index in range(100):
        github.seed_release()["tag_name"] = "unrelated/" + str(index)
    release = github.seed_release(count=13)
    assert run(candidate, github)["release_id"] == release["id"]
    assert ("GET", "/releases?per_page=100&page=2") in github.calls
    assert github.mutations == [("publish", None)]


@pytest.mark.parametrize("draft", [True, False])
@pytest.mark.parametrize("mode", ["unknown", "duplicate-name", "duplicate-id", "wrong-size",
                                   "wrong-digest", "unfinished", "boolean-size", "missing"])
def test_conflicting_remote_assets_never_get_clobbered(candidate, draft, mode):
    github = FakeGitHub(candidate)
    release = github.seed_release(draft=draft, count=13)
    assets = github.assets[release["id"]]
    if mode == "unknown":
        assets[0]["name"] = "unapproved-archive.tar.gz"
    elif mode == "duplicate-name":
        assets[0]["name"] = assets[1]["name"]
    elif mode == "duplicate-id":
        assets[0]["id"] = assets[1]["id"]
    elif mode == "wrong-size":
        assets[0]["size"] += 1
    elif mode == "wrong-digest":
        assets[0]["digest"] = "sha256:" + "0" * 64
    elif mode == "unfinished":
        assets[0]["state"] = "starter"
    elif mode == "boolean-size":
        assets[0]["size"] = True
    elif mode == "missing":
        assets.pop()
        if draft:
            # Missing assets are a valid resumable draft state, not a conflict.
            assert run(candidate, github)["status"] == "published"
            assert [a for a, _ in github.mutations] == ["upload", "publish"]
            return
    before = deepcopy(assets)
    blocked(candidate, github)
    assert not github.mutations and assets == before
    assert not github.downloads


def test_extra_fourteenth_asset_blocks(candidate):
    github = FakeGitHub(candidate)
    release = github.seed_release(count=13)
    github.assets[release["id"]].append({"id": 9999, "name": "extra.tar.gz"})
    blocked(candidate, github)
    assert not github.mutations


@pytest.mark.parametrize("missing_digest", [None, ""])
def test_digest_missing_uses_bounded_readback_for_evidence(candidate, missing_digest):
    github = FakeGitHub(candidate)
    release = github.seed_release(draft=False, count=13)
    asset = github.assets[release["id"]][0]
    asset["digest"] = missing_digest
    receipt = run(candidate, github)
    assert receipt["status"] == "already-published"
    verified = next(a for a in receipt["remote"]["assets"] if a["id"] == asset["id"])
    assert verified["verified_sha256"] == candidate[1]["assets"][0]["sha256"]
    assert verified["verification"] == "downloaded-bytes"
    assert github.downloads == [asset["id"]]
    assert not github.mutations


def test_missing_digest_cannot_hide_different_downloaded_bytes(candidate):
    github = FakeGitHub(candidate)
    release = github.seed_release(draft=False, count=13)
    asset = github.assets[release["id"]][0]
    asset.pop("digest")
    github.bytes[asset["id"]] = b"wrong synthetic contents"
    blocked(candidate, github)
    assert github.downloads == [asset["id"]] and not github.mutations


@pytest.mark.parametrize("confirmation", [None, "", "whatsapp/v0.7.0", "v0.7.1"])
def test_confirmation_must_match_manifest_before_api_access(candidate, confirmation):
    github = FakeGitHub(candidate)
    blocked(candidate, github, confirmation_tag=confirmation)
    assert not github.calls


@pytest.mark.parametrize("file", ["candidate.json", "RELEASE-NOTES.md", "assets/gows-source.tar.gz"])
def test_initial_candidate_tamper_stops_before_api_access(candidate, file):
    directory = candidate[0]
    (directory / file).write_bytes(b"not the reviewed bytes")
    github = FakeGitHub(candidate)
    receipt = blocked(candidate, github)
    assert receipt["phase"] == "validate-candidate" and not github.calls


@pytest.mark.parametrize("file", ["candidate.json", "RELEASE-NOTES.md", "assets/gows-source.tar.gz"])
def test_tamper_after_remote_read_blocks_next_upload(candidate, file):
    github = FakeGitHub(candidate)
    release = github.seed_release()
    def mutate_during_read(path, client):
        if path.startswith(f"/releases/{release['id']}/assets?"):
            (candidate[0] / file).write_bytes(b"changed after approval")
            client.on_get = None
    github.on_get = mutate_during_read
    blocked(candidate, github)
    assert not github.mutations


def test_asset_tamper_while_listing_cannot_create_even_an_empty_draft(candidate):
    github = FakeGitHub(candidate)
    def mutate_while_listing(path, client):
        if path.startswith("/releases?"):
            (candidate[0] / "assets" / candidate[1]["assets"][0]["name"]).write_bytes(b"unapproved")
    github.on_get = mutate_while_listing
    receipt = blocked(candidate, github)
    assert receipt["phase"] == "create-draft"
    assert not github.mutations


def test_notes_preserve_approved_crlf_and_unicode(candidate):
    directory, manifest, _ = candidate
    notes = "Note sintetiche — Ω\r\nSeconda riga\r\n".encode()
    (directory / "RELEASE-NOTES.md").write_bytes(notes)
    manifest["notes"].update(bytes=len(notes), sha256=digest(notes))
    raw = canonical_json(manifest)
    (directory / "candidate.json").write_bytes(raw)
    revised = directory, manifest, digest(raw)
    github = FakeGitHub(revised)
    assert run(revised, github)["status"] == "published"
    assert next(iter(github.releases.values()))["body"].encode() == notes


@pytest.mark.parametrize("status", [401, 403, 422])
def test_upload_rejection_stops_without_retry_or_publish(candidate, status):
    github = FakeGitHub(candidate)
    github.seed_release(count=3)
    github.failures["upload"] = (status, False, False)
    receipt = blocked(candidate, github)
    assert github.mutations == [("upload", candidate[1]["assets"][3]["name"])]
    assert receipt["mutation_attempts"][-1]["state"] == "rejected"
    assert receipt["error"] == {"kind": "github", "http_status": status, "method": "POST"}
    assert "reconciliation" not in receipt


@pytest.mark.parametrize("status", [None, 502])
@pytest.mark.parametrize("accepted", [False, True])
def test_uncertain_upload_stops_then_explicit_resume_reconciles(candidate, status, accepted):
    github = FakeGitHub(candidate)
    release = github.seed_release(count=3)
    github.failures["upload"] = (status, True, accepted)
    receipt = blocked(candidate, github, uncertain=True)
    first_name = candidate[1]["assets"][3]["name"]
    assert github.mutations == [("upload", first_name)]
    assert receipt["reconciliation"]["asset_count"] == 3 + accepted
    assert github.releases[release["id"]]["draft"] is True
    github.mutations.clear()
    assert run(candidate, github)["status"] == "published"
    assert github.mutations.count(("upload", first_name)) == (0 if accepted else 1)
    assert len({a["name"] for a in github.assets[release["id"]]}) == 13


def test_uncertain_create_is_not_retried_and_resume_uses_existing_draft(candidate):
    github = FakeGitHub(candidate)
    github.failures["create"] = (None, True, True)
    receipt = blocked(candidate, github, uncertain=True)
    assert github.mutations == [("create", None)]
    assert receipt["reconciliation"]["release_found"] is True
    github.mutations.clear()
    assert run(candidate, github)["status"] == "published"
    assert all(action != "create" for action, _ in github.mutations)
    assert len(github.releases) == 1


@pytest.mark.parametrize("accepted", [False, True])
def test_uncertain_publication_requires_readback_before_explicit_resume(candidate, accepted):
    github = FakeGitHub(candidate)
    github.seed_release(count=13)
    github.failures["publish"] = (503, True, accepted)
    receipt = blocked(candidate, github, uncertain=True)
    assert github.mutations == [("publish", None)]
    assert receipt["reconciliation"]["draft"] is not accepted
    github.mutations.clear()
    result = run(candidate, github)
    assert result["status"] == ("already-published" if accepted else "published")
    assert github.mutations == ([] if accepted else [("publish", None)])


def test_acknowledged_publish_with_failed_final_read_is_uncertain(candidate):
    github = FakeGitHub(candidate)
    github.seed_release(count=13)
    def fail_after_publish(path, client):
        if client.mutations and client.mutations[-1][0] == "publish":
            raise APIError(503, "GET", path)
    github.on_get = fail_after_publish
    receipt = blocked(candidate, github, uncertain=True)
    assert receipt["phase"] == "verify-published"
    assert receipt["reconciliation"] == {"status": "unavailable"}
    assert github.mutations == [("publish", None)]
    assert receipt["mutation_attempts"][0]["state"] == "acknowledged"


def test_acknowledged_publish_missing_public_tag_lookup_remains_uncertain(candidate):
    github = FakeGitHub(candidate)
    github.seed_release(count=13)
    def invisible_tag_lookup(path, client):
        if path.startswith("/releases/tags/"):
            raise APIError(404, "GET", path)
    github.on_get = invisible_tag_lookup
    receipt = blocked(candidate, github, uncertain=True)
    assert receipt["phase"] == "verify-published"
    assert github.mutations == [("publish", None)]
    assert receipt["reconciliation"]["draft"] is False


def test_tag_changed_between_listing_and_create_blocks_creation(candidate):
    github = FakeGitHub(candidate)
    def change_tag(path, client):
        if path.startswith("/releases?"):
            client.refs[TAG] = {"type": "commit", "sha": "f" * 40}
    github.on_get = change_tag
    blocked(candidate, github)
    assert not github.mutations


def test_external_publication_between_reads_stops_this_writer(candidate):
    github = FakeGitHub(candidate)
    release = github.seed_release(count=13)
    assets_reads = 0
    def external_publish(path, client):
        nonlocal assets_reads
        if path.startswith(f"/releases/{release['id']}/assets?"):
            assets_reads += 1
            if assets_reads == 1:
                release.update(draft=False, published_at="2026-10-21T00:00:00Z")
                client.refs[TAG] = {"type": "commit", "sha": COMMIT}
    github.on_get = external_publish
    assert run(candidate, github)["status"] == "already-published"
    assert not github.mutations


def test_raw_transport_exception_is_not_exposed_in_receipt(candidate):
    github = FakeGitHub(candidate)
    github.seed_release()
    def broken_upload(*args):
        raise RuntimeError("synthetic-secret Authorization Bearer token; signed-url")
    github.upload = broken_upload
    receipt = blocked(candidate, github, uncertain=True)
    assert "synthetic-secret" not in canonical_json(receipt).decode()
    assert "token" not in canonical_json(receipt).decode()


class HTTPResponse:
    def __init__(self, status, value, *, binary=False):
        self.status = status
        self.headers = {}
        self.content = io.BytesIO(value if binary else canonical_json(value))

    def read(self, size):
        return self.content.read(size)

    def close(self):
        self.content.close()


class FakeHTTP:
    """Exercise the real HTTP client's path, auth and streaming contracts."""
    def __init__(self, api):
        self.api = api
        self.requests = []

    def __call__(self, request, *, timeout):
        self.requests.append(request)
        url = urlsplit(request.full_url)
        assert url.scheme == "https"
        assert url.netloc in {"api.github.com", "uploads.github.com"}
        prefix = "/repos/GAL1LEO-X/GAL1LEO-XX"
        assert url.path.startswith(prefix + "/")
        path = url.path[len(prefix):] + ("?" + url.query if url.query else "")
        method = request.get_method()
        headers = {k.lower(): v for k, v in request.header_items()}
        assert headers["authorization"] == "Bearer synthetic-test-token"
        try:
            if method == "GET" and path.startswith("/releases/assets/"):
                return HTTPResponse(200, self.api.bytes[int(path.rsplit("/", 1)[1])], binary=True)
            if method == "GET":
                return HTTPResponse(200, self.api.get(path))
            if url.netloc == "uploads.github.com":
                assert method == "POST"
                chunks = []
                while chunk := request.data.read(8192):
                    chunks.append(chunk)
                body = b"".join(chunks)
                name = parse_qs(url.query)["name"][0]
                expected = next(a for a in self.api.manifest["assets"] if a["name"] == name)
                assert len(body) == expected["bytes"] and digest(body) == expected["sha256"]
                release_id = int(path.split("/")[2])
                value = self.api.upload(release_id, name, self.api.directory / "assets" / name,
                                        expected["bytes"], expected["sha256"])
                return HTTPResponse(201, value)
            assert headers["content-type"] == "application/json"
            data = json.loads(request.data)
            if method == "POST":
                return HTTPResponse(201, self.api.post(path, data))
            assert method == "PATCH"
            return HTTPResponse(200, self.api.patch(path, data))
        except APIError as exc:
            if exc.status is None:
                raise TimeoutError("Synthetic response loss") from None
            return HTTPResponse(exc.status, {})


def test_publisher_and_real_client_integrate_with_synthetic_transport(candidate):
    api = FakeGitHub(candidate)
    transport = FakeHTTP(api)
    client = GitHubClient("synthetic-test-token", transport=transport)
    result = run(candidate, client)
    assert result["status"] == "published"
    assert len([r for r in transport.requests if urlsplit(r.full_url).netloc == "uploads.github.com"]) == 13
    api.mutations.clear()
    assert run(candidate, client)["status"] == "already-published"
    assert not api.mutations


def test_real_client_digest_fallback_reads_bytes_from_asset_endpoint(candidate):
    api = FakeGitHub(candidate)
    release = api.seed_release(draft=False, count=13)
    asset = api.assets[release["id"]][0]
    asset.pop("digest")
    transport = FakeHTTP(api)
    result = run(candidate, GitHubClient("synthetic-test-token", transport=transport))
    assert result["status"] == "already-published"
    assert any(r.full_url.endswith("/releases/assets/" + str(asset["id"])) for r in transport.requests)
    assert not api.mutations


def test_real_client_lost_upload_response_preserves_uncertainty_and_no_retry(candidate):
    api = FakeGitHub(candidate)
    release = api.seed_release(count=2)
    api.failures["upload"] = (None, True, True)
    transport = FakeHTTP(api)
    receipt = blocked(candidate, GitHubClient("synthetic-test-token", transport=transport), uncertain=True)
    assert receipt["reconciliation"]["asset_count"] == 3
    assert api.releases[release["id"]]["draft"] is True
    assert len(api.mutations) == 1
