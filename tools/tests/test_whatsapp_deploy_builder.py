"""Offline package contract regressions; no downloads or production inputs."""
import hashlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("whatsapp_deploy_builder", ROOT / "tools/build-whatsapp-deploy.py")
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)


def wheel(folder, name="example", version="1.0", extra=None):
    path = folder / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{name}-{version}.dist-info/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")
        if extra:
            archive.writestr(extra, "synthetic")
    return path


def wheel_policy_entry(path, name="example", version="1.0"):
    return {"filename": path.name, "version": version, "sha256": builder.digest(path),
            "url": "https://files.pythonhosted.org/packages/synthetic/" + path.name,
            "metadata_url": f"https://pypi.org/pypi/{name}/{version}/json"}


class BuilderTests(unittest.TestCase):
    def test_only_committed_application_bytes_enter_build_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); repo = root / 'repo'; app = repo / 'plugins/whatsapp'; app.mkdir(parents=True)
            (app / 'module.py').write_text('VALUE = "committed"\n')
            (repo / '.gitignore').write_text('.env\n.venv/\nprivate/\n')
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.PIPE).decode().strip()
            git('init'); git('add', '.')
            git('-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.invalid', 'commit', '-qm', 'synthetic')
            commit = git('rev-parse', 'HEAD')
            for relative in ('.env', '.venv/local.py', 'private/session.json'):
                path = app / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('SYNTHETIC_PRIVATE_FIXTURE')
            builder.clean_source(repo, commit)
            output = root / 'materialized'
            builder.materialize_application(repo, commit, output)
            self.assertEqual([path.relative_to(output).as_posix() for path in output.rglob('*')], ['module.py'])
            self.assertEqual((output / 'module.py').read_text(), 'VALUE = "committed"\n')

    def test_runtime_lock_excludes_only_reviewed_windows_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.lock"
            path.write_text('example==1.0\npywin32==312 ; sys_platform == "win32"\n')
            self.assertEqual(builder.runtime_requirements(path), {"example": "1.0"})
            for value in ("--index-url https://example.invalid", "example>=1.0", "example @ https://example.invalid",
                          'example==1.0 ; python_version > "3"', "example==1.0\nExample==1.0"):
                path.write_text(value)
                with self.subTest(value=value), self.assertRaises(ValueError):
                    builder.runtime_requirements(path)

    def test_wheel_inventory_requires_exact_complete_set_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); path = wheel(folder)
            runtime = {"example": wheel_policy_entry(path)}
            app = wheel(folder, "application")
            self.assertEqual(builder.hash_lock(folder, runtime, ("application", "1.0")),
                             "application==1.0 --hash=sha256:" + builder.digest(app) + "\n"
                             "example==1.0 --hash=sha256:" + runtime["example"]["sha256"] + "\n")
            with self.assertRaises(ValueError): builder.hash_lock(folder, runtime, ("application", "2.0"))
            with self.assertRaises(ValueError): builder.hash_lock(folder, runtime, ("missing", "1.0"))
            wheel(folder, "unrequested")
            with self.assertRaises(ValueError): builder.hash_lock(folder, runtime, ("application", "1.0"))

    def test_replacement_wheel_at_same_version_cannot_authorize_itself(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); path = wheel(folder)
            runtime = {"example": wheel_policy_entry(path)}
            wheel(folder, "application")
            wheel(folder, extra="replacement.py")
            with self.assertRaisesRegex(ValueError, "trusted policy"):
                builder.hash_lock(folder, runtime, ("application", "1.0"))

    def test_download_uses_preexisting_hashes_and_exact_urls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); original = wheel(root)
            entries = {"example": wheel_policy_entry(original)}
            destination, requirements = root / "downloads", root / "download.lock"
            def download(args, **kwargs):
                self.assertIn("--require-hashes", args)
                self.assertIn("--only-binary=:all:", args)
                self.assertIn("--no-deps", args)
                self.assertIn("--no-index", args)
                self.assertIn("--no-cache-dir", args)
                self.assertEqual(requirements.read_text(), "example @ " + entries["example"]["url"]
                                 + " --hash=sha256:" + entries["example"]["sha256"] + "\n")
                (destination / original.name).write_bytes(original.read_bytes())
            with patch.object(builder, "run", side_effect=download):
                builder.download_locked_wheels(entries, destination, requirements, {})

    def test_unexpected_download_is_rejected_even_with_matching_metadata(self):
        for tamper in ("contents", "new-filename"):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); original = wheel(root)
                entries = {"example": wheel_policy_entry(original)}
                destination = root / "downloads"
                def download(args, **kwargs):
                    path = wheel(destination, extra="replacement.py" if tamper == "contents" else None)
                    if tamper == "new-filename":
                        path.rename(destination / "example-1.0-py313-none-any.whl")
                with patch.object(builder, "run", side_effect=download), self.assertRaises(ValueError):
                    builder.download_locked_wheels(entries, destination, root / "download.lock", {})

    def test_download_preserves_configured_transport_without_leaking_build_credentials(self):
        network = {name: 'http://proxy.example.invalid:3128' for name in
                   ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')}
        network.update(NO_PROXY='localhost,127.0.0.1', no_proxy='localhost,127.0.0.1')
        network.update({name: '/synthetic/ca.pem' for name in
                        ('SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'PIP_CERT')})
        network['SSL_CERT_DIR'] = '/synthetic/certs'
        unrelated = {'GH_TOKEN': 'synthetic-token', 'UNRELATED_SECRET': 'synthetic-secret',
                     'PIP_INDEX_URL': 'https://index.example.invalid', 'PYTHONPATH': '/untrusted'}
        for configured in (network, {}):
            with self.subTest(configured=bool(configured)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); original = wheel(root)
                entries = {'example': wheel_policy_entry(original)}
                destination, requirements = root / 'downloads', root / 'download.lock'
                isolated = {'PATH': '/synthetic/bin', 'HOME': str(root / 'home'),
                            'PIP_CONFIG_FILE': builder.os.devnull, 'PYTHONNOUSERSITE': '1'}
                before = dict(isolated)

                def download(args, **kwargs):
                    self.assertEqual(kwargs['env'], {**before, **configured})
                    self.assertTrue(set(unrelated).isdisjoint(kwargs['env']))
                    for flag in ('--require-hashes', '--no-index', '--no-deps', '--only-binary=:all:'):
                        self.assertIn(flag, args)
                    self.assertEqual(requirements.read_text(), builder.locked_requirements(entries, remote=True))
                    (destination / original.name).write_bytes(original.read_bytes())

                with patch.dict(builder.os.environ, {**unrelated, **configured}, clear=True), \
                     patch.object(builder, 'run', side_effect=download):
                    builder.download_locked_wheels(entries, destination, requirements, isolated)
                    self.assertEqual(dict(builder.os.environ), {**unrelated, **configured})
                # The same isolated env is subsequently used by offline build/install.
                self.assertEqual(isolated, before)

    def test_committed_policy_covers_exact_runtime_and_build_pins(self):
        expected = builder.runtime_requirements(ROOT / "plugins/whatsapp/requirements.lock")
        policy = builder.dependency_policy(expected)
        self.assertEqual(set(policy["runtime"]), set(expected))
        self.assertEqual({name: entry["version"] for name, entry in policy["build"].items()},
                         {"setuptools": "84.0.0"})
        self.assertNotIn("pywin32", policy["runtime"])

    def test_policy_drift_or_unofficial_urls_fail_closed(self):
        expected = builder.runtime_requirements(ROOT / "plugins/whatsapp/requirements.lock")
        baseline = builder.dependency_policy(expected)
        def version(p): p["runtime"]["anyio"]["version"] = "0.0"
        def digest(p): p["runtime"]["anyio"]["sha256"] = "not-a-hash"
        def target(p): p["target"]["arch"] = "aarch64"
        def missing(p): del p["runtime"]["anyio"]
        def build(p): p["build"]["setuptools"]["version"] = "0.0"
        def url(p): p["runtime"]["anyio"]["url"] = "https://example.invalid/anyio.whl"
        def filename(p): p["runtime"]["anyio"]["filename"] = "../anyio.whl"
        def metadata(p): p["runtime"]["anyio"]["metadata_url"] = "https://example.invalid/json"
        def newline(p): p["runtime"]["anyio"]["url"] = p["runtime"]["anyio"]["url"].replace("/packages/", "/packages/\n")
        with tempfile.TemporaryDirectory() as directory:
            control = Path(directory); path = control / builder.WHEEL_POLICY; path.parent.mkdir()
            for mutate in (version, digest, target, missing, build, url, filename, metadata, newline):
                policy = copy.deepcopy(baseline); mutate(policy); path.write_text(json.dumps(policy))
                with self.subTest(mutation=mutate.__name__), self.assertRaises(ValueError):
                    builder.dependency_policy(expected, control)

    def test_policy_failure_precedes_any_download_or_build(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(source=ROOT, output=Path(directory) / "package.tar.gz", commit="a" * 40)
            with patch.object(builder, "require_target"), patch.object(builder, "clean_source"), \
                 patch.object(builder, "dependency_policy", side_effect=ValueError("policy drift")), \
                 patch.object(builder, "run") as run:
                with self.assertRaisesRegex(ValueError, "policy drift"):
                    builder.build_package(args)
                run.assert_not_called()
            self.assertFalse(args.output.exists())

    def test_wheel_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): builder.wheel_identity(wheel(Path(directory), extra="../escape"))

    def test_vendored_metadata_does_not_replace_top_level_distribution(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            self.assertEqual(builder.wheel_identity(wheel(folder, extra="vendor/other-1.0.dist-info/METADATA")),
                             ("example", "1.0"))
            with self.assertRaises(ValueError):
                builder.wheel_identity(wheel(folder, extra="other-1.0.dist-info/METADATA"))

    def test_archive_is_contract_bound_regular_deterministic_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); payload = root / "payload"; payload.mkdir()
            (payload / "requirements.lock").write_text("example==1.0 --hash=sha256:" + "1" * 64 + "\n")
            wheel(payload)
            kwargs = {"commit": "a" * 40, "version": "0.8.0", "schema": 8,
                      "build": {"repository": builder.REPOSITORY, "run_id": 11, "run_attempt": 2,
                                "workflow_ref": builder.REPOSITORY + "/.github/workflows/deploy.yml@" + "b" * 40}}
            outputs = [root / "first.tar.gz", root / "second.tar.gz"]
            digests = [builder.write_archive(payload, output, **kwargs) for output in outputs]
            self.assertEqual(digests[0], digests[1])
            with tarfile.open(outputs[0], "r:gz") as archive:
                self.assertTrue(all(item.isfile() and item.mode == 0o644 for item in archive.getmembers()))
                manifest = json.load(archive.extractfile("manifest.json"))
                self.assertEqual(manifest["data"], {"schema": 8, "readable_schemas": [8]})
                self.assertEqual(manifest["target"], builder.TARGET)
                for item in manifest["files"]:
                    value = archive.extractfile(item["path"]).read()
                    self.assertEqual(item["sha256"], hashlib.sha256(value).hexdigest())
                    self.assertEqual(item["size"], len(value))
            with self.assertRaises(ValueError): builder.write_archive(payload, outputs[0], **kwargs)
            kwargs["build"]["workflow_ref"] = builder.REPOSITORY + "/.github/workflows/deploy.yml@refs/heads/main"
            with self.assertRaises(ValueError): builder.write_archive(payload, root / "bad.tar.gz", **kwargs)

    def test_wrong_platform_blocks_before_build(self):
        with patch.object(builder.sys, "platform", "win32"), self.assertRaisesRegex(ValueError, "Linux"):
            builder.require_target()

    def test_provider_reference_is_exact_and_does_not_download(self):
        # Carry the exact reviewed provider identity, independently of its version.
        lock = json.loads((ROOT / "tools/templates/provider-release.example.json").read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            control = Path(directory)
            (control / "tools").mkdir()
            (control / "tools/whatsapp-release-provider.lock.json").write_text(json.dumps(lock))
            with patch.object(builder, "provider_fingerprint", return_value=lock["fingerprint"]["entries"]):
                reference = builder.provider_reference(ROOT, "a" * 40, control=control)
            with patch.object(builder, "provider_fingerprint", return_value=[]), self.assertRaisesRegex(ValueError, "Provider inputs changed"):
                builder.provider_reference(ROOT, "a" * 40, control=control)
        self.assertEqual(reference["source_tag"], lock["source_tag"])
        self.assertEqual(reference["assets"], lock["assets"])
        self.assertEqual(len(reference["assets"]), 10)


if __name__ == "__main__":
    unittest.main()
