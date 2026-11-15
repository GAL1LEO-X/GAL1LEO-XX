"""Offline npm drift and real cross-process locking against the legacy bootstrap."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('project_browser', ROOT / 'tools/project.py')
project = importlib.util.module_from_spec(spec); spec.loader.exec_module(project)

def browser_fixture(root):
    package = {'name': 'synthetic-browser', 'version': '1.0.0', 'private': True,
               'dependencies': {'playwright': '^1.0.0'}}
    (root / 'package.json').write_text(json.dumps(package))
    (root / 'package-lock.json').write_text(json.dumps({
        'name': package['name'], 'version': '1.0.0', 'lockfileVersion': 3,
        'packages': {'': package, 'node_modules/playwright': {'version': '1.0.0'}}}))
    installed = root / 'node_modules/playwright'; installed.mkdir(parents=True)
    manifest = installed / 'package.json'
    manifest.write_text(json.dumps({'name': 'playwright', 'version': '1.0.0', 'main': 'index.js'}))
    # Only the executable-path lookup is used: no real browser/server.
    (installed / 'index.js').write_text('exports.chromium={executablePath:()=>__filename};\n')
    return manifest



class BrowserTests(unittest.TestCase):
    def test_version_drift_within_allowed_semver_range_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = browser_fixture(root)
            self.assertEqual(project.browser_state(root)[-1], [])
            manifest.write_text(json.dumps({'name': 'playwright', 'version': '1.1.0', 'main': 'index.js'}))
            npm = subprocess.run(['npm', 'ls', '--all', '--json'], cwd=root, text=True, capture_output=True)
            self.assertEqual(npm.returncode, 0, npm.stderr)  # The old check wrongly passed.
            self.assertTrue(project.browser_state(root)[-1])
            manifest.write_text(json.dumps({'name': 'playwright', 'version': '1.0.0', 'main': 'index.js'}))
            self.assertEqual(project.browser_state(root)[-1], [])

    def test_shared_browser_lock_excludes_legacy_and_new_preparation_both_directions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); cloud = root / 'tools/cloud'; cloud.mkdir(parents=True)
            (cloud / 'bootstrap.sh').write_text((ROOT / 'tools/cloud/bootstrap.sh').read_text())
            (root / 'plugins').mkdir(); project.scaffold(root, 'alpha')
            binaries = root / 'bin'; binaries.mkdir()
            started = root / 'legacy-mutation'; release = root / 'release-legacy'
            interpreter = binaries / 'fixture-python'
            interpreter.write_text('#!' + sys.executable + '\n'
                'from pathlib import Path\nimport sys,time\n'
                'if sys.argv[1:3]==["-m","venv"]:\n'
                f'    Path({str(started)!r}).write_text("synthetic filesystem mutation under lock")\n'
                '    deadline=time.monotonic()+10\n'
                f'    while not Path({str(release)!r}).exists() and time.monotonic()<deadline: time.sleep(.02)\n'
                '    sys.exit(17)\n'
                'print("3.13")\n')
            interpreter.chmod(0o755)
            node = binaries / 'node'; node.write_text('#!/bin/sh\nexit 0\n'); node.chmod(0o755)
            env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ['PATH'], PYTHON_BIN=str(interpreter))
            contract = project.load(root, 'alpha'); contract['browser'] = True
            shared = {'venvs': {'3.13': '.venvs/browser'}}
            # New controller owns the shared lock: legacy cannot reach any pip/npm/venv mutation.
            with project.setup_lock(root, shared, '3.13'):
                blocked = subprocess.run(['bash', str(cloud / 'bootstrap.sh')], env=env, capture_output=True, text=True)
                self.assertNotEqual(blocked.returncode, 0)
                self.assertIn('shared browser', blocked.stderr)
                self.assertFalse(started.exists())
                self.assertFalse((root / '.venvs/whatsapp.setup.lock').exists())
            # Legacy owns browser then Python while performing a real synthetic write:
            # new prepare must fail before entering its own Python setup or installs.
            legacy = subprocess.Popen(['bash', str(cloud / 'bootstrap.sh')], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 10
                while not started.exists() and legacy.poll() is None and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(started.exists(), 'Legacy did not reach the guarded synthetic mutation')
                with self.assertRaises(BlockingIOError): project.prepare(root, contract, '3.13', sys.executable)
                self.assertFalse((root / '.venvs/alpha.setup.lock').exists())
                self.assertFalse((root / '.venvs/alpha').exists())
            finally:
                release.write_text('release')
                try: legacy.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    legacy.kill(); legacy.communicate(); raise
            self.assertEqual(legacy.returncode, 17)


class ReceiptTests(unittest.TestCase):
    def test_malformed_browser_receipts_are_read_only_drift_and_repaired_without_install(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'plugins').mkdir()
            browser_fixture(root); project.scaffold(root, 'alpha')
            contract = project.load(root, 'alpha'); contract['browser'] = True
            runtime = '.'.join(map(str, sys.version_info[:2]))
            folder = root / contract['venvs'][runtime]; folder.mkdir(parents=True)
            python_receipt = folder / '.plugins-dependencies.json'
            value = {'schema': 1, 'fingerprint': project.fingerprint(root, contract), 'runtime': runtime}
            project.write_receipt(python_receipt, value)
            valid_python = python_receipt.read_bytes()
            node_receipt, digest, _, _ = project.browser_state(root)
            original_run = project.run
            def no_install(args, **kwargs):
                if 'install' in args or 'uninstall' in args or 'ci' in args:
                    self.fail('Receipt-only repair must not install dependencies')
                return original_run(args, **kwargs)
            with patch.object(project, 'inventory'), patch.object(project, 'python_version', return_value=runtime), \
                    patch.object(project, 'run', side_effect=no_install):
                for malformed in (b'{"schema":', b'[]', b'{}', b'null', bytes([255])):
                    node_receipt.write_bytes(malformed)
                    self.assertIn('browser: malformed receipt', project.status(root, contract, runtime)[-1])
                    self.assertEqual(node_receipt.read_bytes(), malformed)
                    project.prepare(root, contract, runtime, sys.executable)
                    self.assertEqual(project.read_receipt(node_receipt), ({'schema': 1, 'fingerprint': digest}, False))
                    self.assertEqual(python_receipt.read_bytes(), valid_python)
                    self.assertEqual(project.browser_state(root)[-1], [])

    def test_legacy_browser_receipt_is_preserved_outside_npm_clean_tree_on_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'plugins').mkdir()
            manifest = browser_fixture(root); project.scaffold(root, 'alpha')
            contract = project.load(root, 'alpha'); contract['browser'] = True
            runtime = '.'.join(map(str, sys.version_info[:2]))
            (root / contract['venvs'][runtime]).mkdir(parents=True)
            stamp, digest, _, _ = project.browser_state(root)
            legacy = root / 'node_modules/.plugins-dependencies.json'
            legacy.write_text('{"schema":')
            self.assertIn('browser: malformed receipt', project.browser_state(root)[-1])
            self.assertFalse(stamp.exists())  # even migration is not allowed during a read
            valid = {'schema': 1, 'fingerprint': digest}
            project.write_receipt(legacy, valid)
            self.assertEqual(project.browser_state(root)[2], valid)
            manifest.write_text(json.dumps({'name': 'playwright', 'version': '1.1.0', 'main': 'index.js'}))
            original_run = project.run
            def interrupted_npm(args, **kwargs):
                if args[:2] == ['npm', 'ci']:
                    legacy.unlink()  # npm ci really removes this location before installing
                    raise subprocess.CalledProcessError(17, ['npm', 'ci'])
                return original_run(args, **kwargs)
            with patch.object(project, 'inventory'), patch.object(project, 'python_version', return_value=runtime), \
                    patch.object(project, 'run', side_effect=interrupted_npm):
                with self.assertRaises(subprocess.CalledProcessError):
                    project.prepare(root, contract, runtime, sys.executable)
            self.assertEqual(project.read_receipt(stamp), (valid, False))
            self.assertIn('browser: dependency/runtime drift', project.browser_state(root)[-1])

    def test_failed_atomic_replacement_preserves_last_valid_python_and_browser_receipts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for python in (False, True):
                with self.subTest(python=python):
                    stamp = root / ('python.json' if python else 'browser.json')
                    old = {'schema': 1, 'fingerprint': 'a' * 64}
                    if python: old['runtime'] = '3.13'
                    project.write_receipt(stamp, old)
                    original = stamp.read_bytes()
                    replacement = dict(old, fingerprint='b' * 64)
                    with patch.object(Path, 'replace', side_effect=OSError('synthetic interrupted publication')):
                        with self.assertRaises(OSError): project.write_receipt(stamp, replacement)
                    self.assertEqual(stamp.read_bytes(), original)
                    self.assertEqual(project.read_receipt(stamp, python=python), (old, False))
                    self.assertEqual(list(root.glob(stamp.name + '.*.tmp')), [])
                    project.write_receipt(stamp, replacement)
                    self.assertEqual(project.read_receipt(stamp, python=python), (replacement, False))
