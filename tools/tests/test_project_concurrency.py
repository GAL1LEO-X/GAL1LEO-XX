"""Real processes exercise independent slots, interrupted controllers and port locks."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from test_project_entrypoint import project, ROOT


CONTROLLER = '''
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('controller', sys.argv[1])
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
root = Path(sys.argv[2]); slot, tag = sys.argv[3:5]
contract = {'id': 'alpha', 'browser': True, 'venvs': {'3.13': slot}}
p.status = lambda *args: (Path(sys.executable), None, None, None, [])
p.execute(root, contract, '3.13', 'run', [sys.executable, str(root / 'worker.py'), tag])
'''

WORKER = '''
import json, os, sys, time
from pathlib import Path
tag = sys.argv[1]
Path('holding-' + tag).write_text(json.dumps({'results': os.environ['PLUGINS_TEST_RESULTS_DIR']}))
deadline = time.monotonic() + 20
while not Path('release-' + tag).exists() and time.monotonic() < deadline:
    time.sleep(.02)
Path('finished-' + tag).touch()
'''


@unittest.skipUnless(os.name == 'posix', 'Cloud lock inheritance requires POSIX')
class ConcurrencyTests(unittest.TestCase):
    def wait_for(self, path):
        deadline = time.monotonic() + 10
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertTrue(path.exists(), str(path))

    def start(self, root, slot, tag, *, isolated=False):
        (root / 'worker.py').write_text(WORKER)
        relative = '.venvs/' + ('' if isolated else 'slots/') + slot
        return subprocess.Popen([sys.executable, '-c', CONTROLLER,
            str(ROOT / 'tools/project.py'), str(root), relative, tag], cwd=root,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_equal_basenames_in_isolated_and_slot_modes_have_distinct_results(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); children = []
            try:
                for tag, isolated in [('isolated', True), ('slot', False)]:
                    children.append(self.start(root, 'same-3.14', tag, isolated=isolated))
                    self.wait_for(root / ('holding-' + tag))
                results = [json.loads((root / ('holding-' + tag)).read_text())['results']
                           for tag in ('isolated', 'slot')]
                self.assertNotEqual(*results)
            finally:
                for tag in ('isolated', 'slot'):
                    (root / ('release-' + tag)).touch()
                for child in children:
                    child.wait(timeout=10)
            self.assertTrue(all(child.returncode == 0 for child in children))

    def test_independent_slots_share_browser_reads_and_keep_results_separate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            children = []
            try:
                for tag in ('first', 'second'):
                    children.append(self.start(root, tag, tag))
                    self.wait_for(root / ('holding-' + tag))
                results = [json.loads((root / ('holding-' + tag)).read_text())['results']
                           for tag in ('first', 'second')]
                self.assertNotEqual(*results)
                shared = {'browser': True, 'venvs': {'3.13': '.venvs/slots/third'}}
                # A third reader works, while a browser installation is excluded.
                with project.environment_lock(root, shared, '3.13'):
                    pass
                # An already-valid browser does not serialize Python preparation.
                receipt = root / '.venvs/browser.dependencies.json'; receipt.touch()
                state = (receipt, 'digest', {'schema': 1, 'fingerprint': 'digest'}, [])
                with patch.object(project, 'browser_state', return_value=state), \
                        patch.object(project, 'prepare_locked') as synchronize:
                    project.prepare(root, shared, '3.13', sys.executable)
                    synchronize.assert_called_once()
                with self.assertRaises(BlockingIOError):
                    with project.environment_lock(root, shared, '3.13', browser_write=True):
                        self.fail('Browser mutation entered while readers were active')
                with self.assertRaises(BlockingIOError):
                    with project.environment_lock(root, dict(shared, venvs={'3.13': '.venvs/slots/first'}), '3.13'):
                        self.fail('An active slot was acquired twice')
            finally:
                for tag in ('first', 'second'):
                    (root / ('release-' + tag)).touch()
                for child in children:
                    child.wait(timeout=10)
            self.assertTrue(all(child.returncode == 0 for child in children))

    def test_child_retains_slot_and_browser_lock_after_controller_is_killed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); child = self.start(root, 'active', 'orphan')
            contract = {'browser': True, 'venvs': {'3.13': '.venvs/slots/active'}}
            try:
                self.wait_for(root / 'holding-orphan')
                child.kill(); child.wait(timeout=5)
                with self.assertRaises(BlockingIOError):
                    with project.environment_lock(root, contract, '3.13'):
                        self.fail('The still-running child lost its slot lock')
                with self.assertRaises(BlockingIOError):
                    with project.environment_lock(root, contract, '3.13', browser_write=True):
                        self.fail('The still-running child lost its browser read lock')
            finally:
                (root / 'release-orphan').touch()
                self.wait_for(root / 'finished-orphan')
                child.wait(timeout=10)
            # Completion releases descriptors automatically, without stale lock cleanup.
            deadline = time.monotonic() + 5
            while True:
                try:
                    with project.environment_lock(root, contract, '3.13', browser_write=True):
                        break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.02)

    def test_only_whatsapp_browser_phase_owns_fixed_ports(self):
        import fcntl
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); cloud = root / 'tools/cloud'; cloud.mkdir(parents=True)
            script = cloud / 'check.sh'; script.write_bytes((ROOT / 'tools/cloud/check.sh').read_bytes())
            binaries = root / 'bin'; binaries.mkdir()
            for name, text in {'python': '#!/bin/sh\nexit 0\n',
                               'npm': '#!/bin/sh\ntouch browser-ran\n',
                               'git': '#!/bin/sh\nexit 0\n'}.items():
                path = binaries / name; path.write_text(text); path.chmod(0o755)
            (root / '.venvs').mkdir()
            env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ['PATH'])
            args = ['bash', str(script), '--python', str(binaries / 'python')]
            with (root / '.venvs/whatsapp.browser-test.lock').open('w') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                blocked = subprocess.run(args, env=env, text=True, capture_output=True)
                self.assertNotEqual(blocked.returncode, 0)
                self.assertIn('ports 8875/8876', blocked.stderr)
                self.assertFalse((root / 'browser-ran').exists())
                backend = subprocess.run([*args, '--backend-only'], env=env, text=True, capture_output=True)
                self.assertEqual(backend.returncode, 0, backend.stderr)
            completed = subprocess.run(args, env=env, text=True, capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((root / 'browser-ran').exists())
