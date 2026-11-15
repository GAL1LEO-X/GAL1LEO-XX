"""Real offline venv/package/Git/build boundaries; no synthetic installed plugin survives."""
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('project_entry', ROOT / 'tools/project.py')
project = importlib.util.module_from_spec(spec); spec.loader.exec_module(project)


def command(*args, cwd=None, env=None):
    return subprocess.run(list(map(str, args)), cwd=cwd, env=env, text=True, capture_output=True, check=True)


def wheel(folder, name):
    info = name + '-1.0.0.dist-info/'
    data = {name + '.py': 'VALUE = "synthetic"\n',
            info + 'METADATA': f'Metadata-Version: 2.1\nName: {name.replace("_", "-")}\nVersion: 1.0.0\n',
            info + 'WHEEL': 'Wheel-Version: 1.0\nGenerator: synthetic\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
    data[info + 'RECORD'] = ''.join(path + ',,\n' for path in data) + info + 'RECORD,,\n'
    with zipfile.ZipFile(folder / (name + '-1.0.0-py3-none-any.whl'), 'w') as archive:
        for path, content in data.items(): archive.writestr(path, content)


def packaging_wheel(folder):
    # Repackage only the already-installed test tool for an offline venv fixture.
    dist = importlib.metadata.distribution('packaging')
    with zipfile.ZipFile(folder / f'packaging-{dist.version}-py3-none-any.whl', 'w') as archive:
        for item in dist.files:
            if str(item).startswith(('packaging/', 'packaging-' + dist.version + '.dist-info/')) and '__pycache__' not in str(item):
                archive.write(dist.locate_file(item), str(item))
    return dist.version


class EntryTests(unittest.TestCase):
    def test_system_controller_has_no_site_dependency(self):
        # -S hides site-packages. In the Cloud this is Python 3.12, not test Python.
        base = shutil.which('python3') or sys.executable
        result = command(base, '-S', ROOT / 'tools/project.py', 'list')
        self.assertIn('whatsapp', result.stdout)
        result = command(base, '-S', ROOT / 'tools/project.py', 'operations', 'route',
                         'whatsapp', '--kind', 'backend', '--action', 'deploy', '--commit', 'a'*40)
        self.assertEqual(json.loads(result.stdout)['status'], 'plan-only')
        self.assertEqual(json.loads(result.stdout)['inputs'], {'action': 'deploy', 'commit': 'a'*40})

    def test_operations_cli_rejects_the_retired_receiver_without_execution(self):
        result = subprocess.run([sys.executable, '-S', str(ROOT / 'tools/project.py'), 'operations', 'route',
                                 'whatsapp', '--kind', 'backend', '--tag', 'whatsapp/v1.2.3'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def test_real_isolation_drift_no_reinstall_dirty_git_and_separate_build(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'repo'; root.mkdir(); (root / 'plugins').mkdir()
            wheels = Path(temp) / 'wheels'; wheels.mkdir()
            version = packaging_wheel(wheels)
            for name in ('review_kept', 'review_removed', 'review_extra'): wheel(wheels, name)
            project.scaffold(root, 'alpha'); project.scaffold(root, 'beta')
            (root / '.gitignore').write_text('.venvs/\nwork/\n__pycache__/\n')
            for name in ('alpha', 'beta'):
                (root / 'plugins' / name / 'requirements-test.lock').write_text(
                    f'packaging=={version}\nreview-kept==1.0.0\nreview-removed==1.0.0\n')
            command('git', 'init', cwd=root)
            command('git', 'add', '.', cwd=root)
            command('git', '-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.invalid',
                    'commit', '-qm', 'fixture', cwd=root)
            (root / 'plugins/alpha/README.md').write_text('Concurrent unfinished work\n')
            (root / 'concurrent.txt').write_text('untracked concurrent work\n')
            before = command('git', 'status', '--porcelain', cwd=root).stdout
            head = command('git', 'rev-parse', 'HEAD', cwd=root).stdout
            runtime = '.'.join(map(str, sys.version_info[:2]))
            with patch.dict(os.environ, {'PIP_NO_INDEX': '1', 'PIP_FIND_LINKS': str(wheels)}):
                a = project.load(root, 'alpha'); b = project.load(root, 'beta')
                project.prepare(root, a, runtime, sys.executable)
                project.prepare(root, b, runtime, sys.executable)
                pa = project.venv_python(root / a['venvs'][runtime])
                pb = project.venv_python(root / b['venvs'][runtime])
                self.assertNotEqual(pa, pb)
                self.assertEqual(project.status(root, a, runtime)[-1], [])
                # Simulate a platform without either lock backend. Read-only
                # startup must not import either, even through the controller.
                guard = ('import subprocess,runpy,sys,builtins; original=builtins.__import__\n'
                         'def guarded(name,*args,**kwargs):\n'
                         '    if name in ("fcntl","msvcrt"): raise ImportError("lock backend unavailable")\n'
                         '    return original(name,*args,**kwargs)\n'
                         'builtins.__import__=guarded\n'
                         'sys.argv=sys.argv[1:];runpy.run_path(sys.argv[0],run_name="__main__")')
                index_before = (root / '.git/index').read_bytes()
                index_mtime = (root / '.git/index').stat().st_mtime_ns
                result = command(shutil.which('python3') or sys.executable, '-S', '-c', guard,
                                 ROOT / 'tools/project.py', '--root', root, 'start', 'alpha', '--runtime', runtime, '--venv-mode', 'isolated')
                self.assertIn('READY alpha', result.stdout)
                identity = json.loads(next(line[len('CHECKOUT '):] for line in result.stdout.splitlines() if line.startswith('CHECKOUT ')))
                self.assertEqual(identity['root'], str(root))
                self.assertEqual(identity['head'], head.strip())
                self.assertTrue(identity['branch'])
                self.assertTrue(identity['dirty'])
                self.assertEqual(identity['status'], before.splitlines())
                self.assertEqual((root / '.git/index').read_bytes(), index_before)
                self.assertEqual((root / '.git/index').stat().st_mtime_ns, index_mtime)

                original_run = project.run
                def prohibit_install(args, **kwargs):
                    if 'install' in args or 'uninstall' in args or 'ci' in args:
                        self.fail('Aligned state attempted an installation')
                    return original_run(args, **kwargs)
                with patch.object(project, 'run', side_effect=prohibit_install):
                    project.prepare(root, a, runtime, sys.executable)
                stamp = pa.parent.parent / '.plugins-dependencies.json'
                valid_receipt = stamp.read_bytes()
                for malformed in (b'{"schema":', b'[]', b'{}', b'null', bytes([255])):
                    stamp.write_bytes(malformed)
                    result = subprocess.run([shutil.which('python3') or sys.executable, '-S',
                        str(ROOT / 'tools/project.py'), '--root', str(root), 'start', 'alpha', '--runtime', runtime, '--venv-mode', 'isolated'],
                        text=True, capture_output=True)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('python: malformed receipt', result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
                    self.assertEqual(stamp.read_bytes(), malformed)  # start cannot repair/write
                    with patch.object(project, 'run', side_effect=prohibit_install):
                        project.prepare(root, a, runtime, sys.executable)
                    self.assertEqual(stamp.read_bytes(), valid_receipt)

                # Removal changes the lock even though pip check still passes.
                (root / 'plugins/alpha/requirements-test.lock').write_text(f'packaging=={version}\nreview-kept==1.0.0\n')
                command(pa, '-m', 'pip', 'check')
                self.assertTrue(project.status(root, a, runtime)[-1])
                project.prepare(root, a, runtime, sys.executable)
                def installed(python, module):
                    return command(python, '-c', f'import importlib.util; print(importlib.util.find_spec("{module}") is not None)').stdout.strip()
                self.assertEqual(installed(pa, 'review_removed'), 'False')
                self.assertEqual(installed(pb, 'review_removed'), 'True')
                command(pa, '-m', 'pip', 'install', '--no-index', '--find-links', wheels, 'review-extra==1.0.0')
                command(pa, '-m', 'pip', 'check')
                self.assertTrue(project.status(root, a, runtime)[-1])
                project.prepare(root, a, runtime, sys.executable)
                self.assertEqual(installed(pa, 'review_extra'), 'False')
                receipt = (pa.parent.parent / '.plugins-dependencies.json').read_bytes()
                lock = root / 'plugins/alpha/requirements-test.lock'
                locked = lock.read_text(); lock.write_text(locked + 'nonexistent-fixture==1.0.0\n')
                with self.assertRaises(subprocess.CalledProcessError):
                    project.prepare(root, a, runtime, sys.executable)
                self.assertEqual((pa.parent.parent / '.plugins-dependencies.json').read_bytes(), receipt)
                lock.write_text(locked)
                self.assertEqual(installed(pa, 'review_kept'), 'True')

                self.assertEqual(command('git', 'rev-parse', 'HEAD', cwd=root).stdout, head)
                # Only the intentionally edited lock differs from the dirty snapshot.
                after = command('git', 'status', '--porcelain', cwd=root).stdout
                self.assertEqual(after.replace(' M plugins/alpha/requirements-test.lock\n', ''), before)
                self.assertEqual((root / 'concurrent.txt').read_text(), 'untracked concurrent work\n')
                # Independent version/build; no app registration and output is ignored.
                (root / 'plugins/beta/VERSION').write_text('0.2.0\n')
                (root / 'plugins/beta/src/beta.py').write_text('VERSION = "0.2.0"\n')
                project.prepare(root, b, runtime, sys.executable)
                project.execute(root, a, runtime, 'full')
                project.execute(root, b, runtime, 'full')
                for name, contract, expected in [('alpha', a, '0.1.0'), ('beta', b, '0.2.0')]:
                    output = root / f'work/{name}.zip'
                    command(shutil.which('python3') or sys.executable, '-S', ROOT / 'tools/project.py',
                            '--root', root, 'build', name, '--runtime', runtime, '--venv-mode', 'isolated', '--', '--output', str(output))
                    with zipfile.ZipFile(output) as archive:
                        self.assertEqual(archive.read('VERSION').decode().strip(), expected)
                        self.assertNotIn('project.json', archive.namelist())
                self.assertEqual(project.projects(root), ['alpha', 'beta'])
                command(shutil.which('python3') or sys.executable, '-S', ROOT / 'tools/project.py',
                        '--root', root, 'ci', '--runtime', runtime, '--venv-mode', 'isolated', '--python', sys.executable)
                # Execute the actual workflow run block: a successful plugin
                # check producing tracked OR untracked files must fail CI.
                wrapper = root / 'tools/project.py'; wrapper.parent.mkdir()
                wrapper.write_text('import subprocess,sys\nraise SystemExit(subprocess.call([sys.executable,' +
                    repr(str(ROOT / 'tools/project.py')) + ',"--root",' + repr(str(root)) + ',*sys.argv[1:]]))\n')
                workflow = (ROOT / '.github/workflows/checks.yml').read_text()
                step = workflow.split('      - name: Check additional registered projects without repeating WhatsApp\n', 1)[1].split('      - uses:', 1)[0]
                script = '\n'.join(line[10:] for line in step.splitlines() if line.startswith('          '))
                script = script.replace('${{ matrix.python }}', runtime)
                script = script.replace('--skip whatsapp', '')  # fixture registers only alpha/beta
                version_test = root / 'plugins/alpha/tests/test_version.py'
                original_test = version_test.read_text()
                for target in ('README.md', 'generated-untracked.txt'):
                    version_test.write_text(original_test +
                        f'\n(Path(__file__).resolve().parents[1] / {target!r}).write_text("generated by successful check")\n')
                    command('git', 'add', '.', cwd=root)
                    command('git', '-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.invalid',
                            'commit', '-qm', 'workflow boundary fixture', cwd=root)
                    result = subprocess.run(['bash', '-eu', '-c', script], cwd=root, text=True, capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('READY alpha (no installation)', result.stdout)
                    self.assertIn('READY beta (no installation)', result.stdout)
                    self.assertEqual((root / 'plugins/alpha' / target).read_text(), 'generated by successful check')
                    if target == 'README.md':
                        (root / 'plugins/alpha/README.md').write_text('Concurrent unfinished work\n')


    def test_missing_contract_shared_venv_and_escape_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'plugins').mkdir()
            project.scaffold(root, 'alpha')
            path = root / 'plugins/alpha/project.json'
            value = json.loads(path.read_text()); value['venvs']['3.13'] = '.venvs/whatsapp'
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError): project.load(root, 'alpha')
            value['venvs']['3.13'] = '.venvs/alpha'; value['requirements'] = '../../outside.lock'
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError): project.load(root, 'alpha')
            with self.assertRaises(ValueError): project.scaffold(root, 'alpha')
            with self.assertRaises(ValueError): project.scaffold(root, '../escape')
            (root / 'plugins/unregistered').mkdir()
            with self.assertRaises((ValueError, FileNotFoundError)): project.projects(root)
