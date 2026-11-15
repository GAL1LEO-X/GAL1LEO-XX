#!/usr/bin/env python3
"""Local project entrypoint. No Git writes, remote dispatch or production actions."""
import argparse
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
NAME = re.compile(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*')
LOCK_FDS = ContextVar('project_lock_fds', default=())


def run(args, *, root=ROOT, env=None, capture=False):
    # The direct child retains the lock if its controller is killed mid-command.
    inherited = {'pass_fds': LOCK_FDS.get()} if os.name == 'posix' else {}
    return subprocess.run([str(x) for x in args], cwd=root, env=env, check=True,
                          text=True, capture_output=capture, **inherited)


def inside(root, relative):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError('Contract paths must be relative')
    path = root / relative
    if '..' in Path(relative).parts or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Contract path escapes its project')
    return path


def load(root, name):
    if not NAME.fullmatch(name):
        raise ValueError('Invalid plugin name')
    folder = inside(root, 'plugins/' + name)
    path = folder / 'project.json'
    value = json.loads(path.read_text())
    expected = {'schema', 'id', 'version_file', 'requirements', 'project', 'editable',
                'venvs', 'checks', 'build', 'browser'}
    if set(value) != expected or value['schema'] != 1 or value['id'] != name:
        raise ValueError('Invalid project contract: ' + name)
    for key in ('version_file', 'requirements'):
        if not inside(folder, value[key]).is_file():
            raise ValueError('Missing project input: ' + key)
    if value['project'] is not None:
        if not inside(folder, value['project']).is_file():
            raise ValueError('Missing Python project metadata')
    if type(value['editable']) is not bool or type(value['browser']) is not bool:
        raise ValueError('Project flags must be booleans')
    if value['editable'] and value['project'] != 'pyproject.toml':
        raise ValueError('Editable projects require pyproject.toml')
    if not isinstance(value['venvs'], dict) or set(value['venvs']) != {'3.13', '3.14'}:
        raise ValueError('Declare both supported Python runtimes')
    for version, relative in value['venvs'].items():
        expected_path = '.venvs/' + name + ('' if version == '3.13' else '-3.14')
        if relative != expected_path:
            raise ValueError('Each plugin/runtime must own its isolated venv')
        inside(root, relative)
    if not isinstance(value['checks'], dict) or set(value['checks']) != {'quick', 'full'}:
        raise ValueError('Declare quick and full checks')
    for commands in [*value['checks'].values(), [value['build']]]:
        if not isinstance(commands, list) or not commands:
            raise ValueError('Commands must be nonempty argv lists')
        for command in commands:
            if not isinstance(command, list) or not command or not all(isinstance(x, str) and x for x in command):
                raise ValueError('Commands must be nonempty argv lists')
    return value


def projects(root=ROOT):
    # A plugin without a contract is an error, never silently omitted from CI.
    result = []
    for folder in sorted((root / 'plugins').iterdir()):
        if folder.is_dir() and not folder.name.startswith(('.', '__')):
            load(root, folder.name)
            result.append(folder.name)
    return result


def select_environment(contract, mode='slot', slot='work'):
    """Select a workspace-local environment without changing the plugin contract."""
    if mode == 'isolated':
        return contract
    if mode != 'slot' or not NAME.fullmatch(slot) or len(slot) > 48:
        raise ValueError('Invalid environment selection')
    return dict(contract, venvs={runtime: f'.venvs/slots/{slot}-{runtime}'
                                for runtime in contract['venvs']})


def fingerprint(root, contract):
    folder = root / 'plugins' / contract['id']
    files = {folder / 'project.json', inside(folder, contract['version_file'])}
    if contract['project']:
        files.add(inside(folder, contract['project']))
    def lock(path, visiting):
        if path in visiting:
            raise ValueError('Recursive requirements include')
        files.add(path)
        for line in path.read_text().splitlines():
            if line.strip().startswith('-r '):
                child = inside(path.parent, line.strip()[3:].strip())
                lock(child, visiting | {path})
    lock(inside(folder, contract['requirements']), set())
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(str(path.relative_to(root)).encode() + b'\0' + path.read_bytes() + b'\0')
    return digest.hexdigest()


def venv_python(folder):
    # POSIX/WSL and native Windows layouts; WhatsApp's operational tools need Linux.
    return folder / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def inventory(root, contract, python):
    folder = root / 'plugins' / contract['id']
    command = [python, Path(__file__).parent / 'cloud/sync_dependencies.py',
               '--requirements', inside(folder, contract['requirements'])]
    if contract['project']:
        command.extend(['--project', inside(folder, contract['project'])])
    run(command, root=root, capture=True)
    run([python, '-m', 'pip', 'check'], root=root, capture=True)
    if contract['editable']:
        name = tomllib.loads(inside(folder, contract['project']).read_text())['project']['name']
        source = ('import importlib.metadata as m,json,sys; from pathlib import Path; '
                  'from urllib.parse import urlsplit; from urllib.request import url2pathname; '
                  'd=json.loads(m.distribution(sys.argv[1]).read_text("direct_url.json") or "{}"); '
                  'u=urlsplit(d.get("url", "")); '
                  'valid=d.get("dir_info",{}).get("editable") is True and u.scheme=="file" '
                  'and u.netloc in ("", "localhost") and '
                  'Path(url2pathname(u.path)).resolve()==Path(sys.argv[2]).resolve(); '
                  'sys.exit(0 if valid else 1)')
        run([python, '-c', source, name, folder], root=root, capture=True)


def python_version(root, python):
    return run([python, '-c', 'import sys; print("%d.%d" % sys.version_info[:2])'],
               root=root, capture=True).stdout.strip()


def read_receipt(path, *, python=False):
    try:
        content = path.read_text(encoding='utf-8')
    except FileNotFoundError:
        return None, False
    except UnicodeError:
        return None, True
    try:
        value = json.loads(content)
    except ValueError:
        return None, True
    fields = {'schema', 'fingerprint'} | ({'runtime'} if python else set())
    valid = (isinstance(value, dict) and set(value) == fields and
             type(value['schema']) is int and value['schema'] == 1 and
             isinstance(value['fingerprint'], str) and
             re.fullmatch(r'[0-9a-f]{64}', value['fingerprint']) is not None and
             (not python or value['runtime'] in ('3.13', '3.14')))
    return (value, False) if valid else (None, True)


def write_receipt(path, value):
    # Keep the old receipt until the entire new JSON has been written/closed.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                dir=path.parent, prefix=path.name + '.', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(value, indent=2) + '\n')
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def browser_state(root):
    digest = hashlib.sha256(b''.join((root / name).read_bytes() for name in
                                    ('package.json', 'package-lock.json'))).hexdigest()
    # npm ci removes node_modules; keep the durable receipt outside that tree.
    stamp = root / '.venvs/browser.dependencies.json'
    recorded, malformed = read_receipt(stamp)
    if recorded is None and not malformed:
        # Read-only compatibility with receipts produced earlier in this PR.
        recorded, malformed = read_receipt(root / 'node_modules/.plugins-dependencies.json')
    problems = ['browser: malformed receipt'] if malformed else []
    if recorded and recorded != {'schema': 1, 'fingerprint': digest}:
        problems.append('browser: manifest/lock changed')
    try:
        run(['node', '-e', 'if(process.versions.node.split(".")[0]!=="24") process.exit(1)'], root=root)
        run(['npm', 'ls', '--all', '--json'], root=root, capture=True)
        run(['node', Path(__file__).parent / 'cloud/check_node_dependencies.cjs'], root=root, capture=True)
        run(['node', '-e', 'const fs=require("node:fs"),{chromium}=require("playwright");'
             'if(!fs.existsSync(chromium.executablePath())) process.exit(1)'], root=root)
    except (OSError, subprocess.CalledProcessError):
        problems.append('browser: dependency/runtime drift')
    return stamp, digest, recorded, problems


def status(root, contract, runtime):
    python = venv_python(inside(root, contract['venvs'][runtime]))
    digest = fingerprint(root, contract)
    stamp = inside(root, contract['venvs'][runtime]) / '.plugins-dependencies.json'
    recorded, malformed = read_receipt(stamp, python=True)
    problems = ['python: malformed receipt'] if malformed else []
    if recorded and recorded != {'schema': 1, 'fingerprint': digest, 'runtime': runtime}:
        problems.append('python: manifest/lock changed')
    try:
        if python_version(root, python) != runtime:
            problems.append('python: wrong runtime')
        inventory(root, contract, python)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        problems.append('python: dependency/runtime drift (' + type(error).__name__ + ')')
    if contract['browser']:
        problems.extend(browser_state(root)[-1])
    return python, stamp, digest, recorded, problems


@contextmanager
def setup_lock(root, contract, runtime, *, existing=False, shared=False):
    folder = inside(root, contract['venvs'][runtime]).parent
    if not existing:
        folder.mkdir(parents=True, exist_ok=True)
    # Same lock names as legacy bootstrap/prepare for WhatsApp.
    path = inside(root, contract['venvs'][runtime] + '.setup.lock')
    with path.open('r' if existing else 'a') as stream:
        if os.name == 'nt':
            import msvcrt
            if not existing:
                stream.write('0'); stream.flush(); stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBRLCK if shared or existing else msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        yield stream.fileno()


@contextmanager
def environment_lock(root, contract, runtime, *, existing=False, browser_write=False):
    # Readers hold the same locks through execution, so a slot cannot switch
    # while a check/build is running. Order matches the legacy bootstrap.
    with ExitStack() as stack:
        descriptors = list(LOCK_FDS.get())
        if contract['browser']:
            descriptors.append(stack.enter_context(setup_lock(
                root, {'venvs': {runtime: '.venvs/browser'}}, runtime,
                existing=existing, shared=not browser_write)))
        descriptors.append(stack.enter_context(setup_lock(root, contract, runtime, existing=existing)))
        token = LOCK_FDS.set(tuple(descriptors))
        try:
            yield
        finally:
            LOCK_FDS.reset(token)


def browser_needs_write(state):
    return state and (state[-1] or not state[0].exists() or
                     state[2] != {'schema': 1, 'fingerprint': state[1]})


def prepare(root, contract, runtime, base_python):
    # A Python-only synchronization can coexist with readers in other slots.
    # If shared browser files need changes, release and reacquire exclusively;
    # prepare_locked rechecks state after reacquisition, before any mutation.
    with environment_lock(root, contract, runtime):
        browser = browser_state(root) if contract['browser'] else None
        if not browser_needs_write(browser):
            return prepare_locked(root, contract, runtime, base_python)
    with environment_lock(root, contract, runtime, browser_write=True):
        return prepare_locked(root, contract, runtime, base_python, browser_write=True)


def prepare_locked(root, contract, runtime, base_python, *, browser_write=False):
    python, stamp, digest, recorded, problems = status(root, contract, runtime)
    if python.exists() and python_version(root, python) != runtime:
        raise ValueError('Existing venv has another runtime; it is preserved')
    browser = browser_state(root) if contract['browser'] else None
    if browser_needs_write(browser) and not browser_write:
        raise ValueError('Browser inputs changed during preparation; rerun prepare')
    if any(problem.startswith('python:') and problem != 'python: malformed receipt' for problem in problems):
        if python_version(root, base_python) != runtime:
            raise ValueError('Select --python matching --runtime')
        if not python.exists():
            run([base_python, '-m', 'venv', inside(root, contract['venvs'][runtime])], root=root)
        folder = root / 'plugins' / contract['id']
        # Install only on detected drift; the target interpreter validates
        # exact pins before any pruning. Failed preparation never stamps.
        run([python, '-m', 'pip', '--disable-pip-version-check', 'install',
             '-r', inside(folder, contract['requirements'])], root=root)
        if contract['editable']:
            run([python, '-m', 'pip', '--disable-pip-version-check', 'install',
                 '--no-deps', '-e', folder], root=root)
        sync = [python, Path(__file__).parent / 'cloud/sync_dependencies.py',
                '--requirements', inside(folder, contract['requirements']), '--prune']
        if contract['project']:
            sync.extend(['--project', inside(folder, contract['project'])])
        run(sync, root=root)
        run([python, '-m', 'pip', 'check'], root=root)
    if browser and any(problem != 'browser: malformed receipt' for problem in browser[-1]):
        node_stamp, _, node_recorded, _ = browser
        if node_recorded is not None and not node_stamp.exists():
            # Preserve the last valid legacy receipt before npm can remove it.
            write_receipt(node_stamp, node_recorded)
        run(['node', '-e', 'if(process.versions.node.split(".")[0]!=="24") process.exit(1)'], root=root)
        run(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], root=root)
        run(['npx', '--no-install', 'playwright', 'install', 'chromium'], root=root)
    _, _, final_digest, _, remaining = status(root, contract, runtime)
    # Old receipts may still report a change. Concurrent edits and any
    # unresolved inventory problem must never be stamped as prepared.
    if final_digest != digest or any(not x.endswith(('manifest/lock changed', 'malformed receipt')) for x in remaining):
        raise ValueError('Inputs changed during preparation or inventory still differs')
    if browser:
        node_stamp, node_digest, node_recorded, _ = browser
        if browser_state(root)[1] != node_digest:
            raise ValueError('Browser inputs changed during preparation')
        node_receipt = {'schema': 1, 'fingerprint': node_digest}
        if node_recorded != node_receipt or not node_stamp.exists():
            write_receipt(node_stamp, node_receipt)
    receipt = {'schema': 1, 'fingerprint': digest, 'runtime': runtime}
    if recorded != receipt:
        write_receipt(stamp, receipt)
    print('READY ' + contract['id'] + (' (synchronized)' if problems else ' (no installation)'))


def execute(root, contract, runtime, mode, extra=()):
    with environment_lock(root, contract, runtime):
        return execute_locked(root, contract, runtime, mode, extra)


def execute_locked(root, contract, runtime, mode, extra=()):
    python, _, _, _, problems = status(root, contract, runtime)
    if problems:
        raise ValueError('; '.join(problems) + '; run prepare explicitly')
    results = root / 'work/test-results' / contract['id'] / runtime
    # Distinct slots may run the same project/runtime concurrently.
    # Keep the slots/ component too: isolated and named slots can share a basename.
    results /= Path(contract['venvs'][runtime]).relative_to('.venvs')
    results.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PLUGINS_TEST_PYTHON=str(python), PLUGINS_TEST_RESULTS_DIR=str(results))
    env['VIRTUAL_ENV'] = str(python.parent.parent)
    env['PATH'] = str(python.parent) + os.pathsep + env.get('PATH', '')
    substitutions = dict(python=str(python), root=str(root),
                         plugin=str(root / 'plugins' / contract['id']), results=str(results))
    commands = [contract['build']] if mode == 'build' else ([list(extra)] if mode == 'run' else contract['checks'][mode])
    for command in commands:
        argv = list(command) if mode == 'run' else [part.format(**substitutions) for part in command] + list(extra)
        run(argv, root=root, env=env)


def checkout_identity(root):
    def git(*args):
        return run(['git', '--no-optional-locks', *args], root=root, capture=True).stdout.rstrip('\n')
    status_lines = git('status', '--porcelain=v1', '--untracked-files=normal').splitlines()
    return {'root': git('rev-parse', '--show-toplevel'),
            'branch': git('rev-parse', '--abbrev-ref', 'HEAD'),
            'head': git('rev-parse', 'HEAD'), 'dirty': bool(status_lines),
            'status': status_lines}


def scaffold(root, name):
    if not NAME.fullmatch(name) or len(name) > 48:
        raise ValueError('Invalid plugin name')
    folder = inside(root, 'plugins/' + name)
    if folder.exists() or folder.is_symlink():
        raise ValueError('Plugin already exists')
    folder.mkdir(parents=True)
    (folder / 'src').mkdir()
    (folder / 'tests').mkdir()
    contract = dict(schema=1, id=name, version_file='VERSION', requirements='requirements-test.lock',
                    project=None, editable=False, browser=False,
                    venvs={'3.13': '.venvs/' + name, '3.14': '.venvs/' + name + '-3.14'},
                    checks={level: [['{python}', '-m', 'unittest', 'discover', '-s', '{plugin}/tests']]
                            for level in ('quick', 'full')},
                    build=['{python}', '{plugin}/build.py'])
    (folder / 'project.json').write_text(json.dumps(contract, indent=2) + '\n')
    (folder / 'VERSION').write_text('0.1.0\n')
    (folder / 'requirements-test.lock').write_text('# Exact pins, including the inventory checker. No shared plugin venv.\npackaging==26.3\n')
    (folder / 'src' / (name.replace('-', '_') + '.py')).write_text('"""Project source; implement the reviewed contract here."""\nVERSION = "0.1.0"\n')
    (folder / 'tests/test_version.py').write_text(
        'from pathlib import Path\nimport runpy\nimport unittest\n\n'
        'class VersionTest(unittest.TestCase):\n'
        '    def test_source_version(self):\n'
        '        root = Path(__file__).resolve().parents[1]\n'
        f'        source = runpy.run_path(str(root / "src/{name.replace("-", "_")}.py"))\n'
        '        self.assertEqual(source["VERSION"], (root / "VERSION").read_text().strip())\n')
    (folder / 'README.md').write_text('# ' + name + '\n\nDevelopment scaffold only. No server, account or ChatGPT registration.\n'
        'Define requirements, identity, data, services, health and recovery before production.\n')
    (folder / 'AGENTS.md').write_text('# ' + name + '\n\nRead the root AGENTS.md. Keep code, locks, tests, version and build here.\n'
        'Only synthetic data. Production requires a project-specific mandate.\n'
        'Before adding a publisher, read docs/release-pipeline.md from the repository root.\n'
        'Reuse the corrected repository HTTP client; any new download adapter must pass '
        'tools/release_http_contract.py through a test under tools/tests/.\n')
    template = Path(__file__).parent / 'templates/plugin_build.py'
    (folder / 'build.py').write_text(template.read_text())
    print('CREATED ' + name + ' (development only; CI discovers project.json)')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT, help='Explicit source root, also used by temporary tests')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('list')
    new = sub.add_parser('new'); new.add_argument('name')
    for command in ('start', 'prepare', 'check', 'build', 'run', 'ci'):
        child = sub.add_parser(command)
        if command != 'ci': child.add_argument('plugin')
        child.add_argument('--runtime', choices=['3.13', '3.14'], default='3.13')
        child.add_argument('--venv-mode', choices=['slot', 'isolated'], default='slot',
                           help='Reuse one configurable slot (default), or keep a venv per plugin')
        child.add_argument('--slot', default='work', help='Workspace slot name for separate concurrent work')
        if command in ('prepare', 'ci'): child.add_argument('--python', default=sys.executable)
        if command == 'check': child.add_argument('--level', choices=['quick', 'full'], default='quick')
        if command == 'ci': child.add_argument('--skip', action='append', default=[],
                                             help='Project already checked by another CI step')
    argv = list(sys.argv[1:] if argv is None else argv)
    build_args = []
    if '--' in argv:
        separator = argv.index('--')
        build_args, argv = argv[separator + 1:], argv[:separator]
    args = parser.parse_args(argv)
    if build_args and args.command not in ('build', 'run'): parser.error('Extra argv only supported for build/run after --')
    if args.command == 'run' and not build_args: parser.error('run requires a command after --')
    root = args.root.resolve()
    try:
        if args.command == 'list':
            for name in projects(root): print(name)
        elif args.command == 'new': scaffold(root, args.name)
        elif args.command == 'ci':
            names = projects(root)
            if set(args.skip) - set(names):
                raise ValueError('Unknown project in --skip')
            for name in names:
                if name in args.skip: continue
                contract = select_environment(load(root, name), args.venv_mode, args.slot)
                prepare(root, contract, args.runtime, args.python)
                execute(root, contract, args.runtime, 'full')
        else:
            if args.command == 'start':
                print('CHECKOUT ' + json.dumps(checkout_identity(root)), flush=True)
            contract = select_environment(load(root, args.plugin), args.venv_mode, args.slot)
            if args.command == 'prepare': prepare(root, contract, args.runtime, args.python)
            elif args.command == 'start':
                if args.venv_mode == 'slot':
                    with environment_lock(root, contract, args.runtime, existing=True):
                        _, _, _, recorded, problems = status(root, contract, args.runtime)
                else:
                    _, _, _, recorded, problems = status(root, contract, args.runtime)
                if problems: raise ValueError('; '.join(problems) + '; run prepare explicitly')
                print('READY ' + args.plugin + (' (receipt present)' if recorded else ' (inventory verified; prepare records initial receipt)'))
            else:
                extra = build_args if args.command in ('build', 'run') else []
                if extra[:1] == ['--']: extra = extra[1:]
                execute(root, contract, args.runtime, args.command if args.command in ('build', 'run') else args.level, extra)
        return 0
    except BlockingIOError:
        print('BUSY: environment is in use; finish the running command or select another --slot', file=sys.stderr)
        return 1
    except FileNotFoundError:
        print('NOT PREPARED: run prepare for the selected plugin, runtime and environment', file=sys.stderr)
        return 1
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        # Avoid printing command output, environment, credentials or arbitrary subprocess argv.
        print('BLOCKED: ' + (str(error) if isinstance(error, ValueError) else type(error).__name__), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
