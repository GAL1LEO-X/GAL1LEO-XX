"""Small, server-owned release receiver. Only stdlib; no repository code execution.

The SSH key is restricted to one installed receiver. Its short-lived Actions
token has contents/actions read permissions and is never written to disk.
This module is also versioned independently with the WhatsApp receiver.
"""
import sys as _installation_sys
from pathlib import Path as _InstallationPath
import types as _installation_types
if 'installation_layout' not in _installation_sys.modules:
    _installation_source=_InstallationPath(__file__).with_name('installation_layout.py')
    _installation_module=_installation_types.ModuleType('installation_layout')
    _installation_module.__file__=str(_installation_source)
    _installation_sys.modules['installation_layout']=_installation_module
    try:
        exec(compile(_installation_source.read_bytes(),str(_installation_source),'exec'),_installation_module.__dict__)
    except BaseException:
        _installation_sys.modules.pop('installation_layout',None)
        raise
if getattr(_installation_sys.modules['installation_layout'], 'FORMAT', None) != 'whatsapp-installation-v1':
    raise ImportError('The whatsapp entry point cannot reuse another product installation layout')
from installation_layout import active as installation_profile, mapped as installation_path
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

STATE = Path(installation_path('/var/lib/develative-deploy'))
REPOSITORIES = {'box': 'example-owner/example-project', 'whatsapp': 'GAL1LEO-X/GAL1LEO-XX'}


class ReleaseError(RuntimeError):
    """A safe error message which may be returned to the Actions log."""


def require(condition, message):
    if not condition:
        raise ReleaseError(message)


def sha(path):
    # Callers hash closed SQLite snapshots, never a live main file plus WAL.
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def normalized(path):
    return Path(path).read_bytes().replace(b'\r\n', b'\n')


def file_map(root):
    root = Path(root)
    result = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'Symlinks are not allowed in a deployment source')
        if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc':
            result[path.relative_to(root).as_posix()] = sha(path)
    return result


def run(args, *, env=None, timeout=180, cwd=None, pass_fds=None):
    try:
        process = subprocess.run([str(x) for x in args], cwd=cwd, env=env,
                                 capture_output=True, text=True, timeout=timeout,
                                 **({'pass_fds': pass_fds} if pass_fds is not None else {}))
    except (OSError, subprocess.TimeoutExpired):
        raise ReleaseError('A deployment command could not finish') from None
    require(process.returncode == 0, 'A deployment command failed: ' + Path(str(args[0])).name)
    return process.stdout.strip()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent,
                                         delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        if os.name == 'posix':
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def route(project, tag):
    require(isinstance(tag, str), 'Tag must be a string')
    if project == 'box':
        match = re.fullmatch(r'box/v(\d+\.\d+\.\d+(?:-(beta|ai)\.\d+)?)', tag)
        require(match is not None, 'Use box/vX.Y.Z, box/vX.Y.Z-beta.N or box/vX.Y.Z-ai.N')
        version, suffix = match.groups()
        channel = suffix or 'release'
        return {'version': version, 'channel': channel,
                'branch': {'release': 'main', 'beta': 'box/beta', 'ai': 'box/ai'}[channel]}
    require(project == 'whatsapp', 'Unknown project')
    match = re.fullmatch(r'whatsapp/v(\d+\.\d+\.\d+)', tag)
    require(match is not None, 'Use whatsapp/vX.Y.Z for a WhatsApp backend release')
    return {'version': match.group(1), 'channel': 'whatsapp', 'branch': 'main'}


def version_key(value):
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-(beta|ai)\.(\d+))?', value)
    require(match is not None, 'Unsupported active version')
    major, minor, patch, suffix, number = match.groups()
    return (int(major), int(minor), int(patch), int(number or 0))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token, repository):
        require(isinstance(token, str) and re.fullmatch(r'[A-Za-z0-9_.-]{20,4096}', token),
                'A short-lived GitHub token is required')
        require(repository in REPOSITORIES.values(), 'Repository is not allowed')
        self.token, self.repository = token, repository
        self.opener = urllib.request.build_opener(NoRedirect)

    def get(self, path):
        require(path.startswith('/'), 'Invalid API path')
        request = urllib.request.Request('https://api.github.com/repos/' + self.repository + path,
            headers={'Authorization': 'Bearer ' + self.token,
                     'Accept': 'application/vnd.github+json',
                     'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'develative-release'})
        try:
            with self.opener.open(request, timeout=30) as response:
                return json.load(response)
        except (urllib.error.URLError, ValueError):
            raise ReleaseError('GitHub verification failed; check repository token permissions') from None


def select_ci_run(runs, commit, branch):
    eligible = [item for item in runs if item.get('head_sha') == commit
                and item.get('head_branch') == branch
                and item.get('event') in ('push', 'workflow_dispatch')]
    require(bool(eligible), 'No branch CI run exists for the exact release commit')
    latest = max(eligible, key=lambda item: (item['id'], item.get('run_attempt', 1)))
    require(latest.get('status') == 'completed' and latest.get('conclusion') == 'success',
            'The latest branch CI run for the release commit has not succeeded')
    return latest


def verify_ci(api, project, commit, target):
    workflows = [('box-ci.yml', ['portable (ubuntu-24.04)', 'portable (windows-2025)',
                                 'browser', 'secrets', 'BOX required checks'])] if project == 'box' else [
        ('checks.yml', ['development (3.13)', 'development (3.14)', 'secrets'])]
    if target['channel'] == 'ai':
        workflows.append(('box-ai-voice.yml', ['AI voice browser']))
    evidence = []
    for workflow, required_jobs in workflows:
        path = '/actions/workflows/' + workflow + '/runs?' + urllib.parse.urlencode(
            {'head_sha': commit, 'per_page': 100})
        for attempt in range(31):
            runs = api.get(path)['workflow_runs']
            eligible = [item for item in runs if item.get('head_sha') == commit
                        and item.get('head_branch') == target['branch']
                        and item.get('event') in ('push', 'workflow_dispatch')]
            latest = max(eligible, key=lambda item: (item['id'], item.get('run_attempt', 1))) if eligible else None
            # GitHub may expose the release before its branch workflow run.
            # Absence is pending until the same bounded polling budget expires.
            if (latest and latest.get('status') == 'completed') or attempt == 30:
                break
            time.sleep(10)
        selected = select_ci_run(runs, commit, target['branch'])
        jobs = api.get('/actions/runs/' + str(selected['id']) + '/jobs?per_page=100')['jobs']
        for name in required_jobs:
            matches = [job for job in jobs if job.get('name') == name]
            require(len(matches) == 1 and matches[0].get('conclusion') == 'success',
                    'Required CI job has not succeeded: ' + name)
        evidence.append({'workflow': workflow, 'runId': selected['id'],
                         'attempt': selected.get('run_attempt', 1),
                         'url': selected['html_url'], 'jobs': required_jobs})
    return evidence


def validate_request(project, request):
    """Validate the request contract without configuration or external I/O."""
    require(set(request) <= {'token', 'release_id', 'tag', 'dry_run', 'preview_ref', 'expected_commit'}, 'Unknown request fields')
    dry_run = request.get('dry_run', False)
    require(type(dry_run) is bool, 'dry_run must be a boolean')
    tag = request.get('tag')
    target = route(project, tag)
    preview_ref = request.get('preview_ref', '')
    require(preview_ref == '' or (dry_run and preview_ref == target['branch']),
            'A branch preview is allowed only in preview mode on its channel branch')
    release_id = request.get('release_id', 0)
    require(type(release_id) is int and release_id >= 0, 'Invalid release ID')
    expected_commit = request.get('expected_commit')
    if expected_commit is not None:
        require(isinstance(expected_commit, str) and re.fullmatch(r'[0-9a-f]{40}', expected_commit),
                'Invalid expected commit identity')
    if project == 'whatsapp' and not dry_run:
        require(expected_commit is not None, 'WhatsApp activation requires an expected commit')
    if not dry_run:
        require(release_id > 0, 'Activation requires a published GitHub Release')
    return target


def verify_request(api, project, request):
    target = validate_request(project, request)
    dry_run = request.get('dry_run', False)
    tag = request.get('tag')
    preview_ref = request.get('preview_ref', '')
    release_id = request.get('release_id', 0)
    expected_commit = request.get('expected_commit')
    if release_id:
        release = api.get('/releases/' + str(release_id))
        require(type(release.get('id')) is int and release['id'] == release_id, 'Release ID differs')
        require(not release.get('draft') and bool(release.get('published_at')),
                'Release must be published')
        require(release.get('tag_name') == tag, 'Release and tag do not match')
        require(bool(release.get('prerelease')) == (target['channel'] in ('ai', 'beta')),
                'Beta and AI must be prereleases; Stable and WhatsApp must be ordinary releases')
    reference = preview_ref or tag
    encoded = urllib.parse.quote(reference, safe='')
    commit = api.get('/commits/' + encoded)['sha']
    require(re.fullmatch(r'[0-9a-f]{40}', commit) is not None, 'Invalid commit identity')
    if expected_commit is not None:
        require(commit == expected_commit, 'Release tag differs from the selected commit')
    comparison = api.get('/compare/' + commit + '...' + urllib.parse.quote(target['branch'], safe=''))
    require(comparison.get('status') in ('ahead', 'identical'),
            'Release commit is not contained in its approved channel branch')
    target.update({'tag': tag, 'sourceReference': reference, 'commit': commit, 'githubReleaseId': release_id,
                   'repository': REPOSITORIES[project], 'dryRun': dry_run})
    target['ci'] = verify_ci(api, project, commit, target)
    return target


def checkout(api, commit, destination):
    destination = Path(destination)
    auth = base64.b64encode(('x-access-token:' + api.token).encode()).decode()
    # Credential remains only in the child's environment, never command arguments,
    # Git configuration, remote URL, evidence, or exception output.
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
           'HOME': str(STATE), 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_COUNT': '2',
           'GIT_CONFIG_KEY_0': 'http.https://github.com/.extraheader',
           'GIT_CONFIG_VALUE_0': 'AUTHORIZATION: basic ' + auth,
           'GIT_CONFIG_KEY_1': 'core.hooksPath', 'GIT_CONFIG_VALUE_1': '/dev/null'}
    run(['git', 'init', '-q', str(destination)], env=env)
    run(['git', '-C', destination, 'remote', 'add', 'origin',
         'https://github.com/' + api.repository + '.git'], env=env)
    run(['git', '-C', destination, 'fetch', '-q', '--depth=1', 'origin', commit], env=env)
    # Reject links/submodules before checkout, including outside the app subtree.
    tree = run(['git', '-C', destination, 'ls-tree', '-r', 'FETCH_HEAD'], env=env)
    require(all(line.startswith(('100644 ', '100755 ')) for line in tree.splitlines()),
            'Release sources may not contain symlinks or submodules')
    run(['git', '-C', destination, 'checkout', '-q', '--detach', 'FETCH_HEAD'], env=env)
    require(run(['git', '-C', destination, 'rev-parse', 'HEAD']) == commit, 'Checkout identity mismatch')
    require(not run(['git', '-C', destination, 'status', '--porcelain']), 'Checkout must be clean')


def main(project, handler, *, preflight=None):
    import signal
    import release_admin as administration
    os.umask(0o077)
    def interrupted(signum, frame):
        raise ReleaseError('Publication was interrupted; inspect its recovery record')
    for name in ('SIGTERM', 'SIGHUP', 'SIGALRM'):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), interrupted)
    signal.alarm(1500)
    try:
        require(os.geteuid() == 0, 'Receiver must be installed by the server administrator')
        require(project == 'whatsapp', 'This receiver manages only WhatsApp')
        generation = administration.require_current(__file__)
        raw = sys.stdin.buffer.readline(16385)
        require(0 < len(raw) <= 16384, 'Release request is too large or empty')
        try:
            request = json.loads(raw)
        except (ValueError, UnicodeError):
            raise ReleaseError('Invalid release request') from None
        require(isinstance(request, dict), 'Release request must be an object')
        validate_request(project, request)
        # A receiver-owned, read-only gate runs only after administrative
        # admission and request validation, before configuration or network I/O.
        if preflight is not None:
            preflight()
        config = json.loads(Path(installation_path('/etc/develative-deploy'), project + '.json').read_text())
        require(config.get('enabled') is True or request.get('dry_run') is True,
                'Release activation is disabled on the server')
        api = GitHub(request.get('token'), REPOSITORIES[project])
        target = verify_request(api, project, request)
        with administration.publication_lock(__file__, expected=generation):
            # Preparation may race a cooperative maintenance operation until
            # this lease is acquired. Recheck before creating work or checkout.
            if preflight is not None:
                preflight()
            work = administration.STATE / 'work'
            work.mkdir(exist_ok=True, mode=0o700)
            administration.trusted_path(work, directory=True)
            with tempfile.TemporaryDirectory(prefix=project + '-', dir=work) as temporary:
                source = Path(temporary) / 'source'
                checkout(api, target['commit'], source)
                # Re-resolve the tag after fetching; moving it invalidates the request.
                require(api.get('/commits/' + urllib.parse.quote(target['sourceReference'], safe=''))['sha']
                        == target['commit'], 'Source reference moved during release verification')
                confirmed = verify_request(api, project, request)
                require(confirmed['commit'] == target['commit'], 'Release identity changed during preparation')
                target = confirmed
                result = handler(source, target, config)
                evidence = {**target, **result, 'checkedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
                record = str(time.time_ns()) + '-' + target['commit'][:12] + '.json'
                save(STATE / project / 'receipts' / record, evidence)
                print(json.dumps(evidence), flush=True)
    except BlockingIOError:
        print(json.dumps({'status': 'blocked', 'reason': 'Another publication is in progress; rerun after it finishes'}))
        raise SystemExit(1)
    except (ReleaseError, administration.AdminError) as error:
        print(json.dumps({'status': 'blocked', 'reason': str(error)}))
        raise SystemExit(1)
    except Exception as error:
        # Do not expose local state, credentials, HTTP response bodies or subprocess output.
        print(json.dumps({'status': 'failed', 'reason': 'Server verification failed', 'errorType': type(error).__name__}))
        raise SystemExit(1)
