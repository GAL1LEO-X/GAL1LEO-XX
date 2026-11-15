"""Actions-only manual WhatsApp update client; never publishes a GitHub Release."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request

REPOSITORY = 'GAL1LEO-X/GAL1LEO-XX'


class DispatchError(ValueError):
    """Client-owned error text safe for Actions output."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def github_get(path, token):
    request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + path,
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'whatsapp-manual-update'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        return json.load(response)


def resolve_request(tag, mode, confirmation, token, get=github_get):
    if not isinstance(tag, str) or not re.fullmatch(r'whatsapp/v\d+\.\d+\.\d+', tag):
        raise DispatchError('Select an ordinary whatsapp/vX.Y.Z Release')
    if mode not in ('preview', 'activate'):
        raise DispatchError('Select preview or activate explicitly')
    if mode == 'activate' and confirmation != tag:
        raise DispatchError('Activation requires confirmation equal to the Release tag')
    release = get('/releases/tags/' + urllib.parse.quote(tag, safe=''), token)
    release_id = release.get('id')
    if (type(release_id) is not int or release_id <= 0 or release.get('tag_name') != tag
            or release.get('draft') is not False or release.get('prerelease') is not False
            or not release.get('published_at')):
        raise DispatchError('Select a published ordinary Release with matching tag and ID')
    # Resolve the tag itself: target_commitish may be a moving branch name.
    commit = get('/commits/' + urllib.parse.quote(tag, safe=''), token).get('sha')
    if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise DispatchError('Invalid Release commit')
    comparison = get('/compare/' + commit + '...main', token)
    if comparison.get('status') not in ('ahead', 'identical'):
        raise DispatchError('Release commit must belong to main')
    return {'token': token, 'tag': tag, 'release_id': release_id, 'expected_commit': commit,
            'dry_run': mode == 'preview', 'preview_ref': ''}


def dispatch(request, env):
    host, user = env['DEPLOY_HOST'], env['DEPLOY_USER']
    if not re.fullmatch(r'[a-zA-Z0-9.-]+', host) or not re.fullmatch(r'[a-z][a-z0-9-]*', user):
        raise DispatchError('Configure DEVELATIVE_HOST and DEVELATIVE_USER first')
    if not env['DEPLOY_KEY'] or not env['DEPLOY_KNOWN_HOSTS']:
        raise DispatchError('Dedicated deployment key and pinned host key are required')
    with tempfile.TemporaryDirectory(prefix='develative-', dir=env['RUNNER_TEMP']) as directory:
        key, known = Path(directory)/'key', Path(directory)/'known_hosts'
        key.write_text(env['DEPLOY_KEY'].rstrip()+'\n')
        known.write_text(env['DEPLOY_KNOWN_HOSTS'].rstrip()+'\n')
        key.chmod(0o600)
        command = ['ssh', '-T', '-i', str(key), '-o', 'BatchMode=yes',
                   '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'UserKnownHostsFile='+str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
                   '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
                   '-o', 'ForwardAgent=no', '-o', 'ConnectTimeout=15',
                   '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3',
                   user+'@'+host, 'release-v1']
        result = subprocess.run(command, input=json.dumps(request)+'\n', text=True,
                                capture_output=True, timeout=1600)
    # Only the server-owned sanitized receipt is emitted, never raw SSH stderr.
    # On transport failure activation may already have occurred: inspect journal.
    try:
        receipt = json.loads(result.stdout)
    except ValueError:
        raise DispatchError('No valid server receipt; outcome uncertain, inspect server journal before retry') from None
    valid_status = ('verified',) if request['dry_run'] else ('published', 'already-active')
    if result.returncode == 0 and (receipt.get('githubReleaseId') != request['release_id']
            or receipt.get('tag') != request['tag'] or receipt.get('commit') != request['expected_commit']
            or receipt.get('dryRun') is not request['dry_run']
            or receipt.get('status') not in valid_status
            or receipt.get('activationPerformed') is not (receipt.get('status') == 'published')):
        raise DispatchError('Server receipt differs; outcome uncertain, inspect server journal before retry')
    evidence = {key: value for key, value in request.items() if key != 'token'}
    with open(env['GITHUB_STEP_SUMMARY'], 'a') as summary:
        summary.write('WhatsApp manual update (preview writes preparatory server state)\n\n')
        summary.write(json.dumps(evidence)+'\n\n'+result.stdout[:32000])
    print(result.stdout)
    return result.returncode


def main():
    os.umask(0o077)
    try:
        request = resolve_request(os.environ['RELEASE_TAG'], os.environ['UPDATE_MODE'],
                                  os.environ['UPDATE_CONFIRMATION'], os.environ['GH_READ_TOKEN'])
        return dispatch(request, os.environ)
    except DispatchError as error:
        print(str(error))
        return 1
    except Exception as error:
        # Do not log API responses, credentials, subprocess errors or exception text.
        print('Manual update failed (' + type(error).__name__ + '). '
              'If SSH started, inspect server receipts/journals before retry; outcome may be uncertain.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
