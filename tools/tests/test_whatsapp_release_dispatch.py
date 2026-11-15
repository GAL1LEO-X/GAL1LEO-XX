"""Manual client contract, using synthetic API and SSH; no server access."""
import importlib.util
import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('wa_dispatch', ROOT/'tools/whatsapp_release_dispatch.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
TAG = 'whatsapp/v0.5.0'
SHA = 'a'*40
TOKEN = 'synthetic-token'


def api(path, token):
    assert token == TOKEN
    if path.startswith('/releases/tags/'):
        return {'id': 42, 'tag_name': TAG, 'draft': False, 'prerelease': False,
                'published_at': '2026-10-19T12:00:00Z', 'target_commitish': 'main'}
    if path.startswith('/commits/'):
        return {'sha': SHA}
    assert path == '/compare/'+SHA+'...main'
    return {'status': 'ahead'}


@pytest.mark.parametrize('mode', ['preview', 'activate'])
def test_resolves_published_id_and_tag_sha_independent_of_target_commitish(mode):
    request = client.resolve_request(TAG, mode, TAG if mode == 'activate' else '', TOKEN, api)
    assert request == {'token': TOKEN, 'tag': TAG, 'release_id': 42, 'expected_commit': SHA,
                       'dry_run': mode == 'preview', 'preview_ref': ''}


@pytest.mark.parametrize('mode,confirmation', [('activate', ''), ('activate', 'wrong'), ('', ''), ('true', TAG)])
def test_invalid_intent_does_not_access_network(mode, confirmation):
    with pytest.raises(ValueError), patch.object(client, 'github_get') as get:
        client.resolve_request(TAG, mode, confirmation, TOKEN, get)
    get.assert_not_called()


@pytest.mark.parametrize('change', [{'draft': True}, {'prerelease': True}, {'published_at': None},
                                   {'id': 0}, {'id': True}, {'tag_name': 'whatsapp/v9.0.0'}])
def test_rejects_nonpublished_or_mismatched_release(change):
    def get(path, token):
        result = api(path, token)
        return {**result, **change} if path.startswith('/releases/') else result
    with pytest.raises(ValueError):
        client.resolve_request(TAG, 'activate', TAG, TOKEN, get)


def test_missing_release_never_falls_back_to_tag_only():
    def get(path, token):
        raise OSError('synthetic missing release')
    with pytest.raises(OSError):
        client.resolve_request(TAG, 'preview', '', TOKEN, get)


@pytest.mark.parametrize('payload', [{'sha': 'main'}, {'status': 'behind'}])
def test_rejects_invalid_commit_or_non_main_ancestry(payload):
    def get(path, token):
        return {**api(path, token), **payload} if not path.startswith('/releases/') else api(path, token)
    with pytest.raises(ValueError):
        client.resolve_request(TAG, 'preview', '', TOKEN, get)


@pytest.mark.parametrize('mode,status,activated', [('preview', 'verified', False),
    ('activate', 'published', True), ('activate', 'already-active', False)])
def test_ssh_payload_and_receipt_preserve_protocol_and_secrets(tmp_path, capsys, mode, status, activated):
    request = client.resolve_request(TAG, mode, TAG, TOKEN, api)
    env = {'DEPLOY_HOST': 'synthetic.invalid', 'DEPLOY_USER': 'wa-deploy',
           'DEPLOY_KEY': 'synthetic-private-key', 'DEPLOY_KNOWN_HOSTS': 'synthetic-host-key',
           'RUNNER_TEMP': str(tmp_path), 'GITHUB_STEP_SUMMARY': str(tmp_path/'summary')}
    receipt = {'githubReleaseId': 42, 'tag': TAG, 'commit': SHA, 'dryRun': mode == 'preview',
               'status': status, 'activationPerformed': activated}
    def ssh(command, **kwargs):
        assert command[-1] == 'release-v1'
        assert json.loads(kwargs['input']) == request
        assert TOKEN not in ' '.join(command)
        assert Path(command[command.index('-i')+1]).stat().st_mode & 0o777 == 0o600
        return subprocess.CompletedProcess(command, 0, json.dumps(receipt), 'private stderr')
    with patch.object(client.subprocess, 'run', side_effect=ssh):
        assert client.dispatch(request, env) == 0
    assert not list(tmp_path.glob('develative-*'))
    output = capsys.readouterr().out + (tmp_path/'summary').read_text()
    assert TOKEN not in output and 'private stderr' not in output


def test_mismatched_success_receipt_reports_uncertain_outcome(tmp_path):
    request = client.resolve_request(TAG, 'activate', TAG, TOKEN, api)
    env = {'DEPLOY_HOST': 'synthetic.invalid', 'DEPLOY_USER': 'wa-deploy',
           'DEPLOY_KEY': 'synthetic', 'DEPLOY_KNOWN_HOSTS': 'synthetic', 'RUNNER_TEMP': str(tmp_path)}
    with patch.object(client.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{}', '')):
        with pytest.raises(ValueError, match='outcome uncertain'):
            client.dispatch(request, env)


def test_public_ci_does_not_install_the_private_deployment_receiver():
    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    assert not (ROOT / '.github/workflows/develative-release.yml').exists()
    assert 'pull_request:' in workflow and 'branches: [main]' in workflow
    assert 'workflow_dispatch:' not in workflow
    for executable in ('whatsapp_release_dispatch.py', 'release_recover.py',
                       'ssh ', 'scp ', 'DEPLOY_HOST', 'DEPLOY_KEY'):
        assert executable not in workflow
