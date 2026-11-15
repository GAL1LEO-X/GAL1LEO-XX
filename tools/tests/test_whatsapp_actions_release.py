"""Workflow boundary and actual ZIP-to-publisher orchestration, entirely offline."""
from argparse import Namespace
from copy import deepcopy
from pathlib import Path
import re
import shutil
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import whatsapp_actions_release as cli
from whatsapp_release_common import ReleaseError
from test_whatsapp_release_gates import context, ReadAPI, TARGET, REVIEW, divergent_workflows
from test_whatsapp_release_publish import candidate, FakeGitHub


def publication_args(candidate, tmp_path):
    directory, manifest, digest = candidate
    return Namespace(mode='publish', target=manifest['target_commit'], version=manifest['version'],
        review=manifest['qualification']['review_evidence'], repository=None, python=None,
        output=tmp_path/'received', prepared_run='101', prepared_attempt='1', artifact='300',
        manifest_sha256=digest, confirm_tag=manifest['tag'])


@pytest.fixture
def integration(candidate, tmp_path, monkeypatch):
    directory, manifest, digest = candidate
    archive = tmp_path/'fixture.zip'
    with zipfile.ZipFile(archive, 'w') as zip_file:
        for file in sorted(directory.rglob('*')):
            if file.is_file(): zip_file.write(file, file.relative_to(directory).as_posix())
    api = FakeGitHub(candidate)
    api.download_actions_artifact = lambda artifact_id, target: shutil.copyfile(archive, target)
    ci = dict(id=102, run_attempt=1, head_sha=manifest['target_commit'], target_tree=manifest['target_tree'],
              status='completed', conclusion='success')
    monkeypatch.setattr(cli, 'check_target', lambda *args: deepcopy(ci))
    monkeypatch.setattr(cli, 'check_prepared', lambda *args: {'id':300})
    env = context() | {'WHATSAPP_RELEASE_PUBLISH_ENABLED':'true'}
    return api, publication_args(candidate, tmp_path), env, archive, ci


def test_received_zip_publishes_all_verified_bytes(integration, candidate):
    api, args, env, _, _ = integration
    result = cli.execute(args, api, env)
    assert result['status'] == 'published'
    assert len(api.bytes) == 13
    assert (args.output/'candidate/candidate.json').read_bytes() == (candidate[0]/'candidate.json').read_bytes()


@pytest.mark.parametrize('change', ['disabled','confirmation','digest','attempt','target','version','review'])
def test_boundary_failure_never_mutates_github(integration, change):
    api, args, env, _, _ = integration
    if change == 'disabled': env['WHATSAPP_RELEASE_PUBLISH_ENABLED']='false'
    if change == 'confirmation': args.confirm_tag='whatsapp/v1.2.3'
    if change == 'digest': args.manifest_sha256='f'*64
    if change == 'attempt': args.prepared_attempt='2'
    if change == 'target': args.target='e'*40
    if change == 'version': args.version='0.9.9'; args.confirm_tag='whatsapp/v0.9.9'
    if change == 'review': args.review='https://github.com/GAL1LEO-X/GAL1LEO-XX/pull/99'
    with pytest.raises(ReleaseError): cli.execute(args, api, env)
    assert not api.mutations


def test_tampered_artifact_is_rejected_before_publisher(integration):
    api, args, env, archive, _ = integration
    with zipfile.ZipFile(archive, 'a') as zip_file:
        zip_file.writestr('../escape', b'invalid')
    with pytest.raises(ReleaseError): cli.execute(args, api, env)
    assert not api.mutations


def test_ci_change_during_download_prevents_publication(integration, monkeypatch):
    api, args, env, _, ci = integration
    calls = iter([ci, dict(ci, run_attempt=2)])
    monkeypatch.setattr(cli,'check_target',lambda *args: next(calls))
    with pytest.raises(ReleaseError,match='changed'): cli.execute(args,api,env)
    assert not api.mutations


@pytest.mark.parametrize('mode', ['prepare', 'publish'])
def test_workflow_divergence_blocks_real_entrypoint_before_download_or_writes(tmp_path, mode):
    api = ReadAPI(); divergent_workflows(api)
    args = Namespace(mode=mode, target=TARGET, version='0.8.0', review=REVIEW, output=tmp_path/'received')
    # This API exposes only reads: downloads or mutations would fail the test.
    with pytest.raises(ReleaseError, match='Target workflows differ'):
        cli.execute(args, api, context() | {'WHATSAPP_RELEASE_PUBLISH_ENABLED': 'true'})
    assert not args.output.exists()


def test_workflow_only_manual_and_write_job_is_explicitly_gated():
    root = Path(__file__).resolve().parents[2]
    workflow = (root/'.github/workflows/whatsapp-release.yml').read_text()
    # Structural policy assertions; syntax is checked separately with actionlint.
    triggers = workflow.split('\non:\n',1)[1].split('\npermissions:',1)[0]
    assert re.findall(r'^  ([a-z_]+):',triggers,re.M) == ['workflow_dispatch']
    assert len(re.findall(r'^      [a-z_]+:',triggers,re.M)) <= 10
    assert '\npermissions: {}\n' in workflow
    assert '\n  cancel-in-progress: false\n' in workflow
    prepare, publish = workflow.split('\njobs:\n  prepare:\n',1)[1].split('\n  publish:\n')
    assert 'contents: read' in prepare and 'contents: write' not in prepare
    assert 'contents: write' in publish and 'actions: read' in publish
    assert "vars.WHATSAPP_RELEASE_PUBLISH_ENABLED == 'true'" in publish.split('steps:',1)[0]
    for job in (prepare,publish):
        assert "github.ref == 'refs/heads/main'" in job.split('steps:',1)[0]
        assert 'runs-on: ubuntu-24.04' in job
        uses = re.findall(r'^      - uses: ([^\n#]+)',job,re.M)
        assert all(re.fullmatch(r'actions/[a-z-]+@[0-9a-f]{40}',use.strip()) for use in uses)
        assert job.count('persist-credentials: false') == job.count('uses: actions/checkout@')
        # Dispatch strings only enter quoted environment variables, never shell source.
        for shell in re.findall(r'        run: (.*?)(?=\n      - |\Z)',job,re.S):
            assert '${{ inputs.' not in shell
    assert 'bootstrap.sh' not in publish and 'pip install' not in publish and 'docker' not in publish
    assert 'ssh' not in publish and 'develative' not in publish
