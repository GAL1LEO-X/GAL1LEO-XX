"""Negative provenance cases: old PASS, wrong attempts, fork runs and artifacts."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import whatsapp_release_gates as gates
from whatsapp_release_common import ReleaseError

TARGET = 'a' * 40
WORKFLOW = 'b' * 40
TREE = 'c' * 40
MAIN = 'd' * 40
MAIN_TREE = 'e' * 40
GITHUB_TREE = 'f' * 40
WORKFLOWS_TREE = '1' * 40
REVIEW = 'https://github.com/GAL1LEO-X/GAL1LEO-XX/pull/65#issuecomment-123'


def context():
    return dict(GITHUB_ACTIONS='true', GITHUB_EVENT_NAME='workflow_dispatch',
        GITHUB_REPOSITORY=gates.REPOSITORY, GITHUB_REF='refs/heads/main', GITHUB_SHA=WORKFLOW,
        GITHUB_WORKFLOW_SHA=WORKFLOW,
        GITHUB_WORKFLOW_REF=f'{gates.REPOSITORY}/{gates.WORKFLOW_PATH}@refs/heads/main',
        GITHUB_RUN_ID='40', GITHUB_RUN_ATTEMPT='1')


class ReadAPI:
    def __init__(self):
        self.calls = []
        self.run = dict(id=10, run_attempt=2, workflow_id=5, head_sha=TARGET,
            head_branch='main', event='push', repository={'full_name': gates.REPOSITORY},
            status='completed', conclusion='success')
        # Actual main checks.yml inventory after deploy-v1 adoption. Keep this
        # independent of the gate constant so policy/workflow drift is visible.
        self.jobs = [dict(name=name, run_id=10, head_sha=TARGET, status='completed', conclusion='success')
                     for name in ('development (3.13)', 'development (3.14)', 'secrets',
                                  'tenant-uid-isolation', 'deploy-client-checks',
                                  'PLUGINS required checks', 'deploy-package')]
        self.prepared = dict(id=20, run_attempt=1, head_sha=WORKFLOW, head_branch='main',
            event='workflow_dispatch', path=gates.WORKFLOW_PATH,
            repository={'full_name': gates.REPOSITORY}, status='completed', conclusion='success')
        self.artifact = dict(id=30, name='whatsapp-candidate-20-1', expired=False, size_in_bytes=512)
        self.data = {
            '': {'full_name': gates.REPOSITORY, 'default_branch': 'main'},
            '/commits/main': {'sha': MAIN, 'commit': {'tree': {'sha': MAIN_TREE}}},
            f'/commits/{TARGET}': {'sha': TARGET, 'commit': {'tree': {'sha': TREE}}},
            f'/compare/{TARGET}...{MAIN}': {'status': 'ahead', 'merge_base_commit': {'sha': TARGET}},
            **{f'/git/trees/{root}': {'sha': root, 'truncated': False, 'tree': [
                {'path': '.github', 'mode': '040000', 'type': 'tree', 'sha': GITHUB_TREE}]}
                for root in (TREE, MAIN_TREE)},
            f'/git/trees/{GITHUB_TREE}': {'sha': GITHUB_TREE, 'truncated': False, 'tree': [
                {'path': 'workflows', 'mode': '040000', 'type': 'tree', 'sha': WORKFLOWS_TREE}]},
            '/actions/workflows/checks.yml': {'id': 5, 'path': '.github/workflows/checks.yml',
                'state': 'active', 'name': 'PLUGINS checks'},
            f'/actions/workflows/5/runs?head_sha={TARGET}&branch=main&event=push&per_page=100&page=1': {'workflow_runs': [self.run]},
            '/actions/runs/10/attempts/2/jobs?per_page=100&page=1': {'jobs': self.jobs},
            '/actions/runs/20': self.prepared,
            '/actions/runs/20/attempts/1/jobs?per_page=100&page=1': {'jobs': [dict(name='prepare',
                run_id=20, head_sha=WORKFLOW, status='completed', conclusion='success')]},
            '/actions/runs/20/artifacts?per_page=100&page=1': {'artifacts': [self.artifact]},
        }

    def get(self, path):
        self.calls.append(path)
        return deepcopy(self.data[path])


def test_valid_provenance():
    api = ReadAPI()
    result = gates.check_target(api, TARGET, REVIEW)
    assert result == dict(id=10, run_attempt=2, head_sha=TARGET, status='completed', conclusion='success', target_tree=TREE)
    assert gates.check_prepared(api, 20, 1, 30, WORKFLOW)['id'] == 30


@pytest.mark.parametrize('key,value', [('GITHUB_ACTIONS','false'), ('GITHUB_EVENT_NAME','pull_request'),
    ('GITHUB_REPOSITORY','fork/PLUGINS'), ('GITHUB_REF','refs/heads/task/test'),
    ('GITHUB_SHA','main'), ('GITHUB_WORKFLOW_SHA','d'*40), ('GITHUB_RUN_ID','0'),
    ('GITHUB_RUN_ATTEMPT','-1'), ('GITHUB_WORKFLOW_REF','wrong')])
def test_context_rejects_untrusted_source(key, value):
    env = context(); env[key] = value
    with pytest.raises(ReleaseError): gates.check_context(env)


@pytest.mark.parametrize('field,value', [('head_sha','e'*40), ('head_branch','task/test'),
    ('event','pull_request'), ('workflow_id',6), ('repository', {'full_name':'fork/PLUGINS'}),
    ('status','in_progress'), ('conclusion','failure'), ('run_attempt',True)])
def test_ci_wrong_provenance_or_result(field, value):
    api = ReadAPI(); api.run[field] = value
    with pytest.raises(ReleaseError): gates.check_target(api, TARGET, REVIEW)


def test_new_failure_is_not_hidden_by_old_success():
    api = ReadAPI()
    runs = next(value['workflow_runs'] for value in api.data.values() if 'workflow_runs' in value)
    runs.append(dict(api.run, id=11, conclusion='failure'))
    with pytest.raises(ReleaseError, match='latest'): gates.check_target(api, TARGET, REVIEW)


@pytest.mark.parametrize('change', ['missing','duplicate','failed','wrong_commit','wrong_run'])
def test_exact_required_jobs(change):
    api = ReadAPI()
    if change == 'missing': api.jobs.pop()
    if change == 'duplicate': api.jobs[1] = deepcopy(api.jobs[0])
    if change == 'failed': api.jobs[0]['conclusion'] = 'cancelled'
    if change == 'wrong_commit': api.jobs[0]['head_sha'] = 'f'*40
    if change == 'wrong_run': api.jobs[0]['run_id'] = 12
    with pytest.raises(ReleaseError): gates.check_target(api, TARGET, REVIEW)


@pytest.mark.parametrize('name', ['development (3.13)', 'development (3.14)', 'secrets',
    'tenant-uid-isolation', 'deploy-client-checks', 'PLUGINS required checks', 'deploy-package'])
@pytest.mark.parametrize('change', ['missing', 'skipped', 'failure', 'in_progress'])
def test_every_current_main_job_must_succeed(name, change):
    api = ReadAPI()
    job = next(job for job in api.jobs if job['name'] == name)
    if change == 'missing': api.jobs.remove(job)
    elif change == 'in_progress': job.update(status='in_progress', conclusion=None)
    else: job['conclusion'] = change
    with pytest.raises(ReleaseError): gates.check_target(api, TARGET, REVIEW)


def test_unknown_job_requires_explicit_policy_review():
    api = ReadAPI(); api.jobs.append(dict(api.jobs[0], name='unreviewed-job'))
    with pytest.raises(ReleaseError): gates.check_target(api, TARGET, REVIEW)


@pytest.mark.parametrize('status,base', [('behind',TARGET), ('diverged',TARGET), ('ahead','f'*40)])
def test_target_must_belong_to_main(status, base):
    api = ReadAPI(); api.data[f'/compare/{TARGET}...{MAIN}'] = {'status': status, 'merge_base_commit': {'sha': base}}
    with pytest.raises(ReleaseError): gates.check_target(api, TARGET, REVIEW)


def divergent_workflows(api):
    new_github = '2' * 40
    api.data[f'/git/trees/{MAIN_TREE}']['tree'][0]['sha'] = new_github
    api.data[f'/git/trees/{new_github}'] = {'sha': new_github, 'truncated': False, 'tree': [
        {'path': 'workflows', 'mode': '040000', 'type': 'tree', 'sha': '3' * 40}]}


def test_historical_target_with_different_workflows_is_rejected_before_ci():
    api = ReadAPI(); divergent_workflows(api)
    with pytest.raises(ReleaseError, match='Target workflows differ'):
        gates.check_target(api, TARGET, REVIEW)
    assert not any(path.startswith('/actions/') for path in api.calls)


def test_current_main_target_is_admitted():
    api = ReadAPI()
    api.data['/commits/main'] = deepcopy(api.data[f'/commits/{TARGET}'])
    api.data[f'/compare/{TARGET}...{TARGET}'] = {'status': 'identical', 'merge_base_commit': {'sha': TARGET}}
    assert gates.check_target(api, TARGET, REVIEW)['head_sha'] == TARGET


def test_historical_target_with_unchanged_workflows_is_admitted():
    api = ReadAPI()
    # Other .github files may change without needing workflow write permission.
    new_github = '2' * 40
    api.data[f'/git/trees/{MAIN_TREE}']['tree'][0]['sha'] = new_github
    api.data[f'/git/trees/{new_github}'] = {'sha': new_github, 'truncated': False, 'tree': [
        {'path': 'workflows', 'mode': '040000', 'type': 'tree', 'sha': WORKFLOWS_TREE},
        {'path': 'CODEOWNERS', 'mode': '100644', 'type': 'blob', 'sha': '3' * 40}]}
    assert gates.check_target(api, TARGET, REVIEW)['head_sha'] == TARGET


@pytest.mark.parametrize('change', ['truncated', 'wrong_sha', 'missing', 'duplicate', 'symlink', 'non_dict'])
def test_incomplete_or_ambiguous_workflow_tree_is_rejected(change):
    api = ReadAPI(); tree = api.data[f'/git/trees/{GITHUB_TREE}']
    if change == 'truncated': tree['truncated'] = True
    if change == 'wrong_sha': tree['sha'] = MAIN
    if change == 'missing': tree['tree'].clear()
    if change == 'duplicate': tree['tree'].append(deepcopy(tree['tree'][0]))
    if change == 'symlink': tree['tree'][0].update(type='blob', mode='120000')
    if change == 'non_dict': tree['tree'] = [None]
    with pytest.raises(ReleaseError): gates.check_target(api, TARGET, REVIEW)


def test_changed_default_branch_requires_explicit_publisher_adaptation():
    api = ReadAPI(); api.data['']['default_branch'] = 'production'
    with pytest.raises(ReleaseError, match='default branch'):
        gates.check_target(api, TARGET, REVIEW)


@pytest.mark.parametrize('field,value', [('run_attempt',2), ('head_sha','e'*40), ('head_branch','fork'),
    ('event','pull_request'), ('path','.github/workflows/other.yml'), ('status','in_progress'),
    ('conclusion','failure'), ('repository',{'full_name':'fork/PLUGINS'})])
def test_wrong_preparation_run(field, value):
    api = ReadAPI(); api.prepared[field] = value
    with pytest.raises(ReleaseError): gates.check_prepared(api, 20, 1, 30, WORKFLOW)


@pytest.mark.parametrize('field,value', [('id',31), ('name','whatsapp-candidate-20-2'), ('expired',True),
    ('size_in_bytes',0), ('size_in_bytes',4*1024**3+1)])
def test_wrong_artifact(field, value):
    api = ReadAPI(); api.artifact[field] = value
    with pytest.raises(ReleaseError): gates.check_prepared(api, 20, 1, 30, WORKFLOW)


@pytest.mark.parametrize('value', ['https://github.com/fork/PLUGINS/pull/1',
    'https://github.com/GAL1LEO-X/GAL1LEO-XX/pull/1?token=x', 'https://user@github.com/GAL1LEO-X/GAL1LEO-XX/pull/1',
    'javascript:alert(1)', 'https://github.com/GAL1LEO-X/GAL1LEO-XX/pull/0'])
def test_review_reference_only_accepts_repository_pr(value):
    with pytest.raises(ReleaseError): gates.review_reference(value)
