"""Read-only GitHub provenance gates for the manual WhatsApp release workflow."""
import re

from whatsapp_release_common import ReleaseError, REPOSITORY, WORKFLOW_PATH, validate_sha

REQUIRED_JOBS = frozenset({'development (3.13)', 'development (3.14)', 'secrets',
    'tenant-uid-isolation', 'deploy-client-checks', 'PLUGINS required checks', 'deploy-package'})


def require(condition, message):
    if not condition:
        raise ReleaseError(message)


def positive(value):
    require(isinstance(value, (int, str)) and not isinstance(value, bool)
            and re.fullmatch(r'[1-9][0-9]{0,19}', str(value)), 'A positive bounded identifier is required')
    return int(value)


def check_context(env):
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('GITHUB_REPOSITORY') == REPOSITORY and env.get('GITHUB_REF') == 'refs/heads/main',
            'Only a manual dispatch from this repository main is accepted')
    sha = validate_sha(env.get('GITHUB_SHA'), 40)
    require(env.get('GITHUB_WORKFLOW_SHA') == sha and env.get('GITHUB_WORKFLOW_REF') ==
            f'{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main', 'Unexpected workflow source identity')
    return {'workflow_commit': sha, 'id': positive(env.get('GITHUB_RUN_ID')),
            'attempt': positive(env.get('GITHUB_RUN_ATTEMPT')), 'workflow_path': WORKFLOW_PATH}


def review_reference(value):
    require(isinstance(value, str) and len(value) <= 512 and re.fullmatch(
        r'https://github\.com/GAL1LEO-X/GAL1LEO-XX/pull/[1-9][0-9]*(?:#[A-Za-z0-9_-]+)?', value),
        'An explicit repository PR review evidence URL is required')
    return value  # Operator attestation; not an assertion of machine-verified review approval.


def _pages(github, path, key):
    items = []
    for page in range(1, 11):
        separator = '&' if '?' in path else '?'
        result = github.get(f'{path}{separator}per_page=100&page={page}')
        require(isinstance(result, dict) and isinstance(result.get(key), list), 'Malformed GitHub page')
        batch = result[key]
        require(len(batch) <= 100 and all(isinstance(x, dict) for x in batch), 'Malformed GitHub page items')
        items.extend(batch)
        if len(batch) < 100:
            return items
    raise ReleaseError('GitHub pagination exceeded the bounded verification budget')


def _workflow_tree(github, tree):
    # Compare immutable subtree identities, not the potentially truncated list
    # of changed files returned by the compare API. No recursive tree download.
    for name in ('.github', 'workflows'):
        result = github.get(f'/git/trees/{tree}')
        require(isinstance(result, dict) and result.get('sha') == tree
                and result.get('truncated') is False and isinstance(result.get('tree'), list)
                and all(isinstance(entry, dict) for entry in result['tree']),
                'Cannot establish the complete workflow tree')
        entries = [entry for entry in result['tree'] if entry.get('path') == name]
        require(len(entries) == 1 and entries[0].get('type') == 'tree'
                and entries[0].get('mode') == '040000', 'The workflow directory must be a Git tree')
        tree = validate_sha(entries[0].get('sha'), 40)
    return tree


def check_target(github, target_commit, review_evidence):
    target = validate_sha(target_commit, 40)
    review_reference(review_evidence)
    commit = github.get(f'/commits/{target}')
    require(commit.get('sha') == target, 'GitHub target commit mismatch')
    tree = validate_sha(commit.get('commit', {}).get('tree', {}).get('sha'), 40)
    repository = github.get('')
    require(repository.get('full_name') == REPOSITORY and repository.get('default_branch') == 'main',
            'The repository default branch must remain main')
    main = github.get('/commits/main')
    main_sha = validate_sha(main.get('sha'), 40)
    main_tree = validate_sha(main.get('commit', {}).get('tree', {}).get('sha'), 40)
    comparison = github.get(f'/compare/{target}...{main_sha}')
    require(comparison.get('status') in {'ahead', 'identical'}
            and comparison.get('merge_base_commit', {}).get('sha') == target,
            'Target must be an ancestor of current main')
    # GITHUB_TOKEN cannot acquire workflows:write. GitHub can require that
    # permission when creating a release for a target with different workflows.
    require(_workflow_tree(github, tree) == _workflow_tree(github, main_tree),
            'Target workflows differ from current main; this publisher cannot create that release')
    workflow = github.get('/actions/workflows/checks.yml')
    require(workflow.get('path') == '.github/workflows/checks.yml'
            and workflow.get('state') == 'active' and workflow.get('name') == 'PLUGINS checks',
            'The expected CI workflow is not active')
    workflow_id = positive(workflow.get('id'))
    runs = _pages(github, f'/actions/workflows/{workflow_id}/runs?head_sha={target}&branch=main&event=push', 'workflow_runs')
    require(runs, 'No main push CI exists for the exact target')
    # Do not filter successes: a newer failed/running attempt invalidates an older PASS.
    for run in runs:
        require(run.get('head_sha') == target and run.get('head_branch') == 'main'
                and run.get('event') == 'push' and run.get('workflow_id') == workflow_id
                and run.get('repository', {}).get('full_name') == REPOSITORY,
                'CI run provenance mismatch')
        positive(run.get('id')); positive(run.get('run_attempt'))
    run = max(runs, key=lambda item: (item['id'], item['run_attempt']))
    require(run.get('status') == 'completed' and run.get('conclusion') == 'success',
            'The latest target CI run must be completed successfully')
    jobs = _pages(github, f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", 'jobs')
    require(len(jobs) == len(REQUIRED_JOBS) and {job.get('name') for job in jobs} == REQUIRED_JOBS
            and all(job.get('status') == 'completed' and job.get('conclusion') == 'success'
                    and job.get('head_sha') == target and job.get('run_id') == run['id']
                    for job in jobs), 'All required main jobs must pass on the exact CI attempt and commit')
    return {key: run[key] for key in ('id', 'run_attempt', 'head_sha', 'status', 'conclusion')} | {'target_tree': tree}


def check_prepared(github, run_id, attempt, artifact_id, workflow_commit):
    run_id, attempt, artifact_id = map(positive, (run_id, attempt, artifact_id))
    validate_sha(workflow_commit, 40)
    run = github.get(f'/actions/runs/{run_id}')
    require(run.get('id') == run_id and run.get('run_attempt') == attempt
            and run.get('head_sha') == workflow_commit and run.get('head_branch') == 'main'
            and run.get('event') == 'workflow_dispatch' and run.get('path') == WORKFLOW_PATH
            and run.get('repository', {}).get('full_name') == REPOSITORY
            and run.get('status') == 'completed' and run.get('conclusion') == 'success',
            'Preparation must be a successful manual run of the same workflow commit and exact attempt')
    jobs = _pages(github, f'/actions/runs/{run_id}/attempts/{attempt}/jobs', 'jobs')
    require(sum(job.get('name') == 'prepare' and job.get('conclusion') == 'success'
                and job.get('status') == 'completed' and job.get('head_sha') == workflow_commit
                and job.get('run_id') == run_id for job in jobs) == 1,
            'The preparation job did not succeed in that attempt')
    artifacts = _pages(github, f'/actions/runs/{run_id}/artifacts', 'artifacts')
    matches = [item for item in artifacts if item.get('id') == artifact_id]
    require(len(matches) == 1, 'Artifact does not belong to the preparation run')
    artifact = matches[0]
    require(artifact.get('name') == f'whatsapp-candidate-{run_id}-{attempt}' and artifact.get('expired') is False
            and type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= 4 * 1024**3,
            'Artifact name, expiry or size is invalid')
    return artifact


def bind_candidate(manifest, *, context, run_id, attempt, target_commit, version, review_evidence, ci):
    require(manifest['workflow_commit'] == context['workflow_commit']
            and manifest['prepared_run'] == {'id': positive(run_id), 'attempt': positive(attempt), 'workflow_path': WORKFLOW_PATH}
            and manifest['target_commit'] == target_commit and manifest['target_tree'] == ci['target_tree']
            and manifest['version'] == version and manifest['qualification']['review_evidence'] == review_evidence
            and manifest['qualification']['ci_run_id'] == ci['id']
            and manifest['qualification']['ci_run_attempt'] == ci['run_attempt'],
            'Candidate does not match the approved inputs, preparation or latest target CI')
