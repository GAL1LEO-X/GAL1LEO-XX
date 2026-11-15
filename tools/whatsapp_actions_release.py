#!/usr/bin/env python3
"""Manual GitHub Actions entrypoint. No credentials are loaded outside main()."""
import argparse
import json
import os
from pathlib import Path
import sys

from whatsapp_release_common import (ReleaseError, canonical_json, receive_artifact,
    sha256_file, validate_sha, validate_version)
from whatsapp_release_gates import (bind_candidate, check_context, check_prepared,
    check_target, positive, require, review_reference)
from whatsapp_release_github import GitHubClient


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['gate', 'prepare', 'publish'])
    parser.add_argument('--target', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--review', required=True)
    parser.add_argument('--repository', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--python', type=Path)
    parser.add_argument('--prepared-run')
    parser.add_argument('--prepared-attempt')
    parser.add_argument('--artifact')
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--confirm-tag')
    return parser.parse_args(argv)


def execute(args, github, env):
    context = check_context(env)
    target = validate_sha(args.target, 40)
    version = validate_version(args.version)
    review = review_reference(args.review)
    # All reads, including CI, precede download or mutation.
    ci = check_target(github, target, review)
    if args.mode == 'gate':
        return {'status': 'gated', 'target_commit': target, 'ci': ci}
    if args.mode == 'prepare':
        from whatsapp_release_prepare import prepare_candidate
        require(args.repository is not None and args.python is not None,
                'Preparation requires an explicit source checkout and isolated test Python')
        require(args.python.is_file(), 'Isolated test Python does not exist')
        manifest = prepare_candidate(args.repository, target, context['workflow_commit'], version,
            args.output, github, ci, review,
            {key: context[key] for key in ('id', 'attempt', 'workflow_path')},
            python_executable=str(args.python.absolute()))
        digest = sha256_file(args.output / 'candidate.json')[1]
        return {'status': 'prepared', 'target_commit': target, 'tag': manifest['tag'],
                'manifest_sha256': digest, 'assets': len(manifest['assets']),
                'prepared_run': manifest['prepared_run']}
    require(env.get('WHATSAPP_RELEASE_PUBLISH_ENABLED') == 'true',
            'Publisher activation has not been explicitly enabled')
    require(args.confirm_tag == 'whatsapp/v' + version, 'Explicit exact tag confirmation is required')
    digest = validate_sha(args.manifest_sha256)
    run_id, attempt, artifact_id = map(positive, (args.prepared_run, args.prepared_attempt, args.artifact))
    check_prepared(github, run_id, attempt, artifact_id, context['workflow_commit'])
    require(not args.output.exists() and not args.output.is_symlink(), 'Publication scratch must be new')
    args.output.mkdir(mode=0o700)
    archive = args.output / 'artifact.zip'
    github.download_actions_artifact(artifact_id, archive)
    candidate = args.output / 'candidate'
    manifest = receive_artifact(archive, candidate, digest)
    bind_candidate(manifest, context=context, run_id=run_id, attempt=attempt,
        target_commit=target, version=version, review_evidence=review, ci=ci)
    # Long artifact transfers must not hide a newly failed/running CI attempt.
    fresh_ci = check_target(github, target, review)
    require(ci == fresh_ci, 'Target CI changed during artifact reception; prepare again')
    from whatsapp_release_publish import publish_candidate
    return publish_candidate(candidate, github, expected_manifest_sha256=digest,
                             confirmation_tag=args.confirm_tag)


def main(argv=None):
    args = arguments(argv)
    receipt = None
    try:
        token = os.environ.get('GH_TOKEN')
        require(isinstance(token, str) and bool(token), 'Ephemeral GitHub token is required')
        receipt = execute(args, GitHubClient(token), os.environ)
        code = 0
    except (ReleaseError, OSError) as error:
        # No arbitrary exception body, HTTP body, token, URL or filesystem path is logged.
        receipt = getattr(error, 'receipt', None) or {'status': 'blocked', 'error_type': type(error).__name__}
        if isinstance(error, ReleaseError):
            receipt = dict(receipt, reason=str(error))
        code = 1
    print(canonical_json(receipt).decode(), end='')
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as stream:
            stream.write('### WhatsApp release result\n\n```json\n' +
                         json.dumps(receipt, indent=2, sort_keys=True) + '\n```\n')
    return code


if __name__ == '__main__':
    sys.exit(main())
