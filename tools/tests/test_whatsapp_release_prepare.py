"""Preparation boundary tests with synthetic Git objects and no network/runtime."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from tools import whatsapp_release_prepare as prepare

ROOT = Path(__file__).resolve().parents[2]


class DownloadFixture:
    def __init__(self, data):
        self.data = data
        self.calls = []
        self.tamper = False

    def download_release_asset(self, asset_id, target, expected_bytes, expected_sha256):
        self.calls.append((asset_id, target.name, expected_bytes, expected_sha256))
        with target.open('xb') as handle:
            handle.write(self.data[asset_id] + (b'altered' if self.tamper else b''))


class PrepareReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='prepare-release-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.write('plugins/whatsapp/pyproject.toml', b'[project]\nname="synthetic"\nversion="9.8.7"\n')
        self.write('plugins/whatsapp/sally_whatsapp/__init__.py', b'__version__ = "9.8.7"\n')
        self.write('plugins/whatsapp/README.md', b'Synthetic release fixture\n')
        self.write('plugins/whatsapp/scripts/package_source.py',
                   (ROOT / 'plugins/whatsapp/scripts/package_source.py').read_bytes())
        self.write('plugins/whatsapp/provider-checkpoint/runtime.fixture', b'unchanged provider\n')
        self.write('plugins/whatsapp/deploy/images.lock.json', b'{}\n')
        self.write('plugins/whatsapp/deploy/whatsapp-waha.container', b'# synthetic\n')
        initial = self.commit()
        original = json.loads((ROOT / 'tools/templates/provider-release.example.json').read_text())
        self.lock = copy.deepcopy(original)
        # Qualify an entirely synthetic release policy in this temporary Git
        # repository. The public operator template stays deliberately unusable.
        self.lock.update(source_release_id=101, source_tag='whatsapp-provider/v9.8.6',
                         source_commit=initial)
        self.lock['runtime'] = {'config_digest': 'sha256:' + '1' * 64,
                                'manifest_digest': 'sha256:' + '2' * 64,
                                'gows_sha256': '3' * 64}
        entries = prepare.provider_fingerprint(self.repo, initial)
        self.lock['fingerprint']['entries'] = entries
        self.lock['fingerprint']['sha256'] = hashlib.sha256(prepare.canonical_json(entries)).hexdigest()
        downloads = {}
        for index, item in enumerate(self.lock['assets'], start=1):
            item['origin'].update(release_id=101, asset_id=1000 + index,
                                  tag=self.lock['source_tag'])
            content = ('synthetic pinned asset ' + item['role'] + '\n').encode()
            item['bytes'], item['sha256'] = len(content), hashlib.sha256(content).hexdigest()
            downloads[item['origin']['asset_id']] = content
        self.write(prepare.LOCK_PATH, prepare.canonical_json(self.lock))
        self.target = self.workflow = self.commit()
        self.client = DownloadFixture(downloads)
        self.output = self.root / 'candidate'
        self.ci = {'id': 123, 'run_attempt': 1, 'head_sha': self.target,
                   'status': 'completed', 'conclusion': 'success'}
        self.run = {'id': 456, 'attempt': 1, 'workflow_path': '.github/workflows/whatsapp-release.yml'}
        self.executed = []

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), '-c', 'user.name=Synthetic Fixture',
            '-c', 'user.email=fixture@example.invalid', *args], stderr=subprocess.PIPE).decode().strip()

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'Synthetic preparation fixture')
        return self.git('rev-parse', 'HEAD')

    def qualified(self, *, image_archive, runtime_metadata, source_snapshot, output):
        self.executed.append(runtime_metadata)
        self.assertEqual((source_snapshot / 'plugins/whatsapp/README.md').read_bytes(), b'Synthetic release fixture\n')
        self.assertFalse((source_snapshot / '.git').exists())
        self.assertEqual(prepare.sha256_file(image_archive),
                         (runtime_metadata['archive_bytes'], runtime_metadata['archive_sha256']))
        output.mkdir()
        report = {'passed': True, 'target_commit': runtime_metadata['target_commit'],
                'workflow_commit': runtime_metadata['workflow_commit'],
                'runtime_config_digest': runtime_metadata['config_digest'],
                'checks': {name: {'executed': True, 'passed': True, 'synthetic_unit_test': True}
                           for name in ('backend_regressions', 'runtime_smoke', 'runtime_backend_contract')},
                'limits': ['This injected runner is a unit test, not a runtime qualification.']}
        (output / 'result.json').write_bytes(prepare.canonical_json(report))
        return report

    def call(self, **changes):
        options = dict(repo=self.repo, target_commit=self.target, workflow_commit=self.workflow,
                       version='9.8.7', output=self.output, github=self.client, ci_evidence=self.ci,
                       review_evidence='https://github.com/GAL1LEO-X/GAL1LEO-XX/pull/1',
                       prepared_run=self.run, qualification_runner=self.qualified)
        options.update(changes)
        return prepare.prepare_candidate(**options)

    def test_unconfigured_public_template_cannot_authorize_a_release(self):
        template = (ROOT / 'tools/templates/provider-release.example.json').read_bytes()
        self.write(prepare.LOCK_PATH, template)
        workflow = self.commit()
        with self.assertRaisesRegex(prepare.ReleaseError, 'Invalid source release ID'):
            self.call(workflow_commit=workflow)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.client.calls, [])

    def test_complete_current_candidate_from_git_with_ten_pinned_downloads(self):
        self.write('plugins/whatsapp/README.md', b'Uncommitted material must not be used\n')
        self.write(prepare.LOCK_PATH, b'Not the reviewed workflow lock\n')
        result = self.call()
        self.assertEqual(result['target_commit'], self.target)
        self.assertEqual(result['qualification']['ci_run_id'], 123)
        self.assertEqual(len(result['assets']), 13)
        self.assertEqual(len(self.client.calls), 10)
        self.assertEqual(len(self.executed), 1)
        self.assertEqual({p.name for p in self.output.iterdir()}, {'assets', 'candidate.json', 'RELEASE-NOTES.md'})
        self.assertEqual(len(list((self.output / 'assets').iterdir())), 13)
        self.assertFalse(list(self.root.glob('whatsapp-release-prepare-*')))
        record = next(a for a in result['assets'] if a['role'] == 'validation')
        with tarfile.open(self.output / 'assets' / record['name']) as archive:
            report = json.load(archive.extractfile('whatsapp-validation/qualification.json'))
            self.assertEqual(report['target_commit'], self.target)
            self.assertTrue(report['checks']['runtime_smoke']['synthetic_unit_test'])
        self.assertIn(b'original component version', (self.output / 'RELEASE-NOTES.md').read_bytes())
        repeated = self.call(output=self.root / 'repeat')
        self.assertEqual(result, repeated)

    def test_reject_provider_changes_additions_deletions_and_modes(self):
        cases = ('contents', 'new_file', 'delete', 'mode')
        for case in cases:
            with self.subTest(case=case):
                # Each branch is a separate committed candidate from the same baseline.
                self.git('checkout', '--detach', '-q', self.target)
                path = self.repo / 'plugins/whatsapp/provider-checkpoint/runtime.fixture'
                if case == 'contents': path.write_bytes(b'changed\n')
                elif case == 'new_file': self.write('plugins/whatsapp/provider-checkpoint/extra', b'new\n')
                elif case == 'delete': path.unlink()
                else: path.chmod(0o755)
                changed = self.commit()
                ci = dict(self.ci, head_sha=changed)
                with self.assertRaisesRegex(prepare.ReleaseError, 'full provider rebuild'):
                    self.call(target_commit=changed, ci_evidence=ci)
                self.assertFalse(self.output.exists())
        self.assertEqual(self.client.calls, [])

    def test_backend_change_allowed_but_attributed_to_new_commit(self):
        self.write('plugins/whatsapp/sally_whatsapp/new.py', b'NEW_BACKEND = True\n')
        self.write('plugins/whatsapp/project.json', b'{"schema":1,"id":"synthetic"}\n')
        changed = self.commit()
        result = self.call(target_commit=changed, ci_evidence=dict(self.ci, head_sha=changed))
        self.assertEqual(result['target_commit'], changed)
        self.assertEqual(prepare.provider_fingerprint(self.repo, changed), self.lock['fingerprint']['entries'])
        self.assertTrue(all(a['origin']['commit'] == changed for a in result['assets'] if a['origin']['kind'] == 'built'))

    def test_denies_stale_failed_boolean_or_incomplete_ci_before_download(self):
        for field, value in [('head_sha', '0' * 40), ('status', 'in_progress'), ('conclusion', 'failure'),
                             ('id', True), ('run_attempt', 0)]:
            with self.subTest(field=field), self.assertRaises(prepare.ReleaseError):
                self.call(ci_evidence=dict(self.ci, **{field: value}))
        self.assertFalse(self.output.exists())
        self.assertEqual(self.client.calls, [])

    def test_denies_unsafe_version_review_and_run_identity(self):
        for changes in ({'version': '../9.8.7'}, {'version': '9.8.8'},
                        {'review_evidence': 'https://github.com/other/repo/pull/1'},
                        {'review_evidence': 'https://github.com/GAL1LEO-X/GAL1LEO-XX/pull/1?token=bad'},
                        {'prepared_run': dict(self.run, id=True)},
                        {'target_commit': 'HEAD'}, {'workflow_commit': '0' * 40}):
            with self.subTest(changes=changes), self.assertRaises(prepare.ReleaseError):
                self.call(**changes)
        self.assertFalse(self.output.exists())

    def test_existing_destination_and_symlink_are_preserved(self):
        self.output.mkdir()
        marker = self.output / 'keep'
        marker.write_bytes(b'keep')
        with self.assertRaises(prepare.ReleaseError): self.call()
        self.assertEqual(marker.read_bytes(), b'keep')
        link = self.root / 'linked'
        link.symlink_to(self.output, target_is_directory=True)
        with self.assertRaises(prepare.ReleaseError): self.call(output=link)
        self.assertEqual(self.client.calls, [])

    def test_download_mismatch_prevents_qualification_and_manifest(self):
        self.client.tamper = True
        with self.assertRaisesRegex(prepare.ReleaseError, 'locked bytes'): self.call()
        self.assertEqual(self.executed, [])
        self.assertFalse((self.output / 'candidate.json').exists())

    def test_failed_or_unexecuted_qualification_cannot_create_manifest(self):
        for case in ('failed', 'stale', 'not_executed'):
            with self.subTest(case=case):
                def invalid(**kwargs):
                    report = self.qualified(**kwargs)
                    if case == 'failed': report['passed'] = False
                    elif case == 'stale': report['target_commit'] = '0' * 40
                    else: report['checks']['runtime_smoke']['executed'] = False
                    return report
                destination = self.root / case
                with self.assertRaises(prepare.ReleaseError):
                    self.call(output=destination, qualification_runner=invalid)
                self.assertFalse((destination / 'candidate.json').exists())

    def test_no_historical_receipt_without_current_evidence_files(self):
        def no_files(**kwargs):
            result = self.qualified(**kwargs)
            (kwargs['output'] / 'result.json').unlink()
            return result
        with self.assertRaisesRegex(prepare.ReleaseError, 'evidence files missing'):
            self.call(qualification_runner=no_files)
        self.assertFalse((self.output / 'candidate.json').exists())

    def test_default_path_calls_real_runner_not_injected_receipts(self):
        with mock.patch.object(prepare, 'qualify_runtime', side_effect=prepare.ReleaseError('deliberate no-runtime unit test')) as runner:
            with self.assertRaisesRegex(prepare.ReleaseError, 'deliberate'):
                self.call(qualification_runner=None)
        self.assertEqual(runner.call_count, 1)
        self.assertFalse((self.output / 'candidate.json').exists())

    def test_temporary_keys_and_databases_never_enter_validation(self):
        def fixtures(**kwargs):
            report = self.qualified(**kwargs)
            private = kwargs['output'] / 'pytest-data'
            private.mkdir()
            (private / 'synthetic-key.pem').write_bytes(b'NEVER PACKAGE TEST KEY')
            (private / 'fixture.sqlite').write_bytes(b'NEVER PACKAGE TEST DB')
            return report
        result = self.call(qualification_runner=fixtures)
        validation = next(a for a in result['assets'] if a['role'] == 'validation')
        with tarfile.open(self.output / 'assets' / validation['name']) as archive:
            self.assertFalse(any('pytest-data' in name or 'key.pem' in name or 'sqlite' in name for name in archive.getnames()))

    def test_unexpected_evidence_and_stored_receipt_mismatch_fail_closed(self):
        for case in ('unknown_file', 'stale_receipt'):
            def invalid(**kwargs):
                result = self.qualified(**kwargs)
                if case == 'unknown_file': (kwargs['output'] / 'arbitrary.pem').write_bytes(b'not evidence')
                else: (kwargs['output'] / 'result.json').write_bytes(b'{}\n')
                return result
            with self.subTest(case=case), self.assertRaises(prepare.ReleaseError):
                self.call(qualification_runner=invalid, output=self.root / case)
            self.assertFalse((self.root / case / 'candidate.json').exists())

    def test_explicit_backend_interpreter_is_forwarded_to_runner(self):
        selected = self.root / 'prepared-venv' / 'bin' / 'python'
        seen = []
        def capture(**kwargs):
            seen.append(kwargs.pop('python_executable'))
            return self.qualified(**kwargs)
        self.call(qualification_runner=capture, python_executable=selected)
        self.assertEqual(seen, [selected])

    def test_failed_final_file_verification_has_no_candidate_manifest(self):
        with mock.patch.object(prepare, 'verify_candidate', side_effect=prepare.ReleaseError('changed final bytes')):
            with self.assertRaisesRegex(prepare.ReleaseError, 'changed final bytes'):
                self.call()
        self.assertFalse((self.output / 'candidate.json').exists())
        self.assertTrue((self.output / 'assets').is_dir())

    def test_corrupted_lock_and_repeated_asset_id_rejected_before_output(self):
        for index, mutate in enumerate((lambda lock: lock['assets'][0].update(name='../escape'),
                 lambda lock: lock['assets'][0]['origin'].update(asset_id=lock['assets'][1]['origin']['asset_id']),
                 lambda lock: lock['fingerprint'].update(sha256='0' * 64),
                 lambda lock: lock['fingerprint'].update(scopes=['plugins/whatsapp/provider-checkpoint/']))):
            lock = copy.deepcopy(self.lock)
            mutate(lock)
            self.write(prepare.LOCK_PATH, prepare.canonical_json(lock))
            workflow = self.commit()
            with self.subTest(index=index), self.assertRaises(prepare.ReleaseError):
                self.call(workflow_commit=workflow)
            self.assertFalse(self.output.exists())

    def test_separate_provider_release_requires_same_reviewed_identity(self):
        self.lock['source_tag'] = 'whatsapp-provider/v9.8.7'
        for asset in self.lock['assets']:
            asset['origin']['tag'] = self.lock['source_tag']
        self.write(prepare.LOCK_PATH, prepare.canonical_json(self.lock))
        workflow = self.commit()
        result = self.call(workflow_commit=workflow)
        self.assertEqual(len(result['assets']), 13)
        self.assertEqual(len(self.client.calls), 10)
        self.lock['assets'][0]['origin']['release_id'] += 1
        self.write(prepare.LOCK_PATH, prepare.canonical_json(self.lock))
        mismatched = self.commit()
        with self.assertRaisesRegex(prepare.ReleaseError, 'release identity mismatch'):
            self.call(workflow_commit=mismatched, output=self.root / 'mismatch')
        self.assertFalse((self.root / 'mismatch').exists())


if __name__ == '__main__':
    unittest.main()
