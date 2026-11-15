"""Release source packaging on synthetic Git repositories; no network/runtime."""
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from tools import whatsapp_release_sources as source


REPOSITORY = Path(__file__).resolve().parents[2]


class SourceReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='release-sources-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.write('plugins/whatsapp/pyproject.toml', b'[project]\nname="synthetic"\nversion="9.8.7"\n')
        self.write('plugins/whatsapp/sally_whatsapp/__init__.py', b'__version__ = "9.8.7"\n')
        self.write('plugins/whatsapp/README.md', b'committed fixture\n')
        self.write('plugins/whatsapp/project.json', b'{"schema":1,"id":"synthetic"}\n')
        self.write('plugins/whatsapp/scripts/package_source.py',
                   (REPOSITORY / 'plugins/whatsapp/scripts/package_source.py').read_bytes())
        self.write('plugins/whatsapp/deploy/config.toml', b'# synthetic excluded backend input\n')
        self.write('tools/example.sh', b'#!/bin/sh\nexit 0\n').chmod(0o755)
        self.commit()
        self.output = self.root / 'output'
        self.output.mkdir()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo),
            '-c', 'user.name=Synthetic Fixture', '-c', 'user.email=fixture@example.invalid',
            *args], stderr=subprocess.PIPE).decode().strip()

    def write(self, name, data):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def commit(self, stage=True):
        if stage:
            self.git('add', '.')
        self.git('commit', '-qm', 'Synthetic source fixture')
        self.commit_id = self.git('rev-parse', 'HEAD')

    def prepare(self, **kwargs):
        return source.prepare_sources(kwargs.get('repo', self.repo),
                                      kwargs.get('commit', self.commit_id),
                                      kwargs.get('version', '9.8.7'),
                                      kwargs.get('output', self.output))

    def test_exact_commit_records_members_and_repeatability(self):
        self.write('plugins/whatsapp/README.md', b'dirty worktree\n')
        self.write('plugins/whatsapp/project.json', b'dirty uncommitted contract\n')
        self.write('plugins/whatsapp/sally_whatsapp/untracked.py', b'untracked = True\n')
        self.write('plugins/whatsapp/scripts/package_source.py', b'raise RuntimeError("dirty capture")\n')
        records = self.prepare()
        self.assertEqual([item['role'] for item in records], ['repository_source', 'backend_source'])
        self.assertEqual(len(list(self.output.iterdir())), 2)
        epoch = int(self.git('show', '-s', '--format=%ct', self.commit_id))
        for record in records:
            self.assertEqual(set(record), {'role', 'name', 'bytes', 'sha256', 'origin'})
            self.assertEqual(record['origin'], {'kind': 'built', 'commit': self.commit_id})
            data = (self.output / record['name']).read_bytes()
            self.assertEqual(record['bytes'], len(data))
            self.assertEqual(record['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(data[4:8], b'\0\0\0\0')
            with tarfile.open(self.output / record['name']) as archive:
                self.assertTrue(all(item.isfile() for item in archive))
                self.assertEqual(archive.getnames(), sorted(archive.getnames()))
                self.assertTrue(all(item.mtime == epoch and item.uid == item.gid == 0 for item in archive))
                prefix = 'whatsapp-personal' if record['role'] == 'backend_source' else 'PLUGINS-' + self.commit_id + '/plugins/whatsapp'
                self.assertEqual(archive.extractfile(prefix + '/README.md').read(), b'committed fixture\n')
                self.assertEqual(archive.extractfile(prefix + '/project.json').read(), b'{"schema":1,"id":"synthetic"}\n')
                self.assertNotIn(prefix + '/sally_whatsapp/untracked.py', archive.getnames())
                if record['role'] == 'backend_source':
                    self.assertNotIn(prefix + '/deploy/config.toml', archive.getnames())
                else:
                    self.assertIn(prefix + '/deploy/config.toml', archive.getnames())
                    self.assertEqual(archive.getmember('PLUGINS-' + self.commit_id + '/tools/example.sh').mode, 0o755)
        second = self.root / 'second'
        second.mkdir()
        self.assertEqual(records, self.prepare(output=second))
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()},
                         {p.name: p.read_bytes() for p in second.iterdir()})

    def test_export_attributes_do_not_hide_or_rewrite_git_objects(self):
        self.write('.gitattributes', b'plugins/whatsapp/README.md export-subst\ntools/example.sh export-ignore\n')
        self.write('plugins/whatsapp/README.md', b'$Format:%H$\n')
        self.commit()
        records = self.prepare()
        with tarfile.open(self.output / records[0]['name']) as archive:
            self.assertIn('PLUGINS-' + self.commit_id + '/tools/example.sh', archive.getnames())
        with tarfile.open(self.output / records[1]['name']) as archive:
            self.assertEqual(archive.extractfile('whatsapp-personal/README.md').read(), b'$Format:%H$\n')

    def test_candidate_provider_sources_survive_backend_and_repository_archives(self):
        members = {name: ('synthetic public ' + name + '\n').encode() for name in (
            'README.md', 'manifest.json', 'waha.patch', 'gows.patch',
            'prepare_sources.py', 'qualify_native.py', 'export_candidate_openapi.cjs',
            'Dockerfile.runtime', 'oci-inputs.json', 'oci_archive.py',
            'probe-candidate.cjs', 'qualify_oci.py', 'OCI-QUALIFICATION.md')}
        for name, content in members.items():
            self.write('plugins/whatsapp/provider-checkpoint/qa174/' + name, content)
        self.commit()
        for record in self.prepare():
            prefix = ('whatsapp-personal' if record['role'] == 'backend_source'
                      else 'PLUGINS-' + self.commit_id + '/plugins/whatsapp')
            with tarfile.open(self.output / record['name']) as archive:
                for name, content in members.items():
                    with self.subTest(role=record['role'], member=name):
                        self.assertEqual(archive.extractfile(
                            prefix + '/provider-checkpoint/qa174/' + name).read(), content)

    def test_snapshot_inventory_and_existing_destination(self):
        destination = self.root / 'snapshot'
        inventory = source.snapshot_commit(self.repo, self.commit_id, destination)
        item = inventory['tools/example.sh']
        self.assertEqual(item['mode'], '0755')
        self.assertEqual(item['sha256'], hashlib.sha256((destination / 'tools/example.sh').read_bytes()).hexdigest())
        self.assertEqual(item['git_blob'], self.git('rev-parse', self.commit_id + ':tools/example.sh'))
        with self.assertRaisesRegex(source.ReleaseError, 'absent'):
            source.snapshot_commit(self.repo, self.commit_id, destination)

    def test_links_are_rejected_before_snapshot_creation(self):
        (self.repo / 'linked').symlink_to(self.root / 'absent')
        self.commit()
        destination = self.root / 'snapshot'
        with self.assertRaisesRegex(source.ReleaseError, 'link, submodule'):
            source.snapshot_commit(self.repo, self.commit_id, destination)
        self.assertFalse(destination.exists())
        with self.assertRaises(source.ReleaseError):
            self.prepare()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_submodules_are_rejected(self):
        self.git('update-index', '--add', '--cacheinfo', '160000,' + self.commit_id + ',submodule')
        self.commit(stage=False)
        with self.assertRaisesRegex(source.ReleaseError, 'submodule'):
            self.prepare()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_unsafe_git_filename_is_rejected(self):
        self.write('unsafe\\name', b'synthetic\n')
        self.commit()
        with self.assertRaisesRegex(source.ReleaseError, 'Unsafe'):
            self.prepare()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_exact_commit_and_version_required(self):
        for commit in ('HEAD', self.commit_id[:12], '0' * 40, '--help'):
            with self.subTest(commit=commit), self.assertRaises(source.ReleaseError):
                self.prepare(commit=commit)
        for version in ('../9.8.7', '9.8.7-rc1', '01.2.3', '1.2.3'):
            with self.subTest(version=version), self.assertRaises(source.ReleaseError):
                self.prepare(version=version)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_backend_runtime_version_must_match_project(self):
        self.write('plugins/whatsapp/sally_whatsapp/__init__.py', b'__version__ = "0.0.0"\n')
        self.commit()
        with self.assertRaisesRegex(source.ReleaseError, '__version__ mismatch'):
            self.prepare()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_existing_archive_is_preserved_even_when_backend_target_conflicts(self):
        existing = self.output / f'whatsapp-source-9.8.7-{self.commit_id}.tar.gz'
        existing.write_bytes(b'keep this fixture')
        with self.assertRaisesRegex(source.ReleaseError, 'already exists'):
            self.prepare()
        self.assertEqual(existing.read_bytes(), b'keep this fixture')
        self.assertEqual(list(self.output.iterdir()), [existing])

    def test_output_directory_and_ancestors_must_be_physical(self):
        linked = self.root / 'link'
        linked.symlink_to(self.output, target_is_directory=True)
        for output in (linked, self.root / 'missing'):
            with self.subTest(output=output), self.assertRaises(source.ReleaseError):
                self.prepare(output=output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_archive_member_validation_and_no_overwrite(self):
        path = self.output / 'small.tar.gz'
        invalid = [('../escape', b'x', 0o644), ('/absolute', b'x', 0o644),
                   ('C:/escape', b'x', 0o644), ('a\\b', b'x', 0o644),
                   ('.', b'x', 0o644), ('link', b'x', 0o120777)]
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(source.ReleaseError):
                source.verified_tar(path, [item], 'source', 0)
        for files in ([('a', b'x', 0o644), ('a', b'y', 0o644)],
                      [('a', b'x', 0o644), ('a/b', b'y', 0o644)]):
            with self.assertRaises(source.ReleaseError):
                source.verified_tar(path, files, 'source', 0)
        self.assertFalse(path.exists())
        files = [('a', b'fixture', 0o644)]
        result = source.verified_tar(path, files, 'source', 0)
        self.assertEqual(result['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        with self.assertRaisesRegex(source.ReleaseError, 'already exists'):
            source.verified_tar(path, files, 'source', 0)
        before = path.read_bytes()
        with self.assertRaisesRegex(source.ReleaseError, 'FileExistsError'):
            source.canonical_tar(path, files, 'source', 0)
        self.assertEqual(path.read_bytes(), before)

    def test_repeat_build_mismatch_leaves_no_output(self):
        original = source.canonical_tar
        calls = []

        def altered(path, files, prefix, epoch):
            original(path, files, prefix, epoch)
            calls.append(path)
            if len(calls) == 2:
                path.write_bytes(path.read_bytes() + b'changed')

        with mock.patch.object(source, 'canonical_tar', side_effect=altered):
            with self.assertRaisesRegex(source.ReleaseError, 'repeat comparison'):
                source.verified_tar(self.output / 'bad.tar.gz', [('a', b'x', 0o644)], 'source', 0)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_reread_rejects_identically_corrupted_archive_members(self):
        original = source.canonical_tar

        def altered(path, files, prefix, epoch):
            original(path, [('a', b'wrong', 0o644)], prefix, epoch)

        with mock.patch.object(source, 'canonical_tar', side_effect=altered):
            with self.assertRaisesRegex(source.ReleaseError, 'differs from committed inputs'):
                source.verified_tar(self.output / 'bad.tar.gz', [('a', b'right', 0o644)], 'source', 0)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_post_publication_failure_removes_only_owned_output(self):
        original = source._verify_tar
        final = self.output / 'bad.tar.gz'
        unrelated = self.output / 'keep.txt'
        unrelated.write_bytes(b'keep')

        def fail_final(path, files, prefix, epoch):
            if path == final:
                raise source.ReleaseError('synthetic reread failure')
            return original(path, files, prefix, epoch)

        with mock.patch.object(source, '_verify_tar', side_effect=fail_final):
            with self.assertRaisesRegex(source.ReleaseError, 'synthetic reread failure'):
                source.verified_tar(final, [('a', b'x', 0o644)], 'source', 0)
        self.assertEqual(list(self.output.iterdir()), [unrelated])
        self.assertEqual(unrelated.read_bytes(), b'keep')


if __name__ == '__main__':
    unittest.main()
