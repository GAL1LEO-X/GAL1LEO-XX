"""Synthetic admission/archive tests. Every Docker subprocess is forbidden."""
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

CHECKPOINT = Path(__file__).resolve().parents[2] / 'plugins/whatsapp/provider-checkpoint/qa174'
sys.path.insert(0, str(CHECKPOINT))
import qualify_oci as recipe
import oci_archive


def add(archive, name, data, link=None):
    member = tarfile.TarInfo(name)
    if link:
        member.type, member.linkname = tarfile.SYMTYPE, link
    else:
        member.size = len(data)
    archive.addfile(member, None if link else io.BytesIO(data))


def image(config_id, layers=None):
    return {'Id': config_id, 'Os': 'linux', 'Architecture': 'amd64', 'Size': 1000000,
            'Config': {'Env': ['WAHA_WORKER_RESTART_SESSIONS=true'], 'Entrypoint': ['/usr/bin/tini', '--'],
                       'Cmd': ['/app/entrypoint.sh'], 'WorkingDir': '/app'},
            'RootFS': {'Layers': layers or ['sha256:' + '1' * 64]}}


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.here = self.root / 'recipe'
        self.here.mkdir()
        self.pins = json.loads((CHECKPOINT / 'oci-inputs.json').read_text())
        (self.here / 'oci-inputs.json').write_text(json.dumps(self.pins))
        self.guard = self.here / 'guard'
        self.guard.write_text('synthetic guard')
        self.sources, specs = {}, {}
        for kind in ('waha', 'gows'):
            archive = self.root / (kind + '.tar.gz')
            with tarfile.open(archive, 'w:gz') as target:
                add(target, kind + '-source-qa174/main.txt', b'synthetic source')
            self.sources[kind] = archive
            specs[kind] = {'local_archive_sha256': recipe.digest(archive),
                           'local_archive_bytes': archive.stat().st_size, 'local_archive_files': 1}
        (self.here / 'manifest.json').write_text(json.dumps({'sources': specs}))
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(recipe, 'HERE', self.here).start()
        mock.patch.object(recipe, 'REPOSITORY', self.root / 'checkout').start()
        mock.patch.object(recipe, 'recipe_files', side_effect=lambda: {str(self.guard): recipe.digest(self.guard)}).start()
        self.subprocess_run = mock.patch.object(recipe.subprocess, 'run', side_effect=AssertionError('No subprocess')).start()
        self.subprocess_popen = mock.patch.object(recipe.subprocess, 'Popen', side_effect=AssertionError('No subprocess')).start()

    def plan(self):
        receipt = recipe.prepare(self.sources['waha'], self.sources['gows'], self.root / 'output')
        path = Path(receipt['plan'])
        return path, receipt, recipe.validate_plan(path, receipt['plan_sha256'])

    def test_prepare_is_file_only_and_not_permission(self):
        _, receipt, plan = self.plan()
        self.assertTrue(receipt['prepared_only'])
        self.assertFalse(receipt['docker_invoked'])
        self.assertFalse(plan['approval_granted'])
        self.subprocess_run.assert_not_called()
        self.subprocess_popen.assert_not_called()

    def test_execute_without_digest_refuses_before_docker(self):
        path, _, _ = self.plan()
        with self.assertRaises(ValueError):
            recipe.validate_plan(path, '')
        self.subprocess_run.assert_not_called()

    def test_wrong_archive_refused_before_output(self):
        self.sources['waha'].write_bytes(b'wrong input')
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            recipe.prepare(self.sources['waha'], self.sources['gows'], self.root / 'output')
        self.assertFalse((self.root / 'output').exists())

    def test_plan_drift_refused_before_docker(self):
        path, receipt, _ = self.plan()
        path.write_text(path.read_text() + ' ')
        with self.assertRaisesRegex(ValueError, 'Prepared plan changed'):
            recipe.validate_plan(path, receipt['plan_sha256'])

    def test_guard_drift_refused_even_with_unchanged_plan(self):
        path, receipt, _ = self.plan()
        self.guard.write_text('changed')
        with self.assertRaisesRegex(ValueError, 'guard changed'):
            recipe.validate_plan(path, receipt['plan_sha256'])

    def test_source_drift_refused(self):
        path, receipt, _ = self.plan()
        self.sources['gows'].write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'archive changed'):
            recipe.validate_plan(path, receipt['plan_sha256'])

    def test_existing_output_not_replaced(self):
        self.plan()
        with self.assertRaisesRegex(ValueError, 'already exists'):
            recipe.prepare(self.sources['waha'], self.sources['gows'], self.root / 'output')

    def test_budget_separate_and_shared_filesystems(self):
        recipe.check_budget(5 * recipe.GIB, 2 * recipe.GIB, self.pins)
        for scratch, daemon, shared in ((3 * recipe.GIB, 2 * recipe.GIB, False),
                                       (5 * recipe.GIB, 670 * 1024**2, False),
                                       (4 * recipe.GIB, 4 * recipe.GIB, True)):
            with self.subTest(scratch=scratch, daemon=daemon, shared=shared):
                with self.assertRaisesRegex(ValueError, 'Insufficient'):
                    recipe.check_budget(scratch, daemon, self.pins, shared)

    def test_low_scratch_stops_execution_before_any_docker(self):
        path, receipt, plan = self.plan()
        execution = recipe.Execution(plan)
        with mock.patch.object(recipe.shutil, 'disk_usage', return_value=type('Usage', (), {'free': 1})()), \
                mock.patch.object(execution, 'docker', side_effect=AssertionError('No Docker')) as docker:
            result = execution.execute()
        self.assertFalse(result['passed'])
        self.assertIn('Insufficient scratch', result['error'])
        docker.assert_not_called()

    def test_low_daemon_stops_before_create(self):
        _, _, plan = self.plan()
        execution = recipe.Execution(plan)
        commands = []
        def fake(arguments, name, **kwargs):
            commands.append(arguments)
            if arguments[0] == 'info':
                text = json.dumps(str(self.root))
            elif arguments[:2] == ['image', 'inspect']:
                text = json.dumps([image(arguments[-1])])
            else:
                text = ''
            return type('Completed', (), {'stdout': text, 'stderr': '', 'returncode': 0})()
        def usage(path):
            return type('Usage', (), {'free': 670 * 1024**2 if str(path) == str(self.root) else 6 * recipe.GIB})()
        with mock.patch.object(execution, 'docker', side_effect=fake), mock.patch.object(recipe.shutil, 'disk_usage', side_effect=usage):
            result = execution.execute()
        self.assertFalse(result['passed'])
        self.assertIn('daemon filesystem', result['error'])
        self.assertTrue(all(args[0] in ('--version', 'info', 'image') for args in commands))

    def test_cleanup_never_removes_foreign_container(self):
        _, _, plan = self.plan()
        execution = recipe.Execution(plan)
        execution.owned = [('qa174-synthetic', self.pins['base']['config_digest'])]
        item = {'Image': self.pins['base']['config_digest'], 'Config': {'Labels': {'org.plugins.whatsapp.qa174': 'foreign'}}}
        response = type('Completed', (), {'stdout': json.dumps([item]), 'returncode': 0})()
        with mock.patch.object(execution, 'docker', return_value=response) as docker:
            execution.cleanup()
        self.assertFalse(execution.result['container_cleanup']['passed'])
        self.assertEqual(docker.call_count, 1)
        self.assertEqual(docker.call_args.args[0][0], 'inspect')

    def test_cleanup_graceful_stop_and_kill_are_distinct(self):
        _, _, plan = self.plan()
        execution = recipe.Execution(plan)
        identifier = self.pins['base']['config_digest']
        execution.owned = [('qa174-synthetic', identifier)]
        for exit_code in (0, 143, 137):
            with self.subTest(exit_code=exit_code):
                calls = []
                def fake(arguments, name, **kwargs):
                    calls.append(arguments)
                    after = arguments == ['inspect', 'synthetic-id']
                    item = {'Id': 'synthetic-id', 'Image': identifier,
                            'Config': {'Labels': {'org.plugins.whatsapp.qa174': execution.nonce}},
                            'State': {'Running': not after, 'ExitCode': exit_code, 'OOMKilled': False}}
                    return type('Completed', (), {'stdout': json.dumps([item]), 'returncode': 0})()
                with mock.patch.object(execution, 'docker', side_effect=fake):
                    execution.cleanup()
                self.assertEqual(execution.result['container_cleanup']['passed'], exit_code in (0, 143))
                self.assertEqual(calls[1], ['stop', '--time=20', 'synthetic-id'])
                self.assertEqual('--force' in calls[-1], exit_code == 137)

    def test_inspection_does_not_build_when_budget_is_low(self):
        _, _, plan = self.plan()
        execution = recipe.Execution(plan, inspect_only=True)
        commands = []
        def fake(arguments, name, **kwargs):
            commands.append(arguments)
            value = json.dumps(str(self.root)) if arguments[0] == 'info' else \
                    json.dumps([image(arguments[-1])]) if arguments[0] == 'image' else ''
            return type('Completed', (), {'stdout': value, 'returncode': 0})()
        def usage(path):
            return type('Usage', (), {'free': 670 * 1024**2 if str(path) == str(self.root) else 6 * recipe.GIB})()
        with mock.patch.object(execution, 'docker', side_effect=fake), mock.patch.object(recipe.shutil, 'disk_usage', side_effect=usage):
            result = execution.execute()
        self.assertTrue(result['passed'])
        self.assertFalse(result['oci_qualified'])
        self.assertFalse(result['storage']['build_admitted'])
        self.assertTrue(all(args[0] in ('--version', 'info', 'image') for args in commands))

    def test_runtime_that_dies_before_cleanup_cannot_pass(self):
        _, _, plan = self.plan()
        execution = recipe.Execution(plan)
        identifier = self.pins['base']['config_digest']
        execution.owned = [('qa174-synthetic-runtime', identifier)]
        for code, oom in ((137, True), (1, False), (0, False)):
            with self.subTest(code=code, oom=oom):
                item = {'Id': 'synthetic-id', 'Image': identifier,
                        'Config': {'Labels': {'org.plugins.whatsapp.qa174': execution.nonce}},
                        'State': {'Running': False, 'ExitCode': code, 'OOMKilled': oom}}
                response = type('Completed', (), {'stdout': json.dumps([item]), 'returncode': 0})()
                execution.result['passed'] = True
                with mock.patch.object(execution, 'docker', return_value=response):
                    execution.cleanup()
                self.assertFalse(execution.result['passed'])
                self.assertFalse(execution.result['container_cleanup']['passed'])


class ArchiveAndImageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def saved(self, compressed=False, wrong_diff=False):
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode='w') as target:
            add(target, 'app/gows', b'synthetic ELF replacement')
        data = layer.getvalue()
        diff = 'sha256:' + hashlib.sha256(data).hexdigest()
        actual_diff = 'sha256:' + 'f' * 64 if wrong_diff else diff
        config = {'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': [actual_diff]},
                  'config': {'Env': ['WAHA_WORKER_RESTART_SESSIONS=true']}}
        config_bytes = oci_archive.canonical(config)
        identifier = 'sha256:' + hashlib.sha256(config_bytes).hexdigest()
        path = self.root / 'saved.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            add(archive, 'config.json', config_bytes)
            add(archive, 'manifest.json', json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode())
            add(archive, 'layer.tar', gzip.compress(data, mtime=0) if compressed else data)
        return path, identifier, [actual_diff]

    def test_raw_and_gzip_layer_roundtrip_is_deterministic(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                saved, identifier, layers = self.saved(compressed)
                first = self.root / ('first-' + str(compressed) + '.tar.gz')
                second = self.root / ('second-' + str(compressed) + '.tar.gz')
                receipt = oci_archive.convert(saved, first, identifier, layers)
                self.assertEqual(receipt, oci_archive.convert(saved, second, identifier, layers))
                self.assertEqual(first.read_bytes(), second.read_bytes())
                with tarfile.open(first) as archive:
                    index = json.load(archive.extractfile('index.json'))
                    self.assertEqual(index['manifests'][0]['digest'], receipt['manifest_digest'])
                    manifest = json.load(archive.extractfile('blobs/sha256/' + receipt['manifest_digest'][7:]))
                    self.assertEqual(manifest['config']['digest'], identifier)
                    self.assertEqual(manifest['layers'][0]['mediaType'].endswith('+gzip'), compressed)

    def test_wrong_uncompressed_layer_diff_id_is_rejected(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                saved, identifier, layers = self.saved(compressed, wrong_diff=True)
                with self.assertRaisesRegex(ValueError, 'diff-ID mismatch'):
                    oci_archive.convert(saved, self.root / ('bad-' + str(compressed)), identifier, layers)

    def test_wrong_config_rejected(self):
        saved, _, layers = self.saved()
        with self.assertRaisesRegex(ValueError, 'config mismatch'):
            oci_archive.convert(saved, self.root / 'out', 'sha256:' + '0' * 64, layers)

    def test_stalled_image_pipe_has_actual_deadline(self):
        read_fd, write_fd = os.pipe()
        try:
            with os.fdopen(read_fd, 'rb') as source:
                with self.assertRaisesRegex(ValueError, 'deadline'):
                    recipe.copy_pipe(source, io.BytesIO(), 0.02, lambda: None)
        finally:
            os.close(write_fd)

    def test_image_pipe_copies_bytes_without_subprocess(self):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b'synthetic archive bytes')
        os.close(write_fd)
        target = io.BytesIO()
        with os.fdopen(read_fd, 'rb') as source:
            recipe.copy_pipe(source, target, 1, lambda: None)
        self.assertEqual(target.getvalue(), b'synthetic archive bytes')

    def test_source_path_traversal_and_external_link_rejected(self):
        for name, link in [('waha-source-qa174/../escape', None), ('waha-source-qa174/link', '/etc/passwd'),
                           ('waha-source-qa174/CLAUDE.md', '/etc/passwd')]:
            with self.subTest(name=name, link=link):
                path = self.root / 'bad.tar'
                with tarfile.open(path, 'w') as archive:
                    add(archive, name, b'x', link)
                with self.assertRaises(ValueError):
                    recipe.source_members(path, 'waha')

    def test_source_expected_claude_link_supported(self):
        path = self.root / 'good.tar'
        with tarfile.open(path, 'w') as archive:
            add(archive, 'waha-source-qa174/AGENTS.md', b'instructions')
            add(archive, 'waha-source-qa174/CLAUDE.md', b'', 'AGENTS.md')
        self.assertEqual(recipe.source_members(path, 'waha')['CLAUDE.md'], 'symlink:AGENTS.md')

    def test_wrong_image_platform_or_identity_rejected(self):
        for change in ({'Id': 'sha256:other'}, {'Architecture': 'arm64'}, {'Os': 'windows'}):
            observed = image('sha256:expected')
            observed.update(change)
            with self.assertRaises(ValueError):
                recipe.image_contract(observed, 'sha256:expected')

    def test_implicit_image_volumes_rejected(self):
        observed = image('sha256:expected')
        observed['Config']['Volumes'] = {'/app/.sessions': {}}
        with self.assertRaisesRegex(ValueError, 'implicit'):
            recipe.image_contract(observed, 'sha256:expected')

    def test_overlay_preserves_base_and_config_exactly(self):
        base = image('sha256:base')
        candidate = image('sha256:candidate', base['RootFS']['Layers'] + ['wa', 'go'])
        recipe.overlay_contract(base, candidate)
        for change in ('missing-layer', 'entrypoint', 'restart'):
            bad = copy.deepcopy(candidate)
            if change == 'missing-layer':
                bad['RootFS']['Layers'].pop()
            elif change == 'entrypoint':
                bad['Config']['Entrypoint'] = ['other']
            else:
                bad['Config']['Env'] = ['WAHA_WORKER_RESTART_SESSIONS=false']
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    recipe.overlay_contract(base, bad)


if __name__ == '__main__':
    unittest.main()

