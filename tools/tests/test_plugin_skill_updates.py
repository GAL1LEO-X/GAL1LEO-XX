"""Exercise preservation and bounded packaging, not prose keyword matching."""
import copy
import importlib.util
import json
from pathlib import Path
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('skill_builder', Path(__file__).parents[1] / 'build_plugin.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

SKILLS = {'whatsapp-setup', 'whatsapp-use', 'whatsapp-transcription'}
SKILL_PATHS = {f'skills/{name}/SKILL.md' for name in SKILLS} | {
    'skills/whatsapp-use/references/reading.md',
    'skills/whatsapp-use/references/actions-and-events.md'}


def source_snapshot(prompt=None, required=None):
    app = {'apps': {'dev-fixture': {'id': 'asdk_app_' + '1' * 32}}}
    if required is not None:
        app['apps']['dev-fixture']['required'] = required
    manifest = {'apps': './.app.json', 'author': {'name': 'App developer'},
                'description': 'Synthetic app', 'name': 'dev-fixture', 'version': '1.0.0',
                'interface': {'capabilities': [], 'category': 'Other', 'defaultPrompt': prompt,
                              'developerName': 'App developer', 'displayName': 'Fixture',
                              'longDescription': 'Fixture long', 'shortDescription': 'Fixture short'}}
    contents = {'.app.json': json.dumps(app, indent=3),
                '.codex-plugin/plugin.json': json.dumps(manifest)}
    return {'contents': contents,
            'files': [{'path': path, 'size_bytes': len(body.encode())} for path, body in contents.items()],
            'next_offset': None, 'missing_paths': [], 'size_limited_paths': [],
            'plugin': {'plugin_id': 'plugin_asdk_app_' + '1' * 32, 'name': 'dev-fixture',
                       'version': '1.0.0', 'current_release_id': 'PluginRelease_fixture',
                       'scope': 'USER', 'discoverability': 'PRIVATE'}}


class SkillUpdates(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.output = self.root / 'candidate.zip'
        self.source = source_snapshot()
        self.options = {'expected_plugin_id': self.source['plugin']['plugin_id'],
                        'expected_release_id': self.source['plugin']['current_release_id'],
                        'version': '1.1.0', 'connect_url': 'https://fixture.example/connect'}

    def tearDown(self):
        self.temp.cleanup()

    def test_preserves_effective_app_and_complete_presentation(self):
        for index, (prompt, required) in enumerate(((None, None), ('One', False), (['One', 'Two', 'Three'], True))):
            snapshot = source_snapshot(prompt, required)
            original = copy.deepcopy(snapshot)
            path = self.root / f'candidate-{index}.zip'
            result = builder.build_skill_update(path, snapshot=snapshot, **self.options)
            files = builder.archive_files(path)
            self.assertEqual(set(files), SKILL_PATHS | {'plugin.json', '.codex-plugin/plugin.json', '.app.json'})
            self.assertEqual(files['.app.json'], snapshot['contents']['.app.json'].encode())
            before = json.loads(snapshot['contents']['.codex-plugin/plugin.json'])
            root = json.loads(files['plugin.json'])
            overlay = json.loads(files['.codex-plugin/plugin.json'])
            self.assertEqual(root['$schema'], builder.PLUGIN_SCHEMA)
            self.assertEqual(root['extensions']['com.openai'], {
                'apps': './.app.json', 'interface': before['interface'],
                'onboardingSkill': './skills/whatsapp-setup/SKILL.md'})
            for field in ('name', 'description', 'author'):
                self.assertEqual(root[field], before[field])
            self.assertEqual(root['version'], '1.1.0')
            self.assertEqual(overlay, before | {'version': '1.1.0', 'skills': './skills/',
                'extensions': {'com.openai': {'onboardingSkill': './skills/whatsapp-setup/SKILL.md'}}})
            self.assertEqual(snapshot, original)
            self.assertEqual(result['delete_paths'], [])
            self.assertFalse(result['published'])
            self.assertFalse(result['live_release_guard_verified_by_builder'])

    def test_source_conflicts_partial_reads_and_unknown_layouts_fail_before_output(self):
        cases = []
        for field, value in (('current_release_id', 'changed'), ('plugin_id', 'different'),
                             ('scope', 'WORKSPACE'), ('discoverability', 'LISTED'), ('version', '2.0.0')):
            case = copy.deepcopy(self.source)
            case['plugin'][field] = value
            cases.append(case)
        for field, value in (('next_offset', 2), ('missing_paths', ['unread']),
                             ('size_limited_paths', ['unread']), ('files', [])):
            cases.append(self.source | {field: value})
        case = copy.deepcopy(self.source)
        case['contents']['.app.json'] += ' '
        cases.append(case)
        case = copy.deepcopy(self.source)
        case['files'].append({'path': 'skills/existing/SKILL.md', 'size_bytes': 1})
        case['contents']['skills/existing/SKILL.md'] = 'x'
        cases.append(case)
        for value in (None, [], {}, *cases):
            with self.subTest(value=value), self.assertRaises(ValueError):
                builder.build_skill_update(self.output, snapshot=value, **self.options)
            self.assertFalse(self.output.exists())

    def test_unmapped_metadata_cannot_be_silently_discarded(self):
        for field, value in (('unmapped', 'keep me'), ('author', {'name': 'App', 'unmapped': True}),
                             ('interface', {'default_prompt': 'Keep this prompt'})):
            case = copy.deepcopy(self.source)
            manifest = json.loads(case['contents']['.codex-plugin/plugin.json'])
            manifest[field] = value
            case['contents']['.codex-plugin/plugin.json'] = json.dumps(manifest)
            case['files'] = [{'path': path, 'size_bytes': len(body.encode())}
                             for path, body in case['contents'].items()]
            with self.subTest(field=field), self.assertRaises(ValueError):
                builder.build_skill_update(self.output, snapshot=case, **self.options)
            self.assertFalse(self.output.exists())

    def test_version_guard_and_artifact_are_immutable_and_reproducible(self):
        for changes in ({'version': '1.0.0'}, {'version': '0.9.0'}, {'version': '01.1.0'},
                        {'expected_release_id': ''}, {'expected_plugin_id': ''}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                builder.build_skill_update(self.output, snapshot=self.source, **(self.options | changes))
        first = builder.build_skill_update(self.output, snapshot=self.source, **self.options)
        second = builder.build_skill_update(self.root / 'second.zip', snapshot=self.source, **self.options)
        self.assertEqual(first['sha256'], second['sha256'])
        with self.assertRaises(FileExistsError):
            builder.build_skill_update(self.output, snapshot=self.source, **self.options)

    def test_standalone_packages_include_all_skills_and_resolvable_references(self):
        for mode in ('web', 'portable'):
            path = self.root / f'{mode}.zip'
            connection = {'app_id': 'asdk_app_' + '2' * 32} if mode == 'web' else {'mcp_url': 'https://fixture.example/mcp'}
            builder.build(path, mode=mode, name='whatsapp-fixture', version='1.1.0',
                          connect_url=self.options['connect_url'], **connection)
            files = builder.archive_files(path)
            self.assertEqual({name for name in files if name.startswith('skills/')}, SKILL_PATHS)
            for name in SKILL_PATHS:
                for link in re.findall(r'\]\(([^)]+)\)', files[name].decode()):
                    if not link.startswith('https://'):
                        target = posixpath.normpath(posixpath.join(posixpath.dirname(name), link))
                        self.assertIn(target, files)
            missing = dict(files)
            del missing['skills/whatsapp-use/references/reading.md']
            with self.assertRaises(ValueError):
                builder.validate_files(missing, mode=mode, expected_skill_files=SKILL_PATHS,
                                       **({'app_id': connection['app_id']} if mode == 'web' else {}))

    def test_existing_single_skill_standalone_archives_remain_inspectable(self):
        builder.build(self.output, mode='portable', name='whatsapp-fixture', version='0.3.0',
                      connect_url=self.options['connect_url'], mcp_url='https://fixture.example/mcp')
        files = builder.archive_files(self.output)
        for name in SKILL_PATHS - {'skills/whatsapp-setup/SKILL.md'}:
            del files[name]
        self.assertTrue(builder.validate_files(files, mode='portable')['standalone_complete'])

    def test_collector_excludes_unreviewed_files_and_refuses_linked_inputs(self):
        template = self.root / 'template'
        shutil.copytree(builder.TEMPLATE, template)
        (template / 'skills/whatsapp-use/operator.txt').write_text('not public')
        self.assertEqual(set(builder._skills.collect(template, self.options['connect_url'])), SKILL_PATHS)
        path = template / 'skills/whatsapp-use/references/reading.md'
        outside = self.root / 'outside.md'
        outside.write_text('external')
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaises(ValueError):
            builder.build_skill_update(self.output, snapshot=self.source, template=template, **self.options)
        self.assertFalse(self.output.exists())

    def test_cli_build_is_offline_and_requires_explicit_snapshot_guard(self):
        snapshot = self.root / 'snapshot.json'
        snapshot.write_text(json.dumps(self.source))
        args = [sys.executable, '-I', '-B', str(Path(builder.__file__).resolve()),
                '--mode', 'app-skills-update', '--source-snapshot', str(snapshot),
                '--expected-plugin-id', self.options['expected_plugin_id'],
                '--expected-release-id', self.options['expected_release_id'],
                '--version', '1.1.0', '--connect-url', self.options['connect_url'],
                '--output', str(self.output)]
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)['published'])
        result = subprocess.run(args + ['--app-id', 'asdk_app_' + '2' * 32],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
