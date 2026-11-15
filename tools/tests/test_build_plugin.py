import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import shutil
import subprocess
import sys
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('builder', Path(__file__).parents[1] / 'build_plugin.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.output = Path(self.temp.name) / 'plugin.zip'
        self.options = dict(mode='web', name='whatsapp-fixture', version='0.0.1-test',
                            connect_url='https://fixture.example/connect', app_id='asdk_app_' + '1' * 32)

    def tearDown(self): self.temp.cleanup()

    def test_web_references_only_requested_app_and_has_no_bundled_mcp(self):
        result = builder.build(self.output, **self.options)
        with zipfile.ZipFile(self.output) as archive:
            names = set(archive.namelist())
            self.assertTrue({'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md'} <= names)
            self.assertIn(b'info@gal1leo.com', archive.read('NOTICE'))
            self.assertNotIn('mcp.json', names)
            self.assertIn('.app.json', names)
            manifest = json.loads(archive.read('plugin.json'))
            overlay = json.loads(archive.read('.codex-plugin/plugin.json'))
            self.assertEqual(manifest['extensions']['com.openai']['apps'], './.app.json')
            self.assertEqual(overlay['apps'], './.app.json')
            self.assertEqual(json.loads(archive.read('.app.json'))['apps'], {
                'dev-' + '1' * 32: {'id': self.options['app_id'], 'required': True}})
            skill = archive.read('skills/whatsapp-setup/SKILL.md')
            self.assertIn(b'https://fixture.example/connect', skill)
            self.assertNotIn(b'https://whatsapp.example.invalid/connect', skill)
        self.assertFalse(result['registration_ownership_verified_by_builder'])

    def test_original_green_icon_is_preserved_in_runtime_and_package(self):
        # Exact original user-provided 1.0.4 PNG; no re-encoding or new branding.
        expected = '02f99cfe5e55566352f38d82fd66c90116197cdda7f3e6b270c50371b1a27921'
        template_icon = (builder.TEMPLATE / 'assets/whatsapp-gpt.png').read_bytes()
        runtime_icon = (builder.ROOT / 'plugins/whatsapp/sally_whatsapp/assets/whatsapp-gpt.png').read_bytes()
        self.assertEqual(hashlib.sha256(template_icon).hexdigest(), expected)
        self.assertEqual(template_icon, runtime_icon)
        builder.build(self.output, **self.options)
        with zipfile.ZipFile(self.output) as archive:
            manifest = json.loads(archive.read('plugin.json'))
            overlay = json.loads(archive.read('.codex-plugin/plugin.json'))
            for interface in (manifest['extensions']['com.openai']['interface'], overlay['interface']):
                for key in ('logo', 'composerIcon'):
                    self.assertEqual(archive.read(interface[key][2:]), template_icon)

    def test_portable_is_explicit_and_does_not_reuse_an_app_registration(self):
        self.options.update(mode='portable', app_id=None, mcp_url='https://fixture.example/mcp')
        builder.build(self.output, **self.options)
        with zipfile.ZipFile(self.output) as archive:
            self.assertNotIn('.app.json', archive.namelist())
            self.assertEqual(json.loads(archive.read('mcp.json'))['mcpServers']['whatsapp-fixture']['url'], 'https://fixture.example/mcp')
            self.assertIn(b'only on desktop', archive.read('CONFIGURATION.md'))

    def portable_files(self):
        builder.build(self.output, **(self.options | {
            'mode': 'portable', 'app_id': None, 'mcp_url': 'https://fixture.example/mcp'}))
        with zipfile.ZipFile(self.output) as archive:
            return {name: archive.read(name) for name in archive.namelist()}

    def write_archive(self, name, files):
        path = Path(self.temp.name) / name
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
            for member, data in files.items():
                archive.writestr(member, data)
        return path

    def test_portable_inspection_accepts_generated_manifest_with_or_without_schema(self):
        files = self.portable_files()
        original = self.output.read_bytes()
        self.assertTrue(builder.validate_archive(self.output, mode='portable',
                        expected_name=self.options['name'])['standalone_complete'])
        mcp = json.loads(files['mcp.json'])
        del mcp['$schema']
        without_schema = self.write_archive('without-schema.zip', files | {'mcp.json': json.dumps(mcp).encode()})
        self.assertTrue(builder.validate_archive(without_schema, mode='portable')['standalone_complete'])
        self.assertEqual(original, self.output.read_bytes())

    def test_portable_inspection_rejects_invalid_mcp_structure(self):
        files = self.portable_files()
        server = {'type': 'streamable-http', 'url': 'https://fixture.example/mcp'}
        valid = {'mcpServers': {self.options['name']: server}}
        duplicate_cases = [
            ('{"mcpServers":{},"mcpServers":' + json.dumps(valid['mcpServers']) + '}').encode(),
            ('{"mcpServers":{"whatsapp-fixture":{},"whatsapp-fixture":' + json.dumps(server) + '}}').encode(),
            b'{"mcpServers":{"whatsapp-fixture":{"type":"streamable-http","url":"http://fixture.example","url":"https://fixture.example/mcp"}}}',
        ]
        cases = [b'not json', b'\xff', b'{}', b'null', b'[]', *duplicate_cases,
                 {'mcpServers': None}, {'mcpServers': []}, {'mcpServers': {}},
                 {'mcpServers': {'other-plugin': server}},
                 {'mcpServers': {self.options['name']: server, 'extra': server}},
                 {'mcpServers': {self.options['name']: None}},
                 {'mcpServers': {self.options['name']: []}},
                 {'mcpServers': {self.options['name']: {'url': server['url']}}},
                 {'mcpServers': {self.options['name']: server | {'type': 'stdio'}}},
                 {'mcpServers': {self.options['name']: server | {'command': 'unexpected'}}},
                 valid | {'$schema': 'https://fixture.example/unsupported-schema'},
                 valid | {'extra': {}}]
        for index, value in enumerate(cases):
            payload = value if isinstance(value, bytes) else json.dumps(value).encode()
            path = self.write_archive(f'invalid-{index}.zip', files | {'mcp.json': payload})
            original = path.read_bytes()
            with self.subTest(case=index), self.assertRaises(ValueError):
                builder.validate_archive(path, mode='portable')
            self.assertEqual(original, path.read_bytes())

    def test_portable_inspection_requires_supported_endpoint(self):
        files = self.portable_files()
        endpoints = [None, False, 42, [], {}, '', 'http://fixture.example/mcp',
                     'https:///mcp', 'https://user:password@fixture.example/mcp',
                     'https://fixture.example/mcp?token=synthetic', 'https://fixture.example/mcp#fragment',
                     'https://fixture.example:invalid/mcp', 'https://fixture.example:65536/mcp']
        servers = [{'type': 'streamable-http'}] + [
            {'type': 'streamable-http', 'url': endpoint} for endpoint in endpoints]
        for index, server in enumerate(servers):
            payload = json.dumps({'mcpServers': {self.options['name']: server}}).encode()
            path = self.write_archive(f'endpoint-{index}.zip', files | {'mcp.json': payload})
            with self.subTest(case=index), self.assertRaises(ValueError):
                builder.validate_archive(path, mode='portable')

    def test_portable_inspection_rejects_alternate_or_inline_connections(self):
        files = self.portable_files()
        alternate = self.write_archive('alternate.zip', files | {'.mcp.json': files['mcp.json']})
        with self.assertRaises(ValueError):
            builder.validate_archive(alternate, mode='portable')
        for location in ('manifest', 'extension', 'overlay'):
            for key in ('mcpServers', 'mcp'):
                member = '.codex-plugin/plugin.json' if location == 'overlay' else 'plugin.json'
                document = json.loads(files[member])
                target = document['extensions']['com.openai'] if location == 'extension' else document
                target[key] = {'unexpected': {}}
                path = self.write_archive(f'{location}-{key}.zip', files | {member: json.dumps(document).encode()})
                with self.subTest(location=location, key=key), self.assertRaises(ValueError):
                    builder.validate_archive(path, mode='portable')

    def test_portable_cli_refuses_invalid_manifest_without_modifying_archive(self):
        files = self.portable_files()
        broken = self.write_archive('broken.zip', files | {'mcp.json': b'{}'})
        command = [sys.executable, '-I', '-B', str(Path(builder.__file__).resolve()),
                   '--mode', 'portable', '--validate-zip']
        valid = subprocess.run([*command, str(self.output)], capture_output=True, text=True, timeout=15)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertTrue(json.loads(valid.stdout)['standalone_complete'])
        original = broken.read_bytes()
        invalid = subprocess.run([*command, str(broken)], capture_output=True, text=True, timeout=15)
        self.assertEqual(invalid.returncode, 2, invalid.stderr)
        self.assertEqual(invalid.stdout, '')
        self.assertIn('error:', invalid.stderr)
        self.assertNotIn('Traceback', invalid.stderr)
        self.assertEqual(original, broken.read_bytes())

    def test_ambiguous_or_credential_bearing_inputs_fail(self):
        for changes in [{'app_id': None}, {'app_id': 'asdk_app_placeholder'},
                        {'mcp_url': 'https://fixture.example/mcp'},
                        {'connect_url': 'https://user:password@fixture.example/connect'},
                        {'connect_url': 'http://fixture.example/connect'},
                        {'connect_url': 'https://fixture.example/connect?token=private'},
                        {'name': '../escape'}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                builder.build(self.output, **(self.options | changes))
        self.assertFalse(self.output.exists())

    def test_connect_and_mcp_urls_share_literal_and_port_validation(self):
        invalid = [None, False, 42, '', 'https://fixture.example:70000/connect',
                   'https://fixture.example:invalid/connect', 'https://fixture.example:0/connect',
                   'https://fixture.example:/connect', ' https://fixture.example/connect',
                   'https://fixture.example/con\nnect', 'https://fixture.example/connect\t',
                   'https://fixture.example/\\connect', 'https://@fixture.example/connect',
                   'HTTPS://fixture.example/connect', 'https://fixture.example/connect?',
                   'https://fixture.example/connect#']
        for mode in ('web', 'portable'):
            options = self.options | ({'mode': 'portable', 'app_id': None,
                                       'mcp_url': 'https://fixture.example/mcp'} if mode == 'portable' else {})
            for value in invalid:
                with self.subTest(mode=mode, value=value), self.assertRaises(ValueError):
                    builder.build(self.output, **(options | {'connect_url': value}))
                self.assertFalse(self.output.exists())
        files = self.portable_files()
        for index, value in enumerate(invalid):
            mcp = {'mcpServers': {self.options['name']: {'type': 'streamable-http', 'url': value}}}
            path = self.write_archive(f'literal-{index}.zip', files | {'mcp.json': json.dumps(mcp).encode()})
            with self.subTest(inspection=value), self.assertRaises(ValueError):
                builder.validate_archive(path, mode='portable')

    def test_explicit_ports_and_ipv6_are_preserved_for_both_endpoints(self):
        for index, origin in enumerate(('https://custom.example.invalid:4443', 'https://[2001:db8::1]:8443')):
            path = self.output.with_name(f'custom-{index}.zip')
            builder.build(path, **(self.options | {'mode': 'portable', 'app_id': None,
                          'connect_url': origin + '/connect/', 'mcp_url': origin + '/mcp/'}))
            with zipfile.ZipFile(path) as archive:
                self.assertIn((origin + '/connect').encode(), archive.read('CONFIGURATION.md'))
                self.assertEqual(json.loads(archive.read('mcp.json'))['mcpServers'][self.options['name']]['url'], origin + '/mcp')
            self.assertTrue(builder.validate_archive(path, mode='portable')['standalone_complete'])

    def test_build_is_reproducible_and_preserves_previous_artifact(self):
        first = builder.build(self.output, **self.options)
        with self.assertRaises(FileExistsError): builder.build(self.output, **self.options)
        second = builder.build(self.output.with_name('second.zip'), **self.options)
        self.assertEqual(first['sha256'], second['sha256'])

    def test_bad_template_reference_is_rejected_before_output(self):
        template = Path(self.temp.name) / 'template'
        shutil.copytree(builder.TEMPLATE, template)
        manifest = json.loads((template / 'plugin.json').read_text(encoding='utf-8'))
        for path in ('./assets/missing.png', '../escape.png', './assets/../whatsapp-gpt.png', 'https://example.com/logo.png'):
            manifest['extensions']['com.openai']['interface']['logo'] = path
            (template / 'plugin.json').write_text(json.dumps(manifest), encoding='utf-8')
            with self.subTest(path=path), self.assertRaises(ValueError):
                builder.build(self.output, template=template, **self.options)
            self.assertFalse(self.output.exists())

    def test_inspection_rejects_incomplete_incremental_and_wrong_identity(self):
        builder.build(self.output, **self.options)
        original = self.output.read_bytes()
        self.assertTrue(builder.validate_archive(self.output, mode='web', app_id=self.options['app_id'],
                                                 expected_name=self.options['name'])['standalone_complete'])
        with zipfile.ZipFile(self.output) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        for member in ('assets/whatsapp-gpt.png', 'skills/whatsapp-setup/SKILL.md', '.app.json'):
            partial = dict(files); partial.pop(member)
            with self.subTest(member=member), self.assertRaises(ValueError):
                builder.validate_files(partial, mode='web', app_id=self.options['app_id'])
        for options in ({'app_id': 'asdk_app_' + '2' * 32}, {'expected_name': 'another-plugin'}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                builder.validate_archive(self.output, mode='web', **({'app_id':self.options['app_id']} | options))
        self.assertEqual(original, self.output.read_bytes())

    def test_manifest_disagreement_optional_dependency_and_extra_connection_fail(self):
        builder.build(self.output, **self.options)
        with zipfile.ZipFile(self.output) as archive:
            original = {name: archive.read(name) for name in archive.namelist()}
        for key, value in (('name','different'), ('version','99.0.0'), ('interface',{})):
            files = dict(original)
            overlay = json.loads(files['.codex-plugin/plugin.json']); overlay[key] = value
            files['.codex-plugin/plugin.json'] = json.dumps(overlay).encode()
            with self.subTest(key=key), self.assertRaises(ValueError):
                builder.validate_files(files, mode='web', app_id=self.options['app_id'])
        files = dict(original); app = json.loads(files['.app.json'])
        next(iter(app['apps'].values()))['required'] = False
        files['.app.json'] = json.dumps(app).encode()
        with self.assertRaises(ValueError): builder.validate_files(files, mode='web', app_id=self.options['app_id'])
        for name in ('mcp.json','.mcp.json','../escape'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                builder.validate_files(original | {name: b'{}'}, mode='web', app_id=self.options['app_id'])

    def test_duplicate_members_are_rejected(self):
        with zipfile.ZipFile(self.output, 'w') as archive:
            archive.writestr('plugin.json', b'{}')
            archive.writestr('plugin.json', b'{}')
        with self.assertRaises(ValueError, msg='duplicate archive must fail'):
            builder.validate_archive(self.output, mode='web', app_id=self.options['app_id'])

    def test_required_app_dependency_must_be_literal_true(self):
        builder.build(self.output, **self.options)
        with zipfile.ZipFile(self.output) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        for required in (1, 1.0, 0, False, None, 'true'):
            app = json.loads(files['.app.json'])
            next(iter(app['apps'].values()))['required'] = required
            path = self.write_archive(f'required-{type(required).__name__}-{required}.zip',
                                      files | {'.app.json': json.dumps(app).encode()})
            with self.subTest(required=required), self.assertRaises(ValueError):
                builder.validate_archive(path, mode='web', app_id=self.options['app_id'])

    def test_duplicate_json_keys_are_rejected_in_every_package_manifest(self):
        builder.build(self.output, **self.options)
        with zipfile.ZipFile(self.output) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        for member, key in (
                ('plugin.json', 'name'),
                ('.codex-plugin/plugin.json', 'name'),
                ('.app.json', 'apps')):
            # Last-key-wins parsing previously accepted even conflicting values.
            document = json.loads(files[member])
            ambiguous = ('{' + json.dumps(key) + ':null,' + json.dumps(document)[1:]).encode()
            path = self.write_archive(member.replace('/', '-') + '.zip', files | {member: ambiguous})
            original = path.read_bytes()
            with self.subTest(member=member), self.assertRaises(ValueError, msg='ambiguous manifest must fail'):
                builder.validate_archive(path, mode='web', app_id=self.options['app_id'])
            self.assertEqual(original, path.read_bytes())

    def test_nested_duplicate_json_keys_are_rejected(self):
        files = self.portable_files()
        member = '.codex-plugin/plugin.json'
        document = files[member].decode()
        self.assertIn('"logo":', document)
        files[member] = document.replace('"logo":', '"logo": "./missing.png", "logo":', 1).encode()
        path = self.write_archive('duplicate-icon.zip', files)
        with self.assertRaises(ValueError):
            builder.validate_archive(path, mode='portable')

if __name__ == '__main__': unittest.main()

