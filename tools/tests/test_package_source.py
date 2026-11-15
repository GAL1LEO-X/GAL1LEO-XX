"""Exercise the installed-host snapshot command with synthetic files and no Git."""
from pathlib import Path
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


REPOSITORY = Path(__file__).resolve().parents[2]
SOURCE = REPOSITORY / 'plugins/whatsapp'
SCRIPT = SOURCE / 'scripts/package_source.py'


class SourceSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / 'installed-project'
        self.public = {
            'pyproject.toml': b'[project]\nname="synthetic"\n',
            'project.json': b'{"schema": 1, "id": "synthetic"}\n',
            'requirements.lock': b'# synthetic fixture\n',
            'requirements-transcription.in': b'# synthetic worker dependencies\n',
            'requirements-transcription.lock': b'# synthetic hashed worker dependencies\n',
            'transcription-model.json': b'{"model":"large-v3"}\n',
            'sally_whatsapp/__init__.py': b'__version__ = "0.5.0"\n',
            'sally_whatsapp/store.py': b'# synthetic source\n',
            'sally_whatsapp/operations.json': b'{"synthetic": true}\n',
            'sally_whatsapp/assets/connect.js': b'// synthetic asset\n',
            'sally_whatsapp/migrations/7-8.sql': b'PRAGMA user_version=8;\n',
            'scripts/backup_schemas/8.sql': b'-- synthetic schema\n',
            'deploy/bridge.example.toml': b'# public template\n',
            'deploy/installation.example.json': b'{}\n',
            'deploy/apache-whatsapp.conf.in': b'# synthetic template\n',
            'plugin/plugin.json': b'{}\n',
            'plugin/assets/whatsapp-gpt.png': b'synthetic-not-an-image',
            'plugin/skills/whatsapp-setup/SKILL.md': b'# synthetic skill\n',
            'plugin/skills/whatsapp-use/SKILL.md': b'# synthetic daily skill\n',
            'plugin/skills/whatsapp-use/references/reading.md': b'# synthetic reading rules\n',
            'plugin/skills/whatsapp-use/references/actions-and-events.md': b'# synthetic action rules\n',
            'plugin/skills/whatsapp-transcription/SKILL.md': b'# synthetic audio skill\n',
            'tests/test_fixture.py': b'# synthetic test\n',
            'tests/browser_peer.test.mjs': b'// synthetic browser test\n',
            'qa/__init__.py': b'# synthetic QA package\n',
            'qa/campaign.py': b'# synthetic coordinator\n',
            'qa/browser_peer.mjs': b'// synthetic browser adapter\n',
            'tests/fixtures/schema6.sql': b'-- synthetic historical fixture\n',
            'tests/fixtures/admin_host_777.py.txt': b'# synthetic historical host source\n',
            'tests/fixtures/admin_handoff_777.py.txt': b'# synthetic historical handoff source\n',
            'tests/fixtures/RECOVERY-COMPAT-SOURCES.md': b'# synthetic historical source provenance\n',
            'docs/PUBLIC.md': b'# synthetic public documentation\n',
            'docs/event-coverage.json': b'{"source": "synthetic"}\n',
            'provider-checkpoint/README.md': b'# synthetic public provider guide\n',
            'provider-checkpoint/fixture-requests.json': b'[]\n',
            'provider-checkpoint/run_vertical.py': b'# synthetic offline probe\n',
            'provider-checkpoint/test_plugin_routes.py': b'# synthetic contract test\n',
            'provider-checkpoint/docs/capability-matrix.md': b'# synthetic capability matrix\n',
            'provider-checkpoint/docs/architecture-and-installation.md': b'# synthetic architecture guide\n',
            'provider-checkpoint/docs/problem-cause-fix-proof.md': b'# synthetic evidence matrix\n',
            'provider-checkpoint/patches/gows.patch': b'# synthetic public GOWS patch\n',
            'provider-checkpoint/patches/waha.patch': b'# synthetic public WAHA patch\n',
            'provider-checkpoint/patches/manifest.json': b'{}\n',
            'provider-checkpoint/patches/README.md': b'# synthetic patch application guide\n',
            'provider-checkpoint/patches/APACHE-2.0.txt': b'# synthetic public license\n',
            'provider-checkpoint/qa120/README.md': b'# synthetic supplemental patch guide\n',
            'provider-checkpoint/qa120/manifest.json': b'{}\n',
            'provider-checkpoint/qa120/waha.patch': b'# synthetic supplemental patch\n',
            'provider-checkpoint/qa136/README.md': b'# synthetic receipt diagnostics guide\n',
            'provider-checkpoint/qa136/manifest.json': b'{"schema_version": 1}\n',
            'provider-checkpoint/qa136/gows.patch': b'# synthetic receipt diagnostics patch\n',
            'provider-checkpoint/qa137/README.md': b'# synthetic native build guide\n',
            'provider-checkpoint/qa137/manifest.json': b'{}\n',
            'provider-checkpoint/qa137/Dockerfile.runtime': b'# synthetic native build recipe\n',
            'provider-checkpoint/qa137/runtime.dockerignore': b'# synthetic native build inputs\n',
            'provider-checkpoint/qa158/README.md': b'# synthetic local receipt diagnostics guide\n',
            'provider-checkpoint/qa158/manifest.json': b'{}\n',
            'provider-checkpoint/qa158/gows.patch': b'# synthetic local receipt diagnostics patch\n',
            'provider-checkpoint/qa158/Dockerfile.runtime': b'# synthetic native build recipe\n',
            'provider-checkpoint/qa158/runtime.dockerignore': b'# synthetic native build inputs\n',
            'provider-checkpoint/qa174/README.md': b'# synthetic candidate provider guide\n',
            'provider-checkpoint/qa174/manifest.json': b'{"schema_version": 1}\n',
            'provider-checkpoint/qa174/waha.patch': b'# synthetic WAHA patch\n',
            'provider-checkpoint/qa174/gows.patch': b'# synthetic GOWS patch\n',
            'provider-checkpoint/qa174/prepare_sources.py': b'# synthetic source preparation\n',
            'provider-checkpoint/qa174/qualify_native.py': b'# synthetic offline qualification\n',
            'provider-checkpoint/qa174/export_candidate_openapi.cjs': b'// synthetic schema export\n',
            'provider-checkpoint/qa174/Dockerfile.runtime': b'# synthetic exact overlay\n',
            'provider-checkpoint/qa174/oci-inputs.json': b'{"schema_version": 1}\n',
            'provider-checkpoint/qa174/oci_archive.py': b'# synthetic verified OCI export\n',
            'provider-checkpoint/qa174/probe-candidate.cjs': b'// synthetic runtime probe\n',
            'provider-checkpoint/qa174/qualify_oci.py': b'# synthetic isolated qualification\n',
            'provider-checkpoint/qa174/OCI-QUALIFICATION.md': b'# synthetic isolated OCI runbook\n',
            'provider-checkpoint/qa174/qualified-runtime.json': b'{"qualification":"synthetic"}\n',
            'provider-checkpoint/qa174/recovered/build_gows_harness.py': b'# synthetic recovered build harness\n',
            'provider-checkpoint/qa174/recovered/complete_remaining_packages.py': b'# synthetic remaining-package coverage\n',
            'provider-checkpoint/qa174/recovered/server-build.py': b'# synthetic recovered COPY-only assembler\n',
            'provider-checkpoint/qa174/recovered/server-qualify.py': b'# synthetic historical v1 sealed input; not an execution recipe\n',
            'provider-checkpoint/qa174/recovered/server-qualify-v2.py': b'# synthetic recovered runtime qualifier\n',
            'provider-checkpoint/qa174/recovered/run-compiled-tests.cjs': b'// synthetic actual-image test loader\n',
            'provider-checkpoint/build/Dockerfile': b'# synthetic public runtime recipe\n',
            'provider-checkpoint/build/.dockerignore': b'# synthetic public build excludes\n',
            'provider-checkpoint/build/Dockerfile.gows-builder': b'# synthetic public GOWS recipe\n',
            'provider-checkpoint/build/README.md': b'# synthetic build guide\n',
            'scripts/package_source.py': SCRIPT.read_bytes(),
        }
        for name, content in self.public.items():
            self.write(name, content)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def run_snapshot(self, output):
        return subprocess.run([sys.executable, '-I', '-B', str(self.root / 'scripts/package_source.py'), str(output)],
                              cwd=self.base, capture_output=True, text=True, timeout=20)

    def contents(self, output):
        if output.suffix == '.zip':
            with zipfile.ZipFile(output) as archive:
                self.assertTrue(all(stat.S_ISREG(info.external_attr >> 16) for info in archive.infolist()))
                return {name.removeprefix('whatsapp-personal/'): archive.read(name) for name in archive.namelist()}
        with tarfile.open(output) as archive:
            self.assertTrue(all(member.isfile() for member in archive.getmembers()))
            return {member.name: archive.extractfile(member).read() for member in archive.getmembers()}

    def test_public_snapshot_without_git_excludes_generated_and_private_inputs(self):
        private = ['plugin/skills/whatsapp-use/references/operator.md',
                   'plugin/skills/unreviewed/SKILL.md',
                   'prepared/operator.env', 'prepared/bridge.example.toml', 'prepared/plan.py',
                   'deploy/operator.env', 'deploy/.env', 'deploy/config.toml', 'deploy/installation.json',
                   'deploy/credentials.json', 'scripts/as-user', 'scripts/token.txt',
                   'sally_whatsapp/.env', 'sally_whatsapp/credentials.json', 'sally_whatsapp/archive.sqlite',
                   'sally_whatsapp/__pycache__/config.pyc', 'tests/local-fixture.json',
                   'qa/bindings.json', 'qa/campaign.sqlite', 'qa/operator.mjs',
                   'tests/fixtures/admin_host_local.py.txt', 'tests/fixtures/OPERATOR-NOTES.md',
                   'private/identity.json', 'state/archive.sqlite', 'secrets/key.pem',
                   'dist/source.tar.gz', 'build/generated.py', '.venv/config.py',
                   'provider-checkpoint/operator.env', 'provider-checkpoint/credentials.json',
                   'provider-checkpoint/local-source.py', 'provider-checkpoint/docs/OPERATOR.md',
                   'provider-checkpoint/patches/local.patch', 'provider-checkpoint/patches/operator.json',
                   'provider-checkpoint/build/operator.env', 'provider-checkpoint/build/config.toml',
                   'provider-checkpoint/build/local-recipe.py',
                   'provider-checkpoint/qa120/credentials.json',
                   'provider-checkpoint/qa120/operator.env',
                   'provider-checkpoint/qa120/local.patch',
                   'provider-checkpoint/qa136/credentials.json',
                   'provider-checkpoint/qa136/operator.env',
                   'provider-checkpoint/qa136/local.patch',
                   'provider-checkpoint/qa137/operator.env',
                   'provider-checkpoint/qa137/local.patch',
                   'provider-checkpoint/qa158/operator.env',
                   'provider-checkpoint/qa158/credentials.json',
                   'provider-checkpoint/qa158/local.patch',
                   'provider-checkpoint/qa174/operator.env',
                   'provider-checkpoint/qa174/credentials.json',
                   'provider-checkpoint/qa174/local.patch',
                   'provider-checkpoint/qa174/private.py',
                   'provider-checkpoint/qa174/prepare_sources.py.bak',
                   'provider-checkpoint/qa174/export_candidate_openapi.local.cjs',
                   'provider-checkpoint/qa174/nested/README.md',
                   'provider-checkpoint/qa174/output/manifest.json',
                   'provider-checkpoint/qa174/recovered/input-manifest.json',
                   'provider-checkpoint/qa174/recovered/native-qualification.json',
                   'provider-checkpoint/qa174/recovered/qualification-result.json',
                   'provider-checkpoint/qa174/recovered/operator.env',
                   'provider-checkpoint/qa174/recovered/credentials.json',
                   'provider-checkpoint/qa174/recovered/local-helper.py',
                   'provider-checkpoint/qa174/recovered/server-build.py.bak',
                   'provider-checkpoint/qa174/recovered/context/gows',
                   'provider-checkpoint/qa174/recovered/context/dist/main.js',
                   'provider-checkpoint/qa175/README.md',
                   'provider-checkpoint/qa138/README.md']
        for name in private:
            self.write(name, b'SYNTHETIC_PRIVATE_FIXTURE_ONLY\n')
        self.assertFalse((self.root / '.git').exists())
        for suffix in ('.tar.gz', '.zip'):
            output = self.base / ('source' + suffix)
            result = self.run_snapshot(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.contents(output), self.public)

    def test_symbolic_source_file_and_directory_are_refused_before_output(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'store.py').write_bytes(b'SYNTHETIC_EXTERNAL_FIXTURE_ONLY\n')
        for directory in (False, True):
            linked = self.root / ('sally_whatsapp' if directory else 'sally_whatsapp/store.py')
            if directory:
                shutil.rmtree(linked)
            else:
                linked.unlink()
            try:
                linked.symlink_to(outside if directory else outside / 'store.py', target_is_directory=directory)
            except OSError as exc:
                self.skipTest(f'Filesystem does not permit creating symlinks: {exc}')
            for suffix in ('.tar.gz', '.zip'):
                output = self.base / (f'linked-{directory}' + suffix)
                result = self.run_snapshot(output)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse(output.exists())
            linked.unlink()
            if not directory:
                self.write('sally_whatsapp/store.py', self.public['sally_whatsapp/store.py'])

    def test_hard_linked_source_is_refused_before_output(self):
        outside = self.base / 'outside.py'
        outside.write_bytes(b'SYNTHETIC_EXTERNAL_FIXTURE_ONLY\n')
        source = self.root / 'sally_whatsapp/store.py'
        source.unlink()
        os.link(outside, source)
        output = self.base / 'linked.tar.gz'
        result = self.run_snapshot(output)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(output.exists())

    def test_existing_snapshot_is_preserved(self):
        for suffix in ('.tar.gz', '.zip'):
            output = self.base / ('existing' + suffix)
            output.write_bytes(b'previous-snapshot-synthetic')
            result = self.run_snapshot(output)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(output.read_bytes(), b'previous-snapshot-synthetic')

    @unittest.skipIf(os.name == 'nt', 'Windows does not model the POSIX permission bits restored on Linux')
    def test_public_source_permissions_are_preserved_for_restore(self):
        source = self.root / 'sally_whatsapp/store.py'
        source.chmod(0o600)
        script = self.root / 'scripts/package_source.py'
        script.chmod(0o750)
        for suffix in ('.tar.gz', '.zip'):
            output = self.base / ('permissions' + suffix)
            result = self.run_snapshot(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            if suffix == '.zip':
                with zipfile.ZipFile(output) as archive:
                    modes = {name.removeprefix('whatsapp-personal/'): info.external_attr >> 16 & 0o777
                             for name, info in ((item.filename, item) for item in archive.infolist())}
            else:
                with tarfile.open(output) as archive:
                    modes = {item.name: item.mode for item in archive.getmembers()}
            self.assertEqual(modes['sally_whatsapp/store.py'], 0o600)
            self.assertEqual(modes['scripts/package_source.py'], 0o750)

    def test_all_versioned_public_sources_templates_assets_and_schemas_are_retained(self):
        # The installed-host invocation above needs no Git. Here Git is only the
        # independent development oracle: newly committed public formats must
        # not disappear silently from the snapshot allowlist.
        tracked = subprocess.run(['git', 'ls-files', '-z', '--', 'plugins/whatsapp'], cwd=REPOSITORY,
                                 check=True, capture_output=True).stdout.decode().split('\0')
        expected = {}
        for name in filter(None, tracked):
            relative = Path(name).relative_to('plugins/whatsapp').as_posix()
            expected[relative] = (REPOSITORY / name).read_bytes()
        for name, content in expected.items():
            self.write(name, content)
        # Keep this fixture an exact source tree, independent of generated data.
        for name in self.public.keys() - expected.keys():
            (self.root / name).unlink()
        for suffix in ('.tar.gz', '.zip'):
            output = self.base / ('complete' + suffix)
            result = self.run_snapshot(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            actual = self.contents(output)
            self.assertEqual(set(actual), set(expected))
            for name in expected:
                with self.subTest(format=suffix, member=name):
                    self.assertEqual(actual[name], expected[name])


if __name__ == '__main__':
    unittest.main()
