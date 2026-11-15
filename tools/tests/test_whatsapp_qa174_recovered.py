"""Portable QA174 recovery regressions; no server, account or container engine."""
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import ast
import copy
import hashlib
import io
import json
import os
import re
import runpy
import shutil
import subprocess
import tarfile
import tempfile
import unittest

RECOVERED = Path(__file__).resolve().parents[2] / 'plugins/whatsapp/provider-checkpoint/qa174/recovered'
BUILD = RECOVERED / 'server-build.py'
QUALIFY = RECOVERED / 'server-qualify-v2.py'
B = SimpleNamespace(**runpy.run_path(str(BUILD)))
Q = SimpleNamespace(**runpy.run_path(str(QUALIFY)))
SYNTHETIC_ROOT = Path('/synthetic/qualification')


class NoContainers(unittest.TestCase):
    def setUp(self):
        for method in ('run', 'Popen'):
            patcher = mock.patch.object(subprocess, method, side_effect=AssertionError('No subprocess allowed'))
            patcher.start()
            self.addCleanup(patcher.stop)


def layer(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as archive:
        for name, body, mode, uid, kind in entries:
            item = tarfile.TarInfo(name); item.mode = mode; item.uid = item.gid = uid
            item.type = kind
            if kind == tarfile.REGTYPE: item.size = len(body)
            archive.addfile(item, io.BytesIO(body) if kind == tarfile.REGTYPE else None)
    return raw.getvalue()

class LayerTests(NoContainers):
    def check(self, entries=None, config_mutate=None):
        base_raw = layer([])
        values = [('app',b'',0o755,0,tarfile.DIRTYPE),('app/dist',b'',0o755,0,tarfile.DIRTYPE),
                  ('app/dist/main.js',b'new-waha',0o644,0,tarfile.REGTYPE),('app/gows',b'new-go',0o755,0,tarfile.REGTYPE)]
        candidate_raw = layer(values if entries is None else entries(values))
        blob = lambda value: {'digest': 'sha256:' + hashlib.sha256(value).hexdigest(), 'size': len(value)}
        base_layer, new_layer = blob(base_raw), blob(candidate_raw)
        base_manifest = {'layers': [base_layer] * 12}
        manifest = {'layers': [base_layer] * 12 + [new_layer]}
        base_config = {'config': {'User': '1000', 'Env': ['ORIGINAL=true']}, 'rootfs': {'diff_ids': [base_layer['digest']] * 12}}
        config = {**copy.deepcopy(base_config), 'os': 'linux', 'architecture': 'amd64'}
        config['rootfs']['diff_ids'].append(new_layer['digest'])
        if config_mutate: config_mutate(config)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as archive:
            for value in (base_raw, candidate_raw):
                item = tarfile.TarInfo('blobs/sha256/' + hashlib.sha256(value).hexdigest()); item.size = len(value)
                archive.addfile(item, io.BytesIO(value))
        raw.seek(0)
        runtime = {'main.js': hashlib.sha256(b'new-waha').hexdigest(), 'unchanged.js': 'a' * 64}
        with tarfile.open(fileobj=raw) as archive:
            return B.verify_overlay(archive, manifest, config, base_manifest, base_config, runtime, hashlib.sha256(b'new-go').hexdigest())

    def test_exact_delta_with_unchanged_copy_omitted(self): self.assertEqual(self.check(), (1, 2))

    def test_layer_negatives(self):
        changes = [
            lambda e: e + [('app/unexpected',b'x',0o644,0,tarfile.REGTYPE)],
            lambda e: e[:2] + [('app/dist/main.js',b'new-waha',0o644,1000,tarfile.REGTYPE)] + e[3:],
            lambda e: e[:2] + [('app/dist/main.js',b'new-waha',0o755,0,tarfile.REGTYPE)] + e[3:],
            lambda e: e[:2] + [('app/dist/main.js',b'wrong',0o644,0,tarfile.REGTYPE)] + e[3:],
            lambda e: e + [e[-1]],
            lambda e: e[:-1],
            lambda e: e[:2] + e[3:],
            lambda e: e + [('app/dist/link',b'',0o644,0,tarfile.SYMTYPE)],
        ]
        for index, change in enumerate(changes):
            with self.subTest(index=index), self.assertRaises(RuntimeError): self.check(change)

    def test_config_and_base_chain_change_rejected(self):
        for change in (lambda c:c['config'].update(User='0'), lambda c:c['rootfs']['diff_ids'].__setitem__(0,'sha256:'+'0'*64)):
            with self.assertRaises(RuntimeError): self.check(config_mutate=change)

def observed():
    return {'id': 'a'*64, 'image': 'b'*64, 'labels': {Q.LABEL: 'nonce'}, 'state': {'Running': True, 'ExitCode': 0, 'OOMKilled': False},
        'user': '1000:1000', 'effective_caps': [], 'bounding_caps': [], 'environment': ['WHATSAPP_START_SESSION=', 'WAHA_API_KEY=synthetic'],
        'host': {'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'PortBindings':{},'Memory':1073741824,'PidsLimit':256,'SecurityOpt':['no-new-privileges'],'NanoCpus':2000000000,'Tmpfs':{'/run/qualification':'rw,nosuid,nodev,size=536870912,mode=1777'}},
        'mounts': [{'Type':'bind','Source':str(SYNTHETIC_ROOT/'offline'),'Destination':'/opt/offline','RW':False}]}

class RuntimeTests(NoContainers):
    def test_isolation_and_negatives(self):
        expected = {'WHATSAPP_START_SESSION': '', 'WAHA_API_KEY': 'synthetic'}
        self.assertEqual(Q.isolation(observed(), SYNTHETIC_ROOT, expected)['network'], 'none')
        changes = [lambda x:x['host'].update(NetworkMode='bridge'),lambda x:x['host'].update(ReadonlyRootfs=False),
            lambda x:x['host']['Tmpfs'].update({'/tmp':'rw'}),lambda x:x['mounts'][0].update(RW=True),
            lambda x:x.update(effective_caps=['CAP_CHOWN']),lambda x:x.update(user='0'),
            lambda x:x.update(environment=['WHATSAPP_START_SESSION=default']),lambda x:x['host'].update(NanoCpus=0),
            lambda x:x['mounts'].append({'Type':'volume','Destination':'/app/.sessions'})]
        for index, change in enumerate(changes):
            value = observed(); change(value)
            with self.subTest(index=index), self.assertRaises(RuntimeError): Q.isolation(value,SYNTHETIC_ROOT,expected)

    def cleanup_case(self, running=True, exit_code=0, oom=False, foreign=False, stop_exit=0):
        value = observed(); value['state'].update(Running=running,ExitCode=exit_code,OOMKilled=oom)
        if foreign: value['labels'][Q.LABEL] = 'foreign'
        calls = []
        def run(*args, **kwargs):
            calls.append(args)
            if args[0] == 'inspect': return SimpleNamespace(returncode=0,stdout=json.dumps(value))
            if args[0] == 'stop':
                value['state'].update(Running=False,ExitCode=stop_exit)
                return SimpleNamespace(returncode=0,stdout='')
            return SimpleNamespace(returncode=1 if args[0] == 'container' else 0,stdout='')
        try: result = Q.cleanup(run, value['id'], 'nonce', 'sha256:'+'b'*64, True)
        finally:
            if foreign: self.assertFalse(any(c[0] in ('stop','rm') for c in calls))
        self.assertIn(('rm','--force','a'*64),calls)
        return result

    def test_clean_stop_and_premature_exit_matrix(self):
        self.assertTrue(self.cleanup_case()['graceful_stop'])
        for code, oom in ((0,False),(1,False),(137,True)):
            with self.subTest(code=code): self.assertFalse(self.cleanup_case(False,code,oom)['graceful_stop'])
        self.assertFalse(self.cleanup_case(stop_exit=137)['graceful_stop'])

    def test_foreign_nonce_never_removed(self):
        with self.assertRaisesRegex(RuntimeError,'ownership'): self.cleanup_case(foreign=True)

    def test_podman_wrapper_cwd_timeout_and_bounded_error(self):
        row = {'user':'synthetic','uid':9999}
        with mock.patch('subprocess.run', return_value=SimpleNamespace(returncode=1,stdout='',stderr='z'*5000)) as process:
            with self.assertRaises(RuntimeError) as error: B.podman(row,'inspect','--format','{{json .ID}}','synthetic')
            self.assertLess(len(str(error.exception)),4200)
            self.assertEqual(process.call_args.kwargs['cwd'],'/')
            self.assertEqual(process.call_args.kwargs['timeout'],90)


def reporter_block(statements):
    """Exercise the preserved script's real gate without calling its main."""
    for index, node in enumerate(statements):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'tests' for t in node.targets):
            return statements[index:index + 4]
        for name in ('body', 'orelse', 'finalbody'):
            found = reporter_block(getattr(node, name, []))
            if found:
                return found
        for handler in getattr(node, 'handlers', []):
            found = reporter_block(handler.body)
            if found:
                return found


class ReporterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        statements = reporter_block(ast.parse(QUALIFY.read_text()).body)
        self.assertEqual(len(statements), 4)
        self.gate = compile(ast.Module(body=statements, type_ignores=[]), str(QUALIFY), 'exec')

    def accept(self, stdout, exit_code=0, stderr=''):
        command = mock.Mock(return_value=SimpleNamespace(returncode=exit_code, stdout=stdout, stderr=stderr))
        scope = {'run': command, 'container': 'synthetic-id', 'token': 'synthetic-private-key',
                 'out': self.root, 'require': Q.require, 're': re}
        try:
            exec(self.gate, scope)
            accepted = True
        except RuntimeError:
            accepted = False
        command.assert_called_once_with('exec', 'synthetic-id', 'node', '--test-reporter=tap',
                                        '/opt/offline/run-compiled-tests.cjs', timeout=90, check=False)
        self.assertEqual((self.root / 'compiled-tests.tap').read_text(),
                         (stdout + stderr).replace(scope['token'], '[synthetic-key]'))
        return accepted

    def test_reporter_is_explicit_and_seven_pass_are_required(self):
        self.assertTrue(self.accept('TAP version 13\n# tests 7\n# pass 7\n# fail 0\n'))
        for text in ('ℹ tests 7\nℹ pass 7\nℹ fail 0\n', '# pass 1\n# fail 0\n', '# pass 7\n# fail 1\n'):
            with self.subTest(text=text):
                self.assertFalse(self.accept(text))

    def test_nonzero_exit_keeps_tap_and_cannot_pass_on_summary(self):
        for exit_code in (1, 255):
            with self.subTest(exit_code=exit_code):
                self.assertFalse(self.accept('# pass 7\n# fail 0\n', exit_code, 'synthetic-private-key'))
                self.assertNotIn('synthetic-private-key', (self.root / 'compiled-tests.tap').read_text())

    @unittest.skipUnless(shutil.which('node'), 'Node is needed only for the synthetic reporter integration')
    def test_actual_node_reporter_with_seven_successes_and_one_failure(self):
        # This starts only local Node with seven tiny assertions. There are no
        # imports from WAHA, sessions, HTTP, RPC, processes or external services.
        fixture = self.root / 'synthetic.cjs'
        body = ("const test=require('node:test'),assert=require('node:assert/strict');"
                "for(let i=0;i<7;i++)test('synthetic '+i,()=>"
                "assert.ok(!(process.env.QA174_SYNTHETIC_FAIL==='yes'&&i===6))); ")
        fixture.write_text("const Module=require('node:module');"
                           "const filename='/synthetic/checkpoints/offline-ab/test.cjs';"
                           "const mod=new Module(filename,module);mod.filename=filename;"
                           "mod.paths=Module._nodeModulePaths('/synthetic/checkpoints/offline-ab');"
                           "mod._compile(" + json.dumps(body) + ",filename);\n")
        for failed in (False, True):
            with self.subTest(failed=failed):
                result = subprocess.run([shutil.which('node'), '--test-reporter=tap', str(fixture)],
                                        env=dict(os.environ, QA174_SYNTHETIC_FAIL='yes' if failed else 'no'),
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, int(failed), result.stdout + result.stderr)
                self.assertEqual(self.accept(result.stdout, result.returncode, result.stderr), not failed)


class AttestedScriptTests(NoContainers):
    def test_sanitized_recovery_scripts_match_reviewed_public_bytes(self):
        # Hashes identify the sanitized public compatibility corpus, not
        # executable artifacts from a private production qualification.
        expected = {
            'build_gows_harness.py': 'b7a99cb1bd51ef02a10b2d74662fde8c16be7860d0c03253c027210d64a4f1e0',
            'complete_remaining_packages.py': '18b7dc587be1e339edc593fffdc4587fe7b5a46d1c1a352e84e2e6d1cbeb9003',
            'server-build.py': 'f793e224bb58b3018505d801b145a698a5b2706314ae40769dfc15a3df4123ff',
            # The original input seal includes v1. Only v2 qualified successfully.
            'server-qualify.py': 'd036a9be8ea77559f0dd54a746e698c4c5d43d4dbe2297ff11467919b7129a8f',
            'server-qualify-v2.py': 'f39287271f03164ef5bafcbdf5599cb303bc982be5ce3844dcad91599c19ef79',
            'run-compiled-tests.cjs': 'aff801181c7835d105dca033c87646fc1990399dd0524947327debef086a9042',
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((RECOVERED / name).read_bytes()).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
