"""Synthetic multi-instance barriers and receipt/crash boundaries; no host commands."""
import asyncio
import copy
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'plugins/whatsapp/scripts' / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
hooks = module('new_whatsapp_hooks', 'deploy_hooks.py')
runtime = module('new_whatsapp_runtime', 'deploy_runtime.py')


def fixture(root, phase='maintenance', committed=False):
    config = {'format': 'whatsapp-deploy-profile-v1', 'cutover_verified': True, 'app': 'whatsapp',
              'target_id': 'gal1leo-server-01', 'schema': 8, 'provider_policy_sha256': 'f' * 64,
              'engine_root': str(root), 'gate': str(root / 'gates/whatsapp'), 'current': str(root / 'current'),
              'runtime_entrypoint': '/usr/local/lib/whatsapp-deploy/deploy_runtime.py',
              'tenant_helper': '/usr/local/lib/whatsapp-deploy/tenant_database.py', 'python': '/usr/bin/python3.13',
              'build_uid': 976, 'build_gid': 976, 'instances': []}
    for slug, uid, port in [('personal', 978, 8820), ('secondary', 977, 8822)]:
        config['instances'].append({'slug': slug, 'uid': uid, 'gid': uid, 'user': 'whatsapp-' + slug,
                                    'unit': 'whatsapp-' + slug + '.service', 'config': '/etc/whatsapp/' + slug + '/config.toml',
                                    'database': '/var/lib/whatsapp-data/' + slug + '/archive.sqlite',
                                    'provider_state': '/var/lib/whatsapp-gateway/' + slug, 'port': port, 'gateway_port': port + 1})
    operation = root / 'operations' / ('a' * 64); operation.mkdir(parents=True)
    release = root / 'releases' / ('b' * 64); release.mkdir(parents=True)
    (root / 'gates').mkdir()
    context = {'format': 'deploy-context-v1', 'app': 'whatsapp', 'target_id': config['target_id'], 'operation_id': 'a' * 64,
               'phase': phase, 'kind': 'deploy', 'committed': committed, 'schema_before': 8, 'schema_after': 8,
               'operation_dir': str(operation), 'previous': None,
               'release': {'id': 'b' * 64, 'path': str(release), 'commit': 'c' * 40, 'package_sha256': 'b' * 64,
                           'manifest': {'app': 'whatsapp', 'commit': 'c' * 40, 'version': '0.8.0',
                                        'data': {'schema': 8, 'readable_schemas': [8]}}}}
    return config, context


@unittest.skipIf(os.name == 'nt', 'POSIX adapter filesystem proof runs in Linux/WSL')
class AdapterTests(unittest.TestCase):
    def test_restore_rejects_unqualified_previous_runtime_before_data_or_service_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory), 'restore'); context['kind'] = 'recovery'
            adapter = hooks.Adapter(config, context, host=False); adapter.gate.write_text('closed')
            with patch.object(hooks, 'qualified_runtime', side_effect=ValueError('qualified_runtime_changed')) as qualify, \
                 patch.object(hooks, 'command') as command, patch.object(adapter, 'replace_snapshot') as replace:
                with self.assertRaisesRegex(ValueError, 'qualified_runtime_changed'): adapter.restore()
                qualify.assert_called_once_with(adapter.release_path / 'runtime', adapter.release)
                command.assert_not_called(); replace.assert_not_called()
            self.assertTrue(adapter.gate.exists())

    def test_committed_recovery_reopen_rejects_altered_runtime_before_opening(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory), 'reopen', True); context['kind'] = 'recovery'
            adapter = hooks.Adapter(config, context, host=False); adapter.gate.write_text('closed')
            tree = adapter.release_path / 'runtime'; tree.mkdir()
            code = tree / 'application.py'; code.write_text('qualified previous release')
            inventory = hooks.runtime_inventory
            hooks.save(tree / 'qualified.json', {'commit': adapter.release['commit'],
                       'package_sha256': adapter.release['package_sha256'],
                       'files': inventory(tree, trusted_uid=os.getuid())}, 0o644)
            code.write_text('altered after recovery commit')
            with patch.object(hooks, 'protected', side_effect=lambda path, **kwargs: Path(path)), \
                 patch.object(hooks, 'runtime_inventory', side_effect=lambda path: inventory(path, trusted_uid=os.getuid())), \
                 patch.object(adapter, 'health_once') as health, patch.object(adapter, 'restore') as restore, \
                 patch.object(hooks.time, 'sleep') as sleep:
                with self.assertRaisesRegex(ValueError, 'qualified_runtime_changed'): adapter.execute('reopen', 'run')
                health.assert_not_called(); restore.assert_not_called(); sleep.assert_not_called()
            self.assertTrue(adapter.gate.exists())

    def test_recovery_activation_restarts_running_failed_rollback_target(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory), 'activate'); context['kind'] = 'recovery'
            adapter = hooks.Adapter(config, context, host=False); adapter.gate.write_text('closed')
            adapter.state['active'] = [item['unit'] for item in adapter.instances]
            running = {unit: 'failed-rollback-release' for unit in adapter.state['active']}
            current = ['failed-rollback-release']; events = []
            def systemctl(args):
                events.append(args[1])
                for unit in args[2:]:
                    if args[1] == 'stop': running[unit] = None
                    elif args[1] == 'start' and running[unit] is None: running[unit] = current[0]
            def point():
                events.append('point'); current[0] = 'restored-release'
            with patch.object(adapter, 'verify_identity'), patch.object(hooks, 'qualified_runtime', return_value=True), \
                 patch.object(adapter, 'all_stopped', side_effect=lambda: all(value is None for value in running.values())), \
                 patch.object(adapter, 'point_release', side_effect=point), patch.object(hooks, 'command', side_effect=systemctl):
                adapter.activate()
            self.assertEqual(events, ['stop', 'point', 'start'])
            self.assertEqual(set(running.values()), {'restored-release'})

    def test_redeploy_retained_package_reuses_only_intact_sealed_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory), 'prepare')
            adapter = hooks.Adapter(config, context, host=False)
            payload = adapter.release_path / 'payload'; payload.mkdir()
            (payload / 'provider-reference.json').write_text(json.dumps({'policy_sha256': config['provider_policy_sha256']}))
            tree = adapter.release_path / 'runtime'; (tree / 'venv/lib').mkdir(parents=True)
            (tree / 'venv/lib64').symlink_to('lib')
            code = tree / 'venv/application.py'; code.write_text('synthetic retained package B')
            original_inventory = hooks.runtime_inventory
            expected = original_inventory(tree, trusted_uid=os.getuid())
            hooks.save(tree / 'qualified.json', {'commit': context['release']['commit'],
                       'package_sha256': context['release']['package_sha256'], 'files': expected}, 0o644)
            with patch.object(adapter, 'config_identity', return_value={'personal': 'synthetic', 'secondary': 'synthetic'}), \
                 patch.object(adapter, 'active', return_value=True), patch.object(adapter, 'session', return_value='WORKING'), \
                 patch.object(hooks, 'protected', side_effect=lambda path, **kwargs: Path(path)), \
                 patch.object(hooks, 'runtime_inventory', side_effect=lambda path: original_inventory(path, trusted_uid=os.getuid())), \
                 patch.object(adapter, 'build_command') as build:
                # B was previously qualified, A is now current after rollback.
                adapter.prepare(); build.assert_not_called()
                code.write_text('changed after qualification')
                with self.assertRaisesRegex(ValueError, 'qualified_runtime_changed'): adapter.prepare()
                build.assert_not_called()

    def test_precommit_restore_replaces_corrupt_db_using_validated_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory), 'restore'); context['kind'] = 'recovery'
            adapter = hooks.Adapter(config, context, host=False)
            target = Path(directory) / 'archive.sqlite'; target.write_bytes(b'not a database')
            source = adapter.operation / 'personal-before.sqlite'
            with sqlite3.connect(source) as db:
                db.execute('CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT)')
                db.execute('INSERT INTO state VALUES (?,?)', ('private:technical_state_identity:v1', '{"id":"synthetic"}'))
                db.execute('PRAGMA user_version=8')
            item = {**adapter.instances[0], 'database': str(target), 'uid': os.getuid(), 'gid': os.getgid()}
            adapter.state['identity'] = {'personal': 'verified-profile'}
            class Directory:
                def __enter__(self): self.fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY); return self.fd
                def __exit__(self, *args): os.close(self.fd)
            helper = SimpleNamespace(physical_directory=lambda path: Directory(),
                                     tenant_context=lambda tenant: {'expected': {'id': 'synthetic'}})
            validations = []
            def validate(path, expected, uid, gid, python):
                with sqlite3.connect(path) as db:
                    self.assertEqual(db.execute('PRAGMA integrity_check').fetchone(), ('ok',))
                    self.assertEqual(json.loads(db.execute('SELECT value FROM state').fetchone()[0]), expected)
                validations.append(path)
            with patch.object(hooks, 'protected', side_effect=lambda path, **kwargs: Path(path)), \
                 patch.object(adapter, 'configuration_files', return_value='verified-profile'), \
                 patch.object(adapter, 'tenant_helper', return_value=helper), patch.object(adapter, 'tenant', return_value='tenant'), \
                 patch.object(hooks, 'verify_snapshot', side_effect=validate), patch.object(hooks.os, 'fchown'):
                adapter.replace_snapshot({'path': str(source), 'sha256': hooks.sha(source)}, item)
            self.assertEqual(validations, [source])
            with sqlite3.connect(target) as db:
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone(), ('ok',))

    def test_sealing_rejects_symlink_escape_without_touching_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); tree = root / 'runtime'; tree.mkdir()
            outside = root / 'outside'; outside.write_text('unchanged'); before = outside.stat().st_mode
            (tree / 'escape').symlink_to(outside)
            with patch.object(hooks.os, 'fchown'), self.assertRaisesRegex(ValueError, 'symlink'):
                hooks.seal_runtime(tree)
            self.assertEqual(outside.read_text(), 'unchanged')
            self.assertEqual(outside.stat().st_mode, before)

    def test_sealing_rejects_external_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); tree = root / 'runtime'; tree.mkdir()
            outside = root / 'outside'; outside.write_text('unchanged'); before = outside.stat().st_mode
            os.link(outside, tree / 'hardlink')
            with patch.object(hooks.os, 'fchown'), self.assertRaisesRegex(ValueError, 'linked_file'):
                hooks.seal_runtime(tree)
            self.assertEqual(outside.stat().st_mode, before)

    def test_build_uid_survivor_blocks_sealing(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory); (proc / '123').mkdir()
            for position in range(4):
                values = [0, 0, 0, 0]; values[position] = 976
                (proc / '123/status').write_text('Uid:\t' + '\t'.join(map(str, values)) + '\n')
                with self.subTest(position=position), self.assertRaisesRegex(ValueError, 'surviving_processes'):
                    hooks.require_build_idle(976, proc)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux procfs identity regression')
    def test_nondumpable_build_process_uid_is_detected_from_status(self):
        code = ('import ctypes,json,os,sys; '
                'assert ctypes.CDLL(None).prctl(4,0,0,0,0)==0; '
                'print(json.dumps({"pid":os.getpid(),"uid":os.getuid(),'
                '"dumpable":ctypes.CDLL(None).prctl(3,0,0,0,0)}),flush=True); '
                'sys.stdin.readline()')
        process = subprocess.Popen([sys.executable, '-I', '-B', '-c', code], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            identity = json.loads(process.stdout.readline())
            self.assertEqual(identity['dumpable'], 0)
            with tempfile.TemporaryDirectory() as directory:
                proc = Path(directory)
                (proc / str(identity['pid'])).symlink_to('/proc/' + str(identity['pid']), target_is_directory=True)
                with self.assertRaisesRegex(ValueError, 'surviving_processes'):
                    hooks.require_build_idle(identity['uid'], proc)
        finally:
            try: process.communicate(input='\n', timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.communicate(timeout=5)

    def test_build_process_identity_inspection_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory); (proc / '123').mkdir()
            for value in ('Name:\tsynthetic\n', 'Uid:\t976\tinvalid\t976\t976\n'):
                (proc / '123/status').write_text(value)
                with self.assertRaisesRegex(ValueError, 'inspection_incomplete'):
                    hooks.require_build_idle(976, proc)
            with patch.object(Path, 'open', side_effect=PermissionError), \
                 self.assertRaisesRegex(ValueError, 'inspection_incomplete'):
                hooks.require_build_idle(976, proc)

    def test_build_process_identity_ignores_non_ascii_process_name(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory); (proc / '123').mkdir()
            (proc / '123/status').write_bytes(b'Name:\t\xff\xe2\x98\x83\nUid:\t1000\t1000\t1000\t1000\n')
            hooks.require_build_idle(976, proc)
            (proc / '123/status').write_bytes(b'Name:\t\xff\xe2\x98\x83\nUid:\t976\t976\t976\t976\n')
            with self.assertRaisesRegex(ValueError, 'surviving_processes'):
                hooks.require_build_idle(976, proc)

    def test_recovery_committed_context_reopens_previous_without_data_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory), 'reopen', True); context['kind'] = 'recovery'
            adapter = hooks.Adapter(config, context, host=False); adapter.gate.write_text('closed')
            observations = []
            with patch.object(adapter, 'health', side_effect=lambda ready=False: observations.append((ready, adapter.gate.exists()))), patch.object(adapter, 'restore') as restore:
                self.assertEqual(adapter.execute('reopen', 'run'), 'done')
                restore.assert_not_called()
            self.assertEqual(observations, [(False, True), (True, False)])

    def test_build_runs_as_isolated_transient_service_and_seals_no_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory), 'prepare')
            adapter = hooks.Adapter(config, context, host=False)
            with patch.object(hooks, 'command') as command:
                adapter.build_command('install', ['/synthetic/python', '-m', 'pip', 'install'], adapter.release_path / 'runtime')
            args = command.call_args.args[0]
            self.assertEqual(args[0], 'systemd-run')
            self.assertIn('--property=User=976', args)
            self.assertIn('--property=KillMode=control-group', args)
            self.assertIn('--property=PrivateNetwork=yes', args)
            self.assertIn('--property=NoNewPrivileges=yes', args)
            self.assertEqual(args[args.index('--') + 1:], ['/synthetic/python', '-m', 'pip', 'install'])

    def test_missing_cutover_or_shared_tenant_uid_or_gid_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory))
            invalid = copy.deepcopy(config); invalid['cutover_verified'] = False
            with self.assertRaisesRegex(ValueError, 'cutover'): hooks.Adapter(invalid, context, host=False)
            invalid = copy.deepcopy(config); invalid['instances'][1]['uid'] = invalid['instances'][0]['uid']
            with self.assertRaisesRegex(ValueError, 'overlap'): hooks.Adapter(invalid, context, host=False)
            invalid = copy.deepcopy(config); invalid['instances'][1]['gid'] = invalid['instances'][0]['gid']
            with self.assertRaisesRegex(ValueError, 'overlap'): hooks.Adapter(invalid, context, host=False)

    def test_schema_change_stops_before_any_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory)); context['schema_after'] = 9
            with patch.object(hooks, 'command') as command, self.assertRaisesRegex(ValueError, 'schema_change'):
                hooks.Adapter(config, context, host=False)
            command.assert_not_called()

    def test_effect_then_crash_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory))
            adapter = hooks.Adapter(config, context, host=False)
            def effect():
                adapter.gate.write_text('synthetic barrier')
                raise RuntimeError('synthetic crash after effect')
            with patch.object(adapter, 'maintenance', side_effect=effect) as mutate:
                with self.assertRaises(RuntimeError): adapter.execute('maintenance', 'run')
                self.assertEqual(mutate.call_count, 1)
            retried = hooks.Adapter(config, context, host=False)
            with patch.object(retried, 'maintenance') as mutate:
                self.assertEqual(retried.execute('maintenance', 'reconcile'), 'unknown')
                mutate.assert_not_called()
            self.assertTrue(adapter.gate.exists())

    def test_completed_effect_is_reconciled_without_repeat(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory))
            adapter = hooks.Adapter(config, context, host=False)
            with patch.object(adapter, 'maintenance') as mutate:
                self.assertEqual(adapter.execute('maintenance', 'run'), 'done')
            retried = hooks.Adapter(config, context, host=False)
            with patch.object(retried, 'maintenance') as mutate:
                self.assertEqual(retried.execute('maintenance', 'reconcile'), 'done')
                mutate.assert_not_called()

    def test_no_reopen_before_durable_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory), 'reopen')
            adapter = hooks.Adapter(config, context, host=False); adapter.gate.write_text('closed')
            with self.assertRaisesRegex(ValueError, 'durable_commit'): adapter.reopen()
            self.assertTrue(adapter.gate.exists())

    def test_postcommit_restore_refused_without_host_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory), 'restore', True)
            adapter = hooks.Adapter(config, context, host=False)
            with patch.object(hooks, 'command') as command, self.assertRaisesRegex(ValueError, 'post_commit'):
                adapter.execute('restore', 'run')
            command.assert_not_called()

    def test_postcommit_crash_after_gate_removal_recovers_forward_observationally(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory), 'reopen', True)
            adapter = hooks.Adapter(config, context, host=False)
            adapter.state['steps']['reopen:' + context['release']['id']] = 'started'
            hooks.save(adapter.state_path, adapter.state)
            before = adapter.state_path.read_bytes()
            with patch.object(adapter, 'health') as health, patch.object(adapter, 'restore') as restore:
                self.assertEqual(adapter.execute('reopen', 'reconcile'), 'done')
                health.assert_called_once_with(ready=True); restore.assert_not_called()
            self.assertEqual(adapter.state_path.read_bytes(), before)

    def test_migrate_schema8_does_not_write_database_or_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            config, context = fixture(Path(directory), 'migrate')
            adapter = hooks.Adapter(config, context, host=False); adapter.gate.write_text('closed')
            with patch.object(adapter, 'all_stopped', return_value=True), patch.object(adapter, 'verify_identity'), patch.object(hooks, 'command') as command:
                adapter.migrate()
            self.assertEqual(command.call_count, 2)
            self.assertEqual([call.kwargs['uid'] for call in command.call_args_list], [978, 977])
            self.assertTrue(all('mode=ro' in call.args[0][4] for call in command.call_args_list))


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_barrier_blocks_admin_mcp_and_websockets_preserving_health_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            gate = Path(directory) / 'gate'; gate.write_text('closed'); event = asyncio.Event()
            calls = []
            async def app(scope, receive, send):
                calls.append(scope['path'])
                await send({'type': 'http.response.start', 'status': 200, 'headers': []})
                await send({'type': 'http.response.body', 'body': b'{}'})
            wrapped = runtime.ReleaseAdmission(app, event, gate, 'a' * 40)
            async def receive(): return {}
            for path in ('/mcp', '/admin', '/webhooks/gateway', '/connect'):
                sent = []
                async def send(value): sent.append(value)
                await wrapped({'type': 'http', 'path': path, 'method': 'GET'}, receive, send)
                self.assertEqual(sent[0]['status'], 503)
            self.assertEqual(calls, [])
            sent = []
            async def send(value): sent.append(value)
            await wrapped({'type': 'http', 'path': '/healthz', 'method': 'GET'}, receive, send)
            self.assertIn((b'x-whatsapp-release-commit', b'a' * 40), sent[0]['headers'])
            sent.clear()
            await wrapped({'type': 'websocket', 'path': '/stream'}, receive, send)
            self.assertEqual(sent, [{'type': 'websocket.close', 'code': 1013}])

    async def test_workers_wait_for_gate_removal_even_when_process_starts(self):
        with tempfile.TemporaryDirectory() as directory:
            gate = Path(directory) / 'gate'; gate.write_text('closed'); event = asyncio.Event()
            async def app(scope, receive, send):
                await asyncio.sleep(.02); self.assertFalse(event.is_set())
                gate.unlink(); await asyncio.wait_for(event.wait(), 1)
            async def noop(*args): pass
            await runtime.ReleaseAdmission(app, event, gate, 'a' * 40)({'type': 'lifespan'}, noop, noop)
            self.assertTrue(event.is_set())


class HTTPTests(unittest.TestCase):
    def test_gateway_key_is_not_forwarded_on_redirect(self):
        hits = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                hits.append(self.path)
                if self.path == '/session':
                    self.send_response(302); self.send_header('Location', '/unexpected'); self.end_headers()
                else:
                    self.send_response(200); self.end_headers(); self.wfile.write(b'{}')
        server = HTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        try:
            request = hooks.urllib.request.Request('http://127.0.0.1:' + str(server.server_port) + '/session',
                                                   headers={'X-Api-Key': 'synthetic-test-key'})
            with self.assertRaises(hooks.urllib.error.HTTPError) as result:
                hooks.http_open(request)
            self.assertEqual(result.exception.code, 302)
            self.assertEqual(hits, ['/session'])
        finally:
            server.shutdown(); server.server_close(); worker.join()


if __name__ == '__main__': unittest.main()
