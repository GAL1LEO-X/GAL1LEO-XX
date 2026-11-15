"""Synthetic receipts only: these tests never start Docker or open a network."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
from unittest.mock import patch

import pytest

from tools.whatsapp_release_common import ReleaseError
from tools import whatsapp_release_runtime as runtime


def encoded(value):
    return json.dumps(value).encode()


def descriptor(data):
    return {'digest': 'sha256:' + hashlib.sha256(data).hexdigest(), 'size': len(data)}


@pytest.fixture
def inputs(tmp_path):
    layer = b'synthetic layer, never passed to a real Docker daemon'
    config = encoded({'os': 'linux', 'architecture': 'amd64',
                      'config': {'Env': ['WAHA_WORKER_RESTART_SESSIONS=true']},
                      'rootfs': {'type': 'layers', 'diff_ids': [descriptor(layer)['digest']]}})
    manifest = encoded({'schemaVersion': 2, 'config': descriptor(config), 'layers': [descriptor(layer)]})
    blobs = {descriptor(value)['digest'][7:]: value for value in (layer, config, manifest)}
    archive = tmp_path / 'runtime.tar'
    files = {'oci-layout': encoded({'imageLayoutVersion': '1.0.0'}),
             'index.json': encoded({'schemaVersion': 2, 'manifests': [descriptor(manifest)]}),
             'manifest.json': encoded([{'Config': 'blobs/sha256/' + descriptor(config)['digest'][7:],
                                        'Layers': ['blobs/sha256/' + descriptor(layer)['digest'][7:]]}]),
             **{'blobs/sha256/' + key: value for key, value in blobs.items()}}
    with tarfile.open(archive, 'w') as handle:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            handle.addfile(member, io.BytesIO(data))
    metadata = {'archive_sha256': runtime._sha(archive), 'archive_bytes': archive.stat().st_size,
                'manifest_digest': descriptor(manifest)['digest'], 'config_digest': descriptor(config)['digest'],
                'gows_sha256': 'c' * 64, 'target_commit': 'a' * 40, 'workflow_commit': 'b' * 40}
    snapshot = tmp_path / 'snapshot'
    snapshot.mkdir()
    (snapshot / 'synthetic-source.py').write_text('synthetic = True\n')
    return archive, metadata, snapshot, tmp_path / 'qualification'


class FakeCommands:
    """Fixed expected responses, with injected faults at observable boundaries."""
    def __init__(self, inputs, fault=None):
        self.archive, self.metadata, self.snapshot, self.output = inputs
        self.fault, self.commands, self.container_env = fault, [], {}
        self.nonce, self.token = None, None
        self.identity = 'd' * 64

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        assert kwargs['env'] == runtime._environment(self.output, self.snapshot if command[0] == '/chosen/python' else None)
        assert not any('TOKEN' in key or 'ACTIONS' in key or 'PROXY' in key for key in kwargs['env'])
        assert kwargs['capture_output'] and kwargs['timeout'] > 0
        if command[0] == '/chosen/python':
            assert kwargs['cwd'] == self.snapshot
            if '-m' in command:
                (self.output / 'backend.xml').write_text('<testsuites><testsuite tests="3" failures="0" errors="0"/></testsuites>')
                return subprocess.CompletedProcess(command, 1 if self.fault == 'backend' else 0, 'synthetic pytest', '')
            if self.fault == 'source-change':
                (self.snapshot / 'synthetic-source.py').write_text('changed = True\n')
            return subprocess.CompletedProcess(command, 0, json.dumps({'passed': True, 'version': 'gows-ab-v1',
                                                                      'operations': ['synthetic-operation']}), '')
        assert command[:2] == list(runtime.DOCKER)
        args = command[2:]
        if args[0] == 'load':
            assert args[1:] == ['--input', str(self.archive)]
            value = 'Loaded exact synthetic image'
        elif args[:2] == ['image', 'inspect']:
            value = json.dumps([{'Id': 'sha256:' + 'f' * 64 if self.fault == 'image' else self.metadata['config_digest'],
                                 'Os': 'linux', 'Architecture': 'amd64',
                                 'Config': {'Env': ['WAHA_WORKER_RESTART_SESSIONS=true']}}])
        elif args[0] == 'create':
            for index, arg in enumerate(args):
                if arg == '--env':
                    name, value = args[index + 1].split('=', 1)
                    self.container_env[name] = value
            self.token = self.container_env['WAHA_API_KEY']
            self.nonce = args[args.index('--label') + 1].split('=', 1)[1]
            for flag in ('--pull=never', '--network=none', '--read-only', '--cap-drop=ALL',
                         '--security-opt=no-new-privileges', '--pids-limit=256', '--memory=1073741824'):
                assert flag in args
            assert args[-1] == self.metadata['config_digest']
            if self.fault == 'create-timeout':
                raise subprocess.TimeoutExpired(command, 300)
            value = self.identity
        elif args[0] == 'inspect':
            observed = {'Id': self.identity, 'Image': self.metadata['config_digest'],
                        'Config': {'Image': self.metadata['config_digest'], 'User': '1000:1000',
                                   'Labels': {'org.plugins.whatsapp.qualification': self.nonce},
                                   'Env': [name + '=' + value for name, value in self.container_env.items()]},
                        'HostConfig': {'NetworkMode': 'bridge' if self.fault == 'isolation' else 'none',
                                       'ReadonlyRootfs': True, 'CapDrop': ['ALL'],
                                       'SecurityOpt': ['no-new-privileges'], 'Memory': 1073741824, 'PidsLimit': 256,
                                       'Tmpfs': {'/run/qualification': 'rw,nosuid,nodev,size=536870912,mode=1777'}},
                        'Mounts': [{'Type': 'bind', 'Source': str(Path(runtime.__file__).parent.resolve()),
                                    'Destination': '/opt/offline', 'RW': False}], 'State': {'Running': True}}
            if self.fault == 'wrong-owner':
                observed['Config']['Labels'] = {}
            value = json.dumps([observed])
        elif args[0] == 'start':
            value = self.identity
        elif args[0] == 'exec' and args[-1] == '/opt/offline/probe-runtime.cjs':
            evidence = {'scope': 'isolated-no-account-runtime', 'liveWhatsApp': False,
                        'authenticatedStatus': 200, 'unauthenticatedStatus': 401, 'sessions': [], 'uid': 1000,
                        'gows': {'sha256': self.metadata['gows_sha256']}, 'lifecycleGuard': {'attempts': 0},
                        'audio': {'decoded': True},
                        'abContract': {'version': 'gows-ab-v1', 'operations': ['synthetic-operation']}}
            if self.fault == 'probe':
                evidence['lifecycleGuard']['attempts'] = 1
            value = 'synthetic debug ' + self.token + '\n' + json.dumps(evidence)
        elif args[0] == 'exec':
            value = ''
        elif args[0] == 'logs':
            value = 'synthetic startup ' + self.token
        elif args[0] == 'rm':
            assert args == ['rm', '--force', self.identity]
            return subprocess.CompletedProcess(command, 1 if self.fault == 'cleanup' else 0, '', '')
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, value, '')


def invoke(inputs, fake):
    with patch.object(runtime.subprocess, 'run', side_effect=fake), patch.dict('os.environ', {'GH_TOKEN': 'must-not-leak'}):
        return runtime.qualify_runtime(*inputs, python_executable='/chosen/python')


def test_real_commands_required_success_receipt_and_sanitized_logs(inputs):
    fake = FakeCommands(inputs)
    result = invoke(inputs, fake)
    assert result['passed'] and result['container_removed']
    assert result['target_commit'] == inputs[1]['target_commit']
    assert result['runtime_config_digest'] == inputs[1]['config_digest']
    assert all(check['executed'] and check['passed'] for check in result['checks'].values())
    assert any(command[2:3] == ['load'] for command in fake.commands)
    assert any(command[2:3] == ['start'] for command in fake.commands)
    for path in inputs[3].iterdir():
        if path.is_file():
            assert fake.token not in path.read_text()
            assert 'must-not-leak' not in path.read_text()


@pytest.mark.parametrize('fault', ['backend', 'image', 'isolation', 'probe', 'cleanup', 'source-change', 'create-timeout', 'wrong-owner'])
def test_failures_never_create_a_pass_and_remove_only_owned_container(inputs, fault):
    fake = FakeCommands(inputs, fault)
    with pytest.raises(ReleaseError):
        invoke(inputs, fake)
    result = json.loads((inputs[3] / 'result.json').read_text())
    assert result['passed'] is False
    removals = [command for command in fake.commands if command[2:3] == ['rm']]
    if fault in {'backend', 'image', 'wrong-owner'}:
        assert removals == []
    else:
        assert len(removals) == 1 and removals[0][-1] == fake.identity
    if fault in {'backend', 'image', 'isolation', 'wrong-owner', 'create-timeout'}:
        assert not any(command[2:3] == ['start'] for command in fake.commands)


@pytest.mark.parametrize('field', ['archive_sha256', 'config_digest', 'manifest_digest'])
def test_pinned_archive_and_image_validation_precede_any_subprocess(inputs, field):
    inputs[1][field] = ('sha256:' if field.endswith('digest') else '') + 'e' * 64
    with patch.object(runtime.subprocess, 'run') as commands, pytest.raises(ReleaseError):
        runtime.qualify_runtime(*inputs)
    commands.assert_not_called()


def test_existing_output_is_never_overwritten(inputs):
    inputs[3].mkdir()
    marker = inputs[3] / 'keep'
    marker.write_text('original')
    with patch.object(runtime.subprocess, 'run') as commands, pytest.raises(ReleaseError):
        runtime.qualify_runtime(*inputs)
    commands.assert_not_called()
    assert marker.read_text() == 'original'


def test_snapshot_links_rejected_without_running_commands(inputs):
    (inputs[2] / 'link').symlink_to(inputs[0])
    with patch.object(runtime.subprocess, 'run') as commands, pytest.raises(ReleaseError):
        runtime.qualify_runtime(*inputs)
    commands.assert_not_called()


@pytest.mark.parametrize('name', ['GH_TOKEN', 'GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'HTTPS_PROXY'])
def test_image_must_not_reintroduce_host_or_ci_credentials(name):
    with pytest.raises(ReleaseError):
        runtime._image_environment({'Env': ['WAHA_WORKER_RESTART_SESSIONS=true', name + '=synthetic-forbidden']})


def test_guard_and_probe_preserve_no_account_policy():
    scripts = Path(runtime.__file__).parent
    guard = (scripts / 'lifecycle-guard.cjs').read_text()
    probe = (scripts / 'probe-runtime.cjs').read_text()
    assert "['start', 'restart', 'save', 'delete', 'unpair', 'logout']" in guard
    assert "method !== '/messages.MessageService/GetABContract'" in guard
    for method in ('makeClientStreamRequest', 'makeServerStreamRequest', 'makeBidiStreamRequest'):
        assert method in guard
    assert "fs.existsSync(`${markers}/blocked.jsonl`), false" in probe
    assert "assert.deepEqual(await authenticated.json(), [])" in probe
    assert "assert.deepEqual(await finalSessions.json(), [])" in probe
    assert 'process.getuid()' in probe
    for content in (guard, probe, Path(runtime.__file__).read_text()):
        assert '/workspace/' not in content and '/tmp/' not in content
        assert 'chmod' not in content and 'privileged=true' not in content
