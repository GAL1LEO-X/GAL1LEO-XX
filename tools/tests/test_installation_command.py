"""Cold offline compilers use the explicit profile without host installation files."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


PLUGIN = Path(__file__).resolve().parents[2] / 'plugins/whatsapp'
COMMAND = PLUGIN / 'scripts/installation_command.py'
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Protected public inputs require POSIX')


@pytest.mark.parametrize('name', ['alpha', 'bravo'])
def test_isolated_administration_compilers_materialize_configured_bundle_and_template(tmp_path, name):
    """Real CLI/file generation; no installed identity, services or legacy tree."""
    value = json.loads((PLUGIN / 'deploy/installation.example.json').read_bytes())
    value['paths'] = {
        'project': '/srv/' + name + '/application',
        'configuration': '/etc/' + name,
        'state': '/var/lib/' + name + '-data',
        'gateway': '/var/lib/' + name + '-gateway',
        'backup': '/opt/' + name + '-snapshots',
        'administration_code': '/usr/local/lib/' + name + '-administration',
        'administration_state': '/var/lib/' + name + '-administration',
    }
    value['services'] = {'prefix': name, 'recovery': name + '-recovery'}
    value['accounts'] = {'personal': name + '-owner', 'team': name + '-team'}
    if name == 'bravo':
        value['ports'] = {'personal': {'bridge': 22001, 'gateway': 22501},
                          'team': {'bridge': 23001, 'gateway': 23701}}
    profile = tmp_path / 'installation.json'
    profile.write_text(json.dumps(value))
    profile_bytes = profile.read_bytes()
    driver = '''import runpy,sys
def audit(event,args):
    if event=='open' and isinstance(args[0],str) and args[0].startswith((
        '/etc/whatsapp-installation','/etc/box-installation',
        '/srv/openai-codex','/var/lib/sally-browser')):
        raise AssertionError('Fresh compiler accessed an installed or legacy identity')
sys.addaudithook(audit)
sys.argv=sys.argv[1:]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    base = [sys.executable, '-I', '-B', '-c', driver, str(COMMAND),
            '--profile', str(profile), '--profile-sha256', hashlib.sha256(profile_bytes).hexdigest()]
    bundle = tmp_path / 'bundle'
    result = subprocess.run([*base, 'build-administration', '--source', str(PLUGIN),
        '--source-sha', 'a' * 40, '--output', str(bundle)],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['host_changed'] is False
    metadata = json.loads((bundle / 'bundle.json').read_bytes())
    canonical = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    assert metadata['installation_sha256'] == hashlib.sha256(canonical).hexdigest()
    assert metadata['generation']['destination'].startswith(value['paths']['administration_code'] + '/')
    for relative, item in metadata['artifacts'].items():
        assert hashlib.sha256((bundle / relative).read_bytes()).hexdigest() == item['sha256']
        assert '/srv/openai-codex' not in item['destination']
    template = subprocess.run([*base, 'compile-fresh-administration', '--',
        '--bundle', str(bundle), '--bundle-sha256', hashlib.sha256((bundle / 'bundle.json').read_bytes()).hexdigest(),
        '--source-revision', 'a' * 40, '--input-template'], capture_output=True, text=True, timeout=30)
    assert template.returncode == 0, template.stderr
    inputs = json.loads(template.stdout)
    assert inputs['mode'] == 'fresh' and inputs['attestation']['complete'] is False
    assert inputs['cgroups'] is None  # Requires an operator's actual observation.
    assert any(item['destination'] == '/etc/systemd/system/' + name + '-recovery.service'
               for item in metadata['artifacts'].values())
    assert value['paths']['project'] + '/private' in inputs['directory_modes']
    assert all('/srv/openai-codex' not in path for path in inputs['directory_modes'])
    assert profile.read_bytes() == profile_bytes


@pytest.mark.parametrize('command', ['render-runtime', 'render-host-plan'])
@pytest.mark.parametrize('expanded', [False, True])
def test_cold_compiler_binds_both_layout_modules_to_the_explicit_profile(tmp_path, command, expanded):
    profile = PLUGIN / 'deploy/installation.example.json'
    instance = PLUGIN / 'deploy/instance.example.json'
    profile_bytes = profile.read_bytes()
    instance_bytes = instance.read_bytes()
    configuration = json.loads(instance_bytes)
    selection = []
    if expanded:
        configuration.update(slug='later', bridge_port=22001, public_hostname='later.example.org',
                             oauth_client_id='later-mcp', pairing_client_id='later-link')
        instance = tmp_path / 'later-instance.json'
        instance.write_text(json.dumps(configuration))
        instance_bytes = instance.read_bytes()
        canonical = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        raw = canonical({'format': 'whatsapp-instance-roster-v1',
            'installation_sha256': hashlib.sha256(canonical(json.loads(profile_bytes))).hexdigest(),
            'revision': 1, 'previous': None,
            'instances': {'later': {'account': 'messages-later', 'bridge': 22001, 'gateway': 22009}}})
        roster = tmp_path / 'roster.json'
        roster.write_bytes(raw)
        selection = ['--roster', str(roster), '--roster-sha256', hashlib.sha256(raw).hexdigest()]
    if command == 'render-runtime':
        value = {'issuer': configuration['issuer'], 'jwks_uri': configuration['jwks_url'],
                 'authorization_endpoint': configuration['issuer'] + '/authorize',
                 'token_endpoint': configuration['issuer'] + '/token'}
        option = '--discovery'
    else:
        value = {'operation_id': 'a' * 32,
                 'generation': {'path': '/usr/local/lib/develative-host-components/' + 'b' * 64,
                                'sha256': 'b' * 64},
                 'dns': {'address': '192.0.2.1', 'zone': 'example.org',
                         'local_resolver': '127.0.0.1', 'public_resolver': '192.0.2.2'},
                 'tools': {name: {'path': '/usr/bin/' + name, 'sha256': 'c' * 64}
                           for name in ('dig', 'certbot')}, 'qos': None}
        value['tools']['python'] = {'path': '/usr/bin/python3', 'sha256': 'd' * 64}
        option = '--context'
    context = tmp_path / 'public-input.json'
    context.write_text(json.dumps(value))
    output = tmp_path / 'compiled'
    # Refuse even a read of either installed product's identity. A compiler
    # preparing a new installation cannot depend on the executing host's mode.
    driver = '''import runpy,sys
def audit(event,args):
    if event=='open' and isinstance(args[0],str) and args[0].startswith(('/etc/whatsapp-installation','/etc/box-installation')):
        raise AssertionError('Offline compiler read an installed product identity')
sys.addaudithook(audit)
sys.argv=sys.argv[1:]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', driver, str(COMMAND),
        '--profile', str(profile), '--profile-sha256', hashlib.sha256(profile_bytes).hexdigest(),
        *selection,
        command, '--instance', str(instance), option, str(context), '--output', str(output)],
        capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['host_changed'] is False
    assert profile.read_bytes() == profile_bytes and instance.read_bytes() == instance_bytes
    if command == 'render-runtime':
        bridge = (output / 'bridge.txt').read_text()
        assert 'WorkingDirectory=/srv/messages/app' in bridge
        assert 'ExecStart=/srv/messages/app/.venv/bin/python' in bridge
        assert '/srv/openai-codex/projects/whatsapp-personal' not in bridge
        assert json.loads((output / 'instance.json').read_bytes())['installation'] == json.loads(profile_bytes)
    else:
        plan = json.loads(output.read_bytes())
        assert plan['qos'] is None
        assert plan['instance']['account'] == ('messages-later' if expanded else 'messages-owner')
        assert plan['instance']['gateway_port'] == (22009 if expanded else 19009)
        assert plan['frontend']['webroot'] == '/var/www/messages-' + ('later' if expanded else 'personal') + '-acme'
        if expanded:
            assert plan['allocation_sha256'] == hashlib.sha256(raw).hexdigest()


def test_host_plan_can_select_only_exact_isolated_certificate_store():
    # The compiler's certificate choice changes public paths, never grants
    # permission to run Certbot or installs an issuer/recovery service.
    import importlib.util
    spec=importlib.util.spec_from_file_location('isolated_plan_compiler',COMMAND)
    compiler=importlib.util.module_from_spec(spec);spec.loader.exec_module(compiler)
    from types import SimpleNamespace
    instance=SimpleNamespace(hostname='wa.example.test',slug='personal',service_user='wa-owner',
                             bridge_port=19001,gateway_port=19009,base='wa-personal',
                             _installation_identity=SimpleNamespace(roster_sha256=None))
    context={'operation_id':'a'*32,'generation':{'path':'/usr/local/lib/develative-host-components/'+'b'*64,'sha256':'b'*64},
        'dns':{'address':'192.0.2.1','zone':'example.test','local_resolver':'127.0.0.1','public_resolver':'192.0.2.2'},
        'tools':{name:{'path':'/usr/bin/'+name,'sha256':'c'*64} for name in ('dig','certbot','python')},
        'qos':None,'certificates':'isolated'}
    context['tools']['python']['path']='/usr/bin/python3'
    result=compiler.host_plan(instance,context)
    assert result['frontend']['lineage']=='/etc/develative-certificates/live/wa.example.test'
    assert result['frontend']['certificates']=='isolated'
    context['certificates']='arbitrary-root'
    with pytest.raises(ValueError):compiler.host_plan(instance,context)
