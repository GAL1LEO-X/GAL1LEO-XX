"""Cold diagnostic and potential installer gates for a synthetic 0.6 journal.

The reported host failure was a direct read/validator diagnostic, not an
installer run. CLI inspect is a separate static check and never scans journals.
The additional concrete AdminHost gate below qualifies its potential impact.
"""
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
# A baseline witness may point this test-only constant at an immutable exported
# installer closure. Normal collection always exercises the current checkout.
INSTALLER_REPOSITORY = ROOT


SETUP = r'''
import copy, hashlib, importlib.util, json, os, runpy, shutil, sqlite3, sys
from pathlib import Path
repository, installer_repository, directory = map(Path, sys.argv[1:])
suite = runpy.run_path(str(repository/'tools/tests/test_admin_compile.py'))
inputs, bundle, profile_path, old, current = suite['make_fixture'](
    directory, 'whatsapp', 'upgrade', uid=os.getuid(), gid=os.getgid())
import admin_compile as compiler
import admin_handoff as handoff
import installation_layout as layout
from host.lifecycle import filesystem
profile = layout.active()
sha = lambda raw: hashlib.sha256(raw).hexdigest()
body = compiler.common.encoded(inputs)
files = compiler.compile_operation(bundle, source_revision='a'*40,
    metadata_sha256=sha((bundle/'bundle.json').read_bytes()), input_bytes=body,
    inputs_sha256=sha(body), mode='upgrade', uid=os.getuid(), gid=os.getgid(),
    source_root=installer_repository)
operation = json.loads(files['operation.json'])
base = directory/'root'; base.mkdir(mode=0o700)
def put(logical, content, mode=0o600):
    target = base/logical.lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content); target.chmod(mode)
    return target
for logical, metadata in old['manifest']['directories'].items():
    target = base/logical.lstrip('/')
    target.mkdir(parents=True, exist_ok=True); target.chmod(metadata['mode'])
for logical, content in old['payloads'].items():
    put(logical, content, old['manifest']['files'][logical]['mode'])
put(str(layout.IDENTITY), layout.identity_bytes(profile))
put(str(layout.PROFILE), layout.encoded(profile.as_dict()))
put(handoff.OWNER, handoff.encoded(inputs['previous_owner']), operation['plan']['owner_metadata']['mode'])
for filename, logical in json.loads(files['compilation.json'])['attestation_destinations'].items():
    put(logical, files[filename])
put('/operation.json', files['operation.json'])

# Generate the tenant rows through the official 0.6 producer. Only its registry
# read is projected into the anchored fixture; all returned paths stay logical.
import github_release as release
import release_transaction as transaction
import release_database as database
runtime = Path(profile.path('project'))
registry = {'instances': {slug: {'spec': {'slug': slug,
    'bridge_port': profile.instance_ports(slug)['bridge'], 'installation': profile.as_dict(),
    'auth_mode': 'external-oidc'}} for slug in profile.as_dict()['accounts']}}
registry_path = put(str(runtime/'private/tenants.json'), json.dumps(registry).encode())
original_read_text = Path.read_text
def read_registry(path, *args, **kwargs):
    return original_read_text(registry_path if path == runtime/'private/tenants.json' else path,
                              *args, **kwargs)
Path.read_text = read_registry
try:
    registered = release.instances(runtime)
finally:
    Path.read_text = original_read_text
assert len(registered) == 2 and all(len(row) == 7 for row in registered)
personal = registered[0]
assert {key: str(personal[key]) for key in ('slug', 'unit', 'base', 'port', 'config', 'wrapper')} == {
    'slug': 'personal', 'unit': 'whatsapp-personal.service', 'base': 'whatsapp-personal',
    'port': '19001', 'config': '/etc/whatsapp/personal/config.toml',
    'wrapper': '/srv/whatsapp/app/scripts/as-user'}
# The second tenant "team", its account and ports are public synthetic values;
# they are not attributed to the reported Example user installation.
candidate = directory/'candidate'; candidate.mkdir()
schema = 'CREATE TABLE messages(id TEXT PRIMARY KEY);PRAGMA user_version=8;'
for name in transaction.ENTRIES:
    target = candidate/name
    if name in ('.venv', 'sally_whatsapp'): target.mkdir()
    else: target.write_text('# synthetic candidate source\n')
(candidate/'sally_whatsapp/store.py').write_text('SCHEMA='+repr(schema)+'\n')
(candidate/'deploy').mkdir()
(candidate/'deploy/migrations.json').write_text(json.dumps({'schemaVersion': 8, 'migrations': []}))
record = directory/'producer-record'
journal_path = str(compiler.common.STATE)+'/transaction.json'
transaction.JOURNAL = base/journal_path.lstrip('/')
original_checkpoint = transaction.checkpoint
original_exists = Path.exists
captured = []
class Prepared(BaseException): pass
def checkpoint(plan, phase):
    original_checkpoint(plan, phase)
    assert phase == 'prepared'
    captured.append(copy.deepcopy(plan))
    raise Prepared()
def no_dropin(path):
    return False if str(path).startswith('/etc/systemd/system/whatsapp-') else original_exists(path)
def forbidden(*args, **kwargs):
    raise AssertionError('Synthetic journal preparation attempted a service or activation effect')
transaction.checkpoint = checkpoint
transaction.run = transaction.gate_on = forbidden
Path.exists = no_dropin
try:
    transaction.activate(runtime, candidate, registered, registered,
        {row['slug']: 'WORKING' for row in registered}, '0.5.0', '0.6.0', record,
        forbidden, forbidden, forbidden, source_commit='c6a91b929b73afbd8864df5df1d1212d253439f7')
except Prepared:
    pass
finally:
    Path.exists = original_exists
    transaction.checkpoint = original_checkpoint
assert len(captured) == 1
journal = captured[0]
# This is a terminal SHAPE fixture, not a completed activation. Its prepared
# structure and durable serializers are real, and its SQLite evidence comes
# from real snapshot/migrate calls; no service or application was activated.
for row in registered:
    original = directory/(row['slug']+'-source.sqlite')
    with sqlite3.connect(original) as connection:
        connection.executescript(schema)
        connection.execute('INSERT INTO messages VALUES (?)', ('synthetic-preserved-id',))
    backup = record/(row['slug']+'-before.sqlite')
    migrated = record/(row['slug']+'-candidate.sqlite')
    database.snapshot(original, backup)
    shutil.copyfile(backup, migrated)
    migration = database.migrate(migrated, candidate)
    journal['databases'].append({'path': profile.instance_paths(row['slug'])['state']+'/archive.sqlite',
        'backup': backup.name, 'sha256': sha(backup.read_bytes()), 'migrated': migrated.name,
        'migration': migration})
journal['frozen'] = True
transaction.checkpoint(journal, 'published')
assert json.loads(transaction.JOURNAL.read_bytes()) == journal
context = {'base': str(base), 'operation_sha256': sha(files['operation.json']),
    'journal_path': journal_path, 'owner': handoff.OWNER,
    'attestation': operation['profile']['attestation']['path'],
    'producer_tenant_fields': sorted(journal['registered'][0]),
    'producer_version': journal['version'], 'second_tenant_is_synthetic': True}
(directory/'context.json').write_text(json.dumps(context))
'''


PROBE = r'''
import hashlib, importlib.util, json, sys
from pathlib import Path
repository, directory = map(Path, sys.argv[1:3])
action = sys.argv[3]
context = json.loads((directory/'context.json').read_bytes())
base = Path(context['base'])
source = repository/'plugins/whatsapp/scripts/admin_install.py'
spec = importlib.util.spec_from_file_location('synthetic_admin_install', source)
installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)
data = installer.bootstrap_read(base, '/operation.json')
header = installer.bootstrap_header(data, context['operation_sha256'])
installer.protect_sources(header['installer_sources'], require_root=False)
installer.load_modules(header['installer_sources'], root=base, authority=base.stat().st_uid)
operation, payloads, plan_digest = installer.decode_operation(data, context['operation_sha256'])
host = installer.admin_host
def forbidden(*args, **kwargs):
    raise AssertionError('Read-only journal admission attempted service or process IO')
try:
    if action == 'diagnostic':
        # The reported diagnostic was precisely Path(...).read_bytes → JSON →
        # validate_transaction_journal. Only the path is rooted in the fixture.
        host.JOURNALS = {key: str(base/path.lstrip('/')) for key, path in host.JOURNALS.items()}
        value = json.loads(Path(host.JOURNALS['transaction']).read_bytes())
        host.validate_transaction_journal(value)
    else:
        with installer.filesystem.Root(base) as root:
            installer.admin_handoff.require(
                installer.admin_handoff._owner_value(root, operation['plan'])
                    == operation['plan']['previous_owner'],
                'Existing owner differs from the approved inventory')
            provider = host.AdminHost(root, operation['profile'], readonly_runner=forbidden,
                                      service_runner=forbidden)
            provider.journals_terminal(operation['plan'])
except (OSError, ValueError, RuntimeError) as error:
    print(json.dumps({'action': action, 'accepted': False, 'error': str(error),
                      'error_type': type(error).__name__, 'services_called': False}))
else:
    print(json.dumps({'action': action, 'accepted': True, 'services_called': False}))
'''


def tree(root):
    import hashlib
    return {path.relative_to(root).as_posix():
        (path.lstat().st_mode, path.lstat().st_uid, path.lstat().st_gid, path.lstat().st_mtime_ns,
         path.readlink().as_posix() if path.is_symlink() else
         hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
        for path in (root, *sorted(root.rglob('*')))}


def scenario(tmp_path, change):
    setup = subprocess.run([sys.executable, '-I', '-B', '-c', SETUP, str(ROOT),
                            str(INSTALLER_REPOSITORY), str(tmp_path)],
                           capture_output=True, text=True, timeout=45)
    assert setup.returncode == 0, setup.stderr
    context = json.loads((tmp_path/'context.json').read_bytes())
    base = Path(context['base'])
    journal_path = base/context['journal_path'].lstrip('/')
    value = json.loads(journal_path.read_bytes())
    if change == 'historical6':
        for row in [*value['registered'], *value['selected']]: row.pop('auth_mode')
    elif change in ('mixed-seven-six', 'mixed-six-seven'):
        historical_index = 1 if change == 'mixed-seven-six' else 0
        for collection in ('registered', 'selected'):
            value[collection][historical_index].pop('auth_mode')
        assert value['registered'] == value['selected']
    elif change == 'unknown-auth':
        for row in [*value['registered'], *value['selected']]: row['auth_mode'] = 'future-provider'
    elif change == 'selected-auth':
        value['selected'][0]['auth_mode'] = 'managed-authelia'
    elif change == 'tenant-extra':
        for row in [*value['registered'], *value['selected']]: row['future_field'] = True
    journal_path.write_text(json.dumps(value))
    if change == 'owner-mode': (base/context['owner'].lstrip('/')).chmod(0o644)
    elif change == 'attestation-digest':
        (base/context['attestation'].lstrip('/')).write_bytes(b'{}\n')
    elif change == 'stale-installer':
        import hashlib
        operation = base/'operation.json'
        content = json.loads(operation.read_bytes())
        content['installer_sources']['plugins/whatsapp/scripts/admin_host.py'] = '0'*64
        raw = json.dumps(content).encode(); operation.write_bytes(raw)
        context['operation_sha256'] = hashlib.sha256(raw).hexdigest()
        (tmp_path/'context.json').write_text(json.dumps(context))
    before = tree(base)
    command = [sys.executable, '-I', '-B', str(INSTALLER_REPOSITORY/'plugins/whatsapp/scripts/admin_install.py'),
               'inspect', '--root', str(base), '--operation', '/operation.json',
               '--sha256', context['operation_sha256']]
    inspected = subprocess.run(command, capture_output=True, text=True, timeout=20)
    probes = {}
    if change != 'stale-installer':
        for action in ('diagnostic', 'potential-installer-gate'):
            process = subprocess.run([sys.executable, '-I', '-B', '-S', '-',
                                      str(INSTALLER_REPOSITORY), str(tmp_path), action], input=PROBE,
                                     capture_output=True, text=True, timeout=20)
            assert process.returncode == 0, process.stderr
            probes[action] = json.loads(process.stdout)
    result = {'change': change, 'cli_inspect_exit_code': inspected.returncode,
              'cli_inspect_stderr': inspected.stderr, 'probes': probes,
              'tree_unchanged': tree(base) == before, 'context': context}
    (tmp_path/'transaction-inspect-result.json').write_text(json.dumps(result, indent=2)+'\n')
    assert result['tree_unchanged'], result
    return result, inspected


@pytest.mark.parametrize('shape', ['producer7', 'historical6'])
def test_complete_producer_journal_is_admitted_without_writes(tmp_path, shape):
    result, inspected = scenario(tmp_path, shape)
    assert inspected.returncode == 0, inspected.stderr
    assert json.loads(inspected.stdout)['mutations'] is False
    assert result['context']['producer_version'] == '0.6.0'
    assert len(result['context']['producer_tenant_fields']) == 7
    for probe in result['probes'].values():
        assert probe['accepted'] is True and probe['services_called'] is False, result


@pytest.mark.parametrize('change', ['mixed-seven-six', 'mixed-six-seven',
                                   'unknown-auth', 'selected-auth', 'tenant-extra',
                                   'owner-mode', 'attestation-digest', 'stale-installer'])
def test_preinstallation_rejects_changed_journal_or_authority_without_writes(tmp_path, change):
    result, inspected = scenario(tmp_path, change)
    if change == 'stale-installer':
        assert inspected.returncode == 1 and 'source differs' in inspected.stderr
        assert result['probes'] == {}
    else:
        # Static inspect does not claim to have checked the host journals.
        assert inspected.returncode == 0 and json.loads(inspected.stdout)['mutations'] is False
        assert result['probes']['potential-installer-gate']['accepted'] is False, result
        if change in ('owner-mode', 'attestation-digest'):
            assert result['probes']['diagnostic']['accepted'] is True
        else:
            assert result['probes']['diagnostic']['accepted'] is False
