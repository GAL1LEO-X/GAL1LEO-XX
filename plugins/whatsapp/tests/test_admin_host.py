import hashlib
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest

from host.lifecycle import evidence, filesystem, services

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/admin_host.py'
SPEC = importlib.util.spec_from_file_location('wa_admin_host_tests', SCRIPT)
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)
BOOT = '11111111-2222-3333-4444-555555555555'


def transaction_record(phase):
    root = '/srv/openai-codex/projects/whatsapp-personal'
    instance = {'slug': 'personal', 'base': 'whatsapp-personal', 'unit': 'whatsapp-personal.service',
                'port': 8820, 'config': '/etc/whatsapp-personal/config.toml', 'wrapper': root+'/scripts/as-user'}
    frozen = phase in ('frozen', 'switched', 'committed', 'published')
    return {'root': root, 'candidate': '/opt/develative-releases/whatsapp/'+'a'*32,
        'record': root+'/work/github-release-123/transaction', 'version': '0.5.0',
        'sourceCommit': 'a'*40, 'previousVersion': '0.4.9', 'selected': [instance], 'registered': [instance],
        'before': {'personal': 'WORKING'}, 'activeUnits': [instance['unit']],
        'allUnits': [instance['unit']], 'databases': [] if not frozen else [{
            'path': '/var/lib/whatsapp-personal/archive.sqlite', 'backup': 'personal-before.sqlite',
            'sha256': 'b'*64, 'migrated': 'personal-candidate.sqlite', 'migration': {
                'fromSchema': 7, 'toSchema': 8, 'integrity': 'ok', 'recordIdentitiesPreserved': True}}],
        'dropins': [{'path': '/etc/systemd/system/whatsapp-personal.service.d/70-release-runtime.conf',
                    'before': None}], 'frozen': frozen, 'phase': phase}


def backup_record(phase):
    root = '/srv/openai-codex/projects/whatsapp-personal'
    components = [{'name': 'personal.'+kind, 'kind': kind,
                   'command': ['systemctl'] if kind == 'bridge' else [root+'/scripts/as-user', 'systemctl', '--user'],
                   'unit': 'whatsapp-personal.service' if kind == 'bridge' else 'whatsapp-waha.service',
                   'port': 8820 if kind == 'bridge' else 8821,
                   'config': '/etc/whatsapp-personal/config.toml', 'active': True}
                  for kind in ('gateway', 'bridge')]
    return {'format': 'whatsapp-backup-recovery-v1', 'id': 'a'*32, 'root': root, 'version': '0.5.0',
            'context': {name: 'b'*64 for name in (root+'/private/tenants.json',
                root+'/sally_whatsapp/__init__.py', '/etc/whatsapp-personal/config.toml', root+'/scripts/as-user')},
            'selected': ['personal'],
            'components': components, 'phase': phase, 'copies': {'personal': {'path': None, 'complete': False}},
            'servicesRestored': phase == 'restored', 'failures': [], 'worker': None}


def put(root, logical, content):
    target = root / logical.lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    target.chmod(0o600)
    return {'sha256': hashlib.sha256(content).hexdigest(), 'mode': 0o600,
            'uid': target.stat().st_uid, 'gid': target.stat().st_gid, 'retention': 'managed'}


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    fs = tmp_path / 'fs'; fs.mkdir(mode=0o700)
    proc = tmp_path / 'proc'
    put(proc, '/sys/kernel/random/boot_id', (BOOT + '\n').encode())
    source = '/opt/whatsapp/inventory-anchor.py'
    manifest = {'format': 1, 'owner': 'whatsapp', 'directories': {},
                'files': {source: put(fs, source, b'# synthetic source\n')}}
    for unit in services.WA_RECOVERY:
        manifest['files']['/etc/systemd/system/'+unit] = put(fs, '/etc/systemd/system/'+unit,
            (SCRIPT.parents[1]/'deploy'/unit).read_bytes())
    inventory = {'scope': {'script_paths': [source], 'script_roots': [], 'cgroups': []},
                 'manifest': manifest, 'units': {}}
    attestation = '/etc/develative-deploy/inventory/initial.json'
    attested = evidence.canonical({'format': 2, 'complete': True, 'invokers': [],
        'manual_policy': {'operation_id': 'd'*32, 'unregistered_root_commands': 'frozen-for-operation'}})
    put(fs, attestation, attested)
    empty = {'format': 1, 'owner': 'whatsapp', 'directories': {}, 'files': {}}
    profile = {'format': 'whatsapp-host-inventory-v1', 'attestation': {
        'path': attestation, 'sha256': hashlib.sha256(attested).hexdigest()},
        'retirement_attestation': None, 'stages': {'inventory': inventory, 'installed': inventory},
        'final_manifest': manifest, 'retained_manifest': empty, 'invokers': [], 'generation_id': 'c'*64}
    plan = {'inventory_digest': evidence.digest(profile), 'evidence_digests': {
        stage: evidence.digest_inventory(item['scope'], item['manifest'], item['units'])
        for stage, item in profile['stages'].items()}, 'id': 'd'*32, 'mode': 'fresh',
        'owner': {'epoch': 'e'*32}}
    root = filesystem.Root(fs)
    commands = []
    host = adapter.AdminHost(root, profile, proc_root=proc,
        readonly_runner=recovery_reader,
        service_runner=lambda operation, **kwargs: commands.append((operation, kwargs)), clock_ns=lambda: 100)
    yield root, host, plan, profile, commands
    root.close()


def identity(plan):
    return hashlib.sha256((json.dumps(plan, sort_keys=True, separators=(',', ':')) + '\n').encode()).hexdigest()


def test_real_inventory_and_process_reads_are_bound_to_plan(fixture):
    root, host, plan, profile, commands = fixture
    envelope = host.inventory(plan, identity(plan))
    assert evidence.require_quiescent(envelope['receipt'], context=envelope['context'], now_ns=100)
    assert host.verify_installation(plan)['manifest_digest'] == evidence.digest(profile['final_manifest'])
    assert commands == []
    plan['inventory_digest'] = 'f'*64
    with pytest.raises(filesystem.LifecycleError, match='bound'):
        host.inventory(plan, identity(plan))


@pytest.mark.parametrize('journal,body', [
    ('transaction', {'phase': 'activating'}),
    ('backup', {'format': 'whatsapp-backup-recovery-v1', 'phase': 'restored', 'servicesRestored': False}),
    ('backup', {'phase': 'restored', 'servicesRestored': True}), ('pending', {})])
def test_unfinished_journals_block_without_mutation(fixture, journal, body):
    root, host, plan, profile, commands = fixture
    data = evidence.canonical(body)
    put(root.base, adapter.JOURNALS[journal], data)
    with pytest.raises(filesystem.LifecycleError):
        host.journals_terminal(plan)
    assert root.read_bytes(adapter.JOURNALS[journal]) == data
    assert commands == []


@pytest.mark.parametrize('journal,body', [
    *[('transaction', {'phase': phase}) for phase in adapter.TRANSACTION_PHASES
      if phase not in ('published', 'rolled-back')],
    *[('backup', {'format': 'whatsapp-backup-recovery-v1', 'phase': phase,
                 'servicesRestored': False}) for phase in adapter.BACKUP_PHASES if phase != 'restored'],
    ('pending', {'status': 'activation-pending', 'commit': 'a'*40, 'filesSha256': {},
                 'previousHashes': {}, 'previousCode': '/opt/whatsapp/work/previous'})])
def test_known_unfinished_journals_return_pending(fixture, journal, body):
    from admin_handoff import Pending
    root, host, plan, profile, commands = fixture
    if journal == 'transaction': body = transaction_record(body['phase'])
    elif journal == 'backup': body = backup_record(body['phase'])
    data = evidence.canonical(body)
    put(root.base, adapter.JOURNALS[journal], data)
    with pytest.raises(Pending):
        host.journals_terminal(plan)
    assert root.read_bytes(adapter.JOURNALS[journal]) == data
    assert commands == []


def test_gate_returns_pending_but_does_not_hide_malformed_journal(fixture):
    from admin_handoff import Pending
    root, host, plan, profile, commands = fixture
    put(root.base, adapter.GATE, b'Release validation in progress\n')
    with pytest.raises(Pending):
        host.journals_terminal(plan)
    put(root.base, adapter.JOURNALS['transaction'], b'{"phase":"unknown"}')
    with pytest.raises(filesystem.LifecycleError, match='Unknown activation'):
        host.journals_terminal(plan)
    assert not commands


def test_terminal_journals_and_retained_files_survive_verification(fixture):
    root, host, plan, profile, commands = fixture
    for name, value in [('transaction', transaction_record('published')), ('backup', backup_record('restored'))]:
        put(root.base, adapter.JOURNALS[name], evidence.canonical(value))
    host.journals_terminal(plan)
    source = next(iter(profile['final_manifest']['files']))
    put(root.base, source, b'changed')
    with pytest.raises(filesystem.LifecycleError, match='differs'):
        host.verify_installation(plan)


@pytest.mark.parametrize('phase', ['published', 'rolled-back'])
@pytest.mark.parametrize('auth_mode', [None, 'managed-authelia', 'external-oidc'],
                         ids=['legacy-six-fields', 'managed-seven-fields', 'external-seven-fields'])
def test_terminal_activation_auth_mode_journals_are_read_only(fixture, phase, auth_mode):
    root, host, plan, _, commands = fixture
    record = transaction_record(phase)
    if auth_mode is not None:
        record.update(version='0.6.0', previousVersion='0.5.0')
        for item in (*record['registered'], *record['selected']):
            item['auth_mode'] = auth_mode
    raw = evidence.canonical(record)
    put(root.base, adapter.JOURNALS['transaction'], raw)
    before = root.snapshot(adapter.JOURNALS['transaction'])
    host.journals_terminal(plan)
    assert root.snapshot(adapter.JOURNALS['transaction']) == before
    assert root.read_bytes(adapter.JOURNALS['transaction']) == raw and not commands


@pytest.mark.parametrize('mode_index', [0, 1], ids=['seven-then-six', 'six-then-seven'])
def test_activation_journal_rejects_mixed_tenant_schemas_without_mutation(fixture, mode_index):
    root, host, plan, _, commands = fixture
    record = transaction_record('published')
    rows = [{key: str(value) if isinstance(value, Path) else value for key, value in item.items()}
            for item in producer_instances()]
    rows[mode_index]['auth_mode'] = 'external-oidc'
    record['registered'] = rows
    record['selected'] = copy.deepcopy(rows)
    record['before'] = {item['slug']: 'WORKING' for item in rows}
    record['activeUnits'] = record['allUnits'] = [item['unit'] for item in rows]
    record['dropins'] = [{'path': '/etc/systemd/system/' + item['unit'] + '.d/70-release-runtime.conf',
                          'before': None} for item in rows]
    database = record['databases'][0]
    record['databases'] = [{**copy.deepcopy(database),
        'path': '/var/lib/' + item['base'] + '/archive.sqlite',
        'backup': item['slug'] + '-before.sqlite', 'migrated': item['slug'] + '-candidate.sqlite'}
        for item in rows]
    raw = evidence.canonical(record)
    put(root.base, adapter.JOURNALS['transaction'], raw)
    before = root.snapshot(adapter.JOURNALS['transaction'])
    with pytest.raises(filesystem.LifecycleError):
        host.journals_terminal(plan)
    assert root.snapshot(adapter.JOURNALS['transaction']) == before
    assert root.read_bytes(adapter.JOURNALS['transaction']) == raw and not commands


def test_uniform_seven_field_activation_allows_different_auth_modes(fixture):
    root, host, plan, _, commands = fixture
    record = transaction_record('published')
    rows = [{key: str(value) if isinstance(value, Path) else value for key, value in item.items()}
            for item in producer_instances()]
    for item, auth_mode in zip(rows, ('managed-authelia', 'external-oidc')):
        item['auth_mode'] = auth_mode
    record['registered'] = rows
    record['selected'] = copy.deepcopy(rows)
    record['before'] = {item['slug']: 'WORKING' for item in rows}
    record['activeUnits'] = record['allUnits'] = [item['unit'] for item in rows]
    record['dropins'] = [{'path': '/etc/systemd/system/' + item['unit'] + '.d/70-release-runtime.conf',
                          'before': None} for item in rows]
    database = record['databases'][0]
    record['databases'] = [{**copy.deepcopy(database),
        'path': '/var/lib/' + item['base'] + '/archive.sqlite',
        'backup': item['slug'] + '-before.sqlite', 'migrated': item['slug'] + '-candidate.sqlite'}
        for item in rows]
    raw = evidence.canonical(record)
    put(root.base, adapter.JOURNALS['transaction'], raw)
    before = root.snapshot(adapter.JOURNALS['transaction'])
    host.journals_terminal(plan)
    assert root.snapshot(adapter.JOURNALS['transaction']) == before
    assert root.read_bytes(adapter.JOURNALS['transaction']) == raw and not commands


@pytest.mark.parametrize('auth_mode', ['managed-authelia', 'external-oidc'])
def test_valid_auth_mode_does_not_make_committed_activation_terminal(fixture, auth_mode):
    from admin_handoff import Pending
    root, host, plan, _, commands = fixture
    record = transaction_record('committed')
    for item in (*record['registered'], *record['selected']):
        item['auth_mode'] = auth_mode
    raw = evidence.canonical(record)
    put(root.base, adapter.JOURNALS['transaction'], raw)
    with pytest.raises(Pending):
        host.journals_terminal(plan)
    assert root.read_bytes(adapter.JOURNALS['transaction']) == raw and not commands


@pytest.mark.parametrize('auth_mode', [None, True, False, 0, 1.0, [], {}, ['external-oidc'],
                                     '', 'external', 'EXTERNAL-OIDC', 'external-oidc ', 'managed_authelia'])
def test_activation_journal_rejects_invalid_present_auth_mode(fixture, auth_mode):
    root, host, plan, _, commands = fixture
    record = transaction_record('published')
    record['registered'][0]['auth_mode'] = auth_mode
    raw = evidence.canonical(record)
    put(root.base, adapter.JOURNALS['transaction'], raw)
    with pytest.raises(filesystem.LifecycleError):
        host.journals_terminal(plan)
    assert root.read_bytes(adapter.JOURNALS['transaction']) == raw and not commands


@pytest.mark.parametrize('shape', ['legacy-extra', 'auth-extra', 'same-size-unknown'])
def test_activation_tenant_auth_compatibility_keeps_exact_keys(fixture, shape):
    root, host, plan, _, commands = fixture
    record = transaction_record('published')
    item = record['registered'][0]
    if shape == 'auth-extra':
        item['auth_mode'] = 'external-oidc'
    elif shape == 'same-size-unknown':
        del item['wrapper']
        item['auth_mode'] = 'external-oidc'
    item['futureField'] = 'not-admitted'
    raw = evidence.canonical(record)
    put(root.base, adapter.JOURNALS['transaction'], raw)
    with pytest.raises(filesystem.LifecycleError):
        host.journals_terminal(plan)
    assert root.read_bytes(adapter.JOURNALS['transaction']) == raw and not commands


@pytest.mark.parametrize('difference', ['mode', 'missing-mode', 'extra-field', 'legacy-vs-mode'])
def test_selected_activation_tenant_must_match_auth_record_exactly(fixture, difference):
    root, host, plan, _, commands = fixture
    record = transaction_record('published')
    if difference != 'legacy-vs-mode':
        record['registered'][0]['auth_mode'] = 'external-oidc'
    record['selected'] = copy.deepcopy(record['registered'])
    selected = record['selected'][0]
    if difference in ('mode', 'legacy-vs-mode'):
        selected['auth_mode'] = 'managed-authelia'
    elif difference == 'missing-mode':
        del selected['auth_mode']
    else:
        selected['futureField'] = 'not-admitted'
    raw = evidence.canonical(record)
    put(root.base, adapter.JOURNALS['transaction'], raw)
    with pytest.raises(filesystem.LifecycleError):
        host.journals_terminal(plan)
    assert root.read_bytes(adapter.JOURNALS['transaction']) == raw and not commands


@pytest.mark.parametrize('field,value', [('base', 'box'), ('unit', 'box.service'),
    ('config', '/etc/box/config.toml'), ('wrapper', '/opt/foreign/as-user'),
    ('port', True), ('port', 8821)])
def test_seven_field_activation_keeps_tenant_path_and_port_guards(fixture, field, value):
    root, host, plan, _, commands = fixture
    record = transaction_record('published')
    record['registered'][0].update(auth_mode='external-oidc', **{field: value})
    raw = evidence.canonical(record)
    put(root.base, adapter.JOURNALS['transaction'], raw)
    with pytest.raises(filesystem.LifecycleError):
        host.journals_terminal(plan)
    assert root.read_bytes(adapter.JOURNALS['transaction']) == raw and not commands


@pytest.mark.parametrize('journal,body', [('transaction', {'phase': 'published'}),
    ('transaction', {'phase': 'rolled-back'}), ('backup', {'format': 'whatsapp-backup-recovery-v1',
        'phase': 'restored', 'servicesRestored': True})])
def test_terminal_label_without_complete_record_cannot_open_admission(fixture, journal, body):
    root, host, plan, _, commands = fixture
    data = evidence.canonical(body)
    put(root.base, adapter.JOURNALS[journal], data)
    with pytest.raises(filesystem.LifecycleError):
        host.journals_terminal(plan)
    assert root.read_bytes(adapter.JOURNALS[journal]) == data and not commands


@pytest.mark.parametrize('mutate', [
    lambda record: record.update(frozen=False),
    lambda record: record.update(databases=[]),
    lambda record: record.update(activeUnits=['box.service']),
    lambda record: record['registered'][0].update(config='/etc/box/config.toml'),
    lambda record: record.update(dropins=[]),
    lambda record: record.update(activationError='activation_not_verified'),
    lambda record: record.update(futureFormat=2),
    lambda record: record['before'].update(personal={'status': 'WORKING'}),
    lambda record: record['before'].update(personal=None),
    lambda record: record['databases'][0].update(migration={}),
    lambda record: record['databases'][0]['migration'].update(recordIdentitiesPreserved=False),
    lambda record: record['databases'][0]['migration'].update(integrity='failed'),
    lambda record: record['databases'][0]['migration'].update(fromSchema=9, toSchema=8),
    lambda record: record['databases'][0]['migration'].update(fromSchema=True),
    lambda record: record.update(sourceCommit=int('1'*40)),
])
def test_inconsistent_terminal_activation_requires_inspection(fixture, mutate):
    root, host, plan, _, commands = fixture
    record = transaction_record('published')
    mutate(record)
    put(root.base, adapter.JOURNALS['transaction'], evidence.canonical(record))
    with pytest.raises(filesystem.LifecycleError):
        host.journals_terminal(plan)
    assert not commands


def test_restored_services_do_not_claim_backup_copy_was_completed(fixture):
    root, host, plan, _, commands = fixture
    record = backup_record('restored')
    record['copies']['personal'] = {'path': '/var/backups/whatsapp-personal/incomplete', 'complete': False}
    put(root.base, adapter.JOURNALS['backup'], evidence.canonical(record))
    host.journals_terminal(plan)
    record['failures'] = ['personal.gateway']
    put(root.base, adapter.JOURNALS['backup'], evidence.canonical(record))
    with pytest.raises(filesystem.LifecycleError):
        host.journals_terminal(plan)
    assert not commands


@pytest.mark.parametrize('mutate', [
    lambda record: record['context'].pop('/etc/whatsapp-personal/config.toml'),
    lambda record: record['context'].update({'/etc/box/config.toml': 'a'*64}),
    lambda record: record['components'][0].update(command=[]),
    lambda record: record['components'][0].update(kind='bridge'),
    lambda record: record['components'][0].update(unit='box.service'),
    lambda record: record['components'][0].update(port=8823),
    lambda record: record['components'][1].update(port=8821),
    lambda record: record['components'][0].update(config='/etc/box/config.toml'),
    lambda record: record['components'].reverse(),
    lambda record: record['components'][0].update(name={}),
    lambda record: record.update(worker={'pid': 1, 'session': True, 'start': '42', 'boot': BOOT}),
])
def test_impossible_terminal_backup_requires_inspection(fixture, mutate):
    root, host, plan, _, commands = fixture
    record = backup_record('restored')
    mutate(record)
    content = evidence.canonical(record)
    put(root.base, adapter.JOURNALS['backup'], content)
    with pytest.raises(filesystem.LifecycleError):
        host.journals_terminal(plan)
    assert root.read_bytes(adapter.JOURNALS['backup']) == content and not commands


def producer_instances():
    """The exact dictionaries returned by github_release.instances()."""
    root = Path('/srv/openai-codex/projects/whatsapp-personal')
    result = []
    for slug, port in (('personal', 8820), ('secondary', 8822)):
        base = 'whatsapp-personal' if slug == 'personal' else 'whatsapp-' + slug
        result.append({'slug': slug, 'unit': base + '.service', 'base': base, 'port': port,
            'config': Path('/etc') / base / 'config.toml',
            'wrapper': root / ('scripts/as-user' if slug == 'personal' else 'private/tenants/' + slug + '/as-user')})
    return result


@pytest.mark.parametrize('version', ['0.4.9', '0.5.0'])
def test_actual_backup_producer_records_and_partial_copy_recovery_are_compatible(tmp_path, monkeypatch, version):
    from types import SimpleNamespace
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import github_release as release
    import release_backup as backup
    rows = producer_instances()
    monkeypatch.setattr(backup, 'JOURNAL', tmp_path / 'backup.json')
    monkeypatch.setattr(backup, 'activation_idle', lambda: None)
    # The context function and serialisation are real; fixture hashes avoid
    # reading operational config files. The only service query is substituted.
    monkeypatch.setattr(backup, 'sha', lambda path: hashlib.sha256(str(path).encode()).hexdigest())
    monkeypatch.setattr(release.subprocess, 'run', lambda argv, **kwargs:
                        SimpleNamespace(returncode=3 if 'secondary' in argv[-1] else 0))
    root = Path('/srv/openai-codex/projects/whatsapp-personal')
    created = backup.begin(root, rows, release.backup_components(rows), version)
    adapter.validate_backup_journal(created)
    backup.before_stop(created['id'], 'personal', '/var/backups/whatsapp-personal/incomplete', True, True)
    adapter.validate_backup_journal(backup.read())
    observed = []
    result = backup.recover(root, rows, lambda components, actual_version:
                            observed.append((components, actual_version)) or [])
    assert result['phase'] == 'restored' and result['servicesRestored']
    assert result['copies']['personal']['complete'] is False
    assert result['copies']['secondary'] == {'path': None, 'complete': False}
    assert len(observed) == 1 and observed[0][1] == version
    adapter.validate_backup_journal(result)


@pytest.mark.parametrize('version,schema', [('0.4.9', 7), ('0.5.0', 8)])
def test_actual_transaction_prepare_and_migration_result_match_validator(tmp_path, monkeypatch, version, schema):
    import sqlite3
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import release_transaction as transaction
    import release_database as database
    root = Path('/srv/openai-codex/projects/whatsapp-personal')
    candidate = tmp_path / 'candidate'; candidate.mkdir()
    for name in transaction.ENTRIES:
        selected = candidate / name
        if name in ('.venv', 'sally_whatsapp'): selected.mkdir()
        else: selected.write_text('synthetic source\n')
    monkeypatch.setattr(transaction, 'JOURNAL', tmp_path / 'transaction.json')
    monkeypatch.setattr(transaction, 'SYSTEMD', Path('/etc/systemd/system'))
    original_exists = Path.exists
    monkeypatch.setattr(Path, 'exists', lambda path: False if str(path).startswith('/etc/systemd/system/whatsapp-')
                        else original_exists(path))
    captured = []
    class Prepared(BaseException): pass
    def checkpoint(plan, phase):
        assert phase == 'prepared'
        captured.append({**copy.deepcopy(plan), 'phase': phase})
        raise Prepared()
    monkeypatch.setattr(transaction, 'checkpoint', checkpoint)
    monkeypatch.setattr(transaction, 'run', lambda *args, **kwargs: pytest.fail('No service effect permitted'))
    rows = producer_instances()
    with pytest.raises(Prepared):
        transaction.activate(root, candidate, rows, rows[:1], {'personal': 'WORKING'},
            '0.4.8' if version == '0.4.9' else '0.4.9', version, tmp_path / 'record',
            lambda *args, **kwargs: None, lambda *args: None, lambda *args: None, source_commit='a'*40)
    plan = captured[0]
    adapter.validate_transaction_journal(plan)
    # Use a real SQLite migration's evidence, whose four fields are unchanged
    # in the pinned 0.4.9 producer (04164aa) and the 0.5.0 producer.
    (candidate / 'deploy').mkdir()
    steps = []
    for initial in range(6, schema):
        name = str(initial) + '-' + str(initial + 1) + '.sql'
        (candidate / 'deploy' / name).write_text('PRAGMA user_version=' + str(initial + 1) + ';')
        steps.append({'from': initial, 'to': initial + 1, 'sql': name})
    (candidate / 'deploy/migrations.json').write_text(json.dumps({'schemaVersion': schema, 'migrations': steps}))
    ddl = 'CREATE TABLE messages(id TEXT PRIMARY KEY);PRAGMA user_version=' + str(schema) + ';'
    (candidate / 'sally_whatsapp/store.py').write_text('SCHEMA=' + repr(ddl))
    source = tmp_path / 'source.sqlite'
    with sqlite3.connect(source) as connection:
        connection.executescript('CREATE TABLE messages(id TEXT PRIMARY KEY);PRAGMA user_version=6;')
        connection.execute('INSERT INTO messages VALUES (?)', ('preserved',))
    migration = database.migrate(source, candidate)
    plan['databases'] = [{'path': '/var/lib/' + item['base'] + '/archive.sqlite',
        'backup': item['slug'] + '-before.sqlite', 'migrated': item['slug'] + '-candidate.sqlite',
        'sha256': 'b'*64, 'migration': copy.deepcopy(migration)} for item in rows]
    for phase in ('frozen', 'switched', 'committed', 'published', 'rollback-committed', 'rolled-back'):
        adapter.validate_transaction_journal({**plan, 'phase': phase, 'frozen': True})
    # A rollback before completing the freeze legitimately has no DB evidence.
    adapter.validate_transaction_journal({**plan, 'phase': 'rolled-back', 'frozen': False, 'databases': []})


def test_invoker_attestation_is_rechecked_and_never_inferred(fixture):
    root, host, plan, profile, commands = fixture
    put(root.base, profile['attestation']['path'], b'{"complete":true}')
    with pytest.raises(filesystem.LifecycleError, match='attestation changed'):
        host.observe(plan, [], phase='inventory')
    assert not commands


def test_retirement_requires_separate_operation_bound_absence(fixture):
    root, host, plan, profile, commands = fixture
    with pytest.raises(filesystem.LifecycleError, match='separate'):
        host.verify_invokers_absent(plan)
    value = {'format': 3, 'complete': True, 'invokers': [], 'references': {},
             'operation_id': plan['id'], 'epoch': plan['owner']['epoch']}
    path = '/etc/develative-deploy/inventory/retired.json'
    content = evidence.canonical(value)
    put(root.base, path, content)
    profile['retirement_attestation'] = {'path': path, 'sha256': hashlib.sha256(content).hexdigest()}
    plan['inventory_digest'] = evidence.digest(profile)
    host = adapter.AdminHost(root, profile, readonly_runner=lambda *a, **k: b'',
                             service_runner=lambda *a, **k: None)
    host.verify_invokers_absent(plan)
    plan['id'] = 'f'*32
    bind_attestation(root, profile, plan)
    host = adapter.AdminHost(root, profile, readonly_runner=lambda *a, **k: b'',
                             service_runner=lambda *a, **k: None)
    with pytest.raises(filesystem.LifecycleError, match='this retirement'):
        host.verify_invokers_absent(plan)


def recovery_reader(argv, **limits):
    unit = argv[-1]
    assert argv == services.recovery_show_argv(unit)
    values = {key: '' for key in services.RECOVERY_PROPERTIES[unit]}
    values.update(Id=unit, LoadState='loaded', NeedDaemonReload='no', FragmentPath='/etc/systemd/system/'+unit,
                  Job='0', ActiveState='inactive', SubState='dead')
    if unit.endswith('.timer'):
        values.update(ActiveState='active', UnitFileState='enabled', Unit=services.WA_RECOVERY[0],
            TimersMonotonic='{ OnBootUSec=45s; next=1; } { OnUnitInactiveUSec=60s; next=2; }')
    else:
        values.update(MainPID='0', ControlPID='0', Type='oneshot', User='root', KillMode='control-group', RemainAfterExit='no',
            Restart='no', TimeoutStartUSec='600s', ExecStart='{ path=/usr/bin/python3; argv[]=/usr/bin/python3 -I -B '+services.RECOVERY_ENTRYPOINT+' recovery; }')
    return ('\n'.join(key+'='+value for key, value in values.items())+'\n').encode()


def test_effective_timer_state_blocks_admission_even_with_exact_file_manifest(fixture):
    root, host, plan, profile, commands = fixture
    def stopped(argv, **kwargs):
        return recovery_reader(argv, **kwargs).replace(b'ActiveState=active', b'ActiveState=inactive')
    host.services.reader = stopped
    with pytest.raises(filesystem.LifecycleError, match='active, enabled'):
        host.verify_installation(plan)
    assert commands == []


def test_attestation_rejects_writable_file_even_when_hash_matches(fixture):
    root, host, plan, profile, commands = fixture
    (root.base/profile['attestation']['path'].lstrip('/')).chmod(0o666)
    with pytest.raises(filesystem.LifecycleError, match='protected'):
        host.observe(plan, [], phase='inventory')
    assert commands == []


def bind_attestation(root, profile, plan, *, manual_policy=None):
    value = {'format': 2, 'complete': True, 'invokers': profile['invokers'],
             'manual_policy': manual_policy if manual_policy is not None else {
                 'operation_id': plan['id'], 'unregistered_root_commands': 'frozen-for-operation'}}
    content = evidence.canonical(value)
    put(root.base, profile['attestation']['path'], content)
    profile['attestation']['sha256'] = hashlib.sha256(content).hexdigest()
    plan['inventory_digest'] = evidence.digest(profile)
    plan['evidence_digests'] = {stage: evidence.digest_inventory(item['scope'], item['manifest'], item['units'])
        for stage, item in profile['stages'].items()}


def legacy_admission(fixture):
    root, host, plan, profile, commands = fixture
    profile, plan = copy.deepcopy(profile), copy.deepcopy(plan)
    receiver, dispatcher = adapter.LEGACY_RECEIVER, adapter.GLOBAL_RECOVERY
    unit_path = '/etc/systemd/system/develative-release-recovery.service'
    old_receiver = put(root.base, receiver, b"if __name__ == '__main__':\n    print('fixture')\n")
    old_global = put(root.base, dispatcher, b'# previous global recovery fixture\n')
    unit = put(root.base, unit_path, b'[Service]\nExecStart=/usr/bin/python3 '+dispatcher.encode()+b'\n')
    guarded = {**old_receiver, 'sha256': hashlib.sha256(b'# guarded fixture\n').hexdigest()}
    cut = {**old_global, 'sha256': hashlib.sha256(b'# BOX-only dispatcher fixture\n').hexdigest()}
    empty = {'format': 1, 'owner': 'whatsapp', 'files': {}, 'directories': {}}
    def single(path, spec):
        return {**empty, 'files': {path: spec}}
    plan['mode'] = 'legacy'
    plan['actions'] = {'guard_ingress': {'before': single(receiver, old_receiver),
        'after': single(receiver, guarded)}, 'cut_dispatcher': {'before': single(dispatcher, old_global),
        'after': single(dispatcher, cut)}}
    for stage in ('inventory', 'legacy_work', 'legacy_all'):
        profile['stages'][stage] = {
            'scope': {'script_paths': [receiver] + ([] if stage == 'legacy_work' else [dispatcher]),
                      'script_roots': [], 'cgroups': []},
            'manifest': {**empty, 'files': {receiver: old_receiver if stage == 'inventory' else guarded,
                dispatcher: cut if stage == 'legacy_all' else old_global, unit_path: unit}},
            'units': {}}
    profile['stages']['inventory']['units']['develative-release-recovery.service'] = {
        'fragment_path': unit_path, 'drop_in_paths': [], 'scope_cgroup': None,
        'references': {name: [] for name in evidence.REFERENCE_PROPERTIES}}
    profile['invokers'] = [
        {'id': 'release-key-route', 'kind': 'ssh-forced-command', 'executable': '/usr/bin/python3',
         'argv_sha256': 'a'*64, 'reference': '/etc/develative-deploy/inventory/key-route-metadata.json',
         'role': 'legacy-receiver', 'entrypoint': receiver, 'launch_mode': 'python-main',
         'gate': {'mechanism': 'legacy-main-guard', 'path': receiver}},
        {'id': 'global-recovery-unit', 'kind': 'systemd', 'executable': '/usr/bin/python3',
         'argv_sha256': 'b'*64, 'reference': unit_path, 'role': 'global-recovery',
         'entrypoint': dispatcher, 'launch_mode': 'python-main',
         'gate': {'mechanism': 'dispatcher-cut', 'path': dispatcher}}]
    plan['actions']['install'] = {'before': {**empty, 'files': {}}, 'after': {**empty, 'files': {}}}
    names = {adapter.BACKUP_ENTRY: 'backup_runtime_049.py.txt',
        adapter.TENANT_ENTRY: 'tenant_admin_legacy_20261017.py.txt',
        adapter.PROVISION_ENTRY: 'provision_host_legacy_20261017.py.txt'}
    for destination, (_, tombstone) in adapter.LEGACY_DESTINATIONS.items():
        previous = (Path(__file__).parent/'fixtures'/names[destination]).read_bytes()
        candidate = (Path(__file__).parents[1]/'scripts'/Path(destination).name).read_bytes()
        old_spec = put(root.base, destination, previous)
        guard_spec = {**old_spec, 'sha256': hashlib.sha256(tombstone).hexdigest()}
        new_spec = {**old_spec, 'sha256': hashlib.sha256(candidate).hexdigest()}
        plan['actions']['guard_ingress']['before']['files'][destination] = old_spec
        plan['actions']['guard_ingress']['after']['files'][destination] = guard_spec
        plan['actions']['install']['before']['files'][destination] = guard_spec
        plan['actions']['install']['after']['files'][destination] = new_spec
        for stage in ('inventory', 'legacy_work', 'legacy_all', 'installed'):
            item = profile['stages'][stage]
            item['scope']['script_paths'].append(destination)
            item['manifest']['files'][destination] = old_spec if stage == 'inventory' else new_spec if stage == 'installed' else guard_spec
    for stage in ('inventory', 'legacy_work', 'legacy_all', 'installed'):
        item = profile['stages'][stage]
        for name in (adapter.BACKUP_TIMER, adapter.BACKUP_SERVICE):
            path = '/etc/systemd/system/'+name
            item['manifest']['files'][path] = put(root.base,path,b'# source-pinned finite backup fixture\n')
            observed = {'fragment_path': path, 'drop_in_paths': [], 'scope_cgroup': None,
                'references': {key: [] for key in evidence.REFERENCE_PROPERTIES},
                'state': {'ActiveState':'inactive','SubState':'dead'}}
            if name == adapter.BACKUP_TIMER:
                observed['state']['UnitFileState'] = 'disabled'
                observed['references']['Triggers'] = [adapter.BACKUP_SERVICE]
            else:
                observed['execution'] = adapter.backup_execution_contract()
            item['units'][name] = observed
    bind_attestation(root, profile, plan)
    return root, profile, plan, commands


def test_legacy_routes_require_exact_gate_actions_and_keep_global_pre_cut(fixture):
    root, profile, plan, commands = legacy_admission(fixture)
    host = adapter.AdminHost(root, profile, readonly_runner=recovery_reader,
                             service_runner=lambda *a, **k: commands.append(a))
    host._bind(plan)
    assert adapter.GLOBAL_RECOVERY not in profile['stages']['legacy_work']['scope']['script_paths']
    assert profile['stages']['legacy_work']['manifest']['files'][adapter.GLOBAL_RECOVERY] == \
        plan['actions']['cut_dispatcher']['before']['files'][adapter.GLOBAL_RECOVERY]
    assert not commands


@pytest.mark.parametrize('change', ['role', 'arbitrary-executable', 'entrypoint', 'import-call',
    'manual-route', 'gate-path', 'missing-receiver', 'missing-global', 'missing-census',
    'missing-unit', 'wrong-source', 'no-guard-change', 'global-cut-too-early'])
def test_unmapped_initiators_fail_before_observation_or_effects(fixture, change):
    root, profile, plan, commands = legacy_admission(fixture)
    receiver = profile['invokers'][0]
    if change == 'role': receiver['role'] = 'standalone-backup'
    elif change == 'arbitrary-executable': receiver['executable'] = '/usr/local/bin/arbitrary-wrapper'
    elif change == 'entrypoint': receiver['entrypoint'] = '/opt/other.py'
    elif change == 'import-call': receiver['launch_mode'] = 'python-import-call'
    elif change == 'manual-route': receiver['kind'] = 'manual'
    elif change == 'gate-path': receiver['gate']['path'] = adapter.GLOBAL_RECOVERY
    elif change == 'missing-receiver': profile['invokers'] = profile['invokers'][1:]
    elif change == 'missing-global': profile['invokers'] = profile['invokers'][:1]
    elif change == 'missing-census': profile['stages']['legacy_all']['scope']['script_paths'] = [adapter.LEGACY_RECEIVER]
    elif change == 'missing-unit': profile['stages']['inventory']['units'] = {}
    elif change == 'wrong-source': profile['stages']['legacy_work']['manifest']['files'][adapter.LEGACY_RECEIVER] = \
        plan['actions']['guard_ingress']['before']['files'][adapter.LEGACY_RECEIVER]
    elif change == 'no-guard-change': plan['actions']['guard_ingress']['after'] = plan['actions']['guard_ingress']['before']
    elif change == 'global-cut-too-early': profile['stages']['legacy_work']['manifest']['files'][adapter.GLOBAL_RECOVERY] = \
        plan['actions']['cut_dispatcher']['after']['files'][adapter.GLOBAL_RECOVERY]
    bind_attestation(root, profile, plan)
    before = {str(path): path.read_bytes() for path in root.base.rglob('*') if path.is_file()}
    observed = []
    with pytest.raises(filesystem.LifecycleError):
        host = adapter.AdminHost(root, profile, readonly_runner=lambda *a, **k: observed.append(a),
                                 service_runner=lambda *a, **k: commands.append(a))
        host.critical_section(plan)
    assert not commands and not observed
    assert before == {str(path): path.read_bytes() for path in root.base.rglob('*') if path.is_file()}


@pytest.mark.parametrize('policy', [{}, {'operation_id': 'f'*32, 'unregistered_root_commands': 'frozen-for-operation'},
    {'operation_id': 'd'*32, 'unregistered_root_commands': 'root-cannot-bypass'}])
def test_manual_freeze_is_an_exact_operation_bound_attestation(fixture, policy):
    root, host, plan, profile, commands = fixture
    bind_attestation(root, profile, plan, manual_policy=policy)
    host = adapter.AdminHost(root, profile, readonly_runner=recovery_reader,
                             service_runner=lambda *a, **k: commands.append(a))
    with pytest.raises(filesystem.LifecycleError, match='attested'):
        host.critical_section(plan)
    assert not commands


def removal_admission(fixture):
    root, host, plan, profile, commands = fixture
    profile, plan = copy.deepcopy(profile), copy.deepcopy(plan)
    plan['mode'] = 'remove'
    plan['owner_metadata'] = {'uid': root.uid, 'gid': root.gid, 'mode': 0o600}
    manifest_bytes = b'{"protocol":1,"files":{}}\n'
    generation_digest = hashlib.sha256(manifest_bytes).hexdigest()
    generation = '/usr/local/lib/develative-deploy/whatsapp-generations/'+generation_digest
    plan['owner'] = {'protocol': 1, 'state': 'dedicated', 'epoch': 'e'*32,
                     'manifest_sha256': generation_digest, 'generation': generation}
    plan['previous_owner'] = copy.deepcopy(plan['owner'])
    files = {path: put(root.base, path, (SCRIPT.parent/name).read_bytes())
             for path, (name, _) in adapter.OWNER_GATE_SOURCES.items()}
    for dependency in set(adapter.OWNER_GATE_LAYOUT_DEPENDENCIES.values()):
        files[dependency] = put(root.base, dependency, (SCRIPT.parent/'installation_layout.py').read_bytes())
    files[generation+'/manifest.json'] = put(root.base, generation+'/manifest.json', manifest_bytes)
    for unit in services.WA_RECOVERY:
        path = '/etc/systemd/system/'+unit
        files[path] = put(root.base, path, (SCRIPT.parents[1]/'deploy'/unit).read_bytes())
    backup_unit = '/etc/systemd/system/whatsapp-personal-backup.service'
    files[backup_unit] = put(root.base, backup_unit, b'# backup unit fixture\n')
    key_reference = '/etc/develative-deploy/inventory/release-key-route.json'
    files[key_reference] = put(root.base, key_reference, b'{"route":"receiver"}\n')
    manifest = {'format': 1, 'owner': 'whatsapp', 'directories': {}, 'files': files}
    scope = {'script_paths': [adapter.LEGACY_RECEIVER, adapter.BOOTSTRAP_ENTRY, adapter.BACKUP_ENTRY],
             'script_roots': [generation], 'cgroups': []}
    units = {Path(path).name: {'fragment_path': path, 'drop_in_paths': [], 'scope_cgroup': None,
             'references': {key: [] for key in evidence.REFERENCE_PROPERTIES}}
             for path in files if path.startswith('/etc/systemd/system/')}
    profile['stages'] = {'inventory': {'manifest': manifest, 'scope': scope, 'units': units},
                         'removal': {'manifest': copy.deepcopy(manifest), 'scope': copy.deepcopy(scope), 'units': {}}}
    plan['actions'] = {'close_invokers': {'before': manifest, 'after': copy.deepcopy(manifest)},
                       'remove': {'before': manifest, 'after': {'format': 1, 'owner': 'whatsapp', 'files': {}, 'directories': {}}}}
    profile['invokers'] = []
    for role, reference in (('owner-receiver', key_reference), ('owner-backup', backup_unit),
                            ('dedicated-recovery', '/etc/systemd/system/'+services.WA_RECOVERY[0])):
        entrypoint, mechanism, _ = adapter.INVOKER_CONTRACTS[role]
        profile['invokers'].append({'id': role, 'kind': 'ssh-forced-command' if role == 'owner-receiver' else 'systemd',
            'executable': '/usr/bin/python3', 'argv_sha256': 'b'*64, 'reference': reference,
            'role': role, 'entrypoint': entrypoint,
            'launch_mode': 'python-main-recovery' if role == 'dedicated-recovery' else 'python-main',
            'gate': {'mechanism': mechanism, 'path': adapter.OWNER_RECORD}})
    bind_attestation(root, profile, plan)
    return root, profile, plan, commands


def test_reviewed_owner_gate_contract_tracks_exact_source_bytes():
    for name, digest in adapter.OWNER_GATE_SOURCES.values():
        assert hashlib.sha256((SCRIPT.parent/name).read_bytes()).hexdigest() == digest
    assert hashlib.sha256((SCRIPT.parent/'installation_layout.py').read_bytes()).hexdigest() == adapter.OWNER_GATE_LAYOUT_SHA256


def test_reviewed_prior_release_gate_pins_are_retained():
    # Exact sources at the 0.7.0/main baseline still need admission while an
    # existing generation drains. Their recognition does not admit new bytes.
    previous_backup = 'df04588602f4a9d7a8663a75b6548e5b72003d1be74537ed73580dfe4e37a99f'
    previous_layout = '049be515b1244c421b731cab52d18c09c3eedf5c2a8513aece171f6c47a3c3ef'
    assert previous_backup in adapter.PREVIOUS_CONFIGURED_OWNER_GATE_SHA256['backup_runtime.py']
    assert previous_backup != adapter.OWNER_GATE_SOURCES[adapter.BACKUP_ENTRY][1]
    assert previous_layout in adapter.PREVIOUS_OWNER_GATE_LAYOUT_SHA256
    assert previous_layout != adapter.OWNER_GATE_LAYOUT_SHA256


@pytest.mark.parametrize('entry', [adapter.BOOTSTRAP_ENTRY, adapter.BACKUP_ENTRY])
@pytest.mark.parametrize('change', ['missing', 'digest', 'mode', 'uid', 'action', 'closing-drift'])
def test_current_removal_gates_require_their_reviewed_protected_layout(fixture, entry, change):
    root, profile, plan, commands = removal_admission(fixture)
    dependency = adapter.OWNER_GATE_LAYOUT_DEPENDENCIES[entry]
    stage = profile['stages']['removal']['manifest']['files']
    if change == 'missing': stage.pop(dependency)
    elif change == 'action': plan['actions']['close_invokers']['after']['files'].pop(dependency)
    elif change == 'closing-drift':
        plan['actions']['close_invokers']['after']['files'][dependency]['gid'] += 1
        stage[dependency]['gid'] += 1
    else:
        key, value = {'digest': ('sha256', '0'*64), 'mode': ('mode', 0o666), 'uid': ('uid', root.uid + 1)}[change]
        stage[dependency][key] = value
    with pytest.raises(filesystem.LifecycleError):
        adapter.validate_removal_admission(profile, plan)
    assert not commands


def test_previous_fixed_layout_gate_sources_need_no_new_dependency(fixture, monkeypatch):
    root, profile, plan, commands = removal_admission(fixture)
    for stage in profile['stages'].values():
        files = stage['manifest']['files']
        for path, (name, _) in adapter.OWNER_GATE_SOURCES.items():
            files[path]['sha256'] = adapter.PREVIOUS_OWNER_GATE_SHA256[name]
        for dependency in set(adapter.OWNER_GATE_LAYOUT_DEPENDENCIES.values()):
            files.pop(dependency)
    plan['actions']['close_invokers'] = {
        'before': copy.deepcopy(profile['stages']['inventory']['manifest']),
        'after': copy.deepcopy(profile['stages']['removal']['manifest'])}
    adapter.validate_removal_admission(profile, plan)
    # Historical code contains fixed owner/bootstrap paths. Its exact source
    # identities cannot attest the gate of a configurable installation.
    from types import SimpleNamespace
    monkeypatch.setattr(adapter, 'installation_profile', lambda: SimpleNamespace(compatibility=False))
    with pytest.raises(filesystem.LifecycleError, match='reviewed implementation'):
        adapter.validate_removal_admission(profile, plan)
    assert not commands


def test_existing_dedicated_receiver_backup_and_recovery_have_removal_gates(fixture):
    root, profile, plan, commands = removal_admission(fixture)
    host = adapter.AdminHost(root, profile, readonly_runner=recovery_reader,
                             service_runner=lambda *a, **k: commands.append(a))
    host._bind(plan)
    assert len(profile['invokers']) == 3 and not commands


def upgrade_admission(fixture):
    root, profile, plan, commands = removal_admission(fixture)
    plan['mode'] = 'upgrade'
    plan['owner'] = {**plan['owner'], 'epoch': 'a' * 32,
        'generation': '/usr/local/lib/develative-deploy/whatsapp-generations/' + 'b' * 64,
        'manifest_sha256': 'b' * 64}
    before = copy.deepcopy(plan['actions']['close_invokers']['before'])
    plan['actions'] = {'install': {'before': before, 'after': copy.deepcopy(before)}}
    profile['stages']['previous'] = profile['stages'].pop('removal')
    profile['stages']['installed'] = copy.deepcopy(profile['stages']['previous'])
    return root, profile, plan, commands


def test_dedicated_upgrade_accepts_reviewed_gates_and_tracks_old_generation(fixture):
    root, profile, plan, commands = upgrade_admission(fixture)
    adapter.validate_admission(profile, plan)
    assert not commands


@pytest.mark.parametrize('stage', ['inventory', 'previous', 'installed'])
@pytest.mark.parametrize('change', ['generation-root', 'bootstrap-census', 'generation-digest'])
def test_upgrade_rejects_incomplete_old_generation_census(fixture, stage, change):
    root, profile, plan, commands = upgrade_admission(fixture)
    item = profile['stages'][stage]
    if change == 'generation-root': item['scope']['script_roots'] = []
    elif change == 'bootstrap-census': item['scope']['script_paths'].remove(adapter.BOOTSTRAP_ENTRY)
    else: item['manifest']['files'][plan['previous_owner']['generation'] + '/manifest.json']['sha256'] = '0' * 64
    with pytest.raises(filesystem.LifecycleError):
        adapter.validate_admission(profile, plan)
    assert not commands


@pytest.mark.parametrize('change', ['gate', 'layout', 'epoch', 'legacy-role', 'discard-generation'])
def test_upgrade_requires_reviewed_old_admission_sources(fixture, change):
    root, profile, plan, commands = upgrade_admission(fixture)
    item = profile['stages']['previous']
    if change == 'gate': item['manifest']['files'][adapter.BOOTSTRAP_ENTRY]['sha256'] = '0' * 64
    elif change == 'layout': item['manifest']['files'][adapter.OWNER_GATE_LAYOUT_DEPENDENCIES[adapter.BOOTSTRAP_ENTRY]]['sha256'] = '0' * 64
    elif change == 'epoch': plan['owner']['epoch'] = plan['previous_owner']['epoch']
    elif change == 'discard-generation': plan['actions']['install']['after']['files'].pop(plan['previous_owner']['generation'] + '/manifest.json')
    else: profile['invokers'][0]['role'] = 'legacy-receiver'
    with pytest.raises(filesystem.LifecycleError):
        adapter.validate_admission(profile, plan)
    assert not commands


@pytest.mark.parametrize('old_sha', sorted(adapter.PREVIOUS_OWNER_GATE_LAYOUT_SHA256))
def test_previous_configured_layout_remains_a_reviewed_upgrade_gate(fixture, old_sha):
    root, profile, plan, commands = upgrade_admission(fixture)
    for item in profile['stages'].values():
        for path in set(adapter.OWNER_GATE_LAYOUT_DEPENDENCIES.values()):
            item['manifest']['files'][path]['sha256'] = old_sha
    plan['actions']['install']['before'] = copy.deepcopy(profile['stages']['inventory']['manifest'])
    adapter.validate_admission(profile, plan)
    assert not commands


@pytest.mark.parametrize('mode',['remove','upgrade'])
@pytest.mark.parametrize('previous',sorted(adapter.PREVIOUS_CONFIGURED_OWNER_GATE_SHA256['backup_runtime.py']))
@pytest.mark.parametrize('damage',[None,'missing-layout','changed-layout','writable-layout','wrong-owner','unreviewed-backup'])
def test_prior_configured_backup_requires_exact_protected_layout(fixture,monkeypatch,mode,previous,damage):
    root,profile,plan,commands=(removal_admission(fixture) if mode=='remove' else upgrade_admission(fixture))
    from types import SimpleNamespace
    # The previous configurable backup is admissible even outside the fixed
    # legacy layout, but cannot inherit that version's missing-dependency rule.
    monkeypatch.setattr(adapter,'installation_profile',lambda:SimpleNamespace(compatibility=False))
    dependency=adapter.OWNER_GATE_LAYOUT_DEPENDENCIES[adapter.BACKUP_ENTRY]
    for stage in profile['stages'].values():
        files=stage['manifest']['files']
        files[adapter.BACKUP_ENTRY]['sha256']=previous
        if damage=='missing-layout':files.pop(dependency)
        elif damage=='changed-layout':files[dependency]['sha256']='0'*64
        elif damage=='writable-layout':files[dependency]['mode']=0o666
        elif damage=='wrong-owner':files[dependency]['uid']=root.uid+1
        elif damage=='unreviewed-backup':files[adapter.BACKUP_ENTRY]['sha256']='0'*64
    action='close_invokers' if mode=='remove' else 'install'
    plan['actions'][action]['before']=copy.deepcopy(profile['stages']['inventory']['manifest'])
    if mode=='remove':
        plan['actions'][action]['after']=copy.deepcopy(profile['stages']['removal']['manifest'])
    validate=adapter.validate_removal_admission if mode=='remove' else adapter.validate_upgrade_admission
    if damage is None:validate(profile,plan)
    else:
        with pytest.raises(filesystem.LifecycleError):validate(profile,plan)
    assert not commands


@pytest.mark.parametrize('change', ['old-backup', 'bootstrap', 'generation-scope', 'entry-scope',
    'owner', 'recovery-unit', 'recovery-selector', 'closing-source'])
def test_removal_rejects_unproved_owner_gates_before_effects(fixture, change):
    root, profile, plan, commands = removal_admission(fixture)
    if change == 'old-backup':
        profile['stages']['inventory']['manifest']['files'][adapter.BACKUP_ENTRY]['sha256'] = '0'*64
    elif change == 'bootstrap':
        del profile['stages']['removal']['manifest']['files'][adapter.BOOTSTRAP_ADMIN]
    elif change == 'generation-scope':
        profile['stages']['removal']['scope']['script_roots'] = []
    elif change == 'entry-scope':
        profile['stages']['removal']['scope']['script_paths'].remove(adapter.BACKUP_ENTRY)
    elif change == 'owner': plan['previous_owner']['epoch'] = 'f'*32
    elif change == 'recovery-unit': del profile['stages']['inventory']['units'][services.WA_RECOVERY[1]]
    elif change == 'recovery-selector': profile['invokers'][2]['launch_mode'] = 'python-main'
    elif change == 'closing-source':
        plan['actions']['close_invokers']['after']['files'][adapter.LEGACY_RECEIVER]['sha256'] = '0'*64
    bind_attestation(root, profile, plan)
    with pytest.raises(filesystem.LifecycleError):
        host = adapter.AdminHost(root, profile, readonly_runner=recovery_reader,
                                 service_runner=lambda *a, **k: commands.append(a))
        host.critical_section(plan)
    assert not commands


def inactive_backup(fixture):
    return legacy_admission(fixture)


def test_disabled_legacy_backup_requires_a_guarded_destination_and_old_process_census(fixture):
    root, profile, plan, commands = inactive_backup(fixture)
    host = adapter.AdminHost(root, profile, readonly_runner=recovery_reader,
                             service_runner=lambda *a, **k: commands.append(a))
    host._bind(plan)
    assert adapter.BACKUP_ENTRY in profile['stages']['legacy_work']['scope']['script_paths']
    assert not commands


@pytest.mark.parametrize('change', ['enabled', 'active', 'unexpected-callback', 'missing-stage', 'missing-process-scope'])
def test_guarded_backup_still_requires_the_disabled_policy_and_finite_callbacks(fixture, change):
    root, profile, plan, commands = inactive_backup(fixture)
    item = profile['stages']['legacy_work']
    if change == 'enabled': item['units']['whatsapp-personal-backup.timer']['state']['UnitFileState'] = 'enabled'
    elif change == 'active': item['units']['whatsapp-personal-backup.service']['state']['ActiveState'] = 'active'
    elif change == 'unexpected-callback': item['units'][adapter.BACKUP_SERVICE]['execution']['ExecStopPost']['count'] = 1
    elif change == 'missing-stage': del item['units']['whatsapp-personal-backup.timer']
    else: item['scope']['script_paths'].remove(adapter.BACKUP_ENTRY)
    bind_attestation(root, profile, plan)
    with pytest.raises(filesystem.LifecycleError):
        host = adapter.AdminHost(root, profile, readonly_runner=recovery_reader,
                                 service_runner=lambda *a, **k: commands.append(a))
        host.critical_section(plan)
    assert not commands


def retirement_reference_attestation(root, profile, plan):
    action = plan['actions']['remove']
    stripped = lambda item: {key: value for key, value in item.items() if key != 'retention'}
    references = {}
    for binding in profile['invokers']:
        path = binding['reference']
        before = root.snapshot(path)
        after = stripped(action['after']['files'][path]) if path in action['after']['files'] else (
            None if path in action['before']['files'] else before)
        references[path] = {'before': before, 'after': after}
    record = {'format': 3, 'complete': True, 'invokers': [], 'operation_id': plan['id'],
              'epoch': plan['owner']['epoch'], 'references': references}
    path = '/etc/develative-deploy/inventory/final-reference-mapping.json'
    content = evidence.canonical(record)
    put(root.base, path, content)
    profile['retirement_attestation'] = {'path': path, 'sha256': hashlib.sha256(content).hexdigest()}
    plan['inventory_digest'] = evidence.digest(profile)
    return record


def test_retirement_reference_stage_is_explicit_and_derived_from_remove_action(fixture):
    root, profile, plan, commands = removal_admission(fixture)
    record = retirement_reference_attestation(root, profile, plan)
    host = adapter.AdminHost(root, profile, readonly_runner=recovery_reader,
                             service_runner=lambda *a, **k: commands.append(a))
    host.verify_invokers_absent(plan)
    with pytest.raises(filesystem.LifecycleError, match='changed after'):
        host.verify_invokers_absent(plan, after_removal=True)
    for path in record['references']:
        (root.base/path.lstrip('/')).unlink()
    host.verify_invokers_absent(plan, after_removal=True)
    with pytest.raises(filesystem.LifecycleError, match='changed after'):
        host.verify_invokers_absent(plan)
    assert not commands


@pytest.mark.parametrize('change', ['omitted-reference', 'invented-after', 'changed-reference'])
def test_retirement_attestation_does_not_replace_current_reference_evidence(fixture, change):
    root, profile, plan, commands = removal_admission(fixture)
    record = retirement_reference_attestation(root, profile, plan)
    selected = next(iter(record['references']))
    if change == 'omitted-reference': del record['references'][selected]
    elif change == 'invented-after': record['references'][selected]['after'] = record['references'][selected]['before']
    else: put(root.base, selected, b'changed incoming route after attestation\n')
    content = evidence.canonical(record)
    put(root.base, profile['retirement_attestation']['path'], content)
    profile['retirement_attestation']['sha256'] = hashlib.sha256(content).hexdigest()
    plan['inventory_digest'] = evidence.digest(profile)
    host = adapter.AdminHost(root, profile, readonly_runner=recovery_reader,
                             service_runner=lambda *a, **k: commands.append(a))
    with pytest.raises(filesystem.LifecycleError):
        host.verify_invokers_absent(plan)
    assert not commands


def test_interrupted_reference_removal_delegates_only_managed_changes_to_journal(fixture):
    root, profile, plan, commands = removal_admission(fixture)
    external = profile['invokers'][0]['reference']
    # This mapping remains externally owned and must be checked throughout.
    del plan['actions']['remove']['before']['files'][external]
    bind_attestation(root, profile, plan)
    record = retirement_reference_attestation(root, profile, plan)
    host = adapter.AdminHost(root, profile, readonly_runner=recovery_reader,
                             service_runner=lambda *a, **k: commands.append(a))
    changed = [path for path, value in record['references'].items() if value['before'] != value['after']]
    assert len(changed) == 2
    (root.base/changed[0].lstrip('/')).unlink()  # Synthetic partial engine state.
    with pytest.raises(filesystem.LifecycleError):
        host.verify_invokers_absent(plan)
    with pytest.raises(filesystem.LifecycleError):
        host.verify_invokers_absent(plan, after_removal=True)
    host.verify_invokers_absent(plan, resuming_removal=True)
    put(root.base, external, b'external mapping changed while controller was absent\n')
    with pytest.raises(filesystem.LifecycleError, match='changed after'):
        host.verify_invokers_absent(plan, resuming_removal=True)
    assert not commands
