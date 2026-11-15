"""Synthetic receipt registration, original-source loading and crash recovery."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import types

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import admin_recovery_compat as compat
import admin_install
import test_admin_handoff as fixture
from host.lifecycle import filesystem, services
from tools.tests.test_host_lifecycle_services import recovery_properties


def blocked(tmp_path):
    root, plan, payloads, provider = fixture.fixture(tmp_path, 'fresh')
    fixture.advance(root, plan, payloads, provider, until='installed')
    provider.activate_recovery = lambda _: (_ for _ in ()).throw(ValueError('old reader failed'))
    with pytest.raises(ValueError, match='old reader'):
        fixture.advance(root, plan, payloads, provider)
    operations = []
    unit_manifest = fixture.manifest()
    for unit in services.WA_RECOVERY:
        path = '/etc/systemd/system/' + unit
        fixture.write(root.base, path, (fixture.ROOT/'plugins/whatsapp/deploy'/unit).read_bytes())
        unit_manifest['files'][path] = {**root.snapshot(path), 'retention': 'managed'}
    def reader(argv, **kwargs):
        if argv[0] == '/usr/bin/busctl':
            _, signature, empty = services.RECOVERY_EMPTY_PROPERTIES[argv[-1]]
            return json.dumps({'type': signature, 'data': empty}).encode()
        values = recovery_properties(argv[-1]); values['Job'] = ''
        if argv[-1] == services.WA_RECOVERY[1]:
            armed = bool(operations)
            values.update(ActiveState='active' if armed else 'inactive',
                          UnitFileState='enabled' if armed else 'disabled')
            values['TimersMonotonic'] = ('{ OnUnitInactiveUSec=1min; next=2; }\n'
                                        'TimersMonotonic={ OnBootUSec=45s; next=1; }')
        return '\n'.join(k+'='+v for k,v in values.items() if k not in services.RECOVERY_EMPTY_PROPERTIES).encode()
    operation = {'source_revision': compat.ORIGINAL_REVISION, 'installer_sources': {'fixture': 'a'*64},
                 'plan': plan, 'profile': {'final_manifest': unit_manifest}}
    context = types.SimpleNamespace(fs=filesystem, handoff=fixture.handoff, services=services,
        corrected=services, operation=operation, payloads=payloads, operation_sha=compat.digest(compat.encoded(operation)),
        plan_sha=fixture.handoff.digest(plan), correction_hashes={'fixture': 'b'*64}, installation_sha='c'*64)
    provider.services = services.RecoveryServices(root, reader=compat.compatible_reader(context, reader),
        runner=lambda operation, **kwargs: operations.append(operation))
    provider.activate_recovery = lambda _: provider.services.activate(unit_manifest)
    original_verify = provider.verify_installation
    def verify(plan):
        original_verify(plan)
        provider.services.verify(unit_manifest)
    provider.verify_installation = verify
    initial = root.read_bytes(plan['journal']['path'])
    receipt = compat.encoded(compat.receipt_value(context, initial))
    assert compat.journal(context, root)['sequence'] == 6
    return root, context, provider, receipt, operations


def finish(root, context, provider, receipt, **kwargs):
    for _ in range(4):
        result = compat.advance(context, root, receipt, compat.digest(receipt), provider, **kwargs)
        if result['phase'] == 'verified':
            return result
    pytest.fail('Did not finish the bounded recovery tail')


def test_receipt_bound_tail_preserves_original_artifacts_and_other_owner(tmp_path):
    root, context, provider, receipt, operations = blocked(tmp_path)
    with root:
        original = copy.deepcopy(context.operation)
        runtime, dispatcher = root.read_bytes(fixture.handoff.RUNTIME), root.read_bytes(fixture.DISPATCHER)
        before = {str(p): p.read_bytes() for p in root.base.rglob('*') if p.is_file()}
        result = compat.inspect(context, root, receipt, compat.digest(receipt), provider)
        assert result['phase'] == 'installed' and not result['registered']
        assert before == {str(p): p.read_bytes() for p in root.base.rglob('*') if p.is_file()}
        assert finish(root, context, provider, receipt)['phase'] == 'verified'
        assert context.operation == original
        assert root.read_bytes(fixture.handoff.RUNTIME) == runtime
        assert root.read_bytes(fixture.DISPATCHER) == dispatcher
        assert operations == ['reload-definitions', 'enable-wa-recovery', 'start-wa-recovery']
        record, _ = compat.paths(context)
        assert root.read_bytes(record) == receipt
        assert compat.inspect(context, root, receipt, compat.digest(receipt), provider)['registered']


@pytest.mark.parametrize('event', ['compatibility-registered', 'before-recovery_armed', 'after-recovery_armed',
    'before-owner_dedicated', 'after-owner_dedicated', 'before-verified', 'after-verified', 'journal-saved'])
def test_crashes_resume_only_the_original_tail(tmp_path, event):
    root, context, provider, receipt, operations = blocked(tmp_path)
    crashed = False
    def fault(name, journal):
        nonlocal crashed
        if name == event and not crashed:
            crashed = True
            raise RuntimeError('synthetic compatibility interruption')
    with root:
        runtime = root.read_bytes(fixture.handoff.RUNTIME)
        with pytest.raises(RuntimeError, match='synthetic compatibility'):
            finish(root, context, provider, receipt, fault=fault)
        assert crashed
        assert finish(root, context, provider, receipt)['phase'] == 'verified'
        assert root.read_bytes(fixture.handoff.RUNTIME) == runtime
        assert set(operations) <= {'reload-definitions', 'enable-wa-recovery', 'start-wa-recovery'}
        assert json.loads(root.read_bytes(fixture.handoff.OWNER)) == context.operation['plan']['owner']


@pytest.mark.parametrize('event', ['journal-staging', 'journal-prepared', 'intent-file',
                                  'replaced-file', 'completed-file', 'journal-committed'])
def test_registration_crashes_replay_exact_inline_receipt_before_host_effects(tmp_path, event):
    root, context, provider, receipt, operations = blocked(tmp_path)
    crashed = False
    def fault(name, detail):
        nonlocal crashed
        if name == event and not crashed:
            crashed = True
            raise RuntimeError('synthetic registration interruption')
    with root:
        initial = root.read_bytes(context.operation['plan']['journal']['path'])
        with pytest.raises(RuntimeError, match='synthetic registration'):
            compat.advance(context, root, receipt, compat.digest(receipt), provider, filesystem_fault=fault)
        assert crashed and not operations
        assert root.read_bytes(context.operation['plan']['journal']['path']) == initial
        assert finish(root, context, provider, receipt)['phase'] == 'verified'
        assert root.read_bytes(compat.paths(context)[0]) == receipt


def test_crash_before_first_engine_journal_preserves_reservation_and_blocks(tmp_path, monkeypatch):
    root, context, provider, receipt, operations = blocked(tmp_path)
    _, transaction = compat.paths(context)
    directory = filesystem.STATE+'/whatsapp/operations/'+transaction
    mkdir = filesystem.Root._mkdir
    def interrupt(self, path, spec):
        mkdir(self, path, spec)
        if path == directory:
            raise RuntimeError('reserved before first durable journal')
    with root:
        original_journal = root.read_bytes(context.operation['plan']['journal']['path'])
        with monkeypatch.context() as patch:
            patch.setattr(filesystem.Root, '_mkdir', interrupt)
            with pytest.raises(RuntimeError, match='first durable journal'):
                compat.advance(context, root, receipt, compat.digest(receipt), provider)
        metadata = root.directory(directory)
        assert metadata is not None and root.snapshot(directory+'/journal.json') is None
        for action in (compat.inspect, compat.advance):
            with pytest.raises(ValueError, match='reservation has no durable journal'):
                action(context, root, receipt, compat.digest(receipt), provider)
        assert root.directory(directory) == metadata
        assert not list((root.base/directory.lstrip('/')).iterdir())
        assert root.read_bytes(context.operation['plan']['journal']['path']) == original_journal
        assert not operations


@pytest.mark.parametrize('field', ['format', 'operation_sha256', 'original_revision', 'plan_sha256',
    'installer_sources', 'compat_sources', 'installation_sha256', 'units',
    'initial_journal_sha256', 'initial_sequence'])
def test_receipt_changes_fail_before_any_service_action(tmp_path, field):
    root, context, provider, receipt, operations = blocked(tmp_path)
    value = json.loads(receipt); value[field] = 'wrong'
    receipt = compat.encoded(value)
    with root:
        initial = root.read_bytes(context.operation['plan']['journal']['path'])
        with pytest.raises(ValueError): compat.advance(context, root, receipt, compat.digest(receipt), provider)
        assert not operations and root.read_bytes(context.operation['plan']['journal']['path']) == initial


@pytest.mark.parametrize('change', ['phase', 'intent', 'processes', 'sequence', 'owner', 'timer', 'receipt-digest'])
def test_initial_preconditions_are_not_repaired(tmp_path, change):
    root, context, provider, receipt, operations = blocked(tmp_path)
    with root:
        path = context.operation['plan']['journal']['path']
        value = json.loads(root.read_bytes(path))
        if change in ('phase', 'intent', 'processes', 'sequence'):
            value[change] = {'phase': 'prepared', 'intent': None, 'processes': [{}], 'sequence': 7}[change]
            fixture.write(root.base, path, compat.encoded(value))
        elif change == 'owner':
            fixture.write(root.base, fixture.handoff.OWNER, compat.encoded(context.operation['plan']['owner']))
        elif change == 'timer':
            operations.append('external-start')
        expected = copy.deepcopy(operations)
        with pytest.raises(ValueError):
            compat.advance(context, root, receipt, '0'*64 if change == 'receipt-digest' else compat.digest(receipt), provider)
        assert operations == expected


def test_registered_active_timer_retries_after_client_effect_without_checkpoint(tmp_path):
    root, context, provider, receipt, operations = blocked(tmp_path)
    original = provider.activate_recovery
    def interrupt(plan):
        original(plan)
        raise RuntimeError('client completed before controller died')
    provider.activate_recovery = interrupt
    with root:
        with pytest.raises(RuntimeError, match='client completed'):
            compat.advance(context, root, receipt, compat.digest(receipt), provider)
        assert compat.journal(context, root)['phase'] == 'installed'
        assert operations and root.read_bytes(compat.paths(context)[0]) == receipt
        provider.activate_recovery = original
        assert finish(root, context, provider, receipt)['phase'] == 'verified'


def test_compatibility_lease_blocks_competing_invocations(tmp_path):
    root, context, provider, receipt, operations = blocked(tmp_path)
    with root, services._named_locks(root, (compat.paths(context)[0]+'.lock',)):
        with pytest.raises(filesystem.LifecycleBusy):
            compat.advance(context, root, receipt, compat.digest(receipt), provider)
        assert not operations


def test_process_appearing_after_registration_still_uses_original_drain_gate(tmp_path):
    root, context, provider, receipt, operations = blocked(tmp_path)
    def fault(event, journal):
        if event == 'compatibility-registered':
            raise RuntimeError('registered only')
    with root:
        with pytest.raises(RuntimeError, match='registered only'):
            compat.advance(context, root, receipt, compat.digest(receipt), provider, fault=fault)
        process = fixture.process(provider.proc)
        result = compat.advance(context, root, receipt, compat.digest(receipt), provider)
        assert result['pending'] and result['phase'] == 'installed' and not operations
        for child in process.iterdir(): child.unlink()
        process.rmdir()
        assert finish(root, context, provider, receipt)['phase'] == 'verified'


@pytest.mark.parametrize('damage', ['bytes', 'mode', 'transaction'])
def test_registered_receipt_cannot_be_replaced_or_redirected(tmp_path, damage):
    root, context, provider, receipt, operations = blocked(tmp_path)
    def fault(event, journal):
        if event == 'compatibility-registered': raise RuntimeError('registered only')
    with root:
        with pytest.raises(RuntimeError):
            compat.advance(context, root, receipt, compat.digest(receipt), provider, fault=fault)
        path, transaction = compat.paths(context)
        if damage == 'bytes': fixture.write(root.base, path, b'{}\n')
        elif damage == 'mode': (root.base/path.lstrip('/')).chmod(0o644)
        else:
            state_path = filesystem.STATE+'/whatsapp/operations/'+transaction+'/journal.json'
            state = json.loads(root.read_bytes(state_path))
            state['allowed_paths'] = ['/foreign']
            fixture.write(root.base, state_path, compat.encoded(state))
        with pytest.raises(ValueError):
            compat.advance(context, root, receipt, compat.digest(receipt), provider)
        assert not operations


def original_checkout(tmp_path):
    directory = tmp_path/'original'; directory.mkdir(mode=0o700)
    # Frozen original bytes keep this test independent of both current source
    # changes and Git history (CI may use a shallow checkout).
    archived = {
        'plugins/whatsapp/scripts/installation_layout.py': 'installation_layout_777.py.txt',
        'host/installation.py': 'installation_layout_777.py.txt',
        'host/lifecycle/services.py': 'recovery_services_777.py.txt',
        'plugins/whatsapp/scripts/admin_host.py': 'admin_host_777.py.txt',
        'plugins/whatsapp/scripts/admin_handoff.py': 'admin_handoff_777.py.txt',
    }
    for name in compat.ORIGINAL_SOURCES:
        target = directory/name; target.parent.mkdir(parents=True, exist_ok=True)
        source = (Path(__file__).parent/'fixtures'/archived[name]
                  if name in archived else fixture.ROOT/name)
        assert compat.digest(source.read_bytes()) == compat.ORIGINAL_DIGESTS[name], name
        shutil.copyfile(source, target)
    return directory


@pytest.mark.parametrize('damage', [None, 'source', 'source-and-envelope', 'operation', 'receipt'])
def test_cold_original_artifact_loader_verifies_all_sources_before_import(tmp_path, damage):
    from test_admin_install import operation
    root, data, _ = operation(tmp_path)
    checkout = original_checkout(tmp_path)
    value = json.loads(data); value['source_revision'] = compat.ORIGINAL_REVISION
    value['installer_sources'] = {name: compat.digest((checkout/name).read_bytes()) for name in compat.ORIGINAL_SOURCES}
    data = compat.encoded(value); sha = compat.digest(data)
    operation_file = tmp_path/'op.json'; operation_file.write_bytes(data)
    marker = tmp_path/'unverified-code-ran'
    if damage in ('source', 'source-and-envelope'):
        helper = checkout/'plugins/whatsapp/scripts/admin_host.py'
        helper.write_text('open('+repr(str(marker))+',"w").write("bad")\n')
        if damage == 'source-and-envelope':
            # Rehashing arbitrary code into an otherwise valid envelope must
            # never make it the reviewed historical installer.
            value['installer_sources']['plugins/whatsapp/scripts/admin_host.py'] = compat.digest(helper.read_bytes())
            data = compat.encoded(value); sha = compat.digest(data)
            operation_file.write_bytes(data)
    if damage == 'operation': sha = '0'*64
    script = '''import json,pathlib,sys
sys.path.insert(0,sys.argv[1]); import admin_recovery_compat as c
raw=pathlib.Path(sys.argv[3]).read_bytes()
receipt={'operation_sha256':'wrong'} if sys.argv[5]=='receipt' else None
ctx=c.load_context(pathlib.Path(sys.argv[2]),raw,sys.argv[4],pathlib.Path(sys.argv[6]),receipt)
assert pathlib.Path(ctx.services.__file__).resolve()==pathlib.Path(sys.argv[6],'host/lifecycle/services.py').resolve()
assert ctx.services is not ctx.corrected
assert ctx.operation['source_revision']==c.ORIGINAL_REVISION
def raw_reader(argv, **bounds):
    if argv[0]=='/usr/bin/busctl':
        _,signature,empty=ctx.corrected.RECOVERY_EMPTY_PROPERTIES[argv[-1]]
        return json.dumps({'type':signature,'data':empty}).encode()
    unit=argv[-1]; values={key:'' for key in ctx.services.RECOVERY_PROPERTIES[unit]}
    values.update(Id=unit,LoadState='loaded',NeedDaemonReload='no',FragmentPath='/etc/systemd/system/'+unit,
                  ActiveState='inactive',SubState='dead')
    if unit.endswith('.timer'):
        values.update(Unit=ctx.services.WA_RECOVERY[0],UnitFileState='disabled',
          TimersMonotonic='{ OnUnitInactiveUSec=1min; next=2; }\\nTimersMonotonic={ OnBootUSec=45s; next=1; }')
    return '\\n'.join(k+'='+v for k,v in values.items() if k not in ctx.corrected.RECOVERY_EMPTY_PROPERTIES).encode()
for unit in ctx.services.WA_RECOVERY:
    try: ctx.services._recovery_properties(unit,raw_reader)
    except ValueError as error: assert 'Incomplete dedicated recovery identity' in str(error)
    else: raise AssertionError('Original parser must reproduce the defect')
    observed=ctx.services._recovery_properties(unit,c.compatible_reader(ctx,raw_reader))
    assert observed['Id']==unit and observed['Job']==''
    if unit.endswith('.timer'):
        assert 'OnBootUSec' in observed['TimersMonotonic'] and 'OnUnitInactiveUSec' in observed['TimersMonotonic']
print('original source closure verified')
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', script,
        str(fixture.ROOT/'plugins/whatsapp/scripts'), str(root.base), str(operation_file), sha,
        damage or 'none', str(checkout)], capture_output=True, text=True)
    root.close()
    assert not marker.exists()
    assert (result.returncode == 0) is (damage is None), result.stderr
