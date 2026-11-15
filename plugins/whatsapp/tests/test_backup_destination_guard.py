"""Legacy destination closure with real source bytes and owned processes only.

backup_runtime_049.py.txt is the unchanged public source at baseline 04164aa,
SHA256 8c298c576b131ca8beb82fa8733c7a78693e549f7e28e6061030eb340699bd04.
Its code is never executed by these tests: only compiled, hashed or replaced.
"""
import builtins
import ast
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import types

import pytest

import test_admin_handoff as contract
import test_admin_host as host_contract
from host.lifecycle import filesystem

handoff = contract.handoff
adapter = host_contract.adapter
fixture = host_contract.fixture


@pytest.mark.parametrize('destination', list(handoff.LEGACY_DESTINATIONS))
@pytest.mark.parametrize('module_name', ['__main__', 'legacy_import', 'runpy_import'])
def test_destination_guard_exits_before_every_import_even_as_an_imported_module(module_name, destination):
    attempts = []
    def forbidden_import(*args, **kwargs):
        attempts.append(args[0])
        raise AssertionError('Even a standard-library import would be too late')
    guard = handoff.guarded_legacy_destination(destination, contract.LEGACY_SOURCES[destination])
    assert handoff.LEGACY_DESTINATIONS == adapter.LEGACY_DESTINATIONS
    namespace = {'__name__': module_name, '__builtins__': {**vars(builtins), '__import__': forbidden_import}}
    with pytest.raises(SystemExit, match='admission closed'):
        exec(compile(guard, '<closed-backup>', 'exec'), namespace)
    assert not attempts
    assert set(namespace) == {'__name__', '__builtins__'}


@pytest.mark.parametrize('destination', list(handoff.LEGACY_DESTINATIONS))
def test_exact_reviewed_preimage_is_mandatory(destination):
    source = contract.LEGACY_SOURCES[destination]
    assert hashlib.sha256(source).hexdigest() == handoff.LEGACY_DESTINATIONS[destination][0]
    with pytest.raises(handoff.HandoffError, match='reviewed'):
        handoff.guarded_legacy_destination(destination, source + b'\n')


@pytest.mark.parametrize('destination', list(handoff.LEGACY_DESTINATIONS))
@pytest.mark.parametrize('fault', ['receiver-only', 'wrong-preimage', 'conditional-guard', 'install-baseline-before',
                                  'reinstall-baseline', 'install-no-backup'])
def test_unprotected_destination_transition_fails_before_control_records(tmp_path, fault, destination):
    root, plan, payloads, provider = contract.fixture(tmp_path)
    gate, install = plan['actions']['guard_ingress'], plan['actions']['install']
    if fault == 'receiver-only':
        for side in ('before', 'after'): del gate[side]['files'][destination]
        gate['allowed_paths'].remove(destination)
        del payloads['guard_ingress'][destination]
    elif fault == 'wrong-preimage': gate['before']['files'][destination]['sha256'] = '0'*64
    elif fault == 'conditional-guard':
        content = b"if __name__ == '__main__': raise SystemExit('closed')\n"
        gate['after']['files'][destination]['sha256'] = hashlib.sha256(content).hexdigest()
        payloads['guard_ingress'][destination] = content
    elif fault == 'install-baseline-before':
        install['before'] = copy.deepcopy(install['before'])
        install['before']['files'][destination] = gate['before']['files'][destination]
    elif fault == 'reinstall-baseline':
        install['after']['files'][destination] = gate['before']['files'][destination]
        payloads['install'][destination] = contract.LEGACY_SOURCES[destination]
    else:
        del install['after']['files'][destination]
        del payloads['install'][destination]
    with root, pytest.raises(handoff.HandoffError):
        handoff.handoff(root, plan, payloads, provider)
    assert not (provider.root/handoff.OWNER.lstrip('/')).exists()
    assert (provider.root/destination.lstrip('/')).read_bytes() == contract.LEGACY_SOURCES[destination]


@pytest.mark.parametrize('stage', ['inventory', 'legacy_work', 'legacy_all', 'installed'])
@pytest.mark.parametrize('destination', list(handoff.LEGACY_DESTINATIONS))
def test_every_stage_must_census_all_reviewed_old_destinations(fixture, stage, destination):
    root, profile, plan, calls = host_contract.legacy_admission(fixture)
    profile['stages'][stage]['scope']['script_paths'].remove(destination)
    with pytest.raises(filesystem.LifecycleError, match='census'):
        adapter.validate_admission(profile, plan)
    assert not calls


@pytest.mark.parametrize('fault', ['missing-execution', 'missing-exec-property', 'extra-stop-callback',
                                  'external-failure', 'old-exclusion-contract'])
def test_callback_or_old_exclusion_contract_cannot_substitute_for_destination_closure(fixture, fault):
    root, profile, plan, calls = host_contract.legacy_admission(fixture)
    service = profile['stages']['legacy_work']['units'][adapter.BACKUP_SERVICE]
    if fault == 'missing-execution': del service['execution']
    elif fault == 'missing-exec-property': del service['execution']['ExecStopPost']
    elif fault == 'extra-stop-callback': service['execution']['ExecStop']['count'] = 1
    elif fault == 'external-failure': service['references']['OnFailure'] = ['box-browser.service']
    else: profile['inactive_initiators'] = []
    with pytest.raises((filesystem.LifecycleError, host_contract.evidence.EvidenceError)):
        adapter.validate_profile(profile)
        adapter.validate_admission(profile, plan)
    assert not calls


def test_empty_inverse_is_accepted_only_with_guard_callback_policy_and_stage_sources(fixture):
    root, profile, plan, calls = host_contract.legacy_admission(fixture)
    for item in profile['stages'].values():
        assert item['units'][adapter.BACKUP_SERVICE]['references']['TriggeredBy'] == []
    adapter.validate_admission(profile, plan)
    # The current candidate is bound by the approved operation; this barrier
    # deliberately does not bake a forever-current candidate digest into code.
    changed = copy.deepcopy(profile)
    changed['stages']['installed']['manifest']['files'][adapter.BACKUP_ENTRY]['sha256'] = 'a'*64
    with pytest.raises(filesystem.LifecycleError, match='handoff stage'):
        adapter.validate_admission(changed, plan)
    assert not calls


@pytest.mark.parametrize('destination', list(handoff.LEGACY_DESTINATIONS))
def test_already_compiled_process_still_blocks_after_destination_is_closed(tmp_path, destination):
    root, plan, payloads, provider = contract.fixture(tmp_path)
    program = "import pathlib,sys; code=compile(pathlib.Path(sys.argv[1]).read_bytes(),sys.argv[2],'exec'); print('compiled',flush=True); sys.stdin.readline()"
    child = subprocess.Popen([sys.executable, '-I', '-B', '-c', program,
        str(provider.root/destination.lstrip('/')), destination],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'compiled'
        # The print acknowledges compilation, not arrival at the blocking read.
        # Observing immediately can legitimately record R then S and must fail
        # the production stability check. This child has no remaining work or
        # other wait after its print; wait for its actual stdin sleep instead.
        deadline = time.monotonic() + 5
        while True:
            assert child.poll() is None, 'Compiled fixture child exited before its stdin wait'
            state = contract.evidence.parse_stat(Path('/proc', str(child.pid), 'stat').read_bytes(), child.pid)
            if state['state'] == 'S':
                break
            assert time.monotonic() < deadline, 'Compiled fixture child did not reach its stdin wait'
            time.sleep(0.001)
        (provider.proc/'sys/kernel/random/boot_id').write_bytes(Path('/proc/sys/kernel/random/boot_id').read_bytes())
        (provider.proc/str(child.pid)).symlink_to(Path('/proc')/str(child.pid), target_is_directory=True)
        with root:
            assert contract.advance(root, plan, payloads, provider, until='ingress_closed')['phase'] == 'ingress_closed'
            assert root.read_bytes(destination) == handoff.LEGACY_DESTINATIONS[destination][1]
            result = contract.advance(root, plan, payloads, provider)
            assert result['phase'] == 'ingress_closed' and result['pending']
            assert root.read_bytes(handoff.DISPATCHER) == b'# BOX + WA fixture\n'
            child.communicate('\n', timeout=5)
            (provider.proc/str(child.pid)).unlink()
            assert contract.advance(root, plan, payloads, provider)['phase'] == 'verified'
            assert root.read_bytes(destination) == contract.CANDIDATE_SOURCES[destination]
    finally:
        if child.poll() is None:
            child.kill(); child.communicate(timeout=5)


def test_process_entering_stdin_wait_between_observations_still_blocks_initial_admission(tmp_path, monkeypatch):
    """A changing process state must not be normalized away to fix readiness."""
    root, plan, payloads, provider = contract.fixture(tmp_path)
    process = contract.process(provider.proc, state='R')
    collect = contract.evidence.collect_processes
    observed = []
    def entering_wait(*args, **kwargs):
        result = collect(*args, **kwargs)
        observed.append(result)
        if len(observed) == 1:
            stat_path = process/'stat'
            before = stat_path.read_bytes()
            assert b') R ' in before
            stat_path.write_bytes(before.replace(b') R ', b') S ', 1))
        return result
    monkeypatch.setattr(contract.evidence, 'collect_processes', entering_wait)
    with root, pytest.raises(contract.evidence.EvidenceError, match='Observation changed between snapshots'):
        contract.advance(root, plan, payloads, provider, until='ingress_closed')
    assert [item['processes'][0]['state'] for item in observed] == ['R', 'S']
    assert not (provider.root/handoff.OWNER.lstrip('/')).exists()
    for destination, content in contract.LEGACY_SOURCES.items():
        assert (provider.root/destination.lstrip('/')).read_bytes() == content


def test_original_global_recovery_imports_guarded_receiver_but_not_backup(tmp_path, monkeypatch):
    source = (Path(__file__).parents[3]/'tools/tests/fixtures/legacy_shared_recover_04164aa.py').read_bytes()
    assert hashlib.sha256(source).hexdigest() == 'f5ea554bfc6d69432a9a694e4754bd9137f9cdfd2d915f57165e429b815af9e4'
    state = tmp_path/'state'; state.mkdir()
    project = tmp_path/'project'; (project/'private').mkdir(parents=True)
    journal = state/'transaction.json'; journal.write_text('{"phase":"stopped"}')
    common = types.ModuleType('github_release_common'); common.STATE = state
    common.run = lambda *a, **k: pytest.fail('Recovery must not launch a command in this fixture')
    receiver = types.ModuleType('github_release')
    exec(handoff.guarded_legacy_source(contract.SOURCE, hashlib.sha256(contract.SOURCE).hexdigest()), receiver.__dict__)
    receiver.ROOT = project; receiver.wait_health = object()
    transaction = types.ModuleType('release_transaction'); transaction.JOURNAL = journal
    recovered = []
    transaction.recover = lambda plan, health: recovered.append((plan, health))
    for module in (common, receiver, transaction): monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(sys, 'path', list(sys.path))
    original_import = builtins.__import__
    def no_backup(name, *args, **kwargs):
        assert name not in ('backup_runtime', 'tenant_admin', 'provision_host'), 'Destination guards must not break old recovery'
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', no_backup)
    namespace = {'__name__': 'observed_global_recovery'}
    exec(compile(source, '<reviewed-global-recovery>', 'exec'), namespace)
    namespace['recover_project']('whatsapp')
    assert recovered == [({'phase': 'stopped'}, receiver.wait_health)]


def test_acquired_manual_sources_are_static_fixtures_not_executed_modules():
    tenant = ast.parse(contract.LEGACY_SOURCES[handoff.TENANT_ENTRY])
    provision = ast.parse(contract.LEGACY_SOURCES[handoff.PROVISION_ENTRY])
    assert len(contract.LEGACY_SOURCES[handoff.TENANT_ENTRY]) == 21674
    assert len(contract.LEGACY_SOURCES[handoff.PROVISION_ENTRY]) == 4621
    assert any(isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name) and node.test.left.id == '__name__' for node in tenant.body)
    assert not any(isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name) and node.test.left.id == '__name__' for node in provision.body)
    assert any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'umask'
        for node in provision.body)


@pytest.mark.parametrize('destination', [handoff.RECEIVER, *handoff.LEGACY_DESTINATIONS])
def test_partial_four_destination_guard_resumes_forward_before_phase_advance(tmp_path, destination):
    root, plan, payloads, provider = contract.fixture(tmp_path)
    class Crash(BaseException):
        pass
    class InterruptedFilesystem:
        def __getattr__(self, name):
            return getattr(filesystem, name)
        def reconcile(self, *args, **kwargs):
            def crash(event, detail):
                if event == 'replaced-file' and detail['path'] == destination:
                    raise Crash()
            return filesystem.reconcile(*args, **kwargs, fault=crash)
    with root:
        contract.advance(root, plan, payloads, provider, until='transitioning')
        with pytest.raises(Crash):
            handoff.handoff(root, plan, payloads, provider, filesystem=InterruptedFilesystem())
        journal = json.loads(root.read_bytes(plan['journal']['path']))
        assert journal['phase'] == 'transitioning' and journal['intent'] == 'ingress_closed'
        assert json.loads(root.read_bytes(handoff.OWNER))['state'] == 'transitioning'
        assert root.read_bytes(handoff.DISPATCHER) == b'# BOX + WA fixture\n'
        assert 'arm-whatsapp' not in provider.calls
        assert handoff.handoff(root, plan, payloads, provider)['phase'] == 'ingress_closed'
        for path, guard in payloads['guard_ingress'].items():
            assert root.read_bytes(path) == guard
        assert contract.advance(root, plan, payloads, provider)['phase'] == 'verified'
