"""Lifecycle census fixtures: no server, real systemctl, secret files or DB reads."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest

from host.lifecycle import evidence

BOOT = '11111111-2222-3333-4444-555555555555'
OTHER_BOOT = '99999999-2222-3333-4444-555555555555'
SOURCE = '/opt/wa/admin/receiver.py'
GROUP = '/system.slice/wa-receiver.service'


def process(proc, pid=120, *, ppid=1, session=None, pgrp=None, start=100, state='S', group=GROUP,
            argv=None, comm='python) name'):
    directory = proc/str(pid); directory.mkdir(exist_ok=True)
    # Field 22 starttime; embedded spaces/parentheses in comm are deliberate.
    fields = [state, str(ppid), str(pgrp or pid), str(session or pid)] + ['0'] * 15 + [str(start)]
    (directory/'stat').write_text(f'{pid} ({comm}) '+ ' '.join(fields)+'\n')
    (directory/'cgroup').write_text('0::'+group+'\n')
    (directory/'cmdline').write_bytes(b'\0'.join(arg.encode() for arg in (argv or ['/usr/bin/python3', SOURCE]))+b'\0')


def metadata(path):
    info = path.stat()
    return {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'mode': info.st_mode & 0o7777,
            'uid': info.st_uid, 'gid': info.st_gid, 'retention': 'managed'}


def unit_properties(unit='wa-receiver.service'):
    values = {key: '' for key in evidence.unit_properties(unit)}
    values.update(Id=unit, LoadState='loaded', ActiveState='inactive', SubState='dead',
                  Job='0',
                  FragmentPath='/etc/systemd/system/'+unit, DropInPaths='', NeedDaemonReload='no')
    if unit.endswith('.service'):
        values.update(MainPID='0', ControlPID='0', ControlGroup='')
    return values


def encoded_unit(properties):
    return ('\n'.join(key+'='+value for key, value in properties.items())+'\n').encode()


@pytest.fixture
def fixture(tmp_path):
    fs = tmp_path/'fs'; fs.mkdir()
    for name, content in ((SOURCE, 'old synthetic generation\n'),
                          ('/etc/systemd/system/wa-receiver.service', '[Service]\nExecStart=/synthetic\n')):
        path = fs/name.lstrip('/'); path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content); path.chmod(0o640)
    manifest = {'format': 1, 'owner': 'whatsapp',
                'files': {name: metadata(fs/name.lstrip('/')) for name in
                          (SOURCE, '/etc/systemd/system/wa-receiver.service')}, 'directories': {}}
    scope = {'cgroups': [GROUP], 'script_roots': [], 'script_paths': [SOURCE]}
    units = {'wa-receiver.service': {'fragment_path': '/etc/systemd/system/wa-receiver.service',
              'drop_in_paths': [], 'references': {key: [] for key in evidence.REFERENCE_PROPERTIES}, 'scope_cgroup': GROUP}}
    proc = tmp_path/'proc'; (proc/'sys/kernel/random').mkdir(parents=True)
    (proc/'sys/kernel/random/boot_id').write_text(BOOT+'\n')
    context = {'format': 1, 'authority': 'root-inventory', 'plan_digest': 'a'*64, 'invocation_id': 'handoff-1',
               'generation_id': 'b'*64, 'inventory_digest': evidence.digest_inventory(scope, manifest, units), 'boot_id': BOOT}
    calls = []
    def runner(argv, **limits):
        calls.append((argv, limits)); return encoded_unit(unit_properties())
    return dict(scope=scope, expected_manifest=manifest, context=context, units=units,
                fs_root=fs, proc_root=proc, runner=runner, clock_ns=lambda: 100, calls=calls)


def observe(fixture, **overrides):
    arguments = {key: value for key, value in fixture.items() if key != 'calls'}
    arguments.update(overrides)
    return evidence.observe(**arguments)


def checked(receipt, fixture, **kwargs):
    return evidence.require_quiescent(receipt, context=fixture['context'], now_ns=101, **kwargs)


def test_exact_inventory_empty_census_proves_scoped_quiescence_without_commands(fixture):
    receipt = observe(fixture)
    assert checked(receipt, fixture)['quiescent']
    assert len(fixture['calls']) == 2
    assert all(argv == evidence.show_argv('wa-receiver.service') for argv, limits in fixture['calls'])
    assert all(limits == {'timeout': 5.0, 'max_bytes': evidence.MAX_COMMAND} for argv, limits in fixture['calls'])
    assert 'cmdline' not in json.dumps(receipt) and 'environment' not in json.dumps(receipt)


def test_live_script_pid_and_late_descendant_are_blocked_without_leaking_arguments(fixture):
    process(fixture['proc_root'], argv=['python3', SOURCE, '--token', 'SYNTHETIC-NEVER-RETURN'])
    process(fixture['proc_root'], pid=121, ppid=120, session=120, group='/unrelated', argv=['sleep', '60'])
    receipt = observe(fixture)
    records = receipt['snapshots'][1]['processes']['processes']
    assert {record['pid'] for record in records} == {120, 121}
    assert all(record['generation_id'] == fixture['context']['generation_id'] for record in records)
    assert 'SYNTHETIC-NEVER-RETURN' not in json.dumps(receipt)
    with pytest.raises(evidence.EvidenceError, match='still alive'): checked(receipt, fixture)


def test_exact_script_path_and_cgroup_boundary_do_not_match_substrings(fixture):
    process(fixture['proc_root'], group=GROUP+'-other', argv=['python3', SOURCE+'.bak'])
    assert checked(observe(fixture), fixture)['quiescent']
    process(fixture['proc_root'], group=GROUP+'/child', argv=['sleep', '60'])
    with pytest.raises(evidence.EvidenceError, match='still alive'): checked(observe(fixture), fixture)


@pytest.mark.parametrize('fault', ['missing-stat', 'missing-cgroup', 'missing-cmdline', 'denied', 'truncated-stat'])
def test_incomplete_process_census_is_never_an_empty_success(fixture, monkeypatch, fault):
    process(fixture['proc_root'])
    if fault.startswith('missing-'): (fixture['proc_root']/'120'/fault[8:]).unlink()
    elif fault == 'truncated-stat': (fixture['proc_root']/'120/stat').write_text('120 (x) S 1\n')
    else:
        original = evidence._bounded_read
        def read(path, maximum):
            if path.name == 'cmdline': raise PermissionError('synthetic denied')
            return original(path, maximum)
        monkeypatch.setattr(evidence, '_bounded_read', read)
    with pytest.raises((evidence.EvidenceError, OSError)): observe(fixture)


def test_prior_pid_reuse_is_rejected_and_prior_identity_cannot_be_omitted(fixture):
    process(fixture['proc_root'])
    prior = observe(fixture)['snapshots'][1]['processes']['processes']
    fixture['context']['inventory_digest'] = evidence.digest_inventory(fixture['scope'], fixture['expected_manifest'], fixture['units'], prior_processes=prior)
    with pytest.raises(evidence.EvidenceError, match='does not bind'): observe(fixture)
    process(fixture['proc_root'], start=999, group='/unrelated', argv=['sleep', '60'])
    with pytest.raises(evidence.EvidenceError, match='PID was reused'): observe(fixture, prior_processes=prior)


def test_prior_session_keeps_orphaned_child_in_scope_after_leader_exits(fixture):
    process(fixture['proc_root'])
    prior = observe(fixture)['snapshots'][1]['processes']['processes']
    for path in (fixture['proc_root']/'120').iterdir(): path.unlink()
    (fixture['proc_root']/'120').rmdir()
    process(fixture['proc_root'], pid=121, ppid=1, session=120, group='/unrelated', argv=['sleep', '60'])
    fixture['context']['inventory_digest'] = evidence.digest_inventory(fixture['scope'], fixture['expected_manifest'], fixture['units'], prior_processes=prior)
    with pytest.raises(evidence.EvidenceError, match='still alive'): checked(observe(fixture, prior_processes=prior), fixture)


def test_reboot_invalidates_old_receipt_but_requires_new_census_for_new_context(fixture):
    old = observe(fixture)
    (fixture['proc_root']/'sys/kernel/random/boot_id').write_text(OTHER_BOOT+'\n')
    with pytest.raises(evidence.EvidenceError, match='Boot changed'): checked(observe(fixture), fixture)
    fixture['context']['boot_id'] = OTHER_BOOT
    with pytest.raises(evidence.EvidenceError, match='different operation'): checked(old, fixture)
    assert checked(observe(fixture), fixture)['quiescent']
    process(fixture['proc_root'])
    with pytest.raises(evidence.EvidenceError, match='still alive'): checked(observe(fixture), fixture)


@pytest.mark.parametrize('fault', ['stale', 'future', 'changed-digest', 'wrong-operation', 'boolean-only'])
def test_receipt_freshness_identity_and_structure_are_verified(fixture, fault):
    receipt = observe(fixture)
    with pytest.raises(evidence.EvidenceError):
        if fault == 'stale': evidence.require_quiescent(receipt, context=fixture['context'], now_ns=6_000_000_100)
        elif fault == 'future': evidence.require_quiescent(receipt, context=fixture['context'], now_ns=99)
        elif fault == 'changed-digest': receipt['snapshots'][0]['files'] = {}; checked(receipt, fixture)
        elif fault == 'wrong-operation': fixture['context']['invocation_id'] = 'handoff-other'; checked(receipt, fixture)
        else: checked({'drained': True}, fixture)


def test_unit_job_or_incoherent_generation_is_not_drained(fixture):
    for changes in ({'Job': '123'}, {'ActiveState': 'activating'}, {'MainPID': '123'},
                    {'NeedDaemonReload': 'yes'}, {'FragmentPath': '/old/receiver.service'},
                    {'Requires': 'box.service'}, {'ControlGroup': '/wrong-scope'}):
        properties = unit_properties(); properties.update(changes)
        receipt = observe(fixture, runner=lambda *args, **kwargs: encoded_unit(properties))
        with pytest.raises(evidence.EvidenceError): checked(receipt, fixture)


def test_source_changed_between_snapshots_and_metadata_drift_are_rejected(fixture):
    source = fixture['fs_root']/SOURCE.lstrip('/')
    def runner(*args, **kwargs):
        source.write_text('different loaded-file generation\n')
        return encoded_unit(unit_properties())
    with pytest.raises(evidence.EvidenceError, match='differs|changed'): checked(observe(fixture, runner=runner), fixture)
    source.chmod(0o777)
    with pytest.raises(evidence.EvidenceError, match='differs'): checked(observe(fixture), fixture)


def test_symlink_parent_and_fifo_are_rejected_without_reading_target(fixture):
    source = fixture['fs_root']/SOURCE.lstrip('/')
    source.unlink(); source.symlink_to('/nonexistent-secret')
    with pytest.raises(evidence.EvidenceError, match='unsafe'): observe(fixture)
    source.unlink(); os.mkfifo(source)
    with pytest.raises(evidence.EvidenceError, match='unsafe'): observe(fixture)


def test_script_root_requires_named_sources_and_rejects_ambiguous_paths(fixture):
    fixture['scope'] = {'cgroups': [], 'script_roots': ['/opt/wa/admin'], 'script_paths': []}
    fixture['context']['inventory_digest'] = evidence.digest_inventory(fixture['scope'], fixture['expected_manifest'], fixture['units'])
    for script in ('/opt/wa/admin/other.py', '/opt/wa/admin/../receiver.py'):
        process(fixture['proc_root'], group='/unrelated', argv=['python3', script])
        with pytest.raises(evidence.EvidenceError, match='Scoped source|Ambiguous'): observe(fixture)


def test_collector_runner_rejects_mutation_shell_and_unscoped_argv_before_exec(monkeypatch):
    monkeypatch.setattr(evidence.subprocess, 'Popen', lambda *args, **kwargs: pytest.fail('must not execute'))
    for argv in (['systemctl', 'show', 'x.service'], ['/usr/bin/systemctl', 'stop', 'x.service'],
                 ['/bin/sh', '-c', 'true'], ['/usr/bin/systemctl', 'show', '*']):
        with pytest.raises(evidence.EvidenceError): evidence.readonly_runner(argv)


def test_late_process_between_snapshots_cannot_be_hidden_by_empty_first_census(fixture):
    calls = 0
    def runner(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2: process(fixture['proc_root'])
        return encoded_unit(unit_properties())
    with pytest.raises(evidence.EvidenceError, match='changed between snapshots'):
        checked(observe(fixture, runner=runner), fixture)


def test_collector_subprocess_is_bounded_without_touching_a_real_service(monkeypatch):
    import subprocess
    import sys
    actual_popen = subprocess.Popen
    children = []
    code = 'import sys; sys.stdout.write("x"*4096); sys.stdout.flush()'
    def popen(argv, **kwargs):
        assert argv == evidence.show_argv('wa-receiver.service')
        child = actual_popen([sys.executable, '-c', code], **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(evidence.subprocess, 'Popen', popen)
    with pytest.raises(evidence.EvidenceError, match='oversized'):
        evidence.readonly_runner(evidence.show_argv('wa-receiver.service'), max_bytes=64)
    assert children[0].poll() is not None
    code = 'import time; time.sleep(10)'
    with pytest.raises(evidence.EvidenceError, match='timed out'):
        evidence.readonly_runner(evidence.show_argv('wa-receiver.service'), timeout=0.05)
    assert children[1].poll() is not None


def test_declared_link_is_observed_without_following_and_retargeting_is_rejected(fixture):
    logical = '/etc/systemd/system/multi-user.target.wants/wa-receiver.service'
    link = fixture['fs_root']/logical.lstrip('/'); link.parent.mkdir(); link.symlink_to('/etc/systemd/system/wa-receiver.service')
    info = link.lstat()
    fixture['expected_manifest']['links'] = {logical: {'target': '/etc/systemd/system/wa-receiver.service',
        'uid': info.st_uid, 'gid': info.st_gid, 'retention': 'managed'}}
    fixture['context']['inventory_digest'] = evidence.digest_inventory(fixture['scope'], fixture['expected_manifest'], fixture['units'])
    receipt = observe(fixture)
    assert checked(receipt, fixture)['quiescent']
    assert receipt['snapshots'][0]['files']['links'][logical]['target'] == '/etc/systemd/system/wa-receiver.service'
    link.unlink(); link.symlink_to('/nonexistent-sensitive-path')
    with pytest.raises(evidence.EvidenceError, match='differs'): checked(observe(fixture), fixture)


def test_declared_source_alias_requires_the_real_source_digest_without_following_link(fixture):
    logical = '/opt/wa/current'
    link = fixture['fs_root']/logical.lstrip('/'); link.symlink_to('/opt/wa/admin')
    info = link.lstat()
    fixture['expected_manifest']['links'] = {logical: {'target': '/opt/wa/admin', 'uid': info.st_uid,
        'gid': info.st_gid, 'retention': 'managed'}}
    fixture['scope'] = {'cgroups': [], 'script_roots': [], 'script_paths': ['/opt/wa/current/receiver.py']}
    fixture['context']['inventory_digest'] = evidence.digest_inventory(fixture['scope'], fixture['expected_manifest'], fixture['units'])
    process(fixture['proc_root'], group='/unrelated', argv=['python3', '/opt/wa/current/receiver.py'])
    with pytest.raises(evidence.EvidenceError, match='still alive'): checked(observe(fixture), fixture)
    fixture['expected_manifest']['links'][logical]['target'] = '/opt/missing'
    with pytest.raises(evidence.EvidenceError, match='inventoried digest'):
        evidence.digest_inventory(fixture['scope'], fixture['expected_manifest'], fixture['units'])


def test_disabled_unit_expectation_is_verified_from_actual_properties(fixture):
    fixture['units']['wa-receiver.service']['state'] = {
        'UnitFileState': 'disabled', 'ActiveState': 'inactive', 'SubState': 'dead'}
    fixture['context']['inventory_digest'] = evidence.digest_inventory(
        fixture['scope'], fixture['expected_manifest'], fixture['units'])
    values = {**unit_properties(), 'UnitFileState': 'disabled'}
    runner = lambda *a, **k: encoded_unit(values)
    assert checked(observe(fixture, runner=runner), fixture)['quiescent']
    for key, wrong in [('UnitFileState', 'enabled'), ('ActiveState', 'active'),
                       ('MainPID', '123'), ('ControlPID', '123'), ('Job', '7 /job/7')]:
        original = values[key]
        values[key] = wrong
        with pytest.raises(evidence.EvidenceError, match='state differs|still has processes'):
            evidence.verify(observe(fixture, runner=runner), context=fixture['context'], now_ns=100)
        values[key] = original


def add_timer(fixture):
    """Timer interface fixture independent of the collector's requested fields."""
    name = 'wa-receiver.timer'
    logical = '/etc/systemd/system/' + name
    path = fixture['fs_root']/logical.lstrip('/')
    path.write_text('[Timer]\nUnit=wa-receiver.service\nOnBootSec=45s\n')
    fixture['expected_manifest']['files'][logical] = metadata(path)
    fixture['units'][name] = {'fragment_path': logical, 'drop_in_paths': [],
        'references': {key: [] for key in evidence.REFERENCE_PROPERTIES}, 'scope_cgroup': None,
        'state': {'UnitFileState': 'disabled', 'ActiveState': 'inactive', 'SubState': 'dead'}}
    fixture['units'][name]['references']['Triggers'] = ['wa-receiver.service']
    fixture['units']['wa-receiver.service']['references']['TriggeredBy'] = [name]
    fixture['context']['inventory_digest'] = evidence.digest_inventory(
        fixture['scope'], fixture['expected_manifest'], fixture['units'])
    values = {'Id': name, 'LoadState': 'loaded', 'ActiveState': 'inactive', 'SubState': 'dead',
        'Job': '', 'FragmentPath': logical, 'DropInPaths': '', 'NeedDaemonReload': 'no',
        'InvocationID': '', 'UnitFileState': 'disabled', 'Requires': '', 'Wants': '', 'After': '',
        'Before': '', 'PartOf': '', 'BindsTo': '', 'OnFailure': '', 'OnSuccess': '',
        'PropagatesStopTo': '', 'Triggers': 'wa-receiver.service',
        'TriggeredBy': ''}
    def runner(argv, **limits):
        if argv[-1] == name:
            requested = argv[4].removeprefix('--property=').split(',')
            assert not set(requested) & {'MainPID', 'ControlPID', 'ControlGroup'}
            return encoded_unit(values)
        return encoded_unit({**unit_properties(), 'TriggeredBy': name})
    return values, runner


def test_disabled_timer_uses_its_actual_interface_without_synthetic_pid_or_cgroup(fixture):
    values, runner = add_timer(fixture)
    receipt = observe(fixture, runner=runner)
    assert checked(receipt, fixture)['quiescent']
    assert receipt['snapshots'][0]['units']['wa-receiver.timer'] == values
    assert evidence.unit_quiescent('wa-receiver.timer', values)


@pytest.mark.parametrize('key,value', [('Job', '7 /org/freedesktop/systemd1/job/7'),
                                      ('ActiveState', 'active'), ('UnitFileState', 'enabled')])
def test_disabled_timer_with_pending_job_or_activation_is_blocked(fixture, key, value):
    values, runner = add_timer(fixture)
    values[key] = value
    with pytest.raises(evidence.EvidenceError, match='state differs|still has processes'):
        checked(observe(fixture, runner=runner), fixture)


@pytest.mark.parametrize('fault', ['extra-pid', 'extra-cgroup', 'missing-job', 'missing-state'])
def test_timer_unknown_or_missing_property_is_not_an_empty_success(fixture, fault):
    values, runner = add_timer(fixture)
    if fault == 'extra-pid': values['MainPID'] = '0'
    elif fault == 'extra-cgroup': values['ControlGroup'] = ''
    elif fault == 'missing-job': del values['Job']
    else: del values['ActiveState']
    with pytest.raises(evidence.EvidenceError, match='property|properties'):
        observe(fixture, runner=runner)


@pytest.mark.parametrize('field,value', [('MainPID', None), ('ControlPID', None),
                                         ('ControlGroup', None), ('MainPID', ''), ('ControlPID', 'unknown')])
def test_service_applicable_properties_are_required_and_pids_must_be_numeric(fixture, field, value):
    values = unit_properties()
    if value is None: del values[field]
    else: values[field] = value
    with pytest.raises(evidence.EvidenceError, match='properties|service PID'):
        observe(fixture, runner=lambda *a, **kw: encoded_unit(values))


def test_timer_cannot_claim_a_process_cgroup_and_other_observed_types_are_explicitly_unsupported(fixture):
    add_timer(fixture)
    fixture['units']['wa-receiver.timer']['scope_cgroup'] = GROUP
    with pytest.raises(evidence.EvidenceError, match='no process cgroup'):
        evidence.digest_inventory(fixture['scope'], fixture['expected_manifest'], fixture['units'])
    # These remain legal dependency references, not falsely supported observations.
    for name in ('sockets.target', 'receiver.socket', 'user.slice', 'session.scope', 'files.path'):
        assert evidence.unit_name(name)
        with pytest.raises(evidence.EvidenceError, match='Unsupported observed unit type'):
            evidence.show_argv(name)


def test_relative_named_link_keeps_literal_and_binds_resolved_source(fixture):
    logical = '/etc/systemd/system/timers.target.wants/wa-receiver.service'
    link = fixture['fs_root']/logical.lstrip('/'); link.parent.mkdir()
    link.symlink_to('../wa-receiver.service')
    info = link.lstat()
    fixture['expected_manifest']['links'] = {logical: {'target': '../wa-receiver.service',
        'resolved_target': '/etc/systemd/system/wa-receiver.service', 'uid': info.st_uid,
        'gid': info.st_gid, 'retention': 'managed'}}
    fixture['context']['inventory_digest'] = evidence.digest_inventory(
        fixture['scope'], fixture['expected_manifest'], fixture['units'])
    receipt = observe(fixture)
    assert checked(receipt, fixture)['quiescent']
    actual = receipt['snapshots'][0]['files']['links'][logical]
    assert actual['target'] == '../wa-receiver.service'
    assert actual['resolved_target'] == '/etc/systemd/system/wa-receiver.service'
    fixture['expected_manifest']['links'][logical]['resolved_target'] = '/opt/unrelated.service'
    with pytest.raises(evidence.EvidenceError, match='resolved target differs'):
        evidence.digest_inventory(fixture['scope'], fixture['expected_manifest'], fixture['units'])
