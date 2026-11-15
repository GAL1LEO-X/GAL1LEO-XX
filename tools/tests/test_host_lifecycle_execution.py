"""Typed callbacks and derived comparisons; no real manager or network."""
import copy
import json

import pytest

from host.lifecycle import evidence
from test_host_lifecycle_evidence import fixture, observe, checked, unit_properties, encoded_unit


UNIT = 'wa-receiver.service'
SECRET = 'SYNTHETIC-EXEC-ARGUMENT-NEVER-EXPORTED'


def typed(commands=()):
    return json.dumps({'type': 'a(sasbttttuii)', 'data': list(commands)}).encode()


def row(*arguments):
    return ['/usr/bin/python3', ['/usr/bin/python3', *arguments], False, 0, 0, 0, 0, 0, 0, 0]


def install_execution(fixture):
    raw = {key: typed([row(SECRET)]) if key == 'ExecStart' else typed()
           for key in evidence.EXECUTION_PROPERTIES}
    fixture['units'][UNIT]['execution'] = {key: evidence.execution_identity(value) for key, value in raw.items()}
    fixture['context']['inventory_digest'] = evidence.digest_inventory(
        fixture['scope'], fixture['expected_manifest'], fixture['units'])
    calls = []
    def runner(argv, **limits):
        calls.append(argv)
        assert limits == {'timeout': 5.0, 'max_bytes': evidence.MAX_COMMAND}
        if argv == evidence.show_argv(UNIT):
            return encoded_unit(unit_properties())
        assert argv == evidence.execution_argv(UNIT, argv[-1])
        return raw[argv[-1]]
    return raw, calls, runner


def test_seven_typed_properties_are_explicit_digest_only_and_readonly(fixture):
    raw, calls, runner = install_execution(fixture)
    receipt = observe(fixture, runner=runner)
    assert checked(receipt, fixture)['quiescent']
    assert len(calls) == 16  # Two observations, each show plus exactly seven GetProperty.
    assert SECRET not in json.dumps(receipt)
    assert all(evidence._readonly_argv(argv) for argv in calls)
    assert receipt['snapshots'][0]['units'][UNIT]['Execution']['ExecStart']['count'] == 1
    assert evidence.execution_identity(typed()) == {'count': 0,
        'identity_sha256': '37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570'}


def test_typed_projection_matches_the_approved_public_backup_command():
    entry = '/srv/openai-codex/projects/whatsapp-personal/scripts/backup_runtime.py'
    command = ['/usr/bin/flock', ['/usr/bin/flock', '-n', '/run/lock/whatsapp-personal-backup.lock',
        '/srv/openai-codex/projects/whatsapp-personal/.venv/bin/python', entry], False, 0, 0, 0, 0, 0, 0, 0]
    assert evidence.execution_identity(typed([command])) == {'count': 1,
        'identity_sha256': '459ad8a671b73c55f04706b067b24ccbefac835bf39a0ba97ecc048ccc05cfcb'}


@pytest.mark.parametrize('raw', [b'', b'{}', b'{"type":"a(sasbttttuii)"}',
    b'{"type":"a(sasbttttuii)","data":null}', b'{"type":"s","data":[]}',
    b'{"type":"a(sasbttttuii)","data":[],"data":[]}',
    typed([row('x')[:-1]]), typed([row('x')[:2] + [0] + [0]*7]), typed([row('x')]*33)])
def test_missing_malformed_or_oversized_typed_data_never_becomes_empty(raw):
    with pytest.raises(evidence.EvidenceError, match='typed execution'):
        evidence.execution_identity(raw)


@pytest.mark.parametrize('property_name', ['ExecStopPost', 'ExecCondition', 'ExecReload'])
def test_new_callback_is_rejected_even_with_quiet_unit_and_matching_sources(fixture, property_name):
    raw, _, runner = install_execution(fixture)
    raw[property_name] = typed([row(SECRET)])
    with pytest.raises(evidence.EvidenceError, match='Typed unit execution differs') as error:
        checked(observe(fixture, runner=runner), fixture)
    assert SECRET not in str(error.value)


def test_execution_arg_order_is_significant():
    assert evidence.execution_identity(typed([row('first', 'second')])) != evidence.execution_identity(typed([row('second', 'first')]))


@pytest.mark.parametrize('alteration', ['environment', 'getall', 'refunit', 'timer', 'other-service', 'systemctl-start'])
def test_collector_allowlist_excludes_environment_load_ref_and_mutation(alteration):
    argv = evidence.execution_argv(UNIT, 'ExecStart')
    if alteration == 'environment': argv[-1] = 'Environment'
    elif alteration == 'getall': argv[3] = 'call'
    elif alteration == 'refunit': argv[-1] = 'RefUnit'
    elif alteration == 'timer': argv[5] = argv[5].replace('_2eservice', '_2etimer')
    elif alteration == 'other-service': argv[6] = 'org.freedesktop.systemd1.Timer'
    else: argv = ['/usr/bin/systemctl', 'start', UNIT]
    assert not evidence._readonly_argv(argv)


def test_only_after_before_order_is_derived_and_raw_receipt_stays_unchanged(fixture):
    wanted = ['-.mount', 'sysinit.target']
    fixture['units'][UNIT]['references'].update(After=wanted, Before=wanted)
    fixture['context']['inventory_digest'] = evidence.digest_inventory(
        fixture['scope'], fixture['expected_manifest'], fixture['units'])
    observations = iter(['-.mount sysinit.target', 'sysinit.target -.mount'])
    def runner(*args, **kwargs):
        members = next(observations)
        return encoded_unit({**unit_properties(), 'After': members, 'Before': members})
    receipt = observe(fixture, runner=runner)
    original = evidence.canonical(receipt)
    assert receipt['snapshots'][0] != receipt['snapshots'][1]
    assert checked(receipt, fixture)['quiescent']
    assert evidence.canonical(receipt) == original


@pytest.mark.parametrize('property_name', ['Requires', 'Triggers', 'TriggeredBy', 'InvocationID', 'Execution'])
def test_all_other_observed_values_remain_strict(property_name):
    a = {'units': {UNIT: {property_name: ['a', 'b'] if property_name == 'Execution' else 'a.service b.service'}}}
    b = copy.deepcopy(a)
    b['units'][UNIT][property_name] = ['b', 'a'] if property_name == 'Execution' else 'b.service a.service'
    assert not evidence.snapshots_equal(a, b)


def test_changed_ordering_member_or_duplicate_is_not_an_order_only_difference():
    a = {'units': {UNIT: {'After': 'a.service b.service'}}}
    assert not evidence.snapshots_equal(a, {'units': {UNIT: {'After': 'a.service c.service'}}})
    with pytest.raises(evidence.EvidenceError, match='duplicate'):
        evidence.snapshots_equal(a, {'units': {UNIT: {'After': 'a.service a.service'}}})


def test_old_callback_receipt_cannot_satisfy_new_expectation(fixture):
    raw, _, runner = install_execution(fixture)
    receipt = observe(fixture, runner=runner)
    for snapshot in receipt['snapshots']:
        del snapshot['units'][UNIT]['Execution']
    receipt['receipt_digest'] = evidence.digest({key: value for key, value in receipt.items() if key != 'receipt_digest'})
    with pytest.raises(evidence.EvidenceError, match='Execution observation differs'):
        checked(receipt, fixture)
