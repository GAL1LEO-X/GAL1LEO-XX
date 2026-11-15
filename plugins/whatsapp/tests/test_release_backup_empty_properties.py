"""Synthetic systemd observations for the independently installed N01 reader."""
import json
from types import SimpleNamespace

import pytest

from test_backup_journal import prerequisite
import github_release as release
import github_release_common as common
import release_backup as journal


AUXILIARY = ('ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecCondition')


@pytest.fixture
def omitted_recovery(prerequisite, monkeypatch):
    # These are constructed observations, not a capture from the real server.
    state = SimpleNamespace(prerequisite=prerequisite, omitted=set(AUXILIARY), typed_calls=[],
                            response=json.dumps({'type': 'a(sasbttttuii)', 'data': []}), failure=None,
                            rewrite=lambda value: value)
    original = journal.run
    def run(argv, **kwargs):
        if argv[0] == '/usr/bin/busctl':
            state.typed_calls.append(argv)
            prerequisite.calls.append(argv)
            assert kwargs == {'timeout': 5}
            if state.failure is not None:
                raise state.failure
            return state.response
        result = original(argv, **kwargs)
        if argv[:2] == ['systemctl', 'show']:
            result = '\n'.join(line for line in result.splitlines()
                               if line.partition('=')[0] not in state.omitted)
            result = state.rewrite(result)
        return result
    monkeypatch.setattr(journal, 'run', run)
    return state


def test_omitted_five_empty_commands_require_five_typed_proofs(omitted_recovery):
    p = omitted_recovery
    assert journal.verify_prerequisites(p.prerequisite.root) == journal.capabilities()
    object_name = ''.join(char if char.isascii() and char.isalnum()
                          else '_' + format(ord(char), '02x') for char in journal.RECOVERY_SERVICE)
    assert p.typed_calls == [
        ['/usr/bin/busctl', '--system', '--json=short', 'get-property', 'org.freedesktop.systemd1',
         '/org/freedesktop/systemd1/unit/' + object_name, 'org.freedesktop.systemd1.Service', field]
        for field in AUXILIARY]
    assert all(not {'start', 'restart', 'enable', 'stop'} & set(argv)
               for argv in p.prerequisite.calls)


@pytest.mark.parametrize('field', AUXILIARY)
def test_only_omitted_command_is_queried(omitted_recovery, field):
    p = omitted_recovery
    p.omitted = {field}
    assert journal.verify_prerequisites(p.prerequisite.root) == journal.capabilities()
    assert [argv[-1] for argv in p.typed_calls] == [field]


@pytest.mark.parametrize('response', [
    '{"type":"a(sasbttttuii)","data":[["/unexpected",[],false,0,0,0,0,0,0,0]]}',
    '{"type":"as","data":[]}',
    '{"type":"a(sasbttttuii)"}',
    '{"data":[]}',
    '{"type":"wrong","type":"a(sasbttttuii)","data":[]}',
    '{"type":"a(sasbttttuii)","data":["unexpected"],"data":[]}',
    '{"type":"a(sasbttttuii)","data":[],"extra":true}',
    '{"type":"a(sasbttttuii)","data":null}',
    '{"type":"a(sasbttttuii)","data":{}}',
    '{"type":"a(sasbttttuii)","data":false}',
    '{"type":"a(sasbttttuii)","data":NaN}',
    '{"type":"a(sasbttttuii)","data":Infinity}',
    '[{"type":"a(sasbttttuii)","data":[]}]',
    '{synthetic-private-diagnostic',
    '',
    ' ' * (journal.MAX_TYPED_RECOVERY + 1),
    '[' * 2000 + ']' * 2000,
    '\ud800',
    b'{"type":"a(sasbttttuii)","data":[]}',
], ids=['nonempty', 'wrong-signature', 'missing-data', 'missing-signature',
        'duplicate-signature', 'duplicate-data', 'extra-field', 'null-data',
        'mapping-data', 'boolean-data', 'nan-data', 'infinity-data', 'list-root',
        'invalid-json', 'empty-response', 'oversized', 'deep-json', 'invalid-unicode', 'byte-response'])
def test_omission_does_not_prove_emptiness(omitted_recovery, response):
    p = omitted_recovery
    p.response = response
    with pytest.raises(common.ReleaseError) as caught:
        journal.verify_prerequisites(p.prerequisite.root)
    assert 'synthetic-private-diagnostic' not in str(caught.value)
    assert len(p.typed_calls) == 1
    assert not any('--check' in argv for argv in p.prerequisite.calls)


def test_unavailable_typed_observation_is_not_defaulted(omitted_recovery):
    p = omitted_recovery
    p.failure = common.ReleaseError('A deployment command failed: busctl')
    with pytest.raises(common.ReleaseError, match='busctl'):
        journal.verify_prerequisites(p.prerequisite.root)
    assert len(p.typed_calls) == 1


@pytest.mark.parametrize('field', ['LoadState', 'NeedDaemonReload', 'FragmentPath', 'DropInPaths',
                                  'ActiveState', 'UnitFileState', 'Unit', 'TimersMonotonic',
                                  'Type', 'User', 'ExecStart', 'Restart', 'RestartForceExitStatus'])
def test_missing_identity_state_or_main_command_still_fails_closed(omitted_recovery, field):
    p = omitted_recovery
    p.omitted.add(field)
    with pytest.raises(common.ReleaseError, match='Incomplete effective'):
        journal.verify_prerequisites(p.prerequisite.root)
    assert not p.typed_calls


@pytest.mark.parametrize('tail', ['\nExecStop=', '\nUnexpected=ignored', '\nmalformed'])
def test_unknown_duplicate_or_malformed_show_response_is_rejected(omitted_recovery, tail):
    p = omitted_recovery
    p.omitted = set()
    p.rewrite = lambda response: response + tail if 'Type=oneshot' in response else response
    with pytest.raises(common.ReleaseError, match='Cannot establish'):
        journal.verify_prerequisites(p.prerequisite.root)
    assert not p.typed_calls


@pytest.mark.parametrize('field', AUXILIARY)
def test_present_nonempty_auxiliary_command_is_not_hidden_by_typed_reader(omitted_recovery, field):
    p = omitted_recovery
    p.omitted = set()
    p.prerequisite.service[field] = '{ path=/unexpected ; argv[]=/unexpected ; }'
    with pytest.raises(common.ReleaseError, match='Unexpected auxiliary'):
        journal.verify_prerequisites(p.prerequisite.root)
    assert not p.typed_calls


@pytest.mark.parametrize('unit', ['unrelated.service', journal.RECOVERY_TIMER])
def test_omission_fallback_is_scoped_to_the_dedicated_service(monkeypatch, unit):
    calls = []
    monkeypatch.setattr(journal, 'run', lambda argv, **kwargs: calls.append(argv) or 'Type=oneshot')
    with pytest.raises(common.ReleaseError, match='Incomplete effective'):
        journal.unit_properties(unit, ['Type', 'ExecStop'])
    assert len(calls) == 1 and calls[0][:2] == ['systemctl', 'show']


@pytest.mark.parametrize('unit,field', [('unrelated.service', 'ExecStop'),
                                      (journal.RECOVERY_TIMER, 'ExecStop'),
                                      (journal.RECOVERY_SERVICE, 'ExecStart'),
                                      (journal.RECOVERY_SERVICE, 'User')])
def test_typed_reader_cannot_query_other_units_or_properties(monkeypatch, unit, field):
    monkeypatch.setattr(journal, 'run', lambda *args, **kwargs: pytest.fail('unscoped D-Bus query'))
    with pytest.raises(common.ReleaseError, match='outside the dedicated'):
        journal.require_empty_auxiliary(unit, field)


def test_unproven_empty_command_blocks_before_backup_activity_or_journal(omitted_recovery, monkeypatch):
    p = omitted_recovery
    p.response = '{"type":"a(sasbttttuii)","data":[["unexpected"]]}'
    for name in ('backup_components', 'run_backup_process'):
        monkeypatch.setattr(release, name, lambda *args: pytest.fail('backup effect after failed N01'))
    monkeypatch.setattr(journal, 'begin', lambda *args: pytest.fail('journal after failed N01'))
    with pytest.raises(common.ReleaseError, match='not proven empty'):
        release.runtime_backups(p.prerequisite.root, [], 0, '0.5.0')
