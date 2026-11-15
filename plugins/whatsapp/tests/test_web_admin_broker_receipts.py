"""Exact negative receipts: no certainty is inferred from a missing journal row."""
from contextlib import contextmanager
from copy import deepcopy
import sqlite3

import pytest

from test_web_admin_broker import policy, broker, make, envelope, write, assert_error


def assert_rejected_before_intent(response, request, code):
    assert response['ok'] is True
    row = response['result']
    assert {key: row[key] for key in ('id', 'operation', 'target')} == {
        key: request[key] for key in ('id', 'operation', 'target')}
    assert row['approval'] == request['arguments']['approval']
    assert row['state'] == 'failed_before_execution'
    assert row['execution_phase'] == 'before_intent' and row['error_code'] == code
    assert 'result' not in row


@pytest.mark.parametrize('reason', ['expiry', 'preflight'])
def test_read_only_rejection_has_bound_receipt_without_intent_or_effect(policy, reason):
    p, path = policy
    effects = []
    def preflight(*args):
        raise broker.Rejected('BROKER_SOURCE_CHANGED')
    if reason == 'expiry':
        p['approvals']['e'*32]['expires'] = 1
        write(path, p)
    service = make(policy, lambda *args: effects.append(args), preflight=preflight)
    response = service.handle(1234, envelope())
    assert_rejected_before_intent(response, envelope()['request'],
        'BROKER_APPROVAL_EXPIRED' if reason == 'expiry' else 'BROKER_SOURCE_CHANGED')
    assert effects == []
    with service.database(p) as db:
        assert db.execute('SELECT count(*) FROM requests').fetchone()[0] == 0
    # A lost negative receipt cannot be reconstructed from host row absence.
    assert_error(service.handle(1234, envelope('status')), 'BROKER_NOT_FOUND')


@pytest.mark.parametrize('prior', ['completed', 'uncertain', 'running'])
def test_existing_intent_or_consumed_approval_cannot_be_reclassified_as_rejected(policy, prior):
    def executor(*args):
        if prior == 'running':
            raise KeyboardInterrupt
        if prior == 'uncertain':
            raise broker.Rejected('BROKER_APPROVAL_EXPIRED')
        return {'completed': True, 'operation': 'backup.create', 'target': 'alpha'}
    service = make(policy, executor)
    if prior == 'running':
        with pytest.raises(KeyboardInterrupt):
            service.handle(1234, envelope())
    else:
        service.handle(1234, envelope())
    p, path = policy
    p['approvals']['e'*32]['expires'] = 1
    p['approvals']['1'*32] = deepcopy(p['approvals']['e'*32])
    write(path, p)
    service = make(policy, lambda *_: pytest.fail('Prior request was replayed'))
    assert service.handle(1234, envelope())['result']['state'] == ('completed' if prior == 'completed' else 'uncertain')
    assert_error(service.handle(1234, envelope(approval='1'*32)), 'BROKER_IDEMPOTENCY_CONFLICT')
    assert_error(service.handle(1234, envelope(identifier='2'*32)), 'BROKER_APPROVAL_CONSUMED')


@pytest.mark.parametrize('commit_point', ['before', 'after'])
def test_intent_commit_failure_is_never_a_preintent_receipt(policy, monkeypatch, commit_point):
    original_connect = sqlite3.connect
    armed = [True]
    effects = []
    class Connection(sqlite3.Connection):
        def commit(self):
            intent = self.execute('SELECT count(*) FROM requests').fetchone()[0] > 0
            if intent and armed[0]:
                armed[0] = False
                if commit_point == 'after':
                    super().commit()
                raise broker.Rejected('SYNTHETIC_COMMIT_UNCERTAIN')
            super().commit()
    monkeypatch.setattr(broker.sqlite3, 'connect',
                        lambda *a, **kw: original_connect(*a, **kw, factory=Connection))
    service = make(policy, lambda *args: effects.append(args))
    assert_error(service.handle(1234, envelope()), 'SYNTHETIC_COMMIT_UNCERTAIN')
    assert effects == []
    observation = service.handle(1234, envelope('status'))
    if commit_point == 'after':
        assert observation['result']['state'] == 'uncertain'
    else:
        assert_error(observation, 'BROKER_NOT_FOUND')


def test_worker_rejection_after_effect_is_uncertain_even_with_preintent_error_code(policy):
    effects = []
    def worker(*args):
        effects.append('synthetic-effect')
        raise broker.Rejected('BROKER_APPROVAL_EXPIRED')
    service = make(policy, worker)
    result = service.handle(1234, envelope())
    assert result['result']['state'] == 'uncertain'
    assert 'execution_phase' not in result['result']
    assert service.handle(1234, envelope())['result']['state'] == 'uncertain'
    assert effects == ['synthetic-effect']


def test_id_is_rechecked_after_acquiring_execution_lease(policy):
    service = make(policy, lambda *_: pytest.fail('Previously admitted request was replayed'))
    @contextmanager
    def completing_predecessor(p):
        assert make(policy).handle(1234, envelope())['result']['state'] == 'completed'
        with broker.Broker.execution_lock(service, p) as lease:
            yield lease
    service.execution_lock = completing_predecessor
    result = service.handle(1234, envelope())
    assert result['result']['state'] == 'completed'


def test_policy_rejects_blank_human_description(policy):
    value, _ = policy
    value['approvals']['e'*32]['description'] = ' \n\t '
    with pytest.raises(broker.Rejected):
        broker.validate_policy(value)
