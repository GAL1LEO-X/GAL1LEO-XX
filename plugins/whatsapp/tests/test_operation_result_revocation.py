"""Only synthetic gateway echoes and isolated SQLite databases are used here."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import threading

import pytest

from sally_whatsapp.operations import OPERATIONS, execute
from sally_whatsapp.server import OperationAction
from sally_whatsapp.store import Store, canonical
from test_expanded import enabled


KEY = 'synthetic-result-request'
PROVIDER = 'synthetic-result-message'
ECHO = {'id': PROVIDER, 'body': 'SYNTHETIC_REVOKED_TEXT',
        'nested': [{'caption': 'SYNTHETIC_REVOKED_TEXT'}],
        'media': {'filename': 'synthetic-private.txt'}}


def revoke(store):
    store.ingest({'id': 'synthetic-revocation', 'event': 'message.revoked',
                  'payload': {'revokedMessageId': PROVIDER}})


def queued(store, operation='messages_send_text'):
    store.queue_action(KEY, 'test-owner', operation,
                       {'body': {'chatId': 'fixture@c.us', 'text': 'synthetic'}})


def legacy_result(store, result=ECHO):
    store.finish_send(KEY, 'submitted', PROVIDER)
    with store.db() as db:
        db.execute('INSERT OR REPLACE INTO operation_results VALUES(?,?)', (KEY, canonical(result)))


def persisted(store):
    with store.db() as db:
        return json.loads(db.execute('SELECT result FROM operation_results WHERE key=?', (KEY,)).fetchone()[0])


def test_action_gateway_echo_is_minimized_before_storage(environment):
    service, gateway = enabled(environment)
    gateway.request = lambda *args, **kwargs: ECHO
    args = OperationAction(operation='messages_send_text', arguments={
        'body': {'chatId': 'fixture@c.us', 'text': 'synthetic'}}, idempotency_key=KEY)
    service.operation(args, 'test-owner')
    assert service.process_action()
    assert persisted(service.store) == {'id': PROVIDER}
    revoke(service.store)
    assert service.store.send_status(KEY)['result'] == {'id': PROVIDER}
    assert service.store.send_status(KEY)['delivery']['reason'] == 'message_revoked'
    assert service.operation(args, 'test-owner')['state'] == 'submitted'
    assert not service.process_action()


@pytest.mark.parametrize('revoke_first', [True, False])
@pytest.mark.parametrize('operation', ['messages_send_text', 'messages_set_reaction'])
def test_revoke_and_finish_serial_orders_preserve_only_metadata(tmp_path, revoke_first, operation):
    store = Store(tmp_path / 'synthetic.sqlite')
    queued(store, operation)
    if revoke_first:
        revoke(store)  # Tombstone without an archived message is sufficient.
    result = store.finish_send(KEY, 'submitted', PROVIDER, result=ECHO)
    if not revoke_first:
        revoke(store)
    assert result['result'] == {'id': PROVIDER}
    assert persisted(store) == {'id': PROVIDER}
    status = store.send_status(KEY)
    assert status['state'] == 'submitted' and status['provider_id'] == PROVIDER
    assert status['result'] == {'id': PROVIDER}
    assert store.send_status(KEY, owner='another-owner') is None
    assert store.queue_action(KEY, 'test-owner', operation, {
        'body': {'chatId': 'fixture@c.us', 'text': 'synthetic'}})['state'] == 'submitted'


@pytest.mark.parametrize('writer_first', [True, False])
def test_revoke_write_race_serializes_at_database_lock(tmp_path, writer_first, monkeypatch):
    store = Store(tmp_path / 'synthetic.sqlite')
    queued(store)
    entered, release, other_started = threading.Event(), threading.Event(), threading.Event()
    original = Store.db

    # Hold the write transaction *inside* the first operation, including its mutation.
    @contextmanager
    def transaction_barrier(self):
        with original(self) as db:
            yield db
            if threading.current_thread().name.startswith('held-writer'):
                entered.set()
                assert release.wait(5)

    monkeypatch.setattr(Store, 'db', transaction_barrier)
    finish = lambda: store.finish_send(KEY, 'submitted', PROVIDER, result=ECHO)
    first, second = (finish, lambda: revoke(store)) if writer_first else (lambda: revoke(store), finish)

    def contender():
        other_started.set()
        return second()

    with ThreadPoolExecutor(1, thread_name_prefix='held-writer') as held, ThreadPoolExecutor(1) as other:
        first_future = held.submit(first)
        try:
            assert entered.wait(5)
            second_future = other.submit(contender)
            assert other_started.wait(5)
        finally:
            release.set()
        first_future.result(5)
        second_future.result(5)
    assert persisted(store) == {'id': PROVIDER}
    assert store.send_status(KEY)['delivery']['reason'] == 'message_revoked'


def test_legacy_status_is_safe_and_read_only_before_repair(tmp_path):
    store = Store(tmp_path / 'synthetic.sqlite', migrate_schema=False)
    queued(store)
    legacy_result(store)
    revoke(store)
    # Model a historical/unpatched writer after the tombstone as well.
    legacy_result(store)
    before = persisted(store)
    status = store.send_status(KEY)
    assert status['result'] == {'id': PROVIDER}
    assert status['delivery']['reason'] == 'message_revoked'
    assert persisted(store) == before


def test_new_repair_runs_even_with_existing_revocation_marker(tmp_path):
    store = Store(tmp_path / 'synthetic.sqlite')
    queued(store)
    legacy_result(store)
    # Remove only the new repair marker to model an existing installation.
    with store.db() as db:
        db.execute("DELETE FROM state WHERE key='private:operation_result_metadata:v1'")
        original = dict(db.execute('SELECT * FROM sends WHERE key=?', (KEY,)).fetchone())
    reopened = Store(store.path)
    assert persisted(reopened) == {'id': PROVIDER}
    with reopened.db() as db:
        assert dict(db.execute('SELECT * FROM sends WHERE key=?', (KEY,)).fetchone()) == original
    assert 'private:operation_result_metadata:v1' not in reopened.state()


def test_targeted_revoke_normalizes_legacy_storage(tmp_path):
    store = Store(tmp_path / 'synthetic.sqlite')
    queued(store)
    legacy_result(store)
    revoke(store)
    assert persisted(store) == {'id': PROVIDER}


@pytest.mark.parametrize('value', [ECHO, [{'body': 'SYNTHETIC_REVOKED_TEXT'}], 'SYNTHETIC_REVOKED_TEXT', True, None])
def test_write_response_minimization_does_not_change_readonly_response(environment, value):
    settings = environment[0]
    class Gateway:
        def request(self, *args, **kwargs):
            return value
    args = {'path': {}, 'query': {}, 'body': {}}
    if value is ECHO:
        assert execute(Gateway(), settings, OPERATIONS['messages_send_text'], args) == {'id': PROVIDER}
    else:
        # Non-message payloads must not be acknowledged as a submitted message.
        # The privacy requirement still applies to the failure and read path.
        from sally_whatsapp.gateway import GatewayUnavailable
        with pytest.raises(GatewayUnavailable) as caught:
            execute(Gateway(), settings, OPERATIONS['messages_send_text'], args)
        assert 'SYNTHETIC_REVOKED_TEXT' not in str(caught.value)
    assert execute(Gateway(), settings, OPERATIONS['contacts_get_all'], args) == value


def test_untrusted_error_is_never_preserved_as_local_diagnostic(tmp_path):
    store = Store(tmp_path / 'synthetic.sqlite')
    queued(store)
    status = store.finish_send(KEY, 'failed_before_send', result={'error': 'SYNTHETIC_REVOKED_TEXT'})
    assert status['result'] == {'error': 'Action preparation failed; no provider request made'}


@pytest.mark.parametrize(('operation', 'value', 'expected'), [
    ('groups_get_invite_code', 'SYNTHETIC-INVITE-CODE', 'SYNTHETIC-INVITE-CODE'),
    ('groups_revoke_invite_code', 'SYNTHETIC-INVITE-CODE', 'SYNTHETIC-INVITE-CODE'),
    ('groups_set_subject', False, False),
    ('groups_set_description', True, True),
    ('groups_set_picture', {'success': False, 'body': ECHO}, {'success': False}),
    ('groups_approve_group_join_requests', [{'requesterId': 'fixture@c.us', 'success': False,
        'error': 403, 'body': ECHO}], [{'requesterId': 'fixture@c.us', 'success': False, 'error': 403}]),
    ('groups_add_participants', [{'id': 'fixture@c.us', 'status': 403, 'body': ECHO}],
        [{'id': 'fixture@c.us', 'status': 403}]),
])
def test_administrative_results_preserve_typed_outcomes_and_invite_codes(environment, operation, value, expected):
    service, gateway = enabled(environment, actions=True)
    gateway.request = lambda *args, **kwargs: value
    args = {'path': {'id': 'synthetic@g.us'}, 'query': {}, 'body': {}}
    result = execute(gateway, service.settings, OPERATIONS[operation], args)
    assert result == expected
    service.store.queue_action(KEY, 'test-owner', operation, args)
    assert service.store.finish_send(KEY, 'submitted', result=result)['result'] == expected
    # Model an unpatched historical writer; both read projection and startup
    # normalization must use the stored operation, rather than guessing shapes.
    with service.store.db() as db:
        db.execute('UPDATE operation_results SET result=? WHERE key=?', (canonical(value), KEY))
        db.execute("DELETE FROM state WHERE key='private:operation_result_metadata:v1'")
    assert service.store.send_status(KEY)['result'] == expected
    reopened = Store(service.store.path)
    assert persisted(reopened) == expected
