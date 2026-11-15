from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
from threading import Event, Thread
from concurrent.futures import ThreadPoolExecutor

import pytest

from sally_whatsapp.admin import PREFIX, RuntimeAdminOperations
from sally_whatsapp.admin_broker import AdminBrokerClient, BrokerError, receipt
from test_admin_panel import admin, request


APPROVAL = 'a' * 32


@pytest.fixture
def tmp_path(short_socket_tmp_path):
    """Keep the entire socket fixture physical and below the AF_UNIX limit."""
    return short_socket_tmp_path


def completed(body):
    return {**{key: body[key] for key in ('id', 'operation', 'target')}, 'state': 'completed',
            'approval': body['arguments']['approval'],
            'result': {'exit_code': 0, 'receipt_sha256': 'b' * 64}}


def action(**changes):
    return {'operation': 'instance.prepare', 'target': 'beta', 'approval': APPROVAL,
            'available': True, 'scope': 'instance', 'affected_instances': ['beta'],
            'description': 'Prepara beta con il piano approvato.', **changes}


@contextmanager
def socket_peer(tmp_path, responder):
    path = tmp_path / 'synthetic.sock'
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    path.chmod(0o660)
    server.listen()
    server.settimeout(.05)
    stopping, calls = Event(), []
    failures = []
    def run():
        while not stopping.is_set():
            try:
                connection, _ = server.accept()
            except TimeoutError:
                continue
            with connection:
                connection.settimeout(2)
                raw = bytearray()
                while b'\n' not in raw:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    raw.extend(chunk)
                if not raw:
                    continue
                try:
                    value = json.loads(raw)
                    calls.append(value)
                    output = responder(value)
                    if output is not None:
                        connection.sendall(output if isinstance(output, bytes) else json.dumps(output).encode() + b'\n')
                except Exception as exc:
                    failures.append(exc)
    worker = Thread(target=run)
    worker.start()
    try:
        yield path, calls
    finally:
        stopping.set()
        worker.join(3)
        server.close()
        assert not worker.is_alive()
        assert not failures


def test_configuration_requires_explicit_panel_and_run_socket(environment):
    settings = environment[0]
    configured = replace(settings, admin_enabled=True, link_client_id='pair-client',
                         link_authorize_url='https://issuer.example/authorize',
                         link_token_url='https://issuer.example/token')
    assert replace(configured, admin_broker_socket=Path('/run/whatsapp-admin/broker.sock'), admin_broker_instance='alpha').admin_enabled
    for path in (Path('relative.sock'), Path('/tmp/a.sock'), Path('/run/../tmp/a.sock'), '',
                 Path('/run/' + 'x' * 110), Path('/run')):
        with pytest.raises(ValueError):
            replace(configured, admin_broker_socket=path, admin_broker_instance='alpha')
    with pytest.raises(ValueError):
        replace(settings, admin_broker_socket=Path('/run/whatsapp-admin/broker.sock'))
    for instance in ('Display Name', '', '../alpha'):
        with pytest.raises(ValueError):
            replace(configured, admin_broker_socket=Path('/run/whatsapp-admin/broker.sock'), admin_broker_instance=instance)
    with pytest.raises(ValueError):
        replace(configured, admin_broker_instance='alpha')


def test_unix_rpc_binds_identity_validates_peer_and_strips_private_output(tmp_path, monkeypatch):
    with socket_peer(tmp_path, lambda body: {'ok': True, 'result': {**completed(body['request']),
                            'private_path': '/secret', 'message': 'private'}}) as (path, calls):
        client = AdminBrokerClient(path, 'owner-a', 'alpha', expected_uid=os.getuid())
        # The socket is a synthetic fixture under pytest's writable tmpdir.
        monkeypatch.setattr(client, '_socket_identity', lambda: (1, 2))
        body = request('instance.prepare', 'beta', arguments={'approval': APPROVAL})
        assert client.execute(body) == completed(body)
        assert calls == [{'version': 1, 'method': 'execute', 'owner': 'owner-a', 'instance': 'alpha', 'request': body}]
        client.expected_uid = os.getuid() + 1
        with pytest.raises(BrokerError) as failure:
            client.execute(body)
        assert not failure.value.uncertain
        assert failure.value.code == 'ADMIN_BROKER_PEER_REJECTED'
        assert len(calls) == 1


@pytest.mark.parametrize('output', [None, b'{}\n', b'{"ok":true,"ok":false}\n',
                                   b'x' * 65537, b'{"ok":true}', b'{}\n{}\n'])
def test_lost_or_malformed_response_is_uncertain_and_never_retried(tmp_path, monkeypatch, output):
    with socket_peer(tmp_path, lambda _: output) as (path, calls):
        client = AdminBrokerClient(path, 'owner', 'alpha', expected_uid=os.getuid())
        monkeypatch.setattr(client, '_socket_identity', lambda: (1, 2))
        with pytest.raises(BrokerError) as failure:
            client.execute(request('backup.restore', 'alpha', arguments={'approval': APPROVAL}))
        assert failure.value.uncertain
        assert len(calls) == 1


def test_unprotected_ancestor_symlink_and_missing_socket_are_never_contacted(tmp_path):
    with socket_peer(tmp_path, lambda _: pytest.fail('Unprotected socket contacted')) as (path, calls):
        client = AdminBrokerClient(path, 'owner', 'alpha', expected_uid=os.getuid())
        with pytest.raises(BrokerError) as failure:
            client.call('capabilities', {})
        assert not failure.value.uncertain
        assert failure.value.code == 'ADMIN_BROKER_PATH_REJECTED'
        assert not calls


@pytest.mark.parametrize('field,value', [('id', 'c'*32), ('approval', 'c'*32), ('operation', 'backup.restore'),
    ('target', 'foreign'), ('state', 'running'), ('result', {'exit_code': 0}),
    ('result', {'exit_code': True, 'receipt_sha256': 'b'*64})])
def test_receipts_are_bound_and_completion_requires_evidence(field, value):
    body = request('instance.prepare', 'beta', arguments={'approval': APPROVAL})
    with pytest.raises(BrokerError):
        receipt({**completed(body), field: value}, body)


@pytest.mark.parametrize('change', [{'target': '../private'}, {'approval': 'not-a-reference'},
    {'operation': 'shell'}, {'affected_instances': []}, {'affected_instances': ['other']},
    {'available': 1}, {'scope': 'unknown'}, {'affected_instances': ['beta', 'beta']},
    {'description': ''}, {'description': ' \n\t'}, {'description': None},
    {'description': ['Unexpected array']}, {'description': 'x'*257}])
def test_invalid_capabilities_never_offer_a_command(change, monkeypatch):
    client = AdminBrokerClient('/run/synthetic.sock', 'owner', 'alpha')
    monkeypatch.setattr(client, 'call', lambda *_: {'scope': 'delegated_only', 'actions': [action(**change)]})
    with pytest.raises(BrokerError):
        client.capabilities()


def test_capability_truncation_and_public_description_are_preserved_without_private_fields(monkeypatch):
    client = AdminBrokerClient('/run/synthetic.sock', 'owner', 'alpha')
    monkeypatch.setattr(client, 'call', lambda *_: {'scope': 'delegated_only',
        'actions': [action(description='Ripristina snapshot sintetico del 20 ottobre.', private_debug='/private/host/path')], 'receipts': [],
        'actions_truncated': True, 'receipts_truncated': True})
    value = client.capabilities()
    assert value['actions_truncated'] is True
    assert value['receipts_truncated'] is True
    assert value['actions'][0]['description'] == 'Ripristina snapshot sintetico del 20 ottobre.'
    assert 'private_debug' not in value['actions'][0]


def test_capabilities_require_description_and_preserve_distinct_approved_restore_summaries(monkeypatch):
    client = AdminBrokerClient('/run/synthetic.sock', 'owner', 'alpha')
    first = action(operation='backup.restore', description='Ripristina snapshot del 20 ottobre.')
    second = action(operation='backup.restore', approval='b'*32,
                    description='<img src=x onerror="alert(1)"> Snapshot del 21 ottobre.')
    response = {'scope': 'delegated_only', 'actions': [first, second]}
    monkeypatch.setattr(client, 'call', lambda *_: response)
    observed = client.capabilities()['actions']
    assert observed[0]['description'] == first['description']
    assert observed[1]['description'] == second['description']
    assert observed[0]['target'] == observed[1]['target']
    second['description'] = 'x'*256
    assert client.capabilities()['actions'][1]['description'] == 'x'*256
    del second['description']
    with pytest.raises(BrokerError):
        client.capabilities()


def test_host_api_uses_socket_only_after_owner_csrf_confirmation_and_validated_arguments(admin, tmp_path, monkeypatch):
    app, http, login = admin
    body = request('instance.prepare', 'beta', arguments={'approval': APPROVAL})
    with socket_peer(tmp_path, lambda rpc: {'ok': True, 'result': completed(rpc['request'])}) as (path, calls):
        broker = AdminBrokerClient(path, app.state.service.settings.owner_subject,
                                  app.state.service.settings.profile_name, expected_uid=os.getuid())
        monkeypatch.setattr(broker, '_socket_identity', lambda: (1, 2))
        operations = app.state.admin_portal.operations
        operations.broker = broker
        assert http.post('/admin/api/operations', json=body).status_code == 401
        headers = login()
        assert http.post('/admin/api/operations', json=body).status_code == 403
        assert http.post('/admin/api/operations', headers=headers, json={**body, 'confirmation': 'wrong'}).status_code == 409
        assert http.post('/admin/api/operations', headers=headers,
                         json={**body, 'arguments': {'approval': APPROVAL, 'command': 'shell'}}).status_code == 400
        assert not calls
        result = http.post('/admin/api/operations', headers=headers, json=body)
        assert result.status_code == 200
        assert result.json()['state'] == 'completed'
        assert http.post('/admin/api/operations', headers=headers, json=body).json() == result.json()
        assert len(calls) == 1


def test_lost_response_survives_restart_and_status_reconciles_without_execute(admin, tmp_path, monkeypatch):
    app, http, login = admin
    headers = login()
    observed = {}
    def respond(rpc):
        if rpc['method'] == 'execute':
            observed.update(completed(rpc['request']))
            return None  # the synthetic effect completed, but reply is lost
        assert rpc['method'] == 'status'
        return {'ok': True, 'result': observed}
    with socket_peer(tmp_path, respond) as (path, calls):
        broker = AdminBrokerClient(path, 'owner', 'alpha', expected_uid=os.getuid())
        monkeypatch.setattr(broker, '_socket_identity', lambda: (1, 2))
        app.state.admin_portal.operations.broker = broker
        body = request('backup.restore', 'alpha', arguments={'approval': APPROVAL})
        assert http.post('/admin/api/operations', headers=headers, json=body).json()['state'] == 'uncertain'
        restarted = RuntimeAdminOperations(app.state.service)
        restarted.broker = broker
        app.state.admin_portal.operations = restarted
        assert http.post('/admin/api/operations', headers=headers, json=body).json()['state'] == 'uncertain'
        response = http.get('/admin/api/operations/' + body['id'])
        assert response.json()['state'] == 'completed'
        assert [call['method'] for call in calls] == ['execute', 'status']
        assert http.get('/admin/api/operations/' + 'f'*32).status_code == 404
        assert http.get('/admin/api/operations/' + body['id']).json() == response.json()
        assert [call['method'] for call in calls] == ['execute', 'status', 'status']


def test_receipt_read_winning_timeout_race_cannot_be_downgraded(admin):
    app, _, _ = admin
    operations = app.state.admin_portal.operations
    entered, release = Event(), Event()
    body = request('instance.prepare', 'beta', arguments={'approval': APPROVAL})
    class SlowBroker:
        def execute(self, request):
            entered.set()
            assert release.wait(5)
            raise BrokerError(uncertain=True)
        def status(self, row):
            return completed(body)
    operations.broker = SlowBroker()
    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(operations.execute, body)
        assert entered.wait(5)
        try:
            assert operations.reconcile(body['id'])['state'] == 'completed'
        finally:
            release.set()
        assert running.result(timeout=5)['state'] == 'completed'


def test_broker_unavailable_capability_remains_closed_and_uncertain_record_is_preserved(admin):
    app, _, _ = admin
    operations = app.state.admin_portal.operations
    class UnavailableBroker:
        def capabilities(self):
            raise BrokerError()
        def execute(self, request):
            raise BrokerError(uncertain=True)
        def status(self, row):
            raise BrokerError('NOT_FOUND')
    operations.broker = UnavailableBroker()
    assert all(not item['available'] for item in operations.host_actions())
    body = request('instance.prepare', 'beta', arguments={'approval': APPROVAL})
    assert operations.execute(body)['state'] == 'uncertain'
    value = operations.reconcile(body['id'])
    assert value['state'] == 'uncertain'
    assert value['observation_error_code'] == 'ADMIN_BROKER_UNAVAILABLE'


def test_restore_losing_tenant_journal_recovers_host_receipt_and_never_replays(admin, tmp_path, monkeypatch):
    app, http, login = admin
    headers = login()
    body = request('backup.restore', 'alpha', arguments={'approval': APPROVAL})
    observed = completed(body)
    observed.update(created_at='2026-10-21T12:00:00Z', updated_at='2026-10-21T12:00:01Z')
    def respond(rpc):
        if rpc['method'] == 'capabilities':
            return {'ok': True, 'result': {'actions': [], 'scope': 'delegated_only', 'receipts': [observed]}}
        assert rpc['method'] == 'status'
        return {'ok': True, 'result': observed}
    with socket_peer(tmp_path, respond) as (path, calls):
        broker = AdminBrokerClient(path, 'owner', 'alpha', expected_uid=os.getuid())
        monkeypatch.setattr(broker, '_socket_identity', lambda: (1, 2))
        app.state.admin_portal.operations.broker = broker
        assert app.state.admin_portal.operations.records() == []
        # This models a restored DB predating the operation; root journal remains.
        snapshot = http.get('/admin/api/status').json()
        assert snapshot['operations'][0]['id'] == body['id']
        assert snapshot['operations'][0]['state'] == 'completed'
        response = http.get('/admin/api/operations/' + body['id'])
        assert response.json()['state'] == 'completed'
        with app.state.service.store.db() as db:
            row = json.loads(db.execute('SELECT value FROM state WHERE key=?', (PREFIX + body['id'],)).fetchone()[0])
        assert row['request_hash'] is None
        assert http.post('/admin/api/operations', headers=headers, json=body).status_code == 409
        assert [call['method'] for call in calls] == ['capabilities', 'status']


def test_receipt_reads_require_authenticated_owner_and_unknown_is_not_disclosed(admin):
    app, http, login = admin
    calls = []
    class Broker:
        def status(self, identifier):
            calls.append(identifier)
            raise BrokerError('NOT_FOUND')
    app.state.admin_portal.operations.broker = Broker()
    path = '/admin/api/operations/' + 'a'*32
    assert http.get(path).status_code == 401
    login(sub='other-owner')
    assert http.get(path).status_code == 401
    assert calls == []
    login()
    result = http.get(path)
    assert result.status_code == 404
    assert result.json()['error_code'] == 'ADMIN_RECEIPT_UNAVAILABLE'


def test_restore_maintenance_blocks_local_actions_before_any_effect(admin):
    app, http, login = admin
    headers = login()
    service = app.state.service
    job = service.history.start(service.settings.owner_subject, 'maintenance-test', ['synthetic@c.us'])
    service.restore_maintenance = True
    response = http.post('/admin/api/operations', headers=headers, json=request('history.cancel', job['id']))
    assert response.status_code == 409
    assert response.json()['error_code'] == 'ADMIN_RESTORE_MAINTENANCE'
    assert service.history.status(job['id'], service.settings.owner_subject)['state'] == 'running'
    assert app.state.admin_portal.operations.records() == []
    snapshot = http.get('/admin/api/status').json()
    assert snapshot['restore_maintenance'] is True
    assert snapshot['local_actions'] == []


def test_connection_only_offers_activation_for_exact_delegated_instance(admin):
    app, http, login = admin
    login()
    app.state.service.settings = replace(app.state.service.settings,
        admin_broker_socket=Path('/run/synthetic.sock'), admin_broker_instance='alpha')
    class Broker:
        target = 'beta'
        def capabilities(self):
            return {'actions': [action(operation='instance.activate', target=self.target,
                                       affected_instances=[self.target])], 'receipts': []}
    broker = Broker()
    app.state.admin_portal.operations.broker = broker
    assert http.get('/admin/api/connection').json()['activation']['can_activate_from_panel'] is False
    broker.target = 'alpha'
    assert http.get('/admin/api/connection').json()['activation']['can_activate_from_panel'] is True


def test_restore_maintenance_hides_current_activation_without_revoking_other_instance_delegation(admin):
    app, http, login = admin
    headers = login()
    settings = replace(app.state.service.settings, live_account_enabled=False, link_enabled=False,
        admin_broker_socket=Path('/run/synthetic.sock'), admin_broker_instance='alpha')
    app.state.service.settings = settings
    app.state.link_portal.settings = settings
    app.state.service.restore_maintenance = True
    calls = []
    class Broker:
        def capabilities(self):
            return {'actions': [action(operation='instance.activate', target='alpha', affected_instances=['alpha']),
                                action(operation='instance.prepare', target='beta', affected_instances=['beta'])],
                    'receipts': []}
        def execute(self, body):
            calls.append(body)
            return completed(body)
    app.state.admin_portal.operations.broker = Broker()
    value = http.get('/admin/api/connection').json()
    assert value['activation']['required'] is True
    assert value['activation']['can_activate_from_panel'] is False
    assert value['pairing_url'] is None
    actions = http.get('/admin/api/status').json()['host_actions']
    assert next(item for item in actions if item['target'] == 'beta')['available'] is True
    body = request('instance.prepare', 'beta', arguments={'approval': APPROVAL})
    assert http.post('/admin/api/operations', headers=headers, json=body).json()['state'] == 'completed'
    assert calls == [body]


def test_reconcile_racing_restored_database_never_overwrites_another_approval(admin):
    app, _, _ = admin
    operations = app.state.admin_portal.operations
    body = request('backup.restore', 'alpha', arguments={'approval': APPROVAL})
    class Broker:
        def execute(self, request):
            raise BrokerError(uncertain=True)
        def status(self, original):
            # A concurrent restore changes the local DB during the socket read.
            replacement = {**original, 'approval': 'f'*32, 'request_hash': 'foreign-request'}
            with app.state.service.store.db() as db:
                app.state.service.store._state(db, PREFIX + body['id'], replacement)
            return completed(body)
    operations.broker = Broker()
    assert operations.execute(body)['state'] == 'uncertain'
    observation = operations.reconcile(body['id'])
    assert observation['state'] == 'uncertain'
    assert observation['approval'] == 'f'*32
    assert observation['observation_error_code'] == 'ADMIN_RECEIPT_CONFLICT'
    assert operations.records()[0]['approval'] == 'f'*32
    assert 'result' not in operations.records()[0]


def test_snapshot_never_associates_receipt_for_same_id_with_another_approval(admin):
    app, _, _ = admin
    operations = app.state.admin_portal.operations
    body = request('backup.restore', 'alpha', arguments={'approval': APPROVAL})
    class Broker:
        def execute(self, request):
            raise BrokerError(uncertain=True)
        def capabilities(self):
            return {'actions': [], 'receipts': [{**completed(body), 'approval': 'f'*32}]}
    operations.broker = Broker()
    operations.execute(body)
    row = operations.snapshot()['operations'][0]
    assert row['state'] == 'uncertain'
    assert row['approval'] == APPROVAL
    assert 'result' not in row


def test_cancellation_receipt_explicitly_preserves_allocation_and_administrative_records():
    body = request('instance.cancel', 'beta', arguments={'approval': APPROVAL})
    observation = completed(body)
    with pytest.raises(BrokerError):
        receipt(observation, body)
    observation['result'].update(allocation_released=False, instance_reusable=False,
                                 administrative_records_retained=True)
    result = receipt(observation, body)
    assert result['result']['allocation_released'] is False
    assert result['result']['instance_reusable'] is False
    assert result['result']['administrative_records_retained'] is True
    observation['result']['instance_reusable'] = True
    with pytest.raises(BrokerError):
        receipt(observation, body)


def rejected_before_intent(body):
    return {**{key: body[key] for key in ('id', 'operation', 'target')},
            'approval': body['arguments']['approval'], 'state': 'failed_before_execution',
            'execution_phase': 'before_intent', 'error_code': 'BROKER_APPROVAL_EXPIRED'}


@pytest.mark.parametrize('change', [
    {'id': 'c'*32}, {'operation': 'backup.restore'}, {'target': 'foreign'},
    {'approval': 'c'*32}, {'execution_phase': None}, {'execution_phase': 'after_intent'},
    {'error_code': None}, {'result': {'exit_code': 0}},
])
def test_preintent_receipt_requires_exact_binding_and_explicit_phase(change):
    body = request('backup.create', 'alpha', arguments={'approval': APPROVAL})
    observed = rejected_before_intent(body)
    assert receipt(observed, body) == observed
    with pytest.raises(BrokerError) as failure:
        receipt({**observed, **change}, body)
    assert failure.value.uncertain


@pytest.mark.parametrize('code', ['BROKER_APPROVAL_EXPIRED', 'BROKER_NOT_FOUND',
                                 'BROKER_APPROVAL_CONSUMED', 'BROKER_IDEMPOTENCY_CONFLICT'])
def test_legacy_error_envelope_never_proves_preintent_rejection(tmp_path, monkeypatch, code):
    with socket_peer(tmp_path, lambda _: {'ok': False, 'error_code': code}) as (path, calls):
        client = AdminBrokerClient(path, 'owner', 'alpha', expected_uid=os.getuid())
        monkeypatch.setattr(client, '_socket_identity', lambda: (1, 2))
        with pytest.raises(BrokerError) as failure:
            client.execute(request('backup.create', 'alpha', arguments={'approval': APPROVAL}))
        assert failure.value.uncertain and len(calls) == 1


def test_explicit_preintent_receipt_is_terminal_locally_without_replay(admin):
    app, http, login = admin
    headers = login()
    body = request('backup.create', 'alpha', arguments={'approval': APPROVAL})
    calls = []
    class RejectingBroker:
        def execute(self, value):
            calls.append(value)
            return rejected_before_intent(value)
        def status(self, value):
            pytest.fail('An explicit local terminal receipt must not require a host record')
    app.state.admin_portal.operations.broker = RejectingBroker()
    first = http.post('/admin/api/operations', headers=headers, json=body)
    assert first.json()['state'] == 'failed_before_execution'
    assert first.json()['execution_phase'] == 'before_intent'
    assert http.post('/admin/api/operations', headers=headers, json=body).json() == first.json()
    assert http.get('/admin/api/operations/' + body['id']).json() == first.json()
    assert calls == [body]
