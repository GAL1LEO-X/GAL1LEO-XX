"""Real HTTPS application/SQLite -> UNIX protocol -> durable broker -> synthetic effect.

The broker's trust boundary is a temporary fixture, never host root. Its
preflight/executor are replaced at the host boundary only; policy validation,
kernel peer credentials, dispatch journal, leases and web authorization are real.
"""
import importlib.util
import json
import os
from pathlib import Path
from threading import Thread, Event
import time

import pytest

from sally_whatsapp.admin import PREFIX, MAX_RECORDS
from sally_whatsapp.admin_broker import AdminBrokerClient, BrokerError
from test_admin_panel import admin, request


@pytest.fixture
def tmp_path(short_socket_tmp_path):
    """Keep the entire socket fixture physical and below the AF_UNIX limit."""
    return short_socket_tmp_path


@pytest.fixture
def broker_host(tmp_path, monkeypatch, admin, request):
    if os.getuid() == 0:
        pytest.skip('This real-peer test requires a non-root tenant UID; root is never a broker principal')
    source = Path(__file__).resolve().parents[1] / 'scripts/web_admin_broker.py'
    spec = importlib.util.spec_from_file_location('synthetic_web_broker', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, 'TRUST_ROOT', tmp_path)
    monkeypatch.setattr(module, 'TRUST_UID', os.getuid())
    state = tmp_path / 'broker-state'
    state.mkdir(mode=0o700)
    effects, entered, release = [], Event(), Event()
    hold = {'enabled': False}
    app, _, _ = admin
    policy = {'format': module.FORMAT, 'enabled': True, 'project': str(tmp_path / 'project'),
        'installation_sha256': 'a'*64, 'owner': {'protocol': 1, 'epoch': 'b'*32, 'state': 'dedicated',
            'generation': str(tmp_path / 'generation'), 'manifest_sha256': 'c'*64},
        'sources': {'scripts/synthetic.py': 'd'*64}, 'state_directory': str(state),
        'socket': '/run/synthetic-only.sock', 'socket_gid': os.getgid(),
        'principals': [{'uid': os.getuid(), 'owner': app.state.service.settings.owner_subject,
            'instance': 'alpha', 'targets': ['alpha', 'beta'], 'operations': ['backup.create'], 'global_admin': False}],
        'approvals': {'e'*32: {'uid': os.getuid(), 'operation': 'backup.create', 'target': 'alpha',
            'scope': 'instance', 'affected_instances': ['alpha'], 'description': 'Synthetic isolated copy',
            'expires': time.time()+3600, 'parameters': {}}}}
    policy_path = tmp_path / 'policy.json'
    policy_path.write_bytes(module.encoded(policy))
    policy_path.chmod(0o600)
    def execute(policy, approval, lease):
        effects.append(approval)
        (tmp_path / 'synthetic-effect').write_text(approval)
        entered.set()
        if hold['enabled']:
            assert release.wait(5)
        return {'completed': True, 'operation': 'backup.create', 'target': 'alpha'}
    broker = module.Broker(policy_path, executor=execute, preflight=lambda *_: None)
    capabilities_delay = getattr(request, 'param', 0)
    if capabilities_delay:
        handle = broker.handle
        def delayed_handle(uid, envelope):
            if envelope['method'] == 'capabilities':
                time.sleep(capabilities_delay)
            return handle(uid, envelope)
        monkeypatch.setattr(broker, 'handle', delayed_handle)
    endpoint = tmp_path / 'rpc.sock'
    server = module.Server(str(endpoint), module.Handler)
    endpoint.chmod(0o660)
    server.broker = broker
    thread = Thread(target=server.serve_forever, kwargs={'poll_interval': .02})
    thread.start()
    # Ordinary requests use the production deadline. Only the lost-reply test
    # shortens it around the operation deliberately held by the executor.
    client = AdminBrokerClient(endpoint, app.state.service.settings.owner_subject, 'alpha',
                               expected_uid=os.getuid())
    monkeypatch.setattr(client, '_socket_identity', lambda: (endpoint.stat().st_dev, endpoint.stat().st_ino))
    app.state.admin_portal.operations.broker = client
    try:
        yield client, effects, entered, release, hold, state
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()


@pytest.mark.parametrize('broker_host', [0, .2], indirect=True, ids=['immediate', 'delayed-capabilities'])
def test_real_broker_enforces_scope_and_approval_single_use_through_http(admin, broker_host):
    app, http, login = admin
    client, effects, *_ = broker_host
    headers = login()
    snapshot = http.get('/admin/api/status').json()
    assert snapshot['host_actions'][0]['available'], snapshot['host_actions']
    assert snapshot['host_actions'][0]['affected_instances'] == ['alpha']
    assert snapshot['host_actions'][0]['description'] == 'Synthetic isolated copy'
    body = request('backup.create', 'alpha', arguments={'approval': 'e'*32})
    invalid = {**body, 'target': 'beta', 'confirmation': 'backup.create:beta'}
    assert http.post('/admin/api/operations', headers=headers, json=invalid).json()['state'] == 'uncertain'
    assert effects == []
    body['id'] = 'f'*32
    response = http.post('/admin/api/operations', headers=headers, json=body)
    assert response.json()['state'] == 'completed'
    assert http.post('/admin/api/operations', headers=headers, json=body).json() == response.json()
    another = {**body, 'id': '9'*32}
    assert http.post('/admin/api/operations', headers=headers, json=another).json()['state'] == 'uncertain'
    assert effects == ['e'*32]
    client.owner = 'foreign-owner'
    assert all(not row['available'] for row in http.get('/admin/api/status').json()['host_actions'])
    # Independent host journal contains exactly the admitted request.
    import sqlite3
    with sqlite3.connect(broker_host[-1] / 'journal.sqlite') as db:
        assert db.execute('SELECT count(*) FROM requests').fetchone()[0] == 1


def test_real_socket_timeout_lost_tenant_journal_and_receipt_recovery(admin, broker_host, monkeypatch):
    app, http, login = admin
    client, effects, entered, release, hold, _ = broker_host
    headers = login()
    hold['enabled'] = True
    body = request('backup.create', 'alpha', arguments={'approval': 'e'*32})
    with monkeypatch.context() as timeout:
        timeout.setattr(client, 'timeout', .1)
        assert http.post('/admin/api/operations', headers=headers, json=body).json()['state'] == 'uncertain'
    assert entered.wait(3)
    assert http.get('/admin/api/operations/' + body['id']).json()['state'] == 'uncertain'
    # Model restoring a tenant snapshot that predates its pending journal row.
    with app.state.service.store.db() as db:
        db.execute('DELETE FROM state WHERE key LIKE ?', (PREFIX+'%',))
    snapshot = http.get('/admin/api/status').json()
    assert snapshot['operations'][0]['id'] == body['id']
    assert snapshot['operations'][0]['state'] == 'uncertain'
    release.set()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        response = http.get('/admin/api/operations/' + body['id'])
        if response.json()['state'] == 'completed':
            break
    assert response.json()['state'] == 'completed'
    assert len(effects) == 1
    assert http.post('/admin/api/operations', headers=headers, json=body).status_code == 409


def test_explicit_preintent_rejections_expire_without_poisoning_web_journal(admin, broker_host):
    import sqlite3
    app, http, login = admin
    client, effects, _, _, _, state = broker_host
    headers = login()
    policy_path = state.parent / 'policy.json'
    policy = json.loads(policy_path.read_bytes())
    policy['approvals']['f'*32] = dict(policy['approvals']['e'*32])
    policy['approvals']['e'*32]['expires'] = 1
    # Both admissions are fixed before the first RPC; no live policy mutation.
    policy_path.write_text(json.dumps(policy))
    first = None
    for _ in range(MAX_RECORDS):
        body = request('backup.create', 'alpha', arguments={'approval': 'e'*32})
        first = first or body
        result = http.post('/admin/api/operations', headers=headers, json=body)
        assert result.status_code == 200
        assert result.json()['state'] == 'failed_before_execution', result.json()
        assert result.json()['execution_phase'] == 'before_intent'
        assert result.json()['error_code'] == 'BROKER_APPROVAL_EXPIRED'
    assert effects == []
    with sqlite3.connect(state / 'journal.sqlite') as db:
        assert db.execute('SELECT count(*) FROM requests').fetchone()[0] == 0
    assert http.get('/admin/api/operations/' + first['id']).json()['state'] == 'failed_before_execution'
    assert http.post('/admin/api/operations', headers=headers, json=first).json()['state'] == 'failed_before_execution'
    with app.state.service.store.db() as db:
        rows = db.execute('SELECT key,value FROM state WHERE key LIKE ?', (PREFIX+'%',)).fetchall()
        assert len(rows) == MAX_RECORDS
        for row in rows:
            value = json.loads(row['value'])
            value['updated_epoch'] = 0  # Model retention expiry without expiring OAuth.
            app.state.service.store._state(db, row['key'], value)
    accepted = http.post('/admin/api/operations', headers=headers,
        json=request('backup.create', 'alpha', arguments={'approval': 'f'*32}))
    assert accepted.status_code == 200 and accepted.json()['state'] == 'completed'
    assert effects == ['f'*32]
    assert len(app.state.admin_portal.operations.records()) == 1


def test_lost_preintent_reply_and_missing_host_row_remain_uncertain(admin, broker_host, monkeypatch):
    app, http, login = admin
    client, effects, _, _, _, state = broker_host
    policy_path = state.parent / 'policy.json'
    policy = json.loads(policy_path.read_bytes())
    policy['approvals']['e'*32]['expires'] = 1
    policy_path.write_text(json.dumps(policy))
    execute = client.execute
    received = []
    def lose_reply(request):
        result = execute(request)
        assert result['state'] == 'failed_before_execution'
        received.append(result)
        # The host reply did not reach the application journal. The client
        # cannot substitute what the fixture knows for a delivered receipt.
        raise BrokerError(uncertain=True)
    monkeypatch.setattr(client, 'execute', lose_reply)
    headers = login()
    body = request('backup.create', 'alpha', arguments={'approval': 'e'*32})
    assert http.post('/admin/api/operations', headers=headers, json=body).json()['state'] == 'uncertain'
    observation = http.get('/admin/api/operations/' + body['id']).json()
    assert observation['state'] == 'uncertain'
    assert observation['observation_error_code'] == 'ADMIN_BROKER_UNAVAILABLE'
    assert http.post('/admin/api/operations', headers=headers, json=body).json()['state'] == 'uncertain'
    assert len(received) == 1 and effects == []
