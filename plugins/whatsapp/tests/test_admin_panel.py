from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import secrets
import time
from threading import Event

import pytest
from starlette.testclient import TestClient

from sally_whatsapp.admin import PREFIX, RuntimeAdminOperations
from sally_whatsapp.linking import COOKIE, digest
from sally_whatsapp.server import create_app
from sally_whatsapp.store import canonical


@pytest.fixture
def admin(environment):
    settings, receiver, gateway, token = environment
    settings = replace(settings, live_account_enabled=True, link_enabled=True, admin_enabled=True,
        link_client_id='pair-client', link_authorize_url='https://issuer.example/authorize',
        link_token_url='https://issuer.example/token', allowed_hosts=['bridge.example'])
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app, base_url=settings.public_url) as client:
        def login(**claims):
            sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            value = token(azp='pair-client', scope='whatsapp:link', **claims)
            with app.state.service.store.db() as db:
                db.execute('INSERT INTO link_sessions VALUES(?,?,?,?,?)',
                    (digest(sid), settings.owner_subject, app.state.link_portal.cipher.encrypt(value.encode()), csrf, time.time()+600))
            client.cookies.set(COOKIE, sid, domain='bridge.example', path='/')
            return {'Origin': settings.public_url, 'X-CSRF-Token': csrf}
        yield app, client, login


def request(operation, target, **values):
    return {'id': secrets.token_hex(16), 'operation': operation, 'target': target,
            'arguments': {}, 'confirmation': operation+':'+target, **values}


def test_disabled_is_not_mounted_and_admin_requires_owner_session(environment, admin):
    settings, receiver, gateway, token = environment
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app) as client:
        assert client.get('/admin').status_code == 404
    app, client, login = admin
    assert client.get('/admin/api/status').status_code == 401
    client.headers['Authorization'] = 'Bearer ' + token()
    assert client.get('/admin/api/status').status_code == 401
    login(sub='wrong-owner')
    assert client.get('/admin/api/status').status_code == 401
    login()
    assert client.get('/admin/api/status').status_code == 200
    app.state.service.settings = replace(app.state.service.settings, admin_enabled=False)
    assert client.get('/admin/api/status').status_code == 403


def test_real_local_operation_csrf_target_confirmation_idempotency_and_audit(admin):
    app, client, login = admin
    headers = login()
    service = app.state.service
    job = service.history.start(service.settings.owner_subject, 'synthetic-history-request', ['chat@c.us'])
    body = request('history.pause', job['id'])
    for invalid in ({}, {**headers, 'Origin': 'https://evil.example'}, {**headers, 'X-CSRF-Token':'wrong'}):
        assert client.post('/admin/api/operations', headers=invalid, json=body).status_code == 403
    assert client.post('/admin/api/operations', headers=headers, json={**body,'confirmation':'history.cancel:'+job['id']}).status_code == 409
    result = client.post('/admin/api/operations', headers=headers, json=body)
    assert result.json()['state'] == 'completed'
    assert service.history.status(job['id'], service.settings.owner_subject)['state'] == 'paused'
    assert client.post('/admin/api/operations', headers=headers, json=body).json() == result.json()
    conflict = {**body, 'operation':'history.cancel', 'confirmation':'history.cancel:'+job['id']}
    assert client.post('/admin/api/operations', headers=headers, json=conflict).status_code == 409
    assert 'private:admin' not in json.dumps(service.connection_status())
    logs = client.get('/admin/api/logs').json()['entries']
    assert any(row['event'] == 'admin.finished' for row in logs)
    assert job['id'] not in json.dumps(logs)
    assert headers['X-CSRF-Token'] not in json.dumps(logs)


def test_restart_preserves_uncertain_record_without_reexecuting(admin):
    app, client, login = admin
    headers = login()
    service = app.state.service
    job = service.history.start(service.settings.owner_subject, 'synthetic-crash-history', ['chat@c.us'])
    body = request('history.cancel', job['id'])
    row = {'id':body['id'], 'operation':body['operation'], 'target':body['target'],
           'request_hash':hashlib.sha256(canonical(body).encode()).hexdigest(), 'state':'running',
           'created_at':'2026-10-21T12:00:00Z', 'updated_at':'2026-10-21T12:00:00Z', 'updated_epoch':time.time()}
    with service.store.db() as db:
        service.store._state(db, PREFIX+body['id'], row)
    restarted = RuntimeAdminOperations(service)
    assert restarted.execute(body)['state'] == 'uncertain'
    assert service.history.status(job['id'], service.settings.owner_subject)['state'] == 'running'
    assert client.post('/admin/api/operations', headers=headers, json=body).json()['state'] == 'uncertain'


def test_host_operations_fail_closed_and_unknown_input_never_executes(admin):
    app, client, login = admin
    headers = login()
    for op in ('release.activate','instance.activate','backup.restore'):
        response = client.post('/admin/api/operations', headers=headers, json=request(op, 'current'))
        assert response.status_code == 409
        assert response.json()['error_code'] == 'EXTERNAL_EXECUTION_REQUIRED'
    assert client.post('/admin/api/operations', headers=headers, json=request('shell', 'echo')).status_code == 400
    assert client.post('/admin/api/operations', headers=headers, json=request('history.cancel','../../elsewhere')).status_code == 400
    assert app.state.admin_portal.operations.records() == []


def test_cross_owner_history_rejected_and_no_content_in_status(admin):
    app, client, login = admin
    headers = login()
    service = app.state.service
    job = service.history.start('another-owner', 'other-history', ['private-chat@c.us'])
    response = client.post('/admin/api/operations', headers=headers, json=request('history.cancel',job['id']))
    assert response.json()['state'] == 'uncertain'
    assert service.history.status(job['id'], 'another-owner')['state'] == 'running'
    snapshot = client.get('/admin/api/status')
    assert 'private-chat' not in snapshot.text
    assert snapshot.json()['history'] == []


def test_log_symlink_is_rejected_and_logout_revokes_existing_session(admin, tmp_path):
    app, client, login = admin
    headers = login()
    path = app.state.service.diagnostics.directory / 'events.jsonl'
    # Close current logger before deliberately replacing this synthetic fixture.
    app.state.service.diagnostics.close()
    path.unlink(missing_ok=True)
    other = tmp_path/'private.log'
    other.write_text('{"event":"private"}\n')
    path.symlink_to(other)
    assert client.get('/admin/api/logs').status_code == 503
    path.unlink()
    assert client.post('/connect/api/logout',headers=headers,json={}).status_code == 200
    assert client.get('/admin/api/status').status_code == 401


def test_large_request_rejected_before_execution(admin):
    app, client, login = admin
    headers = login()
    response = client.post('/admin/api/operations', headers={**headers, 'Content-Type':'application/json'}, content='"'+'x'*65536+'"')
    assert response.status_code == 413
    assert app.state.admin_portal.operations.records() == []


def test_concurrent_replay_is_not_executed_twice(admin, monkeypatch):
    app, _, _ = admin
    operations = app.state.admin_portal.operations
    entered, release = Event(), Event()
    calls = []
    original = operations.preview
    def block(*args):
        calls.append(args)
        entered.set()
        assert release.wait(5)
        return {'state':'preview_only'}
    monkeypatch.setattr(operations, 'preview', block)
    body = request('instance.preview','beta')
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(operations.execute, body)
        assert entered.wait(5)
        second = pool.submit(operations.execute, body)
        try:
            assert second.result(timeout=5)['state'] == 'uncertain'
        finally:
            release.set()
        assert first.result(timeout=5)['state'] == 'completed'
    assert len(calls) == 1


def test_subscription_disable_calls_existing_service_and_cancels_queue(admin):
    app, client, login = admin
    headers = login()
    service = app.state.service
    sub = service.events.subscribe(service.settings.owner_subject, 'message.received', {'all_chats':True},
        {'mode':'webhook','url':'https://receiver.example/events','secret':'whsec_'+'c3ludGhldGljLWtleS1vbmx5LTEyMzQ1Njc4OTAxMjM0NTY='})
    with service.store.db() as db:
        db.execute('INSERT INTO deliveries(subscription,event_id,body,next_attempt) VALUES(?,?,?,?)',
            (sub['id'],'synthetic-event','{}',time.time()))
    result = client.post('/admin/api/operations',headers=headers,json=request('subscription.disable',sub['id'])).json()
    assert result['state'] == 'completed'
    with service.store.db() as db:
        assert db.execute('SELECT active FROM subscriptions WHERE id=?',(sub['id'],)).fetchone()[0] == 0
        assert db.execute('SELECT state FROM deliveries WHERE subscription=?',(sub['id'],)).fetchone()[0] == 'cancelled'
    snapshot = client.get('/admin/api/status').json()
    assert snapshot['subscriptions'][0]['active'] is False
    assert 'https://receiver.example' not in json.dumps(snapshot)
    assert 's'*32 not in json.dumps(snapshot)


def test_exception_after_effect_is_uncertain_not_safe_to_repeat(admin, monkeypatch):
    app, _, _ = admin
    operations = app.state.admin_portal.operations
    service = app.state.service
    job = service.history.start(service.settings.owner_subject, 'synthetic-posteffect', ['chat@c.us'])
    original = service.history.control
    def control(*args):
        original(*args)
        raise ValueError('synthetic response construction failure')
    monkeypatch.setattr(service.history, 'control', control)
    body = request('history.pause', job['id'])
    assert operations.execute(body)['state'] == 'uncertain'
    assert service.history.status(job['id'],service.settings.owner_subject)['state'] == 'paused'
    assert operations.execute(body)['state'] == 'uncertain'
