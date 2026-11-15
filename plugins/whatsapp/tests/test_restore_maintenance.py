"""Restore admission uses real owner sessions; no provider or host effects."""
from dataclasses import replace
import json
import secrets
import time

import pytest
from starlette.testclient import TestClient

from sally_whatsapp.gateway import DisconnectedGateway
from sally_whatsapp.linking import COOKIE, digest
from sally_whatsapp.server import create_app


def configuration(settings):
    return replace(settings, admin_enabled=True, link_enabled=True,
                   live_account_enabled=True, link_client_id='owner-portal',
                   link_authorize_url='https://issuer.example/authorize',
                   link_token_url='https://issuer.example/token',
                   allowed_hosts=['bridge.example'])


def login(app, client, token, settings):
    sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    access = token(azp='owner-portal', scope='whatsapp:link')
    with app.state.service.store.db() as db:
        db.execute('INSERT INTO link_sessions VALUES(?,?,?,?,?)',
                   (digest(sid), settings.owner_subject,
                    app.state.link_portal.cipher.encrypt(access.encode()), csrf, time.time() + 600))
    client.cookies.set(COOKIE, sid, domain='bridge.example', path='/')
    return {'Origin': settings.public_url, 'X-CSRF-Token': csrf}


def marker_body(phase='maintenance'):
    return json.dumps({'format': 'whatsapp-restore-maintenance-v1', 'id': 'a' * 32,
                       'plan_sha256': 'b' * 64, 'instance': 'alpha', 'phase': phase})


def test_restore_latches_offline_and_preserves_owner_administration(environment, short_socket_tmp_path):
    settings, receiver, gateway, token = environment
    settings = replace(configuration(settings), transcription_socket=short_socket_tmp_path/'worker.sock',
                       transcription_server_uid=1234)
    marker = settings.encryption_key_file.parent / 'restore-maintenance.json'
    marker.write_text(marker_body())
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    assert app.state.service.restore_maintenance
    assert app.state.service.settings.transcription_socket is None
    assert app.state.service.settings.transcription_server_uid is None
    assert isinstance(app.state.service.gateway, DisconnectedGateway)
    assert set(app.state.readiness.workers) == {'portal'}
    assert not any(getattr(app.state.service.settings, name) for name in (
        'live_account_enabled', 'link_enabled', 'send_enabled', 'account_actions_enabled'))
    with TestClient(app, base_url=settings.public_url) as client:
        assert client.get('/admin/api/status').status_code == 401
        assert client.get('/connect/login', follow_redirects=False).status_code == 302
        headers = login(app, client, token, settings)
        assert client.get('/admin').status_code == 200
        value = client.get('/admin/api/status').json()
        assert value['restore_maintenance'] is True and value['local_actions'] == []
        assert client.get('/healthz').json()['restore_maintenance'] is True
        assert client.get('/connect/api/status').json()['state'] == 'PREPARED'
        for path in ('/mcp', '/webhooks/waha', '/files/old-grant', '/connect/api/pair', '/connect/qr'):
            response = client.post(path, headers=headers, json={})
            assert response.status_code == 503
            assert response.json()['error_code'] == 'RESTORE_RECONCILIATION_REQUIRED'
        # Newly advertised resource methods remain behind the same restore
        # admission as tools; an old signed link cannot expose restored data.
        for method in ('resources/list', 'resources/templates/list', 'resources/read'):
            response = client.post('/mcp', headers=headers, json={
                'jsonrpc': '2.0', 'id': 1, 'method': method,
                'params': {'uri': settings.public_url + '/files/old-grant'} if method == 'resources/read' else {},
            })
            assert response.status_code == 503
            assert response.json()['error_code'] == 'RESTORE_RECONCILIATION_REQUIRED'
        response = client.post('/admin/api/operations', headers=headers, json={
            'id': 'a' * 32, 'operation': 'history.resume', 'target': 'history_' + 'b' * 32,
            'arguments': {}, 'confirmation': 'history.resume:history_' + 'b' * 32,
        })
        assert response.status_code == 409
        marker.unlink()
        # Removing the marker does not revive a running restored process.
        assert client.post('/mcp', json={}).status_code == 503
        assert not app.state.service.settings.live_account_enabled


def test_only_portal_worker_starts_after_restore(environment, monkeypatch):
    from sally_whatsapp.server import Service
    settings, receiver, gateway, token = environment
    settings = configuration(settings)
    (settings.encryption_key_file.parent / 'restore-maintenance.json').write_text(marker_body())
    calls = []
    async def forbidden(self):
        calls.append('worker')
        raise AssertionError('No background data workers in restore maintenance')
    for name in ('worker', 'transfer_worker', 'history_worker', 'action_worker'):
        monkeypatch.setattr(Service, name, forbidden)
    app = create_app(settings, gateway=gateway, event_transport=receiver)
    with TestClient(app, base_url=settings.public_url) as client:
        deadline = time.monotonic() + 5
        while not app.state.readiness.ready and time.monotonic() < deadline:
            time.sleep(0.01)
        assert app.state.readiness.ready
        assert app.state.readiness.snapshot()['workers'] == {'portal': True}
        assert calls == []
        assert client.post('/mcp', json={}).status_code == 503


@pytest.mark.parametrize('kind', ['restoring', 'invalid', 'directory', 'dangling_symlink', 'duplicate'])
def test_partial_or_inflight_marker_blocks_before_database_is_opened(environment, monkeypatch, kind):
    import sally_whatsapp.server as server
    settings, receiver, gateway, _ = environment
    marker = settings.encryption_key_file.parent / 'restore-maintenance.json'
    if kind == 'directory':
        marker.mkdir()
    elif kind == 'dangling_symlink':
        marker.symlink_to(marker.parent / 'absent')
    elif kind == 'duplicate':
        marker.write_text(marker_body()[:-1] + ',"phase":"maintenance"}')
    else:
        marker.write_text(marker_body('restoring') if kind == 'restoring' else '{')
    monkeypatch.setattr(server, 'StateContinuity', lambda *args, **kwargs: pytest.fail('Restore-inflight opened technical state'))
    monkeypatch.setattr(server, 'Store', lambda *args, **kwargs: pytest.fail('Restore-inflight opened database'))
    monkeypatch.setattr(server, 'Waha', lambda *args, **kwargs: pytest.fail('Restore-inflight constructed provider'))
    monkeypatch.setattr(server, 'Media', lambda *args, **kwargs: pytest.fail('Restore-inflight constructed media'))
    monkeypatch.setattr(server, 'read_attachment', lambda *args, **kwargs: pytest.fail('Restore-inflight read a resource'))
    monkeypatch.setattr(server, 'RuntimeReadiness', lambda *args, **kwargs: pytest.fail('Restore-inflight constructed workers'))
    monkeypatch.setattr(server, 'Server', lambda *args, **kwargs: pytest.fail('Restore-inflight constructed MCP handlers'))
    with pytest.raises(RuntimeError, match='RESTORE_RECONCILIATION_REQUIRED'):
        create_app(settings, gateway=gateway, event_transport=receiver)
