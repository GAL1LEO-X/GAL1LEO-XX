from dataclasses import replace
import json
import secrets
import time

import pytest
from starlette.testclient import TestClient

from sally_whatsapp.linking import COOKIE, digest
from sally_whatsapp.server import create_app


def test_prepared_owner_admin_portal_has_no_phone_effects(environment):
    settings, receiver, gateway, token = environment
    settings = replace(settings, admin_enabled=True, link_enabled=False, live_account_enabled=False,
        link_client_id='owner-portal', link_authorize_url='https://issuer.example/authorize',
        link_token_url='https://issuer.example/token', allowed_hosts=['bridge.example'])
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError('Prepared instance must not contact provider')
    gateway.request = forbidden
    gateway.pairing_qr = forbidden
    gateway.ab_operations = forbidden
    app = create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False)
    with TestClient(app,base_url=settings.public_url) as client:
        assert client.get('/admin/api/connection').status_code == 401
        auth = client.get('/connect/login',follow_redirects=False)
        assert auth.status_code == 302
        assert auth.headers['location'].startswith('https://issuer.example/authorize?')
        sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        access = token(azp='owner-portal',scope='whatsapp:link')
        with app.state.service.store.db() as db:
            db.execute('INSERT INTO link_sessions VALUES(?,?,?,?,?)',
                (digest(sid),settings.owner_subject,app.state.link_portal.cipher.encrypt(access.encode()),csrf,time.time()+600))
        client.cookies.set(COOKIE,sid,domain='bridge.example',path='/')
        headers = {'Origin':settings.public_url,'X-CSRF-Token':csrf}
        assert client.get('/admin').status_code == 200
        assert client.get('/admin/api/status').json()['capability_observation'] == 'account_access_disabled'
        result = client.get('/admin/api/connection').json()
        assert result['stage'] == 'activation_required'
        assert result['pairing_url'] is None
        assert result['activation']['can_activate_from_panel'] is False
        assert result['chatgpt']['consent_state'] == 'not_verified_here'
        assert result['chatgpt']['phone_pairing_grants_mcp'] is False
        assert client.get('/connect/api/status').json()['state'] == 'PREPARED'
        assert client.post('/connect/api/pair',headers=headers,json={'mode':'qr'}).status_code == 409
        assert client.post('/connect/api/pair',headers=headers,json={'mode':'code','phone':'10000000000'}).status_code == 409
        assert client.get('/connect/qr').status_code == 409
        assert calls == []
        with app.state.service.store.db() as db:
            assert db.execute('SELECT count(*) FROM link_rate_limit').fetchone()[0] == 0


def test_link_only_configuration_keeps_legacy_activation_requirement(environment):
    settings, _, _, _ = environment
    with pytest.raises(ValueError,match='Pairing requires an enabled gateway'):
        replace(settings,link_enabled=True,live_account_enabled=False,admin_enabled=False)
    with pytest.raises(ValueError,match='dedicated OAuth client'):
        replace(settings,admin_enabled=True,link_enabled=False,live_account_enabled=False)


def test_connection_observation_contains_no_pairing_or_provider_identity(admin):
    app, client, login = admin
    login()
    gateway = app.state.service.gateway
    gateway.session = 'synthetic'
    gateway.request = lambda *args, **kwargs: {'status':'FAILED','code':'TEST-ONLY','qr':'synthetic-qr-secret','me':{'id':'private-provider-id'}}
    value = client.get('/admin/api/connection').json()
    assert value['stage'] == 'reconnection_required'
    assert value['pairing_url'] == '/connect'
    assert value['secrets_included'] is False
    assert all(secret not in json.dumps(value) for secret in ('TEST-ONLY','synthetic-qr-secret','private-provider-id'))


@pytest.mark.parametrize('observation', [None, [], 'private-provider-value',
    {'status':[]}, {'status':{}}, {'status':None}, {'status':True}])
def test_malformed_provider_observation_is_not_client_error_or_retry(admin, observation):
    app, client, login = admin
    headers = login()
    gateway = app.state.service.gateway
    gateway.session = 'synthetic'
    calls = []
    def malformed(method,path,**kwargs):
        calls.append((method,path))
        return observation
    gateway.request = malformed
    response = client.get('/connect/api/status')
    assert response.status_code == 503
    assert 'private-provider-value' not in response.text
    response = client.get('/connect/qr')
    assert response.status_code == 502
    assert 'private-provider-value' not in response.text
    response = client.post('/connect/api/pair',headers=headers,json={'mode':'qr'})
    assert response.status_code == 503
    assert response.json()['outcome'] == 'not_started'
    assert response.json()['error_code'] == 'PAIRING_PRECONDITION_UNAVAILABLE'
    assert 'private-provider-value' not in response.text
    value = client.get('/admin/api/connection').json()
    assert value['stage'] == 'provider_wait'
    assert value['error_code'] == 'PHONE_CONNECTION_UNVERIFIED'
    assert len(calls) == 4
    assert all(method == 'GET' for method,_ in calls)
    with app.state.service.store.db() as db:
        assert db.execute('SELECT count(*) FROM link_rate_limit').fetchone()[0] == 0


@pytest.mark.parametrize('answer', [None, [], 'private-code-response', {'code':[]}, {'code':'invalid-secret-value'}, 'timeout'])
def test_partial_or_lost_pairing_code_response_is_unverified_and_not_retried(admin, answer):
    from sally_whatsapp.gateway import GatewayUnavailable
    app, client, login = admin
    headers = login()
    gateway = app.state.service.gateway
    gateway.session = 'synthetic'
    calls = []
    def request(method,path,**kwargs):
        calls.append((method,path))
        if method == 'GET':
            return {'status':'SCAN_QR_CODE'}
        if answer == 'timeout':
            raise GatewayUnavailable('private-provider-error')
        return answer
    gateway.request = request
    result = client.post('/connect/api/pair',headers=headers,json={'mode':'code','phone':'10000000000'})
    assert result.status_code == 502
    assert result.json()['outcome'] == 'uncertain'
    assert result.json()['error_code'] == 'PAIRING_OUTCOME_UNVERIFIED'
    assert 'cannot be verified' in result.json()['error']
    assert not any(secret in result.text for secret in ('private-code-response','invalid-secret-value','private-provider-error'))
    assert len([method for method,_ in calls if method == 'POST']) == 1
    retry = client.post('/connect/api/pair',headers=headers,json={'mode':'code','phone':'10000000000'})
    assert retry.status_code == 429
    assert len([method for method,_ in calls if method == 'POST']) == 1


# Reuse the actual signed owner-session fixture, never bypass AdminPortal.session.
from test_admin_panel import admin
