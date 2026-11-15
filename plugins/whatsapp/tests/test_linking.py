from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import base64
import hashlib
import json
import re
import secrets
from threading import Barrier,Event
from types import SimpleNamespace
import time
from urllib.parse import parse_qs,urlsplit,urlencode

import httpx
import pytest
from starlette.testclient import TestClient
from starlette.requests import Request

from conftest import call,rpc
from sally_whatsapp.server import create_app
from sally_whatsapp.linking import COOKIE,LOGIN_COOKIE,LOGIN_TTL,LinkError,LinkPortal,digest


@pytest.fixture
def portal(environment):
    settings,receiver,gateway,token=environment
    settings=replace(settings,live_account_enabled=True,link_enabled=True,
        link_client_id='pair-client',link_authorize_url='https://issuer.example/authorize',
        link_token_url='https://issuer.example/token',oauth_client_ids=['test-client'],
        allowed_hosts=['bridge.example'],profile_name='WhatsApp · synthetic owner')
    gateway.session='default'
    gateway.state='SCAN_QR_CODE'
    gateway.requests=[]
    def request(method,path,**kwargs):
        gateway.requests.append((method,path,kwargs))
        if method=='GET': return {'status':gateway.state,'me':{'secret':'not exposed'}}
        if path.endswith('/start'):
            # Actual WAHA leaves an existing failed session unchanged on /start.
            if gateway.state=='STOPPED': gateway.state='SCAN_QR_CODE'
            return {}
        if path.endswith('/restart'): gateway.state='SCAN_QR_CODE';return {}
        if path.endswith('/auth/request-code'): return {'code':'ABCD-1234','secret':'not exposed'}
        raise AssertionError(path)
    gateway.request=request
    gateway.pairing_qr=lambda: b'\x89PNG\r\n\x1a\nsynthetic-qr'
    exchange={'nonce':None,'changes':{},'posts':[]}
    def post(request):
        exchange['posts'].append(request)
        return httpx.Response(200,json={
            'access_token':token(azp='pair-client',scope='whatsapp:link',**exchange['changes']),
            'id_token':token(aud='pair-client',nonce=exchange['nonce'])})
    oauth=httpx.Client(transport=httpx.MockTransport(post))
    app=create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False,link_oauth_client=oauth)
    with TestClient(app,base_url=settings.public_url) as client:
        def login(**callback_changes):
            response=client.get('/connect/login',follow_redirects=False)
            assert response.status_code==302
            query={k:v[0] for k,v in parse_qs(urlsplit(response.headers['location']).query).items()}
            exchange['nonce']=query['nonce']
            params={'code':'synthetic-authorization-code','state':query['state'],'iss':settings.issuer,**callback_changes}
            return client.get('/connect/callback',params=params,follow_redirects=False),query
        yield app,client,gateway,token,login,exchange


def csrf(client):
    page=client.get('/connect')
    assert page.status_code==200
    return {'Origin':'https://bridge.example','X-CSRF-Token':re.search(r'data-csrf="([^"]+)"',page.text)[1]}


def test_complete_pairing_oauth_pkce_nonce_secure_session_and_code(portal):
    app,client,gateway,token,login,exchange=portal
    response,query=login()
    assert response.status_code==303
    assert query['scope']=='openid profile whatsapp:link'
    assert query['resource']=='https://bridge.example'
    assert query['code_challenge_method']=='S256'
    posted=parse_qs(exchange['posts'][0].content.decode())
    challenge=base64.urlsafe_b64encode(hashlib.sha256(posted['code_verifier'][0].encode()).digest()).rstrip(b'=').decode()
    assert challenge==query['code_challenge']
    assert 'HttpOnly' in response.headers['set-cookie'] and 'Secure' in response.headers['set-cookie']
    headers=csrf(client)
    state=client.get('/connect/api/status')
    assert state.json()=={'state':'SCAN_QR_CODE','connected':False,'qr_revision':''}
    response=client.post('/connect/api/pair',headers=headers,json={'mode':'code','phone':'+39 333 1234567'})
    assert response.status_code==200
    assert response.json()['code']=='ABCD-1234'
    outbound=next(r for r in gateway.requests if r[1].endswith('request-code'))
    assert outbound[2]['json']=={'phoneNumber':'393331234567'}
    assert 'ABCD-1234' not in json.dumps(app.state.service.store.state())
    assert 'secret' not in state.text
    with app.state.service.store.db() as db:
        receipt=db.execute('SELECT * FROM link_login_states').fetchone()
        assert receipt['state_hash']==digest(query['state']) and receipt['verifier']==b''
        row=db.execute('SELECT * FROM link_sessions').fetchone()
        assert row['access_token'].startswith(b'gAAAA')
        assert row['id_hash']!=client.cookies.get(COOKIE)
    assert 'no-store' in response.headers['cache-control']


def test_portal_authentication_is_separate_from_mcp(portal):
    _,client,gateway,token,_,_=portal
    client.headers['Authorization']='Bearer '+token()
    assert client.get('/connect/api/status').status_code==401
    assert client.post('/connect/api/pair',json={'mode':'code','phone':'393331234567'}).status_code==401
    assert not gateway.requests
    client.headers['Authorization']='Bearer '+token(azp='pair-client',scope='whatsapp:link')
    client.headers['Accept']='application/json, text/event-stream'
    assert client.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':'tools/list'}).status_code==401


@pytest.mark.parametrize('invalid',['state','proof','issuer','nonce','owner','audience','client','scope'])
def test_oauth_rejects_cross_account_and_replayed_or_mixed_login(portal,invalid):
    app,client,_,token,login,exchange=portal
    first=client.get('/connect/login',follow_redirects=False)
    query={k:v[0] for k,v in parse_qs(urlsplit(first.headers['location']).query).items()}
    exchange['nonce']='wrong-nonce' if invalid=='nonce' else query['nonce']
    params={'state':query['state'],'code':'code','iss':'https://issuer.example'}
    if invalid=='state':params['state']='x'*43
    if invalid=='proof':client.cookies.clear()
    if invalid=='issuer':params['iss']='https://other.example'
    if invalid in ('owner','audience'): exchange['changes']={'sub':'another-owner'} if invalid=='owner' else {'aud':'https://other.example'}
    if invalid in ('client','scope'):
        def badpost(req):
            return httpx.Response(200,json={'access_token':token(azp='wrong-client' if invalid=='client' else 'pair-client',scope='whatsapp:read' if invalid=='scope' else 'whatsapp:link'),'id_token':token(aud='pair-client',nonce=query['nonce'])})
        app.state.link_portal.client=httpx.Client(transport=httpx.MockTransport(badpost))
    response=client.get('/connect/callback',params=params,follow_redirects=False)
    assert response.status_code in (400,403)
    assert client.get('/connect/api/status').status_code==401


def test_callback_single_use_and_csrf_guards(portal):
    _,client,gateway,_,login,_=portal
    response,query=login()
    assert response.status_code==303
    replay=client.get('/connect/callback',params={'state':query['state'],'code':'code','iss':'https://issuer.example'},follow_redirects=False)
    assert replay.status_code==400
    headers=csrf(client)
    for modified in ({},{**headers,'Origin':'https://evil.example'},{**headers,'X-CSRF-Token':'wrong'}):
        assert client.post('/connect/api/pair',headers=modified,json={'mode':'code','phone':'393331234567'}).status_code==403
    assert not gateway.requests


@pytest.mark.parametrize('payload',[[], None, 'synthetic', 1, True, 0.5])
def test_non_object_oauth_response_has_controlled_recovery_and_clears_proof(portal, payload):
    rejected_token_response(portal, json.dumps(payload).encode(), 400)


@pytest.mark.parametrize('body,status',[(b'{',400),(b'{}',403),(b'{"access_token":[]}',400),
                                      (b'{"access_token":""}',403),(b' '*65537,400)])
def test_invalid_oauth_response_recovery_retains_bounds_and_field_validation(portal, body, status):
    rejected_token_response(portal, body, status)


def rejected_token_response(portal, body, status):
    app,client,gateway,_,login,_=portal
    calls=[]
    def respond(request):
        calls.append(request)
        return httpx.Response(200,content=body)
    original=app.state.link_portal.client
    try:
        with httpx.Client(transport=httpx.MockTransport(respond)) as oauth:
            app.state.link_portal.client=oauth
            response,query=login()
            assert response.status_code==status
            assert 'Sign-in incomplete' in response.text and 'Try signing in again' in response.text
            deletion=response.headers['set-cookie']
            assert LOGIN_COOKIE+'=' in deletion and 'Max-Age=0' in deletion
            assert LOGIN_COOKIE not in client.cookies
            replay=client.get('/connect/callback',params={'state':query['state'],'code':'synthetic','iss':'https://issuer.example'})
            assert replay.status_code==400 and len(calls)==1
            with app.state.service.store.db() as db:
                assert db.execute('SELECT count(*) FROM link_sessions').fetchone()[0]==0
            assert not gateway.requests
    finally:
        app.state.link_portal.client=original
    assert login()[0].status_code==303


def test_linked_session_not_replaced_qr_fallback_rate_limit_and_logout(portal):
    app,client,gateway,_,login,_=portal
    assert login()[0].status_code==303
    headers=csrf(client)
    gateway.state='WORKING'
    result=client.post('/connect/api/pair',headers=headers,json={'mode':'code','phone':'393331234567'})
    assert result.json()['connected'] is True
    assert all(method=='GET' for method,_,_ in gateway.requests)
    gateway.state='STOPPED'
    result=client.post('/connect/api/pair',headers=headers,json={'mode':'qr'})
    assert result.json()['qr_url']=='/connect/qr'
    assert client.get('/connect/qr').content.startswith(b'\x89PNG')
    result=client.post('/connect/api/pair',headers=headers,json={'mode':'code','phone':'393331234567'})
    assert result.status_code==429
    assert client.post('/connect/api/logout',headers=headers,json={}).status_code==200
    assert client.get('/connect/api/status').status_code==401
    assert not any('logout' in path or method=='DELETE' for method,path,_ in gateway.requests)


def test_anonymous_flood_with_discarded_cookies_and_spoofed_headers_cannot_fill_login_budget(portal):
    app,client,_,_,login,_=portal
    for attempt in range(100):
        client.cookies.clear()
        headers={'X-Forwarded-For':f'192.0.2.{attempt+1}','X-Real-IP':f'198.51.100.{attempt+1}',
                 'Forwarded':f'for=203.0.113.{attempt+1}'}
        response=client.get('/connect/login',headers=headers,follow_redirects=False)
        assert response.status_code==302
        assert len(client.cookies.get(LOGIN_COOKIE))<2048
    with app.state.service.store.db() as db:
        assert db.execute('SELECT count(*) FROM link_login_states').fetchone()[0]==0
        assert db.execute('SELECT count(*) FROM link_sessions').fetchone()[0]==0
    client.cookies.clear()
    assert login()[0].status_code==303


def test_failed_oauth_callbacks_do_not_reserve_login_capacity(portal):
    app,client,_,_,login,exchange=portal
    original=app.state.link_portal.client
    rejected=httpx.Client(transport=httpx.MockTransport(lambda request:httpx.Response(400,json={'error':'invalid_grant'})))
    app.state.link_portal.client=rejected
    try:
        for _ in range(55):
            assert login()[0].status_code==400
        with app.state.service.store.db() as db:
            assert db.execute('SELECT count(*) FROM link_login_states').fetchone()[0]==0
            assert db.execute('SELECT count(*) FROM link_sessions').fetchone()[0]==0
    finally:
        app.state.link_portal.client=original
        rejected.close()
    assert login()[0].status_code==303


def test_completed_login_records_and_sessions_are_bounded_and_expire(portal,monkeypatch):
    app,client,_,_,login,_=portal
    monkeypatch.setattr('sally_whatsapp.linking.LOGIN_RECORD_LIMIT',3)
    for _ in range(3):
        client.cookies.clear()  # Separate browsers retain independent sessions.
        assert login()[0].status_code==303
    client.cookies.clear()
    assert login()[0].status_code==429
    with app.state.service.store.db() as db:
        assert db.execute('SELECT count(*) FROM link_login_states').fetchone()[0]==3
        assert db.execute('SELECT count(*) FROM link_sessions').fetchone()[0]==3
        db.execute('UPDATE link_login_states SET expires=0')
        db.execute('UPDATE link_sessions SET expires=0')
    assert client.get('/connect/api/status').status_code==401
    app.state.link_portal.cleanup()
    with app.state.service.store.db() as db:
        assert db.execute('SELECT count(*) FROM link_sessions').fetchone()[0]==0
        assert db.execute('SELECT count(*) FROM link_login_states').fetchone()[0]==0
    assert login()[0].status_code==303


def callback_request(query,proof):
    params={'state':query['state'],'code':'synthetic-code','iss':'https://issuer.example'}
    return Request({'type':'http','method':'GET','path':'/connect/callback',
                    'query_string':urlencode(params).encode(),
                    'headers':[(b'cookie',(LOGIN_COOKIE+'='+proof).encode())]})


def pending_context(client,exchange):
    response=client.get('/connect/login',follow_redirects=False)
    assert response.status_code==302
    query={k:v[0] for k,v in parse_qs(urlsplit(response.headers['location']).query).items()}
    exchange['nonce']=query['nonce']
    return query,client.cookies.get(LOGIN_COOKIE)


@pytest.mark.parametrize('alteration',['absent','tamper','other_browser','expired','wrong_purpose','wrong_origin','wrong_client'])
def test_sealed_login_context_rejects_invalid_browser_binding_before_token_exchange(portal,alteration):
    app,client,_,_,_,exchange=portal
    query,proof=pending_context(client,exchange)
    if alteration=='absent': proof=''
    elif alteration=='tamper': proof=proof[:-10]+'A'*10
    elif alteration=='other_browser': _,proof=pending_context(client,exchange)
    else:
        context=json.loads(app.state.link_portal.cipher.decrypt(proof.encode()))
        if alteration=='expired': context['expires']=time.time()-1
        elif alteration=='wrong_origin': context['resource']='https://another-instance.example'
        elif alteration=='wrong_client': context['client_id']='another-link-client'
        else: context['purpose']='media-download'
        proof=app.state.link_portal.cipher.encrypt(json.dumps(context).encode()).decode()
    with pytest.raises(LinkError): app.state.link_portal.exchange(callback_request(query,proof))
    assert not exchange['posts']
    with app.state.service.store.db() as db:
        assert db.execute('SELECT count(*) FROM link_sessions').fetchone()[0]==0
        assert db.execute('SELECT count(*) FROM link_login_states').fetchone()[0]==0


def test_login_context_fernet_age_cannot_be_extended_by_payload(portal):
    app,client,_,_,_,exchange=portal
    query,proof=pending_context(client,exchange)
    context=app.state.link_portal.cipher.decrypt(proof.encode())
    # The authenticated payload still claims a future expiry, but the envelope is old.
    proof=app.state.link_portal.cipher.encrypt_at_time(context,int(time.time())-LOGIN_TTL-1).decode()
    with pytest.raises(LinkError): app.state.link_portal.exchange(callback_request(query,proof))
    assert not exchange['posts']


def test_used_login_context_survives_restart_and_cannot_be_replayed(portal):
    app,client,_,_,_,exchange=portal
    query,proof=pending_context(client,exchange)
    app.state.link_portal.exchange(callback_request(query,proof))
    assert len(exchange['posts'])==1
    # Logging out/deleting the session must not discard its separate replay guard.
    with app.state.service.store.db() as db: db.execute('DELETE FROM link_sessions')
    restarted=LinkPortal(app.state.service,oauth_client=app.state.link_portal.client)
    with pytest.raises(LinkError,match='already used'):
        restarted.exchange(callback_request(query,proof))
    assert len(exchange['posts'])==1


def test_concurrent_successful_callbacks_commit_only_one_session(portal):
    app,client,_,token,_,exchange=portal
    query,proof=pending_context(client,exchange)
    barrier=Barrier(2)
    def post(request):
        barrier.wait(timeout=5)
        return httpx.Response(200,json={
            'access_token':token(azp='pair-client',scope='whatsapp:link'),
            'id_token':token(aud='pair-client',nonce=query['nonce'])})
    original=app.state.link_portal.client
    concurrent=httpx.Client(transport=httpx.MockTransport(post))
    app.state.link_portal.client=concurrent
    def attempt(_):
        try: return app.state.link_portal.exchange(callback_request(query,proof))
        except LinkError as exc: return exc
    try:
        with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(attempt,range(2)))
    finally:
        app.state.link_portal.client=original
        concurrent.close()
    assert sum(isinstance(value,LinkError) for value in results)==1
    with app.state.service.store.db() as db:
        assert db.execute('SELECT count(*) FROM link_sessions').fetchone()[0]==1
        assert db.execute('SELECT count(*) FROM link_login_states').fetchone()[0]==1



@pytest.mark.parametrize('phase',['token_exchange','sqlite_commit_lock'])
def test_login_context_expiring_during_exchange_or_database_wait_cannot_create_session(portal,monkeypatch,phase):
    app,client,_,token,_,exchange=portal
    link=app.state.link_portal
    clock={'now':time.time()}
    monkeypatch.setattr('sally_whatsapp.linking.time',SimpleNamespace(time=lambda:clock['now']))
    query,proof=pending_context(client,exchange)
    token_started,response_allowed,commit_waiting=Event(),Event(),Event()
    def post(request):
        if phase=='token_exchange': clock['now']+=LOGIN_TTL+1
        else:
            token_started.set()
            assert response_allowed.wait(timeout=5)
        return httpx.Response(200,json={
            'access_token':token(azp='pair-client',scope='whatsapp:link'),
            'id_token':token(aud='pair-client',nonce=query['nonce'])})
    def attempt():
        with pytest.raises(LinkError,match='already expired'):
            link.exchange(callback_request(query,proof))
    original_client=link.client
    with httpx.Client(transport=httpx.MockTransport(post)) as oauth:
        link.client=oauth
        try:
            if phase=='token_exchange': attempt()
            else:
                original_db=link.store.db
                @contextmanager
                def observed_db():
                    with original_db() as connection:
                        connection.set_trace_callback(lambda sql:commit_waiting.set() if sql=='BEGIN IMMEDIATE' else None)
                        yield connection
                monkeypatch.setattr(link.store,'db',observed_db)
                with ThreadPoolExecutor(max_workers=1) as worker:
                    pending=worker.submit(attempt)
                    assert token_started.wait(timeout=5)
                    with original_db() as lock:
                        lock.execute('BEGIN IMMEDIATE')
                        response_allowed.set()
                        assert commit_waiting.wait(timeout=5)
                        assert not pending.done()
                        clock['now']+=LOGIN_TTL+1
                    pending.result(timeout=5)
        finally:
            link.client=original_client
    with link.store.db() as db:
        assert db.execute('SELECT count(*) FROM link_sessions').fetchone()[0]==0
        assert db.execute('SELECT count(*) FROM link_login_states').fetchone()[0]==0


def test_upgrade_drops_legacy_pending_states_without_touching_portal_sessions(portal):
    app,client,_,_,login,_=portal
    assert login()[0].status_code==303
    sid=client.cookies.get(COOKIE)
    with app.state.service.store.db() as db:
        for _ in range(50):
            state=secrets.token_urlsafe(32)
            db.execute('INSERT INTO link_login_states VALUES(?,?,?,?,?)',
                       (digest(state),digest('old-proof'),b'old-encrypted-verifier','old-nonce',time.time()+600))
    app.state.link_portal.cleanup()
    with app.state.service.store.db() as db:
        assert db.execute('SELECT count(*) FROM link_login_states').fetchone()[0]==1
        assert db.execute('SELECT count(*) FROM link_sessions WHERE id_hash=?',(digest(sid),)).fetchone()[0]==1
    assert client.get('/connect/api/status').status_code==200
    assert login()[0].status_code==303


@pytest.mark.parametrize('mode',['qr','code'])
def test_failed_pairing_restarts_existing_gateway_session(portal,mode):
    app,client,gateway,_,login,_=portal
    assert login()[0].status_code==303
    gateway.state='FAILED'
    result=client.post('/connect/api/pair',headers=csrf(client),json={'mode':mode,'phone':'393331234567'})
    assert result.status_code==200
    assert result.json()['state']=='SCAN_QR_CODE'
    posts=[path for method,path,_ in gateway.requests if method=='POST']
    assert posts[0]=='/api/sessions/default/restart'
    assert not any(path.endswith(('/start','/logout')) for path in posts)
    assert ('qr_url' if mode=='qr' else 'code') in result.json()


def test_status_reports_qr_rotation_without_exposing_pairing_material(portal):
    app,client,gateway,_,login,_=portal
    assert login()[0].status_code==303
    service=app.state.service
    for generation in ('2026-10-11T12:20:07Z','2026-10-11T12:21:07Z'):
        service.store.set_state('last_status_event_at',generation)
        result=client.get('/connect/api/status').json()
        assert result=={'state':'SCAN_QR_CODE','connected':False,'qr_revision':generation}
    gateway.state='FAILED'
    assert client.get('/connect/api/status').json()=={'state':'FAILED','connected':False}


def test_new_login_invalidates_only_previous_browser_session_even_when_wrong_owner_returns(portal):
    app,client,gateway,_,login,exchange=portal
    assert login()[0].status_code==303
    other_browser=client.cookies.get(COOKIE)
    client.cookies.clear()
    assert login()[0].status_code==303
    previous=client.cookies.get(COOKIE)
    exchange['changes']={'sub':'another-owner'}
    response,_=login()
    assert response.status_code==403
    assert 'WhatsApp · synthetic owner' in response.text
    assert 'this profile accepts only its owner' in response.text
    assert 'private window' in response.text
    assert 'href="/connect/login"' in response.text
    assert client.cookies.get(COOKIE) is None
    assert client.get('/connect/api/status').status_code==401
    assert 'Sign in and continue' in client.get('/connect').text
    with app.state.service.store.db() as db:
        assert not db.execute('SELECT 1 FROM link_sessions WHERE id_hash=?',(digest(previous),)).fetchone()
        assert db.execute('SELECT 1 FROM link_sessions WHERE id_hash=?',(digest(other_browser),)).fetchone()
    assert not gateway.requests
    exchange['changes']={}
    assert login()[0].status_code==303
    assert client.get('/connect/api/status').status_code==200


def test_new_login_closes_old_portal_session_before_callback_even_if_user_goes_back(portal):
    app,client,gateway,_,login,_=portal
    assert login()[0].status_code==303
    old=client.cookies.get(COOKIE)
    response=client.get('/connect/login',follow_redirects=False)
    assert response.status_code==302
    assert client.cookies.get(COOKIE) is None
    assert 'Sign in and continue' in client.get('/connect').text
    with app.state.service.store.db() as db:
        assert not db.execute('SELECT 1 FROM link_sessions WHERE id_hash=?',(digest(old),)).fetchone()
    assert not gateway.requests


def test_portal_profile_and_callback_errors_escape_untrusted_markup(portal):
    app,client,_,_,_,_=portal
    page=app.state.link_portal
    page.settings=replace(page.settings,profile_name='<img src=x onerror=alert(1)>')
    response=page.login_error('<script>alert(1)</script>',403)
    text=response.body.decode()
    assert '<script>alert(1)</script>' not in text
    assert '<img src=x' not in text
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in text
    assert 'no-store' in response.headers['cache-control']
    assert "script-src 'self'" in response.headers['content-security-policy']
