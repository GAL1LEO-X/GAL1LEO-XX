"""Human-only OAuth pairing portal. Pairing credentials never enter MCP tools/events.

Each isolated instance uses a dedicated OAuth client with whatsapp:link only.
The browser proves login state, PKCE and OIDC nonce; every action also needs CSRF.
"""
import asyncio
import base64
from dataclasses import replace
import hashlib
import hmac
from html import escape
import json
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt
from cryptography.fernet import Fernet, InvalidToken
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .auth import JWTVerifier
from .config import secret
from .gateway import GatewayUnavailable


COOKIE='__Host-wa-link'
LOGIN_COOKIE='__Host-wa-link-state'
LOGIN_TTL=600
LOGIN_RECORD_LIMIT=50
LOGIN_PURPOSE='wa-link-login-v1'
ASSETS=Path(__file__).with_name('assets')
HEADERS={
    'Cache-Control':'private, no-store', 'Pragma':'no-cache',
    'Referrer-Policy':'no-referrer', 'X-Content-Type-Options':'nosniff',
    'X-Frame-Options':'DENY',
    'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class LinkError(Exception):
    def __init__(self,message,status=400,*,error_code=None,outcome=None):
        self.status,self.error_code,self.outcome=status,error_code,outcome
        super().__init__(message)


class LinkPortal:
    def __init__(self,service,oauth_client=None):
        self.service=service
        self.settings=service.settings
        self.store=service.store
        self.gateway=service.gateway
        self.cipher=Fernet(secret(self.settings.encryption_key_file).encode())
        self.verifier=JWTVerifier(replace(self.settings,oauth_client_ids=[self.settings.link_client_id]),service.diagnostics)
        self.client=oauth_client or httpx.Client(timeout=15,follow_redirects=False,trust_env=False)

    def close(self):
        self.client.close()

    def routes(self):
        return [Route('/connect',self.page),Route('/connect/',self.page),
                Route('/connect/login',self.login),Route('/connect/callback',self.callback),
                Route('/connect/api/status',self.status),
                Route('/connect/api/pair',self.pair,methods=['POST']),
                Route('/connect/api/logout',self.logout,methods=['POST']),
                Route('/connect/qr',self.qr),
                Route('/connect/static/style.css',self.style),
                Route('/connect/static/app.js',self.script)]

    def cleanup(self):
        with self.store.db() as db:
            # Before F03 this table held pending logins with a stored verifier.
            # Those browser cookies must restart login; active portal sessions survive.
            db.execute("DELETE FROM link_login_states WHERE expires<=? OR verifier!=X''",(time.time(),))
            db.execute('DELETE FROM link_sessions WHERE expires<=?',(time.time(),))

    async def maintenance(self):
        while True:
            await self.service.run_sync(self.cleanup)
            await asyncio.sleep(60)

    def session(self,request):
        sid=request.cookies.get(COOKIE,'')
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}',sid):
            raise LinkError('Sign in to manage your connection.',401)
        with self.store.db() as db:
            row=db.execute('SELECT * FROM link_sessions WHERE id_hash=? AND owner=? AND expires>?',
                           (digest(sid),self.settings.owner_subject,time.time())).fetchone()
        if not row: raise LinkError('The page session expired. Sign in again.',401)
        try:
            token=self.verifier._verify(self.cipher.decrypt(row['access_token']).decode())
        except (InvalidToken,UnicodeError):
            token=None
        if not token or 'whatsapp:link' not in token.scopes:
            raise LinkError('Connection access is not authorized.',401)
        return dict(row)

    def csrf(self,request,session):
        if request.headers.get('origin')!=self.settings.public_url:
            raise LinkError('Request origin is not authorized.',403)
        if not hmac.compare_digest(request.headers.get('x-csrf-token',''),session['csrf']):
            raise LinkError('The request expired. Reload the page.',403)

    def html(self,body,*,session=None,status=200):
        csrf=escape(session['csrf'],quote=True) if session else ''
        profile=escape(self.settings.profile_name)
        access='Access verified' if session else 'Sign-in required'
        markup=f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>Connect WhatsApp · {profile}</title>
<link rel="icon" href="/assets/whatsapp-gpt.png">
<link rel="stylesheet" href="/connect/static/style.css"></head>
<body data-csrf="{csrf}"><main><header class="brand"><img src="/assets/whatsapp-gpt.png" alt="" width="52" height="52"><div><p class="brand-name">WhatsApp</p><p class="brand-caption">Connect with ChatGPT</p></div><span class="private-label">Personal space</span></header>
<section class="identity" aria-label="Profilo selezionato"><div><p class="eyebrow">SELECTED PROFILE</p><p class="profile">{profile}</p></div><span class="access-badge{' verified' if session else ''}" id="access-badge">{access}</span></section>
{body}<footer><span class="footer-mark" aria-hidden="true">✓</span><p>Confirm the connection only from your own phone.<br><span>Management restricted to the profile owner.</span></p></footer>
</main>{'<nav class="admin-return"><a href="/admin">Back to instance administration</a></nav>' if getattr(self.settings,'admin_enabled',False) else ''}{'<script src="/connect/static/app.js" defer></script>' if session else ''}</body></html>'''
        return HTMLResponse(markup,status_code=status,headers=HEADERS)

    def login_error(self,message,status=400):
        help_text=('Check the account used on the sign-in page: this profile accepts only its owner. If another account remains active, open this page in a private window and use the correct account.'
                   if status==403 else 'Restart here to obtain a new sign-in request.')
        return self.html('<section class="hero"><p class="section-label">SIGN IN AGAIN</p><h1>Sign-in incomplete.</h1><p class="intro">'+escape(message)+'</p></section><div class="notice error-notice" role="alert"><h2>How to continue</h2><p>'+help_text+'</p></div><div class="actions"><a class="button primary" href="/connect/login">Try signing in again</a><a class="button secondary" href="/connect">Back to the start</a></div>',status=status)

    async def page(self,request):
        # Standalone HTML rendering can omit the runtime; real portals always
        # route their session work through the service's owned thread executor.
        run_sync = self.service.run_sync if hasattr(self, 'service') else asyncio.to_thread
        try: session=await run_sync(self.session,request)
        except LinkError: session=None
        if not session:
            return self.html('<section class="hero"><p class="section-label">01 · SIGN IN</p><h1>Connect your WhatsApp.</h1><p class="intro">Your phone, in your ChatGPT space. Sign in with the account assigned to the profile above.</p></section>\n<ol class="steps" aria-label="Connection steps"><li class="current"><span aria-hidden="true">1</span>Sign in</li><li><span aria-hidden="true">2</span>Connect</li><li><span aria-hidden="true">3</span>Confirm</li></ol>\n<a class="button primary login-button" href="/connect/login">Sign in and continue <span aria-hidden="true">→</span></a>\n<p class="helper">Enter your password and complete verification on the identity-provider page.</p>\n<div class="notice"><h2>Already signed in with another account?</h2><p>Use the account assigned to this profile. Connecting then requires confirmation on your own phone.</p></div>')
        return self.html('<section class="hero"><p class="section-label" id="page-step">02 · CONNECTION</p><h1 id="page-title">Authorize the connection.</h1>\n<p class="intro" id="page-intro">Choose a code or QR. Keep the phone running WhatsApp nearby.</p></section>\n<div class="status" id="status" role="status" aria-live="polite"><span class="status-dot" aria-hidden="true"></span><div><strong id="status-title">Checking connection…</strong><p id="status-detail">Please wait while we check the phone status.</p></div></div>\n<button class="button secondary" id="status-retry" type="button" hidden>Check again</button>\n<section class="notice" id="activation-required" hidden><h2>Connection activation required</h2><p>This instance does not allow phone access yet. Preparation and activation must be completed through the authorized administration channel.</p><a href="/admin">Check prerequisites and progress</a></section>\n<section id="pairing" aria-label="Choose how to connect your phone" hidden>\n<div class="method"><div class="method-heading"><span class="method-icon" aria-hidden="true">123</span><div><h2>With a code</h2><p>Convenient from this phone too.</p></div></div>\n<form id="code-form"><label for="phone">WhatsApp number with country code</label>\n<input id="phone" name="phone" type="tel" autocomplete="tel" inputmode="tel" placeholder="+ country code …" maxlength="24" aria-describedby="phone-hint" required>\n<p class="helper" id="phone-hint">Use the number of the phone you want to connect.</p>\n<button class="button primary" type="submit" id="code-button">Generate temporary code</button></form>\n<div class="pairing-result" id="code-result" tabindex="-1" hidden><h3>Enter this code on your phone</h3><output id="pairing-code" aria-label="Pairing code"></output><p>In WhatsApp, open <strong>Linked devices → Link a device → Link with phone number</strong>.</p><p class="helper">This code is temporary. Confirm only the connection you initiated.</p></div></div>\n<div class="method-divider"><span>or</span></div>\n<div class="method"><div class="method-heading"><span class="method-icon" aria-hidden="true">QR</span><div><h2>With a QR code</h2><p>Scan with your phone.</p></div></div><p class="helper">Open this page on another screen to scan the QR code.</p>\n<button class="button secondary" id="qr-button" type="button">Use the QR code</button>\n<div class="pairing-result" id="qr-result" tabindex="-1" hidden><h3>Scan the QR code with your phone</h3><img id="qr-image" alt="QR temporaneo per collegare WhatsApp" width="260" height="260"><p>In WhatsApp, open <strong>Linked devices → Link a device</strong>.</p><button class="button secondary" type="button" id="qr-refresh">Refresh QR</button></div></div></section>\n<section class="notice success-notice" id="connected" hidden><h2>You can return to ChatGPT</h2><p>The phone is connected to this profile. You can now close this page.</p></section>\n<section class="notice" id="session-expired" hidden><h2>Resume with a new sign-in</h2><p>Sign in with the account assigned to this profile to check the connection.</p><a class="button primary" href="/connect/login">Sign in and continue</a></section>\n<p id="error" role="alert" tabindex="-1" hidden></p><div class="session-actions" id="session-actions"><button class="text-button" id="logout" type="button">Sign out of this page</button><p class="helper">Leaving this page does not disconnect the phone from WhatsApp.</p></div>',session=session)

    def forget_session(self,request):
        # Starting a different login must never fall back to an earlier owner
        # session when the new exchange fails. This only closes the local portal.
        sid=request.cookies.get(COOKIE,'')
        if re.fullmatch(r'[A-Za-z0-9_-]{43}',sid):
            with self.store.db() as db:
                db.execute('DELETE FROM link_sessions WHERE id_hash=? AND owner=?',
                           (digest(sid),self.settings.owner_subject))

    async def login(self,request):
        await self.service.run_sync(self.forget_session,request)
        # An anonymous request must not reserve scarce server-side login capacity.
        # Keep the PKCE verifier and nonce confidential and bound to this browser.
        # No IP/proxy header or resettable cookie counter is used for admission.
        state,verifier,nonce=[secrets.token_urlsafe(32) for _ in range(3)]
        context={'purpose':LOGIN_PURPOSE,'resource':self.settings.public_url,
                 'client_id':self.settings.link_client_id,'state':state,
                 'verifier':verifier,'nonce':nonce,'expires':time.time()+LOGIN_TTL}
        proof=self.cipher.encrypt(json.dumps(context,separators=(',',':')).encode()).decode()
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        params={'client_id':self.settings.link_client_id,'redirect_uri':self.settings.public_url+'/connect/callback',
                'response_type':'code','scope':'openid profile whatsapp:link','state':state,'nonce':nonce,
                'code_challenge':challenge,'code_challenge_method':'S256','resource':self.settings.public_url}
        response=RedirectResponse(self.settings.link_authorize_url+'?'+urlencode(params),status_code=302,headers=HEADERS)
        response.delete_cookie(COOKIE,path='/',secure=True,httponly=True,samesite='lax')
        response.set_cookie(LOGIN_COOKIE,proof,max_age=LOGIN_TTL,secure=True,httponly=True,samesite='lax',path='/')
        return response

    def exchange(self,request):
        query=request.query_params
        state,code=query.get('state',''),query.get('code','')
        proof=request.cookies.get(LOGIN_COOKIE,'')
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}',state) or not proof or len(proof)>2048:
            raise LinkError('Invalid sign-in request. Restart from the connection page.')
        if query.get('iss')!=self.settings.issuer or not code or len(code)>4096:
            raise LinkError('Sign-in incomplete. Check that you are using the account assigned to this profile.')
        try:
            context=json.loads(self.cipher.decrypt(proof.encode(),ttl=LOGIN_TTL))
            if (not isinstance(context,dict) or context.get('purpose')!=LOGIN_PURPOSE or
                    context.get('resource')!=self.settings.public_url or
                    context.get('client_id')!=self.settings.link_client_id or
                    any(not isinstance(context.get(key),str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',context[key])
                        for key in ('state','verifier','nonce')) or
                    not hmac.compare_digest(context['state'],state) or
                    type(context.get('expires')) not in (int,float) or context['expires']<=time.time()):
                raise ValueError('Invalid login context')
        except (InvalidToken,ValueError,TypeError,UnicodeError):
            raise LinkError('Sign-in request expired or invalid. Restart from the connection page.') from None
        self.cleanup()
        with self.store.db() as db:
            if db.execute('SELECT 1 FROM link_login_states WHERE state_hash=?',(digest(state),)).fetchone():
                raise LinkError('Sign-in request already used.')
        response=self.client.post(self.settings.link_token_url,data={
            'grant_type':'authorization_code','client_id':self.settings.link_client_id,'code':code,
            'code_verifier':context['verifier'],
            'redirect_uri':self.settings.public_url+'/connect/callback','resource':self.settings.public_url})
        if response.status_code!=200 or len(response.content)>65536:
            raise LinkError('The sign-in service did not complete the request. Try again.')
        payload=response.json()
        if not isinstance(payload,dict):
            raise LinkError('The sign-in service response is invalid. Restart from the initial page.')
        raw=payload.get('access_token','')
        if not isinstance(raw,str) or len(raw)>16384: raise LinkError('Invalid sign-in response.')
        token=self.verifier._verify(raw)
        if not token or 'whatsapp:link' not in token.scopes:
            raise LinkError('This account is not authorized for the profile.',403)
        identity=payload.get('id_token','')
        if not isinstance(identity,str) or len(identity)>16384: raise LinkError('Invalid sign-in identity.')
        key=self.verifier.jwks.get_signing_key_from_jwt(identity).key if self.verifier.jwks else self.verifier.key
        claims=jwt.decode(identity,key,algorithms=['RS256'],audience=self.settings.link_client_id,
                          issuer=self.settings.issuer,options={'require':['exp','iat','sub','nonce','iss','aud']})
        if claims['sub']!=self.settings.owner_subject or not isinstance(claims['nonce'],str) or not hmac.compare_digest(claims['nonce'],context['nonce']):
            raise LinkError('The identity does not match the sign-in request.',403)
        sid,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
        expires=min(time.time()+900,token.expires_at)
        if expires<=time.time() or context['expires']<=time.time(): raise LinkError('Sign-in already expired.')
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            # Acquiring the write lock may have waited past either credential's lifetime.
            if expires<=time.time() or context['expires']<=time.time(): raise LinkError('Sign-in already expired.')
            # Only a completed, owner-validated OAuth exchange consumes capacity.
            # Commit its replay marker with the session, also across concurrent callbacks.
            if db.execute('SELECT 1 FROM link_login_states WHERE state_hash=?',(digest(state),)).fetchone():
                raise LinkError('Sign-in request already used.')
            db.execute('DELETE FROM link_login_states WHERE expires<=?',(time.time(),))
            db.execute('DELETE FROM link_sessions WHERE expires<=?',(time.time(),))
            if (db.execute('SELECT count(*) FROM link_login_states').fetchone()[0]>=LOGIN_RECORD_LIMIT or
                    db.execute('SELECT count(*) FROM link_sessions').fetchone()[0]>=LOGIN_RECORD_LIMIT):
                raise LinkError('Several sign-ins have already completed. Wait a few minutes and try again.',429)
            db.execute('INSERT INTO link_login_states VALUES(?,?,?,?,?)',
                       (digest(state),digest(proof),b'',context['nonce'],context['expires']))
            db.execute('INSERT INTO link_sessions VALUES(?,?,?,?,?)',
                       (digest(sid),token.subject,self.cipher.encrypt(raw.encode()),csrf,expires))
        return sid,int(expires-time.time())

    async def callback(self,request):
        try:
            sid,ttl=await self.service.run_sync(self.exchange,request)
            response=RedirectResponse('/connect',status_code=303,headers=HEADERS)
            response.set_cookie(COOKIE,sid,max_age=ttl,secure=True,httponly=True,samesite='lax',path='/')
        except LinkError as exc:
            self.service.diagnostics.emit('pairing.login_failed','warning',error_code='PAIRING_LOGIN',status=exc.status)
            response=self.login_error(str(exc),exc.status)
        except (httpx.HTTPError,jwt.PyJWTError,InvalidToken,ValueError,TypeError,KeyError) as exc:
            self.service.diagnostics.emit('pairing.login_failed','error',error_code='PAIRING_TOKEN_EXCHANGE',exception=type(exc).__name__)
            response=self.login_error('The sign-in service response is invalid or expired. Try again from the initial page.')
        response.delete_cookie(LOGIN_COOKIE,path='/',secure=True,httponly=True,samesite='lax')
        return response

    def connection(self):
        if not self.settings.live_account_enabled or not self.settings.link_enabled:
            return {'state':'PREPARED','connected':False,'pairing_available':False,
                    'activation_required':True,'source':'local_configuration_only'}
        data=self.gateway.request('GET','/api/sessions/'+self.gateway.session)
        if not isinstance(data,dict):
            raise GatewayUnavailable('Invalid provider session observation')
        state=data.get('status','UNKNOWN')
        if not isinstance(state,str):
            raise GatewayUnavailable('Invalid provider session observation')
        allowed={'WORKING','STOPPED','STARTING','SCAN_QR_CODE','FAILED','PASSKEY_REQUIRED','PASSKEY_CONFIRMATION_REQUIRED'}
        result={'state':state if state in allowed else 'UNKNOWN','connected':state=='WORKING'}
        if state=='SCAN_QR_CODE':
            # WhatsApp rotates the QR while the state itself remains unchanged.
            result['qr_revision']=self.store.state().get('last_status_event_at','')
        return result

    async def status(self,request):
        try:
            await self.service.run_sync(self.session,request)
            return JSONResponse(await self.service.run_sync(self.connection),headers=HEADERS)
        except LinkError as exc: return JSONResponse({'error':str(exc)},status_code=exc.status,headers=HEADERS)
        except GatewayUnavailable: return JSONResponse({'error':'The connection is starting or unreachable. Try again shortly.'},status_code=503,headers=HEADERS)

    def request_pair(self,mode,phone):
        if not self.settings.live_account_enabled or not self.settings.link_enabled:
            raise LinkError('Connection is not activated for this instance. Complete prerequisites through the authorized administration channel.',409)
        try:
            status=self.connection()
        except GatewayUnavailable:
            raise LinkError('Provider status unavailable. No connection request was started.',503,
                            error_code='PAIRING_PRECONDITION_UNAVAILABLE',outcome='not_started') from None
        if status['connected']: return status
        if status['state'] in ('PASSKEY_REQUIRED','PASSKEY_CONFIRMATION_REQUIRED'):
            raise LinkError('WhatsApp requires additional confirmation. Complete the request on the phone; if it remains blocked, request assistance with QR pairing.',409)
        now=time.time()
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT last_request FROM link_rate_limit WHERE singleton=1').fetchone()
            if row and now-row[0]<30:
                raise LinkError('Wait 30 seconds before requesting another code or QR.',429)
            db.execute('INSERT OR REPLACE INTO link_rate_limit VALUES(1,?)',(now,))
        if status['state']=='FAILED':
            # WAHA keeps the failed session object in its running-session map.
            # Calling /start is then a no-op: /restart must dispose of it first.
            self.gateway.request('POST','/api/sessions/'+self.gateway.session+'/restart')
            self.service.diagnostics.emit('pairing.recovered',previous_state='FAILED')
        elif status['state']=='STOPPED':
            self.gateway.request('POST','/api/sessions/'+self.gateway.session+'/start')
        for _ in range(16):
            status=self.connection()
            if status['state']!='STARTING': break
            time.sleep(0.5)
        if status['connected']: return status
        if status['state']!='SCAN_QR_CODE':
            raise LinkError('The connection is not ready yet. Wait a few seconds and try again.',409)
        if mode=='qr': return {**status,'qr_url':'/connect/qr'}
        answer=self.gateway.request('POST','/api/'+self.gateway.session+'/auth/request-code',json={'phoneNumber':phone},timeout=30)
        code=answer.get('code') if isinstance(answer,dict) else None
        if not isinstance(code,str) or not re.fullmatch(r'[A-Z0-9]{4}-?[A-Z0-9]{4}',code,re.I):
            raise LinkError('The request outcome cannot be verified. Check connection status before requesting another code or QR.',502,
                            error_code='PAIRING_OUTCOME_UNVERIFIED',outcome='uncertain')
        return {**status,'code':code.upper()}

    async def pair(self,request):
        try:
            session=await self.service.run_sync(self.session,request)
            self.csrf(request,session)
            raw=bytearray()
            async for chunk in request.stream():
                raw.extend(chunk)
                if len(raw)>4096: raise LinkError('Request too large.',413)
            data=json.loads(raw)
            if not isinstance(data,dict) or set(data)-{'mode','phone'}: raise LinkError('Invalid request.')
            mode=data.get('mode')
            if mode not in ('code','qr'): raise LinkError('Choose code or QR.')
            phone=data.get('phone','')
            if not isinstance(phone,str): raise LinkError('Invalid number.')
            phone=re.sub(r'[ +()-]','',phone)
            if mode=='code' and not re.fullmatch(r'[1-9][0-9]{6,14}',phone):
                raise LinkError('Enter the complete number including the international country code.')
            result=await self.service.run_sync(self.request_pair,mode,phone)
            self.service.diagnostics.emit('pairing.requested',state=result.get('state'),operation='code' if mode=='code' else 'qr')
            return JSONResponse(result,headers=HEADERS)
        except LinkError as exc:
            value={'error':str(exc)}
            if exc.error_code: value.update(error_code=exc.error_code,outcome=exc.outcome)
            return JSONResponse(value,status_code=exc.status,headers=HEADERS)
        except (ValueError,TypeError): return JSONResponse({'error':'Invalid request.'},status_code=400,headers=HEADERS)
        except GatewayUnavailable:
            return JSONResponse({'error':'The request outcome cannot be verified. Check connection status before requesting another code or QR.',
                                 'error_code':'PAIRING_OUTCOME_UNVERIFIED','outcome':'uncertain'},status_code=502,headers=HEADERS)

    async def qr(self,request):
        try:
            await self.service.run_sync(self.session,request)
            status=await self.service.run_sync(self.connection)
            if status['state']!='SCAN_QR_CODE': raise LinkError('QR unavailable in the current state.',409)
            data=await self.service.run_sync(self.gateway.pairing_qr)
            return Response(data,media_type='image/png',headers=HEADERS)
        except LinkError as exc: return JSONResponse({'error':str(exc)},status_code=exc.status,headers=HEADERS)
        except GatewayUnavailable: return JSONResponse({'error':'QR temporarily unavailable.'},status_code=502,headers=HEADERS)

    async def logout(self,request):
        try:
            session=await self.service.run_sync(self.session,request)
            self.csrf(request,session)
            def remove_session():
                with self.store.db() as db:
                    db.execute('DELETE FROM link_sessions WHERE id_hash=?',(session['id_hash'],))
            await self.service.run_sync(remove_session)
            response=JSONResponse({'signed_out':True},headers=HEADERS)
            response.delete_cookie(COOKIE,path='/',secure=True,httponly=True,samesite='lax')
            return response
        except LinkError as exc: return JSONResponse({'error':str(exc)},status_code=exc.status,headers=HEADERS)

    async def style(self,request):
        return Response((ASSETS/'connect.css').read_bytes(),media_type='text/css',headers=HEADERS)

    async def script(self,request):
        return Response((ASSETS/'connect.js').read_bytes(),media_type='application/javascript',headers=HEADERS)
