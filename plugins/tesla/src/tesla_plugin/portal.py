"""Small private owner console with independent login, CSRF and secure PIN entry."""
import base64
import asyncio
import hashlib
import hmac
from html import escape
import json
import secrets
from urllib.parse import urlsplit

from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from .config import AUTHORIZE_URL, secret
from .errors import TeslaError
from .store import digest
from .dashboard import render as dashboard, history as vehicle_history
from .catalogue import operation
from .ui import icon, local_time, parameters, PARAMETERS
from .triggers import Triggers
from .trigger_ui import render as trigger_page, rule_form_config
from .telemetry import Telemetry, LOCATION_FIELDS
from .collection import Collection, CREATE, DELETE, full_profile
from .collection_ui import render as collection_page, review as collection_review
from .overview_ui import render as overview, route_panel
from .route_evidence import view as route_view
from .service import redact
from .trigger_catalog import location_allowed

STATUS = {"prepared": 'Awaiting confirmation', "sending": 'Sending', "acknowledged": 'Accepted by Tesla · effect needs verification',
          "rejected": 'Rejected', "unknown": 'Outcome uncertain · do not repeat', "expired": 'Expired', "cancelled": 'Cancelled',
          "blocked": 'Not sent · prerequisite unresolved', "incomplete": 'Incomplete review',
          "reconciled": 'Configuration verified · request acceptance unconfirmed'}


def command_evidence(item, timezone):
    evidence = item.get('verification', {})
    status = item['status']
    sent = 'Not sent' if status in ('prepared', 'cancelled', 'expired') else 'Sending' if status == 'sending' else 'Sent' if evidence.get('command_accepted') else 'Submission attempted · outcome needs verification' if status == 'unknown' or (item.get('result') or {}).get('dispatch_attempted') else 'Delivery not documented'
    accepted = 'Accepted by Tesla' if evidence.get('command_accepted') else 'Rejected' if status == 'rejected' else 'Unconfirmed'
    effect = 'Effect observed after the command' if evidence.get('effect_observed') else 'Effect unverified'
    body = '<section class="command-evidence" aria-label="Submission, acceptance and effect"><dl>'
    body += ''.join('<div><dt>'+label+'</dt><dd>'+escape(value)+'</dd></div>' for label, value in (('Submission', sent), ('Tesla response', accepted), ('Observation', effect)))+'</dl>'
    observed = evidence.get('observation')
    if observed and evidence.get('effect_observed'):
        body += '<p>Source: '+escape(observed['source'])+' · '+escape(local_time(observed['source_timestamp'], timezone))+'. '
        if observed.get('age_seconds') is not None:
            body += 'Age: '+str(round(observed['age_seconds']))+' s. '
        body += 'The observation does not prove current state or causality.</p>'
    if status in ('unknown', 'sending'):
        body += '<p>Outcome uncertain: do not automatically repeat the request.</p>'
    return body+'</section>'


def password_hash(password, salt=None):
    if not isinstance(password, str) or not 16 <= len(password) <= 512:
        raise ValueError("Owner passphrase must contain 16–512 characters")
    salt = salt or secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return "scrypt$"+base64.b64encode(salt).decode()+"$"+base64.b64encode(key).decode()


def password_valid(password, stored):
    try:
        algorithm, salt, expected = stored.split("$")
        if algorithm != "scrypt":
            return False
        actual = password_hash(password, base64.b64decode(salt, validate=True))
        return hmac.compare_digest(actual, stored)
    except (ValueError, TypeError):
        return False


class Portal:
    COOKIE = "__Secure-tesla-owner"

    def __init__(self, service):
        self.service, self.store, self.settings = service, service.store, service.settings
        self.base = urlsplit(self.settings.public_url).path.rsplit("/mcp", 1)[0]
        u = urlsplit(self.settings.public_url)
        self.origin = f"{u.scheme}://{u.netloc}"

    def session(self, request):
        cookie = request.cookies.get(self.COOKIE, "")
        with self.store.db() as db:
            row = db.execute("SELECT * FROM sessions WHERE id=? AND expires>?", (digest(cookie), self.store.clock())).fetchone()
        return dict(row) if row else None

    def csrf(self, request, form, session):
        if not session or request.headers.get("origin") != self.origin:
            raise TeslaError("FORBIDDEN", "Owner session and same-origin request required")
        supplied = form.get("csrf", "")
        if not isinstance(supplied, str) or not hmac.compare_digest(supplied, session["csrf"]):
            raise TeslaError("FORBIDDEN", "Invalid form token")

    def page(self, title, body, *, status=200, layout="message", session=None, subtitle="", badge="", allow_tesla_auth=False, calculator=False, vehicle_ref=None):
        navigation = ''
        back_to_top = ''
        account = '<span class="header-private">Personal space</span>'
        if session:
            collection_url = self.base+'/owner/collection/'+vehicle_ref if vehicle_ref else self.base+'/owner#raccolta'
            triggers_url = self.base+'/owner/triggers/'+vehicle_ref if vehicle_ref else self.base+'/owner#eventi'
            links = ((self.base+'/owner#inizio', 'Overview', 'dashboard'), (collection_url, 'Data collection', 'collection'),
                     (triggers_url, 'Events', 'triggers'), (self.base+'/owner#attivita', 'Activity', ''), (self.base+'/owner#collegamento', 'Connection', ''))
            navigation = '<nav aria-label="Navigazione principale">'+''.join('<a href="'+escape(url, quote=True)+'"'+(' aria-current="page"' if layout == active else '')+'>'+label+'</a>' for url, label, active in links)+'</nav>'
            back_to_top = '<a class="back-to-top" href="#inizio" aria-label="Back to the top of the page">'+icon('arrow')+'<span>Back to top</span></a>'
            account = self.form(self.base+"/owner/logout", 'Sign out', session["csrf"], kind="quiet", symbol="logout")
        script = f'<script defer src="{self.base}/assets/owner.js"></script>' if session else ''
        if calculator:
            script += f'<script defer src="{self.base}/assets/collection.js"></script>'
        script_policy = " script-src 'self';" if script else ''
        heading = '' if layout == 'dashboard' else f'<div class="page-heading"><div><h1>{escape(title)}</h1>{"<p class=page-subtitle>"+escape(subtitle)+"</p>" if subtitle else ""}</div>{badge}</div>'
        html = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} · TESLA</title><link rel="icon" type="image/png" href="{self.base}/assets/tesla-logo.png"><link rel="stylesheet" href="{self.base}/assets/owner.css">{script}</head>
<body id="inizio" class="layout-{escape(layout, quote=True)}"><a class="skip-link" href="#contenuto">Skip to content</a>
<header class="site-header"><a class="brand" href="{self.base}/owner" aria-label="TESLA, overview"><img class="brand-logo" src="{self.base}/assets/tesla-logo.png" width="36" height="36" alt="">TESLA<span>PERSONAL</span></a>{navigation}<div class="header-account">{account}</div></header>
<main id="contenuto">{heading}{body}</main>
<footer class="site-footer"><span>TESLA · Personal</span><span>{icon("shield")}Owner access only</span></footer>{back_to_top}</body></html>'''
        # Browser form POSTs under no-referrer can send Origin: null. Keep the
        # same-origin Origin/CSRF checks usable without leaking cross-site refs.
        form_action = "'self'"
        if allow_tesla_auth:
            # Chromium checks form-action on the POST's cross-origin redirect.
            # Only the dashboard starts OAuth; PIN/password pages stay local.
            authorize = urlsplit(AUTHORIZE_URL)
            form_action += f" {authorize.scheme}://{authorize.netloc}"
        return HTMLResponse(html, status_code=status, headers={"Cache-Control": "no-store", "Referrer-Policy": "same-origin",
            "Content-Security-Policy": f"default-src 'none';{script_policy} style-src 'self'; img-src 'self' data:; form-action {form_action}; frame-ancestors 'none'; base-uri 'none'",
            "X-Content-Type-Options": "nosniff"})

    def form(self, action, label, csrf, fields="", *, kind="primary", symbol=None):
        return f'<form method="post" action="{escape(action, quote=True)}"><input type="hidden" name="csrf" value="{escape(csrf, quote=True)}">{fields}<button class="button button-{kind}" type="submit">{icon(symbol) if symbol else ""}{escape(label)}</button></form>'

    def login_page(self, *, error="", status=200):
        feedback = '<p class="form-error" id="login-error" role="alert">'+escape(error)+'</p>' if error else ''
        invalid = ' aria-invalid="true"' if error else ''
        described_by = 'login-help login-error' if error else 'login-help'
        body = f'<div class="login-panel"><form method="post" action="{self.base}/owner/login"><label>Panel passphrase<input name="password" type="password" required autocomplete="current-password" maxlength="512" aria-describedby="{described_by}"{invalid}></label>{feedback}<p class="field-help" id="login-help">Use your personal panel passphrase.</p><button class="button button-primary">Sign in</button></form><div class="login-note">{icon("shield")}Your data and commands, in a private space.</div></div>'
        return self.page('Sign in', body, layout="auth", subtitle='Your Tesla, in your personal space.', status=status)

    async def login(self, request):
        if not self.settings.owner_password_file:
            return self.page('Configuration required', '<p>The owner panel is not configured yet.</p>', status=503)
        if request.method == "GET":
            return self.login_page()
        if request.headers.get("origin") != self.origin:
            return self.page('Access denied', '<p>Invalid request origin.</p>', status=403)
        now = self.store.clock()
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            attempts = db.execute("SELECT count(*) FROM login_attempts WHERE at>?", (now-300,)).fetchone()[0]
            if attempts >= 10:
                return self.login_page(error='Too many sign-in attempts. Wait a few minutes before trying again.', status=429)
            db.execute("INSERT INTO login_attempts VALUES(?)", (now,))
        form = await request.form(max_fields=3)
        if not password_valid(form.get("password"), secret(self.settings.owner_password_file)):
            return self.login_page(error='Invalid passphrase. Try again.', status=401)
        cookie, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.store.db() as db:
            db.execute("INSERT INTO sessions VALUES(?,?,?)", (digest(cookie), csrf, now+1800))
        response = RedirectResponse(self.base+"/owner", status_code=303)
        response.set_cookie(self.COOKIE, cookie, max_age=1800, path=self.base+"/", secure=True, httponly=True, samesite="lax")
        return response

    async def home(self, request):
        session = self.session(request)
        if not session:
            return RedirectResponse(self.base+"/owner/login", status_code=303)
        state = self.service.connection_status()
        badge_text = 'Account connected' if state["connected"] else 'Account connection required'
        body = ''
        if not state["live_enabled"]:
            body += '<aside class="dev-notice"><span class="notice-mark" aria-hidden="true"></span><strong>Development mode</strong><span>Live Tesla requests are disabled.</span></aside>'
        vehicles = self.service.list_vehicles(refresh=False)
        body += '<div id="panoramica">'
        if not vehicles:
            body += '<section class="empty-vehicle">'+icon("car")+'<h1>Connect your Tesla</h1>'
            if state["connected"]:
                body += '<p>The account is connected. Refresh the list to find your vehicles.</p>'+self.form(self.base+"/owner/refresh", 'Refresh vehicles', session["csrf"])
            else:
                body += '<p>Connect your Tesla account to view authorized vehicles.</p>'+self.form(self.base+"/owner/connect", 'Connect Tesla account', session["csrf"])
            body += '</section>'
        for index, vehicle in enumerate(vehicles):
            body += dashboard(self.store, vehicle["vehicle_ref"], self.settings.timezone,
                              name=vehicle["name"], state=vehicle["state"], base=self.base, primary=index == 0)
            body += overview(Collection(self.service).view(vehicle["vehicle_ref"]),
                             Triggers(self.store).view(vehicle["vehicle_ref"], self.settings.allowed_scopes), self.base, first=index == 0)
            body += vehicle_history(self.store, vehicle["vehicle_ref"], self.settings.timezone)
            with self.store.db() as db:
                snapshots = db.execute("SELECT section,data,source_at FROM snapshots WHERE vehicle=? ORDER BY section", (vehicle["vehicle_ref"],)).fetchall()
            can_locate = location_allowed(self.store.connection(), self.store.vehicle(vehicle["vehicle_ref"]),
                                          self.settings.allowed_scopes)
            body += route_panel(route_view(self.store, vehicle['vehicle_ref'], location_allowed=can_locate), self.settings.timezone)
            snapshots = [s for s in snapshots if s["section"] in ("charge_state", "climate_state", "vehicle_state")]
            if snapshots:
                body += '<details class="snapshot-list"><summary>Recorded technical data</summary>'
            for snapshot in snapshots:
                if snapshot["section"] not in ("charge_state", "climate_state", "vehicle_state"):
                    continue
                label = {"charge_state": 'Charging', "climate_state": 'Climate', "vehicle_state": 'Vehicle'}[snapshot["section"]]
                body += f'<details><summary>Recorded data · {label}<span>{escape(local_time(snapshot["source_at"], self.settings.timezone)) if snapshot["source_at"] else "Timestamp unavailable"}</span></summary><pre>{escape(json.dumps(redact(json.loads(snapshot["data"]), location=can_locate), ensure_ascii=False, indent=2))}</pre></details>'
            if snapshots:
                body += '</details>'
        body += '</div>'
        with self.store.db() as db:
            intents = db.execute("SELECT id,operation,status,created,expires,result FROM intents ORDER BY created DESC LIMIT 30").fetchall()
        incomplete = {i['id'] for i in intents if i['status'] == 'prepared' and i['expires'] > self.store.clock()
                      and i['operation'] in (CREATE, DELETE) and self.service.intent_view(i['id']).get('review_complete') is False}
        blocked_count = sum(i["status"] == "prepared" and i["expires"] > self.store.clock()
                            and i['id'] not in incomplete
                            and bool(i["result"] and json.loads(i["result"]).get("stage") == "preflight") for i in intents)
        pending = sum(i["status"] == "prepared" and i["expires"] > self.store.clock() and i['id'] not in incomplete for i in intents)-blocked_count
        uncertain = sum(i["status"] in ("sending", "unknown") for i in intents)
        action_note = (str(pending)+' awaiting confirmation' if pending else 'Nothing awaiting confirmation')
        if blocked_count:
            action_note += ' · '+str(blocked_count)+' with unresolved prerequisites'
        if uncertain:
            action_note += ' · '+str(uncertain)+' with an outcome requiring verification'
        if incomplete:
            action_note += ' · '+str(len(incomplete))+' with an incomplete review'
        action_note += ' · '+str(len(intents))+' recent'
        body += '<details class="compact-panel actions-panel" id="attivita"><summary>'+icon("car")+'<span><strong>Requested actions</strong><small>'+action_note+'</small></span></summary><div class="disclosure-content">'
        if not intents:
            body += '<div class="empty-actions">'+icon("check")+'<div><p>No pending actions.</p><span>Requests prepared in ChatGPT appear here.</span></div></div>'
        body += '<ul class="intent-list">'
        for intent in intents:
            status = "expired" if intent["status"] == "prepared" and intent["expires"] <= self.store.clock() else intent["status"]
            if status == "prepared" and intent["result"] and json.loads(intent["result"]).get("stage") == "preflight":
                status = "blocked"
            if intent['id'] in incomplete:
                status = 'incomplete'
            description = operation(intent["operation"])["description"]
            body += '<li><span class="action-symbol">'+icon("clock" if status == "prepared" else "car")+'</span><div class="action-description"><strong>'+escape(description)+'</strong><span>'+escape(local_time(intent["created"], self.settings.timezone))+'</span></div>'
            label = STATUS.get(status, status)
            if status == 'acknowledged' and self.service.intent_view(intent['id'])['verification'].get('effect_observed'):
                label = 'Accepted by Tesla · effect observed'
            body += f'<span class="status-badge status-{escape(status, quote=True)}">{escape(label)}</span><a class="review-link" href="{self.base}/owner/intents/{intent["id"]}" aria-label="Review: {escape(description, quote=True)}">Review{icon("arrow")}</a></li>'
        body += '</ul></div></details><section class="connection-panel" id="collegamento"><details><summary>'+icon("settings")+'<span><strong>Connection and account</strong><small>'+badge_text+' · Access and personal data</small></span></summary><div class="connection-content">'
        body += '<p>'+badge_text+'.</p><div class="button-row">'+self.form(self.base+"/owner/connect", 'Reconnect Tesla account' if state["connected"] else 'Connect Tesla account', session["csrf"], kind="secondary")
        body += self.form(self.base+"/owner/refresh", 'Refresh vehicles', session["csrf"], kind="secondary")+'</div>'
        body += '<div class="disconnect-area"><h3>Disconnect the panel</h3><p>Local disconnection deletes plugin history, tokens and notifications. Also revoke the app and key in your Tesla account to stop access on the Tesla side.</p>'
        body += self.form(self.base+"/owner/disconnect", 'Disconnect and delete local data', session["csrf"], kind="danger")+'</div></div></details></section>'
        return self.page('Your Tesla', body, layout="dashboard", session=session,
                         allow_tesla_auth=state["live_enabled"], vehicle_ref=vehicles[0]["vehicle_ref"] if len(vehicles) == 1 else None)

    async def collection(self, request):
        session = self.session(request)
        if not session:
            return RedirectResponse(self.base+"/owner/login", status_code=303)
        ref = request.path_params["vehicle_ref"]
        path = self.base+"/owner/collection/"+ref
        try:
            manager = Collection(self.service)
            view = manager.view(ref, include_fields=True)
            options = {}
            response_status = 200
            if request.method == "POST":
                form = await request.form(max_fields=2000)
                self.csrf(request, form, session)
                action = form.get("collection_action")
                if action == "refresh":
                    await asyncio.to_thread(manager.refresh, ref, self.settings.allowed_scopes)
                    return RedirectResponse(path, status_code=303)
                if action == "estimate":
                    fields, alerts, hours = manager.form_profile(form)
                    options = {"fields": fields, "alerts": alerts, "hours": hours, "preset": "custom"}
                    revision = form.get('revision')
                    if not isinstance(revision, str) or not revision:
                        raise TeslaError('INVALID_ARGUMENT', 'Draft revision missing. Reload collection before editing.')
                    options['draft_revision'] = revision
                    if revision != view['revision']:
                        options['revision_conflict'] = True
                        response_status = 409
                    if form.get('duration_seconds'):
                        try:
                            duration = int(form['duration_seconds'])
                        except ValueError:
                            raise TeslaError('INVALID_ARGUMENT', 'Invalid temporary duration.') from None
                        if not 60 <= duration <= 86400:
                            raise TeslaError('INVALID_ARGUMENT', 'Duration must be between 1 minute and 24 hours.')
                        options['duration_seconds'] = duration
                    if form.get("trigger_revision") is not None:
                        try:
                            options["trigger_revision"] = int(form["trigger_revision"])
                        except ValueError:
                            raise TeslaError("INVALID_ARGUMENT", 'Invalid event revision.') from None
                else:
                    item = await asyncio.to_thread(manager.prepare, ref, form, self.settings.allowed_scopes)
                    return RedirectResponse(self.base+"/owner/intents/"+item["id"], status_code=303)
            else:
                preset = request.query_params.get("preset", "saved")
                options["preset"] = preset
                if request.query_params.getlist("for_trigger"):
                    proposal = manager.trigger_proposal(ref, request.query_params.getlist("for_trigger"), self.settings.allowed_scopes)
                    options["proposal"] = proposal
                    if proposal["available"]:
                        options.update(fields=proposal["fields"], alerts=proposal["customer_alerts"], hours=proposal["estimate"]["active_hours_per_day"],
                                       preset="custom", trigger_revision=proposal["expected_trigger_revision"])
                elif preset != "saved":
                    scenario = manager.scenario(preset, active_hours_per_day=view['hours'], vehicle_context=view['vehicle_context'])
                    options["fields"] = scenario['fields']
                    options["alerts"] = scenario['customer_alerts']
            return self.page('Data collection', collection_page(view, session["csrf"], self.base, self.settings,
                             trigger_items=Triggers(self.store).view(ref, self.settings.allowed_scopes)["items"], **options),
                             layout="collection", session=session, subtitle=view["name"]+' · Fields, frequencies and monthly cost', calculator=True, vehicle_ref=ref, status=response_status)
        except TeslaError as exc:
            return self.page('Collection unchanged', '<p>'+escape(exc.message)+'</p><a class="back-link" href="'+escape(path, quote=True)+'">Back to data collection</a>',
                             status=409 if exc.code in ("REVISION_CONFLICT", "OPERATION_PENDING") else 400, session=session)

    async def triggers(self, request):
        session = self.session(request)
        if not session:
            return RedirectResponse(self.base+"/owner/login", status_code=303)
        ref = request.path_params["vehicle_ref"]
        try:
            manager = Triggers(self.store)
            view = manager.view(ref, self.settings.allowed_scopes)
            if request.method == "POST":
                form = await request.form(max_fields=600)
                self.csrf(request, form, session)
                try:
                    revision = int(form.get("revision", ""))
                    interval = int(form.get("batch_seconds", "")) if form.get("category") == "batching" else None
                except ValueError:
                    raise TeslaError("INVALID_ARGUMENT", "Invalid trigger settings") from None
                category = form.get("category")
                if category == "delivery_access":
                    value = form.get("automatic_access_checks", "false")
                    if value not in ("true", "false"):
                        raise TeslaError("INVALID_ARGUMENT", "Invalid authorization check setting")
                    manager.update(ref, [], self.settings.allowed_scopes, expected_revision=revision,
                                   automatic_access_checks=value == "true", source="owner_panel")
                    return RedirectResponse(self.base+"/owner/triggers/"+ref+"?saved=1", status_code=303)
                if category == "preset":
                    manager.apply_preset(ref, form.get("preset"), self.settings.allowed_scopes,
                                         expected_revision=revision, source="owner_panel")
                    return RedirectResponse(self.base+"/owner/triggers/"+ref+"?saved=1", status_code=303)
                if category == "rule":
                    if "tesla:manage" not in self.settings.allowed_scopes:
                        raise TeslaError("SCOPE_REQUIRED", "Rule management requires tesla:manage")
                    rule = next((i for i in view["items"] if i["id"] == "rule:"+form.get("rule_id", "")), None)
                    if not rule or not rule["available"] or rule.get("config") is None:
                        raise TeslaError("NOT_FOUND", 'Rule unavailable')
                    config = rule_form_config(rule, form)
                    vehicle = self.service.vehicle(ref, refresh_membership=False)
                    if rule["label"] == "geofence" or config.get("field") in LOCATION_FIELDS:
                        self.service.location_allowed(vehicle, self.settings.allowed_scopes)
                    Telemetry(self.store).configure_rule(ref, rule["label"], config, rule_id=form.get("rule_id"),
                                                        expected_revision=revision, source="owner_panel")
                    return RedirectResponse(self.base+"/owner/triggers/"+ref+"?saved=1", status_code=303)
                items = [item for item in view["items"] if item["category"] == category]
                selection = form.get("selection")
                selected = set(form.getlist("enabled"))
                if category != "batching" and (not items or selection not in ("save", "all", "none") or not selected <= {r["id"] for r in items}):
                    raise TeslaError("INVALID_ARGUMENT", "Invalid trigger selection")
                changes = []
                for item in items:
                    enabled = (item["id"] in selected if selection == "save" else selection == "all")
                    if enabled and not item["available"]:
                        # Category-wide actions cannot grant withheld location.
                        enabled = item["enabled"] if selection == "all" else enabled
                    if enabled != item["enabled"]:
                        changes.append({"trigger_id": item["id"], "enabled": enabled})
                # Even a no-op validates the revision; do not overwrite a newer
                # setting from ChatGPT with a stale browser form.
                manager.update(ref, changes, self.settings.allowed_scopes, expected_revision=revision,
                               batch_seconds=interval if interval is not None else view["batch_seconds"], source="owner_panel")
                return RedirectResponse(self.base+"/owner/triggers/"+ref+"?saved=1", status_code=303)
            return self.page('Events for ChatGPT', trigger_page(view, session["csrf"], self.base, saved=request.query_params.get("saved") == "1"),
                             layout="triggers", session=session, subtitle=self.store.vehicle(ref)["name"]+' · Selection shared with chat', vehicle_ref=ref)
        except TeslaError as exc:
            message = 'Settings changed in another window or ChatGPT. Reload the selection before saving.' if exc.code == "REVISION_CONFLICT" else exc.message
            return self.page('Selection not saved', '<p>'+escape(message)+'</p><a class="back-link" href="'+self.base+'/owner/triggers/'+escape(ref, quote=True)+'">Back to events</a>',
                             status=409 if exc.code == "REVISION_CONFLICT" else 400, session=session)

    async def action(self, request):
        session = self.session(request)
        try:
            form = await request.form(max_fields=20)
            self.csrf(request, form, session)
            action = request.path_params["action"]
            if action == "connect":
                return RedirectResponse(self.service.fleet.oauth.begin(session["id"]), status_code=303)
            if action == "refresh":
                await asyncio.to_thread(self.service.read, "account_region", {}, None, self.settings.allowed_scopes)
                await asyncio.to_thread(self.service.list_vehicles, refresh=True)
            elif action == "disconnect":
                self.store.disconnect()
            elif action == "logout":
                with self.store.db() as db:
                    db.execute("DELETE FROM sessions WHERE id=?", (session["id"],))
            else:
                raise TeslaError("INVALID_ARGUMENT", "Unknown owner action")
            return RedirectResponse(self.base+"/owner", status_code=303)
        except TeslaError as exc:
            return self.page('Operation incomplete', f'<p>{escape(exc.message)}</p>', status=400)

    async def callback(self, request):
        session = self.session(request)
        if not session:
            return self.page('Sign-in required', '<p>Repeat the connection from the owner panel.</p>', status=401)
        try:
            await asyncio.to_thread(self.service.fleet.oauth.complete, request.query_params.get("state"), request.query_params.get("code"), session["id"])
            return RedirectResponse(self.base+"/owner", status_code=303)
        except TeslaError as exc:
            return self.page('Connection incomplete', f'<p>{escape(exc.message)}</p>', status=400)

    async def intent(self, request):
        session = self.session(request)
        if not session:
            return RedirectResponse(self.base+"/owner/login", status_code=303)
        try:
            identifier = request.path_params["identifier"]
            item = self.service.intent_view(identifier)
            if request.method == "POST":
                form = await request.form(max_fields=20)
                self.csrf(request, form, session)
                if form.get("decision") == "cancel":
                    with self.store.db() as db:
                        db.execute("UPDATE intents SET status='cancelled' WHERE id=? AND status='prepared'", (identifier,))
                elif form.get("decision") == "execute":
                    item = await asyncio.to_thread(self.service.execute_from_owner, identifier, {key: form.get(key, "") for key in item["secure_owner_fields"]})
                else:
                    raise TeslaError("INVALID_ARGUMENT", "Select an explicit decision")
                return RedirectResponse(self.base+"/owner/intents/"+identifier, status_code=303)
            with self.store.db() as db:
                vehicle = db.execute("SELECT name FROM vehicles WHERE ref=?", (item["vehicle"],)).fetchone()
            display_status = "expired" if item["status"] == "prepared" and item["expires"] <= self.store.clock() else item["status"]
            if display_status == "prepared" and item.get("preflight"):
                display_status = "blocked"
            if display_status in ('prepared', 'blocked') and item.get('review_complete') is False:
                display_status = 'incomplete'
            is_collection = item["operation"] in (CREATE, DELETE)
            back = self.base+"/owner/collection/"+item["vehicle"] if is_collection else self.base+"/owner#attivita"
            back_label = 'Back to data collection' if is_collection else 'Back to activity'
            body = f'<a class="back-link" href="{back}">← {back_label}</a><section class="confirmation-panel"><div class="confirmation-vehicle">{icon("car")}<span>Vehicle: {escape(vehicle[0] if vehicle else "personal account")}</span></div><p class="intent-status status-{escape(display_status, quote=True)}">Status: {escape(STATUS.get(display_status, display_status))}</p>'
            temporary = Collection(self.service).review(item['vehicle'], identifier).get('temporary_collection') if is_collection else None
            body += collection_review(item, self.store, self.settings, temporary=temporary) if is_collection else parameters(item["arguments"])
            if not is_collection:
                body += command_evidence(item, self.settings.timezone)
            if item.get("notice"):
                body += '<p class="confirmation-note">'+icon("shield")+'<span>'+escape(item["notice"])+'</span></p>'
            for requirement in item.get("requirements", []):
                body += '<p class="confirmation-note">'+icon("shield")+'<span>'+escape(requirement["label"])+'</span></p>'
            if item.get("preflight"):
                condition = item["preflight"]["precondition"]
                body += '<div role="status"><p><strong>'+escape(condition["message"])+"</strong></p><p>"+escape(condition["next_step"])+"</p></div>"
                body += '<details class="result-details"><summary>Data that prevented submission</summary><ul>'
                for observation in condition["observations"]:
                    age = observation["age_seconds"]
                    label = ('Tesla read' if observation["source"] == "tesla_live" else 'Gear telemetry')+": "
                    label += observation["value"] or 'value unavailable'
                    label += ' · quality '+observation["quality"]
                    if age is not None:
                        label += ' · age at check '+str(round(age, 1))+" s"
                    if observation["source_timestamp"] is not None:
                        label += " · "+local_time(observation["source_timestamp"], self.settings.timezone)
                    body += '<li>'+escape(label)+'</li>'
                body += '</ul></details>'
            admission = (item.get("result") or {}).get("admission", {})
            if admission.get("id") == "no_recent_driving_gear":
                body += '<p class="confirmation-note">'+escape(admission["message"])+'</p>'
            if item["status"] == "rejected":
                reason = (item["result"] or {}).get("reason") or (item["result"] or {}).get("message")
                if reason:
                    body += '<p role="status">'+escape(reason)+'</p>'
            if item.get("note"):
                body += '<p role="status">'+escape(item["note"])+'</p>'
            if item["status"] == "prepared" and item["expires"] > self.store.clock():
                fields = '<input type="hidden" name="decision" value="execute">'
                for key in item["secure_owner_fields"]:
                    fields += f'<label>{escape(PARAMETERS.get(key, key.replace("_", " ").capitalize()))}<input name="{escape(key, quote=True)}" type="password" autocomplete="off" required maxlength="512"></label>'
                if item.get('review_complete') is not False:
                    body += '<p class="confirmation-note">'+icon("shield")+'<span>'+('Confirm the temporary window and restoration described above.' if temporary else 'Review the parameters and confirm this single action.')+'</span></p>'
                if item["secure_owner_fields"]:
                    body += '<p class="field-help">PINs and codes are used for this submission and are not saved.</p>'
                body += '<div class="confirmation-actions">'
                label = ('Confirm pause' if item["operation"] == DELETE else 'Confirm collection') if is_collection else 'Confirm and execute'
                if item.get('review_complete') is not False:
                    body += self.form(self.base+"/owner/intents/"+identifier, label, session["csrf"], fields)
                body += self.form(self.base+"/owner/intents/"+identifier, 'Cancel', session["csrf"], '<input type="hidden" name="decision" value="cancel">', kind="secondary")+'</div>'
                body += '<p class="expiry-note">Request valid until '+escape(local_time(item["expires"], self.settings.timezone, date=False))+'.</p>'
            if item["result"]:
                body += '<details class="result-details"><summary>Response details</summary><pre>'+escape(json.dumps(item["result"], ensure_ascii=False, indent=2))+'</pre></details>'
            body += '</section>'
            title = ('Pause data collection' if item["operation"] == DELETE else 'Configure data collection') if is_collection else operation(item["operation"])["description"]
            return self.page(title, body, layout="detail", session=session,
                             subtitle='Review of your request.')
        except TeslaError as exc:
            if exc.details.get("stage") == "preflight" and exc.details.get("intent_id") == request.path_params["identifier"]:
                return RedirectResponse(self.base+"/owner/intents/"+request.path_params["identifier"], status_code=303)
            return self.page('Operation incomplete', f'<p>{escape(exc.message)}</p>', status=400)

    async def invoice(self, request):
        if not self.session(request):
            return RedirectResponse(self.base+"/owner/login", status_code=303)
        identifier = request.path_params["identifier"]
        with self.store.db() as db:
            row = db.execute("SELECT vehicle FROM documents WHERE ref=?", (identifier,)).fetchone()
        if not row:
            return self.page('Document unavailable', '<p>Read charging history again.</p>', status=404)
        try:
            result = await asyncio.to_thread(self.service.read, "charging_invoice", {"id": identifier}, row[0], self.settings.allowed_scopes)
            return Response(result["content"], media_type="application/pdf", headers={"Cache-Control": "no-store", "Content-Disposition": 'attachment; filename="tesla-invoice.pdf"', "X-Content-Type-Options": "nosniff"})
        except TeslaError as exc:
            return self.page('Document unavailable', f'<p>{escape(exc.message)}</p>', status=400)

    def routes(self):
        return [Route(self.base+"/owner", self.home), Route(self.base+"/owner/login", self.login, methods=["GET", "POST"]),
                Route(self.base+"/owner/collection/{vehicle_ref}", self.collection, methods=["GET", "POST"]),
                Route(self.base+"/owner/triggers/{vehicle_ref}", self.triggers, methods=["GET", "POST"]),
                Route(self.base+"/owner/intents/{identifier}", self.intent, methods=["GET", "POST"]),
                Route(self.base+"/owner/invoices/{identifier}", self.invoice),
                Route(urlsplit(self.settings.tesla_redirect_uri).path, self.callback),
                Route(self.base+"/owner/{action}", self.action, methods=["POST"])]
