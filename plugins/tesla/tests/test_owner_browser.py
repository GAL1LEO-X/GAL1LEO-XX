"""Real browser forms against a temporary loopback HTTPS synthetic server."""
import json
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
import subprocess
import threading
import time

import pytest
import httpx
import uvicorn
from starlette.responses import HTMLResponse
from starlette.routing import Route
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from tesla_plugin.config import SCOPES
from tesla_plugin.server import create_app
from tesla_plugin.service import Service
from tesla_plugin.fleet import Fleet
from tesla_plugin.store import Store
from tesla_plugin.telemetry import Telemetry
from test_telemetry_events import payload

pytestmark = pytest.mark.integration


def test_browser_owner_login_confirmation_cancellation_and_logout(settings, fleet, store, clock, vehicle_ref, signing_key, tmp_path):
    settings = replace(settings, public_url="https://tesla.localhost/tesla/mcp",
                       tesla_redirect_uri="https://tesla.localhost/tesla/oauth/callback")
    service = Service(settings, store=store, fleet=fleet)
    with store.db() as db:
        vehicle = json.loads(db.execute("SELECT data FROM vehicles WHERE ref=?", (vehicle_ref,)).fetchone()[0])
    store.save_vehicles([vehicle | {"display_name": "the vehicle"}])
    telemetry = Telemetry(store)
    telemetry.ingest("V", payload(clock, {"Gear": "ShiftStateP"}, when=clock()-16))
    telemetry.ingest("V", payload(clock, {"Gear": None}))
    for index in range(12):
        telemetry.ingest("V", payload(clock, {"BatteryLevel": 55+index, "InsideTemp": 21.5,
            "OutsideTemp": 13.2, "Locked": True, "Version": "2026.38.3.1",
            "DetailedChargeState": "DetailedChargeStateCharging"}, when=clock()-3300+index*300))
    execute = service.prepare("set_charge_limit", {"percent": 80}, vehicle_ref, "browser-synthetic-execute-01", SCOPES)
    cancel = service.prepare("set_charge_limit", {"percent": 90}, vehicle_ref, "browser-synthetic-cancel-01", SCOPES)
    result = run_browser(settings, service, signing_key, tmp_path, "owner-browser.js", {
        "execute": execute["id"], "cancel": cancel["id"], "results": os.environ.get("PLUGINS_TEST_RESULTS_DIR")})
    assert result["external_requests"] == 0
    assert sum(name == "set_charge_limit" for name, _, _ in fleet.calls) == 1
    assert service.intent_view(execute["id"])["status"] == "acknowledged"
    assert service.intent_view(cancel["id"])["status"] == "cancelled"
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


def test_browser_owner_oauth_redirect_allows_tesla_and_blocks_other_origins(settings, signing_key, tmp_path, monkeypatch):
    # A distinct loopback origin exercises the same CSP redirect check without
    # depending on external DNS/proxies or contacting Tesla.
    authorize_url = "https://auth.tesla.localhost/oauth2/v3/authorize"
    monkeypatch.setattr("tesla_plugin.oauth.AUTHORIZE_URL", authorize_url)
    monkeypatch.setattr("tesla_plugin.portal.AUTHORIZE_URL", authorize_url)
    settings = replace(settings, public_url="https://tesla.localhost/tesla/mcp", live_enabled=True,
                       tesla_redirect_uri="https://tesla.localhost/tesla/oauth/callback")
    store = Store(settings)
    def no_network(request):
        pytest.fail("Unexpected backend network request during synthetic OAuth navigation")
    fleet = Fleet(store, transport=httpx.MockTransport(no_network))
    authorizations = []
    try:
        service = Service(settings, store=store, fleet=fleet)
        result = run_browser(settings, service, signing_key, tmp_path, "owner-oauth-browser.js", {},
                             authorizations=authorizations)
        assert result == {"synthetic_oauth_pages": 1, "external_requests": 0, "unrelated_form_blocked": True}
        assert len(authorizations) == 1
        host, method, query = authorizations[0]
        assert (host, method) == ("auth.tesla.localhost", "GET")
        assert query["client_id"] == "synthetic-app"
        assert query["redirect_uri"] == "https://tesla.localhost/tesla/oauth/callback"
        assert query["code_challenge_method"] == "S256" and query["state"]
        assert "client_secret" not in query
        with store.db() as db:
            assert db.execute("SELECT count(*) FROM oauth_states").fetchone()[0] == 1
            assert db.execute("SELECT count(*) FROM connection").fetchone()[0] == 0
            assert db.execute("SELECT count(*) FROM requests").fetchone()[0] == 0
    finally:
        fleet.close()


def run_browser(settings, service, signing_key, tmp_path, script, options, *, authorizations=None):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tesla.localhost")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(signing_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
        .not_valid_after(now+timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName("tesla.localhost")]), critical=False)
        .sign(signing_key, hashes.SHA256()))
    keyfile, certfile = tmp_path/"local.key", tmp_path/"local.pem"
    keyfile.write_bytes(signing_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    keyfile.chmod(0o600)
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    app = create_app(settings, service=service, start_worker=False)
    if authorizations is not None:
        async def authorize(request):
            authorizations.append((request.url.hostname, request.method, dict(request.query_params)))
            return HTMLResponse('<h1>Autorizzazione Tesla simulata</h1>')
        app.router.routes.insert(0, Route('/oauth2/v3/authorize', authorize))
    server = uvicorn.Server(uvicorn.Config(app,
        ssl_keyfile=str(keyfile), ssl_certfile=str(certfile), access_log=False, log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic()+5
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started, "Synthetic server did not start"
        config = {"port": listener.getsockname()[1], "origin": "https://tesla.localhost", **options}
        result = subprocess.run(["node", str(Path(__file__).with_name(script)), json.dumps(config)],
                                capture_output=True, text=True, timeout=45)
        assert result.returncode == 0, result.stdout+result.stderr
        return json.loads(result.stdout)
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        assert not thread.is_alive(), "Synthetic server did not stop"


def test_browser_collection_calculator_preview_and_cancel(settings, fleet, store, signing_key, tmp_path):
    from test_profiles_storage_packages import certificate
    settings = replace(settings, public_url="https://tesla.localhost/tesla/mcp",
                       tesla_redirect_uri="https://tesla.localhost/tesla/oauth/callback",
                       telemetry_host="telemetry.example", telemetry_ca_file=certificate(tmp_path/"ca.crt"))
    service = Service(settings, store=store, fleet=fleet)
    result = run_browser(settings, service, signing_key, tmp_path, "collection-browser.js", {
        "results": os.environ.get("PLUGINS_TEST_RESULTS_DIR")})
    assert result == {"calculator": True, "owner_review": True, "external_requests": 0}
    assert not any(name in ("vehicle_fleet_telemetry_config_create", "vehicle_fleet_telemetry_config_delete", "vehicle_wake_up") for name, *_ in fleet.calls)
    with store.db() as db:
        rows = db.execute("SELECT status FROM intents").fetchall()
        assert len(rows) == 1 and rows[0][0] == "cancelled"


def test_browser_trigger_repair_preserves_choices_and_only_builds_local_draft(settings, fleet, store, vehicle_ref, signing_key, tmp_path):
    from test_trigger_dependencies import observed
    from tesla_plugin.triggers import Triggers
    settings = replace(settings, public_url="https://tesla.localhost/tesla/mcp",
                       tesla_redirect_uri="https://tesla.localhost/tesla/oauth/callback")
    service = Service(settings, store=store, fleet=fleet)
    observed(store, vehicle_ref, {"InsideTemp": {"interval_seconds": 600, "resend_interval_seconds": 1200}})
    result = run_browser(settings, service, signing_key, tmp_path, "trigger-repair-browser.js", {
        "vehicle_ref": vehicle_ref, "results": os.environ.get("PLUGINS_TEST_RESULTS_DIR")})
    assert result == {"repair_draft": True, "selection_preserved": True, "external_requests": 0}
    view = Triggers(store).view(vehicle_ref, SCOPES)
    assert view["selection_preset"] == "recommended" and view["revision"] == 2
    assert fleet.calls == []
    with store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM intents").fetchone()[0] == 0


def test_browser_workspace_with_all_events_and_applied_collection(settings, fleet, store, clock, vehicle_ref, signing_key, tmp_path):
    from test_trigger_dependencies import observed
    from tesla_plugin.profiles import profile_fields
    from tesla_plugin.triggers import Triggers
    settings = replace(settings, public_url="https://tesla.localhost/tesla/mcp",
                       tesla_redirect_uri="https://tesla.localhost/tesla/oauth/callback")
    service = Service(settings, store=store, fleet=fleet)
    config = observed(store, vehicle_ref, profile_fields("recommended"), alerts=True)
    store.snapshot(vehicle_ref, "telemetry_saved", config, "owner_request", clock())
    store.snapshot(vehicle_ref, "telemetry_target", config, "owner_request", clock())
    triggers = Triggers(store)
    triggers.apply_preset(vehicle_ref, "all", SCOPES, expected_revision=triggers.view(vehicle_ref, SCOPES)["revision"])
    with store.db() as db:
        vehicle = json.loads(db.execute("SELECT data FROM vehicles WHERE ref=?", (vehicle_ref,)).fetchone()[0])
    store.save_vehicles([vehicle | {"display_name": "the vehicle"}])
    Telemetry(store).ingest("V", payload(clock, {"BatteryLevel": 66, "Locked": True,
        "InsideTemp": 21.5, "OutsideTemp": 13.2, "Version": "2026.38.3.1",
        "DetailedChargeState": "DetailedChargeStateDisconnected"}))
    from tesla_plugin.events import Events
    for index in range(30):
        item = service.prepare("set_charge_limit", {"percent": 80}, vehicle_ref,
                               "compact-synthetic-action-"+str(index), SCOPES)
        with store.db() as db:
            db.execute("UPDATE intents SET status='cancelled' WHERE id=?", (item["id"],))
            Events.emit(db, vehicle_ref, "battery_low", clock()-index, {"synthetic": index}, clock())
    before = triggers.view(vehicle_ref, SCOPES)
    result = run_browser(settings, service, signing_key, tmp_path, "workspace-browser.js", {
        "results": os.environ.get("PLUGINS_TEST_RESULTS_DIR")})
    assert result == {"external_requests": 0, "settings_unchanged": True}
    after = triggers.view(vehicle_ref, SCOPES)
    assert after["revision"] == before["revision"]
    assert [i["enabled"] for i in after["items"]] == [i["enabled"] for i in before["items"]]
    assert fleet.calls == []
    with store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM intents").fetchone()[0] == 30
