from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tesla_plugin.config import SCOPES, Settings
from tesla_plugin.errors import TeslaError
from tesla_plugin.cli import initialize, process_batch
from tesla_plugin.profiles import profile_fields, estimate
from tesla_plugin.telemetry import Telemetry
from tesla_plugin.store import canonical
from tesla_plugin.service import Service
from tesla_plugin.fleet import Fleet
from test_telemetry_events import payload

ROOT = Path(__file__).resolve().parents[1]


def certificate(path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic telemetry CA")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def test_profile_preparation_enforces_receiver_and_does_not_activate(settings, service, store, fleet, vehicle_ref, tmp_path):
    with pytest.raises(TeslaError, match="Configure"):
        service.prepare_profile(vehicle_ref, "essential", None, "profile-request-01", SCOPES)
    configured = replace(settings, telemetry_host="telemetry.example", telemetry_ca_file=certificate(tmp_path/"ca.crt"))
    svc = Service(configured, store=store, fleet=fleet)
    prepared = svc.prepare_profile(vehicle_ref, "notifications", None, "profile-request-02", SCOPES, customer_alerts=True)
    assert prepared["status"] == "prepared"
    assert prepared["arguments"]["config"]["alert_types"] == ["customer"]
    assert "prefer_typed" not in prepared["arguments"]["config"]
    assert not any(c[0] == "vehicle_fleet_telemetry_config_create" for c in fleet.calls)
    result = svc.execute_from_owner(prepared["id"])
    assert result["result"] == {"accepted": True, "synced": False, "dispatch_attempted": True, "confirmation_source": "owner_panel"}


@pytest.mark.parametrize("custom", [
    {"BatteryLevel": {"interval_seconds": True}}, {"BatteryLevel": {"interval_seconds": 0}},
    {"Locked": {"interval_seconds": 10, "minimum_delta": 1}},
    {"BatteryLevel": {"interval_seconds": 10, "resend_interval_seconds": 5}},
    {"BatteryLevel": {"interval_seconds": 10, "include_fields": ["unknown"]}},
    {"NotPublished": {"interval_seconds": 10}},
])
def test_custom_profile_invalid_or_unqualified_options_rejected(custom):
    with pytest.raises(TeslaError):
        profile_fields("custom", custom)


@pytest.mark.parametrize("delta", [None, 0])
def test_self_driving_field_rejected_before_any_provider_request(service, fleet, vehicle_ref, delta):
    options = {"interval_seconds": 60, "resend_interval_seconds": 3600}
    if delta is not None:
        options["minimum_delta"] = delta
    with pytest.raises(TeslaError, match="explicit minimum_delta"):
        service.prepare_profile(vehicle_ref, "custom", {"SelfDrivingMilesSinceReset": options},
                                "invalid-driving-profile", SCOPES)
    assert fleet.calls == []


def test_self_driving_delta_is_in_both_profile_and_operation_schema():
    from tesla_plugin.catalogue import validate
    fields = {"SelfDrivingMilesSinceReset": {"interval_seconds": 60, "minimum_delta": 1}}
    assert profile_fields("custom", fields) == fields
    arguments = {"config": {"hostname": "telemetry.example", "port": 8443, "ca": "synthetic", "fields": fields}}
    validate("vehicle_fleet_telemetry_config_create", arguments)
    del fields["SelfDrivingMilesSinceReset"]["minimum_delta"]
    with pytest.raises(TeslaError):
        validate("vehicle_fleet_telemetry_config_create", arguments)


def test_signal_estimate_is_explicit_and_not_a_billing_cap():
    result = estimate({"BatteryLevel": {"interval_seconds": 60, "resend_interval_seconds": 600}}, 8)
    assert result["planned_signals_30_days"] == 30*(1+480+48)
    assert result["billing_cap"] is False


def test_request_budget_rate_limit_and_reset_are_durable(store, clock):
    for _ in range(3):
        store.reserve_request("wake")
    with pytest.raises(TeslaError, match="rate limit"):
        store.reserve_request("wake")
    clock.advance(61)
    store.reserve_request("wake")
    with store.db() as db:
        db.execute("INSERT INTO requests VALUES(?,?,?)", (clock(), "data", 10_000_000))
    with pytest.raises(TeslaError, match="budget"):
        store.reserve_request("data")


def test_disconnect_purges_data_and_pending_work(store, service, vehicle_ref, clock):
    Telemetry(store).ingest("V", payload(clock, {"BatteryLevel": 55}))
    service.prepare("set_charge_limit", {"percent": 80}, vehicle_ref, "disconnect-request-01", SCOPES)
    store.disconnect()
    with store.db() as db:
        for table in ("connection", "vehicles", "intents", "latest", "samples", "subscriptions", "deliveries", "rules", "documents"):
            assert db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_vehicle_removal_invalidates_old_data_and_intents(store, service, vehicle_ref, clock):
    Telemetry(store).ingest("V", payload(clock, {"BatteryLevel": 55}))
    intent = service.prepare("set_charge_limit", {"percent": 80}, vehicle_ref, "membership-request-1", SCOPES)
    store.save_vehicles([])
    assert store.intent(intent["id"])["status"] == "cancelled"
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM samples").fetchone()[0] == 0
    with pytest.raises(TeslaError):
        store.vehicle(vehicle_ref)


def test_null_rest_park_can_use_recent_explicit_gear(service, fleet, store, clock, vehicle_ref):
    fleet.park = None
    Telemetry(store).ingest("V", payload(clock, {"Gear": "ShiftStateP"}))
    intent = service.prepare("window_control", {"command": "vent"}, vehicle_ref, "explicit-gear-request", SCOPES)
    assert service.execute_from_owner(intent["id"])["status"] == "acknowledged"


@pytest.mark.parametrize("operation,arguments,intercept", [
    ("door_unlock", {}, "vehicle_fleet_status"),
    ("remote_start_drive", {}, "vehicle_vehicle_data"),
    ("window_control", {"command": "vent"}, "vehicle_vehicle_data")])
def test_authorization_change_during_preflight_prevents_dispatch(service, fleet, store, vehicle_ref, operation, arguments, intercept):
    intent = service.prepare(operation, arguments, vehicle_ref, "auth-race-request-01", SCOPES)
    original = fleet.call
    def call(name, *args, **kwargs):
        result = original(name, *args, **kwargs)
        if name == intercept:
            store.disconnect()
        return result
    fleet.call = call
    with pytest.raises(TeslaError, match="Authorization changed"):
        service.execute_from_owner(intent["id"])
    assert not any(c[0] == operation for c in fleet.calls)


def test_local_initialization_is_private_and_never_overwrites(tmp_path):
    initialize(tmp_path, "synthetic-long-owner-passphrase")
    assert (tmp_path/"encryption.key").stat().st_mode & 0o777 == 0o600
    assert b"synthetic-long" not in (tmp_path/"owner.hash").read_bytes()
    public = serialization.load_pem_public_key((tmp_path/"vehicle-public.pem").read_bytes())
    assert public.curve.name == "secp256r1"
    old = (tmp_path/"encryption.key").read_bytes()
    with pytest.raises(ValueError):
        initialize(tmp_path, "another-synthetic-passphrase")
    assert (tmp_path/"encryption.key").read_bytes() == old


def test_kafka_offset_commit_occurs_after_sqlite_commit(store, clock):
    records = [SimpleNamespace(topic="tesla_V", partition=0, offset=5, key=b"TEST0000000000001",
                headers=[("vin", b"TEST0000000000001"), ("txtype", b"V")], value=canonical(payload(clock, {"BatteryLevel": 55})).encode())]
    class Consumer:
        def commit(self, offsets):
            with store.db() as db:
                assert db.execute("SELECT count(*) FROM samples").fetchone()[0] == 1
            assert list(offsets.values())[0].offset == 6
    assert process_batch(Consumer(), Telemetry(store), records) == 1


def test_bad_frame_has_durable_digest_without_payload_before_offset_commit(store):
    record = SimpleNamespace(topic="tesla_V", partition=0, offset=1, key=b"invalid", headers=[], value=b"not-json-sensitive-text")
    class Consumer:
        def commit(self, offsets):
            with store.db() as db:
                rows = db.execute("SELECT * FROM ingestion_errors").fetchall()
            assert len(rows) == 1 and "sensitive" not in str(dict(rows[0]))
    process_batch(Consumer(), Telemetry(store), [record])


def builder():
    spec = importlib.util.spec_from_file_location("tesla_build", ROOT/"build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_source_archive_contains_working_cli_and_reproduces_bytes(tmp_path):
    build = builder()
    one, two = tmp_path/"one.zip", tmp_path/"two.zip"
    assert build.source(ROOT, one) == build.source(ROOT, two)
    with zipfile.ZipFile(one) as archive:
        names = archive.namelist()
        assert "src/tesla_plugin/cli.py" in names and "plugin/plugin.json" in names
        assert archive.read("src/tesla_plugin/assets/model-y-legacy.png").startswith(b"\x89PNG\r\n\x1a\n")
        assert not any(".egg-info" in n or "__pycache__" in n or n.endswith(".pem") for n in names)
    with pytest.raises(ValueError):
        build.source(ROOT, one)


def test_source_archive_rejects_symlink(tmp_path):
    build = builder()
    (tmp_path/"src/tesla_plugin").mkdir(parents=True)
    (tmp_path/"src/tesla_plugin/secret.py").symlink_to(ROOT/"build.py")
    with pytest.raises(ValueError, match="Symlinks"):
        build.source_inputs(tmp_path)


def test_private_package_verifies_real_endpoint_before_writing(tmp_path, monkeypatch):
    build = builder()
    token = tmp_path/"token"
    token.write_text("synthetic-mcp-token")
    token.chmod(0o600)
    def unavailable(*args):
        raise ValueError("Remote verification was not successful")
    monkeypatch.setattr(build, "verify_endpoint", unavailable)
    with pytest.raises(ValueError):
        build.plugin(ROOT, tmp_path/"plugin.zip", "https://bridge.example/tesla/mcp", "https://issuer.example", "test-client", token)
    assert not (tmp_path/"plugin.zip").exists()
    monkeypatch.setattr(build, "verify_endpoint", lambda *args: {"synthetic_test": True})
    build.plugin(ROOT, tmp_path/"plugin.zip", "https://bridge.example/tesla/mcp", "https://issuer.example", "test-client", token)
    with zipfile.ZipFile(tmp_path/"plugin.zip") as archive:
        assert "mcp.json" in archive.namelist()
        assert all(b"synthetic-mcp-token" not in archive.read(n) for n in archive.namelist())
        config = json.loads(archive.read("mcp.json"))
        assert config["mcpServers"]["tesla-personal"]["extensions"]["com.openai"]["auth"]["client"]["clientId"] == "test-client"
        auth = config["mcpServers"]["tesla-personal"]["extensions"]["com.openai"]["auth"]
        assert {"openid", "offline_access", "tesla:read"} <= set(auth["baseScopes"])
        assert set(auth["baseScopes"]) <= set(auth["defaultScopes"])


def test_verification_rejects_malformed_token_without_echo():
    invalid = "synthetic-sensitive-header\r\ninjected"
    with pytest.raises(ValueError) as error:
        builder().verify_endpoint("https://bridge.example/tesla/mcp", "https://issuer.example", invalid)
    assert "synthetic-sensitive" not in str(error.value)


def test_private_package_rejects_symlinked_asset_directory(tmp_path, monkeypatch):
    import shutil
    build = builder()
    root = tmp_path/"source"
    shutil.copytree(ROOT/"plugin", root/"plugin")
    (root/"VERSION").write_text((ROOT/"VERSION").read_text())
    shutil.rmtree(root/"plugin/assets")
    (root/"plugin/assets").symlink_to(ROOT/"plugin/assets", target_is_directory=True)
    token = tmp_path/"token"
    token.write_text("synthetic-token")
    token.chmod(0o600)
    monkeypatch.setattr(build, "verify_endpoint", lambda *args: {})
    with pytest.raises(ValueError, match="Symlinks"):
        build.plugin(root, tmp_path/"plugin.zip", "https://bridge.example/tesla/mcp", "https://issuer.example", "test-client", token)


def test_initial_pilot_connection_verifies_discovery_and_marks_pending_auth(tmp_path, monkeypatch):
    import httpx
    build = builder()
    client_type = httpx.Client
    url, issuer = "https://bridge.example/tesla-test/mcp", "https://issuer.example"
    observed = []
    def respond(request):
        observed.append(request)
        assert "authorization" not in request.headers
        if request.url.path == "/.well-known/oauth-protected-resource/tesla-test/mcp":
            return httpx.Response(200, json={"resource": url, "authorization_servers": [issuer]})
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": issuer, "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"], "authorization_endpoint": issuer+"/authorize",
                "token_endpoint": issuer+"/token", "jwks_uri": issuer+"/jwks"})
        if request.url.path.endswith("/healthz"):
            return httpx.Response(200, json={"process": "running", "live_enabled": False})
        assert request.method == "POST" and str(request.url) == url
        return httpx.Response(401, headers={"WWW-Authenticate": 'Bearer resource_metadata="https://bridge.example/.well-known/oauth-protected-resource/tesla-test/mcp"'})
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: client_type(transport=httpx.MockTransport(respond), **kwargs))
    result = build.plugin(ROOT, tmp_path/"pilot.zip", url, issuer, "tesla-pilot", await_user_auth=True, pilot=True)
    assert result["verification"]["owner_connection_required"]
    assert not result["verification"]["authenticated_discovery_verified"]
    assert len(observed) == 4
    with zipfile.ZipFile(tmp_path/"pilot.zip") as archive:
        manifest = json.loads(archive.read("plugin.json"))
        assert manifest["extensions"]["com.openai"]["interface"]["displayName"] == "TESLA · Test"
        assert b"refresh=false" in archive.read("skills/tesla-personal/SKILL.md")
        assert "tesla-test/mcp" in archive.read("mcp.json").decode()


@pytest.mark.parametrize("broken", ["resource", "issuer", "pkce", "live", "anonymous", "redirect"])
def test_initial_pilot_refuses_unverified_endpoint_without_creating_package(tmp_path, monkeypatch, broken):
    import httpx
    build = builder()
    client_type = httpx.Client
    url, issuer = "https://bridge.example/tesla-test/mcp", "https://issuer.example"
    def respond(request):
        if request.url.path.startswith("/.well-known/oauth-protected-resource"):
            return httpx.Response(200, json={"resource": "https://wrong.example/mcp" if broken == "resource" else url,
                                           "authorization_servers": [issuer]})
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={"issuer": "https://wrong.example" if broken == "issuer" else issuer,
                "code_challenge_methods_supported": [] if broken == "pkce" else ["S256"],
                "token_endpoint_auth_methods_supported": ["none"], "authorization_endpoint": issuer+"/authorize",
                "token_endpoint": issuer+"/token", "jwks_uri": issuer+"/jwks"})
        if request.url.path.endswith("/healthz"):
            return httpx.Response(200, json={"process": "running", "live_enabled": broken == "live"})
        return httpx.Response(200 if broken == "anonymous" else 302,
                              headers={"Location": issuer, "WWW-Authenticate": "Bearer resource_metadata=example"})
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: client_type(transport=httpx.MockTransport(respond), **kwargs))
    with pytest.raises(ValueError):
        build.plugin(ROOT, tmp_path/"pilot.zip", url, issuer, "tesla-pilot", await_user_auth=True, pilot=True)
    assert not (tmp_path/"pilot.zip").exists()


def test_initial_connection_requires_pilot_label_and_cannot_take_a_token(tmp_path):
    for kwargs in ({"await_user_auth": True}, {"await_user_auth": True, "pilot": True, "token_file": tmp_path/"token"}):
        with pytest.raises(ValueError, match="labelled pilot"):
            builder().plugin(ROOT, tmp_path/"pilot.zip", "https://bridge.example/tesla/mcp",
                             "https://issuer.example", "tesla-pilot", **kwargs)
    assert not (tmp_path/"pilot.zip").exists()


def test_authenticated_package_cannot_mislabel_a_live_backend_as_a_pilot(tmp_path, monkeypatch):
    build = builder()
    def unexpected_verification(*args):
        pytest.fail("Invalid pilot mode must be refused before reading a token or verifying tools")
    monkeypatch.setattr(build, "verify_endpoint", unexpected_verification)
    with pytest.raises(ValueError, match="live-disabled"):
        build.plugin(ROOT, tmp_path/"pilot.zip", "https://bridge.example/tesla/mcp",
                     "https://issuer.example", "test-client", tmp_path/"not-read", pilot=True)
    assert not (tmp_path/"pilot.zip").exists()
