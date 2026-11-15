from dataclasses import replace
import json
import time
from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt

from tesla_plugin.config import Settings, SCOPES, TESLA_SCOPES
from tesla_plugin.store import Store
from tesla_plugin.service import Service
from tesla_plugin.portal import password_hash

VIN = "TEST0000000000001"


class Clock:
    def __init__(self):
        self.value = time.time()
    def __call__(self):
        return self.value
    def advance(self, seconds):
        self.value += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def settings(tmp_path, signing_key):
    key = tmp_path / "encryption.key"
    key.write_bytes(Fernet.generate_key())
    key.chmod(0o600)
    pub = tmp_path / "issuer.pem"
    pub.write_bytes(signing_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    password = tmp_path / "owner.hash"
    password.write_text(password_hash("synthetic-owner-passphrase"))
    password.chmod(0o600)
    app_secret = tmp_path / "client.secret"
    app_secret.write_text("synthetic-client-secret-not-a-real-credential")  # gitleaks:allow -- synthetic fixture
    app_secret.chmod(0o600)
    return Settings(database=tmp_path/"state.sqlite3", encryption_key_file=key, owner_subject="owner-test",  # gitleaks:allow -- fixture subject and generated key path
                    public_url="https://bridge.example/tesla/mcp", issuer="https://identity.example",
                    oauth_client_ids=("test-mcp",), public_key_file=pub, owner_password_file=password,
                    tesla_redirect_uri="https://bridge.example/tesla/oauth/callback",
                    tesla_client_id="synthetic-app", tesla_client_secret_file=app_secret,
                    callback_hosts=("receiver.example",), command_proxy_url="https://proxy.example")


@pytest.fixture
def store(settings, clock):
    value = Store(settings, clock=clock)
    value.set_tokens({"access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "expires_in": 3600}, TESLA_SCOPES, "eu")
    value.save_vehicles([{"vin": VIN, "display_name": "Model Y", "state": "online", "access_type": "OWNER", "granular_access": {"hide_private": False}}])
    return value


@pytest.fixture
def vehicle_ref(store):
    with store.db() as db:
        return db.execute("SELECT ref FROM vehicles").fetchone()[0]


class FakeFleet:
    def require_extension(self, op):
        assert op["proxy_extension"] == "gal1leo-vehicle-command/2"

    def __init__(self, store):
        self.store, self.calls = store, []
        self.result, self.error = {"result": True}, None
        self.park = "P"
        self.closed = False
    def discover(self):
        pass
    def close(self):
        self.closed = True
    def authorization(self):
        from tesla_plugin.authorization import Authorization
        return Authorization.from_row(self.store, self.store.connection())
    def call(self, name, arguments=None, *, vehicle=None, binary=False, authorization=None):
        self.calls.append((name, arguments, vehicle["vin"] if vehicle else None))
        if name == "vehicle_fleet_status":
            return {"key_paired_vins": [VIN], "vehicle_info": {VIN: {"vehicle_command_protocol_required": True,
                "firmware_version": "2026.38.3.1", "fleet_telemetry_version": "1.3.0"}}}
        if name == "vehicle_vehicle_data":
            return {"drive_state": {"shift_state": self.park, "timestamp": int(self.store.clock()*1000)},
                    "charge_state": {"battery_level": 55, "timestamp": int(self.store.clock()*1000)}}
        if name == "vehicle_vehicle_data_cached":
            return {"charge_state": {"battery_level": 55, "timestamp": int((self.store.clock()-7200)*1000)}}
        if name == "vehicle_vehicle":
            return {"state": "online"}
        if name == "vehicle_fleet_telemetry_config_create":
            return {"updated_vehicles": 1, "skipped_vehicles": {}}
        if name == "vehicle_fleet_telemetry_config_get":
            return {"synced": True, "config": None, "limit_reached": False}
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def fleet(store):
    return FakeFleet(store)


@pytest.fixture
def service(settings, store, fleet):
    return Service(settings, store=store, fleet=fleet)


@pytest.fixture
def headers(settings, signing_key):
    def build(scopes=SCOPES, **overrides):
        now = int(time.time())
        claims = {"sub": settings.owner_subject, "iss": settings.issuer, "aud": settings.public_url,
                  "azp": "test-mcp", "iat": now, "exp": now+3600, "scope": " ".join(scopes)} | overrides
        token = jwt.encode(claims, signing_key, algorithm="RS256")
        return {"Authorization": "Bearer "+token, "MCP-Protocol-Version": "2026-07-28", "Accept": "application/json, text/event-stream"}
    return build
