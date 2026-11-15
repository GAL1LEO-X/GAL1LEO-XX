from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import httpx
import jwt
import pytest

from tesla_plugin.auth import JWTVerifier
from tesla_plugin.config import SCOPES, TESLA_SCOPES, TOKEN_URL
from tesla_plugin.errors import TeslaError
from tesla_plugin.fleet import Fleet
from tesla_plugin.oauth import TeslaOAuth
from conftest import VIN


@pytest.mark.parametrize("overrides", [{"sub": "another-owner"}, {"aud": "https://elsewhere.example"},
                                       {"iss": "https://wrong.example"}, {"azp": "whatsapp-client"},
                                       {"exp": 1}, {"scp": ["tesla:commands"]}])
def test_mcp_identity_cannot_cross_owner_audience_client_or_scope(settings, headers, overrides):
    bearer = headers(**overrides)["Authorization"][7:]
    assert JWTVerifier(settings).verify(bearer) is None


def test_valid_jwt_only_grants_resource_scopes(settings, headers):
    result = JWTVerifier(settings).verify(headers(scopes=("tesla:read", "unrelated:scope"))["Authorization"][7:])
    assert result.subject == "owner-test"
    assert result.scopes == ["tesla:read"]


def test_live_disabled_never_calls_network(store):
    def transport(_):
        pytest.fail("Unexpected network request")
    fleet = Fleet(store, transport=httpx.MockTransport(transport))
    with pytest.raises(TeslaError) as exc:
        fleet.call("account_me")
    assert exc.value.code == "LIVE_DISABLED"
    fleet.close()


def test_region_and_proxy_credentials_remain_on_configured_hosts(store, vehicle_ref):
    store.settings = replace(store.settings, live_enabled=True)
    requests = []
    def transport(request):
        requests.append(request)
        return httpx.Response(200, json={"response": {"result": True}})
    fleet = Fleet(store, transport=httpx.MockTransport(transport))
    vehicle = store.vehicle(vehicle_ref)
    fleet.call("set_charge_limit", {"percent": 80}, vehicle=vehicle)
    fleet.call("navigation_request", {"type": "share_ext_content_raw", "value": {"android.intent.extra.TEXT": "Vienna"}, "locale": "de-AT", "timestamp_ms": "1792915200000"}, vehicle=vehicle)
    assert [r.url.host for r in requests] == ["proxy.example", "fleet-api.prd.eu.vn.cloud.tesla.com"]
    assert all(r.headers["authorization"] == "Bearer synthetic-access" for r in requests)
    assert json.loads(requests[0].content) == {"percent": 80}
    fleet.close()


def test_redirect_is_not_followed(store, vehicle_ref):
    store.settings = replace(store.settings, live_enabled=True)
    requests = []
    def transport(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "https://attacker.invalid/steal"})
    fleet = Fleet(store, transport=httpx.MockTransport(transport))
    with pytest.raises(TeslaError):
        fleet.call("vehicle_vehicle", vehicle=store.vehicle(vehicle_ref))
    assert len(requests) == 1
    fleet.close()


@pytest.mark.parametrize("status,uncertain", [(400, False), (401, False), (403, False), (429, False), (500, True), (503, True)])
def test_command_http_outcomes_are_not_retried(store, vehicle_ref, status, uncertain):
    store.settings = replace(store.settings, live_enabled=True)
    count = []
    def transport(request):
        count.append(1)
        return httpx.Response(status, text="secret-provider-body-do-not-echo")
    fleet = Fleet(store, transport=httpx.MockTransport(transport))
    with pytest.raises(TeslaError) as exc:
        fleet.call("charge_start", vehicle=store.vehicle(vehicle_ref))
    assert exc.value.uncertain == uncertain
    assert "secret-provider-body" not in json.dumps(exc.value.public())
    assert len(count) == 1
    fleet.close()


@pytest.mark.parametrize("error,expected", [
    ("SelfDrivingMilesSinceReset requires minimum_delta >= 1; token=private-value", "at least 1 mile"),
    ("Unknown field SelfDrivingMilesSinceReset", "did not recognize"),
    ("interval_seconds must be positive; VIN=TEST0000000000001", "parameter: interval_seconds"),
    ("private-value TEST0000000000001", "rejected or could not complete"),
])
def test_telemetry_errors_explain_known_failures_without_exposing_provider_text(store, vehicle_ref, error, expected):
    store.settings = replace(store.settings, live_enabled=True)
    calls = []
    def transport(request):
        calls.append(request)
        return httpx.Response(400, json={"error": error, "access_token": "private-value", "vin": VIN})
    fleet = Fleet(store, transport=httpx.MockTransport(transport))
    with pytest.raises(TeslaError) as exc:
        fleet.call("vehicle_fleet_telemetry_config_create",
                   {"config": {"fields": {"SelfDrivingMilesSinceReset": {"interval_seconds": 60}}}},
                   vehicle=store.vehicle(vehicle_ref))
    public = json.dumps(exc.value.public())
    assert expected in public
    assert "private-value" not in public and VIN not in public
    assert exc.value.http_status == 400 and not exc.value.uncertain
    assert len(calls) == 1
    fleet.close()


def test_refresh_rotation_serializes_concurrent_readers_and_encrypts(store, clock):
    store.settings = replace(store.settings, live_enabled=True)
    clock.advance(3600)
    calls = []
    def transport(request):
        calls.append(request)
        return httpx.Response(200, json={"access_token": "new-private-access", "refresh_token": "new-private-refresh", "expires_in": 3600})
    fleet = Fleet(store, transport=httpx.MockTransport(transport))
    with ThreadPoolExecutor(max_workers=4) as pool:
        tokens = list(pool.map(lambda _: fleet.oauth.access_token(), range(4)))
    assert tokens == ["new-private-access"]*4
    assert len(calls) == 1
    assert str(calls[0].url) == TOKEN_URL
    with store.db() as db:
        value = bytes(db.execute("SELECT tokens FROM connection").fetchone()[0])
    assert b"new-private-refresh" not in value
    assert store.unseal(value)["refresh_token"] == "new-private-refresh"
    fleet.close()


def test_failed_refresh_blocks_repeated_rotation(store, clock):
    store.settings = replace(store.settings, live_enabled=True)
    clock.advance(3600)
    calls = []
    def transport(request):
        calls.append(request)
        raise httpx.ReadTimeout("synthetic timeout")
    fleet = Fleet(store, transport=httpx.MockTransport(transport))
    for _ in range(2):
        with pytest.raises(TeslaError):
            fleet.oauth.access_token()
    assert len(calls) == 1
    fleet.close()


def test_oauth_state_is_session_bound_single_use_and_short_lived(store, clock):
    from urllib.parse import urlsplit, parse_qs
    store.settings = replace(store.settings, live_enabled=True)
    calls = []
    def transport(request):
        calls.append(request)
        return httpx.Response(200, json={"access_token": "new", "refresh_token": "refresh", "expires_in": 3600, "scope": " ".join(TESLA_SCOPES)})
    with httpx.Client(transport=httpx.MockTransport(transport)) as client:
        oauth = TeslaOAuth(store, client)
        state = parse_qs(urlsplit(oauth.begin("session-one")).query)["state"][0]
        with pytest.raises(TeslaError):
            oauth.complete(state, "code", "session-two")
        assert not calls
        assert oauth.complete(state, "code", "session-one")["status"] == "connected"
        sent = parse_qs(calls[0].content.decode())
        assert sent["audience"] == ["https://fleet-api.prd.eu.vn.cloud.tesla.com"]
        assert len(sent["code_verifier"][0]) >= 43
        with pytest.raises(TeslaError):
            oauth.complete(state, "code", "session-one")
        assert len(calls) == 1
        state = parse_qs(urlsplit(oauth.begin("session-one")).query)["state"][0]
        clock.advance(301)
        with pytest.raises(TeslaError):
            oauth.complete(state, "code", "session-one")
        assert len(calls) == 1


def test_oauth_accepts_tesla_scp_without_scope_and_keeps_only_granted_permissions(store, signing_key):
    from urllib.parse import urlsplit, parse_qs
    store.settings = replace(store.settings, live_enabled=True)
    granted = ["openid", "offline_access", "vehicle_device_data"]
    access = jwt.encode({"scp": granted}, signing_key, algorithm="RS256")
    response = {"access_token": access, "refresh_token": "synthetic-refresh", "expires_in": 3600}
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response))) as client:
        oauth = TeslaOAuth(store, client)
        state = parse_qs(urlsplit(oauth.begin("owner-session")).query)["state"][0]
        assert oauth.complete(state, "synthetic-code", "owner-session")["status"] == "connected"
    assert json.loads(store.connection()["scopes"]) == sorted(granted)
    assert "vehicle_cmds" not in json.loads(store.connection()["scopes"])


def test_refresh_reduced_scp_blocks_command_before_any_vehicle_request(store, clock, signing_key, vehicle_ref):
    store.settings = replace(store.settings, live_enabled=True)
    vehicle = store.vehicle(vehicle_ref)
    clock.advance(3600)
    granted = ["openid", "offline_access", "vehicle_device_data"]
    access = jwt.encode({"scp": granted}, signing_key, algorithm="RS256")
    calls = []
    def transport(request):
        calls.append(request)
        assert str(request.url) == TOKEN_URL, "A removed grant must block the vehicle request"
        return httpx.Response(200, json={"access_token": access, "refresh_token": "rotated-refresh", "expires_in": 3600})
    fleet = Fleet(store, transport=httpx.MockTransport(transport))
    try:
        with pytest.raises(TeslaError) as exc:
            fleet.call("charge_start", vehicle=vehicle)
        assert exc.value.code == "TESLA_SCOPE_REQUIRED"
        assert len(calls) == 1
        assert json.loads(store.connection()["scopes"]) == sorted(granted)
        assert store.unseal(store.connection()["tokens"])["refresh_token"] == "rotated-refresh"
        with store.db() as db:
            assert db.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0
    finally:
        fleet.close()


@pytest.mark.parametrize("claims", [{}, {"scp": None}, {"scp": "vehicle_cmds"},
                                    {"scp": [7]}, {"scp": ["vehicle_cmds vehicle_device_data"]}])
def test_initial_grant_without_valid_scope_evidence_preserves_connection(store, signing_key, claims):
    from urllib.parse import urlsplit, parse_qs
    store.settings = replace(store.settings, live_enabled=True)
    before = store.connection()
    access = jwt.encode(claims, signing_key, algorithm="RS256")
    response = {"access_token": access, "refresh_token": "synthetic-refresh", "expires_in": 3600}
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response))) as client:
        oauth = TeslaOAuth(store, client)
        state = parse_qs(urlsplit(oauth.begin("owner-session")).query)["state"][0]
        with pytest.raises(TeslaError) as exc:
            oauth.complete(state, "synthetic-code", "owner-session")
    assert exc.value.code == "AUTH_RESPONSE_INVALID"
    assert access not in json.dumps(exc.value.public())
    assert store.connection() == before


@pytest.mark.parametrize("granted,response_scope,expected", [
    (["vehicle_device_data"], "vehicle_device_data vehicle_cmds", ["vehicle_device_data"]),
    (["vehicle_device_data", "vehicle_cmds"], "vehicle_device_data", ["vehicle_device_data"]),
    ([], "vehicle_cmds", []),
])
def test_optional_response_scope_cannot_expand_jwt_grants(store, signing_key, granted, response_scope, expected):
    from urllib.parse import urlsplit, parse_qs
    store.settings = replace(store.settings, live_enabled=True)
    response = {"access_token": jwt.encode({"scp": granted}, signing_key, algorithm="RS256"),
                "refresh_token": "synthetic-refresh", "expires_in": 3600, "scope": response_scope}
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response))) as client:
        oauth = TeslaOAuth(store, client)
        state = parse_qs(urlsplit(oauth.begin("owner-session")).query)["state"][0]
        oauth.complete(state, "synthetic-code", "owner-session")
    assert json.loads(store.connection()["scopes"]) == expected


def test_refresh_with_missing_jwt_grants_blocks_retries_and_preserves_old_encrypted_tokens(store, clock, signing_key):
    store.settings = replace(store.settings, live_enabled=True)
    before = store.connection()
    clock.advance(3600)
    calls = []
    def transport(request):
        calls.append(request)
        return httpx.Response(200, json={"access_token": jwt.encode({}, signing_key, algorithm="RS256"),
                                       "refresh_token": "synthetic-refresh", "expires_in": 3600})
    fleet = Fleet(store, transport=httpx.MockTransport(transport))
    try:
        for _ in range(2):
            with pytest.raises(TeslaError):
                fleet.oauth.access_token()
        assert len(calls) == 1
        with store.db() as db:
            row = db.execute("SELECT * FROM connection").fetchone()
        assert row["status"] == "reauth_required"
        assert row["tokens"] == before["tokens"]
    finally:
        fleet.close()
