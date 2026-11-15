import json
import re
from dataclasses import replace
import pytest
from starlette.testclient import TestClient

from tesla_plugin.server import create_app
from tesla_plugin.config import SCOPES

pytestmark = pytest.mark.integration


def rpc(client, headers, method, params=None):
    params = {**(params or {}), "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}}
    named = {"mcp-name": params["name"]} if "name" in params else {}
    return client.post("/tesla/mcp", headers={**headers, "mcp-method": method, **named}, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


def test_mcp_discovery_auth_and_readonly_initial_connection(settings, service, headers):
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        assert rpc(client, {}, "tools/list").status_code == 401
        discover = rpc(client, headers(), "server/discover")
        assert discover.status_code == 200, discover.text
        assert "events" in discover.json()["result"]["capabilities"]
        tools = rpc(client, headers(), "tools/list").json()["result"]["tools"]
        assert len(tools) == 24
        assert all(t["securitySchemes"][0]["type"] == "oauth2" for t in tools)
        result = rpc(client, headers(), "tools/call", {"name": "tesla_connection_status", "arguments": {}})
        assert result.status_code == 200
        assert result.json()["result"]["structuredContent"]["live_enabled"] is False
        assert "synthetic-access" not in result.text


def test_missing_command_scope_returns_oauth_challenge(settings, service, headers, vehicle_ref):
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        result = rpc(client, headers(scopes=["tesla:read"]), "tools/call", {"name": "tesla_prepare_action", "arguments": {
            "operation": "set_charge_limit", "arguments": {"percent": 80}, "vehicle_ref": vehicle_ref, "client_request_id": "mcp-action-request-01"}}).json()["result"]
        assert result["isError"] is True
        assert "tesla:commands" in str(result["_meta"]["mcp/www_authenticate"])
        challenge = result["_meta"]["mcp/www_authenticate"][0]
        assert 'resource_metadata="https://bridge.example/.well-known/oauth-protected-resource/tesla/mcp"' in challenge
        metadata = client.get("/.well-known/oauth-protected-resource/tesla/mcp").json()
        assert metadata["resource"] == settings.public_url


def test_operation_schema_has_typed_envelope_without_host_breaking_root_union(settings, service, headers, vehicle_ref):
    from jsonschema import validate, ValidationError
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        tools = rpc(client, headers(), "tools/list").json()["result"]["tools"]
        read = next(t for t in tools if t["name"] == "tesla_read")["inputSchema"]
        assert read["type"] == "object" and "oneOf" not in read
        arguments = {"operation": "vehicle_fleet_telemetry_config_get", "arguments": {}, "vehicle_ref": vehicle_ref}
        validate(arguments, read)
        missing = rpc(client, headers(), "tools/call", {"name": "tesla_read", "arguments": {k: v for k, v in arguments.items() if k != "vehicle_ref"}}).json()["result"]
        assert missing["isError"]
        result = rpc(client, headers(), "tools/call", {"name": "tesla_read", "arguments": arguments}).json()["result"]
        assert not result.get("isError")
        action = next(t for t in tools if t["name"] == "tesla_prepare_action")["inputSchema"]
        assert action["type"] == "object" and "oneOf" not in action
        validate({"operation": "set_charge_limit", "arguments": {"percent": 80}, "vehicle_ref": vehicle_ref,
                  "client_request_id": "mcp-envelope-test-01"}, action)
        assert "client_request_id" in action["required"]
        with pytest.raises(ValidationError):
            validate({"operation": "set_temps", "parameters": {}, "client_request_id": "mcp-envelope-test-02"}, action)


def login(client):
    response = client.post("/tesla/owner/login", data={"password": "synthetic-owner-passphrase"}, headers={"origin": "https://bridge.example"})
    assert response.status_code == 200
    return re.search('name="csrf" value="([^"]+)"', response.text).group(1)


def test_owner_confirmation_requires_login_csrf_and_same_origin(settings, service, fleet, vehicle_ref):
    intent = service.prepare("set_charge_limit", {"percent": 80}, vehicle_ref, "owner-action-request-01", SCOPES)
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        path = "/tesla/owner/intents/"+intent["id"]
        denied = client.post(path, data={"decision": "execute", "csrf": "fake"})
        assert 'Sign in' in denied.text
        csrf = login(client)
        assert client.post(path, data={"decision": "execute", "csrf": csrf}, headers={"origin": "https://attacker.invalid"}).status_code == 400
        assert client.post(path, data={"decision": "execute", "csrf": "fake"}, headers={"origin": "https://bridge.example"}).status_code == 400
        assert not any(n == "set_charge_limit" for n, _, _ in fleet.calls)
        result = client.post(path, data={"decision": "execute", "csrf": csrf}, headers={"origin": "https://bridge.example"})
        assert result.status_code == 200
        assert 'Accepted by Tesla' in result.text
        client.post(path, data={"decision": "execute", "csrf": csrf}, headers={"origin": "https://bridge.example"})
        assert sum(n == "set_charge_limit" for n, _, _ in fleet.calls) == 1


def test_owner_pages_escape_vehicle_content_and_do_not_expose_tokens(settings, service, store):
    with store.db() as db:
        db.execute("UPDATE vehicles SET name=?", ('<script>alert("x")</script>',))
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        login(client)
        response = client.get("/tesla/owner")
        assert "<script>" not in response.text
        assert "&lt;script&gt;" in response.text
        assert "synthetic-access" not in response.text
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_anonymous_health_is_separate_from_connected_status(settings, service):
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        result = client.get("/tesla/healthz").json()
        assert result["process"] == "running"
        assert "vehicles" not in result
        assert "connected" not in result


def test_owner_form_body_is_bounded(settings, service):
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        response = client.post("/tesla/owner/login", content=b"password="+b"a"*262144,
                               headers={"origin": "https://bridge.example", "content-type": "application/x-www-form-urlencoded"})
        assert response.status_code == 413


def test_oauth_csp_exception_is_limited_to_live_dashboard(settings, service, vehicle_ref):
    settings = replace(settings, live_enabled=True)
    service.settings = service.store.settings = settings
    intent = service.prepare("set_charge_limit", {"percent": 80}, vehicle_ref, "csp-synthetic-request-01", SCOPES)
    with TestClient(create_app(settings, service=service, start_worker=False), base_url="https://bridge.example") as client:
        password_page = client.get("/tesla/owner/login")
        assert "form-action 'self';" in password_page.headers["content-security-policy"]
        login(client)
        home = client.get("/tesla/owner")
        assert "form-action 'self' https://auth.tesla.com;" in home.headers["content-security-policy"]
        confirmation = client.get("/tesla/owner/intents/"+intent["id"])
        assert "form-action 'self';" in confirmation.headers["content-security-policy"]
