"""Synthetic OAuth preflight: never create a subscription or invoke the gateway."""
import pytest
from dataclasses import replace

from conftest import call, rpc, subscribe


@pytest.mark.parametrize("array_claim", [False, True])
@pytest.mark.parametrize("has_send", [False, True])
def test_event_upgrade_preserves_only_existing_send_grant(environment, app_client, array_claim, has_send):
    app, client = app_client
    # Enable only the injected fake gateway and one synthetic destination.
    app.state.service.settings = replace(environment[0], live_account_enabled=True,
        send_enabled=True, send_chat_ids=["group-1@g.us"])
    original = ["whatsapp:read"] + (["whatsapp:send"] if has_send else [])
    claims = {"scope": " ".join(original)} if not array_claim else {"_omit": ("scope",), "scp": original}
    client.headers["Authorization"] = "Bearer " + environment[3](**claims)
    challenge = call(client, "check_event_authorization")["result"]["_meta"]["mcp/www_authenticate"][0]
    scopes = challenge.rsplit('scope="', 1)[1].split('"', 1)[0]
    assert scopes.split() == ["whatsapp:read", "whatsapp:events"] + (["whatsapp:send"] if has_send else [])
    assert environment[2].sent == []
    # Simulate the exact replacement grant, without contacting any real IdP.
    client.headers["Authorization"] = "Bearer " + environment[3](scope=scopes)
    assert call(client, "check_event_authorization")["result"]["structuredContent"]["authorized"] is True
    assert call(client, "get_profile")["result"]["structuredContent"]["id"]
    sent = call(client, "send_text", {"chat_id": "group-1@g.us", "text": "synthetic",
        "idempotency_key": "synthetic-preserved-send"})["result"]
    if has_send:
        assert sent.get("isError", False) is False
        assert environment[2].sent == [("group-1@g.us", "synthetic")]
    else:
        assert sent["isError"] is True
        assert environment[2].sent == []
    assert environment[1].requests == []


@pytest.mark.parametrize("array_claim", [False, True])
def test_event_challenge_excludes_unrelated_scopes_and_is_request_local(environment, app_client, array_claim):
    _, client = app_client
    original = ["whatsapp:read", "whatsapp:send", "openid", "email", "offline_access", "custom:retained"]
    claims = {"scope": " ".join(original)} if not array_claim else {"_omit": ("scope",), "scp": original}
    client.headers["Authorization"] = "Bearer " + environment[3](**claims)
    challenge = call(client, "check_event_authorization")["result"]["_meta"]["mcp/www_authenticate"][0]
    assert 'scope="whatsapp:read whatsapp:events whatsapp:send"' in challenge
    assert all(scope not in challenge for scope in original[2:])
    # Metadata declares requirements, not the current connection's upgrade set.
    preflight = next(t for t in rpc(client, "tools/list")["result"]["tools"] if t["name"] == "check_event_authorization")
    assert preflight["securitySchemes"][0]["scopes"] == ["whatsapp:read", "whatsapp:events"]
    assert preflight["_meta"]["securitySchemes"] == preflight["securitySchemes"]
    client.headers["Authorization"] = "Bearer " + environment[3](scope="whatsapp:read")
    challenge = call(client, "check_event_authorization")["result"]["_meta"]["mcp/www_authenticate"][0]
    assert 'scope="whatsapp:read whatsapp:events"' in challenge
    assert "whatsapp:send" not in challenge
    assert environment[2].sent == []
    assert environment[1].requests == []


def test_event_authorization_metadata_includes_transport_requirements(app_client):
    _, client = app_client
    tools = rpc(client, "tools/list")["result"]["tools"]
    preflight = next(t for t in tools if t["name"] == "check_event_authorization")
    security = [{"type": "oauth2", "scopes": ["whatsapp:read", "whatsapp:events"]}]
    assert preflight["securitySchemes"] == security
    assert preflight["_meta"]["securitySchemes"] == security
    assert preflight["inputSchema"]["properties"] == {}
    assert preflight["inputSchema"]["additionalProperties"] is False
    assert preflight["annotations"] == {
        "readOnlyHint": True, "destructiveHint": False,
        "idempotentHint": True, "openWorldHint": False,
    }
    existing = [t for t in tools if t["name"] != preflight["name"]]
    assert len(existing) == 26
    transcription = {t['name']: t for t in existing
                     if t['name'] in ('transcribe_audio', 'get_transcription')}
    assert set(transcription) == {'transcribe_audio', 'get_transcription'}
    assert all(t['securitySchemes'] == [{'type': 'oauth2', 'scopes': ['whatsapp:read']}]
               for t in transcription.values())
    assert {scope for t in existing for s in t["securitySchemes"] for scope in s["scopes"]} == {
        "whatsapp:read", "whatsapp:send",
    }
    for tool in existing:
        expected = ['whatsapp:read'] + (['whatsapp:send'] if tool['name'] in ('send_text','write_whatsapp','send_media') else [])
        assert tool['securitySchemes'] == [{'type':'oauth2','scopes':expected}]
        assert tool['_meta']['securitySchemes'] == tool['securitySchemes']


@pytest.mark.parametrize("scope", ["whatsapp:read", "whatsapp:read whatsapp:send"])
def test_missing_events_scope_requests_consent_without_granting_it(environment, app_client, scope):
    _, client = app_client
    client.headers["Authorization"] = "Bearer " + environment[3](scope=scope)
    value = call(client, "check_event_authorization")["result"]
    assert value["isError"] is True
    assert "structuredContent" not in value
    expected = "whatsapp:read whatsapp:events" + (" whatsapp:send" if "whatsapp:send" in scope.split() else "")
    assert value["_meta"]["mcp/www_authenticate"] == [
        'Bearer resource_metadata="https://bridge.example/.well-known/oauth-protected-resource", '
        f'error="insufficient_scope", error_description="Required scope: {expected}", '
        f'scope="{expected}"'
    ]
    # Asking for consent must not change the token's effective permissions.
    assert subscribe(client)["error"]["code"] == -32001
    assert call(client, "get_profile")["result"]["structuredContent"]["id"]


@pytest.mark.parametrize("array_claim", [False, True])
@pytest.mark.parametrize("has_events", [False, True])
def test_event_preflight_has_no_subscription_callback_or_gateway_effects(
    environment, app_client, monkeypatch, array_claim, has_events,
):
    app, client = app_client
    scopes = ["whatsapp:read"] + (["whatsapp:events"] if has_events else [])
    claims = {"scope": " ".join(scopes)} if not array_claim else {"_omit": ("scope",), "scp": scopes}
    client.headers["Authorization"] = "Bearer " + environment[3](**claims)
    service = app.state.service
    def forbidden(*args, **kwargs):
        pytest.fail("Authorization preflight must not invoke account operations")
    monkeypatch.setattr(service.events, "subscribe", forbidden)
    monkeypatch.setattr(service.gateway, "send", forbidden)
    monkeypatch.setattr(service.gateway, "messages", forbidden)
    def state():
        with service.store.db() as db:
            return {table: db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                    for table in ("subscriptions", "callback_verifications", "deliveries", "action_jobs")}
    before = state()
    value = call(client, "check_event_authorization")["result"]
    if has_events:
        assert value.get("isError", False) is False
        assert value["structuredContent"] == {
            "authorized": True, "required_scope": "whatsapp:events", "subscription_created": False,
        }
        assert "mcp/www_authenticate" not in value.get("_meta", {})
        # Event authorization never implies send permission.
        denied = call(client, "send_text", {"chat_id": "group-1@g.us", "text": "synthetic",
            "idempotency_key": "synthetic-event-preflight"})["result"]
        assert denied["isError"] is True
        assert 'scope="whatsapp:read whatsapp:send whatsapp:events"' in denied["_meta"]["mcp/www_authenticate"][0]
    else:
        assert value["isError"] is True
    assert state() == before
    assert environment[1].requests == []
    assert environment[2].sent == []


@pytest.mark.parametrize("changes", [
    {"aud": "https://another.example"}, {"iss": "https://another-issuer.example"},
    {"sub": "another-owner"}, {"azp": "another-client"}, {"exp": 0},
    {"scope": "whatsapp:read whatsapp:events", "scp": ["whatsapp:read"]},
])
def test_event_preflight_preserves_token_validation(environment, app_client, changes):
    _, client = app_client
    client.headers["Authorization"] = "Bearer " + environment[3](**changes)
    rpc(client, "tools/call", {"name": "check_event_authorization", "arguments": {}}, expected_status=401)


def test_exact_challenged_grant_satisfies_transport_and_preserves_reads(environment, app_client):
    _, client = app_client
    client.headers["Authorization"] = "Bearer " + environment[3](scope="whatsapp:read")
    challenge = call(client, "check_event_authorization")["result"]["_meta"]["mcp/www_authenticate"][0]
    scopes = challenge.rsplit('scope="', 1)[1].split('"', 1)[0]
    assert scopes == "whatsapp:read whatsapp:events"
    client.headers["Authorization"] = "Bearer " + environment[3](scope=scopes)
    assert call(client, "check_event_authorization")["result"]["structuredContent"]["authorized"] is True
    assert call(client, "get_profile")["result"]["structuredContent"]["id"]
    client.headers["Authorization"] = "Bearer " + environment[3](scope="whatsapp:events")
    rpc(client, "tools/call", {"name": "check_event_authorization", "arguments": {}}, expected_status=403)


def test_event_preflight_rejects_arguments_without_account_work(environment, app_client):
    _, client = app_client
    result = call(client, "check_event_authorization", {"all_chats": True})["result"]
    assert result["isError"] is True
    assert result["content"][0]["text"] == "Invalid tool arguments"
    assert environment[1].requests == []
    assert environment[2].sent == []
