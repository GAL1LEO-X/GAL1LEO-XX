import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import hmac
import json
import sqlite3
import time
import pytest
from starlette.testclient import TestClient

from conftest import attachment_payload, install_attachment_readback, call, message, rpc, subscribe
from sally_whatsapp.auth import JWTVerifier
from sally_whatsapp.events import CallbackError, callback_url, public_addresses, signed_headers
from sally_whatsapp.gateway import Waha
from sally_whatsapp.server import create_app, Service, SendText, SyncChat
from sally_whatsapp.store import Store, canonical


def test_mcp2_discovery_tools_and_scopes(app_client):
    app,client = app_client
    discovery = rpc(client,"server/discover")["result"]
    assert discovery["resultType"]=="complete"
    assert "2026-07-28" in discovery["supportedVersions"]
    assert discovery["capabilities"]["events"]=={}
    tools = rpc(client,"tools/list")["result"]["tools"]
    assert len(tools)==27
    assert all(t["securitySchemes"] for t in tools)
    assert next(t for t in tools if t["name"]=="send_text")["annotations"]["openWorldHint"]
    assert next(t for t in tools if t['name']=='write_whatsapp')['annotations']['destructiveHint']
    assert rpc(client,"events/list")["result"]["events"][0]["name"]=="message.received"


@pytest.mark.parametrize("changes",[{"aud":"https://other.example"},{"iss":"https://other-issuer.example"},
    {"sub":"another-user"},{"exp":0},{"nbf":253402300799},{"scope":123}])
def test_invalid_oauth_rejected(environment,app_client,changes):
    _,client = app_client
    client.headers["Authorization"]="Bearer "+environment[3](**changes)
    assert client.post("/mcp",json={"jsonrpc":"2.0","id":1,"method":"server/discover"}).status_code==401


def test_no_bearer_challenge_and_metadata(app_client):
    _,client = app_client
    del client.headers["Authorization"]
    response = client.post("/mcp",json={"jsonrpc":"2.0","id":1,"method":"server/discover"})
    assert response.status_code==401
    assert "oauth-protected-resource" in response.headers["www-authenticate"]
    metadata = client.get("/.well-known/oauth-protected-resource").json()
    assert metadata["resource"]=="https://bridge.example"


def test_scope_escalation_returns_oauth_challenge(environment,app_client):
    _,client = app_client
    client.headers["Authorization"]="Bearer "+environment[3](scope="whatsapp:read")
    result = call(client,"send_text",{"chat_id":"group-1@g.us","text":"hello","idempotency_key":"request-1234567890"})["result"]
    assert result["isError"]
    assert "insufficient_scope" in result["_meta"]["mcp/www_authenticate"][0]
    assert rpc(client,"events/list")["result"]["events"][0]["delivery"]==["webhook"]
    assert subscribe(client)["error"]["code"]==-32001


def test_authelia_scope_array_preserves_granted_permissions(environment,app_client):
    _,client = app_client
    client.headers["Authorization"]="Bearer "+environment[3](_omit=("scope",),scp=["openid","whatsapp:read"])
    assert call(client,"get_profile")["result"]["structuredContent"]["id"]
    assert subscribe(client)["error"]["code"]==-32001
    send=call(client,"send_text",{"chat_id":"group-1@g.us","text":"hello","idempotency_key":"request-1234567890"})
    assert "insufficient_scope" in send["result"]["_meta"]["mcp/www_authenticate"][0]


@pytest.mark.parametrize("changes",[
    {"scp":"whatsapp:read"}, {"scp":["whatsapp:read",123]},
    {"scp":["whatsapp:read whatsapp:send"]}, {"scp":[""]},
    {"scp":["whatsapp:read"],"scope":"whatsapp:read whatsapp:send"},
])
def test_invalid_or_conflicting_scope_arrays_rejected(environment,app_client,changes):
    _,client=app_client
    omit=() if "scope" in changes else ("scope",)
    client.headers["Authorization"]="Bearer "+environment[3](_omit=omit,**changes)
    assert client.post("/mcp",json={"jsonrpc":"2.0","id":1,"method":"server/discover"}).status_code==401


def test_untrusted_origin_rejected(app_client):
    _,client = app_client
    assert client.post("/mcp",headers={"Origin":"https://evil.example"},json={"jsonrpc":"2.0","id":1,"method":"server/discover"}).status_code==403


def test_signed_webhook_dedup_search_and_persistence(environment,app_client):
    app,client = app_client
    raw = canonical(message(text="Caffè e riunione")).encode()
    assert client.post("/webhooks/waha",content=raw).status_code==401
    headers={"X-Webhook-Hmac-Algorithm":"sha512","X-Webhook-Hmac":hmac.digest(environment[0].webhook_secret_file.read_bytes(),raw,"sha512").hex()}
    assert client.post("/webhooks/waha",content=raw,headers=headers).json()["duplicate"] is False
    assert client.post("/webhooks/waha",content=raw,headers=headers).json()["duplicate"] is True
    tampered = raw+b" "
    assert client.post("/webhooks/waha",content=tampered,headers=headers).status_code==401
    result = call(client,"search_messages",{"query":"caffe"})["result"]["structuredContent"]
    assert len(result["messages"])==1
    assert Store(environment[0].database).state()["archive_messages"]==1


def test_same_message_different_event_and_no_sql_injection(app_client):
    app,client = app_client
    event = message()
    app.state.service.store.ingest(event)
    event["id"]="second-envelope"
    assert app.state.service.store.ingest(event)["duplicate"]
    assert call(client,"search_messages",{"query":"\" OR 1=1 --"})["result"]["structuredContent"]["messages"]==[]


def test_invalid_message_rolls_back_receipt(app_client):
    app,_ = app_client
    event = message()
    event["payload"]["timestamp"]="bad"
    with pytest.raises(ValueError):
        app.state.service.store.ingest(event)
    event["payload"]["timestamp"]=int(time.time())
    assert app.state.service.store.ingest(event)["duplicate"] is False


def test_event_filter_history_self_exclusion_and_secret_at_rest(environment,app_client):
    app,client = app_client
    assert "result" in subscribe(client)
    store = app.state.service.store
    store.ingest(message("incoming"))
    store.ingest(message("historical"),historical=True)
    store.ingest(message("old",timestamp=1))
    store.ingest(message("self",from_me=True))
    store.ingest(message("other",chat="other@g.us"))
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM deliveries").fetchone()[0]==1
        encrypted = db.execute("SELECT secret FROM subscriptions").fetchone()[0]
        assert b"whsec_" not in encrypted
    assert app.state.service.events.dispatch_one()
    body,headers = environment[1].requests[-1][1:]
    decoded = json.loads(body)
    assert headers["webhook-id"]==decoded["eventId"]
    key = "whsec_"+base64.b64encode(b"x"*32).decode()
    assert headers==signed_headers(key,decoded["eventId"],headers["X-MCP-Subscription-Id"],body,int(headers["webhook-timestamp"]))


def test_subscription_idempotence_retry_restart_and_unsubscribe(environment,app_client):
    app,client = app_client
    first = subscribe(client)["result"]["id"]
    assert subscribe(client)["result"]["id"]==first
    app.state.service.store.ingest(message())
    receiver = environment[1]
    receiver.responses=[(503,b""),(204,b"")]
    assert app.state.service.events.dispatch_one()
    original_id = json.loads(receiver.requests[-1][1])["eventId"]
    # A new service reuses the persisted pending delivery.
    second = Service(environment[0],gateway=environment[2],event_transport=receiver)
    assert second.events.dispatch_one(now=time.time()+120)
    assert json.loads(receiver.requests[-1][1])["eventId"]==original_id
    assert second.store.state()["deliveries"]=={"accepted":1}
    app.state.service.store.ingest(message("next"))
    unsubscribe_args={"name":"message.received","arguments":{"chat_ids":["group-1@g.us"]},
                      "delivery":{"mode":"webhook","url":"https://receiver.example/callback"}}
    assert "result" in rpc(client,"events/unsubscribe",unsubscribe_args)
    assert not second.events.dispatch_one(now=time.time()+120)
    assert "result" in rpc(client,"events/unsubscribe",unsubscribe_args)


@pytest.mark.parametrize("status",[301,400,401,410,413])
def test_nonretryable_delivery(environment,app_client,status):
    app,client=app_client
    subscribe(client)
    app.state.service.store.ingest(message())
    environment[1].responses=[(status,b"")]
    app.state.service.events.dispatch_one()
    assert app.state.service.store.state()["deliveries"]=={"failed":1}
    assert not app.state.service.events.dispatch_one(now=time.time()+500)


def test_callback_challenge_failure_no_subscription(environment,app_client):
    app,client = app_client
    environment[1].bad_challenge=True
    error = subscribe(client)["error"]
    assert error["code"]==-32015 and error["data"]["reason"]=="challenge_failed"
    with app.state.service.store.db() as db:
        assert db.execute("SELECT count(*) FROM subscriptions").fetchone()[0]==0


@pytest.mark.parametrize("url",["http://receiver.example/x","https://receiver.example:8443/x","https://user@receiver.example/x",
    "https://127.0.0.1/x","https://receiver.example.evil/x","https://receiver.example/x#secret"])
def test_callback_url_controls(url):
    with pytest.raises(CallbackError):
        callback_url(url,["receiver.example"])


@pytest.mark.parametrize("address",["127.0.0.1","10.0.0.1","169.254.169.254","::1","::ffff:8.8.8.8","192.0.2.1"])
def test_dns_rebinding_private_address_rejected(monkeypatch,address):
    monkeypatch.setattr("socket.getaddrinfo",lambda *a,**kw:[(2,1,6,"",(address,443))])
    with pytest.raises(CallbackError):
        public_addresses("receiver.example")


def test_send_disabled_by_default_and_fresh_connection(app_client):
    app,client=app_client
    value = call(client,"send_text",{"chat_id":"group-1@g.us","text":"test","idempotency_key":"synthetic-1234567890"})["result"]  # gitleaks:allow -- synthetic idempotency key, not a credential
    assert value["isError"]
    app.state.service.poll_connection()
    status = call(client,"connection_status")["result"]["structuredContent"]
    assert status["connection"]=="WORKING" and status["connection_fresh"]
    assert status["history_complete"] is False and status["sending_enabled"] is False


def test_send_idempotence_concurrent_and_timeout(environment):
    settings,receiver,gateway,_=environment
    settings=replace(settings,live_account_enabled=True,send_enabled=True,send_chat_ids=["group-1@g.us"])
    service=Service(settings,gateway=gateway,event_transport=receiver)
    args=SendText(chat_id="group-1@g.us",text="synthetic only",idempotency_key="request-1234567890")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(lambda _:service.send(args,"test-owner"),range(8)))
    assert len(gateway.sent)==1
    assert service.store.send_status(args.idempotency_key)["state"]=="submitted"
    with pytest.raises(ValueError):
        service.send(args.model_copy(update={"text":"different"}),"test-owner")
    gateway.timeout=True
    timed=args.model_copy(update={"idempotency_key":"timeout-1234567890"})
    assert service.send(timed,"test-owner")["state"]=="uncertain"
    assert service.send(timed,"test-owner")["state"]=="uncertain"
    assert len(gateway.sent)==2


def test_crash_does_not_resend(environment):
    settings,_,_,_=environment
    store=Store(settings.database)
    store.reserve_send("crashed-1234567890","test-owner",{"test":1})
    restarted=Store(settings.database,recover_inflight=True)
    assert restarted.send_status("crashed-1234567890")["state"]=="uncertain"


def test_sync_pagination_and_no_historical_events(environment,app_client):
    app,client=app_client
    subscribe(client)
    environment[2].pages=[[message(str(i),timestamp=100)["payload"] for i in range(100)],
                          [message("last",timestamp=100)["payload"]]]
    args={"chat_id":"group-1@g.us","since":0,"until":200,"max_pages":1}
    first=call(client,"sync_chat",args)["result"]["structuredContent"]
    assert first["next_offset"]==100 and not first["window_complete"]
    second=call(client,"sync_chat",{**args,"offset":100})["result"]["structuredContent"]
    assert second["window_complete"] and second["inserted"]==1
    assert app.state.service.store.state()["deliveries"]=={}


def test_backup_restore_integrity(environment,app_client,tmp_path):
    app,_=app_client
    app.state.service.store.ingest(message())
    dest=tmp_path/"backup.sqlite"
    app.state.service.store.backup(dest)
    restored=Store(dest)
    assert restored.search()["messages"][0]["id"]=="synthetic-1"
    with pytest.raises(ValueError):
        app.state.service.store.backup(dest)


def test_attachment_no_provider_url_leak(app_client):
    app,client=app_client
    identifier='false_group-1@g.us_SYNTHETICFILE'
    event=message(identifier)
    event['payload']=attachment_payload(identifier,'group-1@g.us',b'synthetic attachment',
                                        name='test.txt',mimetype='text/plain')
    install_attachment_readback(app.state.service.gateway,event['payload'])
    app.state.service.store.ingest(event)
    searched=call(client,"read_conversation",{"chat_id":"group-1@g.us"})
    assert "127.0.0.1" not in json.dumps(searched)
    attachment=call(client,"get_attachment",{"message_id":identifier})['result']['structuredContent']
    assert attachment['state']=='queued'
    app.state.service.media.process_one()
    ready=call(client,'get_transfer_status',{'transfer_id':attachment['id']})['result']
    assert ready['content'][1]['type']=='resource_link'
    url=ready['structuredContent']['download_url']
    assert client.get(url).content==b'synthetic attachment'
    assert '127.0.0.1' not in json.dumps(ready)


@pytest.mark.parametrize("url",["http://169.254.169.254/latest","http://127.0.0.1:8821/api/sessions", "http://127.0.0.1:8821/api/files/../secret",
    "http://127.0.0.1:8821/api/files/%2e%2e/secret"])
def test_media_ssrf_rejected(environment,url):
    settings=replace(environment[0],live_account_enabled=True)
    gateway=Waha(settings)
    try:
        with pytest.raises(ValueError):
            gateway.attachment({"url":url})
    finally:
        gateway.close()

