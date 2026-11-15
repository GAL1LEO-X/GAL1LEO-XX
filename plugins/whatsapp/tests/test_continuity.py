import base64
from dataclasses import replace
from datetime import datetime
import hashlib
import hmac
import json
import time

import httpx
import pytest

from conftest import call, message, rpc, subscribe
from sally_whatsapp.gateway import Waha
from sally_whatsapp.server import Service


def test_profile_stays_the_same_after_refresh_and_service_restart(environment, app_client):
    app, client=app_client
    first=call(client,"get_profile")["result"]["structuredContent"]
    client.headers["Authorization"]="Bearer "+environment[3](exp=int(time.time())+600)
    assert call(client,"get_profile")["result"]["structuredContent"]==first
    restarted=Service(environment[0],gateway=environment[2],event_transport=environment[1])
    assert restarted.store.profile("test-owner")==first
    with pytest.raises(ValueError, match="not initialized"):
        restarted.store.profile("different-owner")
    advertised=next(t for t in rpc(client,"tools/list")["result"]["tools"] if t["name"]=="get_profile")
    assert advertised["_meta"]["openai/profile"] is True
    assert "id" in advertised["outputSchema"]["required"]


def test_subscription_ttl_and_token_expiration(environment,app_client):
    app,client=app_client
    now=time.time()
    value=subscribe(client,ttlMs=120000)["result"]
    deadline=datetime.fromisoformat(value["refreshBefore"].replace("Z","+00:00")).timestamp()
    assert 115<=deadline-now<=125
    token_deadline=int(now)+90
    client.headers["Authorization"]="Bearer "+environment[3](exp=token_deadline)
    value=subscribe(client,ttlMs=None)["result"]
    deadline=datetime.fromisoformat(value["refreshBefore"].replace("Z","+00:00")).timestamp()
    assert deadline==token_deadline
    app.state.service.store.ingest(message())
    assert not app.state.service.events.dispatch_one(now=token_deadline+1)
    assert app.state.service.store.state()["deliveries"]=={"cancelled":1}


def test_refresh_verification_cache_and_key_rotation(environment,app_client):
    app,client=app_client
    receiver=environment[1]
    first=subscribe(client)["result"]["id"]
    assert subscribe(client)["result"]["id"]==first
    assert len(receiver.requests)==1
    new_secret="whsec_"+base64.b64encode(b"n"*32).decode()
    delivery={"mode":"webhook","url":"https://receiver.example/callback","secret":new_secret}
    assert subscribe(client,delivery=delivery)["result"]["id"]==first
    assert len(receiver.requests)==2
    app.state.service.store.ingest(message())
    assert app.state.service.events.dispatch_one()
    _,body,headers=receiver.requests[-1]
    signed=(headers["webhook-id"]+"."+headers["webhook-timestamp"]+".").encode()+body
    signatures=headers["webhook-signature"].split()
    expected={"v1,"+base64.b64encode(hmac.digest(k,signed,"sha256")).decode() for k in (b"n"*32,b"x"*32)}
    assert set(signatures)==expected


def test_unsubscribe_uses_documented_identity_and_only_matching_callback(environment,app_client):
    app,client=app_client
    subscribe(client)
    other={"mode":"webhook","url":"https://receiver.example/second","secret":"whsec_"+base64.b64encode(b"x"*32).decode()}
    subscribe(client,delivery=other)
    arguments={"name":"message.received","arguments":{"chat_ids":["group-1@g.us"]},
               "delivery":{"mode":"webhook","url":"https://receiver.example/callback"}}
    assert "result" in rpc(client,"events/unsubscribe",arguments)
    app.state.service.store.ingest(message())
    assert app.state.service.events.dispatch_one()
    assert environment[1].requests[-1][0]==other["url"]
    assert not app.state.service.events.dispatch_one()


def test_event_message_can_be_fetched_in_full(app_client):
    app,client=app_client
    subscribe(client)
    body="contenuto "*100
    app.state.service.store.ingest(message(text=body))
    fetched=call(client,"get_message",{"message_id":"synthetic-1"})["result"]["structuredContent"]
    assert fetched["message"]["body"]==body
    assert call(client,"get_message",{"message_id":"missing"})["result"]["structuredContent"]["message"] is None


def test_late_incoming_message_within_one_day_keeps_event(app_client):
    app,client=app_client
    subscribe(client)
    app.state.service.store.ingest(message(timestamp=int(time.time())-3600))
    assert app.state.service.events.dispatch_one()
    app.state.service.store.ingest(message("too-old",timestamp=int(time.time())-90000))
    assert not app.state.service.events.dispatch_one()
    state=app.state.service.connection_status()
    assert state["archive_messages"]==2 and state["recovery_required"]
    assert state["last_event_suppressed_reason"]=="message_outside_event_age_window"


def test_live_directory_http_contract_and_internal_data_excluded(environment):
    settings=replace(environment[0],live_account_enabled=True)
    gateway=Waha(settings)
    gateway.client.close()
    requests=[]
    def handler(request):
        requests.append(request)
        assert request.url.params["limit"]=="2"
        assert request.url.params["offset"]=="0"
        if request.url.path.endswith("/chats/overview"):
            return httpx.Response(200,json=[{"id":"group@g.us","name":"Test","_chat":{"sensitive":"internal"}},{"id":"second@g.us"}])
        assert request.url.path=="/api/contacts/all"
        assert request.url.params["session"]=="default"
        return httpx.Response(200,json=[{"id":{"_serialized":"123@c.us"},"name":"Test","_data":{"sensitive":"internal"}}])
    gateway.client=httpx.Client(base_url=settings.waha_url,transport=httpx.MockTransport(handler))
    try:
        chats=gateway.chats(limit=1)
        contacts=gateway.contacts(limit=1)
        assert chats["next_offset"]==1 and chats["chats"]==[{"id":"group@g.us","name":"Test"}]
        assert contacts["next_offset"] is None and contacts["contacts"][0]["id"]=="123@c.us"
        assert "internal" not in json.dumps([chats,contacts])
        assert len(requests)==2
    finally:
        gateway.close()
