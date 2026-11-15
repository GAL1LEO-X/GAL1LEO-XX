import asyncio
from dataclasses import replace
import json
import httpx
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from sally_whatsapp.gateway import Waha, GatewayUnavailable
from sally_whatsapp.server import create_app


@pytest.mark.parametrize("mode",["auto","legacy"])
def test_official_mcp_client_end_to_end(environment,mode):
    settings,receiver,gateway,token=environment
    settings=replace(settings,allowed_hosts=["bridge.example"])
    app=create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False)
    async def exercise():
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),headers={"Authorization":"Bearer "+token()}) as http:
                async with Client(streamable_http_client("https://bridge.example/mcp",http_client=http),mode=mode) as client:
                    tools=await client.list_tools()
                    assert len(tools.tools)==27
                    result=await client.call_tool("connection_status",{})
                    assert result.is_error is not True
                    assert result.structured_content["history_complete"] is False
    asyncio.run(exercise())


def test_waha_http_contract(environment):
    settings=replace(environment[0],live_account_enabled=True,send_enabled=True,send_chat_ids=["group@g.us"])
    gateway=Waha(settings)
    observed=[]
    def handler(request):
        observed.append(request)
        assert request.headers["x-api-key"]==settings.waha_key_file.read_text()
        if request.url.path.endswith("/messages"):
            assert request.url.params["downloadMedia"]=="false"
            assert request.url.params["filter.timestamp.lte"]=="200"
            assert request.url.params["offset"]=="100"
            return httpx.Response(200,json=[])
        if request.url.path=="/api/sendText":
            data=json.loads(request.content)
            assert data=={"session":"default","chatId":"group@g.us","text":"example","linkPreview":False,"linkPreviewHighQuality":False}
            return httpx.Response(201,json={"id":"sent"})
        return httpx.Response(200,json={"status":"WORKING"})
    gateway.client.close()
    gateway.client=httpx.Client(base_url=settings.waha_url,headers={"X-Api-Key":settings.waha_key_file.read_text()},
                                 transport=httpx.MockTransport(handler),follow_redirects=False)
    try:
        assert gateway.status()=="WORKING"
        assert gateway.messages("group@g.us",0,200,100)==[]
        assert gateway.send("group@g.us","example")["id"]=="sent"
        assert len(observed)==3
    finally:
        gateway.close()


def test_media_download_limit_and_redirect(environment):
    settings=replace(environment[0],live_account_enabled=True,max_attachment_bytes=1024)
    gateway=Waha(settings)
    gateway.client.close()
    gateway.client=httpx.Client(transport=httpx.MockTransport(lambda r:httpx.Response(200,stream=httpx.ByteStream(b"X"*1025))),follow_redirects=False)
    try:
        with pytest.raises(ValueError):
            gateway.attachment({"url":"http://127.0.0.1:8821/api/files/sample.bin"})
    finally:
        gateway.close()

