"""Synthetic backend fixtures; the administrative cases explicitly model legacy."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.testing.installation_fixture import select_legacy

select_legacy()

import base64
import json
import secrets
import tempfile
import time
from dataclasses import replace
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient
from sally_whatsapp.config import Settings
from sally_whatsapp.server import create_app


@pytest.fixture
def short_socket_tmp_path():
    """Own a physical test tree whose UNIX sockets fit even with a long TMPDIR.

    Socket tests keep their policy, state and adversarial paths under this same
    private root. An explicit /tmp parent avoids inheriting the release
    qualifier's long TMPDIR/--basetemp; no symlink shortens the trust boundary.
    """
    with tempfile.TemporaryDirectory(prefix='wa-sock-', dir='/tmp') as directory:
        path = Path(directory)
        assert path == path.resolve(strict=True)
        assert len(str(path / 'socket-directory/control.sock').encode()) < 108
        yield path


class Receiver:
    def __init__(self):
        self.requests = []
        self.responses = []
        self.bad_challenge = False

    def post(self,url,body,headers):
        self.requests.append((url,body,headers))
        value = json.loads(body)
        if value.get("type")=="verification":
            return 200, json.dumps({"challenge":"wrong" if self.bad_challenge else value["challenge"]}).encode()
        return self.responses.pop(0) if self.responses else (204,b"")


class FakeGateway:
    def __init__(self):
        self.sent = []
        self.timeout = False
        self.state = "WORKING"
        self.pages = []
        self.media_bytes = b"synthetic attachment"

    def status(self):
        return self.state

    def messages(self,*args,**kwargs):
        return self.pages.pop(0) if self.pages else []

    def send(self,chat_id,text):
        self.sent.append((chat_id,text))
        if self.timeout:
            raise TimeoutError()
        return {"id":"synthetic-send-id"}

    def attachment(self,media):
        return self.media_bytes

    def attachment_to_file(self,media,target,maximum):
        from sally_whatsapp.media import copy_bounded
        return copy_bounded(iter([self.media_bytes]),target,maximum)

    def close(self):
        pass


@pytest.fixture
def environment(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    public = tmp_path/"test-public.pem"
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    hmac = tmp_path/"webhook.key"
    hmac.write_text(secrets.token_hex(32))
    encryption = tmp_path/"encryption.key"
    encryption.write_bytes(Fernet.generate_key())
    settings = Settings(database=tmp_path/"state.sqlite",public_url="https://bridge.example",issuer="https://issuer.example",
                        owner_subject="test-owner",webhook_secret_file=hmac,encryption_key_file=encryption,
                        public_key_file=public,waha_key_file=hmac,allowed_hosts=["testserver"],callback_hosts=["receiver.example"],
                        oauth_client_ids=['test-client'])
    receiver, gateway = Receiver(), FakeGateway()
    def token(*, _omit=(), **changes):
        claims = {"iss":settings.issuer,"aud":settings.public_url,"sub":"test-owner","iat":int(time.time()),
                  "exp":int(time.time())+3600,"scope":"whatsapp:read whatsapp:events whatsapp:send","azp":"test-client"}
        claims.update(changes)
        for name in _omit:
            claims.pop(name, None)
        return jwt.encode(claims,private,algorithm="RS256")
    return settings,receiver,gateway,token


@pytest.fixture
def app_client(environment):
    settings,receiver,gateway,token = environment
    app = create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False)
    with TestClient(app) as client:
        client.headers.update({"Authorization":"Bearer "+token(),"Accept":"application/json, text/event-stream",
                               "MCP-Protocol-Version":"2026-07-28"})
        yield app,client


def rpc(client,method,params=None,expected_status=200):
    params = {**(params or {}),"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
                                       "io.modelcontextprotocol/clientCapabilities":{}}}
    headers = {"mcp-method":method}
    if method=="tools/call":
        headers["mcp-name"]=params["name"]
    response = client.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":1,"method":method,"params":params})
    assert response.status_code==expected_status,response.text
    return response.json()


def call(client,name,arguments=None):
    return rpc(client,"tools/call",{"name":name,"arguments":arguments or {}})


def message(message_id="synthetic-1",chat="group-1@g.us",*,from_me=False,timestamp=None,text="Riunione domani"):
    return {"id":"event-"+message_id,"event":"message.any","session":"default","payload":{
        "id":message_id,"timestamp":int(time.time()) if timestamp is None else timestamp,
        "fromMe":from_me,"from":"self@c.us" if from_me else chat,"to":chat if from_me else "self@c.us","body":text}}


def subscribe(client,**changes):
    params = {"name":"message.received","arguments":{"chat_ids":["group-1@g.us"]},
              "delivery":{"mode":"webhook","url":"https://receiver.example/callback", "secret":"whsec_"+base64.b64encode(b"x"*32).decode()}}
    params.update(changes)
    return rpc(client,"events/subscribe",params)


def ready_external_media(service, *, name='fixture.bin', mimetype='application/octet-stream',
                         data=b'synthetic attachment'):
    """Stage fixture bytes as a native file; never invent a provider message."""
    import hashlib
    from unittest.mock import patch
    from sally_whatsapp.media import copy_bounded
    source={'kind':'external','file_id':'file-synthetic-'+hashlib.sha256(data).hexdigest(),
            'download_url':'https://files.example/synthetic'}
    queued=service.media.enqueue(service.settings.owner_subject,source,name,mimetype)
    with patch('sally_whatsapp.media.download_public',
               lambda url,target,maximum:copy_bounded([data],target,maximum,len(data))):
        assert service.media.process_one()
    assert service.media.row(queued['id'],service.settings.owner_subject)['state']=='ready'
    return queued


def attachment_payload(identifier,chat,content,*,name='fixture.bin',mimetype='application/octet-stream',
                       kind='documentMessage',timestamp=1000,url='http://127.0.0.1:8821/api/files/synthetic'):
    """Provider-shaped fixture with a complete message key and typed SHA256."""
    import hashlib
    payload=message(identifier,chat,timestamp=timestamp)['payload']
    payload.update(hasMedia=True,media={'url':url,'mimetype':mimetype,**({'filename':name} if name else {})},
                   _data={'IsViewOnce':False,'IsViewOnceV2':False,'IsViewOnceV2Extension':False,'IsEphemeral':False,
                          'Message':{kind:{'fileSHA256':base64.b64encode(hashlib.sha256(content).digest()).decode(),
                                           'fileLength':str(len(content)),'mimetype':mimetype,
                                           **({'fileName':name} if name else {})}}})
    return payload


def install_attachment_readback(gateway, payload):
    """Serve exact synthetic source reads; preserve the existing action fake."""
    import copy
    from urllib.parse import quote
    observations = getattr(gateway, '_typed_attachment_observations', None)
    if observations is None:
        observations = gateway._typed_attachment_observations = {}
        def unexpected(*args, **kwargs):
            raise AssertionError('Unexpected provider request in attachment fixture')
        original = getattr(gateway, 'request', unexpected)
        def request(method, path, **kwargs):
            if method == 'GET' and path in observations:
                assert kwargs.get('params', {}).get('downloadMedia') in {'false', 'true'}
                return copy.deepcopy(observations[path])
            return original(method, path, **kwargs)
        gateway.request = request
    chat = payload['to'] if payload['fromMe'] else payload['from']
    path = '/api/default/chats/' + quote(chat, safe='') + '/messages/' + quote(payload['id'], safe='')
    observations[path] = payload

