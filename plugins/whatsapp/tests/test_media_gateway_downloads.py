"""Gateway response contracts, entirely synthetic; no HTTP/DNS connection allowed."""
from dataclasses import replace
import gzip
import hashlib
import random
import socket

import httpx
import pytest

from sally_whatsapp.gateway import GatewayUnavailable, Waha
from sally_whatsapp.media import TRANSFER_CHUNK_BYTES, decoded_gateway_chunks


class Chunks(httpx.SyncByteStream):
    def __init__(self, data, size=7, error=None):
        self.data,self.size,self.error=data,size,error
        self.closed=False

    def __iter__(self):
        for offset in range(0,len(self.data),self.size):
            yield self.data[offset:offset+self.size]
        if self.error:
            raise self.error

    def close(self):
        self.closed=True


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def fail(*args,**kwargs):
        pytest.fail('Unexpected real connection in synthetic gateway test')
    monkeypatch.setattr(socket,'getaddrinfo',fail)
    monkeypatch.setattr(socket.socket,'connect',fail)


@pytest.fixture
def gateway_response(environment):
    gateways=[]
    def create(data, *, encoding='identity', length='actual', maximum=8192, status=200,
               chunk_size=7, error=None):
        settings=replace(environment[0],live_account_enabled=True,max_attachment_bytes=maximum)
        gateway=Waha(settings)
        gateway.client.close()
        stream=Chunks(data,chunk_size,error)
        headers={'Content-Encoding':encoding}
        if length is not None:
            headers['Content-Length']=str(len(data)) if length=='actual' else length
        if status==302:
            headers['Location']='https://other.example/private'
        requests=[]
        def handler(request):
            requests.append(request)
            assert request.headers['accept-encoding']=='identity, gzip'
            return httpx.Response(status,headers=headers,stream=stream)
        gateway.client=httpx.Client(transport=httpx.MockTransport(handler),follow_redirects=False,trust_env=False)
        gateways.append(gateway)
        return gateway,stream,requests
    yield create
    for gateway in gateways:
        gateway.close()


def attachment(gateway):
    return {'url':gateway.settings.waha_url+'/api/files/synthetic'}


@pytest.mark.parametrize('encoding',['identity','gzip'])
@pytest.mark.parametrize('length',['actual',None])
@pytest.mark.parametrize('chunk_size',[1,7,65536])
@pytest.mark.parametrize('destination',['inline','file'])
def test_valid_response_wire_and_decoded_size(gateway_response,tmp_path,encoding,length,chunk_size,destination):
    plain=b'synthetic attachment\n'*175
    wire=gzip.compress(plain,mtime=0) if encoding=='gzip' else plain
    gateway,stream,requests=gateway_response(wire,encoding=encoding,length=length,chunk_size=chunk_size)
    if destination=='file':
        target=tmp_path/'output'
        size,digest=gateway.attachment_to_file(attachment(gateway),target,8192)
        assert size==len(plain) and digest==hashlib.sha256(plain).hexdigest()
        assert target.read_bytes()==plain
    else:
        assert gateway.attachment(attachment(gateway))==plain
    assert stream.closed and len(requests)==1


@pytest.mark.parametrize('encoding',['identity','gzip'])
@pytest.mark.parametrize('size',[1024,1025])
def test_decoded_limit_exact_and_plus_one(gateway_response,tmp_path,encoding,size):
    plain=b'A'*size
    wire=gzip.compress(plain,mtime=0) if encoding=='gzip' else plain
    gateway,stream,_=gateway_response(wire,encoding=encoding,length=None,maximum=1024)
    target=tmp_path/'output'
    if size==1024:
        assert gateway.attachment_to_file(attachment(gateway),target,1024)[0]==size
    else:
        with pytest.raises(ValueError,match='transfer limit'):
            gateway.attachment_to_file(attachment(gateway),target,1024)
        assert not target.exists()
    assert stream.closed


def test_compressed_wire_has_its_own_bound(gateway_response,tmp_path):
    # Gzip FNAME adds wire bytes without expanding the decoded one-byte body.
    raw=gzip.compress(b'A',mtime=0)
    wire=raw[:3]+bytes([raw[3]|8])+raw[4:10]+b'n'*1024+b'\0'+raw[10:]
    assert gzip.decompress(wire)==b'A'
    gateway,_,_=gateway_response(wire,encoding='gzip',length=None,maximum=1024)
    target=tmp_path/'output'
    with pytest.raises(ValueError,match='transfer limit'):
        gateway.attachment_to_file(attachment(gateway),target,1024)
    assert not target.exists()


@pytest.mark.parametrize('size',[0,1,65535,65536,65537,131072])
def test_gzip_decodes_incompressible_and_empty_payloads_across_block_edges(size):
    plain=random.Random(317).randbytes(size)
    wire=gzip.compress(plain,mtime=0)
    chunks=(wire[offset:offset+1009] for offset in range(0,len(wire),1009))
    decoded=list(decoded_gateway_chunks(chunks,max(len(wire),len(plain)),content_encoding='gzip',
                                       content_length=str(len(wire))))
    assert b''.join(decoded)==plain
    assert all(len(chunk)<=TRANSFER_CHUNK_BYTES for chunk in decoded)


def malformed_gzip(kind):
    raw=gzip.compress(b'X'*4096,mtime=0)
    if kind=='missing-footer': return raw[:-8]
    if kind=='truncated-footer': return raw[:-1]
    if kind=='crc': return raw[:-8]+bytes([raw[-8]^1])+raw[-7:]
    if kind=='isize': return raw[:-4]+bytes([raw[-4]^1])+raw[-3:]
    if kind=='invalid': return b'not a gzip stream'
    if kind=='empty': return b''
    if kind=='concatenated': return raw+gzip.compress(b'second',mtime=0)
    if kind=='empty-member': return raw+gzip.compress(b'',mtime=0)
    if kind=='padding': return raw+b'\0'
    if kind=='trailing': return raw+b'suffix'
    raise AssertionError(kind)


@pytest.mark.parametrize('kind',['missing-footer','truncated-footer','crc','isize','invalid','empty',
                                'concatenated','empty-member','padding','trailing'])
@pytest.mark.parametrize('chunk_size',[1,65536])
@pytest.mark.parametrize('destination',['inline','file'])
def test_reject_malformed_or_multiple_gzip(gateway_response,tmp_path,kind,chunk_size,destination):
    gateway,stream,_=gateway_response(malformed_gzip(kind),encoding='gzip',chunk_size=chunk_size)
    target=tmp_path/'partial'
    with pytest.raises(ValueError,match='gzip|trailing'):
        if destination=='file':
            gateway.attachment_to_file(attachment(gateway),target,8192)
        else:
            gateway.attachment(attachment(gateway))
    assert not target.exists() and stream.closed


@pytest.mark.parametrize('encoding',['deflate','br','gzip, gzip','gzip, identity'])
def test_unadvertised_encoding_rejected_before_body(gateway_response,tmp_path,encoding):
    gateway,stream,_=gateway_response(b'synthetic',encoding=encoding)
    target=tmp_path/'partial'
    with pytest.raises(ValueError,match='Unsupported gateway Content-Encoding'):
        gateway.attachment_to_file(attachment(gateway),target,8192)
    assert not target.exists() and stream.closed


@pytest.mark.parametrize('length',['39','41','-1','9000','invalid'])
def test_wire_content_length_is_validated(gateway_response,tmp_path,length):
    wire=gzip.compress(b'Z'*4096,mtime=0)
    assert len(wire)==40
    gateway,stream,_=gateway_response(wire,encoding='gzip',length=length)
    target=tmp_path/'partial'
    with pytest.raises(ValueError):
        gateway.attachment_to_file(attachment(gateway),target,8192)
    assert not target.exists() and stream.closed


def test_decompressor_output_is_bounded_before_oversize_is_detected(monkeypatch):
    import sally_whatsapp.media as module
    wire=gzip.compress(b'X'*(8*1024*1024),mtime=0)
    original=module.zlib.decompressobj
    requested=[]
    produced=[]
    class Spy:
        def __init__(self,*args): self.decoder=original(*args)
        def __getattr__(self,name): return getattr(self.decoder,name)
        def decompress(self,data,max_length):
            requested.append(max_length)
            output=self.decoder.decompress(data,max_length)
            produced.append(len(output))
            return output
    monkeypatch.setattr(module.zlib,'decompressobj',Spy)
    maximum=4*TRANSFER_CHUNK_BYTES
    with pytest.raises(ValueError,match='transfer limit'):
        list(decoded_gateway_chunks([wire],maximum,content_encoding='gzip'))
    assert requested and max(requested)<=TRANSFER_CHUNK_BYTES
    assert max(produced)<=TRANSFER_CHUNK_BYTES
    assert sum(produced)==maximum+1


def test_decoder_checks_timeout_even_when_no_payload_is_emitted(monkeypatch):
    import sally_whatsapp.media as module
    calls=iter([0,module.TRANSFER_TIMEOUT_SECONDS+1])
    monkeypatch.setattr(module.time,'monotonic',lambda:next(calls))
    with pytest.raises(ValueError,match='Transfer time limit'):
        list(decoded_gateway_chunks([b'\x1f'],8192,content_encoding='gzip'))


def test_read_failure_removes_partial_file(gateway_response,tmp_path):
    gateway,stream,_=gateway_response(b'A'*128,error=httpx.ReadError('synthetic'),chunk_size=64)
    target=tmp_path/'partial'
    with pytest.raises(GatewayUnavailable):
        gateway.attachment_to_file(attachment(gateway),target,8192)
    assert not target.exists() and stream.closed


@pytest.mark.parametrize('suffix',['/api/files/../private','/api/files/%2e%2e/private',
                                   '/api/files/a\\b','/api/session','/api/files/a#fragment'])
@pytest.mark.parametrize('destination',['inline','file'])
def test_gateway_paths_remain_restricted(gateway_response,tmp_path,suffix,destination):
    gateway,_,requests=gateway_response(b'unused')
    value={'url':gateway.settings.waha_url+suffix}
    with pytest.raises(ValueError):
        if destination=='file': gateway.attachment_to_file(value,tmp_path/'blocked',8192)
        else: gateway.attachment(value)
    assert not requests


@pytest.mark.parametrize('origin',['https://other.example','https://127.0.0.1:8821',
                                 'http://127.0.0.1:8822','http://user:pass@127.0.0.1:8821'])
def test_gateway_origin_remains_restricted(gateway_response,tmp_path,origin):
    gateway,_,requests=gateway_response(b'unused')
    with pytest.raises(ValueError):
        gateway.attachment_to_file({'url':origin+'/api/files/a'},tmp_path/'blocked',8192)
    assert not requests


def test_redirect_not_followed(gateway_response,tmp_path):
    gateway,stream,requests=gateway_response(b'',status=302)
    with pytest.raises(GatewayUnavailable):
        gateway.attachment_to_file(attachment(gateway),tmp_path/'blocked',8192)
    assert len(requests)==1 and stream.closed
