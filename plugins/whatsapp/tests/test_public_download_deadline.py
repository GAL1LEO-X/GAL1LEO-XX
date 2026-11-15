"""Real HTTP parser with deterministic in-memory sockets, never a live request."""
import hashlib
import io
import socket
import ssl
import threading

import pytest

from sally_whatsapp import media


class Clock:
    now=0.0

    def wait(self,delay,timeout):
        if delay>=timeout:
            self.now+=timeout
            raise TimeoutError('synthetic socket timeout')
        self.now+=delay


class Stream(io.RawIOBase):
    def __init__(self,sock,segments):
        self.sock,self.segments=sock,list(segments)
        self.bytes_read=0
        self.calls=[]

    def readable(self):
        return True

    def readinto(self,buffer):
        self.calls.append((len(buffer),self.sock.timeout,threading.get_ident(),self.sock.closed))
        if not self.segments:
            return 0
        delay,data=self.segments[0]
        self.sock.clock.wait(delay,self.sock.timeout)
        part=data[:len(buffer)]
        if len(part)==len(data):
            self.segments.pop(0)
        else:
            self.segments[0]=(0,data[len(part):])
        buffer[:len(part)]=part
        self.bytes_read+=len(part)
        return len(part)


class Socket:
    def __init__(self,clock,segments,*,connect_delay=0,tls_delay=0,send_delay=0,connect_error=False):
        self.clock,self.timeout=clock,None
        self.connect_delay,self.tls_delay,self.send_delay=connect_delay,tls_delay,send_delay
        self.connect_error=connect_error
        self.stream=Stream(self,segments)
        self.closed=False
        self.timeouts=[]
        self.request=b''

    def settimeout(self,value):
        assert value>0
        self.timeout=value
        self.timeouts.append(value)

    def connect(self,address):
        self.address=address
        self.clock.wait(self.connect_delay,self.timeout)
        if self.connect_error:
            raise OSError('synthetic failed address')

    def sendall(self,data):
        self.clock.wait(self.send_delay,self.timeout)
        self.request+=data

    def makefile(self,mode,buffering=-1):
        assert mode=='rb'
        return self.stream if buffering==0 else io.BufferedReader(self.stream)

    def close(self):
        self.closed=True


@pytest.fixture
def wire(monkeypatch):
    """Only DNS, TCP and TLS boundaries are substituted; HTTP handling is real."""
    clock=Clock()
    sockets=[]
    plans=[]
    resolutions=[]
    addresses=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',443))]

    def resolve(host,port,**kwargs):
        assert host=='files.example' and port==443 and kwargs=={'type':socket.SOCK_STREAM}
        resolutions.append(host)
        return addresses

    def create(family,kind,proto):
        assert (family,kind,proto)==(socket.AF_INET,socket.SOCK_STREAM,6)
        sock=Socket(clock,**plans.pop(0))
        sockets.append(sock)
        return sock

    def wrap(context,sock,*,server_hostname):
        assert context.verify_mode==ssl.CERT_REQUIRED and context.check_hostname
        assert server_hostname=='files.example'
        sock.clock.wait(sock.tls_delay,sock.timeout)
        return sock

    monkeypatch.setattr(media.time,'monotonic',lambda:clock.now)
    monkeypatch.setattr(socket,'getaddrinfo',resolve)
    monkeypatch.setattr(socket,'socket',create)
    monkeypatch.setattr(ssl.SSLContext,'wrap_socket',wrap)
    monkeypatch.setattr(media,'TRANSFER_TIMEOUT_SECONDS',1)
    return clock,sockets,plans,resolutions,addresses


def response(body,*,header=None):
    return [(0,header or b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'),(0,body)]


def assert_closed(sockets):
    assert sockets and all(s.closed for s in sockets)
    assert all(s.stream.closed for s in sockets if s.request)


def test_trickling_body_stops_at_total_deadline_and_removes_partial(wire,tmp_path):
    clock,sockets,plans,_,_=wire
    header=b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n'
    plans.append({'segments':[(0,header)]+[(.1,b'x')]*100})
    target=tmp_path/'download'
    threads={t.ident for t in threading.enumerate()}
    with pytest.raises(ValueError,match='^Transfer time limit exceeded$'):
        media.download_public('https://files.example/audio',target,100)
    assert clock.now==pytest.approx(1)
    assert sockets[0].stream.bytes_read<len(header)+100
    assert not target.exists()
    assert {t.ident for t in threading.enumerate()}==threads
    assert {call[2] for call in sockets[0].stream.calls}=={threading.get_ident()}
    assert_closed(sockets)


@pytest.mark.parametrize('header',[
    b'HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Length: 20\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n',
],ids=['http10-close','body-delimited-by-eof'])
def test_connection_close_keeps_response_file_alive_until_body_complete(wire,tmp_path,header):
    _,sockets,plans,_,_=wire
    body=b'synthetic close body'
    assert len(body)==20
    plans.append({'segments':response(body,header=header)})
    target=tmp_path/'download'
    result=media.download_public('https://files.example/file',target,len(body))
    assert result==(len(body),hashlib.sha256(body).hexdigest())
    assert target.read_bytes()==body
    assert sockets[0].stream.bytes_read==len(header)+len(body)
    # HTTPConnection closes its socket ownership before returning a will_close
    # response. The response's makefile still owns the readable stream.
    assert any(call[3] for call in sockets[0].stream.calls)
    assert_closed(sockets)


@pytest.mark.parametrize('prefix',[
    b'HTTP/1.1 200 OK\r\nX-Slow: ',
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;extension=',
])
def test_trickling_headers_and_chunk_framing_obey_same_deadline(wire,tmp_path,prefix):
    clock,sockets,plans,_,_=wire
    plans.append({'segments':[(0,prefix)]+[(.1,b'x')]*100})
    target=tmp_path/'download'
    with pytest.raises(ValueError,match='^Transfer time limit exceeded$'):
        media.download_public('https://files.example/audio',target,100)
    assert clock.now==pytest.approx(1)
    assert sockets[0].stream.bytes_read<len(prefix)+100
    assert not target.exists()
    assert_closed(sockets)


def test_request_connect_tls_headers_and_body_share_budget(wire,tmp_path):
    clock,sockets,plans,resolutions,_=wire
    header=b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n'
    plans.append({'segments':[(.2,header),(.3,b'abc')],
                  'connect_delay':.2,'tls_delay':.2,'send_delay':.2})
    with pytest.raises(ValueError,match='^Transfer time limit exceeded$'):
        media.download_public('https://files.example/file',tmp_path/'download',3)
    assert clock.now==pytest.approx(1)
    assert resolutions==['files.example']
    assert not (tmp_path/'download').exists()
    assert_closed(sockets)


def test_multiple_pinned_addresses_do_not_reset_connect_budget(wire,tmp_path):
    clock,sockets,plans,resolutions,addresses=wire
    addresses.append((socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.35',443)))
    plans.extend([{'segments':[], 'connect_delay':.7,'connect_error':True},
                  {'segments':[], 'connect_delay':.5}])
    with pytest.raises(ValueError,match='^Transfer time limit exceeded$'):
        media.download_public('https://files.example/file',tmp_path/'download',3)
    assert clock.now==pytest.approx(1)
    assert resolutions==['files.example']
    assert [s.address[0] for s in sockets]==['93.184.216.34','93.184.216.35']
    assert all(s.closed for s in sockets)
    assert not (tmp_path/'download').exists()


def test_tls_handshake_uses_remaining_connect_budget(wire,tmp_path):
    clock,sockets,plans,_,_=wire
    plans.append({'segments':[], 'connect_delay':.7,'tls_delay':.5})
    with pytest.raises(ValueError,match='^Transfer time limit exceeded$'):
        media.download_public('https://files.example/file',tmp_path/'download',3)
    assert clock.now==pytest.approx(1)
    assert sockets[0].timeouts==pytest.approx([1,.3])
    assert sockets[0].closed


def test_over_budget_dns_result_is_rejected_before_connect(wire,tmp_path,monkeypatch):
    clock,sockets,plans,resolutions,addresses=wire
    def resolve(*args,**kwargs):
        # The synchronous OS resolver cannot be interrupted by this transport.
        # It must never open a socket with the already expired result.
        clock.now+=2
        resolutions.append(args[0])
        return addresses
    monkeypatch.setattr(socket,'getaddrinfo',resolve)
    with pytest.raises(ValueError,match='^Transfer time limit exceeded$'):
        media.download_public('https://files.example/file',tmp_path/'download',3)
    assert sockets==[] and resolutions==['files.example']
    assert not (tmp_path/'download').exists()


@pytest.mark.parametrize('chunked',[False,True])
def test_exact_limit_file_is_streamed_and_integrity_retained(wire,tmp_path,chunked):
    clock,sockets,plans,resolutions,_=wire
    body=b'synthetic audio bytes'
    segments=response(body)
    if chunked:
        segments=[(0,b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'),
                  (0,f'{len(body):x}\r\n'.encode()+body+b'\r\n0\r\n\r\n')]
    plans.append({'segments':segments})
    target=tmp_path/'download'
    result=media.download_public('https://files.example/file?part=1',target,len(body))
    assert result==(len(body),hashlib.sha256(body).hexdigest())
    assert target.read_bytes()==body
    assert target.stat().st_mode & 0o777==0o600
    assert resolutions==['files.example']
    assert sockets[0].address==('93.184.216.34',443)
    assert b'GET /file?part=1 HTTP/1.1\r\n' in sockets[0].request
    assert b'Host: files.example\r\n' in sockets[0].request
    assert b'Accept-Encoding: identity\r\n' in sockets[0].request
    assert_closed(sockets)


@pytest.mark.parametrize('segments,maximum,expected',[
    (response(b'abcdef',header=b'HTTP/1.1 200 OK\r\n\r\n'),5,'transfer limit'),
    (response(b'abc',header=b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n'),4,'Incomplete file transfer'),
    (response(b'abcdef'),5,'transfer limit'),
    (response(b'abc',header=b'HTTP/1.1 302 Found\r\nLocation: https://elsewhere.invalid\r\nContent-Length: 3\r\n\r\n'),3,'redirected'),
    (response(b'abc',header=b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\n'),3,'Encoded download'),
])
def test_failure_preserves_bounds_and_closes_parser(wire,tmp_path,segments,maximum,expected):
    _,sockets,plans,_,_=wire
    plans.append({'segments':segments})
    target=tmp_path/'download'
    with pytest.raises(ValueError,match=expected):
        media.download_public('https://files.example/file',target,maximum)
    assert not target.exists()
    assert_closed(sockets)


def test_rejected_mixed_dns_answers_never_open_a_socket(wire,tmp_path):
    _,sockets,_,resolutions,addresses=wire
    addresses.append((socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443)))
    with pytest.raises(ValueError,match='not a public HTTPS endpoint'):
        media.download_public('https://files.example/file',tmp_path/'download',3)
    assert sockets==[] and resolutions==['files.example']


def test_deadline_failure_cannot_remove_a_preexisting_file(wire,tmp_path):
    _,sockets,plans,_,_=wire
    plans.append({'segments':response(b'abc')})
    target=tmp_path/'download'
    target.write_bytes(b'keep original')
    with pytest.raises(ValueError):
        media.download_public('https://files.example/file',target,3)
    assert target.read_bytes()==b'keep original'
    assert_closed(sockets)


def test_inactivity_limit_remains_shorter_than_large_total_budget(wire,tmp_path,monkeypatch):
    clock,sockets,plans,_,_=wire
    monkeypatch.setattr(media,'TRANSFER_TIMEOUT_SECONDS',1800)
    plans.append({'segments':[(61,b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')]})
    with pytest.raises(ValueError,match='File source is unreachable'):
        media.download_public('https://files.example/file',tmp_path/'download',3)
    assert clock.now==60
    assert not (tmp_path/'download').exists()
    assert_closed(sockets)
