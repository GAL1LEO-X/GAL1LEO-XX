"""Real HTTPX/httpcore/h11 and file copy, with deterministic raw socket I/O."""
from dataclasses import replace
import hashlib
import socket
import ssl
import threading

import pytest

from sally_whatsapp import media
from sally_whatsapp.gateway import GatewayUnavailable, Waha


class Clock:
    now = 0.0

    def wait(self, delay, timeout):
        if delay >= timeout:
            self.now += timeout
            raise TimeoutError('synthetic socket timeout')
        self.now += delay


class Socket:
    def __init__(self, clock, segments, *, connect=0, tls=0, write=0, failed=False):
        self.clock, self.segments = clock, list(segments)
        self.connect_delay, self.tls_delay, self.write_delay = connect, tls, write
        self.failed, self.closed, self.timeout = failed, False, None
        self.sent, self.timeouts = bytearray(), []

    def settimeout(self, value):
        assert value > 0
        self.timeout = value
        self.timeouts.append(value)

    def setsockopt(self, *_):
        pass

    def connect(self, address):
        self.address = address
        self.clock.wait(self.connect_delay, self.timeout)
        if self.failed:
            raise OSError('synthetic unreachable address')

    def send(self, data):
        self.clock.wait(self.write_delay, self.timeout)
        self.write_delay = 0
        self.sent.extend(data)
        return len(data)

    def sendall(self, data):
        self.send(data)

    def recv(self, size):
        if not self.segments:
            return b''
        delay, data = self.segments.pop(0)
        self.clock.wait(delay, self.timeout)
        if len(data) > size:
            self.segments.insert(0, (0, data[size:]))
        return data[:size]

    def close(self):
        self.closed = True

    def fileno(self):
        # The baseline pool may inspect a completed connection for reuse.
        # There is deliberately no real descriptor in this socket boundary.
        return -1


@pytest.fixture
def wire(environment, monkeypatch, request):
    clock, plans, sockets, resolutions = Clock(), [], [], []
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 8821))]
    def resolve(host, port, *_, **__):
        assert host == 'gateway.example' and port == 8821
        resolutions.append(host)
        return addresses
    def create(family, kind, proto=0, *_, **__):
        assert (family, kind) == (socket.AF_INET, socket.SOCK_STREAM)
        sock = Socket(clock, **plans.pop(0))
        sockets.append(sock)
        return sock
    def wrap(context, sock, *, server_hostname):
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        assert server_hostname == 'gateway.example'
        sock.clock.wait(sock.tls_delay, sock.timeout)
        return sock
    monkeypatch.setattr(socket, 'getaddrinfo', resolve)
    monkeypatch.setattr(socket, 'socket', create)
    monkeypatch.setattr(ssl.SSLContext, 'wrap_socket', wrap)
    monkeypatch.setattr(media.time, 'monotonic', lambda: clock.now)
    scheme = getattr(request, 'param', 'https')
    settings = replace(environment[0], live_account_enabled=True, waha_url=scheme+'://gateway.example:8821')
    gateway = Waha(settings)
    yield gateway, clock, plans, sockets, resolutions, addresses
    gateway.close()
    assert all(sock.closed for sock in sockets)


def transfer(gateway, target, *, inline=False):
    source = {'url': gateway.settings.waha_url + '/api/files/synthetic'}
    return gateway.attachment(source) if inline else gateway.attachment_to_file(source, target, 100)


@pytest.mark.parametrize('framing', ['headers', 'chunk'])
@pytest.mark.parametrize('inline', [False, True])
def test_hidden_http_reads_cannot_outlive_transfer_deadline(wire, tmp_path, framing, inline):
    gateway, clock, plans, sockets, _, _ = wire
    prefix = (b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Synthetic: ' if framing == 'headers'
              else b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;extension=')
    tail = b'\r\n\r\na' if framing == 'headers' else b'\r\na\r\n0\r\n\r\n'
    # Inline keeps its existing 15s inactivity bound; each byte remains active.
    plans.append({'segments': [(0, prefix)] + [(10, b'x')] * 200 + [(0, tail)]})
    threads = {thread.ident for thread in threading.enumerate()}
    with pytest.raises(ValueError, match='^Transfer time limit exceeded$'):
        transfer(gateway, tmp_path / 'download', inline=inline)
    assert clock.now == pytest.approx(1800)
    assert sockets[0].closed and not (tmp_path / 'download').exists()
    assert {thread.ident for thread in threading.enumerate()} == threads


def test_connect_tls_write_headers_and_body_share_budget(wire, tmp_path, monkeypatch):
    gateway, clock, plans, sockets, resolutions, _ = wire
    monkeypatch.setattr(media, 'TRANSFER_TIMEOUT_SECONDS', 1)
    plans.append({'connect': .2, 'tls': .2, 'write': .2, 'segments': [
        (.2, b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n'), (.3, b'abc')]})
    with pytest.raises(ValueError, match='^Transfer time limit exceeded$'):
        transfer(gateway, tmp_path / 'download')
    assert clock.now == pytest.approx(1)
    assert resolutions == ['gateway.example']
    assert sockets[0].closed and not (tmp_path / 'download').exists()


def test_multiple_addresses_do_not_restart_connect_budget(wire, tmp_path, monkeypatch):
    gateway, clock, plans, sockets, resolutions, addresses = wire
    monkeypatch.setattr(media, 'TRANSFER_TIMEOUT_SECONDS', 1)
    addresses.append((socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.2', 8821)))
    plans.extend([{'connect': .7, 'failed': True, 'segments': []},
                  {'connect': .5, 'segments': []}])
    with pytest.raises(ValueError, match='^Transfer time limit exceeded$'):
        transfer(gateway, tmp_path / 'download')
    assert clock.now == pytest.approx(1)
    assert resolutions == ['gateway.example']
    assert len(sockets) == 2 and all(sock.closed for sock in sockets)


def test_late_synchronous_dns_result_is_rejected_before_socket(wire, tmp_path, monkeypatch):
    gateway, clock, _, sockets, _, addresses = wire
    monkeypatch.setattr(media, 'TRANSFER_TIMEOUT_SECONDS', 1)
    def resolve(*_, **__):
        clock.now += 2  # No detached DNS thread: the OS call itself is not interruptible here.
        return addresses
    monkeypatch.setattr(socket, 'getaddrinfo', resolve)
    with pytest.raises(ValueError, match='^Transfer time limit exceeded$'):
        transfer(gateway, tmp_path / 'download')
    assert clock.now == 2 and not sockets and not (tmp_path / 'download').exists()


def test_tls_handshake_uses_connect_remainder(wire, tmp_path, monkeypatch):
    gateway, clock, plans, sockets, _, _ = wire
    monkeypatch.setattr(media, 'TRANSFER_TIMEOUT_SECONDS', 1)
    plans.append({'connect': .7, 'tls': .5, 'segments': []})
    with pytest.raises(ValueError, match='^Transfer time limit exceeded$'):
        transfer(gateway, tmp_path / 'download')
    assert clock.now == pytest.approx(1) and sockets[0].closed


@pytest.mark.parametrize('wire', ['http', 'https'], indirect=True)
def test_fast_gateway_preserves_original_bytes_auth_and_private_file(wire, tmp_path):
    gateway, clock, plans, sockets, resolutions, _ = wire
    content = b'synthetic original bytes'
    plans.append({'segments': [(0, b'HTTP/1.1 200 OK\r\nContent-Length: ' +
                               str(len(content)).encode() + b'\r\n\r\n' + content)]})
    target = tmp_path / 'download'
    assert transfer(gateway, target) == (len(content), hashlib.sha256(content).hexdigest())
    assert target.read_bytes() == content and target.stat().st_mode & 0o777 == 0o600
    assert resolutions == ['gateway.example']
    assert b'X-Api-Key:' in sockets[0].sent and b'Accept-Encoding: identity, gzip' in sockets[0].sent
    assert clock.now == 0


def test_inactivity_timeout_still_applies_and_preexisting_file_is_kept(wire, tmp_path):
    gateway, clock, plans, sockets, _, _ = wire
    plans.append({'segments': [(61, b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')]})
    target = tmp_path / 'download'
    target.write_bytes(b'keep synthetic original')
    with pytest.raises(GatewayUnavailable):
        transfer(gateway, target)
    assert clock.now == 60 and sockets[0].closed
    assert target.read_bytes() == b'keep synthetic original'


def test_non_attachment_request_keeps_ordinary_provider_transport(wire, monkeypatch):
    gateway, clock, plans, _, _, _ = wire
    monkeypatch.setattr(media, 'TRANSFER_TIMEOUT_SECONDS', 1)
    body = b'{"synthetic":true}'
    plans.append({'segments': [(2, b'HTTP/1.1 200 OK\r\nContent-Length: ' +
                               str(len(body)).encode() + b'\r\n\r\n' + body)]})
    assert gateway.request('GET', '/api/synthetic') == {'synthetic': True}
    assert clock.now == 2  # Existing 15s provider timeout, no attachment deadline.
