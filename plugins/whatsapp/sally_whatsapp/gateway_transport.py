"""Attachment-only elapsed deadlines below the existing HTTPX/httpcore parser.

The ordinary provider client retains its normal transport. Each bounded download
owns a separate one-request pool, so no reused socket carries another request's
deadline. All I/O stays synchronous; no timer or abandoned worker is introduced.
The OS resolver is synchronous: a late result is rejected before socket creation,
but resolving itself is not preempted (the same boundary as public downloads).
"""
from contextlib import contextmanager
import socket
import ssl

import httpcore
import httpx


DEADLINE_EXTENSION = 'whatsapp.attachment_deadline'


def _arm(sock, deadline, timeout):
    remaining = deadline.remaining()
    sock.settimeout(remaining if timeout is None else min(timeout, remaining))


class _Stream(httpcore.NetworkStream):
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline

    def read(self, max_bytes, timeout=None):
        _arm(self.sock, self.deadline, timeout)
        try:
            data = self.sock.recv(max_bytes)
        except OSError as exc:
            self.deadline.remaining()
            error = httpcore.ReadTimeout if isinstance(exc, TimeoutError) else httpcore.ReadError
            raise error('Gateway attachment read failed') from exc
        self.deadline.remaining()
        return data

    def write(self, buffer, timeout=None):
        _arm(self.sock, self.deadline, timeout)
        try:
            # Python's sendall timeout covers this entire write, including any
            # partial sends. Each subsequent HTTP parser write is re-armed.
            self.sock.sendall(buffer)
        except OSError as exc:
            self.deadline.remaining()
            error = httpcore.WriteTimeout if isinstance(exc, TimeoutError) else httpcore.WriteError
            raise error('Gateway attachment write failed') from exc
        self.deadline.remaining()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        try:
            _arm(self.sock, self.deadline, timeout)
            self.sock = ssl_context.wrap_socket(self.sock, server_hostname=server_hostname)
            self.deadline.remaining()
            return self
        except BaseException as exc:
            self.close()
            if isinstance(exc, OSError):
                self.deadline.remaining()
                error = httpcore.ConnectTimeout if isinstance(exc, TimeoutError) else httpcore.ConnectError
                raise error('Gateway attachment TLS failed') from exc
            raise

    def get_extra_info(self, info):
        if info == 'ssl_object' and isinstance(self.sock, ssl.SSLSocket):
            return self.sock
        if info == 'socket':
            return self.sock
        # Pools never retain these connections for reuse.
        return None

    def close(self):
        self.sock.close()


class _Backend(httpcore.NetworkBackend):
    def __init__(self, deadline):
        self.deadline = deadline

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.deadline.remaining()
        try:
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            self.deadline.remaining()
            raise httpcore.ConnectError('Gateway attachment resolution failed') from exc
        self.deadline.remaining()
        last = None
        for family, kind, proto, _, address in addresses:
            self.deadline.remaining()
            sock = socket.socket(family, kind, proto)
            claimed = False
            try:
                if local_address is not None:
                    sock.bind((local_address, 0))
                for option in socket_options or ():
                    sock.setsockopt(*option)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                _arm(sock, self.deadline, timeout)
                sock.connect(address)
                self.deadline.remaining()
                claimed = True
                return _Stream(sock, self.deadline)
            except OSError as exc:
                self.deadline.remaining()
                last = exc
            finally:
                if not claimed:
                    sock.close()
        error = httpcore.ConnectTimeout if isinstance(last, TimeoutError) else httpcore.ConnectError
        raise error('Gateway attachment connection failed') from last


@contextmanager
def _http_errors():
    # This adapter uses public APIs from the already pinned HTTPX/httpcore.
    # Preserve timeout/network/protocol categories; ordinary requests continue
    # to use HTTPX's own adapter and its pre-dispatch classification unchanged.
    try:
        yield
    except httpcore.TimeoutException as exc:
        raise httpx.TimeoutException('Gateway attachment timeout') from exc
    except httpcore.NetworkError as exc:
        raise httpx.NetworkError('Gateway attachment network failure') from exc
    except httpcore.ProtocolError as exc:
        raise httpx.ProtocolError('Gateway attachment protocol failure') from exc
    except httpcore.UnsupportedProtocol as exc:
        raise httpx.UnsupportedProtocol('Gateway attachment protocol unavailable') from exc


class _ResponseStream(httpx.SyncByteStream):
    def __init__(self, response, pool):
        self.response, self.pool = response, pool

    def __iter__(self):
        with _http_errors():
            yield from self.response.iter_stream()

    def close(self):
        try:
            self.response.close()
        finally:
            self.pool.close()


class GatewayTransport(httpx.BaseTransport):
    def __init__(self):
        self.ordinary = httpx.HTTPTransport(trust_env=False)

    def handle_request(self, request):
        deadline = request.extensions.get(DEADLINE_EXTENSION)
        if deadline is None:
            return self.ordinary.handle_request(request)
        deadline.remaining()
        pool = httpcore.ConnectionPool(network_backend=_Backend(deadline),
            ssl_context=httpx.create_ssl_context(trust_env=False), max_connections=1,
            max_keepalive_connections=0, retries=0)
        try:
            core_request = httpcore.Request(method=request.method,
                url=httpcore.URL(scheme=request.url.raw_scheme, host=request.url.raw_host,
                                 port=request.url.port, target=request.url.raw_path),
                headers=request.headers.raw, content=request.stream,
                extensions={key: value for key, value in request.extensions.items()
                            if key != DEADLINE_EXTENSION})
            with _http_errors():
                response = pool.handle_request(core_request)
            deadline.remaining()
            return httpx.Response(response.status, headers=response.headers,
                stream=_ResponseStream(response, pool), extensions=response.extensions)
        except BaseException:
            pool.close()
            raise

    def close(self):
        self.ordinary.close()
