"""Known HTTP status survives body failures; verification still needs a challenge.

Real http.client response parsing over synthetic bytes, no socket/network I/O.
"""
import base64
import http.client
import io
import json
import time

import pytest

from conftest import message
from sally_whatsapp import events
from sally_whatsapp.server import Service


URL = 'https://receiver.example/callback'
SECRET = 'whsec_' + base64.b64encode(b'x' * 32).decode()


@pytest.fixture
def callback_service(environment):
    settings, receiver, gateway, _ = environment
    service = Service(settings, gateway=gateway, event_transport=receiver)
    try:
        yield service, receiver
    finally:
        service.diagnostics.close()


def connection_factory(status, mode, posts, connections, after_headers=None):
    class Connection:
        def __init__(self, *args, **kwargs):
            self.response = None
            self.closed = False
            self.number = len(connections)
            connections.append(self)

        def request(self, method, path, body, headers):
            self.body = body
            posts.append((body, headers))

        def getresponse(self):
            if mode == 'before_headers':
                raise TimeoutError('synthetic failure before response headers')
            if mode == 'challenge':
                content = json.dumps({'challenge': json.loads(self.body)['challenge']}).encode()
            elif mode == 'malformed':
                content = b'not-json'
            elif mode == 'mismatched':
                content = b'{"challenge":"wrong"}'
            elif mode == 'oversized':
                content = b'x' * 65537
            else:
                content = b'x' if mode == 'timeout' else b''
            if mode == 'framing':
                header = (f'HTTP/1.1 {status} Synthetic\r\nTransfer-Encoding: chunked\r\n\r\n').encode()
                content = b'not-hex\r\n'
            else:
                header = (f'HTTP/1.1 {status} Synthetic\r\nContent-Length: {len(content)}\r\n\r\n').encode()
            number = self.number
            class Wire(io.BytesIO):
                def read(self, size=-1):
                    if self.tell() >= len(header):
                        if after_headers is not None:
                            after_headers(number)
                        if mode == 'timeout':
                            raise TimeoutError('synthetic response body timeout')
                    return super().read(size)
            class Socket:
                def makefile(self, _):
                    return Wire(header + content)
            self.response = http.client.HTTPResponse(Socket())
            self.response.begin()
            assert self.response.status == status
            return self.response

        def close(self):
            self.closed = True
            if self.response is not None:
                self.response.close()
    return Connection


def queued(service):
    sub = service.events.subscribe(service.settings.owner_subject, 'message.received',
                                   {'all_chats': True}, {'url': URL, 'secret': SECRET})
    service.ingest(message('synthetic_callback_boundary'))
    return sub['id']


def current(service, subscription):
    with service.store.db() as db:
        row = dict(db.execute('SELECT state,attempts,last_status FROM deliveries ORDER BY id LIMIT 1').fetchone())
        active = db.execute('SELECT active FROM subscriptions WHERE id=?', (subscription,)).fetchone()[0]
    return row, active


@pytest.mark.parametrize('status', [200, 201, 301, 400, 401, 410, 413, 408, 429, 503])
@pytest.mark.parametrize('mode', ['oversized', 'timeout', 'framing'])
def test_received_status_survives_response_body_failure(callback_service, monkeypatch, status, mode):
    service, _ = callback_service
    subscription = queued(service)
    posts, connections = [], []
    monkeypatch.setattr(events, 'PinnedHTTPS', connection_factory(status, mode, posts, connections))
    service.events.transport = events.HTTPSDelivery(service.settings.callback_hosts)
    now = time.time()
    assert service.events.dispatch_one(now)
    row, active = current(service, subscription)
    retry = status in (408, 429, 503)
    assert row == {'state': 'pending' if retry else 'accepted' if status < 300 else 'failed',
                   'attempts': 1, 'last_status': status}
    assert active == int(status != 410)
    assert service.events.dispatch_one(now + 30) is retry
    assert len(posts) == 1 + retry
    if retry:
        assert posts[0][0] == posts[1][0]
        assert posts[0][1]['webhook-id'] == posts[1][1]['webhook-id']
    assert all(connection.closed for connection in connections)


def test_failure_before_headers_keeps_transport_unknown(callback_service, monkeypatch):
    service, _ = callback_service
    subscription = queued(service)
    posts, connections = [], []
    monkeypatch.setattr(events, 'PinnedHTTPS', connection_factory(410, 'before_headers', posts, connections))
    service.events.transport = events.HTTPSDelivery(service.settings.callback_hosts)
    assert service.events.dispatch_one()
    row, active = current(service, subscription)
    assert row == {'state': 'pending', 'attempts': 1, 'last_status': 0}
    assert active and all(connection.closed for connection in connections)


@pytest.mark.parametrize('mode', ['oversized', 'timeout', 'framing', 'malformed', 'mismatched', 'empty', 'challenge'])
def test_verification_requires_body_even_after_success_status(callback_service, monkeypatch, mode):
    service, _ = callback_service
    posts, connections = [], []
    monkeypatch.setattr(events, 'PinnedHTTPS', connection_factory(200, mode, posts, connections))
    service.events.transport = events.HTTPSDelivery(service.settings.callback_hosts)
    def subscribe():
        return service.events.subscribe(service.settings.owner_subject, 'message.received',
            {'all_chats': True}, {'url': URL, 'secret': SECRET})
    if mode == 'challenge':
        subscribe()
    else:
        with pytest.raises(events.CallbackError):
            subscribe()
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM subscriptions').fetchone()[0] == int(mode == 'challenge')
    assert all(connection.closed for connection in connections)


@pytest.mark.parametrize('change', ['renew', 'reclaim'])
def test_410_body_failure_respects_subscription_and_attempt_fences(callback_service, monkeypatch, change):
    service, receiver = callback_service
    subscription = queued(service)
    posts, connections = [], []
    now = time.time()
    changed = []
    transport = events.HTTPSDelivery(service.settings.callback_hosts)
    def change_during_body(number):
        if changed:
            return
        changed.append(True)
        service.events.transport = receiver
        try:
            if change == 'renew':
                service.events.subscribe(service.settings.owner_subject, 'message.received',
                    {'all_chats': True}, {'url': URL, 'secret': 'whsec_' + base64.b64encode(b'y' * 32).decode()})
            else:
                assert service.events.dispatch_one(now + 121)
        finally:
            service.events.transport = transport
    monkeypatch.setattr(events, 'PinnedHTTPS', connection_factory(410, 'timeout', posts, connections,
                                                                 change_during_body))
    service.events.transport = transport
    assert service.events.dispatch_one(now)
    row, active = current(service, subscription)
    assert changed == [True] and active == 1
    assert row == ({'state': 'failed', 'attempts': 1, 'last_status': 410} if change == 'renew' else
                   {'state': 'accepted', 'attempts': 2, 'last_status': 204})
    assert len(posts) == 1 and all(connection.closed for connection in connections)
