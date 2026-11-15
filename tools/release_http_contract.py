"""Reusable offline download-policy check for current and future publisher adapters.

The factory receives an injected transport and must return a compatible client.
This checks request negotiation and credential boundaries, not archive contents.
"""
import io
from pathlib import Path
import socket
import tempfile
from unittest.mock import patch


class Response:
    def __init__(self, status, headers=None):
        self.status, self.headers = status, headers or {}
        self.body = io.BytesIO(b'synthetic response')

    def read(self, size):
        return self.body.read(size)

    def close(self):
        self.body.close()


def check_download_contract(factory, error_type):
    """Raise AssertionError on incompatible negotiation, token leakage or retries."""
    storage = 'https://productionresultssa18.blob.core.windows.net/archive?sig=synthetic'
    scenarios = [('actions', 1, 503), ('actions', 2, 503),
                 ('release', 0, 503), ('actions', 0, 415)]
    for kind, redirects, terminal_status in scenarios:
        calls = []

        def transport(request, **kwargs):
            calls.append(request)
            headers = {key.lower():value for key,value in request.header_items()}
            expected = 'application/vnd.github+json' if kind == 'actions' else 'application/octet-stream'
            if len(calls) == 1 and headers.get('accept') != expected:
                return Response(415)
            if len(calls) <= redirects:
                return Response(302, {'Location':storage})
            return Response(terminal_status)

        def deny_network(*args, **kwargs):
            raise AssertionError('Contract tests must not use the network')

        with tempfile.TemporaryDirectory() as directory, \
             patch.object(socket, 'create_connection', deny_network), \
             patch.object(socket.socket, 'connect', deny_network):
            target = Path(directory)/'candidate.zip'
            client = factory(transport)
            try:
                if kind == 'actions':
                    client.download_actions_artifact(7, target)
                else:
                    client.download_release_asset(7, target, 1, 'a'*64)
            except error_type as error:
                assert error.status == terminal_status, 'Incorrect API media negotiation or transport phase'
            else:
                raise AssertionError('A failed synthetic transfer must stop')
            assert not target.exists(), 'A failed response must not create the destination'
        assert len(calls) == redirects + 1, 'Unexpected redirect count or automatic retry'
        initial = {key.lower():value for key,value in calls[0].header_items()}
        expected = 'application/vnd.github+json' if kind == 'actions' else 'application/octet-stream'
        assert initial.get('accept') == expected, 'Incorrect initial API Accept header'
        assert initial.get('authorization'), 'Initial API request must use explicit authentication'
        for request in calls[1:]:
            headers = {key.lower():value for key,value in request.header_items()}
            assert headers.get('accept') == 'application/octet-stream', 'Storage must request binary content'
            assert 'authorization' not in headers and 'proxy-authorization' not in headers, 'Credentials reached storage'
    return len(scenarios)
