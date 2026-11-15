"""Offline transport and file-integrity tests; all tokens and bodies are fake."""
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import whatsapp_release_github as github

TOKEN = 'synthetic-token-do-not-publish'
DATA = b'\x00verified synthetic release archive\xff' * 100
DIGEST = hashlib.sha256(DATA).hexdigest()


class Response:
    def __init__(self, status=200, body=b'{}', headers=None):
        self.status = status
        self.headers = headers or {}
        self.body = io.BytesIO(body)
        self.closed = False

    def read(self, size):
        return self.body.read(size)

    def close(self):
        self.closed = True


class Transport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, request, *, timeout):
        self.calls.append(request)
        assert timeout == github.TIMEOUT_SECONDS
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if callable(response):
            return response(request)
        return response


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('A synthetic test attempted a real network connection')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)


def headers(request):
    return {key.lower(): value for key, value in request.header_items()}


@pytest.mark.parametrize('method,status', [('get', 200), ('post', 201), ('patch', 200)])
def test_repository_host_headers_and_canonical_json(method, status):
    response = Response(status, b'{"id":42}')
    transport = Transport(response)
    client = github.GitHubClient(TOKEN, transport)
    call = getattr(client, method)
    result = call('/releases/42') if method == 'get' else call('/releases/42', {'draft': True})
    assert result == {'id': 42}
    request, = transport.calls
    assert request.full_url == 'https://api.github.com/repos/GAL1LEO-X/GAL1LEO-XX/releases/42'
    assert request.get_method() == method.upper()
    assert headers(request)['authorization'] == 'Bearer ' + TOKEN
    assert headers(request)['accept'] == 'application/vnd.github+json'
    assert headers(request)['x-github-api-version'] == '2022-11-28'
    if method != 'get':
        assert request.data == github.canonical_json({'draft': True})
        assert headers(request)['content-length'] == str(len(request.data))
    assert response.closed
    assert TOKEN not in repr(client)


@pytest.mark.parametrize('token', ['', None, 12, 'line\nbreak', 'contains space', '\x7f', 'é'])
def test_token_is_explicit_not_discovered(token, monkeypatch):
    monkeypatch.setenv('GH_TOKEN', TOKEN)
    monkeypatch.setenv('GITHUB_TOKEN', TOKEN)
    with pytest.raises(github.ReleaseError):
        github.GitHubClient(token, Transport())


@pytest.mark.parametrize('path', ['https://evil.invalid/x', '//evil.invalid', '/repos/other/repo',
    '/releases/../actions', '/releases/%2e%2e/actions', '/releases/1#token',
    '/releases/1\nAuthorization:secret', '/releases/%0dsecret', '/releases/%zz',
    '/releases\\evil.invalid', '/other', '/'])
def test_path_cannot_escape_repository(path):
    transport = Transport()
    with pytest.raises(github.ReleaseError):
        github.GitHubClient(TOKEN, transport).get(path)
    assert not transport.calls


def test_encoded_tag_and_pagination_are_supported():
    transport = Transport(Response(), Response())
    client = github.GitHubClient(TOKEN, transport)
    client.get('/releases/tags/whatsapp%2Fv1.2.3')
    client.get('/actions/runs?per_page=100&page=2')
    assert transport.calls[0].full_url.endswith('/releases/tags/whatsapp%2Fv1.2.3')
    assert transport.calls[1].full_url.endswith('/actions/runs?per_page=100&page=2')


@pytest.mark.parametrize('path', ['', '/git/trees/' + 'a' * 40, '/git/ref/tags/whatsapp/v1.2.3',
    '/git/ref/tags/whatsapp%2Fv1.2.3', '/git/tags/' + 'a' * 40,
    '/compare/' + 'b' * 40 + '...main', '/actions/workflows/checks.yml',
    '/actions/workflows/123/runs?head_sha=' + 'b' * 40 + '&status=success&per_page=100'])
def test_publisher_tag_resolution_and_gate_routes_are_repository_bound(path):
    transport = Transport(Response(200, b'{"id":123}'))
    assert github.GitHubClient(TOKEN, transport).get(path) == {'id': 123}
    request, = transport.calls
    assert request.full_url == 'https://api.github.com/repos/GAL1LEO-X/GAL1LEO-XX' + path
    assert request.get_method() == 'GET'


@pytest.mark.parametrize('method,path', [('post', '/git/ref/tags/whatsapp/v1.2.3'),
    ('patch', '/git/tags/' + 'a' * 40), ('get', '/git/refs/heads/main'),
    ('get', '/git/tags/not-a-sha'), ('get', '/git/ref/tags/../heads/main'),
    ('post', ''), ('patch', ''), ('post', '/git/trees/' + 'a' * 40),
    ('patch', '/git/trees/' + 'a' * 40), ('get', '/git/trees/main')])
def test_git_route_extension_does_not_allow_mutations_or_other_git_endpoints(method, path):
    transport = Transport()
    call = getattr(github.GitHubClient(TOKEN, transport), method)
    with pytest.raises(github.ReleaseError):
        call(path) if method == 'get' else call(path, {})
    assert not transport.calls


@pytest.mark.parametrize('method,status,uncertain', [('get', 404, False), ('get', 503, False),
    ('post', 401, False), ('post', 403, False), ('patch', 422, False),
    ('post', 500, True), ('patch', 503, True), ('post', 408, True), ('patch', 307, True)])
def test_errors_are_sanitized_and_never_retried(method, status, uncertain):
    response = Response(status, ('private body ' + TOKEN).encode(),
                        {'Location': 'https://evil.invalid/' + TOKEN})
    transport = Transport(response)
    call = getattr(github.GitHubClient(TOKEN, transport), method)
    with pytest.raises(github.APIError) as error:
        if method == 'get':
            call('/commits/private-ref?token=private-query')
        else:
            call('/releases/42', {'body': 'private body'})
    assert error.value.status == status
    assert error.value.uncertain is uncertain
    assert error.value.method == method.upper()
    assert len(transport.calls) == 1
    assert response.body.tell() == 0
    assert response.closed
    assert all(value not in str(error.value) for value in (TOKEN, 'private', 'evil.invalid'))


@pytest.mark.parametrize('method', ['get', 'post', 'patch'])
def test_transport_timeout_has_conservative_write_uncertainty(method):
    transport = Transport(TimeoutError('private URL ' + TOKEN))
    call = getattr(github.GitHubClient(TOKEN, transport), method)
    with pytest.raises(github.APIError) as error:
        call('/releases/42') if method == 'get' else call('/releases/42', {})
    assert error.value.status is None
    assert error.value.uncertain is (method != 'get')
    assert TOKEN not in str(error.value)
    assert len(transport.calls) == 1


@pytest.mark.parametrize('payload', [b'{"id":1,"id":2}', b'{"x":{"a":1,"a":2}}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'null', b'[]trailing', b'\xff'])
def test_invalid_json_write_is_uncertain(payload):
    with pytest.raises(github.APIError) as error:
        github.GitHubClient(TOKEN, Transport(Response(201, payload))).post('/releases', {})
    assert error.value.uncertain


def test_json_read_is_bounded(monkeypatch):
    monkeypatch.setattr(github, 'MAX_JSON_BYTES', 32)
    response = Response(200, b'[' + b' ' * 200 + b']')
    with pytest.raises(github.APIError):
        github.GitHubClient(TOKEN, Transport(response)).get('/releases')
    assert response.body.tell() == 33


def test_default_opener_keeps_no_redirect_and_http_errors(monkeypatch):
    captured = []
    failure = urllib.error.HTTPError('https://api.github.com/repos/GAL1LEO-X/GAL1LEO-XX/releases',
                                    403, TOKEN, {}, io.BytesIO(TOKEN.encode()))
    class Opener:
        def open(self, request, *, timeout):
            raise failure
    def build(*handlers):
        captured.extend(handlers)
        return Opener()
    monkeypatch.setattr(urllib.request, 'build_opener', build)
    with pytest.raises(github.APIError) as error:
        github.GitHubClient(TOKEN).get('/releases')
    assert error.value.status == 403
    assert TOKEN not in str(error.value)
    assert len(captured) == 1
    assert isinstance(captured[0], urllib.request.HTTPRedirectHandler)
    assert captured[0].redirect_request(None, None, 302, '', {}, 'https://evil.invalid') is None


def test_implicit_redirect_from_injected_opener_is_rejected():
    response = Response()
    response.geturl = lambda: 'https://evil.invalid/signed-secret'
    with pytest.raises(github.APIError):
        github.GitHubClient(TOKEN, Transport(response)).get('/releases')
    assert response.closed


def test_close_failure_never_leaks_transport_context():
    response = Response(401, TOKEN.encode())
    def close():
        raise OSError(TOKEN)
    response.close = close
    with pytest.raises(github.APIError) as error:
        github.GitHubClient(TOKEN, Transport(response)).get('/releases')
    assert error.value.status == 401
    assert TOKEN not in str(error.value)


def upload_response(request):
    chunks = []
    while chunk := request.data.read(777):
        chunks.append(chunk)
    assert b''.join(chunks) == DATA
    return Response(201, json.dumps({'id': 72, 'name': 'runtime.oci',
                                    'size': len(DATA), 'state': 'uploaded'}).encode())


def test_upload_streams_verified_bytes_to_fixed_host(tmp_path):
    source = tmp_path / 'archive'
    source.write_bytes(DATA)
    transport = Transport(upload_response)
    result = github.GitHubClient(TOKEN, transport).upload(42, 'runtime.oci', source, len(DATA), DIGEST)
    assert result['id'] == 72
    request, = transport.calls
    assert request.full_url == 'https://uploads.github.com/repos/GAL1LEO-X/GAL1LEO-XX/releases/42/assets?name=runtime.oci'
    assert headers(request)['authorization'] == 'Bearer ' + TOKEN
    assert headers(request)['content-length'] == str(len(DATA))
    assert headers(request)['content-type'] == 'application/octet-stream'
    assert request.get_method() == 'POST'


@pytest.mark.parametrize('kind', ['wrong-size', 'wrong-hash', 'symlink', 'parent-symlink', 'directory', 'fifo'])
def test_unsafe_upload_source_never_sends_request(tmp_path, kind):
    source = tmp_path / 'archive'
    source.write_bytes(DATA)
    size, digest = len(DATA), DIGEST
    if kind == 'wrong-size':
        size += 1
    elif kind == 'wrong-hash':
        digest = '0' * 64
    elif kind == 'symlink':
        link = tmp_path / 'link'
        link.symlink_to(source)
        source = link
    elif kind == 'parent-symlink':
        directory = tmp_path / 'directory'
        directory.mkdir()
        (directory / 'archive').write_bytes(DATA)
        link = tmp_path / 'linked-directory'
        link.symlink_to(directory, target_is_directory=True)
        source = link / 'archive'
    elif kind == 'directory':
        source = tmp_path
    elif kind == 'fifo':
        source.unlink()
        os.mkfifo(source)
    transport = Transport()
    with pytest.raises(github.ReleaseError):
        github.GitHubClient(TOKEN, transport).upload(42, 'runtime.oci', source, size, digest)
    assert not transport.calls


@pytest.mark.parametrize('change', ['same-size', 'grow', 'shrink', 'unconsumed'])
def test_upload_change_during_transport_is_uncertain(tmp_path, change):
    source = tmp_path / 'archive'
    source.write_bytes(DATA)
    def mutate(request):
        if change != 'unconsumed':
            source.write_bytes({'same-size': b'x' * len(DATA), 'grow': DATA + b'x', 'shrink': DATA[:-1]}[change])
            while request.data.read(256):
                pass
        return Response(201, json.dumps({'id': 72, 'name': 'runtime.oci',
                                        'size': len(DATA), 'state': 'uploaded'}).encode())
    transport = Transport(mutate)
    with pytest.raises(github.APIError) as error:
        github.GitHubClient(TOKEN, transport).upload(42, 'runtime.oci', source, len(DATA), DIGEST)
    assert error.value.uncertain
    assert len(transport.calls) == 1


@pytest.mark.parametrize('change', [{'name': 'renamed'}, {'size': 1}, {'id': True}, {'state': 'starter'}])
def test_upload_result_must_identify_complete_asset(tmp_path, change):
    source = tmp_path / 'archive'
    source.write_bytes(DATA)
    def changed(request):
        response = upload_response(request)
        result = json.loads(response.body.getvalue())
        return Response(201, json.dumps({**result, **change}).encode())
    with pytest.raises(github.APIError) as error:
        github.GitHubClient(TOKEN, Transport(changed)).upload(42, 'runtime.oci', source, len(DATA), DIGEST)
    assert error.value.uncertain


@pytest.mark.parametrize('host', ['release-assets.githubusercontent.com', 'objects.githubusercontent.com',
    'pipelines.actions.githubusercontent.com', 'productionresultssa0.blob.core.windows.net'])
def test_download_strips_auth_on_allowed_signed_redirect(tmp_path, host):
    url = 'https://' + host + '/synthetic-asset?sig=synthetic-signature'
    transport = Transport(Response(302, headers={'Location': url}),
                          Response(200, DATA, {'Content-Length': str(len(DATA))}))
    target = tmp_path / 'asset'
    result = github.GitHubClient(TOKEN, transport).download_release_asset(72, target, len(DATA), DIGEST)
    assert result == target
    assert result.read_bytes() == DATA
    assert result.stat().st_mode & 0o777 == 0o600
    initial, redirected = transport.calls
    assert headers(initial)['authorization'] == 'Bearer ' + TOKEN
    assert headers(initial)['accept'] == 'application/octet-stream'
    assert 'authorization' not in headers(redirected)
    assert 'proxy-authorization' not in headers(redirected)
    assert redirected.full_url == url


@pytest.mark.parametrize('url', ['http://release-assets.githubusercontent.com/a',
    'https://release-assets.githubusercontent.com.evil.invalid/a', 'https://evil.invalid/a',
    'https://user@release-assets.githubusercontent.com/a', 'https://api.github.com/a',
    'https://release-assets.githubusercontent.com:444/a', 'https://release-assets.githubusercontent.com/a#fragment',
    'https://release-assets.githubusercontent.com./a', 'https://evil.blob.core.windows.net/a',
    '//release-assets.githubusercontent.com/a', 'https://release-assets.githubusercontent.com/a\nHeader:bad'])
def test_redirect_rejections_never_send_credentials_or_follow(tmp_path, url):
    transport = Transport(Response(302, headers={'Location': url}))
    with pytest.raises(github.APIError) as error:
        github.GitHubClient(TOKEN, transport).download_release_asset(72, tmp_path / 'asset', len(DATA), DIGEST)
    assert len(transport.calls) == 1
    assert url not in str(error.value)
    assert not list(tmp_path.iterdir())


def test_redirect_chain_never_restores_authorization_and_has_limit(tmp_path):
    location = {'Location': 'https://release-assets.githubusercontent.com/asset?sig=synthetic'}
    transport = Transport(*(Response(302, headers=location) for _ in range(github.MAX_REDIRECTS + 1)))
    with pytest.raises(github.APIError):
        github.GitHubClient(TOKEN, transport).download_release_asset(72, tmp_path / 'asset', len(DATA), DIGEST)
    assert len(transport.calls) == github.MAX_REDIRECTS + 1
    assert all('authorization' not in headers(request) for request in transport.calls[1:])


@pytest.mark.parametrize('payload,extra_headers', [(DATA[:-1], {}), (DATA + b'x', {}),
    (b'x' * len(DATA), {}), (DATA, {'Content-Length': str(len(DATA) + 1)}),
    (DATA, {'Content-Length': '-1'}), (DATA, {'Content-Encoding': 'gzip'})])
def test_download_integrity_failure_cleans_only_new_target(tmp_path, payload, extra_headers):
    target = tmp_path / 'asset'
    transport = Transport(Response(200, payload, extra_headers))
    with pytest.raises(github.APIError):
        github.GitHubClient(TOKEN, transport).download_release_asset(72, target, len(DATA), DIGEST)
    assert not target.exists()


@pytest.mark.parametrize('kind', ['existing', 'symlink', 'parent-symlink', 'directory', 'fifo'])
def test_download_never_overwrites_or_follows_links(tmp_path, kind):
    target = tmp_path / 'asset'
    original = tmp_path / 'original'
    original.write_bytes(b'preserve')
    if kind == 'existing':
        target.write_bytes(b'preserve')
    elif kind == 'symlink':
        target.symlink_to(original)
    elif kind == 'parent-symlink':
        directory = tmp_path / 'directory'
        directory.mkdir()
        target.symlink_to(directory, target_is_directory=True)
        target = target / 'asset'
    elif kind == 'directory':
        target.mkdir()
    elif kind == 'fifo':
        os.mkfifo(target)
    with pytest.raises(github.APIError):
        github.GitHubClient(TOKEN, Transport(Response(200, DATA))).download_release_asset(
            72, target, len(DATA), DIGEST)
    assert original.read_bytes() == b'preserve'
    if kind == 'existing':
        assert target.read_bytes() == b'preserve'


def test_download_failure_does_not_delete_replacement_file(tmp_path):
    target = tmp_path / 'asset'
    class Replaced(Response):
        def read(self, size):
            target.unlink()
            target.write_bytes(b'preserve replacement')
            raise OSError('private error ' + TOKEN)
    with pytest.raises(github.APIError) as error:
        github.GitHubClient(TOKEN, Transport(Replaced())).download_release_asset(72, target, len(DATA), DIGEST)
    assert target.read_bytes() == b'preserve replacement'
    assert TOKEN not in str(error.value)


def test_download_stream_timeout_is_sanitized_and_partial_file_removed(tmp_path):
    target = tmp_path / 'asset'
    class Interrupted(Response):
        def read(self, size):
            if self.body.tell():
                raise TimeoutError('private signed URL ' + TOKEN)
            return self.body.read(8)
    with pytest.raises(github.APIError) as error:
        github.GitHubClient(TOKEN, Transport(Interrupted(body=DATA))).download_release_asset(
            72, target, len(DATA), DIGEST)
    assert not target.exists()
    assert not error.value.uncertain
    assert TOKEN not in str(error.value)


def test_download_rechecks_stored_bytes_before_return(tmp_path, monkeypatch):
    target = tmp_path / 'asset'
    original_fsync = github.os.fsync
    def tamper_after_flush(descriptor):
        original_fsync(descriptor)
        target.write_bytes(b'x' * len(DATA))
    monkeypatch.setattr(github.os, 'fsync', tamper_after_flush)
    with pytest.raises(github.APIError):
        github.GitHubClient(TOKEN, Transport(Response(200, DATA))).download_release_asset(
            72, target, len(DATA), DIGEST)
    assert not target.exists()


def test_download_directory_replacement_is_not_returned_as_verified(tmp_path):
    parent = tmp_path / 'directory'
    parent.mkdir()
    moved = tmp_path / 'moved'
    target = parent / 'asset'
    class DirectoryReplaced(Response):
        def read(self, size):
            if self.body.tell() == 0:
                parent.rename(moved)
                parent.mkdir()
                target.write_bytes(b'unverified replacement')
            return self.body.read(size)
    with pytest.raises(github.APIError):
        github.GitHubClient(TOKEN, Transport(DirectoryReplaced(body=DATA))).download_release_asset(
            72, target, len(DATA), DIGEST)
    assert target.read_bytes() == b'unverified replacement'
    assert not (moved / 'asset').exists()


@pytest.mark.parametrize('status', [401, 403, 422, 500, 503])
def test_upload_failure_never_retries_or_overwrites(tmp_path, status):
    source = tmp_path / 'archive'
    source.write_bytes(DATA)
    transport = Transport(Response(status, b'private response body'))
    with pytest.raises(github.APIError) as error:
        github.GitHubClient(TOKEN, transport).upload(42, 'runtime.oci', source, len(DATA), DIGEST)
    assert len(transport.calls) == 1
    assert error.value.status == status
    assert error.value.uncertain is (status >= 500)
    assert source.read_bytes() == DATA


@pytest.mark.parametrize('size', [-1, True, 4 * 1024 ** 3 + 1])
def test_invalid_transfer_bounds_do_not_send_requests(tmp_path, size):
    transport = Transport()
    with pytest.raises(github.ReleaseError):
        github.GitHubClient(TOKEN, transport).download_actions_artifact(72, tmp_path / 'asset', size)
    assert not transport.calls


def test_actions_archive_has_size_cap_and_strips_auth(tmp_path):
    target = tmp_path / 'artifact.zip'
    transport = Transport(Response(302, headers={'Location':
        'https://productionresultssa9.blob.core.windows.net/artifact?sig=synthetic'}), Response(200, DATA))
    assert github.GitHubClient(TOKEN, transport).download_actions_artifact(17, target) == target
    assert transport.calls[0].full_url.endswith('/actions/artifacts/17/zip')
    assert 'authorization' not in headers(transport.calls[1])
    assert target.read_bytes() == DATA
    with pytest.raises(github.APIError):
        github.GitHubClient(TOKEN, Transport(Response(200, DATA))).download_actions_artifact(
            17, tmp_path / 'too-big.zip', max_bytes=10)
    assert not (tmp_path / 'too-big.zip').exists()


@pytest.mark.parametrize('redirects', [1, 2])
def test_actions_download_negotiates_json_then_binary_without_forwarding_token(tmp_path, redirects):
    location = 'https://productionresultssa18.blob.core.windows.net/artifact?sig=synthetic'
    def actions_endpoint(request):
        if headers(request).get('accept') != 'application/vnd.github+json':
            return Response(415, b'unsupported synthetic media type')
        return Response(302, headers={'Location': location})
    transport = Transport(actions_endpoint,
        *(Response(307, headers={'Location': location}) for _ in range(redirects - 1)),
        Response(200, DATA, {'Content-Length': str(len(DATA))}))
    target = tmp_path / 'artifact.zip'
    github.GitHubClient(TOKEN, transport).download_actions_artifact(17, target)
    assert target.read_bytes() == DATA
    assert headers(transport.calls[0])['authorization'] == 'Bearer ' + TOKEN
    assert headers(transport.calls[0])['accept'] == 'application/vnd.github+json'
    for request in transport.calls[1:]:
        assert headers(request)['accept'] == 'application/octet-stream'
        assert 'authorization' not in headers(request)
        assert 'proxy-authorization' not in headers(request)


def test_actions_415_stops_without_retry_or_target(tmp_path):
    transport = Transport(Response(415, b'synthetic private error body'))
    target = tmp_path / 'artifact.zip'
    with pytest.raises(github.APIError) as caught:
        github.GitHubClient(TOKEN, transport).download_actions_artifact(17, target)
    assert caught.value.status == 415
    assert len(transport.calls) == 1
    assert not target.exists()
    assert 'private' not in str(caught.value)


@pytest.mark.parametrize('value', [True, -1, 0, '42'])
def test_invalid_ids_do_not_call_transport(value, tmp_path):
    transport = Transport()
    client = github.GitHubClient(TOKEN, transport)
    with pytest.raises(github.ReleaseError):
        client.download_actions_artifact(value, tmp_path / 'asset')
    assert not transport.calls
