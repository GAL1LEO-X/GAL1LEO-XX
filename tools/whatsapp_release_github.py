"""Small, non-retrying GitHub client for the repository's manual publisher.

The injectable transport is ``transport(request, *, timeout) -> response``.
Responses expose ``status``, ``headers``, ``read(size)`` and ``close()``; the
transport MUST NOT follow redirects. The default transport enforces this and
retains urllib's normal certificate validation and environment proxy handling.
No credentials are discovered here: the workflow caller supplies its token.
"""
from contextlib import contextmanager
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import urllib.error
import urllib.parse
import urllib.request

from whatsapp_release_common import ReleaseError, canonical_json

REPOSITORY = 'GAL1LEO-X/GAL1LEO-XX'
API_ORIGIN = 'https://api.github.com'
UPLOAD_ORIGIN = 'https://uploads.github.com'
REPO_PATH = '/repos/' + REPOSITORY
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_TRANSFER_BYTES = 4 * 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
MAX_REDIRECTS = 4
TIMEOUT_SECONDS = 120


def _safe_path(path):
    """Errors expose endpoint classes, never query values, signed URLs or refs."""
    if not isinstance(path, str):
        return '/invalid'
    parts = path.split('?', 1)[0].split('/')
    known = {'releases', 'assets', 'tags', 'actions', 'artifacts', 'runs',
             'workflows', 'commits', 'compare', 'zip', 'jobs', 'git', 'ref'}
    return '/' + '/'.join(part if part in known or part.isascii() and part.isdecimal()
                          else '{value}' for part in parts if part)[:200]


def _close(response):
    # A transport's close error must not replace a sanitized APIError with an
    # exception containing a signed URL, request header or response body.
    try:
        response.close()
    except Exception:
        pass


class APIError(ReleaseError):
    """Sanitized endpoint failure; uncertain writes require reconciliation."""

    def __init__(self, status, method, path, uncertain=False):
        self.status = status if type(status) is int else None
        self.method = method if method in ('GET', 'POST', 'PATCH') else 'INVALID'
        self.path = _safe_path(path)
        self.uncertain = bool(uncertain)
        super().__init__(f'GitHub {self.method} {self.path}: '
                         f'status={self.status if self.status is not None else "unavailable"}; '
                         f'uncertain={str(self.uncertain).lower()}')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _DefaultTransport:
    def __init__(self):
        self._opener = urllib.request.build_opener(_NoRedirect())

    def __call__(self, request, *, timeout):
        try:
            return self._opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as response:
            # HTTPError is a response with a body. Never copy its reason/body to
            # errors and never allow urllib to follow an authenticated redirect.
            return response


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def _invalid_number(_value):
    raise ValueError('Non-finite JSON number')


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('Non-finite JSON number')
    return number


def _validate_size(size):
    if type(size) is not int or not 0 <= size <= MAX_TRANSFER_BYTES:
        raise ReleaseError('Invalid expected transfer size')


def _validate_hash(digest):
    if not isinstance(digest, str) or re.fullmatch(r'[0-9a-f]{64}', digest) is None:
        raise ReleaseError('Invalid expected SHA256')


def _validate_id(value):
    if type(value) is not int or value <= 0:
        raise ReleaseError('Invalid GitHub object ID')


@contextmanager
def _parent_fd(path):
    """Walk each ancestor by descriptor without following symbolic links."""
    path = Path(path)
    if not path.name or '..' in path.parts:
        raise ReleaseError('Unsafe transfer file path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open('/' if path.is_absolute() else '.', flags)
    try:
        ancestors = path.parts[1:-1] if path.is_absolute() else path.parts[:-1]
        for part in ancestors:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        yield descriptor, path.name
    finally:
        os.close(descriptor)


def _fingerprint(descriptor):
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        raise ReleaseError('Transfer file must be regular')
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _UploadStream:
    """Hash the bytes actually read by the HTTP transport, with a hard limit."""
    def __init__(self, source, expected_bytes, expected_sha256):
        self._source = source
        self._size = expected_bytes
        self._expected = expected_sha256
        self._hash = hashlib.sha256()
        self._count = 0

    def read(self, size=-1):
        size = min(CHUNK_BYTES, self._size - self._count + 1,
                   size if size is not None and size >= 0 else CHUNK_BYTES)
        data = self._source.read(size)
        self._count += len(data)
        if self._count > self._size:
            raise ReleaseError('Upload source changed')
        self._hash.update(data)
        if not data and not self.valid():
            raise ReleaseError('Upload source changed')
        return data

    def valid(self):
        return self._count == self._size and hmac.compare_digest(
            self._hash.hexdigest(), self._expected)


class GitHubClient:
    def __init__(self, token, transport=None):
        if (not isinstance(token, str) or not token or len(token) > 8192
                or any(ord(character) <= 32 or ord(character) >= 127 for character in token)):
            raise ReleaseError('An explicit GitHub token is required')
        self.__token = token
        self._transport = transport if transport is not None else _DefaultTransport()

    @staticmethod
    def _path(path, method='GET'):
        if path == '' and method == 'GET':
            return path  # Read this repository metadata, including default_branch.
        if (not isinstance(path, str) or not path.startswith('/')
                or any(ord(character) <= 32 or ord(character) >= 127 for character in path)
                or '\\' in path or '#' in path or len(path) > 4096
                or re.search(r'%(?![0-9a-fA-F]{2})', path)):
            raise ReleaseError('Invalid GitHub repository path')
        parsed = urllib.parse.urlsplit(path)
        decoded = urllib.parse.unquote(parsed.path)
        allowed_git_read = method == 'GET' and (
            re.fullmatch(r'/git/ref/tags/.+', decoded) is not None
            or re.fullmatch(r'/git/(?:tags|trees)/[0-9a-f]{40}', decoded) is not None)
        if (parsed.scheme or parsed.netloc or decoded.startswith('//')
                or '\\' in decoded or any(part in ('.', '..') for part in decoded.split('/'))
                or any(ord(character) < 32 or ord(character) == 127 for character in decoded)
                or (decoded.split('/')[1] not in ('releases', 'actions', 'commits', 'compare')
                    and not allowed_git_read)):
            raise ReleaseError('Invalid GitHub repository path')
        return path

    def _request(self, method, url, path, *, data=None, authenticated=True,
                 accept='application/vnd.github+json', content_type=None, content_length=None):
        headers = {'Accept': accept, 'User-Agent': 'whatsapp-actions-publisher',
                   'X-GitHub-Api-Version': '2022-11-28', 'Accept-Encoding': 'identity'}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + self.__token
        if content_type is not None:
            headers['Content-Type'] = content_type
        if content_length is not None:
            headers['Content-Length'] = str(content_length)
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            response = self._transport(request, timeout=TIMEOUT_SECONDS)
        except Exception:
            raise APIError(None, method, path, method != 'GET') from None
        try:
            status = response.status
            if type(status) is not int or not 100 <= status <= 599:
                raise ValueError('Invalid HTTP status')
            # Detect an incorrectly configured injected opener, too. This is
            # not a substitute for disabling redirects at transport level.
            if hasattr(response, 'geturl') and response.geturl() != url:
                raise ValueError('Transport followed a redirect')
        except Exception:
            _close(response)
            raise APIError(None, method, path, method != 'GET') from None
        return response

    @staticmethod
    def _check_status(response, method, path, expected):
        status = response.status
        if status not in expected:
            raise APIError(status, method, path,
                           method != 'GET' and (status >= 500 or status == 408 or 300 <= status < 400))

    @staticmethod
    def _read_json(response, method, path):
        try:
            raw = bytearray()
            while True:
                chunk = response.read(min(CHUNK_BYTES, MAX_JSON_BYTES + 1 - len(raw)))
                if not isinstance(chunk, bytes):
                    raise ValueError('Invalid response stream')
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > MAX_JSON_BYTES:
                    raise ValueError('JSON response too large')
            value = json.loads(raw.decode('utf-8'), object_pairs_hook=_json_pairs,
                               parse_constant=_invalid_number, parse_float=_finite_float)
            if not isinstance(value, (dict, list)):
                raise ValueError('Invalid API JSON document')
            return value
        except Exception:
            raise APIError(response.status, method, path, method != 'GET') from None

    def _json(self, method, path, value=None):
        path = self._path(path, method)
        data = None
        if method != 'GET':
            if not isinstance(value, dict):
                raise ReleaseError('GitHub JSON body must be an object')
            try:
                data = canonical_json(value)
            except Exception:
                raise ReleaseError('Invalid GitHub JSON body') from None
            if len(data) > MAX_JSON_BYTES:
                raise ReleaseError('GitHub JSON body too large')
        response = self._request(method, API_ORIGIN + REPO_PATH + path, path, data=data,
                                 content_type='application/json' if data is not None else None,
                                 content_length=len(data) if data is not None else None)
        try:
            self._check_status(response, method, path, {200} if method != 'POST' else {200, 201})
            return self._read_json(response, method, path)
        finally:
            _close(response)

    def get(self, path):
        return self._json('GET', path)

    def post(self, path, value):
        return self._json('POST', path, value)

    def patch(self, path, value):
        return self._json('PATCH', path, value)

    def upload(self, release_id, name, path, expected_bytes, expected_sha256):
        _validate_id(release_id)
        _validate_size(expected_bytes)
        _validate_hash(expected_sha256)
        if not isinstance(name, str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,199}', name) is None:
            raise ReleaseError('Invalid Release asset name')
        endpoint = f'/releases/{release_id}/assets'
        url = UPLOAD_ORIGIN + REPO_PATH + endpoint + '?' + urllib.parse.urlencode({'name': name})
        started = False
        response = None
        try:
            with _parent_fd(path) as (parent, basename):
                descriptor = os.open(basename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                     dir_fd=parent)
                with os.fdopen(descriptor, 'rb') as source:
                    before = _fingerprint(source.fileno())
                    if before[2] != expected_bytes:
                        raise ReleaseError('Upload source size differs')
                    digest = hashlib.sha256()
                    preflight_count = 0
                    while chunk := source.read(min(CHUNK_BYTES, expected_bytes - preflight_count + 1)):
                        preflight_count += len(chunk)
                        if preflight_count > expected_bytes:
                            raise ReleaseError('Upload source changed')
                        digest.update(chunk)
                    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
                        raise ReleaseError('Upload source SHA256 differs')
                    if _fingerprint(source.fileno()) != before:
                        raise ReleaseError('Upload source changed')
                    source.seek(0)
                    stream = _UploadStream(source, expected_bytes, expected_sha256)
                    started = True
                    response = self._request('POST', url, endpoint, data=stream,
                                             content_type='application/octet-stream',
                                             content_length=expected_bytes)
                    self._check_status(response, 'POST', endpoint, {201})
                    if not stream.valid() or _fingerprint(source.fileno()) != before:
                        raise APIError(response.status, 'POST', endpoint, True)
                    result = self._read_json(response, 'POST', endpoint)
                    if (not isinstance(result, dict) or type(result.get('id')) is not int
                            or result['id'] <= 0 or result.get('name') != name
                            or type(result.get('size')) is not int or result['size'] != expected_bytes
                            or result.get('state') != 'uploaded'):
                        raise APIError(response.status, 'POST', endpoint, True)
                    return result
        except APIError:
            raise
        except Exception:
            if started:
                raise APIError(None, 'POST', endpoint, True) from None
            raise ReleaseError('Upload source is not a stable verified regular file') from None
        finally:
            if response is not None:
                _close(response)

    @staticmethod
    def _signed_url(url):
        if (not isinstance(url, str) or len(url) > 16384 or '\\' in url
                or any(ord(character) <= 32 or ord(character) >= 127 for character in url)):
            raise ValueError('Invalid download redirect')
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        if (parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None
                or parsed.port not in (None, 443) or parsed.fragment or not parsed.path.startswith('/')
                or not host or host.endswith('.')):
            raise ValueError('Invalid download redirect')
        github_host = host in {'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
        actions_host = re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.actions\.githubusercontent\.com', host)
        azure_host = re.fullmatch(r'productionresultssa[0-9]+\.blob\.core\.windows\.net', host)
        if not (github_host or actions_host or azure_host):
            raise ValueError('Unapproved download redirect host')
        return url

    def _download(self, endpoint, target, *, max_bytes, expected_bytes=None, expected_sha256=None,
                  api_accept='application/octet-stream'):
        response = None
        try:
            url = API_ORIGIN + REPO_PATH + endpoint
            for attempt in range(MAX_REDIRECTS + 1):
                # Actions negotiates its API redirect as JSON; storage and Release assets use binary.
                response = self._request('GET', url, endpoint, authenticated=attempt == 0,
                                         accept=api_accept if attempt == 0 else 'application/octet-stream')
                if response.status in (301, 302, 303, 307, 308):
                    if attempt == MAX_REDIRECTS:
                        raise APIError(response.status, 'GET', endpoint)
                    try:
                        url = self._signed_url(response.headers.get('Location'))
                    except Exception:
                        raise APIError(response.status, 'GET', endpoint) from None
                    _close(response)
                    response = None
                    continue
                self._check_status(response, 'GET', endpoint, {200})
                break
            content_length = response.headers.get('Content-Length')
            if content_length is not None:
                if (not re.fullmatch(r'[0-9]+', content_length) or int(content_length) > max_bytes
                        or expected_bytes is not None and int(content_length) != expected_bytes):
                    raise APIError(response.status, 'GET', endpoint)
                content_length = int(content_length)
            if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                raise APIError(response.status, 'GET', endpoint)
            with _parent_fd(target) as (parent, basename):
                descriptor = os.open(basename, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                                     | os.O_CLOEXEC, 0o600, dir_fd=parent)
                identity = os.fstat(descriptor)
                success = False
                try:
                    with os.fdopen(descriptor, 'w+b') as output:
                        _fingerprint(output.fileno())
                        count = 0
                        digest = hashlib.sha256()
                        while True:
                            chunk = response.read(min(CHUNK_BYTES, max_bytes - count + 1))
                            if not isinstance(chunk, bytes):
                                raise ValueError('Invalid download stream')
                            if not chunk:
                                break
                            count += len(chunk)
                            if count > max_bytes:
                                raise ValueError('Download exceeded size limit')
                            digest.update(chunk)
                            output.write(chunk)
                        if (expected_bytes is not None and count != expected_bytes
                                or content_length is not None and count != content_length
                                or expected_sha256 is not None and not hmac.compare_digest(
                                    digest.hexdigest(), expected_sha256)):
                            raise ValueError('Download integrity check failed')
                        output.flush()
                        os.fsync(output.fileno())
                        output.seek(0)
                        stored_digest = hashlib.sha256()
                        stored_count = 0
                        while chunk := output.read(min(CHUNK_BYTES, count - stored_count + 1)):
                            stored_count += len(chunk)
                            if stored_count > count:
                                raise ValueError('Download destination changed')
                            stored_digest.update(chunk)
                        if stored_count != count or not hmac.compare_digest(
                                stored_digest.hexdigest(), digest.hexdigest()):
                            raise ValueError('Download destination changed')
                        current = os.stat(basename, dir_fd=parent, follow_symlinks=False)
                        if ((current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)
                                or _fingerprint(output.fileno())[2] != count):
                            raise ValueError('Download destination changed')
                        # A directory rename must not make the returned path
                        # designate a different object from the verified fd.
                        with _parent_fd(target) as (current_parent, current_name):
                            visible = os.stat(current_name, dir_fd=current_parent, follow_symlinks=False)
                            if ((visible.st_dev, visible.st_ino) != (identity.st_dev, identity.st_ino)
                                    or not stat.S_ISREG(visible.st_mode)):
                                raise ValueError('Download destination changed')
                    success = True
                finally:
                    if not success:
                        try:
                            current = os.stat(basename, dir_fd=parent, follow_symlinks=False)
                            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                                os.unlink(basename, dir_fd=parent)
                        except FileNotFoundError:
                            pass
            return Path(target)
        except APIError:
            raise
        except Exception:
            raise APIError(response.status if response is not None else None, 'GET', endpoint) from None
        finally:
            if response is not None:
                _close(response)

    def download_release_asset(self, asset_id, target, expected_bytes, expected_sha256):
        _validate_id(asset_id)
        _validate_size(expected_bytes)
        _validate_hash(expected_sha256)
        return self._download(f'/releases/assets/{asset_id}', target, max_bytes=expected_bytes,
                              expected_bytes=expected_bytes, expected_sha256=expected_sha256)

    def download_actions_artifact(self, artifact_id, target, max_bytes=MAX_TRANSFER_BYTES):
        _validate_id(artifact_id)
        _validate_size(max_bytes)
        return self._download(f'/actions/artifacts/{artifact_id}/zip', target, max_bytes=max_bytes,
                              api_accept='application/vnd.github+json')
