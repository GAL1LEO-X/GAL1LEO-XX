import json
import re
import time
from urllib.parse import quote, urlsplit
import httpx

from .config import secret
from .gateway_transport import DEADLINE_EXTENSION, GatewayTransport


class GatewayUnavailable(Exception):
    def __init__(self, message, *, status_code=None, provider_error_kind=None):
        self.status_code=status_code
        self.provider_error_kind=provider_error_kind
        super().__init__(message)


class GatewayNotSent(GatewayUnavailable):
    """The request could not reach dispatch; never inferred from an HTTP status.

    Only a local disablement, pool acquisition or connection establishment
    failure proves this boundary. Read/write timeouts and protocol failures can
    follow execution and remain GatewayUnavailable with an uncertain outcome.
    """


READ_REJECTIONS = {
    'invalid_request': ('INVALID_ARGUMENT', 'The provider rejected the read request parameters.'),
    'permission_denied': ('PROVIDER_PERMISSION_DENIED', 'The provider denied this read request; this is not an OAuth consent request.'),
    'resource_not_found': ('PROVIDER_RESOURCE_NOT_FOUND', 'The requested resource was not found by the provider; this does not establish deletion.'),
    'invalid_message_identity': ('INVALID_ARGUMENT', 'The provider rejected the requested message identity; check the chat and message references.'),
    'message_identity_mismatch': ('MESSAGE_IDENTITY_MISMATCH', 'The provider could not verify the stored message identity; no message returned.'),
}


class GatewayReadRejected(GatewayUnavailable):
    """A recognized read refusal, never evidence about a write's outcome."""

    def __init__(self, kind, status_code):
        self.error_code, message = READ_REJECTIONS[kind]
        super().__init__(message, status_code=status_code, provider_error_kind=kind)


# Exact, content-free Nest responses emitted by the pinned GOWS identity guard.
# HTTP 422 alone also covers session/engine/capability failures: never guess.
MESSAGE_IDENTITY_REJECTIONS = {
    'Invalid message identity': 'invalid_message_identity',
    'Invalid serialized message identity': 'invalid_message_identity',
    'Message identity does not match the requested chat': 'invalid_message_identity',
    'Invalid message participant': 'invalid_message_identity',
    'Invalid WhatsApp identifier': 'invalid_message_identity',
    'Stored message does not match the requested message identity': 'message_identity_mismatch',
}


class GroupPermissionDenied(GatewayUnavailable):
    """A WhatsApp group permission refusal, distinct from an OAuth scope failure."""

    def __init__(self, *, status_code):
        super().__init__(
            "WhatsApp denied access to this group's pending join requests. "
            "The connected account must be a group administrator.",
            status_code=status_code,
        )


def provider_error_kind(response, exception):
    """Bounded classification only; never return upstream text or infer effects."""
    if response is None:
        return 'transport_failure'
    if isinstance(exception, (ValueError, RecursionError)):
        return 'invalid_provider_response'
    if len(response.content) > 65536:
        return 'provider_failure'
    try: payload = response.json()
    except (ValueError, RecursionError): return 'invalid_provider_response'
    if (response.status_code == 422 and isinstance(payload, dict)
            and type(payload.get('statusCode')) is int and payload['statusCode'] == 422
            and payload.get('error') == 'Unprocessable Entity'
            and isinstance(payload.get('message'), str)):
        kind = MESSAGE_IDENTITY_REJECTIONS.get(payload['message'])
        if kind:
            return kind
    upstream = payload.get('exception') if isinstance(payload, dict) else None
    if not isinstance(upstream, dict): return 'provider_failure'
    code, detail = upstream.get('code'), upstream.get('details')
    if type(code) is int and code == 3: return 'invalid_request'
    if type(code) is int and code == 7: return 'permission_denied'
    if type(code) is int and code == 14: return 'provider_temporarily_unavailable'
    if type(code) is int and code == 2 and isinstance(detail, str):
        if re.fullmatch(r'info query returned status 404: (?:item-not-found|not-found)', detail):
            return 'resource_not_found'
        if detail == 'info query returned status 403: forbidden':
            return 'permission_denied'
    return 'provider_failure'


def _join_requests_forbidden(method, path, response):
    # GOWS wraps WhatsApp's IQ 403 in gRPC UNKNOWN and WAHA HTTP 500.
    # Do not turn unrelated failures, gateway API-key refusals, or writes
    # into group permission errors. Never expose/log the upstream payload.
    if (method != 'GET' or response.status_code != 500
            or not re.fullmatch(r'/api/[^/]+/groups/[^/]+/participants/join-requests', path)
            or len(response.content) > 65536):
        return False
    try:
        payload = response.json()
    except (ValueError, RecursionError):
        return False
    exception = payload.get('exception') if isinstance(payload, dict) else None
    if not isinstance(exception, dict) or type(exception.get('code')) is not int or exception['code'] != 2:
        return False
    reason = 'info query returned status 403: forbidden'
    return (exception.get('details') == reason
            or exception.get('message') == '2 UNKNOWN: ' + reason)


class Waha:
    def __init__(self, settings):
        self.settings = settings
        key = secret(settings.waha_key_file) if settings.waha_key_file else ""
        self.client = httpx.Client(base_url=settings.waha_url, headers={"X-Api-Key":key},
                                   timeout=15, follow_redirects=False, trust_env=False,
                                   transport=GatewayTransport())
        self.session = quote(settings.session, safe="")
        self.diagnostics = None

    def request(self, method, path, **kwargs):
        if not self.settings.live_account_enabled:
            raise GatewayNotSent("Account linking is not enabled; no provider request made")
        started=time.monotonic()
        result = None
        try:
            result = self.client.request(method,path,**kwargs)
            result.raise_for_status()
            if not result.content:
                # HTTP completion is transport evidence only. Never invent a
                # provider acceptance flag that could satisfy an A/B contract
                # or be reported as an explicitly acknowledged mutation.
                return {}
            # Nest returns Promise<string> as text for these two controllers.
            # Keep this exception scoped to the pinned routes; arbitrary text
            # on other routes is still an invalid provider response.
            invite_route = (
                method == 'GET' and re.fullmatch(r'/api/[^/]+/groups/[^/]+/invite-code', path)
                or method == 'POST' and re.fullmatch(r'/api/[^/]+/groups/[^/]+/invite-code/revoke', path))
            if invite_route and result.headers.get('content-type', '').split(';')[0].strip().lower() in ('text/plain', 'text/html'):
                code = result.text
                if len(result.content) > 4096 or not re.fullmatch(r'(?:https://chat\.whatsapp\.com/)?[A-Za-z0-9_-]{1,128}', code):
                    raise ValueError('Invalid invite code response')
                return code
            return result.json()
        except (httpx.HTTPError, ValueError, RecursionError) as exc:
            response = exc.response if isinstance(exc, httpx.HTTPStatusError) else result
            status = response.status_code if response is not None else None
            kind = provider_error_kind(response, exc)
            group_denied = response is not None and _join_requests_forbidden(method, path, response)
            is_read = (method in ('GET', 'HEAD') or
                       method == 'POST' and path in {
                           f'/api/{self.session}/chats/overview',
                           f'/api/{self.session}/channels/search/by-view',
                           f'/api/{self.session}/channels/search/by-text',
                       })
            identity_rejected = (method == 'GET'
                and re.fullmatch(r'/api/[^/]+/chats/[^/]+/messages/[^/]+', path)
                and kind in {'invalid_message_identity', 'message_identity_mismatch'})
            read_rejected = (is_read and status == 500
                             and kind in {'invalid_request', 'permission_denied', 'resource_not_found'})
            rejection = GatewayReadRejected(kind, status) if identity_rejected or read_rejected else None
            if self.diagnostics:
                self.diagnostics.emit('gateway.failed','error',method=method,
                    status=status or 0,
                    exception=type(exc).__name__,duration_ms=(time.monotonic()-started)*1000,
                    provider_error_kind=kind,
                    error_code=('GROUP_PERMISSION_DENIED' if group_denied else
                                rejection.error_code if rejection else 'GATEWAY_REQUEST'))
            if group_denied:
                raise GroupPermissionDenied(status_code=status) from None
            if rejection:
                raise rejection from None
            if isinstance(exc, (httpx.PoolTimeout, httpx.ConnectTimeout, httpx.ConnectError)):
                raise GatewayNotSent("WAHA connection unavailable; no provider request made") from None
            message = ("WAHA read request failed" if is_read
                       else "WAHA request failed; outbound outcome may be uncertain")
            raise GatewayUnavailable(message, status_code=status, provider_error_kind=kind) from None

    def status(self):
        data = self.request("GET", f"/api/sessions/{self.session}")
        if not isinstance(data, dict) or not isinstance(data.get('status'), str):
            raise GatewayUnavailable('Unexpected WAHA session status schema')
        # New provider states must not become a claim of connectivity or raw
        # diagnostic text. The connection poll records this current observation.
        known = {'WORKING', 'STOPPED', 'STARTING', 'SCAN_QR_CODE', 'FAILED',
                 'PASSKEY_REQUIRED', 'PASSKEY_CONFIRMATION_REQUIRED'}
        return data['status'] if data['status'] in known else 'UNKNOWN'

    def ab_operations(self):
        from .ab_operations import contract_operations
        value = self.request('GET', '/api/contacts/ab-capabilities',
                             params={'session': self.settings.session}, timeout=15)
        try:
            return contract_operations(value)
        except ValueError as exc:
            raise GatewayUnavailable(str(exc)) from None

    def chat_archive_state(self, chat_id):
        return self.request('GET', f'/api/{self.session}/chats/{quote(chat_id, safe="")}/archive-state',
                            timeout=15)

    def pairing_qr(self):
        if not self.settings.link_enabled:
            raise GatewayUnavailable('Pairing is disabled')
        try:
            with self.client.stream('GET',f'/api/{self.session}/auth/qr',params={'format':'image'},headers={'Accept':'image/png'}) as response:
                response.raise_for_status()
                data=bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data)>512*1024: raise GatewayUnavailable('Invalid QR response')
            if not data.startswith(b'\x89PNG\r\n\x1a\n'): raise GatewayUnavailable('Invalid QR response')
            return bytes(data)
        except httpx.HTTPError:
            raise GatewayUnavailable('QR is not available') from None

    def messages(self, chat_id, since, until, offset, limit=100):
        data = self.request("GET",f"/api/{self.session}/chats/{quote(chat_id,safe='')}/messages",
                            params={"limit":limit,"offset":offset,"downloadMedia":"false",
                                    "filter.timestamp.gte":since,"filter.timestamp.lte":until})
        if not isinstance(data,list):
            raise GatewayUnavailable("Unexpected WAHA message schema")
        return data

    @staticmethod
    def directory_page(data, limit, offset, key):
        if not isinstance(data,list) or len(data)>limit+1:
            raise GatewayUnavailable("Unexpected WAHA directory schema")
        rows=[]
        for entry in data[:limit]:
            if not isinstance(entry,dict):
                raise GatewayUnavailable("Unexpected WAHA directory entry")
            entry_id=entry.get("id")
            if isinstance(entry_id,dict):
                entry_id=entry_id.get("_serialized")
            if not isinstance(entry_id,str) or not entry_id:
                raise GatewayUnavailable("WAHA directory entry has no usable ID")
            row={"id":entry_id}
            for field in ("name","pushname","shortName","number"):
                if isinstance(entry.get(field),str):
                    row[field]=entry[field]
            if type(entry.get("unreadCount")) is int:
                row["unread_count"]=entry["unreadCount"]
            rows.append(row)
        return {key:rows,"next_offset":offset+limit if len(data)>limit else None,"source":"live_gateway"}

    def chats(self, limit=50, offset=0):
        data=self.request("GET",f"/api/{self.session}/chats/overview",params={"limit":limit+1,"offset":offset,"merge":"true"})
        return self.directory_page(data,limit,offset,"chats")

    def contacts(self, limit=50, offset=0):
        data=self.request("GET","/api/contacts/all",params={"session":self.settings.session,"limit":limit+1,"offset":offset,"sortBy":"id","sortOrder":"asc"})
        return self.directory_page(data,limit,offset,"contacts")

    def send(self, chat_id, text):
        if not self.settings.destination_allowed(chat_id):
            raise GatewayNotSent("Sending is disabled for this chat; no provider request made")
        return self.request("POST","/api/sendText",json={"session":self.settings.session,"chatId":chat_id,
                                                         "text":text,"linkPreview":False,"linkPreviewHighQuality":False})

    def attachment(self, media):
        if not self.settings.live_account_enabled:
            raise GatewayUnavailable("Account linking is not enabled")
        url = media.get("url", "")
        target, base = urlsplit(url), urlsplit(self.settings.waha_url)
        if (target.scheme,target.hostname,target.port) != (base.scheme,base.hostname,base.port) or target.username or target.fragment:
            raise ValueError("Media URL outside the configured WAHA origin")
        if not target.path.startswith("/api/files/") or ".." in target.path or "%" in target.path or "\\" in target.path:
            raise ValueError("Media path is not a WAHA attachment")
        from .media import decoded_gateway_chunks, _DownloadDeadline, _DownloadExpired
        deadline = _DownloadDeadline()
        try:
            with self.client.stream("GET",url,headers={'Accept-Encoding':'identity, gzip'},
                                    extensions={DEADLINE_EXTENSION: deadline}) as response:
                response.raise_for_status()
                data = bytearray()
                for chunk in decoded_gateway_chunks(response.iter_raw(),self.settings.max_attachment_bytes,
                        content_length=response.headers.get('content-length'),
                        content_encoding=response.headers.get('content-encoding','identity'), deadline=deadline):
                    data.extend(chunk)
        except _DownloadExpired:
            raise ValueError('Transfer time limit exceeded') from None
        except httpx.HTTPError:
            raise GatewayUnavailable("Attachment is currently unavailable from WAHA") from None
        return bytes(data)

    def attachment_to_file(self, media, target, max_bytes):
        url=media.get('url','')
        parsed,base=urlsplit(url),urlsplit(self.settings.waha_url)
        if (parsed.scheme,parsed.hostname,parsed.port)!=(base.scheme,base.hostname,base.port) or parsed.username or parsed.fragment:
            raise ValueError('Attachment URL outside configured gateway')
        if not parsed.path.startswith('/api/files/') or any(v in parsed.path for v in ('..','%','\\')):
            raise ValueError('Invalid gateway attachment path')
        if not self.settings.live_account_enabled:
            raise GatewayUnavailable('Account linking is not enabled')
        from .media import copy_bounded, decoded_gateway_chunks, _DownloadDeadline, _DownloadExpired
        deadline = _DownloadDeadline()
        try:
            with self.client.stream('GET',url,timeout=60,headers={'Accept-Encoding':'identity, gzip'},
                                    extensions={DEADLINE_EXTENSION: deadline}) as response:
                response.raise_for_status()
                chunks=decoded_gateway_chunks(response.iter_raw(),max_bytes,
                    content_length=response.headers.get('content-length'),
                    content_encoding=response.headers.get('content-encoding','identity'), deadline=deadline)
                return copy_bounded(chunks,target,max_bytes,deadline=deadline)
        except _DownloadExpired:
            raise ValueError('Transfer time limit exceeded') from None
        except httpx.HTTPError as exc:
            status=exc.response.status_code if isinstance(exc,httpx.HTTPStatusError) else None
            if self.diagnostics:
                self.diagnostics.emit('gateway.failed','warning',operation='attachment_download',
                    status=status or 0,exception=type(exc).__name__,error_code='GATEWAY_ATTACHMENT')
            raise GatewayUnavailable('Attachment download unavailable',status_code=status) from None

    def message(self, chat_id, message_id, download_media=False):
        return self.request('GET',f'/api/{self.session}/chats/{quote(chat_id,safe="")}/messages/{quote(message_id,safe="")}',
                            params={'downloadMedia':str(download_media).lower()})

    def phone_for_lid(self,lid):
        if not re.fullmatch(r'[0-9]{5,25}@lid',lid): raise ValueError('Invalid LID')
        result=self.request('GET',f'/api/{self.session}/lids/{quote(lid,safe="")}')
        if not isinstance(result,dict) or result.get('lid')!=lid:
            raise GatewayUnavailable('Unverified chat alias')
        phone=result.get('pn')
        if phone is None: return None
        if not isinstance(phone,str) or not re.fullmatch(r'[0-9]{5,20}@c\.us',phone):
            raise GatewayUnavailable('Invalid chat alias destination')
        return phone

    def history_chats(self, offset, limit=100):
        data=self.request('GET',f'/api/{self.session}/chats',params={'offset':offset,'limit':limit,'sortBy':'id','sortOrder':'asc'})
        if not isinstance(data,list) or len(data)>limit:
            raise GatewayUnavailable('Unexpected history chat page')
        return data

    def close(self):
        self.client.close()


class DisconnectedGateway:
    def status(self):
        return "NOT_LINKED"

    def messages(self, *args, **kwargs):
        raise GatewayNotSent("WhatsApp account is not linked; no provider request made")

    chats = messages
    contacts = messages
    request = messages

    def send(self, *args, **kwargs):
        raise GatewayNotSent("WhatsApp account is not linked; no provider request made")

    def attachment(self, *args, **kwargs):
        raise GatewayUnavailable("WhatsApp account is not linked")

    def close(self):
        pass

