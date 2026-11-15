from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
import re
import tomllib


MCP_SCOPES = ('whatsapp:read', 'whatsapp:events', 'whatsapp:send')


@dataclass(frozen=True)
class Settings:
    database: Path
    public_url: str
    issuer: str
    owner_subject: str
    webhook_secret_file: Path
    encryption_key_file: Path
    jwks_url: str = ""
    public_key_file: Path | None = None
    waha_url: str = "http://127.0.0.1:8821"
    waha_key_file: Path | None = None
    session: str = "default"
    live_account_enabled: bool = False
    send_enabled: bool = False
    send_chat_ids: list[str] = field(default_factory=list)
    allow_all_destinations: bool = False
    account_actions_enabled: bool = False
    callback_hosts: list[str] = field(default_factory=list)
    allowed_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1:*", "localhost:*"])
    subscription_ttl: int = 86400
    max_callback_attempts: int = 8
    poll_seconds: int = 60
    max_attachment_bytes: int = 512 * 1024 * 1024
    media_cache_bytes: int = 4 * 1024 * 1024 * 1024
    media_ttl_seconds: int = 3600
    media_gateway_origin: str = "http://10.0.2.2:8820"
    event_max_age_seconds: int = 86400
    listen_port: int = 8820
    profile_name: str = 'WhatsApp'
    oauth_client_ids: list[str] = field(default_factory=list)
    # Local resource policy shared by this tenant's admitted MCP clients.
    # Its provenance/freshness is an administrative preflight, not IdP discovery.
    oauth_allowed_scopes: list[str] = field(default_factory=lambda: list(MCP_SCOPES))
    # Explicit setup choice for one complete consent challenge. Empty retains
    # incremental consent; never grants scopes missing from a signed token.
    oauth_consent_scopes: list[str] = field(default_factory=list)
    state_identity_file: Path | None = None
    admin_enabled: bool = False
    admin_broker_socket: Path | None = None
    admin_broker_instance: str = ''
    link_enabled: bool = False
    link_client_id: str = ''
    link_authorize_url: str = ''
    link_token_url: str = ''
    diagnostics_enabled: bool = True
    diagnostics_max_bytes: int = 5 * 1024 * 1024
    diagnostics_backups: int = 4
    transcription_socket: Path | None = None
    transcription_server_uid: int | None = None

    def __post_init__(self):
        if self.transcription_socket is not None:
            path = self.transcription_socket
            if (not isinstance(path, Path) or not path.is_absolute() or '..' in path.parts
                    or '\x00' in str(path) or len(str(path).encode()) > 100
                    or type(self.transcription_server_uid) is not int or self.transcription_server_uid < 0):
                raise ValueError('Transcription requires a fixed local socket and pinned worker UID')
        elif self.transcription_server_uid is not None:
            raise ValueError('Transcription worker UID requires a socket')
        for value in (self.public_url, self.issuer):
            u = urlsplit(value)
            if u.scheme != "https" or not u.hostname or u.username or u.query or u.fragment:
                raise ValueError("public_url and issuer must be canonical HTTPS URLs")
        if self.public_url.endswith("/"):
            raise ValueError("public_url must have no trailing slash")
        if urlsplit(self.public_url).path:
            raise ValueError("public_url must identify the HTTPS origin, without a path")
        if not self.owner_subject:
            raise ValueError("owner_subject is required for single-account isolation")
        if self.state_identity_file is not None:
            if not isinstance(self.state_identity_file,Path) or self.state_identity_file.resolve() == self.database.resolve():
                raise ValueError('state_identity_file must be a separate identity file, not the database')
        if not 65536 <= self.diagnostics_max_bytes <= 50*1024*1024 or not 1 <= self.diagnostics_backups <= 10:
            raise ValueError('Invalid diagnostic log rotation limits')
        if not 1024 <= self.listen_port <= 65535:
            raise ValueError('Invalid bridge listen port')
        if not self.profile_name or len(self.profile_name)>100 or any(ord(c)<32 for c in self.profile_name):
            raise ValueError('Invalid connection profile name')
        if not isinstance(self.oauth_client_ids,list) or not self.oauth_client_ids:
            raise ValueError('oauth_client_ids is required: configure a non-empty list of registered MCP client IDs')
        if any(not isinstance(v,str) or not v or len(v)>200 for v in self.oauth_client_ids):
            raise ValueError('Invalid OAuth client IDs')
        if (not isinstance(self.oauth_allowed_scopes,list)
                or any(not isinstance(v,str) or v not in MCP_SCOPES for v in self.oauth_allowed_scopes)
                or len(set(self.oauth_allowed_scopes)) != len(self.oauth_allowed_scopes)
                or 'whatsapp:read' not in self.oauth_allowed_scopes):
            raise ValueError('oauth_allowed_scopes requires read and unique supported MCP scopes')
        if (not isinstance(self.oauth_consent_scopes,list)
                or any(not isinstance(scope,str) or scope not in self.oauth_allowed_scopes for scope in self.oauth_consent_scopes)
                or len(set(self.oauth_consent_scopes))!=len(self.oauth_consent_scopes)):
            raise ValueError('oauth_consent_scopes must be unique and within oauth_allowed_scopes')
        if type(self.admin_enabled) is not bool:
            raise ValueError('Administration requires an explicit boolean setting')
        if self.admin_broker_socket is not None:
            path = self.admin_broker_socket
            if (not self.admin_enabled or not isinstance(path, Path) or not path.is_absolute()
                    or len(path.parts) < 3 or path.parts[1] != 'run' or '..' in path.parts
                    or '\x00' in str(path) or len(str(path).encode()) > 100):
                raise ValueError('Administrative broker requires an enabled panel and a fixed socket below /run')
            if (not isinstance(self.admin_broker_instance, str)
                    or re.fullmatch('[a-z][a-z0-9-]{0,47}', self.admin_broker_instance) is None):
                raise ValueError('Administrative broker requires its explicitly delegated instance slug')
        elif self.admin_broker_instance != '':
            raise ValueError('Administrative broker instance requires a socket')
        if self.link_enabled and not self.live_account_enabled:
            raise ValueError('Pairing requires an enabled gateway')
        if self.link_enabled or self.admin_enabled:
            if not self.link_client_id:
                raise ValueError('The owner portal requires a dedicated OAuth client')
            issuer=urlsplit(self.issuer)
            for endpoint in (self.link_authorize_url,self.link_token_url):
                u=urlsplit(endpoint)
                if (u.scheme,u.netloc)!=(issuer.scheme,issuer.netloc) or u.username or u.query or u.fragment or not u.path:
                    raise ValueError('Pairing OAuth endpoints must belong to the configured issuer')
        if bool(self.jwks_url) == bool(self.public_key_file):
            raise ValueError("Configure exactly one JWKS URL or RSA public key file")
        if self.jwks_url and not self.jwks_url.startswith("https://"):
            raise ValueError("JWKS requires HTTPS")
        waha = urlsplit(self.waha_url)
        if waha.scheme not in ("http","https") or not waha.hostname or waha.username or waha.query or waha.fragment or waha.path:
            raise ValueError("waha_url must be an HTTP origin without path or credentials")
        if self.live_account_enabled and not self.waha_key_file:
            raise ValueError("Live WAHA requires a key file")
        if self.send_enabled and (not self.live_account_enabled or not (self.send_chat_ids or self.allow_all_destinations)):
            raise ValueError("Real sends require live account and explicit chat allowlist")
        if self.account_actions_enabled and not self.live_account_enabled:
            raise ValueError("Account actions require a linked account")
        if not 60 <= self.subscription_ttl <= 86400:
            raise ValueError("subscription_ttl must be 60..86400 seconds")
        if not 1 <= self.max_callback_attempts <= 20 or self.poll_seconds < 10:
            raise ValueError("Invalid retry or polling limits")
        if not 60 <= self.event_max_age_seconds <= 604800:
            raise ValueError("event_max_age_seconds must be 60..604800")
        if not 1024 <= self.max_attachment_bytes <= 2*1024*1024*1024:
            raise ValueError("max_attachment_bytes must be 1 KiB..2 GiB")
        if self.media_cache_bytes < self.max_attachment_bytes or not 60 <= self.media_ttl_seconds <= 86400:
            raise ValueError("Invalid media cache capacity or lifetime")
        origin=urlsplit(self.media_gateway_origin)
        if origin.scheme not in ('http','https') or not origin.hostname or origin.username or origin.path or origin.query or origin.fragment:
            raise ValueError("media_gateway_origin must be an HTTP origin")

    def destination_allowed(self, chat_id):
        return self.send_enabled and (self.allow_all_destinations or chat_id in self.send_chat_ids)

    @classmethod
    def load(cls, path: str):
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))["bridge"]
        # Registered/file-configured instances require an external marker. Keep
        # the old TOML readable by 0.4.9 during pre-release backup restarts: the
        # new backend supplies this convention, without rewriting that config.
        data.setdefault('state_identity_file', str(Path(path).resolve().parent/'technical-state.json'))
        for key in ["database", "webhook_secret_file", "encryption_key_file", "public_key_file", "waha_key_file", "state_identity_file", "admin_broker_socket", "transcription_socket"]:
            if data.get(key):
                data[key] = Path(data[key])
        return cls(**data)


def secret(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if len(value) < 32:
        raise ValueError("Secret must contain at least 32 characters")
    return value

