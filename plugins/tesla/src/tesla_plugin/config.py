"""Explicit configuration; no secret discovery or live defaults."""
from dataclasses import dataclass, field
from pathlib import Path
import json
import os
import stat
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

SCOPES = ("tesla:read", "tesla:location", "tesla:history", "tesla:commands", "tesla:events", "tesla:manage")
TESLA_SCOPES = ("openid", "offline_access", "user_data", "vehicle_device_data", "vehicle_location", "vehicle_cmds", "vehicle_charging_cmds")
REGIONS = {
    "eu": "https://fleet-api.prd.eu.vn.cloud.tesla.com",
    "na": "https://fleet-api.prd.na.vn.cloud.tesla.com",
    "cn": "https://fleet-api.prd.cn.vn.cloud.tesla.cn",
}
TOKEN_URL = "https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token"
AUTHORIZE_URL = "https://auth.tesla.com/oauth2/v3/authorize"


def secret(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ValueError("Secret must be a regular file")
    if os.name == "posix" and stat.S_IMODE(p.stat().st_mode) & 0o077:
        raise ValueError("Secret file must be accessible only to its owner")
    value = p.read_text().strip()
    if not value:
        raise ValueError("Empty secret")
    return value


def https_url(value, *, path_allowed=True, private_service=False):
    u = urlsplit(value)
    if (u.scheme != "https" or not u.hostname or u.username or u.password or u.fragment or u.query
            or (not private_service and u.port not in (None, 443)) or any(ord(c) < 33 for c in value)):
        raise ValueError("Expected an HTTPS URL without credentials, query or fragment")
    if not path_allowed and u.path not in ("", "/"):
        raise ValueError("Expected an HTTPS origin")
    return value.rstrip("/")


@dataclass(frozen=True)
class Settings:
    database: Path
    encryption_key_file: Path
    owner_subject: str
    public_url: str
    issuer: str
    oauth_client_ids: tuple[str, ...]
    public_key_file: Path | None = None
    jwks_url: str | None = None
    live_enabled: bool = False
    region: str = "eu"
    tesla_client_id: str = ""
    tesla_client_secret_file: Path | None = None
    tesla_redirect_uri: str = "https://example.invalid/tesla/oauth/callback"
    command_proxy_url: str | None = None
    command_proxy_ca: Path | None = None
    owner_password_file: Path | None = None
    callback_hosts: tuple[str, ...] = ()
    telemetry_host: str | None = None
    telemetry_port: int = 443
    telemetry_ca_file: Path | None = None
    monthly_limit_usd: float = 10.0
    history_days: int = 30
    intent_ttl_seconds: int = 300
    timezone: str = "UTC"
    telemetry_bootstrap_servers: tuple[str, ...] = ()
    telemetry_broker_ca: Path | None = None
    telemetry_topics: tuple[str, ...] = ("tesla_V", "tesla_alerts", "tesla_connectivity")
    allowed_scopes: tuple[str, ...] = field(default_factory=lambda: SCOPES)

    def __post_init__(self):
        try:
            if not isinstance(self.timezone, str) or not self.timezone:
                raise ValueError()
            ZoneInfo(self.timezone)
        except (ValueError, ZoneInfoNotFoundError):
            raise ValueError("timezone must name an available IANA timezone") from None
        if type(self.live_enabled) is not bool:
            raise ValueError("live_enabled must be a boolean")
        https_url(self.public_url)
        https_url(self.issuer)
        https_url(self.tesla_redirect_uri)
        resource, callback = urlsplit(self.public_url), urlsplit(self.tesla_redirect_uri)
        if (not resource.path.endswith("/mcp") or "%" in resource.path or "//" in resource.path
                or callback.netloc != resource.netloc or callback.path != resource.path[:-4]+"/oauth/callback"):
            raise ValueError("MCP URL and owner-bound callback must use the same origin and base path")
        if self.region not in REGIONS or not self.owner_subject or not self.oauth_client_ids:
            raise ValueError("Owner, OAuth clients and a supported region are required")
        if bool(self.public_key_file) == bool(self.jwks_url):
            raise ValueError("Configure exactly one IdP public key or JWKS URL")
        if self.jwks_url:
            https_url(self.jwks_url)
        if self.command_proxy_url:
            https_url(self.command_proxy_url, path_allowed=False, private_service=True)
        if self.live_enabled and (not self.tesla_client_id or not self.tesla_client_secret_file):
            raise ValueError("Live mode requires explicit Tesla application credentials")
        if not set(self.allowed_scopes) <= set(SCOPES):
            raise ValueError("Unknown MCP scope")
        if not (0 < self.monthly_limit_usd <= 1000 and 1 <= self.history_days <= 3650
                and 30 <= self.intent_ttl_seconds <= 600 and 1 <= self.telemetry_port <= 65535):
            raise ValueError("Invalid budget, retention, intent lifetime or port")

    @classmethod
    def load(cls, path):
        data = json.loads(Path(path).read_text())
        for key in ("database", "encryption_key_file", "public_key_file", "tesla_client_secret_file",
                    "command_proxy_ca", "owner_password_file", "telemetry_ca_file", "telemetry_broker_ca"):
            if data.get(key) is not None:
                data[key] = Path(data[key])
                if not data[key].is_absolute():
                    raise ValueError("Configuration paths must be absolute")
        for key in ("oauth_client_ids", "callback_hosts", "telemetry_bootstrap_servers", "telemetry_topics", "allowed_scopes"):
            if key in data:
                if not isinstance(data[key], list) or any(not isinstance(v, str) for v in data[key]):
                    raise ValueError("Expected a list of strings")
                data[key] = tuple(data[key])
        return cls(**data)
