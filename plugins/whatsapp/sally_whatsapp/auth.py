import asyncio
import time
import jwt
from mcp.server.auth.provider import AccessToken

from .config import MCP_SCOPES, Settings
from .diagnostics import auth_rejected, auth_verified


class ResilientJWKClient(jwt.PyJWKClient):
    """Keep fresh key lookups independent of a failing JWKS refresh.

    PyJWT 2.15.1 serializes refreshes and lookups with one reentrant lock.
    Its finite set cache is also safe to read as a snapshot: publication only
    replaces a fully parsed set. Do not enable its unbounded per-key cache.
    A successful refresh still replaces the entire set, including removed keys;
    an unsuccessful refresh never renews the original set's 300-second TTL.
    """

    def __init__(self, uri: str):
        super().__init__(uri, cache_keys=False, lifespan=300, timeout=5,
                         cooldown_duration=30)
        self._retry_after = 0.0

    def get_signing_key(self, kid):
        cached = self.jwk_set_cache.get()
        if cached is not None:
            key = self.match_kid(self._get_signing_keys_from_jwk_set(cached), kid)
            if key is not None:
                return key
        # Misses/expired sets retain PyJWT's serialized refresh and cooldown.
        return super().get_signing_key(kid)

    def fetch_data(self):
        with self._client_lock:
            if time.monotonic() < self._retry_after:
                raise jwt.PyJWKClientError('JWKS refresh temporarily unavailable')
            try:
                result = super().fetch_data()
            except (jwt.PyJWTError, ValueError, TypeError, OSError, RecursionError) as exc:
                # Start the same bounded cooldown on failure, including malformed
                # responses. It neither wipes nor extends an existing set cache.
                self._retry_after = time.monotonic() + self.cooldown_duration
                if isinstance(exc, RecursionError):
                    raise jwt.PyJWKClientError('Invalid JWKS response') from exc
                raise
            self._retry_after = 0.0
            return result


def token_scopes(claims: dict) -> list[str]:
    """Accept the standard scope string and Authelia's signed scp array.

    If both exist they must agree; never union conflicting grants.
    """
    scope = claims.get("scope", "")
    if not isinstance(scope, str):
        raise ValueError("Invalid scope claim")
    scopes = scope.split()
    if "scp" in claims:
        scp = claims["scp"]
        if not isinstance(scp, list) or any(
            not isinstance(item, str) or not item or any(c.isspace() for c in item)
            for item in scp
        ):
            raise ValueError("Invalid scp claim")
        if "scope" in claims and set(scopes) != set(scp):
            raise ValueError("Conflicting scope claims")
        scopes = scp
    return sorted(set(scopes))


class JWTVerifier:
    """OAuth resource server. The established IdP owns login, PKCE and refresh."""

    def __init__(self, settings: Settings, diagnostics=None):
        self.settings = settings
        self.diagnostics = diagnostics
        self.key = settings.public_key_file.read_text() if settings.public_key_file else None
        self.jwks = ResilientJWKClient(settings.jwks_url) if settings.jwks_url else None

    async def verify_token(self, token: str) -> AccessToken | None:
        return await asyncio.to_thread(self._verify, token)

    def _verify(self, token: str) -> AccessToken | None:
        try:
            key = self.jwks.get_signing_key_from_jwt(token).key if self.jwks else self.key
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.settings.public_url,
                                issuer=self.settings.issuer, options={"require": ["exp", "iat", "sub", "iss", "aud"]})
            if claims["sub"] != self.settings.owner_subject:
                auth_rejected(self.diagnostics, 'AUTH_OWNER')
                return None
            client_id=claims.get('azp',claims.get('client_id'))
            if not isinstance(client_id,str) or client_id not in self.settings.oauth_client_ids:
                auth_rejected(self.diagnostics, 'AUTH_CLIENT')
                return None
            # Apply the configured resource ceiling after validating the signed
            # claims. The separate pairing verifier also uses this class: do not
            # reinterpret OIDC or whatsapp:link as MCP resource permissions.
            scopes = [scope for scope in token_scopes(claims)
                      if scope not in MCP_SCOPES or scope in self.settings.oauth_allowed_scopes]
            access = AccessToken(token=token, client_id=client_id,
                               subject=claims["sub"], scopes=scopes,
                               expires_at=int(claims["exp"]), resource=self.settings.public_url,
                               claims={"iss": claims["iss"]})
            auth_verified()
            return access
        except (jwt.PyJWTError, ValueError, TypeError, OSError) as exc:
            auth_rejected(self.diagnostics, 'AUTH_TOKEN', type(exc).__name__)
            return None

