"""MCP resource authorization; the existing IdP handles OAuth login and PKCE."""
import asyncio
import jwt
from mcp.server.auth.provider import AccessToken


class JWTVerifier:
    def __init__(self, settings):
        self.settings = settings
        self.key = settings.public_key_file.read_text() if settings.public_key_file else None
        self.jwks = jwt.PyJWKClient(settings.jwks_url, cache_keys=False, lifespan=300, timeout=5) if settings.jwks_url else None

    async def verify_token(self, token):
        return await asyncio.to_thread(self.verify, token)

    def verify(self, token):
        try:
            key = self.jwks.get_signing_key_from_jwt(token).key if self.jwks else self.key
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.settings.public_url,
                                issuer=self.settings.issuer, options={"require": ["exp", "iat", "sub", "iss", "aud"]})
            client = claims.get("azp", claims.get("client_id"))
            if claims["sub"] != self.settings.owner_subject or client not in self.settings.oauth_client_ids:
                return None
            scopes = claims.get("scope", "")
            if not isinstance(scopes, str):
                return None
            scopes = scopes.split()
            if "scp" in claims:
                scp = claims["scp"]
                if not isinstance(scp, list) or any(not isinstance(x, str) or not x or any(c.isspace() for c in x) for x in scp):
                    return None
                if "scope" in claims and set(scopes) != set(scp):
                    return None
                scopes = scp
            return AccessToken(token=token, client_id=client, subject=claims["sub"],
                               scopes=sorted(set(scopes) & set(self.settings.allowed_scopes)),
                               expires_at=int(claims["exp"]), resource=self.settings.public_url)
        except (jwt.PyJWTError, ValueError, TypeError, OSError):
            return None
