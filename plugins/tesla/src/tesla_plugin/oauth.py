"""Tesla authorization-code connection, bound to a logged-in owner session."""
import json
import base64
import hashlib
import re
import secrets
from urllib.parse import urlencode
import httpx
import jwt

from .config import AUTHORIZE_URL, TOKEN_URL, TESLA_SCOPES, REGIONS, secret
from .errors import TeslaError
from .store import digest
from .authorization import Authorization


class TeslaOAuth:
    def __init__(self, store, client):
        self.store, self.settings, self.client = store, store.settings, client

    def begin(self, session_id):
        if not self.settings.live_enabled:
            raise TeslaError("LIVE_DISABLED", "Live account connection is disabled in this configuration")
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            generation = int(db.execute("SELECT value FROM meta WHERE key='connection_generation'").fetchone()[0])
            # Keep the consent fence with the encrypted PKCE state so it also
            # survives another worker/process completing this callback.
            bound_verifier = {"verifier": verifier, "generation": generation}
            db.execute("INSERT INTO oauth_states VALUES(?,?,?,?)", (digest(state), session_id, self.store.clock()+300, self.store.seal(bound_verifier)))
        return AUTHORIZE_URL + "?" + urlencode({
            "client_id": self.settings.tesla_client_id, "redirect_uri": self.settings.tesla_redirect_uri,
            "response_type": "code", "scope": " ".join(TESLA_SCOPES), "state": state,
            "nonce": secrets.token_urlsafe(32), "prompt": "consent",
            "code_challenge": challenge, "code_challenge_method": "S256"})

    def _exchange(self, payload):
        if not self.settings.live_enabled:
            raise TeslaError("LIVE_DISABLED", "Live account connection is disabled")
        data = {**payload, "client_id": self.settings.tesla_client_id,
                "client_secret": secret(self.settings.tesla_client_secret_file)}
        try:
            response = self.client.post(TOKEN_URL, data=data)
        except httpx.HTTPError:
            raise TeslaError("AUTH_EXCHANGE_UNCERTAIN", "Token exchange interrupted; reconnect if recovery is required") from None
        if response.status_code != 200 or len(response.content) > 65536:
            raise TeslaError("AUTH_REQUIRED", "Tesla authorization could not be renewed", http_status=response.status_code)
        try:
            tokens = response.json()
            if not isinstance(tokens, dict):
                raise ValueError()
            return tokens
        except ValueError:
            raise TeslaError("AUTH_RESPONSE_INVALID", "Invalid token response") from None

    @staticmethod
    def _granted_scopes(tokens, *, previous=None):
        """Read only responses from _exchange's fixed, TLS-authenticated endpoint.

        Tesla documents the access token's scp claim as its grant evidence:
        https://developer.tesla.com/docs/fleet-api/support/faq
        The trusted source here is the server-to-server token exchange, not a
        JWT supplied by a caller. This decoding does not authenticate JWTs;
        inbound MCP bearer verification remains separate in auth.py.
        """
        def validate(scopes):
            if not isinstance(scopes, list) or any(not isinstance(s, str) or
                    re.fullmatch(r'[\x21\x23-\x5b\x5d-\x7e]+', s) is None for s in scopes):
                raise TeslaError("AUTH_RESPONSE_INVALID", "Invalid granted permissions from Tesla")
            return set(scopes)

        response_scopes = None
        if "scope" in tokens:
            if not isinstance(tokens["scope"], str):
                raise TeslaError("AUTH_RESPONSE_INVALID", "Invalid granted permissions from Tesla")
            response_scopes = validate(tokens["scope"].split())
        access = tokens.get("access_token")
        if not isinstance(access, str) or not access:
            raise TeslaError("AUTH_RESPONSE_INVALID", "Tesla did not return an access token")
        if access.count(".") == 2:
            try:
                claims = jwt.decode(access, options={"verify_signature": False})
            except (jwt.PyJWTError, ValueError, TypeError):
                raise TeslaError("AUTH_RESPONSE_INVALID", "Invalid access token response from Tesla") from None
            if "scp" in claims:
                scopes = validate(claims["scp"])
                # A second explicit grant list may narrow but never expand scp.
                return sorted(scopes if response_scopes is None else scopes & response_scopes)
            # A new JWT without grant evidence must not inherit stale permissions.
            if response_scopes is None:
                raise TeslaError("AUTH_RESPONSE_INVALID", "Tesla did not attest granted permissions")
        if response_scopes is not None:
            return sorted(response_scopes)
        # OAuth permits an opaque refresh response to omit unchanged scopes.
        # Initial connections never fall back to the requested permissions.
        if previous is not None:
            return sorted(validate(previous))
        raise TeslaError("AUTH_RESPONSE_INVALID", "Tesla did not attest granted permissions")

    def complete(self, state, code, session_id):
        if not isinstance(state, str) or not isinstance(code, str) or len(state) > 128 or len(code) > 4096:
            raise TeslaError("AUTH_STATE_INVALID", "Invalid authorization callback")
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM oauth_states WHERE id=?", (digest(state),)).fetchone()
            if not row or row["session"] != session_id or row["expires"] <= self.store.clock():
                raise TeslaError("AUTH_STATE_INVALID", "Expired or mismatched authorization callback")
            bound = self.store.unseal(row["verifier"])
            # An unbound state from an older version cannot prove which consent
            # it belongs to. Restart Connect; existing tokens are unaffected.
            if (not isinstance(bound, dict) or set(bound) != {"verifier", "generation"}
                    or not isinstance(bound["verifier"], str) or not 43 <= len(bound["verifier"]) <= 128
                    or type(bound["generation"]) is not int or bound["generation"] < 0
                    or int(db.execute("SELECT value FROM meta WHERE key='connection_generation'").fetchone()[0]) != bound["generation"]):
                raise TeslaError("AUTH_STATE_INVALID", "Authorization changed; start a new account connection")
            db.execute("DELETE FROM oauth_states WHERE id=?", (digest(state),))
        tokens = self._exchange({"grant_type": "authorization_code", "code": code,
                                 "redirect_uri": self.settings.tesla_redirect_uri,
                                 "audience": REGIONS[self.settings.region], "code_verifier": bound["verifier"]})
        scopes = self._granted_scopes(tokens)
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if int(db.execute("SELECT value FROM meta WHERE key='connection_generation'").fetchone()[0]) != bound["generation"]:
                raise TeslaError("AUTHORIZATION_CHANGED", "Account authorization changed during connection; the obsolete response was not applied")
            if row["expires"] <= self.store.clock():
                raise TeslaError("AUTH_STATE_INVALID", "Authorization callback expired during token exchange")
            self.store.set_tokens(tokens, scopes, self.settings.region, db=db)
        return {"status": "connected", "region": self.settings.region, "region_verified": False}

    def access_token(self):
        return self.authorization().access_token

    def authorization(self):
        """Return token and its persisted identity from the same row/rotation."""
        state = self.store.connection()
        if state["expires"] > self.store.clock()+60:
            return Authorization.from_row(self.store, state)
        error = None
        with self.store.db() as db:
            # One rotation at a time, including across processes. Persist the new
            # refresh token in the same transaction before another caller proceeds.
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM connection WHERE id=1 AND status='active'").fetchone()
            if not row:
                raise TeslaError("AUTH_REQUIRED", "Reconnect your Tesla account")
            if row["expires"] > self.store.clock()+60:
                return Authorization.from_row(self.store, row)
            try:
                tokens = self._exchange({"grant_type": "refresh_token", "refresh_token": self.store.unseal(row["tokens"])["refresh_token"]})
                scopes = self._granted_scopes(tokens, previous=json.loads(row["scopes"]))
                self.store.set_tokens(tokens, scopes, row["region"], db=db, generation=row["generation"])
                authorized = Authorization.from_row(self.store, db.execute("SELECT * FROM connection WHERE id=1").fetchone())
            except TeslaError as exc:
                # Preserve the previous token encrypted for operator recovery;
                # block requests instead of repeatedly rotating uncertain grants.
                db.execute("UPDATE connection SET status='reauth_required' WHERE id=1")
                db.execute("UPDATE intents SET status='cancelled' WHERE status='prepared'")
                db.execute("UPDATE subscriptions SET active=0")
                error = exc
        if error:
            raise error
        return authorized
