"""OpenID Connect relying party: Authorization Code with PKCE (S256), `state` and `nonce`, as a confidential client
(docs/authentication.md).

Built only on what Keycloak, Okta, Entra ID and Google Workspace all support. What an IdP advertises on top (PAR,
RFC 9207's `iss` in the response, an end-session endpoint) is used, never required, unless the operator asks for PAR
(`par = "required"`).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from pyreqwest.client import Client, ClientBuilder
from pyreqwest.exceptions import PyreqwestError

from slowshield import __version__
from slowshield.auth import jose
from slowshield.clock import Clock
from slowshield.config import AuthConfig

log = logging.getLogger(__name__)

MAX_RESPONSE = 1 << 20
SKEW = 120.0  # seconds of clock difference tolerated between SlowShield and the IdP
METADATA_TTL = 3600.0
JWKS_REFETCH = 30.0  # an unknown `kid` fetches the JWKS again, at most this often


class OidcError(Exception):
    """A sign-in that can't go on. `reason` is a short code for the audit log and metrics."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class Metadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None
    end_session_endpoint: str | None
    par_endpoint: str | None
    iss_parameter: bool  # RFC 9207: the IdP puts `iss` in its response, so it must be there and match


@dataclass(frozen=True, slots=True)
class Tokens:
    claims: dict[str, Any]  # the checked ID token's claims, with missing ones from userinfo
    id_token: str


class Http:
    """The IdP's endpoints only: no redirects, small bodies, short timeouts. Swappable in tests."""

    def __init__(self) -> None:
        self.client: Client = (
            ClientBuilder()
            .user_agent(f"slowshield/{__version__}")
            .follow_redirects(False)
            .connect_timeout(timedelta(seconds=5))
            .timeout(timedelta(seconds=15))
            .https_only(False)  # the issuer check allows plain http only on loopback
            .build()
        )

    async def request(
        self, method: str, url: str, *, form: dict[str, str] | None = None, headers: dict[str, str] | None = None
    ) -> tuple[int, Any]:
        hdrs = {"Accept": "application/json", **(headers or {})}
        try:
            builder = self.client.post(url) if method == "POST" else self.client.get(url)
            if form is not None:
                hdrs["Content-Type"] = "application/x-www-form-urlencoded"
                builder = builder.body_bytes(urlencode(form).encode())
            async with builder.headers(hdrs).build_streamed() as resp:
                body = await _read(resp)
                status = resp.status
        except PyreqwestError as exc:
            raise OidcError("idp_unreachable", f"{urlsplit(url).netloc}: {type(exc).__name__}") from exc
        try:
            return status, json.loads(body) if body else None
        except ValueError:
            return status, None

    async def close(self) -> None:
        try:
            await self.client.close()
        except Exception:  # pragma: no cover
            log.debug("closing the IdP client failed", exc_info=True)


async def _read(resp: Any) -> bytes:
    parts: list[bytes] = []
    total = 0
    reader = resp.body_reader
    while (chunk := await reader.read_chunk()) is not None:
        total += len(chunk)
        if total > MAX_RESPONSE:
            raise OidcError("idp_error", "the IdP's response is too large")
        parts.append(bytes(chunk))
    return b"".join(parts)


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = jose.b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def _endpoint(issuer: str, url: Any, name: str) -> str:
    """An endpoint from discovery: https, or plain http only when the issuer itself is a plain-http loopback URL
    (tests and local development)."""
    if not isinstance(url, str) or not url:
        raise OidcError("idp_error", f"discovery has no {name}")
    scheme = urlsplit(url).scheme
    if scheme == "https" or (scheme == "http" and urlsplit(issuer).scheme == "http"):
        return url
    raise OidcError("idp_error", f"discovery: {name} is not https")


class Provider:
    """One configured IdP. Discovery and the JWKS are fetched lazily and kept; the IdP needn't be up at startup."""

    def __init__(self, auth: AuthConfig, clock: Clock, http: Http | None = None) -> None:
        self.auth = auth
        self.oidc = auth.oidc
        self.clock = clock
        self.http = http or Http()
        self._metadata: Metadata | None = None
        self._metadata_at = 0.0
        self._keys: list[dict[str, Any]] = []
        self._keys_at = 0.0
        self._lock = asyncio.Lock()
        self._secret: str | None = None
        self._key: jose.ClientKey | None = None
        self.load_credentials()

    @property
    def issuer(self) -> str:
        return self.oidc.issuer or ""  # config validation requires it

    @property
    def client_id(self) -> str:
        return self.oidc.client_id or ""

    def load_credentials(self) -> None:
        """Read the key or secret file. Fails the start when it can't be read: sign-in would never work."""
        try:
            if self.oidc.client_key_file:
                self._key = jose.load_client_key(Path(self.oidc.client_key_file).read_bytes())
            elif self.oidc.client_secret_file:
                self._secret = Path(self.oidc.client_secret_file).read_text(encoding="utf-8").strip()
                if not self._secret:
                    raise OidcError("config", f"{self.oidc.client_secret_file} is empty")
        except OSError as exc:
            raise OidcError("config", f"can't read the client credentials: {exc.strerror}") from exc
        except jose.JoseError as exc:
            raise OidcError("config", f"{self.oidc.client_key_file}: {exc}") from exc

    @property
    def client_auth_method(self) -> str:
        return "private_key_jwt" if self._key is not None else "client_secret_basic"

    # ---- discovery and keys -------------------------------------------------------------------------------------

    async def metadata(self) -> Metadata:
        now = self.clock.now()
        if self._metadata is not None and now - self._metadata_at < METADATA_TTL:
            return self._metadata
        async with self._lock:
            if self._metadata is not None and now - self._metadata_at < METADATA_TTL:
                return self._metadata
            try:
                self._metadata = await self._discover()
                self._metadata_at = now
            except OidcError:
                if self._metadata is None:
                    raise
                log.warning("OIDC discovery failed, keeping the last document", exc_info=True)
                self._metadata_at = now - METADATA_TTL + 60  # try again in a minute
        return self._metadata

    async def _discover(self) -> Metadata:
        url = self.issuer.rstrip("/") + "/.well-known/openid-configuration"
        status, doc = await self.http.request("GET", url)
        if status != 200 or not isinstance(doc, dict):
            raise OidcError("idp_unreachable", f"discovery at {url} returned {status}")
        if doc.get("issuer") != self.issuer:
            raise OidcError(
                "idp_error",
                f"discovery names the issuer {doc.get('issuer')!r}, not {self.issuer!r} (set SLOWSHIELD_OIDC_ISSUER "
                "to exactly the IdP's issuer)",
            )
        methods = doc.get("code_challenge_methods_supported")
        if isinstance(methods, list) and "S256" not in methods:
            raise OidcError("idp_error", "the IdP doesn't support PKCE with S256")
        par = doc.get("pushed_authorization_request_endpoint")
        if self.oidc.par == "required" and not par:
            raise OidcError("idp_error", "SLOWSHIELD_OIDC_PAR=required, but the IdP has no PAR endpoint")
        iss = self.issuer
        optional = {
            name: _endpoint(iss, doc[name], name) if doc.get(name) else None
            for name in ("userinfo_endpoint", "end_session_endpoint")
        }
        return Metadata(
            issuer=iss,
            authorization_endpoint=_endpoint(iss, doc.get("authorization_endpoint"), "authorization_endpoint"),
            token_endpoint=_endpoint(iss, doc.get("token_endpoint"), "token_endpoint"),
            jwks_uri=_endpoint(iss, doc.get("jwks_uri"), "jwks_uri"),
            userinfo_endpoint=optional["userinfo_endpoint"],
            end_session_endpoint=optional["end_session_endpoint"],
            par_endpoint=_endpoint(iss, par, "pushed_authorization_request_endpoint")
            if par and self.oidc.par != "off"
            else None,
            iss_parameter=doc.get("authorization_response_iss_parameter_supported") is True,
        )

    async def _jwks(self, *, refresh: bool) -> list[dict[str, Any]]:
        now = self.clock.now()
        if self._keys and not refresh and now - self._keys_at < METADATA_TTL:
            return self._keys
        if self._keys and refresh and now - self._keys_at < JWKS_REFETCH:
            return self._keys
        meta = await self.metadata()
        status, doc = await self.http.request("GET", meta.jwks_uri)
        keys = doc.get("keys") if isinstance(doc, dict) else None
        if status != 200 or not isinstance(keys, list):
            raise OidcError("idp_unreachable", f"the IdP's JWKS returned {status}")
        self._keys, self._keys_at = [k for k in keys if isinstance(k, dict)], now
        return self._keys

    # ---- the flow -----------------------------------------------------------------------------------------------

    def _client_auth(self, audience: str) -> tuple[dict[str, str], dict[str, str]]:
        """Headers and form fields that authenticate SlowShield at a back-channel endpoint."""
        if self._key is not None:
            assertion = self._key.assertion(self.client_id, audience, self.clock.now())
            return {}, {
                "client_id": self.client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
            }
        secret = self._secret or ""
        # RFC 6749 2.3.1: both parts form-urlencoded before Basic.
        pair = f"{quote(self.client_id, safe='')}:{quote(secret, safe='')}"
        return {"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()}, {}

    async def authorization_url(
        self, *, redirect_uri: str, state: str, nonce: str, challenge: str, prompt: str | None
    ) -> str:
        meta = await self.metadata()
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.oidc.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if prompt:
            params["prompt"] = prompt
        sep = "&" if "?" in meta.authorization_endpoint else "?"
        if meta.par_endpoint is None:
            return meta.authorization_endpoint + sep + urlencode(params)
        # RFC 9126: the parameters go to the IdP over the back channel; the browser only carries a reference.
        # The assertion's audience is the token endpoint, which Keycloak and Okta accept at the PAR endpoint too.
        headers, auth = self._client_auth(meta.token_endpoint)
        status, doc = await self.http.request("POST", meta.par_endpoint, form={**params, **auth}, headers=headers)
        uri = doc.get("request_uri") if isinstance(doc, dict) else None
        if status not in (200, 201) or not isinstance(uri, str):
            raise OidcError("idp_error", f"PAR returned {status}: {_error_text(doc)}")
        return meta.authorization_endpoint + sep + urlencode({"client_id": self.client_id, "request_uri": uri})

    async def exchange(self, *, code: str, redirect_uri: str, verifier: str, nonce: str) -> Tokens:
        meta = await self.metadata()
        headers, auth = self._client_auth(meta.token_endpoint)
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                "code_verifier": verifier, **auth}  # fmt: skip
        status, doc = await self.http.request("POST", meta.token_endpoint, form=form, headers=headers)
        if status != 200 or not isinstance(doc, dict):
            raise OidcError("token_error", f"the token endpoint returned {status}: {_error_text(doc)}")
        id_token = doc.get("id_token")
        if not isinstance(id_token, str):
            raise OidcError("token_error", "the token response has no ID token")
        claims = await self.check_id_token(id_token, nonce)
        access = doc.get("access_token")
        if isinstance(access, str) and meta.userinfo_endpoint and self._wants_userinfo(claims):
            claims = {**(await self._userinfo(meta.userinfo_endpoint, access, claims["sub"])), **claims}
        return Tokens(claims, id_token)

    def _wants_userinfo(self, claims: dict[str, Any]) -> bool:
        """Claims the role rules need that the ID token left out (Okta and Keycloak can keep them to userinfo)."""
        from slowshield.auth.roles import claim

        needed = []
        if self.oidc.roles_claim:
            needed.append(self.oidc.roles_claim)
        if self.auth.admin_emails or self.auth.user_emails:
            needed += ["email", "email_verified"]
        needed += [rule.partition("=")[0].strip() for rule in self.oidc.require_claims]
        return any(claim(claims, n) is None for n in needed) or not (claims.get("name") or claims.get("email"))

    async def _userinfo(self, url: str, access_token: str, subject: str) -> dict[str, Any]:
        try:
            status, doc = await self.http.request("GET", url, headers={"Authorization": f"Bearer {access_token}"})
        except OidcError:
            log.warning("OIDC userinfo unreachable; signing in with the ID token's claims only")
            return {}
        if status != 200 or not isinstance(doc, dict):
            log.warning("OIDC userinfo returned %s; signing in with the ID token's claims only", status)
            return {}
        if doc.get("sub") != subject:  # OIDC Core 5.3.2: a mismatch means the response must not be used
            raise OidcError("token_error", "userinfo is for another subject")
        return doc

    async def check_id_token(self, token: str, nonce: str) -> dict[str, Any]:
        """OIDC Core 3.1.3.7, for a confidential client: signature, iss, aud, azp, exp, iat, nonce."""
        try:
            jws = jose.parse(token)
        except jose.JoseError as exc:
            raise OidcError("bad_token", str(exc)) from exc
        keys = jose.candidates(jws, await self._jwks(refresh=False))
        if not keys:  # a key the IdP rotated in since we last looked
            keys = jose.candidates(jws, await self._jwks(refresh=True))
        try:
            if not any(jose.verify(jws, k) for k in keys):
                raise OidcError("bad_token", "the ID token's signature doesn't verify" if keys else "no key fits")
        except jose.JoseError as exc:
            raise OidcError("bad_token", f"the IdP's key can't be used: {exc}") from exc
        c = jws.claims
        now = self.clock.now()
        aud = c.get("aud")
        audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        problems = (
            (c.get("iss") != self.issuer, "issuer"),
            (self.client_id not in audiences, "audience"),
            (len(audiences) > 1 and c.get("azp") != self.client_id, "authorized party"),
            ("azp" in c and c.get("azp") != self.client_id, "authorized party"),
            (not isinstance(c.get("exp"), int | float) or c["exp"] < now - SKEW, "expiry"),
            (not isinstance(c.get("iat"), int | float) or c["iat"] > now + SKEW, "issue time"),
            ("nbf" in c and (not isinstance(c["nbf"], int | float) or c["nbf"] > now + SKEW), "not-before time"),
            (not isinstance(c.get("nonce"), str) or not secrets.compare_digest(c["nonce"], nonce), "nonce"),
            (not isinstance(c.get("sub"), str) or not c["sub"] or len(c["sub"]) > 255, "subject"),
        )
        for bad, what in problems:
            if bad:
                raise OidcError("bad_token", f"the ID token's {what} is wrong")
        return dict(c)

    async def end_session_url(self, *, id_token: str | None, post_logout_redirect_uri: str) -> str | None:
        """RP-initiated logout, where the IdP has it (Keycloak, Okta, Entra ID; not Google)."""
        try:
            meta = await self.metadata()
        except OidcError:
            return None
        if not meta.end_session_endpoint:
            return None
        params = {"client_id": self.client_id, "post_logout_redirect_uri": post_logout_redirect_uri}
        if id_token:
            params["id_token_hint"] = id_token
        sep = "&" if "?" in meta.end_session_endpoint else "?"
        return meta.end_session_endpoint + sep + urlencode(params)

    async def close(self) -> None:
        await self.http.close()


def _error_text(doc: Any) -> str:
    if isinstance(doc, dict):
        err = str(doc.get("error", ""))[:100]
        desc = str(doc.get("error_description", ""))[:200]
        return f"{err} {desc}".strip() or "no details"
    return "no details"
