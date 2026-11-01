"""The OIDC relying party against a stub IdP: discovery checks, caching, the token exchange's failure modes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from slowshield.auth import jose
from slowshield.auth.oidc import OidcError, Provider
from slowshield.clock import FrozenClock
from slowshield.config import AuthConfig, OidcConfig

ISS = "https://idp.example/realms/r"


def _doc(**changes: Any) -> dict[str, Any]:
    doc = {
        "issuer": ISS,
        "authorization_endpoint": f"{ISS}/auth",
        "token_endpoint": f"{ISS}/token",
        "jwks_uri": f"{ISS}/certs",
        "userinfo_endpoint": f"{ISS}/userinfo",
        "code_challenge_methods_supported": ["plain", "S256"],
    }
    doc.update(changes)
    return {k: v for k, v in doc.items() if v is not None}


class StubHttp:
    def __init__(self, routes: dict[tuple[str, str], tuple[int, Any]]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str, dict[str, str] | None, dict[str, str] | None]] = []

    async def request(
        self, method: str, url: str, *, form: dict[str, str] | None = None, headers: dict[str, str] | None = None
    ) -> tuple[int, Any]:
        self.calls.append((method, url, form, headers))
        hit = self.routes.get((method, url))
        if hit is None:
            raise OidcError("idp_unreachable", url)
        return hit

    async def close(self) -> None:
        pass


def _provider(tmp_path: Path, routes: dict[tuple[str, str], tuple[int, Any]], **oidc: Any) -> Provider:
    secret = tmp_path / "secret"
    secret.write_text("s3cret")
    cfg = AuthConfig(mode="oidc", oidc=OidcConfig(issuer=ISS, client_id="slowshield",
                                                  client_secret_file=str(secret), **oidc))  # fmt: skip
    return Provider(cfg, FrozenClock(1_000_000.0), StubHttp(routes))  # type: ignore[arg-type]


DISCOVERY = ("GET", f"{ISS}/.well-known/openid-configuration")


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        (_doc(issuer="https://other.example"), "names the issuer"),
        (_doc(code_challenge_methods_supported=["plain"]), "S256"),
        (_doc(token_endpoint="http://idp.example/token"), "not https"),
        (_doc(jwks_uri=None), "no jwks_uri"),
    ],
)
async def test_discovery_is_checked(tmp_path: Path, doc: dict[str, Any], message: str) -> None:
    p = _provider(tmp_path, {DISCOVERY: (200, doc)})
    with pytest.raises(OidcError, match=message):
        await p.metadata()


async def test_par_required_needs_an_endpoint(tmp_path: Path) -> None:
    with pytest.raises(OidcError, match="no PAR endpoint"):
        await _provider(tmp_path, {DISCOVERY: (200, _doc())}, par="required").metadata()
    p = _provider(tmp_path, {DISCOVERY: (200, _doc(pushed_authorization_request_endpoint=f"{ISS}/par"))}, par="off")
    assert (await p.metadata()).par_endpoint is None


async def test_discovery_is_cached_and_survives_an_outage(tmp_path: Path) -> None:
    p = _provider(tmp_path, {DISCOVERY: (200, _doc())})
    first = await p.metadata()
    assert await p.metadata() is first
    http: StubHttp = p.http  # type: ignore[assignment]
    assert len(http.calls) == 1
    http.routes.clear()
    p.clock.advance(3601)  # type: ignore[attr-defined]
    assert await p.metadata() is first  # the IdP is down: the last document stays
    p.clock.advance(30)  # type: ignore[attr-defined]
    await p.metadata()
    assert len(http.calls) == 2  # and it tries again only after a minute


async def test_discovery_down_at_first(tmp_path: Path) -> None:
    p = _provider(tmp_path, {DISCOVERY: (503, None)})
    with pytest.raises(OidcError) as err:
        await p.metadata()
    assert err.value.reason == "idp_unreachable"


async def test_token_endpoint_errors(tmp_path: Path) -> None:
    token = ("POST", f"{ISS}/token")
    p = _provider(tmp_path, {DISCOVERY: (200, _doc()), token: (400, {"error": "invalid_grant"})})
    with pytest.raises(OidcError, match="invalid_grant"):
        await p.exchange(code="c", redirect_uri="https://s/cb", verifier="v", nonce="n")
    http: StubHttp = p.http  # type: ignore[assignment]
    _method, _url, form, headers = http.calls[-1]
    assert form is not None and form["code_verifier"] == "v" and "client_secret" not in form
    assert headers is not None and headers["Authorization"].startswith("Basic ")
    http.routes[token] = (200, {"access_token": "a"})
    with pytest.raises(OidcError, match="no ID token"):
        await p.exchange(code="c", redirect_uri="https://s/cb", verifier="v", nonce="n")


async def test_userinfo_for_another_subject_is_refused(tmp_path: Path) -> None:
    p = _provider(tmp_path, {DISCOVERY: (200, _doc()), ("GET", f"{ISS}/userinfo"): (200, {"sub": "mallory"})})
    with pytest.raises(OidcError, match="another subject"):
        await p._userinfo(f"{ISS}/userinfo", "a", "alice")
    p.http.routes[("GET", f"{ISS}/userinfo")] = (500, None)  # type: ignore[attr-defined]
    assert await p._userinfo(f"{ISS}/userinfo", "a", "alice") == {}  # not fatal: the ID token's claims count


async def test_end_session_url(tmp_path: Path) -> None:
    p = _provider(tmp_path, {DISCOVERY: (200, _doc(end_session_endpoint=f"{ISS}/logout?x=1"))})
    url = await p.end_session_url(id_token="t", post_logout_redirect_uri="https://s/ui/auth/signed-out")
    assert url is not None and url.startswith(f"{ISS}/logout?x=1&client_id=slowshield&")
    assert "id_token_hint=t" in url
    google = _provider(tmp_path, {DISCOVERY: (200, _doc())})
    assert await google.end_session_url(id_token="t", post_logout_redirect_uri="https://s") is None
    down = _provider(tmp_path, {})
    assert await down.end_session_url(id_token=None, post_logout_redirect_uri="https://s") is None


def test_unreadable_credentials(tmp_path: Path) -> None:
    missing = AuthConfig(mode="oidc", oidc=OidcConfig(issuer=ISS, client_id="c", client_secret_file="/nope"))
    with pytest.raises(OidcError, match="can't read"):
        Provider(missing, FrozenClock(0), StubHttp({}))  # type: ignore[arg-type]
    empty = tmp_path / "empty"
    empty.write_text("\n")
    blank = AuthConfig(mode="oidc", oidc=OidcConfig(issuer=ISS, client_id="c", client_secret_file=str(empty)))
    with pytest.raises(OidcError, match="empty"):
        Provider(blank, FrozenClock(0), StubHttp({}))  # type: ignore[arg-type]
    bad_key = tmp_path / "key.pem"
    bad_key.write_text("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
    keyed = AuthConfig(mode="oidc", oidc=OidcConfig(issuer=ISS, client_id="c", client_key_file=str(bad_key)))
    with pytest.raises(OidcError, match=r"key\.pem"):
        Provider(keyed, FrozenClock(0), StubHttp({}))  # type: ignore[arg-type]


async def test_private_key_jwt_assertion(tmp_path: Path) -> None:
    key_file = tmp_path / "k.pem"
    key_file.write_bytes(jose.key_pem(jose.new_key("ec")))
    cfg = AuthConfig(mode="oidc", oidc=OidcConfig(issuer=ISS, client_id="slowshield", client_key_file=str(key_file)))
    p = Provider(cfg, FrozenClock(1_000_000.0), StubHttp({}))  # type: ignore[arg-type]
    assert p.client_auth_method == "private_key_jwt"
    headers, form = p._client_auth(f"{ISS}/token")
    assert headers == {} and form["client_id"] == "slowshield"
    claims = jose.parse(form["client_assertion"]).claims
    assert claims["aud"] == f"{ISS}/token" and claims["exp"] - claims["iat"] == 60
