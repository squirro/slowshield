"""UI sign-in pieces on their own: JOSE, role rules, `next` paths, configuration and the CLI."""

from __future__ import annotations

import base64
import datetime
import json
from pathlib import Path
from typing import Any

import msgspec
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from slowshield import cli
from slowshield import config as config_mod
from slowshield.auth import ANONYMOUS, Principal, jose, roles
from slowshield.auth.web import safe_next
from slowshield.config import AuthConfig, OidcConfig

# ---- JOSE --------------------------------------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _token(header: dict[str, Any], claims: dict[str, Any], key: Any) -> str:
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}".encode()
    if isinstance(key, ec.EllipticCurvePrivateKey):
        client = jose.ClientKey(key)
        return client.sign(claims) if header.get("kid") == client.kid else _sign_ec(signing_input, key)
    pad = padding.PKCS1v15() if header["alg"] == "RS256" else padding.PSS(padding.MGF1(hashes.SHA256()), 32)
    return signing_input.decode() + "." + _b64(key.sign(signing_input, pad, hashes.SHA256()))


def _sign_ec(signing_input: bytes, key: ec.EllipticCurvePrivateKey) -> str:
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return signing_input.decode() + "." + _b64(r.to_bytes(32) + s.to_bytes(32))


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _rsa_jwk(key: rsa.RSAPrivateKey, **extra: Any) -> dict[str, Any]:
    return {**jose.ClientKey(key).public_jwk(), **extra}


@pytest.mark.parametrize("alg", ["RS256", "PS256"])
def test_rsa_signatures_verify(rsa_key: rsa.RSAPrivateKey, alg: str) -> None:
    jws = jose.parse(_token({"alg": alg, "kid": "k"}, {"sub": "a"}, rsa_key))
    jwk = _rsa_jwk(rsa_key, kid="k")
    assert jose.candidates(jws, [jwk, _rsa_jwk(rsa_key, kid="other")]) == [jwk]
    assert jose.verify(jws, jwk)
    assert not jose.verify(jws, {**jwk, "alg": "RS512"})  # a key's own `alg` binds it
    assert not jose.verify(jws, {**jwk, "use": "enc"})


def test_es256_and_the_client_assertion() -> None:
    client = jose.ClientKey(ec.generate_private_key(ec.SECP256R1()))
    token = client.assertion("slowshield", "https://idp/token", 1000.0)
    jws = jose.parse(token)
    assert jws.header == {"alg": "ES256", "typ": "JWT", "kid": client.kid}
    assert jws.claims["iss"] == jws.claims["sub"] == "slowshield"
    assert jws.claims["aud"] == "https://idp/token" and jws.claims["exp"] == 1060
    assert jose.verify(jws, {**client.public_jwk(), "kid": client.kid})
    head, body, sig = token.split(".")
    other = jose.ClientKey(ec.generate_private_key(ec.SECP256R1())).assertion("slowshield", "x", 1000.0)
    assert not jose.verify(jose.parse(f"{head}.{body}.{other.split('.')[2]}"), client.public_jwk())
    assert not jose.verify(jose.parse(f"{head}.{body}.{sig[:20]}"), client.public_jwk())  # wrong length


def test_rfc7638_thumbprint() -> None:
    # RFC 7638 section 3.1's example key and thumbprint.
    n = (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknj"
        "hMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQ"
        "vRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzK"
        "nqDKgw"
    )
    key = rsa.RSAPublicNumbers(65537, int.from_bytes(jose.b64url_decode(n))).public_key()

    class Fake(jose.ClientKey):
        def public_jwk(self) -> dict[str, str]:
            nums = key.public_numbers()
            return {"kty": "RSA", "e": jose.b64url(jose._bytes(nums.e)), "n": jose.b64url(jose._bytes(nums.n))}

    assert Fake(rsa.generate_private_key(65537, 2048)).kid == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


@pytest.mark.parametrize(
    "header",
    [{"alg": "none"}, {"alg": "HS256"}, {"alg": "RS512"}, {"alg": "EdDSA"}, {"alg": "RS256", "crit": ["exp"]}],
)
def test_refused_headers(header: dict[str, Any]) -> None:
    token = f"{_b64(json.dumps(header).encode())}.{_b64(b'{}')}.{_b64(b'sig')}"
    with pytest.raises(jose.JoseError):
        jose.parse(token)


@pytest.mark.parametrize("token", ["", "a.b", "a.b.c.d", "!!.e30.x", "e30.e30.x+y", "W10.e30.e30"])
def test_malformed_tokens(token: str) -> None:
    with pytest.raises(jose.JoseError):
        jose.parse(token)


def test_key_types_only_with_their_algorithms(rsa_key: rsa.RSAPrivateKey) -> None:
    ec_key = ec.generate_private_key(ec.SECP256R1())
    jws = jose.parse(_token({"alg": "RS256"}, {}, rsa_key))
    assert jose.candidates(jws, [jose.ClientKey(ec_key).public_jwk()]) == []
    small = rsa.generate_private_key(65537, 1024)  # noqa: S505 - refused
    with pytest.raises(jose.JoseError):
        jose.public_key(jose.ClientKey(small).public_jwk())
    with pytest.raises(jose.JoseError):
        jose.public_key({"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"})
    with pytest.raises(jose.JoseError):
        jose.public_key({"kty": "oct", "k": "AA"})


def test_client_key_files(tmp_path: Path, rsa_key: rsa.RSAPrivateKey) -> None:
    ec_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime(2026, 11, 1, tzinfo=datetime.UTC)
    cert = jose.self_signed(ec_key, "slowshield", 30, now)
    pem = jose.key_pem(ec_key) + cert.public_bytes(serialization.Encoding.PEM)
    client = jose.load_client_key(pem)
    assert client.certificate is not None and client.alg == "ES256"
    assert {"x5t#S256", "x5t"} <= jose.parse(client.sign({"a": 1})).header.keys()
    assert jose.load_client_key(jose.key_pem(rsa_key)).alg == "RS256"
    other = jose.self_signed(ec.generate_private_key(ec.SECP256R1()), "x", 30, now)
    for bad in (
        b"not a key",
        jose.key_pem(ec_key) + other.public_bytes(serialization.Encoding.PEM),
        jose.key_pem(ec.generate_private_key(ec.SECP384R1())),
        jose.key_pem(rsa.generate_private_key(65537, 1024)),  # noqa: S505 - refused
    ):
        with pytest.raises(jose.JoseError):
            jose.load_client_key(bad)


# ---- roles -----------------------------------------------------------------------------------------------------------


def _auth(**kw: Any) -> AuthConfig:
    oidc = OidcConfig(roles_claim=kw.pop("claim", "groups"), admin_values=kw.pop("admins", ["Admins"]),
                      user_values=kw.pop("users", ["Devs"]))  # fmt: skip
    return AuthConfig(mode="oidc", oidc=oidc, **kw)


def test_role_precedence_and_sources() -> None:
    auth = _auth(admin_emails=["root@example.com"], user_emails=["*@example.com"])
    decide = roles.decide
    assert decide(auth, {"groups": ["Devs", "Admins"]}) == roles.Role("admin", "claim:Admins")
    assert decide(auth, {"groups": "Devs"}) == roles.Role("user", "claim:Devs")
    assert decide(auth, {"groups": ["devs"]}).role == "viewer"  # exact values
    v = {"email_verified": True}
    assert decide(auth, {"email": "Root@Example.com", **v}) == roles.Role("admin", "email:root@example.com")
    assert decide(auth, {"email": "x@example.com", **v}) == roles.Role("user", "email:*@example.com")
    assert decide(auth, {"email": "x@example.com.evil", **v}).role == "viewer"
    assert decide(auth, {"email": "x@notexample.com", **v}).role == "viewer"
    assert decide(auth, {"email": "root@example.com", "email_verified": "true"}).role == "admin"
    assert decide(auth, {"email": "root@example.com", "email_verified": "false"}).role == "viewer"
    assert decide(auth, {"email": "root@example.com"}).role == "viewer"  # Entra ID: never verified
    assert decide(_auth(default_role="user"), {}) == roles.Role("user", "default")


def test_claim_paths() -> None:
    claims = {"realm_access": {"roles": ["Admins"]}, "https://example.com/roles": ["Devs"]}
    assert roles.decide(_auth(claim="realm_access.roles"), claims).role == "admin"
    assert roles.decide(_auth(claim="https://example.com/roles"), claims).role == "user"
    assert roles.decide(_auth(claim="realm_access.missing.deep"), claims).role == "viewer"


def test_overage_warns() -> None:
    r = roles.decide(_auth(), {"_claim_names": {"groups": "src1"}, "_claim_sources": {}})
    assert r.role == "viewer" and r.warning and "app roles" in r.warning


def test_required_claims() -> None:
    assert roles.missing_required({"hd": "example.com"}, ["hd=example.com"]) is None
    assert roles.missing_required({"hd": "evil.com"}, ["hd=example.com"]) == "hd=example.com"
    assert roles.missing_required({}, ["tid=abc"]) == "tid=abc"
    assert roles.missing_required({"groups": ["a", "b"]}, ["groups=b"]) is None
    assert roles.missing_required({"email_verified": True}, ["email_verified=true"]) is None


def test_principal() -> None:
    assert ANONYMOUS.label == "anonymous" and not ANONYMOUS.signed_in and ANONYMOUS.can("viewer")
    admin = Principal(role="admin", user_id=1, email="a@example.com")
    assert admin.can("user") and admin.label == "a@example.com"
    assert not Principal(role="user", user_id=2).can("admin")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/ui/packages?q=a", "/ui/packages?q=a"),
        ("/ui", "/ui"),
        (None, "/ui/"),
        ("https://evil.example/ui/", "/ui/"),
        ("//evil.example", "/ui/"),
        ("/ui//evil.example", "/ui/"),
        ("/ui/\\evil", "/ui/"),
        ("/ui/auth/callback", "/ui/"),
        ("/ui/static/x", "/ui/"),
        ("/ui/x\ny", "/ui/"),
        ("/uix", "/ui/"),
        ("/ui/" + "a" * 3000, "/ui/"),
    ],
)
def test_safe_next(value: str | None, expected: str) -> None:
    assert safe_next(value) == expected


# ---- configuration ---------------------------------------------------------------------------------------------------


def _cfg(auth: dict[str, Any], **top: Any) -> config_mod.LoadedConfig:
    data = {"public_url": "https://slowshield.example.com", **top, "auth": auth}
    return config_mod.build(msgspec.convert(data, config_mod.Config), path=None, warnings=[])


OK = {"mode": "oidc", "oidc": {"issuer": "https://idp.example/realms/r", "client_id": "c", "client_secret_file": "/s"}}


def _with(**oidc: Any) -> dict[str, Any]:
    return {**OK, "oidc": {**OK["oidc"], **oidc}}


def test_valid_auth_config() -> None:
    cfg = _cfg(OK)
    assert cfg.raw.auth.enabled and cfg.ui_urls() == ["https://slowshield.example.com"]
    assert _cfg({**OK, "ui_urls": ["https://a.example", "https://b.example:8443/"]}).ui_urls() == [
        "https://a.example",
        "https://b.example:8443",
    ]
    assert not _cfg({}).raw.auth.enabled
    assert _cfg(_with(issuer="http://127.0.0.1:9000/oidc")).raw.auth.oidc.issuer


@pytest.mark.parametrize(
    ("auth", "message"),
    [
        ({"require_login": True}, "needs sign-in"),
        (_with(issuer=None), "SLOWSHIELD_OIDC_ISSUER"),
        (_with(issuer="http://idp.example"), "must be https"),
        (_with(issuer="https://login.microsoftonline.com/common/v2.0"), "tenant"),
        (_with(issuer="https://login.microsoftonline.com/organizations/v2.0"), "tenant"),
        (_with(client_key_file="/k"), "exactly one"),
        (_with(client_secret_file=None), "exactly one"),
        (_with(scopes=["email"]), "openid"),
        (_with(admin_values=["x"]), "roles_claim"),
        (_with(require_claims=["hd"]), "claim=value"),
        ({**OK, "admin_emails": ["not-an-email"]}, "address"),
        ({**OK, "ui_urls": ["http://slowshield.example.com"]}, "https"),
        ({**OK, "ui_urls": ["http://127.0.0.1:8080"]}, "https"),
        ({**OK, "ui_urls": ["https://slowshield.example.com/sub"]}, "without a path"),
        ({**OK, "ui_urls": ["https://a.example", "https://A.example/"]}, "once"),
        ({**OK, "session_hours": 0}, "session_hours"),
        ({**OK, "recheck_minutes": 0}, "recheck_minutes"),
    ],
)
def test_invalid_auth_config(auth: dict[str, Any], message: str) -> None:
    with pytest.raises(config_mod.ConfigError, match=message):
        _cfg(auth)


def test_auth_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    env = {
        "SLOWSHIELD_AUTH": "oidc",
        "SLOWSHIELD_UI_REQUIRE_LOGIN": "true",
        "SLOWSHIELD_UI_URLS": "https://slowshield.example.com, https://slowshield.tailnet.ts.net",
        "SLOWSHIELD_OIDC_ISSUER": "https://idp.example/realms/r",
        "SLOWSHIELD_OIDC_CLIENT_ID": "slowshield",
        "SLOWSHIELD_OIDC_CLIENT_KEY_FILE": "/run/secrets/key.pem",
        "SLOWSHIELD_OIDC_PAR": "required",
        "SLOWSHIELD_OIDC_SCOPES": "openid email",
        "SLOWSHIELD_OIDC_ROLES_CLAIM": "slowshield_roles",
        "SLOWSHIELD_OIDC_ADMIN_VALUES": "SlowShield Admins, Ops - Team",
        "SLOWSHIELD_OIDC_USER_VALUES": "SlowShield Users",
        "SLOWSHIELD_OIDC_REQUIRE_CLAIMS": "hd=example.com",
        "SLOWSHIELD_AUTH_ADMIN_EMAILS": "root@example.com,*@sec.example.com",
        "SLOWSHIELD_AUTH_DEFAULT_ROLE": "user",
        "SLOWSHIELD_SESSION_HOURS": "8",
        "SLOWSHIELD_SESSION_RECHECK_MINUTES": "5",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    auth = config_mod.load(None).raw.auth
    assert auth.require_login and auth.default_role == "user"
    assert auth.ui_urls == ["https://slowshield.example.com", "https://slowshield.tailnet.ts.net"]
    assert auth.oidc.admin_values == ["SlowShield Admins", "Ops - Team"]
    assert auth.oidc.scopes == ["openid", "email"] and auth.oidc.par == "required"
    assert auth.admin_emails == ["root@example.com", "*@sec.example.com"]
    assert (auth.session_hours, auth.recheck_minutes) == (8, 5)
    monkeypatch.setenv("SLOWSHIELD_AUTH", "saml")
    with pytest.raises(config_mod.ConfigError, match="none, oidc or password"):
        config_mod.load(None)


def test_auth_changes_need_a_restart() -> None:
    old, new = _cfg({}).raw, _cfg(OK).raw
    assert "auth" in config_mod.restart_only_changes(old, new)


# ---- CLI -------------------------------------------------------------------------------------------------------------


def test_client_cert_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = tmp_path / "key.pem"
    assert cli.main(["auth", "client-cert", "--key", str(key), "--new", "ec"]) == 0
    assert key.stat().st_mode & 0o777 == 0o600
    out = capsys.readouterr()
    assert out.out.startswith("-----BEGIN CERTIFICATE-----") and "kid " in out.err
    assert cli.main(["auth", "client-cert", "--key", str(key), "--new", "ec"]) == 2  # never overwrites
    assert cli.main(["auth", "client-cert", "--key", str(key), "--jwk"]) == 0
    jwks = json.loads(capsys.readouterr().out)
    assert jwks["keys"][0]["kid"] == jose.load_client_key(key.read_bytes()).kid


def test_users_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from slowshield.auth import store
    from slowshield.db import connect, migrate

    monkeypatch.setenv("SLOWSHIELD_DATA_DIR", str(tmp_path))
    db = tmp_path / "slowshield.db"
    migrate(db)
    conn = connect(db)
    ident = store.Identity("oidc", "https://idp", "alice", "a@example.com", True, "Alice", "admin", "default")
    up = store.upsert_user(conn, ident, 1000.0)
    store.create_session(conn, token="t", user_id=up.user_id, host="https://x", idp_sid=None, id_token=None,
                         now=1000.0, hours=1e6)  # fmt: skip
    assert cli.main(["users", "list"]) == 0
    assert "a@example.com" in capsys.readouterr().out
    assert cli.main(["users", "disable", str(up.user_id)]) == 0
    assert conn.execute("SELECT count(*) FROM ui_sessions").fetchone()[0] == 0
    assert cli.main(["users", "disable", "999"]) == 2
    assert cli.main(["users", "enable", str(up.user_id)]) == 0
    assert cli.main(["users", "list", "--json"]) == 0
    assert '"disabled": null' in capsys.readouterr().out
    assert cli.main(["users", "logout-all"]) == 0
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_log ORDER BY id")]
    assert actions == ["user_disabled", "user_enabled", "logout_all"]


@pytest.mark.parametrize(
    ("auth", "message"),
    [
        ({"mode": "password", "password_hash": "sha256:0123456789abcdef:" + "a" * 64}, "USERNAME"),
        ({"mode": "password", "username": "admin"}, "PASSWORD_HASH"),
        ({"mode": "password", "username": "admin", "password_hash": "sha256:short:" + "a" * 64}, "PASSWORD_HASH"),
        ({"mode": "password", "username": "admin", "password_hash": "md5:0123456789abcdef:" + "a" * 32}, "sha256"),
        (
            {"mode": "password", "username": "my admin", "password_hash": "sha256:0123456789abcdef:" + "a" * 64},
            "spaces",
        ),
    ],
)
def test_invalid_password_config(auth: dict[str, Any], message: str) -> None:
    with pytest.raises(config_mod.ConfigError, match=message):
        _cfg(auth)


def test_password_config_from_the_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from slowshield.auth.password import make_hash, verify

    stored = make_hash("correct horse battery staple")
    (tmp_path / "hash").write_text(stored + "\n")
    monkeypatch.setenv("SLOWSHIELD_PUBLIC_URL", "https://localhost")
    monkeypatch.setenv("SLOWSHIELD_AUTH", "password")
    monkeypatch.setenv("SLOWSHIELD_AUTH_USERNAME", "admin")
    monkeypatch.setenv("SLOWSHIELD_AUTH_PASSWORD_HASH_FILE", str(tmp_path / "hash"))
    auth = config_mod.load(None).raw.auth
    assert auth.mode == "password" and auth.password_hash == stored
    assert verify(stored, "correct horse battery staple") and not verify(stored, "wrong")
    assert not verify("sha256:salt:short", "x") and not verify("garbage", "x")
