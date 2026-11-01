"""UI sign-in end to end: the app against the fake IdP in fakeupstream (fakeupstream/oidc.py), over real HTTP."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fakeupstream.oidc import CLIENT_SECRET

from slowshield.auth import jose
from slowshield.auth.web import LOGIN_COOKIE, SESSION_COOKIE
from tests.conftest import NOW, Running

UI = "https://slowshield.test"
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin", "Origin": UI}


def auth_toml(fake_url: str, secret_file: Path, **extra: Any) -> str:
    settings = {
        "mode": "oidc",
        "ui_urls": [UI],
        "oidc": {
            "issuer": f"{fake_url}/oidc",
            "client_id": "slowshield",
            "client_secret_file": str(secret_file),
            "roles_claim": "slowshield_roles",
            "admin_values": ["SlowShield Admins"],
            "user_values": ["SlowShield Users"],
        },
    }
    for key, value in extra.items():
        if key.startswith("oidc_"):
            settings["oidc"][key[5:]] = value  # type: ignore[index]
        else:
            settings[key] = value
    return "auth = " + _toml(settings)


def _toml(value: Any) -> str:
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{k} = {_toml(v)}" for k, v in value.items() if v is not None) + " }"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[" + ", ".join(_toml(v) for v in value) + "]"
    if isinstance(value, int | float):
        return str(value)
    return json.dumps(value)


@pytest.fixture
def secret_file(tmp_path: Path) -> Path:
    path = tmp_path / "client_secret"
    path.write_text(CLIENT_SECRET + "\n")
    return path


@pytest.fixture
def start_auth(start_app: Callable[..., Any], upstream: Any, secret_file: Path) -> Callable[..., Any]:
    async def start(**extra: Any) -> Running:
        data_dir = extra.pop("data_dir", None)
        return await start_app(auth_toml(upstream.url, secret_file, **extra), scheme="https", data_dir=data_dir)

    return start


def idp(run: Running, **settings: Any) -> None:
    run.fake.control("oidc", settings)


def idp_log(run: Running, kind: str) -> list[dict[str, Any]]:
    return [e for e in run.fake.control("oidc-log") if e["kind"] == kind]


async def to_idp(run: Running, location: str) -> httpx.Response:
    async with httpx.AsyncClient() as browser:
        return await browser.get(location)


async def sign_in(run: Running, next_path: str = "/ui/", *, finish: Running | None = None) -> httpx.Response:
    """Through the whole flow; `finish` lets another instance (a shield wall node) take the callback."""
    r = await run.client.get("/ui/auth/login", params={"next": next_path})
    assert r.status_code == 302, r.text
    at_idp = await to_idp(run, r.headers["location"])
    assert at_idp.status_code == 302, at_idp.text
    back = urlsplit(at_idp.headers["location"])
    assert f"{back.scheme}://{back.netloc}" == UI
    other = finish or run
    if finish is not None:
        finish.client.cookies.set(LOGIN_COOKIE, run.client.cookies[LOGIN_COOKIE], domain="slowshield.test")
    return await other.client.get(f"{back.path}?{back.query}")


def advance(run: Running, seconds: float) -> None:
    """Time passes for SlowShield and the IdP alike."""
    run.clock.advance(seconds)
    run.fake.control("clock", offset=run.clock.now() - NOW)


def audit(run: Running) -> list[tuple[Any, ...]]:
    return run.rows("SELECT action, actor, target, details FROM audit_log ORDER BY id")


# ---- nothing changes by default --------------------------------------------------------------------------------------


async def test_default_is_unchanged(running: Running) -> None:
    for path in ("/ui/auth/login", "/ui/auth/callback", "/ui/users", "/ui/activity", "/ui/activity.csv"):
        r = await running.client.get(path)
        assert r.status_code == 404 or "Not found" in r.text, path
    r = await running.client.get("/ui/")
    assert r.status_code == 200
    assert "set-cookie" not in r.headers
    assert "Sign in" not in r.text and "/ui/auth/" not in r.text
    assert (await running.client.post("/ui/auth/logout", headers=SAME_ORIGIN)).status_code in (404, 405)


# ---- signing in ------------------------------------------------------------------------------------------------------


async def test_sign_in_with_par_and_secret(start_auth: Callable[..., Any]) -> None:
    run = await start_auth()
    r = await sign_in(run, "/ui/packages?q=al")
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/packages?q=al"
    cookie = next(c for c in r.headers.get_list("set-cookie") if c.startswith(SESSION_COOKIE))
    assert all(flag in cookie.lower() for flag in ("secure", "httponly", "samesite=lax", "path=/"))
    assert "domain=" not in cookie.lower()
    authorize = idp_log(run, "authorize")[-1]
    assert authorize["via_par"] is True
    assert authorize["params"]["code_challenge_method"] == "S256"
    assert authorize["params"]["redirect_uri"] == f"{UI}/ui/auth/callback"
    assert idp_log(run, "client_auth")[-1] == {"kind": "client_auth", "method": "client_secret_basic", "ok": True}

    page = await run.client.get("/ui/")
    assert "Alice Example" in page.text and "Sign out" in page.text
    assert run.rows("SELECT email, email_verified, name, role, role_source FROM users") == [
        ("alice@example.com", 1, "Alice Example", "admin", "claim:SlowShield Admins")
    ]
    assert [a[0] for a in audit(run)] == ["login"]
    assert (await run.client.get("/ui/users")).status_code == 200
    assert "alice@example.com" in (await run.client.get("/ui/users")).text
    assert "Signed in" in (await run.client.get("/ui/activity")).text
    csv = await run.client.get("/ui/activity.csv")
    assert csv.status_code == 200 and "login" in csv.text


async def test_sign_in_with_private_key_jwt(start_auth: Callable[..., Any], tmp_path: Path) -> None:
    key = jose.new_key("ec")
    key_file = tmp_path / "client.pem"
    key_file.write_bytes(jose.key_pem(key))
    client = jose.load_client_key(key_file.read_bytes())
    run = await start_auth(oidc_client_secret_file=None, oidc_client_key_file=str(key_file), oidc_par="off")
    idp(run, client_jwk={**client.public_jwk(), "kid": client.kid})
    r = await sign_in(run)
    assert r.status_code == 303, r.text
    assert idp_log(run, "authorize")[-1]["via_par"] is False
    auths = idp_log(run, "client_auth")
    assert auths and all(a["method"] == "private_key_jwt" and a["ok"] for a in auths), auths


async def test_par_required_without_par_at_the_idp(start_auth: Callable[..., Any], upstream: Any) -> None:
    upstream.control("oidc", {"par": False})
    run = await start_auth(oidc_par="required")
    r = await run.client.get("/ui/auth/login")
    assert r.status_code == 503
    assert "Sign-in unavailable" in r.text


@pytest.mark.parametrize(
    ("claims", "role", "source"),
    [
        ({"slowshield_roles": ["SlowShield Users"]}, "user", "claim:SlowShield Users"),
        ({"slowshield_roles": ["SlowShield Users", "SlowShield Admins"]}, "admin", "claim:SlowShield Admins"),
        ({"slowshield_roles": []}, "viewer", "default"),
        ({"slowshield_roles": [], "email": "boss@example.com"}, "admin", "email:boss@example.com"),
        ({"slowshield_roles": [], "email": "dev@eng.example.com"}, "user", "email:*@eng.example.com"),
        ({"slowshield_roles": [], "email": "boss@example.com", "email_verified": False}, "viewer", "default"),
        ({"slowshield_roles": [], "email": "boss@example.com", "email_verified": None}, "viewer", "default"),
    ],
)
async def test_roles(start_auth: Callable[..., Any], claims: dict[str, Any], role: str, source: str) -> None:
    run = await start_auth(admin_emails=["boss@example.com"], user_emails=["*@eng.example.com"])
    base = {"email": "alice@example.com", "email_verified": True, "name": "Alice Example"}
    idp(run, claims={k: v for k, v in {**base, **claims}.items() if v is not None})
    assert (await sign_in(run)).status_code == 303
    assert run.rows("SELECT role, role_source FROM users") == [(role, source)]
    page = await run.client.get("/ui/users")
    assert page.status_code == (200 if role == "admin" else 403)


async def test_roles_from_userinfo(start_auth: Callable[..., Any]) -> None:
    run = await start_auth()
    idp(run, userinfo_only=["slowshield_roles"])
    assert (await sign_in(run)).status_code == 303
    assert run.rows("SELECT role FROM users") == [("admin",)]
    assert idp_log(run, "userinfo")[-1]["ok"] is True


async def test_group_overage_gives_the_default_role(start_auth: Callable[..., Any]) -> None:
    run = await start_auth(oidc_roles_claim="groups", oidc_admin_values=["admins"], oidc_user_values=[])
    idp(run, claims={"name": "E", "_claim_names": {"groups": "src1"}}, userinfo_only=[])
    assert (await sign_in(run)).status_code == 303
    assert run.rows("SELECT role, role_source FROM users") == [("viewer", "default")]


async def test_required_claims(start_auth: Callable[..., Any]) -> None:
    run = await start_auth(oidc_require_claims=["hd=example.com"])
    r = await sign_in(run)
    assert r.status_code == 403
    assert run.rows("SELECT count(*) FROM users") == [(0,)]
    assert audit(run)[-1][0] == "login_refused"
    idp(run, claims={"name": "A", "email": "a@example.com", "email_verified": True, "hd": "example.com"})
    assert (await sign_in(run)).status_code == 303


@pytest.mark.parametrize(
    "bad",
    [
        "wrong_aud",
        "wrong_iss",
        "wrong_nonce",
        "expired",
        "future_nbf",
        "alg_none",
        "hs256",
        "unknown_kid",
        "bad_sig",
        "extra_aud",
        "wrong_iss_param",
    ],
)
async def test_bad_tokens_are_refused(start_auth: Callable[..., Any], bad: str) -> None:
    run = await start_auth()
    idp(run, bad=bad)
    r = await sign_in(run)
    assert r.status_code == 403, (bad, r.status_code, r.text[:300])
    assert SESSION_COOKIE not in run.client.cookies
    assert run.rows("SELECT count(*) FROM ui_sessions") == [(0,)]
    assert audit(run)[-1][0] == "login_refused"
    assert (await run.client.get("/ui/users")).status_code == 403


@pytest.mark.parametrize("alg", ["ES256", "PS256"])
async def test_other_signing_algorithms(start_auth: Callable[..., Any], alg: str) -> None:
    run = await start_auth()
    idp(run, alg=alg)
    assert (await sign_in(run)).status_code == 303


async def test_rotated_key_is_fetched(start_auth: Callable[..., Any]) -> None:
    run = await start_auth()
    assert (await sign_in(run)).status_code == 303
    idp(run, kid="rsa-2", jwks=["rsa-2"])
    advance(run, 60)
    assert (await sign_in(run)).status_code == 303


async def test_state_mismatch_and_lost_cookie(start_auth: Callable[..., Any]) -> None:
    run = await start_auth()
    r = await run.client.get("/ui/auth/login")
    at_idp = await to_idp(run, r.headers["location"])
    back = urlsplit(at_idp.headers["location"])
    forged = back.query.replace("state=", "state=x")
    assert (await run.client.get(f"{back.path}?{forged}")).status_code == 400
    run.client.cookies.delete(LOGIN_COOKIE)
    assert (await run.client.get(f"{back.path}?{back.query}")).status_code == 400
    assert run.rows("SELECT count(*) FROM ui_sessions") == [(0,)]


@pytest.mark.parametrize("target", ["https://evil.example/", "//evil.example/", "/\\evil.example", "/ui/auth/logout",
                                    "/pypi/simple/", "/ui//evil", "javascript:alert(1)"])  # fmt: skip
async def test_next_stays_in_the_ui(start_auth: Callable[..., Any], target: str) -> None:
    run = await start_auth()
    r = await sign_in(run, target)
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/"


async def test_unlisted_host(start_auth: Callable[..., Any]) -> None:
    run = await start_auth(require_login=True)
    r = await run.client.get("/ui/auth/login", headers={"Host": "other.example"})
    assert r.status_code == 421
    r = await run.client.get("/ui/", headers={"Host": "other.example"})
    assert r.status_code == 421


async def test_another_node_finishes_the_sign_in(start_auth: Callable[..., Any], tmp_path: Path) -> None:
    a = await start_auth(data_dir=tmp_path / "a")
    b = await start_auth(data_dir=tmp_path / "b")
    r = await sign_in(a, "/ui/blocklist", finish=b)
    assert r.status_code == 303 and r.headers["location"] == "/ui/blocklist"
    assert b.rows("SELECT count(*) FROM ui_sessions") == [(1,)]
    assert a.rows("SELECT count(*) FROM ui_sessions") == [(0,)]


# ---- requiring sign-in -----------------------------------------------------------------------------------------------


async def test_require_login_sends_the_ui_to_the_idp(start_auth: Callable[..., Any]) -> None:
    run = await start_auth(require_login=True)
    r = await run.client.get("/ui/security?range=7d")
    assert r.status_code == 302
    assert r.headers["location"] == "/ui/auth/login?next=%2Fui%2Fsecurity%3Frange%3D7d"
    htmx = await run.client.get("/ui/partials/dashboard", headers={"HX-Request": "true",
                                                                   "HX-Current-URL": f"{UI}/ui/?range=1h"})  # fmt: skip
    assert htmx.status_code == 401
    assert htmx.headers["hx-redirect"] == "/ui/auth/login?next=%2Fui%2F%3Frange%3D1h"
    assert (await run.client.post("/ui/shieldwall/join", headers=SAME_ORIGIN)).status_code == 401
    # Never the proxy, the probes or the UI's assets.
    for path in ("/pypi/simple/alpha/", "/npm/@acme/widget", "/healthz", "/readyz", "/ui/static/app.css"):
        assert (await run.client.get(path)).status_code == 200, path
    assert (await sign_in(run, "/ui/security?range=7d")).headers["location"] == "/ui/security?range=7d"
    assert (await run.client.get("/ui/security?range=7d")).status_code == 200


async def test_public_ui_with_sign_in(start_auth: Callable[..., Any]) -> None:
    run = await start_auth()
    r = await run.client.get("/ui/")
    assert r.status_code == 200
    assert 'href="/ui/auth/login?next=%2Fui%2F"' in r.text
    users = await run.client.get("/ui/users")
    assert users.status_code == 403 and "Sign in to see this page" in users.text


async def test_idp_down(start_auth: Callable[..., Any]) -> None:
    run = await start_auth(require_login=True)
    run.fake.control("fail", prefix="/oidc/par", status=503)
    r = await run.client.get("/ui/auth/login")
    assert r.status_code == 503 and "Sign-in unavailable" in r.text
    assert (await run.client.get("/pypi/simple/alpha/")).status_code == 200


async def test_starts_with_the_idp_unreachable(start_app: Callable[..., Any], secret_file: Path) -> None:
    run = await start_app(auth_toml("http://127.0.0.1:9", secret_file), scheme="https")
    assert (await run.client.get("/readyz")).status_code == 200
    assert (await run.client.get("/ui/auth/login")).status_code == 503


# ---- rechecks, signing out, disabling --------------------------------------------------------------------------------


async def _recheck(run: Running, path: str = "/ui/") -> httpx.Response:
    r = await run.client.get(path)
    assert r.status_code == 302 and "prompt=none" in r.headers["location"], (r.status_code, r.headers)
    r = await run.client.get(r.headers["location"])
    assert r.status_code == 302
    at_idp = await to_idp(run, r.headers["location"])
    assert idp_log(run, "authorize")[-1]["params"]["prompt"] == "none"  # silent: through PAR here
    back = urlsplit(at_idp.headers["location"])
    return await run.client.get(f"{back.path}?{back.query}")


async def test_recheck_keeps_a_live_session_and_takes_new_roles(start_auth: Callable[..., Any]) -> None:
    run = await start_auth()
    await sign_in(run)
    old = run.client.cookies[SESSION_COOKIE]
    advance(run, 10 * 60)
    assert (await run.client.get("/ui/")).status_code == 200  # not due yet
    idp(run, claims={"name": "Alice Example", "slowshield_roles": ["SlowShield Users"]})
    advance(run, 6 * 60)
    r = await _recheck(run, "/ui/blocklist")
    assert r.status_code == 303 and r.headers["location"] == "/ui/blocklist"
    assert run.client.cookies[SESSION_COOKIE] != old  # a new session ID at every recheck
    assert run.rows("SELECT role FROM users") == [("user",)]
    assert [a[0] for a in audit(run)] == ["login", "role_changed"]
    assert (await run.client.get("/ui/users")).status_code == 403


async def test_recheck_ends_the_session_when_the_idp_did(start_auth: Callable[..., Any]) -> None:
    run = await start_auth()
    await sign_in(run)
    idp(run, logged_in=False)
    advance(run, 16 * 60)
    r = await _recheck(run)
    assert r.status_code == 303 and r.headers["location"] == "/ui/"
    assert run.rows("SELECT count(*) FROM ui_sessions") == [(0,)]
    assert audit(run)[-1][0] == "session_ended"
    page = await run.client.get("/ui/")
    assert page.status_code == 200 and "Sign in" in page.text


async def test_recheck_with_require_login_goes_to_interactive_sign_in(start_auth: Callable[..., Any]) -> None:
    run = await start_auth(require_login=True)
    await sign_in(run)
    idp(run, logged_in=False)
    advance(run, 16 * 60)
    r = await _recheck(run)
    assert r.status_code == 303 and r.headers["location"] == "/ui/auth/login?next=%2Fui%2F"


async def test_recheck_waits_when_the_idp_is_down(start_auth: Callable[..., Any]) -> None:
    run = await start_auth()
    await sign_in(run)
    advance(run, 16 * 60)
    run.fake.control("fail", prefix="/oidc/par", status=503)
    r = await run.client.get("/ui/")
    r = await run.client.get(r.headers["location"])
    assert r.status_code == 303 and r.headers["location"] == "/ui/"
    assert (await run.client.get("/ui/")).status_code == 200  # usable; tries again in a minute
    advance(run, 61)
    assert (await run.client.get("/ui/")).status_code == 302


async def test_a_change_waits_for_a_due_recheck(start_auth: Callable[..., Any]) -> None:
    """A role the IdP took away can't be used for a POST either: a session due for a recheck goes to the IdP first."""
    run = await start_auth()
    await sign_in(run)
    me = run.rows("SELECT id FROM users")[0][0]
    advance(run, 16 * 60)
    r = await run.client.post(f"/ui/users/{me + 1}/disable", headers=SAME_ORIGIN)
    assert r.status_code == 303 and r.headers["location"] == "/ui/auth/login?next=%2Fui%2F&prompt=none"
    r = await run.client.post(f"/ui/users/{me + 1}/disable", headers={**SAME_ORIGIN, "HX-Request": "true"})
    assert r.status_code == 401 and "prompt=none" in r.headers["hx-redirect"]
    assert [a[0] for a in audit(run)] == ["login"]


async def test_sign_out_at_the_idp(start_auth: Callable[..., Any]) -> None:
    run = await start_auth()
    await sign_in(run)
    assert (await run.client.post("/ui/auth/logout", headers={"Sec-Fetch-Site": "cross-site"})).status_code == 403
    r = await run.client.post("/ui/auth/logout", headers=SAME_ORIGIN)
    assert r.status_code == 200
    url = re.search(r'http-equiv="refresh" content="0;url=([^"]+)"', r.text)
    assert url is not None
    target = url.group(1).replace("&amp;", "&")
    q = parse_qs(urlsplit(target).query)
    assert q["post_logout_redirect_uri"] == [f"{UI}/ui/auth/signed-out"]
    assert q["client_id"] == ["slowshield"] and q["id_token_hint"]
    assert run.rows("SELECT count(*) FROM ui_sessions") == [(0,)]
    assert audit(run)[-1][0] == "logout"
    assert "Sign in" in (await run.client.get("/ui/")).text


async def test_sign_out_without_an_idp_logout(start_auth: Callable[..., Any], upstream: Any) -> None:
    upstream.control("oidc", {"end_session": False, "par": False, "iss_param": False})  # Google-like
    run = await start_auth()
    await sign_in(run)
    r = await run.client.post("/ui/auth/logout", headers=SAME_ORIGIN)
    assert r.status_code == 303 and r.headers["location"] == "/ui/auth/signed-out"
    assert (await run.client.get("/ui/auth/signed-out")).status_code == 200


async def test_admin_disables_a_user(start_auth: Callable[..., Any], tmp_path: Path) -> None:
    run = await start_auth()
    await sign_in(run)  # alice, admin
    bob = await start_auth(data_dir=tmp_path / "data")  # same database, another browser
    idp(bob, sub="bob", claims={"name": "Bob", "slowshield_roles": ["SlowShield Users"]})
    await sign_in(bob)
    bob_id = run.rows("SELECT id FROM users WHERE subject = 'bob'")[0][0]
    me = run.rows("SELECT id FROM users WHERE subject = 'alice'")[0][0]
    cross = {"Sec-Fetch-Site": "cross-site"}
    assert (await run.client.post(f"/ui/users/{bob_id}/disable", headers=cross)).status_code == 403
    assert (await bob.client.post(f"/ui/users/{me}/disable", headers=SAME_ORIGIN)).status_code == 403  # not an admin
    assert (await run.client.post(f"/ui/users/{me}/disable", headers=SAME_ORIGIN)).status_code == 409  # not yourself
    r = await run.client.post(f"/ui/users/{bob_id}/disable", headers=SAME_ORIGIN)
    assert r.status_code == 303
    assert "Bob" not in (await bob.client.get("/ui/")).text  # signed out at once
    assert (await sign_in(bob)).status_code == 403
    assert [a[0] for a in audit(run)][-2:] == ["user_disabled", "login_refused"]
    assert (await run.client.post(f"/ui/users/{bob_id}/enable", headers=SAME_ORIGIN)).status_code == 303
    assert (await sign_in(bob)).status_code == 303


async def test_client_ips_follow_the_privacy_setting(start_app: Callable[..., Any], upstream: Any, secret_file: Path):
    run = await start_app(auth_toml(upstream.url, secret_file) + "\nrecord_client_ip = false", scheme="https")
    await sign_in(run)
    assert run.rows("SELECT client_ip FROM audit_log") == [(None,)]


async def test_sessions_and_audit_retention(start_auth: Callable[..., Any]) -> None:
    from functools import partial

    from slowshield.auth.store import retention

    run = await start_auth()
    await sign_in(run)
    await run.ctx.db.writer.run(partial(retention, now=NOW + 13 * 3600, audit_days=365, ip_days=30))
    assert run.rows("SELECT count(*) FROM ui_sessions") == [(0,)]
    await run.ctx.db.writer.run(partial(retention, now=NOW + 31 * 86400, audit_days=365, ip_days=30))
    assert run.rows("SELECT client_ip FROM audit_log") == [(None,)]
    await run.ctx.db.writer.run(partial(retention, now=NOW + 366 * 86400, audit_days=365, ip_days=30))
    assert run.rows("SELECT count(*) FROM audit_log") == [(0,)]


async def test_confirming_a_shield_wall_leader_takes_an_admin(
    start_app: Callable[..., Any], upstream: Any, secret_file: Path
) -> None:
    from slowshield.shieldwall.identity import key_hash
    from slowshield.shieldwall.join import JoinString, new_token

    join = JoinString("https://hq.example", key_hash(b"leader key"), *new_token())
    extra = f'\n[shieldwall]\nrole = "follower"\njoin = "{join}"\n'
    run = await start_app(auth_toml(upstream.url, secret_file) + extra, scheme="https")
    await run.ctx.db.writer.run(
        lambda c: c.execute(
            "INSERT INTO shieldwall_leader (id, leader_id, url, pubkey, name, join_token, state, discovered) "
            "VALUES (1, 'L1', 'https://hq.example', x'00', 'hq', 't', 'pending', ?)",
            (NOW,),
        )
    )
    form = {**SAME_ORIGIN, "Content-Type": "application/x-www-form-urlencoded"}
    assert (await run.client.post("/ui/shieldwall/join", content="leader=L1", headers=form)).status_code == 403
    page = await run.client.get("/ui/shieldwall")
    assert "An administrator confirms the leader" in page.text and 'action="/ui/shieldwall/join"' not in page.text
    idp(run, claims={"name": "Uma", "slowshield_roles": ["SlowShield Users"]})
    await sign_in(run)
    assert (await run.client.post("/ui/shieldwall/join", content="leader=L1", headers=form)).status_code == 403
    idp(run, claims={"name": "Alice Example", "slowshield_roles": ["SlowShield Admins"]})
    await sign_in(run)
    assert 'action="/ui/shieldwall/join"' in (await run.client.get("/ui/shieldwall")).text
    assert (await run.client.post("/ui/shieldwall/join", content="leader=L1", headers=form)).status_code == 303
    user_id = run.rows("SELECT id FROM users")[0][0]
    assert run.rows("SELECT confirmed_by FROM shieldwall_leader") == [(f"user:{user_id}",)]
    assert audit(run)[-1][:3] == ("shieldwall_confirmed", "Alice Example", "L1")
