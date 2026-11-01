"""Password sign-in (SLOWSHIELD_AUTH=password): the UI read-only for everyone, a Sign in button for the one Admin."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from slowshield.auth import password, web
from slowshield.auth.web import SESSION_COOKIE
from tests.conftest import Running
from tests.integration.test_auth import SAME_ORIGIN, UI, advance, audit

SECRET = "correct horse battery staple"
SALT = bytes.fromhex("0123456789abcdef0123456789abcdef")
# The smallest scrypt cost SlowShield takes, so the many checks here stay quick; the real default is N=2^17.
HASH = f"scrypt:16384:8:1:{SALT.hex()}:{password._scrypt(SECRET, SALT, 2**14, 8, 1).hex()}"
DOCS = Path(__file__).resolve().parents[2] / "docs" / "authentication.md"
FORM = {**SAME_ORIGIN, "Content-Type": "application/x-www-form-urlencoded"}


@pytest.fixture(autouse=True)
def _fast_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web, "FAILED_PASSWORD_DELAY", 0)


@pytest.fixture
def start_password(start_app: Callable[..., Any]) -> Callable[..., Any]:
    async def start(*, require_login: bool = False, data_dir: Any = None) -> Running:
        extra = f"""
[auth]
mode = "password"
require_login = {"true" if require_login else "false"}
ui_urls = ["{UI}"]
username = "admin"
password_hash = "{HASH}"
"""
        return await start_app(extra, scheme="https", data_dir=data_dir)

    return start


async def _login(run: Running, user: str = "admin", pw: str = SECRET, next_path: str = "/ui/") -> Any:
    from urllib.parse import urlencode

    body = urlencode({"username": user, "password": pw, "next": next_path})
    return await run.client.post("/ui/auth/login", content=body, headers=FORM)


async def test_read_only_until_the_admin_signs_in(start_password: Callable[..., Any]) -> None:
    run = await start_password()
    page = await run.client.get("/ui/")
    assert page.status_code == 200 and 'href="/ui/auth/login?next=%2Fui%2F"' in page.text  # the Sign in button
    assert (await run.client.get("/ui/users")).status_code == 403
    form = await run.client.get("/ui/auth/login?next=/ui/blocklist")
    assert form.status_code == 200 and 'type="password"' in form.text and 'value="/ui/blocklist"' in form.text
    assert (await run.client.get("/ui/auth/callback")).status_code in (404, 405)  # no OIDC here

    for user, pw in (("admin", "wrong"), ("root", SECRET), ("", "")):
        r = await _login(run, user, pw)
        assert r.status_code == 401 and "Wrong username or password" in r.text
    assert SESSION_COOKIE not in run.client.cookies
    r = await _login(run, next_path="/ui/blocklist")
    assert r.status_code == 303 and r.headers["location"] == "/ui/blocklist"
    page = await run.client.get("/ui/")
    assert "Sign out" in page.text and "Admin" in page.text
    assert (await run.client.get("/ui/users")).status_code == 200
    assert run.rows("SELECT provider, issuer, subject, role, role_source FROM users") == [
        ("password", "local", "admin", "admin", "password")
    ]
    assert [a[0] for a in audit(run)] == ["login_refused"] * 3 + ["login"]
    advance(run, 16 * 60)
    assert (await run.client.get("/ui/")).status_code == 200  # no IdP to recheck with
    r = await run.client.post("/ui/auth/logout", headers=SAME_ORIGIN)
    assert r.status_code == 303 and r.headers["location"] == "/ui/auth/signed-out"
    assert "Sign out" not in (await run.client.get("/ui/")).text


async def test_require_login_shows_the_form(start_password: Callable[..., Any]) -> None:
    run = await start_password(require_login=True)
    r = await run.client.get("/ui/packages")
    assert r.status_code == 302 and r.headers["location"] == "/ui/auth/login?next=%2Fui%2Fpackages"
    assert (await run.client.get("/pypi/simple/alpha/")).status_code == 200  # the proxy never asks
    assert (await _login(run, next_path="/ui/packages")).headers["location"] == "/ui/packages"
    assert (await run.client.get("/ui/packages")).status_code == 200


async def test_guessing_is_capped(start_password: Callable[..., Any], tmp_path: Path) -> None:
    run = await start_password(data_dir=tmp_path / "data")
    other = await start_password(data_dir=tmp_path / "data")  # another worker: the same count
    for i in range(password.PER_ADDRESS):
        assert (await _login(run if i % 2 else other, pw="guess")).status_code == 401
    r = await _login(run)  # even the right password waits now
    assert r.status_code == 429 and "Too many failed attempts" in r.text
    assert audit(run)[-1][3] == '{"reason":"throttled"}'


async def test_login_csrf(start_password: Callable[..., Any]) -> None:
    run = await start_password()
    cross = {**FORM, "Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}
    r = await run.client.post("/ui/auth/login", content=f"username=admin&password={SECRET}", headers=cross)
    assert r.status_code == 403


def test_the_documented_python_line() -> None:
    """The exact `python3 -c` line from docs/authentication.md, with the password on stdin."""
    line = next(ln for ln in DOCS.read_text().splitlines() if ln.startswith("python3 -c 'import getpass"))
    code = line.removeprefix("python3 -c '").removesuffix("'")
    out = subprocess.run(  # noqa: S603 - our own interpreter and the docs' line
        [sys.executable, "-c", code], input=SECRET + "\n", capture_output=True, text=True, check=True, timeout=60
    ).stdout.strip()
    stored = out.removeprefix("SLOWSHIELD_AUTH_PASSWORD_HASH=")
    assert stored.startswith("scrypt:131072:8:1:") and password.problem(stored) is None
    assert password.verify(stored, SECRET) and not password.verify(stored, SECRET + "x")


def test_the_default_hash() -> None:
    stored = password.make_hash(SECRET)
    assert stored.startswith("scrypt:131072:8:1:") and password.verify(stored, SECRET)


def test_hash_password_command(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    import io

    from slowshield import cli

    monkeypatch.setattr("sys.stdin", io.StringIO(SECRET + "\n"))
    assert cli.main(["auth", "hash-password"]) == 0
    assert password.verify(capsys.readouterr().out.strip(), SECRET)
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert cli.main(["auth", "hash-password"]) == 2


async def test_everyone_together_is_capped_too(start_password: Callable[..., Any]) -> None:
    run = await start_password()
    for i in range(password.OVERALL):  # from many addresses, as a distributed guess would
        headers = {**FORM, "X-Forwarded-For": f"203.0.113.{i}"}
        r = await run.client.post("/ui/auth/login", content="username=admin&password=guess", headers=headers)
        assert r.status_code == 401
    assert (await _login(run)).status_code == 429


async def test_one_check_at_a_time(start_password: Callable[..., Any]) -> None:
    run = await start_password()
    auth = run.ctx.auth
    async with auth._checking:  # a check is under way on this worker
        r = await _login(run)
    assert r.status_code == 429 and "Try again" in r.text
    assert (await _login(run)).status_code == 303


async def test_a_new_password_ends_earlier_sessions(
    start_app: Callable[..., Any], start_password: Callable[..., Any], tmp_path: Path
) -> None:
    run = await start_password(data_dir=tmp_path / "data")
    await _login(run)
    assert run.rows("SELECT count(*) FROM ui_sessions") == [(1,)]
    again = await start_password(data_dir=tmp_path / "data")  # a restart with the same password keeps them
    assert again.rows("SELECT count(*) FROM ui_sessions") == [(1,)]
    other = password.make_hash("another long password!", salt=SALT)
    extra = f"""
[auth]
mode = "password"
ui_urls = ["{UI}"]
username = "admin"
password_hash = "{other}"
"""
    changed = await start_app(extra, scheme="https", data_dir=tmp_path / "data")
    assert changed.rows("SELECT count(*) FROM ui_sessions") == [(0,)]
    assert "Sign out" not in (await run.client.get("/ui/")).text
