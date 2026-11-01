"""UI sign-in over HTTP: the routes under /ui/auth/ and the gate in front of the UI (docs/authentication.md).

Sign-in state (`state`, `nonce`, the PKCE verifier and where to go back to) lives in a short-lived cookie, not in one
node's memory or database: any node of a shield wall, or any worker, can finish a sign-in another one started.
Sessions live in SQLite, so every worker sees them; the browser only holds a random ID.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from collections.abc import Callable
from functools import partial
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from opentelemetry import trace
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from slowshield.auth import ANONYMOUS, Principal, jose, password, roles, store
from slowshield.auth.oidc import OidcError, Provider, pkce
from slowshield.context import AppContext
from slowshield.telemetry import instruments
from slowshield.web import client_ip

log = logging.getLogger(__name__)

SESSION_COOKIE = "__Host-slowshield_session"
LOGIN_COOKIE = "__Host-slowshield_login"
LOGIN_MAX_AGE = 600
FAILED_PASSWORD_DELAY = 0.5
OPEN_PREFIXES = ("/ui/static/", "/ui/auth/")
# The IdP's answers to prompt=none when it would have to ask the person: the IdP session is over.
NO_SESSION = frozenset({"login_required", "interaction_required", "consent_required", "account_selection_required"})

Render = Callable[..., Response]


def principal(request: Request) -> Principal:
    p = request.scope.get("state", {}).get("principal")
    return p if isinstance(p, Principal) else ANONYMOUS


def safe_next(value: str | None) -> str:
    """Where to go after signing in: a path in the UI only, never another site (no open redirect)."""
    if not value or len(value) > 2000:
        return "/ui/"
    if not (value == "/ui" or value.startswith("/ui/")) or value.startswith(OPEN_PREFIXES):
        return "/ui/"
    if "\\" in value or "//" in value.split("?", 1)[0] or any(ord(c) < 33 or ord(c) == 127 for c in value):
        return "/ui/"
    return value


def _host(scope: Scope) -> str:
    for k, v in scope.get("headers", ()):
        if k == b"host":
            host = v.decode("latin-1").strip().lower()
            for default in (":443", ":80"):
                if host.endswith(default):
                    return host[: -len(default)]
            return host
    return ""


def _is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


def _encode(obj: dict[str, Any]) -> str:
    return jose.b64url(json.dumps(obj, separators=(",", ":")).encode())


def _decode(text: str | None) -> dict[str, Any] | None:
    if not text or len(text) > 4096:
        return None
    try:
        obj = json.loads(jose.b64url_decode(text))
    except ValueError, jose.JoseError:
        return None
    return obj if isinstance(obj, dict) else None


class Auth:
    """Sign-in for one instance: its provider, its routes and its gate."""

    def __init__(self, ctx: AppContext, provider: Provider | None, render: Render) -> None:
        """`provider` None: password sign-in (SLOWSHIELD_AUTH=password), one local Admin."""
        self.ctx = ctx
        self._provider = provider
        self.render = render
        self._checking = asyncio.Semaphore(1)  # one scrypt check at a time per worker: 128 MiB each

    @property
    def provider(self) -> Provider:
        if self._provider is None:  # pragma: no cover - the OIDC routes aren't there without one
            raise RuntimeError("no OIDC provider")
        return self._provider

    @property
    def rechecks(self) -> bool:
        """Sessions go back to an IdP to be checked again: OIDC only."""
        return self._provider is not None

    async def close(self) -> None:
        if self._provider is not None:
            await self._provider.close()

    @property
    def settings(self) -> Any:
        return self.ctx.cfg.raw.auth

    def ui_url(self, scope: Scope) -> str | None:
        """The listed UI URL this request came in on: redirect URIs come from the list, never from the Host header."""
        host = _host(scope)
        for url in self.ctx.cfg.ui_urls():
            if urlsplit(url).netloc.lower() == host:
                return url
        return None

    def routes(self) -> list[Route]:
        if self._provider is None:
            return [
                Route("/ui/auth/login", self.password_form, methods=["GET"]),
                Route("/ui/auth/login", self.password_login, methods=["POST"]),
                Route("/ui/auth/logout", self.logout, methods=["POST"]),
                Route("/ui/auth/signed-out", self.signed_out, methods=["GET"]),
            ]
        return [
            Route("/ui/auth/login", self.login, methods=["GET"]),
            Route("/ui/auth/callback", self.callback, methods=["GET"]),
            Route("/ui/auth/logout", self.logout, methods=["POST"]),
            Route("/ui/auth/signed-out", self.signed_out, methods=["GET"]),
        ]

    def gate(self, app: ASGIApp) -> ASGIApp:
        return Gate(app, self)

    # ---- helpers ---------------------------------------------------------------------------------------------------

    def _ip(self, request: Request) -> str | None:
        cfg = self.ctx.cfg
        return client_ip(request.scope, cfg.trusted_networks) if cfg.raw.record_client_ip else None

    async def _audit(self, request: Request, action: str, **kw: Any) -> None:
        now = self.ctx.clock.now()
        ip = self._ip(request)
        await self.ctx.db.writer.run(partial(store.audit, now=now, action=action, client_ip=ip, **kw))

    async def session(self, request: Request) -> store.Session | None:
        token = request.cookies.get(SESSION_COOKIE)
        if not token or len(token) > 100:
            return None
        now = self.ctx.clock.now()
        conn = self.ctx.db.readers
        return await asyncio.to_thread(lambda: store.load_session(conn.get(), token, now))

    def _page(self, request: Request, status: int, heading: str, message: str, **extra: Any) -> Response:
        resp = self.render("auth.html.j2", request, title=heading, heading=heading, message=message, **extra)
        resp.status_code = status
        return resp

    def login_url(self, next_path: str, *, prompt: str | None = None) -> str:
        query = {"next": next_path, **({"prompt": prompt} if prompt else {})}
        return "/ui/auth/login?" + urlencode(query)

    def _set_session_cookie(self, resp: Response, token: str) -> None:
        resp.set_cookie(SESSION_COOKIE, token, max_age=int(self.settings.session_hours * 3600), path="/",
                        secure=True, httponly=True, samesite="lax")  # fmt: skip

    @staticmethod
    def _clear(resp: Response, name: str) -> None:
        resp.delete_cookie(name, path="/", secure=True, httponly=True, samesite="lax")

    # ---- routes ----------------------------------------------------------------------------------------------------

    # ---- password sign-in ----------------------------------------------------------------------------------------

    def password_form(self, request: Request, *, error: str | None = None, status: int = 200) -> Response:
        if self.ui_url(request.scope) is None:
            return PlainTextResponse("this host name isn't one of the UI's URLs (SLOWSHIELD_UI_URLS)", 421)
        next_path = safe_next(request.query_params.get("next"))
        resp = self.render("auth_password.html.j2", request, title="Sign in", next=next_path, error=error)
        resp.status_code = status
        return resp

    async def password_login(self, request: Request) -> Response:
        """The one local Admin signs in. Refused from another site (login CSRF); failures are slowed down and capped
        per client address."""
        from slowshield.ui import same_origin

        if not same_origin(request, self.ctx.cfg.trusted_networks):
            return PlainTextResponse("refused: the request came from another site", status_code=403)
        base = self.ui_url(request.scope)
        if base is None:
            return PlainTextResponse("this host name isn't one of the UI's URLs (SLOWSHIELD_UI_URLS)", 421)
        form = parse_qs((await request.body())[:4096].decode("utf-8", "replace"))
        username = (form.get("username") or [""])[0]
        given = (form.get("password") or [""])[0]
        next_path = safe_next((form.get("next") or [""])[0])
        address = client_ip(request.scope, self.ctx.cfg.trusted_networks) or "?"
        now = self.ctx.clock.now()
        reader = self.ctx.db.readers
        if await asyncio.to_thread(lambda: password.throttled(reader.get(), address, now)):
            await self._audit(request, "login_refused", actor=username[:100] or None, details={"reason": "throttled"})
            return self.password_form(request, error="Too many failed attempts. Wait a few minutes.", status=429)
        if self._checking.locked():  # one scrypt check at a time per worker (128 MiB each): no queue to pile up
            return self.password_form(request, error="Another sign-in is being checked. Try again.", status=429)
        settings = self.settings
        async with self._checking:  # the hash is checked whatever the username, so timing tells nothing
            hash_ok = await asyncio.to_thread(password.verify, settings.password_hash or "", given)
        ok = password.same(username, settings.username or "") & hash_ok
        if not ok:
            await self.ctx.db.writer.run(partial(password.failed, address=address, now=now))
            instruments.auth_logins.add(1, {"result": "refused"})
            await self._audit(request, "login_refused", actor=username[:100] or None, details={"reason": "password"})
            await asyncio.sleep(FAILED_PASSWORD_DELAY)  # slows guessing down; the cap stops it
            return self.password_form(request, error="Wrong username or password.", status=401)
        await self.ctx.db.writer.run(partial(password.succeeded, address=address))
        ident = store.Identity(provider="password", issuer="local", subject=settings.username, email=None,
                               email_verified=False, name=settings.username, role="admin",
                               role_source="password")  # fmt: skip
        now = self.ctx.clock.now()
        token = store.new_session_token()
        old = await self.session(request)
        replaces = old.principal.session if old is not None else None

        def op(conn: Any) -> store.Upserted:
            up = store.upsert_user(conn, ident, now)
            if not up.disabled:
                store.create_session(conn, token=token, user_id=up.user_id, host=base, idp_sid=None, id_token=None,
                                     now=now, hours=settings.session_hours, replaces=replaces)  # fmt: skip
            return up

        up = await self.ctx.db.writer.run(op)
        who = Principal(role="admin", user_id=up.user_id, name=settings.username)
        if up.disabled:  # `slowshield users enable <id>` lets them back in
            await self._audit(request, "login_refused", principal=who, details={"reason": "disabled"})
            return self.password_form(request, error="This account is disabled.", status=403)
        instruments.auth_logins.add(1, {"result": "ok"})
        await self._audit(request, "login", principal=who, details={"role": "admin", "source": "password"})
        log.info("signed in", extra={"user_id": up.user_id, "role": "admin"})
        resp = RedirectResponse(next_path, status_code=303, headers={"Cache-Control": "no-store"})
        self._set_session_cookie(resp, token)
        return resp

    # ---- OIDC sign-in ----------------------------------------------------------------------------------------------

    async def login(self, request: Request) -> Response:
        """Start a sign-in: to the IdP, with the state in a cookie. `prompt=none` is the silent recheck."""
        base = self.ui_url(request.scope)
        if base is None:
            return PlainTextResponse("this host name isn't one of the UI's URLs (SLOWSHIELD_UI_URLS)", 421)
        next_path = safe_next(request.query_params.get("next"))
        prompt = "none" if request.query_params.get("prompt") == "none" else None
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        verifier, challenge = pkce()
        try:
            url = await self.provider.authorization_url(
                redirect_uri=f"{base}/ui/auth/callback", state=state, nonce=nonce, challenge=challenge, prompt=prompt
            )
        except OidcError as exc:
            if prompt == "none" and (deferred := await self._defer_recheck(request, next_path, exc)):
                return deferred
            log.warning("sign-in unavailable: %s", exc, extra={"reason": exc.reason})
            instruments.auth_logins.add(1, {"result": "error"})
            return self._page(request, 503, "Sign-in unavailable",
                              "The identity provider can't be reached right now. The package proxy isn't affected; "
                              "try again in a moment.", retry=self.login_url(next_path))  # fmt: skip
        flow = {"s": state, "n": nonce, "v": verifier, "x": next_path, "p": prompt == "none", "h": base}
        resp = RedirectResponse(url, status_code=302, headers={"Cache-Control": "no-store"})
        resp.set_cookie(LOGIN_COOKIE, _encode(flow), max_age=LOGIN_MAX_AGE, path="/", secure=True, httponly=True,
                        samesite="lax")  # fmt: skip
        return resp

    async def callback(self, request: Request) -> Response:
        params = request.query_params
        flow = _decode(request.cookies.get(LOGIN_COOKIE))
        base = self.ui_url(request.scope)
        if flow is None or base is None or flow.get("h") != base:
            return self._restart(request, "The sign-in took too long or started elsewhere. Please sign in again.")
        state = params.get("state") or ""
        if not secrets.compare_digest(state.encode(), str(flow.get("s", "")).encode()):
            # Another sign-in (another tab) replaced this one's cookie, or a forged callback (login CSRF).
            return self._restart(request, "This sign-in doesn't match the one this browser started. Please sign in "
                                          "again.", flow)  # fmt: skip
        next_path = safe_next(flow.get("x"))
        silent = flow.get("p") is True
        old = await self.session(request)
        meta_iss = params.get("iss")
        try:
            meta = await self.provider.metadata()
        except OidcError as exc:
            if silent and (deferred := await self._defer_recheck(request, next_path, exc)):
                return deferred
            return self._unavailable(request, exc, next_path)
        # RFC 9207: a response from another IdP (mix-up), or one without the `iss` the IdP promised.
        if (meta_iss is not None or meta.iss_parameter) and meta_iss != self.provider.issuer:
            return await self._refuse(request, "issuer_mismatch", next_path, silent)
        if error := params.get("error"):
            if silent and error in NO_SESSION:
                return await self._ended(request, old, error, next_path)
            return await self._refuse(request, f"idp:{error[:60]}", next_path, silent)
        code = params.get("code")
        if not code:
            return await self._refuse(request, "no_code", next_path, silent)
        try:
            tokens = await self.provider.exchange(
                code=code, redirect_uri=f"{base}/ui/auth/callback", verifier=str(flow.get("v", "")),
                nonce=str(flow.get("n", "")),
            )  # fmt: skip
        except OidcError as exc:
            if exc.reason == "idp_unreachable":
                if silent and (deferred := await self._defer_recheck(request, next_path, exc)):
                    return deferred
                return self._unavailable(request, exc, next_path)
            log.warning("sign-in refused: %s", exc, extra={"reason": exc.reason})
            return await self._refuse(request, exc.reason, next_path, silent, detail=str(exc))
        return await self._signed_in(request, tokens.claims, tokens.id_token, base=base, next_path=next_path,
                                     silent=silent, old=old)  # fmt: skip

    async def _signed_in(
        self,
        request: Request,
        claims: dict[str, Any],
        id_token: str,
        *,
        base: str,
        next_path: str,
        silent: bool,
        old: store.Session | None,
    ) -> Response:
        settings = self.settings
        if rule := roles.missing_required(claims, settings.oidc.require_claims):
            return await self._refuse(request, "required_claim", next_path, silent, detail=rule)
        decided = roles.decide(settings, claims)
        if decided.warning:
            log.warning("sign-in: %s", decided.warning)
        email = claims.get("email") if isinstance(claims.get("email"), str) else None
        name = next((claims[k] for k in ("name", "preferred_username") if isinstance(claims.get(k), str)), None)
        ident = store.Identity(
            provider="oidc", issuer=self.provider.issuer, subject=claims["sub"], email=email,
            email_verified=roles.email_verified(claims), name=name, role=decided.role, role_source=decided.source,
        )  # fmt: skip
        now = self.ctx.clock.now()
        token = store.new_session_token()
        sid = claims.get("sid") if isinstance(claims.get("sid"), str) else None
        replaces = old.principal.session if old is not None else None

        def op(conn: Any) -> store.Upserted:
            up = store.upsert_user(conn, ident, now)
            if not up.disabled:
                store.create_session(conn, token=token, user_id=up.user_id, host=base, idp_sid=sid, id_token=id_token,
                                     now=now, hours=settings.session_hours, replaces=replaces)  # fmt: skip
            elif replaces:
                store.delete_session(conn, replaces)
            return up

        up = await self.ctx.db.writer.run(op)
        who = Principal(role=decided.role, user_id=up.user_id, name=name, email=email)
        if up.disabled:
            return await self._refuse(request, "disabled", next_path, silent, principal=who)
        if silent:
            instruments.auth_rechecks.add(1, {"result": "ok"})
        else:
            instruments.auth_logins.add(1, {"result": "ok"})
            await self._audit(request, "login", principal=who, details={"role": decided.role,
                                                                         "source": decided.source})  # fmt: skip
            log.info("signed in", extra={"user_id": up.user_id, "role": decided.role})
        if up.previous_role is not None and up.previous_role != decided.role:
            change = {"from": up.previous_role, "to": decided.role, "source": decided.source}
            await self._audit(request, "role_changed", principal=who, details=change)
        resp = RedirectResponse(next_path, status_code=303, headers={"Cache-Control": "no-store"})
        self._set_session_cookie(resp, token)
        self._clear(resp, LOGIN_COOKIE)
        return resp

    def _restart(self, request: Request, message: str, flow: dict[str, Any] | None = None) -> Response:
        next_path = safe_next(flow.get("x") if flow else None)
        resp = self._page(request, 400, "Sign-in interrupted", message, retry=self.login_url(next_path))
        self._clear(resp, LOGIN_COOKIE)
        return resp

    async def _defer_recheck(self, request: Request, next_path: str, exc: OidcError) -> Response | None:
        """The IdP is down during a recheck: a live session stays usable and tries again in a minute, rather than
        locking everyone out of the UI with the IdP."""
        current = await self.session(request)
        if current is None:
            return None
        log.warning("session recheck postponed: %s", exc, extra={"reason": exc.reason})
        instruments.auth_rechecks.add(1, {"result": "error"})
        retry_at = self.ctx.clock.now() - self.settings.recheck_minutes * 60 + 60
        await self.ctx.db.writer.run(partial(store.defer_recheck, id_hash=str(current.principal.session), at=retry_at))
        resp = RedirectResponse(next_path, status_code=303)
        self._clear(resp, LOGIN_COOKIE)
        return resp

    def _unavailable(self, request: Request, exc: OidcError, next_path: str) -> Response:
        log.warning("sign-in unavailable: %s", exc, extra={"reason": exc.reason})
        instruments.auth_logins.add(1, {"result": "error"})
        resp = self._page(request, 503, "Sign-in unavailable",
                          "The identity provider can't be reached right now. The package proxy isn't affected; try "
                          "again in a moment.", retry=self.login_url(next_path))  # fmt: skip
        self._clear(resp, LOGIN_COOKIE)
        return resp

    async def _refuse(
        self,
        request: Request,
        reason: str,
        next_path: str,
        silent: bool,
        *,
        detail: str | None = None,
        principal: Principal | None = None,
    ) -> Response:
        instruments.auth_logins.add(1, {"result": "refused"})
        details = {"reason": reason, **({"detail": detail[:300]} if detail else {})}
        await self._audit(request, "login_refused", principal=principal, details=details)
        old = await self.session(request)
        if old is not None:  # a refused recheck ends the session it was for
            await self.ctx.db.writer.run(partial(store.delete_session, id_hash=str(old.principal.session)))
        message = {
            "disabled": "Your account has been disabled on this SlowShield. Ask an administrator.",
            "required_claim": "Your account isn't allowed to use this SlowShield.",
        }.get(reason, "The identity provider's answer wasn't accepted. Please try again, or ask an administrator.")
        resp = self._page(request, 403, "Sign-in refused", message, retry=self.login_url(next_path))
        self._clear(resp, LOGIN_COOKIE)
        self._clear(resp, SESSION_COOKIE)
        return resp

    async def _ended(self, request: Request, old: store.Session | None, error: str, next_path: str) -> Response:
        """A silent recheck found the IdP session over (signed out, disabled, offboarded): so is this one."""
        instruments.auth_rechecks.add(1, {"result": "ended"})
        if old is not None:
            await self.ctx.db.writer.run(partial(store.delete_session, id_hash=str(old.principal.session)))
            await self._audit(request, "session_ended", principal=old.principal, details={"reason": error})
        if self.settings.require_login:
            resp: Response = RedirectResponse(self.login_url(next_path), status_code=303)
        else:
            resp = RedirectResponse(next_path, status_code=303)
        self._clear(resp, LOGIN_COOKIE)
        self._clear(resp, SESSION_COOKIE)
        return resp

    async def logout(self, request: Request) -> Response:
        from slowshield.ui import same_origin

        if not same_origin(request, self.ctx.cfg.trusted_networks):
            return PlainTextResponse("refused: the request came from another site", status_code=403)
        base = self.ui_url(request.scope)
        current = await self.session(request)
        end_url = None
        if current is not None:
            await self.ctx.db.writer.run(partial(store.delete_session, id_hash=str(current.principal.session)))
            await self._audit(request, "logout", principal=current.principal)
            if base is not None and self._provider is not None:
                end_url = await self.provider.end_session_url(
                    id_token=current.id_token, post_logout_redirect_uri=f"{base}/ui/auth/signed-out"
                )
        if end_url:
            # A page, not a redirect: CSP `form-action 'self'` stops a form's redirect to the IdP.
            resp = self.render("auth_leaving.html.j2", request, title="Signing out", url=end_url)
        else:
            resp = RedirectResponse("/ui/auth/signed-out", status_code=303)
        self._clear(resp, SESSION_COOKIE)
        return resp

    async def signed_out(self, request: Request) -> Response:
        return self._page(request, 200, "Signed out", "You have signed out of SlowShield.",
                          retry=self.login_url("/ui/"), retry_label="Sign in again")  # fmt: skip


class Gate:
    """In front of the UI: the session cookie becomes `request.state.principal`; anonymous requests go to the IdP when
    sign-in is required, and sessions due for a recheck go back to it silently. Everything outside /ui/ passes."""

    def __init__(self, app: ASGIApp, auth: Auth) -> None:
        self.app = app
        self.auth = auth

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path: str = scope.get("path", "")
        if scope["type"] != "http" or not (path == "/ui" or path.startswith("/ui/")) or path.startswith(OPEN_PREFIXES):
            await self.app(scope, receive, send)
            return
        auth = self.auth
        request = Request(scope)
        settings = auth.settings
        session = await auth.session(request)
        target = path + (f"?{scope['query_string'].decode('latin-1')}" if scope.get("query_string") else "")
        if session is not None:
            now = auth.ctx.clock.now()
            due = auth.rechecks and now - session.last_recheck > settings.recheck_minutes * 60
            if due and request.method in ("GET", "HEAD"):
                await self._to_idp(request, target, "none")(scope, receive, send)
                return
            if due:
                # A change on a role the IdP may have taken away since: recheck first, then the person does it again.
                if _is_htmx(request):
                    resp: Response = self._to_idp(request, target, "none")
                else:
                    resp = RedirectResponse(auth.login_url("/ui/", prompt="none"), status_code=303)
                await resp(scope, receive, send)
                return
            if now - session.last_seen > store.LAST_SEEN_EVERY:
                auth.ctx.db.writer.enqueue(partial(store.touch, id_hash=str(session.principal.session), now=now))
            who = session.principal
            span = trace.get_current_span()
            span.set_attribute("enduser.id", str(who.user_id))
            span.set_attribute("enduser.role", who.role)
        else:
            if settings.require_login:
                if auth.ui_url(scope) is None:
                    resp = PlainTextResponse("this host name isn't one of the UI's URLs (SLOWSHIELD_UI_URLS)", 421)
                elif request.method in ("GET", "HEAD"):
                    resp = self._to_idp(request, target, None)
                else:
                    resp = PlainTextResponse("sign in first", status_code=401)
                await resp(scope, receive, send)
                return
            who = ANONYMOUS
        scope.setdefault("state", {})["principal"] = who
        await self.app(scope, receive, send)

    def _to_idp(self, request: Request, target: str, prompt: str | None) -> Response:
        """Straight to the IdP, no sign-in page in between. An htmx request gets `HX-Redirect`, for the whole page."""
        if _is_htmx(request):
            current = request.headers.get("hx-current-url", "")
            parts = urlsplit(current)
            back = safe_next(parts.path + (f"?{parts.query}" if parts.query else "")) if current else "/ui/"
            return Response(status_code=401, headers={"HX-Redirect": self.auth.login_url(back, prompt=prompt),
                                                      "Cache-Control": "no-store"})  # fmt: skip
        return RedirectResponse(self.auth.login_url(safe_next(target), prompt=prompt), status_code=302,
                                headers={"Cache-Control": "no-store"})  # fmt: skip


def form_value(body: bytes, name: str) -> str:
    return (parse_qs(body[:4096].decode("latin-1")).get(name) or [""])[0]
