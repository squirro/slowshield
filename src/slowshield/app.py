"""ASGI application factory (used by Granian with `factory=True` and by the tests)."""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import logging
import os
import time
from collections.abc import Awaitable
from functools import partial
from pathlib import Path
from typing import Any

from opentelemetry import context as otel_context
from opentelemetry import propagate
from opentelemetry.trace import SpanKind, Status, StatusCode
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route, Router
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from slowshield import __version__, telemetry
from slowshield.blocklist import Blocklist
from slowshield.cache.artifacts import ArtifactCache
from slowshield.cache.kv import KVStore
from slowshield.cache.metadata import LRUCache
from slowshield.clock import Clock, SystemClock
from slowshield.config import ConfigHolder, LoadedConfig, load
from slowshield.context import AppContext
from slowshield.db import Database
from slowshield.ecosystems.artifacts import ArtifactServer
from slowshield.ecosystems.go.service import GoService
from slowshield.ecosystems.maven.service import MavenService
from slowshield.ecosystems.npm.service import NpmService
from slowshield.ecosystems.pypi.service import PypiService
from slowshield.feeds import FeedScheduler
from slowshield.feeds.github import GithubFeed
from slowshield.feeds.osv import OsvFeed
from slowshield.recorder import Recorder, retention
from slowshield.telemetry import instruments, logsetup, process
from slowshield.upstream import Upstream
from slowshield.web.security import SecurityHeadersMiddleware

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "ui" / "static"


def _hosts(urls: list[str]) -> set[str]:
    from urllib.parse import urlsplit

    return {(urlsplit(u).hostname or "").lower() for u in urls if u}


def build_context(cfg: LoadedConfig, clock: Clock) -> AppContext:
    raw = cfg.raw
    db = Database(cfg.db_path)
    allowed = _hosts(
        [
            *raw.upstreams.pypi.mirrors,
            raw.upstreams.pypi.files_url,
            *raw.upstreams.npm.mirrors,
            *raw.upstreams.go.mirrors,
            raw.upstreams.go.sumdb_url,
            raw.feeds.osv_base_url,
            raw.feeds.github_api_url,
        ]
    )
    allowed |= {h.lower() for h in raw.upstreams.go.download_hosts}
    for repo in raw.upstreams.maven.all_repos().values():
        allowed |= _hosts([repo.url]) | {h.lower() for h in repo.download_hosts}
    upstream = Upstream(
        user_agent=f"slowshield/{__version__} (+https://github.com/squirro/slowshield)", allowed_hosts=allowed
    )
    recorder = Recorder(db, clock, record_client_ip=raw.record_client_ip)
    cache = ArtifactCache(
        cfg.cache_dir,
        db,
        clock,
        max_bytes=int(raw.cache.artifacts_max_gb * (1 << 30)),
        enabled=raw.cache.artifacts_enabled,
    )
    artifacts = ArtifactServer(db=db, cache=cache, upstream=upstream, recorder=recorder, clock=clock)
    return AppContext(
        config=ConfigHolder(cfg),
        clock=clock,
        db=db,
        blocklist=Blocklist(db),
        upstream=upstream,
        recorder=recorder,
        artifact_cache=cache,
        artifacts=artifacts,
        # The memory budget is a total across workers; each worker holds its share.
        metadata_cache=LRUCache(int(raw.cache.metadata_memory_mb * (1 << 20) / max(1, raw.workers))),
        metadata_store=KVStore(cfg.metadata_store_path, int(raw.cache.metadata_max_mb * (1 << 20)), clock.now),
    )


class Leader:
    """Non-blocking flock on <data>/leader.lock: exactly one worker runs feeds and maintenance."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: int | None = None

    def try_acquire(self) -> bool:
        if self._fd is not None:
            return True
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self._fd = fd
        return True

    def release(self) -> None:
        if self._fd is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(self._fd, fcntl.LOCK_UN)
                os.close(self._fd)
            self._fd = None


class SlowShield:
    """Top-level ASGI app: lifespan, telemetry, security headers and host-based routing."""

    def __init__(self, cfg: LoadedConfig, clock: Clock | None = None, *, background: bool = True) -> None:
        self.cfg = cfg
        self.clock = clock or SystemClock()
        self.background = background
        self.ctx: AppContext | None = None
        self._tasks: list[asyncio.Task[Any]] = []
        self._leader = Leader(Path(cfg.raw.data_dir) / "leader.lock")
        self._scheduler: FeedScheduler | None = None
        self._ready = False
        self._handler: ASGIApp = PlainTextResponse("starting", status_code=503)
        self.root_routes: tuple[Any, ...] = ()  # the main host's routes, checked against slowshield.routing

    # ---- lifespan --------------------------------------------------------------------------------

    async def startup(self) -> None:
        logsetup.configure()
        telemetry.setup(version=__version__, worker=int(os.environ.get("SLOWSHIELD_WORKER_ID", "0") or 0))
        ctx = build_context(self.cfg, self.clock)
        self.ctx = ctx
        ctx.started_at = self.clock.now()
        await asyncio.to_thread(ctx.db.open)
        await asyncio.to_thread(ctx.metadata_store.open)
        ctx.artifact_cache.prepare()
        for w in self.cfg.warnings:
            log.warning(w)
        pypi = PypiService(ctx) if self.cfg.raw.upstreams.pypi.enabled else None
        npm = NpmService(ctx) if self.cfg.raw.upstreams.npm.enabled else None
        go = GoService(ctx) if self.cfg.raw.upstreams.go.enabled else None
        maven = MavenService(ctx) if self.cfg.raw.upstreams.maven.enabled else None
        from slowshield.ui import UI

        ui = UI(ctx)
        self._scheduler = FeedScheduler(ctx, [OsvFeed(ctx), GithubFeed(ctx)])
        self._register_gauges(ctx)
        self._handler = SecurityHeadersMiddleware(self._router(ctx, pypi=pypi, npm=npm, go=go, maven=maven, ui=ui))
        if self.background:
            self._spawn(ctx.recorder.run(), "recorder")
            self._spawn(self._config_watcher(ctx), "config")
            self._spawn(self._leader_loop(ctx), "leader")
            self._spawn(process.eventloop_lag_monitor(), "loop-lag")
        self._ready = True
        log.info(
            "slowshield ready",
            extra={
                "version": __version__,
                "pypi": bool(pypi),
                "npm": bool(npm),
                "go": bool(go),
                "maven": bool(maven),
                "db": str(self.cfg.db_path),
                "artifact_cache": self.cfg.raw.cache.artifacts_enabled,
            },
        )

    async def shutdown(self) -> None:
        self._ready = False
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        self._tasks.clear()
        if self.ctx is not None:
            self.ctx.recorder.flush()
            await self.ctx.upstream.close()
            await asyncio.to_thread(self.ctx.db.close)
            self.ctx.metadata_store.close()
        self._leader.release()
        telemetry.shutdown()

    def _spawn(self, coro: Awaitable[Any], name: str) -> None:
        self._tasks.append(asyncio.ensure_future(coro))
        self._tasks[-1].set_name(f"slowshield-{name}")

    def _register_gauges(self, ctx: AppContext) -> None:
        process.register()
        instruments.observe("slowshield.db.writer.queue", lambda: [(ctx.db.writer.queue_depth, {})], unit="{op}")
        instruments.observe(
            "slowshield.cache.size",
            lambda: [
                (ctx.artifact_cache.size_bytes, {"cache": "artifact"}),
                (ctx.metadata_store.usage(max_age=60)[1], {"cache": "metadata"}),
                (ctx.metadata_cache.bytes, {"cache": "metadata_memory"}),
            ],
            unit="By",
        )
        instruments.observe(
            "slowshield.cache.limit",
            lambda: [
                (ctx.artifact_cache.max_bytes, {"cache": "artifact"}),
                (ctx.metadata_store.max_bytes, {"cache": "metadata"}),
                (ctx.metadata_cache.max_bytes, {"cache": "metadata_memory"}),
            ],
            unit="By",
        )
        from slowshield import build_info

        info = build_info()
        instruments.observe(
            "slowshield.build.info",
            lambda: [
                (
                    1,
                    {
                        "version": info["version"],
                        "git_sha": info["git_sha"],
                        "python": info["python"],
                        "gil": info["gil"],
                    },
                )
            ],
        )
        instruments.observe("slowshield.leader", lambda: [(1 if ctx.is_leader else 0, {})])

    async def _config_watcher(self, ctx: AppContext) -> None:
        while True:
            await asyncio.sleep(5)
            if await asyncio.to_thread(ctx.config.maybe_reload):
                ctx.recorder.record_client_ip = ctx.cfg.raw.record_client_ip

    async def _leader_loop(self, ctx: AppContext) -> None:
        if self._scheduler is None:  # pragma: no cover - startup always creates it
            return
        follower = asyncio.ensure_future(self._scheduler.follow())
        try:
            while not self._leader.try_acquire():  # noqa: ASYNC110 - polling an OS file lock, not an event
                await asyncio.sleep(30)
            follower.cancel()
            ctx.is_leader = True
            log.info("this worker is the leader (feeds, cache maintenance, retention)")
            await asyncio.to_thread(ctx.artifact_cache.cleanup)
            await asyncio.gather(self._scheduler.run_forever(), self._maintenance(ctx))
        finally:
            follower.cancel()

    async def _maintenance(self, ctx: AppContext) -> None:
        last_scrub = last_retention = 0.0
        while True:
            try:
                await ctx.artifact_cache.evict()
                await asyncio.to_thread(ctx.artifact_cache.purge_trash)
                await ctx.metadata_store.aevict()
                now = ctx.clock.now()
                raw = ctx.cfg.raw
                if now - last_retention > 3600:
                    last_retention = now
                    await ctx.db.writer.run(
                        partial(
                            retention,
                            now=now,
                            event_days=raw.event_retention_days,
                            stats_days=raw.stats_retention_days,
                            ip_days=raw.client_ip_retention_days,
                        )
                    )
                if now - last_scrub > raw.cache.scrub_interval_hours * 3600:
                    last_scrub = now
                    await ctx.artifact_cache.scrub()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("maintenance cycle failed")
            await asyncio.sleep(60)

    # ---- routing ------------------------------------------------------------------------------------

    def _router(
        self,
        ctx: AppContext,
        *,
        pypi: PypiService | None,
        npm: NpmService | None,
        go: GoService | None,
        maven: MavenService | None,
        ui: Any,
    ) -> ASGIApp:
        raw = self.cfg.raw
        common: list[Any] = [
            Route("/healthz", self.healthz, methods=["GET"]),
            Route("/readyz", self.readyz, methods=["GET"]),
        ]
        # Every first path segment is part of the root contract (slowshield.routing, docs/design/routing.md).
        main: list[Any] = [*common]
        if pypi is not None:
            main.append(Mount("/pypi", app=pypi.router()))
        if npm is not None:
            main.append(Mount("/npm", app=npm))
        if go is not None:
            main.append(Mount("/go", app=go))
        if maven is not None:
            main.append(Mount("/maven", app=maven))
        main.append(Mount("/ui/static", app=StaticFiles(directory=STATIC_DIR), name="static"))
        main.extend(ui.routes())
        # Deprecated, removed in 0.1: the old asset path, and the root PyPI alias from the Rust version
        # (single-host deployments only).
        main.append(Route("/static/{path:path}", _legacy_static, methods=["GET", "HEAD"]))
        root_alias = pypi is not None and not raw.upstreams.pypi.hostnames and not raw.upstreams.npm.hostnames
        if root_alias and pypi is not None:
            main.extend(pypi.routes())
        main_router = Router(main, redirect_slashes=False)
        self.root_routes = tuple(main)

        # Deprecated, removed in 0.1: per-ecosystem hostnames (host routing). New ecosystems never get one.
        host_map: dict[str, tuple[ASGIApp, str]] = {}
        if pypi is not None:
            pypi_router = Router([*common, *pypi.routes()], redirect_slashes=False)
            for h in raw.upstreams.pypi.hostnames:
                host_map[h.lower()] = (pypi_router, "pypi-hostname")
        if npm is not None:
            for h in raw.upstreams.npm.hostnames:
                host_map[h.lower()] = (_with_common(common, npm), "npm-hostname")

        async def dispatch(scope: Scope, receive: Receive, send: Send) -> None:
            path = scope.get("path", "")
            hit = host_map.get(_host(scope)) if host_map else None
            if hit is not None:
                app, legacy = hit
                if path not in ("/healthz", "/readyz"):
                    instruments.legacy_routing.add(1, {"route": legacy})
                await app(scope, receive, send)
                return
            if root_alias and path.startswith(("/simple", "/packages/")):
                instruments.legacy_routing.add(1, {"route": "root-simple"})
            await main_router(scope, receive, send)

        return dispatch

    async def healthz(self, request: Request) -> Response:
        return PlainTextResponse("ok", headers={"Cache-Control": "no-store"})

    async def readyz(self, request: Request) -> Response:
        if not self._ready or self.ctx is None:
            return PlainTextResponse("starting", status_code=503)
        try:
            await asyncio.to_thread(self.ctx.db.readers.one, "SELECT 1")
        except Exception:
            return PlainTextResponse("database unavailable", status_code=503)
        return PlainTextResponse("ready", headers={"Cache-Control": "no-store"})

    # ---- ASGI ----------------------------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        await _traced(self._handler, scope, receive, send)

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                try:
                    await self.startup()
                except Exception as exc:
                    log.exception("startup failed")
                    await send({"type": "lifespan.startup.failed", "message": str(exc)})
                    return
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await self.shutdown()
                await send({"type": "lifespan.shutdown.complete"})
                return


def _host(scope: Scope) -> str:
    """Host header without the port, lower-cased (IPv6 literals keep their brackets)."""
    for k, v in scope.get("headers", ()):
        if k == b"host":
            host = v.decode("latin-1").strip().lower()
            if host.startswith("["):
                return host.split("]", 1)[0] + "]"
            return host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return ""


async def _legacy_static(request: Request) -> Response:
    """Deprecated, removed in 0.1: UI assets moved from /static/ to /ui/static/."""
    instruments.legacy_routing.add(1, {"route": "static"})
    query = f"?{request.url.query}" if request.url.query else ""
    return RedirectResponse(f"/ui/static/{request.path_params['path']}{query}", 301)


def _with_common(common: list[Any], app: ASGIApp) -> ASGIApp:
    router = Router([*common, Mount("", app=app)], redirect_slashes=False)
    return router


async def _traced(app: ASGIApp, scope: Scope, receive: Receive, send: Send) -> None:
    """Server span + duration histogram with low-cardinality attributes."""
    started = time.perf_counter()
    status = {"code": 500}
    method = scope.get("method", "GET")
    carrier = {
        k.decode("latin-1"): v.decode("latin-1")
        for k, v in scope.get("headers", ())
        if k in (b"traceparent", b"tracestate")
    }
    token = otel_context.attach(propagate.extract(carrier)) if carrier else None
    route = _route_label(scope.get("path", ""))
    try:
        with instruments.tracer.start_as_current_span(
            f"{method} {route}",
            kind=SpanKind.SERVER,
            attributes={"http.request.method": method, "http.route": route, "url.path": scope.get("path", "")},
        ) as span:

            async def send_wrapper(message: Message) -> None:
                if message["type"] == "http.response.start":
                    status["code"] = message["status"]
                    span.set_attribute("http.response.status_code", message["status"])
                    if message["status"] >= 500:
                        span.set_status(Status(StatusCode.ERROR))
                await send(message)

            await app(scope, receive, send_wrapper)
    finally:
        if token is not None:
            otel_context.detach(token)
        instruments.http_server_duration.record(
            time.perf_counter() - started,
            {"http.request.method": method, "http.route": route, "http.response.status_code": status["code"]},
        )


_UI_PAGES = frozenset(
    {"packages", "partials", "leaderboards", "security", "security.csv", "blocklist", "feeds", "setup", "about"}
)
_ROUTE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("/pypi/simple/", "/pypi/simple/{project}/"),
    ("/pypi/packages/", "/pypi/packages/{file}"),
    ("/simple/", "/simple/{project}/"),
    ("/packages/", "/packages/{file}"),
    ("/npm/-/", "/npm/-/{endpoint}"),
    ("/go/sumdb/", "/go/sumdb/{endpoint}"),
    ("/ui/static/", "/ui/static/{asset}"),
    ("/static/", "/static/{asset}"),
    ("/ui/", "/ui/{page}"),
)


def _route_label(path: str) -> str:
    if path in ("/", "/ui/", "/healthz", "/readyz", "/simple/", "/pypi/simple/"):
        return path
    for prefix, label in _ROUTE_PREFIXES:
        if path.startswith(prefix):
            if prefix == "/ui/":
                page = path[4:].split("/", 1)[0]
                return "/ui/" + page if page in _UI_PAGES else label
            return label
    if path.startswith("/npm/"):
        return "/npm/{package}/-/{file}" if "/-/" in path else "/npm/{package}"
    if path.startswith("/maven/"):
        if "/maven-metadata.xml" in path:
            return "/maven/{repo}/{artifact}/maven-metadata.xml"
        return "/maven/{repo}/{file}"
    if path.startswith("/go/"):
        if path.endswith("/@v/list"):
            return "/go/{module}/@v/list"
        if path.endswith("/@latest"):
            return "/go/{module}/@latest"
        ext = path.rsplit(".", 1)[-1]
        if "/@v/" in path and ext in ("info", "mod", "zip"):
            return f"/go/{{module}}/@v/{{version}}.{ext}"
        return "/go/{path}"
    if "/-/" in path:
        return "/{package}/-/{file}"
    return "/{package}"


def create_app(
    config: LoadedConfig | str | None = None, *, clock: Clock | None = None, background: bool = True
) -> SlowShield:
    """Granian calls this with no arguments (factory mode); tests pass a config and a clock."""
    cfg = config if isinstance(config, LoadedConfig) else load(Path(config) if config else None)
    return SlowShield(cfg, clock, background=background)
