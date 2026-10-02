"""Read-only web UI (Jinja2 + htmx partials + server-rendered SVG)."""

from __future__ import annotations

import asyncio
import csv
import io
import math
import os
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlencode, urlsplit

import msgspec
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markdown_it import MarkdownIt
from markupsafe import Markup
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from slowshield import __version__, build_info
from slowshield import names as N
from slowshield.context import AppContext
from slowshield.policy import DAY
from slowshield.ui import queries as Q
from slowshield.ui import svg
from slowshield.web import is_loopback_host, local_http_origin

TEMPLATES = Path(__file__).parent / "templates"
HTMX_VERSION = "4.0.0"
ECO_LABEL = {"pypi": "PyPI", "npm": "npm"}
EVENT_LABEL = {
    "blocked": "Blocked",
    "tampered": "Tampered",
    "integrity_mismatch": "Integrity mismatch",
    "fail_open": "Fail-open",
    "age_gate": "Too new",
}
DECISION_ORDER = [
    "served",
    "fail_open",
    "age_gated",
    "blocked",
    "tampered",
    "integrity_mismatch",
    "not_found",
    "upstream_error",
]
DECISION_LABEL = {
    "served": "Served",
    "fail_open": "Fail-open",
    "age_gated": "Too new (403)",
    "blocked": "Blocked (451)",
    "tampered": "Tampered",
    "integrity_mismatch": "Integrity mismatch",
    "not_found": "Not found",
    "upstream_error": "Upstream error",
}


def fmt_bytes(n: float | None) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"  # pragma: no cover


def fmt_num(n: float | None) -> str:
    n = float(n or 0)
    if abs(n) >= 1e6:
        return f"{n / 1e6:.1f}M"
    if abs(n) >= 1e4:
        return f"{n / 1e3:.1f}k"
    return f"{n:,.0f}"


def fmt_ts(ts: float | None) -> str:
    return "—" if not ts else datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M UTC")


def fmt_duration(seconds: float) -> str:
    s = abs(int(seconds))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= size:
            major = s // size
            rest = s % size
            minor = {"d": ("h", 3600), "h": ("m", 60), "m": ("s", 1)}[unit]
            sub = rest // minor[1]
            return f"{major}{unit} {sub}{minor[0]}" if sub and unit != "m" else f"{major}{unit}"
    return f"{s}s"


def safe_href(url: str | None) -> str:
    """Only https links from feed data become clickable (no javascript:/data: URLs)."""
    return url if isinstance(url, str) and url.startswith("https://") else "#"


def fmt_pct(x: float | None) -> str:
    return "—" if x is None else f"{x * 100:.1f}%"


class UI:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        env = Environment(
            loader=FileSystemLoader(TEMPLATES),
            autoescape=select_autoescape(["html", "j2", "svg"], default=True),
            trim_blocks=True,
            lstrip_blocks=True,
            auto_reload=os.environ.get("SLOWSHIELD_DEV_TEMPLATES") == "1",
            cache_size=400,
        )
        env.filters.update(bytes=fmt_bytes, num=fmt_num, ts=fmt_ts, pct=fmt_pct, duration=fmt_duration, href=safe_href)
        cast(dict[str, Any], env.globals).update(
            version=__version__,
            build=build_info(),
            htmx_version=HTMX_VERSION,
            eco_label=ECO_LABEL,
            event_label=EVENT_LABEL,
            decision_label=DECISION_LABEL,
            sparkline=svg.sparkline,
            hbar=svg.hbar,
            ago=self._ago,
            qs=_qs,
        )
        self.env = env
        self.md = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")

    # ---- plumbing ---------------------------------------------------------------------------------

    def routes(self) -> list[Route]:
        return [
            Route("/", self.dashboard),
            Route("/ui", lambda r: RedirectResponse("/", 302)),
            Route("/ui/partials/dashboard", self.dashboard_partial),
            Route("/ui/packages", self.packages),
            Route("/ui/partials/packages", self.packages_partial),
            Route("/ui/packages/{eco}/{name:path}", self.package_detail),
            Route("/ui/leaderboards", self.leaderboards),
            Route("/ui/security", self.security),
            Route("/ui/partials/security", self.security_partial),
            Route("/ui/security.csv", self.security_csv),
            Route("/ui/blocklist", self.blocklist),
            Route("/ui/partials/blocklist", self.blocklist_partial),
            Route("/ui/feeds", self.feeds),
            Route("/ui/setup", self.setup),
            Route("/ui/about", self.about),
            Route("/favicon.ico", lambda r: RedirectResponse("/static/brand/favicon.ico", 301)),
        ]

    def _ago(self, ts: float | None) -> str:
        if not ts:
            return "never"
        delta = self.ctx.clock.now() - ts
        return (
            "just now"
            if 0 <= delta < 60
            else (f"{fmt_duration(delta)} ago" if delta >= 0 else f"in {fmt_duration(delta)}")
        )

    def _render(self, template: str, request: Request, /, **context: Any) -> HTMLResponse:
        tpl = self.env.get_template(template)
        cfg = self.ctx.cfg
        base = {
            "request": request,
            "path": request.url.path,
            "range": context.get("range") or request.query_params.get("range") or Q.DEFAULT_RANGE,
            "ranges": list(Q.RANGES),
            "feeds": self.ctx.feeds,
            "feed_warnings": [f for f in self.ctx.feeds.values() if f.reason in ("missing_token", "error")],
            "cfg": cfg.raw,
            "pypi_enabled": cfg.raw.upstreams.pypi.enabled,
            "npm_enabled": cfg.raw.upstreams.npm.enabled,
            "now": self.ctx.clock.now(),
        }
        base.update(context)
        html = tpl.render(base)
        return HTMLResponse(html, headers={"Cache-Control": "no-store"})

    async def _q(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        conn = self.ctx.db.readers
        return await asyncio.to_thread(lambda: fn(conn.get(), *args, **kwargs))

    def _window(self, request: Request) -> Q.Window:
        return Q.window(request.query_params.get("range"), self.ctx.clock.now())

    @staticmethod
    def _eco(request: Request) -> str | None:
        e = request.query_params.get("eco")
        return e if e in ("pypi", "npm") else None

    @staticmethod
    def _page(request: Request) -> int:
        try:
            return max(1, min(10_000, int(request.query_params.get("page", "1"))))
        except ValueError:
            return 1

    # ---- dashboard --------------------------------------------------------------------------------

    async def _dashboard_data(self, request: Request) -> dict[str, Any]:
        w = self._window(request)
        eco = self._eco(request)

        def collect(conn: Any) -> dict[str, Any]:
            return {
                "kpis": Q.kpis(conn, w, eco),
                "dl": Q.series_downloads(conn, w, eco),
                "dec": Q.series_decisions(conn, w, eco),
                "top": Q.top_packages(conn, w, eco=eco, limit=10),
                "top_bytes": Q.top_packages(conn, w, eco=eco, by="bytes", limit=5),
                "events": Q.recent_events(conn, 8),
                "totals": Q.totals(conn),
                "new_deps": Q.new_dependencies(conn, w, eco=eco, limit=6),
            }

        data = await self._q(collect)
        buckets = w.buckets()
        dl_series = {k: v for k, v in data["dl"].items() if k in ("pypi", "npm")}
        traffic = svg.stacked_bars(
            buckets, dl_series, step=w.step, order=["pypi", "npm"], labels=ECO_LABEL, title="Downloads per ecosystem"
        )
        decisions = svg.stacked_bars(
            buckets,
            data["dec"],
            step=w.step,
            order=[d for d in DECISION_ORDER if d in data["dec"]],
            labels=DECISION_LABEL,
            title="Policy decisions",
        )
        total_series = [sum(dl_series.get(e, {}).get(b, 0) for e in dl_series) for b in buckets]
        peak = max((r["s"] for r in data["top"]), default=0)
        return {
            **data,
            "w": w,
            "eco": eco,
            "traffic_chart": traffic,
            "decisions_chart": decisions,
            "installs_spark": svg.sparkline(total_series, width=160, height=32),
            "top_peak": peak,
        }

    async def dashboard(self, request: Request) -> Response:
        return self._render("dashboard.html.j2", request, **(await self._dashboard_data(request)))

    async def dashboard_partial(self, request: Request) -> Response:
        return self._render("partials/dashboard_body.html.j2", request, **(await self._dashboard_data(request)))

    # ---- packages ---------------------------------------------------------------------------------

    async def _packages_data(self, request: Request) -> dict[str, Any]:
        w = self._window(request)
        eco = self._eco(request)
        q = (request.query_params.get("q") or "").strip()[:100]
        sort = request.query_params.get("sort") or "serves"
        page = self._page(request)

        def collect(conn: Any) -> dict[str, Any]:
            rows, total = Q.package_page(conn, w, q=q, eco=eco, sort=sort, page=page)
            has_next = len(rows) > 50
            rows = rows[:50]
            sparks = Q.sparklines(conn, [(r["ecosystem"], r["name"]) for r in rows], w)
            return {"rows": rows, "total": total, "has_next": has_next, "sparks": sparks}

        data = await self._q(collect)
        buckets = w.buckets()
        data["spark_svgs"] = {
            k: svg.sparkline([series.get(b, 0) for b in buckets], width=100, height=22)
            for k, series in data["sparks"].items()
        }
        data["peak"] = max((r["s"] for r in data["rows"]), default=0)
        return {**data, "w": w, "eco": eco, "q": q, "sort": sort, "page": page, "sorts": list(Q.PACKAGE_SORTS)}

    async def packages(self, request: Request) -> Response:
        return self._render("packages.html.j2", request, **(await self._packages_data(request)))

    async def packages_partial(self, request: Request) -> Response:
        return self._render("partials/packages_table.html.j2", request, **(await self._packages_data(request)))

    async def package_detail(self, request: Request) -> Response:
        eco = request.path_params["eco"]
        raw_name = request.path_params["name"]
        if eco not in ("pypi", "npm"):
            return self._render("not_found.html.j2", request, what="ecosystem")
        name = N.normalize_pypi(raw_name) if eco == "pypi" else N.normalize_npm(raw_name)
        w = Q.window(request.query_params.get("range") or "90d", self.ctx.clock.now())
        cfg = self.ctx.cfg
        blocks = self.ctx.blocklist.for_package(eco, name)
        now = self.ctx.clock.now()

        def collect(conn: Any) -> dict[str, Any]:
            return {
                "pkg": Q.package(conn, eco, name),
                "versions": Q.package_versions(conn, eco, name),
                "series": Q.package_series(conn, eco, name, w),
                "events": Q.package_events(conn, eco, name, 50),
                "blocks": Q.package_blocks(conn, eco, name),
            }

        data = await self._q(collect)
        if data["pkg"] is None and not data["blocks"]:
            return self._render("not_found.html.j2", request, what="package", name=name, eco=eco)
        versions = []
        for v in data["versions"]:
            delay = cfg.delay_days_for(eco, name, v["version"])
            block = blocks.match(eco, v["version"])
            published = v["published"]
            if block is not None:
                status, until = "blocked", None
            elif v["tampered"]:
                status, until = "tampered", None
            elif published is None:
                status, until = "unknown", None
            elif now - published < delay * DAY:
                status, until = "held", published + delay * DAY
            elif v["yanked"]:
                status, until = "yanked", None
            else:
                status, until = "available", None
            versions.append({**dict(v), "status": status, "until": until, "delay": delay, "block": block})
        buckets = w.buckets()
        chart = svg.stacked_bars(
            buckets,
            {"pkg": data["series"]},
            step=w.step,
            order=["pkg"],
            labels={"pkg": "Downloads"},
            title=f"Downloads of {name}",
            height=160,
        )
        held = sum(1 for v in versions if v["status"] == "held")
        upstream_url = f"https://pypi.org/project/{name}/" if eco == "pypi" else f"https://www.npmjs.com/package/{name}"
        return self._render(
            "package.html.j2",
            request,
            eco=eco,
            name=name,
            pkg=data["pkg"],
            versions=versions,
            held=held,
            chart=chart,
            events=data["events"],
            blocks=data["blocks"],
            package_block=blocks.package_block,
            delay=cfg.delay_days_for(eco, name),
            default_delay=cfg.raw.default_delay_days,
            upstream_url=upstream_url,
            w=w,
        )

    # ---- leaderboards -----------------------------------------------------------------------------

    async def leaderboards(self, request: Request) -> Response:
        w = self._window(request)
        eco = self._eco(request)

        def collect(conn: Any) -> dict[str, Any]:
            return {
                "downloads": Q.top_packages(conn, w, eco=eco, limit=15),
                "bandwidth": Q.top_packages(conn, w, eco=eco, by="bytes", limit=15),
                "trending": Q.trending(conn, w, eco=eco, limit=15),
                "age_gated": Q.event_leaders(conn, w, "age_gate", eco=eco, limit=15),
                "fail_open": Q.event_leaders(conn, w, "fail_open", eco=eco, limit=15),
                "blocked": Q.event_leaders(conn, w, "blocked", eco=eco, limit=15),
                "new_deps": Q.new_dependencies(conn, w, eco=eco, limit=25),
            }

        data = await self._q(collect)
        return self._render(
            "leaderboards.html.j2",
            request,
            **data,
            w=w,
            eco=eco,
            dl_peak=max((r["s"] for r in data["downloads"]), default=0),
            bw_peak=max((r["b"] for r in data["bandwidth"]), default=0),
            inf=math.inf,
        )

    # ---- security ---------------------------------------------------------------------------------

    async def _security_data(self, request: Request) -> dict[str, Any]:
        w = Q.window(request.query_params.get("range") or "30d", self.ctx.clock.now())
        eco = self._eco(request)
        type_ = request.query_params.get("type")
        type_ = type_ if type_ in EVENT_LABEL else None
        q = (request.query_params.get("q") or "").strip()[:100]
        ip = (request.query_params.get("ip") or "").strip()[:64]
        page = self._page(request)

        def collect(conn: Any) -> dict[str, Any]:
            rows = Q.events_page(conn, w, type_=type_, eco=eco, q=q, ip=ip, page=page)
            return {"rows": rows[:50], "has_next": len(rows) > 50, "counts": Q.event_counts(conn, w)}

        data = await self._q(collect)
        dec = msgspec.json.Decoder()
        for_rows = []
        for r in data["rows"]:
            details = {}
            if r["details"]:
                try:
                    details = dec.decode(r["details"])
                except msgspec.DecodeError:
                    details = {}
            for_rows.append({**dict(r), "details": details})
        data["rows"] = for_rows
        return {**data, "w": w, "eco": eco, "type": type_, "q": q, "ip": ip, "page": page, "range": w.key}

    async def security(self, request: Request) -> Response:
        return self._render("security.html.j2", request, **(await self._security_data(request)))

    async def security_partial(self, request: Request) -> Response:
        return self._render("partials/security_table.html.j2", request, **(await self._security_data(request)))

    async def security_csv(self, request: Request) -> Response:
        w = Q.window(request.query_params.get("range") or "30d", self.ctx.clock.now())
        rows = await self._q(partial(Q.events_page, w=w, per_page=50_000))
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["time_utc", "type", "ecosystem", "package", "version", "client_ip", "count", "details"])
        for r in rows:
            writer.writerow(
                [
                    fmt_ts(r["ts"]),
                    r["type"],
                    r["ecosystem"],
                    _csv_safe(r["package"]),
                    _csv_safe(r["version"] or ""),
                    r["client_ip"] or "",
                    r["count"],
                    _csv_safe(r["details"] or ""),
                ]
            )
        return Response(
            buf.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="slowshield-security-events.csv"',
                "Cache-Control": "no-store",
            },
        )

    # ---- blocklist & feeds ------------------------------------------------------------------------------

    async def _blocklist_data(self, request: Request) -> dict[str, Any]:
        q = (request.query_params.get("q") or "").strip()[:100]
        eco = self._eco(request)
        source = request.query_params.get("source")
        scope = request.query_params.get("scope")
        page = self._page(request)

        def collect(conn: Any) -> dict[str, Any]:
            rows = Q.blocklist_page(conn, q=q, eco=eco, source=source, scope=scope, page=page)
            return {"rows": rows[:50], "has_next": len(rows) > 50, "counts": Q.blocklist_counts(conn)}

        data = await self._q(collect)
        return {**data, "q": q, "eco": eco, "source": source, "scope": scope, "page": page}

    async def blocklist(self, request: Request) -> Response:
        return self._render("blocklist.html.j2", request, **(await self._blocklist_data(request)))

    async def blocklist_partial(self, request: Request) -> Response:
        return self._render("partials/blocklist_table.html.j2", request, **(await self._blocklist_data(request)))

    async def feeds(self, request: Request) -> Response:
        states = await self._q(Q.feed_states)
        counts = await self._q(Q.blocklist_counts)
        return self._render("feeds.html.j2", request, states=states, counts=counts)

    # ---- static-ish pages -------------------------------------------------------------------------

    async def setup(self, request: Request) -> Response:
        cfg = self.ctx.cfg
        raw = cfg.raw
        base = cfg.public_base()
        pypi_index = (
            f"https://{raw.upstreams.pypi.hostnames[0]}/simple/"
            if raw.upstreams.pypi.hostnames
            else f"{base}/pypi/simple/"
        )
        npm_registry = cfg.npm_public_base() + "/"
        # Local plain HTTP: show http:// URLs that work without trusting Caddy's CA, keep HTTPS as the alternative.
        local = local_http_origin(request.scope, raw.local_http, cfg.trusted_networks)
        if local is None and raw.local_http:
            host = urlsplit(base).hostname or ""
            if is_loopback_host(host):
                local = f"http://{'[' + host + ']' if ':' in host else host}"
        secure = None
        if local:
            secure = {"pypi": pypi_index, "npm": npm_registry}
            if not raw.upstreams.pypi.hostnames:
                pypi_index = f"{local}/pypi/simple/"
            if not (raw.upstreams.npm.hostnames or raw.upstreams.npm.public_url):
                npm_registry = f"{local}/npm/"
        return self._render(
            "setup.html.j2",
            request,
            pypi_index=pypi_index,
            npm_registry=npm_registry,
            base=base,
            plain_http=pypi_index.startswith("http://") or npm_registry.startswith("http://"),
            secure=secure,
        )

    async def about(self, request: Request) -> Response:
        docs = {}
        for name in ("CHANGELOG.md", "ATTRIBUTIONS.md"):
            text = _read_doc(name)
            docs[name] = Markup(self.md.render(text)) if text else None  # noqa: S704 - markdown-it with html disabled
        return self._render("about.html.j2", request, docs=docs, info=build_info())


def _qs(base: dict[str, Any], **changes: Any) -> str:
    merged = {k: v for k, v in {**base, **changes}.items() if v not in (None, "", False)}
    return "?" + urlencode(merged) if merged else ""


def _csv_safe(value: str) -> str:
    """Neutralise spreadsheet formula injection in exported cells."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def _read_doc(name: str) -> str | None:
    candidates = []
    if env := os.environ.get("SLOWSHIELD_DOCS_DIR"):
        candidates.append(Path(env) / name)
    candidates += [Path("/app/share/doc") / name, Path(__file__).resolve().parents[3] / name]
    for path in candidates:
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            continue
    return None
