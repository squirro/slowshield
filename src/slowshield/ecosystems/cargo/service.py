"""Cargo sparse registry (at /cargo/): crates.io index files with held versions marked as yanked, and age-gated
.crate downloads verified against the index.

A version's publish time is the `pubtime` on its index line, which crates.io sets when the version is published.
The first one SlowShield sees is kept, so an index that later moves a version's time earlier can't age it in
advance. A line without a plausible `pubtime` is timed from when SlowShield first listed it. See
docs/design/cargo.md.

Refusals are plain text, which cargo prints under the status line: 403 (too new) and 451 (blocked, tampered).
Upstream failures are 503, which cargo retries; never 404, which cargo reads as "no such crate".
"""

from __future__ import annotations

import hashlib
import logging
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from slowshield import names
from slowshield import versions as V
from slowshield.blocklist import BlockEntry
from slowshield.cache.metadata import SingleFlight
from slowshield.config import CargoUpstream
from slowshield.context import AppContext
from slowshield.ecosystems.artifacts import ArtifactRequest, AsgiResponse
from slowshield.ecosystems.cargo import index as I
from slowshield.integrity import Expected
from slowshield.policy import DAY, Candidate, evaluate, retry_after
from slowshield.telemetry import instruments
from slowshield.upstream import UpstreamError
from slowshield.web import TEXT, JSONResponse, client_ip, local_http_origin, route_path, text_error

log = logging.getLogger(__name__)

ECO = "cargo"
KEEP_STALE = 7 * DAY  # stored index files outlive their TTL for revalidation and stale-if-error
# crates.io opened in November 2014: an earlier (or a future) `pubtime` is not a usable publish time.
EARLIEST = datetime(2014, 1, 1, tzinfo=UTC).timestamp()
CLOCK_SKEW = 300.0
RETRY_SOON = {"Retry-After": "10"}  # cargo waits for Retry-After (up to 10 s) before retrying a 503
_NOT_FOUND = object()


@dataclass(slots=True)
class View:
    crate: str  # canonical name
    held: set[str] = field(default_factory=set)
    blocked: dict[str, BlockEntry] = field(default_factory=dict)
    published: dict[str, float | None] = field(default_factory=dict)
    fail_open: bool = False
    next_change: float = math.inf
    package_block: BlockEntry | None = None
    body: bytes = b""
    etag: str = ""


def _iso(ts: float | None) -> str:
    return "an unknown time" if ts is None else datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _days(value: float) -> str:
    return f"{value:g} day" + ("" if value == 1 else "s")


def cargo_error(status: int, code: str, *, headers: dict[str, str] | None = None, **fields: Any) -> Response:
    """The artifact server's errors as text cargo prints."""
    artifact = fields.get("artifact") or "the crate"
    if code == "tamper_detected":
        msg = (
            f"slowshield: {artifact} changed upstream after it was first served (tampering).\n"
            "It stays refused until an operator investigates; see Security on the SlowShield UI."
        )
    elif code == "integrity_mismatch":
        msg = f"slowshield: {artifact} failed verification: {fields.get('detail', '')}"
    elif code == "not_found":
        msg = "not found"
    else:
        msg = f"slowshield: {code.replace('_', ' ')}" + (f": {fields['detail']}" if fields.get("detail") else "")
    if status == 502:
        status, headers = 503, {**RETRY_SOON, **(headers or {})}  # cargo retries a 503, not a 502
    return text_error(status, msg, headers=headers)


class CargoService:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.flight = SingleFlight()

    @property
    def settings(self) -> CargoUpstream:
        return self.ctx.cfg.raw.upstreams.cargo

    # ---- ASGI dispatch ------------------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # pragma: no cover - lifespan is handled by the outer app
            return
        request = Request(scope, receive)
        response = await self.dispatch(request)
        await response(scope, receive, send)

    async def dispatch(self, request: Request) -> Any:
        if request.method not in ("GET", "HEAD"):
            return text_error(405, "method not allowed", headers={"Allow": "GET, HEAD"})
        path = route_path(request.scope).lstrip("/")
        if path == "":
            return Response(
                b"SlowShield Cargo registry: use sparse+<this URL> as the index of a registry that replaces "
                b"crates-io.\n",
                media_type=TEXT,
            )
        if path == "config.json":
            return self.config_json(request)
        parts = path.split("/")
        if len(parts) == 4 and parts[0] == "crates" and parts[3] == "download":
            if not names.is_valid_cargo(parts[1]) or V.parse_semver(parts[2]) is None:
                return text_error(404, "not found")
            return await self.download(request, parts[1], parts[2])
        name = I.name_of(path)
        if name is None:
            return text_error(404, "not found")
        return await self.index_file(request, name)

    def config_json(self, request: Request) -> Response:
        """The registry configuration: downloads come through SlowShield too. There is no `api`, so cargo refuses
        commands that need the crates.io web API (publish, yank, owner, search) instead of sending them here."""
        cfg = self.ctx.cfg
        local = local_http_origin(request.scope, cfg.raw.local_http, cfg.trusted_networks)
        base = f"{local or cfg.public_base()}/cargo"
        return JSONResponse({"dl": f"{base}/crates"}, headers={"Cache-Control": "max-age=300"})

    # ---- index files --------------------------------------------------------------------------------------

    async def index(self, name: str) -> I.IndexFile | None:
        """The upstream index file of `name` (lower case), or None if upstream has none."""
        key = ("cargo:idx", name)
        hit = self.ctx.metadata_cache.get(key, self.ctx.clock.now())
        if hit is not None:
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            self.ctx.recorder.lookup(ECO, cached=True)
            return None if hit is _NOT_FOUND else hit
        return await self.flight.run(key, lambda: self._load(name))

    async def _load(self, name: str) -> I.IndexFile | None:
        ctx = self.ctx
        key = ("cargo:idx", name)
        skey = f"cargo:idx:{name}"
        now = ctx.clock.now()
        ttl = ctx.cfg.raw.metadata_cache_ttl_hours * 3600
        stored = await ctx.metadata_store.aget(skey)
        if stored is not None and stored.fresh(now):
            # Fetched by another worker, or by this one before a restart: no upstream request.
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            ctx.recorder.lookup(ECO, cached=True)
            idx = I.parse(name, stored.value)
            ctx.metadata_cache.put(key, idx, idx.weight, stored.expires)
            return idx
        headers = {}
        if stored is not None and stored.meta.get("etag"):
            headers["If-None-Match"] = stored.meta["etag"]
        ctx.recorder.lookup(ECO, cached=False)
        url = f"{self.settings.index_url.rstrip('/')}/{I.path_of(name)}"
        try:
            res = await ctx.upstream.fetch(url, headers=headers, max_bytes=I.MAX_INDEX_BYTES)
        except UpstreamError:
            if stored is None:
                raise
            log.warning("upstream unavailable; serving a stale Cargo index file", extra={"package": name})
            idx = I.parse(name, stored.value)
            ctx.metadata_cache.put(key, idx, idx.weight, now + 60)
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "stale"})
            return idx
        if res.status == 304 and stored is not None:
            await ctx.metadata_store.atouch(skey, now + ttl, now + ttl + KEEP_STALE)
            idx = I.parse(name, stored.value)
            ctx.metadata_cache.put(key, idx, idx.weight, now + ttl)
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "revalidated"})
            ctx.recorder.catalog(ECO, names.normalize_cargo(name))
            return idx
        instruments.cache_requests.add(1, {"cache": "metadata", "result": "miss"})
        if res.status in (404, 410):
            ctx.metadata_cache.put(key, _NOT_FOUND, 64, now + 300)
            return None
        if res.status != 200:
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        await ctx.metadata_store.aput(
            skey, res.body, expires=now + ttl, keep_until=now + ttl + KEEP_STALE, meta={"etag": res.etag}
        )
        idx = I.parse(name, res.body)
        ctx.metadata_cache.put(key, idx, idx.weight, now + ttl)
        self._record(idx)
        return idx

    # ---- publish times -----------------------------------------------------------------------------------

    def _times(self, crate: str) -> dict[str, list[float | None]]:
        """version -> [first `pubtime` seen, first listed], shared by all workers through the database."""
        key = ("cargo:times", crate)
        now = self.ctx.clock.now()
        hit = self.ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit
        rows = self.ctx.db.readers.query(
            "SELECT version, published, first_listed FROM package_versions WHERE ecosystem = ? AND name = ? "
            "AND (published IS NOT NULL OR first_listed IS NOT NULL)",
            (ECO, crate),
        )
        times = {r[0]: [r[1], r[2]] for r in rows}
        self.ctx.metadata_cache.put(key, times, 256 + 96 * len(times), now + 300)
        return times

    def _pubtime(self, v: I.Version, now: float) -> float | None:
        return v.pubtime if v.pubtime is not None and EARLIEST <= v.pubtime <= now + CLOCK_SKEW else None

    def _record(self, idx: I.IndexFile) -> None:
        """Keep each version's first `pubtime` (or, without one, when it was first listed) and its yanked flag."""
        ctx = self.ctx
        crate = names.normalize_cargo(idx.name)
        now = ctx.clock.now()
        times = self._times(crate)
        rows: list[tuple[Any, ...]] = []
        untimed = 0
        for v in idx.versions.values():
            pub = self._pubtime(v, now)
            known = times.setdefault(v.vers, [None, None])
            if pub is None:
                untimed += 1
                known[1] = known[1] or now
            else:
                known[0] = known[0] or pub
            rows.append((ECO, crate, v.vers, pub, None if pub is not None else now, int(v.yanked)))
        if untimed:
            log.warning("Cargo index lines without a usable pubtime", extra={"package": crate, "versions": untimed})

        def op(conn: Any) -> None:
            conn.executemany(
                "INSERT INTO package_versions (ecosystem, name, version, published, first_listed, yanked) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (ecosystem, name, version) DO UPDATE SET "
                "published = coalesce(package_versions.published, excluded.published), "
                "first_listed = coalesce(package_versions.first_listed, excluded.first_listed), "
                "yanked = excluded.yanked",
                rows,
            )

        ctx.recorder.catalog(ECO, crate)
        ctx.db.writer.enqueue(op)

    def _published(self, v: I.Version, times: dict[str, list[float | None]], now: float) -> float:
        """The latest of the clocks known for `v`: its `pubtime` now, the first one seen, and when it was first
        listed without one. Each is no earlier than the real publish time, so the latest is the safest."""
        clocks = [c for c in (self._pubtime(v, now), *times.get(v.vers, ())) if c is not None]
        return max(clocks) if clocks else now

    # ---- policy -------------------------------------------------------------------------------------------

    def view(self, idx: I.IndexFile) -> View:
        ctx = self.ctx
        cfg = ctx.cfg
        now = ctx.clock.now()
        key = ("cargo:view", idx.name, idx.content_id, ctx.policy_key())
        hit = ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit
        crate = names.normalize_cargo(idx.name)
        v = View(crate=crate)
        blocks = ctx.blocklist.for_package(ECO, crate)
        if blocks.package_block is not None:
            v.package_block = blocks.package_block
            ctx.metadata_cache.put(key, v, 256, now + 300)
            return v
        times = self._times(crate)
        v.published = {ver: self._published(info, times, now) for ver, info in idx.versions.items()}
        ev = evaluate(
            (Candidate(ver, ver, v.published[ver]) for ver in idx.versions),
            now=now,
            delay_for=lambda ver: cfg.delay_days_for(ECO, crate, ver),
            is_blocked=lambda ver: blocks.match(ECO, ver) is not None,
            fail_open=cfg.fail_open_for(ECO),
        )
        v.held = {c.item for c in ev.held}
        for c in ev.blocked:
            entry = blocks.match(ECO, c.version)
            if entry is not None:
                v.blocked[c.item] = entry
        v.fail_open = ev.fail_open
        v.next_change = ev.next_change
        v.body = I.render(idx, v.held | v.blocked.keys())
        v.etag = '"' + hashlib.blake2b(v.body, digest_size=12).hexdigest() + '"'
        ctx.metadata_cache.put(key, v, 512 + len(v.body) + 64 * len(idx.versions), min(ev.next_change, now + 3600))
        return v

    async def _resolve(self, request: Request, name: str, kind: str) -> tuple[I.IndexFile, View] | Response:
        ctx = self.ctx
        crate = names.normalize_cargo(name)
        blocks = ctx.blocklist.for_package(ECO, crate)
        if blocks.package_block is not None:
            return self._blocked(request, crate, None, blocks.package_block, kind=kind)
        try:
            idx = await self.index(name.lower())
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, kind, "upstream_error")
            return text_error(
                503, f"slowshield: the crates.io index is unavailable for {name}: {exc.detail}", headers=RETRY_SOON
            )
        if idx is None:
            ctx.recorder.decision(ECO, kind, "not_found")
            return text_error(404, "not found")
        v = self.view(idx)
        if v.package_block is not None:
            return self._blocked(request, crate, None, v.package_block, kind=kind)
        return idx, v

    # ---- handlers -----------------------------------------------------------------------------------------

    async def index_file(self, request: Request, name: str) -> Response:
        ctx = self.ctx
        resolved = await self._resolve(request, name, "metadata")
        if isinstance(resolved, Response):
            return resolved
        idx, v = resolved
        if v.blocked and len(v.blocked) == len(idx.versions):
            return self._blocked(request, v.crate, None, next(iter(v.blocked.values())), kind="metadata")
        now = ctx.clock.now()
        headers = {
            "ETag": v.etag,
            "Cache-Control": f"max-age={int(max(0, min(300, v.next_change - now)))}",
            "X-SlowShield-Held-Versions": str(len(v.held)),
        }
        if v.held:
            instruments.versions_held.add(len(v.held), {"slowshield.ecosystem": ECO})
        if v.fail_open:
            headers["X-SlowShield-Fail-Open"] = "1"
            ctx.recorder.decision(ECO, "metadata", "fail_open")
            ctx.recorder.event(
                "fail_open",
                ECO,
                v.crate,
                None,
                client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
                details={"reason": "all_versions_too_new", "versions": list(idx.versions)[-20:]},
            )
        else:
            ctx.recorder.decision(ECO, "metadata", "served")
        if request.headers.get("if-none-match") == v.etag:
            return Response(status_code=304, headers=headers)
        return Response(v.body, media_type="text/plain", headers=headers)

    async def download(self, request: Request, name: str, version: str) -> AsgiResponse:
        ctx = self.ctx
        crate = names.normalize_cargo(name)
        # Known malware is refused (and recorded) before anything else, even when crates.io has deleted the crate
        # since: a lockfile pinned during an attack window must show up as a security event, not a 404.
        blocks = ctx.blocklist.for_package(ECO, crate)
        entry = blocks.package_block or blocks.match(ECO, version)
        if entry is not None:
            return self._blocked(request, crate, version, entry, kind="artifact")
        resolved = await self._resolve(request, name, "artifact")
        if isinstance(resolved, Response):
            return resolved
        idx, v = resolved
        info = idx.versions.get(version)
        if info is None or names.normalize_cargo(info.name) != crate:
            ctx.recorder.decision(ECO, "artifact", "not_found")
            return text_error(404, f"not found: {name}@{version} is not in the crates.io index")
        if version in v.blocked:
            return self._blocked(request, crate, version, v.blocked[version], kind="artifact")
        if ctx.cfg.raw.enforce_age_on_download and version in v.held:
            return self._too_new(request, idx, v, version)
        # Always the index's own spelling of the name: static.crates.io is case- and `-`/`_`-sensitive.
        path = f"/{info.name}/{info.vers}/download"
        art = ArtifactRequest(
            ecosystem=ECO,
            key=path,
            package=crate,
            version=version,
            filename=f"{info.name}-{info.vers}.crate",
            upstream_url=self.settings.download_url.rstrip("/") + path,
            expected=Expected(sha256=info.cksum),
            content_type="application/gzip",
            error=cargo_error,
            published=v.published.get(version),
        )
        return await ctx.artifacts.serve(
            art,
            method=request.method,
            headers_in=dict(request.headers),
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
        )

    # ---- refusals -----------------------------------------------------------------------------------------

    def _too_new(self, request: Request, idx: I.IndexFile, v: View, version: str) -> Response:
        ctx = self.ctx
        now = ctx.clock.now()
        published = v.published.get(version)
        delay = ctx.cfg.delay_days_for(ECO, v.crate, version)
        wait = retry_after(published, delay, now)
        ctx.recorder.decision(ECO, "artifact", "age_gated")
        ctx.recorder.event(
            "age_gate",
            ECO,
            v.crate,
            version,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details={"published": None if published is None else _iso(published), "delay_days": delay},
        )
        name = idx.versions[version].name
        if published is None:
            when = f"SlowShield could not establish when it was published, so it counts as newer than {_days(delay)}."
            until = "Try again later."
        else:
            when = f"It was published {_iso(published)} ({(now - published) / DAY:.1f} days ago); "
            when += f"this proxy requires {_days(delay)}."
            until = f"It becomes available at {_iso(published + delay * DAY)}."
        older = self._older_allowed(idx, v, version)
        use = (
            f"Use an older version (cargo update -p {name}@{version} --precise {older})"
            if older
            else "Use an older version"
        )
        return text_error(
            403,
            f"slowshield: {name}@{version} is too new.\n{when}\n{until}\n"
            f"{use}, or ask your SlowShield administrator for an exception.",
            headers={"Retry-After": str(wait if wait is not None else int(delay * DAY))},
        )

    @staticmethod
    def _older_allowed(idx: I.IndexFile, v: View, version: str) -> str | None:
        """The newest version below `version` that would be served now (and isn't yanked upstream)."""
        top = V.sort_key(ECO, version)
        allowed = [
            ver
            for ver, info in idx.versions.items()
            if ver not in v.held and ver not in v.blocked and not info.yanked and V.sort_key(ECO, ver) < top
        ]
        return max(allowed, key=lambda ver: V.sort_key(ECO, ver)) if allowed else None

    def _blocked(self, request: Request, crate: str, version: str | None, entry: BlockEntry, *, kind: str) -> Response:
        ctx = self.ctx
        ctx.recorder.decision(ECO, kind, "blocked")
        ctx.recorder.event(
            "blocked",
            ECO,
            crate,
            version,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details=entry.as_json(),
        )
        what = f"{crate}@{version}" if version and not entry.package_level else crate
        lines = [f"slowshield: {what} is blocked as known malware."]
        lines.append("Advisory: " + " ".join(p for p in (entry.advisory_id, f"({entry.source})", entry.url or "") if p))
        if entry.reason:
            lines.append(entry.reason.splitlines()[0][:300])
        return text_error(451, "\n".join(lines))
