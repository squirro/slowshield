"""Go module proxy (GOPROXY protocol at /go/): version lists filtered by release age and the blocklist, age-gated
.info/.mod/.zip, downloads verified against the checksum database, and a pass-through for that database.

A version's publish time is the `Last-Modified` of its .mod on proxy.golang.org, which is when the mirror first
stored that version. The `Time` in .info is the commit time, set by the author, and is never used. Times are
looked up once per version, with `Disable-Module-Fetch: true` so the mirror answers from its cache and does not
fetch anything; a version the mirror does not have yet is fetched once, and its clock starts then. See
docs/design/go.md.

Refusals are 403 (too new) and 451 (blocked, tampered), never 404/410: with `GOPROXY=<this>,direct` the go command
falls back to fetching from the origin only on 404/410. Bodies are text/plain, which the go command prints.
"""

from __future__ import annotations

import email.utils
import hashlib
import logging
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import msgspec
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from slowshield import versions as V
from slowshield.blocklist import BlockEntry
from slowshield.cache.metadata import SingleFlight
from slowshield.context import AppContext
from slowshield.ecosystems.artifacts import ArtifactRequest, AsgiResponse
from slowshield.ecosystems.go import dirhash
from slowshield.ecosystems.go import module as M
from slowshield.integrity import Expected
from slowshield.policy import DAY, is_old_enough, retry_after
from slowshield.telemetry import instruments
from slowshield.upstream import UpstreamError
from slowshield.web import TEXT, client_ip, route_path, text_error

log = logging.getLogger(__name__)

ECO = "go"
SUMDB = "sum.golang.org"  # the only checksum database proxied (GOSUMDB's default)
MAX_LIST_BYTES = 8 << 20
MAX_INFO_BYTES = 1 << 20
MAX_MOD_BYTES = 16 << 20  # golang.org/x/mod/zip.MaxGoMod
MAX_SUMDB_BYTES = 4 << 20
PROBE_LIMIT = 20  # versions without a known publish time looked up per list evaluation
# proxy.golang.org went live in April 2019: an earlier (or a future) Last-Modified is not a usable publish time.
MIRROR_LAUNCH = datetime(2019, 4, 1, tzinfo=UTC).timestamp()
CLOCK_SKEW = 300.0
KEEP_STALE = 7 * DAY
INFO_TTL = DAY  # .info of a canonical version (its Origin may change, the version does not)
LOOKUP_TTL = 30 * DAY  # checksum database records never change
TILE_TTL = 365 * DAY  # nor do tiles (partial ones are only superseded)
ABSENT_TTL = 3600.0  # a version the mirror does not have is asked about again after this long
DMF = {"Disable-Module-Fetch": "true"}  # the mirror answers from its cache only


class _Absent:
    """The mirror does not have this version (or it does not exist)."""


ABSENT = _Absent()


@dataclass(frozen=True, slots=True)
class Listing:
    versions: tuple[str, ...]  # canonical versions, in upstream order
    content_id: str


@dataclass(frozen=True, slots=True)
class Gone:
    """Upstream answered 404/410: the body is passed on (it explains why, e.g. a private repository)."""

    status: int
    body: bytes


@dataclass(frozen=True, slots=True)
class Passed:
    status: int
    body: bytes


@dataclass(slots=True)
class View:
    listed: list[str] = field(default_factory=list)
    held: set[str] = field(default_factory=set)
    blocked: dict[str, BlockEntry] = field(default_factory=dict)
    latest: str | None = None  # the version the go command should pick: the newest allowed one
    fail_open: bool = False
    complete: bool = True  # every listed version was judged (none skipped at PROBE_LIMIT or on an error)
    next_change: float = math.inf
    package_block: BlockEntry | None = None


class _Info(msgspec.Struct):
    Version: str = ""


_info_decoder = msgspec.json.Decoder(_Info)


def _iso(ts: float | None) -> str:
    return "an unknown time" if ts is None else datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _days(value: float) -> str:
    return f"{value:g} day" + ("" if value == 1 else "s")


def go_error(status: int, code: str, *, headers: dict[str, str] | None = None, **fields: Any) -> Response:
    """The artifact server's errors as text the go command shows."""
    artifact = fields.get("artifact") or "the module"
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
    return text_error(status, msg, headers=headers)


class GoService:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.flight = SingleFlight()

    @property
    def upstream_bases(self) -> list[str]:
        return [m.rstrip("/") for m in self.ctx.cfg.raw.upstreams.go.mirrors]

    @property
    def sumdb_base(self) -> str:
        return self.ctx.cfg.raw.upstreams.go.sumdb_url.rstrip("/")

    def _urls(self, path: str) -> list[str]:
        return [b + path for b in self.upstream_bases]

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
        path = route_path(request.scope)
        if path in ("", "/"):
            return Response(b"SlowShield Go module proxy: use this URL as GOPROXY.\n", media_type=TEXT)
        if path.startswith("/sumdb/"):
            return await self.sumdb(path[len("/sumdb/") :])
        req = M.parse(path)
        if req is None:
            return text_error(404, "not found")
        blocks = self.ctx.blocklist.for_package(ECO, req.module)
        if blocks.package_block is not None:
            kind = "artifact" if req.kind in ("mod", "zip") else "metadata"
            return self._blocked(request, req.module, req.version, blocks.package_block, kind=kind)
        if req.kind == "list":
            return await self.version_list(request, req)
        if req.kind == "latest":
            return await self.latest(request, req)
        if req.kind == "info":
            return await self.info(request, req)
        return await self.artifact(request, req)

    # ---- publish times ----------------------------------------------------------------------------------

    def _times(self, module: str) -> dict[str, float]:
        """Known publish times of `module`'s versions (shared by all workers through the database)."""
        key = ("go:times", module)
        now = self.ctx.clock.now()
        hit = self.ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit
        rows = self.ctx.db.readers.query(
            "SELECT version, published FROM package_versions "
            "WHERE ecosystem = ? AND name = ? AND published IS NOT NULL",
            (ECO, module),
        )
        times = {r[0]: float(r[1]) for r in rows}
        self.ctx.metadata_cache.put(key, times, 256 + 64 * len(times), now + 300)
        return times

    def _learned(self, module: str, version: str, published: float, *, store: bool = True) -> None:
        times = self.ctx.metadata_cache.get_stale(("go:times", module))
        if isinstance(times, dict):
            times[version] = published
        if store:
            self.ctx.recorder.catalog(ECO, module, [(version, published, False)])

    def _stored_at(self, headers: dict[str, str]) -> float:
        """When the mirror stored the version it just answered with 200 for: its Last-Modified. Without a plausible
        one, the version's clock starts now, when SlowShield first sees it (the 200 proves it exists, so this can't
        age anything in advance; the nightly check in tests/e2e/test_live.py notices the mirror changing)."""
        now = self.ctx.clock.now()
        raw = headers.get("last-modified")
        try:
            ts = email.utils.parsedate_to_datetime(raw).timestamp() if raw else None
        except TypeError, ValueError:
            ts = None
        if ts is None or not MIRROR_LAUNCH <= ts <= now + CLOCK_SKEW:
            log.warning("no plausible Last-Modified from the Go module mirror", extra={"last_modified": raw})
            return now
        return ts

    async def published(self, req: M.ProxyRequest, version: str, *, fetch: bool) -> float | _Absent:
        """When the mirror first stored `version`.

        With `fetch`, a version the mirror does not have yet is fetched once so the mirror stores it; its clock
        starts now. A version that does not exist is ABSENT and nothing is recorded, so no version can be aged
        before it exists.
        """
        known = self._times(req.module).get(version)
        if known is not None:
            return known
        now = self.ctx.clock.now()
        if not fetch and self.ctx.metadata_cache.get(("go:absent", req.module, version), now) is not None:
            return ABSENT
        return await self.flight.run(("go:pub", req.module, version, fetch), lambda: self._probe(req, version, fetch))

    async def _probe(self, req: M.ProxyRequest, version: str, fetch: bool) -> float | _Absent:
        ctx = self.ctx
        row = ctx.db.readers.one(
            "SELECT published FROM package_versions "
            "WHERE ecosystem = ? AND name = ? AND version = ? AND published IS NOT NULL",
            (ECO, req.module, version),
        )
        if row is not None:  # another worker found it meanwhile
            self._learned(req.module, version, float(row[0]), store=False)
            return float(row[0])
        urls = self._urls(f"/{req.escaped}/@v/{M.escape(version)}.mod")
        res = await ctx.upstream.fetch(urls, headers=DMF, max_bytes=0, method="HEAD")
        result = {200: "on_mirror", 404: "not_on_mirror", 410: "not_on_mirror"}.get(res.status, "error")
        instruments.publish_time_lookups.add(1, {"slowshield.ecosystem": ECO, "result": result})
        if res.status == 200:
            published = self._stored_at(res.headers)
            self._learned(req.module, version, published)
            return published
        if res.status not in (404, 410):
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        if not fetch:
            ctx.metadata_cache.put(("go:absent", req.module, version), True, 64, ctx.clock.now() + ABSENT_TTL)
            return ABSENT
        # Not on the mirror yet (or the cache-only answer was a transient error): fetch it for real.
        res = await ctx.upstream.fetch(urls, max_bytes=MAX_MOD_BYTES)
        result = {200: "fetched", 404: "not_found", 410: "not_found"}.get(res.status, "error")
        instruments.publish_time_lookups.add(1, {"slowshield.ecosystem": ECO, "result": result})
        if res.status in (404, 410):
            return ABSENT
        if res.status != 200:
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        published = self._stored_at(res.headers)
        self._learned(req.module, version, published)
        return published

    # ---- version lists ----------------------------------------------------------------------------------

    async def _list(self, req: M.ProxyRequest) -> Listing | Gone:
        key = ("go:list", req.module)
        hit = self.ctx.metadata_cache.get(key, self.ctx.clock.now())
        if hit is not None:
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            self.ctx.recorder.lookup(ECO, cached=True)
            return hit
        return await self.flight.run(key, lambda: self._load_list(req))

    async def _load_list(self, req: M.ProxyRequest) -> Listing | Gone:
        ctx = self.ctx
        key = ("go:list", req.module)
        skey = f"go:list:{req.module}"
        now = ctx.clock.now()
        ttl = ctx.cfg.raw.metadata_cache_ttl_hours * 3600
        stored = await ctx.metadata_store.aget(skey)
        if stored is not None and stored.fresh(now):
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            ctx.recorder.lookup(ECO, cached=True)
            listing = _listing(stored.value)
            ctx.metadata_cache.put(key, listing, 512 + len(stored.value) * 2, stored.expires)
            return listing
        headers = {}
        if stored is not None and stored.meta.get("etag"):
            headers["If-None-Match"] = stored.meta["etag"]
        ctx.recorder.lookup(ECO, cached=False)
        try:
            res = await ctx.upstream.fetch(
                self._urls(f"/{req.escaped}/@v/list"), headers=headers, max_bytes=MAX_LIST_BYTES
            )
        except UpstreamError:
            if stored is None:
                raise
            log.warning("upstream unavailable; serving a stale Go version list", extra={"package": req.module})
            listing = _listing(stored.value)
            ctx.metadata_cache.put(key, listing, 512 + len(stored.value) * 2, now + 60)
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "stale"})
            return listing
        if res.status == 304 and stored is not None:
            await ctx.metadata_store.atouch(skey, now + ttl, now + ttl + KEEP_STALE)
            listing = _listing(stored.value)
            ctx.metadata_cache.put(key, listing, 512 + len(stored.value) * 2, now + ttl)
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "revalidated"})
            ctx.recorder.catalog(ECO, req.module)
            return listing
        instruments.cache_requests.add(1, {"cache": "metadata", "result": "miss"})
        if res.status in (404, 410):
            gone = Gone(res.status, res.body[:2048])
            ctx.metadata_cache.put(key, gone, 256 + len(gone.body), now + 300)
            return gone
        if res.status != 200:
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        await ctx.metadata_store.aput(
            skey, res.body, expires=now + ttl, keep_until=now + ttl + KEEP_STALE, meta={"etag": res.etag}
        )
        listing = _listing(res.body)
        ctx.metadata_cache.put(key, listing, 512 + len(res.body) * 2, now + ttl)
        ctx.recorder.catalog(ECO, req.module)
        return listing

    async def view(self, req: M.ProxyRequest, listing: Listing) -> View:
        key = ("go:view", req.module, listing.content_id, self.ctx.policy_key())
        hit = self.ctx.metadata_cache.get(key, self.ctx.clock.now())
        if hit is not None:
            return hit
        return await self.flight.run(key, lambda: self._evaluate(req, listing, key))

    async def _evaluate(self, req: M.ProxyRequest, listing: Listing, key: tuple[Any, ...]) -> View:
        """Walk the versions the way the go command picks one (newest first, releases before prereleases) until one
        is old enough, and check the prereleases above it too. Versions below it are listed unless their time is
        already known to be too new: showing them changes nothing, because every .info/.mod/.zip request is checked
        on its own."""
        ctx = self.ctx
        cfg = ctx.cfg
        now = ctx.clock.now()
        v = View()
        blocks = ctx.blocklist.for_package(ECO, req.module)
        if blocks.package_block is not None:
            v.package_block = blocks.package_block
            ctx.metadata_cache.put(key, v, 256, now + 300)
            return v
        candidates: list[str] = []
        for ver in listing.versions:
            entry = blocks.match(ECO, ver)
            if entry is not None:
                v.blocked[ver] = entry
            else:
                candidates.append(ver)
        times = self._times(req.module)

        def delay(ver: str) -> float:
            return cfg.delay_days_for(ECO, req.module, ver)

        held: set[str] = set()

        def hold(ver: str, published: float | None) -> None:
            held.add(ver)
            if published is not None:
                v.next_change = min(v.next_change, published + delay(ver) * DAY)

        probes = 0

        async def judge(ver: str) -> bool | None:
            """True: old enough; False: held; None: not judged (PROBE_LIMIT reached, or an upstream error)."""
            nonlocal probes
            known = times.get(ver)
            published: float | _Absent
            if known is not None:
                published = known
            else:
                if probes >= PROBE_LIMIT:
                    v.complete = False
                    return None
                probes += 1
                try:
                    published = await self.published(req, ver, fetch=False)
                except UpstreamError:
                    v.complete = False
                    return None
            if isinstance(published, _Absent):
                hold(ver, None)  # not on the mirror yet
                return False
            if is_old_enough(published, delay(ver), now):
                return True
            hold(ver, published)
            return False

        newest_first = sorted(candidates, key=lambda x: V.sort_key(ECO, x), reverse=True)
        releases = [x for x in newest_first if M.is_release(x)]
        prereleases = [x for x in newest_first if not M.is_release(x)]
        # The go command picks the newest release, or the newest prerelease when there is no release.
        for group in (releases, prereleases):
            for ver in group:
                if await judge(ver):
                    v.latest = ver
                    break
            if v.latest is not None:
                break
        if v.latest is not None and M.is_release(v.latest):
            # Prereleases above the chosen release would still show in `go list -m -versions`: check them too.
            top = V.sort_key(ECO, v.latest)
            for ver in prereleases:
                if V.sort_key(ECO, ver) <= top:
                    break
                await judge(ver)
        for ver in candidates:
            t = times.get(ver)
            if ver not in held and t is not None and not is_old_enough(t, delay(ver), now):
                hold(ver, t)
        if v.latest is None and v.complete and held and cfg.raw.fail_open:
            # Nothing old enough yet (a brand-new module): serve it anyway, like PyPI and npm.
            v.fail_open = True
            v.latest = (releases or prereleases)[0]
            held = set()
        v.held = held
        v.listed = [ver for ver in candidates if ver not in held]
        ctx.metadata_cache.put(key, v, 512 + 64 * len(listing.versions), min(v.next_change, now + 300))
        return v

    async def _fails_open(self, req: M.ProxyRequest) -> bool:
        """True when no version of the module is old enough yet, so fail-open serves the requested one too."""
        cfg = self.ctx.cfg
        try:
            listing = await self._list(req)
        except UpstreamError:
            return False
        if isinstance(listing, Listing) and listing.versions:
            return (await self.view(req, listing)).fail_open
        # No tagged versions: only the pseudo-versions SlowShield has looked up.
        now = self.ctx.clock.now()
        times = self._times(req.module)
        return not any(is_old_enough(t, cfg.delay_days_for(ECO, req.module, ver), now) for ver, t in times.items())

    # ---- gate ---------------------------------------------------------------------------------------------

    async def _gate(self, request: Request, req: M.ProxyRequest, version: str, kind: str) -> Response | None:
        """None when `version` may be served now; otherwise the refusal."""
        ctx = self.ctx
        blocks = ctx.blocklist.for_package(ECO, req.module)
        entry = blocks.package_block or blocks.match(ECO, version)
        if entry is not None:
            return self._blocked(request, req.module, version, entry, kind=kind)
        try:
            published = await self.published(req, version, fetch=True)
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, kind, "upstream_error")
            return text_error(
                503,
                f"slowshield: cannot establish when {req.module}@{version} was published ({exc.detail}).\n"
                "Try again later.",
                headers={"Retry-After": "60"},
            )
        if isinstance(published, _Absent):
            ctx.recorder.decision(ECO, kind, "not_found")
            return text_error(404, f"not found: {req.module}@{version}")
        cfg = ctx.cfg
        if not cfg.raw.enforce_age_on_download:
            return None
        delay = cfg.delay_days_for(ECO, req.module, version)
        if is_old_enough(published, delay, ctx.clock.now()):
            return None
        if cfg.raw.fail_open and await self._fails_open(req):
            ctx.recorder.decision(ECO, kind, "fail_open")
            ctx.recorder.event(
                "fail_open",
                ECO,
                req.module,
                version,
                client_ip=client_ip(request.scope, cfg.trusted_networks),
                details={"reason": "all_versions_too_new"},
            )
            return None
        return self._too_new(request, req.module, version, published, delay, kind=kind)

    def _too_new(
        self, request: Request, module: str, version: str, published: float | None, delay: float, *, kind: str
    ) -> Response:
        ctx = self.ctx
        now = ctx.clock.now()
        wait = retry_after(published, delay, now)
        ctx.recorder.decision(ECO, kind, "age_gated")
        ctx.recorder.event(
            "age_gate",
            ECO,
            module,
            version,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details={"published": None if published is None else _iso(published), "delay_days": delay},
        )
        if published is None:
            when = f"SlowShield could not establish when it was published, so it counts as newer than {_days(delay)}."
            until = "Try again later."
        else:
            when = f"It was published {_iso(published)} ({(now - published) / DAY:.1f} days ago); "
            when += f"this proxy requires {_days(delay)}."
            until = f"It becomes available at {_iso(published + delay * DAY)}."
        return text_error(
            403,
            f"slowshield: {module}@{version} is too new.\n{when}\n{until}\n"
            "Use an older version, or ask your SlowShield administrator for an exception.",
            headers={"Retry-After": str(wait if wait is not None else int(delay * DAY))},
        )

    def _blocked(self, request: Request, module: str, version: str | None, entry: BlockEntry, *, kind: str) -> Response:
        ctx = self.ctx
        ctx.recorder.decision(ECO, kind, "blocked")
        ctx.recorder.event(
            "blocked",
            ECO,
            module,
            version,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details=entry.as_json(),
        )
        what = f"{module}@{version}" if version and not entry.package_level else module
        lines = [f"slowshield: {what} is blocked as known malware."]
        advisory = " ".join(p for p in (entry.advisory_id, f"({entry.source})", entry.url or "") if p)
        lines.append(f"Advisory: {advisory}")
        if entry.reason:
            lines.append(entry.reason.splitlines()[0][:300])
        return text_error(451, "\n".join(lines))

    # ---- handlers ---------------------------------------------------------------------------------------

    async def version_list(self, request: Request, req: M.ProxyRequest) -> Response:
        ctx = self.ctx
        try:
            listing = await self._list(req)
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, "metadata", "upstream_error")
            return text_error(502, f"slowshield: upstream error: {exc.detail}")
        if isinstance(listing, Gone):
            ctx.recorder.decision(ECO, "metadata", "not_found")
            return Response(listing.body, status_code=listing.status, media_type=TEXT)
        v = await self.view(req, listing)
        if v.package_block is not None:
            return self._blocked(request, req.module, None, v.package_block, kind="metadata")
        if not v.listed and v.blocked and not v.held:
            return self._blocked(request, req.module, None, next(iter(v.blocked.values())), kind="metadata")
        now = ctx.clock.now()
        headers = {
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
                req.module,
                None,
                client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
                details={"reason": "all_versions_too_new", "versions": v.listed[-20:]},
            )
        else:
            ctx.recorder.decision(ECO, "metadata", "served")
        return Response("".join(f"{ver}\n" for ver in v.listed).encode(), media_type=TEXT, headers=headers)

    async def info(self, request: Request, req: M.ProxyRequest) -> Response:
        version = req.version or ""
        if M.is_canonical(version):
            refusal = await self._gate(request, req, version, "metadata")
            return refusal if refusal is not None else await self._info_body(req, version)
        # A branch, tag or commit: the mirror resolves it to a canonical version, which is then checked.
        return await self._resolved(request, req, f"/{req.escaped}/@v/{req.escaped_version}.info")

    async def latest(self, request: Request, req: M.ProxyRequest) -> Response:
        try:
            listing = await self._list(req)
        except UpstreamError as exc:
            self.ctx.recorder.decision(ECO, "metadata", "upstream_error")
            return text_error(502, f"slowshield: upstream error: {exc.detail}")
        if isinstance(listing, Listing) and listing.versions:
            v = await self.view(req, listing)
            if v.package_block is not None:
                return self._blocked(request, req.module, None, v.package_block, kind="metadata")
            if v.latest is not None:
                return await self._info_body(req, v.latest)
        # Nothing tagged to offer: the mirror resolves the default branch to a pseudo-version. If that commit is too
        # new, the answer is the newest commit SlowShield knows to be old enough, as a version list leaves out the
        # newest entries. (The go command asks every module in a build for @latest to check retractions.)
        return await self._resolved(request, req, f"/{req.escaped}/@latest", older_ok=True)

    async def _allowed(self, req: M.ProxyRequest, version: str) -> bool:
        """Whether `version` would be served now, without recording a decision."""
        cfg = self.ctx.cfg
        blocks = self.ctx.blocklist.for_package(ECO, req.module)
        if (blocks.package_block or blocks.match(ECO, version)) is not None:
            return False
        published = await self.published(req, version, fetch=True)
        if isinstance(published, _Absent):
            return False
        if not cfg.raw.enforce_age_on_download:
            return True
        if is_old_enough(published, cfg.delay_days_for(ECO, req.module, version), self.ctx.clock.now()):
            return True
        return cfg.raw.fail_open and await self._fails_open(req)

    def _newest_known_allowed(self, req: M.ProxyRequest) -> str | None:
        """The newest version of the module, among those SlowShield has looked up, that is old enough and not
        blocked."""
        cfg = self.ctx.cfg
        now = self.ctx.clock.now()
        blocks = self.ctx.blocklist.for_package(ECO, req.module)
        allowed = [
            ver
            for ver, t in self._times(req.module).items()
            if blocks.match(ECO, ver) is None and is_old_enough(t, cfg.delay_days_for(ECO, req.module, ver), now)
        ]
        if not allowed:
            return None
        return max(allowed, key=lambda ver: V.sort_key(ECO, ver))

    async def _resolved(self, request: Request, req: M.ProxyRequest, path: str, *, older_ok: bool = False) -> Response:
        ctx = self.ctx
        try:
            res = await ctx.upstream.fetch(self._urls(path), max_bytes=MAX_INFO_BYTES)
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, "metadata", "upstream_error")
            return text_error(502, f"slowshield: upstream error: {exc.detail}")
        if res.status in (404, 410):
            ctx.recorder.decision(ECO, "metadata", "not_found")
            return Response(res.body[:2048], status_code=res.status, media_type=TEXT)
        version = _info_version(res.body) if res.status == 200 else None
        if version is None or not M.is_canonical(version):
            ctx.recorder.decision(ECO, "metadata", "upstream_error")
            return text_error(502, f"slowshield: upstream returned an unusable answer ({res.status})")
        if older_ok and not await self._allowed(req, version):
            older = self._newest_known_allowed(req)
            if older is not None:
                return await self._info_body(req, older)
        refusal = await self._gate(request, req, version, "metadata")
        if refusal is not None:
            return refusal
        ctx.recorder.decision(ECO, "metadata", "served")
        return Response(res.body, media_type="application/json", headers={"Cache-Control": "max-age=60"})

    async def _info_body(self, req: M.ProxyRequest, version: str) -> Response:
        """The .info of an allowed canonical version, from the shared store or the mirror."""
        ctx = self.ctx
        skey = f"go:info:{req.module}@{version}"
        now = ctx.clock.now()
        stored = await ctx.metadata_store.aget(skey)
        body: bytes | None = stored.value if stored is not None and stored.fresh(now) else None
        if body is None:
            try:
                res = await ctx.upstream.fetch(
                    self._urls(f"/{req.escaped}/@v/{M.escape(version)}.info"), max_bytes=MAX_INFO_BYTES
                )
            except UpstreamError as exc:
                if stored is None:
                    ctx.recorder.decision(ECO, "metadata", "upstream_error")
                    return text_error(502, f"slowshield: upstream error: {exc.detail}")
                res = None
                body = stored.value
            if res is not None:
                if res.status in (404, 410):
                    ctx.recorder.decision(ECO, "metadata", "not_found")
                    return Response(res.body[:2048], status_code=res.status, media_type=TEXT)
                if res.status != 200 or _info_version(res.body) != version:
                    ctx.recorder.decision(ECO, "metadata", "upstream_error")
                    return text_error(502, f"slowshield: upstream returned an unusable .info ({res.status})")
                body = res.body
                keep = now + INFO_TTL + KEEP_STALE
                await ctx.metadata_store.aput(skey, body, expires=now + INFO_TTL, keep_until=keep)
        ctx.recorder.decision(ECO, "metadata", "served")
        return Response(body, media_type="application/json", headers={"Cache-Control": "max-age=3600"})

    async def artifact(self, request: Request, req: M.ProxyRequest) -> AsgiResponse:
        ctx = self.ctx
        version = req.version or ""
        refusal = await self._gate(request, req, version, "artifact")
        if refusal is not None:
            return refusal
        zip_h1, mod_h1 = await self._sums(req)
        is_zip = req.kind == "zip"
        path = f"/{req.escaped}/@v/{req.escaped_version}.{req.kind}"
        check = None
        if is_zip and zip_h1:

            def check(p: Any, expected: str = zip_h1) -> str | None:
                return dirhash.zip_problem(p, expected)

        art = ArtifactRequest(
            ecosystem=ECO,
            key=path,
            package=req.module,
            version=version,
            filename=f"{req.module.rsplit('/', 1)[-1]}@{version}.{req.kind}",
            upstream_url=self.upstream_bases[0] + path,
            expected=Expected() if is_zip else Expected(go_mod_h1=mod_h1),
            content_type="application/zip" if is_zip else TEXT,
            check_file=check,
            upstream_digest=zip_h1 if is_zip else mod_h1,
            error=go_error,
        )
        return await ctx.artifacts.serve(
            art,
            method=request.method,
            headers_in=dict(request.headers),
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
        )

    # ---- checksum database ----------------------------------------------------------------------------

    async def _sums(self, req: M.ProxyRequest) -> tuple[str | None, str | None]:
        """(zip h1, go.mod h1) from the checksum database. The lookup is cached, so it also answers the client's
        own lookup of the same version. Without them the download is still fingerprinted, and the go command
        checks the hashes itself."""
        try:
            res = await self._sumdb_get(f"lookup/{req.escaped}@{req.escaped_version}", LOOKUP_TTL)
        except UpstreamError as exc:
            log.warning("checksum database unavailable", extra={"package": req.module, "error": exc.detail})
            return None, None
        if res.status != 200:
            return None, None
        zip_h1 = mod_h1 = None
        for line in res.body.decode("utf-8", "replace").splitlines()[1:]:
            if not line:
                break
            parts = line.split(" ")
            if len(parts) == 3 and parts[0] == req.module and parts[2].startswith("h1:"):
                if parts[1] == req.version:
                    zip_h1 = parts[2]
                elif parts[1] == f"{req.version}/go.mod":
                    mod_h1 = parts[2]
        return zip_h1, mod_h1

    async def _sumdb_get(self, sub: str, ttl: float) -> Passed:
        return await self.flight.run(("go:sumdb", sub), lambda: self._sumdb_load(sub, ttl))

    async def _sumdb_load(self, sub: str, ttl: float) -> Passed:
        ctx = self.ctx
        skey = f"go:sumdb:{sub}"
        now = ctx.clock.now()
        stored = await ctx.metadata_store.aget(skey)
        if stored is not None and stored.fresh(now):
            return Passed(200, stored.value)
        res = await ctx.upstream.fetch(f"{self.sumdb_base}/{sub}", max_bytes=MAX_SUMDB_BYTES)
        if res.status == 200:
            await ctx.metadata_store.aput(skey, res.body, expires=now + ttl)
        return Passed(res.status, res.body)

    async def sumdb(self, rest: str) -> Response:
        """`/go/sumdb/sum.golang.org/...`: answering `supported` makes the go command send all its checksum
        database traffic here, so clients need no other route out. Bytes are passed through unchanged."""
        name, _, sub = rest.partition("/")
        if name != SUMDB:
            return text_error(404, f"not found: SlowShield proxies the {SUMDB} checksum database only")
        if sub == "supported":
            return Response(b"", media_type=TEXT, headers={"Cache-Control": "max-age=3600"})
        if sub == "latest":
            ttl, media = 60.0, TEXT
        elif sub.startswith("lookup/") and M.parse_lookup(sub[len("lookup/") :]) is not None:
            ttl, media = LOOKUP_TTL, TEXT
        elif M.TILE.match(sub):
            ttl, media = (DAY if ".p/" in sub else TILE_TTL), "application/octet-stream"
        else:
            return text_error(404, "not found")
        try:
            res = await self._sumdb_get(sub, ttl)
        except UpstreamError as exc:
            return text_error(502, f"slowshield: checksum database unavailable: {exc.detail}")
        cache = f"max-age={int(min(ttl, DAY))}" if res.status == 200 else "no-store"
        return Response(res.body, status_code=res.status, media_type=media, headers={"Cache-Control": cache})


def _listing(body: bytes) -> Listing:
    seen: dict[str, None] = {}
    for line in body.decode("utf-8", "replace").splitlines():
        ver = line.strip()
        if ver and M.is_canonical(ver):
            seen.setdefault(ver, None)
    return Listing(tuple(seen), hashlib.blake2b(body, digest_size=12).hexdigest())


def _info_version(body: bytes) -> str | None:
    try:
        return _info_decoder.decode(body).Version or None
    except msgspec.DecodeError:
        return None
