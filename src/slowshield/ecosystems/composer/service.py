"""Composer repository (at /composer/): Packagist's p2 metadata without the versions that are too new or blocked,
with every dist pointing at SlowShield, and age-gated dist downloads checked against their first download.

A version's publish time is its `published-time`, which Packagist sets when the version is published; `time` is the
author's and never used. The first one SlowShield sees is kept, so a file that later moves a version's time earlier
can't age it in advance. A version without a `published-time` is timed from when SlowShield first listed it; one in
the future counts as now. The kept times belong to the version's commit (dist.reference): a branch, or a moved tag,
is timed afresh. See docs/design/composer.md.

Refusals are JSON with a `warning`, which Composer prints: 425 (too new; a 403 would make Composer ask for
credentials) and 451 (blocked, tampered). Upstream failures are 503 with Retry-After, which Composer retries.
"""

from __future__ import annotations

import email.utils
import hashlib
import logging
import math
import re
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from slowshield import names
from slowshield import versions as V
from slowshield.blocklist import BlockEntry
from slowshield.cache.metadata import SingleFlight
from slowshield.config import ComposerUpstream
from slowshield.context import AppContext
from slowshield.ecosystems.artifacts import ArtifactRequest, AsgiResponse
from slowshield.ecosystems.composer import metadata as M
from slowshield.ecosystems.go import dirhash
from slowshield.integrity import Expected
from slowshield.policy import DAY, Candidate, evaluate, retry_after
from slowshield.telemetry import instruments
from slowshield.upstream import UpstreamError
from slowshield.web import TEXT, JSONResponse, client_ip, local_http_origin, route_path, text_error

log = logging.getLogger(__name__)

ECO = "composer"
KEEP_STALE = 7 * DAY  # stored p2 files outlive their TTL for revalidation and stale-if-error
# Packagist opened in 2011: an earlier (or a future) `published-time` is not a usable publish time.
EARLIEST = datetime(2011, 1, 1, tzinfo=UTC).timestamp()
CLOCK_SKEW = 300.0
RETRY_SOON = {"Retry-After": "10"}  # Composer waits out a Retry-After of up to 60 s before it retries a 503
SUMMARY = "lists/all/summary.json"
MAX_SUMMARY_BYTES = 16 << 20
ADVISORIES = "api/security-advisories/"
MAX_ADVISORY_REQUEST = 256 << 10  # Composer asks about up to 500 packages at a time
MAX_ADVISORY_PACKAGES = 1000
MAX_ADVISORY_BYTES = 32 << 20
_PACKAGES_FIELD = re.compile(r"packages\[[0-9]*\]")
# The stored row's times belong to another commit than the version now names: they start again.
_MOVED = (
    "(excluded.reference IS NOT NULL AND package_versions.reference IS NOT NULL "
    "AND excluded.reference != package_versions.reference)"
)
_NOT_FOUND = object()


@dataclass(slots=True)
class View:
    name: str
    held: set[str] = field(default_factory=set)
    blocked: dict[str, BlockEntry] = field(default_factory=dict)
    unservable: set[str] = field(default_factory=set)  # no dist SlowShield can serve
    published: dict[str, float] = field(default_factory=dict)
    fail_open: bool = False
    next_change: float = math.inf
    package_block: BlockEntry | None = None
    body: bytes = b""
    etag: str = ""
    since: float | None = None  # when this body was first served (Last-Modified), shared through the metadata store


def _iso(ts: float | None) -> str:
    return "an unknown time" if ts is None else datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _days(value: float) -> str:
    return f"{value:g} day" + ("" if value == 1 else "s")


def warning(status: int, message: str, *, headers: dict[str, str] | None = None) -> Response:
    """A refusal Composer prints: it shows the `warning` of a JSON error response as `Warning from <url>: …`."""
    return JSONResponse(
        {"warning": message.rstrip("\n")}, status_code=status, headers={"Cache-Control": "no-store", **(headers or {})}
    )


def composer_error(status: int, code: str, *, headers: dict[str, str] | None = None, **fields: Any) -> Response:
    """The artifact server's errors as warnings Composer prints."""
    artifact = fields.get("artifact") or "the dist"
    if code == "tamper_detected":
        msg = (
            f"slowshield: {artifact} changed upstream after it was first served (tampering). "
            "It stays refused until an operator investigates; see Security on the SlowShield UI."
        )
    elif code == "integrity_mismatch":
        msg = f"slowshield: {artifact} failed verification: {fields.get('detail', '')}"
    elif code == "not_found":
        msg = "slowshield: not found upstream"
    else:
        msg = f"slowshield: {code.replace('_', ' ')}" + (f": {fields['detail']}" if fields.get("detail") else "")
    if status == 502:
        status, headers = 503, {**RETRY_SOON, **(headers or {})}  # retried by Composer, like a 502, with the wait
    return warning(status, msg, headers=headers)


def plausible(published: float | None, now: float) -> float | None:
    return published if published is not None and EARLIEST <= published <= now + CLOCK_SKEW else None


def current(published: float | None, now: float) -> float | None:
    """The clock a `published-time` gives now: a future one counts as now (it can't be older than that), one from
    before Packagist as none."""
    return None if published is None or published < EARLIEST else min(published, now)


def zip_content(path: Path) -> str | None:
    """The `h1:` hash of the files in a zip (Go's dirhash), or None if it isn't a readable zip: anything that can't be
    read (an encrypted entry, a broken stream), an entry name used twice, or bytes before the first entry, which
    other unzip tools may read differently. GitHub builds zipballs on request; their bytes may change while the files
    in them don't (docs/design/composer.md)."""
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len({i.filename for i in infos}) != len(infos) or min((i.header_offset for i in infos), default=0):
                return None
        return dirhash.hash_zip(path)
    except Exception:  # whatever the reason, it isn't a file that can be served
        return None


def _moved(known: list[Any], v: M.Version) -> bool:
    """Whether the times kept for a version belong to another commit than the one it names now."""
    return bool(v.reference and known[2] and known[2] != v.reference)


def _http_date(ts: float) -> str:
    return email.utils.formatdate(ts, usegmt=True)


def _parse_http_date(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return email.utils.parsedate_to_datetime(value).timestamp()
    except TypeError, ValueError, IndexError:
        return None


class ComposerService:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.flight = SingleFlight()

    @property
    def settings(self) -> ComposerUpstream:
        return self.ctx.cfg.raw.upstreams.composer

    # ---- ASGI dispatch ------------------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # pragma: no cover - lifespan is handled by the outer app
            return
        request = Request(scope, receive)
        response = await self.dispatch(request)
        await response(scope, receive, send)

    async def dispatch(self, request: Request) -> Any:
        path = route_path(request.scope).lstrip("/")
        if path == ADVISORIES and request.method == "POST":
            return await self.advisories(request)
        if request.method not in ("GET", "HEAD"):
            return text_error(405, "method not allowed", headers={"Allow": "GET, HEAD"})
        if path == "":
            return Response(
                b"SlowShield Composer repository: composer config -g repo.packagist false && "
                b"composer config -g repos.slowshield composer <this URL>\n",
                media_type=TEXT,
            )
        if path == "packages.json":
            return self.packages_json(request)
        if path == SUMMARY:
            return await self.summary(request)
        parts = path.split("/")
        if len(parts) == 3 and parts[0] == "p2" and parts[2].endswith(".json"):
            stem = parts[2].removesuffix(".json")
            dev = stem.endswith("~dev")
            name = f"{parts[1]}/{stem.removesuffix('~dev')}"
            if not names.is_valid_composer(name):
                return text_error(404, "not found")
            return await self.p2_file(request, name, dev)
        if len(parts) == 4 and parts[0] == "dists":
            name = f"{parts[1]}/{parts[2]}"
            reference, _, dist_type = parts[3].rpartition(".")
            valid = M.REFERENCE.fullmatch(reference) and M.DIST_TYPE.fullmatch(dist_type)
            if not (names.is_valid_composer(name) and valid):
                return text_error(404, "not found")
            return await self.download(request, name, reference, dist_type)
        return text_error(404, "not found")

    def _base(self, request: Request) -> str:
        cfg = self.ctx.cfg
        local = local_http_origin(request.scope, cfg.raw.local_http, cfg.trusted_networks)
        return f"{local or cfg.public_base()}/composer"

    def packages_json(self, request: Request) -> Response:
        """The repository: metadata from p2 files, security advisories (inline in them, and Packagist's advisory API
        for `composer audit`), and Packagist's malware list for Composer's own filter. No search, providers or
        download notifications: those would need packagist.org."""
        base = self._base(request)
        doc = {
            "packages": [],
            "metadata-url": f"{base}/p2/%package%.json",
            "security-advisories": {"metadata": True, "api-url": f"{base}/{ADVISORIES}"},
            "filter": {"metadata": True, "lists": {"malware": {"enabled": True}}, "summary-url": f"{base}/{SUMMARY}"},
        }
        return JSONResponse(doc, headers={"Cache-Control": "max-age=300"})

    # ---- p2 files -----------------------------------------------------------------------------------------

    async def p2(self, name: str, dev: bool) -> M.P2File | None:
        """Packagist's p2 file of `name` (the branches with `dev`), or None if Packagist has none."""
        key = ("composer:p2", name, dev)
        hit = self.ctx.metadata_cache.get(key, self.ctx.clock.now())
        if hit is not None:
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            self.ctx.recorder.lookup(ECO, cached=True)
            return None if hit is _NOT_FOUND else hit
        return await self.flight.run(key, lambda: self._load(name, dev))

    async def _load(self, name: str, dev: bool) -> M.P2File | None:
        ctx = self.ctx
        key = ("composer:p2", name, dev)
        skey = f"composer:{M.file_of(name, dev)}"
        now = ctx.clock.now()
        ttl = ctx.cfg.raw.metadata_cache_ttl_hours * 3600
        stored = await ctx.metadata_store.aget(skey)
        if stored is not None and stored.fresh(now):
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            ctx.recorder.lookup(ECO, cached=True)
            p2 = M.parse(name, dev, stored.value)
            if p2 is not None:
                ctx.metadata_cache.put(key, p2, p2.weight, stored.expires)
                return p2
        headers = {}
        if stored is not None and stored.meta.get("etag"):
            headers["If-None-Match"] = stored.meta["etag"]
        if stored is not None and stored.meta.get("last_modified"):
            headers["If-Modified-Since"] = stored.meta["last_modified"]
        ctx.recorder.lookup(ECO, cached=False)
        url = f"{self.settings.repo_url.rstrip('/')}/{M.file_of(name, dev)}"
        try:
            res = await ctx.upstream.fetch(url, headers=headers, max_bytes=M.MAX_P2_BYTES)
        except UpstreamError:
            if stored is None:
                raise
            log.warning("upstream unavailable; serving a stale Composer p2 file", extra={"package": name})
            return self._stale(name, dev, stored.value, now)
        if res.status == 304 and stored is not None:
            p2 = M.parse(name, dev, stored.value)
            if p2 is not None:
                await ctx.metadata_store.atouch(skey, now + ttl, now + ttl + KEEP_STALE)
                ctx.metadata_cache.put(key, p2, p2.weight, now + ttl)
                instruments.cache_requests.add(1, {"cache": "metadata", "result": "revalidated"})
                ctx.recorder.catalog(ECO, name)
                return p2
        instruments.cache_requests.add(1, {"cache": "metadata", "result": "miss"})
        if res.status in (404, 410):
            ctx.metadata_cache.put(key, _NOT_FOUND, 64, now + 300)
            return None
        if res.status != 200:
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        p2 = M.parse(name, dev, res.body)
        if p2 is None:
            # A 200 that isn't a p2 file (an error page, a broken mirror) is an upstream failure: caching it would
            # make the package look absent until the TTL ends.
            log.warning("unusable Composer p2 file from upstream", extra={"package": name, "bytes": len(res.body)})
            if stored is None:
                raise UpstreamError(res.url, "upstream sent a p2 file that isn't one")
            return self._stale(name, dev, stored.value, now)
        meta = {"etag": res.etag, "last_modified": res.headers.get("last-modified")}
        await ctx.metadata_store.aput(skey, res.body, expires=now + ttl, keep_until=now + ttl + KEEP_STALE, meta=meta)
        ctx.metadata_cache.put(key, p2, p2.weight, now + ttl)
        self._record(p2)
        return p2

    def _stale(self, name: str, dev: bool, body: bytes, now: float) -> M.P2File:
        """The stored p2 file, while upstream can't provide a usable one (asked again in a minute)."""
        p2 = M.parse(name, dev, body)
        if p2 is None:  # pragma: no cover - only usable files are stored
            raise UpstreamError(name, "no usable stored p2 file")
        self.ctx.metadata_cache.put(("composer:p2", name, dev), p2, p2.weight, now + 60)
        instruments.cache_requests.add(1, {"cache": "metadata", "result": "stale"})
        return p2

    # ---- publish times -----------------------------------------------------------------------------------

    def _times(self, name: str) -> dict[str, list[Any]]:
        """version -> [first plausible `published-time` seen, first listed, the reference they belong to], shared by
        all workers through the database."""
        key = ("composer:times", name)
        now = self.ctx.clock.now()
        hit = self.ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit
        rows = self.ctx.db.readers.query(
            "SELECT version, published, first_listed, reference FROM package_versions WHERE ecosystem = ? AND name = ? "
            "AND (published IS NOT NULL OR first_listed IS NOT NULL)",
            (ECO, name),
        )
        times = {r[0]: [r[1], r[2], r[3]] for r in rows}
        self.ctx.metadata_cache.put(key, times, 256 + 96 * len(times), now + 300)
        return times

    def _record(self, p2: M.P2File) -> None:
        """Keep each version's first plausible `published-time`, or, for a version that never had one, when it was
        first listed (as on NuGet: a time that goes missing later doesn't start the clock again). Both belong to the
        version's reference: when it changes, they start again."""
        ctx = self.ctx
        now = ctx.clock.now()
        times = self._times(p2.name)
        rows: list[tuple[Any, ...]] = []
        untimed = 0
        for v in p2.versions.values():
            pub = plausible(v.published, now)
            known: list[Any] | None = times.get(v.version)
            if known is None or _moved(known, v):
                known = times[v.version] = [None, None, v.reference]
            known[2] = known[2] or v.reference
            listed_now = None
            if pub is not None:
                known[0] = known[0] or pub
            elif known[0] is None:
                untimed += 1
                known[1] = known[1] or now
                listed_now = now
            rows.append((ECO, p2.name, v.version, pub, listed_now, 0, v.reference))
        if untimed:
            log.warning(
                "Composer versions without a usable published-time", extra={"package": p2.name, "versions": untimed}
            )

        def op(conn: Any) -> None:
            conn.executemany(
                "INSERT INTO package_versions (ecosystem, name, version, published, first_listed, yanked, reference) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (ecosystem, name, version) DO UPDATE SET "
                f"published = CASE WHEN {_MOVED} THEN excluded.published "
                "ELSE coalesce(package_versions.published, excluded.published) END, "
                f"first_listed = CASE WHEN {_MOVED} THEN excluded.first_listed "
                "ELSE coalesce(package_versions.first_listed, "
                "CASE WHEN package_versions.published IS NULL THEN excluded.first_listed END) END, "
                "reference = coalesce(excluded.reference, package_versions.reference)",
                rows,
            )

        ctx.recorder.catalog(ECO, p2.name)
        ctx.db.writer.enqueue(op)

    @staticmethod
    def _published(v: M.Version, times: dict[str, list[Any]], now: float) -> float:
        """The latest of the clocks known for `v`: its `published-time` now (a future one is now), the first one seen,
        and when it was first listed without one, the last two only for the same reference. Each is no earlier than
        the real publish time, so the latest is the safest."""
        known = times.get(v.version)
        stored = known[:2] if known is not None and not _moved(known, v) else ()
        clocks = [c for c in (current(v.published, now), *stored) if c is not None]
        return max(clocks) if clocks else now

    # ---- policy -------------------------------------------------------------------------------------------

    def _delay(self, name: str, version: str | None) -> float:
        return self.ctx.cfg.delay_days_for(ECO, name, V.canonical(ECO, version) if version else None)

    def view(self, p2: M.P2File, base: str) -> View:
        ctx = self.ctx
        cfg = ctx.cfg
        now = ctx.clock.now()
        key = ("composer:view", p2.name, p2.dev, p2.content_id, ctx.policy_key(), base)
        hit = ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit
        v = View(name=p2.name)
        blocks = ctx.blocklist.for_package(ECO, p2.name)
        if blocks.package_block is not None:
            v.package_block = blocks.package_block
            ctx.metadata_cache.put(key, v, 256, now + 300)
            return v
        times = self._times(p2.name)
        v.unservable = {ver for ver, info in p2.versions.items() if not info.servable}
        if v.unservable:
            log.warning(
                "Composer versions without a dist SlowShield can serve: left out",
                extra={"package": p2.name, "versions": sorted(v.unservable)[:20]},
            )
        v.published = {ver: self._published(info, times, now) for ver, info in p2.versions.items()}
        ev = evaluate(
            (Candidate(ver, ver, v.published[ver]) for ver in p2.versions if ver not in v.unservable),
            now=now,
            delay_for=lambda ver: self._delay(p2.name, ver),
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
        note = None
        if not ev.allowed and ev.held and not p2.dev:
            # Composer would only say that no version matches. (Not for branches: with dev stability allowed, it
            # asks for every package's branches, and most of them change all the time.)
            note = (
                f"slowshield: every version of {p2.name} is newer than {_days(self._delay(p2.name, None))}, so "
                f"none can be installed through this proxy yet. The first becomes available at {_iso(ev.next_change)}."
            )
        drop = v.held | v.blocked.keys() | v.unservable
        v.body = M.render(p2, drop, lambda info: f"{base}/dists/{p2.name}/{info.filename}", warning=note)
        v.etag = '"' + hashlib.blake2b(v.body, digest_size=12).hexdigest() + '"'
        ctx.metadata_cache.put(key, v, 512 + len(v.body) + 64 * len(p2.versions), min(ev.next_change, now + 3600))
        return v

    async def _since(self, v: View, base: str, dev: bool) -> float:
        """When the body of `v` was first served, for `Last-Modified`: kept per file and base in the metadata store, so
        every worker gives the same date, and a client's `If-Modified-Since` gets a 304 exactly when the body is the
        same. It changes with the body, also when a held version comes of age or a block appears."""
        if v.since is not None:
            return v.since
        ctx = self.ctx
        now = ctx.clock.now()
        skey = f"composer:since:{base}:{M.file_of(v.name, dev)}"
        stored = await ctx.metadata_store.aget(skey)
        if stored is not None and stored.value == v.etag.encode() and isinstance(stored.meta.get("since"), float):
            since = stored.meta["since"]
        else:
            since = float(math.floor(now))
            await ctx.metadata_store.aput(skey, v.etag.encode(), expires=now + 30 * DAY, meta={"since": since})
        v.since = since
        return since

    async def _resolve(self, request: Request, name: str, dev: bool, kind: str) -> tuple[M.P2File, View] | Response:
        ctx = self.ctx
        blocks = ctx.blocklist.for_package(ECO, name)
        if blocks.package_block is not None:
            return self._blocked(request, name, None, blocks.package_block, kind=kind)
        try:
            p2 = await self.p2(name, dev)
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, kind, "upstream_error")
            return warning(503, f"slowshield: Packagist is unavailable for {name}: {exc.detail}", headers=RETRY_SOON)
        if p2 is None:
            ctx.recorder.decision(ECO, kind, "not_found")
            return text_error(404, "not found")
        v = self.view(p2, self._base(request))
        if v.package_block is not None:
            return self._blocked(request, name, None, v.package_block, kind=kind)
        return p2, v

    # ---- handlers -----------------------------------------------------------------------------------------

    async def p2_file(self, request: Request, name: str, dev: bool) -> Response:
        ctx = self.ctx
        resolved = await self._resolve(request, name, dev, "metadata")
        if isinstance(resolved, Response):
            return resolved
        p2, v = resolved
        if v.blocked and len(v.blocked) == len(p2.versions):
            return self._blocked(request, name, None, next(iter(v.blocked.values())), kind="metadata")
        now = ctx.clock.now()
        since = await self._since(v, self._base(request), dev)
        headers = {
            "ETag": v.etag,
            "Last-Modified": _http_date(since),
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
                name,
                None,
                client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
                details={"reason": "all_versions_too_new", "versions": list(p2.versions)[:20]},
            )
        else:
            ctx.recorder.decision(ECO, "metadata", "served")
        if request.headers.get("if-none-match") == v.etag:
            return Response(status_code=304, headers=headers)
        modified_since = _parse_http_date(request.headers.get("if-modified-since"))
        if "if-none-match" not in request.headers and modified_since is not None and since <= modified_since:
            return Response(status_code=304, headers=headers)
        return Response(v.body, media_type="application/json", headers=headers)

    async def summary(self, request: Request) -> Response:
        """Packagist's malware list, unchanged, for Composer's own filter (Composer 2.10 or later)."""
        ctx = self.ctx
        skey = f"composer:{SUMMARY}"
        now = ctx.clock.now()
        ttl = ctx.cfg.raw.metadata_cache_ttl_hours * 3600
        stored = await ctx.metadata_store.aget(skey)
        if stored is None or not stored.fresh(now):
            known = stored.meta.get("last_modified") if stored is not None else None
            headers = {"If-Modified-Since": known} if known else {}
            url = f"{self.settings.repo_url.rstrip('/')}/{SUMMARY}"
            try:
                res = await ctx.upstream.fetch(url, headers=headers, max_bytes=MAX_SUMMARY_BYTES)
            except UpstreamError as exc:
                res = None
                if stored is None:
                    detail = f"slowshield: Packagist's malware list is unavailable: {exc.detail}"
                    return warning(503, detail, headers=RETRY_SOON)
            if res is not None and res.status == 304 and stored is not None:
                await ctx.metadata_store.atouch(skey, now + ttl, now + ttl + KEEP_STALE)
            elif res is not None and res.status == 200 and M.parse_summary(res.body):
                meta = {"last_modified": res.headers.get("last-modified") or _http_date(now)}
                keep = now + ttl + KEEP_STALE
                await ctx.metadata_store.aput(skey, res.body, expires=now + ttl, keep_until=keep, meta=meta)
                stored = await ctx.metadata_store.aget(skey)
            elif stored is None:
                detail = f"upstream returned {res.status}" if res is not None else "unavailable"
                return warning(503, f"slowshield: Packagist's malware list is unusable: {detail}", headers=RETRY_SOON)
        if stored is None:  # pragma: no cover - stored just now
            return warning(503, "slowshield: Packagist's malware list is unavailable", headers=RETRY_SOON)
        last_modified = stored.meta.get("last_modified") or _http_date(now)
        headers = {"Last-Modified": last_modified, "Cache-Control": "max-age=300"}
        modified_since = _parse_http_date(request.headers.get("if-modified-since"))
        changed = _parse_http_date(last_modified)
        if modified_since is not None and changed is not None and changed <= modified_since:
            return Response(status_code=304, headers=headers)
        return Response(stored.value, media_type="application/json", headers=headers)

    async def advisories(self, request: Request) -> Response:
        """Packagist's security advisories for the packages Composer names (`packages[]=` in a form), passed on as
        Packagist answers. Only valid package names go upstream, and nothing else from the request."""
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_ADVISORY_REQUEST:
                return warning(413, "slowshield: too many packages in one security advisory request")
        try:
            form_in = parse_qsl(body.decode("ascii"), max_num_fields=MAX_ADVISORY_PACKAGES + 1)
        except UnicodeDecodeError, ValueError:
            return warning(400, "slowshield: a security advisory request is a form with packages[]")
        # PHP's http_build_query, which Composer uses, numbers the list: packages[0]=…&packages[1]=…
        wanted = sorted({v for k, v in form_in if _PACKAGES_FIELD.fullmatch(k) and names.is_valid_composer(v)})
        if not wanted:
            return JSONResponse({"advisories": {}})
        form = urlencode([("packages[]", n) for n in wanted]).encode()
        try:
            res = await self.ctx.upstream.post(
                self.settings.advisories_url,
                form,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                max_bytes=MAX_ADVISORY_BYTES,
            )
        except UpstreamError as exc:
            return warning(503, f"slowshield: Packagist's security advisories are unavailable: {exc.detail}",
                           headers=RETRY_SOON)  # fmt: skip
        if res.status != 200 or not M.parse_advisories(res.body):
            return warning(503, f"slowshield: Packagist's security advisories are unusable (HTTP {res.status})",
                           headers=RETRY_SOON)  # fmt: skip
        return Response(res.body, media_type="application/json", headers={"Cache-Control": "no-store"})

    async def _matching(
        self, request: Request, name: str, reference: str, dist_type: str
    ) -> tuple[M.P2File, View, list[M.Version]] | Response:
        """The versions whose dist is this reference: the tags first, then the branches."""
        found: Response | None = None
        for dev in (False, True):
            resolved = await self._resolve(request, name, dev, "artifact")
            if isinstance(resolved, Response):
                if resolved.status_code != 404:
                    return resolved
                found = found or resolved
                continue
            p2, v = resolved
            hits = [i for i in p2.versions.values() if i.reference == reference and i.dist_type == dist_type]
            if hits:
                return p2, v, hits
        self.ctx.recorder.decision(ECO, "artifact", "not_found")
        return found or text_error(404, f"not found: {name} has no version with the dist {reference}.{dist_type}")

    async def download(self, request: Request, name: str, reference: str, dist_type: str) -> AsgiResponse:
        ctx = self.ctx
        # A package blocked as a whole is refused (and recorded) before anything else, even when Packagist has deleted
        # it since: a lockfile pinned during an attack window must show up as a security event, not a 404.
        blocks = ctx.blocklist.for_package(ECO, name)
        if blocks.package_block is not None:
            return self._blocked(request, name, None, blocks.package_block, kind="artifact")
        found = await self._matching(request, name, reference, dist_type)
        if isinstance(found, Response):
            return found
        p2, v, hits = found
        for info in hits:
            if info.version in v.blocked:
                return self._blocked(request, name, info.version, v.blocked[info.version], kind="artifact")
        hits = [i for i in hits if i.version not in v.unservable]
        if not hits:
            ctx.recorder.decision(ECO, "artifact", "not_found")
            return text_error(404, f"not found: no dist SlowShield can serve for {name} {reference}")
        served = [i for i in hits if i.version not in v.held]
        if not served:
            if ctx.cfg.raw.enforce_age_on_download:
                return self._too_new(request, p2, v, hits[0].version)
            served = hits
        info = served[0]
        upstream = M.fetch_url(info.dist_url or "")  # every servable version has one
        host = (urlsplit(upstream).hostname or "").lower()
        allowed = {h.lower() for h in self.settings.download_hosts} | {
            (urlsplit(self.settings.repo_url).hostname or "").lower()
        }
        if host not in allowed:
            ctx.recorder.decision(ECO, "artifact", "upstream_error")
            return warning(
                502,
                f"slowshield: {name} {info.version} is downloaded from {host}, which is not in "
                "upstreams.composer.download_hosts. Ask your SlowShield administrator to add it.",
            )
        art = ArtifactRequest(
            ecosystem=ECO,
            key=f"/{name}/{info.filename}",
            package=name,
            version=info.version,
            filename=f"{name.replace('/', '-')}-{info.filename}",
            upstream_url=upstream,
            expected=Expected(sha1=info.shasum),
            content_type="application/zip" if dist_type == "zip" else "application/octet-stream",
            content_digest=zip_content if dist_type == "zip" else None,
            error=composer_error,
            published=v.published.get(info.version),
        )
        return await ctx.artifacts.serve(
            art,
            method=request.method,
            headers_in=dict(request.headers),
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
        )

    # ---- refusals -----------------------------------------------------------------------------------------

    def _too_new(self, request: Request, p2: M.P2File, v: View, version: str) -> Response:
        ctx = self.ctx
        now = ctx.clock.now()
        published = v.published.get(version)
        delay = self._delay(p2.name, version)
        wait = retry_after(published, delay, now)
        ctx.recorder.decision(ECO, "artifact", "age_gated")
        ctx.recorder.event(
            "age_gate",
            ECO,
            p2.name,
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
        older = self._older_allowed(p2, v, version)
        use = (
            f"Use an older version (composer update {p2.name} --with {p2.name}:{older})"
            if older
            else "Use an older version"
        )
        return warning(
            425,
            f"slowshield: {p2.name} {version} is too new. {when} {until} "
            f"{use}, or ask your SlowShield administrator for an exception.",
            headers={"Retry-After": str(wait if wait is not None else int(delay * DAY))},
        )

    @staticmethod
    def _older_allowed(p2: M.P2File, v: View, version: str) -> str | None:
        """The newest version below `version` that would be served now."""
        top = V.sort_key(ECO, version)
        allowed = [
            ver
            for ver in p2.versions
            if ver not in v.held and ver not in v.blocked and ver not in v.unservable and V.sort_key(ECO, ver) < top
        ]
        return max(allowed, key=lambda ver: V.sort_key(ECO, ver)) if allowed else None

    def _blocked(self, request: Request, name: str, version: str | None, entry: BlockEntry, *, kind: str) -> Response:
        ctx = self.ctx
        ctx.recorder.decision(ECO, kind, "blocked")
        ctx.recorder.event(
            "blocked",
            ECO,
            name,
            version,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details=entry.as_json(),
        )
        what = f"{name} {version}" if version and not entry.package_level else name
        return warning(451, " ".join(entry.explain(what)))
