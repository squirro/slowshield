"""RubyGems compact index (at /rubygems/): rubygems.org's index with held versions left out of the info files, and
age-gated .gem downloads verified against the index.

A line's publish time is its `created_at`, which rubygems.org sets when the gem is pushed. Every line (a version
and platform) is judged on its own: a platform gem pushed today for an old version waits like a new version. The
first `created_at` SlowShield sees is kept, so an index that later moves a line's time earlier can't age it in
advance. A line that has never had a plausible `created_at` is timed from when SlowShield first listed it. See
docs/design/rubygems.md.

Neither Bundler nor RubyGems shows the body of a failed download; they print the reason phrase, so refusals are
425 (Too Early) and 451, with a plain-text body for people using curl. Metadata is never refused with an error
status: Bundler drops the compact index for the run on one, and a 403 reads as a credentials problem. A gem with
nothing to serve gets an empty info file instead, which both clients report as "could not find".
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from slowshield import names
from slowshield.blocklist import BlockEntry
from slowshield.cache.metadata import SingleFlight
from slowshield.config import RubygemsUpstream
from slowshield.context import AppContext
from slowshield.ecosystems.artifacts import ArtifactRequest, AsgiResponse, StreamedArtifact
from slowshield.ecosystems.rubygems import index as I
from slowshield.ecosystems.rubygems.versions_file import VersionsFile, read_range
from slowshield.integrity import Expected
from slowshield.policy import DAY, Candidate, evaluate, retry_after
from slowshield.telemetry import instruments
from slowshield.upstream import UpstreamError
from slowshield.web import TEXT, client_ip, route_path, text_error

log = logging.getLogger(__name__)

ECO = "rubygems"
KEEP_STALE = 7 * DAY  # stored info files outlive their TTL for revalidation and stale-if-error
# rubygems.org's history starts in 2004 (gems imported in 2009 say 2009-07-25): an earlier or a future
# `created_at` is not a usable publish time.
EARLIEST = datetime(2004, 1, 1, tzinfo=UTC).timestamp()
CLOCK_SKEW = 300.0
MAX_NAMES_BYTES = 64 << 20
SPEC_DIR = "quick/Marshal.4.8/"
# Caddy (and other proxies) must not compress these: a compressed body gets another ETag, which Bundler 2.4 and
# older check against the MD5 of what they receive, and the Repr-Digest describes the uncompressed bytes.
INDEX_CACHE = "no-transform"
RETRY_SOON = {"Retry-After": "10"}
# Index files that list every gem without publish times: SlowShield can't filter them, so it doesn't serve them.
FULL_INDEX = frozenset(
    {
        "specs.4.8.gz", "latest_specs.4.8.gz", "prerelease_specs.4.8.gz", "specs.4.8", "latest_specs.4.8",
        "prerelease_specs.4.8", "Marshal.4.8", "Marshal.4.8.Z", "yaml", "yaml.Z", "yaml.z", "quick/index",
        "quick/index.rz", "quick/latest_index", "quick/latest_index.rz",
    }
)  # fmt: skip
NOT_SERVED = (
    "slowshield: {path} is not served: it lists every gem without publish times, so it can't be filtered by release "
    "age.\nBundler and `gem install` use the compact index (/versions, /info/<gem>) instead. `gem search`, `gem list "
    "--remote`, `gem outdated` and `gem update` need this file and don't work through SlowShield; `bundle outdated` "
    "and `bundle update` do."
)
_NOT_FOUND = object()


@dataclass(slots=True)
class View:
    name: str
    held: set[str] = field(default_factory=set)  # line keys
    blocked: dict[str, BlockEntry] = field(default_factory=dict)
    published: dict[str, float | None] = field(default_factory=dict)
    fail_open: bool = False
    next_change: float = math.inf
    package_block: BlockEntry | None = None
    body: bytes = b""
    etag: str = ""
    digest: str = ""


def _iso(ts: float | None) -> str:
    return "an unknown time" if ts is None else datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _days(value: float) -> str:
    return f"{value:g} day" + ("" if value == 1 else "s")


def _etag_matches(header: str | None, etag: str) -> bool:
    if not header:
        return False
    return any(t.strip().removeprefix("W/") in (etag, "*") for t in header.split(","))


def rubygems_error(status: int, code: str, *, headers: dict[str, str] | None = None, **fields: Any) -> Response:
    """The artifact server's errors as plain text (shown by curl; RubyGems prints the status line)."""
    artifact = fields.get("artifact") or "the gem"
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
        status, headers = 503, {**RETRY_SOON, **(headers or {})}
    return text_error(status, msg, headers=headers)


class RubygemsService:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.flight = SingleFlight()
        self.versions_file = VersionsFile(
            Path(ctx.cfg.raw.data_dir) / "rubygems",
            ctx.upstream,
            f"{self.settings.index_url.rstrip('/')}/versions",
            ctx.clock.now,
        )

    @property
    def settings(self) -> RubygemsUpstream:
        return self.ctx.cfg.raw.upstreams.rubygems

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
                b"SlowShield RubyGems mirror: bundle config set --global mirror.https://rubygems.org <this URL>, or "
                b"this URL as the only source in ~/.gemrc.\n",
                media_type=TEXT,
            )
        if path == "versions":
            return await self.versions(request)
        if path == "names":
            return await self.names(request)
        if path.startswith("info/"):
            name = path[5:]
            if not names.is_valid_rubygems(name):
                return text_error(404, "not found")
            return await self.info_file(request, name)
        if path.startswith("gems/") and path.endswith(".gem"):
            return await self.download(request, path[5:-4], spec=False)
        if path.startswith(SPEC_DIR) and path.endswith(".gemspec.rz"):
            return await self.download(request, path[len(SPEC_DIR) : -len(".gemspec.rz")], spec=True)
        if path in FULL_INDEX or path.startswith("api/"):
            self.ctx.recorder.decision(ECO, "metadata", "not_found")
            return text_error(404, NOT_SERVED.format(path=f"/{path}"))
        return text_error(404, "not found")

    # ---- /versions and /names -----------------------------------------------------------------------------

    async def versions(self, request: Request) -> Any:
        ctx = self.ctx
        try:
            snap = await self.versions_file.snapshot()
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, "metadata", "upstream_error")
            return text_error(
                503, f"slowshield: rubygems.org's /versions is unavailable: {exc.detail}", headers=RETRY_SOON
            )
        ctx.recorder.decision(ECO, "metadata", "served")
        headers = {
            "ETag": snap.etag,
            "Repr-Digest": snap.repr_digest,
            "Accept-Ranges": "bytes",
            "Cache-Control": f"max-age=60, {INDEX_CACHE}",
        }
        if _etag_matches(request.headers.get("if-none-match"), snap.etag):
            return Response(status_code=304, headers=headers)
        start, end = 0, snap.size
        status = 200
        rng = _parse_range(request.headers.get("range"))
        if rng is not None and rng[0] < snap.size:
            # Past the end (a cache filled elsewhere) gets the whole file: Bundler's digest check takes it from there.
            start, end = rng[0], min(snap.size, (rng[1] + 1) if rng[1] is not None else snap.size)
            status = 206
            headers["Content-Range"] = f"bytes {start}-{end - 1}/{snap.size}"
        headers["Content-Length"] = str(end - start)
        headers["Content-Type"] = TEXT
        if request.method == "HEAD":
            return Response(status_code=status, headers=headers)
        for _ in range(3):
            try:
                f = self.versions_file.open(snap)
                break
            except FileNotFoundError:  # rebuilt between reading the state and opening the file
                snap = await self.versions_file.snapshot()
        else:  # pragma: no cover - three rebuilds in a row
            return text_error(503, "slowshield: /versions is being rebuilt", headers=RETRY_SOON)
        return StreamedArtifact(status, headers, read_range(f, start, end), _noop)

    async def names(self, request: Request) -> Response:
        """rubygems.org's list of gem names, unchanged (no versions in it), kept for a minute."""
        ctx = self.ctx
        now = ctx.clock.now()
        stored = await ctx.metadata_store.aget("rubygems:names")
        if stored is None or not stored.fresh(now):
            try:
                res = await ctx.upstream.fetch(
                    f"{self.settings.index_url.rstrip('/')}/names",
                    headers={"Accept-Encoding": "identity"},
                    max_bytes=MAX_NAMES_BYTES,
                )
                if res.status != 200:
                    raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
                meta = {k: res.headers[k] for k in ("etag", "repr-digest") if k in res.headers}
                await ctx.metadata_store.aput(
                    "rubygems:names", res.body, expires=now + 60, keep_until=now + KEEP_STALE, meta=meta
                )
                body, meta_used = res.body, meta
            except UpstreamError as exc:
                if stored is None:
                    return text_error(503, f"slowshield: rubygems.org's /names is unavailable: {exc.detail}")
                body, meta_used = stored.value, stored.meta
        else:
            body, meta_used = stored.value, stored.meta
        headers = {"Cache-Control": f"max-age=60, {INDEX_CACHE}"}
        if meta_used.get("etag"):
            headers["ETag"] = meta_used["etag"]
        if meta_used.get("repr-digest"):
            headers["Repr-Digest"] = meta_used["repr-digest"]
        if headers.get("ETag") and _etag_matches(request.headers.get("if-none-match"), headers["ETag"]):
            return Response(status_code=304, headers=headers)
        return Response(body, media_type=TEXT, headers=headers)

    # ---- info files ---------------------------------------------------------------------------------------

    async def info(self, name: str) -> I.InfoFile | None:
        """The upstream info file of `name`, or None if upstream has none."""
        key = ("rubygems:info", name)
        hit = self.ctx.metadata_cache.get(key, self.ctx.clock.now())
        if hit is not None:
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            self.ctx.recorder.lookup(ECO, cached=True)
            return None if hit is _NOT_FOUND else hit
        return await self.flight.run(key, lambda: self._load(name))

    async def _load(self, name: str) -> I.InfoFile | None:
        ctx = self.ctx
        key = ("rubygems:info", name)
        skey = f"rubygems:info:{name}"
        now = ctx.clock.now()
        ttl = ctx.cfg.raw.metadata_cache_ttl_hours * 3600
        stored = await ctx.metadata_store.aget(skey)
        if stored is not None and stored.fresh(now):
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            ctx.recorder.lookup(ECO, cached=True)
            info = I.parse(name, stored.value)
            ctx.metadata_cache.put(key, info, info.weight, stored.expires)
            return info
        headers = {"Accept-Encoding": "identity"}
        if stored is not None and stored.meta.get("etag"):
            headers["If-None-Match"] = stored.meta["etag"]
        ctx.recorder.lookup(ECO, cached=False)
        url = f"{self.settings.index_url.rstrip('/')}/info/{name}"
        try:
            res = await ctx.upstream.fetch(url, headers=headers, max_bytes=I.MAX_INFO_BYTES)
        except UpstreamError:
            if stored is None:
                raise
            log.warning("upstream unavailable; serving a stale RubyGems info file", extra={"package": name})
            return self._stale(name, stored.value, now)
        if res.status == 304 and stored is not None:
            await ctx.metadata_store.atouch(skey, now + ttl, now + ttl + KEEP_STALE)
            info = I.parse(name, stored.value)
            ctx.metadata_cache.put(key, info, info.weight, now + ttl)
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "revalidated"})
            ctx.recorder.catalog(ECO, name)
            return info
        instruments.cache_requests.add(1, {"cache": "metadata", "result": "miss"})
        if res.status in (404, 410):
            ctx.metadata_cache.put(key, _NOT_FOUND, 64, now + 300)
            return None
        if res.status != 200:
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        info = I.parse(name, res.body)
        if not info.lines and res.body.strip() not in (b"", b"---"):
            # A 200 without one usable line (an error page, a broken mirror) is an upstream failure: caching it would
            # make the gem look empty until the TTL ends.
            log.warning("unusable RubyGems info file from upstream", extra={"package": name, "bytes": len(res.body)})
            if stored is None:
                raise UpstreamError(res.url, "upstream sent an info file without a usable line")
            return self._stale(name, stored.value, now)
        await ctx.metadata_store.aput(
            skey, res.body, expires=now + ttl, keep_until=now + ttl + KEEP_STALE, meta={"etag": res.etag}
        )
        ctx.metadata_cache.put(key, info, info.weight, now + ttl)
        self._record(info)
        return info

    def _stale(self, name: str, body: bytes, now: float) -> I.InfoFile:
        """The stored info file, while upstream can't provide a usable one (asked again in a minute)."""
        info = I.parse(name, body)
        self.ctx.metadata_cache.put(("rubygems:info", name), info, info.weight, now + 60)
        instruments.cache_requests.add(1, {"cache": "metadata", "result": "stale"})
        return info

    # ---- publish times -----------------------------------------------------------------------------------

    def _times(self, name: str) -> dict[str, list[Any]]:
        """line key -> [first `created_at` seen, first listed, yanked], shared by all workers through the database."""
        key = ("rubygems:times", name)
        now = self.ctx.clock.now()
        hit = self.ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit
        rows = self.ctx.db.readers.query(
            "SELECT version, published, first_listed, yanked FROM package_versions WHERE ecosystem = ? AND name = ?",
            (ECO, name),
        )
        times = {r[0]: [r[1], r[2], r[3]] for r in rows}
        self.ctx.metadata_cache.put(key, times, 256 + 112 * len(times), now + 300)
        return times

    def _created(self, line: I.Line, now: float) -> float | None:
        t = line.created_at
        return t if t is not None and EARLIEST <= t <= now + CLOCK_SKEW else None

    def _record(self, info: I.InfoFile) -> None:
        """Keep each line's first `created_at`, or, for a line that never had one, when it was first listed; mark
        lines that are gone (yanked) and lines that are back."""
        ctx = self.ctx
        now = ctx.clock.now()
        times = self._times(info.name)
        rows: list[tuple[Any, ...]] = []
        untimed = 0
        for line in info.lines.values():
            created = self._created(line, now)
            known = times.setdefault(line.key, [None, None, 0])
            listed_now = None
            if created is not None:
                known[0] = known[0] or created
            else:
                untimed += 1
                if known[0] is None:
                    known[1] = known[1] or now
                    listed_now = now
            known[2] = 0
            rows.append((ECO, info.name, line.key, created, listed_now, 0))
        for key, known in times.items():
            if key not in info.lines and not known[2]:
                known[2] = 1
                rows.append((ECO, info.name, key, None, None, 1))
        if untimed:
            log.warning(
                "RubyGems info lines without a usable created_at", extra={"package": info.name, "lines": untimed}
            )

        def op(conn: Any) -> None:
            conn.executemany(
                "INSERT INTO package_versions (ecosystem, name, version, published, first_listed, yanked) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (ecosystem, name, version) DO UPDATE SET "
                "published = coalesce(package_versions.published, excluded.published), "
                "first_listed = coalesce(package_versions.first_listed, "
                "CASE WHEN package_versions.published IS NULL THEN excluded.first_listed END), "
                "yanked = excluded.yanked",
                rows,
            )

        ctx.recorder.catalog(ECO, info.name)
        ctx.db.writer.enqueue(op)

    def _published(self, line: I.Line, times: dict[str, list[Any]], now: float) -> float:
        """The later of `line`'s `created_at` now and the first one seen; for a line that has never had one, when it
        was first listed. A fetch without a `created_at` doesn't hold an old line again once the time is back:
        `first_listed` stays recorded (and goes to shield wall followers), but counts only without a `created_at`."""
        known = times.get(line.key, [None, None, 0])
        created = [c for c in (self._created(line, now), known[0]) if c is not None]
        if created:
            return max(created)
        return known[1] if known[1] is not None else now

    # ---- policy -------------------------------------------------------------------------------------------

    def view(self, info: I.InfoFile) -> View:
        ctx = self.ctx
        cfg = ctx.cfg
        now = ctx.clock.now()
        key = ("rubygems:view", info.name, info.content_id, ctx.policy_key())
        hit = ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit
        v = View(name=info.name)
        blocks = ctx.blocklist.for_package(ECO, info.name)
        if blocks.package_block is not None:
            v.package_block = blocks.package_block
            v.blocked = dict.fromkeys(info.lines, blocks.package_block)
        else:
            times = self._times(info.name)
            v.published = {k: self._published(line, times, now) for k, line in info.lines.items()}
            ev = evaluate(
                (Candidate(k, line.version, v.published[k]) for k, line in info.lines.items()),
                now=now,
                delay_for=lambda ver: cfg.delay_days_for(ECO, info.name, ver),
                is_blocked=lambda ver: blocks.match(ECO, ver) is not None,
                fail_open=cfg.fail_open_for(ECO),
            )
            v.held = {c.item for c in ev.held}
            for c in ev.blocked:
                entry = blocks.match(ECO, c.version)
                if entry is not None:
                    v.blocked[c.item] = entry
            # A key that also reads as one version (`1.0.0-beta.1-linux`: a prerelease, or version 1.0.0 on a platform)
            # is refused when an exact block names it whole, whichever reading split_key chose.
            for k, line in info.lines.items():
                if k != line.version and k not in v.blocked and (entry := blocks.match_exact(ECO, k)) is not None:
                    v.blocked[k] = entry
            v.fail_open = ev.fail_open
            v.next_change = ev.next_change
        v.body = I.render(info, v.held | v.blocked.keys())
        v.etag = I.etag(v.body)
        v.digest = I.repr_digest(v.body)
        ctx.metadata_cache.put(key, v, 512 + len(v.body) + 64 * len(info.lines), min(v.next_change, now + 3600))
        return v

    # ---- handlers -----------------------------------------------------------------------------------------

    async def info_file(self, request: Request, name: str) -> Response:
        ctx = self.ctx
        try:
            info = await self.info(name)
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, "metadata", "upstream_error")
            return text_error(
                503, f"slowshield: rubygems.org's index is unavailable for {name}: {exc.detail}", headers=RETRY_SOON
            )
        if info is None:
            ctx.recorder.decision(ECO, "metadata", "not_found")
            return text_error(404, "This gem could not be found")
        v = self.view(info)
        now = ctx.clock.now()
        headers = {
            "ETag": v.etag,
            "Repr-Digest": v.digest,
            "Cache-Control": f"max-age={int(max(0, min(60, v.next_change - now)))}, {INDEX_CACHE}",
            "X-SlowShield-Held-Versions": str(len(v.held)),
        }
        if v.held:
            instruments.versions_held.add(len(v.held), {"slowshield.ecosystem": ECO})
        if info.lines and len(v.blocked) == len(info.lines):
            # Nothing left but blocked lines: an empty list, which clients report as "could not find".
            self._blocked(request, name, None, v.package_block or next(iter(v.blocked.values())), kind="metadata")
        elif v.fail_open:
            headers["X-SlowShield-Fail-Open"] = "1"
            ctx.recorder.decision(ECO, "metadata", "fail_open")
            ctx.recorder.event(
                "fail_open",
                ECO,
                name,
                None,
                client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
                details={"reason": "all_versions_too_new", "versions": list(info.lines)[-20:]},
            )
        else:
            ctx.recorder.decision(ECO, "metadata", "served")
        if _etag_matches(request.headers.get("if-none-match"), v.etag):
            return Response(status_code=304, headers=headers)
        return Response(v.body, media_type=TEXT, headers=headers)

    async def _resolve(self, stem: str) -> tuple[str, I.InfoFile, I.Line] | Response | None:
        """The gem and line a file name stem means (`nokogiri-1.19.4-x86_64-linux-gnu`), from the gems' info files;
        None when no reading of it is listed. An index that can't be read is a 503 only when no other reading is
        listed: `fake-2fa-1.0.0` is `fake-2fa` 1.0.0 even while the index of `fake` fails."""
        failed: tuple[str, UpstreamError] | None = None
        for name, key in I.split_file(stem)[:4]:
            if not names.is_valid_rubygems(name):
                continue
            try:
                info = await self.info(name)
            except UpstreamError as exc:
                failed = failed or (name, exc)
                continue
            if info is not None and key in info.lines:
                return name, info, info.lines[key]
        if failed is not None:
            name, exc = failed
            self.ctx.recorder.decision(ECO, "artifact", "upstream_error")
            return text_error(
                503, f"slowshield: rubygems.org's index is unavailable for {name}: {exc.detail}", headers=RETRY_SOON
            )
        return None

    async def download(self, request: Request, stem: str, *, spec: bool) -> AsgiResponse:
        ctx = self.ctx
        if "/" in stem or not stem:
            return text_error(404, "not found")
        resolved = await self._resolve(stem)
        if isinstance(resolved, Response):
            return resolved
        if resolved is None:
            # Known malware is refused (and recorded) even when rubygems.org has yanked it since: a lockfile pinned
            # during an attack window must show up as a security event, not a 404. Without the line, a key that can
            # name two versions (`1.0.0-beta.1`) is refused when either is blocked.
            for name, key in I.split_file(stem)[:4]:
                if names.is_valid_rubygems(name):
                    blocks = ctx.blocklist.for_package(ECO, name)
                    entry = (
                        blocks.package_block
                        or next((e for v in I.readings(key) if (e := blocks.match(ECO, v)) is not None), None)
                        or blocks.match_exact(ECO, key)
                    )
                    if entry is not None:
                        return self._blocked(request, name, key, entry, kind="artifact")
            ctx.recorder.decision(ECO, "artifact", "not_found")
            return text_error(404, f"not found: {stem} is not in the rubygems.org index")
        name, info, line = resolved
        v = self.view(info)
        if line.key in v.blocked:
            return self._blocked(request, name, line.key, v.blocked[line.key], kind="artifact")
        if ctx.cfg.raw.enforce_age_on_download and line.key in v.held:
            return self._too_new(request, name, v, line)
        # A specification (`.gemspec.rz`) has no published digest: its first download is its fingerprint, as for
        # any file without one, so other bytes later are tampering (RubyGems 3.4 runs Marshal.load on it).
        path = f"{SPEC_DIR}{stem}.gemspec.rz" if spec else f"gems/{stem}.gem"
        art = ArtifactRequest(
            ecosystem=ECO,
            key=f"/{path}",
            package=name,
            version=line.key,
            filename=path.rsplit("/", 1)[-1],
            upstream_url=f"{self.settings.download_url.rstrip('/')}/{path}",
            expected=Expected() if spec else Expected(sha256=line.sha256),
            error=rubygems_error,
            published=v.published.get(line.key),
        )
        return await ctx.artifacts.serve(
            art,
            method=request.method,
            headers_in=dict(request.headers),
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
        )

    # ---- refusals -----------------------------------------------------------------------------------------

    def _too_new(self, request: Request, name: str, v: View, line: I.Line) -> Response:
        ctx = self.ctx
        now = ctx.clock.now()
        published = v.published.get(line.key)
        delay = ctx.cfg.delay_days_for(ECO, name, line.version)
        wait = retry_after(published, delay, now)
        ctx.recorder.decision(ECO, "artifact", "age_gated")
        ctx.recorder.event(
            "age_gate",
            ECO,
            name,
            line.key,
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
            425,
            f"slowshield: {name}-{line.key} is too new.\n{when}\n{until}\n"
            f"Use an older version (bundle update {name}), or ask your SlowShield administrator for an exception.",
            headers={"Retry-After": str(wait if wait is not None else int(delay * DAY))},
        )

    def _blocked(self, request: Request, name: str, key: str | None, entry: BlockEntry, *, kind: str) -> Response:
        ctx = self.ctx
        ctx.recorder.decision(ECO, kind, "blocked")
        ctx.recorder.event(
            "blocked",
            ECO,
            name,
            key,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details=entry.as_json(),
        )
        what = f"{name}-{key}" if key and not entry.package_level else name
        return text_error(451, "\n".join(entry.explain(what)))


def _parse_range(value: str | None) -> tuple[int, int | None] | None:
    """A single `bytes=a-` or `bytes=a-b` range; anything else is ignored (the whole file is sent)."""
    if not value or not value.startswith("bytes=") or "," in value:
        return None
    start, sep, end = value[6:].strip().partition("-")
    if not sep or not start.isdigit() or (end and not end.isdigit()):
        return None
    a, b = int(start), (int(end) if end else None)
    return None if b is not None and b < a else (a, b)


async def _noop() -> None:
    return None
