"""OSV malicious-package feed (OpenSSF `MAL-*` advisories) for PyPI and npm. No token required.

First sync downloads `<eco>/all.zip` (streamed to disk, read entry by entry with size caps). Later
syncs read the head of `<eco>/modified_id.csv` (newest first, `<RFC3339>,<ID>` per line) until the
watermark and fetch only the changed `MAL-*` documents.
"""

from __future__ import annotations

import asyncio
import logging
import os
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import msgspec

from slowshield import names
from slowshield.feeds import Advisory, BlockSpec, apply_advisories, load_state, save_state
from slowshield.upstream import TooLargeError, UpstreamError

log = logging.getLogger(__name__)

ECOSYSTEMS = {"PyPI": "pypi", "npm": "npm"}
MAX_ZIP_BYTES = 4 << 30
MAX_ENTRY_BYTES = 8 << 20
MAX_DOC_BYTES = 8 << 20
FULL_RESYNC_AFTER = timedelta(days=30)
BATCH = 500


class _Pkg(msgspec.Struct):
    ecosystem: str = ""
    name: str = ""


class _Event(msgspec.Struct):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None


class _Range(msgspec.Struct):
    type: str = ""
    events: list[_Event] = []


class _Affected(msgspec.Struct):
    package: _Pkg | None = None
    versions: list[str] = []
    ranges: list[_Range] = []


class OsvVuln(msgspec.Struct):
    id: str
    modified: str = ""
    withdrawn: str | None = None
    summary: str | None = None
    details: str | None = None
    affected: list[_Affected] = []


_decoder = msgspec.json.Decoder(OsvVuln)


def _ranges_to_specs(ranges: list[_Range]) -> list[str | None]:
    """OSV range events -> comparator specs. `None` means every version (package-level)."""
    specs: list[str | None] = []
    for r in ranges:
        if r.type not in ("SEMVER", "ECOSYSTEM"):
            continue
        start: str | None = None
        for ev in r.events:
            if ev.introduced is not None:
                start = ev.introduced
            elif ev.fixed is not None or ev.last_affected is not None:
                end = f"< {ev.fixed}" if ev.fixed is not None else f"<= {ev.last_affected}"
                specs.append(end if start in (None, "0") else f">= {start}, {end}")
                start = None
        if start is not None:
            specs.append(None if start == "0" else f">= {start}")
    return specs


def to_advisory(v: OsvVuln) -> Advisory | None:
    if not v.id.startswith("MAL-"):
        return None
    specs: list[BlockSpec] = []
    for aff in v.affected:
        if aff.package is None or not aff.package.name:
            continue
        eco = ECOSYSTEMS.get(aff.package.ecosystem)
        if eco is None:
            continue
        name = names.normalize_pypi(aff.package.name) if eco == "pypi" else names.normalize_npm(aff.package.name)
        if aff.versions:
            specs.extend(BlockSpec(eco, name, version=ver) for ver in dict.fromkeys(aff.versions))
            continue
        rng = _ranges_to_specs(aff.ranges)
        if not rng or None in rng:
            specs.append(BlockSpec(eco, name))
        else:
            specs.extend(BlockSpec(eco, name, version_range=s) for s in rng)
    reason = v.summary or (v.details[:300] if v.details else None)
    return Advisory(
        source="osv",
        advisory_id=v.id,
        specs=specs,
        reason=reason,
        url=f"https://osv.dev/vulnerability/{v.id}",
        withdrawn=bool(v.withdrawn) or not specs,
    )


def _parse_ts(raw: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(raw.strip())
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class OsvFeed:
    name = "osv"
    title = "OSV malicious packages (OpenSSF)"
    requires_token = False

    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx

    def configured(self) -> tuple[bool, str]:
        return (True, "ok") if self.ctx.cfg.raw.feeds.osv.enabled else (False, "disabled")

    @property
    def base(self) -> str:
        return self.ctx.cfg.raw.feeds.osv_base_url.rstrip("/")

    async def sync(self) -> int:
        changed = 0
        now = self.ctx.clock.now()
        for osv_eco, eco in ECOSYSTEMS.items():
            if not getattr(self.ctx.cfg.raw.upstreams, eco).enabled:
                continue
            changed += await self._sync_ecosystem(osv_eco)
        total = self.ctx.db.readers.one("SELECT count(*) FROM blocklist WHERE source = 'osv' AND withdrawn IS NULL")
        n = int(total[0]) if total else 0
        await self.ctx.db.writer.run(
            lambda c: save_state(
                c, self.name, last_attempt=now, last_success=self.ctx.clock.now(), last_error=None, entries=n
            )
        )
        return changed

    async def _sync_ecosystem(self, osv_eco: str) -> int:
        key = f"osv:{osv_eco}"
        state = await asyncio.to_thread(lambda: load_state(self.ctx.db.readers.get(), key))
        mark = _parse_ts(state.get("watermark") or "")
        if mark is None or datetime.now(UTC) - mark > FULL_RESYNC_AFTER:
            return await self._full(osv_eco, key, state.get("etag"))
        return await self._incremental(osv_eco, key, mark)

    # ---- full snapshot ---------------------------------------------------------------------------

    async def _full(self, osv_eco: str, key: str, etag: str | None) -> int:
        url = f"{self.base}/{osv_eco}/all.zip"
        tmp_dir = Path(self.ctx.cfg.raw.data_dir) / "tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        target = tmp_dir / f"osv-{osv_eco}.zip"
        headers = {"If-None-Match": etag} if etag else {}
        log.info("downloading OSV snapshot", extra={"ecosystem": osv_eco})
        async with self.ctx.upstream.stream(url, headers=headers) as resp:
            if resp.status == 304:
                return 0
            if resp.status != 200:
                raise UpstreamError(url, f"upstream returned {resp.status}", resp.status)
            new_etag = resp.headers.get("etag")
            size = 0
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                async for chunk in resp.chunks():
                    size += len(chunk)
                    if size > MAX_ZIP_BYTES:
                        raise TooLargeError(url, "OSV snapshot exceeds size cap")
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(fd, view) :]
            finally:
                os.close(fd)
        try:
            changed, watermark = await asyncio.to_thread(self._apply_zip, target)
        finally:
            target.unlink(missing_ok=True)
        await self.ctx.db.writer.run(
            lambda c: save_state(c, key, watermark=watermark, etag=new_etag, last_success=self.ctx.clock.now())
        )
        return changed

    def _apply_zip(self, path: Path) -> tuple[int, str | None]:
        changed = 0
        watermark: str | None = None
        batch: list[Advisory] = []
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                fname = info.filename.rsplit("/", 1)[-1]
                if not (fname.startswith("MAL-") and fname.endswith(".json")) or info.file_size > MAX_ENTRY_BYTES:
                    continue
                with zf.open(info) as fh:
                    data = fh.read(MAX_ENTRY_BYTES + 1)
                if len(data) > MAX_ENTRY_BYTES:
                    continue
                try:
                    vuln = _decoder.decode(data)
                except msgspec.DecodeError:
                    continue
                if vuln.modified and (watermark is None or vuln.modified > watermark):
                    watermark = vuln.modified
                adv = to_advisory(vuln)
                if adv is not None:
                    batch.append(adv)
                if len(batch) >= BATCH:
                    changed += self._write(batch)
                    batch = []
        if batch:
            changed += self._write(batch)
        return changed, watermark

    def _write(self, batch: list[Advisory]) -> int:
        now = self.ctx.clock.now()
        items = list(batch)
        return self.ctx.db.writer.submit(lambda c: apply_advisories(c, items, now)).result()

    # ---- incremental ------------------------------------------------------------------------------

    async def _incremental(self, osv_eco: str, key: str, mark: datetime) -> int:
        url = f"{self.base}/{osv_eco}/modified_id.csv"
        ids: dict[str, str] = {}
        newest: str | None = None
        async with self.ctx.upstream.stream(url) as resp:
            if resp.status != 200:
                raise UpstreamError(url, f"upstream returned {resp.status}", resp.status)
            buf = b""
            done = False
            async for chunk in resp.chunks():
                buf += bytes(chunk)
                *lines, buf = buf.split(b"\n")
                for line in lines:
                    ts_raw, _, vid = line.decode("utf-8", "replace").strip().partition(",")
                    ts = _parse_ts(ts_raw)
                    if ts is None or not vid:
                        continue
                    if ts < mark:  # strictly older: everything after is older too (ties are re-read)
                        done = True
                        break
                    newest = newest or ts_raw
                    if vid.startswith("MAL-"):
                        ids[vid] = ts_raw
                if done:
                    break
        sem = asyncio.Semaphore(8)

        async def fetch(vid: str) -> Advisory | None:
            async with sem:
                res = await self.ctx.upstream.fetch(
                    f"{self.base}/{osv_eco}/{vid}.json", max_bytes=MAX_DOC_BYTES, kind="feed"
                )
            if res.status == 404:
                return Advisory("osv", vid, [], None, None, withdrawn=True)
            if res.status != 200:
                raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
            try:
                return to_advisory(_decoder.decode(res.body))
            except msgspec.DecodeError:
                return None

        advisories = [a for a in await asyncio.gather(*(fetch(v) for v in ids)) if a is not None]
        now = self.ctx.clock.now()
        changed = await self.ctx.db.writer.run(lambda c: apply_advisories(c, advisories, now)) if advisories else 0
        if newest:
            await self.ctx.db.writer.run(lambda c: save_state(c, key, watermark=newest, last_success=now))
        return changed
