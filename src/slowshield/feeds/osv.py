"""OSV malicious-package feed (OpenSSF `MAL-*` advisories) for every served ecosystem. No token required.

For crates.io it also takes the RustSec advisories categorised "malicious" that have no `MAL-*` counterpart: most
crates RustSec reports as malware never got one.

First sync downloads `<eco>/all.zip` (streamed to disk, read entry by entry with size caps). Later
syncs read the head of `<eco>/modified_id.csv` (newest first, `<RFC3339>,<ID>` per line) until the
watermark and fetch only the changed `MAL-*` (and `RUSTSEC-*`) documents.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import msgspec

from slowshield.ecosystems import ECOSYSTEMS as REGISTRY
from slowshield.ecosystems import normalize
from slowshield.feeds import Advisory, BlockSpec, apply_advisories, load_state, save_state
from slowshield.upstream import TooLargeError, UpstreamError

log = logging.getLogger(__name__)

ECOSYSTEMS = {e.osv: e.id for e in REGISTRY.values()}  # OSV name -> ours
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


class _DatabaseSpecific(msgspec.Struct):
    categories: list[Any] = []  # RustSec: "malicious", "code-execution", ...


class _Affected(msgspec.Struct):
    package: _Pkg | None = None
    versions: list[str] = []
    ranges: list[_Range] = []
    database_specific: _DatabaseSpecific | None = None


class OsvVuln(msgspec.Struct):
    id: str
    modified: str = ""
    withdrawn: str | None = None
    aliases: list[str] = []
    summary: str | None = None
    details: str | None = None
    affected: list[_Affected] = []


_decoder = msgspec.json.Decoder(OsvVuln)
_ZERO = ("0", "0.0.0-0")  # introduced at the very first version (RustSec writes the lowest SemVer)


def wanted(vuln_id: str) -> bool:
    """Documents worth reading: OpenSSF malware, and RustSec advisories (only the malicious ones become blocks)."""
    return vuln_id.startswith(("MAL-", "RUSTSEC-"))


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
                specs.append(end if start is None or start in _ZERO else f">= {start}, {end}")
                start = None
        if start is not None:
            specs.append(None if start in _ZERO else f">= {start}")
    return specs


def _rustsec_malware(v: OsvVuln) -> bool:
    """A RustSec advisory categorised "malicious" that no `MAL-*` advisory covers already."""
    malicious = any(
        a.database_specific is not None and "malicious" in a.database_specific.categories for a in v.affected
    )
    return malicious and not any(alias.startswith("MAL-") for alias in v.aliases)


def to_advisory(v: OsvVuln) -> Advisory | None:
    rustsec = v.id.startswith("RUSTSEC-")
    if not (v.id.startswith("MAL-") or rustsec):
        return None
    if rustsec and not _rustsec_malware(v):
        # Not (or no longer) a block of ours: lifts the blocks of an advisory that was recategorised.
        return Advisory("osv", v.id, [], None, None, withdrawn=True)
    specs: list[BlockSpec] = []
    for aff in v.affected:
        if aff.package is None or not aff.package.name:
            continue
        eco = ECOSYSTEMS.get(aff.package.ecosystem)
        if eco is None:
            continue
        name = normalize(eco, aff.package.name)
        if aff.versions:
            specs.extend(BlockSpec(eco, name, version=ver) for ver in dict.fromkeys(aff.versions))
            continue
        rng = _ranges_to_specs(aff.ranges)
        if rustsec:
            # RustSec marks a compromised crate as malicious from some version on, with no end: the versions after
            # crates.io removed the bad ones are not malware. The MAL-* and GitHub advisories cover those cases.
            rng = [s for s in rng if s is None or "<" in s]
            if not rng:
                continue
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
        now = datetime.fromtimestamp(self.ctx.clock.now(), UTC)
        if mark is None or now - mark > FULL_RESYNC_AFTER:
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
        stop = threading.Event()
        try:
            changed, watermark = await asyncio.to_thread(self._apply_zip, target, stop)
        except asyncio.CancelledError:
            stop.set()  # let the worker thread finish promptly on shutdown
            raise
        finally:
            target.unlink(missing_ok=True)
        await self.ctx.db.writer.run(
            lambda c: save_state(c, key, watermark=watermark, etag=new_etag, last_success=self.ctx.clock.now())
        )
        return changed

    def _apply_zip(self, path: Path, stop: threading.Event | None = None) -> tuple[int, str | None]:
        changed = 0
        newest: datetime | None = None
        batch: list[Advisory] = []
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if stop is not None and stop.is_set():
                    return changed, None  # cancelled: do not advance the watermark
                fname = info.filename.rsplit("/", 1)[-1]
                if not (wanted(fname) and fname.endswith(".json")) or info.file_size > MAX_ENTRY_BYTES:
                    continue
                with zf.open(info) as fh:
                    data = fh.read(MAX_ENTRY_BYTES + 1)
                if len(data) > MAX_ENTRY_BYTES:
                    continue
                try:
                    vuln = _decoder.decode(data)
                except msgspec.DecodeError:
                    continue
                ts = _parse_ts(vuln.modified) if vuln.modified else None
                if ts is not None and (newest is None or ts > newest):
                    newest = ts
                adv = to_advisory(vuln)
                if adv is not None:
                    batch.append(adv)
                if len(batch) >= BATCH:
                    changed += self._write(batch)
                    batch = []
        if batch:
            changed += self._write(batch)
        return changed, (newest.isoformat() if newest else None)

    def _write(self, batch: list[Advisory]) -> int:
        now = self.ctx.clock.now()
        items = list(batch)
        return self.ctx.db.writer.submit(lambda c: apply_advisories(c, items, now)).result(timeout=120)

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
                    if wanted(vid):
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
