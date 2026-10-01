"""Content-addressed on-disk cache of verified artifacts.

Layout under `<data>/cache`:
    objects/ab/cd/<sha256>   verified bodies (immutable, served zero-copy via ASGI pathsend)
    tmp/<random>             in-flight downloads (same filesystem, so rename is atomic)
    trash/<sha256>.<ts>      evicted bodies, unlinked after a grace period so in-flight sends finish

Write order on a miss: stream to tmp -> verify digests -> fsync -> rename into objects/ -> insert row.
A crash at any point leaves at worst an orphaned tmp file, which `cleanup()` removes.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from slowshield.clock import Clock
from slowshield.db import Database
from slowshield.telemetry import instruments

log = logging.getLogger(__name__)

_TOUCH_INTERVAL = 3600.0
_TRASH_GRACE = 600.0


@dataclass(frozen=True, slots=True)
class CachedFile:
    path: Path
    sha256: str
    size: int
    content_type: str | None


class TeeFile:
    """Temp file that receives a copy of a streamed body."""

    __slots__ = ("_fd", "path", "size")

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: int | None = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.size = 0

    def write(self, chunk: bytes | memoryview) -> None:
        if self._fd is None:
            return
        view = memoryview(chunk)
        while view:
            n = os.write(self._fd, view)
            view = view[n:]
        self.size += len(chunk)

    def finish(self) -> None:
        if self._fd is not None:
            os.fsync(self._fd)
            os.close(self._fd)
            self._fd = None

    def abort(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class ArtifactCache:
    def __init__(self, root: Path, db: Database, clock: Clock, *, max_bytes: int, enabled: bool = True) -> None:
        self.root = root
        self.db = db
        self.clock = clock
        self.max_bytes = max_bytes
        self.enabled = enabled
        self.objects = root / "objects"
        self.tmp = root / "tmp"
        self.trash = root / "trash"
        self._touched: dict[str, float] = {}
        self.size_bytes = 0
        self.entries = 0

    def prepare(self) -> None:
        if not self.enabled:
            return
        for d in (self.objects, self.tmp, self.trash):
            d.mkdir(parents=True, exist_ok=True)

    def object_path(self, sha256: str) -> Path:
        return self.objects / sha256[:2] / sha256[2:4] / sha256

    def lookup(self, sha256: str | None) -> CachedFile | None:
        if not self.enabled or not sha256:
            return None
        path = self.object_path(sha256)
        try:
            st = path.stat()
        except FileNotFoundError:
            instruments.cache_requests.add(1, {"cache": "artifact", "result": "miss"})
            return None
        row = self.db.readers.one("SELECT content_type FROM cache_entries WHERE sha256 = ?", (sha256,))
        if row is None:
            instruments.cache_requests.add(1, {"cache": "artifact", "result": "miss"})
            return None
        instruments.cache_requests.add(1, {"cache": "artifact", "result": "hit"})
        self._touch(sha256)
        return CachedFile(path, sha256, st.st_size, row[0])

    def _touch(self, sha256: str) -> None:
        now = self.clock.now()
        if now - self._touched.get(sha256, 0.0) < _TOUCH_INTERVAL:
            return
        self._touched[sha256] = now
        if len(self._touched) > 100_000:
            self._touched.clear()
        self.db.writer.execute("UPDATE cache_entries SET last_access = ? WHERE sha256 = ?", (now, sha256))

    def open_tee(self) -> TeeFile | None:
        if not self.enabled:
            return None
        try:
            return TeeFile(self.tmp / f"{secrets.token_hex(12)}.part")
        except OSError:
            log.warning("artifact cache tmp dir not writable; streaming without caching", exc_info=True)
            return None

    async def commit(self, tee: TeeFile, sha256: str, content_type: str | None) -> None:
        """fsync + atomic rename + index row. Never raises: caching is best effort."""
        try:
            await asyncio.to_thread(self._commit_files, tee, sha256)
        except OSError:
            log.warning("could not commit artifact to cache", exc_info=True)
            tee.abort()
            return
        now = self.clock.now()
        self.db.writer.execute(
            "INSERT INTO cache_entries (sha256, size, content_type, created, last_access, verified) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (sha256) DO UPDATE SET last_access = excluded.last_access",
            (sha256, tee.size, content_type, now, now, now),
        )
        self.size_bytes += tee.size
        self.entries += 1

    def _commit_files(self, tee: TeeFile, sha256: str) -> None:
        tee.finish()
        dest = self.object_path(sha256)
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tee.path, dest)

    # ---- maintenance (leader only) -------------------------------------------------------------

    def refresh_stats(self) -> None:
        row = self.db.readers.one("SELECT count(*), coalesce(sum(size), 0) FROM cache_entries")
        if row is not None:
            self.entries, self.size_bytes = int(row[0]), int(row[1])

    async def evict(self) -> int:
        """Evict least-recently-used entries until the cache is under 90% of its cap."""
        if not self.enabled:
            return 0
        await asyncio.to_thread(self.refresh_stats)
        if self.size_bytes <= self.max_bytes:
            return 0
        target = int(self.max_bytes * 0.9)
        rows = await self.db.readers.aquery(
            "SELECT sha256, size FROM cache_entries ORDER BY last_access ASC LIMIT 5000"
        )
        victims: list[str] = []
        freed = 0
        for sha, size in rows:
            if self.size_bytes - freed <= target:
                break
            victims.append(sha)
            freed += size
        if not victims:
            return 0
        await asyncio.to_thread(self._move_to_trash, victims)
        self.db.writer.executemany("DELETE FROM cache_entries WHERE sha256 = ?", [(s,) for s in victims])
        self.size_bytes -= freed
        self.entries -= len(victims)
        instruments.cache_evictions.add(len(victims), {"cache": "artifact"})
        log.info("evicted artifacts from cache", extra={"count": len(victims), "bytes": freed})
        return len(victims)

    def _move_to_trash(self, victims: list[str]) -> None:
        ts = int(time.time())
        for sha in victims:
            try:
                os.replace(self.object_path(sha), self.trash / f"{sha}.{ts}")
            except FileNotFoundError:
                continue

    def purge_trash(self) -> None:
        cutoff = time.time() - _TRASH_GRACE
        for path in self.trash.glob("*"):
            try:
                if path.stat().st_mtime < cutoff or int(path.suffix.lstrip(".") or 0) < cutoff:
                    path.unlink()
            except OSError, ValueError:
                continue

    def cleanup(self) -> None:
        """Startup housekeeping: drop stale tmp files and index rows whose object vanished."""
        if not self.enabled:
            return
        cutoff = time.time() - 3600
        for path in self.tmp.glob("*.part"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
            except OSError:
                continue
        missing = [
            (sha,)
            for (sha,) in self.db.readers.query("SELECT sha256 FROM cache_entries")
            if not self.object_path(sha).exists()
        ]
        if missing:
            self.db.writer.executemany("DELETE FROM cache_entries WHERE sha256 = ?", missing)
        self.purge_trash()

    async def scrub(self, *, budget_bytes: int = 2 << 30) -> list[str]:
        """Re-hash the least recently verified objects; corrupt ones are removed. Returns bad digests."""
        if not self.enabled:
            return []
        rows = await self.db.readers.aquery("SELECT sha256, size FROM cache_entries ORDER BY verified ASC LIMIT 1000")
        checked: list[str] = []
        bad: list[str] = []
        spent = 0
        for sha, size in rows:
            if spent >= budget_bytes:
                break
            spent += size
            ok = await asyncio.to_thread(self._verify_file, sha)
            if ok is None:
                continue
            (checked if ok else bad).append(sha)
        now = self.clock.now()
        if checked:
            self.db.writer.executemany(
                "UPDATE cache_entries SET verified = ? WHERE sha256 = ?", [(now, s) for s in checked]
            )
        if bad:
            log.error("artifact cache corruption detected; removing objects", extra={"digests": bad})
            await asyncio.to_thread(self._move_to_trash, bad)
            self.db.writer.executemany("DELETE FROM cache_entries WHERE sha256 = ?", [(s,) for s in bad])
        return bad

    def _verify_file(self, sha256: str) -> bool | None:
        path = self.object_path(sha256)
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while block := f.read(1 << 20):
                    h.update(block)
        except FileNotFoundError:
            return None
        return h.hexdigest() == sha256
