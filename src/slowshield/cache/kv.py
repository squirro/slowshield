"""Shared, size-bounded key/value cache in SQLite for upstream metadata and rendered responses.

One file for all workers (WAL: readers never block the writer), so a document one worker fetched is served by
every other worker and survives restarts. The bytes live in the file and the kernel's page cache, which the
kernel can reclaim under memory pressure, instead of in each worker's heap. Workers keep only parsed objects and
small bodies in their own (small) in-memory LRU in front of it.

It is a cache: every error degrades to a miss, and a corrupt or unreadable file is deleted and recreated.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS kv ("
    " key TEXT PRIMARY KEY,"
    " value BLOB NOT NULL,"
    " meta TEXT NOT NULL DEFAULT '{}',"
    " expires REAL NOT NULL,"  # fresh until
    " keep_until REAL NOT NULL,"  # kept for revalidation / stale-if-error until, then purged
    " accessed REAL NOT NULL,"
    " size INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS kv_accessed ON kv (accessed)",
    "CREATE INDEX IF NOT EXISTS kv_keep ON kv (keep_until)",
)
_PRAGMAS = (
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA busy_timeout=15000",  # large documents from several workers queue up; a miss is the fallback
    "PRAGMA temp_store=MEMORY",
    "PRAGMA cache_size=-2000",  # 2 MiB per connection: the OS page cache does the real caching
)
TOUCH_EVERY = 300.0  # reads refresh `accessed` at most this often, so a hit is not a write
EVICT_TO = 0.9  # evict down to this fraction of the limit


@dataclass(slots=True, frozen=True)
class Item:
    value: bytes
    meta: dict[str, Any]
    expires: float

    def fresh(self, now: float) -> bool:
        return self.expires > now


class KVStore:
    def __init__(self, path: Path, max_bytes: int, now: Callable[[], float]) -> None:
        self.path = path
        self.max_bytes = max(1, max_bytes)
        self._now = now
        self._local = threading.local()
        self._all: list[sqlite3.Connection] = []
        self._lock = threading.Lock()
        self._usage: tuple[float, int, int] = (0.0, 0, 0)  # (computed at, entries, bytes)

    # ---- connections --------------------------------------------------------------------------------

    def open(self) -> None:
        """Create the file and schema; recreate it if it is corrupt or not a database."""
        try:
            self._create()
        except sqlite3.DatabaseError as exc:
            log.warning("metadata cache unreadable, recreating it", extra={"path": str(self.path), "error": str(exc)})
            self.close()
            for suffix in ("", "-wal", "-shm"):
                Path(f"{self.path}{suffix}").unlink(missing_ok=True)
            self._create()

    def _create(self) -> None:
        conn = self._conn()
        if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise sqlite3.DatabaseError("quick_check failed")
        for stmt in _SCHEMA:
            conn.execute(stmt)

    def _conn(self) -> sqlite3.Connection:
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False, timeout=15.0)
            for pragma in _PRAGMAS:
                conn.execute(pragma)
            self._local.conn = conn
            with self._lock:
                self._all.append(conn)
        return conn

    def close(self) -> None:
        with self._lock:
            for conn in self._all:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            self._all.clear()
        self._local = threading.local()

    # ---- operations (blocking; use the a* variants from the event loop) ---------------------------------

    def get(self, key: str) -> Item | None:
        try:
            conn = self._conn()
            row = conn.execute("SELECT value, meta, expires, accessed FROM kv WHERE key = ?", (key,)).fetchone()
            if row is None:
                return None
            now = self._now()
            if now - row[3] > TOUCH_EVERY:
                conn.execute("UPDATE kv SET accessed = ? WHERE key = ?", (now, key))
            return Item(bytes(row[0]), json.loads(row[1]), row[2])
        except (sqlite3.Error, ValueError) as exc:
            log.warning("metadata cache read failed", extra={"key": key, "error": str(exc)})
            return None

    def put(self, key: str, value: bytes, *, expires: float, keep_until: float | None = None, meta: Any = None) -> None:
        now = self._now()
        keep = max(expires, keep_until or 0.0)
        try:
            self._conn().execute(
                "INSERT OR REPLACE INTO kv (key, value, meta, expires, keep_until, accessed, size)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (key, value, json.dumps(meta or {}), expires, keep, now, len(value) + len(key)),
            )
        except sqlite3.Error as exc:
            log.warning("metadata cache write failed", extra={"key": key, "error": str(exc)})

    def touch(self, key: str, expires: float, keep_until: float | None = None) -> None:
        try:
            self._conn().execute(
                "UPDATE kv SET expires = ?, keep_until = max(keep_until, ?), accessed = ? WHERE key = ?",
                (expires, max(expires, keep_until or 0.0), self._now(), key),
            )
        except sqlite3.Error as exc:
            log.warning("metadata cache write failed", extra={"key": key, "error": str(exc)})

    def delete(self, key: str) -> None:
        try:
            self._conn().execute("DELETE FROM kv WHERE key = ?", (key,))
        except sqlite3.Error as exc:
            log.warning("metadata cache write failed", extra={"key": key, "error": str(exc)})

    def usage(self, max_age: float = 0.0) -> tuple[int, int]:
        """(entries, bytes); with max_age, a value computed less than max_age seconds ago is reused."""
        at, entries, size = self._usage
        now = self._now()
        if max_age and now - at < max_age:
            return entries, size
        try:
            row = self._conn().execute("SELECT count(*), total(size) FROM kv").fetchone()
        except sqlite3.Error:
            return entries, size
        self._usage = (now, int(row[0]), int(row[1]))
        return self._usage[1], self._usage[2]

    def evict(self) -> int:
        """Drop entries past their keep time, then least recently used ones until under the limit."""
        now = self._now()
        conn = self._conn()
        removed = conn.execute("DELETE FROM kv WHERE keep_until <= ?", (now,)).rowcount
        _, size = self.usage()
        target = int(self.max_bytes * EVICT_TO)
        while size > self.max_bytes:
            rows = conn.execute("SELECT key, size FROM kv ORDER BY accessed LIMIT 200").fetchall()
            if not rows:
                break
            batch: list[str] = []
            for key, entry_size in rows:
                batch.append(key)
                size -= entry_size
                if size <= target:
                    break
            conn.executemany("DELETE FROM kv WHERE key = ?", [(k,) for k in batch])
            removed += len(batch)
        if removed:
            conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        self.usage()
        return removed

    # ---- async wrappers -------------------------------------------------------------------------------

    async def aget(self, key: str) -> Item | None:
        return await asyncio.to_thread(self.get, key)

    async def aput(
        self, key: str, value: bytes, *, expires: float, keep_until: float | None = None, meta: Any = None
    ) -> None:
        await asyncio.to_thread(lambda: self.put(key, value, expires=expires, keep_until=keep_until, meta=meta))

    async def atouch(self, key: str, expires: float, keep_until: float | None = None) -> None:
        await asyncio.to_thread(self.touch, key, expires, keep_until)

    async def aevict(self) -> int:
        return await asyncio.to_thread(self.evict)
