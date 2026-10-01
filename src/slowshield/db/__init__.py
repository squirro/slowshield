"""SQLite storage: one database file, WAL mode, a single batched writer thread and per-thread readers."""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import queue
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from importlib import resources
from pathlib import Path
from typing import Any, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")
Op = Callable[[sqlite3.Connection], Any]

_PRAGMAS = (
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA busy_timeout=10000",
    "PRAGMA foreign_keys=ON",
    "PRAGMA temp_store=MEMORY",
    "PRAGMA mmap_size=268435456",
    "PRAGMA cache_size=-16000",
)


def connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        path,
        isolation_level=None,  # autocommit; transactions are explicit
        check_same_thread=False,
        timeout=10.0,
        cached_statements=256,
    )
    for pragma in _PRAGMAS:
        conn.execute(pragma)
    if readonly:
        conn.execute("PRAGMA query_only=1")
    return conn


def _migration_files() -> list[tuple[int, str, str]]:
    out = []
    pkg = resources.files("slowshield.db") / "migrations"
    for entry in pkg.iterdir():
        name = entry.name
        if not name.endswith(".sql"):
            continue
        num = int(name.split("_", 1)[0])
        out.append((num, name, entry.read_text(encoding="utf-8")))
    return sorted(out)


def migrate(path: Path) -> int:
    """Apply pending migrations (idempotent, safe to run concurrently). Returns the schema version."""
    conn = connect(path)
    try:
        conn.execute("BEGIN EXCLUSIVE")
        try:
            current = conn.execute("PRAGMA user_version").fetchone()[0]
            applied = current
            for num, name, sql in _migration_files():
                if num <= current:
                    continue
                log.info("applying migration", extra={"migration": name})
                # executescript() would COMMIT implicitly; split statements instead.
                for stmt in _split_sql(sql):
                    conn.execute(stmt)
                applied = num
            if applied != current:
                conn.execute(f"PRAGMA user_version={int(applied)}")
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        return applied
    finally:
        conn.close()


def _split_sql(sql: str) -> list[str]:
    statements: list[str] = []
    buf: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        buf.append(line)
        candidate = "\n".join(buf)
        if stripped.endswith(";") and sqlite3.complete_statement(candidate):
            statements.append(candidate)
            buf = []
    if buf and "\n".join(buf).strip():
        statements.append("\n".join(buf))
    return statements


class Writer:
    """Single writer thread. Operations are batched into one transaction (up to `batch` ops / `linger`).

    `submit()` returns a future for callers that need the result (e.g. TOFU inserts); fire-and-forget
    callers use `enqueue()`. A failing op is retried alone so one bad statement cannot drop a batch.
    """

    def __init__(self, path: Path, *, batch: int = 500, linger: float = 0.05) -> None:
        self._path = path
        self._batch = batch
        self._linger = linger
        self._q: queue.SimpleQueue[tuple[Op, concurrent.futures.Future[Any] | None] | None] = queue.SimpleQueue()
        self._thread = threading.Thread(target=self._run, name="slowshield-db-writer", daemon=True)
        self._started = False
        self._pending = 0
        self._lock = threading.Lock()
        self.last_flush_seconds = 0.0
        self.flushes = 0
        self.failures = 0

    @property
    def queue_depth(self) -> int:
        return self._pending

    def start(self) -> None:
        if not self._started:
            self._started = True
            self._thread.start()

    def enqueue(self, op: Op) -> None:
        with self._lock:
            self._pending += 1
        self._q.put((op, None))

    def submit(self, op: Callable[[sqlite3.Connection], T]) -> concurrent.futures.Future[T]:
        fut: concurrent.futures.Future[T] = concurrent.futures.Future()
        with self._lock:
            self._pending += 1
        self._q.put((op, fut))
        return fut

    async def run(self, op: Callable[[sqlite3.Connection], T]) -> T:
        return await asyncio.wrap_future(self.submit(op))

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        self.enqueue(lambda c: c.execute(sql, params))

    def executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        rows = list(rows)
        if rows:
            self.enqueue(lambda c: c.executemany(sql, rows))

    def stop(self, timeout: float = 10.0) -> None:
        if self._started:
            self._q.put(None)
            self._thread.join(timeout)
            self._started = False

    def _run(self) -> None:
        conn = connect(self._path)
        try:
            while True:
                item = self._q.get()
                if item is None:
                    return
                items = [item]
                deadline = time.monotonic() + self._linger
                stop = False
                while len(items) < self._batch:
                    remaining = deadline - time.monotonic()
                    try:
                        nxt = self._q.get(timeout=max(0.0, remaining)) if remaining > 0 else self._q.get_nowait()
                    except queue.Empty:
                        break
                    if nxt is None:
                        stop = True
                        break
                    items.append(nxt)
                self._flush(conn, items)
                if stop:
                    return
        finally:
            conn.close()

    def _flush(self, conn: sqlite3.Connection, items: list[tuple[Op, concurrent.futures.Future[Any] | None]]) -> None:
        started = time.perf_counter()
        results: list[tuple[concurrent.futures.Future[Any] | None, Any, BaseException | None]] = []
        try:
            conn.execute("BEGIN IMMEDIATE")
            for op, fut in items:
                results.append((fut, op(conn), None))
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            results = [self._run_one(conn, op, fut) for op, fut in items]
        finally:
            with self._lock:
                self._pending -= len(items)
        self.last_flush_seconds = time.perf_counter() - started
        self.flushes += 1
        for fut, value, exc in results:
            if fut is None:
                continue
            if exc is not None:
                fut.set_exception(exc)
            else:
                fut.set_result(value)

    def _run_one(
        self, conn: sqlite3.Connection, op: Op, fut: concurrent.futures.Future[Any] | None
    ) -> tuple[concurrent.futures.Future[Any] | None, Any, BaseException | None]:
        try:
            conn.execute("BEGIN IMMEDIATE")
            value = op(conn)
            conn.execute("COMMIT")
            return fut, value, None
        except Exception as exc:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self.failures += 1
            log.exception("database write failed")
            return fut, None, exc


class Readers:
    """Per-thread read-only connections (sqlite3 connections must not be shared across threads)."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._local = threading.local()
        self._all: list[sqlite3.Connection] = []
        self._lock = threading.Lock()

    def get(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = connect(self._path, readonly=True)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
            with self._lock:
                self._all.append(conn)
        return conn

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return self.get().execute(sql, params).fetchall()

    def one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        return self.get().execute(sql, params).fetchone()

    async def aquery(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return await asyncio.to_thread(self.query, sql, params)

    def close(self) -> None:
        with self._lock:
            for conn in self._all:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            self._all.clear()


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.writer = Writer(path)
        self.readers = Readers(path)

    def open(self) -> None:
        migrate(self.path)
        self.writer.start()

    def close(self) -> None:
        self.writer.stop()
        self.readers.close()

    def meta(self, key: str) -> str | None:
        row = self.readers.one("SELECT value FROM meta WHERE key = ?", (key,))
        return None if row is None else row[0]
