"""In-memory aggregation of stats and security events, flushed to SQLite every few seconds.

Request handlers only touch dictionaries; one flush turns thousands of requests into a handful of
upserts. Events repeated within a flush window (same type/package/version/client) collapse into one
row with a `count`, which keeps retry storms from flooding the table.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import msgspec

from slowshield.clock import Clock
from slowshield.db import Database
from slowshield.telemetry import instruments

log = logging.getLogger(__name__)

FIVE_MIN = 300
HOUR = 3600
DAY = 86400

EVENT_TYPES = ("blocked", "tampered", "integrity_mismatch", "fail_open", "age_gate")


@dataclass(slots=True)
class _Dl:
    serves: int = 0
    cache_hits: int = 0
    bytes: int = 0
    cache_bytes: int = 0
    leader_bytes: int = 0
    first: float = 0.0
    last: float = 0.0


class Batch(msgspec.Struct, forbid_unknown_fields=False):
    """One flush's statistics and events. Written locally; on a paired follower also queued in shieldwall_outbox, and
    the leader writes the same batch under the follower's instance ID (`write_batch`)."""

    five: list[tuple[int, str, str, str, int, int, int, int, int]] = []  # bucket, eco, package, version, serves,
    # cache hits, bytes, cache bytes, leader bytes
    decisions: list[tuple[int, str, str, str, int]] = []  # bucket, eco, kind, decision, count
    lookups: list[tuple[int, str, str, int]] = []  # bucket, eco, source, count
    events: list[tuple[float, str, str, str, str | None, str | None, int, str | None]] = []  # ts, type, eco,
    # package, version, client ip, count, details (JSON)
    packages: list[tuple[str, str, float, float, int, int, int]] = []  # eco, name, first, last, serves, hits, bytes
    versions: list[tuple[str, str, str, float, float, int, int]] = []  # eco, name, version, first, last, serves,
    # bytes
    # A backfill (a follower's history, sent once at pairing) carries every table's rows as they are: then
    # `derive` is off, and the hourly and daily rows aren't computed from the 5-minute ones.
    derive: bool = True
    hourly: list[tuple[int, str, str, str, int, int, int, int, int]] = []
    daily: list[tuple[int, str, str, str, int, int, int, int, int]] = []
    decisions_hourly: list[tuple[int, str, str, str, int]] = []
    lookups_hourly: list[tuple[int, str, str, int]] = []

    def empty(self) -> bool:
        return not (self.five or self.decisions or self.lookups or self.events)


@dataclass(slots=True)
class _Ev:
    ts: float
    count: int
    details: dict[str, Any] | None


class Recorder:
    def __init__(self, db: Database, clock: Clock, *, record_client_ip: bool = True) -> None:
        self.db = db
        self.clock = clock
        self.record_client_ip = record_client_ip
        self._downloads: dict[tuple[str, str, str, int], _Dl] = {}
        self._decisions: defaultdict[tuple[int, str, str, str], int] = defaultdict(int)
        self._lookups: defaultdict[tuple[int, str, str], int] = defaultdict(int)
        self._events: dict[tuple[str, str, str, str | None, str | None], _Ev] = {}
        self._seen: dict[tuple[str, str], float] = {}
        self._encoder = msgspec.json.Encoder()

    # ---- recording (called on the request path; must stay cheap) ---------------------------------

    def download(
        self,
        ecosystem: str,
        package: str,
        version: str | None,
        nbytes: int,
        *,
        cache_hit: bool,
        via_leader: bool = False,
    ) -> None:
        now = self.clock.now()
        key = (ecosystem, package, version or "", int(now // FIVE_MIN) * FIVE_MIN)
        d = self._downloads.get(key)
        if d is None:
            d = self._downloads[key] = _Dl(first=now)
        d.serves += 1
        d.cache_hits += int(cache_hit)
        d.bytes += nbytes
        d.cache_bytes += nbytes if cache_hit else 0
        d.leader_bytes += nbytes if via_leader else 0
        d.last = now
        source = "cache" if cache_hit else "leader" if via_leader else "upstream"
        instruments.artifact_bytes.add(nbytes, {"slowshield.ecosystem": ecosystem, "source": source})

    def decision(self, ecosystem: str, kind: str, decision: str, n: int = 1) -> None:
        now = self.clock.now()
        self._decisions[(int(now // FIVE_MIN) * FIVE_MIN, ecosystem, kind, decision)] += n
        instruments.decisions.add(
            n, {"slowshield.ecosystem": ecosystem, "slowshield.kind": kind, "slowshield.decision": decision}
        )

    def lookup(self, ecosystem: str, *, cached: bool) -> None:
        """A metadata request answered from the cache, or one that needed the upstream registry."""
        bucket = int(self.clock.now() // FIVE_MIN) * FIVE_MIN
        self._lookups[(bucket, ecosystem, "cache" if cached else "upstream")] += 1

    def event(
        self,
        type_: str,
        ecosystem: str,
        package: str,
        version: str | None = None,
        *,
        client_ip: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        ip = client_ip if self.record_client_ip else None
        key = (type_, ecosystem, package, version, ip)
        ev = self._events.get(key)
        if ev is None:
            self._events[key] = _Ev(self.clock.now(), 1, details)
        else:
            ev.count += 1
        instruments.security_events.add(1, {"slowshield.ecosystem": ecosystem, "slowshield.event": type_})
        level = logging.WARNING if type_ in {"blocked", "tampered", "integrity_mismatch"} else logging.INFO
        log.log(
            level,
            f"security event: {type_}",
            extra={"event": type_, "ecosystem": ecosystem, "package": package, "version": version, "client_ip": ip},
        )

    def catalog(self, ecosystem: str, name: str, versions: list[tuple[str, float | None, bool]] | None = None) -> None:
        """Record that metadata for `name` was fetched (and its versions' publish times, if new)."""
        now = self.clock.now()
        last = self._seen.get((ecosystem, name), 0.0)
        if versions is None and now - last < HOUR:
            return
        self._seen[(ecosystem, name)] = now
        if len(self._seen) > 200_000:
            self._seen.clear()

        def op(conn: Any) -> None:
            conn.execute(
                "INSERT INTO packages (ecosystem, name, first_seen, last_seen) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (ecosystem, name) DO UPDATE SET last_seen = excluded.last_seen",
                (ecosystem, name, now, now),
            )
            if versions:
                conn.executemany(
                    "INSERT INTO package_versions (ecosystem, name, version, published, yanked) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT (ecosystem, name, version) DO UPDATE SET "
                    "published = coalesce(excluded.published, published), yanked = excluded.yanked",
                    [(ecosystem, name, v, p, int(y)) for v, p, y in versions],
                )

        self.db.writer.enqueue(op)

    # ---- flushing --------------------------------------------------------------------------------

    def flush(self) -> None:
        downloads, self._downloads = self._downloads, {}
        decisions, self._decisions = self._decisions, defaultdict(int)
        lookups, self._lookups = self._lookups, defaultdict(int)
        events, self._events = self._events, {}
        if not (downloads or decisions or lookups or events):
            return
        enc = self._encoder
        pkg_rows: dict[tuple[str, str], _Dl] = {}
        ver_rows: dict[tuple[str, str, str], _Dl] = {}
        five = []
        for (eco, pkg, ver, bucket), d in downloads.items():
            five.append((bucket, eco, pkg, ver, d.serves, d.cache_hits, d.bytes, d.cache_bytes, d.leader_bytes))
            for agg in (
                pkg_rows.setdefault((eco, pkg), _Dl(first=d.first)),
                ver_rows.setdefault((eco, pkg, ver), _Dl(first=d.first)),
            ):
                agg.serves += d.serves
                agg.cache_hits += d.cache_hits
                agg.bytes += d.bytes
                agg.first = min(agg.first, d.first)
                agg.last = max(agg.last, d.last)
        batch = Batch(
            five=five,
            decisions=[(b, e, k, dec, n) for (b, e, k, dec), n in decisions.items()],
            lookups=[(b, e, src, n) for (b, e, src), n in lookups.items()],
            events=[
                (ev.ts, t, eco, pkg, ver, ip, ev.count, enc.encode(ev.details).decode() if ev.details else None)
                for (t, eco, pkg, ver, ip), ev in events.items()
            ],
            packages=[(e, p, d.first, d.last, d.serves, d.cache_hits, d.bytes) for (e, p), d in pkg_rows.items()],
            versions=[(e, p, v, d.first, d.last, d.serves, d.bytes) for (e, p, v), d in ver_rows.items()],
        )
        now = self.clock.now()

        def op(conn: Any) -> None:
            write_batch(conn, batch, instance="")
            # Decided inside the write: a follower's history snapshot at pairing and its outbox meet exactly, even
            # with several workers flushing.
            if conn.execute("SELECT 1 FROM shieldwall_leader WHERE state = 'active'").fetchone():
                conn.execute(
                    "INSERT INTO shieldwall_outbox (created, kind, body) VALUES (?, 'stats', ?)",
                    (now, msgspec.json.encode(batch).decode()),
                )

        self.db.writer.enqueue(op)

    async def run(self, interval: float = 5.0) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                self.flush()
            except Exception:  # pragma: no cover - never let the flusher die
                log.exception("stats flush failed")


def write_batch(conn: Any, batch: Batch, *, instance: str) -> None:
    """Add a batch to the statistics tables under `instance` ('' for this instance's own). Counts add up, so a
    batch must be written once: the leader's outbox high-water mark makes sure of that for followers."""
    upsert = (
        " (bucket, ecosystem, package, version, instance, serves, cache_hits, bytes, cache_bytes, leader_bytes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (bucket, ecosystem, package, version, instance) DO UPDATE SET serves = serves + excluded.serves, "
        "cache_hits = cache_hits + excluded.cache_hits, bytes = bytes + excluded.bytes, "
        "cache_bytes = cache_bytes + excluded.cache_bytes, leader_bytes = leader_bytes + excluded.leader_bytes"
    )
    five = [(b, e, p, v, instance, *n) for b, e, p, v, *n in batch.five]
    if batch.derive:
        hourly, daily = _rollup(five, HOUR, 4), _rollup(five, DAY, 4)
        decisions_hourly = None
        lookups_hourly = None
    else:
        hourly = [(b, e, p, v, instance, *n) for b, e, p, v, *n in batch.hourly]
        daily = [(b, e, p, v, instance, *n) for b, e, p, v, *n in batch.daily]
        decisions_hourly = [(b, e, k, d, instance, n) for b, e, k, d, n in batch.decisions_hourly]
        lookups_hourly = [(b, e, src, instance, n) for b, e, src, n in batch.lookups_hourly]
    for table, table_rows in (("downloads_5min", five), ("downloads_hourly", hourly), ("downloads_daily", daily)):
        if table_rows:
            conn.executemany(f"INSERT INTO {table}" + upsert, table_rows)
    if batch.packages:
        conn.executemany(
            "INSERT INTO packages (ecosystem, name, first_seen, last_seen, first_served, last_served, "
            "serves, cache_hits, bytes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (ecosystem, name) DO UPDATE SET "
            "last_seen = max(last_seen, excluded.last_seen), first_served = min(coalesce(first_served, "
            "excluded.first_served), excluded.first_served), "
            "last_served = max(coalesce(last_served, 0), excluded.last_served), serves = serves + excluded.serves, "
            "cache_hits = cache_hits + excluded.cache_hits, bytes = bytes + excluded.bytes",
            [(e, p, first, last, first, last, s, h, b) for e, p, first, last, s, h, b in batch.packages],
        )
    if batch.versions:
        conn.executemany(
            "INSERT INTO package_versions (ecosystem, name, version, first_served, last_served, serves, bytes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (ecosystem, name, version) DO UPDATE SET "
            "first_served = min(coalesce(first_served, excluded.first_served), excluded.first_served), "
            "last_served = max(coalesce(last_served, 0), excluded.last_served), "
            "serves = serves + excluded.serves, bytes = bytes + excluded.bytes",
            batch.versions,
        )
    if batch.decisions or decisions_hourly:
        rows = [(b, e, k, d, instance, n) for b, e, k, d, n in batch.decisions]
        hour_rows = _rollup(rows, HOUR, 4) if decisions_hourly is None else decisions_hourly
        for table, table_rows in (("decisions_5min", rows), ("decisions_hourly", hour_rows)):
            conn.executemany(
                f"INSERT INTO {table} (bucket, ecosystem, kind, decision, instance, count) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (bucket, ecosystem, kind, decision, instance) "
                "DO UPDATE SET count = count + excluded.count",
                table_rows,
            )
    if batch.lookups or lookups_hourly:
        rows = [(b, e, src, instance, n) for b, e, src, n in batch.lookups]
        hour_rows = _rollup(rows, HOUR, 3) if lookups_hourly is None else lookups_hourly
        for table, table_rows in (("lookups_5min", rows), ("lookups_hourly", hour_rows)):
            conn.executemany(
                f"INSERT INTO {table} (bucket, ecosystem, source, instance, count) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (bucket, ecosystem, source, instance) DO UPDATE SET count = count + excluded.count",
                table_rows,
            )
    if batch.events:
        conn.executemany(
            "INSERT INTO events (ts, type, ecosystem, package, version, client_ip, count, details, instance) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(*ev, instance) for ev in batch.events],
        )


def _rollup(rows: list[tuple[Any, ...]], step: int, keys: int) -> list[tuple[Any, ...]]:
    """Re-bucket (bucket, *keys, *counts) rows to a coarser step, summing the count columns."""
    acc: dict[tuple[Any, ...], list[int]] = {}
    for row in rows:
        counts = row[1 + keys :]
        cur = acc.setdefault((row[0] // step * step, *row[1 : 1 + keys]), [0] * len(counts))
        for i, n in enumerate(counts):
            cur[i] += n
    return [(*k, *v) for k, v in acc.items()]


def retention(conn: Any, now: float, *, event_days: float, stats_days: float, ip_days: float) -> None:
    conn.execute("DELETE FROM events WHERE ts < ?", (now - event_days * DAY,))
    conn.execute("UPDATE events SET client_ip = NULL WHERE client_ip IS NOT NULL AND ts < ?", (now - ip_days * DAY,))
    for table in ("downloads_5min", "decisions_5min", "lookups_5min"):
        conn.execute(f"DELETE FROM {table} WHERE bucket < ?", (now - 2 * DAY,))
    conn.execute("DELETE FROM downloads_hourly WHERE bucket < ?", (now - 15 * DAY,))
    conn.execute("DELETE FROM decisions_hourly WHERE bucket < ?", (now - stats_days * DAY,))
    conn.execute("DELETE FROM lookups_hourly WHERE bucket < ?", (now - stats_days * DAY,))
    conn.execute("DELETE FROM downloads_daily WHERE bucket < ?", (now - stats_days * DAY,))
