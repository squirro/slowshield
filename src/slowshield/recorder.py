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

HOUR = 3600
DAY = 86400

EVENT_TYPES = ("blocked", "tampered", "integrity_mismatch", "fail_open", "age_gate")


@dataclass(slots=True)
class _Dl:
    serves: int = 0
    cache_hits: int = 0
    bytes: int = 0
    first: float = 0.0
    last: float = 0.0


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
        self._events: dict[tuple[str, str, str, str | None, str | None], _Ev] = {}
        self._seen: dict[tuple[str, str], float] = {}
        self._encoder = msgspec.json.Encoder()

    # ---- recording (called on the request path; must stay cheap) ---------------------------------

    def download(self, ecosystem: str, package: str, version: str | None, nbytes: int, *, cache_hit: bool) -> None:
        now = self.clock.now()
        key = (ecosystem, package, version or "", int(now // HOUR) * HOUR)
        d = self._downloads.get(key)
        if d is None:
            d = self._downloads[key] = _Dl(first=now)
        d.serves += 1
        d.cache_hits += int(cache_hit)
        d.bytes += nbytes
        d.last = now
        instruments.artifact_bytes.add(
            nbytes, {"slowshield.ecosystem": ecosystem, "source": "cache" if cache_hit else "upstream"}
        )

    def decision(self, ecosystem: str, kind: str, decision: str, n: int = 1) -> None:
        now = self.clock.now()
        self._decisions[(int(now // HOUR) * HOUR, ecosystem, kind, decision)] += n
        instruments.decisions.add(
            n, {"slowshield.ecosystem": ecosystem, "slowshield.kind": kind, "slowshield.decision": decision}
        )

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
        events, self._events = self._events, {}
        if not (downloads or decisions or events):
            return
        enc = self._encoder

        hourly, daily = [], []
        pkg_rows: dict[tuple[str, str], _Dl] = {}
        ver_rows: dict[tuple[str, str, str], _Dl] = {}
        for (eco, pkg, ver, hour), d in downloads.items():
            hourly.append((hour, eco, pkg, ver, d.serves, d.cache_hits, d.bytes))
            daily.append((hour // DAY * DAY, eco, pkg, ver, d.serves, d.cache_hits, d.bytes))
            for agg in (
                pkg_rows.setdefault((eco, pkg), _Dl(first=d.first)),
                ver_rows.setdefault((eco, pkg, ver), _Dl(first=d.first)),
            ):
                agg.serves += d.serves
                agg.cache_hits += d.cache_hits
                agg.bytes += d.bytes
                agg.first = min(agg.first, d.first)
                agg.last = max(agg.last, d.last)
        dec_rows = [(b, e, k, dec, n) for (b, e, k, dec), n in decisions.items()]
        ev_rows = [
            (ev.ts, t, eco, pkg, ver, ip, ev.count, enc.encode(ev.details).decode() if ev.details else None)
            for (t, eco, pkg, ver, ip), ev in events.items()
        ]

        def op(conn: Any) -> None:
            upsert = (
                " (bucket, ecosystem, package, version, serves, cache_hits, bytes) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (bucket, ecosystem, package, version) DO UPDATE SET serves = serves + excluded.serves, "
                "cache_hits = cache_hits + excluded.cache_hits, bytes = bytes + excluded.bytes"
            )
            if hourly:
                conn.executemany("INSERT INTO downloads_hourly" + upsert, hourly)
                conn.executemany("INSERT INTO downloads_daily" + upsert, _merge(daily))
            if pkg_rows:
                conn.executemany(
                    "INSERT INTO packages (ecosystem, name, first_seen, last_seen, first_served, last_served, "
                    "serves, cache_hits, bytes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (ecosystem, name) DO UPDATE SET "
                    "last_seen = max(last_seen, excluded.last_seen), first_served = coalesce(first_served, "
                    "excluded.first_served), "
                    "last_served = excluded.last_served, serves = serves + excluded.serves, "
                    "cache_hits = cache_hits + excluded.cache_hits, bytes = bytes + excluded.bytes",
                    [
                        (e, p, d.first, d.last, d.first, d.last, d.serves, d.cache_hits, d.bytes)
                        for (e, p), d in pkg_rows.items()
                    ],
                )
                conn.executemany(
                    "INSERT INTO package_versions (ecosystem, name, version, first_served, last_served, serves, bytes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (ecosystem, name, version) DO UPDATE SET "
                    "first_served = coalesce(first_served, excluded.first_served), last_served = excluded.last_served, "
                    "serves = serves + excluded.serves, bytes = bytes + excluded.bytes",
                    [(e, p, v, d.first, d.last, d.serves, d.bytes) for (e, p, v), d in ver_rows.items()],
                )
            if dec_rows:
                conn.executemany(
                    "INSERT INTO decisions_hourly (bucket, ecosystem, kind, decision, count) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT (bucket, ecosystem, kind, decision) DO UPDATE SET count = count + excluded.count",
                    dec_rows,
                )
            if ev_rows:
                conn.executemany(
                    "INSERT INTO events (ts, type, ecosystem, package, version, client_ip, count, details) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ev_rows,
                )

        self.db.writer.enqueue(op)

    async def run(self, interval: float = 5.0) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                self.flush()
            except Exception:  # pragma: no cover - never let the flusher die
                log.exception("stats flush failed")


def _merge(rows: list[tuple[Any, ...]]) -> list[tuple[Any, ...]]:
    acc: dict[tuple[Any, ...], list[int]] = {}
    for b, e, p, v, s, c, n in rows:
        cur = acc.setdefault((b, e, p, v), [0, 0, 0])
        cur[0] += s
        cur[1] += c
        cur[2] += n
    return [(*k, *v) for k, v in acc.items()]


def retention(conn: Any, now: float, *, event_days: float, stats_days: float, ip_days: float) -> None:
    conn.execute("DELETE FROM events WHERE ts < ?", (now - event_days * DAY,))
    conn.execute("UPDATE events SET client_ip = NULL WHERE client_ip IS NOT NULL AND ts < ?", (now - ip_days * DAY,))
    conn.execute("DELETE FROM downloads_hourly WHERE bucket < ?", (now - 15 * DAY,))
    conn.execute("DELETE FROM decisions_hourly WHERE bucket < ?", (now - stats_days * DAY,))
    conn.execute("DELETE FROM downloads_daily WHERE bucket < ?", (now - stats_days * DAY,))
