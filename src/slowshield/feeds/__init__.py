"""Threat feeds: status model, blocklist upserts and the scheduler (runs on the leader worker only)."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

from slowshield import versions
from slowshield.blocklist import bump_generation
from slowshield.telemetry import instruments

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class BlockSpec:
    ecosystem: str
    name: str
    version: str | None = None
    version_range: str | None = None

    def __post_init__(self) -> None:
        if self.ecosystem == "nuget" and self.version is not None:
            # NuGet keys are normalized versions: an advisory for 1.0 names 1.0.0 (docs/design/nuget.md).
            object.__setattr__(self, "version", versions.canonical("nuget", self.version))


@dataclass(slots=True)
class Advisory:
    source: str
    advisory_id: str
    specs: list[BlockSpec]
    reason: str | None
    url: str | None
    withdrawn: bool = False


@dataclass(slots=True)
class FeedStatus:
    name: str
    title: str
    requires_token: bool
    enabled: bool = False
    reason: str = "disabled"  # ok | disabled | missing_token | error
    last_attempt: float | None = None
    last_success: float | None = None
    last_error: str | None = None
    entries: int = 0
    running: bool = False
    fix: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class Feed(Protocol):
    name: str
    title: str
    requires_token: bool

    def configured(self) -> tuple[bool, str]:
        """(enabled, reason) from the current config/secrets."""
        ...

    async def sync(self) -> int:
        """Pull changes and apply them; returns the number of advisories changed."""
        ...


RETRY_FIRST_S = 60.0  # first retry after a failed sync; doubles up to the poll interval

GITHUB_FEED_FIX = (
    "Create a GitHub token (a fine-grained personal access token with no extra permissions is enough; "
    "it only reads the public advisory database) and pass it as GITHUB_TOKEN, or mount it as a file and set "
    "GITHUB_TOKEN_FILE (Docker/Podman/Kubernetes secret). Restart SlowShield afterwards."
)


def apply_advisories(conn: sqlite3.Connection, advisories: Iterable[Advisory], now: float) -> int:
    """Replace the blocklist rows of each advisory with its current specs. Returns rows changed."""
    changed = 0
    for adv in advisories:
        if adv.withdrawn:
            cur = conn.execute(
                "UPDATE blocklist SET withdrawn = ?, updated = ? WHERE source = ? AND advisory_id = ? AND withdrawn "
                "IS NULL",
                (now, now, adv.source, adv.advisory_id),
            )
            changed += cur.rowcount
            continue
        existing = {
            (r[1], r[2], r[3], r[4]): r[0]
            for r in conn.execute(
                "SELECT id, ecosystem, name, version, version_range FROM blocklist WHERE source = ? AND advisory_id "
                "= ?",
                (adv.source, adv.advisory_id),
            )
        }
        wanted = {(s.ecosystem, s.name, s.version, s.version_range) for s in adv.specs}
        stale = [rid for key, rid in existing.items() if key not in wanted]
        if stale:
            conn.executemany("DELETE FROM blocklist WHERE id = ?", [(r,) for r in stale])
            changed += len(stale)
        for eco, name, ver, rng in wanted:
            if (eco, name, ver, rng) in existing:
                conn.execute(
                    "UPDATE blocklist SET reason = ?, url = ?, updated = ?, withdrawn = NULL WHERE id = ?",
                    (adv.reason, adv.url, now, existing[(eco, name, ver, rng)]),
                )
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO blocklist (ecosystem, name, version, version_range, source, advisory_id, "
                "reason, url, "
                "first_seen, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (eco, name, ver, rng, adv.source, adv.advisory_id, adv.reason, adv.url, now, now),
            )
            changed += cur.rowcount
    if changed:
        bump_generation(conn)
    return changed


def save_state(conn: sqlite3.Connection, source: str, **fields: Any) -> None:
    cols = ", ".join(fields)
    placeholders = ", ".join("?" for _ in fields)
    updates = ", ".join(f"{k} = excluded.{k}" for k in fields)
    conn.execute(
        f"INSERT INTO feed_state (source, {cols}) VALUES (?, {placeholders}) "
        f"ON CONFLICT (source) DO UPDATE SET {updates}",
        (source, *fields.values()),
    )


def load_state(conn: sqlite3.Connection, source: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT watermark, etag, last_attempt, last_success, last_error, entries, details FROM feed_state WHERE "
        "source = ?",
        (source,),
    ).fetchone()
    if row is None:
        return {}
    keys = ("watermark", "etag", "last_attempt", "last_success", "last_error", "entries", "details")
    return dict(zip(keys, tuple(row), strict=True))


class FeedScheduler:
    def __init__(self, ctx: Any, feeds: list[Feed]) -> None:
        self.ctx = ctx
        self.feeds = feeds
        for f in feeds:
            ctx.feeds[f.name] = FeedStatus(name=f.name, title=f.title, requires_token=f.requires_token)
        self.refresh_status()
        self._register_metrics()

    def refresh_status(self) -> None:
        """Recompute enabled/reason from config and pull last-run info from the DB (any worker)."""
        for f in self.feeds:
            st: FeedStatus = self.ctx.feeds[f.name]
            enabled, reason = f.configured()
            st.enabled, st.reason = enabled, reason
            st.fix = GITHUB_FEED_FIX if reason == "missing_token" else None
            try:
                state = load_state(self.ctx.db.readers.get(), f.name)
            except sqlite3.Error:
                state = {}
            st.last_attempt = state.get("last_attempt")
            st.last_success = state.get("last_success")
            st.last_error = state.get("last_error")
            st.entries = state.get("entries") or 0
            if enabled and st.last_error and (st.last_success or 0) < (st.last_attempt or 0):
                st.reason = "error"

    def _register_metrics(self) -> None:
        self._counts: dict[tuple[str, str], int] = {}
        self.gauges: dict[str, instruments.GaugeCallback] = {
            "slowshield.feed.enabled": lambda: [
                (1.0 if st.enabled else 0.0, {"feed": st.name, "reason": st.reason}) for st in self.ctx.feeds.values()
            ],
            "slowshield.feed.last_success.timestamp": lambda: [
                (st.last_success, {"feed": st.name}) for st in self.ctx.feeds.values() if st.last_success
            ],
            "slowshield.blocklist.entries": lambda: [
                (float(n), {"source": src, "slowshield.ecosystem": eco}) for (src, eco), n in self._counts.items()
            ],
        }
        units = {"slowshield.feed.enabled": "1", "slowshield.feed.last_success.timestamp": "s"}
        for name, cb in self.gauges.items():
            instruments.observe(name, cb, unit=units.get(name, "{entry}"))

    def refresh_counts(self) -> None:
        try:
            self._counts = self.ctx.blocklist.counts()
        except sqlite3.Error:
            pass

    async def run_once(self) -> None:
        for f in self.feeds:
            st: FeedStatus = self.ctx.feeds[f.name]
            enabled, reason = f.configured()
            st.enabled, st.reason = enabled, reason
            if not enabled:
                continue
            st.running = True
            started = time.perf_counter()
            now = self.ctx.clock.now()
            try:
                changed = await f.sync()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                msg = f"{type(exc).__name__}: {exc}"[:500]
                log.error("feed sync failed", extra={"feed": f.name, "error": msg})
                instruments.feed_errors.add(1, {"feed": f.name})
                instruments.feed_sync_duration.record(
                    time.perf_counter() - started, {"feed": f.name, "outcome": "error"}
                )
                await self.ctx.db.writer.run(
                    lambda c, n=f.name, m=msg, t=now: save_state(c, n, last_attempt=t, last_error=m)
                )
                st.reason, st.last_error, st.last_attempt = "error", msg, now
            else:
                instruments.feed_sync_duration.record(time.perf_counter() - started, {"feed": f.name, "outcome": "ok"})
                if changed:
                    instruments.feed_changes.add(changed, {"feed": f.name})
                    log.info("feed applied changes", extra={"feed": f.name, "changed": changed})
                st.reason, st.last_error = "ok", None
            finally:
                st.running = False
            self.refresh_status()
        await asyncio.to_thread(self.refresh_counts)

    def next_delay(self, retry: float) -> tuple[float, float]:
        """Seconds until the next run, and the retry delay after that. A failed sync (say the registry was
        unreachable at startup) is retried after 1, 2, 4 ... minutes, up to the poll interval, instead of
        leaving the blocklist empty or stale for a whole interval."""
        interval = self.ctx.cfg.raw.feeds.poll_interval_minutes * 60
        if any(self.ctx.feeds[f.name].enabled and self.ctx.feeds[f.name].reason == "error" for f in self.feeds):
            return min(retry, interval), min(retry * 2, interval)
        return interval, RETRY_FIRST_S

    async def run_forever(self) -> None:
        retry = RETRY_FIRST_S
        while True:
            await self.run_once()
            delay, retry = self.next_delay(retry)
            await asyncio.sleep(delay)

    async def follow(self, interval: float = 30.0) -> None:
        """Non-leader workers: keep status (UI + gauges) fresh from the DB."""
        while True:
            await asyncio.sleep(interval)
            self.refresh_status()
            await asyncio.to_thread(self.refresh_counts)
