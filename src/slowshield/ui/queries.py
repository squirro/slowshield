"""Read-only SQL for the UI. All functions are synchronous and run in a worker thread."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

HOUR = 3600
DAY = 86400

RANGES: dict[str, tuple[int, str]] = {
    "24h": (DAY, "hourly"),
    "7d": (7 * DAY, "daily"),
    "30d": (30 * DAY, "daily"),
    "90d": (90 * DAY, "daily"),
    "365d": (365 * DAY, "daily"),
}
DEFAULT_RANGE = "7d"


@dataclass(frozen=True, slots=True)
class Window:
    key: str
    seconds: int
    granularity: str  # hourly | daily
    start: int
    end: int

    @property
    def step(self) -> int:
        return HOUR if self.granularity == "hourly" else DAY

    @property
    def table(self) -> str:
        return "downloads_hourly" if self.granularity == "hourly" else "downloads_daily"

    @property
    def previous(self) -> Window:
        return Window(self.key, self.seconds, self.granularity, self.start - self.seconds, self.start)

    def buckets(self) -> list[int]:
        first = self.start // self.step * self.step
        return list(range(first, self.end + 1, self.step))


def window(key: str | None, now: float) -> Window:
    k = key if key in RANGES else DEFAULT_RANGE
    seconds, gran = RANGES[k]
    end = int(now)
    step = HOUR if gran == "hourly" else DAY
    start = (end - seconds) // step * step + step
    return Window(k, seconds, gran, start, end)


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    return conn.execute(sql, params).fetchall()


def _eco_clause(eco: str | None, col: str = "ecosystem") -> tuple[str, tuple[Any, ...]]:
    if eco in ("pypi", "npm"):
        return f" AND {col} = ?", (eco,)
    return "", ()


# ---- dashboard ----------------------------------------------------------------------------------


def kpis(conn: sqlite3.Connection, w: Window, eco: str | None = None) -> dict[str, Any]:
    ec, ep = _eco_clause(eco)

    def downloads(win: Window) -> sqlite3.Row:
        return conn.execute(
            f"SELECT coalesce(sum(serves),0) s, coalesce(sum(cache_hits),0) h, coalesce(sum(bytes),0) b, "
            f"count(DISTINCT ecosystem || ':' || package) p FROM {win.table} WHERE bucket >= ? AND bucket < ?{ec}",
            (win.start, win.end + 1, *ep),
        ).fetchone()

    def decisions(win: Window) -> dict[str, int]:
        rows = _rows(
            conn,
            f"SELECT decision, sum(count) FROM decisions_hourly WHERE bucket >= ? AND bucket < ?{ec} GROUP BY decision",
            (win.start, win.end + 1, *ep),
        )
        return {r[0]: int(r[1]) for r in rows}

    cur, prev = downloads(w), downloads(w.previous)
    dcur, dprev = decisions(w), decisions(w.previous)
    new_deps = conn.execute(f"SELECT count(*) FROM packages WHERE first_served >= ?{ec}", (w.start, *ep)).fetchone()[0]
    new_prev = conn.execute(
        f"SELECT count(*) FROM packages WHERE first_served >= ? AND first_served < ?{ec}",
        (w.previous.start, w.start, *ep),
    ).fetchone()[0]

    def pair(a: float, b: float) -> dict[str, float | None]:
        return {"value": a, "previous": b, "delta": None if not b else (a - b) / b}

    return {
        "installs": pair(cur["s"], prev["s"]),
        "bytes": pair(cur["b"], prev["b"]),
        "packages": pair(cur["p"], prev["p"]),
        "hit_ratio": pair(cur["h"] / cur["s"] if cur["s"] else 0.0, prev["h"] / prev["s"] if prev["s"] else 0.0),
        "age_gated": pair(dcur.get("age_gated", 0), dprev.get("age_gated", 0)),
        "blocked": pair(dcur.get("blocked", 0), dprev.get("blocked", 0)),
        "tampered": pair(
            dcur.get("tampered", 0) + dcur.get("integrity_mismatch", 0),
            dprev.get("tampered", 0) + dprev.get("integrity_mismatch", 0),
        ),
        "fail_open": pair(dcur.get("fail_open", 0), dprev.get("fail_open", 0)),
        "new_deps": pair(new_deps, new_prev),
    }


def series_downloads(conn: sqlite3.Connection, w: Window, eco: str | None = None) -> dict[str, dict[int, int]]:
    ec, ep = _eco_clause(eco)
    out: dict[str, dict[int, int]] = {"pypi": {}, "npm": {}}
    for bucket, ecosystem, serves in _rows(
        conn,
        f"SELECT bucket, ecosystem, sum(serves) FROM {w.table} WHERE bucket >= ? AND bucket < ?{ec} "
        "GROUP BY bucket, ecosystem",
        (w.start, w.end + 1, *ep),
    ):
        out.setdefault(ecosystem, {})[int(bucket)] = int(serves)
    return out


def series_decisions(conn: sqlite3.Connection, w: Window, eco: str | None = None) -> dict[str, dict[int, int]]:
    ec, ep = _eco_clause(eco)
    out: dict[str, dict[int, int]] = {}
    for bucket, decision, n in _rows(
        conn,
        f"SELECT bucket / ? * ? b, decision, sum(count) FROM decisions_hourly WHERE bucket >= ? AND bucket < ?{ec} "
        "GROUP BY b, decision",
        (w.step, w.step, w.start, w.end + 1, *ep),
    ):
        out.setdefault(decision, {})[int(bucket)] = int(n)
    return out


def top_packages(
    conn: sqlite3.Connection, w: Window, *, eco: str | None = None, by: str = "serves", limit: int = 10
) -> list[sqlite3.Row]:
    order = "b" if by == "bytes" else "s"
    ec, ep = _eco_clause(eco)
    return _rows(
        conn,
        f"SELECT ecosystem, package, sum(serves) s, sum(bytes) b, sum(cache_hits) h, count(DISTINCT version) v "
        f"FROM {w.table} WHERE bucket >= ? AND bucket < ?{ec} GROUP BY ecosystem, package ORDER BY {order} DESC LIMIT ?",
        (w.start, w.end + 1, *ep, limit),
    )


def recent_events(conn: sqlite3.Connection, limit: int = 10, types: tuple[str, ...] | None = None) -> list[sqlite3.Row]:
    if types:
        marks = ",".join("?" for _ in types)
        return _rows(
            conn,
            f"SELECT * FROM events WHERE type IN ({marks}) ORDER BY ts DESC LIMIT ?",
            (*types, limit),
        )
    return _rows(conn, "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))


def totals(conn: sqlite3.Connection) -> dict[str, int]:
    row = conn.execute(
        "SELECT (SELECT count(*) FROM packages), (SELECT count(*) FROM package_versions), "
        "(SELECT count(*) FROM blocklist WHERE withdrawn IS NULL), (SELECT count(*) FROM artifacts), "
        "(SELECT count(*) FROM artifacts WHERE tampered = 1)"
    ).fetchone()
    return {"packages": row[0], "versions": row[1], "blocklist": row[2], "artifacts": row[3], "tampered": row[4]}


# ---- packages -----------------------------------------------------------------------------------

PACKAGE_SORTS = {
    "serves": "s DESC",
    "bytes": "b DESC",
    "name": "p.name ASC",
    "recent": "p.last_served DESC",
    "new": "p.first_served DESC",
    "seen": "p.last_seen DESC",
}


def package_page(
    conn: sqlite3.Connection,
    w: Window,
    *,
    q: str = "",
    eco: str | None = None,
    sort: str = "serves",
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[sqlite3.Row], int]:
    where = ["1=1"]
    params: list[Any] = []
    if eco in ("pypi", "npm"):
        where.append("p.ecosystem = ?")
        params.append(eco)
    if q:
        where.append("p.name LIKE ? ESCAPE '\\'")
        params.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    order = PACKAGE_SORTS.get(sort, PACKAGE_SORTS["serves"])
    sql = (
        "SELECT p.ecosystem, p.name, p.first_seen, p.last_seen, p.first_served, p.last_served, p.serves total, "
        "coalesce(d.s, 0) s, coalesce(d.b, 0) b, coalesce(d.v, 0) v "
        f"FROM packages p LEFT JOIN (SELECT ecosystem, package, sum(serves) s, sum(bytes) b, count(DISTINCT version) v "
        f"FROM {w.table} WHERE bucket >= ? AND bucket < ? GROUP BY ecosystem, package) d "
        "ON d.ecosystem = p.ecosystem AND d.package = p.name "
        f"WHERE {' AND '.join(where)} ORDER BY {order}, p.name ASC LIMIT ? OFFSET ?"
    )
    rows = _rows(conn, sql, (w.start, w.end + 1, *params, per_page + 1, (page - 1) * per_page))
    total = conn.execute(f"SELECT count(*) FROM packages p WHERE {' AND '.join(where)}", tuple(params)).fetchone()[0]
    return rows, total


def sparklines(
    conn: sqlite3.Connection, keys: list[tuple[str, str]], w: Window
) -> dict[tuple[str, str], dict[int, int]]:
    if not keys:
        return {}
    out: dict[tuple[str, str], dict[int, int]] = {k: {} for k in keys}
    pairs = " OR ".join("(ecosystem = ? AND package = ?)" for _ in keys)
    flat = [x for k in keys for x in k]
    for eco, pkg, bucket, s in _rows(
        conn,
        f"SELECT ecosystem, package, bucket, sum(serves) FROM {w.table} WHERE bucket >= ? AND bucket < ? AND ({pairs}) "
        "GROUP BY ecosystem, package, bucket",
        (w.start, w.end + 1, *flat),
    ):
        out[(eco, pkg)][int(bucket)] = int(s)
    return out


def package(conn: sqlite3.Connection, eco: str, name: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM packages WHERE ecosystem = ? AND name = ?", (eco, name)).fetchone()


def package_versions(conn: sqlite3.Connection, eco: str, name: str) -> list[sqlite3.Row]:
    return _rows(
        conn,
        "SELECT v.*, (SELECT max(tampered) FROM artifacts a WHERE a.ecosystem = v.ecosystem AND a.package = v.name "
        "AND a.version = v.version) tampered FROM package_versions v WHERE ecosystem = ? AND name = ? "
        "ORDER BY coalesce(published, 0) DESC",
        (eco, name),
    )


def package_series(conn: sqlite3.Connection, eco: str, name: str, w: Window) -> dict[int, int]:
    return {
        int(b): int(s)
        for b, s in _rows(
            conn,
            f"SELECT bucket, sum(serves) FROM {w.table} WHERE ecosystem = ? AND package = ? AND bucket >= ? AND bucket < ? "
            "GROUP BY bucket",
            (eco, name, w.start, w.end + 1),
        )
    }


def package_events(conn: sqlite3.Connection, eco: str, name: str, limit: int = 100) -> list[sqlite3.Row]:
    return _rows(
        conn, "SELECT * FROM events WHERE ecosystem = ? AND package = ? ORDER BY ts DESC LIMIT ?", (eco, name, limit)
    )


def package_blocks(conn: sqlite3.Connection, eco: str, name: str) -> list[sqlite3.Row]:
    return _rows(
        conn,
        "SELECT * FROM blocklist WHERE ecosystem = ? AND name = ? ORDER BY withdrawn IS NOT NULL, first_seen DESC",
        (eco, name),
    )


# ---- leaderboards -------------------------------------------------------------------------------


def trending(conn: sqlite3.Connection, w: Window, *, eco: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
    cur = {(r[0], r[1]): r[2] for r in top_packages(conn, w, eco=eco, limit=500)}
    prev = {(r[0], r[1]): r[2] for r in top_packages(conn, w.previous, eco=eco, limit=2000)}
    rows = []
    for key, s in cur.items():
        p = prev.get(key, 0)
        if s < 5:
            continue
        growth = (s - p) / p if p else float("inf")
        rows.append({"ecosystem": key[0], "package": key[1], "serves": s, "previous": p, "growth": growth})
    rows.sort(key=lambda r: (r["growth"], r["serves"]), reverse=True)
    return rows[:limit]


def event_leaders(
    conn: sqlite3.Connection, w: Window, type_: str, *, eco: str | None = None, limit: int = 10
) -> list[sqlite3.Row]:
    ec, ep = _eco_clause(eco)
    return _rows(
        conn,
        f"SELECT ecosystem, package, sum(count) n, count(DISTINCT version) v, count(DISTINCT client_ip) clients, max(ts) last "
        f"FROM events WHERE type = ? AND ts >= ?{ec} GROUP BY ecosystem, package ORDER BY n DESC LIMIT ?",
        (type_, w.start, *ep, limit),
    )


def new_dependencies(
    conn: sqlite3.Connection, w: Window, *, eco: str | None = None, limit: int = 25
) -> list[sqlite3.Row]:
    ec, ep = _eco_clause(eco)
    return _rows(
        conn,
        f"SELECT ecosystem, name, first_served, serves, bytes FROM packages WHERE first_served >= ?{ec} "
        "ORDER BY first_served DESC LIMIT ?",
        (w.start, *ep, limit),
    )


# ---- security & blocklist -------------------------------------------------------------------------


def events_page(
    conn: sqlite3.Connection,
    w: Window,
    *,
    type_: str | None = None,
    eco: str | None = None,
    q: str = "",
    ip: str = "",
    page: int = 1,
    per_page: int = 50,
) -> list[sqlite3.Row]:
    where = ["ts >= ?"]
    params: list[Any] = [w.start]
    if type_:
        where.append("type = ?")
        params.append(type_)
    if eco in ("pypi", "npm"):
        where.append("ecosystem = ?")
        params.append(eco)
    if q:
        where.append("package LIKE ? ESCAPE '\\'")
        params.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if ip:
        where.append("client_ip = ?")
        params.append(ip)
    return _rows(
        conn,
        f"SELECT * FROM events WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT ? OFFSET ?",
        (*params, per_page + 1, (page - 1) * per_page),
    )


def event_counts(conn: sqlite3.Connection, w: Window) -> dict[str, int]:
    return {
        r[0]: int(r[1])
        for r in _rows(conn, "SELECT type, sum(count) FROM events WHERE ts >= ? GROUP BY type", (w.start,))
    }


def blocklist_page(
    conn: sqlite3.Connection,
    *,
    q: str = "",
    eco: str | None = None,
    source: str | None = None,
    scope: str | None = None,
    page: int = 1,
    per_page: int = 50,
) -> list[sqlite3.Row]:
    where = ["withdrawn IS NULL"]
    params: list[Any] = []
    if q:
        where.append("name LIKE ? ESCAPE '\\'")
        params.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if eco in ("pypi", "npm"):
        where.append("ecosystem = ?")
        params.append(eco)
    if source in ("osv", "github"):
        where.append("source = ?")
        params.append(source)
    if scope == "package":
        where.append("version IS NULL AND version_range IS NULL")
    elif scope == "version":
        where.append("(version IS NOT NULL OR version_range IS NOT NULL)")
    return _rows(
        conn,
        f"SELECT * FROM blocklist WHERE {' AND '.join(where)} ORDER BY first_seen DESC, id DESC LIMIT ? OFFSET ?",
        (*params, per_page + 1, (page - 1) * per_page),
    )


def blocklist_counts(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return _rows(
        conn,
        "SELECT source, ecosystem, count(*) n, sum(version IS NULL AND version_range IS NULL) pkg, max(first_seen) newest "
        "FROM blocklist WHERE withdrawn IS NULL GROUP BY source, ecosystem ORDER BY source, ecosystem",
    )


def feed_states(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return _rows(conn, "SELECT * FROM feed_state ORDER BY source")
