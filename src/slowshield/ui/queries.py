"""Read-only SQL for the UI. All functions are synchronous and run in a worker thread."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from slowshield.ecosystems import ECOSYSTEMS

FIVE_MIN = 300
HOUR = 3600
DAY = 86400
STEP = {"5min": FIVE_MIN, "hourly": HOUR, "daily": DAY}
# Table names are the only interpolated SQL identifiers; they come from these fixed maps, never from input
# (everything else is a bound parameter). Decisions and lookups have no daily rollup: daily windows sum hourly.
_DOWNLOADS = {"5min": "downloads_5min", "hourly": "downloads_hourly", "daily": "downloads_daily"}
_DECISIONS = {"5min": "decisions_5min", "hourly": "decisions_hourly", "daily": "decisions_hourly"}
_LOOKUPS = {"5min": "lookups_5min", "hourly": "lookups_hourly", "daily": "lookups_hourly"}

RANGES: dict[str, tuple[int, str]] = {
    "1h": (HOUR, "5min"),
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
    granularity: str  # 5min | hourly | daily
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.granularity not in STEP:
            raise ValueError(f"unknown granularity {self.granularity!r}")

    @property
    def step(self) -> int:
        return STEP[self.granularity]

    @property
    def table(self) -> str:
        return _DOWNLOADS[self.granularity]

    @property
    def decisions_table(self) -> str:
        return _DECISIONS[self.granularity]

    @property
    def lookups_table(self) -> str:
        return _LOOKUPS[self.granularity]

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
    step = STEP[gran]
    start = (end - seconds) // step * step + step
    return Window(k, seconds, gran, start, end)


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    return conn.execute(sql, params).fetchall()


def _eco_clause(
    eco: str | None, col: str = "ecosystem", inst: tuple[str, ...] | None = None
) -> tuple[str, tuple[Any, ...]]:
    """`AND` conditions for an ecosystem and, on a shield wall's leader, a set of instances ('' is the leader)."""
    sql, params = "", ()
    if eco in ECOSYSTEMS:
        sql, params = f" AND {col} = ?", (eco,)
    if inst is not None:
        marks = ",".join("?" for _ in inst) or "NULL"
        sql, params = f"{sql} AND instance IN ({marks})", (*params, *inst)
    return sql, params


def scope_instances(conn: sqlite3.Connection, selector: str, own_location: str) -> tuple[str, ...] | None:
    """The instances a leader's page covers: everything (None), this instance (`self`), one follower (its ID), a
    location (`loc:<location>`) or a label (`label:<key>=<value>`)."""
    if not selector:
        return None
    if selector == "self":
        return ("",)
    if selector.startswith("loc:"):
        loc = selector[4:]
        ids = [r[0] for r in conn.execute("SELECT id FROM shieldwall_members WHERE location = ?", (loc,))]
        return (*([""] if loc and loc == own_location else []), *ids)
    if selector.startswith("label:"):
        key, _, value = selector[6:].partition("=")
        return tuple(
            r[0] for r in conn.execute("SELECT id, labels FROM shieldwall_members") if _label(r[1], key) == value
        )
    return tuple(r[0] for r in conn.execute("SELECT id FROM shieldwall_members WHERE id = ?", (selector,)))


def _label(raw: str, key: str) -> str | None:
    try:
        labels = json.loads(raw)
    except ValueError:
        return None
    value = labels.get(key) if isinstance(labels, dict) else None
    return value if isinstance(value, str) else None


def shieldwall_members(conn: sqlite3.Connection, now: float) -> list[dict[str, Any]]:
    """A leader's followers, with what they served in the last 24 hours."""
    served = {
        r[0]: (int(r[1]), int(r[2]))
        for r in conn.execute(
            "SELECT instance, sum(serves), sum(bytes) FROM downloads_hourly WHERE bucket >= ? GROUP BY instance",
            (now - DAY,),
        )
    }
    out = []
    for r in _rows(conn, "SELECT * FROM shieldwall_members ORDER BY state, location, name"):
        try:
            status = json.loads(r["status"]) if r["status"] else {}
            labels = json.loads(r["labels"]) if r["labels"] else {}
        except ValueError:
            status, labels = {}, {}
        s, b = served.get(r["id"], (0, 0))
        out.append({**dict(r), "labels": labels, "status": status, "serves": s, "bytes": b})
    return out


def shieldwall_choices(conn: sqlite3.Connection) -> dict[str, list[tuple[str, str]]]:
    """What a leader's pages can be narrowed to: followers, locations, labels."""
    members = _rows(conn, "SELECT id, name, location, labels FROM shieldwall_members ORDER BY name")
    locations = sorted({m["location"] for m in members if m["location"]})
    labels: set[str] = set()
    for m in members:
        try:
            raw = json.loads(m["labels"] or "{}")
        except ValueError:
            continue
        labels.update(f"{k}={v}" for k, v in raw.items() if isinstance(v, str))
    return {
        "members": [(m["id"], m["name"]) for m in members],
        "locations": [(f"loc:{loc}", loc) for loc in locations],
        "labels": [(f"label:{kv}", kv) for kv in sorted(labels)],
    }


def shieldwall_follower(conn: sqlite3.Connection) -> dict[str, Any]:
    leader = conn.execute("SELECT * FROM shieldwall_leader WHERE id = 1").fetchone()
    error = conn.execute("SELECT value FROM meta WHERE key = 'shieldwall_error'").fetchone()
    return {
        "leader": dict(leader) if leader else None,
        "error": error[0] if error and not leader else None,
        "pending": _rows(conn, "SELECT kind, key, due FROM shieldwall_pending ORDER BY due"),
        "outbox": conn.execute("SELECT count(*), min(created) FROM shieldwall_outbox").fetchone(),
        "leader_blocks": conn.execute(
            "SELECT count(*) FROM blocklist WHERE source = 'leader' AND withdrawn IS NULL"
        ).fetchone()[0],
    }


# ---- dashboard ----------------------------------------------------------------------------------


def kpis(
    conn: sqlite3.Connection, w: Window, eco: str | None = None, inst: tuple[str, ...] | None = None
) -> dict[str, Any]:
    ec, ep = _eco_clause(eco, inst=inst)
    pc, pp = _eco_clause(eco)  # the package catalogue is the wall's, not per instance

    def downloads(win: Window) -> sqlite3.Row:
        return conn.execute(
            f"SELECT coalesce(sum(serves),0) s, coalesce(sum(cache_hits),0) h, coalesce(sum(bytes),0) b, "
            f"coalesce(sum(cache_bytes),0) cb, count(DISTINCT ecosystem || ':' || package) p "
            f"FROM {win.table} WHERE bucket >= ? AND bucket < ?{ec}",
            (win.start, win.end + 1, *ep),
        ).fetchone()

    def decisions(win: Window) -> dict[str, int]:
        rows = _rows(
            conn,
            f"SELECT decision, sum(count) FROM {win.decisions_table} WHERE bucket >= ? AND bucket < ?{ec} "
            "GROUP BY decision",
            (win.start, win.end + 1, *ep),
        )
        return {r[0]: int(r[1]) for r in rows}

    def lookups_from_cache(win: Window) -> int:
        return conn.execute(
            f"SELECT coalesce(sum(count),0) FROM {win.lookups_table} WHERE source = 'cache' AND bucket >= ? "
            f"AND bucket < ?{ec}",
            (win.start, win.end + 1, *ep),
        ).fetchone()[0]

    cur, prev = downloads(w), downloads(w.previous)
    dcur, dprev = decisions(w), decisions(w.previous)
    lcur, lprev = lookups_from_cache(w), lookups_from_cache(w.previous)
    new_deps = conn.execute(f"SELECT count(*) FROM packages WHERE first_served >= ?{pc}", (w.start, *pp)).fetchone()[0]
    new_prev = conn.execute(
        f"SELECT count(*) FROM packages WHERE first_served >= ? AND first_served < ?{pc}",
        (w.previous.start, w.start, *pp),
    ).fetchone()[0]

    def pair(a: float, b: float) -> dict[str, float | None]:
        return {"value": a, "previous": b, "delta": None if not b else (a - b) / b}

    return {
        "installs": pair(cur["s"], prev["s"]),
        "bytes": pair(cur["b"], prev["b"]),
        # Kept off the upstream registries: artifact bytes served from the verified cache, and requests
        # (artifact downloads + metadata lookups) answered without contacting the registry.
        "upstream_saved": pair(cur["cb"], prev["cb"]),
        "upstream_fetched": pair(cur["b"] - cur["cb"], prev["b"] - prev["cb"]),
        "upstream_requests_saved": pair(cur["h"] + lcur, prev["h"] + lprev),
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


def series_downloads(
    conn: sqlite3.Connection, w: Window, eco: str | None = None, inst: tuple[str, ...] | None = None
) -> dict[str, dict[int, int]]:
    ec, ep = _eco_clause(eco, inst=inst)
    out: dict[str, dict[int, int]] = {e: {} for e in ECOSYSTEMS}
    for bucket, ecosystem, serves in _rows(
        conn,
        f"SELECT bucket, ecosystem, sum(serves) FROM {w.table} WHERE bucket >= ? AND bucket < ?{ec} "
        "GROUP BY bucket, ecosystem",
        (w.start, w.end + 1, *ep),
    ):
        out.setdefault(ecosystem, {})[int(bucket)] = int(serves)
    return out


def series_decisions(
    conn: sqlite3.Connection, w: Window, eco: str | None = None, inst: tuple[str, ...] | None = None
) -> dict[str, dict[int, int]]:
    ec, ep = _eco_clause(eco, inst=inst)
    out: dict[str, dict[int, int]] = {}
    for bucket, decision, n in _rows(
        conn,
        f"SELECT bucket / ? * ? b, decision, sum(count) FROM {w.decisions_table} WHERE bucket >= ? AND bucket < ?{ec} "
        "GROUP BY b, decision",
        (w.step, w.step, w.start, w.end + 1, *ep),
    ):
        out.setdefault(decision, {})[int(bucket)] = int(n)
    return out


def top_packages(
    conn: sqlite3.Connection,
    w: Window,
    *,
    eco: str | None = None,
    by: str = "serves",
    limit: int = 10,
    inst: tuple[str, ...] | None = None,
) -> list[sqlite3.Row]:
    order = "b" if by == "bytes" else "s"
    ec, ep = _eco_clause(eco, inst=inst)
    return _rows(
        conn,
        f"SELECT ecosystem, package, sum(serves) s, sum(bytes) b, sum(cache_hits) h, count(DISTINCT version) v "
        f"FROM {w.table} WHERE bucket >= ? AND bucket < ?{ec} GROUP BY ecosystem, package ORDER BY {order} DESC LIMIT "
        "?",
        (w.start, w.end + 1, *ep, limit),
    )


def recent_events(
    conn: sqlite3.Connection,
    limit: int = 10,
    types: tuple[str, ...] | None = None,
    inst: tuple[str, ...] | None = None,
) -> list[sqlite3.Row]:
    ic, ip = _eco_clause(None, inst=inst)
    if types:
        marks = ",".join("?" for _ in types)
        return _rows(
            conn,
            f"SELECT * FROM events WHERE type IN ({marks}){ic} ORDER BY ts DESC LIMIT ?",
            (*types, *ip, limit),
        )
    return _rows(conn, f"SELECT * FROM events WHERE 1=1{ic} ORDER BY ts DESC LIMIT ?", (*ip, limit))


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
    if eco in ECOSYSTEMS:
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


def oci_tags(conn: sqlite3.Connection, repo: str, limit: int = 200) -> list[sqlite3.Row]:
    """Every digest the tags of image repository `repo` have pointed to, newest first per tag, with both clocks and
    whether the registry took the digest down."""
    return _rows(
        conn,
        "SELECT t.tag, t.digest, t.first_seen, t.registry_time, d.gone FROM oci_tags t "
        "LEFT JOIN oci_digests d ON d.repository = t.repository AND d.digest = t.digest WHERE t.repository = ? "
        "ORDER BY t.tag, min(t.first_seen, coalesce(t.registry_time, t.first_seen)) DESC LIMIT ?",
        (repo, limit),
    )


def package_series(conn: sqlite3.Connection, eco: str, name: str, w: Window) -> dict[int, int]:
    return {
        int(b): int(s)
        for b, s in _rows(
            conn,
            f"SELECT bucket, sum(serves) FROM {w.table} WHERE ecosystem = ? AND package = ? AND bucket >= ? AND "
            "bucket < ? "
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
        "SELECT ecosystem, package, sum(count) n, count(DISTINCT version) v, count(DISTINCT client_ip) clients, "
        "max(ts) last "
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
    inst: tuple[str, ...] | None = None,
) -> list[sqlite3.Row]:
    where = ["ts >= ?"]
    params: list[Any] = [w.start]
    if inst is not None:
        where.append(f"instance IN ({','.join('?' for _ in inst) or 'NULL'})")
        params.extend(inst)
    if type_:
        where.append("type = ?")
        params.append(type_)
    if eco in ECOSYSTEMS:
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


def event_counts(conn: sqlite3.Connection, w: Window, inst: tuple[str, ...] | None = None) -> dict[str, int]:
    ic, ip = _eco_clause(None, inst=inst)
    return {
        r[0]: int(r[1])
        for r in _rows(conn, f"SELECT type, sum(count) FROM events WHERE ts >= ?{ic} GROUP BY type", (w.start, *ip))
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
    if eco in ECOSYSTEMS:
        where.append("ecosystem = ?")
        params.append(eco)
    if source in ("osv", "github", "config", "leader"):
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
        "SELECT source, ecosystem, count(*) n, sum(version IS NULL AND version_range IS NULL) pkg, max(first_seen) "
        "newest "
        "FROM blocklist WHERE withdrawn IS NULL GROUP BY source, ecosystem ORDER BY source, ecosystem",
    )


def feed_states(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return _rows(conn, "SELECT * FROM feed_state ORDER BY source")
