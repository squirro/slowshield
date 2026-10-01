"""One-off import of a database written by the Rust SlowShield (v0-v8).

What is carried over:
  * artifact checksums (TOFU fingerprints) for PyPI and npm, keyed by the same paths;
  * the blocklist (so protection is immediate, before the first feed sync finishes);
  * security events (blocks, tamper, fail-open, age blocks), aggregated per day;
  * per-package / per-version serve totals and known release times.

Imported checksums are flagged `upstream_digest = 'legacy-import'`: the Rust version (before v8) could
store an upstream error page as an artifact's checksum. When such a fingerprint disagrees with bytes
that *do* match the registry's own published digest, it is corrected instead of reported as tampering.
"""

from __future__ import annotations

import logging
import sqlite3
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from slowshield import names
from slowshield.db import connect
from slowshield.ecosystems.pypi import filenames

log = logging.getLogger(__name__)

LEGACY_DIGEST = "legacy-import"
_SOURCE_MAP = {"osv": "osv", "github_advisory": "github", "github": "github", "phylum": "phylum"}


def _ts(raw: str | None) -> float | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace(" ", "T"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp()


def _norm(eco: str, name: str) -> str:
    return names.normalize_pypi(name) if eco == "pypi" else names.normalize_npm(name)


def _artifact_identity(eco: str, path: str) -> tuple[str, str | None, str] | None:
    """(package, version, filename) from a stored artifact path."""
    if eco == "pypi":
        m = filenames.PACKAGES_PATH.match(path)
        if m is None:
            return None
        pkg, ver = filenames.parse(m.group(4))
        return (pkg, ver, m.group(4)) if pkg else None
    if eco == "npm" and "/-/" in path:
        pkg, _, fname = path.lstrip("/").partition("/-/")
        base = names.npm_basename(pkg)
        ver = fname[len(base) + 1 : -4] if fname.startswith(base + "-") and fname.endswith(".tgz") else None
        return pkg, ver, fname
    return None


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def import_legacy(source: Path, target: Path, *, dry_run: bool = False) -> dict[str, Any]:
    if not source.is_file():
        raise FileNotFoundError(source)
    old = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    old.row_factory = sqlite3.Row
    tables = _tables(old)
    report: dict[str, Any] = {"source": str(source), "dry_run": dry_run}
    now = datetime.now(UTC).timestamp()

    artifacts: list[tuple[Any, ...]] = []
    if "artifact_checksums" in tables:
        skipped = 0
        for r in old.execute("SELECT ecosystem, artifact_path, sha256, first_seen_at FROM artifact_checksums"):
            eco = r["ecosystem"]
            ident = _artifact_identity(eco, r["artifact_path"]) if eco in ("pypi", "npm") else None
            if ident is None or len(r["sha256"] or "") != 64:
                skipped += 1
                continue
            pkg, ver, fname = ident
            first = _ts(r["first_seen_at"]) or now
            artifacts.append(
                (eco, r["artifact_path"], _norm(eco, pkg), ver, fname, r["sha256"].lower(), LEGACY_DIGEST, first, first)
            )
        report["artifacts"] = {"imported": len(artifacts), "skipped": skipped}

    blocks: list[tuple[Any, ...]] = []
    if "blocked_packages" in tables:
        for r in old.execute(
            "SELECT ecosystem, package, version, source, advisory_id, reason, blocked_since FROM blocked_packages"
        ):
            eco = r["ecosystem"]
            if eco not in ("pypi", "npm"):
                continue
            src = _SOURCE_MAP.get(r["source"], r["source"] or "legacy")
            ts = _ts(r["blocked_since"]) or now
            url = None
            adv = r["advisory_id"] or ""
            if adv.startswith("MAL-"):
                url = f"https://osv.dev/vulnerability/{adv}"
            elif adv.startswith("GHSA-"):
                url = f"https://github.com/advisories/{adv}"
            blocks.append((eco, _norm(eco, r["package"]), r["version"], None, src, adv, r["reason"], url, ts, ts))
        report["blocklist"] = len(blocks)

    events: dict[tuple[Any, ...], int] = defaultdict(int)
    event_specs = [
        ("block_events", "blocked", "blocked_at", "package", "version"),
        ("tamper_events", "tampered", "detected_at", None, None),
        ("fail_open_events", "fail_open", "served_at", "package", "version"),
        ("age_block_events", "age_gate", "blocked_at", "package", "version"),
    ]
    for table, etype, tcol, pcol, vcol in event_specs:
        if table not in tables:
            continue
        if table == "tamper_events":
            rows = old.execute(f"SELECT ecosystem, artifact_path, {tcol} t FROM tamper_events")
            for r in rows:
                ident = _artifact_identity(r["ecosystem"], r["artifact_path"])
                if ident is None:
                    continue
                day = int((_ts(r["t"]) or now) // 86400 * 86400)
                events[(day, etype, r["ecosystem"], _norm(r["ecosystem"], ident[0]), ident[1])] += 1
            continue
        for r in old.execute(f"SELECT ecosystem, {pcol} p, {vcol} v, {tcol} t FROM {table}"):
            eco = r["ecosystem"]
            if eco not in ("pypi", "npm"):
                continue
            day = int((_ts(r["t"]) or now) // 86400 * 86400)
            events[(day, etype, eco, _norm(eco, r["p"]), r["v"])] += 1
    report["events"] = sum(events.values())

    totals: list[tuple[Any, ...]] = []
    if "serve_log" in tables:
        for r in old.execute(
            "SELECT ecosystem, package, version, serves, cached_serves, bytes_served, last_served_at FROM serve_log"
        ):
            eco = r["ecosystem"]
            if eco not in ("pypi", "npm"):
                continue
            totals.append(
                (
                    eco,
                    _norm(eco, r["package"]),
                    r["version"],
                    r["serves"],
                    r["cached_serves"],
                    r["bytes_served"],
                    _ts(r["last_served_at"]) or now,
                )
            )
        report["serve_log"] = len(totals)

    releases: list[tuple[Any, ...]] = []
    if "package_metadata" in tables:
        for r in old.execute("SELECT ecosystem, package, version, release_time FROM package_metadata"):
            eco = r["ecosystem"]
            if eco in ("pypi", "npm"):
                releases.append((eco, _norm(eco, r["package"]), r["version"], _ts(r["release_time"])))
        report["releases"] = len(releases)
    old.close()

    if dry_run:
        return report

    conn = connect(target)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.executemany(
            "INSERT INTO artifacts (ecosystem, path, package, version, filename, sha256, upstream_digest, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (ecosystem, path) DO NOTHING",
            artifacts,
        )
        conn.executemany(
            "INSERT OR IGNORE INTO blocklist (ecosystem, name, version, version_range, source, advisory_id, reason, url, first_seen, updated) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            blocks,
        )
        conn.executemany(
            "INSERT INTO events (ts, type, ecosystem, package, version, count, details) VALUES (?, ?, ?, ?, ?, ?, '{\"legacy\":true}')",
            [(day, t, e, p, v, n) for (day, t, e, p, v), n in events.items()],
        )
        pkg_tot: dict[tuple[str, str], list[float]] = defaultdict(lambda: [0, 0, 0, 0.0])
        for eco, pkg, ver, serves, cached, nbytes, last in totals:
            agg = pkg_tot[(eco, pkg)]
            agg[0] += serves
            agg[1] += cached
            agg[2] += nbytes
            agg[3] = max(agg[3], last)
            conn.execute(
                "INSERT INTO package_versions (ecosystem, name, version, serves, bytes, last_served) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (ecosystem, name, version) DO UPDATE SET serves = serves + excluded.serves, bytes = bytes + excluded.bytes, "
                "last_served = max(coalesce(last_served, 0), excluded.last_served)",
                (eco, pkg, ver, serves, nbytes, last),
            )
        for (eco, pkg), (serves, cached, nbytes, last) in pkg_tot.items():
            conn.execute(
                "INSERT INTO packages (ecosystem, name, first_seen, last_seen, first_served, last_served, serves, cache_hits, bytes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (ecosystem, name) DO UPDATE SET serves = serves + excluded.serves, "
                "cache_hits = cache_hits + excluded.cache_hits, bytes = bytes + excluded.bytes, "
                "last_served = max(coalesce(last_served, 0), excluded.last_served)",
                (eco, pkg, last, last, last, last, int(serves), int(cached), int(nbytes)),
            )
        conn.executemany(
            "INSERT INTO package_versions (ecosystem, name, version, published) VALUES (?, ?, ?, ?) "
            "ON CONFLICT (ecosystem, name, version) DO UPDATE SET published = coalesce(published, excluded.published)",
            releases,
        )
        conn.execute(
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'blocklist_generation'"
        )
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    log.info("legacy import complete", extra=report)
    return report
