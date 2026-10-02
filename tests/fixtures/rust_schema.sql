-- Final schema of the Rust SlowShield (migrations 001-005), used to test 'slowshield import-legacy'.
-- 001_initial.sql
CREATE TABLE IF NOT EXISTS package_metadata (
    ecosystem       TEXT NOT NULL CHECK (ecosystem IN ('pypi','npm','yum','homebrew')),
    package         TEXT NOT NULL,
    version         TEXT NOT NULL,
    release_time    TEXT NOT NULL,
    fetched_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    PRIMARY KEY (ecosystem, package, version)
);

CREATE TABLE IF NOT EXISTS artifact_checksums (
    ecosystem       TEXT NOT NULL,
    artifact_path   TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    first_seen_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    PRIMARY KEY (ecosystem, artifact_path)
);

CREATE TABLE IF NOT EXISTS yum_served_versions (
    repo_id              TEXT NOT NULL,
    package_name         TEXT NOT NULL,
    arch                 TEXT NOT NULL,
    version              TEXT NOT NULL,
    primary_xml_fragment TEXT NOT NULL,
    local_rpm_path       TEXT NOT NULL,
    fail_open            INTEGER NOT NULL DEFAULT 0,
    recorded_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    PRIMARY KEY (repo_id, package_name, arch)
);

CREATE TABLE IF NOT EXISTS tamper_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem       TEXT NOT NULL,
    artifact_path   TEXT NOT NULL,
    stored_sha256   TEXT NOT NULL,
    observed_sha256 TEXT NOT NULL,
    detected_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    client_ip       TEXT,
    request_id      TEXT
);

CREATE TABLE IF NOT EXISTS age_block_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem       TEXT NOT NULL,
    package         TEXT NOT NULL,
    version         TEXT NOT NULL,
    delay_days_required INTEGER NOT NULL,
    days_old        REAL NOT NULL,
    blocked_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    client_ip       TEXT
);

CREATE TABLE IF NOT EXISTS fail_open_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem       TEXT NOT NULL,
    package         TEXT NOT NULL,
    version         TEXT NOT NULL,
    reason          TEXT NOT NULL,
    served_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    client_ip       TEXT
);

CREATE TABLE IF NOT EXISTS homebrew_served_versions (
    formula          TEXT NOT NULL,
    os_arch          TEXT NOT NULL,
    version          TEXT NOT NULL,
    manifest_digest  TEXT NOT NULL,
    local_blob_path  TEXT NOT NULL,
    fail_open        INTEGER NOT NULL DEFAULT 0,
    recorded_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    PRIMARY KEY (formula, os_arch)
);

CREATE TABLE IF NOT EXISTS blocked_packages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem     TEXT NOT NULL,
    package       TEXT NOT NULL,
    version       TEXT,
    source        TEXT NOT NULL,
    advisory_id   TEXT,
    reason        TEXT,
    blocked_since TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (ecosystem, package, version)
);

CREATE TABLE IF NOT EXISTS feed_cursors (
    source      TEXT PRIMARY KEY,
    cursor      TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_metadata ON package_metadata (ecosystem, package, version);
CREATE INDEX IF NOT EXISTS idx_checksum ON artifact_checksums (ecosystem, artifact_path);
CREATE INDEX IF NOT EXISTS idx_yum_served ON yum_served_versions (repo_id, package_name, arch);
CREATE INDEX IF NOT EXISTS idx_blocked ON blocked_packages (ecosystem, package, version);

-- 002_serve_log.sql
CREATE TABLE IF NOT EXISTS serve_counters (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    packages_served         INTEGER NOT NULL DEFAULT 0,
    packages_served_cached  INTEGER NOT NULL DEFAULT 0,
    bytes_served            INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO serve_counters (id) VALUES (1);

-- 003_blocked_packages.sql
-- Re-create blocked_packages if it was missed because 001_initial.sql
-- was modified after the migration had already been applied.
CREATE TABLE IF NOT EXISTS blocked_packages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem     TEXT NOT NULL,
    package       TEXT NOT NULL,
    version       TEXT,
    source        TEXT NOT NULL,
    advisory_id   TEXT,
    reason        TEXT,
    blocked_since TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (ecosystem, package, version)
);

CREATE INDEX IF NOT EXISTS idx_blocked ON blocked_packages (ecosystem, package, version);

-- 004_event_tables.sql
-- Per-request block events. One row per hard-block (user tried to fetch a
-- package that's on the blocklist). Backs the "Packages blocked" overview
-- card and its drill-down table.
CREATE TABLE IF NOT EXISTS block_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem   TEXT NOT NULL,
    package     TEXT NOT NULL,
    version     TEXT,
    advisory_id TEXT,
    reason      TEXT,
    source      TEXT,
    blocked_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    client_ip   TEXT
);

CREATE INDEX IF NOT EXISTS idx_block_events_recent  ON block_events (blocked_at DESC);
CREATE INDEX IF NOT EXISTS idx_block_events_package ON block_events (ecosystem, package);

-- Per-package serve counters. Lets the "Packages served" card link to a
-- breakdown of what's actually being proxied.
CREATE TABLE IF NOT EXISTS serve_log (
    ecosystem      TEXT NOT NULL,
    package        TEXT NOT NULL,
    version        TEXT NOT NULL,
    serves         INTEGER NOT NULL DEFAULT 0,
    cached_serves  INTEGER NOT NULL DEFAULT 0,
    bytes_served   INTEGER NOT NULL DEFAULT 0,
    last_served_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    PRIMARY KEY (ecosystem, package, version)
);

CREATE INDEX IF NOT EXISTS idx_serve_log_recent ON serve_log (last_served_at DESC);

-- 005_dedup_blocked_packages.sql
-- Fix bloated blocked_packages table caused by two bugs:
--   1. SQLite UNIQUE treats NULLs as distinct, so INSERT OR IGNORE created
--      duplicate package-level (version IS NULL) rows on every feed poll.
--   2. OSV MAL-* entries stored one row per published version of a typosquat
--      instead of a single package-level block.

-- Step 1: Collapse OSV version-specific rows into package-level blocks.
-- For each (ecosystem, package) that has version-specific OSV rows, ensure a
-- package-level row exists (picking the earliest advisory_id and reason).
INSERT INTO blocked_packages (ecosystem, package, version, source, advisory_id, reason, blocked_since)
SELECT ecosystem, package, NULL, 'osv', MIN(advisory_id), MIN(reason), MIN(blocked_since)
FROM blocked_packages
WHERE source = 'osv' AND version IS NOT NULL
GROUP BY ecosystem, package
HAVING NOT EXISTS (
    SELECT 1 FROM blocked_packages bp2
    WHERE bp2.ecosystem = blocked_packages.ecosystem
      AND bp2.package = blocked_packages.package
      AND bp2.version IS NULL
      AND bp2.source = 'osv'
    LIMIT 1
);

-- Step 2: Delete the now-redundant version-specific OSV rows.
DELETE FROM blocked_packages WHERE source = 'osv' AND version IS NOT NULL;

-- Step 3: Delete duplicate NULL-version rows (keep the one with lowest rowid).
DELETE FROM blocked_packages
WHERE version IS NULL
  AND rowid NOT IN (
    SELECT MIN(rowid)
    FROM blocked_packages
    WHERE version IS NULL
    GROUP BY ecosystem, package
);

-- Step 4: Add partial unique index so future INSERT with version IS NULL
-- is properly deduplicated.
CREATE UNIQUE INDEX IF NOT EXISTS idx_blocked_pkg_null_ver
ON blocked_packages (ecosystem, package) WHERE version IS NULL;

