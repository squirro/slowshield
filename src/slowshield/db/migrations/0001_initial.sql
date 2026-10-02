-- SlowShield schema v1. Timestamps are UNIX seconds (REAL). Package names are stored normalised
-- (PEP 503 for PyPI, exact for npm).

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

INSERT INTO meta (key, value) VALUES ('blocklist_generation', '0');

-- One row per artifact path ever served. `sha256` is the trust-on-first-use digest of the bytes.
CREATE TABLE artifacts (
    ecosystem       TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    package         TEXT    NOT NULL,
    version         TEXT,
    filename        TEXT    NOT NULL,
    sha256          TEXT,
    upstream_digest TEXT,
    size            INTEGER,
    first_seen      REAL    NOT NULL,
    last_seen       REAL    NOT NULL,
    tampered        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ecosystem, path)
) STRICT, WITHOUT ROWID;

CREATE INDEX artifacts_package ON artifacts (ecosystem, package);

-- Verified artifact bodies on disk, content-addressed by sha256.
CREATE TABLE cache_entries (
    sha256       TEXT    PRIMARY KEY,
    size         INTEGER NOT NULL,
    content_type TEXT,
    created      REAL    NOT NULL,
    last_access  REAL    NOT NULL,
    verified     REAL    NOT NULL
) STRICT;

CREATE INDEX cache_entries_lru ON cache_entries (last_access);

CREATE TABLE packages (
    ecosystem   TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    first_seen  REAL    NOT NULL,
    last_seen   REAL    NOT NULL,
    first_served REAL,
    last_served REAL,
    serves      INTEGER NOT NULL DEFAULT 0,
    cache_hits  INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ecosystem, name)
) STRICT, WITHOUT ROWID;

CREATE INDEX packages_serves ON packages (serves DESC);
CREATE INDEX packages_first_served ON packages (first_served);

CREATE TABLE package_versions (
    ecosystem    TEXT    NOT NULL,
    name         TEXT    NOT NULL,
    version      TEXT    NOT NULL,
    published    REAL,
    yanked       INTEGER NOT NULL DEFAULT 0,
    first_served REAL,
    last_served  REAL,
    serves       INTEGER NOT NULL DEFAULT 0,
    bytes        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ecosystem, name, version)
) STRICT, WITHOUT ROWID;

-- Threat-feed blocks. version=NULL and version_range=NULL means the whole package.
CREATE TABLE blocklist (
    id            INTEGER PRIMARY KEY,
    ecosystem     TEXT NOT NULL,
    name          TEXT NOT NULL,
    version       TEXT,
    version_range TEXT,
    source        TEXT NOT NULL,
    advisory_id   TEXT NOT NULL DEFAULT '',
    reason        TEXT,
    url           TEXT,
    first_seen    REAL NOT NULL,
    updated       REAL NOT NULL,
    withdrawn     REAL
) STRICT;

CREATE UNIQUE INDEX blocklist_identity ON blocklist (
    ecosystem, name, ifnull(version, ''), ifnull(version_range, ''), source, advisory_id
);
CREATE INDEX blocklist_lookup ON blocklist (ecosystem, name) WHERE withdrawn IS NULL;
CREATE INDEX blocklist_advisory ON blocklist (source, advisory_id);
CREATE INDEX blocklist_recent ON blocklist (first_seen DESC);

CREATE TABLE feed_state (
    source       TEXT PRIMARY KEY,
    watermark    TEXT,
    etag         TEXT,
    last_attempt REAL,
    last_success REAL,
    last_error   TEXT,
    entries      INTEGER,
    details      TEXT
) STRICT;

-- Security-relevant events, aggregated per flush window (count > 1 = repeated within the window).
CREATE TABLE events (
    id        INTEGER PRIMARY KEY,
    ts        REAL    NOT NULL,
    type      TEXT    NOT NULL,
    ecosystem TEXT    NOT NULL,
    package   TEXT    NOT NULL,
    version   TEXT,
    client_ip TEXT,
    count     INTEGER NOT NULL DEFAULT 1,
    details   TEXT
) STRICT;

CREATE INDEX events_ts ON events (ts DESC);
CREATE INDEX events_type_ts ON events (type, ts DESC);
CREATE INDEX events_package ON events (ecosystem, package, ts DESC);

-- Download rollups. `bucket` is the UNIX start of the hour/day (UTC).
CREATE TABLE downloads_hourly (
    bucket     INTEGER NOT NULL,
    ecosystem  TEXT    NOT NULL,
    package    TEXT    NOT NULL,
    version    TEXT    NOT NULL,
    serves     INTEGER NOT NULL,
    cache_hits INTEGER NOT NULL,
    bytes      INTEGER NOT NULL,
    PRIMARY KEY (bucket, ecosystem, package, version)
) STRICT, WITHOUT ROWID;

CREATE INDEX downloads_hourly_package ON downloads_hourly (ecosystem, package, bucket);

CREATE TABLE downloads_daily (
    bucket     INTEGER NOT NULL,
    ecosystem  TEXT    NOT NULL,
    package    TEXT    NOT NULL,
    version    TEXT    NOT NULL,
    serves     INTEGER NOT NULL,
    cache_hits INTEGER NOT NULL,
    bytes      INTEGER NOT NULL,
    PRIMARY KEY (bucket, ecosystem, package, version)
) STRICT, WITHOUT ROWID;

CREATE INDEX downloads_daily_package ON downloads_daily (ecosystem, package, bucket);

-- Policy decisions per hour (metadata and artifact requests).
CREATE TABLE decisions_hourly (
    bucket    INTEGER NOT NULL,
    ecosystem TEXT    NOT NULL,
    kind      TEXT    NOT NULL,
    decision  TEXT    NOT NULL,
    count     INTEGER NOT NULL,
    PRIMARY KEY (bucket, ecosystem, kind, decision)
) STRICT, WITHOUT ROWID;
