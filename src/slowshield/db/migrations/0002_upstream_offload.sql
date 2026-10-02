-- Upstream offload figures and the 1-hour view.

-- Bytes served from the verified artifact cache (the rest of `bytes` was fetched from upstream).
ALTER TABLE downloads_hourly ADD COLUMN cache_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE downloads_daily ADD COLUMN cache_bytes INTEGER NOT NULL DEFAULT 0;

-- 5-minute rollups behind the 1h range (kept for two days).
CREATE TABLE downloads_5min (
    bucket      INTEGER NOT NULL,
    ecosystem   TEXT    NOT NULL,
    package     TEXT    NOT NULL,
    version     TEXT    NOT NULL,
    serves      INTEGER NOT NULL,
    cache_hits  INTEGER NOT NULL,
    bytes       INTEGER NOT NULL,
    cache_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, ecosystem, package, version)
) STRICT, WITHOUT ROWID;

CREATE INDEX downloads_5min_package ON downloads_5min (ecosystem, package, bucket);

CREATE TABLE decisions_5min (
    bucket    INTEGER NOT NULL,
    ecosystem TEXT    NOT NULL,
    kind      TEXT    NOT NULL,
    decision  TEXT    NOT NULL,
    count     INTEGER NOT NULL,
    PRIMARY KEY (bucket, ecosystem, kind, decision)
) STRICT, WITHOUT ROWID;

-- Metadata lookups: `cache` = answered without contacting the registry; `upstream` = the registry was
-- contacted (a fetch, a conditional revalidation, or a failed attempt that fell back to the stale copy).
CREATE TABLE lookups_5min (
    bucket    INTEGER NOT NULL,
    ecosystem TEXT    NOT NULL,
    source    TEXT    NOT NULL,
    count     INTEGER NOT NULL,
    PRIMARY KEY (bucket, ecosystem, source)
) STRICT, WITHOUT ROWID;

CREATE TABLE lookups_hourly (
    bucket    INTEGER NOT NULL,
    ecosystem TEXT    NOT NULL,
    source    TEXT    NOT NULL,
    count     INTEGER NOT NULL,
    PRIMARY KEY (bucket, ecosystem, source)
) STRICT, WITHOUT ROWID;
