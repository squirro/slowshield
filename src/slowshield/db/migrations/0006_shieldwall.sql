-- Shield wall (docs/design/shieldwall.md): one leader instance, many followers.

-- ---- Statistics per instance ---------------------------------------------------------------------------
-- `instance` is '' for this instance's own rows; a leader also keeps each follower's rows under its instance ID.
-- `leader_bytes`: bytes a follower fetched through its leader instead of the registry.

CREATE TABLE downloads_5min_new (
    bucket       INTEGER NOT NULL,
    ecosystem    TEXT    NOT NULL,
    package      TEXT    NOT NULL,
    version      TEXT    NOT NULL,
    instance     TEXT    NOT NULL DEFAULT '',
    serves       INTEGER NOT NULL,
    cache_hits   INTEGER NOT NULL,
    bytes        INTEGER NOT NULL,
    cache_bytes  INTEGER NOT NULL DEFAULT 0,
    leader_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, ecosystem, package, version, instance)
) STRICT, WITHOUT ROWID;
INSERT INTO downloads_5min_new (bucket, ecosystem, package, version, serves, cache_hits, bytes, cache_bytes)
    SELECT bucket, ecosystem, package, version, serves, cache_hits, bytes, cache_bytes FROM downloads_5min;
DROP TABLE downloads_5min;
ALTER TABLE downloads_5min_new RENAME TO downloads_5min;
CREATE INDEX downloads_5min_package ON downloads_5min (ecosystem, package, bucket);

CREATE TABLE downloads_hourly_new (
    bucket       INTEGER NOT NULL,
    ecosystem    TEXT    NOT NULL,
    package      TEXT    NOT NULL,
    version      TEXT    NOT NULL,
    instance     TEXT    NOT NULL DEFAULT '',
    serves       INTEGER NOT NULL,
    cache_hits   INTEGER NOT NULL,
    bytes        INTEGER NOT NULL,
    cache_bytes  INTEGER NOT NULL DEFAULT 0,
    leader_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, ecosystem, package, version, instance)
) STRICT, WITHOUT ROWID;
INSERT INTO downloads_hourly_new (bucket, ecosystem, package, version, serves, cache_hits, bytes, cache_bytes)
    SELECT bucket, ecosystem, package, version, serves, cache_hits, bytes, cache_bytes FROM downloads_hourly;
DROP TABLE downloads_hourly;
ALTER TABLE downloads_hourly_new RENAME TO downloads_hourly;
CREATE INDEX downloads_hourly_package ON downloads_hourly (ecosystem, package, bucket);

CREATE TABLE downloads_daily_new (
    bucket       INTEGER NOT NULL,
    ecosystem    TEXT    NOT NULL,
    package      TEXT    NOT NULL,
    version      TEXT    NOT NULL,
    instance     TEXT    NOT NULL DEFAULT '',
    serves       INTEGER NOT NULL,
    cache_hits   INTEGER NOT NULL,
    bytes        INTEGER NOT NULL,
    cache_bytes  INTEGER NOT NULL DEFAULT 0,
    leader_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, ecosystem, package, version, instance)
) STRICT, WITHOUT ROWID;
INSERT INTO downloads_daily_new (bucket, ecosystem, package, version, serves, cache_hits, bytes, cache_bytes)
    SELECT bucket, ecosystem, package, version, serves, cache_hits, bytes, cache_bytes FROM downloads_daily;
DROP TABLE downloads_daily;
ALTER TABLE downloads_daily_new RENAME TO downloads_daily;
CREATE INDEX downloads_daily_package ON downloads_daily (ecosystem, package, bucket);

CREATE TABLE decisions_5min_new (
    bucket    INTEGER NOT NULL,
    ecosystem TEXT    NOT NULL,
    kind      TEXT    NOT NULL,
    decision  TEXT    NOT NULL,
    instance  TEXT    NOT NULL DEFAULT '',
    count     INTEGER NOT NULL,
    PRIMARY KEY (bucket, ecosystem, kind, decision, instance)
) STRICT, WITHOUT ROWID;
INSERT INTO decisions_5min_new (bucket, ecosystem, kind, decision, count)
    SELECT bucket, ecosystem, kind, decision, count FROM decisions_5min;
DROP TABLE decisions_5min;
ALTER TABLE decisions_5min_new RENAME TO decisions_5min;

CREATE TABLE decisions_hourly_new (
    bucket    INTEGER NOT NULL,
    ecosystem TEXT    NOT NULL,
    kind      TEXT    NOT NULL,
    decision  TEXT    NOT NULL,
    instance  TEXT    NOT NULL DEFAULT '',
    count     INTEGER NOT NULL,
    PRIMARY KEY (bucket, ecosystem, kind, decision, instance)
) STRICT, WITHOUT ROWID;
INSERT INTO decisions_hourly_new (bucket, ecosystem, kind, decision, count)
    SELECT bucket, ecosystem, kind, decision, count FROM decisions_hourly;
DROP TABLE decisions_hourly;
ALTER TABLE decisions_hourly_new RENAME TO decisions_hourly;

CREATE TABLE lookups_5min_new (
    bucket    INTEGER NOT NULL,
    ecosystem TEXT    NOT NULL,
    source    TEXT    NOT NULL,
    instance  TEXT    NOT NULL DEFAULT '',
    count     INTEGER NOT NULL,
    PRIMARY KEY (bucket, ecosystem, source, instance)
) STRICT, WITHOUT ROWID;
INSERT INTO lookups_5min_new (bucket, ecosystem, source, count) SELECT bucket, ecosystem, source, count FROM lookups_5min;
DROP TABLE lookups_5min;
ALTER TABLE lookups_5min_new RENAME TO lookups_5min;

CREATE TABLE lookups_hourly_new (
    bucket    INTEGER NOT NULL,
    ecosystem TEXT    NOT NULL,
    source    TEXT    NOT NULL,
    instance  TEXT    NOT NULL DEFAULT '',
    count     INTEGER NOT NULL,
    PRIMARY KEY (bucket, ecosystem, source, instance)
) STRICT, WITHOUT ROWID;
INSERT INTO lookups_hourly_new (bucket, ecosystem, source, count)
    SELECT bucket, ecosystem, source, count FROM lookups_hourly;
DROP TABLE lookups_hourly;
ALTER TABLE lookups_hourly_new RENAME TO lookups_hourly;

ALTER TABLE events ADD COLUMN instance TEXT NOT NULL DEFAULT '';
CREATE INDEX events_instance_ts ON events (instance, ts DESC);

-- A follower keeps its leader's blocks as `source = 'leader'` rows, next to its own; `leader_id` is the row's ID on
-- the leader, so updates and withdrawals find it.
ALTER TABLE blocklist ADD COLUMN leader_id INTEGER;
CREATE INDEX blocklist_leader ON blocklist (leader_id) WHERE leader_id IS NOT NULL;

-- ---- Leader -------------------------------------------------------------------------------------------

-- Join tokens from `slowshield shieldwall invite`: single use, minutes long. The secret is kept until it is used or
-- expires, to check the follower's proof (an HMAC binding it to the follower's key).
CREATE TABLE shieldwall_tokens (
    id       TEXT PRIMARY KEY,
    secret   TEXT,
    created  REAL NOT NULL,
    expires  REAL NOT NULL,
    used     REAL,
    member   TEXT,
    name     TEXT,
    location TEXT,
    revoked  REAL
) STRICT;

CREATE TABLE shieldwall_members (
    id             TEXT    PRIMARY KEY,           -- the follower's instance ID (from its key)
    pubkey         BLOB    NOT NULL UNIQUE,
    name           TEXT    NOT NULL,
    location       TEXT    NOT NULL DEFAULT '',
    labels         TEXT    NOT NULL DEFAULT '{}', -- JSON object
    version        TEXT,
    protocol       INTEGER,
    state          TEXT    NOT NULL,              -- active | removed
    joined         REAL    NOT NULL,
    token          TEXT,
    last_seen      REAL,
    inbox_hwm      INTEGER NOT NULL DEFAULT 0,    -- last outbox entry applied (exactly-once delivery)
    policy_version INTEGER,
    status         TEXT                           -- JSON: the follower's last heartbeat
) STRICT;

-- What changed that followers take: one row per (dataset, key), moved to a new seq on every change.
CREATE TABLE shieldwall_changes (
    seq     INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset TEXT    NOT NULL,
    key     TEXT    NOT NULL,
    ts      REAL    NOT NULL,
    UNIQUE (dataset, key)
) STRICT;

-- Package files a leader fetched for its followers, by another digest than sha256 (npm's sha512), so the next
-- follower asking finds them in the cache. Computed from the bytes by the leader itself.
CREATE TABLE shieldwall_blobs (
    alg    TEXT NOT NULL,
    digest TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    PRIMARY KEY (alg, digest)
) STRICT, WITHOUT ROWID;

-- The first fingerprint each instance saw for an artifact; disagreement is tampering somewhere.
CREATE TABLE shieldwall_fingerprints (
    ecosystem  TEXT NOT NULL,
    path       TEXT NOT NULL,
    instance   TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    first_seen REAL NOT NULL,
    package    TEXT NOT NULL,
    version    TEXT,
    flagged    REAL,                               -- the leader saw other bytes: the file is refused on that follower
    PRIMARY KEY (ecosystem, path, instance)
) STRICT, WITHOUT ROWID;

-- Change capture, only on a leader (meta shieldwall_role, set at startup).
CREATE TRIGGER shieldwall_block_insert AFTER INSERT ON blocklist
WHEN NEW.source IN ('config', 'github') AND (SELECT value FROM meta WHERE key = 'shieldwall_role') = 'leader'
BEGIN
    INSERT OR REPLACE INTO shieldwall_changes (dataset, key, ts) VALUES ('block', CAST(NEW.id AS TEXT), unixepoch('subsec'));
END;

CREATE TRIGGER shieldwall_block_update AFTER UPDATE OF withdrawn, reason, url ON blocklist
WHEN NEW.source IN ('config', 'github') AND (SELECT value FROM meta WHERE key = 'shieldwall_role') = 'leader'
BEGIN
    INSERT OR REPLACE INTO shieldwall_changes (dataset, key, ts) VALUES ('block', CAST(NEW.id AS TEXT), unixepoch('subsec'));
END;

CREATE TRIGGER shieldwall_block_delete AFTER DELETE ON blocklist
WHEN OLD.source IN ('config', 'github') AND (SELECT value FROM meta WHERE key = 'shieldwall_role') = 'leader'
BEGIN
    INSERT OR REPLACE INTO shieldwall_changes (dataset, key, ts) VALUES ('block', CAST(OLD.id AS TEXT), unixepoch('subsec'));
END;

CREATE TRIGGER shieldwall_tamper AFTER UPDATE OF tampered ON artifacts
WHEN NEW.tampered = 1 AND OLD.tampered = 0 AND (SELECT value FROM meta WHERE key = 'shieldwall_role') = 'leader'
BEGIN
    INSERT OR REPLACE INTO shieldwall_changes (dataset, key, ts)
    VALUES ('tamper', NEW.ecosystem || char(10) || NEW.path, unixepoch('subsec'));
END;

CREATE TRIGGER shieldwall_gone AFTER UPDATE OF gone ON oci_digests
WHEN NEW.gone IS NOT NULL AND OLD.gone IS NULL AND (SELECT value FROM meta WHERE key = 'shieldwall_role') = 'leader'
BEGIN
    INSERT OR REPLACE INTO shieldwall_changes (dataset, key, ts)
    VALUES ('gone', NEW.repository || char(10) || NEW.digest, unixepoch('subsec'));
END;

CREATE TRIGGER shieldwall_gone_insert AFTER INSERT ON oci_digests
WHEN NEW.gone IS NOT NULL AND (SELECT value FROM meta WHERE key = 'shieldwall_role') = 'leader'
BEGIN
    INSERT OR REPLACE INTO shieldwall_changes (dataset, key, ts)
    VALUES ('gone', NEW.repository || char(10) || NEW.digest, unixepoch('subsec'));
END;

CREATE TRIGGER shieldwall_tag AFTER INSERT ON oci_tags
WHEN (SELECT value FROM meta WHERE key = 'shieldwall_role') = 'leader'
BEGIN
    INSERT OR REPLACE INTO shieldwall_changes (dataset, key, ts)
    VALUES ('tag', NEW.repository || char(10) || NEW.tag || char(10) || NEW.digest, unixepoch('subsec'));
END;

CREATE TRIGGER shieldwall_listed_insert AFTER INSERT ON package_versions
WHEN NEW.first_listed IS NOT NULL AND (SELECT value FROM meta WHERE key = 'shieldwall_role') = 'leader'
BEGIN
    INSERT OR REPLACE INTO shieldwall_changes (dataset, key, ts)
    VALUES ('listed', NEW.ecosystem || char(10) || NEW.name || char(10) || NEW.version, unixepoch('subsec'));
END;

CREATE TRIGGER shieldwall_listed AFTER UPDATE OF first_listed ON package_versions
WHEN NEW.first_listed IS NOT NULL AND OLD.first_listed IS NULL
     AND (SELECT value FROM meta WHERE key = 'shieldwall_role') = 'leader'
BEGIN
    INSERT OR REPLACE INTO shieldwall_changes (dataset, key, ts)
    VALUES ('listed', NEW.ecosystem || char(10) || NEW.name || char(10) || NEW.version, unixepoch('subsec'));
END;

-- ---- Follower -----------------------------------------------------------------------------------------

CREATE TABLE shieldwall_leader (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    leader_id      TEXT    NOT NULL,
    url            TEXT    NOT NULL,
    pubkey         BLOB    NOT NULL,
    name           TEXT,
    join_token     TEXT    NOT NULL,              -- the token id of the join string this pairing came from
    state          TEXT    NOT NULL,              -- pending | active | join_failed | removed | key_changed
    discovered     REAL    NOT NULL,
    paired         REAL,
    confirmed_by   TEXT,                          -- ui | auto
    policy_version INTEGER NOT NULL DEFAULT 0,    -- the last bundle received
    policy         TEXT,                          -- the bundle that applies (JSON)
    boot_head      INTEGER NOT NULL DEFAULT 0,    -- the leader's change head at pairing: older changes are the bootstrap
    cursor         INTEGER NOT NULL DEFAULT 0,    -- last change from the leader applied
    last_sync      REAL,
    last_attempt   REAL,
    last_error     TEXT
) STRICT;

-- Loosening changes from the leader wait out a hold-down before they apply (policy: 1 h, block withdrawals: 24 h).
CREATE TABLE shieldwall_pending (
    kind TEXT NOT NULL,                           -- policy | unblock
    key  TEXT NOT NULL,
    due  REAL NOT NULL,
    body TEXT,
    PRIMARY KEY (kind, key)
) STRICT;

-- (local time, leader change head) per sync: the late-news rule bounds how far back a change can be dated.
CREATE TABLE shieldwall_sync_log (
    ts   REAL    PRIMARY KEY,
    head INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- Reports for the leader, written in the same transaction as the local statistics; acknowledged entries are deleted.
CREATE TABLE shieldwall_outbox (
    seq     INTEGER PRIMARY KEY AUTOINCREMENT,
    created REAL    NOT NULL,
    kind    TEXT    NOT NULL,
    body    TEXT    NOT NULL
) STRICT;
