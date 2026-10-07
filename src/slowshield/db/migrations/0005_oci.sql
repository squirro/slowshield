-- OCI container images (docs/design/oci.md). A tag is a pointer that moves, so SlowShield keeps every digest it has
-- seen a tag point to, with two clocks: a tag then resolves to the newest digest that is old enough ("time travel").
CREATE TABLE oci_tags (
    repository    TEXT NOT NULL,  -- canonical: docker.io/library/nginx
    tag           TEXT NOT NULL,
    digest        TEXT NOT NULL,  -- what the tag pointed to, usually an index
    first_seen    REAL NOT NULL,  -- when SlowShield first saw (or learned from the registry) that the tag pointed here
    registry_time REAL,           -- when the registry says the tag got this digest, where it says
    last_seen     REAL NOT NULL,
    PRIMARY KEY (repository, tag, digest)
) STRICT, WITHOUT ROWID;

-- Manifests SlowShield has served or looked up, by digest.
CREATE TABLE oci_digests (
    repository TEXT NOT NULL,
    digest     TEXT NOT NULL,
    media_type TEXT,
    first_seen REAL NOT NULL,
    stored     REAL,  -- the registry's own time for this digest, where it has one
    gone       REAL,  -- when the registry stopped serving it (a takedown)
    checked    REAL,  -- when SlowShield last asked the registry whether it still serves it
    PRIMARY KEY (repository, digest)
) STRICT, WITHOUT ROWID;

-- The platform and attestation manifests of an index: they come with it, and are judged by its time.
CREATE TABLE oci_children (
    repository TEXT NOT NULL,
    child      TEXT NOT NULL,
    parent     TEXT NOT NULL,
    PRIMARY KEY (repository, child, parent)
) STRICT, WITHOUT ROWID;

-- The optional store for image layers (upstreams.oci.layer_cache_gb): the same shape as cache_entries, with its
-- own budget, so layers never evict package files.
CREATE TABLE oci_layer_entries (
    sha256       TEXT    PRIMARY KEY,
    size         INTEGER NOT NULL,
    content_type TEXT,
    created      REAL    NOT NULL,
    last_access  REAL    NOT NULL,
    verified     REAL    NOT NULL
) STRICT;

CREATE INDEX oci_layer_entries_lru ON oci_layer_entries (last_access);
