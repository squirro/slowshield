-- Fast-tracks (docs/authentication.md): a held-back version released before its delay is up. An Admin grants one
-- with a reason; a User asks with a reason, and a second person approves or rejects it with theirs. Blocks and
-- tamper checks still apply to a fast-tracked version: only the release-age delay is lifted.
CREATE TABLE fast_tracks (
    id               INTEGER PRIMARY KEY,
    ecosystem        TEXT    NOT NULL,
    package          TEXT    NOT NULL,
    version          TEXT    NOT NULL,             -- as package_versions keeps it (an image digest for oci)
    state            TEXT    NOT NULL,             -- pending | active | rejected | revoked
    requested_by     INTEGER REFERENCES users (id) ON DELETE SET NULL,
    requester        TEXT    NOT NULL,             -- who, as shown then
    requested_at     REAL    NOT NULL,
    request_message  TEXT    NOT NULL,
    decided_by       INTEGER REFERENCES users (id) ON DELETE SET NULL,
    decider          TEXT,
    decided_at       REAL,
    decision_message TEXT,
    revoked_by       INTEGER REFERENCES users (id) ON DELETE SET NULL,
    revoker          TEXT,
    revoked_at       REAL,
    revoke_message   TEXT
) STRICT;
-- One open request or active fast-track per version.
CREATE UNIQUE INDEX fast_tracks_open ON fast_tracks (ecosystem, package, version) WHERE state IN ('pending', 'active');
CREATE INDEX fast_tracks_state ON fast_tracks (state, requested_at DESC);
-- Every worker reloads the active fast-tracks when this changes.
INSERT INTO meta (key, value) VALUES ('fast_track_generation', '0');
