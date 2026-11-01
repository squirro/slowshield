-- UI sign-in (docs/authentication.md): people, their sessions and what they did.

-- Created at a person's first sign-in, updated at every sign-in and recheck. The IdP decides the role; only the claim
-- values or the email rule that gave it are kept (`role_source`), never the person's full group list.
-- `instance` is '' for this instance's own users; a shield wall's leader may also keep its followers' under their ID.
CREATE TABLE users (
    id             INTEGER PRIMARY KEY,
    instance       TEXT    NOT NULL DEFAULT '',
    provider       TEXT    NOT NULL,              -- oidc (saml, tailscale later)
    issuer         TEXT    NOT NULL,
    subject        TEXT    NOT NULL,
    email          TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    name           TEXT,
    role           TEXT    NOT NULL,              -- viewer | user | admin
    role_source    TEXT    NOT NULL,              -- claim:<values> | email:<rule> | default
    first_login    REAL    NOT NULL,
    last_login     REAL    NOT NULL,
    disabled       REAL,                          -- set by an admin here: no sign-in, sessions dropped
    UNIQUE (instance, issuer, subject)
) STRICT;

-- The browser holds a random ID; only its SHA-256 is stored. Rows outlive nothing: expired ones are deleted.
CREATE TABLE ui_sessions (
    id_hash      TEXT    PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    host         TEXT    NOT NULL,                -- the UI URL it was created on (cookies are per host)
    idp_sid      TEXT,
    id_token     TEXT,                            -- the latest ID token, as the hint for signing out at the IdP
    created      REAL    NOT NULL,
    expires      REAL    NOT NULL,
    last_seen    REAL    NOT NULL,
    last_recheck REAL    NOT NULL
) STRICT;
CREATE INDEX ui_sessions_user ON ui_sessions (user_id);
CREATE INDEX ui_sessions_expires ON ui_sessions (expires);

-- Sign-ins, refused sign-ins, sign-outs, failed rechecks and admin actions. Kept for event_retention_days; the
-- client IP follows record_client_ip and client_ip_retention_days, as on security events.
CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL    NOT NULL,
    user_id   INTEGER REFERENCES users (id) ON DELETE SET NULL,
    actor     TEXT,                               -- who, as shown then (email or name): survives the user row
    action    TEXT    NOT NULL,
    target    TEXT,
    details   TEXT,                               -- JSON
    client_ip TEXT,
    instance  TEXT    NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX audit_log_ts ON audit_log (ts DESC);
CREATE INDEX audit_log_user ON audit_log (user_id, ts DESC);
