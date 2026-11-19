-- Failed password sign-ins (SLOWSHIELD_AUTH=password), shared by every worker so the cap holds whatever worker a
-- request lands on. The address is kept only as a hash, and only for the 15 minutes the cap looks back.
CREATE TABLE login_failures (
    address TEXT NOT NULL,
    ts      REAL NOT NULL
) STRICT;
CREATE INDEX login_failures_address ON login_failures (address, ts);
CREATE INDEX login_failures_ts ON login_failures (ts);
