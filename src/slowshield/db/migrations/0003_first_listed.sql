-- When SlowShield first saw a version listed in the upstream metadata (Maven): a second clock next to the registry's
-- publish time, so a registry that rewrites its files in bulk doesn't make every version look new again.
ALTER TABLE package_versions ADD COLUMN first_listed REAL;
