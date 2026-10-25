-- The commit a version's times belong to (Composer: dist.reference). A branch, or a tag on a repository other than
-- Packagist, can move to another commit under the same name; the new commit is timed afresh.
ALTER TABLE package_versions ADD COLUMN reference TEXT;
