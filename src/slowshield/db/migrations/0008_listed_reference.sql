-- Shield wall: a version's `first_listed` goes to followers with the commit it belongs to (`reference`, Composer's
-- dist.reference), also when the version moves to another commit on the leader. On a follower, `reference = ''`
-- marks a time from a leader that didn't name the commit (a build from before the field): it belongs to no commit
-- the follower sees, so the follower times any commit afresh.
DROP TRIGGER shieldwall_listed;
CREATE TRIGGER shieldwall_listed AFTER UPDATE OF first_listed, reference ON package_versions
WHEN NEW.first_listed IS NOT NULL AND (OLD.first_listed IS NULL OR NEW.reference IS NOT OLD.reference)
     AND (SELECT value FROM meta WHERE key = 'shieldwall_role') = 'leader'
BEGIN
    INSERT OR REPLACE INTO shieldwall_changes (dataset, key, ts)
    VALUES ('listed', NEW.ecosystem || char(10) || NEW.name || char(10) || NEW.version, unixepoch('subsec'));
END;
