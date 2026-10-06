-- When the registry stored a file (Maven: its own Last-Modified), recorded on its first download, so a cache hit is
-- judged again by the current policy without asking upstream: a file added to an old version later keeps its own date.
ALTER TABLE artifacts ADD COLUMN published REAL;
