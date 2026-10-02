# Operations

## Health

* `GET /healthz` — process is up (liveness).
* `GET /readyz` — database reachable and startup finished (readiness).
* `slowshield healthcheck` — exits 0 when `/readyz` is 200 (used by container health checks; the image has
  no shell or curl).

## Data & backups

Everything lives in the `/data` volume:

| Path | Content | Back up? |
|---|---|---|
| `slowshield.db` (+ `-wal`, `-shm`) | fingerprints, blocklist, events, stats | **yes** — fingerprints are what tamper detection compares against |
| `cache/objects/` | verified artifact bodies | no (re-downloadable) |
| `cache/tmp/`, `cache/trash/` | in-flight / evicted files | no |
| `leader.lock` | worker election | no |

Consistent online backup: `sqlite3 /data/slowshield.db ".backup '/backup/slowshield.db'"` (from a
debug container sharing the volume, since the image has no shell), or stop the container and copy the
files.

## Upgrades

Schema migrations run automatically at start (`PRAGMA user_version`). Releases follow SemVer; read the
changelog before a major upgrade. Podman deployments with `AutoUpdate=registry` pick up new `latest`
images automatically.

## Capacity planning

* Memory: about 200 MB per worker under load plus `cache.metadata_memory_mb` (default 64 MB, in total across all workers).
  Upstream metadata and rendered responses live in `data_dir/metadata-cache.db` (`cache.metadata_max_mb`,
  default 1 GB), shared by all workers and kept in the OS page cache, which the kernel can reclaim. At
  startup SlowShield warns if the workers and the in-memory budget do not fit the container's memory limit.
* Disk: the artifact cache cap (`cache.artifacts_max_gb`), the metadata cache cap (`cache.metadata_max_mb`) and
  a few hundred MB for the database.
* CPU: metadata responses are cached; artifact streaming is I/O bound. Start with 1–2 workers.

## Alerts

The observability stack ([`observability/`](../observability/README.md)) provisions these Grafana alert
rules. Each one links here from its `runbook_url`. Thresholds and expressions are in
`observability/build_alerts.py`. Critical alerts notify at once and repeat hourly; warnings are grouped
and repeat every 4 hours.

### TamperDetected

**Critical.** SlowShield aborted a download because the bytes differed from the first-seen SHA-256 or
from the digest the registry publishes (`slowshield_event` = `tampered` or `integrity_mismatch`). The
client got an error, not the file. Open the UI → **Security** to see the artifact and the client.
Treat it as a possible supply-chain compromise until it is explained (registry incident, re-uploaded
file, broken mirror).

### MalwareBlocked

**Warning.** A client requested a package version on the threat-feed blocklist and got HTTP 451. The
install was prevented. Find the requesting machine (client IP) in the UI → **Security** and work out
how the dependency got there: a direct requirement, a transitive one, or a typo.

### FailOpenSpike

**Warning.** More than 50 fail-open responses in an hour, held for 10 minutes. These packages had no
version older than the delay, so SlowShield served them anyway (`fail_open = true`). Usually these are
new internal or newly adopted packages. A sudden spike can also mean dependency confusion or
typosquatting. Review the UI → **Leaderboards** → fail-open list. Add `[[exceptions]]` for packages you trust, or set
`fail_open = false` if new packages should wait too.

### FeedDisabled

**Warning.** A threat feed has not been running for 15 minutes. Known malware from that source is not
being blocked. `reason="missing_token"`: give the GitHub Advisory feed a token (`GITHUB_TOKEN` or
`GITHUB_TOKEN_FILE`, see [feeds](feeds.md)) and restart SlowShield. `reason="error"`: the last sync
failed. The UI → **Feeds** page shows the error. Feeds switched off on purpose (`reason="disabled"`)
don't alert.

### FeedStale

**Warning.** No successful sync of a feed for more than 3 hours (three times the default poll
interval), so new advisories are not being applied. Check egress to
`osv-vulnerabilities.storage.googleapis.com` and `api.github.com`, and the SlowShield logs. Only the
leader syncs feeds, so also check [NoLeader](#noleader).

### FeedErrors

**Warning.** A feed failed more than twice within an hour. The last error is on the UI → **Feeds**
page.

### SlowShieldDown

**Critical.** No instance has reported `slowshield_build_info` for 5 minutes. Either SlowShield is down
(installs through the proxy are probably failing) or it cannot reach the collector. Check the
container or pod, `GET /readyz` and the Alloy logs.

### NoLeader

**Warning.** For 10 minutes no worker has held the leader lock. Feed syncs, cache eviction and
retention run only on the leader, so they have stopped. Check that the data volume is writable
(`/data/leader.lock`) and look for startup errors in the logs.

### UpstreamErrorRate

**Warning.** More than 5% of requests to a registry fail with 5xx or 429, or fail before getting a
response (`status_code` 0). SlowShield serves stale metadata where it can, but new metadata and
uncached artifacts fail. Check the registry's status page and the egress path (proxy, firewall, DNS).

### Http5xxRate

**Warning.** More than 2% of SlowShield's own responses are server errors. The **Upstream &
Performance** dashboard and the logs usually show whether the cause is upstream, the database or the
proxy itself.

### HighLatency

**Warning.** The p99 of PyPI index pages and npm packuments is above 1 second. The cause is usually a
slow upstream (compare `http_client_request_duration_seconds`) or an overloaded instance. Check
event-loop lag and CPU on the **Upstream & Performance** dashboard, then add workers or CPU.

### DBWriterBacklog

**Warning.** More than 5000 database operations have been queued for 5 minutes. The data volume is too
slow (network storage), or something holds a lock on the database (a backup running without
`.backup`, an external `sqlite3` session).

### ArtifactCacheOverLimit

**Warning.** The artifact cache has stayed above 105% of `cache.artifacts_max_gb` for 30 minutes. It
normally stays between 90% and 100%, and eviction runs every minute on the leader. Check that a leader
exists, then look for eviction errors in the logs and the free space on the data volume.
