# Threat feeds

Feeds populate the blocklist with known-**malicious** packages (not ordinary vulnerabilities — those are
your SCA tool's job). They run on the leader worker every `feeds.poll_interval_minutes` (default 60).

| Feed | Source | Token | Sync |
|---|---|---|---|
| `osv` | OSV.dev bucket, OpenSSF `MAL-*` advisories for PyPI, npm, Go, Maven and crates.io, plus RustSec's malware advisories | none | first run downloads `<eco>/all.zip`; afterwards reads the head of `<eco>/modified_id.csv` until the stored watermark and fetches only changed `MAL-*` (and `RUSTSEC-*`) documents |
| `github` | GitHub Advisory Database REST API, `type=malware` | `GITHUB_TOKEN` | `GET /advisories?type=malware&ecosystem=<pip|npm|go|maven|rust>&sort=updated&direction=asc&updated=>=<watermark>` with cursor pagination; withdrawn advisories fetched separately |

## Version semantics

* OSV entries listing explicit `versions` block exactly those versions (e.g. the backdoored axios
  releases in `MAL-2026-2307` while clean versions stay installable).
* OSV range events become comparator ranges (`>= 1.0.0, < 1.4.2`); `introduced: 0` without an end blocks
  the whole package.
* GitHub `vulnerable_version_range`: `= x` → exact version; `>= 0` / empty → whole package; other ranges are
  evaluated per version.
* RustSec (in OSV's crates.io data): only advisories categorised `malicious`, and not those that alias a `MAL-*` id.
  `introduced: 0.0.0-0` without an end blocks the whole crate; an open range from a later version is skipped,
  because the versions published after crates.io removed the bad ones are not malware
  ([design/cargo.md](design/cargo.md)).
* Withdrawn advisories lift their blocks (rows are kept, marked withdrawn, for the audit trail).

## Missing token → feed off, loudly

Without `GITHUB_TOKEN` (or `GITHUB_TOKEN_FILE`), the GitHub feed does not run. SlowShield keeps working
with OSV only, and:

* every UI page shows a banner linking to **Feeds**, which explains how to create a token (a fine-grained
  personal access token with *no* permissions is enough) and how to pass it for Docker, Podman and Helm;
* the metric `slowshield_feed_enabled{feed="github",reason="missing_token"}` is `0`, and the shipped Grafana
  alert **FeedDisabled** fires on it; **FeedStale** fires when a feed has not synced successfully for three
  poll intervals.

## Feed status

`/ui/feeds` shows each feed's state (`active`, `disabled`, `needs token`, `failing`), last success, last
error, active entries and per-stream watermarks. Metrics: `slowshield_feed_enabled`,
`slowshield_feed_last_success_timestamp_seconds`, `slowshield_feed_sync_duration_seconds`,
`slowshield_feed_errors_total`, `slowshield_feed_changes_total`, `slowshield_blocklist_entries`.

## Adding a feed

Implement the `Feed` protocol in `src/slowshield/feeds/__init__.py` (`configured()` and `sync()`), turn
upstream records into `Advisory` objects and apply them with `apply_advisories()`; the scheduler, status
page and metrics pick it up automatically.
