# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Overview: three upstream-offload figures (traffic saved, fetched from upstream, upstream requests saved) and a
  1-hour range backed by 5-minute rollups (schema migration 2).
- `SLOWSHIELD_LOCAL_HTTP`: plain HTTP for localhost so local clients work without trusting Caddy's CA; the
  Setup page and npm tarball URLs follow it.

### Changed
- Release images are published to `ghcr.io/squirro/slowshield` and `ghcr.io/squirro/slowshield-caddy`;
  every push to `main` publishes dev images to the internal registry (`docs/releasing.md`).
- Metadata caching uses far less memory. Upstream documents and rendered responses live in one SQLite
  file shared by all workers (`data_dir/metadata-cache.db`, `cache.metadata_max_mb`, default 1 GB), so a
  document fetched by one worker is served by all of them and survives restarts. Workers keep only parsed
  documents and small responses in memory, within `cache.metadata_memory_mb` (new, default 64 MB in total
  across workers), sized from measured object sizes. SQLite reader page caches are smaller, and `serve` warns
  when the workers and the memory budget do not fit the container's memory limit.
- New brand: the Inbound mark, Night Field palette and an outlined Schibsted Grotesk wordmark across the UI,
  Grafana dashboards and README.

### Fixed
- Workers were killed for running out of memory under load (2 workers in 1 GiB): each kept its own
  in-memory metadata cache, which counted neither parsed objects nor rendered responses, and tarball requests
  each held a full packument (30 MB for firebase). Tarballs now use a compact per-package index, full
  documents are loaded at most two at a time per worker, and the image limits glibc malloc arenas so freed
  memory goes back to the OS.
- Every npm download streamed from upstream logged `ASGI transport error: "Closed(..)"`: the empty final
  HTTP/2 frame was forwarded as an extra body message after the response was complete.
- Known-malicious versions that the registry has since removed returned 404; they are now refused with 451
  and recorded as blocked, so a lockfile pinned during an attack window shows up as a security event.
- The database writer's flush-duration histogram was never recorded.

## [1.0.0] - unreleased

First open-source release: a rewrite of the internal Rust SlowShield (v0–v8) in Python 3.15.

### Added
- PyPI simple API (PEP 503/691, JSON and HTML, PEP 658 metadata, PEP 700 upload times, PEP 740
  provenance links) with **per-file** release-age filtering.
- npm registry proxy: full and abbreviated (`application/vnd.npm.install-v1+json`) packuments, scoped
  packages, dist-tag recomputation, preserved signatures/attestations, `npm audit` pass-through.
- Release-age enforcement on **direct downloads** (403 + `Retry-After`), closing the lockfile bypass.
- Verified on-disk artifact cache (content-addressed, LRU, periodic scrub, zero-copy serving).
- Integrity verification against registry digests (sha256, PyPI path blake2b-256, npm sha512/sha1) in
  addition to trust-on-first-use fingerprints; tampered downloads are aborted before completion.
- OSV incremental sync and GitHub Advisory REST feed with version ranges and withdrawn advisories; the
  GitHub feed is optional and reports `missing_token` in the UI and metrics.
- New UI: dashboard with trends, package explorer and detail pages, leaderboards (incl. new dependencies),
  security timeline with CSV export, blocklist explorer, feed status, client setup snippets.
- OpenTelemetry traces, metrics and logs; Grafana stack examples (Alloy, Prometheus, Loki, Tempo, Grafana)
  with dashboards and alert rules for Docker Compose, rootless Podman (Quadlet) and Kubernetes (Helm).
- Caddy front end with TLS 1.3, post-quantum hybrid key exchange, HTTP/3, ACME / file / internal CA modes.
- Distroless Amazon Linux 2023 images (amd64 + arm64), non-root, read-only.
- Performance A/B regression gate on every release.
- `slowshield import-legacy` to migrate fingerprints, blocklist, events and stats from the Rust version.

### Fixed (compared to the Rust version)
- Brand-new PyPI versions could slip through the release-time cache.
- Failing open re-added blocklisted PyPI files; PyPI JSON-API failures returned unfiltered upstream HTML.
- Release time per version was taken from its first file only; filenames were split on the first `-`.
- Missing PEP 503 normalisation in blocklist and exception matching.
- npm `latest` could point at a blocked version; npm signatures/attestations were dropped; tarball URLs
  were hard-coded to `http://`.
- Concurrent first downloads could fail with a checksum insert race; artifacts were fully buffered in
  memory with a 30-second total timeout.
- UI values were not HTML-escaped; no security headers were sent.
