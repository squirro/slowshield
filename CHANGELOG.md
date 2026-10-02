# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
