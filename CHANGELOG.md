# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.0.1] - 2026-10-02

First open-source release, in Python 3.15.

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
- Known-malicious versions that the registry has since removed are refused with 451 and recorded as blocked,
  so a lockfile pinned during an attack window shows up as a security event.
- Web UI: dashboard with trends and upstream-offload figures (traffic saved, fetched from upstream, upstream
  requests saved) from a 1-hour range up, package explorer and detail pages, leaderboards (incl. new
  dependencies), security timeline with CSV export, blocklist explorer, feed status, client setup snippets.
- Low memory use: upstream documents and rendered responses live in one SQLite file shared by all workers
  (`data_dir/metadata-cache.db`, `cache.metadata_max_mb`, default 1 GB) and survive restarts; workers keep
  only parsed documents and small responses in memory, within `cache.metadata_memory_mb` (default 64 MB
  across workers). `serve` warns when the workers and the memory budget do not fit the container's memory
  limit.
- `SLOWSHIELD_LOCAL_HTTP`: plain HTTP for localhost so local clients work without trusting Caddy's CA; the
  Setup page and npm tarball URLs follow it.
- OpenTelemetry traces, metrics and logs; Grafana stack examples (Alloy, Prometheus, Loki, Tempo, Grafana)
  with dashboards and alert rules for Docker Compose, rootless Podman (Quadlet) and Kubernetes (Helm).
- Caddy front end with TLS 1.3, post-quantum hybrid key exchange, HTTP/3, ACME / file / internal CA modes.
- Distroless Amazon Linux 2023 images (amd64 + arm64), non-root, read-only, published as
  `ghcr.io/squirro/slowshield` and `ghcr.io/squirro/slowshield-caddy` with SBOM and provenance attestations.
- Performance A/B regression gate on every release.

### Security
- `slowshield-caddy` ships Caddy 2.11.6 built with Go 1.26.8, which fixes 32 known vulnerabilities in Caddy
  2.11.4's Go standard library and bundled modules (x/crypto, x/net, x/text, grpc, OpenTelemetry, cel-go),
  including CVE-2026-39821 (critical). Taken inside the 7-day dependency cooldown as a security exception,
  after verifying the release's cosign signature and checksums.
