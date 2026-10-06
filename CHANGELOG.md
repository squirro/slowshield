# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.0.6] - 2026-10-06

### Added
- Maven repositories at `/maven/` for Maven, Gradle, sbt and Coursier ([docs/design/maven.md](docs/design/maven.md),
  https://github.com/squirro/slowshield/issues/18). `/maven/all/` serves Maven Central and Google Maven behind one
  URL for a `settings.xml` mirror; `/maven/central/`, `/maven/google/` and `/maven/gradle-plugins/` serve each
  repository (Gradle's init script uses those), and operator repositories go under `/maven/<id>/`.
  - `maven-metadata.xml` leaves out versions that are too new or blocked, with `<latest>`/`<release>` and the
    checksum files recomputed. Files that are too new get `425 Too Early`, which Maven and Gradle show as the reason
    and re-request on the next build. Malware gets `451`; upstream failures `503`, never a `404` Maven would cache.
  - A file's publish time is its `Last-Modified` on the repository, or when SlowShield first saw the version listed,
    whichever is earlier, so a file added to an old version later is held on its own.
  - Downloads are checked against Central's `x-checksum-sha1`, the `.sha1` file, or the sha256 in the Plugin
    Portal's path, and fingerprinted. Responses carry `X-Checksum-Sha1`, so Maven skips checksum requests.
  - OSV and GitHub malware advisories for Maven feed the blocklist, matched in Maven's version order (`1.0` = `1.0.0`).
  - Metadata SlowShield can't filter is refused with `503`, never passed on unfiltered.
  - A cached file is judged again by its own recorded `Last-Modified` (migration `0004_artifact_published`), so it is
    held again when the policy gets stricter, without a request upstream.
- `fail_open` per ecosystem (`upstreams.<ecosystem>.fail_open`). Maven defaults to off: brand-new artifacts are held.
- The Setup page has Maven (`settings.xml`), Gradle (init script), sbt and Coursier.

### Changed
- Maven is shown in Java orange `#ED8B00` (Maven's own red is too close to npm's), in the UI and in Grafana.
- CI: the performance comparison on pull requests (k6 against the base branch, and the micro benchmarks) can be
  skipped with the `skip-perf` label. Releases no longer run a performance gate against the previous release,
  only the end-to-end tests and the observability smoke test on the release images.

## [0.0.5] - 2026-10-05

### Added
- Go modules at `/go/`: set `GOPROXY=https://<host>/go` (without `,direct`). Versions younger than the delay are left
  out of version lists, and requests for them get `403` with a `Retry-After` header and a message the go command
  prints. Known malware gets `451`, never `404`/`410`, so a `,direct` fallback can't go around SlowShield either.
  `.mod` and `.zip` downloads are checked against the `h1:` hashes in `sum.golang.org` and against their first-seen
  fingerprint. The checksum database itself is proxied at `/go/sumdb/sum.golang.org/`, so clients need no other
  route out. A version's publish time is when proxy.golang.org first stored it (the `Last-Modified` of its `.mod`),
  never the commit time, which authors can backdate. It is looked up once per version, at no extra load on the
  upstreams beyond one `HEAD` ([docs/design/go.md](docs/design/go.md),
  https://github.com/squirro/slowshield/issues/15). `@latest` of a module without tags answers with the newest
  commit known to be old enough when the newest one is too new. OSV and GitHub malware advisories for Go feed the
  blocklist.
  Configuration: `[upstreams.go]`, `SLOWSHIELD_GO_ENABLED`, Helm `ecosystems.go.enabled`.
- The Setup page and slowshield.org set `GOPROXY` in the shell setup, and the tool finder has Go.
- A nightly check that proxy.golang.org's `Last-Modified` still matches index.golang.org, and Go perf scenarios
  (`go_list`, `go_mod`). The perf gate reports a scenario the baseline release doesn't serve yet without comparing it.

### Changed
- Ecosystems are shown in their logos' primary colours, in the UI and the Grafana dashboards: PyPI `#3775A9`, npm
  `#CB3837`, Go `#00ADD8`, the same in light and dark mode.

### Fixed
- Chart axes in the UI show round, distinct values, with each gridline at its value. Small counts used to repeat
  labels (a peak of 2 read `0, 1, 2, 2`).

## [0.0.4] - 2026-10-04

### Added
- The Setup page follows slowshield.org: one global shell setup (bash on Linux, bash on macOS, zsh, fish) filled in
  with this instance's URLs and preselected from the visitor's OS, a one-line install to try it, a tool finder (type
  `poe` for Poetry, `ya` for Yarn) for pip, uv, Poetry, PDM, Pipenv, npm, pnpm, Yarn and Bun, and CI/Dockerfile
  snippets. Its shell and install snippets come from the same file as the website's
  (`src/slowshield/ui/snippets.toml`), and an end-to-end test runs every one of them in bash, zsh and fish against
  the stack, including Debian 12's pip 23.0.1.

### Changed
- One host, one path per ecosystem ([docs/design/routing.md](docs/design/routing.md)). The UI lives entirely
  under `/ui/`: the dashboard moved from `/` to `/ui/` (`/` redirects there) and assets from `/static/` to
  `/ui/static/`. The root paths SlowShield answers on are a fixed list, with names reserved for every ecosystem
  on the roadmap.
- The Setup page shows path URLs only (`/pypi/simple/`, `/npm/`).

### Deprecated
- Per-ecosystem hostnames (`upstreams.pypi.hostnames` / `SLOWSHIELD_PYPI_HOSTNAMES`, `upstreams.npm.hostnames` /
  `SLOWSHIELD_NPM_HOSTNAMES`, Helm `ecosystems.*.hostnames`), the root PyPI alias (`/simple/`, `/packages/`) and
  `/static/`. They keep working until 0.1, log a startup warning (hostnames), show a notice on the Setup page,
  and are counted in `slowshield_legacy_routing_requests_total` so operators can see when nothing uses them.

### Security
- Values shown in copy-paste shell snippets can no longer carry shell syntax (reported by Aikido). With
  `local_http` on, a loopback `Host` header such as `localhost:$(id)` was echoed into the Setup page and npm
  tarball links; only well-formed hosts with a numeric port qualify now. `public_url` and
  `upstreams.npm.public_url` must be plain `http(s)://host[:port][/path]` URLs (no query, credentials or
  special characters), and the snippet renderer refuses anything else. A config with such a URL now fails to
  load instead of being served.

### Fixed
- The UI's CSS and JavaScript URLs are versioned by content instead of the release, so an image rebuilt under the
  same version no longer leaves browsers on stale assets.
- With npm hostnames configured, clients using `/npm/` got tarball links on the npm hostname, which then ended
  up in their lockfiles. Tarball links now follow the route the client used.

## [0.0.3] - 2026-10-04

0.0.2 was tagged but never published: its release stopped at the performance gate, which counted the expected
HTTP 451 responses of the blocked-package scenario as errors. 0.0.3 has the same changes plus that fix.

### Fixed
- pip 22.3 to 23.1, including Debian 12's pip 23.0.1, crashed (`TypeError: unhashable type: 'dict'`) on every
  install through the JSON simple index: it carried the metadata hashes under the `dist-info-metadata` key that
  PEP 714 retired. The index now uses `core-metadata` and `data-dist-info-metadata`, as PyPI does, and its ETag
  changes with the rendering, so clients holding the old index fetch the new one.
- Quick start (README and website): the install example runs pip in a throwaway virtualenv, since Homebrew and
  current Linux Pythons refuse pip installs outside one, and bash on macOS gets its own shell setup
  (`~/.bash_profile`, which Terminal's login shells read).
- A failed feed sync, for example with the registry unreachable at startup, was retried only after the poll
  interval (60 minutes by default), so a fresh install could run that long without a malware blocklist. Failed
  syncs are now retried after 1, 2, 4 ... minutes, up to the poll interval.
- Release performance gate: the blocked-package scenario treats 451 as success, the harness waits for its fake
  registry and for the malware feed before measuring, and pull requests run the scenario too.

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
