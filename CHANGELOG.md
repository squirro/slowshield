# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.0.8] - 2026-10-07

### Added
- Shield wall: several instances standing together, one leader and many followers
  ([docs/design/shieldwall.md](docs/design/shieldwall.md), https://github.com/squirro/slowshield/issues/34).
  - Pairing: `slowshield shieldwall invite` on the leader prints a join string (single use, 10 minutes); a follower
    started with it (`SLOWSHIELD_JOIN`) checks the leader's key and asks for a click on Join on its new Shield wall
    page (`SLOWSHIELD_JOIN_CONFIRM=auto` skips it). Every message is signed with the instances' Ed25519 keys.
  - The leader's overview, security timeline and CSV cover every instance, and narrow to one, a location or a label.
    Followers report their statistics and events exactly once, including their history at pairing and what they
    queued while the leader was away.
  - Followers take the leader's policy and blocks: stricter settings at once, looser ones after an hour and never
    below `SLOWSHIELD_SHIELDWALL_MIN_DELAY_DAYS` (1 day); a block the leader lifts stays a day. Their own stricter
    settings and their own exceptions stay in force. Takedowns, tamper flags, tag history and Maven and Cargo listing
    times come down too, with the leader's observation times bounded by how recently the follower synced.
  - Package files come through the leader's cache when it is up (`SLOWSHIELD_SHIELDWALL_VIA_LEADER`), checked by the
    follower as always; a follower that can't reach its leader works on its own.
  - The leader compares every follower's first fingerprint of a file with its own; a follower that saw different
    bytes refuses the file, and the leader records it.
- Container images at `/v2/`, the OCI distribution API, for pulls ([docs/design/oci.md](docs/design/oci.md),
  https://github.com/squirro/slowshield/issues/22). Built in: docker.io, ghcr.io, quay.io, registry.k8s.io, gcr.io,
  mcr.microsoft.com and public.ecr.aws.
  - Tags lag behind: a tag resolves to the newest digest it has pointed to for the delay, so `nginx:latest` keeps
    working, about a week behind. A tag's time is when it got that digest: from the Docker Hub API, Quay's tag
    history, Artifact Registry's upload times or MCR's catalog where the registry has one, and SlowShield's own
    first sight, whichever is earlier.
  - A pinned digest that is too new, a blocked image and a digest the registry took down are refused with `403` and
    a message Docker, Podman, BuildKit, skopeo and crane print (containerd 2.2 and older show only the status).
  - During an instance's first `default_delay_days`, tags it has no history for are served at their current digest
    and recorded as fail-open; `upstreams.oci.fail_open = false` is strict from the start.
  - Manifests are checked against their digests and kept by digest; blobs are checked while streaming. Layers aren't
    stored unless `upstreams.oci.layer_cache_gb` is above 0, which keeps them in a separate store (Helm:
    `persistence.ociLayers`). Redirects go only to each registry's `download_hosts`, without the registry token.
  - Docker Hub pulls: tags are resolved with `HEAD`, which doesn't count, and each manifest is fetched once for all
    clients. `username` and `token_file` add a Docker Hub token; `slowshield_oci_ratelimit_remaining` shows what is
    left.
  - The Setup page has containerd and Kubernetes, Docker, Podman (also CRI-O, Buildah and skopeo), BuildKit and
    image names, checked with the real clients: containerd, Docker's containerd image store and Podman don't go
    around SlowShield; BuildKit and Docker's classic store pull from the registry after a refusal, which the page
    says. The package page shows every digest each tag pointed to.
- Operator blocks for every ecosystem: `[[blocks]]` in `config.toml` refuses a package, a version, or an image
  repository, tag or digest, like a malware advisory. They apply on reload and are listed with source `config`.
- The Setup page links every tool to its guide on slowshield.org.

### Changed
- The shipped configs (Compose, Podman, Helm) leave `default_delay_days`, `enforce_age_on_download` and `fail_open` at
  their defaults, commented out: set, they also count against a shield wall leader's policy.
- Caddy no longer applies the 16 KB request body limit on top of the 10 MB one for `npm audit`.
- The UI names ecosystems by language, as slowshield.org does: Python, JavaScript, Go, Java, Rust and Containers
  instead of PyPI, npm, Go, Maven, Cargo and OCI. URLs, config, metrics and CSV exports keep the ids (`pypi`, `npm`,
  …).
- Digests are shortened wherever the UI shows a version (`sha256:3734a9c4892e…`), with the full value on hover.

### Fixed
- Links from the security events to a package that was only ever refused, never served, led to "not found"; such a
  package now has a page.

## [0.0.7] - 2026-10-06

### Added
- Cargo at `/cargo/`: a sparse registry that replaces crates-io in `$CARGO_HOME/config.toml`
  ([docs/design/cargo.md](docs/design/cargo.md), https://github.com/squirro/slowshield/issues/16). Cargo.lock keeps
  crates.io as its source and checksums. Needs cargo 1.68 or later.
  - Index files pass through byte for byte, except that versions too new or blocked are marked
    `"yanked":true`, so cargo resolves to an older version. A Cargo.lock that pins one gets `403` with the time it
    becomes available and the `cargo update --precise` command for the newest version allowed; malware gets `451`.
    Cargo prints both. Upstream failures are `503`, which cargo retries.
  - A version's publish time is its `pubtime` in the index, which crates.io sets. The first one seen is kept, so a
    rewritten index can't move it earlier. No requests to the crates.io API.
  - Downloads are checked against the index's `cksum` (sha256) and fingerprinted; static.crates.io is always asked
    for the index's exact spelling of the name.
  - Crate names match in crates.io's canonical form (lower case, `-` as `_`) in exceptions, advisories and the UI.
  - `fail_open` is off for Cargo: crates none of whose versions is old enough are held too.
- The OSV feed also takes RustSec's malware advisories (category `malicious`) that have no `MAL-*` counterpart: most
  crates RustSec reports as malware never got one. GitHub's malware advisories for Rust are read too.
- The Setup page has Cargo: the `config.toml`, and a one-line command for CI and Dockerfiles (the official `rust`
  images set `CARGO_HOME`, so `~/.cargo` isn't read there).

- The Setup page also sets the package managers' own release age, 3 days, where they have one (pip, uv, Poetry,
  PDM, npm, pnpm, Yarn, Bun), as a second layer: a release then still waits on a machine that goes around
  SlowShield, or when SlowShield serves a brand-new package because nothing is old enough yet (fail-open). In
  normal use only SlowShield holds anything, since its delay is longer. A switch turns it off; each tool shows the
  version it needs, and what older versions do with the setting. Never more than SlowShield's own delay. uv's and
  PDM's go in `pyproject.toml` only: uv records the setting in `uv.lock` (an environment variable on one machine
  breaks `uv sync --locked` on another), and PDM doesn't keep its command-line flag.

### Changed
- Cargo is shown in `#DEA584` (GitHub's Rust colour) in the UI and in Grafana.

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
  skipped with the `skip-perf` label, and release pull requests (branches `release-*`) skip it. Releases no longer
  run a performance gate against the previous release, only the end-to-end tests and the observability smoke test
  on the release images.

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
