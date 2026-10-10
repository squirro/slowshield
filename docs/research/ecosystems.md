# Ecosystem feasibility

SlowShield needs three things from an ecosystem: a way to point clients at a proxy, a **trustworthy**
per-version publish time, and metadata it can filter without breaking a signature the client verifies.

| Ecosystem | Point clients at a proxy | Publish time | Integrity / signing | Rating | Why |
|---|---|---|---|---|---|
| PyPI | index URL (pip, uv, Poetry, PDM) | PEP 700 `upload-time` (server) | sha256 in index, lockfiles | **live** | |
| npm (+pnpm, Yarn, Bun) | `registry` / `npmRegistryServer` / bunfig | `time` map (server) | `dist.integrity`, signatures | **live** | Yarn Berry ignores `.npmrc` |
| Cargo | `source.crates-io.replace-with` → sparse | `pubtime` (server) | index `cksum` → Cargo.lock | **live** | unsigned line-JSON index; held versions marked yanked; see [design/cargo.md](../design/cargo.md) |
| Go modules | `GOPROXY` (no `,direct`) | `.info` Time is **commit time** → the `Last-Modified` of the `.mod` on proxy.golang.org (when the mirror stored it; equals the index.golang.org `Timestamp`) | go.sum + sum.golang.org (only `.mod`/`.zip`) | **live** | spec: lists and `.info` are not authenticated, filtering allowed; MVS → refuse, don't hide. Tailing index.golang.org was rejected: ~100k entries/day, see [design/go.md](../design/go.md) |
| NuGet | `NuGet.Config` `<clear/>` + one source named `nuget.org` | registration `published` (1900-01-01 while unlisted) | repo signature inside `.nupkg`; catalog `packageHash` (SHA512) | **live** | held versions left out of the flat container, registration and search; see [design/nuget.md](../design/nuget.md) |
| RubyGems | `bundle config mirror.…` | compact index `created_at` | sha256 per version; Gemfile.lock CHECKSUMS | medium | `/versions` stores MD5 of each info file → rewrite consistently |
| Maven Central / Gradle / sbt | `settings.xml` mirror; Gradle repositories/init script | none per version in `maven-metadata.xml` → `Last-Modified` of immutable POM/JAR | `.sha1`/`.md5` sidecars (unsigned), `.asc` | **live** | exact pins → refuse (`425`), not downgrade; see [design/maven.md](../design/maven.md) |
| OCI images | containerd `hosts.toml` `server`, podman `registries.conf` `location`; dockerd's classic mirrors only Docker Hub and fall back | none in the API; image `created` is builder-set → registry APIs (Docker Hub, Quay, Artifact Registry, MCR) and first sight | digests; cosign/notation bound to digest | **live** | mutable tags → tag→digest history and time travel; see [design/oci.md](../design/oci.md) |
| Terraform / OpenTofu providers | `provider_installation { network_mirror }` | `published-at` / `published` | lockfile `h1:`/`zh:` | easy | modules from git are hard |
| Helm | `helm repo add` | index.yaml `created` (indexer) | `digest`, optional `.prov` | easy | every publisher hosts its own repo |
| pub.dev | `PUB_HOSTED_URL` | `published` | `archive_sha256` | easy | |
| Deno / JSR | `JSR_URL` (undocumented) | `createdAt` | per-file sha256 | easy | |
| JetBrains plugins | `idea.plugins.host` | `cdate` per update | Marketplace re-signs; custom repo warns | medium | |
| CRAN | `options(repos=)` | `Published:` | MD5 only | medium | rewrite too-new to the Archive copy via `Path:` |
| conda | `.condarc` `channel_alias` | repodata `timestamp` = build time (packager-set) | sha256 | medium | shards, `.jlap`, `current_repodata` |
| Hugging Face | `HF_ENDPOINT` | commit `date`, `lastModified` | sha256 (`X-Linked-Etag`) | medium | Xet CAS redirects bypass the endpoint |
| Composer | `repositories` + `packagist.org: false` | p2 `time` is **author-controlled** | `dist.shasum` often empty; GitHub zipballs | medium | needs first-seen ledger, URL rewriting |
| Julia | `JULIA_PKG_SERVER` | none (git history) | tree SHA1 | medium | serve filtered registry under new hash |
| Bazel (BCR) | `--registry` | none (git history) | SRI `integrity` | medium | sources live on GitHub |
| dnf / yum | `.repo` `baseurl` | `<time build=>` (packager) | RPM GPG; repomd GPG if `repo_gpgcheck` | medium | regenerate repomd; re-sign only with `repo_gpgcheck=1` |
| apt / deb | sources.list + `signed-by` | none per package | InRelease GPG chain | hard | re-sign with an org key |
| Alpine apk | `/etc/apk/repositories` | `t:` build time | signed APKINDEX | hard | org key in `/etc/apk/keys` |
| Homebrew | `HOMEBREW_API_DOMAIN`, `HOMEBREW_BOTTLE_DOMAIN` | only `generated_date`; one rolling version | JWS-signed API, bottle sha256 | hard | cache + refuse only |
| Hex | `HEX_MIRROR` | `published_at` inside **signed** protobuf | RSA-signed registry | hard | refuse at download; Hex has its own cooldown |
| CocoaPods / SwiftPM (git) | Podfile source / git mirrors | none trustworthy | git revisions | hard | trunk goes read-only 2026-12-02 |
| GitHub Releases | none (URLs hard-coded) | `published_at`, `immutable` | asset `digest` | hard | needs forward proxy |
| Nix | `substituters` | none | signed narinfo | n/a | gate the flake input revision instead |

## Cross-cutting

* **Who sets the timestamp matters more than whether there is one.** Server-set: PyPI, npm, crates, RubyGems,
  NuGet, pub, JSR, Hex, CRAN, index.golang.org and proxy.golang.org's `Last-Modified`. Author/builder-set: Go `.info`, Packagist, conda, apk, RPM, OCI
  `created`, Helm, git. → build one **first-seen ledger** shared by all adapters.
* **Signed metadata can't be filtered** (apt, apk, Homebrew, Hex, Nix, dnf with `repo_gpgcheck`): refuse at
  download (fail closed), opt-in re-signing with an org key, or rely on the client's own gate.
* **Exact-pin ecosystems** (Go MVS, Maven, Bazel, Nix): hiding a version breaks the build instead of
  downgrading; return a clear refusal and align with Renovate `minimumReleaseAge` / Dependabot `cooldown`.
* **Client-side age gates now exist** (npm `min-release-age`, pnpm `minimumReleaseAge`, Yarn `npmMinimalAgeGate`,
  Bun, Deno, uv `exclude-newer`, pip `--uploaded-prior-to`, Cargo `min-publish-age`, Hex, Bundler). They all read
  the registry timestamps, so SlowShield must **preserve, never invent** `upload-time` / `time` / `pubtime`.
  SlowShield's value: central enforcement, also for clients without a gate (Maven, NuGet, Go, pub) and for
  developers who switch theirs off.

## Proposed phases

1. **Shipped:** Go, Maven/Gradle, Cargo, OCI images (https://github.com/squirro/slowshield/issues/22) and NuGet
   (https://github.com/squirro/slowshield/issues/38).
2. **Then:** RubyGems, Terraform/OpenTofu, pub.dev, JSR, Helm, JetBrains; compatibility tests for
   pnpm/Yarn/Bun.
3. **Later:** conda, CRAN, Hugging Face, Composer, Julia, Bazel (each needs a custom adapter).
4. **Opt-in only:** apt/dnf/apk re-signing, Hex/Homebrew refuse-at-download, GitHub Releases forward proxy.

Sources: go.dev/ref/mod · index.golang.org · rust-lang RFC 3923 (cargo min-publish-age) · rubygems.org/info ·
api.nuget.org v3 registration · repo.packagist.org p2 + composer#12793 · hexpm/specifications registry-v2 ·
pub.dev API · cloud.r-project.org PACKAGES · conda-forge repodata · docs.brew.sh security · Alpine APKINDEX ·
docs.docker.com mirror · helm.sh chart repository · Terraform provider network mirror protocol ·
huggingface_hub env vars · api.github.com releases · bcr.bazel.build · pkgdocs.julialang.org protocol ·
jsr.io meta.json · cooldowns.dev.
