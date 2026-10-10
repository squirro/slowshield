# Routing: one host, one path per ecosystem

Status: accepted (issue [#10](https://github.com/squirro/slowshield/issues/10)). The root contract, the
deprecation of per-ecosystem hostnames and the new Setup page are implemented. Go is served at `/go/`
([go.md](go.md)), Maven at `/maven/` ([maven.md](maven.md)), Cargo at `/cargo/` ([cargo.md](cargo.md)), NuGet at
`/nuget/` ([nuget.md](nuget.md)) and container images at `/v2/` ([oci.md](oci.md)); the other ecosystems are planned.

SlowShield serves every ecosystem from **one host**, each under a path named after its **protocol**. No
ecosystem gets its own hostname. This document is the contract for those paths, so that new ecosystems never
need a breaking change, and records how each ecosystem on the [roadmap](https://slowshield.org/#ecosystems)
fits it.

The research behind it (October 2026) read the official documentation and client source of all 20 package
systems on the roadmap and checked the live registries. Go and Cargo were also tested end to end against a
path-prefixed proxy.

## Decisions

1. **Paths, not hostnames.** Every client on the roadmap accepts a base URL with a path. The one exception is
   the OCI distribution API, which the spec puts at `/v2/` on the host root.
2. **Name the protocol, not the language.** `/npm/` rather than `/js/`, because npm, pnpm, Yarn and Bun all
   speak the npm protocol, and JSR is a second JavaScript registry. Use full names: `/huggingface/`, not `/hf/`.
3. **Single-upstream protocols** use `/<protocol>/`: `/pypi/`, `/npm/`, `/go/`, `/cargo/`. A second upstream,
   if one ever appears, gets an id (`/go/<repo-id>/`) without changing the existing URLs.
4. **Multi-upstream protocols** use `/<protocol>/<repo-id>/<path inside that repo>`:
   - Examples: `/rpm/rocky/…`, `/apt/debian/…`, `/maven/central/…`.
   - Repo ids are operator-defined in `config.toml`, with built-in ids for well-known repositories.
   - Ids are matched by the **longest configured prefix**, so an id may have several segments
     (`/rpm/custom/repo/name/…`).
   - The rest of the path is passed to that upstream unchanged.
5. **`/pypi/` and `/npm/` stay exactly as they are.** Lockfiles already record them.
6. **Per-ecosystem hostnames are deprecated and removed in 0.1.** This covers PyPI and npm, the only two
   ecosystems that ever had them, and no new ecosystem gets one. The root PyPI alias from the Rust version
   (`/simple/`, `/packages/`) goes in the same release.

## The root contract

Only these first path segments exist. `slowshield.routing` lists them, and a test fails when a route outside
them is added.

| Segment | Purpose |
|---|---|
| `/` | redirects to `/ui/` (every request) |
| `/ui/` | the whole UI, assets under `/ui/static/` |
| `/healthz`, `/readyz` | probes (Caddy, Helm, the image healthcheck) |
| `/favicon.ico` | redirect to `/ui/static/brand/favicon.ico` (browsers ask for it) |
| `/v2/` | OCI distribution API (mandated at the root by the spec): container images, served today ([oci.md](oci.md)) |
| `/.well-known/` | RFC 8615 (e.g. Terraform service discovery, if ever needed) |
| `/pypi/`, `/npm/`, `/go/`, `/maven/`, `/cargo/`, `/nuget/` | served today |
| `/rubygems/`, `/composer/`, `/helm/`, `/terraform/`, `/huggingface/`, `/apt/`, `/rpm/`, `/apk/`, `/oci/`, `/homebrew/`, `/github/`, `/github-api/`, `/openvsx/`, `/jetbrains/` | reserved for the roadmap |
| `/static/`, `/simple/`, `/packages/` | deprecated, removed in 0.1 |

If two protocols ever need the same root path:

1. Dispatch on the request signature: media types in `Accept`, the auth flow, then the `User-Agent`.
2. If that isn't reliable enough, use a dedicated listener or hostname. Proxies and CI sometimes rewrite the
   `User-Agent`.

The internal host-routing code stays for that purpose after the PyPI and npm hostname settings are removed.

## Ecosystems

| Ecosystem | Path | Global client setup | Rewriting by the proxy | Publish time | Malware data |
|---|---|---|---|---|---|
| PyPI | `/pypi/` (shipped) | `PIP_INDEX_URL`, `UV_DEFAULT_INDEX` | none (relative URLs) | `upload-time` (PEP 700) | OSV PyPI |
| npm | `/npm/` (shipped) | `npm_config_registry` | tarball URLs | `time` | OSV npm |
| Go | `/go/` (shipped, [go.md](go.md)) | `go env -w GOPROXY=https://HOST/go` (without `,direct`) | none; checksum DB passed through unchanged | `Last-Modified` of the `.mod` on proxy.golang.org (when the mirror stored it; the module time can be backdated) | OSV Go, GitHub go |
| Cargo | `/cargo/` (shipped, [cargo.md](cargo.md); `/cargo/<id>/` kept for alternative registries) | `$CARGO_HOME/config.toml` source replacement | `dl` in `config.json`; held versions marked yanked | `pubtime`, never earlier than first seen | OSV crates.io (incl. RustSec), GitHub rust |
| Maven, Gradle | `/maven/<repo-id>/` (shipped, [maven.md](maven.md): all, central, google, gradle-plugins) | `settings.xml` mirror (`mirrorOf *` → `/maven/all/`); Gradle init script | regenerate checksums of filtered metadata; follow Plugin Portal 303s on the server | `Last-Modified` per file, or first listed | OSV Maven, GitHub maven |
| NuGet | `/nuget/v3/index.json` (shipped, [nuget.md](nuget.md); `/nuget/<id>/` kept for other feeds) | `NuGet.Config` with `<clear/>` and one source named `nuget.org` | service index generated; registration and search URLs; held versions removed from the flat container, registration pages and search | registration `published`, never earlier than first seen; first listed for unlisted versions (`1900-01-01`) | OSV NuGet, GitHub nuget |
| RubyGems | `/rubygems/` (trailing `/`) | `bundle config --global mirror.https://rubygems.org …`, `~/.gemrc` | none; block the legacy Marshal index | `created_at` | OSV RubyGems |
| Composer | `/composer/` | `composer config -g repos.packagist …` | metadata URLs; `dist` mirrors keep `composer.lock` proxy-free; re-minify | `published-time` | Packagist malware list |
| Helm | `/helm/<repo-id>/`; OCI charts via `/v2/` | `helm repo add` per upstream | chart `urls` | first-seen | none |
| Terraform | `/terraform/providers/`; modules via `/terraform/<registry-host>/modules/v1/` | `~/.terraformrc` network mirror; modules via the CLI `host` block (undocumented) | `download_url`, `X-Terraform-Get` | first-seen | none |
| Hugging Face | `/huggingface/` | `HF_ENDPOINT` | `Location`; strip the Xet headers, or clients bypass the proxy | first-seen per commit | HF scan status |
| apt | `/apt/<repo-id>/` (debian, debian-security, ubuntu, ubuntu-ports, custom), also over plain http | one `sed` on `*.sources` | none (upstream tree 1:1) | snapshots | curated deny list |
| dnf / yum | `/rpm/<repo-id>/` (fedora, rocky, alma, al2023, epel, custom) | `baseurl` in `.repo` | mirrorlist / metalink / AL2023 `mirror.list` | AL2023 releasever, Fedora Bodhi, first-seen | curated deny list |
| apk | `/apk/<repo-id>/` (alpine, custom) | one `sed` on `/etc/apk/repositories` | none | first-seen (own history) | curated deny list |
| Containers | `/v2/<registry-host>/<repo>` (shipped, [oci.md](oci.md)); `/v2/<repo>` is Docker Hub, or the registry containerd names in `?ns=` | `hosts.toml` (containerd, Docker's containerd store), `registries.conf`, `buildkitd.toml`, `daemon.json` | none (byte-exact); SlowShield authenticates upstream; blob redirects followed on the server | tag→digest history: registry times (Docker Hub, Quay, Artifact Registry, MCR) and first seen | operator `[[blocks]]`, registry takedowns |
| Homebrew | `/homebrew/` (API) + bottles via `/v2/ghcr.io/…` | `/etc/homebrew/brew.env` | none (the API is JWS-signed) | whole signed snapshot | Homebrew advisories |
| GitHub Releases | `/github/<owner>/<repo>/releases/download/…` (+ `/github-api/`) | mise `url_replacements`, uv/rustup/nvm mirror variables | none | `published_at`, asset `digest` | none |
| VS Code / Open VSX / JetBrains | `/openvsx/`, `/jetbrains/`; the VS Code Marketplace only through its enterprise private-marketplace policy or generated `AllowedExtensions` pins | env vars, `idea.plugins.host`, policy | gallery manifest URLs | `timestamp` / `cdate` / `lastUpdated` | vendor malicious lists |
| GitHub Actions | **cannot be proxied**: GitHub resolves `uses:` on its servers | — | — | — | GHSA |

For GitHub Actions, SlowShield will instead generate the organisation's allowed-actions list. It contains
`OWNER/REPO@SHA` entries that are at least N days old and have no advisory. It also enables the SHA-pinning
policy and provides a linter.

## What the research changes in the design

- **First-seen tracking is a core component.** Only PyPI, npm, Cargo, RubyGems, Composer and partly NuGet
  publish trustworthy times. Go uses the mirror's storage time ([go.md](go.md)); everything else needs
  SlowShield's own record.
- **Three ways to hold back a release.** Which one applies depends on the ecosystem:
  - **Filter the version list.** This works for most language registries. Cargo uses *yanked*, which keeps
    lockfiles working.
  - **Serve older content.** For containers, serve the newest tag→digest that is old enough. For Homebrew,
    serve a whole signed snapshot.
  - **Time travel for Linux distributions.** Serve upstream's own signed metadata as of N days ago:
    - Debian, Ubuntu and AL2023 use the official snapshot services.
    - Alpine, Fedora, Rocky and Alma use history that SlowShield records itself.

    Filtering won't work here:
    - Debian, Ubuntu, Alpine and Fedora updates delete superseded versions, so there is nothing older to
      fall back to.
    - Filtering an apt or apk index would mean re-signing it, which makes SlowShield a signing root. It
      doesn't.

    Security suites get their own delay, defaulting to 0. apt is also served over plain http: stock Debian
    and Ubuntu images can't do HTTPS, and the distribution signatures protect integrity.
- **Never modify signed or content-addressed bytes.** That covers the Go checksum DB, OCI manifests, NuGet
  packages, Homebrew JWS and apt `InRelease`.
- **Mirror mode is soft control.** These clients fall back to the upstream when the mirror returns an error:
  Docker's classic image store, BuildKit, containerd with SlowShield as a mirror `[host]`, Homebrew, Go
  `,direct`, extra NuGet sources and Bundler. The setup docs pair each ecosystem with its no-fallback option
  (for images: containerd's `server`, Podman's `location`, checked with real clients in [oci.md](oci.md)) and
  recommend an egress firewall for hard enforcement.
- **One public base URL per deployment** drives all URL rewriting.

## Deprecated until 0.1

| What | Replacement |
|---|---|
| `upstreams.pypi.hostnames`, `SLOWSHIELD_PYPI_HOSTNAMES`, Helm `ecosystems.pypi.hostnames` | `<public_url>/pypi/simple/` |
| `upstreams.npm.hostnames`, `SLOWSHIELD_NPM_HOSTNAMES`, Helm `ecosystems.npm.hostnames` | `<public_url>/npm/` |
| root `/simple/…`, `/packages/…` | `/pypi/simple/…`, `/pypi/packages/…` |
| `/static/…` | `/ui/static/…` (301) |

How the deprecated forms behave until 0.1:

- **They keep working.** Configured hostnames log a startup warning, and the Setup page shows a notice with
  the path URLs.
- **Usage is counted.** `slowshield_legacy_routing_requests_total{route}` counts every request that still
  uses one of them. When it stays at zero, the deployment is ready for 0.1.
- **npm tarball links follow the route the client used.** Requests under `/npm/` get path links, so new
  lockfiles never record a hostname. Only requests on a deprecated npm hostname keep host links.

## Setup page

[#10](https://github.com/squirro/slowshield/issues/10), implemented:

- **Follow slowshield.org.** Same steps: start, try it, use it for everything. The global shell setup has tabs
  for bash (Linux), bash (macOS), zsh and fish, filled in with this instance's URLs. The visitor's OS is
  detected and preselected, and the choice is remembered. Python installs go into a virtualenv. Per-tool
  snippets move into a collapsed section.
- **One snippets data file** is shared by the website build and the UI.
- **CI runs every published snippet** in bash, zsh and fish containers, and against old pip versions, on the
  e2e stack.

## Not decided yet

- Whether re-signing distribution indexes is ever offered (an opt-in mode); time travel needs no key.
