# Configuration

SlowShield reads, in increasing order of precedence:

1. built-in defaults,
2. a TOML file — `$SLOWSHIELD_CONFIG`, else `/etc/slowshield/config.toml`, else `./config.toml`,
3. environment variables (and `*_FILE` variants for secrets).

The annotated reference is [`config.example.toml`](../config.example.toml).

## Environment variables

| Variable | Config key | Notes |
|---|---|---|
| `SLOWSHIELD_CONFIG` | — | path to the TOML file |
| `SLOWSHIELD_BIND` | `bind_address` | `host:port` |
| `SLOWSHIELD_PUBLIC_URL` | `public_url` | external URL of the UI host, used in setup snippets and as default npm base |
| `SLOWSHIELD_NPM_PUBLIC_URL` | `upstreams.npm.public_url` | base URL written into npm tarball links |
| `SLOWSHIELD_LOCAL_HTTP` | `local_http` | with Caddy's switch of the same name: offer `http://localhost` in the Setup page and npm tarball links (Compose default `on`) |
| `SLOWSHIELD_DATA_DIR` | `data_dir` | SQLite DB, artifact cache, leader lock |
| `SLOWSHIELD_DATABASE_PATH`, `DATABASE_URL` | `database_path` | `DATABASE_URL` takes `sqlite:/path` |
| `SLOWSHIELD_WORKERS` | `workers` | Granian workers |
| `SLOWSHIELD_DEFAULT_DELAY_DAYS` | `default_delay_days` | float |
| `SLOWSHIELD_PYPI_HOSTNAMES`, `SLOWSHIELD_NPM_HOSTNAMES` | `upstreams.*.hostnames` | **deprecated, removed in 0.1**; space/comma separated |
| `SLOWSHIELD_PYPI_ENABLED`, `SLOWSHIELD_NPM_ENABLED`, `SLOWSHIELD_GO_ENABLED`, `SLOWSHIELD_MAVEN_ENABLED`, `SLOWSHIELD_CARGO_ENABLED`, `SLOWSHIELD_OCI_ENABLED` | `upstreams.*.enabled` | booleans |
| `SLOWSHIELD_ENFORCE_AGE_ON_DOWNLOAD` | `enforce_age_on_download` | |
| `SLOWSHIELD_FAIL_OPEN` | `fail_open` | |
| `SLOWSHIELD_RECORD_CLIENT_IP` | `record_client_ip` | |
| `SLOWSHIELD_TRUSTED_PROXIES` | `trusted_proxies` | CIDRs whose `X-Forwarded-For` is honoured |
| `SLOWSHIELD_ARTIFACT_CACHE`, `SLOWSHIELD_ARTIFACT_CACHE_MAX_GB` | `cache.artifacts_*` | |
| `SLOWSHIELD_FEED_OSV`, `SLOWSHIELD_FEED_GITHUB` | `feeds.*.enabled` | |
| `GITHUB_TOKEN` / `GITHUB_TOKEN_FILE` | `feeds.github_advisory.api_key` | the file variant wins; prefer it |
| `SLOWSHIELD_SHIELDWALL_ROLE` | `shieldwall.role` | `leader` makes this instance a shield wall leader ([docs/design/shieldwall.md](design/shieldwall.md)) |
| `SLOWSHIELD_JOIN`, `SLOWSHIELD_JOIN_FILE` | `shieldwall.join` | a follower's join string; `SLOWSHIELD_JOIN_CONFIRM=auto` joins without the click on the Shield wall page |
| `SLOWSHIELD_INSTANCE_NAME`, `SLOWSHIELD_INSTANCE_LOCATION`, `SLOWSHIELD_INSTANCE_LABELS` | `shieldwall.name`, `.location`, `.labels` | how a leader shows and filters this instance; labels as `env=prod,team=ml` |
| `SLOWSHIELD_SHIELDWALL_MIN_DELAY_DAYS` | `shieldwall.min_delay_days` | no delay from the leader goes lower (default 1) |
| `SLOWSHIELD_SHIELDWALL_VIA_LEADER` | `shieldwall.via_leader` | fetch package files through the leader (default on) |
| `SLOWSHIELD_LEADER_CA_FILE` | `shieldwall.leader_ca_file` | a leader whose certificate a private CA signed |
| `SLOWSHIELD_LOG_LEVEL`, `SLOWSHIELD_LOG_FORMAT` | — | `info`…; `json` (default in containers) or `text` |
| `SLOWSHIELD_ACCESS_LOG` | — | `1` enables Granian access logs (Caddy already logs requests) |
| `SLOWSHIELD_TRACE_SAMPLE_RATIO` | — | head sampling ratio (default 0.1) unless `OTEL_TRACES_SAMPLER` is set |
| `OTEL_*` | — | standard OpenTelemetry SDK variables; telemetry is off without an OTLP endpoint |

Local development: `uv run slowshield serve` also loads a `.env` file from the working directory
(python-dotenv) without overriding variables that are already set.

## Routing

One host serves everything, each ecosystem under a path named after its protocol: PyPI at `/pypi/simple/`,
npm at `/npm/`, Go modules at `/go/` (`GOPROXY`, [design/go.md](design/go.md)), Maven at `/maven/<repo-id>/`
([design/maven.md](design/maven.md)), Cargo at `/cargo/` ([design/cargo.md](design/cargo.md)), and container images
at `/v2/`, the path the OCI distribution API requires ([design/oci.md](design/oci.md)). The UI lives under `/ui/` (`/` redirects there), probes at `/healthz` and `/readyz`. Only
these and the names reserved for future ecosystems may be used at the root; see
[design/routing.md](design/routing.md) for the contract and the plan for every ecosystem on the roadmap.

PyPI file links are relative, so they work behind any prefix without trusting the `Host` header. npm
requires absolute tarball URLs; they are built from `upstreams.npm.public_url`, or `public_url + /npm`,
never from request headers. Cargo's `config.json` points downloads at `public_url + /cargo/crates` (or the local
HTTP origin). The Go module proxy protocol has no URLs in its responses.

## Go

```toml
[upstreams.go]
enabled = true
mirrors = ["https://proxy.golang.org"]
sumdb_url = "https://sum.golang.org"
download_hosts = ["storage.googleapis.com"]
```

A version's publish time is the `Last-Modified` of its `.mod` on the mirror, which on proxy.golang.org is when the
mirror first stored it ([design/go.md](design/go.md)). A mirror that fronts proxy.golang.org (Athens,
Artifactory) reports its own storage time, which is later, so versions are held a little longer. `sumdb_url` is
the checksum database proxied at `/go/sumdb/sum.golang.org/`. `download_hosts` are the only hosts the mirrors may
redirect a download to: proxy.golang.org sends large zips to signed Cloud Storage URLs.

## Maven

```toml
[upstreams.maven]
enabled = true
fail_open = false
central = { url = "https://repo1.maven.org/maven2" }
google = { url = "https://dl.google.com/dl/android/maven2" }
gradle_plugins = { url = "https://plugins.gradle.org/m2", download_hosts = ["plugins-artifacts.gradle.org", "repo.maven.apache.org"] }

[upstreams.maven.repos]
jitpack = { url = "https://jitpack.io" }                                    # served at /maven/jitpack/
nightlies = { url = "https://repo.example.com/snapshots", snapshots = true }  # snapshots, without an age check
```

`/maven/all/` serves Google Maven's groups from Google and everything else from Central: point Maven's
`<mirrorOf>*</mirrorOf>` there. `fail_open` (per ecosystem; `null` means the top-level setting) is off for Maven:
an artifact none of whose versions is old enough is held too. A file's publish time is its `Last-Modified`, or when
SlowShield first saw its version listed upstream, whichever is earlier ([design/maven.md](design/maven.md)).

## Cargo

```toml
[upstreams.cargo]
enabled = true
fail_open = false
index_url = "https://index.crates.io"
download_url = "https://static.crates.io/crates"
download_hosts = []
```

Clients use `sparse+<public_url>/cargo/` as a registry that replaces crates-io (the Setup page has the
`config.toml`). A version's publish time is the `pubtime` on its index line, which crates.io sets; the first one seen
is kept. `fail_open` is off, as for Maven. `download_hosts` are hosts `download_url` may redirect to (static.crates.io
doesn't). Changing these needs a restart ([design/cargo.md](design/cargo.md)).

## Container images

```toml
[upstreams.oci]
enabled = true
layer_cache_gb = 0

[upstreams.oci.registries."registry.example.com"]
url = "https://registry.example.com"
download_hosts = ["cdn.example.com"]
times = "none"
```

Clients name the registry in the path (`/v2/ghcr.io/…`) or, for containerd, in `?ns=`; a registry that isn't
configured is refused. docker.io, ghcr.io, quay.io, registry.k8s.io, gcr.io, mcr.microsoft.com and public.ecr.aws
are built in, with their CDN hosts and time sources (`times`: `hub`, `quay`, `gcr`, `mcr` or `none`). A table for one
of them changes only the keys it sets, such as `enabled = false`, or `username` and `token_file` for a Docker Hub
token. Layers are streamed and checked, not stored, unless `layer_cache_gb` is above 0. Registries and
`layer_cache_gb` need a restart ([design/oci.md](design/oci.md)).

## Operator blocks

```toml
[[blocks]]
ecosystem = "oci"
package = "docker.io/aquasec/trivy"
version = "0.69.4"        # optional: a version, or an image tag or digest
reason = "compromised release"
url = "https://example.com/advisory"
```

A block works like a malware advisory in every ecosystem: `451` with the reason (`403` for images), a security event,
and the UI marks the package. It is for what no feed covers yet, and for container images, which no feed covers. A
block without `version` covers the whole package or image repository. Blocks apply on reload, and removing one lifts
it.

## Fail-open per ecosystem

`upstreams.<ecosystem>.fail_open` overrides the top-level `fail_open` for one ecosystem; unset, the top-level
value applies. Maven and Cargo default to `false`, the others to the top-level setting (`true`). For container
images it only ever applies during the instance's first `default_delay_days`, to tags it has no history for yet.

**Deprecated, removed in 0.1:**

* Per-ecosystem hostnames (`upstreams.pypi.hostnames`, `upstreams.npm.hostnames`): requests whose `Host`
  matches are served as a PyPI index or npm registry at the root of that host. npm tarball links on such a
  host use `https://<first npm hostname>`; everywhere else they use the path form.
* The root PyPI alias (`/simple/…`, `/packages/…`) on deployments without hostnames, from the Rust version.
* The old UI asset path `/static/…` (redirects to `/ui/static/…`).

All of them still work, log a startup warning (hostnames) and are counted in
`slowshield_legacy_routing_requests_total{route}`. To migrate, point clients at the path URLs (the Setup page
shows them) and re-lock, or replace `https://pypi.example.com/` with `https://<host>/pypi/` and
`https://npm.example.com/` with `https://<host>/npm/` in lockfiles. Once the counter stays at zero, the
deployment is ready for 0.1.

## Hot reload

The config file is polled every 5 seconds. Delays, exceptions, blocks, `fail_open`, `enforce_age_on_download`,
TTLs, feeds and mirror lists apply immediately (cached policy decisions are invalidated). Listener,
storage, routing and `public_url` changes are logged and need a restart.

## Checking a configuration

```bash
slowshield check-config --config /etc/slowshield/config.toml
```
