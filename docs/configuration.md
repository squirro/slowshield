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
| `SLOWSHIELD_PYPI_ENABLED`, `SLOWSHIELD_NPM_ENABLED`, `SLOWSHIELD_GO_ENABLED` | `upstreams.*.enabled` | booleans |
| `SLOWSHIELD_ENFORCE_AGE_ON_DOWNLOAD` | `enforce_age_on_download` | |
| `SLOWSHIELD_FAIL_OPEN` | `fail_open` | |
| `SLOWSHIELD_RECORD_CLIENT_IP` | `record_client_ip` | |
| `SLOWSHIELD_TRUSTED_PROXIES` | `trusted_proxies` | CIDRs whose `X-Forwarded-For` is honoured |
| `SLOWSHIELD_ARTIFACT_CACHE`, `SLOWSHIELD_ARTIFACT_CACHE_MAX_GB` | `cache.artifacts_*` | |
| `SLOWSHIELD_FEED_OSV`, `SLOWSHIELD_FEED_GITHUB` | `feeds.*.enabled` | |
| `GITHUB_TOKEN` / `GITHUB_TOKEN_FILE` | `feeds.github_advisory.api_key` | the file variant wins; prefer it |
| `SLOWSHIELD_LOG_LEVEL`, `SLOWSHIELD_LOG_FORMAT` | — | `info`…; `json` (default in containers) or `text` |
| `SLOWSHIELD_ACCESS_LOG` | — | `1` enables Granian access logs (Caddy already logs requests) |
| `SLOWSHIELD_TRACE_SAMPLE_RATIO` | — | head sampling ratio (default 0.1) unless `OTEL_TRACES_SAMPLER` is set |
| `OTEL_*` | — | standard OpenTelemetry SDK variables; telemetry is off without an OTLP endpoint |

Local development: `uv run slowshield serve` also loads a `.env` file from the working directory
(python-dotenv) without overriding variables that are already set.

## Routing

One host serves everything, each ecosystem under a path named after its protocol: PyPI at `/pypi/simple/`,
npm at `/npm/`, Go modules at `/go/` (`GOPROXY`, [design/go.md](design/go.md)). The UI lives under `/ui/` (`/` redirects there), probes at `/healthz` and `/readyz`. Only
these and the names reserved for future ecosystems may be used at the root; see
[design/routing.md](design/routing.md) for the contract and the plan for every ecosystem on the roadmap.

PyPI file links are relative, so they work behind any prefix without trusting the `Host` header. npm
requires absolute tarball URLs; they are built from `upstreams.npm.public_url`, or `public_url + /npm`,
never from request headers. The Go module proxy protocol has no URLs in its responses.

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

The config file is polled every 5 seconds. Delays, exceptions, `fail_open`, `enforce_age_on_download`,
TTLs, feeds and mirror lists apply immediately (cached policy decisions are invalidated). Listener,
storage, routing and `public_url` changes are logged and need a restart.

## Checking a configuration

```bash
slowshield check-config --config /etc/slowshield/config.toml
```
