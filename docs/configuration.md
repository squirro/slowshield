# Configuration

SlowShield reads, in increasing order of precedence:

1. built-in defaults,
2. a TOML file — `$SLOWSHIELD_CONFIG`, else `/etc/slowshield/config.toml`, else `./config.toml`,
3. environment variables (and `*_FILE` variants for secrets).

The annotated reference is [`config.example.toml`](../config.example.toml). The file format is compatible
with the Rust implementation's `config.toml`; keys for features that were not ported (`mode`,
`mirror_probe_interval_minutes`, `[upstreams.yum]`, `[upstreams.homebrew]`, `[feeds.phylum]`) are
accepted and ignored with a warning, and `database_url = "sqlite:/path"` is still understood.

## Environment variables

| Variable | Config key | Notes |
|---|---|---|
| `SLOWSHIELD_CONFIG` | — | path to the TOML file |
| `SLOWSHIELD_BIND` | `bind_address` | `host:port` |
| `SLOWSHIELD_PUBLIC_URL` | `public_url` | external URL of the UI host, used in setup snippets and as default npm base |
| `SLOWSHIELD_NPM_PUBLIC_URL` | `upstreams.npm.public_url` | base URL written into npm tarball links |
| `SLOWSHIELD_DATA_DIR` | `data_dir` | SQLite DB, artifact cache, leader lock |
| `SLOWSHIELD_DATABASE_PATH`, `DATABASE_URL` | `database_path` | `DATABASE_URL` takes `sqlite:/path` |
| `SLOWSHIELD_WORKERS` | `workers` | Granian workers |
| `SLOWSHIELD_DEFAULT_DELAY_DAYS` | `default_delay_days` | float |
| `SLOWSHIELD_PYPI_HOSTNAMES`, `SLOWSHIELD_NPM_HOSTNAMES` | `upstreams.*.hostnames` | space/comma separated |
| `SLOWSHIELD_PYPI_ENABLED`, `SLOWSHIELD_NPM_ENABLED` | `upstreams.*.enabled` | booleans |
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

* **Single host** (no `hostnames` configured): PyPI at `/pypi/simple/` (and, for compatibility, at
  `/simple/`), npm at `/npm/`, the UI at `/`.
* **Per-ecosystem hosts**: requests whose `Host` matches `upstreams.pypi.hostnames` are served as a
  PyPI index at the root (`/simple/…`, `/packages/…`); `upstreams.npm.hostnames` are served as an npm
  registry at the root. Any other host gets the UI plus the prefixed routes.

PyPI file links are relative, so they work behind any prefix without trusting the `Host` header. npm
requires absolute tarball URLs; they are built from `upstreams.npm.public_url` (or the first npm
hostname, or `public_url + /npm`), never from request headers.

## Hot reload

The config file is polled every 5 seconds. Delays, exceptions, `fail_open`, `enforce_age_on_download`,
TTLs, feeds and mirror lists apply immediately (cached policy decisions are invalidated). Listener,
storage, routing and `public_url` changes are logged and need a restart.

## Checking a configuration

```bash
slowshield check-config --config /etc/slowshield/config.toml
```
