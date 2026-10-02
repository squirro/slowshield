# Observability stack

Configuration for a self-contained Grafana stack next to SlowShield, shared by every deployment
variant:

```
SlowShield ──OTLP/HTTP──▶ Alloy ──OTLP──▶ Prometheus (metrics, 15 d)
Caddy ──OTLP/gRPC───────▶   │   ──OTLP──▶ Loki (logs, 15 d)
Caddy ◀──scrape :9180───────┤   ──OTLP──▶ Tempo (traces, 15 d) ──span metrics──▶ Prometheus
Caddy access log ──tail─────┘
                                Grafana: datasources, 6 dashboards, 13 alert rules
```

| Runtime | Deploy with |
|---|---|
| Docker Compose | `deploy/docker/compose.observability.yaml` (overlay on `compose.yaml`) |
| Rootless Podman (Quadlet) | [`deploy/podman/observability/`](../deploy/podman/observability/README.md) |
| Kubernetes (Helm) | [`deploy/helm/slowshield-observability/`](../deploy/helm/slowshield-observability/README.md) |

Already have a Grafana stack? Point SlowShield's `OTEL_EXPORTER_OTLP_ENDPOINT` at your collector and
import [`grafana/dashboards/*.json`](grafana/dashboards/). The dashboards pick their datasources
through template variables. The series they use are documented in [`METRICS.md`](METRICS.md).

## What is here

| Path | |
|---|---|
| `images.env` | The image pins (tag + multi-arch digest), the single source of truth for every variant |
| `alloy/config.alloy` | Collector for Compose/Podman: OTLP in, Caddy scrape, Caddy access log file |
| `alloy/config.k8s.alloy` | Same pipeline on Kubernetes: discovers Caddy through the API, adds pod metadata |
| `prometheus/`, `loki/`, `tempo/` | Single-binary backends with local storage and 15 day retention |
| `grafana/provisioning/` | Datasources (with trace↔logs↔metrics links), dashboard provider, alerting |
| `grafana/dashboards/` | Overview, Security, Upstream & Performance, Feeds, Caddy / TLS, Traces (generated) |
| `build_dashboards.py`, `build_alerts.py` | The generators: dashboards and alert rules are code |
| `sync.py` | Copies image pins and configs into Compose, Quadlet and the Helm chart |
| `check.py` | Static checks, run by CI |
| `smoke.py` | End-to-end test of the Compose stack (nightly and release) |
| `METRICS.md` | Every series SlowShield exports, as Prometheus stores it |

## Alerts

Rules live in Grafana's SlowShield folder and notify the `slowshield-default` contact point, a webhook
whose URL comes from `SLOWSHIELD_ALERT_WEBHOOK_URL`. Until you set it, notifications go nowhere. Critical
alerts notify at once and repeat hourly; warnings are grouped and repeat every 4 h. Runbooks:
[`docs/operations.md`](../docs/operations.md#alerts).

| Alert | Severity | Fires when |
|---|---|---|
| `TamperDetected` | critical | A download was aborted: the bytes did not match the first-seen or published digest |
| `MalwareBlocked` | warning | A client requested a blocklisted package version (refused with 451) |
| `FailOpenSpike` | warning | More than 50 fail-open responses in an hour |
| `FeedDisabled` | warning | A threat feed is not running (missing token or failing sync) for 15 min |
| `FeedStale` | warning | A feed has had no successful sync for 3 h |
| `FeedErrors` | warning | More than two failed syncs of a feed within an hour |
| `SlowShieldDown` | critical | No instance has reported metrics for 5 min |
| `NoLeader` | warning | No worker has held the leader lock for 10 min (feeds and housekeeping stopped) |
| `UpstreamErrorRate` | warning | Over 5% of requests to a registry fail (5xx, 429, transport errors) |
| `Http5xxRate` | warning | Over 2% of SlowShield's responses are 5xx |
| `HighLatency` | warning | p99 of index/packument responses above 1 s |
| `DBWriterBacklog` | warning | More than 5000 database writes have been queued for 5 min |
| `ArtifactCacheOverLimit` | warning | The artifact cache has been above 105% of its limit for 30 min |

Exact expressions and thresholds are in `build_alerts.py`.

## Changing things

```sh
# dashboards / alert rules: edit the generator, then regenerate
uv run python observability/build_dashboards.py
uv run python observability/build_alerts.py

# configs or images.env changed: propagate to Compose, Quadlet and the Helm chart
uv run python observability/sync.py

# after a Dependabot bump of compose.observability.yaml: adopt its pins first
uv run python observability/sync.py --from-compose

# what CI runs
uv run python observability/check.py
```

`check.py` fails when:

* a generated file or a copy is stale;
* a dashboard or alert queries a series that `METRICS.md` does not list;
* `METRICS.md` disagrees with the instruments in `src/slowshield` (name, type, unit);
* a dashboard hard-codes a datasource;
* `smoke.py` expects different dashboards or alert rules than are provisioned;
* the Compose or Kubernetes wiring points at a file, host or port that does not exist.

So a new metric goes into the code and `METRICS.md` together, and a dashboard can only use it after
that.

## Smoke test

```sh
SLOWSHIELD_IMAGE=slowshield:ci SLOWSHIELD_CADDY_IMAGE=slowshield-caddy:ci \
FAKEUPSTREAM_IMAGE=slowshield-fakeupstream:ci uv run python observability/smoke.py
```

It brings up Compose with the observability overlay and the fake registry and sends PyPI and npm
traffic, including a blocked package, a too-new release and a fail-open case. It then checks, through
Grafana's datasource proxy, that metrics, logs (security events included), traces and Caddy's access
log arrived, and that every dashboard and alert rule was provisioned. `--keep` leaves the stack running.
