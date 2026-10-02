# Observability

SlowShield emits OpenTelemetry **traces, metrics and logs** over OTLP/HTTP when an endpoint is configured
(`OTEL_EXPORTER_OTLP_ENDPOINT`, e.g. `http://alloy:4318`). Without it, telemetry is a no-op.

* **Traces**: one server span per request (W3C trace context continues from Caddy), client spans for
  upstream calls; head sampling via `SLOWSHIELD_TRACE_SAMPLE_RATIO` (default 10 %) or the standard
  `OTEL_TRACES_SAMPLER*` variables.
* **Metrics**: HTTP server/client latency histograms (exponential/native), policy decisions, held
  versions, security events, cache hit ratios and sizes, artifact bytes, feed state and freshness,
  blocklist size, DB writer queue, event-loop lag, process RSS/CPU/FDs/threads, build info. The exact
  Prometheus names are listed in [`observability/METRICS.md`](../observability/METRICS.md).
* **Logs**: JSON on stdout (always) and OTLP (when enabled), with `trace_id`/`span_id`; security events
  are structured log records (`event`, `ecosystem`, `package`, `version`, `client_ip`).

## Ready-made Grafana stack

[`observability/`](../observability/README.md) contains Alloy, Prometheus, Loki, Tempo and Grafana
configuration with provisioned dashboards (Overview, Security, Upstream & Performance, Feeds,
Caddy/TLS, Traces) and alert rules (feed disabled/stale, tamper detected, malware blocked, fail-open spike,
upstream and 5xx error rates, latency, DB backlog, cache nearly full, instance down).

| Runtime | Base | With the Grafana stack |
|---|---|---|
| Docker Compose | `deploy/docker/compose.yaml` | `+ compose.observability.yaml` |
| Podman (rootless Quadlet) | `deploy/podman/` | `deploy/podman/observability/` |
| Kubernetes (Helm) | `deploy/helm/slowshield` | `deploy/helm/slowshield-observability` + `telemetry.otlpEndpoint` |

If you already run a Grafana stack, just point `OTEL_EXPORTER_OTLP_ENDPOINT` at your collector and import
the dashboards from `observability/grafana/dashboards/`.
