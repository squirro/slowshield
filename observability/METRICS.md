# SlowShield metrics

SlowShield exports OpenTelemetry metrics over OTLP. This page lists the series as Prometheus 3 stores them
after OTLP translation (`translation_strategy: UnderscoreEscapingWithSuffixes` in
[`prometheus/prometheus.yml`](prometheus/prometheus.yml)):

* dots become underscores: `slowshield.decisions` becomes `slowshield_decisions`;
* the unit becomes a suffix unless the name already ends with it: `s` gives `_seconds` and `By` gives `_bytes`.
  Annotations in braces such as `{request}` add nothing;
* monotonic counters get `_total`;
* histograms are native (exponential) histograms, a single series per label set with no `_bucket`, `_sum` or
  `_count`. Query them with `histogram_quantile(0.95, sum by (…) (rate(x[5m])))` and
  `histogram_count(rate(x[5m]))`;
* metric attributes become labels the same way (`slowshield.ecosystem` becomes `slowshield_ecosystem`).

The dashboards and alert rules depend on these names. `python3 observability/check.py` fails when a
dashboard or alert queries a series that is not in the table below, or when the table and the instruments
in `src/slowshield` disagree. So a renamed or new metric has to be documented here first.

## Resource labels

Every series carries `job` (`service.namespace/service.name`, i.e. `slowshield/slowshield`) and
`instance` (`service.instance.id`: host, PID and a random suffix, one per worker process). Prometheus also promotes
these resource attributes to labels:

| Label | Source |
|---|---|
| `service_version` | SlowShield version |
| `slowshield_worker` | Granian worker index (0…n-1) |
| `deployment_environment_name` | `OTEL_RESOURCE_ATTRIBUTES` (`docker`, `podman`, the Helm release name, …) |
| `k8s_namespace_name`, `k8s_pod_name` | Kubernetes only (Helm chart and Alloy's `k8sattributes`) |

Each worker exports its own series, so aggregate across `instance` with `sum` (counters, histograms) or pick
`max` (gauges that every worker reports identically, such as feed state and cache limits).

## SlowShield series

| Series | Type | Instrument | Unit | Labels | Meaning |
|---|---|---|---|---|---|
| `slowshield_decisions_total` | counter | `slowshield.decisions` | `{request}` | `slowshield_ecosystem`, `slowshield_kind`, `slowshield_decision` | Policy outcome per request. `kind`: `metadata`, `artifact`. `decision`: `served`, `age_gated`, `blocked`, `tampered`, `integrity_mismatch`, `fail_open`, `not_found`, `upstream_error` |
| `slowshield_versions_held_total` | counter | `slowshield.versions.held` | `{version}` | `slowshield_ecosystem` | Versions hidden from metadata responses because they are younger than the delay |
| `slowshield_security_events_total` | counter | `slowshield.security.events` | `{event}` | `slowshield_ecosystem`, `slowshield_event` | Security events: `blocked`, `tampered`, `integrity_mismatch`, `fail_open`, `age_gate`. Each one is also a structured log record |
| `slowshield_artifact_bytes_total` | counter | `slowshield.artifact.bytes` | `By` | `slowshield_ecosystem`, `source` | Artifact bytes served. `source`: `cache`, `upstream` |
| `slowshield_cache_requests_total` | counter | `slowshield.cache.requests` | `{request}` | `cache`, `result` | Cache lookups. `cache`: `artifact`, `metadata`. `result`: `hit`, `miss`, `stale`, `revalidated` |
| `slowshield_cache_evictions_total` | counter | `slowshield.cache.evictions` | `{entry}` | `cache` | Artifact cache evictions (LRU, over `artifacts_max_gb`) |
| `slowshield_cache_size_bytes` | gauge | `slowshield.cache.size` | `By` | `cache` | Current cache size. `cache`: `artifact`, `metadata` (shared SQLite file), `metadata_memory` (this worker's in-memory share) |
| `slowshield_cache_limit_bytes` | gauge | `slowshield.cache.limit` | `By` | `cache` | Configured cache limit (same `cache` values; `metadata_memory` is per worker) |
| `slowshield_feed_enabled` | gauge | `slowshield.feed.enabled` | | `feed`, `reason` | 1 if the threat feed is on. `reason`: `ok`, `error`, `disabled`, `missing_token`, … (unit `1` is dropped by Alloy so the name gets no `_ratio` suffix) |
| `slowshield_feed_last_success_timestamp_seconds` | gauge | `slowshield.feed.last_success.timestamp` | `s` | `feed` | Unix time of the last successful sync |
| `slowshield_feed_errors_total` | counter | `slowshield.feed.errors` | `{error}` | `feed` | Failed feed syncs |
| `slowshield_feed_changes_total` | counter | `slowshield.feed.changes` | `{advisory}` | `feed` | Advisories added, updated or withdrawn |
| `slowshield_feed_sync_duration_seconds` | histogram | `slowshield.feed.sync.duration` | `s` | `feed`, `outcome` | Feed sync duration. `outcome`: `ok`, `error` |
| `slowshield_blocklist_entries` | gauge | `slowshield.blocklist.entries` | `{entry}` | `source`, `slowshield_ecosystem` | Active blocklist entries per feed |
| `slowshield_db_writer_queue` | gauge | `slowshield.db.writer.queue` | `{op}` | | Writes waiting for the single database writer |
| `slowshield_db_writer_flush_duration_seconds` | histogram | `slowshield.db.writer.flush.duration` | `s` | | Duration of one batched write transaction |
| `slowshield_eventloop_lag_seconds` | histogram | `slowshield.eventloop.lag` | `s` | | Event-loop scheduling lag, sampled every 0.5 s; sustained lag means blocking work on the loop |
| `slowshield_leader` | gauge | `slowshield.leader` | | | 1 on the worker that runs feeds and housekeeping |
| `slowshield_build_info` | gauge | `slowshield.build.info` | | `version`, `git_sha`, `python`, `gil` | Always 1. `gil`: `true`, or `false` on the free-threaded build |
| `http_server_request_duration_seconds` | histogram | `http.server.request.duration` | `s` | `http_request_method`, `http_route`, `http_response_status_code` | Requests served (OTel HTTP semantic conventions). `http_route` is the route template, never the package name |
| `http_client_request_duration_seconds` | histogram | `http.client.request.duration` | `s` | `server_address`, `http_request_method`, `http_response_status_code`, `slowshield_kind` | Upstream requests to the registries (`status_code` is 0 on connection errors) |
| `process_memory_usage_bytes` | gauge | `process.memory.usage` | `By` | | Resident set size |
| `process_cpu_time_seconds` | gauge | `process.cpu.time` | `s` | `cpu_mode` | CPU seconds consumed (`user`, `system`); use `rate()` although it is exported as a gauge |
| `process_open_file_descriptor_count` | gauge | `process.open_file_descriptor.count` | `{fd}` | | Open file descriptors |
| `process_thread_count` | gauge | `process.thread.count` | `{thread}` | | Threads |
| `python_gc_objects` | gauge | `python.gc.objects` | `{object}` | | Objects tracked by the garbage collector (sum of the generation counts) |

## Other series used by the dashboards

These come from the rest of the stack, not from SlowShield. They are listed so `check.py` accepts them.

| Prefix | Source |
|---|---|
| `caddy_` | Caddy's Prometheus endpoint (`:9180`, `CADDY_METRICS=on`), scraped by Alloy, `job="caddy"` |
| `process_resident_memory_bytes` | Caddy's Go runtime metrics on the same endpoint |
| `traces_spanmetrics_` | Tempo's metrics-generator (RED metrics from spans), remote-written to Prometheus |
| `traces_service_graph_` | Tempo's service graph, remote-written to Prometheus |

## Logs

Security events are also log records, both JSON on stdout and OTLP to Loki, with the fields `event`,
`ecosystem`, `package`, `version` and `client_ip`. Through OTLP they become the structured metadata
`slowshield_event`, `slowshield_ecosystem`, `slowshield_package`, `slowshield_version` and
`slowshield_client_ip`. Every record carries `trace_id` and `span_id`.
