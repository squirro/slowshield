"""Metric instruments and the tracer. Names follow OTel semantic conventions where one exists.

Prometheus (via OTLP) renders them as e.g. `slowshield_decisions_total`,
`http_server_request_duration_seconds`, `slowshield_feed_last_success_timestamp_seconds`.
The dashboards and alert rules in `observability/` depend on these names; keep them stable.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from opentelemetry import metrics, trace
from opentelemetry.metrics import CallbackOptions, Observation

tracer = trace.get_tracer("slowshield")
meter = metrics.get_meter("slowshield")

http_server_duration = meter.create_histogram(
    "http.server.request.duration", unit="s", description="Duration of HTTP server requests."
)
http_client_duration = meter.create_histogram(
    "http.client.request.duration", unit="s", description="Duration of upstream HTTP requests."
)
decisions = meter.create_counter(
    "slowshield.decisions",
    unit="{request}",
    description="Policy decisions by ecosystem, request kind (metadata/artifact) and outcome.",
)
versions_held = meter.create_counter(
    "slowshield.versions.held",
    unit="{version}",
    description="Versions hidden from metadata responses because they are younger than the delay.",
)
security_events = meter.create_counter(
    "slowshield.security.events",
    unit="{event}",
    description="Security events: blocked, tampered, integrity_mismatch, fail_open, age_gate.",
)
artifact_bytes = meter.create_counter(
    "slowshield.artifact.bytes", unit="By", description="Artifact bytes served, by source (cache/upstream)."
)
cache_requests = meter.create_counter(
    "slowshield.cache.requests", unit="{request}", description="Cache lookups by cache and result."
)
cache_evictions = meter.create_counter(
    "slowshield.cache.evictions", unit="{entry}", description="Artifact cache evictions."
)
feed_sync_duration = meter.create_histogram(
    "slowshield.feed.sync.duration", unit="s", description="Duration of threat-feed synchronisation runs."
)
feed_errors = meter.create_counter("slowshield.feed.errors", unit="{error}", description="Feed sync failures.")
feed_changes = meter.create_counter(
    "slowshield.feed.changes", unit="{advisory}", description="Advisories added/updated/withdrawn by feeds."
)
eventloop_lag = meter.create_histogram(
    "slowshield.eventloop.lag", unit="s", description="Event-loop scheduling lag (sampled)."
)
db_flush_duration = meter.create_histogram(
    "slowshield.db.writer.flush.duration", unit="s", description="Duration of batched database writes."
)


GaugeCallback = Callable[[], Iterable[tuple[float, dict[str, str | int | float | bool]]]]
_registered: list[object] = []


def observe(name: str, callback: GaugeCallback, *, unit: str = "", description: str = "") -> None:
    """Register an observable gauge backed by `callback` -> [(value, attributes), ...]."""

    def _cb(_options: CallbackOptions) -> Iterable[Observation]:
        try:
            return [Observation(v, a) for v, a in callback()]
        except Exception:  # pragma: no cover - a broken gauge must never break the exporter
            return []

    _registered.append(meter.create_observable_gauge(name, callbacks=[_cb], unit=unit, description=description))
