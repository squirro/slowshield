"""OpenTelemetry setup: traces, metrics and logs over OTLP/HTTP.

Everything is configured through the standard `OTEL_*` environment variables. Without an OTLP endpoint
(`OTEL_EXPORTER_OTLP_ENDPOINT` or a signal-specific one) or with `OTEL_SDK_DISABLED=true`, nothing is
installed and the API stays a cheap no-op. Instruments live in `slowshield.telemetry.instruments` and
are created against the API's proxy meter, so they start recording as soon as `setup()` runs.
"""

from __future__ import annotations

import logging
import os
import socket
import uuid

from opentelemetry import metrics, trace

log = logging.getLogger(__name__)

_state: dict[str, object] = {}

SERVICE_NAME = "slowshield"


def _enabled(signal: str) -> bool:
    if os.environ.get("OTEL_SDK_DISABLED", "").strip().lower() == "true":
        return False
    if os.environ.get(f"OTEL_{signal.upper()}_EXPORTER", "").strip().lower() == "none":
        return False
    return bool(
        os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
        or os.environ.get(f"OTEL_EXPORTER_OTLP_{signal.upper()}_ENDPOINT", "").strip()
    )


def is_active() -> bool:
    return bool(_state)


def setup(*, version: str, worker: int = 0) -> bool:
    """Install SDK providers if an OTLP endpoint is configured. Returns True when telemetry is active."""
    if _state:
        return True
    want = {s: _enabled(s) for s in ("traces", "metrics", "logs")}
    if not any(want.values()):
        return False

    from opentelemetry.sdk.resources import Resource

    attributes = {
        "service.name": os.environ.get("OTEL_SERVICE_NAME", SERVICE_NAME),
        "service.namespace": "slowshield",
        "service.version": version,
        "service.instance.id": f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}",
        "slowshield.worker": worker,
    }
    resource = Resource.create(attributes)  # merges OTEL_RESOURCE_ATTRIBUTES

    if want["traces"]:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import ParentBasedTraceIdRatio

        ratio = float(os.environ.get("SLOWSHIELD_TRACE_SAMPLE_RATIO", "0.1"))
        sampler = None if os.environ.get("OTEL_TRACES_SAMPLER") else ParentBasedTraceIdRatio(ratio)
        tp = TracerProvider(resource=resource, sampler=sampler) if sampler else TracerProvider(resource=resource)
        tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(tp)
        _state["tracer_provider"] = tp

    if want["metrics"]:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.metrics.view import ExponentialBucketHistogramAggregation, View

        interval = int(os.environ.get("OTEL_METRIC_EXPORT_INTERVAL", "15000"))
        reader = PeriodicExportingMetricReader(OTLPMetricExporter(), export_interval_millis=interval)
        views = [
            # Native (exponential) histograms: precise quantiles at a fraction of the series count.
            View(instrument_name="*duration*", aggregation=ExponentialBucketHistogramAggregation()),
            View(instrument_name="*lag*", aggregation=ExponentialBucketHistogramAggregation()),
        ]
        mp = MeterProvider(resource=resource, metric_readers=[reader], views=views)
        metrics.set_meter_provider(mp)
        _state["meter_provider"] = mp

    if want["logs"]:
        from opentelemetry._logs import set_logger_provider
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
        from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

        lp = LoggerProvider(resource=resource)
        lp.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))
        set_logger_provider(lp)
        handler = LoggingHandler(level=logging.INFO, logger_provider=lp)
        logging.getLogger().addHandler(handler)
        _state["logger_provider"] = lp
        _state["log_handler"] = handler

    log.info("telemetry enabled", extra={"signals": [k for k, v in want.items() if v]})
    return True


def shutdown() -> None:
    handler = _state.pop("log_handler", None)
    if isinstance(handler, logging.Handler):
        logging.getLogger().removeHandler(handler)
    for key in ("tracer_provider", "meter_provider", "logger_provider"):
        provider = _state.pop(key, None)
        if provider is not None:
            try:
                provider.shutdown()  # type: ignore[attr-defined]
            except Exception:  # pragma: no cover - exporter failures at exit are not actionable
                log.debug("telemetry shutdown failed", exc_info=True)
