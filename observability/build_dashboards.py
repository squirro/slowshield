#!/usr/bin/env python3
"""Generate the SlowShield Grafana dashboards (stdlib only).

    python3 observability/build_dashboards.py          # (re)write grafana/dashboards/*.json
    python3 observability/build_dashboards.py --check  # exit 1 if the committed JSON is stale

Dashboards are code: edit the definitions below, regenerate, commit both. Metric names follow the
Prometheus 3 OTLP translation documented in METRICS.md. Datasources are template variables
(defaulting to the provisioned uids) so the JSON also imports cleanly into an existing Grafana.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parent / "grafana" / "dashboards"
SCHEMA_VERSION = 41

# SlowShield palette (brand/tokens.css).
C = {
    "brand": "#0f6e5d",
    "brand_light": "#3cc4a6",
    "brand_deep": "#0b4f43",
    "hold": "#d98a1c",
    "hold_text": "#a44a07",
    "danger": "#c0262d",
    "tamper": "#a21caf",
    "ok": "#137334",
    "muted": "#5d6b63",
    "pypi": "#2f6fb3",
    "npm": "#cb3837",
}
DECISION_COLORS = {
    "served": C["brand"],
    "fail_open": C["hold"],
    "age_gated": C["hold_text"],
    "blocked": C["danger"],
    "tampered": C["tamper"],
    "integrity_mismatch": "#d946ef",
    "not_found": "#8a9a91",
    "upstream_error": C["muted"],
}
EVENT_COLORS = {
    "blocked": C["danger"],
    "tampered": C["tamper"],
    "integrity_mismatch": "#d946ef",
    "fail_open": C["hold"],
    "age_gate": C["hold_text"],
}

PROM = {"type": "prometheus", "uid": "${prometheus}"}
LOKI = {"type": "loki", "uid": "${loki}"}
TEMPO = {"type": "tempo", "uid": "${tempo}"}

# Common label selectors.
INST = 'instance=~"$instance"'
ECO = 'slowshield_ecosystem=~"$ecosystem"'
RI = "$__rate_interval"


# ---------------------------------------------------------------------------------------------
# panel builders
# ---------------------------------------------------------------------------------------------


class Layout:
    """Places panels left-to-right on Grafana's 24-column grid."""

    def __init__(self) -> None:
        self.x = 0
        self.y = 0
        self.row_h = 0
        self.next_id = 1
        self.panels: list[dict[str, Any]] = []

    def add(self, panel: dict[str, Any], w: int, h: int) -> None:
        if self.x + w > 24:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0
        panel["gridPos"] = {"x": self.x, "y": self.y, "w": w, "h": h}
        panel["id"] = self.next_id
        self.next_id += 1
        self.x += w
        self.row_h = max(self.row_h, h)
        self.panels.append(panel)

    def row(self, title: str) -> None:
        if self.x:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0
        self.panels.append(
            {
                "type": "row",
                "title": title,
                "collapsed": False,
                "id": self.next_id,
                "panels": [],
                "gridPos": {"x": 0, "y": self.y, "w": 24, "h": 1},
            }
        )
        self.next_id += 1
        self.y += 1


def prom(
    expr: str, legend: str = "", *, ref: str = "A", instant: bool = False, fmt: str | None = None
) -> dict[str, Any]:
    t: dict[str, Any] = {"datasource": PROM, "expr": expr, "refId": ref, "legendFormat": legend or "__auto"}
    if instant:
        t["instant"] = True
        t["range"] = False
    if fmt:
        t["format"] = fmt
    return t


def loki(expr: str, *, ref: str = "A", instant: bool = False, legend: str = "") -> dict[str, Any]:
    t: dict[str, Any] = {"datasource": LOKI, "expr": expr, "refId": ref, "queryType": "instant" if instant else "range"}
    if legend:
        t["legendFormat"] = legend
    return t


def overrides_colors(colors: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "matcher": {"id": "byName", "options": name},
            "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}],
        }
        for name, color in colors.items()
    ]


def timeseries(
    title: str,
    targets: list[dict[str, Any]],
    *,
    unit: str = "short",
    stack: bool = False,
    bars: bool = False,
    colors: dict[str, str] | None = None,
    desc: str = "",
    min0: bool = True,
    fill: int = 12,
    ds: dict[str, Any] = PROM,
) -> dict[str, Any]:
    custom: dict[str, Any] = {
        "drawStyle": "bars" if bars else "line",
        "lineWidth": 1 if bars else 2,
        "fillOpacity": 80 if bars else fill,
        "gradientMode": "opacity" if not bars else "none",
        "showPoints": "never",
        "spanNulls": True,
        "lineInterpolation": "smooth",
        "stacking": {"mode": "normal" if stack else "none", "group": "A"},
        "axisSoftMin": 0 if min0 else None,
    }
    return {
        "type": "timeseries",
        "title": title,
        "description": desc,
        "datasource": ds,
        "targets": targets,
        "fieldConfig": {
            "defaults": {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}},
            "overrides": overrides_colors(colors or {}),
        },
        "options": {
            "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
    }


def stat(
    title: str,
    target: dict[str, Any],
    *,
    unit: str = "short",
    color: str = C["brand"],
    thresholds: list[tuple[float | None, str]] | None = None,
    mappings: list[dict[str, Any]] | None = None,
    desc: str = "",
    graph: bool = True,
    decimals: int | None = None,
    ds: dict[str, Any] = PROM,
    text_mode: str = "value",
) -> dict[str, Any]:
    steps = [{"color": c, "value": v} for v, c in (thresholds or [(None, color)])]
    defaults: dict[str, Any] = {
        "unit": unit,
        "color": {"mode": "thresholds"},
        "thresholds": {"mode": "absolute", "steps": steps},
        "mappings": mappings or [],
    }
    if decimals is not None:
        defaults["decimals"] = decimals
    return {
        "type": "stat",
        "title": title,
        "description": desc,
        "datasource": ds,
        "targets": [target],
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "colorMode": "background" if not graph else "value",
            "graphMode": "area" if graph else "none",
            "justifyMode": "auto",
            "textMode": text_mode,
            "orientation": "auto",
            "wideLayout": True,
            "showPercentChange": False,
        },
    }


def table(
    title: str,
    targets: list[dict[str, Any]],
    *,
    desc: str = "",
    ds: dict[str, Any] = PROM,
    transformations: list[dict[str, Any]] | None = None,
    overrides: list[dict[str, Any]] | None = None,
    sort: str | None = None,
) -> dict[str, Any]:
    opts: dict[str, Any] = {"showHeader": True, "cellHeight": "sm", "footer": {"show": False, "reducer": ["sum"]}}
    if sort:
        opts["sortBy"] = [{"displayName": sort, "desc": True}]
    return {
        "type": "table",
        "title": title,
        "description": desc,
        "datasource": ds,
        "targets": targets,
        "transformations": transformations or [],
        "fieldConfig": {
            "defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}}},
            "overrides": overrides or [],
        },
        "options": opts,
    }


def bargauge(
    title: str,
    targets: list[dict[str, Any]],
    *,
    unit: str = "short",
    desc: str = "",
    color: str = C["brand"],
    ds: dict[str, Any] = PROM,
) -> dict[str, Any]:
    return {
        "type": "bargauge",
        "title": title,
        "description": desc,
        "datasource": ds,
        "targets": targets,
        "fieldConfig": {
            "defaults": {
                "unit": unit,
                "color": {"mode": "fixed", "fixedColor": color},
                "min": 0,
                "thresholds": {"mode": "absolute", "steps": [{"color": color, "value": None}]},
            },
            "overrides": [],
        },
        "options": {
            "displayMode": "gradient",
            "orientation": "horizontal",
            "showUnfilled": True,
            "valueMode": "color",
            "namePlacement": "left",
            "sizing": "auto",
            "minVizHeight": 12,
            "maxVizHeight": 24,
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True},
        },
    }


def piechart(
    title: str,
    targets: list[dict[str, Any]],
    *,
    desc: str = "",
    colors: dict[str, str] | None = None,
    ds: dict[str, Any] = PROM,
    unit: str = "short",
) -> dict[str, Any]:
    return {
        "type": "piechart",
        "title": title,
        "description": desc,
        "datasource": ds,
        "targets": targets,
        "fieldConfig": {
            "defaults": {"unit": unit, "color": {"mode": "palette-classic"}},
            "overrides": overrides_colors(colors or {}),
        },
        "options": {
            "pieType": "donut",
            "legend": {"displayMode": "table", "placement": "right", "values": ["value", "percent"]},
            "reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
            "tooltip": {"mode": "single"},
        },
    }


def logs(title: str, expr: str, *, desc: str = "") -> dict[str, Any]:
    return {
        "type": "logs",
        "title": title,
        "description": desc,
        "datasource": LOKI,
        "targets": [loki(expr)],
        "options": {
            "showTime": True,
            "wrapLogMessage": True,
            "enableLogDetails": True,
            "sortOrder": "Descending",
            "dedupStrategy": "none",
            "prettifyLogMessage": False,
            "showLabels": False,
            "showCommonLabels": False,
        },
    }


def text(title: str, content: str) -> dict[str, Any]:
    return {"type": "text", "title": title, "options": {"mode": "markdown", "content": content}}


def feed_mappings() -> list[dict[str, Any]]:
    return [
        {
            "type": "value",
            "options": {
                "1": {"text": "Active", "color": C["ok"], "index": 0},
                "0": {"text": "Off", "color": C["hold"], "index": 1},
            },
        }
    ]


# ---------------------------------------------------------------------------------------------
# dashboard shell
# ---------------------------------------------------------------------------------------------


def ds_var(name: str, kind: str, default_uid: str, label: str) -> dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "type": "datasource",
        "query": kind,
        "hide": 2 if name != "prometheus" else 0,
        "current": {"text": default_uid, "value": default_uid},
        "refresh": 1,
        "regex": "",
        "options": [],
    }


def query_var(name: str, label: str, query: str, *, all_value: str = ".*") -> dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "type": "query",
        "datasource": PROM,
        "query": {"query": query, "refId": "vars", "qryType": 1},
        "definition": query,
        "refresh": 2,
        "sort": 1,
        "multi": True,
        "includeAll": True,
        "allValue": all_value,
        "current": {"text": ["All"], "value": ["$__all"]},
        "options": [],
        "hide": 0,
    }


def custom_var(name: str, label: str, values: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "type": "custom",
        "query": ",".join(values),
        "multi": True,
        "includeAll": True,
        "allValue": ".*",
        "current": {"text": ["All"], "value": ["$__all"]},
        "options": [{"text": v, "value": v, "selected": False} for v in values],
        "hide": 0,
    }


def dashboard(
    uid: str,
    title: str,
    layout: Layout,
    *,
    tags: list[str],
    variables: list[dict[str, Any]],
    description: str,
    refresh: str = "30s",
    time_from: str = "now-6h",
) -> dict[str, Any]:
    links = [
        {
            "title": "SlowShield dashboards",
            "type": "dashboards",
            "tags": ["slowshield"],
            "asDropdown": True,
            "includeVars": True,
            "keepTime": True,
            "targetBlank": False,
            "icon": "external link",
            "tooltip": "",
            "url": "",
        },
    ]
    return {
        "uid": uid,
        "title": title,
        "description": description,
        "tags": ["slowshield", *tags],
        "editable": False,
        "graphTooltip": 1,
        "fiscalYearStartMonth": 0,
        "liveNow": False,
        "refresh": refresh,
        "schemaVersion": SCHEMA_VERSION,
        "version": 1,
        "time": {"from": time_from, "to": "now"},
        "timepicker": {},
        "timezone": "browser",
        "weekStart": "",
        "links": links,
        "annotations": {
            "list": [
                {
                    "builtIn": 1,
                    "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                    "enable": True,
                    "hide": True,
                    "iconColor": "rgba(0, 211, 255, 1)",
                    "name": "Annotations & Alerts",
                    "type": "dashboard",
                },
            ]
        },
        "templating": {
            "list": [
                ds_var("prometheus", "prometheus", "slowshield-prometheus", "Metrics"),
                ds_var("loki", "loki", "slowshield-loki", "Logs"),
                ds_var("tempo", "tempo", "slowshield-tempo", "Traces"),
                *variables,
            ]
        },
        "panels": layout.panels,
    }


INSTANCE_VAR = query_var("instance", "Instance", "label_values(slowshield_build_info, instance)")
ECOSYSTEM_VAR = custom_var("ecosystem", "Ecosystem", ["pypi", "npm"])


# request-rate helper for native histograms
def hcount(metric: str, sel: str, by: str = "") -> str:
    group = f" by ({by})" if by else ""
    return f"sum{group} (histogram_count(rate({metric}{{{sel}}}[{RI}])))"


def hq(q: float, metric: str, sel: str, by: str = "") -> str:
    group = f" by ({by})" if by else ""
    return f"histogram_quantile({q}, sum{group} (rate({metric}{{{sel}}}[{RI}])))"


# ---------------------------------------------------------------------------------------------
# 1. Overview
# ---------------------------------------------------------------------------------------------


def overview() -> dict[str, Any]:
    L = Layout()
    srv = "http_server_request_duration_seconds"
    L.row("At a glance")
    L.add(
        stat("Requests / s", prom(hcount(srv, INST)), unit="reqps", desc="All HTTP requests handled by SlowShield."),
        4,
        4,
    )
    L.add(
        stat(
            "Installs / min",
            prom(
                f'sum(rate(slowshield_decisions_total{{{INST},{ECO},slowshield_kind="artifact",slowshield_decision="served"}}[{RI}])) * 60'
            ),
            unit="short",
            decimals=1,
            desc="Artifacts (wheels, sdists, tarballs) served per minute.",
        ),
        4,
        4,
    )
    L.add(
        stat(
            "5xx ratio",
            prom(hcount(srv, INST + ',http_response_status_code=~"5.."') + " / " + hcount(srv, INST)),
            unit="percentunit",
            decimals=2,
            thresholds=[(None, C["ok"]), (0.01, C["hold"]), (0.05, C["danger"])],
        ),
        4,
        4,
    )
    L.add(
        stat(
            "p99 metadata latency",
            prom(hq(0.99, srv, INST + ',http_route=~".*simple/\\\\{project\\\\}/|(/npm)?/\\\\{package\\\\}"')),
            unit="s",
            decimals=3,
            thresholds=[(None, C["ok"]), (0.5, C["hold"]), (1, C["danger"])],
            desc="99th percentile of PyPI index and npm packument responses.",
        ),
        4,
        4,
    )
    L.add(
        stat(
            "Artifact cache hit ratio",
            prom(
                f'sum(rate(slowshield_cache_requests_total{{{INST},cache="artifact",result="hit"}}[{RI}])) / '
                f'sum(rate(slowshield_cache_requests_total{{{INST},cache="artifact"}}[{RI}]))'
            ),
            unit="percentunit",
            decimals=1,
        ),
        4,
        4,
    )
    L.add(
        stat(
            "Data served",
            prom(f"sum(increase(slowshield_artifact_bytes_total{{{INST},{ECO}}}[$__range]))", instant=True),
            unit="bytes",
            graph=False,
            desc="Artifact bytes served in the selected time range.",
        ),
        4,
        4,
    )

    L.add(
        stat(
            "Malware blocked",
            prom(
                f'sum(increase(slowshield_security_events_total{{{INST},{ECO},slowshield_event="blocked"}}[$__range]))',
                instant=True,
            ),
            graph=False,
            thresholds=[(None, C["ok"]), (1, C["danger"])],
            desc="Requests for packages on the threat-feed blocklist (HTTP 451).",
        ),
        4,
        4,
    )
    L.add(
        stat(
            "Tamper detections",
            prom(
                f'sum(increase(slowshield_security_events_total{{{INST},{ECO},slowshield_event=~"tampered|integrity_mismatch"}}[$__range]))',
                instant=True,
            ),
            graph=False,
            thresholds=[(None, C["ok"]), (1, C["tamper"])],
        ),
        4,
        4,
    )
    L.add(
        stat(
            "Too new (403)",
            prom(
                f'sum(increase(slowshield_decisions_total{{{INST},{ECO},slowshield_decision="age_gated"}}[$__range]))',
                instant=True,
            ),
            graph=False,
            color=C["hold_text"],
            desc="Downloads refused because the version is younger than the delay.",
        ),
        4,
        4,
    )
    L.add(
        stat(
            "Fail-open serves",
            prom(
                f'sum(increase(slowshield_decisions_total{{{INST},{ECO},slowshield_decision="fail_open"}}[$__range]))',
                instant=True,
            ),
            graph=False,
            color=C["hold"],
            desc="Brand-new packages served because no version was old enough yet.",
        ),
        4,
        4,
    )
    L.add(
        stat(
            "Versions held back",
            prom(f"sum(increase(slowshield_versions_held_total{{{INST},{ECO}}}[$__range]))", instant=True),
            graph=False,
            color=C["brand"],
            desc="Too-new versions hidden from metadata responses (summed over responses).",
        ),
        4,
        4,
    )
    L.add(
        stat(
            "Threat feeds active",
            prom("count(max by (feed) (slowshield_feed_enabled) == 1) or vector(0)", instant=True),
            graph=False,
            thresholds=[(None, C["hold"]), (2, C["ok"])],
            desc="OSV + GitHub = 2. Fewer means a feed is disabled, missing its token or failing.",
        ),
        4,
        4,
    )

    L.row("Traffic & policy")
    dec_targets = [
        prom(
            f"sum by (slowshield_decision) (rate(slowshield_decisions_total{{{INST},{ECO}}}[{RI}]))",
            "{{slowshield_decision}}",
        )
    ]
    L.add(
        timeseries(
            "Policy decisions",
            dec_targets,
            unit="reqps",
            stack=True,
            colors=DECISION_COLORS,
            desc="Every metadata and artifact request ends in one decision.",
        ),
        12,
        8,
    )
    L.add(
        timeseries(
            "Requests by ecosystem",
            [
                prom(
                    f"sum by (slowshield_ecosystem) (rate(slowshield_decisions_total{{{INST},{ECO}}}[{RI}]))",
                    "{{slowshield_ecosystem}}",
                )
            ],
            unit="reqps",
            stack=True,
            colors={"pypi": C["pypi"], "npm": C["npm"]},
        ),
        12,
        8,
    )
    L.add(
        timeseries(
            "Latency by route (p50 / p95 / p99)",
            [
                prom(hq(0.5, srv, INST, "http_route"), "p50 {{http_route}}", ref="A"),
                prom(hq(0.95, srv, INST, "http_route"), "p95 {{http_route}}", ref="B"),
                prom(hq(0.99, srv, INST, "http_route"), "p99 {{http_route}}", ref="C"),
            ],
            unit="s",
            fill=0,
        ),
        12,
        9,
    )
    L.add(
        timeseries(
            "Requests by route and status",
            [
                prom(
                    hcount(srv, INST, "http_route, http_response_status_code"),
                    "{{http_route}} {{http_response_status_code}}",
                ),
            ],
            unit="reqps",
        ),
        12,
        9,
    )

    L.row("Caches & bandwidth")
    L.add(
        timeseries(
            "Cache hit ratio",
            [
                prom(
                    f'sum by (cache) (rate(slowshield_cache_requests_total{{{INST},result=~"hit|revalidated"}}[{RI}])) / '
                    f"sum by (cache) (rate(slowshield_cache_requests_total{{{INST}}}[{RI}]))",
                    "{{cache}}",
                ),
            ],
            unit="percentunit",
            colors={"artifact": C["brand"], "metadata": C["pypi"]},
            fill=0,
            desc="Metadata counts 304-revalidations as hits.",
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "Bytes served by source",
            [
                prom(f"sum by (source) (rate(slowshield_artifact_bytes_total{{{INST},{ECO}}}[{RI}]))", "{{source}}"),
            ],
            unit="Bps",
            stack=True,
            colors={"cache": C["brand"], "upstream": C["hold"]},
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "Cache usage",
            [
                prom(f"max by (cache) (slowshield_cache_size_bytes{{{INST}}})", "{{cache}} used", ref="A"),
                prom(f"max by (cache) (slowshield_cache_limit_bytes{{{INST}}})", "{{cache}} limit", ref="B"),
            ],
            unit="bytes",
            fill=0,
        ),
        8,
        8,
    )

    L.row("Build")
    L.add(
        table(
            "Running instances",
            [
                prom(
                    f"max by (instance, version, git_sha, python, gil) (slowshield_build_info{{{INST}}})",
                    instant=True,
                    fmt="table",
                )
            ],
            transformations=[{"id": "organize", "options": {"excludeByName": {"Time": True, "Value": True}}}],
        ),
        16,
        6,
    )
    L.add(
        stat(
            "Leader",
            prom("sum(slowshield_leader) or vector(0)", instant=True),
            graph=False,
            thresholds=[(None, C["danger"]), (1, C["ok"])],
            desc="Exactly one worker should be leader (it runs feeds and cache maintenance).",
        ),
        8,
        6,
    )
    return dashboard(
        "slowshield-overview",
        "SlowShield Overview",
        L,
        tags=["overview"],
        variables=[INSTANCE_VAR, ECOSYSTEM_VAR],
        description="Traffic, policy decisions, latency, caches and protection status of SlowShield.",
    )


# ---------------------------------------------------------------------------------------------
# 2. Security
# ---------------------------------------------------------------------------------------------

SEC_SEL = '{service_name="slowshield"}'


def security() -> dict[str, Any]:
    L = Layout()
    L.row("Security events")
    for title, ev, color in (
        ("Malware blocked", "blocked", C["danger"]),
        ("Tampered / integrity", "tampered|integrity_mismatch", C["tamper"]),
        ("Too new (403)", "age_gate", C["hold_text"]),
        ("Fail-open", "fail_open", C["hold"]),
    ):
        L.add(
            stat(
                title,
                prom(
                    f'sum(increase(slowshield_security_events_total{{{INST},{ECO},slowshield_event=~"{ev}"}}[$__range]))',
                    instant=True,
                ),
                graph=False,
                thresholds=[(None, C["ok"]), (1, color)],
            ),
            6,
            4,
        )
    L.add(
        timeseries(
            "Security events over time",
            [
                prom(
                    f"sum by (slowshield_event) (increase(slowshield_security_events_total{{{INST},{ECO}}}[$__interval]))",
                    "{{slowshield_event}}",
                ),
            ],
            bars=True,
            stack=True,
            colors=EVENT_COLORS,
            desc="Counts per interval.",
        ),
        16,
        8,
    )
    L.add(
        piechart(
            "Events by ecosystem",
            [
                prom(
                    f"sum by (slowshield_ecosystem) (increase(slowshield_security_events_total{{{INST},{ECO}}}[$__range]))",
                    "{{slowshield_ecosystem}}",
                    instant=True,
                ),
            ],
            colors={"pypi": C["pypi"], "npm": C["npm"]},
        ),
        8,
        8,
    )

    L.row("Who and what (from logs)")

    # Log attributes arrive namespaced (`slowshield.event` -> Loki structured metadata `slowshield_event`),
    # matching the `slowshield_event` label on the metrics.
    def top(title: str, ev: str, by: str, n: int = 15) -> dict[str, Any]:
        fields = [f.strip() for f in by.split(",")]
        group = ", ".join(f"slowshield_{f}" for f in fields)
        expr = f'topk({n}, sum by ({group}) (count_over_time({SEC_SEL} | slowshield_event=~"{ev}" [$__range])))'
        rename = {"Value": "count"} | {f"slowshield_{f}": f.replace("_", " ") for f in fields}
        return table(
            title,
            [loki(expr, instant=True)],
            ds=LOKI,
            sort="Value",
            transformations=[{"id": "organize", "options": {"excludeByName": {"Time": True}, "renameByName": rename}}],
        )

    L.add(top("Top blocked packages", "blocked", "ecosystem, package, version"), 8, 9)
    L.add(top("Top too-new downloads", "age_gate", "ecosystem, package, version"), 8, 9)
    L.add(
        top("Clients with security events", "blocked|tampered|integrity_mismatch|age_gate", "client_ip, event", 20),
        8,
        9,
    )
    L.add(top("Fail-open packages", "fail_open", "ecosystem, package"), 12, 8)
    L.add(top("Tampered artifacts", "tampered|integrity_mismatch", "ecosystem, package, version, client_ip"), 12, 8)
    L.add(
        logs(
            "Security event log",
            f'{SEC_SEL} | slowshield_event=~"blocked|tampered|integrity_mismatch|fail_open|age_gate"',
            desc="Each line links to its trace (trace_id).",
        ),
        24,
        12,
    )
    return dashboard(
        "slowshield-security",
        "SlowShield Security",
        L,
        tags=["security"],
        variables=[INSTANCE_VAR, ECOSYSTEM_VAR],
        description="Blocked malware, tamper detections, fail-open serves and too-new downloads, with the packages and clients involved.",
        time_from="now-24h",
    )


# ---------------------------------------------------------------------------------------------
# 3. Upstream & performance
# ---------------------------------------------------------------------------------------------


def upstream() -> dict[str, Any]:
    L = Layout()
    cli = "http_client_request_duration_seconds"
    L.row("Upstream registries")
    L.add(
        timeseries(
            "Upstream requests by host",
            [prom(hcount(cli, INST, "server_address"), "{{server_address}}")],
            unit="reqps",
            stack=True,
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "Upstream latency p95 by host and kind",
            [prom(hq(0.95, cli, INST, "server_address, slowshield_kind"), "{{server_address}} {{slowshield_kind}}")],
            unit="s",
            fill=0,
            desc="Artifact latency covers the whole streamed download.",
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "Upstream error ratio",
            [
                prom(
                    hcount(cli, INST + ',http_response_status_code=~"5..|0|429"', "server_address")
                    + " / "
                    + hcount(cli, INST, "server_address"),
                    "{{server_address}}",
                ),
            ],
            unit="percentunit",
            fill=0,
            colors={},
            desc="5xx, 429 and transport errors (status 0).",
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "Upstream responses by status",
            [prom(hcount(cli, INST, "http_response_status_code"), "{{http_response_status_code}}")],
            unit="reqps",
            stack=True,
        ),
        12,
        8,
    )
    L.add(
        piechart(
            "Upstream HTTP versions (sampled traces)",
            [
                prom(
                    'sum by (network_protocol_version) (increase(traces_spanmetrics_calls_total{service="slowshield",span_kind="SPAN_KIND_CLIENT"}[$__range]))',
                    "HTTP/{{network_protocol_version}}",
                    instant=True,
                ),
            ],
            desc="From Tempo span-metrics; only sampled requests are counted.",
        ),
        12,
        8,
    )

    L.row("Runtime")
    L.add(
        timeseries(
            "Event-loop lag p99",
            [prom(hq(0.99, "slowshield_eventloop_lag_seconds", INST, "instance"), "{{instance}}")],
            unit="s",
            fill=0,
            desc="Sustained lag means blocking work on the event loop.",
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "DB writer queue",
            [prom(f"max by (instance) (slowshield_db_writer_queue{{{INST}}})", "{{instance}}")],
            unit="short",
            fill=0,
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "DB flush duration p95",
            [prom(hq(0.95, "slowshield_db_writer_flush_duration_seconds", INST, "instance"), "{{instance}}")],
            unit="s",
            fill=0,
            desc="Batched SQLite write transactions.",
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "Resident memory",
            [
                prom(
                    f'max by (instance) (process_memory_usage_bytes{{{INST},job="slowshield/slowshield"}})',
                    "{{instance}}",
                )
            ],
            unit="bytes",
            fill=0,
        ),
        6,
        8,
    )
    L.add(
        timeseries(
            "CPU",
            [
                prom(
                    f'sum by (instance) (rate(process_cpu_time_seconds{{{INST},job="slowshield/slowshield"}}[{RI}]))',
                    "{{instance}}",
                )
            ],
            unit="percentunit",
            fill=0,
            desc="CPU seconds per second (1.0 = one core).",
        ),
        6,
        8,
    )
    L.add(
        timeseries(
            "Open file descriptors",
            [prom(f"max by (instance) (process_open_file_descriptor_count{{{INST}}})", "{{instance}}")],
            unit="short",
            fill=0,
        ),
        6,
        8,
    )
    L.add(
        timeseries(
            "Threads",
            [prom(f"max by (instance) (process_thread_count{{{INST}}})", "{{instance}}")],
            unit="short",
            fill=0,
        ),
        6,
        8,
    )
    return dashboard(
        "slowshield-upstream",
        "SlowShield Upstream & Performance",
        L,
        tags=["performance"],
        variables=[INSTANCE_VAR],
        description="Upstream registry latency/errors and SlowShield runtime health.",
    )


# ---------------------------------------------------------------------------------------------
# 4. Feeds
# ---------------------------------------------------------------------------------------------


def feeds() -> dict[str, Any]:
    L = Layout()
    L.row("Status")
    L.add(
        text(
            "About feeds",
            "SlowShield blocks known-malicious packages from **OSV** (OpenSSF malicious-packages, no token) and the "
            "**GitHub Advisory Database** (needs `GITHUB_TOKEN`). A feed shows *Off* when it is disabled in the config, its token is "
            "missing or its last sync failed — the `reason` column says which. See the SlowShield UI → Feeds for how to fix it.",
        ),
        8,
        6,
    )
    L.add(
        table(
            "Feed status",
            [prom("max by (feed, reason) (slowshield_feed_enabled)", instant=True, fmt="table")],
            transformations=[
                {"id": "organize", "options": {"excludeByName": {"Time": True}, "renameByName": {"Value": "active"}}}
            ],
            overrides=[
                {
                    "matcher": {"id": "byName", "options": "active"},
                    "properties": [
                        {"id": "mappings", "value": feed_mappings()},
                        {"id": "custom.cellOptions", "value": {"type": "color-background"}},
                    ],
                }
            ],
        ),
        8,
        6,
    )
    L.add(
        stat(
            "Time since last successful sync",
            prom("time() - max by (feed) (slowshield_feed_last_success_timestamp_seconds)", "{{feed}}"),
            unit="s",
            graph=False,
            thresholds=[(None, C["ok"]), (7200, C["hold"]), (10800, C["danger"])],
            desc="Alerts fire after 3 hours (3× the default 60 minute poll interval).",
        ),
        8,
        6,
    )
    L.row("Sync runs")
    L.add(
        timeseries(
            "Sync duration p95",
            [prom(hq(0.95, "slowshield_feed_sync_duration_seconds", "", "feed"), "{{feed}}")],
            unit="s",
            fill=0,
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "Sync runs by outcome",
            [
                prom(
                    "sum by (feed, outcome) (histogram_count(increase(slowshield_feed_sync_duration_seconds[$__interval])))",
                    "{{feed}} {{outcome}}",
                )
            ],
            bars=True,
            stack=True,
            colors={},
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "Sync errors",
            [prom("sum by (feed) (increase(slowshield_feed_errors_total[$__interval]))", "{{feed}}")],
            bars=True,
            colors={},
        ),
        8,
        8,
    )
    L.row("Blocklist")
    L.add(
        timeseries(
            "Blocklist entries by source and ecosystem",
            [
                prom(
                    "max by (source, slowshield_ecosystem) (slowshield_blocklist_entries)",
                    "{{source}} {{slowshield_ecosystem}}",
                ),
            ],
            unit="short",
            stack=True,
        ),
        16,
        8,
    )
    L.add(
        bargauge(
            "Advisories changed (range)",
            [prom("sum by (feed) (increase(slowshield_feed_changes_total[$__range]))", "{{feed}}", instant=True)],
            color=C["brand"],
        ),
        8,
        8,
    )
    return dashboard(
        "slowshield-feeds",
        "SlowShield Feeds",
        L,
        tags=["feeds"],
        variables=[],
        description="Threat-feed health, freshness and blocklist size.",
        time_from="now-7d",
        refresh="1m",
    )


# ---------------------------------------------------------------------------------------------
# 5. Caddy / TLS
# ---------------------------------------------------------------------------------------------

CADDY_LOG = '{service_name="caddy"}'


def caddy() -> dict[str, Any]:
    L = Layout()
    sel = 'job="caddy"'
    L.row("Edge traffic (Caddy metrics)")
    L.add(
        stat(
            "Requests / s", prom(f"sum(rate(caddy_http_request_duration_seconds_count{{{sel}}}[{RI}]))"), unit="reqps"
        ),
        6,
        4,
    )
    L.add(
        stat(
            "5xx ratio",
            prom(
                f'sum(rate(caddy_http_request_duration_seconds_count{{{sel},code=~"5.."}}[{RI}])) / sum(rate(caddy_http_request_duration_seconds_count{{{sel}}}[{RI}]))'
            ),
            unit="percentunit",
            decimals=2,
            thresholds=[(None, C["ok"]), (0.01, C["hold"]), (0.05, C["danger"])],
        ),
        6,
        4,
    )
    L.add(stat("In flight", prom(f"sum(caddy_http_requests_in_flight{{{sel}}})"), unit="short"), 6, 4)
    L.add(
        stat(
            "Upstream healthy",
            prom(f"min(caddy_reverse_proxy_upstreams_healthy{{{sel}}})"),
            graph=False,
            thresholds=[(None, C["danger"]), (1, C["ok"])],
            mappings=[{"type": "value", "options": {"1": {"text": "healthy"}, "0": {"text": "DOWN"}}}],
        ),
        6,
        4,
    )
    L.add(
        timeseries(
            "Requests by status code",
            [prom(f"sum by (code) (rate(caddy_http_request_duration_seconds_count{{{sel}}}[{RI}]))", "{{code}}")],
            unit="reqps",
            stack=True,
        ),
        12,
        8,
    )
    L.add(
        timeseries(
            "Latency p50 / p95 / p99",
            [
                prom(
                    f"histogram_quantile({q}, sum by (le) (rate(caddy_http_request_duration_seconds_bucket{{{sel}}}[{RI}])))",
                    f"p{int(q * 100)}",
                    ref=r,
                )
                for q, r in ((0.5, "A"), (0.95, "B"), (0.99, "C"))
            ],
            unit="s",
            fill=0,
        ),
        12,
        8,
    )
    L.add(
        timeseries(
            "Response bytes / s",
            [prom(f"sum(rate(caddy_http_response_size_bytes_sum{{{sel}}}[{RI}]))", "bytes")],
            unit="Bps",
        ),
        12,
        8,
    )
    L.add(
        timeseries(
            "Caddy memory & goroutines",
            [
                prom(f"max(process_resident_memory_bytes{{{sel}}})", "RSS", ref="A"),
            ],
            unit="bytes",
            fill=0,
        ),
        12,
        8,
    )
    L.row("TLS & protocols (access logs)")
    L.add(
        piechart(
            "TLS versions",
            [loki(f"sum by (tls) (count_over_time({CADDY_LOG} [$__range]))", instant=True, legend="{{tls}}")],
            ds=LOKI,
            colors={"TLS1.3": C["brand"], "TLS1.2": C["hold"], "none": C["muted"]},
        ),
        8,
        8,
    )
    L.add(
        piechart(
            "HTTP versions",
            [loki(f"sum by (proto) (count_over_time({CADDY_LOG} [$__range]))", instant=True, legend="{{proto}}")],
            ds=LOKI,
        ),
        8,
        8,
    )
    L.add(
        table(
            "Top clients",
            [loki(f"topk(15, sum by (remote_ip) (count_over_time({CADDY_LOG} [$__range])))", instant=True)],
            ds=LOKI,
            sort="Value",
            transformations=[
                {"id": "organize", "options": {"excludeByName": {"Time": True}, "renameByName": {"Value": "requests"}}}
            ],
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "Requests by host (logs)",
            [loki(f"sum by (host) (count_over_time({CADDY_LOG} [$__interval]))", legend="{{host}}")],
            ds=LOKI,
            bars=True,
            stack=True,
        ),
        12,
        8,
    )
    L.add(logs("Access log (errors)", f'{CADDY_LOG} | status=~"[45].."'), 12, 8)
    return dashboard(
        "slowshield-caddy",
        "SlowShield Caddy / TLS",
        L,
        tags=["caddy", "tls"],
        variables=[],
        description="Edge traffic, status codes and TLS/HTTP versions as seen by Caddy.",
    )


# ---------------------------------------------------------------------------------------------
# 6. Traces
# ---------------------------------------------------------------------------------------------


def traces() -> dict[str, Any]:
    L = Layout()
    sm = 'service=~"slowshield|caddy"'
    L.row("Span metrics (RED from Tempo)")
    L.add(
        timeseries(
            "Rate by span",
            [
                prom(
                    f'sum by (service, span_name) (rate(traces_spanmetrics_calls_total{{{sm},span_kind="SPAN_KIND_SERVER"}}[{RI}]))',
                    "{{service}} {{span_name}}",
                )
            ],
            unit="reqps",
            desc="Computed from sampled traces.",
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "Error ratio by span",
            [
                prom(
                    f'sum by (service, span_name) (rate(traces_spanmetrics_calls_total{{{sm},status_code="STATUS_CODE_ERROR"}}[{RI}])) / '
                    f"sum by (service, span_name) (rate(traces_spanmetrics_calls_total{{{sm}}}[{RI}]))",
                    "{{service}} {{span_name}}",
                )
            ],
            unit="percentunit",
            fill=0,
        ),
        8,
        8,
    )
    L.add(
        timeseries(
            "Duration p95 by span",
            [
                prom(
                    f"histogram_quantile(0.95, sum by (le, service, span_name) (rate(traces_spanmetrics_latency_bucket{{{sm}}}[{RI}])))",
                    "{{service}} {{span_name}}",
                )
            ],
            unit="s",
            fill=0,
        ),
        8,
        8,
    )
    L.row("Service graph & traces")
    L.add(
        {
            "type": "nodeGraph",
            "title": "Service graph",
            "datasource": TEMPO,
            "targets": [{"datasource": TEMPO, "queryType": "serviceMap", "refId": "A"}],
            "options": {},
        },
        12,
        12,
    )
    L.add(
        table(
            "Recent traces",
            [
                {
                    "datasource": TEMPO,
                    "queryType": "traceql",
                    "refId": "A",
                    "limit": 25,
                    "tableType": "traces",
                    "query": '{resource.service.name=~"slowshield|caddy"}',
                }
            ],
            ds=TEMPO,
        ),
        12,
        12,
    )
    L.add(
        table(
            "Slow traces (> 1 s)",
            [
                {
                    "datasource": TEMPO,
                    "queryType": "traceql",
                    "refId": "A",
                    "limit": 25,
                    "tableType": "traces",
                    "query": '{resource.service.name="slowshield" && duration > 1s}',
                }
            ],
            ds=TEMPO,
        ),
        12,
        10,
    )
    L.add(
        table(
            "Error traces",
            [
                {
                    "datasource": TEMPO,
                    "queryType": "traceql",
                    "refId": "A",
                    "limit": 25,
                    "tableType": "traces",
                    "query": '{resource.service.name=~"slowshield|caddy" && status = error}',
                }
            ],
            ds=TEMPO,
        ),
        12,
        10,
    )
    return dashboard(
        "slowshield-traces",
        "SlowShield Traces",
        L,
        tags=["traces"],
        variables=[],
        description="Tempo search, service graph and span-metric RED for SlowShield and Caddy.",
        time_from="now-1h",
    )


DASHBOARDS = {
    "slowshield-overview.json": overview,
    "slowshield-security.json": security,
    "slowshield-upstream.json": upstream,
    "slowshield-feeds.json": feeds,
    "slowshield-caddy.json": caddy,
    "slowshield-traces.json": traces,
}


def render() -> dict[str, str]:
    return {name: json.dumps(fn(), indent=2, sort_keys=False) + "\n" for name, fn in DASHBOARDS.items()}


def main(argv: list[str]) -> int:
    rendered = render()
    if "--check" in argv:
        stale = [n for n, body in rendered.items() if not (OUT / n).is_file() or (OUT / n).read_text() != body]
        if stale:
            print("stale dashboards (run build_dashboards.py):", ", ".join(stale))
            return 1
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    for name, body in rendered.items():
        (OUT / name).write_text(body)
        print("wrote", OUT / name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
