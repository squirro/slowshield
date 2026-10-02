#!/usr/bin/env python3
"""Static checks for the observability stack (stdlib only; CI runs it in the lint job).

    uv run python observability/check.py

1. Generated files are fresh: dashboards (build_dashboards.py) and alert rules (build_alerts.py).
2. Copies are in sync (sync.py): image pins in compose, Quadlet and Helm match images.env, and the
   Helm chart's files/ match observability/.
3. Dashboards: the file name is the uid, uids, titles and panel ids are unique, and datasources are only
   referenced through the template variables, whose defaults are provisioned datasource uids.
4. Alert rules: unique uids and titles; every query targets a provisioned datasource.
5. Metrics: every series a dashboard or alert rule queries is documented in METRICS.md, and the table in
   METRICS.md matches the instruments in src/slowshield (name, type and unit, which give the Prometheus name).
6. smoke.py expects exactly the provisioned dashboards and alert rules.
7. Wiring: the files compose and Quadlet mount exist, Grafana provisioning file names are unique (they
   become ConfigMap keys), the configs only address backends the Helm chart rewrites, both Alloy configs
   apply the same unit fixes, and the Kubernetes Alloy config scrapes the port the SlowShield chart names.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import re
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import redirect_stdout
from pathlib import Path
from types import ModuleType
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DASHBOARDS = HERE / "grafana" / "dashboards"
PROVISIONING = HERE / "grafana" / "provisioning"
RULES = PROVISIONING / "alerting" / "rules.yaml"
DATASOURCES = PROVISIONING / "datasources" / "datasources.yaml"
METRICS_MD = HERE / "METRICS.md"
SRC = ROOT / "src" / "slowshield"
COMPOSE = ROOT / "deploy" / "docker" / "compose.observability.yaml"
QUADLET_DIR = ROOT / "deploy" / "podman" / "observability"
SLOWSHIELD_DEPLOYMENT = ROOT / "deploy" / "helm" / "slowshield" / "templates" / "deployment.yaml"

# Backends the configs may address; the Helm chart rewrites exactly these (obs.rewriteHosts in
# deploy/helm/slowshield-observability/templates/_helpers.tpl).
REWRITTEN_HOSTS = {"prometheus:9090", "loki:3100", "tempo:3200"}
# Datasource references a dashboard may use besides its template variables.
BUILTIN_DATASOURCES = {"-- Grafana --", "-- Mixed --", "-- Dashboard --", "__expr__"}
UNIT_SUFFIXES = {"s": "seconds", "ms": "milliseconds", "us": "microseconds", "By": "bytes", "1": "ratio"}
PROMQL_WORDS = {"by", "without", "on", "ignoring", "group_left", "group_right", "bool", "and", "or", "unless"}
PROMQL_WORDS |= {"offset", "inf", "nan", "atan2"}

Problems = list[str]


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"_obs_{name}", HERE / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load observability/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_main(name: str, argv: list[str]) -> Problems:
    out = io.StringIO()
    with redirect_stdout(out):
        code = load(name).main(argv)
    lines = [f"{name}.py: {line}" for line in out.getvalue().splitlines()]
    return lines or ([f"{name}.py exited {code}"] if code else [])


# ---- dashboards & alert rules --------------------------------------------------------------------


def dashboards() -> dict[str, dict[str, Any]]:
    return {p.name: json.loads(p.read_text()) for p in sorted(DASHBOARDS.glob("*.json"))}


def alert_rules() -> list[dict[str, Any]]:
    body = "".join(line for line in RULES.read_text().splitlines(keepends=True) if not line.startswith("#"))
    return [r for g in json.loads(body)["groups"] for r in g["rules"]]


def datasource_uids() -> set[str]:
    return set(re.findall(r"(?m)^\s+uid:\s*(\S+)\s*$", DATASOURCES.read_text()))


def walk_panels(panels: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for p in panels:
        yield p
        yield from walk_panels(p.get("panels", []))


def _ds_ok(ds: Any, variables: set[str]) -> bool:
    if ds is None:
        return True
    uid = ds.get("uid") if isinstance(ds, dict) else ds
    return uid in BUILTIN_DATASOURCES or uid in {f"${{{v}}}" for v in variables} or uid in {f"${v}" for v in variables}


def check_dashboards() -> Problems:
    problems: Problems = []
    boards = dashboards()
    uids = datasource_uids()
    titles = Counter(d["title"] for d in boards.values())
    problems += [f"dashboard title used twice: {t}" for t, n in titles.items() if n > 1]
    for name, d in boards.items():
        if name != f"{d['uid']}.json":
            problems.append(f"{name}: file name does not match uid {d['uid']!r}")
        variables = d.get("templating", {}).get("list", [])
        ds_vars = {v["name"] for v in variables if v.get("type") == "datasource"}
        for v in variables:
            if v.get("type") == "datasource" and v["current"]["value"] not in uids:
                problems.append(
                    f"{name}: datasource variable {v['name']} defaults to unknown uid {v['current']['value']}"
                )
            elif not _ds_ok(v.get("datasource"), ds_vars):
                problems.append(f"{name}: variable {v['name']} uses datasource {v.get('datasource')} directly")
        ids = Counter()
        for panel in walk_panels(d.get("panels", [])):
            ids[panel.get("id")] += 1
            refs = [panel.get("datasource")] + [t.get("datasource") for t in panel.get("targets", [])]
            problems += [
                f"{name}: panel {panel.get('title')!r} uses datasource {ref} instead of a template variable"
                for ref in refs
                if not _ds_ok(ref, ds_vars)
            ]
        problems += [f"{name}: panel id {i} used {n} times" for i, n in ids.items() if n > 1]
    return problems


def check_alerts() -> Problems:
    problems: Problems = []
    rules = alert_rules()
    known = datasource_uids() | {"__expr__"}
    for key in ("uid", "title"):
        counts = Counter(r[key] for r in rules)
        problems += [f"alert rule {key} used twice: {v}" for v, n in counts.items() if n > 1]
    for r in rules:
        problems += [
            f"alert {r['title']}: query {q['refId']} targets unknown datasource {q['datasourceUid']}"
            for q in r["data"]
            if q["datasourceUid"] not in known
        ]
    return problems


def check_smoke() -> Problems:
    smoke = load("smoke")
    problems: Problems = []
    boards = {d["uid"] for d in dashboards().values()}
    titles = {r["title"] for r in alert_rules()}
    for label, expected, actual in (
        ("dashboards", smoke.DASHBOARD_UIDS, boards),
        ("alert rules", smoke.ALERT_TITLES, titles),
    ):
        if missing := sorted(actual - expected):
            problems.append(f"smoke.py does not expect provisioned {label}: {', '.join(missing)}")
        if extra := sorted(expected - actual):
            problems.append(f"smoke.py expects {label} that are not provisioned: {', '.join(extra)}")
    return problems


# ---- metrics ------------------------------------------------------------------------------------------


def promql_queries() -> list[tuple[str, str]]:
    """(where, PromQL) for every Prometheus query in the dashboards and alert rules."""
    queries: list[tuple[str, str]] = []
    for name, d in dashboards().items():
        for v in d.get("templating", {}).get("list", []):
            if v.get("type") == "query" and (v.get("datasource") or {}).get("type") == "prometheus":
                q = v["query"]["query"] if isinstance(v["query"], dict) else v["query"]
                m = re.fullmatch(r"\s*label_values\((.+),\s*\w+\s*\)\s*", q) or re.fullmatch(
                    r"\s*query_result\((.+)\)\s*", q
                )
                if m:
                    queries.append((f"{name} variable {v['name']}", m[1]))
        queries.extend(
            (f"{name} panel {panel.get('title')!r}", t["expr"])
            for panel in walk_panels(d.get("panels", []))
            for t in panel.get("targets", [])
            if (t.get("datasource") or {}).get("type") == "prometheus" and t.get("expr")
        )
    queries.extend(
        (f"alert {r['title']}", q["model"]["expr"])
        for r in alert_rules()
        for q in r["data"]
        if q["datasourceUid"] == "slowshield-prometheus"
    )
    return queries


def promql_metrics(expr: str) -> set[str]:
    """Metric names in a PromQL expression (strings, matchers, ranges and grouping clauses removed)."""
    s = re.sub(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', '""', expr)
    for _ in range(3):  # matchers may contain Grafana's ${var}
        s = re.sub(r"\{[^{}]*\}", " ", s)
    s = re.sub(r"\[[^\[\]]*\]", " ", s)
    s = re.sub(r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^()]*\)", " ", s)
    names = re.findall(r"(?<![\w$.])([a-zA-Z_:][\w:]*+)(?!\s*\()", s)
    return {n for n in names if n not in PROMQL_WORDS}


def metrics_doc() -> tuple[dict[str, dict[str, str]], set[str]]:
    """METRICS.md: {series: {type, instrument, unit}} and the accepted prefixes of other sources."""
    text = METRICS_MD.read_text()
    sections = dict(re.findall(r"(?ms)^## (.+?)\n(.*?)(?=^## |\Z)", text))
    series: dict[str, dict[str, str]] = {}
    for row in re.findall(r"(?m)^\|\s*`([^`]+)`\s*\|(.*)\|\s*$", sections["SlowShield series"]):
        cells = [c.strip().strip("`") for c in row[1].split("|")]
        series[row[0]] = {"type": cells[0], "instrument": cells[1], "unit": cells[2]}
    prefixes = set(re.findall(r"(?m)^\|\s*`([^`]+)`\s*\|", sections["Other series used by the dashboards"]))
    return series, prefixes


def alloy_unit_overrides(path: Path) -> dict[str, str]:
    """Units Alloy rewrites before export (`set(metric.unit, "x") where metric.name == "y"`)."""
    pattern = r'set\(metric\.unit,\s*"([^"]*)"\)\s*where\s+metric\.name\s*==\s*"([^"]+)"'
    return {name: unit for unit, name in re.findall(pattern, path.read_text())}


def source_instruments() -> dict[str, tuple[str, str | None]]:
    """{instrument: (type, unit or None if not statically known)} from src/slowshield."""
    kinds = {
        "create_counter": "counter",
        "create_histogram": "histogram",
        "create_up_down_counter": "gauge",
        "create_observable_gauge": "gauge",
        "create_gauge": "gauge",
        "observe": "gauge",
    }
    found: dict[str, tuple[str, str | None]] = {}
    unit_maps: dict[str, str] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                first = node.args[0] if node.args else None
                if func in kinds and isinstance(first, ast.Constant) and isinstance(first.value, str):
                    unit = next((k.value for k in node.keywords if k.arg == "unit"), ast.Constant(""))
                    found[first.value] = (kinds[func], unit.value if isinstance(unit, ast.Constant) else None)
            elif isinstance(node, ast.Dict) and node.keys:
                keys = [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                if len(keys) != len(node.keys) or not all("." in k for k in keys):
                    continue
                if all(isinstance(v, ast.Lambda) for v in node.values):  # {name: lambda: [...]} gauge tables
                    for k in keys:
                        found.setdefault(k, ("gauge", None))
                elif all(isinstance(v, ast.Constant) and isinstance(v.value, str) for v in node.values):
                    unit_maps.update(
                        zip(keys, [v.value for v in node.values if isinstance(v, ast.Constant)], strict=True)
                    )
    return {name: (kind, unit if unit is not None else unit_maps.get(name)) for name, (kind, unit) in found.items()}


def prometheus_name(instrument: str, kind: str, unit: str) -> str:
    """Prometheus 3 OTLP translation with UnderscoreEscapingWithSuffixes."""
    name = re.sub(r"[^a-zA-Z0-9_:]", "_", instrument)
    suffix = "" if not unit or unit.startswith("{") else UNIT_SUFFIXES.get(unit, unit)
    if suffix == "ratio" and kind != "gauge":
        suffix = ""
    if suffix and not name.endswith(f"_{suffix}"):
        name += f"_{suffix}"
    if kind == "counter" and not name.endswith("_total"):
        name += "_total"
    return name


def check_metrics() -> Problems:
    problems: Problems = []
    documented, prefixes = metrics_doc()
    overrides = alloy_unit_overrides(HERE / "alloy" / "config.alloy")
    by_instrument = {row["instrument"]: (series, row) for series, row in documented.items()}
    code = source_instruments()

    for instrument, (kind, unit) in sorted(code.items()):
        if instrument not in by_instrument:
            problems.append(f"METRICS.md lacks instrument {instrument} ({kind})")
            continue
        series, row = by_instrument[instrument]
        if row["type"] != kind:
            problems.append(f"METRICS.md: {series} is a {kind} in the code, documented as {row['type']}")
        exported = overrides.get(instrument, unit)
        if exported is not None and exported != row["unit"]:
            problems.append(f"METRICS.md: {series} has unit {exported!r} after export, documented as {row['unit']!r}")
        expected = prometheus_name(instrument, kind, exported if exported is not None else row["unit"])
        if expected != series:
            problems.append(f"METRICS.md: {instrument} is stored as {expected}, documented as {series}")
    problems += [
        f"METRICS.md documents {row['instrument']} which the code does not define"
        for row in documented.values()
        if row["instrument"] not in code
    ]

    for where, expr in promql_queries():
        for metric in sorted(promql_metrics(expr)):
            if metric not in documented and not any(metric.startswith(p) for p in prefixes):
                problems.append(f"{where}: queries {metric}, which METRICS.md does not document")
    return problems


# ---- wiring ---------------------------------------------------------------------------------------------


def check_wiring() -> Problems:
    problems: Problems = []
    for rel in re.findall(r"-\s+\.\./\.\./(observability/[^:\s]+):", COMPOSE.read_text()):
        if not (ROOT / rel).exists():
            problems.append(f"{COMPOSE.relative_to(ROOT)} mounts missing {rel}")
    for unit in sorted(QUADLET_DIR.glob("*.container")):
        for rel in re.findall(r"(?m)^Volume=%h/\.config/slowshield/observability/([^:\s]+):", unit.read_text()):
            if not (HERE / rel).exists():
                problems.append(f"{unit.relative_to(ROOT)} mounts missing observability/{rel}")

    names = Counter(p.name for p in PROVISIONING.rglob("*") if p.is_file())
    problems += [
        f"grafana/provisioning: file name {n} used {c} times (ConfigMap keys must be unique)"
        for n, c in names.items()
        if c > 1
    ]

    configs = [
        *PROVISIONING.rglob("*.yaml"),
        *(HERE / d / f for d, f in (("prometheus", "prometheus.yml"), ("loki", "loki.yaml"), ("tempo", "tempo.yaml"))),
    ]
    for path in configs:
        for host in re.findall(r"https?://([\w.\-]+:\d+)", path.read_text()):
            if host not in REWRITTEN_HOSTS and not host.startswith(("127.0.0.1:", "localhost:")):
                problems.append(f"{path.relative_to(ROOT)} addresses {host}, which the Helm chart does not rewrite")

    compose_alloy, k8s_alloy = HERE / "alloy" / "config.alloy", HERE / "alloy" / "config.k8s.alloy"
    if alloy_unit_overrides(compose_alloy) != alloy_unit_overrides(k8s_alloy):
        problems.append("alloy: config.alloy and config.k8s.alloy rewrite different metric units")
    port = re.search(r'regex\s*=\s*"caddy;([\w-]+)"', k8s_alloy.read_text())
    chart_ports = set(
        re.findall(r"-\s+name:\s*([\w-]+)\s*\n\s+containerPort:\s*9180", SLOWSHIELD_DEPLOYMENT.read_text())
    )
    if not port or port[1] not in chart_ports:
        problems.append(
            f"config.k8s.alloy scrapes Caddy port {port[1] if port else '?'}, the SlowShield chart names it {sorted(chart_ports)}"
        )
    return problems


CHECKS: list[tuple[str, Callable[[], Problems]]] = [
    ("dashboards are generated", lambda: run_main("build_dashboards", ["--check"])),
    ("alert rules are generated", lambda: run_main("build_alerts", ["--check"])),
    ("image pins and Helm copies are in sync", lambda: run_main("sync", ["--check"])),
    ("dashboards", check_dashboards),
    ("alert rules", check_alerts),
    ("metrics match METRICS.md and the code", check_metrics),
    ("smoke test expectations", check_smoke),
    ("wiring", check_wiring),
]


def main() -> int:
    failed = 0
    for title, fn in CHECKS:
        try:
            problems = fn()
        except Exception as exc:  # a broken input file is a failed check, not a crash
            problems = [f"{type(exc).__name__}: {exc}"]
        print(f"{'FAIL' if problems else 'ok  '} {title}")
        for p in problems:
            print(f"     - {p}")
        failed += bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
