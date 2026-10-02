#!/usr/bin/env python3
"""End-to-end smoke test of the observability stack (stdlib only).

    SLOWSHIELD_IMAGE=... SLOWSHIELD_CADDY_IMAGE=... FAKEUPSTREAM_IMAGE=... \
        uv run python observability/smoke.py [--keep] [--timeout 180]

Brings up deploy/docker/compose.yaml + compose.observability.yaml + compose.e2e.yaml (SlowShield wired
to the fake registry) under a unique project name, sends PyPI and npm traffic through Caddy (including
a blocked package, a too-new download and a fail-open package), then asserts that metrics reached
Prometheus, logs reached Loki, traces reached Tempo and that Grafana provisioned every dashboard and
alert rule. Backends are queried through Grafana's datasource proxy, so nothing but Grafana (on
loopback) and Caddy is published. Always tears the stack down (`down -v`) unless --keep is given.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOCKER_DIR = ROOT / "deploy" / "docker"
DASHBOARD_UIDS = {
    "slowshield-overview",
    "slowshield-security",
    "slowshield-upstream",
    "slowshield-feeds",
    "slowshield-caddy",
    "slowshield-traces",
}
ALERT_TITLES = {
    "TamperDetected",
    "MalwareBlocked",
    "FailOpenSpike",
    "FeedDisabled",
    "FeedStale",
    "FeedErrors",
    "SlowShieldDown",
    "NoLeader",
    "UpstreamErrorRate",
    "Http5xxRate",
    "HighLatency",
    "DBWriterBacklog",
    "ArtifactCacheOverLimit",
}
_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE  # Caddy's internal CA in the smoke stack


def log(msg: str) -> None:
    print(f"[smoke {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def free_port(preferred: int) -> int:
    for port in (preferred, 0):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return s.getsockname()[1]
    raise RuntimeError("no free port")


class Stack:
    def __init__(self, project: str, env: dict[str, str]) -> None:
        self.project = project
        self.env = env
        default = "compose.yaml compose.observability.yaml compose.e2e.yaml"
        self.files = os.environ.get("SMOKE_COMPOSE_FILES", default).split()

    def compose(self, *args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
        cmd = ["docker", "compose", "-p", self.project]
        for f in self.files:
            cmd += ["-f", f]
        cmd += list(args)
        return subprocess.run(
            cmd,
            cwd=DOCKER_DIR,
            env=self.env,
            check=check,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
        )


def http(
    url: str, *, headers: dict[str, str] | None = None, auth: tuple[str, str] | None = None, timeout: float = 15
) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers=headers or {})
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_INSECURE) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_for_blocklist(base: str, timeout: float = 120) -> bool:
    """The first feed sync runs at startup; wait until the fake MAL advisory is enforced."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, _body = http(f"{base}/pypi/simple/malware-pkg/")
        if status == 451:
            return True
        time.sleep(2)
    return False


def generate_traffic(base: str, rounds: int = 3) -> dict[str, int]:
    """PyPI + npm requests through Caddy. Returns status counts per scenario (for the report)."""
    seen: dict[str, int] = {}
    if not wait_for_blocklist(base):
        log("blocklist did not sync in time; 'blocked' checks will likely fail")
    json_accept = {"Accept": "application/vnd.pypi.simple.v1+json"}
    for _ in range(rounds):
        status, body = http(f"{base}/pypi/simple/alpha/", headers=json_accept)
        seen[f"pypi index {status}"] = seen.get(f"pypi index {status}", 0) + 1
        if status == 200:
            files = json.loads(body).get("files", [])
            wheels = [f for f in files if f["filename"].endswith(".whl")] or files
            if wheels:
                url = urllib.parse.urljoin(f"{base}/pypi/simple/alpha/", wheels[0]["url"])
                for _ in range(2):  # miss then cache hit
                    s, _b = http(url)
                    seen[f"pypi artifact {s}"] = seen.get(f"pypi artifact {s}", 0) + 1
        for path, label in (
            ("/pypi/simple/malware-pkg/", "pypi blocked"),
            ("/pypi/simple/brand-new/", "pypi fail-open"),
            ("/npm/left-pad-ng", "npm packument"),
            ("/npm/@acme%2fwidget", "npm scoped"),
            ("/npm/left-pad-ng/-/left-pad-ng-1.1.0.tgz", "npm tarball"),
            ("/npm/left-pad-ng/-/left-pad-ng-2.0.0.tgz", "npm too-new"),
            ("/npm/malicious-npm", "npm blocked"),
            ("/", "ui"),
        ):
            s, _b = http(base + path)
            seen[f"{label} {s}"] = seen.get(f"{label} {s}", 0) + 1
        time.sleep(2)
    return seen


class Grafana:
    def __init__(self, base: str, password: str) -> None:
        self.base = base
        self.auth = ("admin", password)

    def get(self, path: str, **params: str) -> Any:
        qs = ("?" + urllib.parse.urlencode(params)) if params else ""
        status, body = http(self.base + path + qs, auth=self.auth)
        if status != 200:
            raise RuntimeError(f"GET {path} -> {status}: {body[:200]!r}")
        return json.loads(body)

    def prom(self, query: str) -> list[Any]:
        data = self.get("/api/datasources/proxy/uid/slowshield-prometheus/api/v1/query", query=query)
        return data["data"]["result"]

    def loki_count(self, query: str) -> int:
        now = time.time()
        data = self.get(
            "/api/datasources/proxy/uid/slowshield-loki/loki/api/v1/query_range",
            query=query,
            start=str(int((now - 3600) * 1e9)),
            end=str(int((now + 60) * 1e9)),
            limit="1000",
        )
        return sum(len(s["values"]) for s in data["data"]["result"])

    def tempo_traces(self, service: str) -> int:
        data = self.get(
            "/api/datasources/proxy/uid/slowshield-tempo/api/search", tags=f"service.name={service}", limit="20"
        )
        return len(data.get("traces") or [])


def checks(g: Grafana) -> dict[str, tuple[bool, str]]:
    out: dict[str, tuple[bool, str]] = {}

    def attempt(name: str, fn: Any) -> None:
        try:
            ok, detail = fn()
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"[:200]
        out[name] = (ok, detail)

    def series(q: str) -> tuple[bool, str]:
        n = len(g.prom(q))
        return n > 0, f"{n} series"

    attempt("prometheus: slowshield_decisions_total", lambda: series("slowshield_decisions_total"))
    attempt("prometheus: http_server_request_duration_seconds", lambda: series("http_server_request_duration_seconds"))
    attempt("prometheus: slowshield_feed_enabled", lambda: series("slowshield_feed_enabled"))
    attempt("prometheus: blocked decision", lambda: series('slowshield_decisions_total{slowshield_decision="blocked"}'))
    attempt("prometheus: caddy metrics", lambda: series('caddy_http_request_duration_seconds_count{job="caddy"}'))
    attempt("prometheus: span-metrics", lambda: series('traces_spanmetrics_calls_total{service="slowshield"}'))

    def loki_lines() -> tuple[bool, str]:
        n = g.loki_count('{service_name="slowshield"}')
        return n > 0, f"{n} lines"

    def loki_security() -> tuple[bool, str]:
        n = g.loki_count('{service_name="slowshield"} | slowshield_event=~"blocked|age_gate|fail_open"')
        return n > 0, f"{n} security events"

    def loki_caddy() -> tuple[bool, str]:
        n = g.loki_count('{service_name="caddy"}')
        return n > 0, f"{n} access-log lines"

    attempt("loki: slowshield logs", loki_lines)
    attempt("loki: security event logs", loki_security)
    attempt("loki: caddy access logs", loki_caddy)

    def tempo() -> tuple[bool, str]:
        n = g.tempo_traces("slowshield")
        return n > 0, f"{n} traces"

    attempt("tempo: slowshield traces", tempo)

    def dashboards() -> tuple[bool, str]:
        found = {d.get("uid") for d in g.get("/api/search", type="dash-db")}
        missing = DASHBOARD_UIDS - found
        return not missing, "all 6 provisioned" if not missing else f"missing {sorted(missing)}"

    def alerts() -> tuple[bool, str]:
        found = {r.get("title") for r in g.get("/api/v1/provisioning/alert-rules")}
        missing = ALERT_TITLES - found
        return not missing, f"{len(found)} rules" if not missing else f"missing {sorted(missing)}"

    attempt("grafana: dashboards", dashboards)
    attempt("grafana: alert rules", alerts)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--keep", action="store_true", help="leave the stack running for debugging")
    ap.add_argument("--timeout", type=float, default=180.0, help="seconds to wait for telemetry")
    args = ap.parse_args()

    required = ["SLOWSHIELD_IMAGE", "SLOWSHIELD_CADDY_IMAGE"]
    if "compose.e2e.yaml" in os.environ.get("SMOKE_COMPOSE_FILES", "compose.e2e.yaml"):
        required.append("FAKEUPSTREAM_IMAGE")
    missing = [v for v in required if not os.environ.get(v)]
    if missing:
        print(f"error: set {', '.join(missing)} (image references to test)", file=sys.stderr)
        return 2

    project = f"slowshield-smoke-{secrets.token_hex(3)}"
    https_port = free_port(int(os.environ.get("HTTPS_PORT", "8443")))
    http_port = free_port(int(os.environ.get("HTTP_PORT", "8080")))
    grafana_port = free_port(int(os.environ.get("GRAFANA_PORT", "3000")))
    fake_port = free_port(int(os.environ.get("FAKEUPSTREAM_PORT", "19000")))
    password = secrets.token_urlsafe(18)
    env = {
        **os.environ,
        "HTTPS_PORT": str(https_port),
        "HTTP_PORT": str(http_port),
        "GRAFANA_PORT": str(grafana_port),
        "FAKEUPSTREAM_PORT": str(fake_port),
        # Same SlowShield config as tests/e2e: every upstream (PyPI, npm, OSV, GitHub) is the fake registry.
        "SLOWSHIELD_CONFIG_FILE": str(ROOT / "tests" / "e2e" / "config.e2e.toml"),
        "GITHUB_TOKEN_SECRET_FILE": str(ROOT / "tests" / "e2e" / "github_token"),
        "GRAFANA_ADMIN_PASSWORD": password,
        "SLOWSHIELD_TLS_MODE": "internal",
        "SLOWSHIELD_HOSTNAMES": "localhost",
        "SLOWSHIELD_PUBLIC_URL": f"https://localhost:{https_port}",
        "SLOWSHIELD_TRACE_SAMPLE_RATIO": "1.0",
        "SLOWSHIELD_ENVIRONMENT": "smoke",
    }
    stack = Stack(project, env)
    base = f"https://localhost:{https_port}"
    log(f"project {project}: https={https_port} grafana={grafana_port}")
    failed = True
    try:
        stack.compose("up", "-d", "--wait", "--wait-timeout", "240", "--quiet-pull")
        log("stack is up; generating traffic")
        seen = generate_traffic(base)
        for k in sorted(seen):
            log(f"  {k}: {seen[k]}")
        g = Grafana(f"http://127.0.0.1:{grafana_port}", password)
        deadline = time.monotonic() + args.timeout
        results: dict[str, tuple[bool, str]] = {}
        while True:
            results = checks(g)
            if all(ok for ok, _ in results.values()) or time.monotonic() > deadline:
                break
            generate_traffic(base, rounds=1)
            time.sleep(5)
        print("\nObservability smoke test")
        for name, (ok, detail) in results.items():
            print(f"  {'PASS' if ok else 'FAIL'}  {name:48} {detail}")
        failed = not all(ok for ok, _ in results.values())
        if failed:
            log("failure — last service logs follow")
            stack.compose("logs", "--tail", "40", check=False)
        return 1 if failed else 0
    except subprocess.CalledProcessError as exc:
        log(f"docker compose failed: {exc}")
        stack.compose("ps", "-a", check=False)
        stack.compose("logs", "--tail", "60", check=False)
        return 1
    finally:
        if args.keep:
            log(
                f"--keep: stack left running (docker compose -p {project} ... down -v to remove); grafana password: {password}"
            )
        else:
            stack.compose("down", "-v", "--remove-orphans", check=False, capture=True)
            log("stack removed")


if __name__ == "__main__":
    raise SystemExit(main())
