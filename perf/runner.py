"""A/B performance runner: candidate vs baseline container image on the same machine.

Each round starts a fresh proxy container (CPU-pinned, memory-capped, read-only, same hardening as
production) against the deterministic fakeupstream, warms it up, runs every k6 scenario and records
throughput, latency percentiles, error rate, peak RSS, CPU per 1k requests and startup time. Rounds
alternate image order (AB, BA, ...) so drift on a shared runner hits both sides equally.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from perf.stats import mann_whitney_p, median, relative_change

ROOT = Path(__file__).resolve().parent
K6_SCRIPT = ROOT / "k6" / "scenarios.js"
PORT = 18080
UPSTREAM_PORT = 18099  # fakeupstream, published only to wait for /healthz
CONFIG = ROOT / "slowshield.toml"
_GO_SECTION = re.compile(r"(?ms)^# Releases before Go and Maven support.*?(?=^\[feeds\])")


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    mode: str  # latency | throughput
    rate: int = 0
    vus: int = 0


PROFILES: dict[str, list[Scenario]] = {
    "full": [
        Scenario("pypi_simple_json", "throughput", vus=32),
        Scenario("pypi_simple_json", "latency", rate=300),
        Scenario("pypi_simple_html", "latency", rate=300),
        Scenario("npm_packument_corgi", "throughput", vus=32),
        Scenario("npm_packument_full", "latency", rate=300),
        Scenario("npm_huge_full", "throughput", vus=8),
        Scenario("npm_huge_corgi", "throughput", vus=8),
        Scenario("artifact_cached", "throughput", vus=32),
        Scenario("artifact_cached", "latency", rate=300),
        Scenario("artifact_big", "throughput", vus=4),
        Scenario("blocked", "latency", rate=300),
        Scenario("dashboard", "latency", rate=30),
        Scenario("mixed", "throughput", vus=32),
        Scenario("go_list", "throughput", vus=32),
        Scenario("go_mod", "latency", rate=300),
        Scenario("maven_metadata", "throughput", vus=32),
        Scenario("maven_jar", "latency", rate=300),
    ],
    "quick": [
        Scenario("pypi_simple_json", "throughput", vus=32),
        Scenario("npm_packument_corgi", "throughput", vus=32),
        Scenario("artifact_cached", "throughput", vus=32),
        Scenario("mixed", "latency", rate=200),
        Scenario("blocked", "latency", rate=200),
        Scenario("go_mod", "throughput", vus=32),
        Scenario("maven_jar", "throughput", vus=32),
    ],
}


@dataclass(slots=True)
class Sample:
    image: str
    round: int
    scenario: str
    mode: str
    rps: float
    p50: float
    p95: float
    p99: float
    error_rate: float
    data_mb_s: float
    cpu_ms_per_1k: float | None


@dataclass(slots=True)
class ImageRun:
    image: str
    round: int
    startup_s: float
    rss_peak_bytes: int | None


@dataclass(slots=True)
class Results:
    started: float
    host: dict[str, str]
    images: dict[str, str]  # role -> ref
    image_sizes: dict[str, int] = field(default_factory=dict)
    samples: list[Sample] = field(default_factory=list)
    runs: list[ImageRun] = field(default_factory=list)


def sh(*args: str, check: bool = True, capture: bool = True, timeout: float | None = None) -> str:
    proc = subprocess.run(args, check=check, capture_output=capture, text=True, timeout=timeout)
    return proc.stdout.strip() if capture else ""


def _cgroup_dir(container_id: str) -> Path | None:
    for candidate in (
        Path(f"/sys/fs/cgroup/system.slice/docker-{container_id}.scope"),
        Path(f"/sys/fs/cgroup/docker/{container_id}"),
    ):
        if candidate.is_dir():
            return candidate
    return None


def _cpu_usec(cg: Path | None) -> int | None:
    if cg is None:
        return None
    try:
        for line in (cg / "cpu.stat").read_text().splitlines():
            if line.startswith("usage_usec"):
                return int(line.split()[1])
    except OSError:
        return None
    return None


def _mem_peak(cg: Path | None, container: str) -> int | None:
    if cg is not None:
        try:
            return int((cg / "memory.peak").read_text().strip())
        except OSError, ValueError:
            pass
    try:  # Docker Desktop / no cgroup access: current usage is the best we can do
        raw = sh("docker", "stats", "--no-stream", "--format", "{{json .}}", container)
        usage = json.loads(raw)["MemUsage"].split("/")[0].strip()
        units = {"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "B": 1}
        for suffix, mult in units.items():
            if usage.endswith(suffix):
                return int(float(usage[: -len(suffix)]) * mult)
    except subprocess.CalledProcessError, KeyError, ValueError, json.JSONDecodeError:
        return None
    return None


def _wait_ready(url: str, timeout: float = 60.0) -> float:
    start = time.perf_counter()
    while time.perf_counter() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return time.perf_counter() - start
        except urllib.error.URLError, OSError:
            pass
        time.sleep(0.05)
    raise TimeoutError(f"{url} not ready after {timeout}s")


def _wait_blocked(url: str, timeout: float = 120.0) -> None:
    """Wait until the malware feed is loaded and `url` answers 451. The `blocked` scenario measures the
    451 path; a round started earlier would be served 200s and report every request as an error."""
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.pypi.simple.v1+json"})
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        try:
            with urllib.request.urlopen(req, timeout=5):
                pass
        except urllib.error.HTTPError as exc:
            if exc.code == 451:
                return
        except urllib.error.URLError, OSError:
            pass
        time.sleep(0.5)
    raise TimeoutError(f"{url} not blocked after {timeout}s: the malware feed did not load")


def _diagnose(container: str) -> None:
    """A failed run removes its container: print what it knew first (logs, feed status) for the CI log."""
    logs = subprocess.run(["docker", "logs", "--tail", "60", container], capture_output=True, text=True, check=False)
    print(f"--- {container}: last log lines\n{logs.stdout}{logs.stderr}", flush=True)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/ui/feeds", timeout=5) as resp:
            page = resp.read().decode(errors="replace")
        text = " ".join(re.sub(r"<[^>]+>", " ", page).split())
        start = text.find("OSV malicious packages")
        osv = text[start : start + 400] if start >= 0 else "(no OSV section)"
        print(f"--- {container}: feeds page: {osv}", flush=True)
    except urllib.error.URLError, OSError, ValueError:
        print(f"--- {container}: feeds page not reachable", flush=True)


class Harness:
    def __init__(
        self,
        *,
        fakeupstream: str,
        k6: str = "k6",
        duration: str = "20s",
        server_cpus: str = "1",
        load_cpus: str = "0",
        memory: str = "1g",
        workers: int = 1,
    ) -> None:
        self.fakeupstream = fakeupstream
        self.k6 = k6
        self.duration = duration
        self.server_cpus = server_cpus
        self.load_cpus = load_cpus
        self.memory = memory
        self.workers = workers
        self.network = f"slowshield-perf-{os.getpid()}"
        self.now = int(time.time())
        self.taskset = shutil.which("taskset") if platform.system() == "Linux" else None
        self._configs: dict[str, Path] = {}

    def __enter__(self) -> Harness:
        sh("docker", "network", "create", self.network)
        sh(
            "docker", "run", "-d", "--rm", "--name", f"{self.network}-up", "--network", self.network,
            "--network-alias", "fakeupstream", *self._cpuset(self.load_cpus), "-p", f"127.0.0.1:{UPSTREAM_PORT}:9000",
            self.fakeupstream, "--host", "0.0.0.0", "--port", "9000", "--perf", "--now", str(self.now),
        )  # fmt: skip
        # SlowShield syncs its feeds right at startup: an upstream still starting would fail that sync.
        _wait_ready(f"http://127.0.0.1:{UPSTREAM_PORT}/healthz")
        return self

    def __exit__(self, *exc: object) -> None:
        subprocess.run(
            ["docker", "rm", "-f", f"{self.network}-up", f"{self.network}-ss"], capture_output=True, check=False
        )
        subprocess.run(["docker", "network", "rm", self.network], capture_output=True, check=False)

    def _cpuset(self, cpus: str) -> list[str]:
        return ["--cpuset-cpus", cpus] if platform.system() == "Linux" and cpus else []

    def _config_for(self, image: str) -> Path:
        """perf/slowshield.toml, without the Go upstream for an image that rejects it (a baseline from before Go
        support). Its Go scenarios then fail and are reported as new, without a comparison."""
        if image not in self._configs:
            probe = subprocess.run(
                ["docker", "run", "--rm", "-v", f"{CONFIG}:/c.toml:ro", image, "check-config", "--config", "/c.toml"],
                capture_output=True,
                check=False,
            )
            path = CONFIG
            if probe.returncode != 0:
                path = Path(tempfile.gettempdir()) / f"slowshield-perf-{os.getpid()}-nogo.toml"
                path.write_text(_GO_SECTION.sub("", CONFIG.read_text()))
            self._configs[image] = path
        return self._configs[image]

    def run_image(self, image: str, rnd: int, scenarios: list[Scenario]) -> tuple[ImageRun, list[Sample]]:
        name = f"{self.network}-ss"
        volume = f"{name}-data-{rnd}-{abs(hash(image)) % 10_000}"
        t0 = time.perf_counter()
        cid = sh(
            "docker", "run", "-d", "--rm", "--name", name, "--network", self.network,
            *self._cpuset(self.server_cpus), "--memory", self.memory, "--pids-limit", "256",
            "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "-p", f"127.0.0.1:{PORT}:8080",
            "-v", f"{volume}:/data", "-v", f"{self._config_for(image)}:/etc/slowshield/config.toml:ro",
            "-e", "SLOWSHIELD_CONFIG=/etc/slowshield/config.toml", "-e", f"SLOWSHIELD_WORKERS={self.workers}",
            "-e", "SLOWSHIELD_LOG_LEVEL=warning", image,
        )  # fmt: skip
        try:
            _wait_ready(f"http://127.0.0.1:{PORT}/readyz")
            startup = time.perf_counter() - t0
            cg = _cgroup_dir(cid)
            # Before the warmup, so its large downloads do not compete with the first feed sync.
            _wait_blocked(f"http://127.0.0.1:{PORT}/pypi/simple/malware-pkg/")
            self._warmup()
            samples = [self._k6(image, rnd, sc, cg) for sc in scenarios]
            rss = _mem_peak(cg, name)
            return ImageRun(image, rnd, startup, rss), samples
        except Exception:
            _diagnose(name)
            raise
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
            subprocess.run(["docker", "volume", "rm", "-f", volume], capture_output=True, check=False)

    def _warmup(self) -> None:
        base = f"http://127.0.0.1:{PORT}"
        for path, accept in (
            ("/pypi/simple/alpha/", "application/vnd.pypi.simple.v1+json"),
            ("/pypi/simple/many-versions/", "application/vnd.pypi.simple.v1+json"),
            ("/pypi/simple/many-versions/", "text/html"),
            ("/pypi/simple/big-wheel/", "application/vnd.pypi.simple.v1+json"),
            ("/npm/left-pad-ng", "application/json"),
            ("/npm/left-pad-ng", "application/vnd.npm.install-v1+json"),
            ("/npm/huge-packument", "application/json"),
            ("/npm/huge-packument", "application/vnd.npm.install-v1+json"),
            ("/npm/@acme%2fwidget", "application/vnd.npm.install-v1+json"),
            ("/npm/tagged", "application/json"),
            ("/go/example.com/many/@v/list", "text/plain"),
            ("/go/example.com/hello/@v/v1.0.0.mod", "text/plain"),  # verified and cached on the first request
            ("/maven/all/org/example/many/maven-metadata.xml", "text/xml"),
            ("/maven/all/org/example/hello/1.0.0/hello-1.0.0.jar", "*/*"),
            ("/", "text/html"),
        ):
            req = urllib.request.Request(base + path, headers={"Accept": accept})
            for _ in range(3):
                try:
                    with urllib.request.urlopen(req, timeout=60) as resp:
                        resp.read()
                except urllib.error.URLError, OSError:
                    pass
        # First artifact downloads populate the verified cache.
        self._k6_raw("artifact_cached", "throughput", vus=2, rate=0, duration="3s")
        self._k6_raw("artifact_big", "throughput", vus=1, rate=0, duration="5s")

    def _k6_raw(self, scenario: str, mode: str, *, vus: int, rate: int, duration: str) -> dict[str, Any]:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out = Path(tmp.name)
        cmd = [
            self.k6, "run", "--quiet", "--no-color", "--summary-export", str(out),
            "-e", f"TARGET=http://127.0.0.1:{PORT}", "-e", f"SCENARIO={scenario}", "-e", f"MODE={mode}",
            "-e", f"VUS={vus}", "-e", f"RATE={rate}", "-e", f"DURATION={duration}", str(K6_SCRIPT),
        ]  # fmt: skip
        if self.taskset:
            cmd = [self.taskset, "-c", self.load_cpus, *cmd]
        subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=900)
        try:
            return json.loads(out.read_text())
        except OSError, json.JSONDecodeError:
            return {}
        finally:
            out.unlink(missing_ok=True)

    def _k6(self, image: str, rnd: int, sc: Scenario, cg: Path | None) -> Sample:
        before = _cpu_usec(cg)
        summary = self._k6_raw(sc.name, sc.mode, vus=sc.vus, rate=sc.rate, duration=self.duration)
        after = _cpu_usec(cg)
        metrics = summary.get("metrics", {})
        dur = metrics.get("http_req_duration", {})
        reqs = metrics.get("http_reqs", {})
        failed = metrics.get("http_req_failed", {})
        received = metrics.get("data_received", {})
        count = reqs.get("count", 0) or 0
        cpu = None
        if before is not None and after is not None and count:
            cpu = (after - before) / 1000 / (count / 1000)
        return Sample(
            image=image,
            round=rnd,
            scenario=sc.name,
            mode=sc.mode,
            rps=float(reqs.get("rate", 0.0)),
            p50=float(dur.get("med", 0.0)),
            p95=float(dur.get("p(95)", 0.0)),
            p99=float(dur.get("p(99)", 0.0)),
            error_rate=float(failed.get("value", failed.get("rate", 0.0)) or 0.0),
            data_mb_s=float(received.get("rate", 0.0)) / 1e6,
            cpu_ms_per_1k=cpu,
        )


def image_size(ref: str) -> int:
    try:
        return int(sh("docker", "image", "inspect", "--format", "{{.Size}}", ref))
    except subprocess.CalledProcessError, ValueError:
        return 0


def run(
    *,
    candidate: str,
    baseline: str | None,
    fakeupstream: str,
    rounds: int,
    profile: str,
    duration: str,
    k6: str,
    workers: int,
    only: set[str] | None = None,
) -> Results:
    scenarios = [s for s in PROFILES[profile] if not only or f"{s.name}:{s.mode}" in only]
    images = {"candidate": candidate} | ({"baseline": baseline} if baseline else {})
    res = Results(
        started=time.time(),
        host={"machine": platform.machine(), "system": platform.system(), "cpus": str(os.cpu_count())},
        images=images,
    )
    for role, ref in images.items():
        res.image_sizes[role] = image_size(ref)
    with Harness(fakeupstream=fakeupstream, k6=k6, duration=duration, workers=workers) as h:
        for rnd in range(rounds):
            order = list(images.values())
            if rnd % 2:
                order.reverse()
            for ref in order:
                run_, samples = h.run_image(ref, rnd, scenarios)
                res.runs.append(run_)
                res.samples.extend(samples)
                print(
                    f"round {rnd + 1}/{rounds} {ref}: startup {run_.startup_s:.2f}s, rss {run_.rss_peak_bytes}",
                    flush=True,
                )
    return res


# ---- gate ------------------------------------------------------------------------------------------


@dataclass(slots=True)
class Finding:
    scenario: str
    metric: str
    baseline: float
    candidate: float
    change: float
    threshold: float
    p_value: float | None
    regression: bool


def _limits(thresholds: dict[str, Any], scenario: str) -> dict[str, float]:
    out = dict(thresholds.get("defaults", {}))
    out.update(thresholds.get("scenario", {}).get(scenario, {}))
    return out


def evaluate(res: Results, thresholds: dict[str, Any]) -> list[Finding]:
    if "baseline" not in res.images:
        return []
    gate = thresholds.get("gate", {})
    alpha = float(gate.get("alpha", 0.05))
    min_rounds = int(gate.get("min_rounds_for_significance", 5))
    cand, base = res.images["candidate"], res.images["baseline"]
    findings: list[Finding] = []

    def compare(scn: str, metric: str, a: list[float], b: list[float], limit: float, higher_is_worse: bool) -> None:
        if not a or not b:
            return
        mb, mc = median(b), median(a)
        change = relative_change(mb, mc)
        worse = change > limit if higher_is_worse else change < -limit
        p = mann_whitney_p(a, b) if min(len(a), len(b)) >= min_rounds else None
        significant = p is None or p < alpha
        findings.append(Finding(scn, metric, mb, mc, change, limit, p, bool(worse and significant)))

    keys = sorted({(s.scenario, s.mode) for s in res.samples})
    for scn, mode in keys:
        lim = _limits(thresholds, scn)
        a = [s for s in res.samples if s.image == cand and s.scenario == scn and s.mode == mode]
        # A baseline that does not serve the scenario yet (Go before its release) answers mostly with errors:
        # the scenario is new, so it is reported without a comparison (its own error rate is still checked).
        b = [s for s in res.samples if s.image == base and s.scenario == scn and s.mode == mode and s.error_rate < 0.5]
        label = f"{scn}:{mode}"
        if mode == "throughput":
            compare(label, "rps", [s.rps for s in a], [s.rps for s in b], lim["throughput_drop"], higher_is_worse=False)
        else:
            compare(label, "p95_ms", [s.p95 for s in a], [s.p95 for s in b], lim["p95_increase"], higher_is_worse=True)
            compare(label, "p99_ms", [s.p99 for s in a], [s.p99 for s in b], lim["p99_increase"], higher_is_worse=True)
        errs = [s.error_rate for s in a]
        if errs and max(errs) > lim["error_rate_max"]:
            findings.append(Finding(label, "error_rate", 0.0, max(errs), 0.0, lim["error_rate_max"], None, True))
    lim = thresholds.get("defaults", {})
    rss_a = [r.rss_peak_bytes for r in res.runs if r.image == cand and r.rss_peak_bytes]
    rss_b = [r.rss_peak_bytes for r in res.runs if r.image == base and r.rss_peak_bytes]
    compare(
        "process", "rss_peak_bytes", [float(x) for x in rss_a], [float(x) for x in rss_b], lim["rss_increase"], True
    )
    st_a = [r.startup_s for r in res.runs if r.image == cand]
    st_b = [r.startup_s for r in res.runs if r.image == base]
    compare("process", "startup_s", st_a, st_b, lim["startup_increase"], True)
    if res.image_sizes.get("baseline") and res.image_sizes.get("candidate"):
        size_change = relative_change(res.image_sizes["baseline"], res.image_sizes["candidate"])
        findings.append(
            Finding(
                "image",
                "size_bytes",
                res.image_sizes["baseline"],
                res.image_sizes["candidate"],
                size_change,
                lim["image_size_increase"],
                None,
                size_change > lim["image_size_increase"],
            )
        )
    return findings


def report(res: Results, findings: list[Finding]) -> str:
    cand = res.images["candidate"]
    base = res.images.get("baseline")
    lines = [
        "## SlowShield performance report",
        "",
        f"Host: `{res.host['system']}/{res.host['machine']}`, {res.host['cpus']} CPUs · candidate `{cand}`"
        + (f" · baseline `{base}`" if base else " (no baseline: this run establishes it)"),
        "",
        "| Scenario | Metric | Baseline | Candidate | Change | Limit | p | |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for f in findings:
        mark = "❌" if f.regression else "✅"
        p = "—" if f.p_value is None else f"{f.p_value:.3f}"
        lines.append(
            f"| {f.scenario} | {f.metric} | {_fmt(f.metric, f.baseline)} | {_fmt(f.metric, f.candidate)} | "
            f"{f.change * 100:+.1f}% | {f.threshold * 100:.0f}% | {p} | {mark} |"
        )
    if not findings:
        lines.append("| — | — | — | — | — | — | — | |")
    lines += [
        "",
        "### Candidate medians",
        "",
        "| Scenario | rps | p50 ms | p95 ms | p99 ms | MB/s | CPU ms/1k |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    if True:
        for scn, mode in sorted({(s.scenario, s.mode) for s in res.samples}):
            ss = [s for s in res.samples if s.image == cand and s.scenario == scn and s.mode == mode]
            cpu = [s.cpu_ms_per_1k for s in ss if s.cpu_ms_per_1k is not None]
            lines.append(
                f"| {scn}:{mode} | {median([s.rps for s in ss]):.0f} | {median([s.p50 for s in ss]):.2f} | "
                f"{median([s.p95 for s in ss]):.2f} | {median([s.p99 for s in ss]):.2f} | "
                f"{median([s.data_mb_s for s in ss]):.1f} | {median(cpu) if cpu else float('nan'):.1f} |"
            )
    rss = [r.rss_peak_bytes for r in res.runs if r.image == cand and r.rss_peak_bytes]
    lines += [
        "",
        f"Image size: {res.image_sizes.get('candidate', 0) / 1e6:.1f} MB (uncompressed)"
        + (f", RSS peak median {median([float(x) for x in rss]) / 1e6:.1f} MB" if rss else ""),
    ]
    return "\n".join(lines) + "\n"


def _fmt(metric: str, v: float) -> str:
    if metric.endswith("bytes"):
        return f"{v / 1e6:.1f} MB"
    if metric == "rps":
        return f"{v:.0f}"
    return f"{v:.2f}"


def load_thresholds(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text())


def save(res: Results, findings: list[Finding], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(
        json.dumps({"results": asdict(res), "findings": [asdict(f) for f in findings]}, indent=2)
    )
    (out / "report.md").write_text(report(res, findings))
