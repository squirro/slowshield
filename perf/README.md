# Performance baseline & regression gate

Two layers, both runnable locally and in CI:

| Layer | What | Command |
|---|---|---|
| **Macro** (gate) | Container image under load: k6 against the hardened proxy container, upstream = deterministic `fakeupstream` | `uv run python -m perf run --candidate slowshield:dev --baseline registry.squirro.com/slowshield/slowshield:latest --gate` |
| **Micro** (signal) | Hot code paths in-process (packument filtering, PEP 691 parse/render, blocklist, negotiation) | `uv run python -m perf micro --out perf/results/micro.json [--compare old.json]` |

## Why A/B instead of absolute numbers

GitHub-hosted runners are shared VMs (2 vCPUs for private repositories), so absolute throughput varies from
run to run by more than the regressions we care about. The release workflow therefore never compares against
numbers recorded on another day: it measures the **previous release image and the candidate on the same
runner, in the same job**, alternating order every round (AB, BA, AB, …), and compares medians.

Noise controls:

* the proxy runs in a container pinned to one CPU (`--cpuset-cpus 1 --memory 1g`); k6 and the fake upstream
  share the other CPU (`taskset -c 0`);
* fresh container (and fresh `/data` volume) per round, explicit warm-up so caches are in steady state;
* open-model (`constant-arrival-rate`) scenarios for latency, closed-model (`constant-vus`) for throughput;
* a metric regresses only if its median moves past the threshold in `thresholds.toml` **and** the difference is
  significant (two-sided exact Mann–Whitney U, p < 0.05, ≥ 5 rounds); regressed scenarios are re-measured once
  before the gate fails.

## Scenarios (`k6/scenarios.js`, profiles in `runner.py`)

`pypi_simple_json`, `pypi_simple_html` (500-version project), `npm_packument_full` / `npm_packument_corgi`,
`npm_huge_full` / `npm_huge_corgi` (5,000 versions), `artifact_cached` (verified cache hit, zero-copy),
`artifact_big` (100 MB stream, MB/s), `blocked` (451 path), `dashboard` (UI render) and `mixed`
(45 % PyPI index, 30 % npm abbreviated, 20 % artifacts, 5 % full packuments).

Recorded per scenario: requests/s, p50/p95/p99, error rate, MB/s, CPU-ms per 1,000 requests (cgroup
`cpu.stat`); per image: peak RSS (cgroup `memory.peak`), startup-to-ready time and image size.

## Baseline

The first tagged release has no predecessor: its run *establishes* the baseline (report only, no gate).
Every later release is gated against the image currently tagged `latest` in Harbor. Reports are attached to
the GitHub Release and written to the job summary; raw samples are uploaded as `results.json`.

## Running locally

```bash
docker buildx build -f containers/slowshield/Dockerfile -t slowshield:dev --load .
docker buildx build -f containers/fakeupstream/Dockerfile -t slowshield-fakeupstream:dev --load .
brew install k6   # or https://grafana.com/docs/k6/latest/set-up/install-k6/
uv run python -m perf run --candidate slowshield:dev --rounds 3 --profile quick --duration 10s
```

On macOS (Docker Desktop) CPU pinning and cgroup statistics are unavailable; numbers are indicative only.
