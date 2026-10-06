# Development

```bash
uv sync                                   # Python 3.15 (uv-managed) + dependencies into .venv
uv run pytest                             # unit + integration tests, coverage gate 90 %
uv run pytest -m e2e tests/e2e            # needs built images and E2E=1 (see tests/e2e)
uv run ruff check . && uv run ruff format --check . && uv run ty check
uv run python -m perf micro               # hot-path micro benchmarks
uv run python -m fakeupstream --port 9000 # deterministic fake PyPI/npm/Go/OSV/GitHub for manual testing
```

Run a local instance against the fake registries:

```bash
uv run python -m fakeupstream --port 9000 &
SLOWSHIELD_CONFIG=perf/slowshield.toml SLOWSHIELD_DATA_DIR=./data SLOWSHIELD_LOG_FORMAT=text \
  uv run slowshield serve --bind 127.0.0.1:8080
```

(`perf/slowshield.toml` points at `http://fakeupstream:9000`; add `127.0.0.1 fakeupstream` to
`/etc/hosts` or copy the file and change the URLs.)

UI templates reload on every request with `SLOWSHIELD_DEV_TEMPLATES=1`.

## Layout

| Path | What |
|---|---|
| `src/slowshield/` | the application (see [architecture.md](architecture.md)) |
| `fakeupstream/` | deterministic fake registries for tests, e2e and perf |
| `tests/` | unit, integration and e2e tests |
| `perf/` | k6 scenarios, A/B runner, thresholds, micro benchmarks |
| `containers/` | Dockerfiles (Amazon Linux 2023 only) |
| `deploy/` | Docker Compose, rootless Podman (Quadlet), Helm |
| `observability/` | Alloy, Prometheus, Loki, Tempo, Grafana provisioning, dashboards, alerts |
| `brand/` | logo and theme assets |

## Python 3.15 and free-threading

The default image uses the regular (GIL) build. The nightly workflow builds `PYTHON_VARIANT=3.15t` and
compares it against the GIL build with the same perf harness; Granian refuses to start if any extension
re-enables the GIL, so a green free-threaded run is meaningful.
