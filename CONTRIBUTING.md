# Contributing

Thanks for helping! A few ground rules keep SlowShield fast and safe.

## Issues first

For now, contributions come in as [issues](https://github.com/squirro/slowshield/issues/new/choose): bug
reports, requests for the next ecosystem and notes on how you run SlowShield. Pull requests are limited to
the maintainers while the project settles. If you have a fix, describe it in an issue; a link to the commit
in your fork helps. Report vulnerabilities privately, never in an issue: see [SECURITY.md](SECURITY.md).

The setup and guidelines below apply to every change, including the ones in your fork.

## Setup

```bash
uv sync                    # Python 3.15 + all dev tools into .venv
uv run pytest              # must stay green, coverage ≥ 90 %
uv run ruff check . && uv run ruff format --check . && uv run ty check
uvx zizmor==1.30.1 --persona=pedantic .github/   # when touching workflows
```

## Guidelines

- **Security first.** Every request path is a potential policy bypass: add a test for the bypass you are
  closing or could be opening. Never trust upstream data in the UI (it is escaped by Jinja2 autoescape —
  don't use `|safe` on anything derived from feeds or registries).
- **Performance matters.** Keep blocking work off the event loop, avoid per-request allocations of large
  objects, and run `uv run python -m perf micro` before/after changes to hot paths. Release builds are
  gated on the macro benchmarks (see `perf/README.md`).
- **Containers** use Amazon Linux 2023 only (builder stages too), pinned by digest.
- **Workflows** must pass zizmor's pedantic persona: SHA-pinned actions with version comments, explicit
  minimal permissions with comments, no `${{ }}` inside `run:`, `persist-credentials: false`.
- **Dependencies**: add with `uv add`, keep `uv.lock` committed. The lockfile must reference public PyPI only (CI
  checks this); if your environment points uv at a private mirror, lock with
  `UV_INDEX_URL= uv lock --default-index https://pypi.org/simple`. Prefer components with a proven
  performance and security track record; justify new ones in the issue or PR.
- **Metrics, dashboards and alerts** are code (`observability/`). Document a new or renamed metric in
  `observability/METRICS.md`, edit the generators rather than the JSON, and run
  `uv run python observability/sync.py` and `uv run python observability/check.py` (CI runs the check).
  See `observability/README.md`.
- Update `CHANGELOG.md` (Keep a Changelog format) under *Unreleased*.

## Releases

Maintainers tag `vX.Y.Z` on `main`; the release workflow builds both architectures, runs e2e tests and the
performance gate against the previous release, then promotes the images and creates the GitHub Release.
