"""The root URL contract (slowshield.routing, docs/design/routing.md) and the deprecated routing kept until 0.1."""

from __future__ import annotations

from typing import Any

import pytest
from starlette.routing import Mount, Route

from slowshield import routing
from slowshield.ecosystems.pypi.project import JSON_V1
from slowshield.telemetry import instruments
from tests.conftest import Running

HOSTNAMES = """
public_url = "https://slowshield.example.com"
[upstreams.pypi]
hostnames = ["pypi.internal"]
[upstreams.npm]
hostnames = ["npm.internal"]
"""


class _Counter:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def add(self, amount: int, attributes: dict[str, Any]) -> None:
        self.calls.extend([attributes["route"]] * amount)


@pytest.fixture
def legacy(monkeypatch: pytest.MonkeyPatch) -> _Counter:
    counter = _Counter()
    monkeypatch.setattr(instruments, "legacy_routing", counter)
    return counter


def _paths(run: Running) -> list[str]:
    paths = [r.path for r in run.app.root_routes if isinstance(r, Route | Mount)]
    assert len(paths) == len(run.app.root_routes), "every root entry must be a Route or Mount"
    return paths


@pytest.mark.parametrize("config", ["", HOSTNAMES])
async def test_every_root_route_is_in_the_contract(start_app, config: str) -> None:
    run = await start_app(config)
    segments = {routing.first_segment(p) for p in _paths(run)}
    assert segments <= routing.ALLOWED, sorted(segments - routing.ALLOWED)
    assert segments >= routing.ECOSYSTEMS
    assert not segments & routing.RESERVED_ECOSYSTEMS  # reserved names stay free until their ecosystem ships


def test_contract_names_do_not_overlap() -> None:
    groups = [routing.ECOSYSTEMS, routing.RESERVED_ECOSYSTEMS, routing.SYSTEM, routing.LEGACY]
    assert sum(len(g) for g in groups) == len(routing.ALLOWED)


@pytest.mark.parametrize("accept", ["text/html", "application/json", "*/*"])
async def test_root_redirects_to_the_ui(running: Running, accept: str) -> None:
    for path in ("/", "/ui"):
        r = await running.client.get(path, headers={"Accept": accept}, follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/ui/", path
    r = await running.client.get("/ui/")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]


async def test_old_static_path_redirects_and_is_counted(running: Running, legacy: _Counter) -> None:
    r = await running.client.get("/static/app.css?v=1", follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"] == "/ui/static/app.css?v=1"
    assert legacy.calls == ["static"]


async def test_root_pypi_alias_still_works_and_is_counted(running: Running, legacy: _Counter) -> None:
    assert (await running.client.get("/pypi/simple/alpha/", headers={"Accept": JSON_V1})).status_code == 200
    assert legacy.calls == []
    assert (await running.client.get("/simple/alpha/", headers={"Accept": JSON_V1})).status_code == 200
    assert legacy.calls == ["root-simple"]


async def test_hostnames_still_work_and_are_counted(start_app, legacy: _Counter) -> None:
    run = await start_app(HOSTNAMES)
    r = await run.client.get("http://pypi.internal/simple/alpha/", headers={"Accept": JSON_V1})
    assert r.status_code == 200
    assert (await run.client.get("http://npm.internal/left-pad-ng")).status_code == 200
    assert (await run.client.get("http://npm.internal/healthz")).status_code == 200  # probes are not usage
    assert legacy.calls == ["pypi-hostname", "npm-hostname"]


async def test_npm_tarball_urls_follow_the_route_the_client_used(start_app) -> None:
    run = await start_app(HOSTNAMES)
    via_path = (await run.client.get("http://slowshield.example.com/npm/left-pad-ng")).json()
    via_host = (await run.client.get("http://npm.internal/left-pad-ng")).json()
    tarball = "left-pad-ng/-/left-pad-ng-1.0.0.tgz"
    # Path clients record path URLs in their lockfiles, so removing the hostname in 0.1 breaks nothing.
    assert via_path["versions"]["1.0.0"]["dist"]["tarball"] == f"https://slowshield.example.com/npm/{tarball}"
    assert via_host["versions"]["1.0.0"]["dist"]["tarball"] == f"https://npm.internal/{tarball}"


async def test_setup_page_shows_path_urls_and_the_deprecation(start_app) -> None:
    run = await start_app(HOSTNAMES)
    page = (await run.client.get("http://slowshield.example.com/ui/setup")).text
    assert "https://slowshield.example.com/pypi/simple/" in page
    assert "https://slowshield.example.com/npm/" in page
    assert "deprecated" in page and "pypi.internal" in page and "npm.internal" in page
    assert "https://pypi.internal/" not in page and "https://npm.internal/" not in page
    plain = (await (await start_app()).client.get("/ui/setup")).text
    assert "deprecated" not in plain
