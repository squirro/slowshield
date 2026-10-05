"""The root URL contract (slowshield.routing, docs/design/routing.md) and the deprecated routing kept until 0.1."""

from __future__ import annotations

import re
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


@pytest.mark.parametrize(
    ("headers", "shell", "windows_note"),
    [
        ({"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_6) AppleWebKit/605.1.15"}, "zsh", False),
        ({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/150.0"}, "bash", False),
        ({"Sec-CH-UA-Platform": '"macOS"', "User-Agent": "Mozilla/5.0"}, "zsh", False),
        ({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}, "bash", True),
        ({"User-Agent": "curl/8.18.0"}, "bash", False),
    ],
)
async def test_setup_page_preselects_the_shell(
    running: Running, headers: dict[str, str], shell: str, windows_note: bool
) -> None:
    page = (await running.client.get("/ui/setup", headers=headers)).text
    selected = re.findall(r'data-shell="([a-z-]+)"\s+aria-selected="true"', page)
    assert selected == [shell]
    assert re.search(rf'id="sh-{shell}" aria-labelledby="t-sh-{shell}">', page)  # its panel is not hidden
    assert page.count(" hidden>") >= 3
    assert ("WSL" in page) is windows_note


async def test_setup_page_snippets_use_this_instance(start_app) -> None:
    run = await start_app('public_url = "https://slowshield.example.com"\n')
    page = (await run.client.get("http://slowshield.example.com/ui/setup")).text
    assert "export PIP_INDEX_URL=https://slowshield.example.com/pypi/simple/" in page
    assert "set -Ux npm_config_registry https://slowshield.example.com/npm/" in page
    assert "set -Ux GOPROXY https://slowshield.example.com/go" in page
    assert "python3 -m venv /tmp/slowshield-try" in page
    assert "{pypi}" not in page and "{npm}" not in page


async def test_setup_page_shows_path_urls_and_the_deprecation(start_app) -> None:
    run = await start_app(HOSTNAMES)
    page = (await run.client.get("http://slowshield.example.com/ui/setup")).text
    assert "https://slowshield.example.com/pypi/simple/" in page
    assert "https://slowshield.example.com/npm/" in page
    assert "deprecated" in page and "pypi.internal" in page and "npm.internal" in page
    assert "https://pypi.internal/" not in page and "https://npm.internal/" not in page
    plain = (await (await start_app()).client.get("/ui/setup")).text
    assert "deprecated" not in plain


@pytest.mark.parametrize("host", ["localhost:$(id)", "127.0.0.1:80;id", "x$(id).localhost"])
async def test_crafted_host_never_reaches_snippets_or_tarballs(start_app, host: str) -> None:
    run = await start_app('local_http = true\npublic_url = "https://localhost"\n', host="localhost:8080")
    page = (await run.client.get("/ui/setup", headers={"Host": host})).text
    assert "$(" not in page and "80;id" not in page  # (the settings.xml snippet's escaped <id> contains ";id")
    assert "export PIP_INDEX_URL=http://localhost/pypi/simple/" in page  # from public_url, never the Host header
    doc = (await run.client.get("/npm/left-pad-ng", headers={"Host": host})).json()
    assert doc["versions"]["1.0.0"]["dist"]["tarball"].startswith("https://localhost/npm/")


async def test_setup_page_tool_finder(start_app) -> None:
    run = await start_app('public_url = "https://slowshield.example.com"\n')
    page = (await run.client.get("http://slowshield.example.com/ui/setup")).text
    names = [
        "pip",
        "uv",
        "Poetry",
        "PDM",
        "Pipenv",
        "npm",
        "pnpm",
        "Yarn",
        "Bun",
        "Go",
        "Maven",
        "Gradle",
        "sbt",
        "Coursier",
    ]
    assert re.findall(r'<option value="([^"]+)">', page) == names  # the native pulldown
    assert re.findall(r'data-tool-pick="([^"]+)"', page) == names
    keywords = dict(re.findall(r'data-tool="(([a-z]+)[^"]*)"', page)[i][::-1] for i in range(len(names)))
    assert "pipfile" in keywords["pipenv"] and "npmrc" in keywords["npm"] and "berry" in keywords["yarn"]
    assert "poetry source add --priority=primary slowshield https://slowshield.example.com/pypi/simple/" in page
    assert "verify_ssl = true" in page and "unsafeHttpWhitelist" not in page
    assert "data-tool-empty hidden" in page  # JS shows it; without JS every tool stays visible
    assert "go env -w GOPROXY=https://slowshield.example.com/go" in page and "GOPROXY: https://slowshield" in page
    assert "&lt;url&gt;https://slowshield.example.com/maven/all/&lt;/url&gt;" in page  # settings.xml mirror
    assert (
        "&#39;https://plugins.gradle.org/m2&#39;: &#39;https://slowshield.example.com/maven/gradle-plugins/&#39;"
        in page
    )
    assert "allowInsecureProtocol" not in page and "maven-default-http-blocker" not in page  # HTTPS instance
