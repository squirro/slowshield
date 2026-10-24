"""snippets.toml: one source for the Setup page and slowshield.org, so the two cannot drift apart."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from slowshield.ui import snippets as S

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "website" / "src" / "index.html"
PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


def test_shells_and_placeholders() -> None:
    s = S.load()
    ids = [sh.id for sh in s.shells]
    assert ids == ["bash", "bash-macos", "zsh", "fish"]
    assert len({sh.label for sh in s.shells}) == len(ids)
    for code in [sh.code for sh in s.shells] + [s.try_python]:
        assert set(PLACEHOLDER.findall(code)) <= {"pypi", "npm", "go", "py_pkg", "age_days"}, code
    # macOS Terminal opens login shells, which read ~/.bash_profile, not ~/.bashrc.
    assert "~/.bash_profile" in s.shells[1].code and "~/.bashrc" not in s.shells[1].code
    # PEP 668: Homebrew and current Linux Pythons refuse pip installs outside a virtualenv.
    assert "python3 -m venv" in s.try_python


def test_rendering_fills_every_placeholder() -> None:
    s = S.for_instance("https://h/pypi/simple/", "https://h/npm/", "https://h/go")
    for code in [sh.code for sh in s.shells] + [s.try_python]:
        assert not PLACEHOLDER.search(code), code
    assert "export PIP_INDEX_URL=https://h/pypi/simple/" in s.shells[0].code
    # No `,direct` (or `|`): the go command would then fetch from the origin whenever the proxy says 404.
    assert all(("GOPROXY https://h/go\n" if sh.id == "fish" else "GOPROXY=https://h/go\n") in sh.code + "\n"
               for sh in s.shells)  # fmt: skip
    assert "pip install --index-url https://h/pypi/simple/ requests" in s.try_python


def test_website_uses_every_shared_snippet() -> None:
    markers = set(re.findall(r"<!-- @snippet ([a-z]+\.[a-z-]+) -->", SITE.read_text(encoding="utf-8")))
    shared = {f"shell.{sh.id}" for sh in S.load().shells} | {"try.python"}
    assert markers == shared


@pytest.mark.parametrize(
    "bad", ["https://h/$(id)", "https://h/`id`", "https://h/a;b", "https://h/?a&b", "https://h/ x", "h'x"]
)
def test_unsafe_values_never_reach_a_snippet(bad: str) -> None:
    with pytest.raises(ValueError, match="shell snippet"):
        S.for_instance(bad, "https://h/npm/", "https://h/go")


def test_package_managers_also_wait_unless_switched_off() -> None:
    s = S.for_instance("https://h/pypi/simple/", "https://h/npm/", "https://h/go")
    bash, fish = s.shells[0], s.shells[3]
    for line in (
        "export PIP_UPLOADED_PRIOR_TO=P3D",
        "export npm_config_min_release_age=3",
    ):
        assert line in bash.code and line not in bash.plain
    assert "set -Ux npm_config_min_release_age 3" in fish.code
    # Not uv's: it records exclude-newer in uv.lock, so it goes in pyproject.toml, never the environment.
    assert not any("UV_EXCLUDE_NEWER" in sh.code for sh in s.shells)
    # The plain version is the same snippet without those lines.
    for sh in s.shells:
        assert sh.plain == S.without_client_age(sh.code)
        assert sh.plain.count("\n") == sh.code.count("\n") - 2
        assert ("GOPROXY" in sh.plain and "EOF" in sh.plain) or sh.id == "fish"
    off = S.for_instance("https://h/pypi/simple/", "https://h/npm/", "https://h/go", age_days=0)
    assert [sh.code for sh in off.shells] == [sh.plain for sh in s.shells]


def test_the_client_age_never_exceeds_slowshields_delay() -> None:
    assert S.client_age_days(7) == 3
    assert S.client_age_days(2.5) == 2
    assert S.client_age_days(0.5) == 0
    assert S.client_age_days(0) == 0


def test_nuget_config_clears_the_other_sources_and_keeps_the_name_nuget_org() -> None:
    urls = ("https://h/pypi/simple/", "https://h/npm/", "https://h/go", "https://h/maven", "https://h/cargo/")
    tool = {
        t.name: t
        for t in S.tools(
            *urls, nuget="https://h/nuget/v3/index.json", composer="https://h/composer/", rubygems="https://h/rubygems"
        )
    }["NuGet"]
    assert tool.ecosystem == "nuget" and tool.age == S.NO_AGE_DEFAULT
    config, command, props = (code for _, code in tool.snippets)
    assert config.startswith('<?xml version="1.0" encoding="utf-8"?>\n<configuration>\n  <packageSources>')
    assert "    <clear />\n" in config  # without it, nuget.org stays a source and goes around SlowShield
    assert '<add key="nuget.org" value="https://h/nuget/v3/index.json" protocolVersion="3" />' in config
    assert "allowInsecureConnections" not in config
    assert command.startswith('mkdir -p "$HOME/.nuget/NuGet" && printf ')
    assert command.endswith(' > "$HOME/.nuget/NuGet/NuGet.Config"') and "'    <clear />'" in command
    # A held version skipped for a higher one is only warning NU1603: the build should fail on it.
    assert "<WarningsAsErrors>$(WarningsAsErrors);NU1603</WarningsAsErrors>" in props
    assert "TreatWarningsAsErrors" in props and "NU1603" in tool.snippets[2][0]
    # Plain HTTP on localhost: NuGet refuses an http:// source without it (NU1302).
    local = {
        t.name: t
        for t in S.tools(
            *urls, nuget="http://localhost/nuget/v3/index.json", composer="https://h/composer/", rubygems="r"
        )
    }["NuGet"]
    assert 'protocolVersion="3" allowInsecureConnections="true" />' in local.snippets[0][1]
    with pytest.raises(ValueError, match="refusing"):
        S.tools(*urls, nuget="https://h/nuget/'$(id)'", composer="https://h/composer/", rubygems="r")
    assert (
        S.docs_url("nuget", "NuGet") == f"{S.DOCS}csharp/#nuget"
        and S.docs_url("cargo", "Cargo") == f"{S.DOCS}rust/#cargo"
    )
    # An ecosystem the guide has no page for: its start page.
    assert S.docs_url("unknown", "Tool") == S.DOCS


def test_ruby_tools_mirror_rubygems_org_and_make_slowshield_gems_only_source() -> None:
    urls = ("https://h/pypi/simple/", "https://h/npm/", "https://h/go", "https://h/maven", "https://h/cargo/")
    tools = {t.name: t for t in S.tools(*urls, nuget="n", rubygems="https://h/rubygems")}
    bundler, gem = tools["Bundler"], tools["gem"]
    assert bundler.ecosystem == gem.ecosystem == "rubygems"
    # A mirror, so Gemfiles and Gemfile.lock keep rubygems.org; never a fallback_timeout, which goes around it.
    assert bundler.snippets[0][1] == "bundle config set --global mirror.https://rubygems.org https://h/rubygems"
    assert not any("fallback" in code for _, code in bundler.snippets)
    assert gem.snippets[0][1] == "---\n:sources:\n- https://h/rubygems/"
    assert gem.snippets[1][1] == "printf -- '---\\n:sources:\\n- %s\\n' https://h/rubygems/ > ~/.gemrc"
    assert gem.age == S.NO_AGE_DEFAULT
    assert S.docs_url("rubygems", "Bundler") == f"{S.DOCS}ruby/#bundler"
    with pytest.raises(ValueError, match="refusing"):
        S.tools(*urls, nuget="n", rubygems="https://h/rubygems'$(id)'")


def test_tools_name_the_version_their_release_age_needs() -> None:
    urls = ("https://h/pypi/simple/", "https://h/npm/", "https://h/go", "https://h/maven", "https://h/cargo/")
    nuget = "https://h/nuget/v3/index.json"
    on = {t.name: t for t in S.tools(*urls, nuget=nuget, composer="https://h/composer/", rubygems="https://h/rubygems")}
    off = {
        t.name: t
        for t in S.tools(*urls, nuget=nuget, composer="https://h/composer/", rubygems="https://h/rubygems", age_days=0)
    }
    assert on["npm"].age.startswith("npm 11.10 or later") and on["uv"].age.startswith("uv 0.9.17 or later")
    assert on["Go"].age == S.NO_AGE_DEFAULT and "min-publish-age" in on["Cargo"].age
    assert all(t.age == "" for t in off.values())
    codes = {name: "\n".join(code for _, code in t.snippets) for name, t in on.items()}
    # npm counts days, pnpm minutes, Bun seconds: each says 3 days.
    assert "npm config set min-release-age 3" in codes["npm"] and "min-release-age=3" in codes["npm"]
    assert "minimumReleaseAge: 4320" in codes["pnpm"] and 'npmMinimalAgeGate: "3d"' in codes["Yarn"]
    assert (
        "minimumReleaseAge = 259200" in codes["Bun"] and "pip config set global.uploaded-prior-to P3D" in codes["pip"]
    )
    assert 'exclude-newer = "P3D"' in codes["uv"] and "poetry config solver.min-release-age 3" in codes["Poetry"]
    assert '[tool.pdm.resolution]\nexclude-newer = "3d"' in codes["PDM"]
    assert "bundle config set --global cooldown 3" in codes["Bundler"] and on["Bundler"].age.startswith(
        "Bundler 4.0.13"
    )
    assert "UV_EXCLUDE_NEWER" not in codes["uv"]
    for name, t in off.items():
        plain = "\n".join(code for _, code in t.snippets)
        assert not any(
            k in plain for k in ("release-age", "exclude-newer", "ReleaseAge", "AgeGate", "prior-to", "cooldown")
        ), name
    assert on["Go"].snippets == off["Go"].snippets  # tools without a setting are the same either way
    assert "config.policy.cooldown.period" in on["Composer"].age and on["Composer"].snippets == off["Composer"].snippets


def test_ci_and_dockerfile_snippets() -> None:
    ci = S.ci_env("https://h/pypi/simple/", "https://h/npm/", "https://h/go", age_days=3)
    assert ci.endswith("  GOPROXY: https://h/go\n  PIP_UPLOADED_PRIOR_TO: P3D\n  npm_config_min_release_age: 3")
    plain = S.dockerfile_env("https://h/pypi/simple/", "https://h/npm/", "https://h/go", age_days=0)
    assert plain == (
        "ENV PIP_INDEX_URL=https://h/pypi/simple/ \\\n    UV_DEFAULT_INDEX=https://h/pypi/simple/ \\\n"
        "    npm_config_registry=https://h/npm/ \\\n    GOPROXY=https://h/go"
    )


def test_composer_replaces_packagist_org() -> None:
    urls = ("https://h/pypi/simple/", "https://h/npm/", "https://h/go", "https://h/maven", "https://h/cargo/")
    tool = {t.name: t for t in S.tools(*urls, nuget="n", composer="https://h/composer/")}["Composer"]
    assert tool.ecosystem == "composer" and S.docs_url("composer", "Composer") == f"{S.DOCS}php/#composer"
    command, project, relock = (code for _, code in tool.snippets)
    # packagist.org off: a repository named packagist is added next to it, not in its place.
    assert command == (
        "composer config -g repo.packagist false && composer config -g repos.slowshield composer https://h/composer/"
    )
    # packagist.org must be off in a project too: Composer asks every repository.
    assert json.loads(project) == {
        "repositories": [{"type": "composer", "url": "https://h/composer/"}, {"packagist.org": False}]
    }
    # composer update --lock only writes GitHub, GitLab and Bitbucket URLs into a lock: a PHP line does it.
    assert relock.startswith("php -r '") and relock.endswith("'") and relock.count("'") == 2
    assert '"https://h/composer/dists/{$p["name"]}/{$p["dist"]["reference"]}.{$p["dist"]["type"]}"' in relock
    # Plain HTTP on localhost needs secure-http off.
    local = {t.name: t for t in S.tools(*urls, nuget="n", composer="http://localhost/composer/")}["Composer"]
    assert local.snippets[0][1].endswith(" && composer config -g secure-http false")
    assert json.loads(local.snippets[1][1])["config"] == {"secure-http": False}
    with pytest.raises(ValueError, match="refusing"):
        S.tools(*urls, nuget="n", composer="https://h/composer/'$(id)'")
