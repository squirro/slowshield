"""snippets.toml: one source for the Setup page and slowshield.org, so the two cannot drift apart."""

from __future__ import annotations

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
        "export UV_EXCLUDE_NEWER=P3D",
        "export npm_config_min_release_age=3",
    ):
        assert line in bash.code and line not in bash.plain
    assert "set -Ux UV_EXCLUDE_NEWER P3D" in fish.code
    # The plain version is the same snippet without those lines.
    for sh in s.shells:
        assert sh.plain == S.without_client_age(sh.code)
        assert sh.plain.count("\n") == sh.code.count("\n") - 3
        assert ("GOPROXY" in sh.plain and "EOF" in sh.plain) or sh.id == "fish"
    off = S.for_instance("https://h/pypi/simple/", "https://h/npm/", "https://h/go", age_days=0)
    assert [sh.code for sh in off.shells] == [sh.plain for sh in s.shells]


def test_the_client_age_never_exceeds_slowshields_delay() -> None:
    assert S.client_age_days(7) == 3
    assert S.client_age_days(2.5) == 2
    assert S.client_age_days(0.5) == 0
    assert S.client_age_days(0) == 0


def test_tools_name_the_version_their_release_age_needs() -> None:
    urls = ("https://h/pypi/simple/", "https://h/npm/", "https://h/go", "https://h/maven", "https://h/cargo/")
    on = {t.name: t for t in S.tools(*urls)}
    off = {t.name: t for t in S.tools(*urls, age_days=0)}
    assert on["npm"].age.startswith("npm 11.10 or later") and on["uv"].age.startswith("uv 0.9.17 or later")
    assert on["Go"].age == S.NO_AGE_DEFAULT and "min-publish-age" in on["Cargo"].age
    assert all(t.age == "" for t in off.values())
    codes = {name: "\n".join(code for _, code in t.snippets) for name, t in on.items()}
    assert "npm config set min-release-age 3" in codes["npm"] and "min-release-age=3" in codes["npm"]
    assert "minimumReleaseAge: 4320" in codes["pnpm"] and 'npmMinimalAgeGate: "3d"' in codes["Yarn"]
    assert (
        "minimumReleaseAge = 259200" in codes["Bun"] and "pip config set global.uploaded-prior-to P3D" in codes["pip"]
    )
    assert 'exclude-newer = "P3D"' in codes["uv"] and "poetry config solver.min-release-age 3" in codes["Poetry"]
    assert "pdm lock --exclude-newer 3d" in codes["PDM"]
    for name, t in off.items():
        plain = "\n".join(code for _, code in t.snippets)
        assert not any(k in plain for k in ("release-age", "exclude-newer", "ReleaseAge", "AgeGate", "prior-to")), name
    assert on["Go"].snippets == off["Go"].snippets  # tools without a setting are the same either way


def test_ci_and_dockerfile_snippets() -> None:
    ci = S.ci_env("https://h/pypi/simple/", "https://h/npm/", "https://h/go", age_days=3)
    assert ci.endswith("  GOPROXY: https://h/go\n  PIP_UPLOADED_PRIOR_TO: P3D\n  UV_EXCLUDE_NEWER: P3D\n"
                       "  npm_config_min_release_age: 3")  # fmt: skip
    plain = S.dockerfile_env("https://h/pypi/simple/", "https://h/npm/", "https://h/go", age_days=0)
    assert plain == (
        "ENV PIP_INDEX_URL=https://h/pypi/simple/ \\\n    UV_DEFAULT_INDEX=https://h/pypi/simple/ \\\n"
        "    npm_config_registry=https://h/npm/ \\\n    GOPROXY=https://h/go"
    )
