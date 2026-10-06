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
        assert set(PLACEHOLDER.findall(code)) <= {"pypi", "npm", "go", "py_pkg"}, code
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
