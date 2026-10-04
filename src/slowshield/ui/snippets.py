"""Client setup snippets from snippets.toml, shared with slowshield.org (website/build.py reads the same file)."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from functools import cache
from pathlib import Path

PATH = Path(__file__).with_name("snippets.toml")
# Values are placed unquoted in shell code. Config validation and the loopback Host check already guarantee URL-safe
# values; refusing anything else here means a regression fails the page instead of serving runnable shell syntax.
_SAFE = re.compile(r"[A-Za-z0-9._~:/%\[\]-]+")


@dataclass(frozen=True, slots=True)
class Shell:
    id: str
    label: str
    os: str
    code: str


@dataclass(frozen=True, slots=True)
class Snippets:
    shells: tuple[Shell, ...]
    try_python: str


def safe(value: str) -> str:
    """`value` if it is URL-safe, else ValueError: it is about to be placed unquoted in a shell snippet."""
    if not _SAFE.fullmatch(value):
        raise ValueError(f"refusing to put {value!r} into a shell snippet")
    return value


def render(code: str, *, pypi: str, npm: str, py_pkg: str = "requests") -> str:
    """Fill the placeholders. Plain replacement: the shell code itself may contain braces."""
    for key, value in (("pypi", pypi), ("npm", npm), ("py_pkg", py_pkg)):
        code = code.replace("{" + key + "}", safe(value))
    return code


@cache
def load() -> Snippets:
    data = tomllib.loads(PATH.read_text(encoding="utf-8"))
    shells = tuple(Shell(s["id"], s["label"], s["os"], s["code"].strip("\n")) for s in data["shell"])
    return Snippets(shells, data["try"]["python"].strip("\n"))


@dataclass(frozen=True, slots=True)
class Tool:
    """One tool on the Setup page's finder: `keywords` is what typing matches (name, aliases, config files)."""

    name: str
    ecosystem: str  # pypi | npm
    keywords: str
    snippets: tuple[tuple[str, str], ...]  # (label, code)


def tools(pypi: str, npm: str) -> tuple[Tool, ...]:
    """Per-tool setup (Setup page only), with this instance's URLs."""
    pypi, npm = safe(pypi), safe(npm)
    secure = "false" if pypi.startswith("http://") else "true"
    yarn_http = "\nunsafeHttpWhitelist:\n  - localhost" if npm.startswith("http://") else ""
    return (
        Tool("pip", "pypi", "pip pip.conf pip.ini python", (("command", f"pip config set global.index-url {pypi}"),)),
        Tool(
            "uv",
            "pypi",
            "uv astral pyproject python",
            (
                ("pyproject.toml", f'[[tool.uv.index]]\nname = "slowshield"\nurl = "{pypi}"\ndefault = true'),
                ("environment", f"export UV_DEFAULT_INDEX={pypi}"),
            ),
        ),
        Tool(
            "Poetry",
            "pypi",
            "poetry python pyproject",
            (("command", f"poetry source add --priority=primary slowshield {pypi}"),),
        ),
        Tool(
            "PDM",
            "pypi",
            "pdm python pyproject",
            (("pyproject.toml", f'[[tool.pdm.source]]\nname = "pypi"\nurl = "{pypi}"'),),
        ),
        Tool(
            "Pipenv",
            "pypi",
            "pipenv pipfile python",
            (("Pipfile", f'[[source]]\nurl = "{pypi}"\nverify_ssl = {secure}\nname = "slowshield"'),),
        ),
        Tool(
            "npm",
            "npm",
            "npm npmrc node javascript",
            (("command", f"npm config set registry {npm}"), (".npmrc (project or ~)", f"registry={npm}")),
        ),
        Tool("pnpm", "npm", "pnpm npmrc node javascript", (("command", f"pnpm config set registry {npm}"),)),
        Tool(
            "Yarn",
            "npm",
            "yarn berry yarnrc node javascript",
            ((".yarnrc.yml (Yarn Berry)", f'npmRegistryServer: "{npm}"{yarn_http}'),),
        ),
        Tool("Bun", "npm", "bun bunfig node javascript", (("bunfig.toml", f'[install]\nregistry = "{npm}"'),)),
    )


def for_instance(pypi: str, npm: str) -> Snippets:
    """The snippets with this instance's URLs."""
    s = load()
    shells = tuple(Shell(sh.id, sh.label, sh.os, render(sh.code, pypi=pypi, npm=npm)) for sh in s.shells)
    return Snippets(shells, render(s.try_python, pypi=pypi, npm=npm))
