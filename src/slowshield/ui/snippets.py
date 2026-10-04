"""Client setup snippets from snippets.toml, shared with slowshield.org (website/build.py reads the same file)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import cache
from pathlib import Path

PATH = Path(__file__).with_name("snippets.toml")


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


def render(code: str, *, pypi: str, npm: str, py_pkg: str = "requests") -> str:
    """Fill the placeholders. Plain replacement: the shell code itself may contain braces."""
    for key, value in (("pypi", pypi), ("npm", npm), ("py_pkg", py_pkg)):
        code = code.replace("{" + key + "}", value)
    return code


@cache
def load() -> Snippets:
    data = tomllib.loads(PATH.read_text(encoding="utf-8"))
    shells = tuple(Shell(s["id"], s["label"], s["os"], s["code"].strip("\n")) for s in data["shell"])
    return Snippets(shells, data["try"]["python"].strip("\n"))


def for_instance(pypi: str, npm: str) -> Snippets:
    """The snippets with this instance's URLs."""
    s = load()
    shells = tuple(Shell(sh.id, sh.label, sh.os, render(sh.code, pypi=pypi, npm=npm)) for sh in s.shells)
    return Snippets(shells, render(s.try_python, pypi=pypi, npm=npm))
