"""The ecosystems SlowShield serves: one table for their labels, name rules, feed names and registry links.

Config, feeds and the UI read it instead of listing ecosystems themselves, so adding one is a new row here plus
its service. The URL paths they are served under are part of the root contract in `slowshield.routing`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from slowshield import names


@dataclass(frozen=True, slots=True)
class EcosystemInfo:
    id: str  # also the URL path segment, the `ecosystem` column and the metric label
    label: str
    language: str  # the Setup page groups tools by it
    normalize: Callable[[str], str]
    is_valid: Callable[[str], bool]
    osv: str  # ecosystem name in OSV
    github: str  # ecosystem name in the GitHub Advisory Database
    registry_page: str  # the package's page on the public registry; `{name}` is replaced
    registry_site: str  # what that site is called ("View on ...")

    def page_url(self, name: str) -> str:
        return self.registry_page.replace("{name}", name)


ECOSYSTEMS: dict[str, EcosystemInfo] = {
    e.id: e
    for e in (
        EcosystemInfo(
            "pypi", "PyPI", "Python", names.normalize_pypi, names.is_valid_pypi, "PyPI", "pip",
            "https://pypi.org/project/{name}/", "PyPI",
        ),
        EcosystemInfo(
            "npm", "npm", "JavaScript", names.normalize_npm, names.is_valid_npm, "npm", "npm",
            "https://www.npmjs.com/package/{name}", "npm",
        ),
        EcosystemInfo(
            "go", "Go", "Go", names.normalize_go, names.is_valid_go, "Go", "go", "https://pkg.go.dev/{name}",
            "pkg.go.dev",
        ),
    )
}  # fmt: skip
IDS: tuple[str, ...] = tuple(ECOSYSTEMS)
LABELS: dict[str, str] = {e.id: e.label for e in ECOSYSTEMS.values()}


def normalize(ecosystem: str, name: str) -> str:
    """`name` in the form SlowShield stores and matches it for `ecosystem`."""
    return ECOSYSTEMS[ecosystem].normalize(name)
