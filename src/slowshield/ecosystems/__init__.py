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
    label: str  # what the UI calls it: the language, as on slowshield.org (the registry is `registry_site`)
    normalize: Callable[[str], str]
    is_valid: Callable[[str], bool]
    osv: str  # ecosystem name in OSV
    github: str  # ecosystem name in the GitHub Advisory Database
    registry_page: str  # the package's page on the public registry; `{name}` (Maven: `{group}`, `{artifact}`)
    registry_site: str  # what that site is called ("View on ...")

    def page_url(self, name: str) -> str:
        if self.id == "oci":
            return _oci_page(name)
        group, _, artifact = name.partition(":")
        return self.registry_page.replace("{name}", name).replace("{group}", group).replace("{artifact}", artifact)


def _oci_page(name: str) -> str:
    registry, path = names.oci_split(name)
    if registry == names.OCI_DOCKER_HUB:
        return (
            f"https://hub.docker.com/_/{path[8:]}"
            if path.startswith("library/")
            else f"https://hub.docker.com/r/{path}"
        )
    if registry == "quay.io":
        return f"https://quay.io/repository/{path}"
    return f"https://{registry}/{path}"


ECOSYSTEMS: dict[str, EcosystemInfo] = {
    e.id: e
    for e in (
        EcosystemInfo(
            "pypi", "Python", names.normalize_pypi, names.is_valid_pypi, "PyPI", "pip",
            "https://pypi.org/project/{name}/", "PyPI",
        ),
        EcosystemInfo(
            "npm", "JavaScript", names.normalize_npm, names.is_valid_npm, "npm", "npm",
            "https://www.npmjs.com/package/{name}", "npm",
        ),
        EcosystemInfo(
            "go", "Go", names.normalize_go, names.is_valid_go, "Go", "go", "https://pkg.go.dev/{name}",
            "pkg.go.dev",
        ),
        EcosystemInfo(
            "maven", "Java", names.normalize_maven, names.is_valid_maven, "Maven", "maven",
            "https://central.sonatype.com/artifact/{group}/{artifact}", "Maven Central",
        ),
        EcosystemInfo(
            "cargo", "Rust", names.normalize_cargo, names.is_valid_cargo, "crates.io", "rust",
            "https://crates.io/crates/{name}", "crates.io",
        ),
        EcosystemInfo(
            "nuget", "C#", names.normalize_nuget, names.is_valid_nuget, "NuGet", "nuget",
            "https://www.nuget.org/packages/{name}", "NuGet Gallery",
        ),
        # No advisory database covers container images: OCI has no OSV or GitHub ecosystem name.
        EcosystemInfo(
            "oci", "Containers", names.normalize_oci, names.is_valid_oci, "", "", "https://{name}",
            "the registry",
        ),
    )
}  # fmt: skip
IDS: tuple[str, ...] = tuple(ECOSYSTEMS)
LABELS: dict[str, str] = {e.id: e.label for e in ECOSYSTEMS.values()}


def normalize(ecosystem: str, name: str) -> str:
    """`name` in the form SlowShield stores and matches it for `ecosystem`."""
    return ECOSYSTEMS[ecosystem].normalize(name)
