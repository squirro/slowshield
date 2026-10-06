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


def render(code: str, *, pypi: str, npm: str, go: str, py_pkg: str = "requests") -> str:
    """Fill the placeholders. Plain replacement: the shell code itself may contain braces."""
    for key, value in (("pypi", pypi), ("npm", npm), ("go", go), ("py_pkg", py_pkg)):
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
    ecosystem: str  # an id from slowshield.ecosystems
    keywords: str
    snippets: tuple[tuple[str, str], ...]  # (label, code)


def tools(pypi: str, npm: str, go: str, maven: str) -> tuple[Tool, ...]:
    """Per-tool setup (Setup page only), with this instance's URLs. `maven` is the base of the Maven repositories
    (`<public_url>/maven`)."""
    pypi, npm, go, maven = safe(pypi), safe(npm), safe(go), safe(maven)
    sbt_insecure = ", allowInsecureProtocol" if maven.startswith("http://") else ""
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
        Tool(
            "Go",
            "go",
            "go golang gomod go.mod goproxy modules",
            (
                ("command (writes go env)", f"go env -w GOPROXY={go}"),
                ("private modules: fetched directly, not through SlowShield", "go env -w GOPRIVATE=git.example.com/*"),
            ),
        ),
        Tool("Maven", "maven", "maven mvn settings.xml m2 java pom", (("~/.m2/settings.xml", maven_settings(maven)),)),
        Tool(
            "Gradle",
            "maven",
            "gradle gradlew kotlin android java init.d",
            (("~/.gradle/init.d/slowshield.init.gradle", gradle_init(maven)),),
        ),
        Tool(
            "sbt",
            "maven",
            "sbt scala coursier",
            (
                ("~/.sbt/repositories", f"[repositories]\n  local\n  slowshield: {maven}/all/{sbt_insecure}"),
                # Not ~/.sbtopts: the sbt script doesn't read it, and the build definition's own Scala and plugins
                # would then come from Maven Central directly (checked with sbt 1.11). SBT_OPTS works for every version.
                ("environment", 'export SBT_OPTS="-Dsbt.override.build.repos=true $SBT_OPTS"'),
            ),
        ),
        Tool(
            "Coursier",
            "maven",
            "coursier cs scala-cli mill",
            (("environment", f'export COURSIER_REPOSITORIES="ivy2Local|{maven}/all/"'),),
        ),
    )


def gradle_init(maven: str) -> str:
    """~/.gradle/init.d/slowshield.init.gradle: points mavenCentral(), google() and the Plugin Portal at SlowShield, in
    plugin resolution (beforeSettings), settings repositories (settingsEvaluated) and project/buildscript repositories
    (allprojects). Checked on Gradle 8.14 and 9.8."""
    insecure = "; repo.allowInsecureProtocol = true" if maven.startswith("http://") else ""
    return (
        "def slowshield = [\n"
        f"  'https://repo.maven.apache.org/maven2': '{maven}/central/',\n"
        f"  'https://repo1.maven.org/maven2': '{maven}/central/',\n"
        f"  'https://dl.google.com/dl/android/maven2': '{maven}/google/',\n"
        f"  'https://plugins.gradle.org/m2': '{maven}/gradle-plugins/',\n"
        "]\n"
        "def rewrite = { repo ->\n"
        "  if (repo instanceof MavenArtifactRepository) {\n"
        "    def to = slowshield[repo.url.toString().replaceAll('/$', '')]\n"
        f"    if (to) {{ repo.url = new URI(to){insecure} }}\n"
        "  }\n"
        "}\n"
        "beforeSettings { s -> s.pluginManagement.repositories.all(rewrite) }\n"
        "settingsEvaluated { s ->\n"
        "  s.pluginManagement.repositories.all(rewrite)\n"
        "  s.dependencyResolutionManagement.repositories.all(rewrite)\n"
        "}\n"
        "allprojects { p ->\n"
        "  p.buildscript.repositories.all(rewrite)\n"
        "  p.repositories.all(rewrite)\n"
        "}"
    )


def maven_settings(maven: str) -> str:
    """~/.m2/settings.xml: one mirror for everything (`mirrorOf *`), since Maven sends a whole build through one
    mirror. Over plain HTTP it replaces Maven's built-in blocker of http:// repositories, which has that id."""
    mirror_id = "maven-default-http-blocker" if maven.startswith("http://") else "slowshield"
    blocked = "\n      <blocked>false</blocked>" if maven.startswith("http://") else ""
    return (
        "<settings>\n  <mirrors>\n    <mirror>\n"
        f"      <id>{mirror_id}</id>\n"
        "      <!-- private repositories stay direct: *,!their-id -->\n"
        f"      <mirrorOf>*</mirrorOf>\n      <url>{maven}/all/</url>{blocked}\n"
        "    </mirror>\n  </mirrors>\n</settings>"
    )


def for_instance(pypi: str, npm: str, go: str) -> Snippets:
    """The snippets with this instance's URLs."""
    s = load()
    shells = tuple(Shell(sh.id, sh.label, sh.os, render(sh.code, pypi=pypi, npm=npm, go=go)) for sh in s.shells)
    return Snippets(shells, render(s.try_python, pypi=pypi, npm=npm, go=go))
