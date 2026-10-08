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

# The second layer: package managers that can also refuse releases younger than this themselves. If a machine goes
# around SlowShield, or SlowShield serves a brand-new package because nothing is old enough yet (fail-open), the
# package manager still waits. Never more than SlowShield's own delay, so in normal use only SlowShield holds anything.
CLIENT_AGE_DAYS = 3
# slowshield.org's guide has a page per ecosystem with a section per tool; the Setup page links to them.
DOCS = "https://slowshield.org/docs/"
DOCS_PAGES = {"pypi": "python", "npm": "javascript", "go": "go", "maven": "java", "cargo": "rust", "oci": "containers"}
_AGE_VARS = ("PIP_UPLOADED_PRIOR_TO", "npm_config_min_release_age")


def client_age_days(delay_days: float) -> int:
    """The release age to suggest for package managers: CLIENT_AGE_DAYS, or less under a shorter delay (0: none)."""
    return max(0, min(CLIENT_AGE_DAYS, int(delay_days)))


def client_age_env(age_days: int) -> list[tuple[str, str]]:
    """The environment variables that make pip and npm wait `age_days` themselves (none for 0). Not uv's
    UV_EXCLUDE_NEWER: uv records it in uv.lock, so it must be the same wherever the project is locked or synced."""
    if age_days <= 0:
        return []
    return [("PIP_UPLOADED_PRIOR_TO", f"P{age_days}D"), ("npm_config_min_release_age", str(age_days))]


def ci_env(pypi: str, npm: str, go: str, *, age_days: int) -> str:
    """The `env:` block for a GitHub Actions workflow or job."""
    pairs = [("PIP_INDEX_URL", pypi), ("UV_DEFAULT_INDEX", pypi), ("npm_config_registry", npm), ("GOPROXY", go)]
    pairs += client_age_env(age_days)
    return "# GitHub Actions (workflow or job)\nenv:\n" + "\n".join(f"  {k}: {safe(v)}" for k, v in pairs)


def dockerfile_env(pypi: str, npm: str, go: str, *, age_days: int) -> str:
    """One `ENV` instruction for a Dockerfile."""
    pairs = [("PIP_INDEX_URL", pypi), ("UV_DEFAULT_INDEX", pypi), ("npm_config_registry", npm), ("GOPROXY", go)]
    pairs += client_age_env(age_days)
    return "ENV " + " \\\n    ".join(f"{k}={safe(v)}" for k, v in pairs)


def without_client_age(code: str) -> str:
    """A shell snippet without the lines that set the package managers' own release age."""
    return "\n".join(line for line in code.split("\n") if not any(var in line for var in _AGE_VARS))


@dataclass(frozen=True, slots=True)
class Shell:
    id: str
    label: str
    os: str
    code: str
    plain: str = ""  # `code` without the package managers' own release age


@dataclass(frozen=True, slots=True)
class Snippets:
    shells: tuple[Shell, ...]
    try_python: str


def slug(name: str) -> str:
    """A tool's anchor on its guide page: `Image names` -> `image-names`."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def docs_url(ecosystem: str, tool: str = "") -> str:
    """The guide page for `ecosystem` on slowshield.org, at `tool`'s section if given; the guide's start page for an
    ecosystem it has no page for yet (NuGet)."""
    page = DOCS_PAGES.get(ecosystem)
    if page is None:
        return DOCS
    url = f"{DOCS}{page}/"
    return f"{url}#{slug(tool)}" if tool else url


def safe(value: str) -> str:
    """`value` if it is URL-safe, else ValueError: it is about to be placed unquoted in a shell snippet."""
    if not _SAFE.fullmatch(value):
        raise ValueError(f"refusing to put {value!r} into a shell snippet")
    return value


def render(
    code: str, *, pypi: str, npm: str, go: str, py_pkg: str = "requests", age_days: int = CLIENT_AGE_DAYS
) -> str:
    """Fill the placeholders. Plain replacement: the shell code itself may contain braces. With `age_days` 0, the
    lines that set the package managers' own release age are left out."""
    if age_days <= 0:
        code = without_client_age(code)
    for key, value in (("pypi", pypi), ("npm", npm), ("go", go), ("py_pkg", py_pkg), ("age_days", str(age_days))):
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
    age: str = ""  # what the tool's own release age needs (shown while it is switched on); "" when it has none


# The first version with a relative release-age setting, and what older ones do with it (checked 2026-10-06).
AGE_SUPPORT = {
    "pip": "pip 26.1 or later (pip 26.0 fails with it, 25 and older ignore it). Installs from pylock.toml fail "
    "with it, because pip doesn't record upload times there",
    "uv": "uv 0.9.17 or later (older versions fail with it). In pyproject.toml, not the environment: uv records it in "
    "uv.lock, so a different value elsewhere breaks uv sync --locked",
    "Poetry": "Poetry 2.4 or later",
    "PDM": "PDM 2.27 or later. In pyproject.toml, not as pdm lock --exclude-newer, which isn't kept and re-resolves "
    "every pin",
    "npm": "npm 11.10 or later (11.0 to 11.9 warn about an unknown setting, 10 ignores it)",
    "pnpm": "pnpm 10.16 or later (older versions ignore it)",
    "Yarn": "Yarn 4.10 or later (older versions refuse to run with it)",
    "Bun": "Bun 1.3 or later (older versions ignore it)",
}
NO_AGE = {
    "Cargo": "Cargo's own setting (min-publish-age) isn't stable yet: SlowShield is the only layer.",
}
NO_AGE_DEFAULT = "No release-age setting of its own: SlowShield is the only layer."


def tools(
    pypi: str, npm: str, go: str, maven: str, cargo: str, *, nuget: str, age_days: int = CLIENT_AGE_DAYS
) -> tuple[Tool, ...]:
    """Per-tool setup (Setup page only), with this instance's URLs and, unless `age_days` is 0, each tool's own
    release age. `maven` is the base of the Maven repositories (`<public_url>/maven`), `cargo` the sparse index
    (`<public_url>/cargo/`), `nuget` the service index (`<public_url>/nuget/v3/index.json`)."""
    urls = (safe(pypi), safe(npm), safe(go), safe(maven), safe(cargo))
    if age_days <= 0:
        return _tools(*urls, nuget=safe(nuget), age_days=0)
    aged = _tools(*urls, nuget=safe(nuget), age_days=age_days)
    return tuple(
        Tool(t.name, t.ecosystem, t.keywords, t.snippets, AGE_SUPPORT.get(t.name) or NO_AGE.get(t.name, NO_AGE_DEFAULT))
        for t in aged
    )


def _tools(pypi: str, npm: str, go: str, maven: str, cargo: str, *, nuget: str, age_days: int) -> tuple[Tool, ...]:
    # Units differ per tool: npm's min-release-age and Poetry's solver.min-release-age count days (npm 11.10 to 12.1:
    # `before = now - 86400000 * min-release-age`), pnpm's minimumReleaseAge minutes, Bun's seconds; pip, uv, Yarn and
    # PDM take a duration (P3D, 3d).
    d = age_days

    def aged(*parts: tuple[str, str]) -> tuple[tuple[str, str], ...]:
        """`parts`, without those that only set the release age when `d` is 0 (their label starts with "+")."""
        return tuple((label.removeprefix("+"), code) for label, code in parts if d or not label.startswith("+"))

    def line(text: str) -> str:
        return f"\n{text}" if d else ""

    sbt_insecure = ", allowInsecureProtocol" if maven.startswith("http://") else ""
    secure = "false" if pypi.startswith("http://") else "true"
    yarn_http = "\nunsafeHttpWhitelist:\n  - localhost" if npm.startswith("http://") else ""
    return (
        Tool(
            "pip",
            "pypi",
            "pip pip.conf pip.ini python",
            aged(
                ("command", f"pip config set global.index-url {pypi}"),
                ("+release age", f"pip config set global.uploaded-prior-to P{d}D"),
            ),
        ),
        Tool(
            "uv",
            "pypi",
            "uv astral pyproject python",
            (
                (
                    "pyproject.toml",
                    f'[[tool.uv.index]]\nname = "slowshield"\nurl = "{pypi}"\ndefault = true'
                    + (f'\n\n[tool.uv]\nexclude-newer = "P{d}D"' if d else ""),
                ),
                ("environment", f"export UV_DEFAULT_INDEX={pypi}"),
            ),
        ),
        Tool(
            "Poetry",
            "pypi",
            "poetry python pyproject",
            aged(
                ("command", f"poetry source add --priority=primary slowshield {pypi}"),
                ("+release age", f"poetry config solver.min-release-age {d}"),
            ),
        ),
        Tool(
            "PDM",
            "pypi",
            "pdm python pyproject",
            (
                (
                    "pyproject.toml",
                    f'[[tool.pdm.source]]\nname = "pypi"\nurl = "{pypi}"'
                    + (f'\n\n[tool.pdm.resolution]\nexclude-newer = "{d}d"' if d else ""),
                ),
            ),
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
            (
                ("command", f"npm config set registry {npm}" + line(f"npm config set min-release-age {d}")),
                (".npmrc (project or ~)", f"registry={npm}" + line(f"min-release-age={d}")),
            ),
        ),
        Tool(
            "pnpm",
            "npm",
            "pnpm npmrc node javascript workspace",
            aged(
                ("command", f"pnpm config set registry {npm}"),
                ("+pnpm-workspace.yaml", f"minimumReleaseAge: {d * 1440}  # {d} days, in minutes"),
            ),
        ),
        Tool(
            "Yarn",
            "npm",
            "yarn berry yarnrc node javascript",
            (
                (
                    ".yarnrc.yml (Yarn Berry)",
                    f'npmRegistryServer: "{npm}"{yarn_http}' + line(f'npmMinimalAgeGate: "{d}d"'),
                ),
            ),
        ),
        Tool(
            "Bun",
            "npm",
            "bun bunfig node javascript",
            (
                (
                    "bunfig.toml",
                    f'[install]\nregistry = "{npm}"' + line(f"minimumReleaseAge = {d * 86400}  # {d} days, in seconds"),
                ),
            ),
        ),
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
        Tool(
            "Cargo",
            "cargo",
            "cargo rust crates crates.io config.toml cargo_home rustup",
            (
                ("~/.cargo/config.toml", cargo_config(cargo)),
                # The official rust images set CARGO_HOME=/usr/local/cargo, where ~/.cargo is not read.
                ("CI and Dockerfiles (appends to $CARGO_HOME/config.toml)", cargo_command(cargo)),
            ),
        ),
        Tool(
            "NuGet",
            "nuget",
            "nuget dotnet .net c# csharp nuget.config msbuild packagereference visual studio rider paket",
            (
                ("~/.nuget/NuGet/NuGet.Config (Windows: %AppData%\\NuGet\\NuGet.Config), or next to a solution",
                 nuget_config(nuget)),
                ("CI and Dockerfiles (replaces ~/.nuget/NuGet/NuGet.Config)", nuget_command(nuget)),
            ),
        ),
    )  # fmt: skip


def oci_tools(base: str, registries: tuple[str, ...], *, age_days: int = CLIENT_AGE_DAYS) -> tuple[Tool, ...]:
    """Container image clients, for the instance at `base` (https://host or http://localhost:port) and the registries
    it serves (none has a release age of its own; `age_days` only decides whether to say so). Checked against
    containerd 2.2, Docker 29.8, Podman 5.8, BuildKit 0.33, skopeo and crane: with these files containerd, Docker's
    containerd store and Podman only ever ask SlowShield; BuildKit and Docker's classic store go to the registry
    themselves after a refusal."""
    base = safe(base.rstrip("/"))
    host = base.split("://", 1)[1]
    plain = base.startswith("http://")
    regs = tuple(safe(r) for r in registries)
    # `server` rather than a [host] entry: containerd tries the server after a host refuses, so it must not be the
    # registry. Pull-only, so pushes need the registry's own file.
    default = f'server = "{base}"\ncapabilities = ["pull", "resolve"]'
    push = (
        f'server = "https://ghcr.io"\ncapabilities = ["push"]\n\n[host."{base}"]\n  capabilities = ["pull", "resolve"]'
    )
    drop_in = "\n\n".join(
        f'[[registry]]\nprefix = "{r}"\nlocation = "{host}/{r}"' + ("\ninsecure = true" if plain else "") for r in regs
    )
    # Without a path: containerd's resolver names the registry in ?ns=. `http` goes on the mirror's exact name.
    buildkit = "\n".join(f'[registry."{r}"]\n  mirrors = ["{host}"]' for r in regs)
    if plain:
        buildkit += f'\n[registry."{host}"]\n  http = true'
    age = NO_AGE_DEFAULT if age_days > 0 else ""
    mirrors = (
        f'{{\n  "registry-mirrors": ["{base}"]' + (f',\n  "insecure-registries": ["{host}"]' if plain else "") + "\n}"
    )
    return (
        Tool(
            "containerd",
            "oci",
            "containerd kubernetes k8s kubelet cri nerdctl ctr hosts.toml certs.d",
            (
                ("/etc/containerd/certs.d/_default/hosts.toml: every registry, pull only", default),
                ("/etc/containerd/certs.d/ghcr.io/hosts.toml: a registry you also push to", push),
            ),
            age,
        ),
        Tool(
            "Docker",
            "oci",
            "docker dockerd docker build compose daemon.json registry-mirrors certs.d hosts.toml",
            (
                ("/etc/docker/certs.d/_default/hosts.toml: the containerd image store (docker info lists "
                 "io.containerd.snapshotter.v1), for docker pull and docker build", default),
                ("/etc/docker/daemon.json: the classic image store. Docker Hub only, and Docker pulls from Docker Hub "
                 "itself after a refusal", mirrors),
            ),
            age,
        ),
        Tool(
            "Podman",
            "oci",
            "podman cri-o crio buildah skopeo registries.conf",
            (("/etc/containers/registries.conf.d/50-slowshield.conf: Podman, CRI-O, Buildah and skopeo", drop_in),),
            age,
        ),
        Tool(
            "BuildKit",
            "oci",
            "buildkit buildkitd buildctl buildx docker-container builder",
            (("buildkitd.toml (also docker buildx create --buildkitd-config): BuildKit pulls from the registry itself "
              "after a refusal", buildkit),),
            age,
        ),
        Tool(
            "Image names",
            "oci",
            "crane skopeo kaniko oras regctl dockerfile FROM image reference prefix",
            (
                ("any client: SlowShield's host in front of the image name",
                 f"crane pull {host}/docker.io/library/nginx:1.29 nginx.tar"),
                ("Dockerfile", f"FROM {host}/docker.io/library/nginx:1.29"),
            ),
            age,
        ),
    )  # fmt: skip


def cargo_config(cargo: str) -> str:
    """Source replacement: crates-io resolves through SlowShield, so Cargo.lock keeps crates.io's source and
    checksums. A `[registries]` entry rather than `[source.slowshield] registry = ...`, with which `cargo info` won't
    run. Cargo 1.68 or later (sparse protocol)."""
    return f'[source.crates-io]\nreplace-with = "slowshield"\n\n[registries.slowshield]\nindex = "sparse+{cargo}"'


def cargo_command(cargo: str) -> str:
    """`cargo_config` as one shell command (source replacement can't be set through environment variables)."""
    lines = (
        "[source.crates-io]",
        'replace-with = "slowshield"',
        "[registries.slowshield]",
        f'index = "sparse+{cargo}"',
    )
    return (
        "mkdir -p \"${CARGO_HOME:-$HOME/.cargo}\" && printf '%s\\n' "
        + " ".join(f"'{line}'" for line in lines)
        + ' >> "${CARGO_HOME:-$HOME/.cargo}/config.toml"'
    )


def _nuget_lines(nuget: str) -> tuple[str, ...]:
    insecure = ' allowInsecureConnections="true"' if nuget.startswith("http://") else ""
    return (
        '<?xml version="1.0" encoding="utf-8"?>',
        "<configuration>",
        "  <packageSources>",
        "    <clear />",
        f'    <add key="nuget.org" value="{nuget}" protocolVersion="3"{insecure} />',
        "  </packageSources>",
        "</configuration>",
    )


def nuget_config(nuget: str) -> str:
    """NuGet.Config with SlowShield as the only source. `<clear/>` is required: NuGet asks every enabled source, so an
    enabled nuget.org would bypass SlowShield. The source keeps the name nuget.org, so packageSourceMapping entries
    that name it still match. Plain HTTP needs allowInsecureConnections (NU1302 otherwise)."""
    lines = list(_nuget_lines(nuget))
    lines.insert(3, "    <!-- required: NuGet asks every enabled source, so nuget.org would go around SlowShield -->")
    return "\n".join(lines)


def nuget_command(nuget: str) -> str:
    """`nuget_config` as one shell command for CI and images: dotnet can't set `<clear/>` from the command line."""
    return (
        "mkdir -p \"$HOME/.nuget/NuGet\" && printf '%s\\n' "
        + " ".join(f"'{line}'" for line in _nuget_lines(nuget))
        + ' > "$HOME/.nuget/NuGet/NuGet.Config"'
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


def for_instance(pypi: str, npm: str, go: str, age_days: int = CLIENT_AGE_DAYS) -> Snippets:
    """The snippets with this instance's URLs; each shell also without the package managers' own release age."""
    s = load()
    shells = tuple(
        Shell(
            sh.id,
            sh.label,
            sh.os,
            render(sh.code, pypi=pypi, npm=npm, go=go, age_days=age_days),
            render(sh.code, pypi=pypi, npm=npm, go=go, age_days=0),
        )
        for sh in s.shells
    )
    return Snippets(shells, render(s.try_python, pypi=pypi, npm=npm, go=go))
