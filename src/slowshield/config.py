"""Configuration: `config.toml` + environment overrides.

The TOML layout stays compatible with the Rust implementation's `config.toml`; keys for features that
were not ported (yum, homebrew, phylum, primary/secondary mode, mirror prober) are accepted and ignored
with a warning so existing deployments keep starting.

Precedence (highest first): environment variables (incl. ``*_FILE`` secrets), config file, defaults.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import os
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import msgspec

from slowshield.ecosystems import normalize

log = logging.getLogger(__name__)

Ecosystem = Literal["pypi", "npm", "go", "maven", "cargo", "oci"]
ECOSYSTEMS: tuple[Ecosystem, ...] = ("pypi", "npm", "go", "maven", "cargo", "oci")

DEFAULT_TRUSTED_PROXIES = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
]

# Policy keys a shield wall's leader also sets: on a follower, only the ones set here (file or environment) count
# against the leader's (stricter wins); the defaults don't.
POLICY_KEYS = frozenset({"default_delay_days", "fail_open", "enforce_age_on_download"})

# Keys from the Rust config that are recognised but intentionally unsupported in this version.
_LEGACY_TOP_LEVEL = {"mode", "mirror_probe_interval_minutes"}
_LEGACY_UPSTREAMS = {"homebrew", "yum"}
_LEGACY_FEEDS = {"phylum"}


class ConfigError(ValueError):
    """Raised for invalid configuration; the message is meant for operators."""


class ExceptionRule(msgspec.Struct, forbid_unknown_fields=True):
    """Per-package (optionally per-version) delay override."""

    ecosystem: Ecosystem
    package: str
    delay_days: float
    version: str | None = None
    note: str | None = None


class BlockRule(msgspec.Struct, forbid_unknown_fields=True):
    """A block the operator sets: a whole package (or image repository), or one version (or image tag or digest).
    Applied like an advisory, for the ecosystems no feed covers (container images) or before a feed catches up."""

    ecosystem: Ecosystem
    package: str
    version: str | None = None
    reason: str | None = None
    url: str | None = None


class PypiUpstream(msgspec.Struct, forbid_unknown_fields=True):
    enabled: bool = True
    fail_open: bool | None = None  # None: the top-level `fail_open`
    hostnames: list[str] = []
    mirrors: list[str] = msgspec.field(default_factory=lambda: ["https://pypi.org"])
    files_url: str = "https://files.pythonhosted.org"


class NpmUpstream(msgspec.Struct, forbid_unknown_fields=True):
    enabled: bool = True
    fail_open: bool | None = None  # None: the top-level `fail_open`
    hostnames: list[str] = []
    mirrors: list[str] = msgspec.field(default_factory=lambda: ["https://registry.npmjs.org"])
    # Absolute base URL clients use for this registry (tarball URLs are rewritten to it).
    # Defaults to `<public_url>/npm`; requests on a deprecated npm hostname use `https://<first hostname>`.
    public_url: str | None = None
    audit_passthrough: bool = True


class GoUpstream(msgspec.Struct, forbid_unknown_fields=True):
    enabled: bool = True
    fail_open: bool | None = None  # None: the top-level `fail_open`
    # GOPROXY-protocol mirrors. Publish times are the `Last-Modified` of each version's .mod, which on
    # proxy.golang.org is when the mirror first stored the version (docs/design/go.md).
    mirrors: list[str] = msgspec.field(default_factory=lambda: ["https://proxy.golang.org"])
    # The checksum database (GOSUMDB name sum.golang.org), proxied at /go/sumdb/sum.golang.org/.
    sumdb_url: str = "https://sum.golang.org"
    # Hosts the mirrors may redirect downloads to: proxy.golang.org sends large zips to signed Cloud Storage URLs.
    # Every zip is checked against the checksum database wherever it comes from.
    download_hosts: list[str] = msgspec.field(default_factory=lambda: ["storage.googleapis.com"])


class MavenRepo(msgspec.Struct, forbid_unknown_fields=True):
    url: str
    # Hosts this repository may redirect downloads to (the Plugin Portal sends files to its artifact store and to
    # Central). Every file is checked against the repository's checksums wherever it comes from.
    download_hosts: list[str] = []
    # Serve -SNAPSHOT versions, without the release-age check (they change by design). Operator repositories only.
    snapshots: bool = False


MAVEN_BUILTIN = ("all", "central", "google", "gradle-plugins")


class MavenUpstream(msgspec.Struct, forbid_unknown_fields=True):
    enabled: bool = True
    # An artifact none of whose versions is old enough is held too: on Maven, brand-new artifacts are the realistic
    # attack (typosquats, dependency confusion), and builds pin exact versions anyway (docs/design/maven.md).
    fail_open: bool | None = False
    central: MavenRepo = msgspec.field(default_factory=lambda: MavenRepo("https://repo1.maven.org/maven2"))
    google: MavenRepo = msgspec.field(default_factory=lambda: MavenRepo("https://dl.google.com/dl/android/maven2"))
    gradle_plugins: MavenRepo = msgspec.field(
        default_factory=lambda: MavenRepo(
            "https://plugins.gradle.org/m2", ["plugins-artifacts.gradle.org", "repo.maven.apache.org"]
        )
    )
    # More repositories, served at /maven/<id>/ (for example jitpack = { url = "https://jitpack.io" }).
    repos: dict[str, MavenRepo] = {}

    def repository(self, repo_id: str) -> MavenRepo | None:
        builtin = {"central": self.central, "google": self.google, "gradle-plugins": self.gradle_plugins}
        return builtin.get(repo_id) or self.repos.get(repo_id)

    def all_repos(self) -> dict[str, MavenRepo]:
        return {"central": self.central, "google": self.google, "gradle-plugins": self.gradle_plugins, **self.repos}


class CargoUpstream(msgspec.Struct, forbid_unknown_fields=True):
    enabled: bool = True
    # A crate none of whose versions is old enough is held too: on crates.io, brand-new crates are the realistic
    # attack (typosquats and impersonations), as on Maven (docs/design/cargo.md).
    fail_open: bool | None = False
    # The sparse index. Each line carries the version's publish time (`pubtime`), set by crates.io.
    index_url: str = "https://index.crates.io"
    # Where .crate files come from: <download_url>/<name>/<version>/download.
    download_url: str = "https://static.crates.io/crates"
    # Hosts the download URL may redirect to (static.crates.io does not redirect). Every .crate is checked against
    # the index's `cksum` wherever it comes from.
    download_hosts: list[str] = []


OciTimes = Literal["hub", "quay", "gcr", "mcr", "none"]


class OciRegistry(msgspec.Struct, forbid_unknown_fields=True):
    url: str  # the registry API (https://registry-1.docker.io for docker.io)
    # Hosts its token service and downloads may use, `*` allowed (blob CDNs, regional backends). Every manifest and
    # blob is checked against its digest wherever it comes from; tokens are never sent to another host.
    download_hosts: list[str] = []
    # Where the time a tag got its digest comes from: the Docker Hub API, Quay's tag history, the `manifest` map in
    # gcr.io/Artifact Registry `tags/list`, MCR's catalog, or none (SlowShield's own first sight only).
    times: OciTimes = "none"
    # The base URL of that time source when it isn't the registry itself: https://hub.docker.com (Docker Hub's API),
    # https://quay.io, https://mcr.microsoft.com. gcr.io and Artifact Registry answer on the registry API.
    times_url: str | None = None
    aliases: list[str] = []  # other names clients use for it (index.docker.io)
    enabled: bool = True
    # Credentials for its token service (Docker Hub: a username and a "Public Repo Read-only" access token), so
    # pulls count against an account instead of a shared IP. The token is read from this file at startup.
    username: str | None = None
    token_file: str | None = None


def _oci_builtin() -> dict[str, OciRegistry]:
    return {
        "docker.io": OciRegistry(
            "https://registry-1.docker.io",
            ["auth.docker.io", "hub.docker.com", "production.cloudfront.docker.com",
             "production.cloudflare.docker.com", "*.r2.cloudflarestorage.com"],
            "hub", "https://hub.docker.com", ["index.docker.io", "registry-1.docker.io"],
        ),
        "ghcr.io": OciRegistry("https://ghcr.io", ["pkg-containers.githubusercontent.com"]),
        "quay.io": OciRegistry(
            "https://quay.io", ["cdn*.quay.io", "quayio-production-s3.s3.amazonaws.com"], "quay", "https://quay.io"
        ),
        "registry.k8s.io": OciRegistry(
            "https://registry.k8s.io",
            ["*-docker.pkg.dev", "cdn.registry.k8s.io", "prod-registry-k8s-io-*.s3.dualstack.*.amazonaws.com"],
            "gcr",
        ),
        "gcr.io": OciRegistry("https://gcr.io", ["storage.googleapis.com"], "gcr"),
        "mcr.microsoft.com": OciRegistry(
            "https://mcr.microsoft.com", ["*.data.mcr.microsoft.com"], "mcr", "https://mcr.microsoft.com"
        ),
        "public.ecr.aws": OciRegistry("https://public.ecr.aws", ["*.cloudfront.net"]),
    }  # fmt: skip


class OciUpstream(msgspec.Struct, forbid_unknown_fields=True):
    enabled: bool = True
    # A tag with nothing old enough is refused, except during the first `default_delay_days` after this instance
    # started serving images: it has no tag history yet, so it serves the current digest and records a fail-open
    # event. False: strict from the first day (docs/design/oci.md).
    fail_open: bool | None = None
    # Image layers are streamed and checked, not stored: they would evict the package files the artifact cache is
    # for. A budget above 0 keeps them in a separate store under <data_dir>/cache/oci-layers.
    layer_cache_gb: float = 0
    # More registries, or changes to the built-in ones (docker.io, ghcr.io, quay.io, registry.k8s.io, gcr.io,
    # mcr.microsoft.com, public.ecr.aws: only the keys set change), keyed by the name clients use in image references.
    registries: dict[str, OciRegistry] = {}

    def all_registries(self) -> dict[str, OciRegistry]:
        return {name: reg for name, reg in {**_oci_builtin(), **self.registries}.items() if reg.enabled}

    def canonical(self, repository: str) -> str:
        """A normalised repository with a configured alias of its registry replaced by the registry's own name, so
        exceptions, blocks and history have one key whichever name a client uses."""
        registry, sep, path = repository.partition("/")
        for name, reg in self.all_registries().items():
            if registry in {a.lower() for a in reg.aliases}:
                return f"{name}{sep}{path}"
        return repository


class Upstreams(msgspec.Struct, forbid_unknown_fields=True):
    pypi: PypiUpstream = msgspec.field(default_factory=PypiUpstream)
    npm: NpmUpstream = msgspec.field(default_factory=NpmUpstream)
    go: GoUpstream = msgspec.field(default_factory=GoUpstream)
    maven: MavenUpstream = msgspec.field(default_factory=MavenUpstream)
    cargo: CargoUpstream = msgspec.field(default_factory=CargoUpstream)
    oci: OciUpstream = msgspec.field(default_factory=OciUpstream)


class FeedSource(msgspec.Struct, forbid_unknown_fields=True):
    enabled: bool = True
    api_key: str | None = None


class Feeds(msgspec.Struct, forbid_unknown_fields=True):
    poll_interval_minutes: float = 60
    osv: FeedSource = msgspec.field(default_factory=FeedSource)
    github_advisory: FeedSource = msgspec.field(default_factory=FeedSource)
    osv_base_url: str = "https://osv-vulnerabilities.storage.googleapis.com"
    github_api_url: str = "https://api.github.com"


class CacheConfig(msgspec.Struct, forbid_unknown_fields=True):
    # Upstream metadata and rendered responses: one SQLite file shared by all workers (disk + OS page cache).
    metadata_max_mb: float = 1024
    # Parsed metadata and small responses held in process memory, in total across all workers.
    metadata_memory_mb: float = 64
    artifacts_enabled: bool = True
    artifacts_max_gb: float = 20
    scrub_interval_hours: float = 24


ShieldwallRole = Literal["standalone", "leader", "follower"]


class ShieldwallConfig(msgspec.Struct, forbid_unknown_fields=True):
    """A shield wall: one leader, many followers (docs/design/shieldwall.md). Usually set through the environment."""

    role: ShieldwallRole = "standalone"  # SLOWSHIELD_SHIELDWALL_ROLE; a join string makes it `follower`
    # The join string from the leader's `slowshield wall invite` (SLOWSHIELD_JOIN or SLOWSHIELD_JOIN_FILE).
    join: str | None = None
    join_confirm: Literal["ui", "auto"] = "ui"  # SLOWSHIELD_JOIN_CONFIRM: `auto` joins without the UI click
    name: str | None = None  # SLOWSHIELD_INSTANCE_NAME (default: the host name)
    location: str = ""  # SLOWSHIELD_INSTANCE_LOCATION
    labels: dict[str, str] = {}  # SLOWSHIELD_INSTANCE_LABELS=env=prod,team=ml
    # A follower never takes a delay below this from its leader, exceptions for single versions included.
    min_delay_days: float = 1.0  # SLOWSHIELD_SHIELDWALL_MIN_DELAY_DAYS
    via_leader: bool = True  # SLOWSHIELD_SHIELDWALL_VIA_LEADER: fetch package files through the leader when it's up
    leader_ca_file: str | None = None  # SLOWSHIELD_LEADER_CA_FILE: for a leader behind Caddy's internal CA


class Config(msgspec.Struct, forbid_unknown_fields=True):
    bind_address: str = "0.0.0.0:8080"
    # Externally visible base URL of the UI host (e.g. https://slowshield.example.com).
    public_url: str | None = None
    # Caddy also serves localhost / 127.0.0.1 / [::1] over plain HTTP (SLOWSHIELD_LOCAL_HTTP=on), so local
    # clients work without trusting its internal CA. The Setup page and npm tarball URLs then use http://.
    local_http: bool = False
    data_dir: str = "/data"
    database_path: str | None = None
    workers: int = 1

    default_delay_days: float = 7
    metadata_cache_ttl_hours: float = 6
    enforce_age_on_download: bool = True
    fail_open: bool = True

    trusted_proxies: list[str] = msgspec.field(default_factory=lambda: list(DEFAULT_TRUSTED_PROXIES))
    record_client_ip: bool = True
    client_ip_retention_days: float = 30
    event_retention_days: float = 365
    stats_retention_days: float = 400

    upstreams: Upstreams = msgspec.field(default_factory=Upstreams)
    feeds: Feeds = msgspec.field(default_factory=Feeds)
    cache: CacheConfig = msgspec.field(default_factory=CacheConfig)
    exceptions: list[ExceptionRule] = []
    blocks: list[BlockRule] = []
    shieldwall: ShieldwallConfig = msgspec.field(default_factory=ShieldwallConfig)


@dataclass(frozen=True, slots=True)
class FeedTokenStatus:
    configured: bool
    source: str  # "env", "file", "config" or "missing"


@dataclass(slots=True)
class LoadedConfig:
    """A validated config plus derived lookup tables. Immutable by convention; swapped atomically on reload."""

    raw: Config
    path: Path | None
    generation: int = 0
    warnings: list[str] = field(default_factory=list)
    explicit: frozenset[str] = frozenset()  # the POLICY_KEYS set in the file or the environment
    github_token: str | None = None
    github_token_status: FeedTokenStatus = FeedTokenStatus(False, "missing")
    _pkg_rules: dict[tuple[str, str], float] = field(default_factory=dict)
    _ver_rules: dict[tuple[str, str, str], float] = field(default_factory=dict)
    _networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    @property
    def db_path(self) -> Path:
        if self.raw.database_path:
            return Path(self.raw.database_path)
        return Path(self.raw.data_dir) / "slowshield.db"

    @property
    def cache_dir(self) -> Path:
        return Path(self.raw.data_dir) / "cache"

    @property
    def metadata_store_path(self) -> Path:
        return Path(self.raw.data_dir) / "metadata-cache.db"

    @property
    def trusted_networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return self._networks

    def delay_days_for(self, ecosystem: str, name: str, version: str | None = None) -> float:
        """Delay for a package (already normalised name). Version-specific rules win over package rules."""
        if version is not None and self._ver_rules:
            v = self._ver_rules.get((ecosystem, name, version))
            if v is not None:
                return v
        v = self._pkg_rules.get((ecosystem, name))
        return self.raw.default_delay_days if v is None else v

    def fail_open_for(self, ecosystem: str) -> bool:
        """`upstreams.<ecosystem>.fail_open` if set, else the top-level `fail_open`."""
        value = getattr(self.raw.upstreams, ecosystem).fail_open
        return self.raw.fail_open if value is None else value

    def has_version_rules(self, ecosystem: str, name: str) -> bool:
        return any(k[0] == ecosystem and k[1] == name for k in self._ver_rules)

    def npm_public_base(self, *, via_hostname: bool = False) -> str:
        """Base for npm tarball URLs: `upstreams.npm.public_url`, else `<public_url>/npm`. Only requests that
        arrived on a deprecated npm hostname (removed in 0.1) keep `https://<first hostname>`."""
        npm = self.raw.upstreams.npm
        if npm.public_url:
            return npm.public_url.rstrip("/")
        if via_hostname and npm.hostnames:
            return f"https://{npm.hostnames[0]}"
        return f"{self.public_base()}/npm"

    def public_base(self) -> str:
        return (self.raw.public_url or "http://localhost:8080").rstrip("/")


def _read_secret(name: str, warnings: list[str]) -> tuple[str | None, str]:
    """Read ``NAME`` or ``NAME_FILE`` from the environment (file wins, as with Docker/K8s secrets).

    An unreadable or missing file is treated as "no secret" (the dependent feature switches off and the
    UI explains how to fix it) rather than preventing startup.
    """
    file_path = os.environ.get(f"{name}_FILE", "").strip()
    if file_path:
        try:
            value = Path(file_path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            warnings.append(f"{name}_FILE={file_path!r} cannot be read ({exc.strerror}); treating {name} as unset")
            return None, "file"
        return (value or None), "file"
    value = os.environ.get(name, "").strip()
    return (value or None), "env"


def _env_bool(name: str) -> bool | None:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return None
    v = raw.strip().lower()
    if v in {"1", "true", "yes", "on"}:
        return True
    if v in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean, got {raw!r}")


def _split_list(raw: str) -> list[str]:
    return [p.strip() for p in raw.replace(",", " ").split() if p.strip()]


def _strip_legacy(data: dict[str, Any], warnings: list[str]) -> None:
    for key in sorted(_LEGACY_TOP_LEVEL & data.keys()):
        warnings.append(f"config key {key!r} is not supported by this version and is ignored")
        data.pop(key)
    if "database_url" in data:
        url = data.pop("database_url")
        if isinstance(url, str) and url.startswith("sqlite:"):
            data.setdefault("database_path", url.removeprefix("sqlite:").removeprefix("//"))
        else:
            raise ConfigError("database_url must be of the form sqlite:/path/to.db")
    ups = data.get("upstreams")
    if isinstance(ups, dict):
        for key in sorted(_LEGACY_UPSTREAMS & ups.keys()):
            warnings.append(f"upstream {key!r} is not supported yet and is ignored")
            ups.pop(key)
    feeds = data.get("feeds")
    if isinstance(feeds, dict):
        for key in sorted(_LEGACY_FEEDS & feeds.keys()):
            warnings.append(f"feed {key!r} is not supported and is ignored")
            feeds.pop(key)


def _apply_env(cfg: Config) -> set[str]:
    """Apply the environment; returns the POLICY_KEYS it set."""
    env = os.environ
    explicit: set[str] = set()
    if v := env.get("DATABASE_URL", "").strip():
        if not v.startswith("sqlite:"):
            raise ConfigError("DATABASE_URL must be of the form sqlite:/path/to.db")
        cfg.database_path = v.removeprefix("sqlite:").removeprefix("//")
    if v := env.get("SLOWSHIELD_DATABASE_PATH", "").strip():
        cfg.database_path = v
    if v := env.get("SLOWSHIELD_DATA_DIR", "").strip():
        cfg.data_dir = v
    if v := env.get("SLOWSHIELD_BIND", "").strip():
        cfg.bind_address = v
    if v := env.get("SLOWSHIELD_PUBLIC_URL", "").strip():
        cfg.public_url = v
    if v := env.get("SLOWSHIELD_NPM_PUBLIC_URL", "").strip():
        cfg.upstreams.npm.public_url = v
    if v := env.get("SLOWSHIELD_WORKERS", "").strip():
        try:
            cfg.workers = int(v)
        except ValueError as exc:
            raise ConfigError(f"SLOWSHIELD_WORKERS must be an integer, got {v!r}") from exc
    if v := env.get("SLOWSHIELD_DEFAULT_DELAY_DAYS", "").strip():
        try:
            cfg.default_delay_days = float(v)
        except ValueError as exc:
            raise ConfigError(f"SLOWSHIELD_DEFAULT_DELAY_DAYS must be a number, got {v!r}") from exc
        explicit.add("default_delay_days")
    if v := env.get("SLOWSHIELD_PYPI_HOSTNAMES", "").strip():
        cfg.upstreams.pypi.hostnames = _split_list(v)
    if v := env.get("SLOWSHIELD_NPM_HOSTNAMES", "").strip():
        cfg.upstreams.npm.hostnames = _split_list(v)
    if v := env.get("SLOWSHIELD_TRUSTED_PROXIES", "").strip():
        cfg.trusted_proxies = _split_list(v)
    for name, setter in (
        ("SLOWSHIELD_PYPI_ENABLED", lambda b: setattr(cfg.upstreams.pypi, "enabled", b)),
        ("SLOWSHIELD_NPM_ENABLED", lambda b: setattr(cfg.upstreams.npm, "enabled", b)),
        ("SLOWSHIELD_GO_ENABLED", lambda b: setattr(cfg.upstreams.go, "enabled", b)),
        ("SLOWSHIELD_MAVEN_ENABLED", lambda b: setattr(cfg.upstreams.maven, "enabled", b)),
        ("SLOWSHIELD_CARGO_ENABLED", lambda b: setattr(cfg.upstreams.cargo, "enabled", b)),
        ("SLOWSHIELD_OCI_ENABLED", lambda b: setattr(cfg.upstreams.oci, "enabled", b)),
        ("SLOWSHIELD_ENFORCE_AGE_ON_DOWNLOAD", lambda b: setattr(cfg, "enforce_age_on_download", b)),
        ("SLOWSHIELD_FAIL_OPEN", lambda b: setattr(cfg, "fail_open", b)),
        ("SLOWSHIELD_RECORD_CLIENT_IP", lambda b: setattr(cfg, "record_client_ip", b)),
        ("SLOWSHIELD_LOCAL_HTTP", lambda b: setattr(cfg, "local_http", b)),
        ("SLOWSHIELD_ARTIFACT_CACHE", lambda b: setattr(cfg.cache, "artifacts_enabled", b)),
        ("SLOWSHIELD_FEED_OSV", lambda b: setattr(cfg.feeds.osv, "enabled", b)),
        ("SLOWSHIELD_FEED_GITHUB", lambda b: setattr(cfg.feeds.github_advisory, "enabled", b)),
    ):
        b = _env_bool(name)
        if b is not None:
            setter(b)
            if name in ("SLOWSHIELD_FAIL_OPEN", "SLOWSHIELD_ENFORCE_AGE_ON_DOWNLOAD"):
                explicit.add(name.removeprefix("SLOWSHIELD_").lower())
    _apply_shieldwall_env(cfg.shieldwall)
    if v := env.get("SLOWSHIELD_ARTIFACT_CACHE_MAX_GB", "").strip():
        try:
            cfg.cache.artifacts_max_gb = float(v)
        except ValueError as exc:
            raise ConfigError(f"SLOWSHIELD_ARTIFACT_CACHE_MAX_GB must be a number, got {v!r}") from exc
    return explicit


def _apply_shieldwall_env(sw: ShieldwallConfig) -> None:
    env = os.environ
    if v := env.get("SLOWSHIELD_SHIELDWALL_ROLE", "").strip().lower():
        if v not in ("standalone", "leader", "follower"):
            raise ConfigError(f"SLOWSHIELD_SHIELDWALL_ROLE must be standalone, leader or follower, got {v!r}")
        sw.role = v
    if v := env.get("SLOWSHIELD_JOIN_FILE", "").strip():
        try:
            sw.join = Path(v).read_text(encoding="utf-8").strip() or None
        except OSError as exc:
            raise ConfigError(f"SLOWSHIELD_JOIN_FILE: cannot read {v}: {exc}") from exc
    if v := env.get("SLOWSHIELD_JOIN", "").strip():
        sw.join = v
    if sw.join and sw.role == "standalone":
        sw.role = "follower"
    if v := env.get("SLOWSHIELD_JOIN_CONFIRM", "").strip().lower():
        if v not in ("ui", "auto"):
            raise ConfigError(f"SLOWSHIELD_JOIN_CONFIRM must be ui or auto, got {v!r}")
        sw.join_confirm = v
    if v := env.get("SLOWSHIELD_INSTANCE_NAME", "").strip():
        sw.name = v
    if v := env.get("SLOWSHIELD_INSTANCE_LOCATION", "").strip():
        sw.location = v
    if v := env.get("SLOWSHIELD_INSTANCE_LABELS", "").strip():
        labels: dict[str, str] = {}
        for item in _split_list(v):
            key, sep, value = item.partition("=")
            if not sep or not key.strip():
                raise ConfigError(f"SLOWSHIELD_INSTANCE_LABELS: expected key=value, got {item!r}")
            labels[key.strip()] = value.strip()
        sw.labels = labels
    if v := env.get("SLOWSHIELD_SHIELDWALL_MIN_DELAY_DAYS", "").strip():
        try:
            sw.min_delay_days = float(v)
        except ValueError as exc:
            raise ConfigError(f"SLOWSHIELD_SHIELDWALL_MIN_DELAY_DAYS must be a number, got {v!r}") from exc
    b = _env_bool("SLOWSHIELD_SHIELDWALL_VIA_LEADER")
    if b is not None:
        sw.via_leader = b
    if v := env.get("SLOWSHIELD_LEADER_CA_FILE", "").strip():
        sw.leader_ca_file = v


_LABEL = re.compile(r"[A-Za-z0-9._-]{1,63}")


def _validate_shieldwall(sw: ShieldwallConfig) -> None:
    if sw.role == "leader" and sw.join:
        raise ConfigError("shieldwall: a leader can't also join another leader (remove the join string)")
    if sw.role == "follower" and not sw.join:
        raise ConfigError("shieldwall: a follower needs the join string from its leader (SLOWSHIELD_JOIN)")
    if sw.join:
        from slowshield.shieldwall.join import JoinString, JoinStringError

        try:
            JoinString.parse(sw.join)
        except JoinStringError as exc:
            raise ConfigError(f"shieldwall.join: {exc}") from exc
    if not 0 <= sw.min_delay_days <= 365:
        raise ConfigError("shieldwall.min_delay_days must be between 0 and 365")
    for text, what in ((sw.name or "", "name"), (sw.location, "location")):
        if len(text) > 100 or any(ord(c) < 32 for c in text):
            raise ConfigError(f"shieldwall.{what}: at most 100 printable characters")
    for key, value in sw.labels.items():
        if not _LABEL.fullmatch(key) or len(value) > 100 or any(ord(c) < 32 for c in value):
            raise ConfigError(f"shieldwall.labels: invalid label {key!r}")


# Public URLs end up unquoted in the Setup page's shell snippets and in npm tarball links: scheme, host, optional
# port and a path of URL-safe characters only, so no value can carry shell syntax.
_PUBLIC_URL = re.compile(
    r"https?://(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%/-]*)?"
)


_HOSTNAME = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_HOST_PATTERN = re.compile(r"[A-Za-z0-9*-]+(?:\.[A-Za-z0-9*-]+)*")
_OCI_REGISTRY = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::[0-9]{1,5})?|localhost(?::[0-9]{1,5})?")


def _validate(cfg: Config) -> None:
    _validate_shieldwall(cfg.shieldwall)
    if cfg.default_delay_days < 0:
        raise ConfigError("default_delay_days must be >= 0")
    if cfg.metadata_cache_ttl_hours <= 0:
        raise ConfigError("metadata_cache_ttl_hours must be > 0")
    if cfg.workers < 1:
        raise ConfigError("workers must be >= 1")
    if cfg.cache.metadata_max_mb <= 0 or cfg.cache.metadata_memory_mb <= 0:
        raise ConfigError("cache.metadata_max_mb and cache.metadata_memory_mb must be > 0")
    if cfg.feeds.poll_interval_minutes < 1:
        raise ConfigError("feeds.poll_interval_minutes must be >= 1")
    host, sep, port = cfg.bind_address.rpartition(":")
    if not sep or not port.isdigit() or not host:
        raise ConfigError(f"bind_address must be host:port, got {cfg.bind_address!r}")
    for name, url in (("public_url", cfg.public_url), ("upstreams.npm.public_url", cfg.upstreams.npm.public_url)):
        if url and not _PUBLIC_URL.fullmatch(url):
            raise ConfigError(
                f"{name} must be a plain http(s)://host[:port][/path] URL (no query, credentials or special "
                f"characters: it appears in copy-paste shell snippets), got {url!r}"
            )
    for eco in ("pypi", "npm", "go"):
        mirrors = getattr(cfg.upstreams, eco).mirrors
        if not mirrors:
            raise ConfigError(f"upstreams.{eco}.mirrors must not be empty")
        for m in mirrors:
            if not m.startswith(("https://", "http://")):
                raise ConfigError(f"upstreams.{eco}.mirrors entries must be http(s) URLs, got {m!r}")
    if not cfg.upstreams.go.sumdb_url.startswith(("https://", "http://")):
        raise ConfigError(f"upstreams.go.sumdb_url must be an http(s) URL, got {cfg.upstreams.go.sumdb_url!r}")
    for host in cfg.upstreams.go.download_hosts:
        if not _HOSTNAME.fullmatch(host):
            raise ConfigError(f"upstreams.go.download_hosts entries must be host names, got {host!r}")
    for repo_id in cfg.upstreams.maven.repos:
        if repo_id in MAVEN_BUILTIN or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", repo_id):
            raise ConfigError(
                f"upstreams.maven.repos: {repo_id!r} must be lower-case letters, digits and dashes, and not one of "
                f"{', '.join(MAVEN_BUILTIN)}"
            )
    for repo_id, repo in cfg.upstreams.maven.all_repos().items():
        if not repo.url.startswith(("https://", "http://")):
            raise ConfigError(f"upstreams.maven {repo_id}: url must be an http(s) URL, got {repo.url!r}")
        for host in repo.download_hosts:
            if not _HOSTNAME.fullmatch(host):
                raise ConfigError(f"upstreams.maven {repo_id}: download_hosts entries must be host names, got {host!r}")
    cargo = cfg.upstreams.cargo
    for name, url in (("index_url", cargo.index_url), ("download_url", cargo.download_url)):
        if not url.startswith(("https://", "http://")):
            raise ConfigError(f"upstreams.cargo.{name} must be an http(s) URL, got {url!r}")
    for host in cargo.download_hosts:
        if not _HOSTNAME.fullmatch(host):
            raise ConfigError(f"upstreams.cargo.download_hosts entries must be host names, got {host!r}")
    oci = cfg.upstreams.oci
    if oci.layer_cache_gb < 0:
        raise ConfigError("upstreams.oci.layer_cache_gb must be >= 0")
    for name in oci.registries:
        if not _OCI_REGISTRY.fullmatch(name):
            raise ConfigError(
                f"upstreams.oci.registries: {name!r} must be a registry host name (e.g. registry.example.com)"
            )
    for name, reg in oci.all_registries().items():
        if not reg.url.startswith(("https://", "http://")):
            raise ConfigError(f"upstreams.oci.registries.{name}: url must be an http(s) URL, got {reg.url!r}")
        for host in reg.download_hosts:
            if not _HOST_PATTERN.fullmatch(host):
                raise ConfigError(
                    f"upstreams.oci.registries.{name}: download_hosts entries must be host names or `*` patterns, "
                    f"got {host!r}"
                )
        if reg.times_url and not reg.times_url.startswith(("https://", "http://")):
            raise ConfigError(
                f"upstreams.oci.registries.{name}: times_url must be an http(s) URL, got {reg.times_url!r}"
            )
        if reg.times in ("hub", "quay", "mcr") and not reg.times_url:
            raise ConfigError(f"upstreams.oci.registries.{name}: times = {reg.times!r} needs times_url")
        if bool(reg.username) != bool(reg.token_file):
            raise ConfigError(f"upstreams.oci.registries.{name}: username and token_file go together")
    # One registry per name: an alias shared by two registries, or one that is another registry's name, would route
    # to one registry while exceptions and blocks resolve to the other.
    owners: dict[str, str] = {name: name for name in oci.all_registries()}
    for name, reg in oci.all_registries().items():
        for alias in reg.aliases:
            key = alias.lower()
            if not _OCI_REGISTRY.fullmatch(key):
                raise ConfigError(f"upstreams.oci.registries.{name}: alias {alias!r} must be a registry host name")
            owner = owners.setdefault(key, name)
            if owner != name:
                raise ConfigError(f"upstreams.oci.registries: {alias!r} names both {owner!r} and {name!r}")
    overlap = set(map(str.lower, cfg.upstreams.pypi.hostnames)) & set(map(str.lower, cfg.upstreams.npm.hostnames))
    if overlap:
        raise ConfigError(f"a hostname cannot serve both pypi and npm: {sorted(overlap)}")
    for block in cfg.blocks:
        if not block.package.strip() or (block.version is not None and not block.version.strip()):
            raise ConfigError(f"blocks: {block.ecosystem}/{block.package!r} needs a package (and a non-empty version)")
        if block.url and not block.url.startswith(("https://", "http://")):
            raise ConfigError(f"blocks: {block.ecosystem}/{block.package}: url must be an http(s) URL")
    for rule in cfg.exceptions:
        if rule.delay_days < 0:
            raise ConfigError(f"exception for {rule.ecosystem}/{rule.package}: delay_days must be >= 0")


def rule_tables(
    exceptions: list[ExceptionRule], oci: OciUpstream
) -> tuple[dict[tuple[str, str], float], dict[tuple[str, str, str], float]]:
    """Exceptions as lookup tables, by package and by version, with names normalised. The first rule for a key
    wins."""
    pkg_rules: dict[tuple[str, str], float] = {}
    ver_rules: dict[tuple[str, str, str], float] = {}
    for rule in exceptions:
        name = normalize(rule.ecosystem, rule.package)
        if rule.ecosystem == "oci":
            name = oci.canonical(name)
        if rule.version:
            version = rule.version.strip()
            if rule.ecosystem == "go" and not version.startswith("v"):
                version = "v" + version  # Go versions always carry the `v`; accept "1.2.3" as well
            ver_rules.setdefault((rule.ecosystem, name, version), rule.delay_days)
        else:
            pkg_rules.setdefault((rule.ecosystem, name), rule.delay_days)
    return pkg_rules, ver_rules


def build(
    cfg: Config,
    *,
    path: Path | None,
    warnings: list[str],
    generation: int = 0,
    explicit: frozenset[str] = frozenset(),
) -> LoadedConfig:
    explicit = explicit | _apply_env(cfg)
    _validate(cfg)
    base = (cfg.public_url or "http://localhost:8080").rstrip("/")
    for eco, env, path_url in (
        ("pypi", "SLOWSHIELD_PYPI_HOSTNAMES", f"{base}/pypi/simple/"),
        ("npm", "SLOWSHIELD_NPM_HOSTNAMES", f"{base}/npm/"),
    ):
        if getattr(cfg.upstreams, eco).hostnames:
            warnings.append(
                f"upstreams.{eco}.hostnames ({env}) is deprecated and will be removed in 0.1: "
                f"point clients at {path_url} instead (docs/design/routing.md)"
            )
    pkg_rules, ver_rules = rule_tables(cfg.exceptions, cfg.upstreams.oci)
    networks = []
    for cidr in cfg.trusted_proxies:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError as exc:
            raise ConfigError(f"trusted_proxies: invalid network {cidr!r}") from exc

    token, origin = _read_secret("GITHUB_TOKEN", warnings)
    if token is None and cfg.feeds.github_advisory.api_key:
        token, origin = cfg.feeds.github_advisory.api_key, "config"
    status = FeedTokenStatus(token is not None, origin if token else "missing")

    return LoadedConfig(
        raw=cfg,
        path=path,
        generation=generation,
        warnings=warnings,
        explicit=explicit,
        github_token=token,
        github_token_status=status,
        _pkg_rules=pkg_rules,
        _ver_rules=ver_rules,
        _networks=tuple(networks),
    )


def _merge_builtin_registries(data: dict[str, Any]) -> None:
    """A table for a built-in registry changes only the keys it sets: `token_file` for docker.io keeps Docker Hub's
    CDN hosts and time source."""
    upstreams = data.get("upstreams")
    oci = upstreams.get("oci") if isinstance(upstreams, dict) else None
    regs = oci.get("registries") if isinstance(oci, dict) else None
    if not isinstance(regs, dict):
        return
    for name, builtin in _oci_builtin().items():
        if isinstance(regs.get(name), dict):
            regs[name] = {**msgspec.to_builtins(builtin), **regs[name]}


def parse(text: str, *, path: Path | None = None, generation: int = 0) -> LoadedConfig:
    warnings: list[str] = []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path or 'config'}: invalid TOML: {exc}") from exc
    _strip_legacy(data, warnings)
    _merge_builtin_registries(data)
    try:
        cfg = msgspec.convert(data, Config, strict=False)
    except msgspec.ValidationError as exc:
        raise ConfigError(f"{path or 'config'}: {exc}") from exc
    explicit = frozenset(POLICY_KEYS & data.keys())
    return build(cfg, path=path, warnings=warnings, generation=generation, explicit=explicit)


def config_path_from_env() -> Path | None:
    raw = os.environ.get("SLOWSHIELD_CONFIG", "").strip()
    if raw:
        return Path(raw)
    for candidate in (Path("/etc/slowshield/config.toml"), Path("config.toml")):
        if candidate.is_file():
            return candidate
    return None


def load(path: Path | None = None, *, generation: int = 0) -> LoadedConfig:
    """Load from `path` (or $SLOWSHIELD_CONFIG); a missing file means defaults + env."""
    path = path or config_path_from_env()
    if path is None:
        return build(Config(), path=None, warnings=[], generation=generation)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if os.environ.get("SLOWSHIELD_CONFIG"):
            raise ConfigError(f"SLOWSHIELD_CONFIG={path} does not exist") from None
        return build(Config(), path=None, warnings=[], generation=generation)
    return parse(text, path=path, generation=generation)


# Fields that only take effect on restart (routing, storage, listeners).
RESTART_ONLY = (
    "bind_address",
    "data_dir",
    "database_path",
    "workers",
    "public_url",
    "shieldwall",
)


def restart_only_changes(old: Config, new: Config) -> list[str]:
    changed = [name for name in RESTART_ONLY if getattr(old, name) != getattr(new, name)]
    for eco in ECOSYSTEMS:
        o, n = getattr(old.upstreams, eco), getattr(new.upstreams, eco)
        if o.enabled != n.enabled:
            changed.append(f"upstreams.{eco}.enabled")
        if getattr(o, "hostnames", None) != getattr(n, "hostnames", None):
            changed.append(f"upstreams.{eco}.hostnames")
    if old.upstreams.npm.public_url != new.upstreams.npm.public_url:
        changed.append("upstreams.npm.public_url")
    changed.extend(  # repositories decide which upstream hosts the client may reach
        f"upstreams.maven.{name}"
        for name in ("central", "google", "gradle_plugins", "repos")
        if getattr(old.upstreams.maven, name) != getattr(new.upstreams.maven, name)
    )
    changed.extend(  # registries decide which upstream hosts the client may reach
        f"upstreams.oci.{name}"
        for name in ("registries", "layer_cache_gb")
        if getattr(old.upstreams.oci, name) != getattr(new.upstreams.oci, name)
    )
    changed.extend(  # these decide which upstream hosts the client may reach
        f"upstreams.cargo.{name}"
        for name in ("index_url", "download_url", "download_hosts")
        if getattr(old.upstreams.cargo, name) != getattr(new.upstreams.cargo, name)
    )
    if old.cache.artifacts_enabled != new.cache.artifacts_enabled:
        changed.append("cache.artifacts_enabled")
    changed.extend(
        f"cache.{name}"
        for name in ("metadata_max_mb", "metadata_memory_mb")
        if getattr(old.cache, name) != getattr(new.cache, name)
    )
    return changed


class ConfigHolder:
    """Holds the active config; `maybe_reload()` swaps it in when the file changed (mtime + size).

    On a shield wall follower, `current` is this instance's own config (`local`) with the leader's policy merged in
    (`set_overlay`); every swap gets a new generation, so cached evaluations are dropped.
    """

    def __init__(self, cfg: LoadedConfig) -> None:
        self.local = cfg
        self.current = cfg
        self._stamp = self._file_stamp(cfg.path)
        self._generation = cfg.generation
        self._overlay: Callable[[LoadedConfig], LoadedConfig] | None = None
        self._overlay_key: object = None

    def set_overlay(self, key: object, overlay: Callable[[LoadedConfig], LoadedConfig] | None) -> bool:
        """Merge something into the local config (the shield wall leader's policy); `key` identifies it, so setting the
        same overlay again is a no-op. Returns whether the active config changed."""
        if key == self._overlay_key:
            return False
        self._overlay_key = key
        self._overlay = overlay
        self._swap()
        return True

    def _swap(self) -> None:
        self._generation += 1
        merged = self.local if self._overlay is None else self._overlay(self.local)
        self.current = dataclasses.replace(merged, generation=self._generation)

    @staticmethod
    def _file_stamp(path: Path | None) -> tuple[float, int] | None:
        if path is None:
            return None
        try:
            st = path.stat()
        except OSError:
            return None
        return (st.st_mtime, st.st_size)

    def maybe_reload(self) -> bool:
        path = self.current.path
        if path is None:
            return False
        stamp = self._file_stamp(path)
        if stamp is None or stamp == self._stamp:
            return False
        self._stamp = stamp
        try:
            new = load(path, generation=self._generation + 1)
        except ConfigError as exc:
            log.error("config reload failed, keeping previous config", extra={"error": str(exc)})
            return False
        ignored = restart_only_changes(self.current.raw, new.raw)
        if ignored:
            log.warning("config changes require a restart and were not applied", extra={"fields": ignored})
            for name in ignored:
                _restore_field(new.raw, self.local.raw, name)
            new = build(new.raw, path=path, warnings=new.warnings, generation=new.generation, explicit=new.explicit)
        self.local = new
        self._swap()
        log.info("config reloaded", extra={"generation": self._generation})
        return True


def _restore_field(target: Config, source: Config, dotted: str) -> None:
    parts = dotted.split(".")
    t: Any = target
    s: Any = source
    for p in parts[:-1]:
        t, s = getattr(t, p), getattr(s, p)
    setattr(t, parts[-1], getattr(s, parts[-1]))
