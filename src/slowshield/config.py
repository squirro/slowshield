"""Configuration: `config.toml` + environment overrides.

The TOML layout stays compatible with the Rust implementation's `config.toml`; keys for features that
were not ported (yum, homebrew, phylum, primary/secondary mode, mirror prober) are accepted and ignored
with a warning so existing deployments keep starting.

Precedence (highest first): environment variables (incl. ``*_FILE`` secrets), config file, defaults.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import msgspec

from slowshield.names import normalize_npm, normalize_pypi

log = logging.getLogger(__name__)

Ecosystem = Literal["pypi", "npm"]
ECOSYSTEMS: tuple[Ecosystem, ...] = ("pypi", "npm")

DEFAULT_TRUSTED_PROXIES = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
]

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


class PypiUpstream(msgspec.Struct, forbid_unknown_fields=True):
    enabled: bool = True
    hostnames: list[str] = []
    mirrors: list[str] = msgspec.field(default_factory=lambda: ["https://pypi.org"])
    files_url: str = "https://files.pythonhosted.org"


class NpmUpstream(msgspec.Struct, forbid_unknown_fields=True):
    enabled: bool = True
    hostnames: list[str] = []
    mirrors: list[str] = msgspec.field(default_factory=lambda: ["https://registry.npmjs.org"])
    # Absolute base URL clients use for this registry (tarball URLs are rewritten to it).
    # Defaults to `<public_url>/npm`; requests on a deprecated npm hostname use `https://<first hostname>`.
    public_url: str | None = None
    audit_passthrough: bool = True


class Upstreams(msgspec.Struct, forbid_unknown_fields=True):
    pypi: PypiUpstream = msgspec.field(default_factory=PypiUpstream)
    npm: NpmUpstream = msgspec.field(default_factory=NpmUpstream)


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


def _apply_env(cfg: Config) -> None:
    env = os.environ
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
    if v := env.get("SLOWSHIELD_PYPI_HOSTNAMES", "").strip():
        cfg.upstreams.pypi.hostnames = _split_list(v)
    if v := env.get("SLOWSHIELD_NPM_HOSTNAMES", "").strip():
        cfg.upstreams.npm.hostnames = _split_list(v)
    if v := env.get("SLOWSHIELD_TRUSTED_PROXIES", "").strip():
        cfg.trusted_proxies = _split_list(v)
    for name, setter in (
        ("SLOWSHIELD_PYPI_ENABLED", lambda b: setattr(cfg.upstreams.pypi, "enabled", b)),
        ("SLOWSHIELD_NPM_ENABLED", lambda b: setattr(cfg.upstreams.npm, "enabled", b)),
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
    if v := env.get("SLOWSHIELD_ARTIFACT_CACHE_MAX_GB", "").strip():
        try:
            cfg.cache.artifacts_max_gb = float(v)
        except ValueError as exc:
            raise ConfigError(f"SLOWSHIELD_ARTIFACT_CACHE_MAX_GB must be a number, got {v!r}") from exc


# Public URLs end up unquoted in the Setup page's shell snippets and in npm tarball links: scheme, host, optional
# port and a path of URL-safe characters only, so no value can carry shell syntax.
_PUBLIC_URL = re.compile(
    r"https?://(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%/-]*)?"
)


def _validate(cfg: Config) -> None:
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
    for eco, mirrors in (("pypi", cfg.upstreams.pypi.mirrors), ("npm", cfg.upstreams.npm.mirrors)):
        if not mirrors:
            raise ConfigError(f"upstreams.{eco}.mirrors must not be empty")
        for m in mirrors:
            if not m.startswith(("https://", "http://")):
                raise ConfigError(f"upstreams.{eco}.mirrors entries must be http(s) URLs, got {m!r}")
    overlap = set(map(str.lower, cfg.upstreams.pypi.hostnames)) & set(map(str.lower, cfg.upstreams.npm.hostnames))
    if overlap:
        raise ConfigError(f"a hostname cannot serve both pypi and npm: {sorted(overlap)}")
    for rule in cfg.exceptions:
        if rule.delay_days < 0:
            raise ConfigError(f"exception for {rule.ecosystem}/{rule.package}: delay_days must be >= 0")


def build(cfg: Config, *, path: Path | None, warnings: list[str], generation: int = 0) -> LoadedConfig:
    _apply_env(cfg)
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
    pkg_rules: dict[tuple[str, str], float] = {}
    ver_rules: dict[tuple[str, str, str], float] = {}
    for rule in cfg.exceptions:
        name = normalize_pypi(rule.package) if rule.ecosystem == "pypi" else normalize_npm(rule.package)
        if rule.version:
            key = (rule.ecosystem, name, rule.version)
            ver_rules.setdefault(key, rule.delay_days)
        else:
            pkg_rules.setdefault((rule.ecosystem, name), rule.delay_days)
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
        github_token=token,
        github_token_status=status,
        _pkg_rules=pkg_rules,
        _ver_rules=ver_rules,
        _networks=tuple(networks),
    )


def parse(text: str, *, path: Path | None = None, generation: int = 0) -> LoadedConfig:
    warnings: list[str] = []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path or 'config'}: invalid TOML: {exc}") from exc
    _strip_legacy(data, warnings)
    try:
        cfg = msgspec.convert(data, Config, strict=False)
    except msgspec.ValidationError as exc:
        raise ConfigError(f"{path or 'config'}: {exc}") from exc
    return build(cfg, path=path, warnings=warnings, generation=generation)


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
)


def restart_only_changes(old: Config, new: Config) -> list[str]:
    changed = [name for name in RESTART_ONLY if getattr(old, name) != getattr(new, name)]
    for eco in ECOSYSTEMS:
        o, n = getattr(old.upstreams, eco), getattr(new.upstreams, eco)
        if o.enabled != n.enabled:
            changed.append(f"upstreams.{eco}.enabled")
        if o.hostnames != n.hostnames:
            changed.append(f"upstreams.{eco}.hostnames")
    if old.upstreams.npm.public_url != new.upstreams.npm.public_url:
        changed.append("upstreams.npm.public_url")
    if old.cache.artifacts_enabled != new.cache.artifacts_enabled:
        changed.append("cache.artifacts_enabled")
    changed.extend(
        f"cache.{name}"
        for name in ("metadata_max_mb", "metadata_memory_mb")
        if getattr(old.cache, name) != getattr(new.cache, name)
    )
    return changed


class ConfigHolder:
    """Holds the active config; `maybe_reload()` swaps it in when the file changed (mtime + size)."""

    def __init__(self, cfg: LoadedConfig) -> None:
        self.current = cfg
        self._stamp = self._file_stamp(cfg.path)

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
            new = load(path, generation=self.current.generation + 1)
        except ConfigError as exc:
            log.error("config reload failed, keeping previous config", extra={"error": str(exc)})
            return False
        ignored = restart_only_changes(self.current.raw, new.raw)
        if ignored:
            log.warning("config changes require a restart and were not applied", extra={"fields": ignored})
            for name in ignored:
                _restore_field(new.raw, self.current.raw, name)
            new = build(new.raw, path=path, warnings=new.warnings, generation=new.generation)
        self.current = new
        log.info("config reloaded", extra={"generation": new.generation})
        return True


def _restore_field(target: Config, source: Config, dotted: str) -> None:
    parts = dotted.split(".")
    t: Any = target
    s: Any = source
    for p in parts[:-1]:
        t, s = getattr(t, p), getattr(s, p)
    setattr(t, parts[-1], getattr(s, parts[-1]))
