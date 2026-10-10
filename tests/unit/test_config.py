"""Configuration: TOML compatibility, env overrides, secrets, validation, hot reload."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from slowshield import config as C

RUST_CONFIG = """
bind_address = "0.0.0.0:8080"
mode = "primary"
default_delay_days = 7
metadata_cache_ttl_hours = 6
mirror_probe_interval_minutes = 15
database_url = "sqlite:/data/mirror.db"

[upstreams.pypi]
enabled = true
hostnames = ["pypi-slowshield.squirro.net"]
mirrors = ["https://pypi.org"]

[upstreams.npm]
enabled = true
hostnames = ["npmjs-slowshield.squirro.net"]
mirrors = ["https://registry.npmjs.org"]

[upstreams.homebrew]
enabled = false
hostnames = ["brew-slowshield.squirro.net"]
mirrors = ["https://ghcr.io"]

[feeds]
poll_interval_minutes = 60

[feeds.phylum]
enabled = false

[feeds.osv]
enabled = true

[feeds.github_advisory]
enabled = true

[[exceptions]]
ecosystem = "pypi"
package = "LiteLLM"
delay_days = 14
note = "supply chain incident 2026-03"
"""


def test_rust_config_is_accepted_with_warnings() -> None:
    cfg = C.parse(RUST_CONFIG)
    assert cfg.raw.default_delay_days == 7
    assert cfg.db_path == Path("/data/mirror.db")
    assert cfg.raw.upstreams.pypi.hostnames == ["pypi-slowshield.squirro.net"]
    joined = " ".join(cfg.warnings)
    for key in ("mode", "mirror_probe_interval_minutes", "homebrew", "phylum"):
        assert key in joined
    assert cfg.delay_days_for("pypi", "litellm") == 14  # normalised name
    assert cfg.delay_days_for("pypi", "other") == 7
    # Path requests get path URLs; only requests on the deprecated npm hostname keep it.
    assert cfg.npm_public_base() == "http://localhost:8080/npm"
    assert cfg.npm_public_base(via_hostname=True) == "https://npmjs-slowshield.squirro.net"
    for eco in ("pypi", "npm"):
        assert any(f"upstreams.{eco}.hostnames" in w and "removed in 0.1" in w for w in cfg.warnings), eco


def test_defaults_and_paths() -> None:
    cfg = C.load(None)
    assert cfg.raw.bind_address == "0.0.0.0:8080"
    assert cfg.db_path == Path("/data/slowshield.db")
    assert cfg.cache_dir == Path("/data/cache")
    assert cfg.public_base() == "http://localhost:8080"
    assert cfg.npm_public_base() == "http://localhost:8080/npm"
    assert cfg.github_token_status == C.FeedTokenStatus(False, "missing")


def test_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    env = {
        "DATABASE_URL": "sqlite:///tmp/x.db",
        "SLOWSHIELD_DATA_DIR": "/srv",
        "SLOWSHIELD_BIND": "127.0.0.1:9000",
        "SLOWSHIELD_PUBLIC_URL": "https://ui.example",
        "SLOWSHIELD_NPM_PUBLIC_URL": "https://npm.example",
        "SLOWSHIELD_WORKERS": "4",
        "SLOWSHIELD_DEFAULT_DELAY_DAYS": "3.5",
        "SLOWSHIELD_PYPI_HOSTNAMES": "a.example, b.example",
        "SLOWSHIELD_NPM_HOSTNAMES": "n.example",
        "SLOWSHIELD_TRUSTED_PROXIES": "10.0.0.0/8 192.0.2.1",
        "SLOWSHIELD_FAIL_OPEN": "no",
        "SLOWSHIELD_ENFORCE_AGE_ON_DOWNLOAD": "false",
        "SLOWSHIELD_RECORD_CLIENT_IP": "0",
        "SLOWSHIELD_ARTIFACT_CACHE": "off",
        "SLOWSHIELD_ARTIFACT_CACHE_MAX_GB": "2.5",
        "SLOWSHIELD_FEED_OSV": "true",
        "SLOWSHIELD_FEED_GITHUB": "1",
        "SLOWSHIELD_PYPI_ENABLED": "yes",
        "SLOWSHIELD_NPM_ENABLED": "on",
        "GITHUB_TOKEN": "ghp_x",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    cfg = C.load(None)
    r = cfg.raw
    assert cfg.db_path == Path("/tmp/x.db")
    assert r.data_dir == "/srv" and r.bind_address == "127.0.0.1:9000" and r.workers == 4
    assert r.default_delay_days == 3.5
    assert r.upstreams.pypi.hostnames == ["a.example", "b.example"]
    assert cfg.npm_public_base() == "https://npm.example"
    assert [str(n) for n in cfg.trusted_networks] == ["10.0.0.0/8", "192.0.2.1/32"]
    assert not r.fail_open and not r.enforce_age_on_download and not r.record_client_ip
    assert not r.cache.artifacts_enabled and r.cache.artifacts_max_gb == 2.5
    assert cfg.github_token == "ghp_x" and cfg.github_token_status.source == "env"


@pytest.mark.parametrize(
    ("var", "value"),
    [
        ("SLOWSHIELD_WORKERS", "many"),
        ("SLOWSHIELD_DEFAULT_DELAY_DAYS", "soon"),
        ("SLOWSHIELD_FAIL_OPEN", "maybe"),
        ("SLOWSHIELD_ARTIFACT_CACHE_MAX_GB", "big"),
        ("DATABASE_URL", "postgres://x"),
    ],
)
def test_env_validation(monkeypatch: pytest.MonkeyPatch, var: str, value: str) -> None:
    monkeypatch.setenv(var, value)
    with pytest.raises(C.ConfigError):
        C.load(None)


def test_missing_secret_file_disables_feed_instead_of_crashing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_env_is_ignored_when_file_is_set")
    monkeypatch.setenv("GITHUB_TOKEN_FILE", "/nonexistent/token")
    cfg = C.load(None)
    assert cfg.github_token is None
    assert not cfg.github_token_status.configured
    assert any("GITHUB_TOKEN_FILE" in w for w in cfg.warnings)


def test_secret_file_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    f = tmp_path / "t"
    f.write_text(" ghp_file \n")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_env")
    monkeypatch.setenv("GITHUB_TOKEN_FILE", str(f))
    cfg = C.load(None)
    assert cfg.github_token == "ghp_file"


def test_token_from_config_file() -> None:
    cfg = C.parse('[feeds.github_advisory]\napi_key = "ghp_cfg"\n')
    assert cfg.github_token == "ghp_cfg" and cfg.github_token_status.source == "config"


@pytest.mark.parametrize(
    "url",
    [
        "https://slowshield.example.com",
        "http://localhost:8080",
        "https://h.example/",
        "https://h/sub/path_1.2~x",
        "http://[::1]:8080",
        "http://127.0.0.1:8080/",
        "https://xn--bcher-kva.example/%7Euser",
    ],
)
def test_valid_public_urls(url: str) -> None:
    assert C.parse(f'public_url = "{url}"').raw.public_url == url


@pytest.mark.parametrize(
    "toml",
    [
        "default_delay_days = -1",
        "metadata_cache_ttl_hours = 0",
        "workers = 0",
        "[feeds]\npoll_interval_minutes = 0",
        'bind_address = "nope"',
        'public_url = "ftp://x"',
        # public URLs appear unquoted in shell snippets: no shell syntax, query, credentials or spaces
        'public_url = "https://h/$(id)"',
        'public_url = "https://h/pypi;id"',
        'public_url = "https://h/?a=1&b=2"',
        'public_url = "https://user:pw@h"',
        'public_url = "https://h/a b"',
        'public_url = "https://h`id`"',
        '[upstreams.npm]\npublic_url = "https://h/npm\'x"',
        "[upstreams.pypi]\nmirrors = []",
        '[upstreams.npm]\nmirrors = ["registry.npmjs.org"]',
        '[upstreams.pypi]\nhostnames = ["same"]\n[upstreams.npm]\nhostnames = ["SAME"]',
        '[[exceptions]]\necosystem = "pypi"\npackage = "x"\ndelay_days = -2',
        '[[exceptions]]\necosystem = "rubygems"\npackage = "x"\ndelay_days = 1',
        "unknown_key = 1",
        "this is not toml",
        'database_url = "mysql://x"',
        'trusted_proxies = ["not-a-network"]',
    ],
)
def test_invalid_configs(toml: str) -> None:
    with pytest.raises(C.ConfigError):
        C.parse(toml)


def test_version_specific_exceptions() -> None:
    cfg = C.parse(
        '[[exceptions]]\necosystem = "npm"\npackage = "@a/b"\nversion = "1.2.3"\ndelay_days = 0\n'
        '[[exceptions]]\necosystem = "npm"\npackage = "@a/b"\ndelay_days = 30\n'
    )
    assert cfg.delay_days_for("npm", "@a/b", "1.2.3") == 0
    assert cfg.delay_days_for("npm", "@a/b", "1.2.4") == 30
    assert cfg.has_version_rules("npm", "@a/b") and not cfg.has_version_rules("npm", "x")


def test_load_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text("default_delay_days = 2\n")
    monkeypatch.setenv("SLOWSHIELD_CONFIG", str(p))
    assert C.config_path_from_env() == p
    assert C.load().raw.default_delay_days == 2
    monkeypatch.setenv("SLOWSHIELD_CONFIG", str(tmp_path / "missing.toml"))
    with pytest.raises(C.ConfigError):
        C.load()
    monkeypatch.delenv("SLOWSHIELD_CONFIG")
    assert C.load(tmp_path / "missing.toml").path is None  # implicit path missing -> defaults
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.toml").write_text("default_delay_days = 4\n")
    assert C.config_path_from_env() in (Path("/etc/slowshield/config.toml"), Path("config.toml"))


def test_hot_reload_applies_policy_and_keeps_restart_only_fields(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text('default_delay_days = 7\nbind_address = "0.0.0.0:8080"\n')
    holder = C.ConfigHolder(C.load(p))
    assert not holder.maybe_reload()  # unchanged
    p.write_text('default_delay_days = 2\nbind_address = "0.0.0.0:9999"\n[upstreams.npm]\nenabled = false\n')
    os.utime(p, (1, 1))
    assert holder.maybe_reload()
    cur = holder.current
    assert cur.raw.default_delay_days == 2
    assert cur.raw.bind_address == "0.0.0.0:8080"  # restart-only: kept
    assert cur.raw.upstreams.npm.enabled is True
    assert cur.generation == 1
    # a broken file keeps the previous config
    p.write_text("default_delay_days = [")
    os.utime(p, (2, 2))
    assert not holder.maybe_reload()
    assert holder.current.raw.default_delay_days == 2
    # file deleted
    p.unlink()
    assert not holder.maybe_reload()
    assert not C.ConfigHolder(C.load(None)).maybe_reload()


def test_restart_only_changes_detects_everything() -> None:
    a = C.parse("").raw
    b = C.parse(
        'bind_address = "1.2.3.4:1"\ndata_dir = "/x"\nworkers = 2\npublic_url = "https://p"\n'
        '[upstreams.pypi]\nenabled = false\nhostnames = ["h"]\n[upstreams.npm]\npublic_url = "https://n"\n'
        "[cache]\nartifacts_enabled = false\n"
    ).raw
    changed = C.restart_only_changes(a, b)
    assert {
        "bind_address",
        "data_dir",
        "workers",
        "public_url",
        "upstreams.pypi.enabled",
        "upstreams.pypi.hostnames",
        "upstreams.npm.public_url",
        "cache.artifacts_enabled",
    } <= set(changed)
