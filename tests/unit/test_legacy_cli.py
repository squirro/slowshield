"""Legacy (Rust) database import and the command line."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from slowshield import cli
from slowshield.db import connect, migrate
from slowshield.legacy import LEGACY_DIGEST, import_legacy

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "rust_schema.sql"
WHEEL_PATH = "/packages/42/d7/" + "a" * 60 + "/markdown_it_py-3.0.0-py3-none-any.whl"


def make_rust_db(path: Path) -> Path:
    conn = sqlite3.connect(path)
    conn.executescript(FIXTURE.read_text())
    sha = "b" * 64
    conn.executemany(
        "INSERT INTO artifact_checksums (ecosystem, artifact_path, sha256, first_seen_at) VALUES (?, ?, ?, ?)",
        [
            ("pypi", WHEEL_PATH, sha, "2026-04-01T10:00:00Z"),
            ("npm", "/@babel/core/-/core-7.24.0.tgz", "c" * 64, "2026-04-02T10:00:00Z"),
            ("npm", "/lodash/-/lodash-4.17.21.tgz", "d" * 64, "2026-04-02T10:00:00Z"),
            ("yum", "/centos/x.rpm", sha, "2026-04-01T10:00:00Z"),  # not ported
            ("secondary", "/whatever", sha, "2026-04-01T10:00:00Z"),
            ("pypi", "/packages/bad", sha, "2026-04-01T10:00:00Z"),
            ("pypi", WHEEL_PATH.replace("markdown", "x"), "short", "2026-04-01T10:00:00Z"),
        ],
    )
    conn.executemany(
        "INSERT INTO blocked_packages (ecosystem, package, version, source, advisory_id, reason, blocked_since) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            ("pypi", "Evil_Pkg", None, "osv", "MAL-2026-1", "malware", "2026-04-01T00:00:00Z"),
            ("npm", "axios", "1.14.1", "github_advisory", "GHSA-xxxx", "compromised", "2026-04-15T00:00:00Z"),
            ("npm", "x", None, "phylum", None, None, "2026-04-15T00:00:00Z"),
            ("yum", "y", None, "osv", "MAL-2", None, "2026-04-15T00:00:00Z"),
        ],
    )
    conn.execute(
        "INSERT INTO block_events (ecosystem, package, version, advisory_id, source, blocked_at, client_ip) "
        "VALUES ('pypi', 'evil_pkg', NULL, 'MAL-2026-1', 'osv', '2026-04-03T08:00:00Z', NULL)"
    )
    conn.execute(
        "INSERT INTO tamper_events (ecosystem, artifact_path, stored_sha256, observed_sha256, detected_at) "
        "VALUES ('pypi', ?, 'b', 'c', '2026-04-04T00:00:00Z')",
        (WHEEL_PATH,),
    )
    conn.execute(
        "INSERT INTO tamper_events (ecosystem, artifact_path, stored_sha256, observed_sha256) "
        "VALUES ('yum', '/x', 'a', 'b')"
    )
    for _ in range(3):
        conn.execute(
            "INSERT INTO age_block_events (ecosystem, package, version, delay_days_required, days_old, blocked_at) "
            "VALUES ('npm', 'react', '19.0.0', 7, 1.5, '2026-04-05T01:00:00Z')"
        )
    conn.execute(
        "INSERT INTO fail_open_events (ecosystem, package, version, reason, served_at) "
        "VALUES ('pypi', 'Brand_New', '0.1', 'all_versions_too_new', '2026-04-06T00:00:00Z')"
    )
    conn.executemany(
        "INSERT INTO serve_log (ecosystem, package, version, serves, cached_serves, bytes_served, last_served_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            ("pypi", "Markdown_It_Py", "3.0.0", 10, 4, 1000, "2026-04-07T00:00:00Z"),
            ("pypi", "markdown-it-py", "2.0.0", 5, 0, 500, "2026-04-08T00:00:00Z"),
            ("homebrew", "wget", "1", 1, 0, 1, "2026-04-08T00:00:00Z"),
        ],
    )
    conn.execute(
        "INSERT INTO package_metadata (ecosystem, package, version, release_time) VALUES "
        "('pypi', 'markdown-it-py', '3.0.0', '2023-06-03T06:00:00Z')"
    )
    conn.commit()
    conn.close()
    return path


def test_import_legacy(tmp_path: Path) -> None:
    src = make_rust_db(tmp_path / "mirror.db")
    target = tmp_path / "new.db"
    migrate(target)
    dry = import_legacy(src, target, dry_run=True)
    assert dry["dry_run"] and dry["artifacts"] == {"imported": 3, "skipped": 4}
    report = import_legacy(src, target)
    assert report["blocklist"] == 3 and report["events"] == 6 and report["serve_log"] == 2
    conn = connect(target)
    arts = conn.execute(
        "SELECT ecosystem, package, version, sha256, upstream_digest FROM artifacts ORDER BY path"
    ).fetchall()
    assert ("npm", "@babel/core", "7.24.0", "c" * 64, LEGACY_DIGEST) in arts
    assert ("pypi", "markdown-it-py", "3.0.0", "b" * 64, LEGACY_DIGEST) in arts
    blocks = conn.execute("SELECT ecosystem, name, version, source, url FROM blocklist ORDER BY name").fetchall()
    assert ("pypi", "evil-pkg", None, "osv", "https://osv.dev/vulnerability/MAL-2026-1") in blocks
    assert ("npm", "axios", "1.14.1", "github", "https://github.com/advisories/GHSA-xxxx") in blocks
    assert ("npm", "x", None, "phylum", None) in blocks
    events = dict(conn.execute("SELECT type, sum(count) FROM events GROUP BY type").fetchall())
    assert events == {"blocked": 1, "tampered": 1, "age_gate": 3, "fail_open": 1}
    pkg = conn.execute("SELECT serves, cache_hits, bytes FROM packages WHERE name = 'markdown-it-py'").fetchone()
    assert tuple(pkg) == (15, 4, 1500)
    ver = conn.execute(
        "SELECT published, serves FROM package_versions WHERE name = 'markdown-it-py' AND version = '3.0.0'"
    ).fetchone()
    assert ver[0] is not None and ver[1] == 10
    assert conn.execute("SELECT value FROM meta WHERE key = 'blocklist_generation'").fetchone()[0] == "1"
    conn.close()
    # importing twice does not duplicate artifacts/blocks
    import_legacy(src, target)
    conn = connect(target)
    assert conn.execute("SELECT count(*) FROM artifacts").fetchone()[0] == 3
    assert conn.execute("SELECT count(*) FROM blocklist").fetchone()[0] == 3
    conn.close()


def test_import_legacy_missing_source(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        import_legacy(tmp_path / "nope.db", tmp_path / "new.db")


def test_import_legacy_tolerates_partial_schema(tmp_path: Path) -> None:
    src = tmp_path / "old.db"
    sqlite3.connect(src).execute("CREATE TABLE unrelated (x)").connection.close()
    target = tmp_path / "new.db"
    migrate(target)
    assert import_legacy(src, target) == {"source": str(src), "dry_run": False, "events": 0}


# ---- CLI ---------------------------------------------------------------------------------------


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["version"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert set(info) == {"version", "git_sha", "python", "gil"}


def test_cli_check_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = tmp_path / "ok.toml"
    good.write_text('mode = "primary"\n')
    assert cli.main(["check-config", "--config", str(good)]) == 0
    out = capsys.readouterr()
    assert "ok:" in out.out and "mode" in out.err
    bad = tmp_path / "bad.toml"
    bad.write_text("default_delay_days = -3\n")
    assert cli.main(["check-config", "--config", str(bad)]) == 2


def test_cli_migrate_and_import(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'data_dir = "{tmp_path / "data"}"\n')
    assert cli.main(["migrate", "--config", str(cfg)]) == 0
    assert "schema version 4" in capsys.readouterr().out
    src = make_rust_db(tmp_path / "mirror.db")
    assert cli.main(["import-legacy", str(src), "--config", str(cfg), "--dry-run"]) == 0
    assert '"dry_run": true' in capsys.readouterr().out


def test_cli_healthcheck(fake, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    assert cli.main(["healthcheck", "--url", f"{fake.url}/healthz"]) == 0
    assert cli.main(["healthcheck", "--url", "http://127.0.0.1:9/readyz", "--timeout", "0.5"]) == 1
    assert "unhealthy" in capsys.readouterr().err
    monkeypatch.setenv("SLOWSHIELD_BIND", f"127.0.0.1:{fake.port}")
    assert cli._port() == str(fake.port)
    monkeypatch.delenv("SLOWSHIELD_BIND")
    assert cli._port() == "8080"


def test_cli_loads_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("SLOWSHIELD_TEST_DOTENV=yes\n")
    cli._load_dotenv()
    import os

    assert os.environ.get("SLOWSHIELD_TEST_DOTENV") == "yes"
    monkeypatch.delenv("SLOWSHIELD_TEST_DOTENV")
