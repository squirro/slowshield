"""`slowshield` command line: serve, healthcheck, migrate, import-legacy, version, check-config."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def _load_dotenv() -> None:
    """Local development convenience: read `.env` from the working directory if present."""
    if Path(".env").is_file():
        from dotenv import load_dotenv

        load_dotenv(".env", override=False)


def cmd_serve(args: argparse.Namespace) -> int:
    from granian.constants import HTTPModes, Interfaces, Loops
    from granian.server import Server

    from slowshield import config as config_mod
    from slowshield import limits
    from slowshield.db import migrate
    from slowshield.telemetry import logsetup

    logsetup.configure()
    if args.config:
        os.environ["SLOWSHIELD_CONFIG"] = args.config
    if args.workers:
        os.environ["SLOWSHIELD_WORKERS"] = str(args.workers)  # workers size their share of the memory budget
    cfg = config_mod.load()
    for w in cfg.warnings:
        print(f"warning: {w}", file=sys.stderr)
    memory = limits.memory_warning(cfg.raw.workers, cfg.raw.cache.metadata_memory_mb, limits.cgroup_memory_limit())
    if memory:
        print(f"warning: {memory}", file=sys.stderr)
    # Migrate once in the parent so workers start against the final schema.
    migrate(cfg.db_path)
    bind = args.bind or cfg.raw.bind_address
    host, _, port = bind.rpartition(":")
    workers = cfg.raw.workers
    server = Server(
        "slowshield.app:create_app",
        address=host.strip("[]"),
        port=int(port),
        interface=Interfaces.ASGI,
        factory=True,
        workers=workers,
        loop=Loops.uvloop,
        http=HTTPModes.auto,
        websockets=False,
        backlog=2048,
        log_enabled=True,
        log_access=os.environ.get("SLOWSHIELD_ACCESS_LOG") == "1",
        respawn_failed_workers=True,
        workers_kill_timeout=30,
    )
    server.serve()
    return 0


def cmd_healthcheck(args: argparse.Namespace) -> int:
    url = args.url or f"http://127.0.0.1:{_port()}/readyz"
    if not url.startswith(("http://", "https://")):  # urlopen would also read file:// and ftp:// URLs
        print(f"unhealthy: --url must be http(s), got {url!r}", file=sys.stderr)
        return 2
    try:
        with urllib.request.urlopen(url, timeout=args.timeout) as resp:  # noqa: S310 - http(s) checked above
            ok = resp.status == 200
    except (urllib.error.URLError, OSError) as exc:
        print(f"unhealthy: {exc}", file=sys.stderr)
        return 1
    return 0 if ok else 1


def _port() -> str:
    bind = os.environ.get("SLOWSHIELD_BIND", "")
    if bind:
        return bind.rpartition(":")[2]
    try:
        from slowshield import config as config_mod

        return config_mod.load().raw.bind_address.rpartition(":")[2]
    except Exception:
        return "8080"


def cmd_migrate(args: argparse.Namespace) -> int:
    from slowshield import config as config_mod
    from slowshield.db import migrate

    cfg = config_mod.load(Path(args.config) if args.config else None)
    version = migrate(cfg.db_path)
    print(f"schema version {version} at {cfg.db_path}")
    return 0


def cmd_import_legacy(args: argparse.Namespace) -> int:
    from slowshield import config as config_mod
    from slowshield.db import migrate
    from slowshield.legacy import import_legacy

    cfg = config_mod.load(Path(args.config) if args.config else None)
    migrate(cfg.db_path)
    report = import_legacy(Path(args.source), cfg.db_path, dry_run=args.dry_run)
    print(json.dumps(report, indent=2))
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    from slowshield import build_info

    print(json.dumps(build_info()))
    return 0


def cmd_check_config(args: argparse.Namespace) -> int:
    from slowshield import config as config_mod

    try:
        cfg = config_mod.load(Path(args.config) if args.config else None)
    except config_mod.ConfigError as exc:
        print(f"invalid configuration: {exc}", file=sys.stderr)
        return 2
    for w in cfg.warnings:
        print(f"warning: {w}", file=sys.stderr)
    print(f"ok: {cfg.path or 'defaults'}; github token: {cfg.github_token_status.source}")
    return 0


def main(argv: list[str] | None = None) -> int:
    _load_dotenv()
    parser = argparse.ArgumentParser(prog="slowshield", description="Supply-chain defence proxy for PyPI and npm.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", help="run the proxy")
    p.add_argument("--config", help="path to config.toml (default: $SLOWSHIELD_CONFIG)")
    p.add_argument("--bind", help="host:port to listen on (default from config)")
    p.add_argument("--workers", type=int, help="worker processes (threads on free-threaded Python)")
    p.set_defaults(fn=cmd_serve)

    p = sub.add_parser("healthcheck", help="exit 0 if the local instance is ready")
    p.add_argument("--url", help="URL to probe (default http://127.0.0.1:<port>/readyz)")
    p.add_argument("--timeout", type=float, default=3.0)
    p.set_defaults(fn=cmd_healthcheck)

    p = sub.add_parser("migrate", help="create/upgrade the database schema")
    p.add_argument("--config")
    p.set_defaults(fn=cmd_migrate)

    p = sub.add_parser("import-legacy", help="import a database from the Rust SlowShield")
    p.add_argument("source", help="path to the old mirror.db")
    p.add_argument("--config")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_import_legacy)

    p = sub.add_parser("check-config", help="validate configuration and exit")
    p.add_argument("--config")
    p.set_defaults(fn=cmd_check_config)

    p = sub.add_parser("version", help="print version information")
    p.set_defaults(fn=cmd_version)

    args = parser.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
