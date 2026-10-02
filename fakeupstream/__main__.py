"""CLI: run the fake registry with Granian."""

from __future__ import annotations

import argparse
import os
import time


def main() -> None:
    p = argparse.ArgumentParser(prog="fakeupstream")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--now", type=float, default=None, help="reference UNIX time (default: process start)")
    p.add_argument("--perf", action="store_true", help="add large perf fixtures (100 MB wheel, 5000-version packument)")
    p.add_argument("--workers", type=int, default=1)
    args = p.parse_args()
    os.environ["FAKEUPSTREAM_NOW"] = str(args.now if args.now is not None else time.time())
    os.environ["FAKEUPSTREAM_SEED"] = str(args.seed)
    os.environ["FAKEUPSTREAM_PERF"] = "1" if args.perf else "0"

    from granian.constants import Interfaces, Loops
    from granian.server import Server

    Server(
        "fakeupstream.__main__:factory",
        address=args.host,
        port=args.port,
        interface=Interfaces.ASGI,
        factory=True,
        workers=args.workers,
        loop=Loops.uvloop,
        websockets=False,
        log_access=False,
    ).serve()


def factory():
    from fakeupstream.app import create_app

    return create_app(
        now=float(os.environ["FAKEUPSTREAM_NOW"]),
        seed=int(os.environ.get("FAKEUPSTREAM_SEED", "1")),
        perf=os.environ.get("FAKEUPSTREAM_PERF") == "1",
    )


if __name__ == "__main__":
    main()
