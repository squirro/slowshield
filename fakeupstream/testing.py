"""Run the fake registry in a subprocess on a free port (pytest helper)."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeUpstream:
    """`with FakeUpstream(now=...) as fake: fake.url` — a real HTTP server in a child process."""

    def __init__(self, *, now: float, seed: int = 1, perf: bool = False, port: int | None = None) -> None:
        self.now = now
        self.seed = seed
        self.perf = perf
        self.port = port or free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self._proc: subprocess.Popen[bytes] | None = None

    def start(self) -> FakeUpstream:
        root = Path(__file__).resolve().parents[1]
        env = {**os.environ, "PYTHONPATH": str(root) + os.pathsep + os.environ.get("PYTHONPATH", "")}
        cmd = [
            sys.executable,
            "-m",
            "fakeupstream",
            "--port",
            str(self.port),
            "--now",
            str(self.now),
            "--seed",
            str(self.seed),
        ]
        if self.perf:
            cmd.append("--perf")
        self._proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)  # noqa: S603
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                err = self._proc.stderr.read().decode() if self._proc.stderr else ""
                raise RuntimeError(f"fakeupstream exited early: {err}")
            try:
                with urllib.request.urlopen(self.url + "/healthz", timeout=1) as r:  # noqa: S310
                    if r.status == 200:
                        return self
            except OSError:
                time.sleep(0.05)
        self.stop()
        raise RuntimeError("fakeupstream did not start")

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def __enter__(self) -> FakeUpstream:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- control helpers --
    def control(self, action: str, body: Any = None, **params: Any) -> Any:
        url = f"{self.url}/_control/{action}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else b""
        method = "GET" if action in ("hits", "info") else "POST"
        req = urllib.request.Request(url, data=data if method == "POST" else None, method=method)  # noqa: S310
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310
            return json.loads(r.read() or b"null")

    def reset(self) -> None:
        self.control("reset")

    def hits(self, prefix: str = "") -> dict[str, int]:
        return self.control("hits", prefix=prefix)

    def info(self) -> dict[str, Any]:
        return self.control("info")
