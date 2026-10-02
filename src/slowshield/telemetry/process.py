"""Process/runtime metrics read from /proc (no psutil), with a portable fallback for local dev."""

from __future__ import annotations

import asyncio
import gc
import os
import resource
import sys
import threading
import time

from slowshield.telemetry import instruments

_PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
_TICKS = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100


def rss_bytes() -> int:
    try:
        with open("/proc/self/statm", "rb") as f:
            return int(f.read().split()[1]) * _PAGE
    except OSError:
        ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return ru if sys.platform == "darwin" else ru * 1024


def cpu_seconds() -> tuple[float, float]:
    try:
        with open("/proc/self/stat", "rb") as f:
            fields = f.read().rsplit(b")", 1)[1].split()
        return int(fields[11]) / _TICKS, int(fields[12]) / _TICKS
    except OSError:
        ru = resource.getrusage(resource.RUSAGE_SELF)
        return ru.ru_utime, ru.ru_stime


def open_fds() -> int:
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return 0


def register() -> None:
    instruments.observe(
        "process.memory.usage", lambda: [(rss_bytes(), {})], unit="By", description="Resident set size."
    )

    def _cpu() -> list[tuple[float, dict[str, str | int | float | bool]]]:
        user, system = cpu_seconds()
        return [(user, {"cpu.mode": "user"}), (system, {"cpu.mode": "system"})]

    instruments.observe("process.cpu.time", _cpu, unit="s", description="CPU time consumed by the process.")
    instruments.observe("process.open_file_descriptor.count", lambda: [(open_fds(), {})], unit="{fd}")
    instruments.observe("process.thread.count", lambda: [(threading.active_count(), {})], unit="{thread}")
    instruments.observe(
        "python.gc.objects", lambda: [(float(sum(gc.get_count())), {})], unit="{object}", description="GC gen counts."
    )


async def eventloop_lag_monitor(interval: float = 0.5) -> None:
    """Measures how late the loop wakes us up; persistent lag means blocking work on the loop."""
    while True:
        start = time.perf_counter()
        await asyncio.sleep(interval)
        lag = time.perf_counter() - start - interval
        instruments.eventloop_lag.record(max(0.0, lag))
