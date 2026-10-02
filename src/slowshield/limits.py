"""The container's memory limit versus what the configuration needs (cgroup v2, then v1)."""

from __future__ import annotations

from pathlib import Path

# Per worker without the metadata cache: interpreter and libraries, SQLite connections (page caches of the
# per-thread readers and the writer), request buffers and in-flight bodies under load.
PER_WORKER_MB = 200
HEADROOM = 0.8  # warn when the estimate exceeds this share of the limit


def cgroup_memory_limit(root: Path = Path("/sys/fs/cgroup")) -> int | None:
    """The memory limit in bytes, or None when there is none (or it cannot be read)."""
    for path in (root / "memory.max", root / "memory" / "memory.limit_in_bytes"):
        try:
            text = path.read_text(encoding="ascii").strip()
        except OSError:
            continue
        if text == "max":
            return None
        try:
            value = int(text)
        except ValueError:
            continue
        return None if value >= 1 << 60 else value  # cgroup v1 reports "unlimited" as a huge number
    return None


def memory_warning(workers: int, metadata_memory_mb: float, limit: int | None) -> str | None:
    """A warning when `workers` and the in-memory metadata budget do not fit the limit with headroom."""
    if limit is None:
        return None
    need_mb = workers * PER_WORKER_MB + metadata_memory_mb
    limit_mb = limit / (1 << 20)
    if need_mb <= limit_mb * HEADROOM:
        return None
    return (
        f"{workers} worker(s) need about {need_mb:.0f} MiB ({PER_WORKER_MB} MiB each plus "
        f"cache.metadata_memory_mb = {metadata_memory_mb:g}), but the memory limit is {limit_mb:.0f} MiB: "
        "lower workers or cache.metadata_memory_mb, or raise the limit"
    )
