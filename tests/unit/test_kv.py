"""The shared SQLite metadata store and the container memory check."""

from __future__ import annotations

from pathlib import Path

from slowshield import limits
from slowshield.cache.kv import TOUCH_EVERY, KVStore


class Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def store(tmp_path: Path, clock: Clock, max_bytes: int = 1 << 20) -> KVStore:
    s = KVStore(tmp_path / "metadata-cache.db", max_bytes, clock)
    s.open()
    return s


def test_put_get_fresh_and_stale(tmp_path: Path) -> None:
    clock = Clock()
    s = store(tmp_path, clock)
    s.put("npm:doc:a", b"body", expires=1100, keep_until=2000, meta={"etag": '"1"'})
    item = s.get("npm:doc:a")
    assert item is not None and item.value == b"body" and item.meta == {"etag": '"1"'}
    assert item.fresh(1050) and not item.fresh(1100)
    assert s.get("missing") is None


def test_shared_between_instances(tmp_path: Path) -> None:
    """Two workers open the same file: what one stores, the other reads."""
    clock = Clock()
    a, b = store(tmp_path, clock), store(tmp_path, clock)
    a.put("k", b"v" * 1000, expires=2000)
    item = b.get("k")
    assert item is not None and item.value == b"v" * 1000


def test_touch_extends_and_reads_rarely_write(tmp_path: Path) -> None:
    clock = Clock()
    s = store(tmp_path, clock)
    s.put("k", b"v", expires=1100)
    s.touch("k", 5000)
    item = s.get("k")
    assert item is not None and item.expires == 5000
    conn = s._conn()
    (accessed,) = conn.execute("SELECT accessed FROM kv WHERE key = 'k'").fetchone()
    clock.t += TOUCH_EVERY / 2
    s.get("k")
    assert conn.execute("SELECT accessed FROM kv WHERE key = 'k'").fetchone()[0] == accessed
    clock.t += TOUCH_EVERY
    s.get("k")
    assert conn.execute("SELECT accessed FROM kv WHERE key = 'k'").fetchone()[0] == clock.t


def test_evict_purges_past_keep_then_least_recently_used(tmp_path: Path) -> None:
    clock = Clock()
    s = store(tmp_path, clock, max_bytes=10_000)
    s.put("old-body", b"x" * 100, expires=1001)  # keep_until = expires
    for i in range(12):
        clock.t += TOUCH_EVERY + 1
        s.put(f"doc{i}", b"y" * 1000, expires=clock.t + 10_000)
    s.get("doc0")  # recently used again: survives
    clock.t += 1
    removed = s.evict()
    _, size = s.usage()
    assert removed >= 4 and size <= 10_000 * 0.9
    assert s.get("old-body") is None
    assert s.get("doc0") is not None
    assert s.get("doc1") is None and s.get("doc11") is not None


def test_corrupt_file_is_recreated(tmp_path: Path) -> None:
    path = tmp_path / "metadata-cache.db"
    path.write_bytes(b"this is not a database" * 100)
    s = KVStore(path, 1 << 20, Clock())
    s.open()
    s.put("k", b"v", expires=2000)
    assert s.get("k") is not None


def test_cgroup_memory_limit(tmp_path: Path) -> None:
    assert limits.cgroup_memory_limit(tmp_path) is None
    (tmp_path / "memory.max").write_text("max\n")
    assert limits.cgroup_memory_limit(tmp_path) is None
    (tmp_path / "memory.max").write_text("1073741824\n")
    assert limits.cgroup_memory_limit(tmp_path) == 1 << 30
    (tmp_path / "memory.max").unlink()
    (tmp_path / "memory").mkdir()
    (tmp_path / "memory" / "memory.limit_in_bytes").write_text(str(1 << 62))
    assert limits.cgroup_memory_limit(tmp_path) is None


def test_memory_warning() -> None:
    gib = 1 << 30
    assert limits.memory_warning(2, 64, None) is None
    assert limits.memory_warning(2, 64, gib) is None  # 464 MiB of 1024
    assert limits.memory_warning(2, 64, gib * 6 // 10) is None  # 464 MiB fit in 80 % of 614
    assert limits.memory_warning(2, 64, gib // 2) is not None  # but not in 80 % of 512
    warning = limits.memory_warning(8, 256, gib)
    assert warning is not None and "8 worker(s)" in warning and "1024 MiB" in warning
