"""Per-worker application context shared by the ecosystems, feeds and UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from slowshield.blocklist import Blocklist
from slowshield.cache.artifacts import ArtifactCache
from slowshield.cache.metadata import LRUCache
from slowshield.clock import Clock
from slowshield.config import ConfigHolder, LoadedConfig
from slowshield.db import Database
from slowshield.recorder import Recorder
from slowshield.upstream import Upstream

if TYPE_CHECKING:
    from slowshield.ecosystems.artifacts import ArtifactServer
    from slowshield.feeds import FeedStatus


@dataclass(slots=True)
class AppContext:
    config: ConfigHolder
    clock: Clock
    db: Database
    blocklist: Blocklist
    upstream: Upstream
    recorder: Recorder
    artifact_cache: ArtifactCache
    artifacts: ArtifactServer
    metadata_cache: LRUCache[Any]
    feeds: dict[str, FeedStatus] = field(default_factory=dict)
    is_leader: bool = False
    started_at: float = 0.0

    @property
    def cfg(self) -> LoadedConfig:
        return self.config.current

    def policy_key(self) -> tuple[int, str]:
        """Changes whenever the policy inputs change (config reload or blocklist update)."""
        return (self.config.current.generation, self.blocklist.generation)
