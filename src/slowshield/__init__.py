"""SlowShield: supply-chain defence proxy for PyPI, npm and Go modules."""

from __future__ import annotations

import os
from importlib import metadata

__all__ = ["__version__", "build_info"]


def _version() -> str:
    env = os.environ.get("SLOWSHIELD_VERSION", "").strip()
    if env:
        return env
    try:
        return metadata.version("slowshield")
    except metadata.PackageNotFoundError:  # pragma: no cover - only in odd source checkouts
        return "0.0.0+unknown"


__version__ = _version()


def build_info() -> dict[str, str]:
    """Version, git commit and interpreter flavour, as shown in the UI footer and `slowshield version`."""
    import sys

    gil = getattr(sys, "_is_gil_enabled", lambda: True)()
    return {
        "version": __version__,
        "git_sha": os.environ.get("SLOWSHIELD_GIT_SHA", "unknown").strip() or "unknown",
        "python": sys.version.split()[0],
        "gil": "enabled" if gil else "disabled",
    }
