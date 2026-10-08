"""The Helm chart's own checks, rendered with `helm template` (skipped where helm isn't installed)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

CHART = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "slowshield"
HELM = shutil.which("helm")

pytestmark = pytest.mark.skipif(HELM is None, reason="helm is not installed")


def _render(*values: str) -> subprocess.CompletedProcess[str]:
    argv = [str(HELM), "template", "t", str(CHART)]
    for v in values:
        argv += ["--set", v]
    return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=60)  # noqa: S603 - fixed argv


def test_a_follower_must_say_how_it_trusts_its_leader() -> None:
    # The chart's default TLS is Caddy's private CA: a follower without that CA (or a public leader) can't sync.
    r = _render("shieldwall.joinSecret=slowshield-join")
    assert r.returncode != 0
    assert "shieldwall.leaderCaSecret" in r.stderr and "shieldwall.leaderPubliclyTrusted" in r.stderr
    r = _render("shieldwall.joinSecret=slowshield-join", "shieldwall.leaderCaSecret=slowshield-leader-ca")
    assert r.returncode == 0, r.stderr
    assert "SLOWSHIELD_LEADER_CA_FILE" in r.stdout and "secretName: slowshield-leader-ca" in r.stdout
    r = _render("shieldwall.joinSecret=slowshield-join", "shieldwall.leaderPubliclyTrusted=true")
    assert r.returncode == 0, r.stderr
    assert "SLOWSHIELD_JOIN" in r.stdout and "SLOWSHIELD_LEADER_CA_FILE" not in r.stdout
    # Not a follower: nothing to trust.
    assert _render().returncode == 0
    assert _render("shieldwall.role=leader").returncode == 0
