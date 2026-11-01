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


def test_host_aliases_reach_the_pod() -> None:
    # A follower whose leader only resolves on a tailnet maps the leader's name to an in-cluster egress proxy.
    r = _render("hostAliases[0].ip=172.20.31.7", "hostAliases[0].hostnames[0]=slowshield.example.com")
    assert r.returncode == 0, r.stderr
    assert "hostAliases:" in r.stdout and "ip: 172.20.31.7" in r.stdout and "- slowshield.example.com" in r.stdout
    assert "hostAliases" not in _render().stdout


def test_ui_sign_in() -> None:
    assert "SLOWSHIELD_AUTH" not in _render().stdout  # off by default
    oidc = ("auth.mode=oidc", "auth.oidc.issuer=https://idp.example/realms/r", "auth.oidc.clientId=slowshield")
    r = _render(*oidc)
    assert r.returncode != 0 and "clientKeySecret or auth.oidc.clientSecretSecret" in r.stderr
    both = ("auth.oidc.clientKeySecret=k", "auth.oidc.clientSecretSecret=s")
    assert _render(*oidc, *both).returncode != 0
    r = _render(*oidc, "auth.oidc.clientKeySecret=slowshield-oidc", "auth.requireLogin=true",
                "auth.oidc.adminValues[0]=SlowShield Admins", "auth.oidc.adminValues[1]=Ops")  # fmt: skip
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert "SLOWSHIELD_OIDC_CLIENT_KEY_FILE" in out and "value: /run/secrets/oidc/key.pem" in out
    assert 'value: "SlowShield Admins,Ops"' in out and "secretName: slowshield-oidc" in out
    assert "SLOWSHIELD_OIDC_CLIENT_SECRET_FILE" not in out
    r = _render(*oidc, "auth.oidc.clientSecretSecret=slowshield-oidc")
    assert "value: /run/secrets/oidc/secret" in r.stdout


def test_password_sign_in() -> None:
    r = _render("auth.mode=password", "auth.username=admin")
    assert r.returncode != 0 and "auth.passwordHashSecret" in r.stderr
    r = _render("auth.mode=password", "auth.username=admin", "auth.passwordHashSecret=slowshield-password")
    assert r.returncode == 0, r.stderr
    assert "SLOWSHIELD_AUTH_PASSWORD_HASH" in r.stdout and "name: slowshield-password" in r.stdout
    assert "SLOWSHIELD_OIDC_ISSUER" not in r.stdout and "/run/secrets/oidc" not in r.stdout
