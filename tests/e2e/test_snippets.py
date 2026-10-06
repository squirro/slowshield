# ruff: noqa: S603, S607 - the e2e suite drives docker on purpose
"""Run the published client snippets (Setup page and slowshield.org) against the e2e stack.

Every shell snippet runs in a fresh home directory; a new shell must then send pip, npm and go through
SlowShield. The image's Debian 12 python3-venv brings pip 23.0.1, which also guards the PEP 714 crash
(pip 22.3-23.1 failed on every install through the JSON index before 0.0.3).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from slowshield.ui import snippets as S

if TYPE_CHECKING:
    from tests.e2e.conftest import Stack

pytestmark = pytest.mark.e2e

# Debian 12 (bash, apt for zsh/fish, python3-venv with pip 23.0.1, golang-go 1.19) plus npm.
IMAGE = "node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6"
PYPI, NPM, GO = "http://localhost:8080/pypi/simple/", "http://localhost:8080/npm/", "http://localhost:8080/go"

CHECKS = r"""
# Full path: a login shell (bash -l) resets PATH from /etc/profile.
/tmp/slowshield-try/bin/pip download -q --no-deps -d "/tmp/dl-$SHELLNAME" alpha >/dev/null && echo "OK $SHELLNAME pip"
[ "$(npm view left-pad-ng name 2>/dev/null)" = left-pad-ng ] && echo "OK $SHELLNAME npm"
# The fake checksum database is not signed by sum.golang.org's key: skip that check (SlowShield still verifies h1).
GOSUMDB=off GOFLAGS=-modcacherw GOMODCACHE="/tmp/gomod-$SHELLNAME" go mod download -json example.com/hello@v1.1.0 \
  2>/dev/null | grep -q '"Version": "v1.1.0"' && echo "OK $SHELLNAME go"
[ "$PIP_INDEX_URL" = "$WANT_PYPI" ] && [ "$UV_DEFAULT_INDEX" = "$WANT_PYPI" ] \
  && [ "$npm_config_registry" = "$WANT_NPM" ] && [ "$GOPROXY" = "$WANT_GO" ] && echo "OK $SHELLNAME env"
"""

RUNNER = r"""
set -u
apt-get update -qq >/dev/null && apt-get install -y -qq zsh fish python3-venv golang-go >/dev/null 2>&1 \
  || { echo "apt failed"; exit 1; }
cd /tmp
bash -e /s/try.python.sh >/tmp/try.log 2>&1 && /tmp/slowshield-try/bin/pip show -q alpha >/dev/null && echo "OK try pip"
/tmp/slowshield-try/bin/pip --version | cut -d' ' -f1-2
export WANT_PYPI=%(pypi)s WANT_NPM=%(npm)s WANT_GO=%(go)s
for sh in bash bash-macos zsh fish; do
  home=/home/$sh; mkdir -p "$home"
  case $sh in
    bash) HOME=$home bash /s/shell.$sh.sh && HOME=$home SHELLNAME=$sh bash -ic "$(cat /s/checks.sh)" 2>/dev/null ;;
    bash-macos) HOME=$home bash /s/shell.$sh.sh && HOME=$home SHELLNAME=$sh bash -lc "$(cat /s/checks.sh)" ;;
    zsh) HOME=$home zsh /s/shell.$sh.sh && HOME=$home SHELLNAME=$sh zsh -ic "$(cat /s/checks.sh)" ;;
    fish) HOME=$home fish /s/shell.$sh.sh && HOME=$home SHELLNAME=$sh fish -c "bash /s/checks.sh" ;;
  esac
done
"""


def test_published_snippets_work(stack: Stack, tmp_path: Path) -> None:
    s = S.load()
    (tmp_path / "try.python.sh").write_text(S.render(s.try_python, pypi=PYPI, npm=NPM, go=GO, py_pkg="alpha") + "\n")
    for sh in s.shells:
        (tmp_path / f"shell.{sh.id}.sh").write_text(S.render(sh.code, pypi=PYPI, npm=NPM, go=GO) + "\n")
    (tmp_path / "checks.sh").write_text(CHECKS)
    (tmp_path / "run.sh").write_text(RUNNER % {"pypi": PYPI, "npm": NPM, "go": GO})
    proxy = stack.container_id("slowshield")
    res = subprocess.run(
        ["docker", "run", "--rm", "--network", f"container:{proxy}", "-v", f"{tmp_path}:/s:ro", IMAGE,
         "bash", "/s/run.sh"],
        capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    out = res.stdout
    assert "pip 23.0.1" in out, out + res.stderr
    expected = ["OK try pip"] + [f"OK {sh.id} {check}" for sh in s.shells for check in ("pip", "npm", "go", "env")]
    missing = [line for line in expected if line not in out.splitlines()]
    assert not missing, f"{missing}\n--- stdout\n{out}\n--- stderr\n{res.stderr[-3000:]}"
