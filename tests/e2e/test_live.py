"""Live checks against the real registries (nightly: `pytest -m live tests/e2e`).

SlowShield's Go publish times rest on behaviour proxy.golang.org does not document: the `Last-Modified` of a
version's .mod is when the mirror first stored it (docs/design/go.md). This compares it with index.golang.org,
which publishes exactly that time, for one recent version: two requests a night.
"""

from __future__ import annotations

import email.utils
import json
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta

import pytest

pytestmark = pytest.mark.live

UA = {"User-Agent": "slowshield-nightly (+https://github.com/squirro/slowshield)"}


def _escape(value: str) -> str:
    return "".join("!" + c.lower() if "A" <= c <= "Z" else c for c in value)


def test_go_last_modified_is_when_the_mirror_stored_the_version() -> None:
    since = (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    req = urllib.request.Request(f"https://index.golang.org/index?since={since}&limit=1", headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        entry = json.loads(r.read().splitlines()[0])
    stored = datetime.fromisoformat(entry["Timestamp"].replace("Z", "+00:00"))
    path = urllib.parse.quote(f"{_escape(entry['Path'])}/@v/{_escape(entry['Version'])}.mod")
    head = urllib.request.Request(
        f"https://proxy.golang.org/{path}", method="HEAD", headers={**UA, "Disable-Module-Fetch": "true"}
    )
    with urllib.request.urlopen(head, timeout=30) as r:
        last_modified = email.utils.parsedate_to_datetime(r.headers["Last-Modified"])
    # Last-Modified has whole seconds; the index has microseconds.
    assert abs((last_modified - stored).total_seconds()) < 5, (entry, r.headers["Last-Modified"])
