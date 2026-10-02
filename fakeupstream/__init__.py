"""Deterministic fake PyPI / npm / OSV / GitHub registry for SlowShield tests, e2e runs and perf runs.

    uv run python -m fakeupstream --port 9000 --now 1790000000 [--perf]

Base paths: /pypi/simple/, /files/packages/, /npm/, /osv/<PyPI|npm>/, /github/advisories,
control hooks under /_control/ (see fakeupstream.app).
"""

from fakeupstream.app import create_app
from fakeupstream.catalog import Catalog
from fakeupstream.testing import FakeUpstream

__all__ = ["Catalog", "FakeUpstream", "create_app"]
