"""Fixtures for the integration tests with UI sign-in on (against the fake IdP in fakeupstream/oidc.py)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fakeupstream.oidc import CLIENT_SECRET

from tests.conftest import Running


@pytest.fixture
def secret_file(tmp_path: Path) -> Path:
    path = tmp_path / "client_secret"
    path.write_text(CLIENT_SECRET + "\n")
    return path


@pytest.fixture
def start_auth(start_app: Callable[..., Any], upstream: Any, secret_file: Path) -> Callable[..., Any]:
    """An instance with UI sign-in on; keyword arguments go into its [auth] table (`oidc_*` into [auth.oidc])."""
    from tests.integration.test_auth import auth_toml

    async def start(**extra: Any) -> Running:
        data_dir = extra.pop("data_dir", None)
        return await start_app(auth_toml(upstream.url, secret_file, **extra), scheme="https", data_dir=data_dir)

    return start
