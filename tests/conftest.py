"""Shared fixtures: fake clock, random token key, service factory."""

from __future__ import annotations

import os

import pytest

from helpers import FakeClock, make_service

# Re-exported for test modules that import them from helpers; fixtures live here.


@pytest.fixture()
def token_key() -> bytes:
    return os.urandom(32)


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def service(tmp_path, token_key, clock):
    return make_service(tmp_path / "proposals.db", token_key=token_key, clock=clock)
