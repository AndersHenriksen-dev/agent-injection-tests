"""Shared fixtures: the case files, loaded once per test session."""

from __future__ import annotations

import pytest

from injectiontests.cases import Cases, load


@pytest.fixture(scope="session")
def cases() -> Cases:
    return load()
