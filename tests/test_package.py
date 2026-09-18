"""Tests for installed package metadata."""
from __future__ import annotations

from importlib.metadata import version

import wazuhtester


def test_package_version_matches_distribution_metadata() -> None:
    assert wazuhtester.__version__ == version("wazuhtester")
