"""Tests for installed package metadata."""
from __future__ import annotations

from importlib.metadata import version
import subprocess
import sys

import wazuhtester


def test_package_version_matches_distribution_metadata() -> None:
    assert wazuhtester.__version__ == version("wazuhtester")


def test_import_rejects_non_linux_platform() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.platform = 'win32'; import wazuhtester",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "wazuhtester supports Linux only" in result.stderr
