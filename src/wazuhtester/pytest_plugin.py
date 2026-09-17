"""pytest plugin: Wazuh logtest availability checks and fixtures.

Registered on the `pytest11` entry point, so installing `wazuhtester`
is enough for pytest to pick it up automatically — no `-p` flag needed.

Deliberately opt-in on the availability check: a project that merely
depends on wazuhtester (this package's own test suite included) must not
have every `pytest` invocation hard-fail just because no Wazuh daemon is
reachable. `--wazuh-require-logtest` (or the `wazuh_require_logtest` ini
option) turns on the old wazuh-devenv `tester.py` behaviour of treating a
missing daemon as fatal; otherwise, only tests marked
`@pytest.mark.wazuh_logtest` are skipped when the daemon is unavailable.
"""
from __future__ import annotations

import os
from collections.abc import Callable, Generator
from typing import TYPE_CHECKING

import pytest

from wazuhtester.api import send_log as _send_log
from wazuhtester.config import get_socket_path
from wazuhtester.protocol import is_logtest_available
from wazuhtester.response import LogtestResponse
from wazuhtester.session import LogtestSession

if TYPE_CHECKING:
    from _pytest.config import Config
    from _pytest.config.argparsing import Parser

MARKER_NAME = "wazuh_logtest"


def pytest_addoption(parser: Parser) -> None:
    group = parser.getgroup("wazuhtester")
    group.addoption(
        "--wazuh-socket",
        action="store",
        default=None,
        help="Path to the Wazuh logtest socket (overrides WAZUH_LOGTEST_SOCKET).",
    )
    group.addoption(
        "--wazuh-require-logtest",
        action="store_true",
        default=False,
        help=(
            "Fail the whole session immediately if the Wazuh logtest daemon "
            "is unreachable, instead of only skipping tests marked "
            "'wazuh_logtest'. Also settable via the 'wazuh_require_logtest' "
            "ini option."
        ),
    )
    parser.addini(
        "wazuh_require_logtest",
        help="Same as --wazuh-require-logtest, set from pyproject.toml/pytest.ini.",
        type="bool",
        default=False,
    )


def pytest_configure(config: Config) -> None:
    config.addinivalue_line(
        "markers",
        f"{MARKER_NAME}: mark test as requiring a live Wazuh logtest daemon",
    )
    socket_path = config.getoption("--wazuh-socket")
    if socket_path:
        os.environ["WAZUH_LOGTEST_SOCKET"] = socket_path


def _require_logtest(config: Config) -> bool:
    return bool(config.getoption("--wazuh-require-logtest") or config.getini("wazuh_require_logtest"))


def pytest_collection_modifyitems(config: Config, items: list[pytest.Item]) -> None:
    if config.option.collectonly:
        return

    require = _require_logtest(config)
    has_marked = any(item.get_closest_marker(MARKER_NAME) for item in items)
    if not (require or has_marked):
        return

    if is_logtest_available():
        return

    socket_path = get_socket_path()
    message = (
        f"Wazuh logtest daemon unreachable at {socket_path}. "
        "Start wazuh-manager (see install.sh) or point WAZUH_LOGTEST_SOCKET "
        "at a running instance."
    )
    if require:
        pytest.exit(message, returncode=1)

    skip_marker = pytest.mark.skip(reason=message)
    for item in items:
        if item.get_closest_marker(MARKER_NAME):
            item.add_marker(skip_marker)


@pytest.fixture
def logtest_session() -> Generator[LogtestSession, None, None]:
    """A `LogtestSession`, torn down (last session removed) after the test."""
    session = LogtestSession()
    yield session
    session.remove_last_session()


@pytest.fixture
def send_log() -> Callable[..., LogtestResponse]:
    """Convenience fixture wrapping `wazuhtester.send_log`."""
    return _send_log
