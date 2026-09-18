"""wazuhtester: a client library for the Wazuh logtest daemon.

Extracted from wazuh-devenv's `internal.logtest` module so the protocol
client and response model can be reused outside that repository and
installed with `pip` independently of its regression-test corpus.

    from wazuhtester import send_log, LogtestStatus

    response = send_log("Oct 10 10:00:00 host sshd[123]: Failed password ...")
    assert response.status == LogtestStatus.RuleMatch
"""
from __future__ import annotations

from importlib.metadata import version as distribution_version

from wazuhtester.api import send_log, send_multiple_logs
from wazuhtester.config import LOGTEST_SOCKET, WAZUH_MAX_EVENT_SIZE, get_socket_path
from wazuhtester.errors import (
    LogtestConnectionError,
    LogtestDaemonError,
    LogtestError,
    LogtestProtocolError,
)
from wazuhtester.protocol import is_logtest_available
from wazuhtester.response import LogtestResponse, LogtestStatus
from wazuhtester.session import LogtestSession

__version__ = distribution_version("wazuhtester")

__all__ = [
    "__version__",
    "send_log",
    "send_multiple_logs",
    "LogtestResponse",
    "LogtestStatus",
    "LogtestSession",
    "is_logtest_available",
    "get_socket_path",
    "LOGTEST_SOCKET",
    "WAZUH_MAX_EVENT_SIZE",
    "LogtestError",
    "LogtestConnectionError",
    "LogtestProtocolError",
    "LogtestDaemonError",
]
