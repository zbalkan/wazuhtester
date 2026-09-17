"""Alias module mirroring the top-level package.

Lets callers write either form:

    from wazuhtester import send_log
    from wazuhtester.logtest import send_log

The second form matches the historical `internal.logtest` import path
that wazuh-devenv's deprecation shim forwards to.
"""
from __future__ import annotations

from wazuhtester import (  # noqa: F401
    LOGTEST_SOCKET,
    WAZUH_MAX_EVENT_SIZE,
    LogtestConnectionError,
    LogtestDaemonError,
    LogtestError,
    LogtestProtocolError,
    LogtestResponse,
    LogtestSession,
    LogtestStatus,
    __all__,
    get_socket_path,
    is_logtest_available,
    send_log,
    send_multiple_logs,
)
