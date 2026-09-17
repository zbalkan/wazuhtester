"""Exception hierarchy for wazuhtester.

Every exception subclasses a matching builtin (`ConnectionError`,
`ValueError`) so code written against the original `internal.logtest`
module's bare-builtin exceptions keeps working unchanged.
"""
from __future__ import annotations

from typing import Any


class LogtestError(Exception):
    """Base class for all errors raised by wazuhtester."""


class LogtestConnectionError(LogtestError, ConnectionError):
    """Raised when communication with the Wazuh logtest socket fails.

    Covers connection failures, timeouts, and short reads (the daemon
    closing the connection before the full framed response arrives).
    """


class LogtestProtocolError(LogtestError, ValueError):
    """Raised when the logtest daemon's response cannot be decoded as JSON."""


class LogtestDaemonError(LogtestError, ValueError):
    """Raised when the logtest daemon's response reports an error itself.

    Distinct from `LogtestProtocolError`: the response was well-formed JSON,
    but the daemon set a non-zero `error` field.
    """

    def __init__(self, error_code: Any, message: str) -> None:
        self.error_code = error_code
        self.message = message
        super().__init__(f"{error_code}: {message}")
