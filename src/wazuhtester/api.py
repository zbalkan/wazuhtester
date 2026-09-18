"""High-level functions for sending logs to the Wazuh logtest daemon."""
from __future__ import annotations

from typing import Any

from wazuhtester.response import LogtestResponse
from wazuhtester.session import LogtestSession


def send_log(
    log: str,
    location: str = "stdin",
    log_format: str = "syslog",
    token: str | None = None,
    socket_path: str | None = None,
) -> LogtestResponse:
    """Send a single log to Wazuh logtest and return the parsed response.

    A call without `token` owns the daemon session it creates and removes it
    before returning. When an existing `token` is supplied, session lifetime
    remains the caller's responsibility.

    Args:
        log: The log message to send.
        location: The location field to report to Wazuh.
        log_format: The log format to report to Wazuh.
        token: An existing caller-owned session token to continue, if any.
        socket_path: Socket to connect to. Defaults to `get_socket_path()`.

    Returns:
        The parsed `LogtestResponse`.
    """
    session = LogtestSession(location=location, log_format=log_format, socket_path=socket_path)
    try:
        response_dict = session.process_log(log, token=token)
        return LogtestResponse(response_dict)
    finally:
        if token is None:
            session.remove_last_session()


def send_multiple_logs(
    logs: list[str],
    location: str = "stdin",
    log_format: str = "syslog",
    options: dict[str, Any] | None = None,
    socket_path: str | None = None,
) -> list[LogtestResponse]:
    """Send a sequence of logs within a single session.

    Needed for stateful/composite rules, which only fire once the full
    sequence has been seen under the same session token. The session is
    always removed afterwards, whether or not an error occurred.

    Args:
        logs: The log messages to send, in order.
        location: The location field to report to Wazuh.
        log_format: The log format to report to Wazuh.
        options: Additional wazuh-logtest options.
        socket_path: Socket to connect to. Defaults to `get_socket_path()`.

    Returns:
        The parsed `LogtestResponse` for each log, in order.
    """
    responses: list[LogtestResponse] = []
    with LogtestSession(location=location, log_format=log_format, socket_path=socket_path) as session:
        for log in logs:
            response_dict = session.process_log(log, options=options)
            responses.append(LogtestResponse(response_dict))
    return responses
