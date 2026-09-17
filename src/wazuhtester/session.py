"""Session management for the Wazuh logtest daemon."""
from __future__ import annotations

import logging
from types import TracebackType
from typing import Any

from wazuhtester.config import WAZUH_MAX_EVENT_SIZE
from wazuhtester.protocol import send, unwrap_response, wrap_command

logger = logging.getLogger(__name__)


class LogtestSession:
    """Interacts with wazuh-logtest to process logs and manage daemon sessions.

    A session groups a sequence of `process_log` calls under one location
    and log_format, and tracks the daemon-issued token so stateful
    (composite) rules see the full sequence. Use it directly, or as a
    context manager, which removes the last opened session on exit:

        with LogtestSession() as session:
            reply = session.process_log(log)
    """

    def __init__(
        self,
        location: str = "stdin",
        log_format: str = "syslog",
        socket_path: str | None = None,
    ) -> None:
        self._fixed_fields: dict[str, str] = {"location": location, "log_format": log_format}
        self._socket_path = socket_path
        self._last_token = ""

    def process_log(self, log: str, token: str | None = None, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a log event to wazuh-logtest and return the raw daemon reply.

        Args:
            log: The log message to process.
            token: An existing session token to continue, if any.
            options: Additional wazuh-logtest options.

        Returns:
            The raw (unwrapped) daemon reply.

        Raises:
            ValueError: `log` exceeds `WAZUH_MAX_EVENT_SIZE` bytes.
        """
        if len(log.encode("utf-8")) > WAZUH_MAX_EVENT_SIZE:
            raise ValueError(f"Log size exceeds the maximum limit of {WAZUH_MAX_EVENT_SIZE} bytes.")

        data: dict[str, Any] = self._fixed_fields.copy()
        if token:
            data["token"] = token
        data["event"] = log.strip("\n")
        if options:
            data["options"] = options

        request = wrap_command("log_processing", data)
        logger.debug("Request: %s", request)
        recv_packet = send(request, socket_path=self._socket_path)
        logger.debug("Reply: %s", recv_packet.decode("utf-8"))
        reply: dict[str, Any] = unwrap_response(recv_packet)

        new_token = reply.get("data", {}).get("token")
        if new_token:
            self._last_token = new_token
        return reply

    def remove_last_session(self) -> None:
        """Remove the last opened session, if any."""
        if self._last_token:
            self.remove_session(self._last_token)
            self._last_token = ""

    def remove_session(self, token: str) -> bool:
        """Remove a session by token.

        Returns:
            True if the daemon confirmed removal.
        """
        data: dict[str, Any] = self._fixed_fields.copy()
        data["token"] = token
        request = wrap_command("remove_session", data)
        try:
            recv_packet = send(request, socket_path=self._socket_path)
            reply: dict[str, Any] = unwrap_response(recv_packet)
            codemsg = int(reply.get("codemsg", -1))
            return codemsg >= 0
        except Exception:
            logger.exception("Failed to remove session %s", token)
            return False

    def __enter__(self) -> LogtestSession:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.remove_last_session()
