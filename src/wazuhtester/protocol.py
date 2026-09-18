"""Wire protocol for the Wazuh logtest Unix domain socket.

Handles the length-prefixed framing (a 4-byte little-endian size header
followed by the payload) and the JSON command envelope wazuh-logtest
expects, independent of any particular command.
"""
from __future__ import annotations

import json
import socket
import struct
from typing import Any

from wazuhtester.config import get_socket_path
from wazuhtester.errors import (LogtestConnectionError, LogtestDaemonError,
                                LogtestProtocolError)

_ORIGIN_NAME = "wazuh-logtest"
_CONNECT_TIMEOUT_SECONDS = 5


def is_logtest_available(socket_path: str | None = None) -> bool:
    """Return True if the Wazuh logtest socket accepts connections.

    Args:
        socket_path: Socket to probe. Defaults to `get_socket_path()`.
    """
    path = socket_path or get_socket_path()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(_CONNECT_TIMEOUT_SECONDS)
        try:
            sock.connect(path)
            return True
        except OSError:
            return False


def wrap_command(command: str, parameters: dict[str, Any]) -> str:
    """Wrap a command and its parameters in the Wazuh daemon JSON envelope.

    Args:
        command: The wazuh-logtest command name (e.g. "log_processing").
        parameters: The command's parameters.

    Returns:
        The JSON-encoded envelope, ready to be framed and sent.
    """
    msg: dict[str, Any] = {
        "version": 1,
        "origin": {"name": _ORIGIN_NAME, "module": _ORIGIN_NAME},
        "command": command,
        "parameters": parameters,
    }
    return json.dumps(msg)


def unwrap_response(msg: bytes) -> Any:
    """Unwrap a Wazuh daemon JSON envelope.

    Args:
        msg: The raw response body (already de-framed).

    Returns:
        The decoded JSON message.

    Raises:
        LogtestProtocolError: The body is not valid JSON.
        LogtestDaemonError: The daemon reported an error in the response.
    """
    try:
        json_msg: Any = json.loads(msg.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise LogtestProtocolError(f"Failed to decode JSON response: {e}") from e
    if json_msg.get("error"):
        raise LogtestDaemonError(json_msg.get("error"), json_msg.get("message", "Unknown error"))
    return json_msg


def send(msg: str, socket_path: str | None = None) -> bytes:
    """Send a framed message to the Wazuh logtest socket and return the reply.

    Args:
        msg: The message to send (typically the output of `wrap_command`).
        socket_path: Socket to connect to. Defaults to `get_socket_path()`.

    Returns:
        The de-framed response body.

    Raises:
        LogtestConnectionError: The socket could not be reached, or the
            daemon closed the connection before sending the full framed
            response (a short read).
    """
    path = socket_path or get_socket_path()
    encoded_msg = msg.encode("utf-8")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(_CONNECT_TIMEOUT_SECONDS)
            sock.connect(path)
            sock.sendall(struct.pack("<I", len(encoded_msg)) + encoded_msg)

            size_data = sock.recv(4, socket.MSG_WAITALL)
            if not size_data or len(size_data) < 4:
                raise LogtestConnectionError("No size header received from Wazuh socket.")
            size = struct.unpack("<I", size_data)[0]

            recv_msg = b""
            while len(recv_msg) < size:
                chunk = sock.recv(size - len(recv_msg), socket.MSG_WAITALL)
                if not chunk:
                    raise LogtestConnectionError(
                        f"Wazuh socket closed after {len(recv_msg)} of {size} expected bytes."
                    )
                recv_msg += chunk
            return recv_msg
    except OSError as e:
        raise LogtestConnectionError(f"Failed to communicate with Wazuh socket: {e}") from e
