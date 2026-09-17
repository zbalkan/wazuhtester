"""Shared fixtures: a fake Wazuh logtest Unix-socket server.

Replays the same length-prefixed framing wazuh-logtest uses, so the
protocol, session and response layers can be exercised end to end
without a real Wazuh install.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest

pytest_plugins = ["pytester"]


def _frame(payload: dict) -> bytes:
    encoded = json.dumps(payload).encode("utf-8")
    return struct.pack("<I", len(encoded)) + encoded


@dataclass
class FakeLogtestServer:
    """A minimal AF_UNIX server replaying the Wazuh logtest wire protocol."""

    socket_path: str
    handler: Callable[[dict], dict]
    _thread: threading.Thread | None = field(default=None, init=False)
    _server: socket.socket | None = field(default=None, init=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False)

    def start(self) -> None:
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.socket_path)
        self._server.listen(1)
        self._server.settimeout(0.2)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with conn:
                try:
                    size_data = conn.recv(4, socket.MSG_WAITALL)
                    if not size_data:
                        continue
                    size = struct.unpack("<I", size_data)[0]
                    body = b""
                    while len(body) < size:
                        chunk = conn.recv(size - len(body))
                        if not chunk:
                            break
                        body += chunk
                    request: dict[str, Any] = json.loads(body.decode("utf-8"))
                    response = self.handler(request)
                    conn.sendall(_frame(response))
                except OSError:
                    continue

    def stop(self) -> None:
        self._stop.set()
        if self._server:
            self._server.close()
        if self._thread:
            self._thread.join(timeout=2)
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)


@pytest.fixture
def fake_logtest_server(tmp_path, monkeypatch):
    """Start a fake logtest server and point WAZUH_LOGTEST_SOCKET at it.

    Yields a `set_handler(fn)` callable so each test can script the
    daemon's reply to the next `wrap_command`-shaped request it receives.
    """
    socket_path = str(tmp_path / "logtest.sock")
    handler_box: dict[str, Callable[[dict], dict]] = {"fn": lambda req: {"error": 0, "data": {}}}

    def handler(request: dict) -> dict:
        return handler_box["fn"](request)

    server = FakeLogtestServer(socket_path=socket_path, handler=handler)
    server.start()
    monkeypatch.setenv("WAZUH_LOGTEST_SOCKET", socket_path)

    def set_handler(fn: Callable[[dict], dict]) -> None:
        handler_box["fn"] = fn

    yield set_handler
    server.stop()


@pytest.fixture
def fake_socket_path(fake_logtest_server) -> str:
    """The socket path the current `fake_logtest_server` is bound to."""
    return os.environ["WAZUH_LOGTEST_SOCKET"]
