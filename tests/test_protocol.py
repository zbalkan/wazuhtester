"""Tests for framing, the command envelope, and daemon availability."""
from __future__ import annotations

import json
import socket
import struct
import threading

import pytest

from wazuhtester.errors import LogtestConnectionError, LogtestDaemonError, LogtestProtocolError
from wazuhtester.protocol import is_logtest_available, send, unwrap_response, wrap_command


def test_wrap_command_envelope() -> None:
    msg = wrap_command("log_processing", {"event": "hello"})
    parsed = json.loads(msg)
    assert parsed["command"] == "log_processing"
    assert parsed["parameters"] == {"event": "hello"}
    assert parsed["origin"] == {"name": "wazuh-logtest", "module": "wazuh-logtest"}
    assert parsed["version"] == 1


def test_unwrap_response_success() -> None:
    assert unwrap_response(b'{"data": {"ok": true}}') == {"data": {"ok": True}}


def test_unwrap_response_daemon_error() -> None:
    with pytest.raises(LogtestDaemonError) as excinfo:
        unwrap_response(b'{"error": 6, "message": "boom"}')
    assert excinfo.value.error_code == 6
    assert "boom" in str(excinfo.value)


@pytest.mark.parametrize("payload", [b"not json", b"\xff"])
def test_unwrap_response_malformed_payload(payload: bytes) -> None:
    with pytest.raises(LogtestProtocolError):
        unwrap_response(payload)


@pytest.mark.parametrize("payload", [b"[]", b'"error"', b"42", b"null"])
def test_unwrap_response_rejects_non_object_json(payload: bytes) -> None:
    with pytest.raises(LogtestProtocolError, match="must be a JSON object"):
        unwrap_response(payload)


def test_is_logtest_available_false_when_socket_missing(tmp_path) -> None:
    assert is_logtest_available(str(tmp_path / "no-such.sock")) is False


def test_is_logtest_available_true(fake_socket_path: str) -> None:
    assert is_logtest_available(fake_socket_path) is True


def test_send_round_trip(fake_logtest_server, fake_socket_path: str) -> None:
    fake_logtest_server(lambda req: {"echo": req})
    reply = send(wrap_command("log_processing", {"event": "x"}), socket_path=fake_socket_path)
    assert json.loads(reply)["echo"]["command"] == "log_processing"


def test_send_connection_refused_raises(tmp_path) -> None:
    with pytest.raises(LogtestConnectionError):
        send(wrap_command("x", {}), socket_path=str(tmp_path / "no-such.sock"))


def test_send_short_read_raises(tmp_path) -> None:
    # A server that advertises a body size, then closes before sending it.
    socket_path = str(tmp_path / "short.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(socket_path)
    srv.listen(1)

    def serve() -> None:
        conn, _ = srv.accept()
        with conn:
            conn.recv(4096)
            conn.sendall(struct.pack("<I", 100) + b"short")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with pytest.raises(LogtestConnectionError, match="closed after"):
            send(wrap_command("x", {}), socket_path=socket_path)
    finally:
        thread.join(timeout=2)
        srv.close()


def test_send_times_out_waiting_for_header(tmp_path, monkeypatch) -> None:
    socket_path = str(tmp_path / "stalled-header.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(socket_path)
    srv.listen(1)
    release = threading.Event()

    def serve() -> None:
        conn, _ = srv.accept()
        with conn:
            conn.recv(4096)
            release.wait(timeout=1)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    monkeypatch.setattr("wazuhtester.protocol._CONNECT_TIMEOUT_SECONDS", 0.05)
    try:
        with pytest.raises(LogtestConnectionError, match="timed out"):
            send(wrap_command("x", {}), socket_path=socket_path)
    finally:
        release.set()
        thread.join(timeout=2)
        srv.close()


def test_send_times_out_waiting_for_body(tmp_path, monkeypatch) -> None:
    socket_path = str(tmp_path / "stalled-body.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(socket_path)
    srv.listen(1)
    release = threading.Event()

    def serve() -> None:
        conn, _ = srv.accept()
        with conn:
            conn.recv(4096)
            conn.sendall(struct.pack("<I", 10) + b"x")
            release.wait(timeout=1)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    monkeypatch.setattr("wazuhtester.protocol._CONNECT_TIMEOUT_SECONDS", 0.05)
    try:
        with pytest.raises(LogtestConnectionError, match="timed out"):
            send(wrap_command("x", {}), socket_path=socket_path)
    finally:
        release.set()
        thread.join(timeout=2)
        srv.close()
