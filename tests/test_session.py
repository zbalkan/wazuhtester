"""Tests for LogtestSession against the fake daemon."""
from __future__ import annotations

import pytest

from wazuhtester.config import WAZUH_MAX_EVENT_SIZE
from wazuhtester.session import LogtestSession


def test_process_log_tracks_token(fake_logtest_server, fake_socket_path: str) -> None:
    fake_logtest_server(lambda req: {"data": {"token": "tok-123", "output": {}}})
    session = LogtestSession(socket_path=fake_socket_path)
    reply = session.process_log("hello")
    assert reply["data"]["token"] == "tok-123"


def test_process_log_reuses_tracked_token(fake_logtest_server, fake_socket_path: str) -> None:
    calls: list[dict] = []

    def handler(req: dict) -> dict:
        calls.append(req)
        if req["command"] == "remove_session":
            return {"codemsg": 0}
        return {"data": {"token": "tok-123", "output": {}}}

    fake_logtest_server(handler)
    with LogtestSession(socket_path=fake_socket_path) as session:
        session.process_log("first")
        session.process_log("second")

    process_calls = [call for call in calls if call["command"] == "log_processing"]
    assert "token" not in process_calls[0]["parameters"]
    assert process_calls[1]["parameters"]["token"] == "tok-123"


def test_explicit_token_overrides_tracked_token_and_updates_state(
    fake_logtest_server,
    fake_socket_path: str,
) -> None:
    calls: list[dict] = []
    tokens = iter(["tok-first", "tok-second", "tok-second"])

    def handler(req: dict) -> dict:
        calls.append(req)
        if req["command"] == "remove_session":
            return {"codemsg": 0}
        return {"data": {"token": next(tokens), "output": {}}}

    fake_logtest_server(handler)
    with LogtestSession(socket_path=fake_socket_path) as session:
        session.process_log("first")
        session.process_log("second", token="tok-external")
        session.process_log("third")

    process_calls = [call for call in calls if call["command"] == "log_processing"]
    assert process_calls[1]["parameters"]["token"] == "tok-external"
    assert process_calls[2]["parameters"]["token"] == "tok-second"


def test_process_log_rejects_oversized_log(fake_socket_path: str) -> None:
    session = LogtestSession(socket_path=fake_socket_path)
    with pytest.raises(ValueError, match="exceeds the maximum limit"):
        session.process_log("x" * (WAZUH_MAX_EVENT_SIZE + 1))


def test_remove_session_reports_success(fake_logtest_server, fake_socket_path: str) -> None:
    fake_logtest_server(lambda req: {"codemsg": 0})
    session = LogtestSession(socket_path=fake_socket_path)
    assert session.remove_session("tok-123") is True


def test_remove_session_reports_failure_without_raising(fake_logtest_server, fake_socket_path: str) -> None:
    fake_logtest_server(lambda req: {"codemsg": -1})
    session = LogtestSession(socket_path=fake_socket_path)
    assert session.remove_session("tok-123") is False


def test_remove_last_session_noop_when_no_token(fake_socket_path: str) -> None:
    session = LogtestSession(socket_path=fake_socket_path)
    session.remove_last_session()


def test_context_manager_removes_last_session(fake_logtest_server, fake_socket_path: str) -> None:
    calls: list[dict] = []

    def handler(req: dict) -> dict:
        calls.append(req)
        command = req["command"]
        if command == "log_processing":
            return {"data": {"token": "tok-abc", "output": {}}}
        return {"codemsg": 0}

    fake_logtest_server(handler)
    with LogtestSession(socket_path=fake_socket_path) as session:
        session.process_log("hello")

    commands = [c["command"] for c in calls]
    assert commands == ["log_processing", "remove_session"]
    assert calls[-1]["parameters"]["token"] == "tok-abc"
