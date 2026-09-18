"""Tests for the high-level send_log / send_multiple_logs API."""
from __future__ import annotations

import logging

import pytest

from wazuhtester.api import send_log, send_multiple_logs
from wazuhtester.errors import LogtestDaemonError
from wazuhtester.response import LogtestStatus


def _rule_match_reply(rule_id: str, token: str = "tok-1") -> dict:
    return {
        "data": {
            "token": token,
            "output": {
                "decoder": {"name": "sshd"},
                "rule": {"id": rule_id, "level": 5},
            },
        }
    }


def test_send_log_returns_parsed_response_and_removes_owned_session(
    fake_logtest_server,
    fake_socket_path: str,
) -> None:
    calls: list[dict] = []

    def handler(req: dict) -> dict:
        calls.append(req)
        if req["command"] == "remove_session":
            return {"codemsg": 0}
        return _rule_match_reply("5710")

    fake_logtest_server(handler)
    response = send_log("a log line", socket_path=fake_socket_path)

    assert response.status == LogtestStatus.RuleMatch
    assert response.rule_id == "5710"
    assert [call["command"] for call in calls] == ["log_processing", "remove_session"]


def test_send_log_with_explicit_token_leaves_session_owned_by_caller(
    fake_logtest_server,
    fake_socket_path: str,
) -> None:
    calls: list[dict] = []

    def handler(req: dict) -> dict:
        calls.append(req)
        return _rule_match_reply("5710")

    fake_logtest_server(handler)
    send_log("a log line", token="tok-external", socket_path=fake_socket_path)

    assert [call["command"] for call in calls] == ["log_processing"]
    assert calls[0]["parameters"]["token"] == "tok-external"


def test_send_multiple_logs_reuses_token_and_removes_session(fake_logtest_server, fake_socket_path: str) -> None:
    calls: list[dict] = []

    def handler(req: dict) -> dict:
        calls.append(req)
        if req["command"] == "remove_session":
            return {"codemsg": 0}
        return _rule_match_reply("5712")

    fake_logtest_server(handler)
    responses = send_multiple_logs(["log1", "log2", "log3"], socket_path=fake_socket_path)

    assert len(responses) == 3
    assert all(r.status == LogtestStatus.RuleMatch for r in responses)

    process_calls = [c for c in calls if c["command"] == "log_processing"]
    assert "token" not in process_calls[0]["parameters"]
    assert process_calls[1]["parameters"]["token"] == "tok-1"
    assert process_calls[2]["parameters"]["token"] == "tok-1"

    remove_calls = [c for c in calls if c["command"] == "remove_session"]
    assert len(remove_calls) == 1
    assert remove_calls[0]["parameters"]["token"] == "tok-1"


def test_send_multiple_logs_removes_session_even_on_error(fake_logtest_server, fake_socket_path: str) -> None:
    calls: list[dict] = []
    responses_left = [_rule_match_reply("1"), {"error": 6, "message": "boom"}]

    def handler(req: dict) -> dict:
        calls.append(req)
        if req["command"] == "remove_session":
            return {"codemsg": 0}
        return responses_left.pop(0)

    fake_logtest_server(handler)
    with pytest.raises(LogtestDaemonError):
        send_multiple_logs(["log1", "log2"], socket_path=fake_socket_path)

    remove_calls = [c for c in calls if c["command"] == "remove_session"]
    assert len(remove_calls) == 1


def test_send_log_does_not_log_exception_before_reraising(
    fake_logtest_server,
    fake_socket_path: str,
    caplog,
) -> None:
    fake_logtest_server(lambda req: {"error": 6, "message": "boom"})
    caplog.set_level(logging.ERROR)

    with pytest.raises(LogtestDaemonError):
        send_log("a log line", socket_path=fake_socket_path)

    assert not [record for record in caplog.records if record.name == "wazuhtester.api"]
