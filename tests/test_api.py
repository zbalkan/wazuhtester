"""Tests for the high-level send_log / send_multiple_logs API."""
from __future__ import annotations

from wazuhtester.api import send_log, send_multiple_logs
from wazuhtester.response import LogtestStatus


def _rule_match_reply(rule_id: str) -> dict:
    return {
        "data": {
            "token": "tok-1",
            "output": {
                "decoder": {"name": "sshd"},
                "rule": {"id": rule_id, "level": 5},
            },
        }
    }


def test_send_log_returns_parsed_response(fake_logtest_server, fake_socket_path: str) -> None:
    fake_logtest_server(lambda req: _rule_match_reply("5710"))
    response = send_log("a log line", socket_path=fake_socket_path)
    assert response.status == LogtestStatus.RuleMatch
    assert response.rule_id == "5710"


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
    # Only the second and third calls should carry the token from the first reply.
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
    try:
        send_multiple_logs(["log1", "log2"], socket_path=fake_socket_path)
    except Exception:
        pass

    remove_calls = [c for c in calls if c["command"] == "remove_session"]
    assert len(remove_calls) == 1, "the session must be cleaned up even when a log in the middle errors"
