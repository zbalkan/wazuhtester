"""Tests for the wazuhtester command-line interface."""
from __future__ import annotations

import io
import json
import sys

import pytest

from wazuhtester import __version__
from wazuhtester.cli import main


def _rule_match_reply(token: str = "tok-1") -> dict:
    return {
        "data": {
            "token": token,
            "alert": True,
            "output": {
                "decoder": {"name": "sshd"},
                "rule": {
                    "id": "5710",
                    "level": 5,
                    "description": "sshd rule",
                    "mitre": {"id": ["T1110"]},
                },
            },
        }
    }


def test_cli_human_output(fake_logtest_server, fake_socket_path: str, monkeypatch, capsys) -> None:
    def handler(req: dict) -> dict:
        if req["command"] == "remove_session":
            return {"codemsg": 0}
        return _rule_match_reply()

    fake_logtest_server(handler)
    monkeypatch.setattr(sys, "stdin", io.StringIO("one\n"))

    assert main(["--socket", fake_socket_path]) == 0

    output = capsys.readouterr().out
    assert "Status:      RuleMatch" in output
    assert "Decoder:     sshd" in output
    assert "Rule:        5710" in output
    assert "Level:       5" in output
    assert "Alert:       yes" in output
    assert "MITRE:       T1110" in output


def test_cli_json_is_ndjson_and_reuses_session(
    fake_logtest_server,
    fake_socket_path: str,
    monkeypatch,
    capsys,
) -> None:
    calls: list[dict] = []

    def handler(req: dict) -> dict:
        calls.append(req)
        if req["command"] == "remove_session":
            return {"codemsg": 0}
        return _rule_match_reply()

    fake_logtest_server(handler)
    monkeypatch.setattr(sys, "stdin", io.StringIO("first\nsecond\n"))

    assert main(["--socket", fake_socket_path, "--json"]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["status"] == "RuleMatch" for line in lines)

    process_calls = [call for call in calls if call["command"] == "log_processing"]
    assert "token" not in process_calls[0]["parameters"]
    assert process_calls[1]["parameters"]["token"] == "tok-1"
    assert calls[-1]["command"] == "remove_session"


def test_cli_forwards_location_and_log_format(
    fake_logtest_server,
    fake_socket_path: str,
    monkeypatch,
) -> None:
    calls: list[dict] = []

    def handler(req: dict) -> dict:
        calls.append(req)
        if req["command"] == "remove_session":
            return {"codemsg": 0}
        return _rule_match_reply()

    fake_logtest_server(handler)
    monkeypatch.setattr(sys, "stdin", io.StringIO("event\n"))

    assert main(
        [
            "--socket",
            fake_socket_path,
            "--location",
            "custom-location",
            "--log-format",
            "json",
        ]
    ) == 0

    parameters = calls[0]["parameters"]
    assert parameters["location"] == "custom-location"
    assert parameters["log_format"] == "json"


def test_cli_connection_error_returns_one(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("event\n"))

    assert main(["--socket", str(tmp_path / "missing.sock")]) == 1
    assert "wazuhtester: error:" in capsys.readouterr().err


def test_cli_version(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])

    assert excinfo.value.code == 0
    assert f"wazuhtester {__version__}" in capsys.readouterr().out


def test_cli_invalid_argument_uses_argparse_exit_code() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["unexpected"])

    assert excinfo.value.code == 2
