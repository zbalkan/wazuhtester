"""Tests for LogtestResponse parsing, including defect #1: every attribute
must be safe to read regardless of `status`, in particular on Error."""
from __future__ import annotations

from wazuhtester.response import LogtestResponse, LogtestStatus


def test_error_status_leaves_every_attribute_readable() -> None:
    response = LogtestResponse({"error": 6, "data": {"messages": ["boom"]}})
    assert response.status == LogtestStatus.Error
    # Regression test for defect #1: these used to raise AttributeError.
    assert response.full_log == ""
    assert response.timestamp == ""
    assert response.location == ""
    assert response.alert is False
    assert response.rule_id is None
    assert response.rule_groups == set()
    assert response.get_dynamic_field_value("anything") is None
    assert response.get_dynamic_field_names() == []


def test_no_decoder_status() -> None:
    response = LogtestResponse({"data": {"output": {"full_log": "raw log line"}}})
    assert response.status == LogtestStatus.NoDecoder
    assert response.full_log == "raw log line"
    assert response.decoder is None


def test_no_rule_status() -> None:
    response = LogtestResponse(
        {"data": {"output": {"decoder": {"name": "json"}, "data": {}}}}
    )
    assert response.status == LogtestStatus.NoRule
    assert response.decoder == "json"
    assert response.rule_id is None


def test_rule_match_status_populates_rule_fields() -> None:
    response = LogtestResponse(
        {
            "data": {
                "alert": True,
                "output": {
                    "full_log": "the log",
                    "timestamp": "2026-09-17T00:00:00",
                    "location": "stdin",
                    "decoder": {"name": "sshd", "parent": "sshd"},
                    "data": {"srcip": "1.2.3.4", "date": "2019-10-10"},
                    "rule": {
                        "id": "5710",
                        "level": 5,
                        "description": ["Attempt", "to login using a non-existent user"],
                        "groups": ["authentication_failed", "custom"],
                        "mitre": {"id": ["T1110"]},
                    },
                },
            }
        }
    )
    assert response.status == LogtestStatus.RuleMatch
    assert response.alert is True
    assert response.rule_id == "5710"
    assert response.rule_level == 5
    assert response.rule_description == "Attempt. to login using a non-existent user"
    assert response.rule_groups == {"authentication_failed", "custom"}
    assert response.rule_mitre_ids == {"T1110"}
    assert response.srcip == "1.2.3.4"
    assert response.get_dynamic_field_value("date") == "2019-10-10"
    assert "date" in response.get_dynamic_field_names()


def test_rule_match_single_mitre_id_as_string() -> None:
    response = LogtestResponse(
        {
            "data": {
                "output": {
                    "decoder": {"name": "d"},
                    "rule": {"id": "1", "mitre": {"id": "T1110"}},
                }
            }
        }
    )
    assert response.rule_mitre_ids == {"T1110"}


def test_rule_match_scalar_description_not_joined() -> None:
    response = LogtestResponse(
        {
            "data": {
                "output": {
                    "decoder": {"name": "d"},
                    "rule": {"id": "1", "description": "single description"},
                }
            }
        }
    )
    assert response.rule_description == "single description"


def test_flatten_nested_dict_and_list() -> None:
    response = LogtestResponse(
        {
            "data": {
                "output": {
                    "data": {
                        "win": {"eventdata": {"targetUserName": "alice"}},
                        "items": ["a", "b"],
                        "empty_dict": {},
                        "empty_list": [],
                    }
                }
            }
        }
    )
    assert response.get_dynamic_field_value("win.eventdata.targetUserName") == "alice"
    assert response.get_dynamic_field_value("items.0") == "a"
    assert response.get_dynamic_field_value("items.1") == "b"
    assert response.get_dynamic_field_value("empty_dict") is None
    assert response.get_dynamic_field_value("empty_list") is None
