"""Tests for the pytest11 plugin's opt-in availability gating.

Uses pytest's `pytester` fixture to run a small inner pytest session
against a scratch project, so we can assert on collection/skip behaviour
without affecting this test run's own session.
"""
from __future__ import annotations


def test_unmarked_tests_run_normally_without_daemon(pytester) -> None:
    # The plugin auto-loads via its pytest11 entry point since wazuhtester
    # is installed in this environment - no explicit -p needed (passing one
    # would register it a second time under a different name).
    pytester.makepyfile(
        """
        def test_ok():
            assert True
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_marked_test_is_skipped_when_daemon_unavailable(pytester, tmp_path) -> None:
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.wazuh_logtest
        def test_needs_daemon():
            assert True
        """
    )
    result = pytester.runpytest("--wazuh-socket", str(tmp_path / "no-such.sock"))
    result.assert_outcomes(skipped=1)


def test_require_logtest_exits_session_when_daemon_unavailable(pytester, tmp_path) -> None:
    pytester.makepyfile(
        """
        def test_ok():
            assert True
        """
    )
    result = pytester.runpytest(
        "--wazuh-require-logtest",
        "--wazuh-socket",
        str(tmp_path / "no-such.sock"),
    )
    assert result.ret != 0
    result.stdout.fnmatch_lines(["*unreachable*"])
