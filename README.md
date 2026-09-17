# wazuhtester

A small client library for the [Wazuh](https://wazuh.com/) `wazuh-logtest`
daemon. It handles the Unix-socket wire protocol and gives back a parsed,
typed response, so testing rules and decoders doesn't require re-implementing
the framing and JSON envelope every time.

It was extracted from [`wazuh-devenv`](https://github.com/zbalkan/wazuh-devenv),
which now consumes it via `pip` instead of carrying its own copy. See
[`ROADMAP.md`](ROADMAP.md) for how the two repositories are sequenced.

## Status

Pre-release (`0.1.0.dev0`). The API below is expected to be stable through
`1.0.0`, but hasn't shipped to PyPI yet — see the roadmap's M1–M3 milestones.

## Install

```shell
pip install wazuhtester
```

Requires Python 3.10+ and a reachable `wazuh-logtest` Unix socket (from a
running `wazuh-manager` — this library is a client, it doesn't install or run
Wazuh itself).

## Quick start

```python
from wazuhtester import send_log, LogtestStatus

response = send_log('Oct 10 10:00:00 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2')

assert response.status == LogtestStatus.RuleMatch
assert response.rule_id == "5710"
print(response.rule_description)
```

For a rule that only fires across a sequence of events (composite/stateful
rules), send them in one session with `send_multiple_logs`, which keeps the
Wazuh-issued token across calls and always removes the session afterwards:

```python
from wazuhtester import send_multiple_logs, LogtestStatus

logs = [
    "sshd: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
    "sshd: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
    "sshd: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
]
responses = send_multiple_logs(logs)
assert responses[-1].status == LogtestStatus.RuleMatch
```

## Configuring the socket path

By default the client looks for the socket at Wazuh's usual install location,
`/var/ossec/queue/sockets/logtest`. Point it elsewhere — a container, a
non-default install, a test fixture — with an environment variable or a
per-call argument:

```shell
export WAZUH_LOGTEST_SOCKET=/path/to/logtest.sock
```

```python
from wazuhtester import send_log

send_log("...", socket_path="/path/to/logtest.sock")
```

Check reachability without sending a log:

```python
from wazuhtester import is_logtest_available

if not is_logtest_available():
    raise SystemExit("wazuh-logtest is not reachable")
```

## pytest plugin

Installing `wazuhtester` registers a pytest plugin automatically (no `-p`
flag needed). It is deliberately opt-in: by default it does nothing beyond
providing fixtures, so a project that merely depends on wazuhtester doesn't
get its whole test session hard-failed just because no Wazuh daemon happens
to be reachable during that run.

- `@pytest.mark.wazuh_logtest` — mark a test as needing a live daemon. If the
  daemon is unavailable, marked tests are skipped rather than erroring.
- `--wazuh-require-logtest` (or the `wazuh_require_logtest` ini option) —
  treat a missing daemon as fatal for the whole session instead, with an
  actionable error message. Set this in a project (such as `wazuh-devenv`)
  where effectively every test needs the daemon.
- `--wazuh-socket PATH` — override the socket path for the run (equivalent to
  setting `WAZUH_LOGTEST_SOCKET`).
- Fixtures: `logtest_session` (a `LogtestSession`, torn down automatically)
  and `send_log` (a thin wrapper around `wazuhtester.send_log`).

```python
import pytest


@pytest.mark.wazuh_logtest
def test_custom_rule(send_log):
    response = send_log("...")
    assert response.rule_id == "100100"
```

## API surface

| Name | What it is |
|---|---|
| `send_log(log, location="stdin", log_format="syslog", token=None, socket_path=None)` | Send one log, get back a `LogtestResponse`. |
| `send_multiple_logs(logs, location="stdin", log_format="syslog", options=None, socket_path=None)` | Send a sequence within one session; returns a `LogtestResponse` per log. |
| `LogtestResponse` | Parsed daemon reply: `status`, `alert`, `full_log`, `timestamp`, `location`, decoder/rule fields, `get_dynamic_field_value(name)`. Every attribute is safe to read regardless of `status`. |
| `LogtestStatus` | `RuleMatch`, `Error`, `NoDecoder`, `NoRule`. |
| `LogtestSession` | Lower-level session object (also a context manager) for explicit control over session lifetime. |
| `is_logtest_available(socket_path=None)` | Cheap reachability check, no log sent. |
| `get_socket_path()` | The socket path that will be used, honouring `WAZUH_LOGTEST_SOCKET`. |
| `LogtestError`, `LogtestConnectionError`, `LogtestProtocolError`, `LogtestDaemonError` | Exception hierarchy; the connection/protocol errors subclass the matching builtins (`ConnectionError`, `ValueError`). |

## Development

```shell
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check src tests
.venv/bin/mypy src/wazuhtester
```

The test suite runs against a fake `AF_UNIX` server that replays the Wazuh
logtest wire protocol, so no Wazuh install is needed to develop or run CI.

## License

MIT — see [LICENSE](LICENSE).
