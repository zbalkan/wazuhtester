# wazuhtester

`wazuhtester` is a Python library and command-line tool for interacting with the
[Wazuh](https://wazuh.com/) `wazuh-logtest` daemon. It handles the Unix-socket
wire protocol, daemon sessions, and response parsing so rule and decoder tests do
not need to reimplement the framing and JSON envelope.

It was extracted from [`wazuh-devenv`](https://github.com/zbalkan/wazuh-devenv),
which consumes the package instead of carrying its own protocol client. See
[`ROADMAP.md`](ROADMAP.md) for the release and migration sequence.

## Status

Pre-release (`0.1.0.dev0`). The package has not shipped to PyPI yet.

## Installation

Install the package into a Python environment for library use:

```shell
python -m pip install wazuhtester
```

For command-line-only use, `pipx` is the preferred installation model once the
package is published:

```shell
pipx install wazuhtester
```

A local checkout can be installed with:

```shell
pipx install --editable .
```

The package requires Python 3.10+ and a reachable `wazuh-logtest` Unix socket
from a running Wazuh manager. It does not install or run Wazuh itself.

## Python API

For a single independent event:

```python
from wazuhtester import LogtestStatus, send_log

response = send_log(
    "Oct 10 10:00:00 host sshd[1234]: "
    "Failed password for root from 1.2.3.4 port 22 ssh2"
)

assert response.status == LogtestStatus.RuleMatch
print(response.rule_id)
print(response.rule_description)
```

A one-shot `send_log()` call owns the daemon session it creates and removes it
before returning. Supplying an explicit `token` means the caller owns that
existing session, so `send_log()` does not remove it.

For stateful, frequency, or composite rules, send the sequence in one session:

```python
from wazuhtester import LogtestStatus, send_multiple_logs

logs = [
    "sshd: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
    "sshd: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
    "sshd: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
]

responses = send_multiple_logs(logs)
assert responses[-1].status == LogtestStatus.RuleMatch
```

For explicit session control, `LogtestSession` automatically reuses the token
returned by the daemon:

```python
from wazuhtester import LogtestResponse, LogtestSession

with LogtestSession() as session:
    first = LogtestResponse(session.process_log("event one"))
    second = LogtestResponse(session.process_log("event two"))
```

The second request uses the token returned by the first. Exiting the context
removes the active daemon session.

## CLI

Installing the package exposes the `wazuhtester` console command. The executable
name deliberately does not use `wazuh-logtest`, which is the name of Wazuh's
native tool.

The console-script and module entry points are equivalent:

```shell
wazuhtester
python -m wazuhtester
```

The CLI reads one log record per line from stdin. All records in one invocation
share one daemon session, preserving correlation and frequency semantics:

```shell
printf '%s\n' \
  'sshd: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2' \
  'sshd: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2' |
  wazuhtester
```

Useful options:

```text
-l, --location TEXT
-f, --log-format FORMAT
-s, --socket PATH
    --json
    --version
-h, --help
```

`--json` emits one JSON object per input record (NDJSON), suitable for shell
pipelines:

```shell
cat samples.log | wazuhtester --json | jq 'select(.rule_id == "5710")'
```

A valid event that produces no rule match is still a successful CLI operation.
Runtime communication or protocol failures return exit code 1, argparse usage
errors return 2, and Ctrl+C returns 130.

## Configuring the socket path

By default the client uses:

```text
/var/ossec/queue/sockets/logtest
```

Override it through the environment:

```shell
export WAZUH_LOGTEST_SOCKET=/path/to/logtest.sock
```

or per call:

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

Installing `wazuhtester` also registers a pytest plugin through the `pytest11`
entry point. It is deliberately opt-in for daemon availability checks.

- `@pytest.mark.wazuh_logtest` marks a test as requiring a live daemon. Marked
  tests are skipped if the daemon is unavailable.
- `--wazuh-require-logtest`, or the `wazuh_require_logtest` ini option, makes
  an unavailable daemon fatal for the test session.
- `--wazuh-socket PATH` overrides the socket path for the test run.
- `logtest_session` provides a `LogtestSession` and removes its active session
  during teardown.
- `send_log` exposes the high-level one-shot API as a fixture.

```python
import pytest


@pytest.mark.wazuh_logtest
def test_custom_rule(send_log):
    response = send_log("...")
    assert response.rule_id == "100100"
```

## API surface

| Name | Purpose |
|---|---|
| `send_log(...)` | Send one event and return a `LogtestResponse`. A newly created daemon session is cleaned up automatically. |
| `send_multiple_logs(...)` | Send an ordered sequence in one daemon session and return one response per event. |
| `LogtestSession` | Lower-level session API. Automatically reuses the current daemon token and supports context-manager cleanup. |
| `LogtestResponse` | Parsed daemon response with status, decoder, rule, static and dynamic fields. `to_dict()` returns deterministic JSON-compatible data. |
| `LogtestStatus` | `RuleMatch`, `Error`, `NoDecoder`, or `NoRule`. |
| `is_logtest_available(...)` | Probe the configured Unix socket without sending an event. |
| `get_socket_path()` | Resolve the socket path, including `WAZUH_LOGTEST_SOCKET`. |
| `LogtestError` hierarchy | Distinguish connection, daemon, and protocol failures while preserving compatible builtin base classes. |

## Development

```shell
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check src tests
.venv/bin/mypy src/wazuhtester
```

The test suite uses a fake `AF_UNIX` server that implements the Wazuh logtest
framing, so a Wazuh installation is not required for normal package CI.

## License

MIT — see [LICENSE](LICENSE).
