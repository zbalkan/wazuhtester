# Roadmap

Covers the separation of the Wazuh logtest client package (`wazuhtester`, published to
PyPI as both a library and CLI) from the rule/decoder test corpus and development environment
(`wazuh-devenv`). The design behind the split is in the extraction plan;
see [`docs/library-extraction-plan.md`](https://github.com/zbalkan/wazuh-devenv/blob/main/docs/library-extraction-plan.md) in `wazuh-devenv` for the API surface, the defects fixed during the move, and the migration mechanics.

**Versioning.** Neither repository has git tags today; `wazuh-devenv`'s only version
marker is `APP_VERSION = '0.2'` inside `src/tester.py`, the file the migration deletes.
This roadmap therefore establishes tagging rather than continuing it. Both repositories
follow SemVer. Before 1.0 a minor bump may break API — the `wazuhtester~=0.1` pin in
`wazuh-devenv` is what contains that.

**Commitment level.** Milestones M0–M4 are committed scope. M5 and M6 are candidates,
listed so the sequencing is visible, not promised. Gates are conditions, not dates.

**Critical path.** The `wazuh-devenv` migration runs against a temporary git pin *before*
the library's first PyPI release, deliberately. A PyPI version number cannot be
re-uploaded, so `0.1.0` is spent only after the full corpus has passed against the exact
code that will carry it.

## Milestones

| ID | Repo | Version | Theme | Exit gate |
|---|---|---|---|---|
| **M0** | wazuhtester | — | Foundations | `pip install -e .` works; CI green on 3.10–3.13; PyPI and TestPyPI projects claimed, Trusted Publishing configured |
| **M1** | wazuhtester | `0.1.0rc1` → TestPyPI | Extraction + CLI | Library and CLI tests green against a fake `AF_UNIX` server; installed wheel supports import, `wazuhtester --help`, and `python -m wazuhtester --help`; clean install from TestPyPI |
| **M2** | wazuh-devenv | branch only | Migration | Full corpus green on a live Wazuh host via the git pin; collected test count and pass/fail set identical to the pre-migration `tester.py` baseline |
| **M3** | wazuhtester | `0.1.0` → PyPI | First release | M2 passed — the release is the consequence of integration, not its precondition |
| **M4** | wazuh-devenv | `0.3.0` | Cutover | Pin swapped from `git+https` to `wazuhtester~=0.1`; CI green; merged and tagged |
| **M5** | wazuhtester | `0.2.0` | *Candidate* — reuse | A second consumer exists outside `wazuh-devenv` |
| **M6** | wazuh-devenv | `0.4.0` | *Candidate* — corpus | Regenerated builtin corpus green against a current Wazuh ruleset |
| **M7** | both | `1.0.0` | Freeze | API frozen; `internal.*` shim deleted |

## Milestone detail

### M0 — Foundations (`wazuhtester`)

Scaffolding only, no logic moved yet, so that M1 is a pure code move reviewed against a
working build.

`pyproject.toml` (`requires-python = ">=3.10"`), `src/` layout, `py.typed`, a CI workflow
running lint, type checks and unit tests across Python 3.10–3.13, and a publish workflow
using PyPI Trusted Publishing (OIDC, so no long-lived token lives in repository secrets).
Mirror the two security workflows `wazuh-devenv` already has — CodeQL and DevSkim — into
the library; a published package deserves at least the scanning the consuming repository
already gets.

Claim both the PyPI and TestPyPI project names in this milestone. `wazuhtester`,
`wazuh-tester` and `wazuh-logtest` were all unregistered as of 2026-09-16; an unclaimed
name adjacent to a published project is a supply-chain risk, not merely an inconvenience.

### M1 — Extraction (`wazuhtester 0.1.0rc1`)

`src/internal/logtest.py` from `wazuh-devenv` becomes `errors.py`, `config.py`,
`protocol.py`, `session.py`, `response.py` and `api.py`, plus `pytest_plugin.py`
registered on the `pytest11` entry point. `src/internal/result.py` is deleted rather than
moved — pytest's built-in `--junitxml` replaces it with no new code.

Three API changes carry the entire reuse argument and must not be deferred past this
release:

| Change | Replaces | Why it cannot wait |
|---|---|---|
| `is_logtest_available()` | `_WazuhLogtestHelpers.is_socket_open()` | A preflight test already imports the private helper; that is the concrete evidence the boundary is wrong |
| `get_socket_path()` with a `WAZUH_LOGTEST_SOCKET` override | hardcoded `/var/ossec/queue/sockets/logtest` | Hardcoding blocks containers and non-default installs, which is the single biggest obstacle to reuse |
| `LogtestError` hierarchy subclassing the builtins | bare `ConnectionError` / `ValueError` | Callers cannot currently distinguish "daemon down" from "malformed reply"; subclassing keeps existing `except ConnectionError` working |

The defects catalogued in the extraction plan land here too. After `0.1.0` they become
breaking changes rather than fixes.

The first release also exposes the package as a command-line application. `wazuhtester`
and `python -m wazuhtester` are equivalent entry points. The CLI reads stdin as a stream,
uses one daemon session for the invocation, supports human-readable and NDJSON output,
and delegates all protocol and session behavior to the library. The command is deliberately
named `wazuhtester` rather than `wazuh-logtest` to avoid colliding with Wazuh's native
executable.

Before exposing that CLI, `LogtestSession` owns automatic token reuse, one-shot
`send_log()` calls clean up sessions they create, explicit-token calls retain caller
ownership, and `LogtestResponse.to_dict()` provides the stable serialization boundary
used by the CLI.

Library and CLI tests run against a fake `AF_UNIX` server replaying recorded daemon envelopes, so
library CI never provisions a Wazuh manager. That is what keeps the feedback loop fast and
is the main structural gain over the status quo.

### M2 — Migration (`wazuh-devenv`, branch)

Runs against `wazuhtester @ git+https://github.com/zbalkan/wazuhtester@main`: rewrite the
93 `from internal.logtest import …` sites, leave the deprecating `internal.logtest` shim,
add `pyproject.toml` and `requirements.txt` plus pytest configuration, restore
preflight-first ordering via `src/tests/conftest.py`, extend `install.sh` to install the
Python dependencies, and move CI from `tester.py` to `pytest`.

The gate is a diff, not an impression. Capture the pre-migration
`python src/tester.py --verbosity 2` output on a live host, then diff it against
`pytest -x -v`. A changed test count means the rewrite silently dropped a file.

The pin swap at M4 is the most forgettable step in this roadmap. Guard it mechanically: a
CI check that fails when `requirements.txt` contains `git+` on a tagged build is cheap
insurance against shipping a git dependency to end users.

### M3 — First release (`wazuhtester 0.1.0`)

Tag and publish. Nothing new is built here. The milestone exists to make explicit that the
release is gated on M2 having passed.

### M4 — Cutover (`wazuh-devenv 0.3.0`)

Swap the pin, merge, and tag `v0.3.0` — the repository's first tag. Ship a `CHANGELOG.md`
stating that the `internal.*` deprecation window closes at 1.0.0, and recording the loss
of the `/tmp/tester.log` JSON line in favour of JUnit XML, since anything downstream
parsing that line breaks.

### M5 — Reuse (`wazuhtester 0.2.0`) — candidate

The split only pays for itself if a second consumer appears. Likely contents are CLI and
session ergonomics driven by actual consumers: file input, selected diagnostic modes, and
controlled exposure of the daemon's `options` parameter so capabilities such as
`rules_debug` can be reached without turning arbitrary protocol JSON into the public CLI.

Do not build this speculatively. Let a second consumer's actual requirements drive it.

A ruleset-introspection API — parsing rule and decoder XML — belongs here as well. It is
the prerequisite for relocating the coverage reporter out of `wazuh-devenv`, which was
deliberately excluded from the initial split.

### M6 — Corpus (`wazuh-devenv 0.4.0`) — candidate

Regenerate the 90-file builtin corpus against a current Wazuh ruleset using the existing
[wazuh_test_generator](https://github.com/zbalkan/wazuh_test_generator), evaluate
`pytest-xdist -n auto` for parallelism, and fill the empty `behavioral_tests/`
placeholder.

Parallelism is plausible rather than certain: each `send_log` call opens its own session,
and the installer already sets `max_sessions 500` and `threads auto`. It should be
measured, not assumed, and it should not ride along with the extraction.

### M7 — Freeze (`1.0.0`)

API freeze on the library with a written deprecation policy; the `internal.*` shim deleted
from `wazuh-devenv`.

## Support matrix

| Axis | Committed | Verified in CI |
|---|---|---|
| Python | 3.10+ — PEP 604 unions evaluated in annotations set the floor | 3.10, 3.11, 3.12, 3.13 |
| Wazuh | 4.x | One pinned minor |
| OS | Linux only — `AF_UNIX` sockets, and `grp`/`pwd` in the preflight tests | Ubuntu runner |

**Reproducibility gap to close in M2.** `install.sh` adds the Wazuh `4.x` apt channel
(line 406) and the `4.x` yum channel (line 454) with no version pin, so CI installs
whatever 4.x is current at run time. A Wazuh point release can therefore turn the corpus
red with no change in either repository, and that build cannot be reproduced afterwards.
Add a `WAZUH_VERSION` environment override to the installer and pin it in CI, while
keeping unpinned as the default for end users, who generally do want current.

## Non-goals

Stated explicitly so that scope creep has to argue its case.

- The builtin regression corpus is not shipped to PyPI. It stays in `wazuh-devenv` and arrives by git clone.
- The existing `unittest.TestCase` tests are not rewritten pytest-native. pytest collects them as they are, which is what makes this split cheap.
- The package covers the logtest socket only — not the Wazuh API, not agent management, not alert ingestion.
- The CLI does not replace or shadow Wazuh's native `wazuh-logtest` executable.
- No Windows support. WSL remains the documented path, as it is today.
- Air-gapped installation is not supported. `install.sh` may assume reachable
  package indexes, so no `--no-python-deps` flag and no offline wheel workflow are
  built. This is a deliberate exclusion, not an oversight.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Pin swap forgotten at M4, shipping a git dependency to users | High | CI check rejecting `git+` in `requirements.txt` on tagged builds |
| `0.1.0` published before real integration | High | Sequencing M2 ahead of M3 exists precisely to prevent this |
| `install.sh` gains its first PyPI dependency, so a PyPI or network outage now fails the install | Medium | Fail loudly through the existing `on_error` trap rather than leaving an empty venv that later yields `ModuleNotFoundError`. Air-gapped operation is out of scope (see Non-goals) |
| Two-repo lockstep adds release ceremony for a single maintainer | Medium | `~=0.1` pinning; accept that the payoff is conditional on M5 actually happening |
| Unpinned Wazuh 4.x breaks CI unreproducibly | Medium | `WAZUH_VERSION` override, pinned in CI at M2 |
| Downstream forks parsing `/tmp/tester.log` break silently | Low | CHANGELOG entry at M4; JUnit XML is the replacement |

## Open decisions

1. **GitHub Releases for `wazuh-devenv`**, or tags only? It has neither today.
2. **Which Wazuh minor to pin in CI.** The support matrix says one pinned minor but not which; pick whatever `install.sh` resolves on the day M2 starts.
