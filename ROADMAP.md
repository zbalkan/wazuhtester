# Roadmap

`wazuhtester` is the reusable Python library, CLI, and pytest integration for the local Wazuh `wazuh-logtest` daemon.

The Wazuh regression corpus now lives independently in [wazuh-rule-tests](https://github.com/zbalkan/wazuh-rule-tests). Environment provisioning belongs to [wazuh-devenv](https://github.com/zbalkan/wazuh-devenv). Archive coverage analysis belongs to [wazuhcoverage](https://github.com/zbalkan/wazuhcoverage).

## Scope

`wazuhtester` owns:

- Unix-socket protocol framing;
- daemon session lifecycle;
- request/response parsing;
- high-level single and batch APIs;
- typed exceptions and response models;
- pytest integration;
- the `wazuhtester` CLI.

It does not own Wazuh installation, rule/decoder content, regression-corpus distribution, or archive coverage analysis.

## Milestones

| ID | Version | Theme | Exit gate |
| --- | --- | --- | --- |
| M0 | done | Library extraction | Public API and fake-socket tests complete |
| M1 | done | CLI + pytest integration | Console/module entry points and plugin complete |
| M2 | `0.1.0rc1` | Real Wazuh qualification | Full `wazuh-rule-tests` corpus passes against pinned Wazuh |
| M3 | `0.1.0` | First PyPI release | TestPyPI wheel validated; release workflow green |
| M4 | `0.1.x` | Compatibility fixes | Only backward-compatible protocol/packaging corrections |
| M5 | `0.2.0` | Consumer-driven expansion | New functionality justified by real consumers |
| M6 | `1.0.0` | API freeze | Public API and deprecation policy stabilized |

## M2 — Real Wazuh qualification

The release workflow installs Wazuh 4.14.7 and runs the external `wazuh-rule-tests` corpus using the candidate package.

This gate validates behavior that the fake AF_UNIX server cannot prove:

- compatibility with the real daemon envelope;
- token/session behavior;
- no-decoder/no-rule variants;
- response-field semantics used by the regression corpus;
- pytest plugin behavior against a live daemon.

The corpus is a consumer, not part of this repository.

## M3 — First release

Release sequence:

```text
0.1.0rc1 -> TestPyPI
0.1.0    -> PyPI
```

Both library and CLI use the same PyPI distribution.

Library installation:

```bash
python -m pip install wazuhtester
```

CLI-oriented installation:

```bash
pipx install wazuhtester
```

A release is permitted only after unit/type checks, installed-package checks, and the live external regression corpus pass.

## Future work

Future functionality is consumer-driven rather than part of the extraction project.

Possible examples include:

- controlled exposure of Wazuh logtest `options`, including diagnostic modes such as `rules_debug`;
- file-input CLI ergonomics;
- additional session/batch APIs when concrete consumers require them;
- compatibility handling for future Wazuh protocol changes.

Ruleset XML introspection, corpus generation, archive coverage analysis, and Wazuh environment provisioning are explicitly outside this package.

## Support

| Axis | Support |
| --- | --- |
| Python | 3.10–3.13 currently validated |
| Wazuh | Wazuh 4.x; release qualification currently pins 4.14.7 |
| OS | Linux only; WSL is supported as Linux |
