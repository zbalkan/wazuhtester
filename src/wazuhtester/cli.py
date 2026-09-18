"""Command-line interface for the Wazuh logtest client."""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import TextIO

from wazuhtester import __version__
from wazuhtester.errors import LogtestError
from wazuhtester.response import LogtestResponse
from wazuhtester.session import LogtestSession


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wazuhtester",
        description="Send log records from stdin to the Wazuh logtest daemon.",
    )
    parser.add_argument("-l", "--location", default="stdin", help="Wazuh event location (default: stdin)")
    parser.add_argument("-f", "--log-format", default="syslog", help="Wazuh log format (default: syslog)")
    parser.add_argument("-s", "--socket", dest="socket_path", help="Path to the wazuh-logtest Unix socket")
    parser.add_argument("--json", action="store_true", help="Emit one JSON object per input record")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _remove_line_delimiter(line: str) -> str:
    if line.endswith("\n"):
        line = line[:-1]
    if line.endswith("\r"):
        line = line[:-1]
    return line


def _write_human(response: LogtestResponse, stream: TextIO) -> None:
    print(f"Status:      {response.status.name}", file=stream)
    if response.decoder:
        print(f"Decoder:     {response.decoder}", file=stream)
    if response.rule_id is not None:
        print(f"Rule:        {response.rule_id}", file=stream)
    if response.rule_level is not None:
        print(f"Level:       {response.rule_level}", file=stream)
    if response.rule_description:
        print(f"Description: {response.rule_description}", file=stream)
    print(f"Alert:       {'yes' if response.alert else 'no'}", file=stream)
    if response.rule_mitre_ids:
        print(f"MITRE:       {', '.join(sorted(response.rule_mitre_ids))}", file=stream)


def _run(args: argparse.Namespace, stdin: TextIO, stdout: TextIO) -> None:
    first = True
    with LogtestSession(
        location=args.location,
        log_format=args.log_format,
        socket_path=args.socket_path,
    ) as session:
        for line in stdin:
            event = _remove_line_delimiter(line)
            if not event:
                continue

            response = LogtestResponse(session.process_log(event))
            if args.json:
                print(
                    json.dumps(response.to_dict(), ensure_ascii=False, sort_keys=True),
                    file=stdout,
                    flush=True,
                )
            else:
                if not first:
                    print(file=stdout)
                _write_human(response, stdout)
            first = False


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line client."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        _run(args, sys.stdin, sys.stdout)
    except KeyboardInterrupt:
        return 130
    except (LogtestError, ValueError) as exc:
        print(f"wazuhtester: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
